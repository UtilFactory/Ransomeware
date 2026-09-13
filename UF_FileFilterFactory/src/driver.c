#include "driver.h"

PFLT_FILTER gUfFilter;
PFLT_PORT gUfServerPort;
PFLT_PORT gUfClientPort;

static NTSTATUS UfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS UfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static FLT_PREOP_CALLBACK_STATUS UfPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static NTSTATUS UfPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie);
static VOID UfPortDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS UfPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, UfPreOperation, NULL },
    { IRP_MJ_READ, 0, UfPreOperation, NULL },
    { IRP_MJ_WRITE, 0, UfPreOperation, UfBootPostWrite },
    { IRP_MJ_SET_INFORMATION, 0, UfPreOperation, NULL },
    { IRP_MJ_SET_SECURITY, 0, UfPreOperation, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, UfPreOperation, NULL },
    { IRP_MJ_QUERY_SECURITY, 0, UfPreOperation, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, UfPreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    UfUnload,
    UfInstanceSetup,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static VOID
UfCopyUnicodeToFixed(
    _Out_writes_(CapacityChars) PWCHAR Destination,
    _In_ ULONG CapacityChars,
    _Out_ PULONG WrittenChars,
    _In_ PCUNICODE_STRING Source)
{
    ULONG chars = Source->Length / sizeof(WCHAR);
    if (chars >= CapacityChars) {
        chars = CapacityChars - 1;
    }
    if (chars != 0) {
        RtlCopyMemory(Destination, Source->Buffer, chars * sizeof(WCHAR));
    }
    Destination[chars] = L'\0';
    *WrittenChars = chars;
}

VOID
UfSendEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _In_ UF_EVENT_ACTION Action,
    _In_ UF_IO_OPERATION Operation,
    _In_ ULONG DesiredAccess,
    _In_ ULONG Disposition,
    _In_ ULONGLONG ProcessCreateTime,
    _In_opt_ const UF_POLICY_EVALUATION* Evaluation)
{
    UF_FILE_EVENT_V2* eventMessage;
    LARGE_INTEGER timeout;
    if (gUfClientPort == NULL) {
        return;
    }

    eventMessage = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*eventMessage), UF_POOL_TAG);
    if (eventMessage == NULL) {
        return;
    }

    RtlZeroMemory(eventMessage, sizeof(*eventMessage));
    eventMessage->Version = UF_PROTOCOL_VERSION;
    eventMessage->Size = sizeof(*eventMessage);
    eventMessage->ProcessId = FltGetRequestorProcessId(Data);
    eventMessage->DesiredAccess = DesiredAccess;
    eventMessage->Disposition = Disposition;
    eventMessage->Action = Action;
    UfCopyUnicodeToFixed(
        eventMessage->Path, UF_MAX_PATH_CHARS,
        &eventMessage->PathLengthChars, FileName);
    UfCopyUnicodeToFixed(
        eventMessage->Image, UF_MAX_IMAGE_CHARS,
        &eventMessage->ImageLengthChars, ImageName);
    eventMessage->Operation = Operation;
    eventMessage->ProcessCreateTime = ProcessCreateTime;
    if (Evaluation != NULL) {
        eventMessage->FolderRuleId = Evaluation->FolderRuleId;
        eventMessage->ProcessRuleId = Evaluation->ProcessRuleId;
        eventMessage->RequestedAccess = Evaluation->RequestedAccess;
        eventMessage->TrustDecision = Evaluation->TrustDecision;
        eventMessage->PolicyGeneration = Evaluation->PolicyGeneration;
    }

    /* 부팅 영역 알림은 수신 대기자가 없으면 즉시 끝나며 차단 경로를 지연하지 않는다. */
    timeout.QuadPart = (Action == UfEventBootDenied || Action == UfEventBootInspectionFailed)
        ? 0 : -10000LL * 50LL;
    (VOID)FltSendMessage(
        gUfFilter, &gUfClientPort, eventMessage, sizeof(*eventMessage),
        NULL, NULL, &timeout);
    ExFreePoolWithTag(eventMessage, UF_POOL_TAG);
}

static USHORT
UfGetRequestedAccess(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PULONG DesiredAccess,
    _Out_ PULONG Disposition,
    _Out_ UF_IO_OPERATION* Operation)
{
    ACCESS_MASK desired = 0;
    USHORT access = PF_ACCESS_NONE;

    *DesiredAccess = 0;
    *Disposition = 0;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        *Operation = UfIoOperationCreate;
        if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
            desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        }
        *DesiredAccess = desired;
        *Disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
        if (FlagOn(desired,
                FILE_READ_DATA | FILE_LIST_DIRECTORY | FILE_READ_EA |
                FILE_READ_ATTRIBUTES | READ_CONTROL)) {
            access |= PF_ACCESS_READ;
        }
        if (FlagOn(desired,
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_ADD_FILE |
                FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                DELETE | WRITE_DAC | WRITE_OWNER) ||
            *Disposition == FILE_SUPERSEDE ||
            *Disposition == FILE_CREATE ||
            *Disposition == FILE_OPEN_IF ||
            *Disposition == FILE_OVERWRITE ||
            *Disposition == FILE_OVERWRITE_IF) {
            access |= PF_ACCESS_WRITE;
        }
        break;
    case IRP_MJ_READ:
        *Operation = UfIoOperationRead;
        access = PF_ACCESS_READ;
        break;
    case IRP_MJ_WRITE:
        *Operation = UfIoOperationWrite;
        access = PF_ACCESS_WRITE;
        break;
    case IRP_MJ_SET_INFORMATION:
        *Operation = UfIoOperationSetInformation;
        access = PF_ACCESS_WRITE;
        break;
    case IRP_MJ_SET_SECURITY:
        *Operation = UfIoOperationSetSecurity;
        access = PF_ACCESS_WRITE;
        break;
    case IRP_MJ_QUERY_INFORMATION:
        *Operation = UfIoOperationQueryInformation;
        access = PF_ACCESS_READ;
        break;
    case IRP_MJ_QUERY_SECURITY:
        *Operation = UfIoOperationQuerySecurity;
        access = PF_ACCESS_READ;
        break;
    case IRP_MJ_DIRECTORY_CONTROL:
        *Operation = UfIoOperationDirectoryControl;
        access = PF_ACCESS_READ;
        break;
    default:
        *Operation = UfIoOperationCreate;
        break;
    }
    return access;
}

static FLT_PREOP_CALLBACK_STATUS
UfPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PEPROCESS process;
    PUNICODE_STRING processImage = NULL;
    UNICODE_STRING emptyImage = RTL_CONSTANT_STRING(L"");
    PCUNICODE_STRING imageName = &emptyImage;
    UF_POLICY_EVALUATION evaluation;
    UF_IO_OPERATION operation;
    ULONG desiredAccess;
    ULONG disposition;
    ULONG processId;
    ULONGLONG processCreateTime = 0;
    USHORT requestedAccess;

    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode ||
        (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
         FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) ||
        Data->Iopb->TargetFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 볼륨 쓰기는 일반 파일 이름 조회보다 먼저 검사한다. 일반 파일의 선두는 대상이 아니다. */
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && UfBootIsRawWriteTarget(Data)) {
        return UfBootPreWrite(Data, FltObjects);
    }

    requestedAccess = UfGetRequestedAccess(
        Data, &desiredAccess, &disposition, &operation);
    if (requestedAccess == PF_ACCESS_NONE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    process = FltGetRequestorProcess(Data);
    if (process != NULL &&
        NT_SUCCESS(SeLocateProcessImageName(process, &processImage))) {
        imageName = processImage;
        processCreateTime = (ULONGLONG)PsGetProcessCreateTimeQuadPart(process);
    }
    processId = FltGetRequestorProcessId(Data);

    UfPolicyEvaluate(
        &nameInfo->Name, imageName, processId, processCreateTime,
        requestedAccess, &evaluation);
    if (evaluation.Matched) {
        if (evaluation.MonitorOnly) {
            UfSendEvent(
                Data, &nameInfo->Name, imageName, UfEventObserved,
                operation, desiredAccess, disposition, processCreateTime,
                &evaluation);
        } else if (evaluation.TrustDecision != UfTrustAllow) {
            if (evaluation.NeedsTrustValidation && evaluation.ShouldNotifyTrust) {
                UfSendEvent(
                    Data, &nameInfo->Name, imageName, UfEventTrustRequired,
                    operation, desiredAccess, disposition, processCreateTime,
                    &evaluation);
            } else {
                UfSendEvent(
                    Data, &nameInfo->Name, imageName, UfEventDenied,
                    operation, desiredAccess, disposition, processCreateTime,
                    &evaluation);
            }
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            if (processImage != NULL) {
                ExFreePool(processImage);
            }
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        } else {
            UfSendEvent(
                Data, &nameInfo->Name, imageName, UfEventObserved,
                operation, desiredAccess, disposition, processCreateTime,
                &evaluation);
        }
    }

    if (processImage != NULL) {
        ExFreePool(processImage);
    }
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS
UfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
UfPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    *ConnectionCookie = NULL;

    if (InterlockedCompareExchangePointer(
            (PVOID volatile*)&gUfClientPort, ClientPort, NULL) != NULL) {
        return STATUS_DEVICE_BUSY;
    }
    UfBootSetController(PsGetCurrentProcess());
    return STATUS_SUCCESS;
}

static VOID
UfPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UfBootSetController(NULL);
    FltCloseClientPort(gUfFilter, &gUfClientPort);
}

static NTSTATUS
UfPortMessageUnsafe(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UF_MESSAGE_HEADER capturedHeader;
    const UF_MESSAGE_HEADER* header = &capturedHeader;
    UNREFERENCED_PARAMETER(PortCookie);
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(UF_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(&capturedHeader, InputBuffer, sizeof(capturedHeader));
    if (header->Version != UF_PROTOCOL_VERSION ||
        header->Size > InputBufferLength ||
        header->Size < sizeof(*header)) {
        return STATUS_REVISION_MISMATCH;
    }

    switch ((UF_COMMAND)header->Command) {
    case UfCommandReplacePolicy:
        if (header->Size != sizeof(UF_REPLACE_POLICY_V2)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        return UfPolicyReplace((const UF_REPLACE_POLICY_V2*)InputBuffer);

    case UfCommandClearPolicy:
        UfPolicyClear();
        return STATUS_SUCCESS;

    case UfCommandQueryState:
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(UF_STATE_REPLY_V2)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        UfPolicyQuery((UF_STATE_REPLY_V2*)OutputBuffer);
        *ReturnOutputBufferLength = sizeof(UF_STATE_REPLY_V2);
        return STATUS_SUCCESS;

    case UfCommandSetProcessTrust:
        if (header->Size != sizeof(UF_PROCESS_TRUST_UPDATE)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        return UfPolicySetProcessTrust((const UF_PROCESS_TRUST_UPDATE*)InputBuffer);

    case UfCommandSetBootProtection:
    {
        UF_SET_BOOT_PROTECTION request;
        if (InputBufferLength != sizeof(request) || header->Size != sizeof(request) ||
            OutputBufferLength != 0) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        /* 사용자 버퍼는 한 번 복사한 값만 검사하고 사용한다. */
        RtlCopyMemory(&request, InputBuffer, sizeof(request));
        if (request.Header.Version != UF_PROTOCOL_VERSION) {
            return STATUS_REVISION_MISMATCH;
        }
        if (request.Header.Command != UfCommandSetBootProtection ||
            request.Header.Size != sizeof(request) || request.Header.Reserved != 0 ||
            request.Enabled > 1 || request.Reserved != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        UfBootSetEnabled(request.Enabled != 0);
        return STATUS_SUCCESS;
    }

    case UfCommandQueryBootProtection:
    {
        UF_BOOT_PROTECTION_STATE state;
        if (InputBufferLength != sizeof(*header) || header->Size != sizeof(*header)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if (header->Reserved != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(state)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (OutputBufferLength != sizeof(state)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        UfBootQuery(&state);
        RtlCopyMemory(OutputBuffer, &state, sizeof(state));
        *ReturnOutputBufferLength = sizeof(state);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS
UfPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    /* 필터 포트 버퍼의 접근 예외를 커널 경계에서 처리한다. */
    __try {
        return UfPortMessageUnsafe(PortCookie, InputBuffer, InputBufferLength,
            OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *ReturnOutputBufferLength = 0;
        return GetExceptionCode();
    }
}

static NTSTATUS
UfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gUfServerPort != NULL) {
        FltCloseCommunicationPort(gUfServerPort);
        gUfServerPort = NULL;
    }
    if (gUfClientPort != NULL) {
        FltCloseClientPort(gUfFilter, &gUfClientPort);
    }
    UfBootShutdown();
    FltUnregisterFilter(gUfFilter);
    gUfFilter = NULL;
    UfPolicyClear();
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(UF_FILTER_PORT_NAME);
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;

    UNREFERENCED_PARAMETER(RegistryPath);
    UfPolicyInitialize();
    UfBootInitialize();

    status = FltRegisterFilter(DriverObject, &gRegistration, &gUfFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gUfFilter);
        gUfFilter = NULL;
        return status;
    }

    InitializeObjectAttributes(
        &objectAttributes, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, securityDescriptor);
    status = FltCreateCommunicationPort(
        gUfFilter, &gUfServerPort, &objectAttributes, NULL,
        UfPortConnect, UfPortDisconnect, UfPortMessage, 1);
    FltFreeSecurityDescriptor(securityDescriptor);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gUfFilter);
        gUfFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gUfFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gUfServerPort);
        gUfServerPort = NULL;
        if (gUfClientPort != NULL) {
            FltCloseClientPort(gUfFilter, &gUfClientPort);
        }
        UfBootShutdown();
        FltUnregisterFilter(gUfFilter);
        gUfFilter = NULL;
    }
    return status;
}
