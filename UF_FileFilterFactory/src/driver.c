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
static FLT_PREOP_CALLBACK_STATUS UfPreCreate(
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
    { IRP_MJ_CREATE, 0, UfPreCreate, NULL },
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

static VOID
UfSendEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _In_ UF_EVENT_ACTION Action)
{
    UF_FILE_EVENT* eventMessage;
    LARGE_INTEGER timeout;
    PFLT_PORT clientPort;

    clientPort = gUfClientPort;
    if (clientPort == NULL) {
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
    eventMessage->DesiredAccess =
        Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    eventMessage->Disposition =
        (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
    eventMessage->Action = Action;
    UfCopyUnicodeToFixed(
        eventMessage->Path, UF_MAX_PATH_CHARS,
        &eventMessage->PathLengthChars, FileName);
    UfCopyUnicodeToFixed(
        eventMessage->Image, UF_MAX_IMAGE_CHARS,
        &eventMessage->ImageLengthChars, ImageName);

    timeout.QuadPart = -10000LL * 50LL;
    (VOID)FltSendMessage(
        gUfFilter, &clientPort, eventMessage, sizeof(*eventMessage),
        NULL, NULL, &timeout);
    ExFreePoolWithTag(eventMessage, UF_POOL_TAG);
}

static FLT_PREOP_CALLBACK_STATUS
UfPreCreate(
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
    UF_RULE_MODE mode;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        Data->Iopb->TargetFileObject == NULL) {
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
    }

    if (UfPolicyEvaluate(&nameInfo->Name, imageName, &mode)) {
        if (mode == UfRuleAllowList) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            UfSendEvent(Data, &nameInfo->Name, imageName, UfEventDenied);
            if (processImage != NULL) {
                ExFreePool(processImage);
            }
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
        UfSendEvent(Data, &nameInfo->Name, imageName, UfEventObserved);
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
    return STATUS_SUCCESS;
}

static VOID
UfPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gUfFilter, &gUfClientPort);
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
    const UF_MESSAGE_HEADER* header;
    UNREFERENCED_PARAMETER(PortCookie);
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(UF_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }
    header = (const UF_MESSAGE_HEADER*)InputBuffer;
    if (header->Version != UF_PROTOCOL_VERSION ||
        header->Size > InputBufferLength ||
        header->Size < sizeof(*header)) {
        return STATUS_REVISION_MISMATCH;
    }

    switch ((UF_COMMAND)header->Command) {
    case UfCommandReplacePolicy:
        if (header->Size != sizeof(UF_REPLACE_POLICY)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        return UfPolicyReplace((const UF_REPLACE_POLICY*)InputBuffer);

    case UfCommandClearPolicy:
        UfPolicyClear();
        return STATUS_SUCCESS;

    case UfCommandQueryState:
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(UF_STATE_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        UfPolicyQuery((UF_STATE_REPLY*)OutputBuffer);
        *ReturnOutputBufferLength = sizeof(UF_STATE_REPLY);
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
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
        FltUnregisterFilter(gUfFilter);
        gUfFilter = NULL;
    }
    return status;
}
