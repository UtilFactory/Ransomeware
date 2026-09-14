#include "driver.h"
#include "boot_guard_logic.h"

#define UF_BOOT_MAX_WRITE_BYTES (1024UL * 1024UL)
#define UF_BOOT_MAX_PENDING 16
#define UF_BOOT_TAG 'BtFU'

typedef struct _UF_BOOT_WRITE_CONTEXT {
    LONG References;
    PFLT_INSTANCE Instance;
    PFLT_VOLUME Volume;
    PEPROCESS Process;
    PVOID WriteCopy;
    PMDL WriteMdl;
    ULONG CompareLength;
} UF_BOOT_WRITE_CONTEXT;

static volatile LONG gUfBootEnabled;
static volatile LONG gUfBootPending;
static volatile LONG64 gUfBootInspected;
static volatile LONG64 gUfBootBlocked;
static volatile LONG64 gUfBootFailures;
static EX_RUNDOWN_REF gUfBootRundown;
static KSPIN_LOCK gUfBootControllerLock;
static PEPROCESS gUfBootController;

VOID
UfBootInitialize(VOID)
{
    gUfBootEnabled = 0;
    gUfBootPending = 0;
    gUfBootInspected = 0;
    gUfBootBlocked = 0;
    gUfBootFailures = 0;
    gUfBootController = NULL;
    ExInitializeRundownProtection(&gUfBootRundown);
    KeInitializeSpinLock(&gUfBootControllerLock);
}

VOID
UfBootSetController(_In_opt_ PEPROCESS Process)
{
    KIRQL oldIrql;
    PEPROCESS previous;
    if (Process != NULL) {
        ObReferenceObject(Process);
    }
    KeAcquireSpinLock(&gUfBootControllerLock, &oldIrql);
    previous = gUfBootController;
    gUfBootController = Process;
    KeReleaseSpinLock(&gUfBootControllerLock, oldIrql);
    if (previous != NULL) {
        ObDereferenceObject(previous);
    }
}

static BOOLEAN
UfBootIsController(_In_opt_ PEPROCESS Process)
{
    KIRQL oldIrql;
    BOOLEAN matches;
    KeAcquireSpinLock(&gUfBootControllerLock, &oldIrql);
    matches = Process != NULL && Process == gUfBootController;
    KeReleaseSpinLock(&gUfBootControllerLock, oldIrql);
    return matches;
}

VOID
UfBootSetEnabled(_In_ BOOLEAN Enabled)
{
    LONG previous = InterlockedExchange(&gUfBootEnabled, Enabled ? 1 : 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[UF][control] stage=boot-enabled-change previous=%ld requested=%lu pending=%ld pid=%lu tid=%lu\n",
        previous, (ULONG)(Enabled != FALSE), InterlockedCompareExchange(&gUfBootPending, 0, 0),
        HandleToULong(PsGetCurrentProcessId()), HandleToULong(PsGetCurrentThreadId()));
}

VOID
UfBootQuery(_Out_ UF_BOOT_PROTECTION_STATE* State)
{
    RtlZeroMemory(State, sizeof(*State));
    State->Version = UF_PROTOCOL_VERSION;
    State->Size = sizeof(*State);
    State->Enabled = (ULONG)InterlockedCompareExchange(&gUfBootEnabled, 0, 0);
    State->ProtectedBytes = UF_BOOT_GUARD_BYTES;
    State->InspectedWrites = (ULONGLONG)InterlockedCompareExchange64(&gUfBootInspected, 0, 0);
    State->BlockedWrites = (ULONGLONG)InterlockedCompareExchange64(&gUfBootBlocked, 0, 0);
    State->InspectionFailures = (ULONGLONG)InterlockedCompareExchange64(&gUfBootFailures, 0, 0);
}

VOID
UfBootShutdown(VOID)
{
    ULONGLONG started = KeQueryInterruptTime();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[UF][control] stage=boot-shutdown-enter pending=%ld\n",
        InterlockedCompareExchange(&gUfBootPending, 0, 0));
    InterlockedExchange(&gUfBootEnabled, 0);
    UfBootSetController(NULL);
    /* 보류 읽기 및 교체 버퍼의 쓰기 완료 전에 모듈 메모리를 해제하지 않는다. */
    ExWaitForRundownProtectionRelease(&gUfBootRundown);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[UF][control] stage=boot-shutdown-exit elapsedMs=%I64u\n",
        (KeQueryInterruptTime() - started) / 10000ULL);
}

static VOID
UfBootReleaseContext(_In_ UF_BOOT_WRITE_CONTEXT* Context)
{
    if (InterlockedDecrement(&Context->References) != 0) {
        return;
    }
    if (Context->WriteMdl != NULL) {
        IoFreeMdl(Context->WriteMdl);
    }
    if (Context->WriteCopy != NULL) {
        FltFreePoolAlignedWithTag(Context->Instance, Context->WriteCopy, UF_BOOT_TAG);
    }
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
    }
    if (Context->Volume != NULL) {
        FltObjectDereference(Context->Volume);
    }
    if (Context->Instance != NULL) {
        FltObjectDereference(Context->Instance);
    }
    ExFreePoolWithTag(Context, UF_BOOT_TAG);
    InterlockedDecrement(&gUfBootPending);
    ExReleaseRundownProtection(&gUfBootRundown);
}

static VOID
UfBootReport(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_VOLUME Volume,
    _In_opt_ PEPROCESS Process,
    _In_opt_ PCUNICODE_STRING DeviceName,
    _In_ UF_EVENT_ACTION Action,
    _In_ NTSTATUS Status)
{
    WCHAR nameBuffer[256];
    UNICODE_STRING volumeName;
    UNICODE_STRING unknownName = RTL_CONSTANT_STRING(L"(raw device identity unavailable)");
    UNICODE_STRING emptyImage = RTL_CONSTANT_STRING(L"");
    PUNICODE_STRING processImage = NULL;
    PCUNICODE_STRING image = &emptyImage;
    PCUNICODE_STRING path = DeviceName;
    ULONGLONG createTime = 0;
    NTSTATUS nameStatus;

    if (Action == UfEventBootInspectionFailed || Action == UfEventBootInspectionDenied) {
        InterlockedIncrement64(&gUfBootFailures);
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[UF] Boot action=%lu status=0x%08lx pid=%lu\n",
        (ULONG)Action, Status, FltGetRequestorProcessId(Data));

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }
    if (path == NULL || path->Length == 0) {
        volumeName.Buffer = nameBuffer;
        volumeName.Length = 0;
        volumeName.MaximumLength = sizeof(nameBuffer);
        nameStatus = Volume != NULL
            ? FltGetVolumeName(Volume, &volumeName, NULL) : STATUS_NOT_FOUND;
        path = NT_SUCCESS(nameStatus) ? &volumeName : &unknownName;
    }
    if (Process != NULL) {
        createTime = (ULONGLONG)PsGetProcessCreateTimeQuadPart(Process);
        /* 이미지 조회 실패가 차단 결정을 뒤집지는 않는다. */
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled() &&
            IoGetTopLevelIrp() == NULL &&
            NT_SUCCESS(SeLocateProcessImageName(Process, &processImage))) {
            image = processImage;
        }
    }
    UfSendEvent(Data, path, image, Action, UfIoOperationWrite,
        0, 0, createTime, NULL);
    if (processImage != NULL) {
        ExFreePool(processImage);
    }
}

static VOID
UfBootTraceWrite(_In_ PFLT_CALLBACK_DATA Data, _In_ PCSTR Stage, _In_ NTSTATUS Status)
{
    /* 바이트 내용이나 커널 주소 없이 검사 분기와 원래 실패 코드를 남긴다. */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[UF][boot] revision=20260915.1 stage=%s status=0x%08lx pid=%lu tid=%lu mode=%lu irql=%lu flags=0x%08lx offset=%I64d length=%lu\n",
        Stage, Status, FltGetRequestorProcessId(Data), HandleToULong(PsGetCurrentThreadId()),
        (ULONG)Data->RequestorMode, (ULONG)KeGetCurrentIrql(), Data->Iopb->IrpFlags,
        Data->Iopb->Parameters.Write.ByteOffset.QuadPart, Data->Iopb->Parameters.Write.Length);
}

static FLT_PREOP_CALLBACK_STATUS
UfBootDenyInspection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_VOLUME Volume,
    _In_opt_ PEPROCESS Process,
    _In_opt_ PCUNICODE_STRING DeviceName,
    _In_ NTSTATUS FailureStatus,
    _In_ PCSTR Stage)
{
    UfBootTraceWrite(Data, Stage, FailureStatus);
    /* 이미 확인한 원시 선두 쓰기만 호출한다. 정지는 진행 중 검사에도 적용한다. */
    if (InterlockedCompareExchange(&gUfBootEnabled, 0, 0) == 0 || UfBootIsController(Process)) {
        UfBootTraceWrite(Data, "inspection-cancelled", STATUS_SUCCESS);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&gUfBootBlocked);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    UfBootReport(Data, Volume, Process, DeviceName, UfEventBootInspectionDenied, FailureStatus);
    return FLT_PREOP_COMPLETE;
}

BOOLEAN
UfBootIsRawWriteTarget(_In_ PFLT_CALLBACK_DATA Data)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN raw = FALSE;
    NTSTATUS status;
    if (fileObject == NULL) {
        return FALSE;
    }
    if (FlagOn(fileObject->Flags, FO_VOLUME_OPEN)) {
        return TRUE;
    }
    if (fileObject->FileName.Length != 0 || fileObject->RelatedFileObject != NULL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(status)) {
        raw = (BOOLEAN)UfBootIsDeviceIdentity(nameInfo->Name.Buffer,
            nameInfo->Name.Length / sizeof(WCHAR));
        FltReleaseFileNameInformation(nameInfo);
    }
    /* 파일 ID로 연 일반 파일의 빈 FileName은 기존 폴더 정책 경로로 돌려보낸다. */
    return raw;
}

static NTSTATUS
UfBootValidateTarget(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ UF_BOOT_WRITE_CONTEXT* Context,
    _Out_ PULONG ReadLength,
    _Outptr_result_maybenull_ PFLT_FILE_NAME_INFORMATION* NameInfo)
{
    FLT_VOLUME_PROPERTIES properties;
    ULONG returned;
    NTSTATUS status;
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    BOOLEAN volumeOpen = BooleanFlagOn(fileObject->Flags, FO_VOLUME_OPEN);
    BOOLEAN emptyName = fileObject->FileName.Length == 0;
    BOOLEAN deviceVerified;

    *NameInfo = NULL;
    RtlZeroMemory(&properties, sizeof(properties));
    status = FltGetVolumeProperties(Context->Volume, &properties, sizeof(properties), &returned);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }
    deviceVerified = properties.DeviceType == FILE_DEVICE_DISK ||
        properties.DeviceType == FILE_DEVICE_VIRTUAL_DISK ||
        properties.DeviceType == FILE_DEVICE_MASS_STORAGE;
    if (!deviceVerified) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* FO_VOLUME_OPEN은 공식 볼륨 열기 표식이다. 빈 이름만으로는 일반 파일을 분류하지 않는다. */
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, NameInfo);
    if (!volumeOpen) {
        deviceVerified = NT_SUCCESS(status) && emptyName &&
            fileObject->RelatedFileObject == NULL &&
            UfBootIsDeviceIdentity((*NameInfo)->Name.Buffer,
                (*NameInfo)->Name.Length / sizeof(WCHAR));
    }
    if (!UfBootIsRawTarget(volumeOpen, emptyName, deviceVerified)) {
        return NT_SUCCESS(status) ? STATUS_OBJECT_TYPE_MISMATCH : status;
    }
    *ReadLength = UfBootAlignedReadLength(properties.SectorSize);
    return *ReadLength == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

static NTSTATUS
UfBootReadExistingPrefix(
    _In_ UF_BOOT_WRITE_CONTEXT* Context,
    _In_opt_ PCUNICODE_STRING DeviceName,
    _In_ ULONG ReadLength,
    _Out_writes_bytes_(ReadLength) PVOID ReadBuffer,
    _Out_ PULONG BytesRead)
{
    WCHAR nameBuffer[256];
    UNICODE_STRING openName;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE readHandle = NULL;
    PFILE_OBJECT readFileObject = NULL;
    PFLT_VOLUME readVolume = NULL;
    LARGE_INTEGER offset;
    NTSTATUS status;

    if (DeviceName != NULL && UfBootIsDeviceIdentity(DeviceName->Buffer,
        DeviceName->Length / sizeof(WCHAR))) {
        openName = *DeviceName;
    } else {
        openName.Buffer = nameBuffer;
        openName.Length = 0;
        openName.MaximumLength = sizeof(nameBuffer);
        status = FltGetVolumeName(Context->Volume, &openName, NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    InitializeObjectAttributes(&attributes, &openName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, NULL, NULL);
    /* 원본처럼 별도 읽기 핸들을 소유하여 요청자 핸들의 CLEANUP과 경쟁하지 않는다. */
    status = FltCreateFileEx2(gUfFilter, Context->Instance, &readHandle, &readFileObject,
        FILE_READ_DATA | SYNCHRONIZE, &attributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | FILE_OPEN_REPARSE_POINT,
        NULL, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = FltGetVolumeFromFileObject(gUfFilter, readFileObject, &readVolume);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    /* 재열기 이름이 다른 장치나 일반 파일로 바뀌면 비교하지 않고 실패를 기록한다. */
    if (readVolume != Context->Volume ||
        (!FlagOn(readFileObject->Flags, FO_VOLUME_OPEN) &&
         (readFileObject->FileName.Length != 0 || readFileObject->RelatedFileObject != NULL))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto Cleanup;
    }
    offset.QuadPart = 0;
    status = FltReadFile(Context->Instance, readFileObject, &offset, ReadLength, ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        BytesRead, NULL, NULL);
Cleanup:
    if (readVolume != NULL) {
        FltObjectDereference(readVolume);
    }
    FltClose(readHandle);
    ObDereferenceObject(readFileObject);
    return status;
}

static VOID
UfBootInspectWorker(
    _In_ PFLT_DEFERRED_IO_WORKITEM WorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PVOID WorkContext)
{
    UF_BOOT_WRITE_CONTEXT* context = WorkContext;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PCUNICODE_STRING deviceName = NULL;
    PVOID source;
    PVOID readBuffer = NULL;
    ULONG readLength = 0;
    ULONG bytesRead = 0;
    ULONG writeAllocationLength;
    PMDL sourceMdl;
    NTSTATUS status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS completion = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PVOID postContext = NULL;
    PCSTR failureStage = "worker-context";
    int differs;

    FltFreeDeferredIoWorkItem(WorkItem);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedCompareExchange(&gUfBootEnabled, 0, 0) == 0) {
        goto Complete;
    }
    if (KeAreAllApcsDisabled() || IoGetTopLevelIrp() != NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Failed;
    }
    failureStage = "target-validation";
    status = UfBootValidateTarget(Data, context, &readLength, &nameInfo);
    if (nameInfo != NULL) {
        deviceName = &nameInfo->Name;
    }
    if (!NT_SUCCESS(status)) {
        goto Failed;
    }

    /* FltLockUserBuffer의 MDL은 FltMgr 소유이며 여기서는 해제하지 않는다. */
    failureStage = "source-mdl";
    sourceMdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (sourceMdl == NULL || MmGetMdlByteCount(sourceMdl) < Data->Iopb->Parameters.Write.Length) {
        status = STATUS_INVALID_USER_BUFFER;
        goto Failed;
    }
    source = MmGetSystemAddressForMdlSafe(sourceMdl, NormalPagePriority | MdlMappingNoExecute);
    if (source == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failed;
    }
    /* 하위 파일시스템의 섹터 반올림 접근까지 할당하되 요청 길이는 변경하지 않는다.
       readLength는 검증된 섹터 크기의 배수이자 2의 거듭제곱이다. */
    writeAllocationLength = (Data->Iopb->Parameters.Write.Length + readLength - 1) & ~(readLength - 1);
    failureStage = "snapshot-allocation";
    context->WriteCopy = FltAllocatePoolAlignedWithTag(context->Instance,
        NonPagedPoolNx, writeAllocationLength, UF_BOOT_TAG);
    if (context->WriteCopy == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failed;
    }
    RtlZeroMemory(context->WriteCopy, writeAllocationLength);
    failureStage = "snapshot-copy";
    __try {
        RtlCopyMemory(context->WriteCopy, source, Data->Iopb->Parameters.Write.Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        goto Failed;
    }
    failureStage = "snapshot-mdl";
    context->WriteMdl = IoAllocateMdl(context->WriteCopy,
        writeAllocationLength, FALSE, FALSE, NULL);
    if (context->WriteMdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failed;
    }
    MmBuildMdlForNonPagedPool(context->WriteMdl);

    failureStage = "read-buffer-allocation";
    readBuffer = FltAllocatePoolAlignedWithTag(context->Instance,
        NonPagedPoolNx, readLength, UF_BOOT_TAG);
    if (readBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failed;
    }
    /* 아래쪽 필터로만 읽고 최대 16개 작업자의 완료까지 메모리와 rundown을 유지한다. */
    failureStage = "prefix-reopen-read";
    status = UfBootReadExistingPrefix(context, deviceName, readLength, readBuffer, &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead <
        (ULONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart + context->CompareLength) {
        if (NT_SUCCESS(status)) {
            status = STATUS_DEVICE_DATA_ERROR;
        }
        goto Failed;
    }
    failureStage = "prefix-compare";
    differs = UfBootPrefixDiffers(
        (const unsigned char*)readBuffer + (ULONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
        context->WriteCopy, context->CompareLength);
    if (differs < 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Failed;
    }
    /* 읽기 중 정지한 요청에는 새 차단을 적용하지 않는다. 제품 전용 신뢰 목록은 이관하지 않는다. */
    if (InterlockedCompareExchange(&gUfBootEnabled, 0, 0) == 0 ||
        UfBootIsController(context->Process)) {
        goto Complete;
    }
    if (differs != 0) {
        UfBootTraceWrite(Data, "changed-prefix-denied", STATUS_ACCESS_DENIED);
        InterlockedIncrement64(&gUfBootBlocked);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        completion = FLT_PREOP_COMPLETE;
        UfBootReport(Data, context->Volume, context->Process,
            deviceName, UfEventBootDenied, STATUS_ACCESS_DENIED);
        goto Complete;
    }

    /* 비교 뒤 사용자가 원래 버퍼를 바꿔도 통과한 스냅숏만 실제 쓰기에 사용한다.
       교체 MDL은 FltMgr가 해제하고, 교체 버퍼는 쓰기 사후 콜백까지 보존한다. */
    Data->Iopb->Parameters.Write.WriteBuffer = context->WriteCopy;
    Data->Iopb->Parameters.Write.MdlAddress = context->WriteMdl;
    context->WriteMdl = NULL;
    FltSetCallbackDataDirty(Data);
    InterlockedIncrement(&context->References);
    postContext = context;
    completion = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    UfBootTraceWrite(Data, "identical-prefix-snapshot-allowed", STATUS_SUCCESS);
    goto Complete;

Failed:
    completion = UfBootDenyInspection(Data, context->Volume, context->Process,
        deviceName, status, failureStage);
Complete:
    if (readBuffer != NULL) {
        FltFreePoolAlignedWithTag(context->Instance, readBuffer, UF_BOOT_TAG);
    }
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
    FltCompletePendedPreOperation(Data, completion, postContext);
    /* 사후 콜백이 동기적으로 실행되어도 작업자 참조가 남아 있다. */
    UfBootReleaseContext(context);
}

FLT_PREOP_CALLBACK_STATUS
UfBootPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PEPROCESS process = FltGetRequestorProcess(Data);
    UF_BOOT_WRITE_CONTEXT* context;
    PFLT_DEFERRED_IO_WORKITEM workItem;
    ULONG compareLength;
    NTSTATUS status;
    FLT_PREOP_CALLBACK_STATUS failureCompletion;

    if (fileObject == NULL || UfBootIsController(process) ||
        InterlockedCompareExchange(&gUfBootEnabled, 0, 0) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    compareLength = UfBootProtectedWriteLength(
        Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
        Data->Iopb->Parameters.Write.Length);
    if (compareLength == 0 || (!FlagOn(fileObject->Flags, FO_VOLUME_OPEN) &&
        fileObject->FileName.Length != 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* 원본의 커널 페이징 예외만 유지한다. PID나 KernelMode 전체를 신뢰하지 않는다. */
    if (Data->RequestorMode == KernelMode &&
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        UfBootTraceWrite(Data, "kernel-paging-exempt", STATUS_SUCCESS);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_DISALLOW_FASTIO;
    }
    InterlockedIncrement64(&gUfBootInspected);
    UfBootTraceWrite(Data, "inspect-enter", STATUS_SUCCESS);
    if (!FLT_IS_IRP_OPERATION(Data) || KeGetCurrentIrql() > APC_LEVEL ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO) ||
        IoGetTopLevelIrp() != NULL || FltObjects->Instance == NULL || FltObjects->Volume == NULL ||
        Data->Iopb->Parameters.Write.Length > UF_BOOT_MAX_WRITE_BYTES) {
        return UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            STATUS_NOT_SUPPORTED, "request-context-or-size");
    }
    if (!ExAcquireRundownProtection(&gUfBootRundown)) {
        return UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            STATUS_DELETE_PENDING, "rundown-unavailable");
    }
    if (InterlockedIncrement(&gUfBootPending) > UF_BOOT_MAX_PENDING) {
        InterlockedDecrement(&gUfBootPending);
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            STATUS_DEVICE_BUSY, "pending-limit");
        ExReleaseRundownProtection(&gUfBootRundown);
        return failureCompletion;
    }
    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), UF_BOOT_TAG);
    if (context == NULL) {
        InterlockedDecrement(&gUfBootPending);
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            STATUS_INSUFFICIENT_RESOURCES, "context-allocation");
        ExReleaseRundownProtection(&gUfBootRundown);
        return failureCompletion;
    }
    context->References = 1;
    context->CompareLength = compareLength;
    status = FltObjectReference(FltObjects->Instance);
    if (!NT_SUCCESS(status)) {
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            status, "instance-reference");
        UfBootReleaseContext(context);
        return failureCompletion;
    }
    context->Instance = FltObjects->Instance;
    status = FltObjectReference(FltObjects->Volume);
    if (!NT_SUCCESS(status)) {
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            status, "volume-reference");
        UfBootReleaseContext(context);
        return failureCompletion;
    }
    context->Volume = FltObjects->Volume;
    if (process != NULL) {
        ObReferenceObject(process);
        context->Process = process;
    }
    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status)) {
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            status, "lock-write-buffer");
        UfBootReleaseContext(context);
        return failureCompletion;
    }
    workItem = FltAllocateDeferredIoWorkItem();
    if (workItem == NULL) {
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            STATUS_INSUFFICIENT_RESOURCES, "work-item-allocation");
        UfBootReleaseContext(context);
        return failureCompletion;
    }
    status = FltQueueDeferredIoWorkItem(workItem, Data,
        UfBootInspectWorker, DelayedWorkQueue, context);
    if (!NT_SUCCESS(status)) {
        FltFreeDeferredIoWorkItem(workItem);
        failureCompletion = UfBootDenyInspection(Data, FltObjects->Volume, process, NULL,
            status, "queue-work-item");
        UfBootReleaseContext(context);
        return failureCompletion;
    }
    return FLT_PREOP_PENDING;
}

FLT_POSTOP_CALLBACK_STATUS
UfBootPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    if (CompletionContext != NULL) {
        UfBootReleaseContext(CompletionContext);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}
