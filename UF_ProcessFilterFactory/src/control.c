#include "driver.h"

#define UF_PROC_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

static const GUID gUfProcessDeviceClassGuid =
    { 0xed5e7c89, 0x7765, 0x4b25, { 0xa4, 0xcd, 0x62, 0xb7, 0xfd, 0xcc, 0x8b, 0x61 } };

static NTSTATUS UfDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

C_ASSERT(sizeof(UF_PROC_POLICY_RULE) == 1056);
C_ASSERT(sizeof(UF_PROC_REPLACE_POLICY) == 33808);
C_ASSERT(sizeof(UF_PROC_STATE_REPLY) == 40);
C_ASSERT(sizeof(UF_PROC_EVENT) == 600);
C_ASSERT(sizeof(UF_PROC_EVENT_BATCH) == 19224);

static NTSTATUS
UfCompleteIrp(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static VOID
UfResetEventQueue(
    VOID
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&gUfProcessDriverContext.EventLock, &oldIrql);
    gUfProcessDriverContext.EventHead = 0;
    gUfProcessDriverContext.EventTail = 0;
    gUfProcessDriverContext.EventCount = 0;
    KeReleaseSpinLock(&gUfProcessDriverContext.EventLock, oldIrql);
}

static PCWCHAR
UfFindImageNameComponent(
    _In_reads_(LengthChars) PCWCHAR Image,
    _In_ ULONG LengthChars,
    _Out_ PULONG NameLengthChars
    )
{
    ULONG index;
    ULONG start = 0;

    for (index = 0; index < LengthChars; ++index) {
        if (Image[index] == L'\\' || Image[index] == L'/') {
            start = index + 1;
        }
    }

    *NameLengthChars = LengthChars - start;
    return Image + start;
}

static BOOLEAN
UfEqualTextInsensitive(
    _In_reads_(LeftLengthChars) PCWCHAR Left,
    _In_ ULONG LeftLengthChars,
    _In_reads_(RightLengthChars) PCWCHAR Right,
    _In_ ULONG RightLengthChars
    )
{
    UNICODE_STRING leftString;
    UNICODE_STRING rightString;

    if (LeftLengthChars != RightLengthChars ||
        LeftLengthChars > (MAXUSHORT / sizeof(WCHAR))) {
        return FALSE;
    }

    leftString.Buffer = (PWCH)Left;
    leftString.Length = (USHORT)(LeftLengthChars * sizeof(WCHAR));
    leftString.MaximumLength = leftString.Length;
    rightString.Buffer = (PWCH)Right;
    rightString.Length = (USHORT)(RightLengthChars * sizeof(WCHAR));
    rightString.MaximumLength = rightString.Length;
    return RtlEqualUnicodeString(&leftString, &rightString, TRUE);
}

static BOOLEAN
UfIsCriticalImageName(
    _In_reads_(LengthChars) PCWCHAR Image,
    _In_ ULONG LengthChars
    )
{
    static const PCWSTR criticalNames[] = {
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"services.exe",
        L"lsass.exe",
        L"winlogon.exe",
        L"system"
    };
    PCWCHAR imageName;
    ULONG imageNameLength;
    ULONG index;

    imageName = UfFindImageNameComponent(Image, LengthChars, &imageNameLength);
    for (index = 0; index < RTL_NUMBER_OF(criticalNames); ++index) {
        ULONG criticalLength = (ULONG)wcslen(criticalNames[index]);

        if (UfEqualTextInsensitive(
                imageName,
                imageNameLength,
                criticalNames[index],
                criticalLength)) {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS
UfValidatePolicy(
    _In_ const UF_PROC_REPLACE_POLICY* Request
    )
{
    ULONG index;
    ULONG compareIndex;

    if (Request->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        Request->Header.Size != sizeof(*Request) ||
        Request->RuleCount > UF_PROC_MAX_RULES ||
        Request->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->RuleCount; ++index) {
        const UF_PROC_POLICY_RULE* rule = &Request->Rules[index];

        if (rule->RuleId == 0 ||
            rule->ImageLengthChars == 0 ||
            rule->ImageLengthChars >= UF_PROC_MAX_IMAGE_CHARS ||
            (rule->MatchMode != UfProcMatchFullPath &&
             rule->MatchMode != UfProcMatchImageName)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (rule->MatchMode == UfProcMatchImageName) {
            if (rule->DeviceImageLengthChars != 0 ||
                UfFindImageNameComponent(
                    rule->Image,
                    rule->ImageLengthChars,
                    &compareIndex) != rule->Image) {
                return STATUS_INVALID_PARAMETER;
            }
        } else if (rule->DeviceImageLengthChars >= UF_PROC_MAX_IMAGE_CHARS) {
            return STATUS_INVALID_PARAMETER;
        }

        if (UfIsCriticalImageName(rule->Image, rule->ImageLengthChars)) {
            return STATUS_ACCESS_DENIED;
        }

        for (compareIndex = 0; compareIndex < index; ++compareIndex) {
            if (Request->Rules[compareIndex].RuleId == rule->RuleId) {
                return STATUS_DUPLICATE_OBJECTID;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
UfReplacePolicy(
    _In_ const UF_PROC_REPLACE_POLICY* Request
    )
{
    PUF_PROC_POLICY newPolicy;
    PUF_PROC_POLICY oldPolicy;
    NTSTATUS status;

    status = UfValidatePolicy(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    newPolicy = (PUF_PROC_POLICY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(UF_PROC_POLICY),
        UF_PROC_POOL_TAG);
    if (newPolicy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newPolicy, sizeof(*newPolicy));
    newPolicy->RuleCount = Request->RuleCount;
    if (Request->RuleCount != 0) {
        RtlCopyMemory(
            newPolicy->Rules,
            Request->Rules,
            sizeof(UF_PROC_POLICY_RULE) * Request->RuleCount);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    oldPolicy = gUfProcessDriverContext.Policy;
    gUfProcessDriverContext.Policy = newPolicy;
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    if (oldPolicy != NULL) {
        ExFreePoolWithTag(oldPolicy, UF_PROC_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
UfClearPolicy(
    _In_reads_bytes_opt_(InputLength) const VOID* Input,
    _In_ ULONG InputLength
    )
{
    const UF_PROC_MESSAGE_HEADER* header;
    PUF_PROC_POLICY oldPolicy;

    if (Input == NULL || InputLength != sizeof(UF_PROC_MESSAGE_HEADER)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    header = (const UF_PROC_MESSAGE_HEADER*)Input;
    if (header->Version != UF_PROC_PROTOCOL_VERSION ||
        header->Size != sizeof(*header)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    oldPolicy = gUfProcessDriverContext.Policy;
    gUfProcessDriverContext.Policy = NULL;
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    if (oldPolicy != NULL) {
        ExFreePoolWithTag(oldPolicy, UF_PROC_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
UfQueryState(
    _Out_writes_bytes_(OutputLength) VOID* Output,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PUF_PROC_STATE_REPLY reply;
    KIRQL oldIrql;

    if (Output == NULL || OutputLength < sizeof(UF_PROC_STATE_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    reply = (PUF_PROC_STATE_REPLY)Output;
    RtlZeroMemory(reply, sizeof(*reply));
    reply->Header.Version = UF_PROC_PROTOCOL_VERSION;
    reply->Header.Size = sizeof(*reply);
    reply->PolicyGeneration = (ULONGLONG)InterlockedCompareExchange64(
        &gUfProcessDriverContext.PolicyGeneration,
        0,
        0);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gUfProcessDriverContext.PolicyLock);
    if (gUfProcessDriverContext.Policy != NULL) {
        reply->RuleCount = gUfProcessDriverContext.Policy->RuleCount;
    }
    ExReleasePushLockShared(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    KeAcquireSpinLock(&gUfProcessDriverContext.EventLock, &oldIrql);
    reply->QueueDepth = gUfProcessDriverContext.EventCount;
    KeReleaseSpinLock(&gUfProcessDriverContext.EventLock, oldIrql);

    reply->DroppedEvents = (ULONGLONG)InterlockedCompareExchange64(
        &gUfProcessDriverContext.DroppedEvents,
        0,
        0);
    reply->Connected = InterlockedCompareExchange(
        &gUfProcessDriverContext.ClientConnected,
        0,
        0) != 0;
    *Information = sizeof(*reply);
    return STATUS_SUCCESS;
}

static NTSTATUS
UfDequeueEvents(
    _Out_writes_bytes_(OutputLength) VOID* Output,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PUF_PROC_EVENT_BATCH batch;
    ULONG maximumEvents;
    KIRQL oldIrql;

    if (Output == NULL ||
        OutputLength < (ULONG)FIELD_OFFSET(UF_PROC_EVENT_BATCH, Events)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maximumEvents = (OutputLength - FIELD_OFFSET(UF_PROC_EVENT_BATCH, Events)) /
        sizeof(UF_PROC_EVENT);
    if (maximumEvents > UF_PROC_MAX_EVENT_BATCH) {
        maximumEvents = UF_PROC_MAX_EVENT_BATCH;
    }

    batch = (PUF_PROC_EVENT_BATCH)Output;
    RtlZeroMemory(batch, FIELD_OFFSET(UF_PROC_EVENT_BATCH, Events));
    batch->Header.Version = UF_PROC_PROTOCOL_VERSION;
    batch->Header.Size = sizeof(*batch);

    KeAcquireSpinLock(&gUfProcessDriverContext.EventLock, &oldIrql);
    while (batch->EventCount < maximumEvents &&
           gUfProcessDriverContext.EventCount != 0) {
        batch->Events[batch->EventCount] =
            gUfProcessDriverContext.EventQueue[gUfProcessDriverContext.EventHead];
        gUfProcessDriverContext.EventHead =
            (gUfProcessDriverContext.EventHead + 1) % UF_PROC_EVENT_QUEUE_CAPACITY;
        --gUfProcessDriverContext.EventCount;
        ++batch->EventCount;
    }
    KeReleaseSpinLock(&gUfProcessDriverContext.EventLock, oldIrql);

    batch->DroppedEvents = (ULONGLONG)InterlockedCompareExchange64(
        &gUfProcessDriverContext.DroppedEvents,
        0,
        0);
    *Information = FIELD_OFFSET(UF_PROC_EVENT_BATCH, Events) +
        (sizeof(UF_PROC_EVENT) * batch->EventCount);
    return STATUS_SUCCESS;
}

static NTSTATUS
UfDispatchUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return UfCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS
UfDispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);

    if (InterlockedCompareExchange(
            &gUfProcessDriverContext.ClientConnected,
            1,
            0) != 0) {
        return UfCompleteIrp(Irp, STATUS_SHARING_VIOLATION, 0);
    }

    stack->FileObject->FsContext = (PVOID)(ULONG_PTR)1;
    UfResetEventQueue();
    return UfCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
UfDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->FileObject->FsContext != NULL) {
        stack->FileObject->FsContext = NULL;
        InterlockedExchange(&gUfProcessDriverContext.ClientConnected, 0);
        UfResetEventQueue();
    }

    return UfCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
UfDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG controlCode;
    ULONG_PTR information = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case UF_PROC_IOCTL_REPLACE_POLICY:
        if (buffer == NULL || inputLength != sizeof(UF_PROC_REPLACE_POLICY)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            status = UfReplacePolicy((const UF_PROC_REPLACE_POLICY*)buffer);
        }
        break;

    case UF_PROC_IOCTL_CLEAR_POLICY:
        status = UfClearPolicy(buffer, inputLength);
        break;

    case UF_PROC_IOCTL_QUERY_STATE:
        status = UfQueryState(buffer, outputLength, &information);
        break;

    case UF_PROC_IOCTL_DEQUEUE_EVENTS:
        status = UfDequeueEvents(buffer, outputLength, &information);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return UfCompleteIrp(Irp, status, information);
}

NTSTATUS
UfCreateControlPlane(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(UF_PROC_DEVICE_NT_NAME);
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(UF_PROC_DEVICE_DOS_NAME);
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(UF_PROC_DEVICE_SDDL);
    NTSTATUS status;
    ULONG majorFunction;

    ExInitializePushLock(&gUfProcessDriverContext.PolicyLock);
    KeInitializeSpinLock(&gUfProcessDriverContext.EventLock);

    gUfProcessDriverContext.EventQueue = (PUF_PROC_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(UF_PROC_EVENT) * UF_PROC_EVENT_QUEUE_CAPACITY,
        UF_PROC_POOL_TAG);
    if (gUfProcessDriverContext.EventQueue == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (majorFunction = 0; majorFunction <= IRP_MJ_MAXIMUM_FUNCTION; ++majorFunction) {
        DriverObject->MajorFunction[majorFunction] = UfDispatchUnsupported;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = UfDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UfDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UfDispatchDeviceControl;

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &sddl,
        &gUfProcessDeviceClassGuid,
        &gUfProcessDriverContext.ControlDevice);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(gUfProcessDriverContext.EventQueue, UF_PROC_POOL_TAG);
        gUfProcessDriverContext.EventQueue = NULL;
        return status;
    }

    gUfProcessDriverContext.ControlDevice->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gUfProcessDriverContext.ControlDevice);
        gUfProcessDriverContext.ControlDevice = NULL;
        ExFreePoolWithTag(gUfProcessDriverContext.EventQueue, UF_PROC_POOL_TAG);
        gUfProcessDriverContext.EventQueue = NULL;
        return status;
    }

    gUfProcessDriverContext.SymbolicLinkCreated = TRUE;
    gUfProcessDriverContext.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

VOID
UfDeleteControlPlane(
    VOID
    )
{
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(UF_PROC_DEVICE_DOS_NAME);
    PUF_PROC_POLICY oldPolicy;

    InterlockedExchange(&gUfProcessDriverContext.ClientConnected, 0);

    if (gUfProcessDriverContext.SymbolicLinkCreated != FALSE) {
        IoDeleteSymbolicLink(&symbolicLink);
        gUfProcessDriverContext.SymbolicLinkCreated = FALSE;
    }

    if (gUfProcessDriverContext.ControlDevice != NULL) {
        IoDeleteDevice(gUfProcessDriverContext.ControlDevice);
        gUfProcessDriverContext.ControlDevice = NULL;
    }

    oldPolicy = gUfProcessDriverContext.Policy;
    gUfProcessDriverContext.Policy = NULL;
    if (oldPolicy != NULL) {
        ExFreePoolWithTag(oldPolicy, UF_PROC_POOL_TAG);
    }

    if (gUfProcessDriverContext.EventQueue != NULL) {
        ExFreePoolWithTag(gUfProcessDriverContext.EventQueue, UF_PROC_POOL_TAG);
        gUfProcessDriverContext.EventQueue = NULL;
    }
}

NTSTATUS
UfEvaluateProcessCreation(
    _In_ PEPROCESS Process,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PULONG RuleId
    )
{
    PUF_PROC_POLICY policy;
    PCWCHAR imageName;
    ULONG imageLength;
    ULONG imageNameLength;
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    *RuleId = 0;
    if (CreateInfo->ImageFileName == NULL ||
        CreateInfo->ImageFileName->Buffer == NULL ||
        PsIsProtectedProcess(Process) ||
        PsIsProtectedProcessLight(Process)) {
        return STATUS_SUCCESS;
    }

    imageName = CreateInfo->ImageFileName->Buffer;
    imageLength = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
    if (UfIsCriticalImageName(imageName, imageLength)) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gUfProcessDriverContext.PolicyLock);
    policy = gUfProcessDriverContext.Policy;
    if (policy != NULL) {
        for (index = 0; index < policy->RuleCount; ++index) {
            const UF_PROC_POLICY_RULE* rule = &policy->Rules[index];
            BOOLEAN matched = FALSE;

            if (rule->MatchMode == UfProcMatchImageName) {
                PCWCHAR finalName = UfFindImageNameComponent(
                    imageName,
                    imageLength,
                    &imageNameLength);
                matched = UfEqualTextInsensitive(
                    finalName,
                    imageNameLength,
                    rule->Image,
                    rule->ImageLengthChars);
            } else if (CreateInfo->FileOpenNameAvailable != 0) {
                matched = UfEqualTextInsensitive(
                    imageName,
                    imageLength,
                    rule->Image,
                    rule->ImageLengthChars);
                if (!matched && rule->DeviceImageLengthChars != 0) {
                    matched = UfEqualTextInsensitive(
                        imageName,
                        imageLength,
                        rule->DeviceImage,
                        rule->DeviceImageLengthChars);
                }
            }

            if (matched) {
                *RuleId = rule->RuleId;
                status = STATUS_ACCESS_DENIED;
                break;
            }
        }
    }
    ExReleasePushLockShared(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();
    return status;
}

VOID
UfQueueProcessEvent(
    _In_ ULONG Type,
    _In_ ULONG Action,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ HANDLE RequesterProcessId,
    _In_opt_ HANDLE TargetProcessId,
    _In_ ULONG Operation,
    _In_ ACCESS_MASK OriginalDesiredAccess,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG RuleId,
    _In_opt_ PCUNICODE_STRING ImageName
    )
{
    UF_PROC_EVENT event;
    LARGE_INTEGER systemTime;
    ULONG imageLengthChars = 0;
    KIRQL oldIrql;

    if (InterlockedCompareExchange(
            &gUfProcessDriverContext.ClientConnected,
            0,
            0) == 0 ||
        gUfProcessDriverContext.EventQueue == NULL) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.Header.Version = UF_PROC_PROTOCOL_VERSION;
    event.Header.Size = sizeof(event);
    event.Type = Type;
    event.Action = Action;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(
        &gUfProcessDriverContext.EventSequence);
    KeQuerySystemTimePrecise(&systemTime);
    event.SystemTime100ns = (ULONGLONG)systemTime.QuadPart;
    event.PolicyGeneration = (ULONGLONG)InterlockedCompareExchange64(
        &gUfProcessDriverContext.PolicyGeneration,
        0,
        0);
    event.ProcessId = HandleToULong(ProcessId);
    event.ParentProcessId = HandleToULong(ParentProcessId);
    event.RequesterProcessId = HandleToULong(RequesterProcessId);
    event.TargetProcessId = HandleToULong(TargetProcessId);
    event.Operation = Operation;
    event.OriginalDesiredAccess = OriginalDesiredAccess;
    event.DesiredAccess = DesiredAccess;
    event.RuleId = RuleId;

    if (ImageName != NULL && ImageName->Buffer != NULL) {
        imageLengthChars = ImageName->Length / sizeof(WCHAR);
        if (imageLengthChars >= UF_PROC_MAX_IMAGE_CHARS) {
            imageLengthChars = UF_PROC_MAX_IMAGE_CHARS - 1;
        }
        RtlCopyMemory(
            event.Image,
            ImageName->Buffer,
            imageLengthChars * sizeof(WCHAR));
        event.ImageLengthChars = imageLengthChars;
    }

    KeAcquireSpinLock(&gUfProcessDriverContext.EventLock, &oldIrql);
    if (gUfProcessDriverContext.EventCount == UF_PROC_EVENT_QUEUE_CAPACITY) {
        InterlockedIncrement64(&gUfProcessDriverContext.DroppedEvents);
    } else {
        gUfProcessDriverContext.EventQueue[gUfProcessDriverContext.EventTail] = event;
        gUfProcessDriverContext.EventTail =
            (gUfProcessDriverContext.EventTail + 1) % UF_PROC_EVENT_QUEUE_CAPACITY;
        ++gUfProcessDriverContext.EventCount;
    }
    KeReleaseSpinLock(&gUfProcessDriverContext.EventLock, oldIrql);
}
