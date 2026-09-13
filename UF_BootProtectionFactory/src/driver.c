#include <ntifs.h>
#include <wdf.h>
#include <wdmsec.h>
#include <ntdddisk.h>
#include <ntddstor.h>
#include <ntstrsafe.h>
#include <initguid.h>
#include <devpkey.h>
#include "layout.h"

#define UF_TAG 'tBfU'
#define UF_EVENT_SLOTS 256u
#define UF_PROCESS_SLOTS 256u

C_ASSERT(sizeof(UF_BOOT_DEVICE_INFO) == 2000);
C_ASSERT(sizeof(UF_BOOT_DEVICE_LIST) == 64016);
C_ASSERT(sizeof(UF_BOOT_SET_REQUEST) == 32);
C_ASSERT(sizeof(UF_BOOT_EVENT) == 1136);
C_ASSERT(sizeof(UF_BOOT_EVENT_BATCH) == 36376);

typedef struct _UF_DEVICE {
    LIST_ENTRY Link;
    WDFDEVICE Device;
    KMUTEX Operation;
    KSPIN_LOCK Lock;
    KEVENT Drained;
    LONG Inflight;
    BOOLEAN Listed;
    BOOLEAN Ready;
    BOOLEAN Special;
    BOOLEAN Lab;
    UF_BOOT_DEVICE_INFO Info;
} UF_DEVICE;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UF_DEVICE, UfDevice)
typedef struct _UF_PROCESS {
    PEPROCESS Process;
    ULONGLONG Pid;
    ULONGLONG Created;
    ULONG Length;
    ULONG Status;
    WCHAR Path[UF_BOOT_PATH_CHARS];
} UF_PROCESS;
typedef struct _UF_GLOBAL {
    WDFDRIVER Driver;
    WDFDEVICE Control;
    WDFWAITLOCK ControlLock;
    KSPIN_LOCK DevicesLock;
    KSPIN_LOCK EventsLock;
    KSPIN_LOCK ProcessesLock;
    LIST_ENTRY Devices;
    ULONG Count;
    ULONGLONG NextId;
    ULONGLONG Sequence;
    ULONGLONG Dropped;
    ULONG Head;
    ULONG EventCount;
    BOOLEAN NotifyRegistered;
    UF_BOOT_EVENT Events[UF_EVENT_SLOTS];
    UF_PROCESS Processes[UF_PROCESS_SLOTS];
} UF_GLOBAL;
static UF_GLOBAL* g;
static NTSTATUS CreateControl(VOID);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD UfAddDevice;
EVT_WDF_DRIVER_UNLOAD UfUnload;
EVT_WDF_DEVICE_D0_ENTRY UfD0Entry;
EVT_WDF_DEVICE_D0_EXIT UfD0Exit;
EVT_WDF_DEVICE_RELEASE_HARDWARE UfRelease;
EVT_WDF_DEVICE_USAGE_NOTIFICATION_EX UfUsage;
EVT_WDF_OBJECT_CONTEXT_CLEANUP UfCleanup;
EVT_WDF_IO_QUEUE_IO_WRITE UfWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL UfDiskControl;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL UfInternalControl;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL UfControl;
EVT_WDF_REQUEST_COMPLETION_ROUTINE UfForwardDone;

static VOID ProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KIRQL irql;
    ULONG i, slot = UF_PROCESS_SLOTS;
    UF_PROCESS snapshot;
    RtlZeroMemory(&snapshot, sizeof(snapshot));
    if (CreateInfo) {
        snapshot.Process = Process; snapshot.Pid = (ULONGLONG)(ULONG_PTR)ProcessId;
        snapshot.Created = (ULONGLONG)PsGetProcessCreateTimeQuadPart(Process);
        snapshot.Status = (ULONG)STATUS_NOT_FOUND;
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            ULONG chars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            snapshot.Length = min(chars, UF_BOOT_PATH_CHARS - 1);
            RtlCopyMemory(snapshot.Path, CreateInfo->ImageFileName->Buffer, snapshot.Length * sizeof(WCHAR));
            snapshot.Status = (ULONG)(chars >= UF_BOOT_PATH_CHARS ? STATUS_BUFFER_OVERFLOW :
                (CreateInfo->FileOpenNameAvailable ? STATUS_SUCCESS : STATUS_OBJECT_PATH_NOT_FOUND));
        }
    }
    KeAcquireSpinLock(&g->ProcessesLock, &irql);
    for (i = 0; i < UF_PROCESS_SLOTS; ++i) {
        if (g->Processes[i].Process == Process) { slot = i; break; }
        if (!g->Processes[i].Process && slot == UF_PROCESS_SLOTS) slot = i;
    }
    if (slot < UF_PROCESS_SLOTS) {
        UF_PROCESS* p = &g->Processes[slot];
        *p = snapshot;
    }
    KeReleaseSpinLock(&g->ProcessesLock, irql);
}
static VOID Emit(UF_DEVICE* d, WDFREQUEST Request, ULONG kind, ULONGLONG offset, ULONGLONG length, ULONG code, ULONGLONG generation)
{
    UF_BOOT_EVENT event;
    PEPROCESS process;
    KIRQL irql;
    ULONG i;
    LARGE_INTEGER time;
    RtlZeroMemory(&event, sizeof(event));
    event.Version = UF_BOOT_VERSION; event.Size = sizeof(event);
    KeQuerySystemTime(&time); event.Time = (ULONGLONG)time.QuadPart;
    event.DeviceId = d->Info.DeviceId;
    event.PolicyGeneration = generation;
    event.Offset = offset; event.Length = length; event.Kind = kind;
    event.IoctlCode = code; event.Action = UF_BOOT_ACTION_BLOCKED; event.Status = (ULONG)STATUS_ACCESS_DENIED;
    event.PathStatus = (ULONG)STATUS_NOT_FOUND;
    process = IoGetRequestorProcess(WdfRequestWdmGetIrp(Request));
    event.ProcessId = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
    if (process) event.ProcessCreated = (ULONGLONG)PsGetProcessCreateTimeQuadPart(process);
    KeAcquireSpinLock(&g->ProcessesLock, &irql);
    for (i = 0; process && i < UF_PROCESS_SLOTS; ++i) {
        UF_PROCESS* p = &g->Processes[i];
        if (p->Process == process && p->Pid == event.ProcessId && p->Created == event.ProcessCreated) {
            event.ProcessCreated = p->Created; event.PathLength = p->Length;
            event.PathStatus = p->Status;
            RtlCopyMemory(event.Path, p->Path, sizeof(event.Path));
            break;
        }
    }
    KeReleaseSpinLock(&g->ProcessesLock, irql);
    KeAcquireSpinLock(&g->EventsLock, &irql);
    event.Sequence = ++g->Sequence;
    if (g->EventCount < UF_EVENT_SLOTS) {
        g->Events[(g->Head + g->EventCount) % UF_EVENT_SLOTS] = event; ++g->EventCount;
    } else ++g->Dropped;
    KeReleaseSpinLock(&g->EventsLock, irql);
}
static NTSTATUS LowerIoctl(UF_DEVICE* d, ULONG code, PVOID input, ULONG inSize, PVOID output, ULONG outSize, ULONG required)
{
    WDF_MEMORY_DESCRIPTOR inDesc, outDesc;
    WDF_REQUEST_SEND_OPTIONS options;
    ULONG_PTR returned = 0;
    NTSTATUS status;
    WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_TIMEOUT | WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE);
    WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options, WDF_REL_TIMEOUT_IN_SEC(2));
    if (input) WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&inDesc, input, inSize);
    if (output) WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&outDesc, output, outSize);
    status = WdfIoTargetSendIoctlSynchronously(WdfDeviceGetIoTarget(d->Device), NULL, code,
        input ? &inDesc : NULL, output ? &outDesc : NULL, &options, &returned);
    if (NT_SUCCESS(status) && output && returned < required) return STATUS_INFO_LENGTH_MISMATCH;
    return status;
}
typedef struct _UF_SCAN {
    UF_DEVICE* Device;
    WDFREQUEST Request;
    ULONGLONG Deadline;
} UF_SCAN;
static NTSTATUS LowerRead(PVOID context, ULONGLONG offset, ULONG length, PVOID buffer)
{
    UF_SCAN* scan = context;
    WDF_MEMORY_DESCRIPTOR desc;
    WDF_REQUEST_SEND_OPTIONS options;
    LONGLONG position = (LONGLONG)offset;
    ULONG_PTR returned = 0;
    NTSTATUS status;
    if (KeQueryInterruptTime() >= scan->Deadline) return STATUS_IO_TIMEOUT;
    if (WdfRequestIsCanceled(scan->Request)) return STATUS_CANCELLED;
    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&desc, buffer, length);
    WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_TIMEOUT);
    WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options, WDF_REL_TIMEOUT_IN_SEC(2));
    status = WdfIoTargetSendReadSynchronously(WdfDeviceGetIoTarget(scan->Device->Device), NULL,
        &desc, &position, &options, &returned);
    if (NT_SUCCESS(status) && returned != length) return STATUS_DEVICE_DATA_ERROR;
    return status;
}
static BOOLEAN ReadOnlyIoctl(ULONG code)
{
    switch (code) {
    case IOCTL_STORAGE_QUERY_PROPERTY:
    case IOCTL_STORAGE_GET_DEVICE_NUMBER:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
    case IOCTL_STORAGE_GET_HOTPLUG_INFO:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
    case IOCTL_DISK_GET_LENGTH_INFO:
    case IOCTL_DISK_GET_DRIVE_LAYOUT:
    case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
    case IOCTL_DISK_GET_PARTITION_INFO:
    case IOCTL_DISK_GET_PARTITION_INFO_EX:
    case IOCTL_DISK_IS_WRITABLE:
    case IOCTL_DISK_VERIFY:
    case IOCTL_DISK_CHECK_VERIFY:
    case IOCTL_DISK_GET_DISK_ATTRIBUTES:
        return TRUE;
    default: return FALSE;
    }
}
VOID UfForwardDone(WDFREQUEST Request, WDFIOTARGET Target, PWDF_REQUEST_COMPLETION_PARAMS Params, WDFCONTEXT Context)
{
    UF_DEVICE* d = Context;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Target);
    KeAcquireSpinLock(&d->Lock, &irql);
    if (--d->Inflight == 0) KeSetEvent(&d->Drained, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&d->Lock, irql);
    WdfRequestCompleteWithInformation(Request, Params->IoStatus.Status, Params->IoStatus.Information);
}
static VOID Forward(UF_DEVICE* d, WDFREQUEST request, BOOLEAN mutation)
{
    WDF_REQUEST_SEND_OPTIONS options;
    NTSTATUS status;
    WdfRequestFormatRequestUsingCurrentType(request);
    if (mutation) WdfRequestSetCompletionRoutine(request, UfForwardDone, d);
    WDF_REQUEST_SEND_OPTIONS_INIT(&options, mutation ? 0 : WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(request, WdfDeviceGetIoTarget(d->Device), &options)) {
        KIRQL irql;
        status = WdfRequestGetStatus(request);
        if (mutation) {
            KeAcquireSpinLock(&d->Lock, &irql);
            if (--d->Inflight == 0) KeSetEvent(&d->Drained, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&d->Lock, irql);
        }
        WdfRequestComplete(request, status);
    }
}
static VOID Inspect(UF_DEVICE* d, WDFREQUEST request, BOOLEAN write, ULONGLONG offset, ULONGLONG length, ULONG code)
{
    KIRQL irql;
    ULONG kind = 0, i;
    ULONGLONG generation;
    BOOLEAN mutation = write || !ReadOnlyIoctl(code);
    KeAcquireSpinLock(&d->Lock, &irql);
    if (mutation && d->Info.State == UF_BOOT_SCANNING) kind = UF_BOOT_KIND_CONTROL;
    else if (mutation && d->Info.State == UF_BOOT_ACTIVE) {
        if (!write || offset >= d->Info.DiskBytes || length > d->Info.DiskBytes - offset) kind = UF_BOOT_KIND_CONTROL;
        else if (length) {
            for (i = 0; i < d->Info.RangeCount; ++i) {
                UF_BOOT_RANGE* r = &d->Info.Ranges[i];
                if (offset < r->Offset + r->Length && r->Offset < offset + length) { kind = r->Kind; break; }
            }
        }
    }
    if (!kind && mutation && d->Inflight++ == 0) KeResetEvent(&d->Drained);
    generation = d->Info.PolicyGeneration;
    if (kind) ++d->Info.BlockedWrites;
    KeReleaseSpinLock(&d->Lock, irql);
    if (kind) {
        Emit(d, request, kind, offset, length, code, generation);
        WdfRequestComplete(request, STATUS_ACCESS_DENIED);
    } else Forward(d, request, mutation);
}
VOID UfWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
    WDF_REQUEST_PARAMETERS p;
    WDF_REQUEST_PARAMETERS_INIT(&p); WdfRequestGetParameters(Request, &p);
    Inspect(UfDevice(WdfIoQueueGetDevice(Queue)), Request, TRUE,
        (ULONGLONG)p.Parameters.Write.DeviceOffset, (ULONGLONG)Length, 0);
}
VOID UfDiskControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(OutputBufferLength); UNREFERENCED_PARAMETER(InputBufferLength);
    Inspect(UfDevice(WdfIoQueueGetDevice(Queue)), Request, FALSE, 0, 0, IoControlCode);
}
VOID UfInternalControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    UF_DEVICE* d = UfDevice(WdfIoQueueGetDevice(Queue));
    KIRQL irql;
    BOOLEAN block;
    ULONGLONG generation;
    UNREFERENCED_PARAMETER(OutputBufferLength); UNREFERENCED_PARAMETER(InputBufferLength);
    KeAcquireSpinLock(&d->Lock, &irql);
    block = d->Info.State == UF_BOOT_ACTIVE || d->Info.State == UF_BOOT_SCANNING;
    if (!block && d->Inflight++ == 0) KeResetEvent(&d->Drained);
    generation = d->Info.PolicyGeneration;
    if (block) ++d->Info.BlockedWrites;
    KeReleaseSpinLock(&d->Lock, irql);
    if (block) { Emit(d, Request, UF_BOOT_KIND_CONTROL, 0, 0, IoControlCode, generation); WdfRequestComplete(Request, STATUS_ACCESS_DENIED); }
    else Forward(d, Request, TRUE);
}
static NTSTATUS Change(UF_DEVICE* d, WDFREQUEST request, const UF_BOOT_SET_REQUEST* input)
{
    KIRQL irql;
    NTSTATUS status;
    LARGE_INTEGER noWait;
    LARGE_INTEGER wait;
    UF_LAYOUT_RESULT* layout = NULL;
    PUCHAR scratch = NULL;
    UF_SCAN scan;
    ULONG oldState;
    noWait.QuadPart = 0;
    status = KeWaitForSingleObject(&d->Operation, Executive, KernelMode, FALSE, &noWait);
    if (status != STATUS_SUCCESS) return STATUS_DEVICE_BUSY;
    KeAcquireSpinLock(&d->Lock, &irql);
    if (input->ExpectedGeneration != d->Info.PolicyGeneration) status = STATUS_REVISION_MISMATCH;
    else if (!d->Ready) status = STATUS_DEVICE_NOT_READY;
    else if (WdfRequestIsCanceled(request)) status = STATUS_CANCELLED;
    else if (input->Enabled && (!d->Lab || d->Special)) status = STATUS_NOT_SUPPORTED;
    else status = STATUS_SUCCESS;
    oldState = d->Info.State;
    if (NT_SUCCESS(status)) {
        if (!input->Enabled) { d->Info.State = UF_BOOT_STOPPED; d->Info.LastStatus = STATUS_SUCCESS; ++d->Info.PolicyGeneration; }
        else d->Info.State = UF_BOOT_SCANNING;
    }
    KeReleaseSpinLock(&d->Lock, irql);
    if (!NT_SUCCESS(status) || !input->Enabled) goto Exit;
    scan.Device = d; scan.Request = request; scan.Deadline = KeQueryInterruptTime() + 70000000ull;
    wait.QuadPart = -20000000ll;
    status = KeWaitForSingleObject(&d->Drained, Executive, KernelMode, FALSE, &wait);
    if (status == STATUS_TIMEOUT) status = STATUS_IO_TIMEOUT;
    if (!NT_SUCCESS(status)) goto Commit;
    scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, UF_LAYOUT_SCRATCH, UF_TAG);
    layout = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*layout), UF_TAG);
    if (!scratch || !layout) { status = STATUS_INSUFFICIENT_RESOURCES; goto Commit; }
    status = UfParseLayout(d->Info.DiskBytes, d->Info.SectorBytes, LowerRead, &scan, scratch, layout);
    if (NT_SUCCESS(status) && (WdfRequestIsCanceled(request) || KeQueryInterruptTime() >= scan.Deadline)) status = STATUS_CANCELLED;
Commit:
    KeAcquireSpinLock(&d->Lock, &irql);
    if (NT_SUCCESS(status)) {
        d->Info.RangeCount = layout->Count;
        RtlCopyMemory(d->Info.Ranges, layout->Ranges, sizeof(layout->Ranges));
        d->Info.State = UF_BOOT_ACTIVE;
        ++d->Info.PolicyGeneration;
    } else {
        /* 기존 활성 보호를 갱신하다 실패한 경우 기존 범위는 계속 방어한다. */
        d->Info.State = oldState == UF_BOOT_ACTIVE ? UF_BOOT_ACTIVE : UF_BOOT_FAILED;
    }
    d->Info.LastStatus = (ULONG)status;
    KeReleaseSpinLock(&d->Lock, irql);
Exit:
    if (layout) ExFreePoolWithTag(layout, UF_TAG);
    if (scratch) ExFreePoolWithTag(scratch, UF_TAG);
    KeReleaseMutex(&d->Operation, FALSE);
    return status;
}
VOID UfControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    NTSTATUS status;
    UF_BOOT_HEADER* header;
    size_t expected = IoControlCode == IOCTL_UF_BOOT_SET ? sizeof(UF_BOOT_SET_REQUEST) : sizeof(UF_BOOT_HEADER);
    ULONG_PTR information = 0;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Queue);
    if (IoControlCode != IOCTL_UF_BOOT_QUERY && IoControlCode != IOCTL_UF_BOOT_SET && IoControlCode != IOCTL_UF_BOOT_EVENTS) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST); return;
    }
    if (InputBufferLength != expected) { WdfRequestComplete(Request, STATUS_INFO_LENGTH_MISMATCH); return; }
    status = WdfRequestRetrieveInputBuffer(Request, expected, (PVOID*)&header, NULL);
    if (!NT_SUCCESS(status)) goto Done;
    if (header->Version != UF_BOOT_VERSION) { status = STATUS_REVISION_MISMATCH; goto Done; }
    if (header->Size != expected) { status = STATUS_INFO_LENGTH_MISMATCH; goto Done; }
    if (IoControlCode == IOCTL_UF_BOOT_QUERY) {
        UF_BOOT_DEVICE_LIST* output;
        PLIST_ENTRY p;
        if (OutputBufferLength != sizeof(*output)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Done; }
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) goto Done;
        RtlZeroMemory(output, sizeof(*output)); output->Version = UF_BOOT_VERSION; output->Size = sizeof(*output);
        KeAcquireSpinLock(&g->DevicesLock, &irql);
        for (p = g->Devices.Flink; p != &g->Devices && output->Count < UF_BOOT_MAX_DEVICES; p = p->Flink) {
            UF_DEVICE* d = CONTAINING_RECORD(p, UF_DEVICE, Link);
            KeAcquireSpinLockAtDpcLevel(&d->Lock);
            output->Devices[output->Count++] = d->Info;
            KeReleaseSpinLockFromDpcLevel(&d->Lock);
        }
        KeReleaseSpinLock(&g->DevicesLock, irql);
        information = sizeof(*output);
    } else if (IoControlCode == IOCTL_UF_BOOT_EVENTS) {
        UF_BOOT_EVENT_BATCH* output;
        if (OutputBufferLength != sizeof(*output)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Done; }
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) goto Done;
        RtlZeroMemory(output, sizeof(*output)); output->Version = UF_BOOT_VERSION; output->Size = sizeof(*output);
        KeAcquireSpinLock(&g->EventsLock, &irql);
        output->Dropped = g->Dropped;
        while (g->EventCount && output->Count < UF_BOOT_MAX_EVENTS) {
            output->Events[output->Count++] = g->Events[g->Head];
            g->Head = (g->Head + 1) % UF_EVENT_SLOTS; --g->EventCount;
        }
        KeReleaseSpinLock(&g->EventsLock, irql);
        information = sizeof(*output);
    } else {
        UF_BOOT_SET_REQUEST input = *(UF_BOOT_SET_REQUEST*)header;
        UF_DEVICE* found = NULL;
        UF_BOOT_DEVICE_INFO* output;
        PLIST_ENTRY p;
        if (input.Reserved || input.Enabled > 1 || !input.DeviceId) { status = STATUS_INVALID_PARAMETER; goto Done; }
        if (OutputBufferLength != sizeof(*output)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Done; }
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*output), (PVOID*)&output, NULL);
        if (!NT_SUCCESS(status)) goto Done;
        KeAcquireSpinLock(&g->DevicesLock, &irql);
        for (p = g->Devices.Flink; p != &g->Devices; p = p->Flink) {
            UF_DEVICE* d = CONTAINING_RECORD(p, UF_DEVICE, Link);
            if (d->Info.DeviceId == input.DeviceId) { found = d; WdfObjectReference(d->Device); break; }
        }
        KeReleaseSpinLock(&g->DevicesLock, irql);
        if (!found) { status = STATUS_NO_SUCH_DEVICE; goto Done; }
        status = Change(found, Request, &input);
        if (NT_SUCCESS(status)) {
            KeAcquireSpinLock(&found->Lock, &irql); *output = found->Info; KeReleaseSpinLock(&found->Lock, irql);
            information = sizeof(*output);
        }
        WdfObjectDereference(found->Device);
    }
Done:
    WdfRequestCompleteWithInformation(Request, status, NT_SUCCESS(status) ? information : 0);
}
NTSTATUS UfD0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
    UF_DEVICE* d = UfDevice(Device);
    STORAGE_DEVICE_NUMBER number;
    GET_LENGTH_INFORMATION length = {0};
    DISK_GEOMETRY geometry = {0};
    STORAGE_PROPERTY_QUERY query;
    UCHAR descriptorBuffer[1024];
    PSTORAGE_DEVICE_DESCRIPTOR descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)descriptorBuffer;
    KIRQL irql;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(PreviousState);
    KeWaitForSingleObject(&d->Operation, Executive, KernelMode, FALSE, NULL);
    RtlZeroMemory(&query, sizeof(query)); query.PropertyId = StorageDeviceProperty; query.QueryType = PropertyStandardQuery;
    RtlZeroMemory(descriptorBuffer, sizeof(descriptorBuffer));
    status = LowerIoctl(d, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &number, sizeof(number), sizeof(number));
    if (NT_SUCCESS(status)) status = LowerIoctl(d, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &length, sizeof(length), sizeof(length));
    if (NT_SUCCESS(status)) status = LowerIoctl(d, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof(geometry), sizeof(geometry));
    if (NT_SUCCESS(status)) status = LowerIoctl(d, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), descriptorBuffer, sizeof(descriptorBuffer), sizeof(*descriptor));
    KeAcquireSpinLock(&d->Lock, &irql);
    d->Ready = NT_SUCCESS(status);
    if (d->Ready) {
        d->Info.DiskNumber = number.DeviceNumber;
        d->Info.DiskBytes = (ULONGLONG)length.Length.QuadPart;
        d->Info.SectorBytes = geometry.BytesPerSector;
        d->Lab = descriptor->BusType == BusTypeFileBackedVirtual && !descriptor->RemovableMedia &&
            number.DeviceType == FILE_DEVICE_DISK && (number.PartitionNumber == MAXULONG || number.PartitionNumber == 0);
        d->Info.Flags = UF_BOOT_FLAG_READY | (d->Lab ? UF_BOOT_FLAG_LAB_DISK : 0);
        if (!d->Lab || d->Special) d->Info.State = UF_BOOT_UNSUPPORTED;
    }
    d->Info.LastStatus = (ULONG)status;
    KeReleaseSpinLock(&d->Lock, irql);
    KeReleaseMutex(&d->Operation, FALSE);
    /* 부가 기능의 지원 실패 때문에 디스크 PnP 시작 자체를 실패시키지 않는다. */
    return STATUS_SUCCESS;
}
NTSTATUS UfD0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
    UF_DEVICE* d = UfDevice(Device);
    KIRQL irql;
    UNREFERENCED_PARAMETER(TargetState);
    KeWaitForSingleObject(&d->Operation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&d->Lock, &irql);
    d->Ready = FALSE; d->Info.Flags &= ~UF_BOOT_FLAG_READY;
    KeReleaseSpinLock(&d->Lock, irql);
    KeReleaseMutex(&d->Operation, FALSE);
    return STATUS_SUCCESS;
}
NTSTATUS UfRelease(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
    UF_DEVICE* d = UfDevice(Device);
    KIRQL irql;
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    KeWaitForSingleObject(&d->Operation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&d->Lock, &irql);
    d->Ready = FALSE; d->Info.Flags = 0; d->Info.RangeCount = 0;
    d->Info.State = UF_BOOT_STOPPED; ++d->Info.PolicyGeneration;
    KeReleaseSpinLock(&d->Lock, irql);
    KeReleaseMutex(&d->Operation, FALSE);
    return STATUS_SUCCESS;
}
NTSTATUS UfUsage(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath)
{
    UF_DEVICE* d = UfDevice(Device);
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(NotificationType);
    KeAcquireSpinLock(&d->Lock, &irql);
    if (IsInNotificationPath) {
        if (d->Info.State == UF_BOOT_ACTIVE || d->Info.State == UF_BOOT_SCANNING) status = STATUS_DEVICE_BUSY;
        else { d->Special = TRUE; d->Info.State = UF_BOOT_UNSUPPORTED; }
    }
    KeReleaseSpinLock(&d->Lock, irql);
    return status;
}
VOID UfCleanup(WDFOBJECT Object)
{
    UF_DEVICE* d = UfDevice(Object);
    KIRQL irql;
    BOOLEAN last = FALSE;
    WdfWaitLockAcquire(g->ControlLock, NULL);
    KeAcquireSpinLock(&g->DevicesLock, &irql);
    if (d->Listed) { RemoveEntryList(&d->Link); d->Listed = FALSE; last = --g->Count == 0; }
    KeReleaseSpinLock(&g->DevicesLock, irql);
    if (last && g->Control) { WdfObjectDelete(g->Control); g->Control = NULL; }
    WdfWaitLockRelease(g->ControlLock);
}
NTSTATUS UfAddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnp;
    WDF_IO_QUEUE_CONFIG queue;
    WDFDEVICE device;
    UF_DEVICE* d;
    NTSTATUS status;
    KIRQL irql;
    ULONG bytes = 0;
    WDF_DEVICE_PROPERTY_DATA property;
    DEVPROPTYPE propertyType;
    UNREFERENCED_PARAMETER(Driver);
    WdfFdoInitSetFilter(DeviceInit);
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDeviceD0Entry = UfD0Entry; pnp.EvtDeviceD0Exit = UfD0Exit;
    pnp.EvtDeviceReleaseHardware = UfRelease; pnp.EvtDeviceUsageNotificationEx = UfUsage;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnp);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, UF_DEVICE);
    attributes.EvtCleanupCallback = UfCleanup;
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) return status;
    d = UfDevice(device); d->Device = device;
    KeInitializeSpinLock(&d->Lock); KeInitializeEvent(&d->Drained, NotificationEvent, TRUE);
    KeInitializeMutex(&d->Operation, 0);
    d->Info.Version = UF_BOOT_VERSION; d->Info.Size = sizeof(d->Info); d->Info.PolicyGeneration = 1;
    d->Info.State = UF_BOOT_STOPPED; d->Info.DiskNumber = MAXULONG;
    WDF_DEVICE_PROPERTY_DATA_INIT(&property, &DEVPKEY_Device_InstanceId);
    status = WdfDeviceQueryPropertyEx(device, &property,
        sizeof(d->Info.InstanceId), d->Info.InstanceId, &bytes, &propertyType);
    if (!NT_SUCCESS(status)) d->Info.InstanceId[0] = 0;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue, WdfIoQueueDispatchParallel);
    queue.EvtIoWrite = UfWrite; queue.EvtIoDeviceControl = UfDiskControl;
    queue.EvtIoInternalDeviceControl = UfInternalControl;
    status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) return status;
    WdfWaitLockAcquire(g->ControlLock, NULL);
    if (!g->Control) {
        status = CreateControl();
        if (!NT_SUCCESS(status)) { WdfWaitLockRelease(g->ControlLock); return status; }
    }
    KeAcquireSpinLock(&g->DevicesLock, &irql);
    if (g->Count >= UF_BOOT_MAX_DEVICES) status = STATUS_INSUFFICIENT_RESOURCES;
    else {
        d->Info.DeviceId = ++g->NextId;
        InsertTailList(&g->Devices, &d->Link); d->Listed = TRUE; ++g->Count;
    }
    KeReleaseSpinLock(&g->DevicesLock, irql);
    WdfWaitLockRelease(g->ControlLock);
    return status;
}
VOID UfUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    if (g) {
        if (g->NotifyRegistered) PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        ExFreePoolWithTag(g, UF_TAG); g = NULL;
    }
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    WDF_OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;
    LARGE_INTEGER time;
    g = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*g), UF_TAG);
    if (!g) return STATUS_INSUFFICIENT_RESOURCES;
    KeInitializeSpinLock(&g->DevicesLock); KeInitializeSpinLock(&g->EventsLock); KeInitializeSpinLock(&g->ProcessesLock);
    InitializeListHead(&g->Devices); KeQuerySystemTime(&time); g->NextId = (ULONGLONG)time.QuadPart;
    WDF_DRIVER_CONFIG_INIT(&config, UfAddDevice); config.EvtDriverUnload = UfUnload;
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(g, UF_TAG); g = NULL; return status; }
    g->Driver = driver;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes); attributes.ParentObject = driver;
    status = WdfWaitLockCreate(&attributes, &g->ControlLock);
    if (NT_SUCCESS(status)) {
        status = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
        if (NT_SUCCESS(status)) g->NotifyRegistered = TRUE;
    }
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(g, UF_TAG); g = NULL; }
    return status;
}
static NTSTATUS CreateControl(VOID)
{
    WDFDEVICE control;
    PWDFDEVICE_INIT init;
    WDF_IO_QUEUE_CONFIG queue;
    WDF_OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name = RTL_CONSTANT_STRING(UF_BOOT_DEVICE_NAME);
    UNICODE_STRING link = RTL_CONSTANT_STRING(UF_BOOT_DOS_NAME);
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    init = WdfControlDeviceInitAllocate(g->Driver, &sddl);
    if (!init) return STATUS_INSUFFICIENT_RESOURCES;
    WdfDeviceInitSetDeviceType(init, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(init, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetExclusive(init, FALSE);
    status = WdfDeviceInitAssignName(init, &name);
    if (!NT_SUCCESS(status)) { WdfDeviceInitFree(init); return status; }
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfDeviceCreate(&init, &attributes, &control);
    if (!NT_SUCCESS(status)) { if (init) WdfDeviceInitFree(init); return status; }
    status = WdfDeviceCreateSymbolicLink(control, &link);
    if (!NT_SUCCESS(status)) goto Fail;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue, WdfIoQueueDispatchParallel);
    queue.PowerManaged = WdfFalse; queue.EvtIoDeviceControl = UfControl;
    status = WdfIoQueueCreate(control, &queue, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) goto Fail;
    WdfControlFinishInitializing(control);
    g->Control = control;
    return STATUS_SUCCESS;
Fail:
    WdfObjectDelete(control);
    return status;
}
