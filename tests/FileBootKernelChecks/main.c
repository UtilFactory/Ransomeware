/* 실제 부트 검사 소스를 사용자 모드로 빌드하되 OS API만 메모리 모의 함수로 교체한다. */
#include "fltKernel.h"
#include <stdio.h>

#include "../../UF_FileFilterFactory/src/boot_guard.c"

typedef enum {
    FaultNone, FaultContextAlloc, FaultFirstReference, FaultSecondReference,
    FaultLockBuffer, FaultWorkAlloc, FaultQueue, FaultProperties, FaultDeviceType,
    FaultName, FaultSectorSize, FaultMissingMdl, FaultShortMdl, FaultMapMdl, FaultCopy,
    FaultWriteAlloc, FaultWriteMdlAlloc, FaultReadAlloc, FaultOpen,
    FaultReopenVolume, FaultWrongVolume, FaultWrongReadObject, FaultRead, FaultShortRead
} TEST_FAULT;

static TEST_FAULT gFault;
static ULONG gChecks, gFailures, gAllocations, gReferenceCalls, gPoolCalls;
static ULONG gEvents, gLastAction, gReads, gOpens, gCloses, gCompletions;
static KIRQL gIrql;
static BOOLEAN gApcsDisabled, gTopLevel, gImmediatePost, gStopOnRead, gControllerOnRead;
static FLT_PREOP_CALLBACK_STATUS gCompletionStatus;
static PVOID gPostContext;
static PFLT_DEFERRED_IO_WORKITEM gQueuedWork;
static PFLT_CALLBACK_DATA gQueuedData;
static PVOID gQueuedContext;
static PFLT_DEFERRED_IO_WORKITEM_ROUTINE gQueuedRoutine;
static TEST_FLT_OBJECT gInstance, gVolume, gOtherVolume;
static EPROCESS gProcess, gController;
static FILE_OBJECT gFile, gReadFile;
static FLT_IO_PARAMETER_BLOCK gIopb;
static FLT_CALLBACK_DATA gData;
static FLT_RELATED_OBJECTS gObjects;
static MDL gSourceMdl;
static FLT_FILE_NAME_INFORMATION gNameInfo;
static unsigned char gDiskBytes[65536], gWriteBytes[1024 * 1024];
static WCHAR gDeviceName[] = L"\\Device\\HarddiskVolume3";
PFLT_FILTER gUfFilter = &gInstance;

static void Check(int Condition, const char* Name)
{
    ++gChecks;
    if (!Condition) { ++gFailures; printf("FAIL: %s\n", Name); }
}

static PVOID TestAllocate(SIZE_T Bytes)
{
    PVOID result = calloc(1, Bytes);
    if (result != NULL) ++gAllocations;
    return result;
}

static void TestFree(PVOID Buffer)
{
    if (Buffer != NULL) { assert(gAllocations != 0); --gAllocations; free(Buffer); }
}

static void Reset(TEST_FAULT Fault)
{
    Check(gAllocations == 0, "all owned allocations released before next case");
    gFault = Fault;
    gReferenceCalls = gPoolCalls = gEvents = gLastAction = gReads = gOpens = gCloses = gCompletions = 0;
    gIrql = PASSIVE_LEVEL;
    gApcsDisabled = gTopLevel = gStopOnRead = gControllerOnRead = FALSE;
    gImmediatePost = TRUE;
    gPostContext = NULL;
    gQueuedWork = NULL; gQueuedData = NULL; gQueuedContext = NULL; gQueuedRoutine = NULL;
    gInstance.References = gVolume.References = gOtherVolume.References = 1;
    gProcess.References = gController.References = 1;
    gProcess.Id = 1234; gController.Id = 777;
    ZeroMemory(&gFile, sizeof(gFile));
    ZeroMemory(&gReadFile, sizeof(gReadFile));
    ZeroMemory(&gIopb, sizeof(gIopb));
    ZeroMemory(&gData, sizeof(gData));
    ZeroMemory(gDiskBytes, sizeof(gDiskBytes));
    ZeroMemory(gWriteBytes, sizeof(gWriteBytes));
    gFile.References = 1; gFile.Flags = FO_VOLUME_OPEN;
    gReadFile.References = 1; gReadFile.Flags = FO_VOLUME_OPEN;
    gIopb.MajorFunction = IRP_MJ_WRITE;
    gIopb.TargetFileObject = &gFile;
    gIopb.Parameters.Write.Length = 512;
    gIopb.Parameters.Write.WriteBuffer = gWriteBytes;
    gData.Iopb = &gIopb; gData.OperationKind = 1; gData.Process = &gProcess; gData.RequestorMode = UserMode;
    gObjects.Instance = &gInstance; gObjects.Volume = &gVolume; gObjects.FileObject = &gFile;
    gNameInfo.Name.Buffer = gDeviceName;
    gNameInfo.Name.Length = (USHORT)(wcslen(gDeviceName) * sizeof(WCHAR));
    gNameInfo.Name.MaximumLength = sizeof(gDeviceName);
    UfBootInitialize();
    UfBootSetEnabled(TRUE);
}

static void CheckCleanup(void)
{
    Check(gAllocations == 0, "no owned allocation leak");
    Check(gUfBootPending == 0 && gUfBootRundown.Count == 0, "pending and rundown released");
    Check(gInstance.References == 1 && gVolume.References == 1 && gProcess.References == 1,
        "instance volume process references balanced");
    Check(gOtherVolume.References == 1, "mismatching reopened volume reference balanced");
    Check(gReadFile.References == (gOpens == 0 ? 1 : 0), "owned read file object reference released");
    Check(gOpens == gCloses, "opened read handles closed");
}

static FLT_PREOP_CALLBACK_STATUS Run(void)
{
    FLT_PREOP_CALLBACK_STATUS result = UfBootPreWrite(&gData, &gObjects);
    if (result == FLT_PREOP_PENDING) {
        PFLT_DEFERRED_IO_WORKITEM work = gQueuedWork;
        PFLT_CALLBACK_DATA data = gQueuedData;
        PVOID context = gQueuedContext;
        PFLT_DEFERRED_IO_WORKITEM_ROUTINE routine = gQueuedRoutine;
        Check(work != NULL && routine != NULL, "pending request has queued worker");
        gQueuedWork = NULL; gQueuedRoutine = NULL;
        gIrql = PASSIVE_LEVEL;
        routine(work, data, context);
        Check(gCompletions == 1, "pending request completed once");
        result = gCompletionStatus;
    }
    return result;
}

static void CheckFailureBlocked(TEST_FAULT Fault, const char* Label)
{
    FLT_PREOP_CALLBACK_STATUS result;
    Reset(Fault);
    gWriteBytes[0] = 0x55;
    result = Run();
    Check(result == FLT_PREOP_COMPLETE, Label);
    Check(gData.IoStatus.Status == STATUS_ACCESS_DENIED && gData.IoStatus.Information == 0,
        "failed inspection denies bytes");
    Check(gUfBootInspected == 1 && gUfBootFailures == 1 && gUfBootBlocked == 1,
        "failed inspection counters include inspected failed and blocked");
    Check(gEvents == 1 && gLastAction == 7, "failed inspection emits Action 7 not legacy pass Action 6");
    CheckCleanup();
}

static void TestExclusionsAndDecisions(void)
{
    Reset(FaultNone);
    UfBootSetEnabled(FALSE); gWriteBytes[0] = 1;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootInspected == 0, "disabled raw write passes");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gData.RequestorMode = KernelMode;
    Check(Run() == FLT_PREOP_COMPLETE && gUfBootBlocked == 1, "kernel nonpaging changed write blocked");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gProcess.Id = 4;
    Check(Run() == FLT_PREOP_COMPLETE && gUfBootBlocked == 1, "PID 4 is not blanket exception");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gProcess.Id = 0;
    Check(Run() == FLT_PREOP_COMPLETE && gUfBootBlocked == 1, "PID 0 is not blanket exception");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gData.RequestorMode = KernelMode; gIopb.IrpFlags = IRP_PAGING_IO;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootInspected == 0, "kernel paging exception retained");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gData.RequestorMode = UserMode; gIopb.IrpFlags = IRP_PAGING_IO;
    Check(Run() == FLT_PREOP_COMPLETE, "user mode paging flag is not kernel paging exception");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; UfBootSetController(&gProcess);
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootInspected == 0, "controller exception retained");
    UfBootSetController(NULL); CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gIopb.Parameters.Write.ByteOffset.QuadPart = 2048;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootInspected == 0, "outside protected prefix passes");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.ByteOffset.QuadPart = -1;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK, "negative special offset not treated as disk prefix");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gData.OperationKind = 2;
    Check(Run() == FLT_PREOP_DISALLOW_FASTIO && gUfBootInspected == 0, "raw fast IO reissued as IRP");
    CheckCleanup();

    Reset(FaultNone); gFile.Flags = 0;
    gFile.FileName.Buffer = L"\\ordinary.txt"; gFile.FileName.Length = 26;
    Check(!UfBootIsRawWriteTarget(&gData), "ordinary file is not raw target");
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootInspected == 0, "ordinary file prefix unaffected");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 5, "changed prefix is content denial Action 5");
    Check(gUfBootFailures == 0 && gUfBootBlocked == 1 && gReads == 1, "content mismatch is not inspection failure");
    CheckCleanup();

    Reset(FaultNone);
    Check(Run() == FLT_PREOP_SUCCESS_WITH_CALLBACK && gData.Dirty == 1, "identical prefix passes snapshot to post callback");
    Check(gUfBootFailures == 0 && gUfBootBlocked == 0 && gEvents == 0, "identical prefix not reported as block");
    CheckCleanup();

    Reset(FaultNone); gImmediatePost = FALSE;
    Check(Run() == FLT_PREOP_SUCCESS_WITH_CALLBACK && gPostContext != NULL, "post context retained until completion");
    gWriteBytes[0] = 0xff;
    Check(((unsigned char*)gIopb.Parameters.Write.WriteBuffer)[0] == 0,
        "user buffer mutation cannot alter approved write snapshot");
    Check(gUfBootPending == 1 && gAllocations > 0, "pending write owns snapshot memory");
    IoFreeMdl(gIopb.Parameters.Write.MdlAddress); gIopb.Parameters.Write.MdlAddress = NULL;
    UfBootPostWrite(&gData, &gObjects, gPostContext, 0); gPostContext = NULL;
    CheckCleanup();
}

static void TestFaultsAndLimits(void)
{
    TEST_FAULT fault;
    char label[80];
    for (fault = FaultContextAlloc; fault <= FaultShortRead; fault = (TEST_FAULT)(fault + 1)) {
        /* 볼륨 열기 표식이 있으므로 이름 조회 실패만으로 비교를 포기하지 않는다. */
        if (fault == FaultName) continue;
        (void)sprintf_s(label, sizeof(label), "fault %u must fail closed", (unsigned int)fault);
        CheckFailureBlocked(fault, label);
    }
    Reset(FaultName); gWriteBytes[0] = 1;
    Check(Run() == FLT_PREOP_COMPLETE && gUfBootFailures == 0, "volume identity fallback still compares and blocks");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.Length = 1024 * 1024 + 1;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7 && gUfBootBlocked == 1,
        "over 1 MiB prefix write fails closed before buffer access");
    CheckCleanup();

    Reset(FaultNone); gUfBootPending = 16;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7 && gUfBootBlocked == 1,
        "pending work limit fails closed");
    Check(gUfBootPending == 16, "rejected overflow preserves previous pending count");
    gUfBootPending = 0; CheckCleanup();

    Reset(FaultNone); gTopLevel = TRUE;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7, "unsafe top-level IRP fails closed");
    gTopLevel = FALSE; CheckCleanup();

    Reset(FaultNone); gIrql = DISPATCH_LEVEL;
    Check(Run() == FLT_PREOP_COMPLETE && gUfBootBlocked == 1 && gUfBootFailures == 1,
        "high IRQL denies without unsafe user event resolution");
    gIrql = PASSIVE_LEVEL; CheckCleanup();

    Reset(FaultNone); gObjects.Instance = NULL;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7, "missing instance fails closed");
    CheckCleanup();

    Reset(FaultNone); gObjects.Volume = NULL;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7, "missing volume fails closed");
    CheckCleanup();

    Reset(FaultNone); gApcsDisabled = TRUE;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7, "worker disabled APC context fails closed");
    gApcsDisabled = FALSE; CheckCleanup();

    Reset(FaultNone); gUfBootRundown.Closing = TRUE;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 7, "active rundown refusal fails closed");
    CheckCleanup();
}

static void TestTransitionsAndBoundaries(void)
{
    FLT_PREOP_CALLBACK_STATUS result;
    Reset(FaultNone); gWriteBytes[0] = 1;
    result = UfBootPreWrite(&gData, &gObjects);
    Check(result == FLT_PREOP_PENDING, "transition case queued before stop");
    UfBootSetEnabled(FALSE);
    gQueuedRoutine(gQueuedWork, gQueuedData, gQueuedContext);
    Check(gCompletionStatus == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootBlocked == 0 && gReads == 0,
        "stop before worker cancels without new block or disk read");
    CheckCleanup();

    Reset(FaultNone); gWriteBytes[0] = 1; gStopOnRead = TRUE;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootBlocked == 0 && gUfBootFailures == 0,
        "stop during successful read cancels changed-content block");
    CheckCleanup();

    Reset(FaultRead); gWriteBytes[0] = 1; gStopOnRead = TRUE;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootBlocked == 0 && gUfBootFailures == 0,
        "stop during failed read cancels failure block");
    CheckCleanup();

    Reset(FaultRead); gWriteBytes[0] = 1; gControllerOnRead = TRUE;
    Check(Run() == FLT_PREOP_SUCCESS_NO_CALLBACK && gUfBootBlocked == 0 && gUfBootFailures == 0,
        "new controller identity during failed read cancels failure block");
    UfBootSetController(NULL); CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.ByteOffset.QuadPart = 512; gDiskBytes[0] = 0xff;
    Check(Run() == FLT_PREOP_SUCCESS_WITH_CALLBACK && gUfBootBlocked == 0,
        "nonzero offset compares corresponding existing bytes not prefix zero");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.ByteOffset.QuadPart = 512; gDiskBytes[512] = 0xff;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 5, "nonzero offset changed byte blocked");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.ByteOffset.QuadPart = 2047; gWriteBytes[0] = 0xff;
    Check(Run() == FLT_PREOP_COMPLETE && gLastAction == 5, "last protected byte is covered");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.ByteOffset.QuadPart = 2047; gWriteBytes[1] = 0xff;
    Check(Run() == FLT_PREOP_SUCCESS_WITH_CALLBACK, "change beyond protected boundary not mislabeled as protected");
    CheckCleanup();

    Reset(FaultNone); gIopb.Parameters.Write.Length = 1024 * 1024;
    Check(Run() == FLT_PREOP_SUCCESS_WITH_CALLBACK, "exact 1 MiB limit accepted when prefix identical");
    CheckCleanup();

    Reset(FaultNone); gFile.Flags = 0;
    Check(UfBootIsRawWriteTarget(&gData), "empty-name verified canonical raw device classified");
    gNameInfo.Name.Buffer = L"\\Device\\HarddiskVolume3\\ordinary.txt";
    gNameInfo.Name.Length = (USHORT)(wcslen(gNameInfo.Name.Buffer) * sizeof(WCHAR));
    Check(!UfBootIsRawWriteTarget(&gData), "empty-name ordinary file identity is not raw");
    CheckCleanup();

    Reset(FaultName); gFile.Flags = 0;
    Check(!UfBootIsRawWriteTarget(&gData), "unverified empty-name target remains outside confirmed raw scope");
    CheckCleanup();

    Reset(FaultNone); UfBootSetController(&gController);
    UfBootShutdown();
    Check(gUfBootEnabled == 0 && gUfBootRundown.Closing && gController.References == 1,
        "shutdown disables protection and releases controller after drain");
    CheckCleanup();
}

int main(void)
{
    TestExclusionsAndDecisions();
    TestFaultsAndLimits();
    TestTransitionsAndBoundaries();
    printf("FileBootKernelChecks: %lu checks, %lu failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}

/* 아래 함수는 실제 디스크·핸들·드라이버 API를 호출하지 않는 시험 전용 대체 구현이다. */
#pragma warning(push)
#pragma warning(disable:4100)
VOID ExInitializeRundownProtection(EX_RUNDOWN_REF* Ref) { Ref->Count = 0; Ref->Closing = FALSE; }
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF* Ref) { if (Ref->Closing) return FALSE; ++Ref->Count; return TRUE; }
VOID ExReleaseRundownProtection(EX_RUNDOWN_REF* Ref) { assert(Ref->Count > 0); --Ref->Count; }
VOID ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* Ref) { assert(Ref->Count == 0); Ref->Closing = TRUE; }
VOID KeInitializeSpinLock(KSPIN_LOCK* Lock) { *Lock = 0; }
VOID KeAcquireSpinLock(KSPIN_LOCK* Lock, KIRQL* OldIrql) { *OldIrql = gIrql; }
VOID KeReleaseSpinLock(KSPIN_LOCK* Lock, KIRQL OldIrql) {}
KIRQL KeGetCurrentIrql(VOID) { return gIrql; }
BOOLEAN KeAreAllApcsDisabled(VOID) { return gApcsDisabled; }
PVOID IoGetTopLevelIrp(VOID) { return gTopLevel ? &gData : NULL; }
ULONGLONG KeQueryInterruptTime(VOID) { return GetTickCount64() * 10000; }
HANDLE PsGetCurrentProcessId(VOID) { return (HANDLE)(ULONG_PTR)1234; }
HANDLE PsGetCurrentThreadId(VOID) { return (HANDLE)(ULONG_PTR)4567; }
LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS Process) { return 1000; }
NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING* Name) { *Name = NULL; return STATUS_NOT_FOUND; }
ULONG DbgPrintEx(ULONG Component, ULONG Level, const char* Format, ...) { return 0; }
VOID ObReferenceObject(PVOID Object) { ++((TEST_FLT_OBJECT*)Object)->References; }
VOID ObDereferenceObject(PVOID Object) { assert(((TEST_FLT_OBJECT*)Object)->References > 0); --((TEST_FLT_OBJECT*)Object)->References; }
NTSTATUS FltObjectReference(PVOID Object)
{
    ++gReferenceCalls;
    if ((gFault == FaultFirstReference && gReferenceCalls == 1) ||
        (gFault == FaultSecondReference && gReferenceCalls == 2)) return STATUS_FLT_DELETING_OBJECT;
    ObReferenceObject(Object); return STATUS_SUCCESS;
}
VOID FltObjectDereference(PVOID Object) { ObDereferenceObject(Object); }
PVOID ExAllocatePool2(ULONGLONG Flags, SIZE_T Bytes, ULONG Tag) { return gFault == FaultContextAlloc ? NULL : TestAllocate(Bytes); }
VOID ExFreePoolWithTag(PVOID Buffer, ULONG Tag) { TestFree(Buffer); }
VOID ExFreePool(PVOID Buffer) { TestFree(Buffer); }
PVOID FltAllocatePoolAlignedWithTag(PFLT_INSTANCE Instance, ULONG Pool, SIZE_T Bytes, ULONG Tag)
{
    ++gPoolCalls;
    if ((gFault == FaultWriteAlloc && gPoolCalls == 1) || (gFault == FaultReadAlloc && gPoolCalls == 2)) return NULL;
    return TestAllocate(Bytes);
}
VOID FltFreePoolAlignedWithTag(PFLT_INSTANCE Instance, PVOID Buffer, ULONG Tag) { TestFree(Buffer); }
PMDL IoAllocateMdl(PVOID Buffer, ULONG Bytes, BOOLEAN Secondary, BOOLEAN Charge, PVOID Irp)
{
    PMDL mdl = gFault == FaultWriteMdlAlloc ? NULL : TestAllocate(sizeof(MDL));
    if (mdl != NULL) { mdl->Address = Buffer; mdl->Bytes = Bytes; }
    return mdl;
}
VOID IoFreeMdl(PMDL Mdl) { TestFree(Mdl); }
VOID MmBuildMdlForNonPagedPool(PMDL Mdl) {}
ULONG MmGetMdlByteCount(PMDL Mdl) { return gFault == FaultShortMdl ? 0 : Mdl->Bytes; }
PVOID MmGetSystemAddressForMdlSafe(PMDL Mdl, ULONG Priority)
{
    if (gFault == FaultMapMdl) return NULL;
    /* 실제 소스의 __try/__except가 복사 오류를 차단으로 바꾸는지 확인한다. */
    return gFault == FaultCopy ? (PVOID)(ULONG_PTR)1 : Mdl->Address;
}
ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA Data) { return Data->Process == NULL ? 0 : Data->Process->Id; }
PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA Data) { return Data->Process; }
NTSTATUS FltGetVolumeName(PFLT_VOLUME Volume, PUNICODE_STRING Name, PULONG Required)
{
    if (Name->MaximumLength < sizeof(gDeviceName)) return STATUS_BUFFER_TOO_SMALL;
    CopyMemory(Name->Buffer, gDeviceName, sizeof(gDeviceName));
    Name->Length = sizeof(gDeviceName) - sizeof(WCHAR); return STATUS_SUCCESS;
}
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA Data, ULONG Flags, PFLT_FILE_NAME_INFORMATION* Name)
{
    *Name = NULL;
    if (gFault == FaultName) return STATUS_FLT_INVALID_NAME_REQUEST;
    *Name = &gNameInfo; return STATUS_SUCCESS;
}
VOID FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION Name) {}
NTSTATUS FltGetVolumeProperties(PFLT_VOLUME Volume, FLT_VOLUME_PROPERTIES* Properties, ULONG Bytes, PULONG Returned)
{
    if (gFault == FaultProperties) return STATUS_DEVICE_NOT_READY;
    Properties->DeviceType = gFault == FaultDeviceType ? 0 : FILE_DEVICE_DISK;
    Properties->SectorSize = gFault == FaultSectorSize ? 123 : 512;
    *Returned = sizeof(*Properties); return STATUS_SUCCESS;
}
NTSTATUS FltCreateFileEx2(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PHANDLE Handle, PFILE_OBJECT* Object,
    ACCESS_MASK Access, POBJECT_ATTRIBUTES Attributes, PIO_STATUS_BLOCK IoStatus, PLARGE_INTEGER Allocation,
    ULONG FileAttributes, ULONG Share, ULONG Disposition, ULONG Options, PVOID Ea, ULONG EaBytes,
    ULONG Flags, PVOID Context)
{
    if (gFault == FaultOpen) return STATUS_SHARING_VIOLATION;
    ++gOpens; *Handle = &gReadFile; *Object = &gReadFile;
    if (gFault == FaultWrongReadObject) { gReadFile.Flags = 0; gReadFile.FileName.Length = 10; }
    return STATUS_SUCCESS;
}
NTSTATUS FltGetVolumeFromFileObject(PFLT_FILTER Filter, PFILE_OBJECT File, PFLT_VOLUME* Volume)
{
    if (gFault == FaultReopenVolume) return STATUS_FLT_VOLUME_NOT_FOUND;
    *Volume = gFault == FaultWrongVolume ? &gOtherVolume : &gVolume;
    ObReferenceObject(*Volume); return STATUS_SUCCESS;
}
NTSTATUS FltReadFile(PFLT_INSTANCE Instance, PFILE_OBJECT File, PLARGE_INTEGER Offset, ULONG Bytes,
    PVOID Buffer, ULONG Flags, PULONG Returned, PVOID Callback, PVOID Context)
{
    ++gReads;
    if (gStopOnRead) UfBootSetEnabled(FALSE);
    if (gControllerOnRead) UfBootSetController(&gProcess);
    if (gFault == FaultRead) return STATUS_DEVICE_DATA_ERROR;
    assert(Offset->QuadPart == 0 && Bytes <= sizeof(gDiskBytes));
    CopyMemory(Buffer, gDiskBytes, Bytes); *Returned = gFault == FaultShortRead ? 0 : Bytes;
    return STATUS_SUCCESS;
}
VOID FltClose(HANDLE Handle) { ++gCloses; }
NTSTATUS FltLockUserBuffer(PFLT_CALLBACK_DATA Data)
{
    if (gFault == FaultLockBuffer) return STATUS_INVALID_USER_BUFFER;
    gSourceMdl.Address = Data->Iopb->Parameters.Write.WriteBuffer;
    gSourceMdl.Bytes = Data->Iopb->Parameters.Write.Length;
    Data->Iopb->Parameters.Write.MdlAddress = gFault == FaultMissingMdl ? NULL : &gSourceMdl;
    return STATUS_SUCCESS;
}
PFLT_DEFERRED_IO_WORKITEM FltAllocateDeferredIoWorkItem(VOID)
{ return gFault == FaultWorkAlloc ? NULL : TestAllocate(sizeof(FLT_DEFERRED_IO_WORKITEM)); }
VOID FltFreeDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM WorkItem) { TestFree(WorkItem); }
NTSTATUS FltQueueDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM WorkItem, PFLT_CALLBACK_DATA Data,
    PFLT_DEFERRED_IO_WORKITEM_ROUTINE Routine, ULONG Queue, PVOID Context)
{
    if (gFault == FaultQueue) return STATUS_FLT_NOT_SAFE_TO_POST_OPERATION;
    gQueuedWork = WorkItem; gQueuedData = Data; gQueuedRoutine = Routine; gQueuedContext = Context;
    return STATUS_SUCCESS;
}
VOID FltSetCallbackDataDirty(PFLT_CALLBACK_DATA Data) { ++Data->Dirty; }
VOID FltCompletePendedPreOperation(PFLT_CALLBACK_DATA Data, FLT_PREOP_CALLBACK_STATUS Status, PVOID Context)
{
    ++gCompletions; gCompletionStatus = Status; gPostContext = Context;
    if (Status == FLT_PREOP_SUCCESS_WITH_CALLBACK && gImmediatePost) {
        /* OS가 소유하는 교체 MDL의 해제를 모의한 후 실제 사후 콜백을 실행한다. */
        IoFreeMdl(Data->Iopb->Parameters.Write.MdlAddress); Data->Iopb->Parameters.Write.MdlAddress = NULL;
        UfBootPostWrite(Data, &gObjects, Context, 0); gPostContext = NULL;
    }
}
VOID UfSendEvent(PFLT_CALLBACK_DATA Data, PCUNICODE_STRING FileName, PCUNICODE_STRING ImageName,
    UF_EVENT_ACTION Action, UF_IO_OPERATION Operation, ULONG DesiredAccess, ULONG Disposition,
    ULONGLONG ProcessCreateTime, const UF_POLICY_EVALUATION* Evaluation)
{ ++gEvents; gLastAction = (ULONG)Action; }
#pragma warning(pop)
