#pragma once

/* 사용자 모드 회귀 시험 전용이다. 이 헤더를 드라이버 프로젝트에 포함하지 않는다. */
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef unsigned char KIRQL;
typedef ULONG EX_PUSH_LOCK;
typedef struct { LONG Count; BOOLEAN Closing; } EX_RUNDOWN_REF;
typedef struct { LONG References; ULONG Id; } EPROCESS, *PEPROCESS;
typedef struct { LONG References; } TEST_FLT_OBJECT;
typedef TEST_FLT_OBJECT* PFLT_FILTER;
typedef TEST_FLT_OBJECT* PFLT_PORT;
typedef TEST_FLT_OBJECT* PFLT_INSTANCE;
typedef TEST_FLT_OBJECT* PFLT_VOLUME;
typedef struct _FILE_OBJECT {
    LONG References;
    ULONG Flags;
    UNICODE_STRING FileName;
    struct _FILE_OBJECT* RelatedFileObject;
} FILE_OBJECT, *PFILE_OBJECT;
typedef struct { PVOID Address; ULONG Bytes; } MDL, *PMDL;
typedef struct {
    UCHAR MajorFunction;
    ULONG IrpFlags;
    PFILE_OBJECT TargetFileObject;
    union {
        struct { LARGE_INTEGER ByteOffset; ULONG Length; PVOID WriteBuffer; PMDL MdlAddress; } Write;
    } Parameters;
} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;
typedef struct {
    PFLT_IO_PARAMETER_BLOCK Iopb;
    UCHAR RequestorMode;
    IO_STATUS_BLOCK IoStatus;
    ULONG OperationKind;
    PEPROCESS Process;
    ULONG Dirty;
} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;
typedef struct {
    PFLT_INSTANCE Instance;
    PFLT_VOLUME Volume;
    PFILE_OBJECT FileObject;
} FLT_RELATED_OBJECTS;
typedef const FLT_RELATED_OBJECTS* PCFLT_RELATED_OBJECTS;
typedef struct { UNICODE_STRING Name; } FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
typedef struct { ULONG DeviceType; USHORT SectorSize; } FLT_VOLUME_PROPERTIES;
typedef struct { ULONG Value; } FLT_DEFERRED_IO_WORKITEM, *PFLT_DEFERRED_IO_WORKITEM;
typedef ULONG FLT_POST_OPERATION_FLAGS;
typedef enum {
    FLT_PREOP_SUCCESS_WITH_CALLBACK,
    FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_PREOP_PENDING,
    FLT_PREOP_DISALLOW_FASTIO,
    FLT_PREOP_COMPLETE
} FLT_PREOP_CALLBACK_STATUS;
typedef enum { FLT_POSTOP_FINISHED_PROCESSING } FLT_POSTOP_CALLBACK_STATUS;
typedef VOID (*PFLT_DEFERRED_IO_WORKITEM_ROUTINE)(PFLT_DEFERRED_IO_WORKITEM, PFLT_CALLBACK_DATA, PVOID);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_ASSERT(Expression) assert(Expression)
#define RTL_CONSTANT_STRING(Value) { sizeof(Value) - sizeof(WCHAR), sizeof(Value), (PWSTR)(Value) }
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define KernelMode 0
#define UserMode 1
#define IRP_MJ_WRITE 4
#define IRP_PAGING_IO 0x00000002
#define IRP_SYNCHRONOUS_PAGING_IO 0x00000040
#define FO_VOLUME_OPEN 0x00400000
#define FILE_DEVICE_DISK 7
#define FILE_DEVICE_VIRTUAL_DISK 0x24
#define FILE_DEVICE_MASS_STORAGE 0x2d
#define NonPagedPoolNx 512
#define POOL_FLAG_NON_PAGED 0x40
#define NormalPagePriority 16
#define MdlMappingNoExecute 0x40000000
#define FLT_FILE_NAME_OPENED 2
#define FLT_FILE_NAME_QUERY_DEFAULT 0
#define FLTFL_IO_OPERATION_NON_CACHED 1
#define FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET 2
#define DelayedWorkQueue 1
#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define FlagOn(Value, Flags) ((Value) & (Flags))
#define BooleanFlagOn(Value, Flags) ((BOOLEAN)(((Value) & (Flags)) != 0))
#define HandleToULong(Value) ((ULONG)(ULONG_PTR)(Value))
#define FLT_IS_IRP_OPERATION(Data) ((Data)->OperationKind == 1)
#define FLT_IS_FASTIO_OPERATION(Data) ((Data)->OperationKind == 2)

VOID ExInitializeRundownProtection(EX_RUNDOWN_REF* Ref);
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF* Ref);
VOID ExReleaseRundownProtection(EX_RUNDOWN_REF* Ref);
VOID ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* Ref);
VOID KeInitializeSpinLock(KSPIN_LOCK* Lock);
VOID KeAcquireSpinLock(KSPIN_LOCK* Lock, KIRQL* OldIrql);
VOID KeReleaseSpinLock(KSPIN_LOCK* Lock, KIRQL OldIrql);
KIRQL KeGetCurrentIrql(VOID);
BOOLEAN KeAreAllApcsDisabled(VOID);
PVOID IoGetTopLevelIrp(VOID);
ULONGLONG KeQueryInterruptTime(VOID);
HANDLE PsGetCurrentProcessId(VOID);
HANDLE PsGetCurrentThreadId(VOID);
LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS Process);
NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING* Name);
ULONG DbgPrintEx(ULONG Component, ULONG Level, const char* Format, ...);
VOID ObReferenceObject(PVOID Object);
VOID ObDereferenceObject(PVOID Object);
NTSTATUS FltObjectReference(PVOID Object);
VOID FltObjectDereference(PVOID Object);
PVOID ExAllocatePool2(ULONGLONG Flags, SIZE_T Bytes, ULONG Tag);
VOID ExFreePoolWithTag(PVOID Buffer, ULONG Tag);
VOID ExFreePool(PVOID Buffer);
PVOID FltAllocatePoolAlignedWithTag(PFLT_INSTANCE Instance, ULONG Pool, SIZE_T Bytes, ULONG Tag);
VOID FltFreePoolAlignedWithTag(PFLT_INSTANCE Instance, PVOID Buffer, ULONG Tag);
PMDL IoAllocateMdl(PVOID Buffer, ULONG Bytes, BOOLEAN Secondary, BOOLEAN Charge, PVOID Irp);
VOID IoFreeMdl(PMDL Mdl);
VOID MmBuildMdlForNonPagedPool(PMDL Mdl);
ULONG MmGetMdlByteCount(PMDL Mdl);
PVOID MmGetSystemAddressForMdlSafe(PMDL Mdl, ULONG Priority);
ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA Data);
PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA Data);
NTSTATUS FltGetVolumeName(PFLT_VOLUME Volume, PUNICODE_STRING Name, PULONG Required);
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA Data, ULONG Flags, PFLT_FILE_NAME_INFORMATION* Name);
VOID FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION Name);
NTSTATUS FltGetVolumeProperties(PFLT_VOLUME Volume, FLT_VOLUME_PROPERTIES* Properties, ULONG Bytes, PULONG Returned);
NTSTATUS FltCreateFileEx2(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PHANDLE Handle, PFILE_OBJECT* Object,
    ACCESS_MASK Access, POBJECT_ATTRIBUTES Attributes, PIO_STATUS_BLOCK IoStatus, PLARGE_INTEGER Allocation,
    ULONG FileAttributes, ULONG Share, ULONG Disposition, ULONG Options, PVOID Ea, ULONG EaBytes,
    ULONG Flags, PVOID Context);
NTSTATUS FltGetVolumeFromFileObject(PFLT_FILTER Filter, PFILE_OBJECT File, PFLT_VOLUME* Volume);
NTSTATUS FltReadFile(PFLT_INSTANCE Instance, PFILE_OBJECT File, PLARGE_INTEGER Offset, ULONG Bytes,
    PVOID Buffer, ULONG Flags, PULONG Returned, PVOID Callback, PVOID Context);
VOID FltClose(HANDLE Handle);
NTSTATUS FltLockUserBuffer(PFLT_CALLBACK_DATA Data);
PFLT_DEFERRED_IO_WORKITEM FltAllocateDeferredIoWorkItem(VOID);
VOID FltFreeDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM WorkItem);
NTSTATUS FltQueueDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM WorkItem, PFLT_CALLBACK_DATA Data,
    PFLT_DEFERRED_IO_WORKITEM_ROUTINE Routine, ULONG Queue, PVOID Context);
VOID FltSetCallbackDataDirty(PFLT_CALLBACK_DATA Data);
VOID FltCompletePendedPreOperation(PFLT_CALLBACK_DATA Data, FLT_PREOP_CALLBACK_STATUS Status, PVOID Context);
