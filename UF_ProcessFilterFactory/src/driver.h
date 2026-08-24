#pragma once

#include <ntifs.h>
#include <wdmsec.h>

#include "../include/uf_processfilter_protocol.h"

#define UF_PROCESS_FILTER_ALTITUDE L"370040.8"
#define UF_PROC_POOL_TAG 'PfPU'
#define UF_PROC_PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define UF_PROC_PROCESS_TERMINATE 0x0001u

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcessLight(
    _In_ PEPROCESS Process
    );

typedef struct _UF_PROC_POLICY UF_PROC_POLICY, *PUF_PROC_POLICY;

typedef struct _UF_PROC_PROCESS_INFO {
    LIST_ENTRY ProcessListEntry;
    HANDLE ProcessId;
    HANDLE ProcessHandle;
    PEPROCESS ProcessObject;
    UNICODE_STRING ProcessPath;
    PUF_PROC_POLICY Policy;
} UF_PROC_PROCESS_INFO, *PUF_PROC_PROCESS_INFO;

struct _UF_PROC_POLICY {
    LIST_ENTRY PolicyListEntry;
    UNICODE_STRING ProcessName;
    UNICODE_STRING ProcessPath;
    USHORT IsSign;
    USHORT IsCmpFullPath;
    LIST_ENTRY ProcList;
    ULONG RuleId;
};

typedef struct _UF_PROC_SIGNATURE_QUERY {
    ULONGLONG RequestId;
    HANDLE ProcessId;
    ULONG PathLengthChars;
    WCHAR ProcessPath[UF_PROC_MAX_PROCESS_PATH_CHARS];
    KEVENT CompletionEvent;
    BOOLEAN Completed;
    BOOLEAN Allow;
} UF_PROC_SIGNATURE_QUERY, *PUF_PROC_SIGNATURE_QUERY;

typedef struct _UF_PROCESS_DRIVER_CONTEXT {
    BOOLEAN ProcessNotifyRegistered;
    PVOID ObjectCallbackHandle;
    PDEVICE_OBJECT ControlDevice;
    BOOLEAN SymbolicLinkCreated;
    EX_PUSH_LOCK PolicyLock;
    LIST_ENTRY PolicyListHead;
    LIST_ENTRY OrphanProcList;
    volatile LONG64 PolicyGeneration;
    KSPIN_LOCK EventLock;
    PUF_PROC_EVENT EventQueue;
    ULONG EventHead;
    ULONG EventTail;
    ULONG EventCount;
    volatile LONG64 EventSequence;
    volatile LONG64 DroppedEvents;
    volatile LONG ClientConnected;
    KSPIN_LOCK SignatureLock;
    PIRP SignatureWaitIrp;
    PUF_PROC_SIGNATURE_QUERY SignatureQuery;
    volatile LONG64 SignatureRequestSequence;
} UF_PROCESS_DRIVER_CONTEXT;

extern UF_PROCESS_DRIVER_CONTEXT gUfProcessDriverContext;

NTSTATUS
UfCreateControlPlane(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
UfDeleteControlPlane(
    VOID
    );

NTSTATUS
UfEvaluateProcessCreation(
    _In_ PEPROCESS Process,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PULONG RuleId,
    _Out_ PBOOLEAN TrackProcess,
    _Out_writes_(ProcessNameCapacity) PWCHAR ProcessName,
    _In_ ULONG ProcessNameCapacity,
    _Out_ PULONG ProcessNameLengthChars,
    _Out_writes_(ProcessPathCapacity) PWCHAR ProcessPath,
    _In_ ULONG ProcessPathCapacity,
    _Out_ PULONG ProcessPathLengthChars
    );

NTSTATUS
UfTrackProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ ULONG RuleId,
    _In_reads_(ProcessNameLengthChars) PCWCHAR ProcessName,
    _In_ ULONG ProcessNameLengthChars,
    _In_reads_(ProcessPathLengthChars) PCWCHAR ProcessPath,
    _In_ ULONG ProcessPathLengthChars
    );

VOID
UfRemoveTrackedProcess(
    _In_ HANDLE ProcessId
    );

NTSTATUS
UfRequestSignatureDecision(
    _In_ HANDLE ProcessId,
    _In_reads_(PathLengthChars) PCWCHAR ProcessPath,
    _In_ ULONG PathLengthChars,
    _Out_ PBOOLEAN Allow
    );

VOID
UfCancelSignatureWait(
    _In_ NTSTATUS Status
    );

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
    );
