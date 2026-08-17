#pragma once

#include <ntddk.h>
#include <wdmsec.h>

#include "../include/uf_processfilter_protocol.h"

#define UF_PROCESS_FILTER_ALTITUDE L"370040.8"
#define UF_PROC_POOL_TAG 'PfPU'

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

typedef struct _UF_PROC_POLICY {
    unsigned long RuleCount;
    UF_PROC_POLICY_RULE Rules[UF_PROC_MAX_RULES];
} UF_PROC_POLICY, *PUF_PROC_POLICY;

typedef struct _UF_PROCESS_DRIVER_CONTEXT {
    BOOLEAN ProcessNotifyRegistered;
    PVOID ObjectCallbackHandle;
    PDEVICE_OBJECT ControlDevice;
    BOOLEAN SymbolicLinkCreated;
    EX_PUSH_LOCK PolicyLock;
    PUF_PROC_POLICY Policy;
    volatile LONG64 PolicyGeneration;
    KSPIN_LOCK EventLock;
    PUF_PROC_EVENT EventQueue;
    unsigned long EventHead;
    unsigned long EventTail;
    unsigned long EventCount;
    volatile LONG64 EventSequence;
    volatile LONG64 DroppedEvents;
    volatile LONG ClientConnected;
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
    _Out_ PULONG RuleId
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
