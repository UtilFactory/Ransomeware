#include "driver.h"

DRIVER_INITIALIZE DriverEntry;

UF_PROCESS_DRIVER_CONTEXT gUfProcessDriverContext;

static VOID UfDriverUnload(_In_ PDRIVER_OBJECT DriverObject);
static VOID UfUnregisterCallbacks(VOID);
static VOID UfProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
static OB_PREOP_CALLBACK_STATUS UfPreProcessHandleOperation(
    _In_opt_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

static VOID
UfProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS decision;
    ULONG ruleId = 0;
    BOOLEAN trackProcess = FALSE;
    WCHAR processName[UF_PROC_MAX_PROCESS_NAME_CHARS];
    WCHAR processPath[UF_PROC_MAX_PROCESS_PATH_CHARS];
    ULONG processNameLength = 0;
    ULONG processPathLength = 0;

    if (CreateInfo == NULL) {
        UfRemoveTrackedProcess(ProcessId);
        UfQueueProcessEvent(
            UfProcEventExit,
            UfProcActionObserved,
            ProcessId,
            NULL,
            NULL,
            NULL,
            UfProcAccessNone,
            0,
            0,
            0,
            NULL);
        return;
    }

    RtlZeroMemory(processName, sizeof(processName));
    RtlZeroMemory(processPath, sizeof(processPath));
    decision = UfEvaluateProcessCreation(
        Process,
        CreateInfo,
        &ruleId,
        &trackProcess,
        processName,
        RTL_NUMBER_OF(processName),
        &processNameLength,
        processPath,
        RTL_NUMBER_OF(processPath),
        &processPathLength);

    if (NT_SUCCESS(decision) && trackProcess) {
        NTSTATUS trackStatus = UfTrackProcess(
            Process,
            ProcessId,
            ruleId,
            processName,
            processNameLength,
            processPath,
            processPathLength);
        if (!NT_SUCCESS(trackStatus)) {
            KdPrintEx((
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[UF_ProcessFilterFactory] process-track-failed status=0x%08X pid=%p\n",
                trackStatus,
                ProcessId));
        }
    }

    UfQueueProcessEvent(
        UfProcEventCreate,
        NT_SUCCESS(decision) ? UfProcActionObserved : UfProcActionBlocked,
        ProcessId,
        CreateInfo->ParentProcessId,
        CreateInfo->CreatingThreadId.UniqueProcess,
        NULL,
        UfProcAccessNone,
        0,
        0,
        ruleId,
        CreateInfo->ImageFileName);

    if (!NT_SUCCESS(decision)) {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[UF_ProcessFilterFactory] process-blocked pid=%p rule=%lu status=0x%08X image=%wZ\n",
            ProcessId,
            ruleId,
            decision,
            CreateInfo->ImageFileName));
        CreateInfo->CreationStatus = decision;
    }
}

static OB_PREOP_CALLBACK_STATUS
UfPreProcessHandleOperation(
    _In_opt_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    HANDLE requesterProcessId;
    HANDLE targetProcessId;
    ACCESS_MASK originalDesiredAccess;
    ACCESS_MASK desiredAccess;
    ULONG operation;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle != 0) {
        return OB_PREOP_SUCCESS;
    }

    requesterProcessId = PsGetCurrentProcessId();
    targetProcessId = PsGetProcessId((PEPROCESS)OperationInformation->Object);
    if (requesterProcessId == targetProcessId) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        operation = UfProcAccessCreateHandle;
        originalDesiredAccess =
            OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        desiredAccess =
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        operation = UfProcAccessDuplicateHandle;
        originalDesiredAccess =
            OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        desiredAccess =
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    UfQueueProcessEvent(
        UfProcEventAccess,
        UfProcActionObserved,
        requesterProcessId,
        NULL,
        requesterProcessId,
        targetProcessId,
        operation,
        originalDesiredAccess,
        desiredAccess,
        0,
        NULL);

    return OB_PREOP_SUCCESS;
}

static VOID
UfUnregisterCallbacks(
    VOID
    )
{
    if (gUfProcessDriverContext.ObjectCallbackHandle != NULL) {
        ObUnRegisterCallbacks(gUfProcessDriverContext.ObjectCallbackHandle);
        gUfProcessDriverContext.ObjectCallbackHandle = NULL;
    }

    if (gUfProcessDriverContext.ProcessNotifyRegistered != FALSE) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(UfProcessNotify, TRUE);
        gUfProcessDriverContext.ProcessNotifyRegistered = FALSE;
    }
}

static VOID
UfDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    UfUnregisterCallbacks();
    UfCancelSignatureWait(STATUS_DELETE_PENDING);
    UfDeleteControlPlane();
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] driver-unloaded\n"));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operationRegistration;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(UF_PROCESS_FILTER_ALTITUDE);

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&gUfProcessDriverContext, sizeof(gUfProcessDriverContext));
    DriverObject->DriverUnload = UfDriverUnload;

    status = UfCreateControlPlane(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[UF_ProcessFilterFactory] control-plane-create-failed status=0x%08X\n",
            status));
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(UfProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[UF_ProcessFilterFactory] process-notify-registration-failed status=0x%08X\n",
            status));
        UfDeleteControlPlane();
        return status;
    }
    gUfProcessDriverContext.ProcessNotifyRegistered = TRUE;

    RtlZeroMemory(&operationRegistration, sizeof(operationRegistration));
    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = UfPreProcessHandleOperation;

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.OperationRegistration = &operationRegistration;

    status = ObRegisterCallbacks(
        &callbackRegistration,
        &gUfProcessDriverContext.ObjectCallbackHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[UF_ProcessFilterFactory] object-callback-registration-failed status=0x%08X\n",
            status));
        UfUnregisterCallbacks();
        UfDeleteControlPlane();
        return status;
    }

    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] driver-loaded altitude=%wZ\n",
        &altitude));
    return STATUS_SUCCESS;
}
