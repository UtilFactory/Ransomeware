#include "driver.h"

#define UF_PROC_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

static const GUID gUfProcessDeviceClassGuid =
    { 0xed5e7c89, 0x7765, 0x4b25, { 0xa4, 0xcd, 0x62, 0xb7, 0xfd, 0xcc, 0x8b, 0x61 } };

static NTSTATUS UfDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS UfDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

C_ASSERT(sizeof(UF_PROC_POLICY_RULE) == 1580);
C_ASSERT(sizeof(UF_PROC_POLICY_NAME) == 528);
C_ASSERT(sizeof(UF_PROC_REPLACE_POLICY) == 50576);
C_ASSERT(sizeof(UF_PROC_STATE_REPLY) == 40);
C_ASSERT(sizeof(UF_PROC_EVENT) == 1120);
C_ASSERT(sizeof(UF_PROC_EVENT_BATCH) == 35864);
C_ASSERT(sizeof(UF_PROC_SIGNATURE_REQUEST) == 1064);

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

static ULONG
UfStringLengthChars(
    _In_ PCUNICODE_STRING String
    )
{
    return String == NULL ? 0 : String->Length / sizeof(WCHAR);
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

    if (Image == NULL || LengthChars == 0) {
        *NameLengthChars = 0;
        return NULL;
    }

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

    if (Left == NULL || Right == NULL || LeftLengthChars != RightLengthChars ||
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
        SIZE_T criticalLength = 0;
        while (criticalNames[index][criticalLength] != L'\0') {
            ++criticalLength;
        }
        if (UfEqualTextInsensitive(
                imageName,
                imageNameLength,
                criticalNames[index],
                (ULONG)criticalLength)) {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS
UfCopyWireString(
    _In_reads_(LengthChars) PCWCHAR Source,
    _In_ ULONG LengthChars,
    _Out_ PUNICODE_STRING Destination
    )
{
    SIZE_T bytes;
    PWCHAR buffer;

    RtlZeroMemory(Destination, sizeof(*Destination));
    if (LengthChars == 0) {
        return STATUS_SUCCESS;
    }
    if (LengthChars >= (MAXUSHORT / sizeof(WCHAR))) {
        return STATUS_INVALID_PARAMETER;
    }
    bytes = ((SIZE_T)LengthChars + 1) * sizeof(WCHAR);
    buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, UF_PROC_POOL_TAG);
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(buffer, Source, LengthChars * sizeof(WCHAR));
    buffer[LengthChars] = L'\0';
    Destination->Buffer = buffer;
    Destination->Length = (USHORT)(LengthChars * sizeof(WCHAR));
    Destination->MaximumLength = (USHORT)bytes;
    return STATUS_SUCCESS;
}

static VOID
UfFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, UF_PROC_POOL_TAG);
        RtlZeroMemory(String, sizeof(*String));
    }
}

static VOID
UfDestroyProcessInfo(
    _In_ PUF_PROC_PROCESS_INFO ProcessInfo
    )
{
    if (ProcessInfo->ProcessHandle != NULL) {
        ZwClose(ProcessInfo->ProcessHandle);
    }
    if (ProcessInfo->ProcessObject != NULL) {
        ObDereferenceObject(ProcessInfo->ProcessObject);
    }
    UfFreeUnicodeString(&ProcessInfo->ProcessPath);
    ExFreePoolWithTag(ProcessInfo, UF_PROC_POOL_TAG);
}

static VOID
UfDestroyPolicy(
    _In_ PUF_PROC_POLICY Policy
    )
{
    UfFreeUnicodeString(&Policy->ProcessName);
    UfFreeUnicodeString(&Policy->ProcessPath);
    ExFreePoolWithTag(Policy, UF_PROC_POOL_TAG);
}

static BOOLEAN
UfValidateWireString(
    _In_reads_(Capacity) PCWCHAR String,
    _In_ ULONG LengthChars,
    _In_ ULONG Capacity
    )
{
    ULONG index;

    if (LengthChars == 0 || LengthChars >= Capacity || String[LengthChars] != L'\0') {
        return FALSE;
    }
    for (index = 0; index < LengthChars; ++index) {
        if (String[index] == L'\0') {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
UfValidatePolicyRule(
    _In_ const UF_PROC_POLICY_RULE* Rule
    )
{
    ULONG nameLength;

    if (Rule->RuleId == 0 || Rule->Reserved != 0 ||
        !UfValidateWireString(
            Rule->ProcessName,
            Rule->ProcessNameLengthChars,
            UF_PROC_MAX_PROCESS_NAME_CHARS) ||
        Rule->ProcessPathLengthChars >= UF_PROC_MAX_PROCESS_PATH_CHARS ||
        (Rule->ProcessPathLengthChars != 0 &&
         Rule->ProcessPath[Rule->ProcessPathLengthChars] != L'\0')) {
        return FALSE;
    }

    if (UfFindImageNameComponent(
            Rule->ProcessName,
            Rule->ProcessNameLengthChars,
            &nameLength) != Rule->ProcessName ||
        UfIsCriticalImageName(Rule->ProcessName, Rule->ProcessNameLengthChars)) {
        return FALSE;
    }

    if (Rule->IsCmpFullPath != 0 && Rule->ProcessPathLengthChars == 0) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
UfCreatePolicy(
    _In_ const UF_PROC_POLICY_RULE* Rule,
    _Out_ PUF_PROC_POLICY* Policy
    )
{
    PUF_PROC_POLICY policy;
    NTSTATUS status;

    *Policy = NULL;
    if (!UfValidatePolicyRule(Rule)) {
        return STATUS_INVALID_PARAMETER;
    }

    policy = (PUF_PROC_POLICY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*policy),
        UF_PROC_POOL_TAG);
    if (policy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(policy, sizeof(*policy));
    InitializeListHead(&policy->PolicyListEntry);
    InitializeListHead(&policy->ProcList);
    policy->IsSign = Rule->IsSign;
    policy->IsCmpFullPath = Rule->IsCmpFullPath;
    policy->RuleId = Rule->RuleId;

    status = UfCopyWireString(
        Rule->ProcessName,
        Rule->ProcessNameLengthChars,
        &policy->ProcessName);
    if (!NT_SUCCESS(status)) {
        UfDestroyPolicy(policy);
        return status;
    }
    status = UfCopyWireString(
        Rule->ProcessPath,
        Rule->ProcessPathLengthChars,
        &policy->ProcessPath);
    if (!NT_SUCCESS(status)) {
        UfDestroyPolicy(policy);
        return status;
    }
    *Policy = policy;
    return STATUS_SUCCESS;
}

static PUF_PROC_POLICY
UfFindPolicyLocked(
    _In_reads_(ProcessNameLengthChars) PCWCHAR ProcessName,
    _In_ ULONG ProcessNameLengthChars
    )
{
    PLIST_ENTRY entry;

    for (entry = gUfProcessDriverContext.PolicyListHead.Flink;
         entry != &gUfProcessDriverContext.PolicyListHead;
         entry = entry->Flink) {
        PUF_PROC_POLICY policy = CONTAINING_RECORD(
            entry,
            UF_PROC_POLICY,
            PolicyListEntry);
        if (UfEqualTextInsensitive(
                policy->ProcessName.Buffer,
                UfStringLengthChars(&policy->ProcessName),
                ProcessName,
                ProcessNameLengthChars)) {
            return policy;
        }
    }
    return NULL;
}

static PUF_PROC_POLICY
UfFindPolicyInList(
    _In_ PLIST_ENTRY ListHead,
    _In_reads_(ProcessNameLengthChars) PCWCHAR ProcessName,
    _In_ ULONG ProcessNameLengthChars
    )
{
    PLIST_ENTRY entry;

    for (entry = ListHead->Flink; entry != ListHead; entry = entry->Flink) {
        PUF_PROC_POLICY policy = CONTAINING_RECORD(
            entry,
            UF_PROC_POLICY,
            PolicyListEntry);
        if (UfEqualTextInsensitive(
                policy->ProcessName.Buffer,
                UfStringLengthChars(&policy->ProcessName),
                ProcessName,
                ProcessNameLengthChars)) {
            return policy;
        }
    }
    return NULL;
}

static VOID
UfMoveProcessList(
    _In_ PUF_PROC_POLICY From,
    _In_ PUF_PROC_POLICY To
    )
{
    while (!IsListEmpty(&From->ProcList)) {
        PLIST_ENTRY entry = RemoveHeadList(&From->ProcList);
        PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
            entry,
            UF_PROC_PROCESS_INFO,
            ProcessListEntry);
        processInfo->Policy = To;
        InsertTailList(&To->ProcList, entry);
    }
}

static VOID
UfMoveOrphanProcessesToPoliciesLocked(
    VOID
    )
{
    PLIST_ENTRY entry = gUfProcessDriverContext.OrphanProcList.Flink;

    while (entry != &gUfProcessDriverContext.OrphanProcList) {
        PLIST_ENTRY next = entry->Flink;
        PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
            entry,
            UF_PROC_PROCESS_INFO,
            ProcessListEntry);
        PCWCHAR processName;
        ULONG processNameLength;

        processName = UfFindImageNameComponent(
            processInfo->ProcessPath.Buffer,
            UfStringLengthChars(&processInfo->ProcessPath),
            &processNameLength);
        {
            PUF_PROC_POLICY policy = UfFindPolicyLocked(processName, processNameLength);
            if (policy != NULL) {
                RemoveEntryList(entry);
                processInfo->Policy = policy;
                InsertTailList(&policy->ProcList, entry);
            }
        }
        entry = next;
    }
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

static NTSTATUS
UfValidatePolicySet(
    _In_ const UF_PROC_REPLACE_POLICY* Request
    )
{
    ULONG index;
    ULONG compareIndex;

    if (Request->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        Request->Header.Size != sizeof(*Request) ||
        Request->PolicyCount > UF_PROC_MAX_POLICIES ||
        Request->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < Request->PolicyCount; ++index) {
        if (!UfValidatePolicyRule(&Request->Policies[index])) {
            return STATUS_INVALID_PARAMETER;
        }
        for (compareIndex = 0; compareIndex < index; ++compareIndex) {
            if (UfEqualTextInsensitive(
                    Request->Policies[compareIndex].ProcessName,
                    Request->Policies[compareIndex].ProcessNameLengthChars,
                    Request->Policies[index].ProcessName,
                    Request->Policies[index].ProcessNameLengthChars)) {
                /* 같은 이름은 마지막 요청을 기준으로 처리합니다. */
                break;
            }
        }
    }
    return STATUS_SUCCESS;
}

static VOID
UfFreePolicyList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    while (!IsListEmpty(ListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(ListHead);
        PUF_PROC_POLICY policy = CONTAINING_RECORD(
            entry,
            UF_PROC_POLICY,
            PolicyListEntry);
        UfDestroyPolicy(policy);
    }
}

static NTSTATUS
UfBuildPolicyList(
    _In_ const UF_PROC_REPLACE_POLICY* Request,
    _Out_ PLIST_ENTRY NewList
    )
{
    ULONG index;

    InitializeListHead(NewList);
    for (index = 0; index < Request->PolicyCount; ++index) {
        PUF_PROC_POLICY policy;
        PUF_PROC_POLICY duplicate;
        NTSTATUS status = UfCreatePolicy(&Request->Policies[index], &policy);
        if (!NT_SUCCESS(status)) {
            UfFreePolicyList(NewList);
            return status;
        }
        duplicate = UfFindPolicyInList(
            NewList,
            policy->ProcessName.Buffer,
            UfStringLengthChars(&policy->ProcessName));
        if (duplicate != NULL) {
            RemoveEntryList(&duplicate->PolicyListEntry);
            UfDestroyPolicy(duplicate);
        }
        InsertTailList(NewList, &policy->PolicyListEntry);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
UfReplacePolicy(
    _In_ const UF_PROC_REPLACE_POLICY* Request
    )
{
    LIST_ENTRY newList;
    LIST_ENTRY oldList;
    NTSTATUS status;
    PUF_PROC_POLICY oldPolicy;

    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_ENTER);
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy enter count=%lu\n",
        Request != NULL ? Request->PolicyCount : 0));

    status = UfValidatePolicySet(Request);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
            UF_PROC_POLICY_STAGE_IDLE);
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[UF_ProcessFilterFactory] replace-policy validate-failed status=0x%08X\n",
            status));
        return status;
    }
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_VALIDATED);
    status = UfBuildPolicyList(Request, &newList);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
            UF_PROC_POLICY_STAGE_IDLE);
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[UF_ProcessFilterFactory] replace-policy build-failed status=0x%08X\n",
            status));
        return status;
    }
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy built count=%lu\n",
        Request->PolicyCount));
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_BUILT);
    InitializeListHead(&oldList);

    KeEnterCriticalRegion();
    /* 정책 교체에서 락을 무기한 기다리면 사용자 모드 요청도 반환되지 않는다. */
    if (!ExTryAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock)) {
        KeLeaveCriticalRegion();
        UfFreePolicyList(&newList);
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[UF_ProcessFilterFactory] replace-policy lock-busy\n"));
        return STATUS_DEVICE_BUSY;
    }
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_LOCKED);
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy lock-acquired\n"));

    while (!IsListEmpty(&gUfProcessDriverContext.PolicyListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&gUfProcessDriverContext.PolicyListHead);
        InsertTailList(&oldList, entry);
    }
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy lists-swapped\n"));
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_SWAPPED);
    while (!IsListEmpty(&newList)) {
        PLIST_ENTRY entry = RemoveHeadList(&newList);
        InsertTailList(&gUfProcessDriverContext.PolicyListHead, entry);
    }
    for (PLIST_ENTRY entry = oldList.Flink;
         entry != &oldList;
         entry = entry->Flink) {
        PUF_PROC_POLICY old = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        PUF_PROC_POLICY replacement = UfFindPolicyLocked(
            old->ProcessName.Buffer,
            UfStringLengthChars(&old->ProcessName));
        if (replacement != NULL) {
            UfMoveProcessList(old, replacement);
        } else {
            while (!IsListEmpty(&old->ProcList)) {
                PLIST_ENTRY processEntry = RemoveHeadList(&old->ProcList);
                PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
                    processEntry,
                    UF_PROC_PROCESS_INFO,
                    ProcessListEntry);
                processInfo->Policy = NULL;
                InsertTailList(&gUfProcessDriverContext.OrphanProcList, processEntry);
            }
        }
    }
    UfMoveOrphanProcessesToPoliciesLocked();
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_ORPHANS_MOVED);
    {
        LONG policyCount = 0;
        PLIST_ENTRY policyEntry;
        for (policyEntry = gUfProcessDriverContext.PolicyListHead.Flink;
             policyEntry != &gUfProcessDriverContext.PolicyListHead;
             policyEntry = policyEntry->Flink) {
            ++policyCount;
        }
        InterlockedExchange(&gUfProcessDriverContext.PolicyCount, policyCount);
    }
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);

    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy unlock\n"));

    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_UNLOCKED);

    /* 상태 조회는 정책 락을 잡지 않으므로 원자 카운터를 갱신합니다. */
    InterlockedExchange(
        &gUfProcessDriverContext.PolicyCount,
        (LONG)Request->PolicyCount);

    while (!IsListEmpty(&oldList)) {
        PLIST_ENTRY entry = RemoveHeadList(&oldList);
        oldPolicy = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        UfDestroyPolicy(oldPolicy);
    }
    KdPrintEx((
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[UF_ProcessFilterFactory] replace-policy complete\n"));
    InterlockedExchange(&gUfProcessDriverContext.PolicyReplaceStage,
        UF_PROC_POLICY_STAGE_COMPLETE);
    return STATUS_SUCCESS;
}

static NTSTATUS
UfAddPolicy(
    _In_ const UF_PROC_REPLACE_POLICY* Request
    )
{
    LIST_ENTRY newList;
    LIST_ENTRY retiredList;
    NTSTATUS status;

    status = UfValidatePolicySet(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = UfBuildPolicyList(Request, &newList);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeListHead(&retiredList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    while (!IsListEmpty(&newList)) {
        PLIST_ENTRY entry = RemoveHeadList(&newList);
        PUF_PROC_POLICY policy = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        PUF_PROC_POLICY old = UfFindPolicyLocked(
            policy->ProcessName.Buffer,
            UfStringLengthChars(&policy->ProcessName));
        if (old != NULL) {
            RemoveEntryList(&old->PolicyListEntry);
            UfMoveProcessList(old, policy);
            InsertTailList(&retiredList, &old->PolicyListEntry);
        }
        InsertTailList(&gUfProcessDriverContext.PolicyListHead, &policy->PolicyListEntry);
        {
            PLIST_ENTRY orphanEntry = gUfProcessDriverContext.OrphanProcList.Flink;
            while (orphanEntry != &gUfProcessDriverContext.OrphanProcList) {
                PLIST_ENTRY next = orphanEntry->Flink;
                PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
                    orphanEntry,
                    UF_PROC_PROCESS_INFO,
                    ProcessListEntry);
                ULONG processNameLength;
                PCWCHAR processName = UfFindImageNameComponent(
                    processInfo->ProcessPath.Buffer,
                    UfStringLengthChars(&processInfo->ProcessPath),
                    &processNameLength);
                if (UfEqualTextInsensitive(
                        processName,
                        processNameLength,
                        policy->ProcessName.Buffer,
                        UfStringLengthChars(&policy->ProcessName))) {
                    RemoveEntryList(orphanEntry);
                    processInfo->Policy = policy;
                    InsertTailList(&policy->ProcList, orphanEntry);
                }
                orphanEntry = next;
            }
        }
    }
    {
        LONG policyCount = 0;
        PLIST_ENTRY policyEntry;
        for (policyEntry = gUfProcessDriverContext.PolicyListHead.Flink;
             policyEntry != &gUfProcessDriverContext.PolicyListHead;
             policyEntry = policyEntry->Flink) {
            ++policyCount;
        }
        InterlockedExchange(&gUfProcessDriverContext.PolicyCount, policyCount);
    }
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    while (!IsListEmpty(&retiredList)) {
        PLIST_ENTRY entry = RemoveHeadList(&retiredList);
        PUF_PROC_POLICY policy = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        UfDestroyPolicy(policy);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
UfClearPolicy(
    _In_reads_bytes_(InputLength) const VOID* Input,
    _In_ ULONG InputLength
    )
{
    const UF_PROC_MESSAGE_HEADER* header;
    LIST_ENTRY retiredList;

    if (Input == NULL || InputLength != sizeof(UF_PROC_MESSAGE_HEADER)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    header = (const UF_PROC_MESSAGE_HEADER*)Input;
    if (header->Version != UF_PROC_PROTOCOL_VERSION || header->Size != sizeof(*header)) {
        return STATUS_INVALID_PARAMETER;
    }
    InitializeListHead(&retiredList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    while (!IsListEmpty(&gUfProcessDriverContext.PolicyListHead)) {
        PLIST_ENTRY policyEntry = RemoveHeadList(&gUfProcessDriverContext.PolicyListHead);
        PUF_PROC_POLICY policy = CONTAINING_RECORD(policyEntry, UF_PROC_POLICY, PolicyListEntry);
        while (!IsListEmpty(&policy->ProcList)) {
            PLIST_ENTRY processEntry = RemoveHeadList(&policy->ProcList);
            UfDestroyProcessInfo(CONTAINING_RECORD(
                processEntry,
                UF_PROC_PROCESS_INFO,
                ProcessListEntry));
        }
        InsertTailList(&retiredList, policyEntry);
    }
    while (!IsListEmpty(&gUfProcessDriverContext.OrphanProcList)) {
        PLIST_ENTRY processEntry = RemoveHeadList(&gUfProcessDriverContext.OrphanProcList);
        UfDestroyProcessInfo(CONTAINING_RECORD(
            processEntry,
            UF_PROC_PROCESS_INFO,
            ProcessListEntry));
    }
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    UfFreePolicyList(&retiredList);
    InterlockedExchange(&gUfProcessDriverContext.PolicyCount, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS
UfRemovePolicy(
    _In_ const UF_PROC_REMOVE_POLICY* Request
    )
{
    LIST_ENTRY retiredList;
    ULONG index;

    if (Request->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        Request->Header.Size != sizeof(*Request) ||
        Request->PolicyCount > UF_PROC_MAX_POLICIES || Request->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < Request->PolicyCount; ++index) {
        const UF_PROC_POLICY_NAME* name = &Request->Policies[index];
        if (!UfValidateWireString(
                name->ProcessName,
                name->ProcessNameLengthChars,
                UF_PROC_MAX_PROCESS_NAME_CHARS) || name->Reserved != 0) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    InitializeListHead(&retiredList);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    for (index = 0; index < Request->PolicyCount; ++index) {
        PUF_PROC_POLICY policy = UfFindPolicyLocked(
            Request->Policies[index].ProcessName,
            Request->Policies[index].ProcessNameLengthChars);
        if (policy != NULL) {
            RemoveEntryList(&policy->PolicyListEntry);
            while (!IsListEmpty(&policy->ProcList)) {
                PLIST_ENTRY processEntry = RemoveHeadList(&policy->ProcList);
                UfDestroyProcessInfo(CONTAINING_RECORD(
                    processEntry,
                    UF_PROC_PROCESS_INFO,
                    ProcessListEntry));
            }
            InsertTailList(&retiredList, &policy->PolicyListEntry);
        }
        {
            PLIST_ENTRY orphanEntry = gUfProcessDriverContext.OrphanProcList.Flink;
            while (orphanEntry != &gUfProcessDriverContext.OrphanProcList) {
                PLIST_ENTRY next = orphanEntry->Flink;
                PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
                    orphanEntry,
                    UF_PROC_PROCESS_INFO,
                    ProcessListEntry);
                ULONG processNameLength;
                PCWCHAR processName = UfFindImageNameComponent(
                    processInfo->ProcessPath.Buffer,
                    UfStringLengthChars(&processInfo->ProcessPath),
                    &processNameLength);
                if (UfEqualTextInsensitive(
                        processName,
                        processNameLength,
                        Request->Policies[index].ProcessName,
                        Request->Policies[index].ProcessNameLengthChars)) {
                    RemoveEntryList(orphanEntry);
                    UfDestroyProcessInfo(processInfo);
                }
                orphanEntry = next;
            }
        }
    }
    {
        LONG policyCount = 0;
        PLIST_ENTRY policyEntry;
        for (policyEntry = gUfProcessDriverContext.PolicyListHead.Flink;
             policyEntry != &gUfProcessDriverContext.PolicyListHead;
             policyEntry = policyEntry->Flink) {
            ++policyCount;
        }
        InterlockedExchange(&gUfProcessDriverContext.PolicyCount, policyCount);
    }
    InterlockedIncrement64(&gUfProcessDriverContext.PolicyGeneration);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    UfFreePolicyList(&retiredList);
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
    if (Output == NULL || OutputLength < sizeof(UF_PROC_STATE_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    reply = (PUF_PROC_STATE_REPLY)Output;
    RtlZeroMemory(reply, sizeof(*reply));
    reply->Header.Version = UF_PROC_PROTOCOL_VERSION;
    reply->Header.Size = sizeof(*reply);
    reply->Reserved = UF_PROC_POLICY_DIAGNOSTIC_MAGIC |
        (ULONG)InterlockedCompareExchange(
            &gUfProcessDriverContext.PolicyReplaceStage,
            0,
            0);
    reply->PolicyGeneration = (ULONGLONG)InterlockedCompareExchange64(
        &gUfProcessDriverContext.PolicyGeneration,
        0,
        0);
    /* 진단 상태 조회는 정책/이벤트 락을 절대 획득하지 않습니다. */
    reply->PolicyCount = (ULONG)InterlockedCompareExchange(
        &gUfProcessDriverContext.PolicyCount,
        0,
        0);
    reply->QueueDepth = (ULONG)InterlockedCompareExchange(
        (volatile LONG*)&gUfProcessDriverContext.EventCount,
        0,
        0);
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
UfWaitSignature(
    _Inout_ PIRP Irp,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength
    )
{
    const UF_PROC_WAIT_SIGNATURE* request;
    KIRQL oldIrql;

    if (InputLength != sizeof(UF_PROC_WAIT_SIGNATURE) ||
        OutputLength < sizeof(UF_PROC_SIGNATURE_REQUEST)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    request = (const UF_PROC_WAIT_SIGNATURE*)Irp->AssociatedIrp.SystemBuffer;
    if (request == NULL || request->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        request->Header.Size != sizeof(*request) || request->Reserved != 0 ||
        request->TimeoutMs == 0 || request->TimeoutMs > UF_PROC_SIGNATURE_TIMEOUT_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&gUfProcessDriverContext.SignatureLock, &oldIrql);
    if (gUfProcessDriverContext.SignatureWaitIrp != NULL) {
        KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
        return STATUS_DEVICE_BUSY;
    }
    gUfProcessDriverContext.SignatureWaitIrp = Irp;
    KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
    IoMarkIrpPending(Irp);
    return STATUS_PENDING;
}

static NTSTATUS
UfCompleteSignature(
    _In_ const UF_PROC_SIGNATURE_RESPONSE* Response,
    _In_ ULONG InputLength
    )
{
    KIRQL oldIrql;
    PUF_PROC_SIGNATURE_QUERY query;

    if (InputLength != sizeof(*Response) ||
        Response->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        Response->Header.Size != sizeof(*Response) || Response->Reserved != 0 ||
        (Response->Decision != UfProcSignatureAllow &&
         Response->Decision != UfProcSignatureDeny)) {
        return STATUS_INVALID_PARAMETER;
    }
    KeAcquireSpinLock(&gUfProcessDriverContext.SignatureLock, &oldIrql);
    query = gUfProcessDriverContext.SignatureQuery;
    if (query == NULL || query->RequestId != Response->RequestId) {
        KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
        return STATUS_NOT_FOUND;
    }
    query->Allow = Response->Decision == UfProcSignatureAllow;
    query->Completed = TRUE;
    KeSetEvent(&query->CompletionEvent, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
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
        UfCancelSignatureWait(STATUS_CANCELLED);
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
    case UF_PROC_IOCTL_ADD_POLICY:
        if (buffer == NULL || inputLength != sizeof(UF_PROC_ADD_POLICY)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            status = UfAddPolicy((const UF_PROC_REPLACE_POLICY*)buffer);
        }
        break;
    case UF_PROC_IOCTL_REMOVE_POLICY:
        if (buffer == NULL || inputLength != sizeof(UF_PROC_REMOVE_POLICY)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            status = UfRemovePolicy((const UF_PROC_REMOVE_POLICY*)buffer);
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
    case UF_PROC_IOCTL_WAIT_SIGNATURE:
        status = UfWaitSignature(Irp, inputLength, outputLength);
        if (status == STATUS_PENDING) {
            return status;
        }
        break;
    case UF_PROC_IOCTL_COMPLETE_SIGNATURE:
        if (buffer == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            status = UfCompleteSignature(
                (const UF_PROC_SIGNATURE_RESPONSE*)buffer,
                inputLength);
        }
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
    InitializeListHead(&gUfProcessDriverContext.PolicyListHead);
    InitializeListHead(&gUfProcessDriverContext.OrphanProcList);
    KeInitializeSpinLock(&gUfProcessDriverContext.EventLock);
    KeInitializeSpinLock(&gUfProcessDriverContext.SignatureLock);

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
UfCancelSignatureWait(
    _In_ NTSTATUS Status
    )
{
    PIRP waitIrp;
    PUF_PROC_SIGNATURE_QUERY query;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gUfProcessDriverContext.SignatureLock, &oldIrql);
    waitIrp = gUfProcessDriverContext.SignatureWaitIrp;
    gUfProcessDriverContext.SignatureWaitIrp = NULL;
    query = gUfProcessDriverContext.SignatureQuery;
    if (query != NULL) {
        gUfProcessDriverContext.SignatureQuery = NULL;
        query->Completed = FALSE;
        KeSetEvent(&query->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
    if (waitIrp != NULL) {
        (VOID)UfCompleteIrp(waitIrp, Status, 0);
    }
}

VOID
UfDeleteControlPlane(
    VOID
    )
{
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(UF_PROC_DEVICE_DOS_NAME);
    LIST_ENTRY retiredList;

    UfCancelSignatureWait(STATUS_DELETE_PENDING);
    InterlockedExchange(&gUfProcessDriverContext.ClientConnected, 0);
    if (gUfProcessDriverContext.SymbolicLinkCreated != FALSE) {
        IoDeleteSymbolicLink(&symbolicLink);
        gUfProcessDriverContext.SymbolicLinkCreated = FALSE;
    }
    if (gUfProcessDriverContext.ControlDevice != NULL) {
        IoDeleteDevice(gUfProcessDriverContext.ControlDevice);
        gUfProcessDriverContext.ControlDevice = NULL;
    }

    InitializeListHead(&retiredList);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    while (!IsListEmpty(&gUfProcessDriverContext.PolicyListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&gUfProcessDriverContext.PolicyListHead);
        PUF_PROC_POLICY policy = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        while (!IsListEmpty(&policy->ProcList)) {
            PLIST_ENTRY processEntry = RemoveHeadList(&policy->ProcList);
            UfDestroyProcessInfo(CONTAINING_RECORD(
                processEntry,
                UF_PROC_PROCESS_INFO,
                ProcessListEntry));
        }
        InsertTailList(&retiredList, entry);
    }
    while (!IsListEmpty(&gUfProcessDriverContext.OrphanProcList)) {
        PLIST_ENTRY processEntry = RemoveHeadList(&gUfProcessDriverContext.OrphanProcList);
        UfDestroyProcessInfo(CONTAINING_RECORD(
            processEntry,
            UF_PROC_PROCESS_INFO,
            ProcessListEntry));
    }
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();
    UfFreePolicyList(&retiredList);

    if (gUfProcessDriverContext.EventQueue != NULL) {
        ExFreePoolWithTag(gUfProcessDriverContext.EventQueue, UF_PROC_POOL_TAG);
        gUfProcessDriverContext.EventQueue = NULL;
    }
}

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
    )
{
    PUF_PROC_POLICY policy;
    PCWCHAR image;
    ULONG imageLength;
    ULONG imageNameLength;
    PCWCHAR imageName;
    BOOLEAN pathMatches = TRUE;
    BOOLEAN signRequired = FALSE;
    BOOLEAN fullPathAvailable;

    *RuleId = 0;
    *TrackProcess = FALSE;
    *ProcessNameLengthChars = 0;
    *ProcessPathLengthChars = 0;
    if (ProcessNameCapacity == 0 || ProcessPathCapacity == 0 ||
        CreateInfo->ImageFileName == NULL ||
        CreateInfo->ImageFileName->Buffer == NULL ||
        PsIsProtectedProcess(Process) || PsIsProtectedProcessLight(Process)) {
        return STATUS_SUCCESS;
    }

    image = CreateInfo->ImageFileName->Buffer;
    imageLength = UfStringLengthChars(CreateInfo->ImageFileName);
    fullPathAvailable = CreateInfo->FileOpenNameAvailable != FALSE;
    imageName = UfFindImageNameComponent(image, imageLength, &imageNameLength);
    if (imageNameLength == 0 || imageNameLength >= ProcessNameCapacity ||
        UfIsCriticalImageName(image, imageLength)) {
        return STATUS_SUCCESS;
    }
    RtlCopyMemory(ProcessName, imageName, imageNameLength * sizeof(WCHAR));
    ProcessName[imageNameLength] = L'\0';
    *ProcessNameLengthChars = imageNameLength;

    if (imageLength < ProcessPathCapacity) {
        RtlCopyMemory(ProcessPath, image, imageLength * sizeof(WCHAR));
        ProcessPath[imageLength] = L'\0';
        *ProcessPathLengthChars = imageLength;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gUfProcessDriverContext.PolicyLock);
    policy = UfFindPolicyLocked(ProcessName, *ProcessNameLengthChars);
    if (policy == NULL) {
        ExReleasePushLockShared(&gUfProcessDriverContext.PolicyLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }
    *RuleId = policy->RuleId;
    signRequired = policy->IsSign != 0;
    if (policy->IsCmpFullPath != 0) {
        pathMatches = FALSE;
        if (fullPathAvailable && *ProcessPathLengthChars != 0 &&
            UfEqualTextInsensitive(
                policy->ProcessPath.Buffer,
                UfStringLengthChars(&policy->ProcessPath),
                ProcessPath,
                *ProcessPathLengthChars)) {
            pathMatches = TRUE;
        }
    }
    ExReleasePushLockShared(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();

    if (!pathMatches) {
        return STATUS_ACCESS_DENIED;
    }
    if (signRequired) {
        BOOLEAN allow = FALSE;
        if (!fullPathAvailable || *ProcessPathLengthChars == 0 ||
            !NT_SUCCESS(UfRequestSignatureDecision(
                PsGetProcessId(Process),
                ProcessPath,
                *ProcessPathLengthChars,
                &allow)) || !allow) {
            return STATUS_ACCESS_DENIED;
        }
    }
    *TrackProcess = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS
UfTrackProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ ULONG RuleId,
    _In_reads_(ProcessNameLengthChars) PCWCHAR ProcessName,
    _In_ ULONG ProcessNameLengthChars,
    _In_reads_(ProcessPathLengthChars) PCWCHAR ProcessPath,
    _In_ ULONG ProcessPathLengthChars
    )
{
    PUF_PROC_PROCESS_INFO processInfo;
    PUF_PROC_POLICY policy;
    NTSTATUS status;

    processInfo = (PUF_PROC_PROCESS_INFO)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*processInfo),
        UF_PROC_POOL_TAG);
    if (processInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(processInfo, sizeof(*processInfo));
    InitializeListHead(&processInfo->ProcessListEntry);
    processInfo->ProcessId = ProcessId;
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        UF_PROC_PROCESS_QUERY_LIMITED_INFORMATION | UF_PROC_PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &processInfo->ProcessHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(processInfo, UF_PROC_POOL_TAG);
        return status;
    }
    ObReferenceObject(Process);
    processInfo->ProcessObject = Process;
    status = UfCopyWireString(
        ProcessPath,
        ProcessPathLengthChars,
        &processInfo->ProcessPath);
    if (!NT_SUCCESS(status)) {
        UfDestroyProcessInfo(processInfo);
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    policy = UfFindPolicyLocked(ProcessName, ProcessNameLengthChars);
    if (policy == NULL) {
        ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
        KeLeaveCriticalRegion();
        UfDestroyProcessInfo(processInfo);
        return STATUS_NOT_FOUND;
    }
    processInfo->Policy = policy;
    InsertTailList(&policy->ProcList, &processInfo->ProcessListEntry);
    UNREFERENCED_PARAMETER(RuleId);
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

VOID
UfRemoveTrackedProcess(
    _In_ HANDLE ProcessId
    )
{
    PUF_PROC_PROCESS_INFO found = NULL;
    PLIST_ENTRY entry;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    for (entry = gUfProcessDriverContext.PolicyListHead.Flink;
         entry != &gUfProcessDriverContext.PolicyListHead && found == NULL;
         entry = entry->Flink) {
        PUF_PROC_POLICY policy = CONTAINING_RECORD(entry, UF_PROC_POLICY, PolicyListEntry);
        PLIST_ENTRY processEntry;
        for (processEntry = policy->ProcList.Flink;
             processEntry != &policy->ProcList;
             processEntry = processEntry->Flink) {
            PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
                processEntry,
                UF_PROC_PROCESS_INFO,
                ProcessListEntry);
            if (processInfo->ProcessId == ProcessId) {
                RemoveEntryList(processEntry);
                found = processInfo;
                break;
            }
        }
    }
    if (found == NULL) {
        for (entry = gUfProcessDriverContext.OrphanProcList.Flink;
             entry != &gUfProcessDriverContext.OrphanProcList;
             entry = entry->Flink) {
            PUF_PROC_PROCESS_INFO processInfo = CONTAINING_RECORD(
                entry,
                UF_PROC_PROCESS_INFO,
                ProcessListEntry);
            if (processInfo->ProcessId == ProcessId) {
                RemoveEntryList(entry);
                found = processInfo;
                break;
            }
        }
    }
    ExReleasePushLockExclusive(&gUfProcessDriverContext.PolicyLock);
    KeLeaveCriticalRegion();
    if (found != NULL) {
        UfDestroyProcessInfo(found);
    }
}

NTSTATUS
UfRequestSignatureDecision(
    _In_ HANDLE ProcessId,
    _In_reads_(PathLengthChars) PCWCHAR ProcessPath,
    _In_ ULONG PathLengthChars,
    _Out_ PBOOLEAN Allow
    )
{
    PUF_PROC_SIGNATURE_QUERY query;
    PIRP waitIrp;
    KIRQL oldIrql;
    NTSTATUS status;
    LARGE_INTEGER timeout;

    *Allow = FALSE;
    if (PathLengthChars == 0 || PathLengthChars >= UF_PROC_MAX_PROCESS_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    query = (PUF_PROC_SIGNATURE_QUERY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*query),
        UF_PROC_POOL_TAG);
    if (query == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(query, sizeof(*query));
    query->RequestId = (ULONGLONG)InterlockedIncrement64(
        &gUfProcessDriverContext.SignatureRequestSequence);
    query->ProcessId = ProcessId;
    query->PathLengthChars = PathLengthChars;
    RtlCopyMemory(query->ProcessPath, ProcessPath, PathLengthChars * sizeof(WCHAR));
    query->ProcessPath[PathLengthChars] = L'\0';
    KeInitializeEvent(&query->CompletionEvent, NotificationEvent, FALSE);

    KeAcquireSpinLock(&gUfProcessDriverContext.SignatureLock, &oldIrql);
    waitIrp = gUfProcessDriverContext.SignatureWaitIrp;
    if (InterlockedCompareExchange(
            &gUfProcessDriverContext.ClientConnected,
            0,
            0) == 0 || waitIrp == NULL || gUfProcessDriverContext.SignatureQuery != NULL) {
        KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
        ExFreePoolWithTag(query, UF_PROC_POOL_TAG);
        return STATUS_ACCESS_DENIED;
    }
    gUfProcessDriverContext.SignatureWaitIrp = NULL;
    gUfProcessDriverContext.SignatureQuery = query;
    {
        PUF_PROC_SIGNATURE_REQUEST output =
            (PUF_PROC_SIGNATURE_REQUEST)waitIrp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(output, sizeof(*output));
        output->Header.Version = UF_PROC_PROTOCOL_VERSION;
        output->Header.Size = sizeof(*output);
        output->RequestId = query->RequestId;
        output->ProcessId = HandleToULong(ProcessId);
        output->PathLengthChars = PathLengthChars;
        RtlCopyMemory(
            output->ProcessPath,
            query->ProcessPath,
            PathLengthChars * sizeof(WCHAR));
        waitIrp->IoStatus.Status = STATUS_SUCCESS;
        waitIrp->IoStatus.Information = sizeof(*output);
    }
    KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
    IoCompleteRequest(waitIrp, IO_NO_INCREMENT);

    timeout.QuadPart = -((LONGLONG)UF_PROC_SIGNATURE_TIMEOUT_MS * 10000);
    status = KeWaitForSingleObject(
        &query->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);
    KeAcquireSpinLock(&gUfProcessDriverContext.SignatureLock, &oldIrql);
    if (gUfProcessDriverContext.SignatureQuery == query) {
        gUfProcessDriverContext.SignatureQuery = NULL;
    }
    if (status == STATUS_SUCCESS && query->Completed) {
        *Allow = query->Allow;
        status = *Allow ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    } else {
        status = STATUS_TIMEOUT;
    }
    KeReleaseSpinLock(&gUfProcessDriverContext.SignatureLock, oldIrql);
    ExFreePoolWithTag(query, UF_PROC_POOL_TAG);
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
            0) == 0 || gUfProcessDriverContext.EventQueue == NULL) {
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
        imageLengthChars = UfStringLengthChars(ImageName);
        if (imageLengthChars >= UF_PROC_MAX_IMAGE_CHARS) {
            imageLengthChars = UF_PROC_MAX_IMAGE_CHARS - 1;
        }
        RtlCopyMemory(event.Image, ImageName->Buffer, imageLengthChars * sizeof(WCHAR));
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
