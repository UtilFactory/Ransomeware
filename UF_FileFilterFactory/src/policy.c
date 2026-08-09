#include "driver.h"

UF_POLICY gUfPolicy;
UF_PROCESS_TRUST_ENTRY gUfTrustEntries[UF_MAX_PROCESS_TRUST_ENTRIES];

static BOOLEAN
UfEqualImageRule(
    _In_ PCUNICODE_STRING ImageName,
    _In_reads_(ImageLengthChars) const WCHAR* Image,
    _In_ ULONG ImageLengthChars)
{
    UNICODE_STRING configured;

    configured.Buffer = (PWCH)Image;
    configured.Length = (USHORT)(ImageLengthChars * sizeof(WCHAR));
    configured.MaximumLength = configured.Length;
    return RtlEqualUnicodeString(ImageName, &configured, TRUE);
}

static BOOLEAN
UfPathIsUnderRule(_In_ PCUNICODE_STRING FileName, _In_ const UF_PATH_RULE_V2* Rule)
{
    UNICODE_STRING prefix;
    USHORT prefixBytes;

    prefixBytes = (USHORT)(Rule->PathLengthChars * sizeof(WCHAR));
    if (FileName->Length < prefixBytes) {
        return FALSE;
    }
    prefix.Buffer = (PWCH)Rule->Path;
    prefix.Length = prefixBytes;
    prefix.MaximumLength = prefixBytes;
    if (!RtlPrefixUnicodeString(&prefix, FileName, TRUE)) {
        return FALSE;
    }
    if (FileName->Length == prefixBytes) {
        return TRUE;
    }
    return FileName->Buffer[Rule->PathLengthChars] == L'\\';
}

static const UF_PATH_RULE_V2*
UfFindPathRuleByIdLocked(_In_ ULONG RuleId)
{
    ULONG index;
    for (index = 0; index < gUfPolicy.PathRuleCount; ++index) {
        if (gUfPolicy.PathRules[index].RuleId == RuleId) {
            return &gUfPolicy.PathRules[index];
        }
    }
    return NULL;
}

static const UF_SIGNER_RULE*
UfFindSignerRuleByIdLocked(_In_ ULONG RuleId)
{
    ULONG index;
    for (index = 0; index < gUfPolicy.SignerRuleCount; ++index) {
        if (gUfPolicy.Signers[index].RuleId == RuleId) {
            return &gUfPolicy.Signers[index];
        }
    }
    return NULL;
}

static const UF_PROTECTED_PROCESS_RULE*
UfFindProcessRuleByIdLocked(_In_ ULONG RuleId)
{
    ULONG index;
    for (index = 0; index < gUfPolicy.ProtectedProcessRuleCount; ++index) {
        if (gUfPolicy.ProtectedProcesses[index].RuleId == RuleId) {
            return &gUfPolicy.ProtectedProcesses[index];
        }
    }
    return NULL;
}

static UF_PROCESS_TRUST_ENTRY*
UfFindTrustEntryLocked(
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessCreateTime,
    _In_ ULONG ProcessRuleId)
{
    ULONG index;
    for (index = 0; index < UF_MAX_PROCESS_TRUST_ENTRIES; ++index) {
        UF_PROCESS_TRUST_ENTRY* entry = &gUfTrustEntries[index];
        if (entry->InUse &&
            entry->PolicyGeneration == gUfPolicy.Generation &&
            entry->ProcessId == ProcessId &&
            entry->ProcessCreateTime == ProcessCreateTime &&
            entry->ProcessRuleId == ProcessRuleId) {
            return entry;
        }
    }
    return NULL;
}

static UF_PROCESS_TRUST_ENTRY*
UfAllocateTrustEntryLocked(VOID)
{
    ULONG index;
    ULONG oldestIndex = 0;
    ULONGLONG oldestTime = MAXULONGLONG;

    for (index = 0; index < UF_MAX_PROCESS_TRUST_ENTRIES; ++index) {
        if (!gUfTrustEntries[index].InUse) {
            return &gUfTrustEntries[index];
        }
        if (gUfTrustEntries[index].LastRequestTime < oldestTime) {
            oldestTime = gUfTrustEntries[index].LastRequestTime;
            oldestIndex = index;
        }
    }
    return &gUfTrustEntries[oldestIndex];
}

VOID
UfPolicyInitialize(VOID)
{
    RtlZeroMemory(&gUfPolicy, sizeof(gUfPolicy));
    RtlZeroMemory(gUfTrustEntries, sizeof(gUfTrustEntries));
    ExInitializePushLock(&gUfPolicy.Lock);
}

VOID
UfPolicyClear(VOID)
{
    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    ++gUfPolicy.Generation;
    gUfPolicy.PathRuleCount = 0;
    gUfPolicy.MonitorExceptionCount = 0;
    gUfPolicy.ProtectedProcessRuleCount = 0;
    gUfPolicy.SignerRuleCount = 0;
    RtlZeroMemory(&gUfPolicy.Revocation, sizeof(gUfPolicy.Revocation));
    RtlZeroMemory(gUfPolicy.PathRules, sizeof(gUfPolicy.PathRules));
    RtlZeroMemory(gUfPolicy.MonitorExceptions, sizeof(gUfPolicy.MonitorExceptions));
    RtlZeroMemory(gUfPolicy.ProtectedProcesses, sizeof(gUfPolicy.ProtectedProcesses));
    RtlZeroMemory(gUfPolicy.Signers, sizeof(gUfPolicy.Signers));
    RtlZeroMemory(gUfTrustEntries, sizeof(gUfTrustEntries));
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
}

static NTSTATUS
UfValidatePolicyRequest(_In_ const UF_REPLACE_POLICY_V2* Request)
{
    ULONG index;
    ULONG other;

    if (Request->PolicyGeneration == 0 ||
        Request->PathRuleCount > UF_MAX_RULES ||
        Request->MonitorExceptionCount > UF_MAX_RULES ||
        Request->ProtectedProcessRuleCount > UF_MAX_PROTECTED_PROCESS_RULES ||
        Request->SignerRuleCount > UF_MAX_SIGNER_RULES ||
        Request->Revocation.TimeoutMilliseconds > 60000 ||
        Request->Revocation.TimeoutAction > UfRevocationTimeoutAllowLocalTrust) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->PathRuleCount; ++index) {
        const UF_PATH_RULE_V2* rule = &Request->PathRules[index];
        if (rule->RuleId == 0 || rule->PathLengthChars == 0 ||
            rule->PathLengthChars >= UF_MAX_PATH_CHARS ||
            rule->Path[rule->PathLengthChars] != L'\0' ||
            (rule->Mode != UfRuleMonitor && rule->Mode != UfRuleProtected)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (other = 0; other < index; ++other) {
            if (Request->PathRules[other].RuleId == rule->RuleId) {
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }
    for (index = 0; index < Request->MonitorExceptionCount; ++index) {
        const UF_IMAGE_RULE* rule = &Request->MonitorExceptions[index];
        if (rule->ImageLengthChars == 0 ||
            rule->ImageLengthChars >= UF_MAX_IMAGE_CHARS ||
            rule->Image[rule->ImageLengthChars] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
    }
    for (index = 0; index < Request->SignerRuleCount; ++index) {
        const UF_SIGNER_RULE* signer = &Request->Signers[index];
        if (signer->RuleId == 0 ||
            (signer->MatchType != UfSignerMatchThumbprintSha256 &&
             signer->MatchType != UfSignerMatchIssuerSha256AndSerial) ||
            (signer->MatchType == UfSignerMatchIssuerSha256AndSerial &&
             (signer->SerialLengthBytes == 0 ||
              signer->SerialLengthBytes > UF_CERT_SERIAL_BYTES))) {
            return STATUS_INVALID_PARAMETER;
        }
        for (other = 0; other < index; ++other) {
            if (Request->Signers[other].RuleId == signer->RuleId) {
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }
    for (index = 0; index < Request->ProtectedProcessRuleCount; ++index) {
        const UF_PROTECTED_PROCESS_RULE* processRule = &Request->ProtectedProcesses[index];
        BOOLEAN folderFound = FALSE;
        BOOLEAN signerFound = FALSE;

        if (processRule->RuleId == 0 || processRule->FolderRuleId == 0 ||
            processRule->SignerRuleId == 0 ||
            processRule->Access == PF_ACCESS_NONE ||
            FlagOn(processRule->Access, (USHORT)~PF_ACCESS_ALL) ||
            processRule->ImageLengthChars == 0 ||
            processRule->ImageLengthChars >= UF_MAX_IMAGE_CHARS ||
            processRule->Image[processRule->ImageLengthChars] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
        for (other = 0; other < Request->PathRuleCount; ++other) {
            if (Request->PathRules[other].RuleId == processRule->FolderRuleId &&
                Request->PathRules[other].Mode == UfRuleProtected) {
                folderFound = TRUE;
                break;
            }
        }
        for (other = 0; other < Request->SignerRuleCount; ++other) {
            if (Request->Signers[other].RuleId == processRule->SignerRuleId) {
                signerFound = TRUE;
                break;
            }
        }
        if (!folderFound || !signerFound) {
            return STATUS_NOT_FOUND;
        }
        for (other = 0; other < index; ++other) {
            if (Request->ProtectedProcesses[other].RuleId == processRule->RuleId) {
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
UfPolicyReplace(_In_ const UF_REPLACE_POLICY_V2* Request)
{
    NTSTATUS status = UfValidatePolicyRequest(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    gUfPolicy.Generation = Request->PolicyGeneration;
    gUfPolicy.PathRuleCount = Request->PathRuleCount;
    gUfPolicy.MonitorExceptionCount = Request->MonitorExceptionCount;
    gUfPolicy.ProtectedProcessRuleCount = Request->ProtectedProcessRuleCount;
    gUfPolicy.SignerRuleCount = Request->SignerRuleCount;
    gUfPolicy.Revocation = Request->Revocation;
    RtlCopyMemory(gUfPolicy.PathRules, Request->PathRules, sizeof(gUfPolicy.PathRules));
    RtlCopyMemory(gUfPolicy.MonitorExceptions, Request->MonitorExceptions, sizeof(gUfPolicy.MonitorExceptions));
    RtlCopyMemory(gUfPolicy.ProtectedProcesses, Request->ProtectedProcesses, sizeof(gUfPolicy.ProtectedProcesses));
    RtlCopyMemory(gUfPolicy.Signers, Request->Signers, sizeof(gUfPolicy.Signers));
    RtlZeroMemory(gUfTrustEntries, sizeof(gUfTrustEntries));
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
    return STATUS_SUCCESS;
}

NTSTATUS
UfPolicySetProcessTrust(_In_ const UF_PROCESS_TRUST_UPDATE* Update)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING processImage = NULL;
    const UF_PROTECTED_PROCESS_RULE* processRule;
    const UF_SIGNER_RULE* signerRule;
    UF_PROCESS_TRUST_ENTRY* entry;

    if (Update->Decision < UfTrustAllow || Update->Decision > UfTrustInvalidate ||
        Update->Access == PF_ACCESS_NONE ||
        FlagOn(Update->Access, (USHORT)~PF_ACCESS_ALL) ||
        Update->SerialLengthBytes > UF_CERT_SERIAL_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Update->ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(process) != Update->ProcessCreateTime) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    status = SeLocateProcessImageName(process, &processImage);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    processRule = UfFindProcessRuleByIdLocked(Update->ProcessRuleId);
    signerRule = processRule == NULL
        ? NULL : UfFindSignerRuleByIdLocked(processRule->SignerRuleId);
    if (Update->PolicyGeneration != gUfPolicy.Generation || processRule == NULL ||
        signerRule == NULL ||
        !UfEqualImageRule(processImage, processRule->Image, processRule->ImageLengthChars) ||
        !FlagOn(processRule->Access, Update->Access) ||
        (signerRule->MatchType == UfSignerMatchThumbprintSha256 &&
         RtlCompareMemory(
             signerRule->ThumbprintSha256,
             Update->ImageIdentitySha256,
             UF_CERT_SHA256_BYTES) != UF_CERT_SHA256_BYTES) ||
        (signerRule->MatchType == UfSignerMatchIssuerSha256AndSerial &&
         (Update->SerialLengthBytes == 0 ||
          RtlCompareMemory(
              signerRule->IssuerSha256,
              Update->IssuerIdentitySha256,
              UF_CERT_SHA256_BYTES) != UF_CERT_SHA256_BYTES ||
          signerRule->SerialLengthBytes != Update->SerialLengthBytes ||
          RtlCompareMemory(
              signerRule->SerialNumber,
              Update->SerialNumber,
              signerRule->SerialLengthBytes) != signerRule->SerialLengthBytes))) {
        status = STATUS_REVISION_MISMATCH;
        goto Exit;
    }

    entry = UfFindTrustEntryLocked(
        Update->ProcessId, Update->ProcessCreateTime, Update->ProcessRuleId);
    if (Update->Decision == UfTrustInvalidate) {
        if (entry != NULL) {
            RtlZeroMemory(entry, sizeof(*entry));
        }
        status = STATUS_SUCCESS;
        goto Exit;
    }
    if (entry == NULL) {
        entry = UfAllocateTrustEntryLocked();
    }
    RtlZeroMemory(entry, sizeof(*entry));
    entry->InUse = TRUE;
    entry->Decision = (UCHAR)Update->Decision;
    entry->Access = Update->Access;
    entry->ProcessId = Update->ProcessId;
    entry->ProcessRuleId = Update->ProcessRuleId;
    entry->ProcessCreateTime = Update->ProcessCreateTime;
    entry->PolicyGeneration = Update->PolicyGeneration;
    entry->LastRequestTime = KeQueryInterruptTime();
    entry->Temporary = Update->Temporary != 0;
    RtlCopyMemory(
        entry->ImageIdentitySha256,
        Update->ImageIdentitySha256,
        sizeof(entry->ImageIdentitySha256));
    RtlCopyMemory(
        entry->IssuerIdentitySha256,
        Update->IssuerIdentitySha256,
        sizeof(entry->IssuerIdentitySha256));
    RtlCopyMemory(
        entry->SerialNumber,
        Update->SerialNumber,
        sizeof(entry->SerialNumber));
    entry->SerialLengthBytes = Update->SerialLengthBytes;
    status = STATUS_SUCCESS;

Exit:
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
    ExFreePool(processImage);
    ObDereferenceObject(process);
    return status;
}

VOID
UfPolicyQuery(_Out_ UF_STATE_REPLY_V2* Reply)
{
    ULONG index;
    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->Version = UF_PROTOCOL_VERSION;
    Reply->Size = sizeof(*Reply);
    ExAcquirePushLockShared(&gUfPolicy.Lock);
    Reply->PathRuleCount = gUfPolicy.PathRuleCount;
    Reply->MonitorExceptionCount = gUfPolicy.MonitorExceptionCount;
    Reply->ProtectedProcessRuleCount = gUfPolicy.ProtectedProcessRuleCount;
    Reply->SignerRuleCount = gUfPolicy.SignerRuleCount;
    Reply->PolicyGeneration = gUfPolicy.Generation;
    for (index = 0; index < UF_MAX_PROCESS_TRUST_ENTRIES; ++index) {
        if (gUfTrustEntries[index].InUse) {
            ++Reply->ProcessTrustEntryCount;
        }
    }
    ExReleasePushLockShared(&gUfPolicy.Lock);
    Reply->Connected = gUfClientPort != NULL;
}

VOID
UfPolicyEvaluate(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessCreateTime,
    _In_ USHORT RequestedAccess,
    _Out_ UF_POLICY_EVALUATION* Evaluation)
{
    ULONG index;
    ULONG bestPathLength = 0;
    const UF_PATH_RULE_V2* folderRule = NULL;

    RtlZeroMemory(Evaluation, sizeof(*Evaluation));
    Evaluation->RequestedAccess = RequestedAccess;
    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    for (index = 0; index < gUfPolicy.PathRuleCount; ++index) {
        if (gUfPolicy.PathRules[index].PathLengthChars >= bestPathLength &&
            UfPathIsUnderRule(FileName, &gUfPolicy.PathRules[index])) {
            folderRule = &gUfPolicy.PathRules[index];
            bestPathLength = gUfPolicy.PathRules[index].PathLengthChars;
        }
    }
    if (folderRule == NULL) {
        goto Exit;
    }

    Evaluation->Matched = TRUE;
    Evaluation->FolderRuleId = folderRule->RuleId;
    Evaluation->PolicyGeneration = gUfPolicy.Generation;
    if (folderRule->Mode == UfRuleMonitor) {
        Evaluation->MonitorOnly = TRUE;
        for (index = 0; index < gUfPolicy.MonitorExceptionCount; ++index) {
            const UF_IMAGE_RULE* exception = &gUfPolicy.MonitorExceptions[index];
            if (UfEqualImageRule(ImageName, exception->Image, exception->ImageLengthChars)) {
                Evaluation->Matched = FALSE;
                break;
            }
        }
        goto Exit;
    }

    for (index = 0; index < gUfPolicy.ProtectedProcessRuleCount; ++index) {
        const UF_PROTECTED_PROCESS_RULE* processRule = &gUfPolicy.ProtectedProcesses[index];
        UF_PROCESS_TRUST_ENTRY* entry;
        ULONGLONG now;

        if (processRule->FolderRuleId != folderRule->RuleId ||
            !UfEqualImageRule(ImageName, processRule->Image, processRule->ImageLengthChars)) {
            continue;
        }
        Evaluation->ProcessRuleMatched = TRUE;
        Evaluation->ProcessRuleId = processRule->RuleId;
        if (!FlagOn(processRule->Access, RequestedAccess)) {
            Evaluation->TrustDecision = UfTrustDeny;
            goto Exit;
        }

        entry = UfFindTrustEntryLocked(ProcessId, ProcessCreateTime, processRule->RuleId);
        if (entry != NULL && FlagOn(entry->Access, RequestedAccess)) {
            Evaluation->TrustDecision = entry->Decision;
            goto Exit;
        }

        Evaluation->NeedsTrustValidation = TRUE;
        now = KeQueryInterruptTime();
        if (entry == NULL) {
            entry = UfAllocateTrustEntryLocked();
            RtlZeroMemory(entry, sizeof(*entry));
            entry->InUse = TRUE;
            entry->Decision = UfTrustUnknown;
            entry->Access = processRule->Access;
            entry->ProcessId = ProcessId;
            entry->ProcessRuleId = processRule->RuleId;
            entry->ProcessCreateTime = ProcessCreateTime;
            entry->PolicyGeneration = gUfPolicy.Generation;
            Evaluation->ShouldNotifyTrust = TRUE;
        } else if (now - entry->LastRequestTime >= 2ULL * 1000ULL * 1000ULL * 10ULL) {
            Evaluation->ShouldNotifyTrust = TRUE;
        }
        if (Evaluation->ShouldNotifyTrust) {
            entry->LastRequestTime = now;
        }
        goto Exit;
    }

    Evaluation->TrustDecision = UfTrustDeny;

Exit:
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
}
