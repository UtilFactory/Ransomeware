#include "driver.h"

UF_POLICY gUfPolicy;

static BOOLEAN
UfEqualImage(_In_ PCUNICODE_STRING ImageName, _In_ const UF_IMAGE_RULE* Rule)
{
    UNICODE_STRING configured;
    configured.Buffer = (PWCH)Rule->Image;
    configured.Length = (USHORT)(Rule->ImageLengthChars * sizeof(WCHAR));
    configured.MaximumLength = configured.Length;
    return RtlEqualUnicodeString(ImageName, &configured, TRUE);
}

static BOOLEAN
UfPathIsUnderRule(_In_ PCUNICODE_STRING FileName, _In_ const UF_PATH_RULE* Rule)
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

VOID
UfPolicyInitialize(VOID)
{
    RtlZeroMemory(&gUfPolicy, sizeof(gUfPolicy));
    ExInitializePushLock(&gUfPolicy.Lock);
}

VOID
UfPolicyClear(VOID)
{
    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    gUfPolicy.PathRuleCount = 0;
    gUfPolicy.MonitorExceptionCount = 0;
    gUfPolicy.AllowedImageCount = 0;
    RtlZeroMemory(gUfPolicy.PathRules, sizeof(gUfPolicy.PathRules));
    RtlZeroMemory(gUfPolicy.MonitorExceptions, sizeof(gUfPolicy.MonitorExceptions));
    RtlZeroMemory(gUfPolicy.AllowedImages, sizeof(gUfPolicy.AllowedImages));
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
}

NTSTATUS
UfPolicyReplace(_In_ const UF_REPLACE_POLICY* Request)
{
    ULONG index;

    if (Request->PathRuleCount > UF_MAX_RULES ||
        Request->MonitorExceptionCount > UF_MAX_RULES ||
        Request->AllowedImageCount > UF_MAX_RULES) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->PathRuleCount; ++index) {
        if (Request->PathRules[index].PathLengthChars == 0 ||
            Request->PathRules[index].PathLengthChars >= UF_MAX_PATH_CHARS ||
            (Request->PathRules[index].Mode != UfRuleMonitor &&
             Request->PathRules[index].Mode != UfRuleAllowList)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    for (index = 0; index < Request->MonitorExceptionCount; ++index) {
        if (Request->MonitorExceptions[index].ImageLengthChars == 0 ||
            Request->MonitorExceptions[index].ImageLengthChars >= UF_MAX_IMAGE_CHARS) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    for (index = 0; index < Request->AllowedImageCount; ++index) {
        if (Request->AllowedImages[index].ImageLengthChars == 0 ||
            Request->AllowedImages[index].ImageLengthChars >= UF_MAX_IMAGE_CHARS) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    ExAcquirePushLockExclusive(&gUfPolicy.Lock);
    gUfPolicy.PathRuleCount = Request->PathRuleCount;
    gUfPolicy.MonitorExceptionCount = Request->MonitorExceptionCount;
    gUfPolicy.AllowedImageCount = Request->AllowedImageCount;
    RtlCopyMemory(gUfPolicy.PathRules, Request->PathRules, sizeof(gUfPolicy.PathRules));
    RtlCopyMemory(gUfPolicy.MonitorExceptions, Request->MonitorExceptions, sizeof(gUfPolicy.MonitorExceptions));
    RtlCopyMemory(gUfPolicy.AllowedImages, Request->AllowedImages, sizeof(gUfPolicy.AllowedImages));
    ExReleasePushLockExclusive(&gUfPolicy.Lock);
    return STATUS_SUCCESS;
}

VOID
UfPolicyQuery(_Out_ UF_STATE_REPLY* Reply)
{
    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->Version = UF_PROTOCOL_VERSION;
    Reply->Size = sizeof(*Reply);
    ExAcquirePushLockShared(&gUfPolicy.Lock);
    Reply->PathRuleCount = gUfPolicy.PathRuleCount;
    Reply->MonitorExceptionCount = gUfPolicy.MonitorExceptionCount;
    Reply->AllowedImageCount = gUfPolicy.AllowedImageCount;
    ExReleasePushLockShared(&gUfPolicy.Lock);
    Reply->Connected = gUfClientPort != NULL;
}

BOOLEAN
UfPolicyEvaluate(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _Out_ UF_RULE_MODE* MatchedMode)
{
    ULONG index;
    BOOLEAN matched = FALSE;

    *MatchedMode = UfRuleMonitor;
    ExAcquirePushLockShared(&gUfPolicy.Lock);
    for (index = 0; index < gUfPolicy.PathRuleCount; ++index) {
        const UF_PATH_RULE* rule = &gUfPolicy.PathRules[index];
        if (!UfPathIsUnderRule(FileName, rule)) {
            continue;
        }

        *MatchedMode = (UF_RULE_MODE)rule->Mode;
        matched = TRUE;
        if (rule->Mode == UfRuleMonitor) {
            ULONG imageIndex;
            for (imageIndex = 0; imageIndex < gUfPolicy.MonitorExceptionCount; ++imageIndex) {
                if (UfEqualImage(ImageName, &gUfPolicy.MonitorExceptions[imageIndex])) {
                    matched = FALSE;
                    break;
                }
            }
        } else {
            ULONG imageIndex;
            matched = TRUE;
            for (imageIndex = 0; imageIndex < gUfPolicy.AllowedImageCount; ++imageIndex) {
                if (UfEqualImage(ImageName, &gUfPolicy.AllowedImages[imageIndex])) {
                    matched = FALSE;
                    break;
                }
            }
        }
        break;
    }
    ExReleasePushLockShared(&gUfPolicy.Lock);
    return matched;
}
