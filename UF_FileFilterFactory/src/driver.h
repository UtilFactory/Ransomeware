#pragma once

#include <fltKernel.h>
#include "../include/uf_filefilter_protocol.h"

#define UF_POOL_TAG 'FtFU'

typedef struct _UF_POLICY {
    EX_PUSH_LOCK Lock;
    ULONG PathRuleCount;
    ULONG MonitorExceptionCount;
    ULONG AllowedImageCount;
    UF_PATH_RULE PathRules[UF_MAX_RULES];
    UF_IMAGE_RULE MonitorExceptions[UF_MAX_RULES];
    UF_IMAGE_RULE AllowedImages[UF_MAX_RULES];
} UF_POLICY;

extern PFLT_FILTER gUfFilter;
extern PFLT_PORT gUfServerPort;
extern PFLT_PORT gUfClientPort;
extern UF_POLICY gUfPolicy;

VOID UfPolicyInitialize(VOID);
NTSTATUS UfPolicyReplace(_In_ const UF_REPLACE_POLICY* Request);
VOID UfPolicyClear(VOID);
VOID UfPolicyQuery(_Out_ UF_STATE_REPLY* Reply);
BOOLEAN UfPolicyEvaluate(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _Out_ UF_RULE_MODE* MatchedMode);

