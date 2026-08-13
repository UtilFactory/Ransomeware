#pragma once

#include <fltKernel.h>
#include "../include/uf_filefilter_protocol.h"

#define UF_POOL_TAG 'FtFU'

typedef struct _UF_POLICY {
    EX_PUSH_LOCK Lock;
    ULONGLONG Generation;
    ULONG PathRuleCount;
    ULONG MonitorExceptionCount;
    ULONG ProtectedProcessRuleCount;
    ULONG SignerRuleCount;
    UF_REVOCATION_POLICY Revocation;
    UF_PATH_RULE_V2 PathRules[UF_MAX_RULES];
    UF_IMAGE_RULE MonitorExceptions[UF_MAX_RULES];
    UF_PROTECTED_PROCESS_RULE ProtectedProcesses[UF_MAX_PROTECTED_PROCESS_RULES];
    UF_SIGNER_RULE Signers[UF_MAX_SIGNER_RULES];
} UF_POLICY;

typedef struct _UF_PROCESS_TRUST_ENTRY {
    BOOLEAN InUse;
    UCHAR Decision;
    USHORT Access;
    ULONG ProcessId;
    ULONG ProcessRuleId;
    ULONGLONG ProcessCreateTime;
    ULONGLONG PolicyGeneration;
    ULONGLONG LastRequestTime;
    BOOLEAN Temporary;
    UCHAR Reserved[7];
    UCHAR ImageIdentitySha256[UF_CERT_SHA256_BYTES];
    UCHAR IssuerIdentitySha256[UF_CERT_SHA256_BYTES];
    UCHAR SerialNumber[UF_CERT_SERIAL_BYTES];
    ULONG SerialLengthBytes;
} UF_PROCESS_TRUST_ENTRY;

typedef struct _UF_POLICY_EVALUATION {
    BOOLEAN Matched;
    BOOLEAN MonitorOnly;
    BOOLEAN ProcessRuleMatched;
    BOOLEAN NeedsTrustValidation;
    BOOLEAN ShouldNotifyTrust;
    UCHAR TrustDecision;
    USHORT RequestedAccess;
    ULONG FolderRuleId;
    ULONG ProcessRuleId;
    ULONGLONG PolicyGeneration;
} UF_POLICY_EVALUATION;

extern PFLT_FILTER gUfFilter;
extern PFLT_PORT gUfServerPort;
extern PFLT_PORT gUfClientPort;
extern UF_POLICY gUfPolicy;
extern UF_PROCESS_TRUST_ENTRY gUfTrustEntries[UF_MAX_PROCESS_TRUST_ENTRIES];

VOID UfPolicyInitialize(VOID);
NTSTATUS UfPolicyReplace(_In_ const UF_REPLACE_POLICY_V2* Request);
NTSTATUS UfPolicySetProcessTrust(_In_ const UF_PROCESS_TRUST_UPDATE* Update);
VOID UfPolicyClear(VOID);
VOID UfPolicyQuery(_Out_ UF_STATE_REPLY_V2* Reply);
VOID UfPolicyEvaluate(
    _In_ PCUNICODE_STRING FileName,
    _In_ PCUNICODE_STRING ImageName,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessCreateTime,
    _In_ USHORT RequestedAccess,
    _Out_ UF_POLICY_EVALUATION* Evaluation);

