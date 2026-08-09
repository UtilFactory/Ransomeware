#pragma once

/*
 * UF_FileFilterFactory.sys와 추후 제작할 uf_fltwarp.dll이 함께 사용하는
 * 통신 규약입니다. 모든 구조체는 고정 크기 필드와 버전 헤더를 사용합니다.
 * 드라이버에 전달하는 경로는 다음과 같은 정규화된 NT 경로여야 합니다.
 *   \Device\HarddiskVolume3\Protected
 */

#define UF_PROTOCOL_VERSION                    2u
#define UF_LEGACY_PUBLIC_VERSION               1u
#define UF_FILTER_PORT_NAME                    L"\\UF_FileFilterFactoryPort"
#define UF_MAX_RULES                           64u
#define UF_MAX_PROTECTED_PROCESS_RULES         128u
#define UF_MAX_SIGNER_RULES                    64u
#define UF_MAX_PATH_CHARS                      520u
#define UF_MAX_IMAGE_CHARS                     260u
#define UF_CERT_SHA256_BYTES                   32u
#define UF_CERT_SERIAL_BYTES                   32u
#define UF_MAX_PROCESS_TRUST_ENTRIES           256u

typedef unsigned short PROTECTED_FOLDER_ACCESS;

#define PF_ACCESS_NONE   ((unsigned short)0x0000)
#define PF_ACCESS_READ   ((unsigned short)0x0001)
#define PF_ACCESS_WRITE  ((unsigned short)0x0002)
#define PF_ACCESS_ALL    ((unsigned short)0x0003)

// 보호 폴더 허용 프로세스 규칙의 서명 확인 플래그입니다.
// SignerRuleId가 0이면 지정한 비교 방식과 접근 권한만 확인합니다.
#define UF_PROCESS_RULE_FLAG_REQUIRE_CODE_SIGNATURE ((unsigned short)0x0001)

// 프로세스 이미지의 마지막 파일 이름만 비교합니다. 플래그가 없으면 전체 경로를 비교합니다.
#define UF_PROCESS_RULE_FLAG_MATCH_IMAGE_NAME       ((unsigned short)0x0002)
#define UF_PROCESS_RULE_FLAG_ALLOWED_MASK           ((unsigned short)(UF_PROCESS_RULE_FLAG_REQUIRE_CODE_SIGNATURE | UF_PROCESS_RULE_FLAG_MATCH_IMAGE_NAME))

typedef enum _UF_COMMAND {
    UfCommandInvalid = 0,
    UfCommandReplacePolicy = 1,
    UfCommandClearPolicy = 2,
    UfCommandQueryState = 3,
    UfCommandSetProcessTrust = 4
} UF_COMMAND;

typedef enum _UF_RULE_MODE {
    UfRuleMonitor = 1,
    UfRuleAllowList = 2,
    UfRuleProtected = 2
} UF_RULE_MODE;

typedef enum _UF_EVENT_ACTION {
    UfEventObserved = 1,
    UfEventDenied = 2,
    UfEventTrustRequired = 3,
    UfEventTrustRevoked = 4
} UF_EVENT_ACTION;

typedef enum _UF_IO_OPERATION {
    UfIoOperationCreate = 1,
    UfIoOperationRead = 2,
    UfIoOperationWrite = 3,
    UfIoOperationSetInformation = 4,
    UfIoOperationSetSecurity = 5,
    UfIoOperationQueryInformation = 6,
    UfIoOperationQuerySecurity = 7,
    UfIoOperationDirectoryControl = 8
} UF_IO_OPERATION;

typedef enum _UF_SIGNER_MATCH_TYPE {
    UfSignerMatchThumbprintSha256 = 1,
    UfSignerMatchIssuerSha256AndSerial = 2
} UF_SIGNER_MATCH_TYPE;

typedef enum _UF_TRUST_DECISION {
    UfTrustUnknown = 0,
    UfTrustAllow = 1,
    UfTrustDeny = 2,
    UfTrustInvalidate = 3
} UF_TRUST_DECISION;

typedef enum _UF_REVOCATION_TIMEOUT_ACTION {
    UfRevocationTimeoutDeny = 0,
    UfRevocationTimeoutAllowLocalTrust = 1
} UF_REVOCATION_TIMEOUT_ACTION;

typedef struct _UF_MESSAGE_HEADER {
    unsigned long Version;
    unsigned long Size;
    unsigned long Command;
    unsigned long Reserved;
} UF_MESSAGE_HEADER;

typedef struct _UF_PATH_RULE {
    unsigned long Mode;
    unsigned long PathLengthChars;
    wchar_t Path[UF_MAX_PATH_CHARS];
} UF_PATH_RULE;

typedef struct _UF_IMAGE_RULE {
    unsigned long ImageLengthChars;
    unsigned long Reserved;
    wchar_t Image[UF_MAX_IMAGE_CHARS];
} UF_IMAGE_RULE;

typedef struct _UF_REPLACE_POLICY {
    UF_MESSAGE_HEADER Header;
    unsigned long PathRuleCount;
    unsigned long MonitorExceptionCount;
    unsigned long AllowedImageCount;
    unsigned long Reserved;
    UF_PATH_RULE PathRules[UF_MAX_RULES];
    UF_IMAGE_RULE MonitorExceptions[UF_MAX_RULES];
    UF_IMAGE_RULE AllowedImages[UF_MAX_RULES];
} UF_REPLACE_POLICY;

typedef struct _UF_STATE_REPLY {
    unsigned long Version;
    unsigned long Size;
    unsigned long PathRuleCount;
    unsigned long MonitorExceptionCount;
    unsigned long AllowedImageCount;
    unsigned long Connected;
} UF_STATE_REPLY;

typedef struct _UF_FILE_EVENT {
    unsigned long Version;
    unsigned long Size;
    unsigned long ProcessId;
    unsigned long DesiredAccess;
    unsigned long Disposition;
    unsigned long Action;
    unsigned long PathLengthChars;
    unsigned long ImageLengthChars;
    wchar_t Path[UF_MAX_PATH_CHARS];
    wchar_t Image[UF_MAX_IMAGE_CHARS];
} UF_FILE_EVENT;

typedef struct _UF_PATH_RULE_V2 {
    unsigned long RuleId;
    unsigned long Mode;
    unsigned long PathLengthChars;
    unsigned long Reserved;
    wchar_t Path[UF_MAX_PATH_CHARS];
} UF_PATH_RULE_V2;

typedef struct _UF_PROTECTED_PROCESS_RULE {
    unsigned long RuleId;
    unsigned long FolderRuleId;
    unsigned long SignerRuleId;
    unsigned short Access;
    unsigned short Reserved16;
    unsigned long ImageLengthChars;
    wchar_t Image[UF_MAX_IMAGE_CHARS];
} UF_PROTECTED_PROCESS_RULE;

typedef struct _UF_SIGNER_RULE {
    unsigned long RuleId;
    unsigned long MatchType;
    unsigned long SerialLengthBytes;
    unsigned long Reserved;
    unsigned char ThumbprintSha256[UF_CERT_SHA256_BYTES];
    unsigned char IssuerSha256[UF_CERT_SHA256_BYTES];
    unsigned char SerialNumber[UF_CERT_SERIAL_BYTES];
} UF_SIGNER_RULE;

typedef struct _UF_REVOCATION_POLICY {
    unsigned long OnlineCheckEnabled;
    unsigned long TimeoutMilliseconds;
    unsigned long TimeoutAction;
    unsigned long TerminateOnRevoked;
} UF_REVOCATION_POLICY;

typedef struct _UF_REPLACE_POLICY_V2 {
    UF_MESSAGE_HEADER Header;
    unsigned long long PolicyGeneration;
    unsigned long PathRuleCount;
    unsigned long MonitorExceptionCount;
    unsigned long ProtectedProcessRuleCount;
    unsigned long SignerRuleCount;
    UF_REVOCATION_POLICY Revocation;
    UF_PATH_RULE_V2 PathRules[UF_MAX_RULES];
    UF_IMAGE_RULE MonitorExceptions[UF_MAX_RULES];
    UF_PROTECTED_PROCESS_RULE ProtectedProcesses[UF_MAX_PROTECTED_PROCESS_RULES];
    UF_SIGNER_RULE Signers[UF_MAX_SIGNER_RULES];
} UF_REPLACE_POLICY_V2;

typedef struct _UF_STATE_REPLY_V2 {
    unsigned long Version;
    unsigned long Size;
    unsigned long PathRuleCount;
    unsigned long MonitorExceptionCount;
    unsigned long ProtectedProcessRuleCount;
    unsigned long SignerRuleCount;
    unsigned long ProcessTrustEntryCount;
    unsigned long Connected;
    unsigned long long PolicyGeneration;
} UF_STATE_REPLY_V2;

typedef struct _UF_PROCESS_TRUST_UPDATE {
    UF_MESSAGE_HEADER Header;
    unsigned long long PolicyGeneration;
    unsigned long long ProcessCreateTime;
    unsigned long ProcessId;
    unsigned long ProcessRuleId;
    unsigned short Access;
    unsigned short Decision;
    unsigned long Temporary;
    unsigned char ImageIdentitySha256[UF_CERT_SHA256_BYTES];
    unsigned char IssuerIdentitySha256[UF_CERT_SHA256_BYTES];
    unsigned char SerialNumber[UF_CERT_SERIAL_BYTES];
    unsigned long SerialLengthBytes;
} UF_PROCESS_TRUST_UPDATE;

typedef struct _UF_FILE_EVENT_V2 {
    unsigned long Version;
    unsigned long Size;
    unsigned long ProcessId;
    unsigned long DesiredAccess;
    unsigned long Disposition;
    unsigned long Action;
    unsigned long PathLengthChars;
    unsigned long ImageLengthChars;
    wchar_t Path[UF_MAX_PATH_CHARS];
    wchar_t Image[UF_MAX_IMAGE_CHARS];
    unsigned long Operation;
    unsigned long FolderRuleId;
    unsigned long ProcessRuleId;
    unsigned short RequestedAccess;
    unsigned short TrustDecision;
    unsigned long Reserved;
    unsigned long long ProcessCreateTime;
    unsigned long long PolicyGeneration;
} UF_FILE_EVENT_V2;
