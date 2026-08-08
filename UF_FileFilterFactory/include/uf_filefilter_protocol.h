#pragma once

/*
 * UF_FileFilterFactory.sys와 추후 제작할 uf_fltwarp.dll이 함께 사용하는
 * 통신 규약입니다. 모든 구조체는 고정 크기 필드와 버전 헤더를 사용합니다.
 * 드라이버에 전달하는 경로는 다음과 같은 정규화된 NT 경로여야 합니다.
 *   \Device\HarddiskVolume3\Protected
 */

#define UF_PROTOCOL_VERSION       1u
#define UF_FILTER_PORT_NAME       L"\\UF_FileFilterFactoryPort"
#define UF_MAX_RULES              64u
#define UF_MAX_PATH_CHARS         520u
#define UF_MAX_IMAGE_CHARS        260u

typedef enum _UF_COMMAND {
    UfCommandInvalid = 0,
    UfCommandReplacePolicy = 1,
    UfCommandClearPolicy = 2,
    UfCommandQueryState = 3
} UF_COMMAND;

typedef enum _UF_RULE_MODE {
    UfRuleMonitor = 1,
    UfRuleAllowList = 2
} UF_RULE_MODE;

typedef enum _UF_EVENT_ACTION {
    UfEventObserved = 1,
    UfEventDenied = 2
} UF_EVENT_ACTION;

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
