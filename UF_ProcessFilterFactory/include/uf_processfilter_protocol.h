#pragma once

/*
 * UF_ProcessFilterFactory.sys와 uf_procwarp.dll이 공유하는 V1 ABI입니다.
 * 공개 구조체는 Windows x64의 고정 크기 기본 형식만 사용합니다.
 */

#define UF_PROC_PROTOCOL_VERSION          1u
#define UF_PROC_DEVICE_NT_NAME            L"\\Device\\UF_ProcessFilterFactory"
#define UF_PROC_DEVICE_DOS_NAME           L"\\DosDevices\\UF_ProcessFilterFactory"
#define UF_PROC_DEVICE_WIN32_NAME         L"\\\\.\\UF_ProcessFilterFactory"
#define UF_PROC_MAX_RULES                 32u
#define UF_PROC_MAX_IMAGE_CHARS           260u
#define UF_PROC_MAX_EVENT_BATCH           32u
#define UF_PROC_EVENT_QUEUE_CAPACITY      512u

#define UF_PROC_IOCTL_REPLACE_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800u, METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define UF_PROC_IOCTL_CLEAR_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801u, METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define UF_PROC_IOCTL_QUERY_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802u, METHOD_BUFFERED, FILE_READ_ACCESS)
#define UF_PROC_IOCTL_DEQUEUE_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803u, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef enum _UF_PROC_MATCH_MODE {
    UfProcMatchFullPath = 1,
    UfProcMatchImageName = 2
} UF_PROC_MATCH_MODE;

typedef enum _UF_PROC_EVENT_TYPE {
    UfProcEventCreate = 1,
    UfProcEventExit = 2,
    UfProcEventAccess = 3
} UF_PROC_EVENT_TYPE;

typedef enum _UF_PROC_EVENT_ACTION {
    UfProcActionObserved = 1,
    UfProcActionBlocked = 2
} UF_PROC_EVENT_ACTION;

typedef enum _UF_PROC_ACCESS_OPERATION {
    UfProcAccessNone = 0,
    UfProcAccessCreateHandle = 1,
    UfProcAccessDuplicateHandle = 2
} UF_PROC_ACCESS_OPERATION;

typedef struct _UF_PROC_MESSAGE_HEADER {
    unsigned long Version;
    unsigned long Size;
} UF_PROC_MESSAGE_HEADER, *PUF_PROC_MESSAGE_HEADER;

typedef struct _UF_PROC_POLICY_RULE {
    unsigned long RuleId;
    unsigned long MatchMode;
    unsigned long ImageLengthChars;
    unsigned long DeviceImageLengthChars;
    wchar_t Image[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t DeviceImage[UF_PROC_MAX_IMAGE_CHARS];
} UF_PROC_POLICY_RULE, *PUF_PROC_POLICY_RULE;

typedef struct _UF_PROC_REPLACE_POLICY {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long RuleCount;
    unsigned long Reserved;
    UF_PROC_POLICY_RULE Rules[UF_PROC_MAX_RULES];
} UF_PROC_REPLACE_POLICY, *PUF_PROC_REPLACE_POLICY;

typedef struct _UF_PROC_STATE_REPLY {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long long PolicyGeneration;
    unsigned long RuleCount;
    unsigned long QueueDepth;
    unsigned long long DroppedEvents;
    unsigned long Connected;
    unsigned long Reserved;
} UF_PROC_STATE_REPLY, *PUF_PROC_STATE_REPLY;

typedef struct _UF_PROC_EVENT {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long Type;
    unsigned long Action;
    unsigned long long Sequence;
    unsigned long long SystemTime100ns;
    unsigned long long PolicyGeneration;
    unsigned long ProcessId;
    unsigned long ParentProcessId;
    unsigned long RequesterProcessId;
    unsigned long TargetProcessId;
    unsigned long Operation;
    unsigned long OriginalDesiredAccess;
    unsigned long DesiredAccess;
    unsigned long RuleId;
    unsigned long ImageLengthChars;
    unsigned long Reserved;
    wchar_t Image[UF_PROC_MAX_IMAGE_CHARS];
} UF_PROC_EVENT, *PUF_PROC_EVENT;

typedef struct _UF_PROC_EVENT_BATCH {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long EventCount;
    unsigned long Reserved;
    unsigned long long DroppedEvents;
    UF_PROC_EVENT Events[UF_PROC_MAX_EVENT_BATCH];
} UF_PROC_EVENT_BATCH, *PUF_PROC_EVENT_BATCH;
