#pragma once

/*
 * UF_ProcessFilterFactory.sys와 uf_procwarp.dll이 공유하는 V2 ABI입니다.
 * 정책의 LIST_ENTRY와 실행 프로세스 정보는 커널 내부에만 존재하며,
 * 사용자 모드는 고정 크기 정책 입력과 이름 목록만 전달합니다.
 */

#define UF_PROC_PROTOCOL_VERSION          2u
#define UF_PROC_DEVICE_NT_NAME            L"\\Device\\UF_ProcessFilterFactory"
#define UF_PROC_DEVICE_DOS_NAME           L"\\DosDevices\\Global\\UF_ProcessFilterFactory"
#define UF_PROC_DEVICE_WIN32_NAME         L"\\\\.\\UF_ProcessFilterFactory"
#define UF_PROC_DEVICE_WIN32_GLOBAL_NAME  L"\\\\.\\Global\\UF_ProcessFilterFactory"
#define UF_PROC_MAX_POLICIES              32u
#define UF_PROC_MAX_RULES                 UF_PROC_MAX_POLICIES
#define UF_PROC_MAX_PROCESS_NAME_CHARS    260u
#define UF_PROC_MAX_PROCESS_PATH_CHARS    520u
#define UF_PROC_MAX_IMAGE_CHARS           UF_PROC_MAX_PROCESS_PATH_CHARS
#define UF_PROC_MAX_EVENT_BATCH           32u
#define UF_PROC_EVENT_QUEUE_CAPACITY      512u
#define UF_PROC_SIGNATURE_TIMEOUT_MS      5000u

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
#define UF_PROC_IOCTL_ADD_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804u, METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define UF_PROC_IOCTL_REMOVE_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805u, METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define UF_PROC_IOCTL_WAIT_SIGNATURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806u, METHOD_BUFFERED, FILE_READ_ACCESS)
#define UF_PROC_IOCTL_COMPLETE_SIGNATURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807u, METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

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

typedef enum _UF_PROC_SIGNATURE_DECISION {
    UfProcSignatureUnknown = 0,
    UfProcSignatureAllow = 1,
    UfProcSignatureDeny = 2
} UF_PROC_SIGNATURE_DECISION;

typedef struct _UF_PROC_MESSAGE_HEADER {
    unsigned long Version;
    unsigned long Size;
} UF_PROC_MESSAGE_HEADER, *PUF_PROC_MESSAGE_HEADER;

typedef struct _UF_PROC_POLICY_RULE {
    unsigned long RuleId;
    unsigned long ProcessNameLengthChars;
    unsigned long ProcessPathLengthChars;
    unsigned short IsSign;
    unsigned short IsCmpFullPath;
    unsigned long Reserved;
    wchar_t ProcessName[UF_PROC_MAX_PROCESS_NAME_CHARS];
    wchar_t ProcessPath[UF_PROC_MAX_PROCESS_PATH_CHARS];
} UF_PROC_POLICY_RULE, *PUF_PROC_POLICY_RULE;

typedef struct _UF_PROC_POLICY_NAME {
    unsigned long ProcessNameLengthChars;
    unsigned long Reserved;
    wchar_t ProcessName[UF_PROC_MAX_PROCESS_NAME_CHARS];
} UF_PROC_POLICY_NAME, *PUF_PROC_POLICY_NAME;

typedef struct _UF_PROC_REPLACE_POLICY {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long PolicyCount;
    unsigned long Reserved;
    UF_PROC_POLICY_RULE Policies[UF_PROC_MAX_POLICIES];
} UF_PROC_REPLACE_POLICY, *PUF_PROC_REPLACE_POLICY;

typedef UF_PROC_REPLACE_POLICY UF_PROC_ADD_POLICY;
typedef PUF_PROC_REPLACE_POLICY PUF_PROC_ADD_POLICY;

typedef struct _UF_PROC_REMOVE_POLICY {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long PolicyCount;
    unsigned long Reserved;
    UF_PROC_POLICY_NAME Policies[UF_PROC_MAX_POLICIES];
} UF_PROC_REMOVE_POLICY, *PUF_PROC_REMOVE_POLICY;

typedef struct _UF_PROC_STATE_REPLY {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long long PolicyGeneration;
    unsigned long PolicyCount;
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

typedef struct _UF_PROC_WAIT_SIGNATURE {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long TimeoutMs;
    unsigned long Reserved;
} UF_PROC_WAIT_SIGNATURE, *PUF_PROC_WAIT_SIGNATURE;

typedef struct _UF_PROC_SIGNATURE_REQUEST {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long long RequestId;
    unsigned long ProcessId;
    unsigned long PathLengthChars;
    wchar_t ProcessPath[UF_PROC_MAX_PROCESS_PATH_CHARS];
} UF_PROC_SIGNATURE_REQUEST, *PUF_PROC_SIGNATURE_REQUEST;

typedef struct _UF_PROC_SIGNATURE_RESPONSE {
    UF_PROC_MESSAGE_HEADER Header;
    unsigned long long RequestId;
    unsigned long Decision;
    unsigned long Reserved;
} UF_PROC_SIGNATURE_RESPONSE, *PUF_PROC_SIGNATURE_RESPONSE;
