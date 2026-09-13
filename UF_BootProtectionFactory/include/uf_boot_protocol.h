#pragma once

/* 커널과 사용자 모드가 공유하는 V1 고정 크기 ABI. 포인터를 전송하지 않는다. */
#define UF_BOOT_VERSION 1u
#define UF_BOOT_MAX_DEVICES 32u
#define UF_BOOT_MAX_RANGES 64u
#define UF_BOOT_MAX_EVENTS 32u
#define UF_BOOT_PATH_CHARS 520u
#define UF_BOOT_INSTANCE_CHARS 200u
#define UF_BOOT_DEVICE_NAME L"\\Device\\UF_BootProtectionFactory"
#define UF_BOOT_DOS_NAME L"\\DosDevices\\UF_BootProtectionFactory"
#define UF_BOOT_USER_PATH L"\\\\.\\UF_BootProtectionFactory"
#define IOCTL_UF_BOOT_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x930, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_UF_BOOT_SET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x931, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_UF_BOOT_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x932, METHOD_BUFFERED, FILE_READ_ACCESS)

#define UF_BOOT_STOPPED 0u
#define UF_BOOT_SCANNING 1u
#define UF_BOOT_ACTIVE 2u
#define UF_BOOT_UNSUPPORTED 3u
#define UF_BOOT_FAILED 4u
#define UF_BOOT_REMOVED 5u
#define UF_BOOT_FLAG_LAB_DISK 1u
#define UF_BOOT_FLAG_READY 2u
#define UF_BOOT_KIND_MBR 1u
#define UF_BOOT_KIND_GPT 2u
#define UF_BOOT_KIND_FAT32 3u
#define UF_BOOT_KIND_NTFS 4u
#define UF_BOOT_KIND_CONTROL 5u
#define UF_BOOT_ACTION_BLOCKED 1u
#define UF_BOOT_ACTION_STATE 2u

#pragma pack(push, 8)
typedef struct _UF_BOOT_HEADER { ULONG Version; ULONG Size; } UF_BOOT_HEADER;
typedef struct _UF_BOOT_RANGE {
    ULONGLONG Offset;
    ULONGLONG Length;
    ULONG Kind;
    ULONG Reserved;
} UF_BOOT_RANGE;
typedef struct _UF_BOOT_DEVICE_INFO {
    ULONG Version;
    ULONG Size;
    ULONGLONG DeviceId;
    ULONGLONG PolicyGeneration;
    ULONGLONG DiskBytes;
    ULONGLONG BlockedWrites;
    ULONG DiskNumber;
    ULONG SectorBytes;
    ULONG State;
    ULONG LastStatus;
    ULONG RangeCount;
    ULONG Flags;
    WCHAR InstanceId[UF_BOOT_INSTANCE_CHARS];
    UF_BOOT_RANGE Ranges[UF_BOOT_MAX_RANGES];
} UF_BOOT_DEVICE_INFO;
typedef struct _UF_BOOT_DEVICE_LIST {
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG Reserved;
    UF_BOOT_DEVICE_INFO Devices[UF_BOOT_MAX_DEVICES];
} UF_BOOT_DEVICE_LIST;
typedef struct _UF_BOOT_SET_REQUEST {
    ULONG Version;
    ULONG Size;
    ULONGLONG DeviceId;
    ULONGLONG ExpectedGeneration;
    ULONG Enabled;
    ULONG Reserved;
} UF_BOOT_SET_REQUEST;
typedef struct _UF_BOOT_EVENT {
    ULONG Version;
    ULONG Size;
    ULONGLONG Sequence;
    ULONGLONG Time;
    ULONGLONG DeviceId;
    ULONGLONG PolicyGeneration;
    ULONGLONG ProcessId;
    ULONGLONG ProcessCreated;
    ULONGLONG Offset;
    ULONGLONG Length;
    ULONG IoctlCode;
    ULONG Action;
    ULONG Status;
    ULONG Kind;
    ULONG PathStatus;
    ULONG PathLength;
    WCHAR Path[UF_BOOT_PATH_CHARS];
} UF_BOOT_EVENT;
typedef struct _UF_BOOT_EVENT_BATCH {
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG Reserved;
    ULONGLONG Dropped;
    UF_BOOT_EVENT Events[UF_BOOT_MAX_EVENTS];
} UF_BOOT_EVENT_BATCH;
#pragma pack(pop)
