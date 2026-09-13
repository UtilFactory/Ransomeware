#pragma once
#ifdef UF_BOOT_LAYOUT_TEST
#include <Windows.h>
#include <winioctl.h>
#define NT_SUCCESS(s) ((LONG)(s) >= 0)
#define STATUS_SUCCESS ((LONG)0)
#define STATUS_NOT_SUPPORTED ((LONG)0xC00000BBL)
#define STATUS_DISK_CORRUPT_ERROR ((LONG)0xC0000032L)
#define STATUS_BUFFER_OVERFLOW ((LONG)0x80000005L)
typedef LONG NTSTATUS;
#else
#include <ntddk.h>
#endif
#include "../include/uf_boot_protocol.h"

#define UF_LAYOUT_SCRATCH 73728u
typedef NTSTATUS (*UF_LAYOUT_READ)(PVOID Context, ULONGLONG Offset, ULONG Length, PVOID Buffer);
typedef struct _UF_LAYOUT_RESULT {
    ULONG Count;
    UF_BOOT_RANGE Ranges[UF_BOOT_MAX_RANGES];
} UF_LAYOUT_RESULT;
NTSTATUS UfParseLayout(ULONGLONG DiskBytes, ULONG SectorBytes, UF_LAYOUT_READ Read,
    PVOID Context, PUCHAR Scratch, UF_LAYOUT_RESULT* Result);
ULONG UfLayoutCrc32(const UCHAR* Buffer, ULONG Length);
