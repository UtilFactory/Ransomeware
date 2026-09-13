#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <winioctl.h>
#include <stdio.h>
#include <wchar.h>
#include "../include/uf_bootwarp.h"

C_ASSERT(sizeof(UF_BOOT_DEVICE_INFO) == 2000);
C_ASSERT(sizeof(UF_BOOT_DEVICE_LIST) == 64016);
C_ASSERT(sizeof(UF_BOOT_SET_REQUEST) == 32);
C_ASSERT(sizeof(UF_BOOT_EVENT) == 1136);
C_ASSERT(sizeof(UF_BOOT_EVENT_BATCH) == 36376);

typedef struct _UF_BOOT_CALL {
    volatile LONG References;
    DWORD Code, InputSize, OutputSize, Error, Bytes;
    volatile LONG Cancelled;
    HMODULE Module;
    BYTE Input[sizeof(UF_BOOT_SET_REQUEST)];
    BYTE Output[sizeof(UF_BOOT_DEVICE_LIST)];
} UF_BOOT_CALL;
static volatile LONG gCalls;

static void Log(DWORD Code, DWORD Error)
{
    WCHAR path[32768];
    WCHAR* end;
    SYSTEMTIME now;
    char line[256];
    HANDLE file;
    DWORD bytes;
    int size;
    if (!GetModuleFileNameW(NULL, path, _countof(path))) return;
    end = wcsrchr(path, L'\\');
    if (!end) return;
    *end = 0;
    if (wcscat_s(path, _countof(path), L"\\logs") != 0) return;
    (void)CreateDirectoryW(path, NULL);
    if (wcscat_s(path, _countof(path), L"\\uf_bootwarp.log") != 0) return;
    GetLocalTime(&now);
    size = sprintf_s(line, sizeof(line),
        "%04u-%02u-%02u %02u:%02u:%02u.%03u pid=%lu ioctl=0x%08lx GetLastError=%lu\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        now.wMilliseconds, GetCurrentProcessId(), Code, Error);
    if (size <= 0) return;
    file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        (void)WriteFile(file, line, (DWORD)size, &bytes, NULL);
        CloseHandle(file);
    }
}

static void ReleaseCall(UF_BOOT_CALL* Call)
{
    if (InterlockedDecrement(&Call->References) == 0) HeapFree(GetProcessHeap(), 0, Call);
}

static DWORD WINAPI CallWorker(void* Context)
{
    UF_BOOT_CALL* call = Context;
    HMODULE module = call->Module;
    HANDLE device = CreateFileW(UF_BOOT_USER_PATH, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    call->Error = ERROR_SUCCESS;
    if (device == INVALID_HANDLE_VALUE) call->Error = GetLastError();
    else {
        if (InterlockedCompareExchange(&call->Cancelled, 0, 0)) call->Error = ERROR_CANCELLED;
        else if (!DeviceIoControl(device, call->Code, call->Input, call->InputSize,
            call->Output, call->OutputSize, &call->Bytes, NULL)) call->Error = GetLastError();
        CloseHandle(device);
    }
    /* 로그 경로가 느려도 호출자의 제한 시간 밖에서 기다리게 하지 않는다. */
    if (call->Error != ERROR_SUCCESS || call->Code == IOCTL_UF_BOOT_SET)
        Log(call->Code, InterlockedCompareExchange(&call->Cancelled, 0, 0) ? ERROR_TIMEOUT : call->Error);
    InterlockedDecrement(&gCalls);
    ReleaseCall(call);
    /* 시간 초과 뒤에도 진행 중인 호출의 코드와 버퍼 수명을 유지한다. */
    FreeLibraryAndExitThread(module, 0);
}

static DWORD Invoke(DWORD Code, const void* Input, DWORD InputSize, void* Output, DWORD OutputSize)
{
    UF_BOOT_CALL* call;
    HANDLE thread;
    DWORD error, wait;
    if (!Input || !Output || InputSize > sizeof(call->Input) || OutputSize > sizeof(call->Output))
        return ERROR_INVALID_PARAMETER;
    ZeroMemory(Output, OutputSize);
    if (InterlockedIncrement(&gCalls) > 4) { InterlockedDecrement(&gCalls); return ERROR_BUSY; }
    call = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*call));
    if (!call) { InterlockedDecrement(&gCalls); return ERROR_OUTOFMEMORY; }
    call->References = 2;
    call->Code = Code; call->InputSize = InputSize; call->OutputSize = OutputSize;
    CopyMemory(call->Input, Input, InputSize);
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)(const void*)&gCalls, &call->Module)) {
        error = GetLastError(); HeapFree(GetProcessHeap(), 0, call); InterlockedDecrement(&gCalls); return error;
    }
    thread = CreateThread(NULL, 0, CallWorker, call, 0, NULL);
    if (!thread) {
        error = GetLastError(); FreeLibrary(call->Module); HeapFree(GetProcessHeap(), 0, call);
        InterlockedDecrement(&gCalls); return error;
    }
    wait = WaitForSingleObject(thread, Code == IOCTL_UF_BOOT_SET ? 10000 : 3000);
    if (wait == WAIT_OBJECT_0) {
        error = call->Error;
        if (error == ERROR_SUCCESS) {
            UF_BOOT_HEADER* header = (UF_BOOT_HEADER*)call->Output;
            if (call->Bytes != OutputSize || header->Version != UF_BOOT_VERSION || header->Size != OutputSize)
                error = ERROR_REVISION_MISMATCH;
            else CopyMemory(Output, call->Output, OutputSize);
        }
    } else {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        InterlockedExchange(&call->Cancelled, 1);
        (void)CancelSynchronousIo(thread);
        /* 시간 초과 후 호출자 버퍼를 참조하지 않고 작업 종료까지 내부 힙만 유지한다. */
    }
    CloseHandle(thread);
    ReleaseCall(call);
    return error;
}

static BOOLEAN ValidDevice(const UF_BOOT_DEVICE_INFO* Device)
{
    ULONG i;
    if (Device->Version != UF_BOOT_VERSION || Device->Size != sizeof(*Device) || !Device->DeviceId ||
        Device->RangeCount > UF_BOOT_MAX_RANGES || Device->State > UF_BOOT_REMOVED ||
        (Device->Flags & ~(UF_BOOT_FLAG_LAB_DISK | UF_BOOT_FLAG_READY)) ||
        Device->InstanceId[UF_BOOT_INSTANCE_CHARS - 1] != 0) return FALSE;
    for (i = 0; i < Device->RangeCount; ++i) {
        const UF_BOOT_RANGE* range = &Device->Ranges[i];
        if (range->Reserved || !range->Length || range->Offset >= Device->DiskBytes ||
            range->Length > Device->DiskBytes - range->Offset ||
            range->Kind < UF_BOOT_KIND_MBR || range->Kind > UF_BOOT_KIND_NTFS) return FALSE;
    }
    return TRUE;
}

DWORD __stdcall UfBootQueryDevices(UF_BOOT_DEVICE_LIST* Reply)
{
    UF_BOOT_HEADER header = { UF_BOOT_VERSION, sizeof(header) };
    DWORD error = Invoke(IOCTL_UF_BOOT_QUERY, &header, sizeof(header), Reply, sizeof(*Reply));
    ULONG i;
    if (error == 0 && Reply->Count > UF_BOOT_MAX_DEVICES) error = ERROR_INVALID_DATA;
    if (error == 0) for (i = 0; i < Reply->Count; ++i) {
        if (!ValidDevice(&Reply->Devices[i])) { error = ERROR_INVALID_DATA; break; }
    }
    if (error && Reply) ZeroMemory(Reply, sizeof(*Reply));
    return error;
}

DWORD __stdcall UfBootSetProtection(const UF_BOOT_SET_REQUEST* Request, UF_BOOT_DEVICE_INFO* Reply)
{
    DWORD error;
    if (!Request || Request->Version != UF_BOOT_VERSION || Request->Size != sizeof(*Request) ||
        Request->Enabled > 1 || Request->Reserved || !Request->DeviceId) return ERROR_INVALID_PARAMETER;
    error = Invoke(IOCTL_UF_BOOT_SET, Request, sizeof(*Request), Reply, sizeof(*Reply));
    if (!error && (!ValidDevice(Reply) || Reply->DeviceId != Request->DeviceId)) error = ERROR_INVALID_DATA;
    if (error && Reply) ZeroMemory(Reply, sizeof(*Reply));
    return error;
}

DWORD __stdcall UfBootReadEvents(UF_BOOT_EVENT_BATCH* Reply)
{
    UF_BOOT_HEADER header = { UF_BOOT_VERSION, sizeof(header) };
    DWORD error = Invoke(IOCTL_UF_BOOT_EVENTS, &header, sizeof(header), Reply, sizeof(*Reply));
    ULONG i;
    if (error == 0 && Reply->Count > UF_BOOT_MAX_EVENTS) error = ERROR_INVALID_DATA;
    if (error == 0) for (i = 0; i < Reply->Count; ++i) {
        UF_BOOT_EVENT* e = &Reply->Events[i];
        if (e->Version != UF_BOOT_VERSION || e->Size != sizeof(*e) || e->PathLength >= UF_BOOT_PATH_CHARS ||
            e->Path[e->PathLength] != 0) { error = ERROR_INVALID_DATA; break; }
    }
    if (error && Reply) ZeroMemory(Reply, sizeof(*Reply));
    return error;
}
