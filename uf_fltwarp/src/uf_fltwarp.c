#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include <limits.h>
#include "../include/uf_fltwarp.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

typedef struct _UF_USER_EVENT_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    UF_FILE_EVENT Event;
} UF_USER_EVENT_MESSAGE;

static SRWLOCK gLock = SRWLOCK_INIT;
static HANDLE gPort = INVALID_HANDLE_VALUE;
static HANDLE gStopEvent = NULL;
static HANDLE gReceiverThread = NULL;
static UF_FLT_EVENT_CALLBACK gCallback = NULL;
static void* gCallbackContext = NULL;

static unsigned long
UfResultFromHresult(HRESULT Result)
{
    if (SUCCEEDED(Result)) {
        return ERROR_SUCCESS;
    }
    if (HRESULT_FACILITY(Result) == FACILITY_WIN32) {
        return HRESULT_CODE(Result);
    }
    return (unsigned long)Result;
}

static unsigned long
UfCopyString(
    const wchar_t* Source,
    wchar_t* Destination,
    unsigned long Capacity,
    unsigned long* WrittenChars)
{
    size_t length;

    if (Source == NULL || Destination == NULL || WrittenChars == NULL ||
        Capacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    length = wcslen(Source);
    if (length >= Capacity || length > ULONG_MAX) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    CopyMemory(Destination, Source, (length + 1) * sizeof(wchar_t));
    *WrittenChars = (unsigned long)length;
    return ERROR_SUCCESS;
}

static unsigned long
UfFillImageRule(const wchar_t* DosPath, UF_IMAGE_RULE* Rule)
{
    wchar_t ntPath[UF_MAX_IMAGE_CHARS];
    unsigned long result;

    if (Rule == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    result = UfFltDosPathToNtPath(
        DosPath, ntPath, (unsigned long)_countof(ntPath));
    if (result != ERROR_SUCCESS) {
        return result;
    }
    ZeroMemory(Rule, sizeof(*Rule));
    return UfCopyString(
        ntPath, Rule->Image, UF_MAX_IMAGE_CHARS,
        &Rule->ImageLengthChars);
}

static DWORD WINAPI
UfReceiverMain(void* Parameter)
{
    HANDLE port;
    HANDLE stopEvent;
    OVERLAPPED overlapped;
    UF_USER_EVENT_MESSAGE message;
    HANDLE waitHandles[2];
    HRESULT result;
    DWORD waitResult;
    DWORD bytesTransferred;
    UF_FLT_EVENT_CALLBACK callback;
    void* callbackContext;

    UNREFERENCED_PARAMETER(Parameter);
    AcquireSRWLockShared(&gLock);
    port = gPort;
    stopEvent = gStopEvent;
    ReleaseSRWLockShared(&gLock);

    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL) {
        return GetLastError();
    }
    waitHandles[0] = stopEvent;
    waitHandles[1] = overlapped.hEvent;

    for (;;) {
        ZeroMemory(&message, sizeof(message));
        ResetEvent(overlapped.hEvent);
        result = FilterGetMessage(
            port, &message.Header, sizeof(message), &overlapped);
        if (result == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0) {
                CancelIoEx(port, &overlapped);
                (void)GetOverlappedResult(port, &overlapped, &bytesTransferred, TRUE);
                break;
            }
            if (waitResult != WAIT_OBJECT_0 + 1 ||
                !GetOverlappedResult(port, &overlapped, &bytesTransferred, FALSE)) {
                break;
            }
        } else if (FAILED(result)) {
            break;
        }

        if (message.Event.Version != UF_PROTOCOL_VERSION ||
            message.Event.Size != sizeof(UF_FILE_EVENT)) {
            continue;
        }
        AcquireSRWLockShared(&gLock);
        callback = gCallback;
        callbackContext = gCallbackContext;
        ReleaseSRWLockShared(&gLock);
        if (callback != NULL) {
            callback(&message.Event, callbackContext);
        }
    }

    CloseHandle(overlapped.hEvent);
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltInitialize(void)
{
    return ERROR_SUCCESS;
}

void __stdcall
UfFltShutdown(void)
{
    UfFltDisconnect();
}

unsigned long __stdcall
UfFltConnect(void)
{
    HANDLE port;
    HRESULT result;

    AcquireSRWLockExclusive(&gLock);
    if (gPort != INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_ALREADY_EXISTS;
    }
    result = FilterConnectCommunicationPort(
        UF_FILTER_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(result)) {
        ReleaseSRWLockExclusive(&gLock);
        return UfResultFromHresult(result);
    }
    gPort = port;
    ReleaseSRWLockExclusive(&gLock);
    return ERROR_SUCCESS;
}

void __stdcall
UfFltDisconnect(void)
{
    HANDLE port;

    UfFltStopEventReceiver();
    AcquireSRWLockExclusive(&gLock);
    port = gPort;
    gPort = INVALID_HANDLE_VALUE;
    ReleaseSRWLockExclusive(&gLock);
    if (port != INVALID_HANDLE_VALUE) {
        CloseHandle(port);
    }
}

int __stdcall
UfFltIsConnected(void)
{
    int connected;
    AcquireSRWLockShared(&gLock);
    connected = gPort != INVALID_HANDLE_VALUE;
    ReleaseSRWLockShared(&gLock);
    return connected;
}

unsigned long __stdcall
UfFltDosPathToNtPath(
    const wchar_t* DosPath,
    wchar_t* NtPath,
    unsigned long NtPathChars)
{
    wchar_t fullPath[UF_MAX_PATH_CHARS];
    wchar_t deviceName[UF_MAX_PATH_CHARS];
    wchar_t drive[3];
    DWORD fullLength;
    DWORD deviceLength;
    size_t required;
    size_t currentLength;

    if (DosPath == NULL || NtPath == NULL || NtPathChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    fullLength = GetFullPathNameW(
        DosPath, (DWORD)_countof(fullPath), fullPath, NULL);
    if (fullLength == 0) {
        return GetLastError();
    }
    if (fullLength >= (DWORD)_countof(fullPath) ||
        fullLength < 3 || fullPath[1] != L':' || fullPath[2] != L'\\') {
        return ERROR_BAD_PATHNAME;
    }
    drive[0] = fullPath[0];
    drive[1] = L':';
    drive[2] = L'\0';
    deviceLength = QueryDosDeviceW(
        drive, deviceName, (DWORD)_countof(deviceName));
    if (deviceLength == 0) {
        return GetLastError();
    }
    required = wcslen(deviceName) + wcslen(fullPath + 2) + 1;
    if (required > NtPathChars) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    wcscpy_s(NtPath, NtPathChars, deviceName);
    wcscat_s(NtPath, NtPathChars, fullPath + 2);
    currentLength = wcslen(NtPath);
    if (currentLength > 1 && NtPath[currentLength - 1] == L'\\' &&
        !(fullLength == 3 && fullPath[2] == L'\\')) {
        NtPath[currentLength - 1] = L'\0';
    }
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltReplacePolicy(const UF_FLT_POLICY_INPUT* Policy)
{
    UF_REPLACE_POLICY* request;
    unsigned long index;
    unsigned long result = ERROR_SUCCESS;
    DWORD bytesReturned;
    HRESULT sendResult;
    HANDLE port;

    if (Policy == NULL ||
        Policy->PathRuleCount > UF_MAX_RULES ||
        Policy->MonitorExceptionCount > UF_MAX_RULES ||
        Policy->AllowedImageCount > UF_MAX_RULES ||
        (Policy->PathRuleCount != 0 && Policy->PathRules == NULL) ||
        (Policy->MonitorExceptionCount != 0 && Policy->MonitorExceptions == NULL) ||
        (Policy->AllowedImageCount != 0 && Policy->AllowedImages == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }

    request = (UF_REPLACE_POLICY*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*request));
    if (request == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    request->Header.Version = UF_PROTOCOL_VERSION;
    request->Header.Size = sizeof(*request);
    request->Header.Command = UfCommandReplacePolicy;
    request->PathRuleCount = Policy->PathRuleCount;
    request->MonitorExceptionCount = Policy->MonitorExceptionCount;
    request->AllowedImageCount = Policy->AllowedImageCount;

    for (index = 0; index < Policy->PathRuleCount; ++index) {
        UF_PATH_RULE* rule = &request->PathRules[index];
        if (Policy->PathRules[index].Mode != UfRuleMonitor &&
            Policy->PathRules[index].Mode != UfRuleAllowList) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }
        rule->Mode = Policy->PathRules[index].Mode;
        result = UfFltDosPathToNtPath(
            Policy->PathRules[index].DosPath,
            rule->Path, UF_MAX_PATH_CHARS);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
        rule->PathLengthChars = (unsigned long)wcslen(rule->Path);
    }
    for (index = 0; index < Policy->MonitorExceptionCount; ++index) {
        result = UfFillImageRule(
            Policy->MonitorExceptions[index],
            &request->MonitorExceptions[index]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }
    for (index = 0; index < Policy->AllowedImageCount; ++index) {
        result = UfFillImageRule(
            Policy->AllowedImages[index],
            &request->AllowedImages[index]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }

    AcquireSRWLockShared(&gLock);
    port = gPort;
    if (port == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&gLock);
        result = ERROR_INVALID_HANDLE;
        goto Exit;
    }
    bytesReturned = 0;
    sendResult = FilterSendMessage(
        port, request, sizeof(*request), NULL, 0, &bytesReturned);
    ReleaseSRWLockShared(&gLock);
    result = UfResultFromHresult(sendResult);

Exit:
    SecureZeroMemory(request, sizeof(*request));
    HeapFree(GetProcessHeap(), 0, request);
    return result;
}

unsigned long __stdcall
UfFltClearPolicy(void)
{
    UF_MESSAGE_HEADER request;
    DWORD bytesReturned = 0;
    HRESULT result;
    HANDLE port;

    ZeroMemory(&request, sizeof(request));
    request.Version = UF_PROTOCOL_VERSION;
    request.Size = sizeof(request);
    request.Command = UfCommandClearPolicy;

    AcquireSRWLockShared(&gLock);
    port = gPort;
    if (port == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&gLock);
        return ERROR_INVALID_HANDLE;
    }
    result = FilterSendMessage(
        port, &request, sizeof(request), NULL, 0, &bytesReturned);
    ReleaseSRWLockShared(&gLock);
    return UfResultFromHresult(result);
}

unsigned long __stdcall
UfFltQueryState(UF_STATE_REPLY* State)
{
    UF_MESSAGE_HEADER request;
    DWORD bytesReturned = 0;
    HRESULT result;
    HANDLE port;

    if (State == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(&request, sizeof(request));
    ZeroMemory(State, sizeof(*State));
    request.Version = UF_PROTOCOL_VERSION;
    request.Size = sizeof(request);
    request.Command = UfCommandQueryState;

    AcquireSRWLockShared(&gLock);
    port = gPort;
    if (port == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&gLock);
        return ERROR_INVALID_HANDLE;
    }
    result = FilterSendMessage(
        port, &request, sizeof(request),
        State, sizeof(*State), &bytesReturned);
    ReleaseSRWLockShared(&gLock);
    if (FAILED(result)) {
        return UfResultFromHresult(result);
    }
    if (bytesReturned != sizeof(*State) ||
        State->Version != UF_PROTOCOL_VERSION ||
        State->Size != sizeof(*State)) {
        return ERROR_REVISION_MISMATCH;
    }
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltStartEventReceiver(UF_FLT_EVENT_CALLBACK Callback, void* Context)
{
    HANDLE thread;
    HANDLE stopEvent;

    if (Callback == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    AcquireSRWLockExclusive(&gLock);
    if (gPort == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_INVALID_HANDLE;
    }
    if (gReceiverThread != NULL) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_ALREADY_EXISTS;
    }
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) {
        unsigned long error = GetLastError();
        ReleaseSRWLockExclusive(&gLock);
        return error;
    }
    gStopEvent = stopEvent;
    gCallback = Callback;
    gCallbackContext = Context;
    thread = CreateThread(NULL, 0, UfReceiverMain, NULL, 0, NULL);
    if (thread == NULL) {
        unsigned long error = GetLastError();
        CloseHandle(gStopEvent);
        gStopEvent = NULL;
        gCallback = NULL;
        gCallbackContext = NULL;
        ReleaseSRWLockExclusive(&gLock);
        return error;
    }
    gReceiverThread = thread;
    ReleaseSRWLockExclusive(&gLock);
    return ERROR_SUCCESS;
}

void __stdcall
UfFltStopEventReceiver(void)
{
    HANDLE thread;
    HANDLE stopEvent;

    AcquireSRWLockExclusive(&gLock);
    thread = gReceiverThread;
    stopEvent = gStopEvent;
    if (thread == NULL) {
        ReleaseSRWLockExclusive(&gLock);
        return;
    }
    SetEvent(stopEvent);
    ReleaseSRWLockExclusive(&gLock);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(stopEvent);

    AcquireSRWLockExclusive(&gLock);
    gReceiverThread = NULL;
    gStopEvent = NULL;
    gCallback = NULL;
    gCallbackContext = NULL;
    ReleaseSRWLockExclusive(&gLock);
}

unsigned long __stdcall
UfFltGetErrorMessage(
    unsigned long ErrorCode,
    wchar_t* Message,
    unsigned long MessageChars)
{
    DWORD length;
    if (Message == NULL || MessageChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, ErrorCode, 0, Message, MessageChars, NULL);
    if (length == 0) {
        return GetLastError();
    }
    while (length != 0 &&
        (Message[length - 1] == L'\r' || Message[length - 1] == L'\n')) {
        Message[--length] = L'\0';
    }
    return ERROR_SUCCESS;
}
