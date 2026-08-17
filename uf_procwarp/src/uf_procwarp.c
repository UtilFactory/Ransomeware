#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdio.h>
#include "../include/uf_procwarp.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

static SRWLOCK gLock = SRWLOCK_INIT;
static HANDLE gDevice = INVALID_HANDLE_VALUE;
static HANDLE gStopEvent = NULL;
static HANDLE gReceiverThread = NULL;
static UF_PROC_EVENT_CALLBACK gCallback = NULL;
static void* gCallbackContext = NULL;

static const wchar_t* const gCriticalNames[] = {
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"winlogon.exe",
    L"system"
};

static const wchar_t*
UfProcFindImageName(
    const wchar_t* Image
    )
{
    const wchar_t* current;
    const wchar_t* name = Image;

    for (current = Image; *current != L'\0'; ++current) {
        if (*current == L'\\' || *current == L'/') {
            name = current + 1;
        }
    }
    return name;
}

static int
UfProcIsCriticalImage(
    const wchar_t* Image
    )
{
    const wchar_t* name;
    size_t index;

    if (Image == NULL) {
        return 0;
    }
    name = UfProcFindImageName(Image);
    for (index = 0; index < _countof(gCriticalNames); ++index) {
        if (_wcsicmp(name, gCriticalNames[index]) == 0) {
            return 1;
        }
    }
    return 0;
}

static unsigned long
UfProcCopyString(
    const wchar_t* Source,
    wchar_t* Destination,
    unsigned long Capacity,
    unsigned long* LengthChars
    )
{
    size_t length;

    if (Source == NULL || Destination == NULL || LengthChars == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    length = wcslen(Source);
    if (length == 0 || length >= Capacity || length > ULONG_MAX) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    CopyMemory(Destination, Source, (length + 1) * sizeof(wchar_t));
    *LengthChars = (unsigned long)length;
    return ERROR_SUCCESS;
}

static unsigned long
UfProcBuildFullPathRule(
    const wchar_t* Path,
    UF_PROC_POLICY_RULE* Rule
    )
{
    wchar_t fullPath[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t openPath[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t devicePrefix[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t devicePath[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t drive[3];
    DWORD fullLength;
    DWORD deviceLength;
    int written;
    unsigned long result;

    fullLength = GetFullPathNameW(Path, (DWORD)_countof(fullPath), fullPath, NULL);
    if (fullLength == 0) {
        return GetLastError();
    }
    if (fullLength >= _countof(fullPath) ||
        fullLength < 3 || fullPath[1] != L':' || fullPath[2] != L'\\') {
        return ERROR_BAD_PATHNAME;
    }

    written = swprintf_s(openPath, _countof(openPath), L"\\??\\%s", fullPath);
    if (written < 0) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    result = UfProcCopyString(
        openPath,
        Rule->Image,
        UF_PROC_MAX_IMAGE_CHARS,
        &Rule->ImageLengthChars);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    drive[0] = fullPath[0];
    drive[1] = L':';
    drive[2] = L'\0';
    deviceLength = QueryDosDeviceW(
        drive,
        devicePrefix,
        (DWORD)_countof(devicePrefix));
    if (deviceLength == 0) {
        return GetLastError();
    }

    written = swprintf_s(
        devicePath,
        _countof(devicePath),
        L"%s%s",
        devicePrefix,
        fullPath + 2);
    if (written < 0) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    return UfProcCopyString(
        devicePath,
        Rule->DeviceImage,
        UF_PROC_MAX_IMAGE_CHARS,
        &Rule->DeviceImageLengthChars);
}

static unsigned long
UfProcSendIoctl(
    unsigned long ControlCode,
    void* Input,
    unsigned long InputSize,
    void* Output,
    unsigned long OutputSize,
    unsigned long* BytesReturned
    )
{
    HANDLE device;
    DWORD returned = 0;
    BOOL succeeded;
    unsigned long result;

    AcquireSRWLockShared(&gLock);
    device = gDevice;
    if (device == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&gLock);
        return ERROR_INVALID_HANDLE;
    }
    succeeded = DeviceIoControl(
        device,
        ControlCode,
        Input,
        InputSize,
        Output,
        OutputSize,
        &returned,
        NULL);
    result = succeeded ? ERROR_SUCCESS : GetLastError();
    ReleaseSRWLockShared(&gLock);

    if (BytesReturned != NULL) {
        *BytesReturned = returned;
    }
    return result;
}

static DWORD WINAPI
UfProcReceiverMain(
    void* Parameter
    )
{
    UF_PROC_EVENT_BATCH* batch;

    UNREFERENCED_PARAMETER(Parameter);
    batch = (UF_PROC_EVENT_BATCH*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*batch));
    if (batch == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    for (;;) {
        unsigned long bytesReturned = 0;
        unsigned long result;
        unsigned long index;
        UF_PROC_EVENT_CALLBACK callback;
        void* callbackContext;

        if (WaitForSingleObject(gStopEvent, 100) == WAIT_OBJECT_0) {
            break;
        }

        ZeroMemory(batch, sizeof(*batch));
        result = UfProcSendIoctl(
            UF_PROC_IOCTL_DEQUEUE_EVENTS,
            NULL,
            0,
            batch,
            sizeof(*batch),
            &bytesReturned);
        if (result != ERROR_SUCCESS) {
            if (result == ERROR_INVALID_HANDLE || result == ERROR_DEVICE_NOT_CONNECTED) {
                break;
            }
            continue;
        }
        if (bytesReturned < (unsigned long)FIELD_OFFSET(UF_PROC_EVENT_BATCH, Events) ||
            batch->Header.Version != UF_PROC_PROTOCOL_VERSION ||
            batch->Header.Size != sizeof(*batch) ||
            batch->EventCount > UF_PROC_MAX_EVENT_BATCH) {
            continue;
        }

        AcquireSRWLockShared(&gLock);
        callback = gCallback;
        callbackContext = gCallbackContext;
        ReleaseSRWLockShared(&gLock);
        if (callback == NULL) {
            continue;
        }
        for (index = 0; index < batch->EventCount; ++index) {
            const UF_PROC_EVENT* event = &batch->Events[index];
            if (event->Header.Version == UF_PROC_PROTOCOL_VERSION &&
                event->Header.Size == sizeof(*event) &&
                event->ImageLengthChars < UF_PROC_MAX_IMAGE_CHARS) {
                callback(event, callbackContext);
            }
        }
    }

    SecureZeroMemory(batch, sizeof(*batch));
    HeapFree(GetProcessHeap(), 0, batch);
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfProcInitialize(
    void
    )
{
    return ERROR_SUCCESS;
}

void __stdcall
UfProcShutdown(
    void
    )
{
    UfProcDisconnect();
}

unsigned long __stdcall
UfProcConnect(
    void
    )
{
    HANDLE device;

    AcquireSRWLockExclusive(&gLock);
    if (gDevice != INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_ALREADY_EXISTS;
    }
    device = CreateFileW(
        UF_PROC_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device == INVALID_HANDLE_VALUE) {
        unsigned long result = GetLastError();
        ReleaseSRWLockExclusive(&gLock);
        return result;
    }
    gDevice = device;
    ReleaseSRWLockExclusive(&gLock);
    return ERROR_SUCCESS;
}

void __stdcall
UfProcDisconnect(
    void
    )
{
    HANDLE device;

    UfProcStopEventReceiver();
    AcquireSRWLockExclusive(&gLock);
    device = gDevice;
    gDevice = INVALID_HANDLE_VALUE;
    ReleaseSRWLockExclusive(&gLock);
    if (device != INVALID_HANDLE_VALUE) {
        CloseHandle(device);
    }
}

int __stdcall
UfProcIsConnected(
    void
    )
{
    int connected;

    AcquireSRWLockShared(&gLock);
    connected = gDevice != INVALID_HANDLE_VALUE;
    ReleaseSRWLockShared(&gLock);
    return connected;
}

unsigned long __stdcall
UfProcReplacePolicy(
    const UF_PROC_POLICY_INPUT* Policy
    )
{
    UF_PROC_REPLACE_POLICY* request;
    unsigned long index;
    unsigned long result = ERROR_SUCCESS;

    if (Policy == NULL ||
        Policy->RuleCount > UF_PROC_MAX_RULES ||
        (Policy->RuleCount != 0 && Policy->Rules == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }

    request = (UF_PROC_REPLACE_POLICY*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*request));
    if (request == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    request->Header.Version = UF_PROC_PROTOCOL_VERSION;
    request->Header.Size = sizeof(*request);
    request->RuleCount = Policy->RuleCount;

    for (index = 0; index < Policy->RuleCount; ++index) {
        const UF_PROC_RULE_INPUT* input = &Policy->Rules[index];
        UF_PROC_POLICY_RULE* rule = &request->Rules[index];

        if (input->RuleId == 0 || input->Image == NULL ||
            UfProcIsCriticalImage(input->Image)) {
            result = ERROR_ACCESS_DENIED;
            goto Exit;
        }
        rule->RuleId = input->RuleId;
        rule->MatchMode = input->MatchMode;
        if (input->MatchMode == UfProcMatchFullPath) {
            result = UfProcBuildFullPathRule(input->Image, rule);
        } else if (input->MatchMode == UfProcMatchImageName &&
                   UfProcFindImageName(input->Image) == input->Image) {
            result = UfProcCopyString(
                input->Image,
                rule->Image,
                UF_PROC_MAX_IMAGE_CHARS,
                &rule->ImageLengthChars);
        } else {
            result = ERROR_INVALID_PARAMETER;
        }
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }

    result = UfProcSendIoctl(
        UF_PROC_IOCTL_REPLACE_POLICY,
        request,
        sizeof(*request),
        NULL,
        0,
        NULL);

Exit:
    SecureZeroMemory(request, sizeof(*request));
    HeapFree(GetProcessHeap(), 0, request);
    return result;
}

unsigned long __stdcall
UfProcClearPolicy(
    void
    )
{
    UF_PROC_MESSAGE_HEADER header;

    ZeroMemory(&header, sizeof(header));
    header.Version = UF_PROC_PROTOCOL_VERSION;
    header.Size = sizeof(header);
    return UfProcSendIoctl(
        UF_PROC_IOCTL_CLEAR_POLICY,
        &header,
        sizeof(header),
        NULL,
        0,
        NULL);
}

unsigned long __stdcall
UfProcQueryState(
    UF_PROC_STATE_REPLY* State
    )
{
    unsigned long bytesReturned = 0;
    unsigned long result;

    if (State == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(State, sizeof(*State));
    result = UfProcSendIoctl(
        UF_PROC_IOCTL_QUERY_STATE,
        NULL,
        0,
        State,
        sizeof(*State),
        &bytesReturned);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    if (bytesReturned != sizeof(*State) ||
        State->Header.Version != UF_PROC_PROTOCOL_VERSION ||
        State->Header.Size != sizeof(*State)) {
        return ERROR_REVISION_MISMATCH;
    }
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfProcStartEventReceiver(
    UF_PROC_EVENT_CALLBACK Callback,
    void* Context
    )
{
    HANDLE stopEvent;
    HANDLE thread;

    if (Callback == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    AcquireSRWLockExclusive(&gLock);
    if (gDevice == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_INVALID_HANDLE;
    }
    if (gReceiverThread != NULL) {
        ReleaseSRWLockExclusive(&gLock);
        return ERROR_ALREADY_EXISTS;
    }
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) {
        unsigned long result = GetLastError();
        ReleaseSRWLockExclusive(&gLock);
        return result;
    }
    gStopEvent = stopEvent;
    gCallback = Callback;
    gCallbackContext = Context;
    thread = CreateThread(NULL, 0, UfProcReceiverMain, NULL, 0, NULL);
    if (thread == NULL) {
        unsigned long result = GetLastError();
        CloseHandle(stopEvent);
        gStopEvent = NULL;
        gCallback = NULL;
        gCallbackContext = NULL;
        ReleaseSRWLockExclusive(&gLock);
        return result;
    }
    gReceiverThread = thread;
    ReleaseSRWLockExclusive(&gLock);
    return ERROR_SUCCESS;
}

void __stdcall
UfProcStopEventReceiver(
    void
    )
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
UfProcGetErrorMessage(
    unsigned long ErrorCode,
    wchar_t* Message,
    unsigned long MessageChars
    )
{
    DWORD length;

    if (Message == NULL || MessageChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        0,
        Message,
        MessageChars,
        NULL);
    if (length == 0) {
        return GetLastError();
    }
    while (length != 0 &&
           (Message[length - 1] == L'\r' || Message[length - 1] == L'\n')) {
        Message[--length] = L'\0';
    }
    return ERROR_SUCCESS;
}
