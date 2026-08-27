#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdio.h>
#include <wintrust.h>
#include <softpub.h>
#include "../include/uf_procwarp.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

static SRWLOCK gLock = SRWLOCK_INIT;
static HANDLE gDevice = INVALID_HANDLE_VALUE;
static HANDLE gStopEvent = NULL;
static HANDLE gReceiverThread = NULL;
static HANDLE gSignatureThread = NULL;
static UF_PROC_EVENT_CALLBACK gCallback = NULL;
static void* gCallbackContext = NULL;
static volatile LONG gPolicyCallStage = 0;

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
    wchar_t devicePrefix[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t devicePath[UF_PROC_MAX_IMAGE_CHARS];
    wchar_t drive[3];
    DWORD fullLength;
    DWORD deviceLength;
    unsigned long result;

    fullLength = GetFullPathNameW(Path, (DWORD)_countof(fullPath), fullPath, NULL);
    if (fullLength == 0) {
        return GetLastError();
    }
    if (fullLength >= _countof(fullPath) ||
        fullLength < 3 || fullPath[1] != L':' || fullPath[2] != L'\\') {
        return ERROR_BAD_PATHNAME;
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

    if (swprintf_s(
        devicePath,
        _countof(devicePath),
        L"%s%s",
        devicePrefix,
        fullPath + 2) < 0) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    result = UfProcCopyString(
        UfProcFindImageName(fullPath),
        Rule->ProcessName,
        UF_PROC_MAX_PROCESS_NAME_CHARS,
        &Rule->ProcessNameLengthChars);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    result = UfProcCopyString(
        devicePath,
        Rule->ProcessPath,
        UF_PROC_MAX_PROCESS_PATH_CHARS,
        &Rule->ProcessPathLengthChars);
    if (result == ERROR_SUCCESS) {
        Rule->IsCmpFullPath = 1;
    }
    return result;
}

static unsigned long
UfProcBuildPolicyRuleV2(
    const UF_PROC_RULE_INPUT_V2* Input,
    UF_PROC_POLICY_RULE* Rule
    )
{
    unsigned long result;

    if (Input == NULL || Input->RuleId == 0 || Input->ProcessName == NULL ||
        UfProcIsCriticalImage(Input->ProcessName)) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(Rule, sizeof(*Rule));
    Rule->RuleId = Input->RuleId;
    Rule->IsSign = Input->IsSign;
    Rule->IsCmpFullPath = Input->IsCmpFullPath;
    result = UfProcCopyString(
        Input->ProcessName,
        Rule->ProcessName,
        UF_PROC_MAX_PROCESS_NAME_CHARS,
        &Rule->ProcessNameLengthChars);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    if (Input->IsCmpFullPath != 0) {
        if (Input->ProcessPath == NULL) {
            return ERROR_INVALID_PARAMETER;
        }
        result = UfProcBuildFullPathRule(Input->ProcessPath, Rule);
        if (result != ERROR_SUCCESS) {
            return result;
        }
        Rule->RuleId = Input->RuleId;
        Rule->IsSign = Input->IsSign;
        result = UfProcCopyString(
            Input->ProcessName,
            Rule->ProcessName,
            UF_PROC_MAX_PROCESS_NAME_CHARS,
            &Rule->ProcessNameLengthChars);
        return result;
    }
    if (Input->ProcessPath != NULL && Input->ProcessPath[0] != L'\0') {
        result = UfProcCopyString(
            Input->ProcessPath,
            Rule->ProcessPath,
            UF_PROC_MAX_PROCESS_PATH_CHARS,
            &Rule->ProcessPathLengthChars);
        if (result != ERROR_SUCCESS) {
            return result;
        }
    }
    return ERROR_SUCCESS;
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

static int
UfProcGetProcessImagePath(
    unsigned long ProcessId,
    wchar_t* Path,
    unsigned long PathChars
    )
{
    HANDLE process;
    DWORD length = PathChars;
    int result = 0;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL) {
        return 0;
    }
    if (QueryFullProcessImageNameW(process, 0, Path, &length) != FALSE &&
        length != 0 && length < PathChars) {
        result = 1;
    }
    CloseHandle(process);
    return result;
}

static int
UfProcConvertDevicePathToDos(
    const wchar_t* DevicePath,
    unsigned long DevicePathLength,
    wchar_t* DosPath,
    unsigned long DosPathChars
    )
{
    wchar_t drive[3];
    wchar_t deviceName[UF_PROC_MAX_PROCESS_PATH_CHARS];
    wchar_t* suffix;
    DWORD deviceLength;
    unsigned int driveIndex;

    if (DevicePath == NULL || DevicePathLength == 0) {
        return 0;
    }
    for (driveIndex = 0; driveIndex < 26; ++driveIndex) {
        drive[0] = (wchar_t)(L'A' + driveIndex);
        drive[1] = L':';
        drive[2] = L'\0';
        deviceLength = QueryDosDeviceW(
            drive,
            deviceName,
            (DWORD)_countof(deviceName));
        if (deviceLength == 0 || deviceLength >= _countof(deviceName)) {
            continue;
        }
        if (DevicePathLength < deviceLength ||
            _wcsnicmp(DevicePath, deviceName, deviceLength) != 0) {
            continue;
        }
        suffix = (wchar_t*)DevicePath + deviceLength;
        if (swprintf_s(DosPath, DosPathChars, L"%ls%ls", drive, suffix) >= 0) {
            return 1;
        }
    }
    return 0;
}

static int
UfProcVerifyImageSignature(
    const UF_PROC_SIGNATURE_REQUEST* Request
    )
{
    wchar_t path[UF_PROC_MAX_PROCESS_PATH_CHARS];
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA trustData;
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG verifyResult;

    ZeroMemory(path, sizeof(path));
    if (Request->PathLengthChars >= 4 &&
        Request->ProcessPath[0] == L'\\' &&
        Request->ProcessPath[1] == L'?' &&
        Request->ProcessPath[2] == L'?' &&
        Request->ProcessPath[3] == L'\\') {
        unsigned long pathLength = Request->PathLengthChars - 4;
        if (pathLength >= _countof(path)) {
            return 0;
        }
        CopyMemory(path, Request->ProcessPath + 4, pathLength * sizeof(wchar_t));
        path[pathLength] = L'\0';
    } else if (Request->PathLengthChars >= 2 && Request->ProcessPath[1] == L':') {
        if (Request->PathLengthChars >= _countof(path)) {
            return 0;
        }
        CopyMemory(path, Request->ProcessPath, Request->PathLengthChars * sizeof(wchar_t));
        path[Request->PathLengthChars] = L'\0';
    } else if (!UfProcConvertDevicePathToDos(
                   Request->ProcessPath,
                   Request->PathLengthChars,
                   path,
                   (unsigned long)_countof(path)) &&
               (Request->ProcessId == 0 || !UfProcGetProcessImagePath(
                   Request->ProcessId,
                   path,
                   (unsigned long)_countof(path)))) {
        return 0;
    }

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    verifyResult = WinVerifyTrust(NULL, &policyGuid, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(NULL, &policyGuid, &trustData);
    return verifyResult == ERROR_SUCCESS;
}

static DWORD WINAPI
UfProcSignatureMain(
    void* Parameter
    )
{
    UF_PROC_WAIT_SIGNATURE waitRequest;
    UF_PROC_SIGNATURE_REQUEST signatureRequest;

    UNREFERENCED_PARAMETER(Parameter);
    ZeroMemory(&waitRequest, sizeof(waitRequest));
    waitRequest.Header.Version = UF_PROC_PROTOCOL_VERSION;
    waitRequest.Header.Size = sizeof(waitRequest);
    waitRequest.TimeoutMs = UF_PROC_SIGNATURE_TIMEOUT_MS;
    for (;;) {
        unsigned long bytesReturned = 0;
        unsigned long result;
        UF_PROC_SIGNATURE_RESPONSE response;

        if (WaitForSingleObject(gStopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }
        ZeroMemory(&signatureRequest, sizeof(signatureRequest));
        result = UfProcSendIoctl(
            UF_PROC_IOCTL_WAIT_SIGNATURE,
            &waitRequest,
            sizeof(waitRequest),
            &signatureRequest,
            sizeof(signatureRequest),
            &bytesReturned);
        if (result == ERROR_OPERATION_ABORTED ||
            result == ERROR_INVALID_HANDLE ||
            result == ERROR_DEVICE_NOT_CONNECTED) {
            break;
        }
        if (result != ERROR_SUCCESS ||
            bytesReturned != sizeof(signatureRequest) ||
            signatureRequest.Header.Version != UF_PROC_PROTOCOL_VERSION ||
            signatureRequest.Header.Size != sizeof(signatureRequest) ||
            signatureRequest.PathLengthChars >= UF_PROC_MAX_PROCESS_PATH_CHARS) {
            continue;
        }
        ZeroMemory(&response, sizeof(response));
        response.Header.Version = UF_PROC_PROTOCOL_VERSION;
        response.Header.Size = sizeof(response);
        response.RequestId = signatureRequest.RequestId;
        response.Decision = UfProcVerifyImageSignature(&signatureRequest) != 0
            ? UfProcSignatureAllow
            : UfProcSignatureDeny;
        (void)UfProcSendIoctl(
            UF_PROC_IOCTL_COMPLETE_SIGNATURE,
            &response,
            sizeof(response),
            NULL,
            0,
            NULL);
    }
    return ERROR_SUCCESS;
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

static HANDLE
UfProcOpenDevice(
    void
    )
{
    HANDLE device;
    DWORD firstError;

    device = CreateFileW(
        UF_PROC_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device != INVALID_HANDLE_VALUE) {
        return device;
    }

    firstError = GetLastError();
    if (firstError != ERROR_FILE_NOT_FOUND && firstError != ERROR_PATH_NOT_FOUND) {
        return INVALID_HANDLE_VALUE;
    }

    /* 전역 DOS 네임스페이스를 명시한 경로도 시도해 세션별 매핑 차이를 흡수한다. */
    return CreateFileW(
        UF_PROC_DEVICE_WIN32_GLOBAL_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
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
    device = UfProcOpenDevice();
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
    request->PolicyCount = Policy->RuleCount;

    for (index = 0; index < Policy->RuleCount; ++index) {
        const UF_PROC_RULE_INPUT* input = &Policy->Rules[index];
        UF_PROC_POLICY_RULE* rule = &request->Policies[index];

        if (input->RuleId == 0 || input->Image == NULL ||
            UfProcIsCriticalImage(input->Image)) {
            result = ERROR_ACCESS_DENIED;
            goto Exit;
        }
        rule->RuleId = input->RuleId;
        if (input->MatchMode == UfProcMatchFullPath) {
            result = UfProcBuildFullPathRule(input->Image, rule);
        } else if (input->MatchMode == UfProcMatchImageName &&
                   UfProcFindImageName(input->Image) == input->Image) {
            result = UfProcCopyString(
                input->Image,
                rule->ProcessName,
                UF_PROC_MAX_PROCESS_NAME_CHARS,
                &rule->ProcessNameLengthChars);
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

static unsigned long
UfProcSendPolicyV2(
    unsigned long ControlCode,
    const UF_PROC_POLICY_INPUT_V2* Policy
    )
{
    UF_PROC_REPLACE_POLICY* request;
    unsigned long index;
    unsigned long result = ERROR_SUCCESS;

    InterlockedExchange(&gPolicyCallStage, 1);

    if (Policy == NULL || Policy->PolicyCount > UF_PROC_MAX_POLICIES ||
        (Policy->PolicyCount != 0 && Policy->Policies == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }
    request = (UF_PROC_REPLACE_POLICY*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*request));
    if (request == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    request->Header.Version = UF_PROC_PROTOCOL_VERSION;
    request->Header.Size = sizeof(*request);
    request->PolicyCount = Policy->PolicyCount;
    for (index = 0; index < Policy->PolicyCount; ++index) {
        result = UfProcBuildPolicyRuleV2(
            &Policy->Policies[index],
            &request->Policies[index]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }
    InterlockedExchange(&gPolicyCallStage, 2);
    result = UfProcSendIoctl(
        ControlCode,
        request,
        sizeof(*request),
        NULL,
        0,
        NULL);
    InterlockedExchange(&gPolicyCallStage, result == ERROR_SUCCESS ? 3 : 4);
Exit:
    SecureZeroMemory(request, sizeof(*request));
    HeapFree(GetProcessHeap(), 0, request);
    return result;
}

unsigned long __stdcall
UfProcGetPolicyCallStage(
    void
    )
{
    return (unsigned long)InterlockedCompareExchange(&gPolicyCallStage, 0, 0);
}

unsigned long __stdcall
UfProcReplacePolicyV2(
    const UF_PROC_POLICY_INPUT_V2* Policy
    )
{
    return UfProcSendPolicyV2(UF_PROC_IOCTL_REPLACE_POLICY, Policy);
}

unsigned long __stdcall
UfProcAddPolicyV2(
    const UF_PROC_POLICY_INPUT_V2* Policy
    )
{
    return UfProcSendPolicyV2(UF_PROC_IOCTL_ADD_POLICY, Policy);
}

unsigned long __stdcall
UfProcRemovePolicyNames(
    const wchar_t* const* ProcessNames,
    unsigned long ProcessNameCount
    )
{
    UF_PROC_REMOVE_POLICY* request;
    unsigned long index;
    unsigned long result = ERROR_SUCCESS;

    if (ProcessNameCount > UF_PROC_MAX_POLICIES ||
        (ProcessNameCount != 0 && ProcessNames == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }
    request = (UF_PROC_REMOVE_POLICY*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*request));
    if (request == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    request->Header.Version = UF_PROC_PROTOCOL_VERSION;
    request->Header.Size = sizeof(*request);
    request->PolicyCount = ProcessNameCount;
    for (index = 0; index < ProcessNameCount; ++index) {
        if (ProcessNames[index] == NULL) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }
        result = UfProcCopyString(
            ProcessNames[index],
            request->Policies[index].ProcessName,
            UF_PROC_MAX_PROCESS_NAME_CHARS,
            &request->Policies[index].ProcessNameLengthChars);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }
    result = UfProcSendIoctl(
        UF_PROC_IOCTL_REMOVE_POLICY,
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
    HANDLE device;
    unsigned long bytesReturned = 0;
    unsigned long result;

    if (State == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(State, sizeof(*State));
    /*
     * 진단 조회는 정책 적용 요청과 사용자 모드 SRW 락을 공유하지 않습니다.
     * 적용 IOCTL이 반환되지 않아도 동일 디바이스의 QUERY_STATE를 직접 보내
     * 커널 디스패치/락 교착 여부를 분리해서 확인할 수 있어야 합니다.
     */
    device = gDevice;
    if (device == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }
    result = DeviceIoControl(
        device,
        UF_PROC_IOCTL_QUERY_STATE,
        NULL,
        0,
        State,
        sizeof(*State),
        &bytesReturned,
        NULL) ? ERROR_SUCCESS : GetLastError();
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
    HANDLE signatureThread;

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
    signatureThread = CreateThread(NULL, 0, UfProcSignatureMain, NULL, 0, NULL);
    if (signatureThread == NULL) {
        unsigned long result = GetLastError();
        SetEvent(stopEvent);
        ReleaseSRWLockExclusive(&gLock);
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        CloseHandle(stopEvent);
        AcquireSRWLockExclusive(&gLock);
        gStopEvent = NULL;
        gCallback = NULL;
        gCallbackContext = NULL;
        ReleaseSRWLockExclusive(&gLock);
        return result;
    }
    gReceiverThread = thread;
    gSignatureThread = signatureThread;
    ReleaseSRWLockExclusive(&gLock);
    return ERROR_SUCCESS;
}

void __stdcall
UfProcStopEventReceiver(
    void
    )
{
    HANDLE thread;
    HANDLE signatureThread;
    HANDLE stopEvent;

    AcquireSRWLockExclusive(&gLock);
    thread = gReceiverThread;
    signatureThread = gSignatureThread;
    stopEvent = gStopEvent;
    if (thread == NULL && signatureThread == NULL) {
        ReleaseSRWLockExclusive(&gLock);
        return;
    }
    SetEvent(stopEvent);
    ReleaseSRWLockExclusive(&gLock);

    WaitForSingleObject(thread, INFINITE);
    if (signatureThread != NULL) {
        WaitForSingleObject(signatureThread, INFINITE);
    }
    CloseHandle(thread);
    if (signatureThread != NULL) {
        CloseHandle(signatureThread);
    }
    CloseHandle(stopEvent);

    AcquireSRWLockExclusive(&gLock);
    gReceiverThread = NULL;
    gSignatureThread = NULL;
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
