#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include <limits.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include "../include/uf_fltwarp.h"
#include "../include/uf_log.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

typedef struct _UF_USER_EVENT_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    UF_FILE_EVENT_V2 Event;
} UF_USER_EVENT_MESSAGE;

static SRWLOCK gLock = SRWLOCK_INIT;
static HANDLE gPort = INVALID_HANDLE_VALUE;
static HANDLE gStopEvent = NULL;
static HANDLE gReceiverThread = NULL;
static UF_FLT_EVENT_CALLBACK gCallback = NULL;
static UF_FLT_EVENT_CALLBACK_V2 gCallbackV2 = NULL;
static void* gCallbackContext = NULL;

// 커널 응답이 반환되지 않아도 사용자 모드 호출이 무한 대기하지 않도록 제한합니다.
#define UF_FILTER_SEND_TIMEOUT_MILLISECONDS 5000UL

typedef struct _UF_SEND_CONTEXT {
    HANDLE Port;
    HANDLE CompleteEvent;
    void* Request;
    unsigned long RequestSize;
    void* Reply;
    unsigned long ReplySize;
    unsigned long BytesReturned;
    HRESULT Result;
    volatile LONG References;
} UF_SEND_CONTEXT;

static unsigned long UfStartEventReceiverInternal(
    UF_FLT_EVENT_CALLBACK Callback,
    UF_FLT_EVENT_CALLBACK_V2 CallbackV2,
    void* Context);

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
            message.Event.Size != sizeof(UF_FILE_EVENT_V2)) {
            continue;
        }
        AcquireSRWLockShared(&gLock);
        callback = gCallback;
        UF_FLT_EVENT_CALLBACK_V2 callbackV2 = gCallbackV2;
        callbackContext = gCallbackContext;
        ReleaseSRWLockShared(&gLock);
        if (callback != NULL) {
            UF_FILE_EVENT legacyEvent;
            ZeroMemory(&legacyEvent, sizeof(legacyEvent));
            legacyEvent.Version = UF_LEGACY_PUBLIC_VERSION;
            legacyEvent.Size = sizeof(legacyEvent);
            legacyEvent.ProcessId = message.Event.ProcessId;
            legacyEvent.DesiredAccess = message.Event.DesiredAccess;
            legacyEvent.Disposition = message.Event.Disposition;
            legacyEvent.Action = message.Event.Action;
            legacyEvent.PathLengthChars = message.Event.PathLengthChars;
            legacyEvent.ImageLengthChars = message.Event.ImageLengthChars;
            CopyMemory(legacyEvent.Path, message.Event.Path, sizeof(legacyEvent.Path));
            CopyMemory(legacyEvent.Image, message.Event.Image, sizeof(legacyEvent.Image));
            callback(&legacyEvent, callbackContext);
        }
        if (callbackV2 != NULL) {
            callbackV2(&message.Event, callbackContext);
        }
    }

    CloseHandle(overlapped.hEvent);
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltInitialize(void)
{
    UfLogBootstrapWrite("UfFltInitialize 진입");
    UfLogInitialize();
    UfLogBootstrapWrite("UfLogInitialize 호출 완료");
    UfLogWrite(UfLogInfo, "uf_fltwarp 초기화");
    UfLogBootstrapWrite("UfLogWrite 호출 완료");
    return ERROR_SUCCESS;
}

void __stdcall
UfFltShutdown(void)
{
    UfLogWrite(UfLogInfo, "uf_fltwarp 종료 시작");
    UfFltDisconnect();
    UfLogShutdown();
}

unsigned long __stdcall
UfFltConnect(void)
{
    HANDLE port;
    HRESULT result;

    AcquireSRWLockExclusive(&gLock);
    if (gPort != INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        UfLogWrite(UfLogDebug, "통신 포트가 이미 연결됨");
        return ERROR_ALREADY_EXISTS;
    }
    result = FilterConnectCommunicationPort(
        UF_FILTER_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(result)) {
        ReleaseSRWLockExclusive(&gLock);
        result = (HRESULT)UfResultFromHresult(result);
        UfLogWriteFormat(UfLogError, "통신 포트 연결 실패 error=%lu", (unsigned long)result);
        return (unsigned long)result;
    }
    gPort = port;
    ReleaseSRWLockExclusive(&gLock);
    UfLogWrite(UfLogInfo, "통신 포트 연결 성공");
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
        UfLogWrite(UfLogInfo, "통신 포트 연결 해제");
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

static void
UfReleaseSendContext(_In_ UF_SEND_CONTEXT* Context)
{
    if (InterlockedDecrement(&Context->References) != 0) {
        return;
    }
    if (Context->CompleteEvent != NULL) {
        CloseHandle(Context->CompleteEvent);
    }
    if (Context->Port != NULL && Context->Port != INVALID_HANDLE_VALUE) {
        CloseHandle(Context->Port);
    }
    if (Context->Request != NULL) {
        SecureZeroMemory(Context->Request, Context->RequestSize);
        HeapFree(GetProcessHeap(), 0, Context->Request);
    }
    if (Context->Reply != NULL) {
        SecureZeroMemory(Context->Reply, Context->ReplySize);
        HeapFree(GetProcessHeap(), 0, Context->Reply);
    }
    HeapFree(GetProcessHeap(), 0, Context);
}

static DWORD WINAPI
UfSendRequestThread(_In_ void* Parameter)
{
    UF_SEND_CONTEXT* context = (UF_SEND_CONTEXT*)Parameter;

    context->BytesReturned = 0;
    context->Result = FilterSendMessage(
        context->Port,
        context->Request,
        context->RequestSize,
        context->ReplySize == 0 ? NULL : context->Reply,
        context->ReplySize,
        &context->BytesReturned);
    UfLogBootstrapWrite("FilterSendMessage 종료");
    SetEvent(context->CompleteEvent);
    UfReleaseSendContext(context);
    return 0;
}

static unsigned long
UfSendRequest(
    const void* Request,
    unsigned long RequestSize,
    void* Reply,
    unsigned long ReplySize,
    unsigned long* ReplySizeReturned)
{
    UF_SEND_CONTEXT* context = NULL;
    HANDLE port;
    HANDLE duplicatedPort = NULL;
    HANDLE thread = NULL;
    DWORD waitResult;
    const UF_MESSAGE_HEADER* header = (const UF_MESSAGE_HEADER*)Request;
    unsigned long result;

    if (Request == NULL || RequestSize < sizeof(UF_MESSAGE_HEADER)) {
        UfLogWrite(UfLogError, "잘못된 통신 요청 인수");
        return ERROR_INVALID_PARAMETER;
    }
    UfLogWriteFormat(UfLogDebug, "통신 요청 command=%lu size=%lu",
        header->Command, RequestSize);
    AcquireSRWLockShared(&gLock);
    port = gPort;
    if (port == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(&gLock);
        UfLogWrite(UfLogWarn, "통신 요청 실패: 연결되지 않음");
        return ERROR_INVALID_HANDLE;
    }
    if (!DuplicateHandle(
            GetCurrentProcess(), port,
            GetCurrentProcess(), &duplicatedPort,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        result = GetLastError();
        ReleaseSRWLockShared(&gLock);
        UfLogWriteFormat(UfLogError,
            "통신 포트 핸들 복제 실패 error=%lu", result);
        return result;
    }
    ReleaseSRWLockShared(&gLock);

    context = (UF_SEND_CONTEXT*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*context));
    if (context == NULL) {
        CloseHandle(duplicatedPort);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    context->Port = duplicatedPort;
    context->RequestSize = RequestSize;
    context->ReplySize = ReplySize;
    context->References = 2;
    context->Request = HeapAlloc(GetProcessHeap(), 0, RequestSize);
    if (context->Request == NULL) {
        UfReleaseSendContext(context);
        UfReleaseSendContext(context);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    CopyMemory(context->Request, Request, RequestSize);
    if (ReplySize != 0) {
        context->Reply = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReplySize);
        if (context->Reply == NULL) {
            UfReleaseSendContext(context);
            UfReleaseSendContext(context);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    context->CompleteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (context->CompleteEvent == NULL) {
        result = GetLastError();
        UfReleaseSendContext(context);
        UfReleaseSendContext(context);
        return result;
    }

    UfLogBootstrapWrite("FilterSendMessage 시작");
    thread = CreateThread(NULL, 0, UfSendRequestThread, context, 0, NULL);
    if (thread == NULL) {
        result = GetLastError();
        UfReleaseSendContext(context);
        UfReleaseSendContext(context);
        return result;
    }
    waitResult = WaitForSingleObject(
        context->CompleteEvent, UF_FILTER_SEND_TIMEOUT_MILLISECONDS);
    if (waitResult == WAIT_TIMEOUT) {
        // 작업 스레드는 자체 참조를 보유하므로 요청 버퍼를 안전하게 정리합니다.
        UfLogBootstrapWrite("FilterSendMessage 시간 제한");
        CloseHandle(thread);
        UfReleaseSendContext(context);
        return ERROR_TIMEOUT;
    }
    if (waitResult != WAIT_OBJECT_0) {
        result = GetLastError();
        CloseHandle(thread);
        UfReleaseSendContext(context);
        return result == ERROR_SUCCESS ? ERROR_GEN_FAILURE : result;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    if (Reply != NULL && ReplySize != 0 && context->Reply != NULL) {
        CopyMemory(Reply, context->Reply, ReplySize);
    }
    if (ReplySizeReturned != NULL) {
        *ReplySizeReturned = context->BytesReturned;
    }
    result = SUCCEEDED(context->Result)
        ? ERROR_SUCCESS : UfResultFromHresult(context->Result);
    if (FAILED(context->Result)) {
        UfLogWriteFormat(UfLogError, "통신 요청 실패 command=%lu error=%lu",
            header->Command, result);
    }
    UfReleaseSendContext(context);
    return result;
}

static int
UfHexValue(wchar_t Character)
{
    if (Character >= L'0' && Character <= L'9') {
        return (int)(Character - L'0');
    }
    if (Character >= L'a' && Character <= L'f') {
        return (int)(Character - L'a') + 10;
    }
    if (Character >= L'A' && Character <= L'F') {
        return (int)(Character - L'A') + 10;
    }
    return -1;
}

static unsigned long
UfParseHex(
    const wchar_t* Text,
    unsigned char* Destination,
    unsigned long Capacity,
    unsigned long* LengthBytes)
{
    size_t length;
    size_t index;
    int high;
    int low;

    if (Text == NULL || Destination == NULL || LengthBytes == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    length = wcslen(Text);
    if ((length & 1u) != 0 || length / 2 > Capacity) {
        return ERROR_INVALID_DATA;
    }
    for (index = 0; index < length / 2; ++index) {
        high = UfHexValue(Text[index * 2]);
        low = UfHexValue(Text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return ERROR_INVALID_DATA;
        }
        Destination[index] = (unsigned char)((high << 4) | low);
    }
    *LengthBytes = (unsigned long)(length / 2);
    return ERROR_SUCCESS;
}

static unsigned long
UfFillV2PathRule(
    const UF_FLT_PATH_INPUT_V2* Input,
    UF_PATH_RULE_V2* Rule)
{
    unsigned long result;

    if (Input == NULL || Rule == NULL || Input->RuleId == 0 ||
        (Input->Mode != UfRuleMonitor && Input->Mode != UfRuleProtected)) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(Rule, sizeof(*Rule));
    Rule->RuleId = Input->RuleId;
    Rule->Mode = Input->Mode;
    result = UfFltDosPathToNtPath(
        Input->DosPath, Rule->Path, UF_MAX_PATH_CHARS);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    Rule->PathLengthChars = (unsigned long)wcslen(Rule->Path);
    return Rule->PathLengthChars == 0 ? ERROR_BAD_PATHNAME : ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltReplacePolicyV2(const UF_FLT_POLICY_INPUT_V2* Policy)
{
    UF_REPLACE_POLICY_V2* request;
    unsigned long index;
    unsigned long result = ERROR_SUCCESS;
    unsigned long serialLength;
    unsigned long long generation;

    if (Policy == NULL ||
        Policy->PathRuleCount > UF_MAX_RULES ||
        Policy->MonitorExceptionCount > UF_MAX_RULES ||
        Policy->ProtectedProcessRuleCount > UF_MAX_PROTECTED_PROCESS_RULES ||
        Policy->SignerRuleCount > UF_MAX_SIGNER_RULES ||
        (Policy->PathRuleCount != 0 && Policy->PathRules == NULL) ||
        (Policy->MonitorExceptionCount != 0 && Policy->MonitorExceptions == NULL) ||
        (Policy->ProtectedProcessRuleCount != 0 && Policy->ProtectedProcesses == NULL) ||
        (Policy->SignerRuleCount != 0 && Policy->Signers == NULL) ||
        Policy->RevocationTimeoutMilliseconds > 60000 ||
        Policy->RevocationTimeoutAction > UfRevocationTimeoutAllowLocalTrust) {
        UfLogWrite(UfLogError, "V2 정책 입력 검증 실패");
        return ERROR_INVALID_PARAMETER;
    }

    UfLogWriteFormat(UfLogInfo,
        "V2 정책 적용 시작 paths=%lu protected=%lu signers=%lu",
        Policy->PathRuleCount, Policy->ProtectedProcessRuleCount,
        Policy->SignerRuleCount);

    request = (UF_REPLACE_POLICY_V2*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*request));
    if (request == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    generation = Policy->PolicyGeneration != 0
        ? Policy->PolicyGeneration : GetTickCount64();
    if (generation == 0) {
        generation = 1;
    }
    request->Header.Version = UF_PROTOCOL_VERSION;
    request->Header.Size = sizeof(*request);
    request->Header.Command = UfCommandReplacePolicy;
    request->PolicyGeneration = generation;
    request->PathRuleCount = Policy->PathRuleCount;
    request->MonitorExceptionCount = Policy->MonitorExceptionCount;
    request->ProtectedProcessRuleCount = Policy->ProtectedProcessRuleCount;
    request->SignerRuleCount = Policy->SignerRuleCount;
    request->Revocation.OnlineCheckEnabled = Policy->OnlineRevocationEnabled != 0;
    request->Revocation.TimeoutMilliseconds = Policy->RevocationTimeoutMilliseconds;
    request->Revocation.TimeoutAction = Policy->RevocationTimeoutAction;
    request->Revocation.TerminateOnRevoked = Policy->TerminateOnRevoked != 0;

    for (index = 0; index < Policy->PathRuleCount; ++index) {
        result = UfFillV2PathRule(
            &Policy->PathRules[index], &request->PathRules[index]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }
    for (index = 0; index < Policy->MonitorExceptionCount; ++index) {
        result = UfFillImageRule(
            Policy->MonitorExceptions[index], &request->MonitorExceptions[index]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }
    for (index = 0; index < Policy->SignerRuleCount; ++index) {
        const UF_FLT_SIGNER_INPUT* input = &Policy->Signers[index];
        UF_SIGNER_RULE* signer = &request->Signers[index];
        if (input->RuleId == 0 ||
            (input->MatchType != UfSignerMatchThumbprintSha256 &&
             input->MatchType != UfSignerMatchIssuerSha256AndSerial)) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }
        signer->RuleId = input->RuleId;
        signer->MatchType = input->MatchType;
        if (input->MatchType == UfSignerMatchThumbprintSha256) {
            result = UfParseHex(
                input->ThumbprintSha256Hex, signer->ThumbprintSha256,
                UF_CERT_SHA256_BYTES, &serialLength);
            if (result != ERROR_SUCCESS || serialLength != UF_CERT_SHA256_BYTES) {
                result = ERROR_INVALID_DATA;
                goto Exit;
            }
        } else {
            result = UfParseHex(
                input->IssuerSha256Hex, signer->IssuerSha256,
                UF_CERT_SHA256_BYTES, &serialLength);
            if (result != ERROR_SUCCESS || serialLength != UF_CERT_SHA256_BYTES) {
                result = ERROR_INVALID_DATA;
                goto Exit;
            }
            result = UfParseHex(
                input->SerialNumberHex, signer->SerialNumber,
                UF_CERT_SERIAL_BYTES, &signer->SerialLengthBytes);
            if (result != ERROR_SUCCESS || signer->SerialLengthBytes == 0) {
                result = ERROR_INVALID_DATA;
                goto Exit;
            }
        }
    }
    for (index = 0; index < Policy->ProtectedProcessRuleCount; ++index) {
        const UF_FLT_PROTECTED_PROCESS_INPUT* input = &Policy->ProtectedProcesses[index];
        UF_PROTECTED_PROCESS_RULE* process = &request->ProtectedProcesses[index];
        if (input->RuleId == 0 || input->FolderRuleId == 0 ||
            (input->Reserved & (unsigned short)~UF_PROCESS_RULE_FLAG_ALLOWED_MASK) != 0 ||
            ((input->Reserved & UF_PROCESS_RULE_FLAG_REQUIRE_CODE_SIGNATURE) != 0 &&
                input->SignerRuleId == 0) ||
            input->Access == PF_ACCESS_NONE ||
            (input->Access & (unsigned short)~PF_ACCESS_ALL) != 0) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }
        ZeroMemory(process, sizeof(*process));
        process->RuleId = input->RuleId;
        process->FolderRuleId = input->FolderRuleId;
        process->SignerRuleId = input->SignerRuleId;
        process->Access = input->Access;
        process->Reserved16 = input->Reserved;
        result = UfFltDosPathToNtPath(
            input->DosImagePath, process->Image, UF_MAX_IMAGE_CHARS);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
        process->ImageLengthChars = (unsigned long)wcslen(process->Image);
    }
    UfLogBootstrapWrite("V2 정책 요청 전송 시작");
    result = UfSendRequest(request, sizeof(*request), NULL, 0, NULL);
    UfLogBootstrapWrite("V2 정책 요청 전송 완료");

Exit:
    SecureZeroMemory(request, sizeof(*request));
    HeapFree(GetProcessHeap(), 0, request);
    UfLogWriteFormat(result == ERROR_SUCCESS ? UfLogInfo : UfLogError,
        "V2 정책 적용 종료 error=%lu", result);
    return result;
}

unsigned long __stdcall
UfFltReplacePolicy(const UF_FLT_POLICY_INPUT* Policy)
{
    UF_FLT_POLICY_INPUT_V2 compatibilityPolicy;
    UF_FLT_PATH_INPUT_V2 compatibilityPaths[UF_MAX_RULES];
    unsigned long index;

    if (Policy == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (Policy->AllowedImageCount == 0) {
        ZeroMemory(&compatibilityPolicy, sizeof(compatibilityPolicy));
        ZeroMemory(compatibilityPaths, sizeof(compatibilityPaths));
        compatibilityPolicy.PathRuleCount = Policy->PathRuleCount;
        compatibilityPolicy.MonitorExceptionCount = Policy->MonitorExceptionCount;
        compatibilityPolicy.PathRules = compatibilityPaths;
        compatibilityPolicy.MonitorExceptions = Policy->MonitorExceptions;
        for (index = 0; index < Policy->PathRuleCount; ++index) {
            compatibilityPaths[index].RuleId = index + 1;
            compatibilityPaths[index].Mode = Policy->PathRules[index].Mode;
            compatibilityPaths[index].DosPath = Policy->PathRules[index].DosPath;
        }
        return UfFltReplacePolicyV2(&compatibilityPolicy);
    }
    return ERROR_REVISION_MISMATCH;

#if 0
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
#endif
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
    result = (HRESULT)UfResultFromHresult(result);
    UfLogWriteFormat((unsigned long)result == ERROR_SUCCESS ? UfLogInfo : UfLogError,
        "정책 초기화 종료 error=%lu", (unsigned long)result);
    return (unsigned long)result;
}

unsigned long __stdcall
UfFltQueryState(UF_STATE_REPLY* State)
{
    UF_STATE_REPLY_V2 stateV2;
    unsigned long result;

    if (State == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    result = UfFltQueryStateV2(&stateV2);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    ZeroMemory(State, sizeof(*State));
    State->Version = UF_LEGACY_PUBLIC_VERSION;
    State->Size = sizeof(*State);
    State->PathRuleCount = stateV2.PathRuleCount;
    State->MonitorExceptionCount = stateV2.MonitorExceptionCount;
    State->AllowedImageCount = stateV2.ProtectedProcessRuleCount;
    State->Connected = stateV2.Connected;
    return ERROR_SUCCESS;

#if 0
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
#endif
}

static unsigned long
UfStartEventReceiverInternal(
    UF_FLT_EVENT_CALLBACK Callback,
    UF_FLT_EVENT_CALLBACK_V2 CallbackV2,
    void* Context)
{
    HANDLE thread;
    HANDLE stopEvent;

    if (Callback == NULL && CallbackV2 == NULL) {
        UfLogWrite(UfLogError, "이벤트 수신 콜백이 없음");
        return ERROR_INVALID_PARAMETER;
    }
    AcquireSRWLockExclusive(&gLock);
    if (gPort == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&gLock);
        UfLogWrite(UfLogWarn, "이벤트 수신 시작 실패: 연결되지 않음");
        return ERROR_INVALID_HANDLE;
    }
    if (gReceiverThread != NULL) {
        ReleaseSRWLockExclusive(&gLock);
        UfLogWrite(UfLogDebug, "이벤트 수신기가 이미 실행 중");
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
    gCallbackV2 = CallbackV2;
    gCallbackContext = Context;
    thread = CreateThread(NULL, 0, UfReceiverMain, NULL, 0, NULL);
    if (thread == NULL) {
        unsigned long error = GetLastError();
        CloseHandle(gStopEvent);
        gStopEvent = NULL;
        gCallback = NULL;
        gCallbackV2 = NULL;
        gCallbackContext = NULL;
        ReleaseSRWLockExclusive(&gLock);
        return error;
    }
    gReceiverThread = thread;
    ReleaseSRWLockExclusive(&gLock);
    UfLogWrite(UfLogInfo, "이벤트 수신 시작");
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltQueryStateV2(UF_STATE_REPLY_V2* State)
{
    UF_MESSAGE_HEADER request;
    unsigned long bytesReturned = 0;
    unsigned long result;

    if (State == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(&request, sizeof(request));
    ZeroMemory(State, sizeof(*State));
    request.Version = UF_PROTOCOL_VERSION;
    request.Size = sizeof(request);
    request.Command = UfCommandQueryState;
    result = UfSendRequest(
        &request, sizeof(request), State, sizeof(*State), &bytesReturned);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    if (bytesReturned != sizeof(*State) ||
        State->Version != UF_PROTOCOL_VERSION ||
        State->Size != sizeof(*State)) {
        return ERROR_REVISION_MISMATCH;
    }
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltSetProcessTrust(const UF_FLT_PROCESS_TRUST_INPUT* Trust)
{
    UF_PROCESS_TRUST_UPDATE update;
    unsigned long result;

    if (Trust == NULL || Trust->PolicyGeneration == 0 ||
        Trust->ProcessId == 0 || Trust->ProcessRuleId == 0 ||
        Trust->ProcessCreateTime == 0 || Trust->Access == PF_ACCESS_NONE ||
        (Trust->Access & (unsigned short)~PF_ACCESS_ALL) != 0 ||
        Trust->Decision < UfTrustAllow || Trust->Decision > UfTrustInvalidate ||
        Trust->SignerIdentity == NULL ||
        Trust->SignerIdentity->SerialLengthBytes > UF_CERT_SERIAL_BYTES) {
        UfLogWrite(UfLogError, "프로세스 신뢰 입력 검증 실패");
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(&update, sizeof(update));
    update.Header.Version = UF_PROTOCOL_VERSION;
    update.Header.Size = sizeof(update);
    update.Header.Command = UfCommandSetProcessTrust;
    update.PolicyGeneration = Trust->PolicyGeneration;
    update.ProcessCreateTime = Trust->ProcessCreateTime;
    update.ProcessId = Trust->ProcessId;
    update.ProcessRuleId = Trust->ProcessRuleId;
    update.Access = Trust->Access;
    update.Decision = Trust->Decision;
    update.Temporary = Trust->Temporary != 0;
    CopyMemory(update.ImageIdentitySha256,
        Trust->SignerIdentity->ThumbprintSha256,
        sizeof(update.ImageIdentitySha256));
    CopyMemory(update.IssuerIdentitySha256,
        Trust->SignerIdentity->IssuerSha256,
        sizeof(update.IssuerIdentitySha256));
    CopyMemory(update.SerialNumber,
        Trust->SignerIdentity->SerialNumber,
        sizeof(update.SerialNumber));
    update.SerialLengthBytes = Trust->SignerIdentity->SerialLengthBytes;
    result = UfSendRequest(&update, sizeof(update), NULL, 0, NULL);
    UfLogWriteFormat(result == ERROR_SUCCESS ? UfLogInfo : UfLogError,
        "프로세스 신뢰 전달 pid=%lu rule=%lu decision=%u error=%lu",
        Trust->ProcessId, Trust->ProcessRuleId, Trust->Decision, result);
    SecureZeroMemory(&update, sizeof(update));
    return result;
}

unsigned long __stdcall
UfFltStartEventReceiver(UF_FLT_EVENT_CALLBACK Callback, void* Context)
{
    return UfStartEventReceiverInternal(Callback, NULL, Context);
}

unsigned long __stdcall
UfFltStartEventReceiverV2(UF_FLT_EVENT_CALLBACK_V2 Callback, void* Context)
{
    return UfStartEventReceiverInternal(NULL, Callback, Context);
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
    gCallbackV2 = NULL;
    gCallbackContext = NULL;
    ReleaseSRWLockExclusive(&gLock);
    UfLogWrite(UfLogInfo, "이벤트 수신 중지");
}

static unsigned long
UfTrustStatusToError(LONG Status)
{
    HRESULT result = (HRESULT)Status;
    if (Status == ERROR_SUCCESS) {
        return ERROR_SUCCESS;
    }
    if (HRESULT_FACILITY(result) == FACILITY_WIN32) {
        return HRESULT_CODE(result);
    }
    return (unsigned long)result;
}

static unsigned long
UfGetSignerCertificate(
    const wchar_t* ImagePath,
    HCERTSTORE* CertificateStore,
    HCRYPTMSG* CryptographicMessage,
    PCCERT_CONTEXT* Certificate)
{
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    const void* queryContext = NULL;
    DWORD signerInfoSize = 0;
    CMSG_SIGNER_INFO* signerInfo = NULL;
    CERT_INFO findInfo;
    PCCERT_CONTEXT found = NULL;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, ImagePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            &encoding, &content, &format, CertificateStore,
            CryptographicMessage, &queryContext)) {
        return GetLastError();
    }
    if (!CryptMsgGetParam(
            *CryptographicMessage, CMSG_SIGNER_INFO_PARAM, 0,
            NULL, &signerInfoSize)) {
        return GetLastError();
    }
    signerInfo = (CMSG_SIGNER_INFO*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, signerInfoSize);
    if (signerInfo == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!CryptMsgGetParam(
            *CryptographicMessage, CMSG_SIGNER_INFO_PARAM, 0,
            signerInfo, &signerInfoSize)) {
        HeapFree(GetProcessHeap(), 0, signerInfo);
        return GetLastError();
    }
    ZeroMemory(&findInfo, sizeof(findInfo));
    findInfo.Issuer = signerInfo->Issuer;
    findInfo.SerialNumber = signerInfo->SerialNumber;
    found = CertFindCertificateInStore(
        *CertificateStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_FIND_SUBJECT_CERT, &findInfo, NULL);
    HeapFree(GetProcessHeap(), 0, signerInfo);
    if (found == NULL) {
        return GetLastError();
    }
    *Certificate = found;
    return ERROR_SUCCESS;
}

static unsigned long
UfHashIssuer(
    PCCERT_CONTEXT Certificate,
    unsigned char* Hash,
    DWORD HashBytes)
{
    DWORD bytes = HashBytes;
    if (!CryptHashCertificate(
            X509_ASN_ENCODING, CALG_SHA_256, 0,
            Certificate->pCertInfo->Issuer.pbData,
            Certificate->pCertInfo->Issuer.cbData,
            Hash, &bytes)) {
        return GetLastError();
    }
    return bytes == UF_CERT_SHA256_BYTES ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

static LONG
UfVerifyTrustNow(const wchar_t* ImagePath, int OnlineRevocation)
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA trustData;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = ImagePath;
    ZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = OnlineRevocation
        ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwProvFlags = OnlineRevocation ? 0 : WTD_CACHE_ONLY_URL_RETRIEVAL;
    return WinVerifyTrust(NULL, &action, &trustData);
}

typedef struct _UF_TRUST_VERIFY_CONTEXT {
    HANDLE CompletionEvent;
    LONG Status;
    wchar_t ImagePath[UF_MAX_PATH_CHARS];
} UF_TRUST_VERIFY_CONTEXT;

static DWORD WINAPI
UfVerifyTrustThread(void* Parameter)
{
    UF_TRUST_VERIFY_CONTEXT* context = (UF_TRUST_VERIFY_CONTEXT*)Parameter;
    context->Status = UfVerifyTrustNow(context->ImagePath, TRUE);
    SetEvent(context->CompletionEvent);
    CloseHandle(context->CompletionEvent);
    HeapFree(GetProcessHeap(), 0, context);
    return 0;
}

static unsigned long
UfVerifyTrustWithTimeout(
    const wchar_t* ImagePath,
    int OnlineRevocation,
    unsigned long TimeoutMilliseconds,
    LONG* TrustStatus)
{
    UF_TRUST_VERIFY_CONTEXT* context;
    HANDLE thread;
    DWORD waitResult;
    size_t length;

    if (!OnlineRevocation) {
        *TrustStatus = UfVerifyTrustNow(ImagePath, FALSE);
        return ERROR_SUCCESS;
    }
    if (TimeoutMilliseconds == 0) {
        TimeoutMilliseconds = 1000;
    }
    length = wcslen(ImagePath);
    if (length >= UF_MAX_PATH_CHARS) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    context = (UF_TRUST_VERIFY_CONTEXT*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*context));
    if (context == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    context->CompletionEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (context->CompletionEvent == NULL) {
        unsigned long error = GetLastError();
        HeapFree(GetProcessHeap(), 0, context);
        return error;
    }
    CopyMemory(context->ImagePath, ImagePath, (length + 1) * sizeof(wchar_t));
    thread = CreateThread(NULL, 0, UfVerifyTrustThread, context, 0, NULL);
    if (thread == NULL) {
        unsigned long error = GetLastError();
        CloseHandle(context->CompletionEvent);
        HeapFree(GetProcessHeap(), 0, context);
        return error;
    }
    waitResult = WaitForSingleObject(context->CompletionEvent, TimeoutMilliseconds);
    if (waitResult == WAIT_TIMEOUT) {
        CloseHandle(thread);
        return ERROR_TIMEOUT;
    }
    if (waitResult != WAIT_OBJECT_0) {
        CloseHandle(thread);
        return GetLastError();
    }
    *TrustStatus = context->Status;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltGetImageSignerIdentityWithTimeout(
    const wchar_t* ImagePath,
    int OnlineRevocation,
    unsigned long TimeoutMilliseconds,
    UF_FLT_SIGNER_IDENTITY* Identity)
{
    LONG trustStatus = ERROR_TIMEOUT;
    HCERTSTORE certificateStore = NULL;
    HCRYPTMSG cryptographicMessage = NULL;
    PCCERT_CONTEXT certificate = NULL;
    DWORD hashBytes = UF_CERT_SHA256_BYTES;
    DWORD subjectChars;
    unsigned long result;

    if (ImagePath == NULL || Identity == NULL || ImagePath[0] == L'\0') {
        UfLogWrite(UfLogError, "서명자 조회 입력 검증 실패");
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(Identity, sizeof(*Identity));
    Identity->Size = sizeof(*Identity);

    result = UfVerifyTrustWithTimeout(
        ImagePath, OnlineRevocation, TimeoutMilliseconds, &trustStatus);
    if (result != ERROR_SUCCESS && result != ERROR_TIMEOUT) {
        return result;
    }
    Identity->Trusted = trustStatus == ERROR_SUCCESS;

    result = UfGetSignerCertificate(
        ImagePath, &certificateStore, &cryptographicMessage, &certificate);
    if (result != ERROR_SUCCESS) {
        UfLogWriteFormat(UfLogError, "서명자 인증서 추출 실패 error=%lu", result);
        if (cryptographicMessage != NULL) {
            CryptMsgClose(cryptographicMessage);
        }
        if (certificateStore != NULL) {
            CertCloseStore(certificateStore, 0);
        }
        return result;
    }
    if (!CertGetCertificateContextProperty(
            certificate, CERT_SHA256_HASH_PROP_ID,
            Identity->ThumbprintSha256, &hashBytes)) {
        result = GetLastError();
        goto Exit;
    }
    result = UfHashIssuer(
        certificate, Identity->IssuerSha256, UF_CERT_SHA256_BYTES);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }
    if (certificate->pCertInfo->SerialNumber.cbData > UF_CERT_SERIAL_BYTES) {
        result = ERROR_BUFFER_OVERFLOW;
        goto Exit;
    }
    Identity->SerialLengthBytes = certificate->pCertInfo->SerialNumber.cbData;
    CopyMemory(
        Identity->SerialNumber,
        certificate->pCertInfo->SerialNumber.pbData,
        Identity->SerialLengthBytes);
    subjectChars = CertGetNameStringW(
        certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
        Identity->Subject, UF_MAX_IMAGE_CHARS);
    if (subjectChars == 0) {
        result = GetLastError();
        goto Exit;
    }
    result = ERROR_SUCCESS;

Exit:
    if (certificate != NULL) {
        CertFreeCertificateContext(certificate);
    }
    if (cryptographicMessage != NULL) {
        CryptMsgClose(cryptographicMessage);
    }
    if (certificateStore != NULL) {
        CertCloseStore(certificateStore, 0);
    }
    if (result != ERROR_SUCCESS) {
        UfLogWriteFormat(UfLogError, "서명자 식별 정보 생성 실패 error=%lu", result);
        return result;
    }
    if (result == ERROR_TIMEOUT) {
        return ERROR_TIMEOUT;
    }
    if (trustStatus != ERROR_SUCCESS && OnlineRevocation) {
        return UfTrustStatusToError(trustStatus);
    }
    UfLogWriteFormat(UfLogInfo, "서명자 식별 정보 조회 완료 trusted=%lu", Identity->Trusted);
    return ERROR_SUCCESS;
}

unsigned long __stdcall
UfFltGetImageSignerIdentity(
    const wchar_t* ImagePath,
    int OnlineRevocation,
    UF_FLT_SIGNER_IDENTITY* Identity)
{
    return UfFltGetImageSignerIdentityWithTimeout(
        ImagePath, OnlineRevocation, 1000, Identity);
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
