#define WIN32_LEAN_AND_MEAN
#define UF_FLTWARP_EXPORTS
#include <windows.h>
#include <fltuser.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* 실제 전송 함수만 교체한다. 드라이버 연결이나 원시 디스크 접근은 하지 않는다. */
static HRESULT WINAPI TestFilterSendMessage(
    HANDLE Port, LPVOID Input, DWORD InputBytes,
    LPVOID Output, DWORD OutputBytes, LPDWORD ReturnedBytes);
#define FilterSendMessage TestFilterSendMessage
#include "../../uf_fltwarp/src/uf_fltwarp.c"
#undef FilterSendMessage

static SRWLOCK gTestLogLock = SRWLOCK_INIT;
static char gTestLog[131072];
static size_t gTestLogBytes;
static unsigned int gTestChecks;
static unsigned int gTestFailures;
static unsigned int gTestSends;
static HRESULT gTestResult;
static DWORD gTestReturnedBytes;
static DWORD gTestInputBytes;
static DWORD gTestOutputBytes;
static DWORD gTestWorkerThread;
static BOOL gTestValidDuplicate;
static UF_SET_BOOT_PROTECTION gTestRequest;
static UF_BOOT_PROTECTION_STATE gTestReply;

static void TestAppendLog(const char* Message)
{
    size_t length = strlen(Message);
    AcquireSRWLockExclusive(&gTestLogLock);
    if (length + 2 < sizeof(gTestLog) - gTestLogBytes) {
        CopyMemory(gTestLog + gTestLogBytes, Message, length);
        gTestLogBytes += length;
        gTestLog[gTestLogBytes++] = '\n';
        gTestLog[gTestLogBytes] = '\0';
    }
    ReleaseSRWLockExclusive(&gTestLogLock);
}

void UfLogInitialize(void) {}
void UfLogShutdown(void) {}
void UfLogBootstrapWrite(const char* Message) { TestAppendLog(Message); }
void UfLogWrite(int Level, const char* Message)
{
    UNREFERENCED_PARAMETER(Level);
    TestAppendLog(Message);
}
void UfLogWriteFormat(int Level, const char* Format, ...)
{
    char message[8192];
    va_list arguments;
    UNREFERENCED_PARAMETER(Level);
    va_start(arguments, Format);
    (void)vsnprintf(message, sizeof(message), Format, arguments);
    va_end(arguments);
    message[sizeof(message) - 1] = '\0';
    TestAppendLog(message);
}

static HRESULT WINAPI TestFilterSendMessage(
    HANDLE Port, LPVOID Input, DWORD InputBytes,
    LPVOID Output, DWORD OutputBytes, LPDWORD ReturnedBytes)
{
    DWORD flags = 0;
    ++gTestSends;
    gTestInputBytes = InputBytes;
    gTestOutputBytes = OutputBytes;
    gTestWorkerThread = GetCurrentThreadId();
    gTestValidDuplicate = Port != gPort && GetHandleInformation(Port, &flags);
    ZeroMemory(&gTestRequest, sizeof(gTestRequest));
    if (Input != NULL && InputBytes <= sizeof(gTestRequest)) {
        CopyMemory(&gTestRequest, Input, InputBytes);
    }
    if (Output != NULL && OutputBytes == sizeof(gTestReply)) {
        /* 실패 응답에도 쓰레기 값을 넣어 공개 출력으로 유출되지 않는지 확인한다. */
        CopyMemory(Output, &gTestReply, sizeof(gTestReply));
    }
    if (ReturnedBytes != NULL) *ReturnedBytes = gTestReturnedBytes;
    /* 마지막 오류는 의도적으로 HRESULT와 다르게 설정한다. */
    SetLastError(ERROR_ACCESS_DENIED);
    return gTestResult;
}

static void TestCheck(BOOL Condition, const char* Name)
{
    ++gTestChecks;
    if (!Condition) {
        ++gTestFailures;
        printf("FAIL: %s\n", Name);
    }
}

static void TestReset(void)
{
    ZeroMemory(gTestLog, sizeof(gTestLog));
    gTestLogBytes = 0;
    gTestSends = 0;
    gTestResult = S_OK;
    gTestReturnedBytes = sizeof(gTestReply);
    gTestInputBytes = 0;
    gTestOutputBytes = 0;
    gTestValidDuplicate = FALSE;
    ZeroMemory(&gTestReply, sizeof(gTestReply));
    gTestReply.Version = UF_PROTOCOL_VERSION;
    gTestReply.Size = sizeof(gTestReply);
    gTestReply.Enabled = 1;
    gTestReply.ProtectedBytes = UF_BOOT_PROTECTED_BYTES;
    gTestReply.InspectedWrites = 123;
    gTestReply.BlockedWrites = 45;
    gTestReply.InspectionFailures = 6;
}

static BOOL TestIsZero(const void* Buffer, size_t Size)
{
    const unsigned char* bytes = (const unsigned char*)Buffer;
    size_t index;
    for (index = 0; index < Size; ++index) {
        if (bytes[index] != 0) return FALSE;
    }
    return TRUE;
}

static void TestBadReply(unsigned int Case)
{
    UF_BOOT_PROTECTION_STATE state;
    unsigned long expected = ERROR_REVISION_MISMATCH;
    TestReset();
    switch (Case) {
    case 0: gTestReturnedBytes = sizeof(gTestReply) - 1; break;
    case 1: gTestReply.Version = UF_PROTOCOL_VERSION + 1; break;
    case 2: gTestReply.Size = sizeof(gTestReply) - 1; break;
    case 3: gTestReply.Enabled = 2; expected = ERROR_INVALID_DATA; break;
    default: gTestReply.ProtectedBytes = 4096; expected = ERROR_INVALID_DATA; break;
    }
    FillMemory(&state, sizeof(state), 0xA5);
    TestCheck(UfFltQueryBootProtection(&state) == expected, "invalid reply rejected");
    TestCheck(TestIsZero(&state, sizeof(state)), "invalid reply output is zero");
    TestCheck(gTestSends == 1, "invalid reply not retried");
}

int main(void)
{
    UF_BOOT_PROTECTION_STATE state;
    unsigned int index;
    DWORD callerThread = GetCurrentThreadId();

    /* 포트 대신 일반 이벤트 핸들만 사용하여 DuplicateHandle 경로를 실행한다. */
    gPort = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (gPort == NULL) {
        printf("FAIL: local event creation error=%lu\n", GetLastError());
        return 1;
    }

    TestReset();
    gTestReturnedBytes = 0;
    TestCheck(UfFltSetBootProtection(1) == ERROR_SUCCESS, "SET success");
    TestCheck(gTestSends == 1 && gTestInputBytes == 24 && gTestOutputBytes == 0,
        "SET exact 24-byte input and no output");
    TestCheck(gTestRequest.Header.Version == 2 && gTestRequest.Header.Size == 24 &&
        gTestRequest.Header.Command == 5 && gTestRequest.Header.Reserved == 0 &&
        gTestRequest.Enabled == 1 && gTestRequest.Reserved == 0, "SET exact request fields");
    TestCheck(gTestValidDuplicate, "worker uses duplicated local event handle");
    TestCheck(gTestWorkerThread != callerThread, "real worker thread executed");

    TestReset();
    gTestReturnedBytes = 0;
    TestCheck(UfFltSetBootProtection(0) == ERROR_SUCCESS && gTestRequest.Enabled == 0,
        "STOP carries zero");

    TestReset();
    TestCheck(UfFltSetBootProtection(2) == ERROR_INVALID_PARAMETER && gTestSends == 0,
        "invalid Enabled is rejected before transport");
    TestCheck(UfFltQueryBootProtection(NULL) == ERROR_INVALID_PARAMETER && gTestSends == 0,
        "NULL state is rejected before transport");

    TestReset();
    FillMemory(&state, sizeof(state), 0xA5);
    TestCheck(UfFltQueryBootProtection(&state) == ERROR_SUCCESS, "QUERY success");
    TestCheck(gTestSends == 1 && gTestInputBytes == 16 && gTestOutputBytes == 40,
        "QUERY exact 16-byte input and 40-byte output");
    TestCheck(gTestRequest.Header.Version == 2 && gTestRequest.Header.Size == 16 &&
        gTestRequest.Header.Command == 6 && gTestRequest.Header.Reserved == 0,
        "QUERY exact request fields");
    TestCheck(memcmp(&state, &gTestReply, sizeof(state)) == 0, "valid QUERY copied unchanged");

    TestReset();
    gTestResult = HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    FillMemory(&state, sizeof(state), 0xA5);
    TestCheck(UfFltQueryBootProtection(&state) == ERROR_INVALID_FUNCTION,
        "HRESULT 0x80070001 maps to error 1, not stale GetLastError 5");
    TestCheck(TestIsZero(&state, sizeof(state)), "failed QUERY output is zero");
    TestCheck(gTestSends == 1, "failed QUERY not retried");
    TestCheck(strstr(gTestLog, "HRESULT=0x80070001") != NULL, "raw HRESULT retained in log");
    TestCheck(strstr(gTestLog, "lastErrorSnapshot=5") != NULL, "last-error snapshot distinguished");
    TestCheck(strstr(gTestLog, "stage=FilterSendMessage-enter") != NULL &&
        strstr(gTestLog, "stage=FilterSendMessage-return") != NULL &&
        strstr(gTestLog, "stage=request-complete") != NULL, "transport stages retained in log");
    TestCheck(strstr(gTestLog, "GetLastError=1 (0x00000001)") != NULL,
        "mapped error retained in log");

    TestReset();
    gTestResult = HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    TestCheck(UfFltSetBootProtection(1) == ERROR_INVALID_FUNCTION && gTestSends == 1,
        "failed SET maps error without retry");
    TestCheck(strstr(gTestLog, "HRESULT=0x80070001") != NULL,
        "failed SET retains raw HRESULT");

    TestReset();
    gTestResult = E_FAIL;
    TestCheck(UfFltSetBootProtection(1) == (unsigned long)E_FAIL,
        "non-Win32 HRESULT is not truncated");

    for (index = 0; index < 5; ++index) TestBadReply(index);

    CloseHandle(gPort);
    gPort = INVALID_HANDLE_VALUE;
    TestReset();
    TestCheck(UfFltSetBootProtection(1) == ERROR_INVALID_HANDLE,
        "disconnected SET rejected");
    FillMemory(&state, sizeof(state), 0xA5);
    TestCheck(UfFltQueryBootProtection(&state) == ERROR_INVALID_HANDLE,
        "disconnected QUERY rejected");
    TestCheck(TestIsZero(&state, sizeof(state)), "disconnected QUERY output is zero");
    TestCheck(gTestSends == 0, "disconnected calls never enter transport");

    printf("FileBootTransportChecks: checks=%u failures=%u (mock transport; no driver connection)\n",
        gTestChecks, gTestFailures);
    return gTestFailures == 0 ? 0 : 1;
}
