#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../uf_procwarp/include/uf_procwarp.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

static void
PrintError(
    const wchar_t* Operation,
    unsigned long Error
    )
{
    wchar_t message[512];

    if (UfProcGetErrorMessage(Error, message, _countof(message)) == ERROR_SUCCESS) {
        fwprintf(stderr, L"%ls 실패: %lu (%ls)\n", Operation, Error, message);
    } else {
        fwprintf(stderr, L"%ls 실패: %lu\n", Operation, Error);
    }
}

static int
ConnectOrReport(
    void
    )
{
    unsigned long error = UfProcConnect();

    if (error != ERROR_SUCCESS && error != ERROR_ALREADY_EXISTS) {
        PrintError(L"프로세스 드라이버 연결", error);
        return 0;
    }
    return 1;
}

static const wchar_t*
EventTypeName(
    unsigned long Type
    )
{
    switch (Type) {
    case UfProcEventCreate:
        return L"실행";
    case UfProcEventExit:
        return L"종료";
    case UfProcEventAccess:
        return L"접근";
    default:
        return L"알 수 없음";
    }
}

static void __stdcall
OnProcessEvent(
    const UF_PROC_EVENT* Event,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(Context);
    wprintf(
        L"[#%llu][%ls][%ls] PID=%lu 요청=%lu 대상=%lu 권한=0x%08lX 규칙=%lu 이미지=%.*ls\n",
        Event->Sequence,
        EventTypeName(Event->Type),
        Event->Action == UfProcActionBlocked ? L"차단" : L"감시",
        Event->ProcessId,
        Event->RequesterProcessId,
        Event->TargetProcessId,
        Event->DesiredAccess,
        Event->RuleId,
        (int)Event->ImageLengthChars,
        Event->Image);
}

static unsigned long
SetSingleRule(
    unsigned long MatchMode,
    const wchar_t* Image
    )
{
    UF_PROC_RULE_INPUT rule;
    UF_PROC_POLICY_INPUT policy;

    ZeroMemory(&rule, sizeof(rule));
    ZeroMemory(&policy, sizeof(policy));
    rule.RuleId = 1;
    rule.MatchMode = MatchMode;
    rule.Image = Image;
    policy.RuleCount = 1;
    policy.Rules = &rule;
    return UfProcReplacePolicy(&policy);
}

static DWORD WINAPI
RunConnectionTest(void* Context)
{
    unsigned long index;
    UNREFERENCED_PARAMETER(Context);
    for (index = 0; index < 3; ++index) {
        UF_PROC_STATE_REPLY state;
        unsigned long error = UfProcStartEventReceiver(OnProcessEvent, NULL);
        if (error != ERROR_SUCCESS) {
            PrintError(L"두 번째 장치 핸들 및 수신 시작", error);
            return 1;
        }
        /* 서명 요청이 대기하는 동안 일반 상태 조회가 반환되는지 검사합니다. */
        Sleep(200);
        error = UfProcQueryState(&state);
        if (error != ERROR_SUCCESS || ((state.Reserved >> 8) & 0xffu) < 3 ||
            ((state.Reserved >> 16) & 0xffu) < 2) {
            fwprintf(stderr, L"수신 중 상태 검증 실패 error=%lu diagnostic=0x%08lX\n",
                error, state.Reserved);
            UfProcStopEventReceiver();
            return 1;
        }
        UfProcStopEventReceiver();
        error = UfProcQueryState(&state);
        if (error != ERROR_SUCCESS || ((state.Reserved >> 16) & 0xffu) != 1) {
            fwprintf(stderr, L"수신 중지 후 핸들 정리 검증 실패 error=%lu\n", error);
            return 1;
        }
        wprintf(L"연결·조회·서명 대기 취소·수신 재시작 시험 %lu/3 성공\n", index + 1);
    }
    return 0;
}

static unsigned long
SetMismatchedPathPolicy(
    const wchar_t* ProcessName,
    const wchar_t* ProcessPath
    )
{
    UF_PROC_RULE_INPUT_V2 rule;
    UF_PROC_POLICY_INPUT_V2 policy;

    ZeroMemory(&rule, sizeof(rule));
    ZeroMemory(&policy, sizeof(policy));
    rule.RuleId = 1;
    rule.ProcessName = ProcessName;
    rule.ProcessPath = ProcessPath;
    rule.IsCmpFullPath = 1;
    policy.PolicyCount = 1;
    policy.Policies = &rule;
    return UfProcReplacePolicyV2(&policy);
}

static int
RunSelfTest(
    void
    )
{
    wchar_t sourcePath[MAX_PATH];
    wchar_t probePath[MAX_PATH];
    wchar_t* fileName;
    wchar_t* probeName;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInformation;
    DWORD length;
    unsigned long error;
    int policyInstalled = 0;
    int exitCode = 1;

    length = GetModuleFileNameW(NULL, sourcePath, _countof(sourcePath));
    if (length == 0 || length >= _countof(sourcePath)) {
        PrintError(L"시험 실행 파일 경로 조회", GetLastError());
        return 1;
    }
    if (wcscpy_s(probePath, _countof(probePath), sourcePath) != 0) {
        return 1;
    }
    fileName = wcsrchr(probePath, L'\\');
    if (fileName == NULL ||
        wcscpy_s(fileName + 1,
                 _countof(probePath) - (size_t)(fileName + 1 - probePath),
                 L"UF_ProcessBlockedProbe.exe") != 0) {
        fwprintf(stderr, L"시험 실행 파일 경로를 만들지 못했습니다.\n");
        return 1;
    }
    probeName = fileName + 1;
    if (!CopyFileW(sourcePath, probePath, FALSE)) {
        PrintError(L"시험 실행 파일 복사", GetLastError());
        return 1;
    }

    error = UfProcStartEventReceiver(OnProcessEvent, NULL);
    if (error != ERROR_SUCCESS) {
        PrintError(L"정책 적용 전 이벤트 수신 시작", error);
        goto Exit;
    }
    Sleep(200);
    error = SetMismatchedPathPolicy(probeName, sourcePath);
    if (error != ERROR_SUCCESS) {
        PrintError(L"시험 전체 경로 불일치 정책 등록", error);
        goto Exit;
    }
    policyInstalled = 1;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInformation, sizeof(processInformation));
    startupInfo.cb = sizeof(startupInfo);
    if (CreateProcessW(
            probePath,
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &startupInfo,
            &processInformation)) {
        fwprintf(stderr, L"전체 경로가 불일치한 프로세스가 실행되었습니다.\n");
        WaitForSingleObject(processInformation.hProcess, 3000);
        CloseHandle(processInformation.hThread);
        CloseHandle(processInformation.hProcess);
        goto Exit;
    }

    error = GetLastError();
    if (error != ERROR_ACCESS_DENIED) {
        PrintError(L"전체 경로 불일치 차단 검증", error);
        goto Exit;
    }
    Sleep(300);
    wprintf(L"전체 경로 불일치 차단 자체 시험 성공: %ls (ERROR_ACCESS_DENIED)\n", probePath);
    exitCode = 0;

Exit:
    UfProcStopEventReceiver();
    if (policyInstalled) {
        error = UfProcClearPolicy();
        if (error != ERROR_SUCCESS) {
            PrintError(L"시험 정책 초기화", error);
            exitCode = 1;
        }
    }
    if (!DeleteFileW(probePath) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        PrintError(L"시험 실행 파일 삭제", GetLastError());
        exitCode = 1;
    }
    return exitCode;
}

static void
PrintUsage(
    void
    )
{
    wprintf(
        L"UF_ProcessControlTest 사용법\n"
        L"  --self-test\n"
        L"  --connection-test (정책 변경 없이 연결·취소 반복 시험)\n"
        L"  --state\n"
        L"  --clear\n"
        L"  --block-path <실행 파일 전체 경로> (정책 등록 호환 명령)\n"
        L"  --block-name <실행 파일 이름> (정책 등록 호환 명령)\n"
        L"  --listen <초>\n");
}

int wmain(
    int argc,
    wchar_t** argv
    )
{
    unsigned long error;
    int exitCode = 0;

    (void)UfProcInitialize();
    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    if (!ConnectOrReport()) {
        UfProcShutdown();
        return 1;
    }

    if (_wcsicmp(argv[1], L"--connection-test") == 0 && argc == 2) {
        DWORD testResult = 1;
        HANDLE thread = CreateThread(NULL, 0, RunConnectionTest, NULL, 0, NULL);
        if (thread == NULL) {
            PrintError(L"연결 시험 스레드 생성", GetLastError());
            exitCode = 1;
        } else {
            if (WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) {
                fwprintf(stderr, L"연결 시험이 15초 안에 반환되지 않았습니다.\n");
                /* 교착된 시험 DLL의 종료 경로로 다시 들어가지 않습니다. */
                ExitProcess(ERROR_TIMEOUT);
            }
            GetExitCodeThread(thread, &testResult);
            CloseHandle(thread);
            exitCode = (int)testResult;
        }
    } else if (_wcsicmp(argv[1], L"--self-test") == 0 && argc == 2) {
        exitCode = RunSelfTest();
    } else if (_wcsicmp(argv[1], L"--state") == 0 && argc == 2) {
        UF_PROC_STATE_REPLY state;

        error = UfProcQueryState(&state);
        if (error != ERROR_SUCCESS) {
            PrintError(L"상태 조회", error);
            exitCode = 1;
        } else {
            wprintf(
                L"세대=%llu 규칙=%lu 큐=%lu 유실=%llu 연결=%lu\n",
                state.PolicyGeneration,
                state.PolicyCount,
                state.QueueDepth,
                state.DroppedEvents,
                state.Connected);
        }
    } else if (_wcsicmp(argv[1], L"--clear") == 0 && argc == 2) {
        error = UfProcClearPolicy();
        if (error != ERROR_SUCCESS) {
            PrintError(L"정책 초기화", error);
            exitCode = 1;
        } else {
            wprintf(L"프로세스 정책을 초기화했습니다.\n");
        }
    } else if (_wcsicmp(argv[1], L"--block-path") == 0 && argc == 3) {
        error = SetSingleRule(UfProcMatchFullPath, argv[2]);
        if (error != ERROR_SUCCESS) {
            PrintError(L"전체 경로 실행 정책 등록", error);
            exitCode = 1;
        } else {
            wprintf(L"전체 경로 실행 정책을 등록했습니다.\n");
        }
    } else if (_wcsicmp(argv[1], L"--block-name") == 0 && argc == 3) {
        error = SetSingleRule(UfProcMatchImageName, argv[2]);
        if (error != ERROR_SUCCESS) {
            PrintError(L"파일 이름 실행 정책 등록", error);
            exitCode = 1;
        } else {
            wprintf(L"파일 이름 실행 정책을 등록했습니다.\n");
        }
    } else if (_wcsicmp(argv[1], L"--listen") == 0 && argc == 3) {
        wchar_t* end = NULL;
        unsigned long seconds = wcstoul(argv[2], &end, 10);

        if (end == argv[2] || *end != L'\0' || seconds == 0 || seconds > 3600) {
            fwprintf(stderr, L"수신 시간은 1~3600초여야 합니다.\n");
            exitCode = 2;
        } else {
            error = UfProcStartEventReceiver(OnProcessEvent, NULL);
            if (error != ERROR_SUCCESS) {
                PrintError(L"이벤트 수신 시작", error);
                exitCode = 1;
            } else {
                wprintf(L"%lu초 동안 프로세스 이벤트를 수신합니다.\n", seconds);
                Sleep(seconds * 1000);
                UfProcStopEventReceiver();
            }
        }
    } else {
        PrintUsage();
        exitCode = 2;
    }

    UfProcShutdown();
    return exitCode;
}
