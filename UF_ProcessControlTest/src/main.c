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

static int
RunSelfTest(
    void
    )
{
    wchar_t sourcePath[MAX_PATH];
    wchar_t probePath[MAX_PATH];
    wchar_t* fileName;
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
    if (!CopyFileW(sourcePath, probePath, FALSE)) {
        PrintError(L"시험 실행 파일 복사", GetLastError());
        return 1;
    }

    error = SetSingleRule(UfProcMatchFullPath, probePath);
    if (error != ERROR_SUCCESS) {
        PrintError(L"시험 차단 정책 등록", error);
        goto Exit;
    }
    policyInstalled = 1;
    (void)UfProcStartEventReceiver(OnProcessEvent, NULL);

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
        fwprintf(stderr, L"차단해야 할 프로세스가 실행되었습니다.\n");
        WaitForSingleObject(processInformation.hProcess, 3000);
        CloseHandle(processInformation.hThread);
        CloseHandle(processInformation.hProcess);
        goto Exit;
    }

    error = GetLastError();
    if (error != ERROR_ACCESS_DENIED) {
        PrintError(L"차단 결과 검증", error);
        goto Exit;
    }
    Sleep(300);
    wprintf(L"실행 차단 자체 시험 성공: %ls (ERROR_ACCESS_DENIED)\n", probePath);
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
        L"  --state\n"
        L"  --clear\n"
        L"  --block-path <실행 파일 전체 경로>\n"
        L"  --block-name <실행 파일 이름>\n"
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

    if (_wcsicmp(argv[1], L"--self-test") == 0 && argc == 2) {
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
                state.RuleCount,
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
            wprintf(L"프로세스 차단 정책을 초기화했습니다.\n");
        }
    } else if (_wcsicmp(argv[1], L"--block-path") == 0 && argc == 3) {
        error = SetSingleRule(UfProcMatchFullPath, argv[2]);
        if (error != ERROR_SUCCESS) {
            PrintError(L"전체 경로 차단 정책 등록", error);
            exitCode = 1;
        } else {
            wprintf(L"전체 경로 차단 정책을 등록했습니다.\n");
        }
    } else if (_wcsicmp(argv[1], L"--block-name") == 0 && argc == 3) {
        error = SetSingleRule(UfProcMatchImageName, argv[2]);
        if (error != ERROR_SUCCESS) {
            PrintError(L"파일 이름 차단 정책 등록", error);
            exitCode = 1;
        } else {
            wprintf(L"파일 이름 차단 정책을 등록했습니다.\n");
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
