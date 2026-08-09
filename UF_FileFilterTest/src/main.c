#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../uf_fltwarp/include/uf_fltwarp.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

static void
PrintError(const wchar_t* Operation, unsigned long Error)
{
    wchar_t message[512];
    if (UfFltGetErrorMessage(Error, message, _countof(message)) == ERROR_SUCCESS) {
        fwprintf(stderr, L"%ls 실패: %lu (%ls)\n", Operation, Error, message);
    } else {
        fwprintf(stderr, L"%ls 실패: %lu\n", Operation, Error);
    }
}

static void
HexEncode(
    const unsigned char* Bytes,
    unsigned long ByteCount,
    wchar_t* Text,
    unsigned long TextChars)
{
    static const wchar_t digits[] = L"0123456789ABCDEF";
    unsigned long index;
    if (TextChars < ByteCount * 2 + 1) {
        return;
    }
    for (index = 0; index < ByteCount; ++index) {
        Text[index * 2] = digits[(Bytes[index] >> 4) & 0x0f];
        Text[index * 2 + 1] = digits[Bytes[index] & 0x0f];
    }
    Text[ByteCount * 2] = L'\0';
}

static void __stdcall
OnFileEvent(const UF_FILE_EVENT* Event, void* Context)
{
    UNREFERENCED_PARAMETER(Context);
    wprintf(
        L"[%ls] PID=%lu 접근=0x%08lX 경로=%.*ls 프로세스=%.*ls\n",
        Event->Action == UfEventDenied ? L"차단" : L"감시",
        Event->ProcessId,
        Event->DesiredAccess,
        (int)Event->PathLengthChars, Event->Path,
        (int)Event->ImageLengthChars, Event->Image);
}

static int
ConnectOrReport(void)
{
    unsigned long error = UfFltConnect();
    if (error != ERROR_SUCCESS && error != ERROR_ALREADY_EXISTS) {
        PrintError(L"드라이버 연결", error);
        return 0;
    }
    return 1;
}

static void
PrintUsage(void)
{
    wprintf(
        L"UF_FileFilterTest 사용법\n"
        L"  --self-test\n"
        L"  --convert <DOS 경로>\n"
        L"  --state\n"
        L"  --clear\n"
        L"  --signer <실행 파일>\n"
        L"  --monitor <폴더> [예외 실행 파일]\n"
        L"  --protect <폴더> <허용 실행 파일>\n"
        L"  --protect-v2 <폴더> <허용 실행 파일>\n"
        L"  --listen <초>\n");
}

int wmain(int argc, wchar_t** argv)
{
    unsigned long error;
    int exitCode = 0;

    UfFltInitialize();
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    if (_wcsicmp(argv[1], L"--self-test") == 0) {
        wchar_t path[UF_MAX_PATH_CHARS];
        error = UfFltDosPathToNtPath(L".", path, _countof(path));
        if (error != ERROR_SUCCESS) {
            PrintError(L"경로 변환 자체 시험", error);
            exitCode = 1;
        } else {
            wprintf(L"경로 변환 자체 시험 성공: %ls\n", path);
        }
    } else if (_wcsicmp(argv[1], L"--convert") == 0 && argc == 3) {
        wchar_t path[UF_MAX_PATH_CHARS];
        error = UfFltDosPathToNtPath(argv[2], path, _countof(path));
        if (error != ERROR_SUCCESS) {
            PrintError(L"경로 변환", error);
            exitCode = 1;
        } else {
            wprintf(L"%ls\n", path);
        }
    } else if (_wcsicmp(argv[1], L"--state") == 0) {
        UF_STATE_REPLY state;
        if (!ConnectOrReport()) {
            exitCode = 1;
        } else {
            error = UfFltQueryState(&state);
            if (error != ERROR_SUCCESS) {
                PrintError(L"상태 조회", error);
                exitCode = 1;
            } else {
                wprintf(
                    L"버전=%lu 경로=%lu 감시예외=%lu 허용=%lu 연결=%lu\n",
                    state.Version, state.PathRuleCount,
                    state.MonitorExceptionCount, state.AllowedImageCount,
                    state.Connected);
            }
        }
    } else if (_wcsicmp(argv[1], L"--clear") == 0) {
        if (!ConnectOrReport()) {
            exitCode = 1;
        } else {
            error = UfFltClearPolicy();
            if (error != ERROR_SUCCESS) {
                PrintError(L"정책 초기화", error);
                exitCode = 1;
            } else {
                wprintf(L"정책을 초기화했습니다.\n");
            }
        }
    } else if (_wcsicmp(argv[1], L"--signer") == 0 && argc == 3) {
        UF_FLT_SIGNER_IDENTITY identity;
        error = UfFltGetImageSignerIdentity(argv[2], 0, &identity);
        if (error != ERROR_SUCCESS) {
            PrintError(L"로컬 서명 검증", error);
            exitCode = 1;
        } else {
            wprintf(
                L"서명 신뢰=%lu 주체=%ls 일련번호 바이트=%lu\n",
                identity.Trusted, identity.Subject, identity.SerialLengthBytes);
        }
    } else if (_wcsicmp(argv[1], L"--monitor") == 0 &&
        (argc == 3 || argc == 4)) {
        UF_FLT_PATH_INPUT pathRule;
        UF_FLT_POLICY_INPUT policy;
        const wchar_t* exceptions[1];
        ZeroMemory(&policy, sizeof(policy));
        pathRule.Mode = UfRuleMonitor;
        pathRule.DosPath = argv[2];
        policy.PathRuleCount = 1;
        policy.PathRules = &pathRule;
        if (argc == 4) {
            exceptions[0] = argv[3];
            policy.MonitorExceptionCount = 1;
            policy.MonitorExceptions = exceptions;
        }
        if (!ConnectOrReport()) {
            exitCode = 1;
        } else {
            error = UfFltReplacePolicy(&policy);
            if (error != ERROR_SUCCESS) {
                PrintError(L"감시 정책 설정", error);
                exitCode = 1;
            } else {
                wprintf(L"감시 정책을 설정했습니다.\n");
            }
        }
    } else if (_wcsicmp(argv[1], L"--protect") == 0 && argc == 4) {
        UF_FLT_PATH_INPUT pathRule;
        UF_FLT_POLICY_INPUT policy;
        const wchar_t* allowed[1];
        ZeroMemory(&policy, sizeof(policy));
        pathRule.Mode = UfRuleAllowList;
        pathRule.DosPath = argv[2];
        allowed[0] = argv[3];
        policy.PathRuleCount = 1;
        policy.PathRules = &pathRule;
        policy.AllowedImageCount = 1;
        policy.AllowedImages = allowed;
        if (!ConnectOrReport()) {
            exitCode = 1;
        } else {
            error = UfFltReplacePolicy(&policy);
            if (error != ERROR_SUCCESS) {
                PrintError(L"접근 제한 정책 설정", error);
                exitCode = 1;
            } else {
                wprintf(L"접근 제한 정책을 설정했습니다.\n");
            }
        }
    } else if (_wcsicmp(argv[1], L"--protect-v2") == 0 && argc == 4) {
        UF_FLT_SIGNER_IDENTITY identity;
        UF_FLT_PATH_INPUT_V2 pathRule;
        UF_FLT_SIGNER_INPUT signerRule;
        UF_FLT_PROTECTED_PROCESS_INPUT processRule;
        UF_FLT_POLICY_INPUT_V2 policy;
        wchar_t thumbprint[UF_CERT_SHA256_BYTES * 2 + 1];

        error = UfFltGetImageSignerIdentity(argv[3], 0, &identity);
        if (error != ERROR_SUCCESS || identity.Trusted == 0) {
            if (error == ERROR_SUCCESS) {
                error = ERROR_INVALID_IMAGE_HASH;
            }
            PrintError(L"허용 프로세스 로컬 서명 검증", error);
            exitCode = 1;
        } else {
            ZeroMemory(&pathRule, sizeof(pathRule));
            ZeroMemory(&signerRule, sizeof(signerRule));
            ZeroMemory(&processRule, sizeof(processRule));
            ZeroMemory(&policy, sizeof(policy));
            HexEncode(identity.ThumbprintSha256, UF_CERT_SHA256_BYTES,
                thumbprint, _countof(thumbprint));
            pathRule.RuleId = 100;
            pathRule.Mode = UfRuleProtected;
            pathRule.DosPath = argv[2];
            signerRule.RuleId = 300;
            signerRule.MatchType = UfSignerMatchThumbprintSha256;
            signerRule.ThumbprintSha256Hex = thumbprint;
            processRule.RuleId = 200;
            processRule.FolderRuleId = pathRule.RuleId;
            processRule.SignerRuleId = signerRule.RuleId;
            processRule.Access = PF_ACCESS_ALL;
            processRule.DosImagePath = argv[3];
            policy.PolicyGeneration = GetTickCount64();
            policy.PathRuleCount = 1;
            policy.PathRules = &pathRule;
            policy.ProtectedProcessRuleCount = 1;
            policy.ProtectedProcesses = &processRule;
            policy.SignerRuleCount = 1;
            policy.Signers = &signerRule;
            policy.RevocationTimeoutAction = UfRevocationTimeoutDeny;
            if (!ConnectOrReport()) {
                exitCode = 1;
            } else {
                error = UfFltReplacePolicyV2(&policy);
                if (error != ERROR_SUCCESS) {
                    PrintError(L"V2 보호 정책 설정", error);
                    exitCode = 1;
                } else {
                    wprintf(L"V2 보호 정책을 설정했습니다.\n");
                }
            }
        }
    } else if (_wcsicmp(argv[1], L"--listen") == 0 && argc == 3) {
        unsigned long seconds = wcstoul(argv[2], NULL, 10);
        if (seconds == 0 || !ConnectOrReport()) {
            exitCode = 1;
        } else {
            error = UfFltStartEventReceiver(OnFileEvent, NULL);
            if (error != ERROR_SUCCESS) {
                PrintError(L"이벤트 수신 시작", error);
                exitCode = 1;
            } else {
                wprintf(L"%lu초 동안 이벤트를 수신합니다.\n", seconds);
                Sleep(seconds * 1000);
                UfFltStopEventReceiver();
            }
        }
    } else {
        PrintUsage();
        exitCode = 2;
    }

    UfFltShutdown();
    return exitCode;
}
