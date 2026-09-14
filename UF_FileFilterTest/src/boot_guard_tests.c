#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <limits.h>
#include "../../UF_FileFilterFactory/include/uf_filefilter_protocol.h"
#include "../../UF_FileFilterFactory/src/boot_guard_logic.h"

#ifndef _countof
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

// 실제 이벤트 출력과 같은 함수로 과거 통과 이벤트와 새 차단 이벤트를 구분해 검사합니다.
const wchar_t* UfFileEventActionText(unsigned long Action);

static int gChecks;
static int gFailures;

static void UfCheck(int Passed, const char* Name)
{
    ++gChecks;
    if (!Passed) ++gFailures;
    printf("%s %s\n", Passed ? "PASS" : "FAIL", Name);
}

int UfRunBootGuardSelfTests(void)
{
    unsigned char before[UF_BOOT_PROTECTED_BYTES] = {0};
    unsigned char after[UF_BOOT_PROTECTED_BYTES] = {0};
    const WCHAR* accepted[] = {
        L"\\Device\\HarddiskVolume0", L"\\Device\\HarddiskVolume123",
        L"\\device\\harddiskvolume11", L"\\Device\\Harddisk0\\DR0",
        L"\\DEVICE\\HARDDISK123\\DR456"
    };
    const WCHAR* rejected[] = {
        L"", L"\\Device\\HarddiskVolume", L"\\Device\\HarddiskVolumeX",
        L"\\Device\\HarddiskVolume1\\", L"\\Device\\HarddiskVolume1\\file.txt",
        L"\\Device\\Harddisk0\\DR", L"\\Device\\Harddisk0\\DR0\\file",
        L"\\Device\\Harddisk0\\DR0junk", L"C:\\", L"\\Device\\NamedPipe\\DR0"
    };
    size_t index;
    ULONG offset;
    int exhaustive = 1;
    gChecks = gFailures = 0;
    UfCheck(sizeof(UF_MESSAGE_HEADER) == 16, "message ABI 16");
    UfCheck(sizeof(UF_SET_BOOT_PROTECTION) == 24, "set ABI 24");
    UfCheck(sizeof(UF_BOOT_PROTECTION_STATE) == 40, "state ABI 40");
    UfCheck(FIELD_OFFSET(UF_BOOT_PROTECTION_STATE, InspectedWrites) == 16, "64-bit counters aligned");
    UfCheck(sizeof(UF_FILE_EVENT_V2) == 1632, "existing event ABI unchanged");
    UfCheck(UfCommandSetBootProtection == 5 && UfCommandQueryBootProtection == 6, "command values");
    UfCheck(UfEventBootDenied == 5 && UfEventBootInspectionFailed == 6, "action values");
    UfCheck(UfEventBootInspectionDenied == 7, "inspection denied action 7");
    UfCheck(wcscmp(UfFileEventActionText(UfEventBootDenied), L"부트 영역 차단") == 0,
        "changed boot bytes displayed as blocked");
    UfCheck(wcscmp(UfFileEventActionText(UfEventBootInspectionFailed), L"부트 검사 실패(통과)") == 0,
        "legacy inspection failure remains passed");
    UfCheck(wcscmp(UfFileEventActionText(UfEventBootInspectionDenied), L"부트 검사 실패(차단)") == 0,
        "new inspection failure displayed as blocked");
    UfCheck(wcscmp(UfFileEventActionText(UfEventDenied), L"차단") == 0,
        "ordinary denial label unchanged");
    UfCheck(wcscmp(UfFileEventActionText(UfEventObserved), L"감시") == 0,
        "ordinary observation label unchanged");
    UfCheck(UfBootProtectedWriteLength(0, 512) == 512, "first sector");
    UfCheck(UfBootProtectedWriteLength(0, 4096) == 2048, "clip prefix");
    UfCheck(UfBootProtectedWriteLength(2047, 1024) == 1, "last protected byte");
    UfCheck(UfBootProtectedWriteLength(2048, 512) == 0, "end boundary");
    UfCheck(UfBootProtectedWriteLength(-1, 512) == 0, "negative offset");
    UfCheck(UfBootProtectedWriteLength(MAXLONGLONG, ULONG_MAX) == 0, "large offset");
    UfCheck(UfBootProtectedWriteLength(0, 0) == 0, "zero length");
    for (offset = 0; offset < 4096; ++offset) {
        ULONG length = offset % 513;
        ULONG expected = offset >= 2048 ? 0 : min(length, 2048 - offset);
        exhaustive &= UfBootProtectedWriteLength(offset, length) == expected;
    }
    UfCheck(exhaustive, "4096 independent overlap cases");
    for (index = 0; index < _countof(accepted); ++index)
        UfCheck(UfBootIsDeviceIdentity(accepted[index], (ULONG)wcslen(accepted[index])), "canonical device accepted");
    for (index = 0; index < _countof(rejected); ++index)
        UfCheck(!UfBootIsDeviceIdentity(rejected[index], (ULONG)wcslen(rejected[index])), "ordinary path rejected");
    UfCheck(!UfBootIsDeviceIdentity(NULL, 20), "null identity");
    UfCheck(UfBootIsRawTarget(1, 0, 1), "volume flag verified");
    UfCheck(UfBootIsRawTarget(0, 1, 1), "empty name verified");
    UfCheck(!UfBootIsRawTarget(1, 1, 0), "unverified device excluded");
    UfCheck(!UfBootIsRawTarget(0, 0, 1), "ordinary file excluded");
    UfCheck(UfBootAlignedReadLength(512) == 2048, "512-sector alignment");
    UfCheck(UfBootAlignedReadLength(4096) == 4096, "4Kn alignment");
    UfCheck(UfBootAlignedReadLength(65536) == 65536, "maximum sector alignment");
    UfCheck(UfBootAlignedReadLength(0) == 0 && UfBootAlignedReadLength(1000) == 0, "invalid sectors");
    UfCheck(UfBootPrefixDiffers(before, after, 2048) == 0, "identical bytes allowed");
    after[2047] = 1;
    UfCheck(UfBootPrefixDiffers(before, after, 2048) == 1, "changed prefix detected");
    UfCheck(UfBootPrefixDiffers(before, after, 512) == 0, "compare length observed");
    UfCheck(UfBootPrefixDiffers(NULL, after, 1) == -1, "null compare invalid");
    UfCheck(UfBootPrefixDiffers(before, after, 2049) == -1, "oversized compare invalid");
    printf("Boot guard checks=%d failed=%d; pure logic only, no driver connection or device I/O.\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
