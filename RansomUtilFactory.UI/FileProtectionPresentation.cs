using System.ComponentModel;
using System.IO;

namespace RansomUtilFactory.UI;

// 보호 상태와 사건의 표시는 폴더 허용 정책이나 프로세스 정책에 의존하지 않는다.
internal static class FileProtectionPresentation
{
    internal static void ValidateState(NativeMethods.BootProtectionState state)
    {
        if (state.Version != 2 || state.Size != 40 || state.ProtectedBytes != 2048 ||
            state.Enabled > 1)
        {
            throw new InvalidDataException("선두 영역 보호 상태의 버전·크기·범위·활성 값이 규약과 일치하지 않습니다.");
        }
    }

    internal static string Status(NativeMethods.BootProtectionState? state) => state.HasValue
        ? state.Value.Enabled == 1 ? "설정 활성 · 미니필터 선두 2 KiB 변경 비교" : "정지 · 선두 2 KiB 보호 꺼짐"
        : "상태 미확인 · 보호가 정지했다는 뜻이 아닙니다.";

    // 실패 누적에는 구버전의 통과와 검사 실패 후 차단이 함께 포함될 수 있다.
    internal static string Counters(NativeMethods.BootProtectionState? state) => state.HasValue
        ? $"검사 {state.Value.InspectedWrites:N0}회 · 차단 {state.Value.BlockedWrites:N0}회 · 검사 실패 {state.Value.InspectionFailures:N0}회"
        : "검사·차단·검사 실패 횟수: 미확인";

    internal static string Action(uint action) => action switch
    {
        1 => "감시",
        2 => "차단",
        3 => "검증 요청",
        4 => "서명 폐기",
        NativeMethods.UfEventBootDenied => "부트 영역 차단",
        NativeMethods.UfEventBootInspectionFailed => "부트 검사 실패(통과)",
        NativeMethods.UfEventBootInspectionDenied => "부트 검사 실패(차단)",
        _ => $"알 수 없음 ({action})"
    };

    internal static bool IsBootEvent(uint action) => action is NativeMethods.UfEventBootDenied or
        NativeMethods.UfEventBootInspectionFailed or NativeMethods.UfEventBootInspectionDenied;

    internal static string Error(uint error) =>
        $"GetLastError={error} (0x{error:X8}, {new Win32Exception(unchecked((int)error)).Message})";

    internal static uint ErrorCode(Exception exception) => exception switch
    {
        Win32Exception native => unchecked((uint)native.NativeErrorCode),
        TimeoutException => 1460,
        DllNotFoundException => 126,
        EntryPointNotFoundException => 127,
        BadImageFormatException => 193,
        InvalidDataException => 13,
        _ => 31
    };
}
