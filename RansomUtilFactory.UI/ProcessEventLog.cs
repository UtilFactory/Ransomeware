using System.IO;

namespace RansomUtilFactory.UI;

public sealed record ProcessEventLog(
    string Time,
    string ProcessName,
    string Action,
    uint ProcessId,
    string Image)
{
    internal static ProcessEventLog? FromEvent(ProcessNativeMethods.ProcessEvent processEvent)
    {
        // 규칙 ID는 커널이 실행 당시 적용 정책의 프로세스명과 일치하면 설정합니다.
        // UI에서 편집 중인 목록 대신 이 값을 사용해야 적용 실패·정책 교체 시에도 정확합니다.
        if (processEvent.Type != ProcessNativeMethods.EventCreate || processEvent.RuleId == 0)
        {
            return null;
        }

        string image = processEvent.Image ?? string.Empty;
        DateTime time = DateTime.FromFileTimeUtc(unchecked((long)processEvent.SystemTime100ns))
            .ToLocalTime();
        return new ProcessEventLog(
            time.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            Path.GetFileName(image),
            processEvent.Action switch
            {
                ProcessNativeMethods.ActionBlocked => "차단",
                ProcessNativeMethods.ActionObserved => "통과",
                _ => "알 수 없음"
            },
            processEvent.ProcessId,
            image);
    }
}
