using System.IO;

namespace RansomUtilFactory.UI;

public sealed record ProcessEventLog(
    string Time,
    string ProcessName,
    string Action,
    uint ProcessId,
    string Image)
{
    internal static ProcessEventLog? FromEvent(
        ProcessNativeMethods.ProcessEvent processEvent,
        AppliedProcessLogPolicy? appliedPolicy)
    {
        // 현재 UI 연결에서 적용에 성공한 정책만 표시합니다. 이전 커널 정책은 포함하지 않습니다.
        if (processEvent.Type != ProcessNativeMethods.EventCreate ||
            appliedPolicy is null || !appliedPolicy.Matches(processEvent))
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

internal sealed class AppliedProcessLogPolicy(
    IEnumerable<KeyValuePair<uint, string>> rules,
    ulong appliedAt)
{
    private readonly Dictionary<uint, string> _names = rules.ToDictionary(pair => pair.Key, pair => pair.Value);

    internal bool Matches(ProcessNativeMethods.ProcessEvent processEvent)
    {
        // 수신 큐에 남아 있는 적용 이전 이벤트와 편집 목록의 미적용 규칙을 제외합니다.
        return processEvent.RuleId != 0 && processEvent.SystemTime100ns >= appliedAt &&
            _names.TryGetValue(processEvent.RuleId, out string? name) &&
            string.Equals(name, Path.GetFileName(processEvent.Image ?? string.Empty),
                StringComparison.OrdinalIgnoreCase);
    }
}
