using System.Windows;
using System.Windows.Media;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private bool _bootOperationRunning;
    private Task _bootOperationTask = Task.CompletedTask;
    private NativeMethods.BootProtectionState? _bootProtectionState;

    private async void StartBootProtection_Click(object sender, RoutedEventArgs e) =>
        await BeginBootProtectionOperationAsync(true);

    private async void StopBootProtection_Click(object sender, RoutedEventArgs e) =>
        await BeginBootProtectionOperationAsync(false);

    private async void RefreshBootProtection_Click(object sender, RoutedEventArgs e) =>
        await RefreshBootProtectionAsync();

    private Task RefreshBootProtectionAsync() => BeginBootProtectionOperationAsync(null);

    private Task BeginBootProtectionOperationAsync(bool? enabled)
    {
        if (_bootOperationRunning || _fileConnectionOperationRunning || !_connected || _closing)
            return Task.CompletedTask;
        _bootOperationRunning = true;
        UpdateBootProtectionButtons();
        BootProtectionCommandText.Text = enabled.HasValue
            ? $"선두 영역 보호 {(enabled.Value ? "시작" : "정지")} 요청 중 · 응답 후 실제 상태 조회"
            : "선두 영역 보호 상태 조회 중...";
        _bootOperationTask = ExecuteBootProtectionOperationAsync(enabled, _fileConnectionVersion);
        return _bootOperationTask;
    }

    private async Task ExecuteBootProtectionOperationAsync(bool? enabled, int connectionVersion)
    {
        try
        {
            BootOperationResult result = await RunFileNativeAsync(() =>
            {
                // 연결 해제 직전에 대기열에 들어간 설정이 새 연결에 적용되는 것을 막는다.
                if (_closing || !_connected || connectionVersion != Volatile.Read(ref _fileConnectionVersion))
                    return new BootOperationResult(null, null, 1223, "연결이 변경되어 요청을 취소했습니다.");
                uint? setError = null;
                string? details = null;
                if (enabled.HasValue)
                {
                    try { setError = NativeMethods.UfFltSetBootProtection(enabled.Value); }
                    catch (Exception exception)
                    {
                        setError = FileProtectionPresentation.ErrorCode(exception);
                        details = exception.Message;
                    }
                }
                NativeMethods.BootProtectionState state = NativeMethods.CreateBootProtectionState();
                uint queryError;
                try
                {
                    // 설정 실패나 시간 초과도 적용되지 않았다는 보장이 없으므로 자동 재설정 없이 조회한다.
                    queryError = NativeMethods.UfFltQueryBootProtection(ref state);
                    if (queryError == NativeMethods.ErrorSuccess) FileProtectionPresentation.ValidateState(state);
                }
                catch (Exception exception)
                {
                    queryError = FileProtectionPresentation.ErrorCode(exception);
                    details = exception.Message;
                }
                return new BootOperationResult(
                    queryError == NativeMethods.ErrorSuccess ? state : null, setError, queryError, details);
            });
            string command = enabled.HasValue ? enabled.Value ? "시작" : "정지" : "조회";
            string message = result.SetError.HasValue && result.SetError != NativeMethods.ErrorSuccess
                ? $"보호 {command} 실패: {FileProtectionPresentation.Error(result.SetError.Value)}"
                : enabled.HasValue ? $"보호 {command} 요청 응답: 성공" : "보호 상태 조회";
            if (result.QueryError != NativeMethods.ErrorSuccess)
                message += $"\n상태 조회 실패: {FileProtectionPresentation.Error(result.QueryError)}";
            if (!string.IsNullOrWhiteSpace(result.Details)) message += $" · {result.Details}";
            if (result.QueryError != NativeMethods.ErrorSuccess ||
                result.SetError.HasValue && result.SetError != NativeMethods.ErrorSuccess)
                UiLogger.Error(message);
            else
                UiLogger.Info($"{message} · {FileProtectionPresentation.Status(result.State)} · {FileProtectionPresentation.Counters(result.State)}");

            // 지연 응답은 끊긴 연결이나 닫히는 창의 표시를 복원할 수 없다.
            if (_closing || !_connected || connectionVersion != _fileConnectionVersion) return;
            _bootProtectionState = result.State;
            BootProtectionStatusText.Text = FileProtectionPresentation.Status(result.State);
            BootProtectionCountersText.Text = FileProtectionPresentation.Counters(result.State);
            BootProtectionCommandText.Text = message;
            BootProtectionStatusText.Foreground = result.State.HasValue
                ? result.State.Value.Enabled == 1 ? Brushes.DarkGreen : Brushes.DimGray
                : Brushes.DarkOrange;
        }
        catch (Exception exception)
        {
            string message = $"보호 상태 미확인: {FileProtectionPresentation.Error(FileProtectionPresentation.ErrorCode(exception))} · {exception.Message}";
            UiLogger.Error(message, exception);
            if (!_closing && _connected && connectionVersion == _fileConnectionVersion)
                SetBootProtectionUnknown(message);
        }
        finally
        {
            _bootOperationRunning = false;
            if (!_closing) UpdateBootProtectionButtons();
        }
    }

    private void SetBootProtectionUnknown(string detail)
    {
        _bootProtectionState = null;
        BootProtectionStatusText.Text = FileProtectionPresentation.Status(null);
        BootProtectionCountersText.Text = FileProtectionPresentation.Counters(null);
        BootProtectionCommandText.Text = detail;
        BootProtectionStatusText.Foreground = Brushes.DarkOrange;
    }

    private void UpdateBootProtectionButtons()
    {
        bool ready = _connected && !_closing && !_fileConnectionOperationRunning && !_bootOperationRunning;
        StartBootProtectionButton.IsEnabled = ready && (!_bootProtectionState.HasValue || _bootProtectionState.Value.Enabled == 0);
        StopBootProtectionButton.IsEnabled = ready && (!_bootProtectionState.HasValue || _bootProtectionState.Value.Enabled == 1);
        RefreshBootProtectionButton.IsEnabled = ready;
    }

    private sealed record BootOperationResult(NativeMethods.BootProtectionState? State,
        uint? SetError, uint QueryError, string? Details);
}
