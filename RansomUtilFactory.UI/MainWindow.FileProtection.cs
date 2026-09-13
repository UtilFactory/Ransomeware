using System.Windows;
using System.Windows.Media;
using System.Diagnostics;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private bool _bootOperationRunning;
    private Task _bootOperationTask = Task.CompletedTask;
    private NativeMethods.BootProtectionState? _bootProtectionState;
    private readonly string _bootDiagnosticSession = Guid.NewGuid().ToString("N");
    private long _bootDiagnosticSequence;
    private int _bootDiagnosticIdentityVersion = -1;

    private async void StartBootProtection_Click(object sender, RoutedEventArgs e) =>
        await BeginBootProtectionOperationAsync(true);

    private async void StopBootProtection_Click(object sender, RoutedEventArgs e) =>
        await BeginBootProtectionOperationAsync(false);

    private async void RefreshBootProtection_Click(object sender, RoutedEventArgs e) =>
        await RefreshBootProtectionAsync();

    private Task RefreshBootProtectionAsync() => BeginBootProtectionOperationAsync(null);

    private Task BeginBootProtectionOperationAsync(bool? enabled)
    {
        string diagnosticContext = $"[FileBoot requestId={_bootDiagnosticSession}-{++_bootDiagnosticSequence} " +
            $"command={FileProtectionDiagnostics.Command(enabled)}]";
        UiLogger.Info($"{diagnosticContext} stage=request connectionVersion={_fileConnectionVersion} connected={_connected} " +
            $"initialized={_fileInitialized} bootBusy={_bootOperationRunning} lifecycleBusy={_fileConnectionOperationRunning} " +
            $"closing={_closing} {FileProtectionDiagnostics.ThreadIdentity()}");
        if (_bootOperationRunning || _fileConnectionOperationRunning || !_connected || _closing)
        {
            UiLogger.Warn($"{diagnosticContext} stage=request-skipped reason=busy-disconnected-or-closing");
            return Task.CompletedTask;
        }
        _bootOperationRunning = true;
        UpdateBootProtectionButtons();
        BootProtectionCommandText.Text = enabled.HasValue
            ? $"선두 영역 보호 {(enabled.Value ? "시작" : "정지")} 요청 중 · 응답 후 실제 상태 조회"
            : "선두 영역 보호 상태 조회 중...";
        _bootOperationTask = ExecuteBootProtectionOperationAsync(enabled, _fileConnectionVersion, diagnosticContext);
        return _bootOperationTask;
    }

    private async Task ExecuteBootProtectionOperationAsync(bool? enabled, int connectionVersion, string diagnosticContext)
    {
        Stopwatch operationWatch = Stopwatch.StartNew();
        try
        {
            BootOperationResult result = await RunFileNativeAsync(() =>
            {
                UiLogger.Info($"{diagnosticContext} stage=worker-enter expectedConnectionVersion={connectionVersion} " +
                    $"currentConnectionVersion={Volatile.Read(ref _fileConnectionVersion)} connected={_connected} " +
                    $"initialized={_fileInitialized} closing={_closing} {FileProtectionDiagnostics.ThreadIdentity()}");
                if (!_closing && _connected && connectionVersion == Volatile.Read(ref _fileConnectionVersion) &&
                    _bootDiagnosticIdentityVersion != connectionVersion)
                {
                    _bootDiagnosticIdentityVersion = connectionVersion;
                    LogBootRuntimeIdentity(diagnosticContext);
                }
                // 연결 해제 직전에 대기열에 들어간 설정이 새 연결에 적용되는 것을 막는다.
                if (_closing || !_connected || connectionVersion != Volatile.Read(ref _fileConnectionVersion))
                {
                    UiLogger.Warn($"{diagnosticContext} stage=worker-cancelled reason=connection-invalidated nativeCallMade=false");
                    return new BootOperationResult(null, null, 1223, "연결이 변경되어 요청을 취소했습니다.");
                }
                uint? setError = null;
                string? details = null;
                if (enabled.HasValue)
                {
                    Stopwatch setWatch = Stopwatch.StartNew();
                    UiLogger.Info($"{diagnosticContext} stage=native-set-begin api=UfFltSetBootProtection " +
                        $"enabled={(enabled.Value ? 1 : 0)} wireCommand=5 wireInputBytes=24 protocolVersion=2 " +
                        FileProtectionDiagnostics.ThreadIdentity());
                    try
                    {
                        setError = NativeMethods.UfFltSetBootProtection(enabled.Value);
                        UiLogger.Info($"{diagnosticContext} stage=native-set-return elapsedMs={setWatch.ElapsedMilliseconds} " +
                            FileProtectionDiagnostics.Error(setError.Value));
                    }
                    catch (Exception exception)
                    {
                        setError = FileProtectionPresentation.ErrorCode(exception);
                        details = exception.Message;
                        UiLogger.Error($"{diagnosticContext} stage=native-set-exception elapsedMs={setWatch.ElapsedMilliseconds} " +
                            $"{FileProtectionDiagnostics.Error(setError.Value)} exceptionType={exception.GetType().FullName} " +
                            $"exceptionHResult=0x{exception.HResult:X8}", exception);
                    }
                }
                NativeMethods.BootProtectionState state = NativeMethods.CreateBootProtectionState();
                uint queryError;
                Stopwatch queryWatch = Stopwatch.StartNew();
                UiLogger.Info($"{diagnosticContext} stage=native-query-begin api=UfFltQueryBootProtection " +
                    $"wireCommand=6 wireInputBytes=16 wireOutputBytes=40 afterSet={enabled.HasValue} automaticSetRetry=false " +
                    $"{FileProtectionDiagnostics.State(state)} {FileProtectionDiagnostics.ThreadIdentity()}");
                try
                {
                    // 설정 실패나 시간 초과도 적용되지 않았다는 보장이 없으므로 자동 재설정 없이 조회한다.
                    queryError = NativeMethods.UfFltQueryBootProtection(ref state);
                    UiLogger.Info($"{diagnosticContext} stage=native-query-return elapsedMs={queryWatch.ElapsedMilliseconds} " +
                        $"{FileProtectionDiagnostics.Error(queryError)} rawState=({FileProtectionDiagnostics.State(state)}) " +
                        $"requiresValidation={queryError == NativeMethods.ErrorSuccess}");
                    if (queryError == NativeMethods.ErrorSuccess)
                    {
                        FileProtectionPresentation.ValidateState(state);
                        UiLogger.Info($"{diagnosticContext} stage=state-validated {FileProtectionDiagnostics.State(state)}");
                    }
                }
                catch (Exception exception)
                {
                    queryError = FileProtectionPresentation.ErrorCode(exception);
                    details = exception.Message;
                    UiLogger.Error($"{diagnosticContext} stage=native-query-or-validation-exception elapsedMs={queryWatch.ElapsedMilliseconds} " +
                        $"{FileProtectionDiagnostics.Error(queryError)} rawState=({FileProtectionDiagnostics.State(state)}) " +
                        $"exceptionType={exception.GetType().FullName} exceptionHResult=0x{exception.HResult:X8}", exception);
                }
                return new BootOperationResult(
                    queryError == NativeMethods.ErrorSuccess ? state : null, setError, queryError, details);
            }, diagnosticContext);
            string command = enabled.HasValue ? enabled.Value ? "시작" : "정지" : "조회";
            string message = result.SetError.HasValue && result.SetError != NativeMethods.ErrorSuccess
                ? $"보호 {command} 실패: {FileProtectionPresentation.Error(result.SetError.Value)}"
                : enabled.HasValue ? $"보호 {command} 요청 응답: 성공" : "보호 상태 조회";
            if (result.QueryError != NativeMethods.ErrorSuccess)
                message += $"\n상태 조회 실패: {FileProtectionPresentation.Error(result.QueryError)}";
            if (!string.IsNullOrWhiteSpace(result.Details)) message += $" · {result.Details}";
            if (result.QueryError != NativeMethods.ErrorSuccess ||
                result.SetError.HasValue && result.SetError != NativeMethods.ErrorSuccess)
                UiLogger.Error($"{diagnosticContext} stage=result {message}");
            else
                UiLogger.Info($"{diagnosticContext} stage=result {message} · {FileProtectionPresentation.Status(result.State)} · {FileProtectionPresentation.Counters(result.State)}");

            // 지연 응답은 끊긴 연결이나 닫히는 창의 표시를 복원할 수 없다.
            if (_closing || !_connected || connectionVersion != _fileConnectionVersion)
            {
                UiLogger.Warn($"{diagnosticContext} stage=result-suppressed expectedConnectionVersion={connectionVersion} " +
                    $"currentConnectionVersion={_fileConnectionVersion} connected={_connected} closing={_closing}");
                return;
            }
            _bootProtectionState = result.State;
            BootProtectionStatusText.Text = FileProtectionPresentation.Status(result.State);
            BootProtectionCountersText.Text = FileProtectionPresentation.Counters(result.State);
            BootProtectionCommandText.Text = message;
            BootProtectionStatusText.Foreground = result.State.HasValue
                ? result.State.Value.Enabled == 1 ? Brushes.DarkGreen : Brushes.DimGray
                : Brushes.DarkOrange;
            UiLogger.Info($"{diagnosticContext} stage=ui-updated stateKnown={result.State.HasValue}");
        }
        catch (Exception exception)
        {
            string message = $"보호 상태 미확인: {FileProtectionPresentation.Error(FileProtectionPresentation.ErrorCode(exception))} · {exception.Message}";
            UiLogger.Error($"{diagnosticContext} stage=operation-exception elapsedMs={operationWatch.ElapsedMilliseconds} " +
                $"exceptionType={exception.GetType().FullName} exceptionHResult=0x{exception.HResult:X8} {message}", exception);
            if (!_closing && _connected && connectionVersion == _fileConnectionVersion)
                SetBootProtectionUnknown(message);
        }
        finally
        {
            _bootOperationRunning = false;
            if (!_closing) UpdateBootProtectionButtons();
            UiLogger.Info($"{diagnosticContext} stage=complete elapsedMs={operationWatch.ElapsedMilliseconds} " +
                $"connectionVersion={_fileConnectionVersion} connected={_connected} closing={_closing}");
        }
    }

    private static void LogBootRuntimeIdentity(string diagnosticContext)
    {
        try
        {
            UiLogger.Info($"{diagnosticContext} stage=runtime-identity {FileProtectionDiagnostics.RuntimeIdentity()}");
            UiLogger.Info($"{diagnosticContext} stage=native-module-identity {FileProtectionDiagnostics.LoadedNativeModule()}");
            FileProtectionDiagnostics.LogDeploymentSnapshot(message =>
                UiLogger.Info($"{diagnosticContext} stage=deployment-snapshot {message}"));
        }
        catch (Exception exception)
        {
            // 배포 식별 정보 조회 실패가 원래 보호 명령을 막아서는 안 된다.
            UiLogger.Warn($"{diagnosticContext} stage=identity-unavailable exception={exception}");
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
