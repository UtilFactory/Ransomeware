using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private readonly SemaphoreSlim _fileNativeGate = new(1, 1);
    private bool _fileInitialized;
    private bool _fileConnectionOperationRunning;
    private bool _closing;
    private bool _closeReady;
    private int _fileConnectionVersion;
    private Task _fileLifecycleTask = Task.CompletedTask;

    private async Task<T> RunFileNativeAsync<T>(Func<T> operation, string? diagnosticContext = null)
    {
        Stopwatch? gateWatch = diagnosticContext is null ? null : Stopwatch.StartNew();
        if (diagnosticContext is not null)
            UiLogger.Info($"{diagnosticContext} stage=gate-wait {FileProtectionDiagnostics.ThreadIdentity()}");
        await _fileNativeGate.WaitAsync();
        try
        {
            if (diagnosticContext is not null)
                UiLogger.Info($"{diagnosticContext} stage=gate-enter waitMs={gateWatch!.ElapsedMilliseconds}");
            return await Task.Run(operation);
        }
        finally
        {
            _fileNativeGate.Release();
            if (diagnosticContext is not null)
                UiLogger.Info($"{diagnosticContext} stage=gate-release elapsedMs={gateWatch!.ElapsedMilliseconds}");
        }
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        await RunFileLifecycleAsync(async () =>
        {
            NativeMethods.ValidateAbi();
            uint error = await RunFileNativeAsync(NativeMethods.UfFltInitialize);
            _fileInitialized = error == NativeMethods.ErrorSuccess;
            if (_closing) return;
            if (!_fileInitialized)
            {
                ShowNativeError("통신 DLL 초기화", error);
                return;
            }
            // 포트 자동 연결은 보호를 시작하지 않는다. 상태만 조회한다.
            await ConnectDriverAsync(showFailure: false);
        });
        if (!_closing) InitializeProcessControl();
    }

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_closeReady) return;
        e.Cancel = true;
        if (_closing) return;
        _closing = true;
        _connected = false;
        ++_fileConnectionVersion;
        SetConnectionState(false);
        UiLogger.Info("메인 창 종료: 진행 중인 파일 요청을 마친 후 연결만 해제합니다. 보호 정지는 요청하지 않습니다.");
        UiLogger.Info($"[FileBoot lifecycle] stage=closing connectionVersion={_fileConnectionVersion} " +
            $"initialized={_fileInitialized} bootBusy={_bootOperationRunning} lifecycleBusy={_fileConnectionOperationRunning}");
        try
        {
            await _fileLifecycleTask;
            await _bootOperationTask;
            ShutdownProcessControl();
            await RunFileNativeAsync(() =>
            {
                if (_fileInitialized)
                {
                    NativeMethods.UfFltStopEventReceiver();
                    NativeMethods.UfFltDisconnect();
                    NativeMethods.UfFltShutdown();
                }
                return 0;
            });
        }
        catch (Exception exception)
        {
            UiLogger.Error("종료 중 파일 통신 정리 실패", exception);
        }
        finally
        {
            _closeReady = true;
            Close();
        }
    }

    private Task RunFileLifecycleAsync(Func<Task> operation)
    {
        if (_fileConnectionOperationRunning || _closing) return Task.CompletedTask;
        _fileConnectionOperationRunning = true;
        UpdateFileControlButtons();
        _fileLifecycleTask = ExecuteFileLifecycleAsync(operation);
        return _fileLifecycleTask;
    }

    private async Task ExecuteFileLifecycleAsync(Func<Task> operation)
    {
        try
        {
            await operation();
        }
        catch (Exception exception)
        {
            uint error = FileProtectionPresentation.ErrorCode(exception);
            string message = $"파일 통신 작업 실패: {FileProtectionPresentation.Error(error)} · {exception.Message}";
            UiLogger.Error(message, exception);
            if (!_closing)
            {
                FileDriverStatusText.Text = message;
                SetConnectionState(_connected);
            }
        }
        finally
        {
            _fileConnectionOperationRunning = false;
            if (!_closing) UpdateFileControlButtons();
        }
        if (_connected && !_closing)
        {
            await RefreshBootProtectionAsync();
        }
    }

    private async void Connect_Click(object sender, RoutedEventArgs e) =>
        await RunFileLifecycleAsync(async () =>
        {
            DriverOperationResult result = await Task.Run(DriverInstaller.LoadFileDriver);
            if (_closing) return;
            FileDriverStatusText.Text = result.Message;
            if (!result.Success)
            {
                ShowDriverOperationResult("파일 드라이버 로드", result);
                return;
            }
            await ConnectDriverAsync(showFailure: true);
        });

    private async void Disconnect_Click(object sender, RoutedEventArgs e) =>
        await RunFileLifecycleAsync(DisconnectDriverAsync);

    private async void InstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        if (_closing || _fileConnectionOperationRunning) return;
        if (MessageBox.Show("파일 드라이버를 설치하고 로드하시겠습니까?\n시험용 VM에서만 실행하십시오.",
            "파일 드라이버 설치", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunFileLifecycleAsync(async () =>
        {
            await DisconnectDriverAsync();
            if (_closing) return;
            DriverOperationResult result = await Task.Run(DriverInstaller.InstallFileDriver);
            if (_closing) return;
            FileDriverStatusText.Text = result.Message;
            if (result.Success) await ConnectDriverAsync(showFailure: true);
            if (!_closing) ShowDriverOperationResult("파일 드라이버 설치", result);
        });
    }

    private async void UninstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        if (_closing || _fileConnectionOperationRunning) return;
        if (MessageBox.Show("파일 드라이버를 언로드하고 제거하시겠습니까?\n폴더 정책과 활성 선두 영역 보호도 드라이버 언로드 시 해제됩니다.",
            "파일 드라이버 제거", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunFileLifecycleAsync(async () =>
        {
            await DisconnectDriverAsync();
            if (_closing) return;
            DriverOperationResult result = await Task.Run(DriverInstaller.UninstallFileDriver);
            if (_closing) return;
            FileDriverStatusText.Text = result.Message;
            ShowDriverOperationResult("파일 드라이버 제거", result);
        });
    }

    private async Task ConnectDriverAsync(bool showFailure)
    {
        if (_connected || _closing) return;
        uint error = await RunFileNativeAsync(() =>
        {
            if (!_fileInitialized)
            {
                uint initializeError = NativeMethods.UfFltInitialize();
                if (initializeError != NativeMethods.ErrorSuccess) return initializeError;
                _fileInitialized = true;
            }
            uint connectError = NativeMethods.UfFltConnect();
            if (connectError != NativeMethods.ErrorSuccess && connectError != NativeMethods.ErrorAlreadyExists)
                return connectError;
            try
            {
                uint receiverError = NativeMethods.UfFltStartEventReceiverV2(_eventCallback, IntPtr.Zero);
                if (receiverError == NativeMethods.ErrorSuccess || receiverError == NativeMethods.ErrorAlreadyExists)
                    return NativeMethods.ErrorSuccess;
                NativeMethods.UfFltDisconnect();
                return receiverError;
            }
            catch
            {
                NativeMethods.UfFltDisconnect();
                throw;
            }
        });
        if (_closing) return;
        _connected = error == NativeMethods.ErrorSuccess;
        ++_fileConnectionVersion;
        UiLogger.Info($"[FileBoot lifecycle] stage=connection-result connectionVersion={_fileConnectionVersion} " +
            $"connected={_connected} initialized={_fileInitialized} {FileProtectionDiagnostics.Error(error)}");
        SetConnectionState(_connected);
        if (!_connected)
        {
            FileDriverStatusText.Text = $"파일 필터 연결 실패: {FileProtectionPresentation.Error(error)}";
            UiLogger.Error(FileDriverStatusText.Text);
            if (showFailure) ShowNativeError("파일 필터 연결", error);
        }
        else
        {
            UiLogger.Info("파일 필터 연결 성공. 선두 영역 보호 시작은 보내지 않고 실제 상태를 조회합니다.");
        }
    }

    private async Task DisconnectDriverAsync()
    {
        // 늦은 조회/설정 결과와 이미 대기 중인 이벤트를 먼저 무효화한다.
        _connected = false;
        ++_fileConnectionVersion;
        UiLogger.Info($"[FileBoot lifecycle] stage=disconnect-invalidate connectionVersion={_fileConnectionVersion} " +
            $"initialized={_fileInitialized} bootBusy={_bootOperationRunning}");
        SetConnectionState(false);
        await RunFileNativeAsync(() =>
        {
            if (_fileInitialized)
            {
                NativeMethods.UfFltStopEventReceiver();
                NativeMethods.UfFltDisconnect();
            }
            return 0;
        });
        UiLogger.Info("파일 필터 연결만 해제했습니다. 활성 선두 영역 보호의 정지는 요청하지 않았습니다.");
    }

    private void SetConnectionState(bool connected)
    {
        FileDriverConnectionText.Text = connected ? "파일 필터: 연결됨" : "파일 필터: 연결 안 됨";
        FileDriverConnectionIndicator.Fill = new SolidColorBrush(
            connected ? Color.FromRgb(22, 163, 74) : Color.FromRgb(179, 38, 30));
        if (!connected) SetBootProtectionUnknown("파일 필터 연결 해제 · 보호 상태는 재연결 후 조회해야 합니다.");
        UpdateFileControlButtons();
    }

    private void UpdateFileControlButtons()
    {
        bool available = !_fileConnectionOperationRunning && !_closing;
        ConnectFileButton.IsEnabled = available && !_connected;
        DisconnectFileButton.IsEnabled = available && _connected;
        InstallFileButton.IsEnabled = available;
        UninstallFileButton.IsEnabled = available;
        ApplyPolicyButton.IsEnabled = available && _connected && !_policyOperationRunning;
        ClearPolicyButton.IsEnabled = available && _connected && !_policyOperationRunning;
        UpdateBootProtectionButtons();
    }

    private static void ShowDriverOperationResult(string title, DriverOperationResult result)
    {
        string message = result.Message;
        if (result.LastError.HasValue)
            message += $"\n{FileProtectionPresentation.Error(unchecked((uint)result.LastError.Value))}";
        if (result.RebootRequired) message += "\n작업을 완료하려면 Windows를 다시 시작해야 합니다.";
        if (result.Success) UiLogger.Info($"{title}: {message}");
        else UiLogger.Error($"{title}: {message}");
        MessageBox.Show(message, title, MessageBoxButton.OK,
            result.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
    }
}
