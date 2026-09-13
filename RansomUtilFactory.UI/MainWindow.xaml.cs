using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;

namespace RansomUtilFactory.UI;

public partial class MainWindow : Window
{
    private const int MaxLogCount = 2000;
    private readonly NativeMethods.EventCallbackV2 _eventCallback;
    private bool _connected;
    private bool _receiverStarted;
    private bool _policyOperationRunning;

    public ObservableCollection<string> MonitorFolders { get; } = [];
    public ObservableCollection<ProtectedFolderEntry> ProtectFolders { get; } = [];
    public ObservableCollection<FileEventLog> EventLogs { get; } = [];

    public MainWindow()
    {
        UiLogger.Info("메인 창 생성 시작");
        InitializeComponent();
        DataContext = this;
        _eventCallback = ReceiveFileEvent;
        UiLogger.Info("메인 창 생성 완료");
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        InitializeBootControl();
        try
        {
            UiLogger.Info("메인 창 로드 시작");
        try
        {
            UiLogger.Info("통신 DLL ABI 검증 시작");
            NativeMethods.ValidateAbi();
            UiLogger.Info("통신 DLL ABI 검증 완료");
        }
        catch (Exception exception)
        {
            UiLogger.Error("통신 DLL ABI 검증 실패", exception);
            MessageBox.Show(exception.Message, "통신 DLL 초기화",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        uint error;
        try
        {
            UiLogger.Info("UfFltInitialize 호출 시작");
            error = NativeMethods.UfFltInitialize();
            UiLogger.Info($"UfFltInitialize 호출 완료 error={error}");
        }
        catch (Exception exception)
        {
            UiLogger.Error("통신 DLL 초기화 호출 예외", exception);
            MessageBox.Show(exception.Message, "통신 DLL 초기화",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        if (error != NativeMethods.ErrorSuccess)
        {
            UiLogger.Error($"통신 DLL 초기화 실패 error={error}");
            ShowNativeError("통신 DLL 초기화", error);
            return;
        }
        UiLogger.Info("창 로드 시 자동 드라이버 연결 시작");
        ConnectDriver(showFailure: false);
        UiLogger.Info($"창 로드 시 자동 드라이버 연결 완료 connected={_connected} receiver={_receiverStarted}");
        InitializeProcessControl();
        UiLogger.Info("메인 창 로드 완료");
    }
    catch (Exception exception)
    {
        UiLogger.Error("메인 창 로드 처리 중 예외", exception);
        MessageBox.Show(exception.Message, "RansomUtilFactory.UI 시작",
            MessageBoxButton.OK, MessageBoxImage.Error);
    }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        UiLogger.Info("메인 창 종료 시작");
        ShutdownBootControl();
        ShutdownProcessControl();
        DisconnectDriver();
        NativeMethods.UfFltShutdown();
        UiLogger.Info("메인 창 종료 완료");
    }

    private void Connect_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 파일 드라이버 연결을 요청");
        DriverOperationResult loadResult;
        try
        {
            loadResult = DriverInstaller.LoadFileDriver();
        }
        catch (Exception exception)
        {
            UiLogger.Error("파일 드라이버 로드 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "파일 드라이버 로드",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        FileDriverStatusText.Text = loadResult.Message;
        if (!loadResult.Success)
        {
            UiLogger.Error($"파일 드라이버 로드 실패 message={loadResult.Message}");
            ShowDriverOperationResult("파일 드라이버 로드", loadResult);
            return;
        }
        ConnectDriver(showFailure: true);
    }

    private void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 파일 드라이버 연결 해제를 요청");
        DisconnectDriver();
    }

    private void InstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 파일 드라이버 설치를 요청");
        if (MessageBox.Show(
                "파일 드라이버를 설치하고 로드하시겠습니까?\n시험용 VM에서만 실행하십시오.",
                "파일 드라이버 설치", MessageBoxButton.YesNo, MessageBoxImage.Warning) !=
            MessageBoxResult.Yes)
        {
            UiLogger.Info("파일 드라이버 설치 취소");
            return;
        }

        DisconnectDriver();
        DriverOperationResult result;
        try
        {
            result = DriverInstaller.InstallFileDriver();
        }
        catch (Exception exception)
        {
            UiLogger.Error("파일 드라이버 설치 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "파일 드라이버 설치",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        UiLogger.Info($"파일 드라이버 설치 결과 success={result.Success} message={result.Message}");
        FileDriverStatusText.Text = result.Message;
        if (!result.Success)
        {
            ShowDriverOperationResult("파일 드라이버 설치", result);
            return;
        }
        ConnectDriver(showFailure: true);
        ShowDriverOperationResult("파일 드라이버 설치", result);
    }

    private void UninstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 파일 드라이버 제거를 요청");
        if (MessageBox.Show(
                "적용된 정책을 초기화하고 파일 드라이버를 제거하시겠습니까?",
                "파일 드라이버 제거", MessageBoxButton.YesNo, MessageBoxImage.Warning) !=
            MessageBoxResult.Yes)
        {
            UiLogger.Info("파일 드라이버 제거 취소");
            return;
        }

        if (_connected)
        {
            uint clearError = NativeMethods.UfFltClearPolicy();
            if (clearError != NativeMethods.ErrorSuccess)
            {
                UiLogger.Warn($"파일 드라이버 제거 전 정책 초기화 실패 error={clearError}");
            }
        }
        DisconnectDriver();
        DriverOperationResult result;
        try
        {
            result = DriverInstaller.UninstallFileDriver();
        }
        catch (Exception exception)
        {
            UiLogger.Error("파일 드라이버 제거 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "파일 드라이버 제거",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        UiLogger.Info($"파일 드라이버 제거 결과 success={result.Success} message={result.Message}");
        FileDriverStatusText.Text = result.Message;
        ShowDriverOperationResult("파일 드라이버 제거", result);
    }

    private static void ShowDriverOperationResult(string title, DriverOperationResult result)
    {
        string lastError = result.LastError?.ToString() ?? "없음";
        if (result.Success)
        {
            UiLogger.Info($"{title} 성공 message={result.Message} GetLastError={lastError}");
        }
        else
        {
            UiLogger.Error($"{title} 실패 GetLastError={lastError} message={result.Message}");
        }
        string message = result.RebootRequired
            ? $"{result.Message}\n작업을 완료하려면 Windows를 다시 시작해야 합니다."
            : result.Message;
        if (!result.Success && result.LastError.HasValue)
        {
            message += $"\nGetLastError: {result.LastError.Value}";
        }
        MessageBox.Show(message, title, MessageBoxButton.OK,
            result.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
    }

    private void ConnectDriver(bool showFailure)
    {
        if (_connected)
        {
            UiLogger.Debug("드라이버 연결 요청 무시: 이미 연결됨");
            return;
        }
        UiLogger.Info($"드라이버 통신 연결 호출 시작 showFailure={showFailure}");
        uint error;
        try
        {
            error = NativeMethods.UfFltConnect();
        }
        catch (Exception exception)
        {
            UiLogger.Error("UfFltConnect 호출 예외", exception);
            SetConnectionState(false);
            if (showFailure)
            {
                MessageBox.Show(exception.Message, "드라이버 연결",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }
        UiLogger.Info($"드라이버 통신 연결 호출 완료 error={error}");
        if (error != NativeMethods.ErrorSuccess && error != NativeMethods.ErrorAlreadyExists)
        {
            UiLogger.Warn($"파일 필터 통신 연결 실패 GetLastError={error} message={GetFileNativeErrorMessage(error)}");
            SetConnectionState(false);
            if (showFailure)
            {
                ShowNativeError("드라이버 연결", error);
            }
            return;
        }
        _connected = true;
        UiLogger.Info("이벤트 수신 시작 호출 시작");
        try
        {
            error = NativeMethods.UfFltStartEventReceiverV2(_eventCallback, IntPtr.Zero);
        }
        catch (Exception exception)
        {
            UiLogger.Error("UfFltStartEventReceiverV2 호출 예외", exception);
            try
            {
                NativeMethods.UfFltDisconnect();
            }
            catch (Exception disconnectException)
            {
                UiLogger.Error("이벤트 수신 시작 실패 후 DLL 연결 해제 예외", disconnectException);
            }
            _connected = false;
            SetConnectionState(false);
            if (showFailure)
            {
                MessageBox.Show(exception.Message, "이벤트 수신 시작",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }
        UiLogger.Info($"이벤트 수신 시작 호출 완료 error={error}");
        if (error != NativeMethods.ErrorSuccess && error != NativeMethods.ErrorAlreadyExists)
        {
            NativeMethods.UfFltDisconnect();
            _connected = false;
            SetConnectionState(false);
            if (showFailure)
            {
                ShowNativeError("이벤트 수신 시작", error);
            }
            return;
        }
        _receiverStarted = true;
        SetConnectionState(true);
        UiLogger.Info("드라이버 통신 연결 및 이벤트 수신 시작 완료");
    }

    private void DisconnectDriver()
    {
        bool succeeded = true;
        try
        {
            if (_receiverStarted)
            {
                UiLogger.Info("이벤트 수신 중지 호출 시작");
                NativeMethods.UfFltStopEventReceiver();
                _receiverStarted = false;
                UiLogger.Info("이벤트 수신 중지 호출 완료");
            }
            if (_connected)
            {
                UiLogger.Info("드라이버 통신 연결 해제 호출 시작");
                NativeMethods.UfFltDisconnect();
                _connected = false;
                UiLogger.Info("드라이버 통신 연결 해제 호출 완료");
            }
        }
        catch (Exception exception)
        {
            succeeded = false;
            UiLogger.Error("드라이버 연결 해제 처리 예외", exception);
        }
        SetConnectionState(false);
        UiLogger.Info($"드라이버 통신 연결 해제 처리 종료 success={succeeded}");
    }

    private void SetConnectionState(bool connected)
    {
        FileDriverConnectionText.Text = connected ? "파일 필터: 연결됨" : "파일 필터: 연결 안 됨";
        FileDriverConnectionIndicator.Fill = new SolidColorBrush(
            connected ? Color.FromRgb(22, 163, 74) : Color.FromRgb(179, 38, 30));
    }

    private void SetProcessConnectionState(bool connected, string? detail = null)
    {
        ProcessDriverConnectionText.Text = connected
            ? $"프로세스 제어 필터: 연결됨{(string.IsNullOrWhiteSpace(detail) ? string.Empty : $" ({detail})")}"
            : $"프로세스 제어 필터: 연결 안 됨{(string.IsNullOrWhiteSpace(detail) ? string.Empty : $" ({detail})")}";
        ProcessDriverConnectionIndicator.Fill = new SolidColorBrush(
            connected ? Color.FromRgb(22, 163, 74) : Color.FromRgb(179, 38, 30));
    }

    private void AddMonitorFolder_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("감시 폴더 추가 버튼 클릭");
        AddFolder(MonitorFolders, "감시 폴더");
    }

    private void AddProtectFolder_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("보호 폴더 추가 버튼 클릭");
        try
        {
            OpenFolderDialog dialog = new()
            {
                Title = "보호 폴더 선택",
                Multiselect = false
            };
            if (dialog.ShowDialog() != true)
            {
                UiLogger.Info("보호 폴더 선택 취소");
                return;
            }

            string path = NormalizeFolderPath(dialog.FolderName);
            if (ProtectFolders.Any(item => string.Equals(item.Path, path,
                    StringComparison.OrdinalIgnoreCase)))
            {
                UiLogger.Warn($"보호 폴더 중복 추가 거부 path={path}");
                return;
            }

            ProtectedFolderEntry entry = new(path);
            ProtectFolders.Add(entry);
            ProtectFolderList.SelectedItem = entry;
            UiLogger.Info($"보호 폴더 추가 완료 path={path}");
        }
        catch (Exception exception)
        {
            UiLogger.Error("보호 폴더 추가 실패", exception);
            MessageBox.Show(exception.Message, "보호 폴더 추가",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddFolder(ObservableCollection<string> target, string folderType)
    {
        try
        {
            OpenFolderDialog dialog = new()
            {
                Title = "폴더 선택",
                Multiselect = false
            };
            if (dialog.ShowDialog() != true)
            {
                UiLogger.Info($"{folderType} 선택 취소");
                return;
            }

            string path = NormalizeFolderPath(dialog.FolderName);
            if (target.Contains(path, StringComparer.OrdinalIgnoreCase))
            {
                UiLogger.Warn($"{folderType} 중복 추가 거부 path={path}");
                return;
            }

            target.Add(path);
            UiLogger.Info($"{folderType} 추가 완료 path={path}");
        }
        catch (Exception exception)
        {
            UiLogger.Error($"{folderType} 추가 실패", exception);
            MessageBox.Show(exception.Message, folderType,
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string NormalizeFolderPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath) ?? string.Empty;
        return string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase)
            ? root
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private void RemoveMonitorFolder_Click(object sender, RoutedEventArgs e)
    {
        if (MonitorFolderList.SelectedItem is string selected)
        {
            MonitorFolders.Remove(selected);
            UiLogger.Info($"감시 폴더 제거 완료 path={selected}");
            return;
        }
        UiLogger.Warn("감시 폴더 제거 실패: 선택된 폴더 없음");
    }

    private void RemoveProtectFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ProtectFolderList.SelectedItem is ProtectedFolderEntry selected)
        {
            ProtectFolders.Remove(selected);
            AllowedProcessList.ItemsSource = null;
            UiLogger.Info($"보호 폴더 제거 완료 path={selected.Path}");
            return;
        }
        UiLogger.Warn("보호 폴더 제거 실패: 선택된 폴더 없음");
    }

    private void ProtectFolderList_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        AllowedProcessList.ItemsSource =
            (ProtectFolderList.SelectedItem as ProtectedFolderEntry)?.AllowedProcesses;
    }

    private void AddAllowedProcess_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("허용 프로그램 추가 버튼 클릭");
        if (ProtectFolderList.SelectedItem is not ProtectedFolderEntry folder)
        {
            UiLogger.Warn("허용 프로그램 추가 실패: 보호 폴더가 선택되지 않음");
            MessageBox.Show("먼저 보호 폴더를 선택하십시오.", "허용 프로그램",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            OpenFileDialog dialog = new()
            {
                Title = "허용할 실행 파일 선택",
                Filter = "실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*",
                Multiselect = false,
                CheckFileExists = true
            };
            if (dialog.ShowDialog() != true)
            {
                UiLogger.Info("허용 프로그램 선택 취소");
                return;
            }

            string path = Path.GetFullPath(dialog.FileName);
            if (folder.AllowedProcesses.Any(item => string.Equals(item.Path, path,
                    StringComparison.OrdinalIgnoreCase)))
            {
                UiLogger.Warn($"허용 프로그램 중복 추가 거부 path={path}");
                return;
            }

            folder.AllowedProcesses.Add(new AllowedProcessEntry(path));
            UiLogger.Info($"허용 프로그램 추가 완료 folder={folder.Path} path={path}");
        }
        catch (Exception exception)
        {
            UiLogger.Error("허용 프로그램 추가 실패", exception);
            MessageBox.Show(exception.Message, "허용 프로그램",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RemoveAllowedProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ProtectFolderList.SelectedItem is ProtectedFolderEntry folder &&
            AllowedProcessList.SelectedItem is AllowedProcessEntry selected)
        {
            folder.AllowedProcesses.Remove(selected);
            UiLogger.Info($"허용 프로그램 제거 완료 folder={folder.Path} path={selected.Path}");
            return;
        }
        UiLogger.Warn("허용 프로그램 제거 실패: 보호 폴더 또는 프로그램이 선택되지 않음");
    }

    private async void ApplyPolicy_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 정책 적용을 요청");
        if (_policyOperationRunning)
        {
            UiLogger.Warn("정책 적용 요청 무시: 이전 작업이 아직 실행 중");
            return;
        }
        if (!_connected)
        {
            UiLogger.Warn("정책 적용 실패: 드라이버에 연결되지 않음");
            MessageBox.Show("먼저 드라이버에 연결하십시오.", "정책 적용",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MonitorFolders.Count + ProtectFolders.Count > 64)
        {
            UiLogger.Warn($"정책 적용 실패: 폴더 개수 초과 monitor={MonitorFolders.Count} protected={ProtectFolders.Count}");
            MessageBox.Show("감시 폴더와 보호 폴더는 합계 64개까지 설정할 수 있습니다.",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        HashSet<string> monitored = new(MonitorFolders, StringComparer.OrdinalIgnoreCase);
        ProtectedFolderEntry? duplicate = ProtectFolders.FirstOrDefault(folder =>
            monitored.Contains(folder.Path));
        if (duplicate is not null)
        {
            UiLogger.Warn($"정책 적용 실패: 감시·보호 폴더 중복 path={duplicate.Path}");
            MessageBox.Show($"같은 폴더를 감시와 보호에 동시에 설정할 수 없습니다.\n{duplicate.Path}",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        List<string> monitorFolders = MonitorFolders.ToList();
        List<ProtectedFolderPolicySnapshot> protectedFolders = ProtectFolders
            .Select(folder => new ProtectedFolderPolicySnapshot(
                folder.Path,
                folder.AllowedProcesses
                    .Select(process => new AllowedProcessPolicySnapshot(
                        process.Path, process.Access, process.RequireCodeSignature,
                        process.MatchMode))
                    .ToArray()))
            .ToList();

        _policyOperationRunning = true;
        ApplyPolicyButton.IsEnabled = false;
        ClearPolicyButton.IsEnabled = false;
        PolicyStatusText.Text = "정책 적용 중...";
        UiLogger.Info("정책 적용 네이티브 호출 시작");

        uint error;
        string? validationMessage;
        try
        {
            PolicyApplyResult result = await Task.Run(() =>
            {
                string? message;
                uint nativeError = ReplacePolicyV2(
                    monitorFolders, protectedFolders, out message);
                return new PolicyApplyResult(nativeError, message);
            });
            error = result.Error;
            validationMessage = result.ValidationMessage;
            UiLogger.Info($"정책 적용 네이티브 호출 완료 error={error}");
        }
        catch (Exception exception)
        {
            UiLogger.Error("정책 적용 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "정책 적용",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        finally
        {
            _policyOperationRunning = false;
            ApplyPolicyButton.IsEnabled = true;
            ClearPolicyButton.IsEnabled = true;
        }
        if (error != NativeMethods.ErrorSuccess)
        {
            UiLogger.Error($"정책 적용 실패 error={error} validation={validationMessage}");
            if (!string.IsNullOrWhiteSpace(validationMessage))
            {
                MessageBox.Show(validationMessage, "정책 적용",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            ShowNativeError("정책 적용", error);
            return;
        }
        PolicyStatusText.Text = $"정책 적용됨: 감시 {monitorFolders.Count}개, 보호 {protectedFolders.Count}개";
        UiLogger.Info($"정책 적용 성공 monitor={monitorFolders.Count} protected={protectedFolders.Count}");
    }

    private uint ReplacePolicyV2(
        IReadOnlyList<string> monitorFolders,
        IReadOnlyList<ProtectedFolderPolicySnapshot> protectFolders,
        out string? validationMessage)
    {
        validationMessage = null;
        List<IntPtr> strings = [];
        IntPtr pathBuffer = IntPtr.Zero;
        IntPtr processBuffer = IntPtr.Zero;
        IntPtr signerBuffer = IntPtr.Zero;
        try
        {
            List<(uint RuleId, uint Mode, string Path)> pathRules = [];
            uint nextFolderRuleId = 1000;
            foreach (string path in monitorFolders)
            {
                pathRules.Add((nextFolderRuleId++, NativeMethods.UfRuleMonitor, path));
            }
            foreach (ProtectedFolderPolicySnapshot folder in protectFolders)
            {
                pathRules.Add((nextFolderRuleId++, NativeMethods.UfRuleProtected, folder.Path));
            }
            pathRules = pathRules.OrderByDescending(rule => rule.Path.Length).ToList();

            List<NativeMethods.ProtectedProcessInput> processRules = [];
            List<NativeMethods.SignerInput> signerRules = [];
            Dictionary<string, uint> folderIds = pathRules
                .Where(rule => rule.Mode == NativeMethods.UfRuleProtected)
                .ToDictionary(rule => rule.Path, rule => rule.RuleId,
                    StringComparer.OrdinalIgnoreCase);
            uint nextProcessRuleId = 3000;
            uint nextSignerRuleId = 4000;
            foreach (ProtectedFolderPolicySnapshot folder in protectFolders)
            {
                if (!folderIds.TryGetValue(folder.Path, out uint folderRuleId))
                {
                    validationMessage = $"보호 폴더 규칙을 만들 수 없습니다: {folder.Path}";
                    return 87;
                }
                foreach (AllowedProcessPolicySnapshot allowedProcess in folder.AllowedProcesses)
                {
                    string imagePath = allowedProcess.Path;
                    if (imagePath.Length >= 260)
                    {
                        validationMessage = $"실행 파일 경로가 너무 깁니다.\n{imagePath}";
                        return 206;
                    }
                    if (allowedProcess.Access == 0)
                    {
                        validationMessage = $"허용 프로세스의 읽기 또는 쓰기 권한을 하나 이상 선택하십시오.\n{imagePath}";
                        return 87;
                    }

                    uint signerRuleId = 0;
                    ushort processFlags = 0;
                    NativeMethods.SignerIdentity identity = NativeMethods.CreateSignerIdentity();
                    if (allowedProcess.RequireCodeSignature)
                    {
                        uint signerError = NativeMethods.UfFltGetImageSignerIdentityWithTimeout(
                            imagePath, 0, 1000, ref identity);
                        if (signerError != NativeMethods.ErrorSuccess || identity.Trusted == 0)
                        {
                            validationMessage = $"허용 프로그램의 유효한 코드 서명을 확인하지 못했습니다.\n{imagePath}\n오류 코드: {signerError}";
                            return signerError == NativeMethods.ErrorSuccess ? 577u : signerError;
                        }

                        signerRuleId = nextSignerRuleId++;
                        processFlags = NativeMethods.UfProcessRuleFlagRequireCodeSignature;
                        IntPtr thumbprintHex = Marshal.StringToHGlobalUni(
                            Convert.ToHexString(identity.ThumbprintSha256));
                        IntPtr issuerHex = Marshal.StringToHGlobalUni(
                            Convert.ToHexString(identity.IssuerSha256));
                        IntPtr serialHex = Marshal.StringToHGlobalUni(
                            Convert.ToHexString(
                                identity.SerialNumber, 0,
                                (int)identity.SerialLengthBytes));
                        strings.Add(thumbprintHex);
                        strings.Add(issuerHex);
                        strings.Add(serialHex);
                        signerRules.Add(new NativeMethods.SignerInput
                        {
                            RuleId = signerRuleId,
                            MatchType = NativeMethods.UfSignerMatchThumbprintSha256,
                            ThumbprintSha256Hex = thumbprintHex,
                            IssuerSha256Hex = issuerHex,
                            SerialNumberHex = serialHex,
                            DisplayCompany = IntPtr.Zero
                        });
                    }
                    if (allowedProcess.MatchMode == NativeMethods.UfProcessMatchImageName)
                    {
                        processFlags |= NativeMethods.UfProcessRuleFlagMatchImageName;
                    }

                    IntPtr imagePathPointer = Marshal.StringToHGlobalUni(imagePath);
                    strings.Add(imagePathPointer);
                    processRules.Add(new NativeMethods.ProtectedProcessInput
                    {
                        RuleId = nextProcessRuleId++, FolderRuleId = folderRuleId,
                        SignerRuleId = signerRuleId, Reserved16 = processFlags,
                        Access = allowedProcess.Access,
                        DosImagePath = imagePathPointer
                    });
                }
            }

            int pathSize = Marshal.SizeOf<NativeMethods.PathInputV2>();
            if (pathRules.Count > 0)
            {
                pathBuffer = Marshal.AllocHGlobal(pathSize * pathRules.Count);
                for (int index = 0; index < pathRules.Count; index++)
                {
                    IntPtr path = Marshal.StringToHGlobalUni(pathRules[index].Path);
                    strings.Add(path);
                    NativeMethods.PathInputV2 input = new()
                    {
                        RuleId = pathRules[index].RuleId,
                        Mode = pathRules[index].Mode,
                        DosPath = path
                    };
                    Marshal.StructureToPtr(input, IntPtr.Add(pathBuffer, index * pathSize), false);
                }
            }

            int processSize = Marshal.SizeOf<NativeMethods.ProtectedProcessInput>();
            if (processRules.Count > 0)
            {
                processBuffer = Marshal.AllocHGlobal(processSize * processRules.Count);
                for (int index = 0; index < processRules.Count; index++)
                {
                    Marshal.StructureToPtr(processRules[index],
                        IntPtr.Add(processBuffer, index * processSize), false);
                }
            }

            int signerSize = Marshal.SizeOf<NativeMethods.SignerInput>();
            if (signerRules.Count > 0)
            {
                signerBuffer = Marshal.AllocHGlobal(signerSize * signerRules.Count);
                for (int index = 0; index < signerRules.Count; index++)
                {
                    Marshal.StructureToPtr(signerRules[index],
                        IntPtr.Add(signerBuffer, index * signerSize), false);
                }
            }

            NativeMethods.PolicyInputV2 policy = new()
            {
                PolicyGeneration = unchecked((ulong)Environment.TickCount64),
                PathRuleCount = (uint)pathRules.Count,
                PathRules = pathBuffer,
                ProtectedProcessRuleCount = (uint)processRules.Count,
                ProtectedProcesses = processBuffer,
                SignerRuleCount = (uint)signerRules.Count,
                Signers = signerBuffer,
                OnlineRevocationEnabled = 0,
                RevocationTimeoutMilliseconds = 1000,
                RevocationTimeoutAction = NativeMethods.UfRevocationTimeoutDeny,
                TerminateOnRevoked = 0
            };
            return NativeMethods.UfFltReplacePolicyV2(ref policy);
        }
        finally
        {
            foreach (IntPtr value in strings)
            {
                Marshal.FreeHGlobal(value);
            }
            if (pathBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pathBuffer);
            }
            if (processBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(processBuffer);
            }
            if (signerBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(signerBuffer);
            }
        }
    }

    private sealed record PolicyApplyResult(uint Error, string? ValidationMessage);

    private sealed record ProtectedFolderPolicySnapshot(
        string Path,
        IReadOnlyList<AllowedProcessPolicySnapshot> AllowedProcesses);

    private sealed record AllowedProcessPolicySnapshot(
        string Path,
        ushort Access,
        bool RequireCodeSignature,
        int MatchMode);

    private void ClearPolicy_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 정책 초기화를 요청");
        if (!_connected)
        {
            UiLogger.Warn("정책 초기화 실패: 드라이버에 연결되지 않음");
            MessageBox.Show("먼저 드라이버에 연결하십시오.", "정책 초기화",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        uint error;
        try
        {
            error = NativeMethods.UfFltClearPolicy();
        }
        catch (Exception exception)
        {
            UiLogger.Error("정책 초기화 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "정책 초기화",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        if (error != NativeMethods.ErrorSuccess)
        {
            ShowNativeError("정책 초기화", error);
            return;
        }
        PolicyStatusText.Text = "드라이버 정책을 초기화했습니다.";
        UiLogger.Info("정책 초기화 성공");
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("UI 이벤트 로그 목록 초기화");
        EventLogs.Clear();
    }

    private void ReceiveFileEvent(IntPtr eventPointer, IntPtr context)
    {
        NativeMethods.FileEventV2 fileEvent = Marshal.PtrToStructure<NativeMethods.FileEventV2>(eventPointer);
        FileEventLog log = new(
            DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            fileEvent.Action switch
            {
                1 => "감시",
                3 => "검증 요청",
                4 => "서명 폐기",
                _ => "차단"
            },
            fileEvent.ProcessId,
            fileEvent.Image ?? string.Empty,
            fileEvent.Path ?? string.Empty);
        Dispatcher.BeginInvoke(() =>
        {
            EventLogs.Insert(0, log);
            while (EventLogs.Count > MaxLogCount)
            {
                EventLogs.RemoveAt(EventLogs.Count - 1);
            }
        });

        if (fileEvent.Action == 3)
        {
            UiLogger.Info($"프로세스 신뢰 요청 pid={fileEvent.ProcessId} rule={fileEvent.ProcessRuleId}");
            _ = Task.Run(() => ResolveProcessTrust(fileEvent));
        }
    }

    private static void ResolveProcessTrust(NativeMethods.FileEventV2 fileEvent)
    {
        string imagePath = NativeMethods.TryGetProcessImagePath(fileEvent.ProcessId)
            ?? fileEvent.Image;
        NativeMethods.SignerIdentity identity = NativeMethods.CreateSignerIdentity();
        uint signerError = NativeMethods.UfFltGetImageSignerIdentityWithTimeout(
            imagePath, 0, 1000, ref identity);
        ushort decision = signerError == NativeMethods.ErrorSuccess && identity.Trusted != 0
            ? NativeMethods.UfTrustAllow
            : NativeMethods.UfTrustDeny;

        IntPtr identityBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.SignerIdentity>());
        try
        {
            Marshal.StructureToPtr(identity, identityBuffer, false);
            NativeMethods.ProcessTrustInput trust = new()
            {
                PolicyGeneration = fileEvent.PolicyGeneration,
                ProcessCreateTime = fileEvent.ProcessCreateTime,
                ProcessId = fileEvent.ProcessId,
                ProcessRuleId = fileEvent.ProcessRuleId,
                Access = fileEvent.RequestedAccess,
                Decision = decision,
                Temporary = 0,
                SignerIdentity = identityBuffer
            };
            uint trustResult = NativeMethods.UfFltSetProcessTrust(ref trust);
            UiLogger.Info($"프로세스 신뢰 응답 pid={fileEvent.ProcessId} rule={fileEvent.ProcessRuleId} decision={decision} signerError={signerError} result={trustResult}");
        }
        finally
        {
            Marshal.FreeHGlobal(identityBuffer);
        }
    }

    private void ShowNativeError(string operation, uint error)
    {
        string message = GetFileNativeErrorMessage(error);
        UiLogger.Error($"네이티브 작업 실패 operation={operation} GetLastError={error} message={message}");
        MessageBox.Show($"{operation} 실패\nGetLastError: {error}\n{message}",
            "RansomUtilFactory", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static string GetFileNativeErrorMessage(uint error)
    {
        char[] buffer = new char[512];
        uint result = NativeMethods.UfFltGetErrorMessage(error, buffer, (uint)buffer.Length);
        return result == NativeMethods.ErrorSuccess
            ? new string(buffer).TrimEnd('\0')
            : $"오류 메시지 조회 실패(GetLastError={result})";
    }
}

public sealed record FileEventLog(
    string Time,
    string Action,
    uint ProcessId,
    string Image,
    string Path);

public sealed class ProtectedFolderEntry
{
    public ProtectedFolderEntry(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public ObservableCollection<AllowedProcessEntry> AllowedProcesses { get; } = [];
}

public sealed class AllowedProcessEntry
{
    public AllowedProcessEntry(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public ushort Access { get; private set; } = NativeMethods.PfAccessAll;

    public bool AllowRead
    {
        get => (Access & NativeMethods.PfAccessRead) != 0;
        set => Access = value
            ? (ushort)(Access | NativeMethods.PfAccessRead)
            : (ushort)(Access & ~NativeMethods.PfAccessRead);
    }

    public bool AllowWrite
    {
        get => (Access & NativeMethods.PfAccessWrite) != 0;
        set => Access = value
            ? (ushort)(Access | NativeMethods.PfAccessWrite)
            : (ushort)(Access & ~NativeMethods.PfAccessWrite);
    }

    public bool RequireCodeSignature { get; set; } = true;

    public int MatchMode { get; set; } = NativeMethods.UfProcessMatchFullPath;
}
