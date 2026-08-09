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
        if (result.Success)
        {
            UiLogger.Info($"{title} 성공 message={result.Message}");
        }
        else
        {
            UiLogger.Error($"{title} 실패 message={result.Message}");
        }
        string message = result.RebootRequired
            ? $"{result.Message}\n작업을 완료하려면 Windows를 다시 시작해야 합니다."
            : result.Message;
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
            UiLogger.Warn($"드라이버 통신 연결 실패 error={error}");
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
        ConnectionText.Text = connected ? "드라이버 연결됨" : "드라이버 연결 안 됨";
        ConnectionIndicator.Fill = new SolidColorBrush(
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
            if (folder.AllowedProcesses.Contains(path, StringComparer.OrdinalIgnoreCase))
            {
                UiLogger.Warn($"허용 프로그램 중복 추가 거부 path={path}");
                return;
            }

            folder.AllowedProcesses.Add(path);
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
            AllowedProcessList.SelectedItem is string selected)
        {
            folder.AllowedProcesses.Remove(selected);
            UiLogger.Info($"허용 프로그램 제거 완료 folder={folder.Path} path={selected}");
            return;
        }
        UiLogger.Warn("허용 프로그램 제거 실패: 보호 폴더 또는 프로그램이 선택되지 않음");
    }

    private void ApplyPolicy_Click(object sender, RoutedEventArgs e)
    {
        UiLogger.Info("사용자가 정책 적용을 요청");
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

        uint error;
        string? validationMessage;
        try
        {
            error = ReplacePolicyV2(out validationMessage);
        }
        catch (Exception exception)
        {
            UiLogger.Error("정책 적용 버튼 처리 예외", exception);
            MessageBox.Show(exception.Message, "정책 적용",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
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
        PolicyStatusText.Text = $"정책 적용됨: 감시 {MonitorFolders.Count}개, 보호 {ProtectFolders.Count}개";
        UiLogger.Info($"정책 적용 성공 monitor={MonitorFolders.Count} protected={ProtectFolders.Count}");
    }

    private uint ReplacePolicyV2(out string? validationMessage)
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
            foreach (string path in MonitorFolders)
            {
                pathRules.Add((nextFolderRuleId++, NativeMethods.UfRuleMonitor, path));
            }
            foreach (ProtectedFolderEntry folder in ProtectFolders)
            {
                pathRules.Add((nextFolderRuleId++, NativeMethods.UfRuleProtected, folder.Path));
            }
            pathRules = pathRules.OrderByDescending(rule => rule.Path.Length).ToList();

            List<NativeMethods.ProtectedProcessRule> processRules = [];
            List<NativeMethods.SignerRule> signerRules = [];
            Dictionary<string, uint> folderIds = pathRules
                .Where(rule => rule.Mode == NativeMethods.UfRuleProtected)
                .ToDictionary(rule => rule.Path, rule => rule.RuleId,
                    StringComparer.OrdinalIgnoreCase);
            uint nextProcessRuleId = 3000;
            uint nextSignerRuleId = 4000;
            foreach (ProtectedFolderEntry folder in ProtectFolders)
            {
                if (!folderIds.TryGetValue(folder.Path, out uint folderRuleId))
                {
                    validationMessage = $"보호 폴더 규칙을 만들 수 없습니다: {folder.Path}";
                    return 87;
                }
                foreach (string imagePath in folder.AllowedProcesses)
                {
                    if (imagePath.Length >= 260)
                    {
                        validationMessage = $"실행 파일 경로가 너무 깁니다.\n{imagePath}";
                        return 206;
                    }

                    NativeMethods.SignerIdentity identity = NativeMethods.CreateSignerIdentity();
                    uint signerError = NativeMethods.UfFltGetImageSignerIdentityWithTimeout(
                        imagePath, 0, 1000, ref identity);
                    if (signerError != NativeMethods.ErrorSuccess || identity.Trusted == 0)
                    {
                        validationMessage = $"허용 프로그램의 유효한 코드 서명을 확인하지 못했습니다.\n{imagePath}\n오류 코드: {signerError}";
                        return signerError == NativeMethods.ErrorSuccess ? 577u : signerError;
                    }

                    uint signerRuleId = nextSignerRuleId++;
                    signerRules.Add(new NativeMethods.SignerRule
                    {
                        RuleId = signerRuleId,
                        MatchType = NativeMethods.UfSignerMatchThumbprintSha256,
                        SerialLengthBytes = identity.SerialLengthBytes,
                        ThumbprintSha256 = identity.ThumbprintSha256,
                        IssuerSha256 = identity.IssuerSha256,
                        SerialNumber = identity.SerialNumber
                    });
                    processRules.Add(new NativeMethods.ProtectedProcessRule
                    {
                        RuleId = nextProcessRuleId++, FolderRuleId = folderRuleId,
                        SignerRuleId = signerRuleId, Access = NativeMethods.PfAccessAll,
                        ImageLengthChars = (uint)imagePath.Length, Image = imagePath
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

            int processSize = Marshal.SizeOf<NativeMethods.ProtectedProcessRule>();
            if (processRules.Count > 0)
            {
                processBuffer = Marshal.AllocHGlobal(processSize * processRules.Count);
                for (int index = 0; index < processRules.Count; index++)
                {
                    Marshal.StructureToPtr(processRules[index],
                        IntPtr.Add(processBuffer, index * processSize), false);
                }
            }

            int signerSize = Marshal.SizeOf<NativeMethods.SignerRule>();
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
                Access = NativeMethods.PfAccessAll,
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
        UiLogger.Error($"네이티브 작업 실패 operation={operation} error={error}");
        char[] buffer = new char[512];
        uint messageResult = NativeMethods.UfFltGetErrorMessage(error, buffer, (uint)buffer.Length);
        string message = messageResult == NativeMethods.ErrorSuccess
            ? new string(buffer).TrimEnd('\0')
            : "오류 메시지를 확인할 수 없습니다.";
        if (messageResult != NativeMethods.ErrorSuccess)
        {
            UiLogger.Warn($"네이티브 오류 메시지 조회 실패 operation={operation} error={error} messageError={messageResult}");
        }
        MessageBox.Show($"{operation} 실패\n오류 코드: {error}\n{message}",
            "RansomUtilFactory", MessageBoxButton.OK, MessageBoxImage.Error);
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

    public ObservableCollection<string> AllowedProcesses { get; } = [];
}
