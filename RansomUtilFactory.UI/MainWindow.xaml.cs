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
        InitializeComponent();
        DataContext = this;
        _eventCallback = ReceiveFileEvent;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        NativeMethods.ValidateAbi();
        uint error = NativeMethods.UfFltInitialize();
        if (error != NativeMethods.ErrorSuccess)
        {
            ShowNativeError("통신 DLL 초기화", error);
            return;
        }
        ConnectDriver(showFailure: false);
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        DisconnectDriver();
        NativeMethods.UfFltShutdown();
    }

    private void Connect_Click(object sender, RoutedEventArgs e)
    {
        DriverOperationResult loadResult = DriverInstaller.LoadFileDriver();
        FileDriverStatusText.Text = loadResult.Message;
        if (!loadResult.Success)
        {
            ShowDriverOperationResult("파일 드라이버 로드", loadResult);
            return;
        }
        ConnectDriver(showFailure: true);
    }

    private void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        DisconnectDriver();
    }

    private void InstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                "파일 드라이버를 설치하고 로드하시겠습니까?\n시험용 VM에서만 실행하십시오.",
                "파일 드라이버 설치", MessageBoxButton.YesNo, MessageBoxImage.Warning) !=
            MessageBoxResult.Yes)
        {
            return;
        }

        DisconnectDriver();
        DriverOperationResult result = DriverInstaller.InstallFileDriver();
        FileDriverStatusText.Text = result.Message;
        if (!result.Success)
        {
            MessageBox.Show(result.Message, "파일 드라이버 설치",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        ConnectDriver(showFailure: true);
        ShowDriverOperationResult("파일 드라이버 설치", result);
    }

    private void UninstallFileDriver_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                "적용된 정책을 초기화하고 파일 드라이버를 제거하시겠습니까?",
                "파일 드라이버 제거", MessageBoxButton.YesNo, MessageBoxImage.Warning) !=
            MessageBoxResult.Yes)
        {
            return;
        }

        if (_connected)
        {
            _ = NativeMethods.UfFltClearPolicy();
        }
        DisconnectDriver();
        DriverOperationResult result = DriverInstaller.UninstallFileDriver();
        FileDriverStatusText.Text = result.Message;
        ShowDriverOperationResult("파일 드라이버 제거", result);
    }

    private static void ShowDriverOperationResult(string title, DriverOperationResult result)
    {
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
            return;
        }
        uint error = NativeMethods.UfFltConnect();
        if (error != NativeMethods.ErrorSuccess && error != NativeMethods.ErrorAlreadyExists)
        {
            SetConnectionState(false);
            if (showFailure)
            {
                ShowNativeError("드라이버 연결", error);
            }
            return;
        }
        _connected = true;
        error = NativeMethods.UfFltStartEventReceiverV2(_eventCallback, IntPtr.Zero);
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
    }

    private void DisconnectDriver()
    {
        if (_receiverStarted)
        {
            NativeMethods.UfFltStopEventReceiver();
            _receiverStarted = false;
        }
        if (_connected)
        {
            NativeMethods.UfFltDisconnect();
            _connected = false;
        }
        SetConnectionState(false);
    }

    private void SetConnectionState(bool connected)
    {
        ConnectionText.Text = connected ? "드라이버 연결됨" : "드라이버 연결 안 됨";
        ConnectionIndicator.Fill = new SolidColorBrush(
            connected ? Color.FromRgb(22, 163, 74) : Color.FromRgb(179, 38, 30));
    }

    private void AddMonitorFolder_Click(object sender, RoutedEventArgs e)
    {
        AddFolder(MonitorFolders);
    }

    private void AddProtectFolder_Click(object sender, RoutedEventArgs e)
    {
        OpenFolderDialog dialog = new()
        {
            Title = "보호 폴더 선택",
            Multiselect = false
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        string path = NormalizeFolderPath(dialog.FolderName);
        if (ProtectFolders.Any(item => string.Equals(item.Path, path,
                StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        ProtectedFolderEntry entry = new(path);
        ProtectFolders.Add(entry);
        ProtectFolderList.SelectedItem = entry;
    }

    private static void AddFolder(ObservableCollection<string> target)
    {
        OpenFolderDialog dialog = new()
        {
            Title = "폴더 선택",
            Multiselect = false
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }
        string path = NormalizeFolderPath(dialog.FolderName);
        if (!target.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            target.Add(path);
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
        }
    }

    private void RemoveProtectFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ProtectFolderList.SelectedItem is ProtectedFolderEntry selected)
        {
            ProtectFolders.Remove(selected);
            AllowedProcessList.ItemsSource = null;
        }
    }

    private void ProtectFolderList_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        AllowedProcessList.ItemsSource =
            (ProtectFolderList.SelectedItem as ProtectedFolderEntry)?.AllowedProcesses;
    }

    private void AddAllowedProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ProtectFolderList.SelectedItem is not ProtectedFolderEntry folder)
        {
            MessageBox.Show("먼저 보호 폴더를 선택하십시오.", "허용 프로그램",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        OpenFileDialog dialog = new()
        {
            Title = "허용할 실행 파일 선택",
            Filter = "실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*",
            Multiselect = false,
            CheckFileExists = true
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        string path = Path.GetFullPath(dialog.FileName);
        if (!folder.AllowedProcesses.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            folder.AllowedProcesses.Add(path);
        }
    }

    private void RemoveAllowedProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ProtectFolderList.SelectedItem is ProtectedFolderEntry folder &&
            AllowedProcessList.SelectedItem is string selected)
        {
            folder.AllowedProcesses.Remove(selected);
        }
    }

    private void ApplyPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (!_connected)
        {
            MessageBox.Show("먼저 드라이버에 연결하십시오.", "정책 적용",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MonitorFolders.Count + ProtectFolders.Count > 64)
        {
            MessageBox.Show("감시 폴더와 보호 폴더는 합계 64개까지 설정할 수 있습니다.",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        HashSet<string> monitored = new(MonitorFolders, StringComparer.OrdinalIgnoreCase);
        ProtectedFolderEntry? duplicate = ProtectFolders.FirstOrDefault(folder =>
            monitored.Contains(folder.Path));
        if (duplicate is not null)
        {
            MessageBox.Show($"같은 폴더를 감시와 보호에 동시에 설정할 수 없습니다.\n{duplicate.Path}",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        uint error = ReplacePolicyV2(out string? validationMessage);
        if (error != NativeMethods.ErrorSuccess)
        {
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
        if (!_connected)
        {
            MessageBox.Show("먼저 드라이버에 연결하십시오.", "정책 초기화",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        uint error = NativeMethods.UfFltClearPolicy();
        if (error != NativeMethods.ErrorSuccess)
        {
            ShowNativeError("정책 초기화", error);
            return;
        }
        PolicyStatusText.Text = "드라이버 정책을 초기화했습니다.";
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
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
            _ = NativeMethods.UfFltSetProcessTrust(ref trust);
        }
        finally
        {
            Marshal.FreeHGlobal(identityBuffer);
        }
    }

    private void ShowNativeError(string operation, uint error)
    {
        char[] buffer = new char[512];
        uint messageResult = NativeMethods.UfFltGetErrorMessage(error, buffer, (uint)buffer.Length);
        string message = messageResult == NativeMethods.ErrorSuccess
            ? new string(buffer).TrimEnd('\0')
            : "오류 메시지를 확인할 수 없습니다.";
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
