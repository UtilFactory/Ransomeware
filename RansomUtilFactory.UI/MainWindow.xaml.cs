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
    private readonly NativeMethods.EventCallback _eventCallback;
    private bool _connected;
    private bool _receiverStarted;

    public ObservableCollection<string> MonitorFolders { get; } = [];
    public ObservableCollection<string> ProtectFolders { get; } = [];
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
        error = NativeMethods.UfFltStartEventReceiver(_eventCallback, IntPtr.Zero);
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
        AddFolder(ProtectFolders);
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
        string path = Path.GetFullPath(dialog.FolderName).TrimEnd(Path.DirectorySeparatorChar);
        if (!target.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            target.Add(path);
        }
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
        if (ProtectFolderList.SelectedItem is string selected)
        {
            ProtectFolders.Remove(selected);
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
        List<(uint Mode, string Path)> rules = [];
        rules.AddRange(MonitorFolders.Select(path => (NativeMethods.UfRuleMonitor, path)));
        rules.AddRange(ProtectFolders.Select(path => (NativeMethods.UfRuleAllowList, path)));
        if (rules.Count > 64)
        {
            MessageBox.Show("감시 폴더와 보호 폴더는 합계 64개까지 설정할 수 있습니다.",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        HashSet<string> monitored = new(MonitorFolders, StringComparer.OrdinalIgnoreCase);
        string? duplicate = ProtectFolders.FirstOrDefault(monitored.Contains);
        if (duplicate is not null)
        {
            MessageBox.Show($"같은 폴더를 감시와 보호에 동시에 설정할 수 없습니다.\n{duplicate}",
                "정책 적용", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        rules = rules.OrderByDescending(rule => rule.Path.Length).ToList();
        uint error = ReplacePolicy(rules);
        if (error != NativeMethods.ErrorSuccess)
        {
            ShowNativeError("정책 적용", error);
            return;
        }
        PolicyStatusText.Text = $"정책 적용됨: 감시 {MonitorFolders.Count}개, 보호 {ProtectFolders.Count}개";
    }

    private static uint ReplacePolicy(IReadOnlyList<(uint Mode, string Path)> rules)
    {
        List<IntPtr> strings = [];
        IntPtr ruleBuffer = IntPtr.Zero;
        try
        {
            int ruleSize = Marshal.SizeOf<NativeMethods.PathInput>();
            if (rules.Count != 0)
            {
                ruleBuffer = Marshal.AllocHGlobal(ruleSize * rules.Count);
                for (int index = 0; index < rules.Count; index++)
                {
                    IntPtr path = Marshal.StringToHGlobalUni(rules[index].Path);
                    strings.Add(path);
                    NativeMethods.PathInput input = new()
                    {
                        Mode = rules[index].Mode,
                        DosPath = path
                    };
                    Marshal.StructureToPtr(input, IntPtr.Add(ruleBuffer, index * ruleSize), false);
                }
            }
            NativeMethods.PolicyInput policy = new()
            {
                PathRuleCount = (uint)rules.Count,
                PathRules = ruleBuffer
            };
            return NativeMethods.UfFltReplacePolicy(ref policy);
        }
        finally
        {
            foreach (IntPtr value in strings)
            {
                Marshal.FreeHGlobal(value);
            }
            if (ruleBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ruleBuffer);
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
        NativeMethods.FileEvent fileEvent = Marshal.PtrToStructure<NativeMethods.FileEvent>(eventPointer);
        FileEventLog log = new(
            DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            fileEvent.Action == NativeMethods.UfEventDenied ? "차단" : "감시",
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
