using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private ProcessNativeMethods.EventCallback? _processEventCallback;
    private bool _processInitialized;
    private bool _processConnected;
    private bool _processReceiverStarted;
    private uint _nextProcessRuleId = 1;

    public ObservableCollection<ProcessRuleEntry> ProcessRules { get; } = [];
    public ObservableCollection<ProcessEventLog> ProcessEventLogs { get; } = [];

    private void InitializeProcessControl()
    {
        try
        {
            ProcessNativeMethods.ValidateAbi();
            uint error = ProcessNativeMethods.UfProcInitialize();
            if (error != ProcessNativeMethods.ErrorSuccess)
            {
                ShowProcessNativeError("프로세스 통신 DLL 초기화", error);
                return;
            }
            _processEventCallback = ReceiveProcessEvent;
            _processInitialized = true;
            ConnectProcessControl(showFailure: false);
            UiLogger.Info($"프로세스 제어 초기화 완료 connected={_processConnected}");
        }
        catch (Exception exception)
        {
            UiLogger.Error("프로세스 제어 초기화 실패", exception);
            ProcessDriverStatusText.Text = $"프로세스 통신 초기화 실패: {exception.Message}";
        }
    }

    private void ShutdownProcessControl()
    {
        if (!_processInitialized)
        {
            return;
        }
        DisconnectProcessControl();
        ProcessNativeMethods.UfProcShutdown();
        _processInitialized = false;
    }

    private void AddProcessPathRule_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog dialog = new()
        {
            Title = "전체 경로로 차단할 실행 파일 선택",
            Filter = "실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true)
        {
            AddProcessRule(ProcessNativeMethods.MatchFullPath, dialog.FileName);
        }
    }

    private void AddProcessNameRule_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog dialog = new()
        {
            Title = "파일 이름으로 차단할 실행 파일 선택",
            Filter = "실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true)
        {
            AddProcessRule(ProcessNativeMethods.MatchImageName,
                Path.GetFileName(dialog.FileName));
        }
    }

    private void AddProcessRule(uint matchMode, string image)
    {
        if (ProcessRules.Any(rule =>
                rule.MatchMode == matchMode &&
                string.Equals(rule.Image, image, StringComparison.OrdinalIgnoreCase)))
        {
            MessageBox.Show("같은 프로세스 차단 규칙이 이미 있습니다.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ProcessRules.Add(new ProcessRuleEntry(_nextProcessRuleId++, matchMode, image));
    }

    private void RemoveProcessRule_Click(object sender, RoutedEventArgs e)
    {
        foreach (ProcessRuleEntry rule in ProcessRuleGrid.SelectedItems
                     .Cast<ProcessRuleEntry>().ToArray())
        {
            ProcessRules.Remove(rule);
        }
    }

    private void InstallProcessDriver_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                "프로세스 커널 드라이버를 설치하고 로드하시겠습니까?\n시험용 VM에서만 실행하십시오.",
                "프로세스 드라이버 설치",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }
        DisconnectProcessControl();
        DriverOperationResult result = DriverInstaller.InstallProcessDriver();
        ProcessDriverStatusText.Text = result.Message;
        if (result.Success)
        {
            ConnectProcessControl(showFailure: true);
        }
        ShowDriverOperationResult("프로세스 드라이버 설치", result);
    }

    private void ConnectProcessDriver_Click(object sender, RoutedEventArgs e)
    {
        DriverOperationResult result = DriverInstaller.LoadProcessDriver();
        ProcessDriverStatusText.Text = result.Message;
        if (!result.Success)
        {
            ShowDriverOperationResult("프로세스 드라이버 로드", result);
            return;
        }
        ConnectProcessControl(showFailure: true);
    }

    private void DisconnectProcessDriver_Click(object sender, RoutedEventArgs e)
    {
        DisconnectProcessControl();
    }

    private void UninstallProcessDriver_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                "적용된 프로세스 정책을 초기화하고 드라이버를 제거하시겠습니까?",
                "프로세스 드라이버 제거",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }
        if (_processConnected)
        {
            _ = ProcessNativeMethods.UfProcClearPolicy();
        }
        DisconnectProcessControl();
        DriverOperationResult result = DriverInstaller.UninstallProcessDriver();
        ProcessDriverStatusText.Text = result.Message;
        ShowDriverOperationResult("프로세스 드라이버 제거", result);
    }

    private void ConnectProcessControl(bool showFailure)
    {
        if (!_processInitialized || _processConnected)
        {
            return;
        }
        uint error = ProcessNativeMethods.UfProcConnect();
        if (error != ProcessNativeMethods.ErrorSuccess &&
            error != ProcessNativeMethods.ErrorAlreadyExists)
        {
            ProcessDriverStatusText.Text = $"프로세스 드라이버 연결 실패: {error}";
            if (showFailure)
            {
                ShowProcessNativeError("프로세스 드라이버 연결", error);
            }
            return;
        }
        _processConnected = true;
        error = ProcessNativeMethods.UfProcStartEventReceiver(
            _processEventCallback!, IntPtr.Zero);
        if (error != ProcessNativeMethods.ErrorSuccess &&
            error != ProcessNativeMethods.ErrorAlreadyExists)
        {
            ProcessNativeMethods.UfProcDisconnect();
            _processConnected = false;
            if (showFailure)
            {
                ShowProcessNativeError("프로세스 이벤트 수신", error);
            }
            return;
        }
        _processReceiverStarted = true;
        ProcessNativeMethods.StateReply state = new();
        error = ProcessNativeMethods.UfProcQueryState(ref state);
        ProcessDriverStatusText.Text = error == ProcessNativeMethods.ErrorSuccess
            ? $"연결됨 · 정책 세대 {state.PolicyGeneration} · 규칙 {state.RuleCount}개"
            : "프로세스 드라이버에 연결되었습니다.";
    }

    private void DisconnectProcessControl()
    {
        if (_processReceiverStarted)
        {
            ProcessNativeMethods.UfProcStopEventReceiver();
            _processReceiverStarted = false;
        }
        if (_processConnected)
        {
            ProcessNativeMethods.UfProcDisconnect();
            _processConnected = false;
        }
        if (ProcessDriverStatusText is not null)
        {
            ProcessDriverStatusText.Text = "프로세스 드라이버 연결이 해제되었습니다.";
        }
    }

    private void ApplyProcessPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (!_processConnected)
        {
            MessageBox.Show("먼저 프로세스 드라이버에 연결하십시오.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (ProcessRules.Count > 32)
        {
            MessageBox.Show("프로세스 차단 규칙은 최대 32개입니다.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        List<IntPtr> strings = [];
        IntPtr rulesBuffer = IntPtr.Zero;
        try
        {
            int ruleSize = Marshal.SizeOf<ProcessNativeMethods.RuleInput>();
            if (ProcessRules.Count != 0)
            {
                rulesBuffer = Marshal.AllocHGlobal(ruleSize * ProcessRules.Count);
                for (int index = 0; index < ProcessRules.Count; ++index)
                {
                    ProcessRuleEntry rule = ProcessRules[index];
                    IntPtr image = Marshal.StringToHGlobalUni(rule.Image);
                    strings.Add(image);
                    ProcessNativeMethods.RuleInput nativeRule = new()
                    {
                        RuleId = rule.RuleId,
                        MatchMode = rule.MatchMode,
                        Image = image
                    };
                    Marshal.StructureToPtr(nativeRule,
                        IntPtr.Add(rulesBuffer, index * ruleSize), false);
                }
            }
            ProcessNativeMethods.PolicyInput policy = new()
            {
                RuleCount = (uint)ProcessRules.Count,
                Rules = rulesBuffer
            };
            uint error = ProcessNativeMethods.UfProcReplacePolicy(ref policy);
            if (error != ProcessNativeMethods.ErrorSuccess)
            {
                ShowProcessNativeError("프로세스 정책 적용", error);
                return;
            }
            ProcessPolicyStatusText.Text = $"실행 차단 정책 적용됨: {ProcessRules.Count}개";
        }
        finally
        {
            foreach (IntPtr value in strings)
            {
                Marshal.FreeHGlobal(value);
            }
            if (rulesBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(rulesBuffer);
            }
        }
    }

    private void ClearProcessPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (!_processConnected)
        {
            MessageBox.Show("먼저 프로세스 드라이버에 연결하십시오.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        uint error = ProcessNativeMethods.UfProcClearPolicy();
        if (error != ProcessNativeMethods.ErrorSuccess)
        {
            ShowProcessNativeError("프로세스 정책 초기화", error);
            return;
        }
        ProcessPolicyStatusText.Text = "프로세스 차단 정책을 초기화했습니다.";
    }

    private void ClearProcessLog_Click(object sender, RoutedEventArgs e)
    {
        ProcessEventLogs.Clear();
    }

    private void ReceiveProcessEvent(IntPtr eventPointer, IntPtr context)
    {
        ProcessNativeMethods.ProcessEvent processEvent =
            Marshal.PtrToStructure<ProcessNativeMethods.ProcessEvent>(eventPointer);
        DateTime time = DateTime.FromFileTimeUtc(unchecked((long)processEvent.SystemTime100ns))
            .ToLocalTime();
        ProcessEventLog log = new(
            time.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            processEvent.Type switch
            {
                ProcessNativeMethods.EventCreate => "실행",
                ProcessNativeMethods.EventExit => "종료",
                ProcessNativeMethods.EventAccess => "접근",
                _ => "기타"
            },
            processEvent.Action == ProcessNativeMethods.ActionBlocked ? "차단" : "감시",
            processEvent.ProcessId,
            processEvent.RequesterProcessId,
            processEvent.TargetProcessId,
            $"0x{processEvent.DesiredAccess:X8}",
            processEvent.Image ?? string.Empty);
        Dispatcher.BeginInvoke(() =>
        {
            ProcessEventLogs.Insert(0, log);
            while (ProcessEventLogs.Count > MaxLogCount)
            {
                ProcessEventLogs.RemoveAt(ProcessEventLogs.Count - 1);
            }
        });
    }

    private static void ShowProcessNativeError(string operation, uint error)
    {
        char[] buffer = new char[512];
        uint messageError = ProcessNativeMethods.UfProcGetErrorMessage(
            error, buffer, (uint)buffer.Length);
        string message = messageError == ProcessNativeMethods.ErrorSuccess
            ? new string(buffer).TrimEnd('\0')
            : "오류 메시지를 확인할 수 없습니다.";
        MessageBox.Show($"{operation} 실패\n오류 코드: {error}\n{message}",
            "RansomUtilFactory", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

public sealed record ProcessRuleEntry(uint RuleId, uint MatchMode, string Image)
{
    public string MatchModeText => MatchMode == ProcessNativeMethods.MatchFullPath
        ? "전체 경로"
        : "파일 이름";
}

public sealed record ProcessEventLog(
    string Time,
    string Type,
    string Action,
    uint ProcessId,
    uint RequesterProcessId,
    uint TargetProcessId,
    string DesiredAccess,
    string Image);
