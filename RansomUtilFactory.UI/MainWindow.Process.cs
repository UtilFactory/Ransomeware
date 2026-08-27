using Microsoft.Win32;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private ProcessNativeMethods.EventCallback? _processEventCallback;
    private bool _processInitialized;
    private bool _processConnected;
    private bool _processReceiverStarted;
    private uint _nextProcessRuleId = 1;
    private const int MaxPendingProcessEventLogs = 4000;
    private const int ProcessEventBatchSize = 200;
    private readonly ConcurrentQueue<ProcessEventLog> _pendingProcessEventLogs = new();
    private int _processLogDrainScheduled;
    private int _processPolicyApplyRunning;

    public ObservableCollection<ProcessRuleEntry> ProcessRules { get; } = [];
    public ObservableCollection<ProcessEventLog> ProcessEventLogs { get; } = [];

    private void InitializeProcessControl()
    {
        if (!EnsureProcessCommunicationInitialized(showFailure: false))
        {
            return;
        }
        ConnectProcessControl(showFailure: false);
        UiLogger.Info($"프로세스 제어 초기화 완료 connected={_processConnected}");
    }

    private bool EnsureProcessCommunicationInitialized(bool showFailure)
    {
        if (_processInitialized)
        {
            return true;
        }

        try
        {
            UiLogger.Info("프로세스 통신 DLL 초기화 시작");
            ProcessNativeMethods.ValidateAbi();
            uint error = ProcessNativeMethods.UfProcInitialize();
            if (error != ProcessNativeMethods.ErrorSuccess)
            {
                UiLogger.Error($"프로세스 통신 DLL 초기화 실패 GetLastError={error} message={GetProcessNativeErrorMessage(error)}");
                SetProcessConnectionState(false, $"GetLastError={error}");
                if (showFailure)
                {
                    ShowProcessNativeError("프로세스 통신 DLL 초기화", error);
                }
                return false;
            }

            _processEventCallback = ReceiveProcessEvent;
            _processInitialized = true;
            UiLogger.Info("프로세스 통신 DLL 초기화 완료");
            return true;
        }
        catch (Exception exception)
        {
            UiLogger.Error("프로세스 제어 초기화 실패", exception);
            ProcessDriverStatusText.Text = $"프로세스 통신 초기화 실패: {exception.Message}";
            SetProcessConnectionState(false, "초기화 예외");
            if (showFailure)
            {
                MessageBox.Show(exception.Message, "프로세스 통신 초기화",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return false;
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
            Title = "전체 경로로 허용할 실행 파일 선택",
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
            Title = "파일 이름으로 허용할 실행 파일 선택",
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
        string processName = matchMode == ProcessNativeMethods.MatchFullPath
            ? Path.GetFileName(image)
            : image;
        ProcessRuleEntry? duplicate = ProcessRules.FirstOrDefault(rule =>
            string.Equals(
                rule.MatchMode == ProcessNativeMethods.MatchFullPath
                    ? Path.GetFileName(rule.Image)
                    : rule.Image,
                processName,
                StringComparison.OrdinalIgnoreCase));
        if (duplicate is not null)
        {
            ProcessRules.Remove(duplicate);
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
        if (!EnsureProcessCommunicationInitialized(showFailure))
        {
            return;
        }
        if (_processConnected)
        {
            UiLogger.Debug("프로세스 제어 필터 연결 요청 무시: 이미 연결됨");
            ProcessDriverStatusText.Text = "프로세스 제어 필터 연결됨";
            SetProcessConnectionState(true);
            return;
        }
        uint error = ProcessNativeMethods.UfProcConnect();
        if (error != ProcessNativeMethods.ErrorSuccess &&
            error != ProcessNativeMethods.ErrorAlreadyExists)
        {
            string message = GetProcessNativeErrorMessage(error);
            UiLogger.Warn($"프로세스 제어 필터 통신 연결 실패 GetLastError={error} message={message}");
            ProcessDriverStatusText.Text = $"프로세스 제어 필터 연결 실패 (GetLastError={error}): {message}";
            SetProcessConnectionState(false, $"GetLastError={error}");
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
            UiLogger.Warn($"프로세스 이벤트 수신 시작 실패 GetLastError={error} message={GetProcessNativeErrorMessage(error)}");
            if (showFailure)
            {
                ShowProcessNativeError("프로세스 이벤트 수신", error);
            }
            SetProcessConnectionState(false, $"GetLastError={error}");
            return;
        }
        _processReceiverStarted = true;
        ProcessNativeMethods.StateReply state = new();
        error = ProcessNativeMethods.UfProcQueryState(ref state);
        if (error == ProcessNativeMethods.ErrorSuccess)
        {
            bool diagnosticDriver = (state.Reserved & 0x7f000000u) == 0x55000000u;
            uint diagnosticVersion = (state.Reserved >> 8) & 0xffu;
            uint openHandleCount = (state.Reserved >> 16) & 0xffu;
            string detail = $"정책 세대 {state.PolicyGeneration} · 정책 {state.PolicyCount}개" +
                (diagnosticDriver
                    ? $" · 진단 드라이버 v{diagnosticVersion} · 핸들 {openHandleCount}개"
                    : " · 구버전 드라이버");
            ProcessDriverStatusText.Text = $"프로세스 제어 필터 연결됨 · {detail}";
            SetProcessConnectionState(true, detail);
        }
        else
        {
            string message = GetProcessNativeErrorMessage(error);
            UiLogger.Warn($"프로세스 상태 조회 실패 GetLastError={error} message={message}");
            ProcessDriverStatusText.Text = $"프로세스 제어 필터 연결됨 · 상태 조회 실패 (GetLastError={error})";
            SetProcessConnectionState(true, $"상태 조회 실패 GetLastError={error}");
        }
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
            ProcessDriverStatusText.Text = "프로세스 제어 필터 연결이 해제되었습니다.";
            SetProcessConnectionState(false);
        }
    }

    private async void ApplyProcessPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (!_processConnected)
        {
            MessageBox.Show("먼저 프로세스 드라이버에 연결하십시오.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (Interlocked.Exchange(ref _processPolicyApplyRunning, 1) != 0)
        {
            return;
        }
        if (ProcessRules.Count > 32)
        {
            Interlocked.Exchange(ref _processPolicyApplyRunning, 0);
            MessageBox.Show("프로세스 정책은 최대 32개입니다.", "프로세스 정책",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ApplyProcessPolicyButton.IsEnabled = false;
        ProcessPolicyStatusText.Text = "프로세스 정책 적용 중...";
        List<IntPtr> strings = [];
        IntPtr rulesBuffer = IntPtr.Zero;
        try
        {
            int ruleSize = Marshal.SizeOf<ProcessNativeMethods.RuleInputV2>();
            if (ProcessRules.Count != 0)
            {
                rulesBuffer = Marshal.AllocHGlobal(ruleSize * ProcessRules.Count);
                for (int index = 0; index < ProcessRules.Count; ++index)
                {
                    ProcessRuleEntry rule = ProcessRules[index];
                    string processName = rule.MatchMode == ProcessNativeMethods.MatchFullPath
                        ? Path.GetFileName(rule.Image)
                        : rule.Image;
                    IntPtr processNamePointer = Marshal.StringToHGlobalUni(processName);
                    strings.Add(processNamePointer);
                    IntPtr processPathPointer = IntPtr.Zero;
                    if (rule.MatchMode == ProcessNativeMethods.MatchFullPath)
                    {
                        processPathPointer = Marshal.StringToHGlobalUni(rule.Image);
                        strings.Add(processPathPointer);
                    }
                    ProcessNativeMethods.RuleInputV2 nativeRule = new()
                    {
                        RuleId = rule.RuleId,
                        ProcessName = processNamePointer,
                        ProcessPath = processPathPointer,
                        IsSign = rule.IsSign ? (ushort)1 : (ushort)0,
                        IsCmpFullPath = rule.MatchMode == ProcessNativeMethods.MatchFullPath
                            ? (ushort)1
                            : (ushort)0
                    };
                    Marshal.StructureToPtr(nativeRule,
                        IntPtr.Add(rulesBuffer, index * ruleSize), false);
                    UiLogger.Info($"프로세스 정책 규칙 변환 index={index} ruleId={nativeRule.RuleId} " +
                        $"name={processName} fullPath={nativeRule.IsCmpFullPath != 0} " +
                        $"sign={nativeRule.IsSign != 0} path={rule.Image}");
                }
            }
            ProcessNativeMethods.PolicyInputV2 policy = new()
            {
                PolicyCount = (uint)ProcessRules.Count,
                Policies = rulesBuffer
            };
            UiLogger.Info($"프로세스 정책 네이티브 호출 시작 count={policy.PolicyCount}");
            Task<uint> applyTask = Task.Run(() =>
                ProcessNativeMethods.UfProcReplacePolicyV2(ref policy));
            bool diagnosticQueryTimedOut = false;
            while (!applyTask.IsCompleted)
            {
                await Task.Delay(500);
                if (!applyTask.IsCompleted && !diagnosticQueryTimedOut)
                {
                    uint nativeStage = ProcessNativeMethods.UfProcGetPolicyCallStage();
                    UiLogger.Debug($"프로세스 정책 적용 진단 조회 시작 nativeStage={nativeStage}");
                    ProcessNativeMethods.StateReply diagnosticState = new();
                    Task<uint> diagnosticTask = Task.Run(() =>
                        ProcessNativeMethods.UfProcQueryState(ref diagnosticState));
                    Task completedTask = await Task.WhenAny(
                        diagnosticTask,
                        Task.Delay(TimeSpan.FromSeconds(1)));
                    if (completedTask != diagnosticTask)
                    {
                        diagnosticQueryTimedOut = true;
                        UiLogger.Warn($"프로세스 정책 적용 진단 상태 조회 시간 초과 nativeStage={nativeStage}");
                        ProcessPolicyStatusText.Text =
                            $"프로세스 정책 적용 중... (상태 조회 응답 없음, 사용자 단계 {nativeStage})";
                        continue;
                    }
                    uint diagnosticError = await diagnosticTask;
                    UiLogger.Debug($"프로세스 정책 적용 진단 조회 완료 error={diagnosticError} " +
                        $"stage={diagnosticState.Reserved} generation={diagnosticState.PolicyGeneration}");
                    if (diagnosticError == ProcessNativeMethods.ErrorSuccess)
                    {
                        bool diagnosticDriver =
                            (diagnosticState.Reserved & 0x7f000000u) == 0x55000000u;
                        uint diagnosticVersion = (diagnosticState.Reserved >> 8) & 0xffu;
                        uint openHandleCount = (diagnosticState.Reserved >> 16) & 0xffu;
                        uint stage = diagnosticState.Reserved & 0xffu;
                        UiLogger.Info($"프로세스 정책 적용 진단 stage={diagnosticState.Reserved} " +
                            $"generation={diagnosticState.PolicyGeneration} diagnostic={diagnosticDriver} " +
                            $"version={diagnosticVersion} handles={openHandleCount}");
                        ProcessPolicyStatusText.Text =
                            $"프로세스 정책 적용 중... (커널 단계 {stage}, " +
                            $"{(diagnosticDriver ? "진단 드라이버" : "구버전 드라이버")})";
                    }
                    else
                    {
                        UiLogger.Warn($"프로세스 정책 적용 진단 상태 조회 실패 GetLastError={diagnosticError}");
                        ProcessPolicyStatusText.Text =
                            $"프로세스 정책 적용 중... (상태 조회 실패 GetLastError={diagnosticError})";
                    }
                }
            }
            uint error = await applyTask;
            UiLogger.Info($"프로세스 정책 네이티브 호출 완료 GetLastError={error}");
            if (error != ProcessNativeMethods.ErrorSuccess)
            {
                ShowProcessNativeError("프로세스 정책 적용", error);
                return;
            }
            ProcessPolicyStatusText.Text = $"프로세스 실행 허용 정책 적용됨: {ProcessRules.Count}개";
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
            ApplyProcessPolicyButton.IsEnabled = true;
            Interlocked.Exchange(ref _processPolicyApplyRunning, 0);
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
        ProcessPolicyStatusText.Text = "프로세스 실행 허용 정책을 초기화했습니다.";
    }

    private void ClearProcessLog_Click(object sender, RoutedEventArgs e)
    {
        while (_pendingProcessEventLogs.TryDequeue(out _))
        {
        }
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
        _pendingProcessEventLogs.Enqueue(log);
        while (_pendingProcessEventLogs.Count > MaxPendingProcessEventLogs &&
               _pendingProcessEventLogs.TryDequeue(out _))
        {
        }
        ScheduleProcessLogDrain();
    }

    private void ScheduleProcessLogDrain()
    {
        if (Interlocked.Exchange(ref _processLogDrainScheduled, 1) != 0)
        {
            return;
        }
        try
        {
            Dispatcher.BeginInvoke(
                DispatcherPriority.Background,
                new Action(DrainProcessEventLogs));
        }
        catch (InvalidOperationException)
        {
            Interlocked.Exchange(ref _processLogDrainScheduled, 0);
        }
    }

    private void DrainProcessEventLogs()
    {
        try
        {
            int count = 0;
            while (count < ProcessEventBatchSize &&
                   _pendingProcessEventLogs.TryDequeue(out ProcessEventLog? log))
            {
                ProcessEventLogs.Insert(0, log);
                ++count;
            }
            while (ProcessEventLogs.Count > MaxLogCount)
            {
                ProcessEventLogs.RemoveAt(ProcessEventLogs.Count - 1);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _processLogDrainScheduled, 0);
        }

        if (!_pendingProcessEventLogs.IsEmpty)
        {
            ScheduleProcessLogDrain();
        }
    }

    private static void ShowProcessNativeError(string operation, uint error)
    {
        string message = GetProcessNativeErrorMessage(error);
        UiLogger.Error($"프로세스 네이티브 작업 실패 operation={operation} GetLastError={error} message={message}");
        MessageBox.Show($"{operation} 실패\nGetLastError: {error}\n{message}",
            "RansomUtilFactory", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static string GetProcessNativeErrorMessage(uint error)
    {
        char[] buffer = new char[512];
        uint messageError = ProcessNativeMethods.UfProcGetErrorMessage(
            error, buffer, (uint)buffer.Length);
        return messageError == ProcessNativeMethods.ErrorSuccess
            ? new string(buffer).TrimEnd('\0')
            : $"오류 메시지 조회 실패(GetLastError={messageError})";
    }
}

public sealed class ProcessRuleEntry(uint ruleId, uint matchMode, string image)
{
    public uint RuleId { get; } = ruleId;
    public uint MatchMode { get; } = matchMode;
    public string Image { get; } = image;
    public bool IsSign { get; set; }
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
