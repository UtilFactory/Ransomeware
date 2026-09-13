using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private readonly ObservableCollection<BootDeviceEntry> _bootDevices = [];
    private readonly ObservableCollection<BootDiskCandidate> _bootCandidates = [];
    private readonly ObservableCollection<BootRangeEntry> _bootRanges = [];
    private readonly CancellationTokenSource _bootPollCancellation = new();
    private bool _bootAbiValid;
    private bool _bootOperationRunning;
    private bool _bootRefreshing;
    private bool _bootStateFresh;
    private bool _bootUpdatingDevices;
    private bool _bootShuttingDown;
    private bool _bootDeviceWasSelected;
    private ulong? _bootPendingStartDeviceId;
    private string _bootLastConnectionError = string.Empty;

    public ObservableCollection<BootEventLog> BootEventLogs { get; } = [];

    private void InitializeBootControl()
    {
        if (_bootAbiValid || _bootShuttingDown)
        {
            return;
        }
        BootDeviceList.ItemsSource = _bootDevices;
        BootCandidateList.ItemsSource = _bootCandidates;
        BootRangeGrid.ItemsSource = _bootRanges;
        try
        {
            BootNativeMethods.ValidateAbi();
            _bootAbiValid = true;
            UiLogger.Info("부트 통신 ABI 크기·오프셋 검증 완료");
            _ = PollBootControlAsync(_bootPollCancellation.Token);
        }
        catch (Exception exception)
        {
            SetBootConnectionFailure(exception.Message);
            UiLogger.Error("부트 통신 초기화 실패", exception);
        }
        UpdateBootButtons();
    }

    private void ShutdownBootControl()
    {
        _bootShuttingDown = true;
        _bootPollCancellation.Cancel();
        // 창 종료는 조회만 중단한다. 커널의 활성 보호는 명시적 정지 요청까지 유지한다.
        UiLogger.Info("부트 상태·이벤트 조회 종료: 기존 커널 보호 상태 유지");
    }

    private async Task PollBootControlAsync(CancellationToken cancellationToken)
    {
        try
        {
            bool refreshCandidates = true;
            while (!cancellationToken.IsCancellationRequested)
            {
                await RefreshBootAsync(refreshCandidates);
                refreshCandidates = false;
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            UiLogger.Error("부트 상태·이벤트 조회 루프 종료", exception);
            if (!_bootShuttingDown)
            {
                SetBootConnectionFailure(exception.Message);
            }
        }
    }

    private async Task RefreshBootAsync(bool refreshCandidates)
    {
        if (!_bootAbiValid || _bootShuttingDown || _bootRefreshing || _bootOperationRunning)
        {
            return;
        }
        _bootRefreshing = true;
        UpdateBootButtons();
        try
        {
            if (refreshCandidates)
            {
                await RefreshBootCandidatesAsync();
            }
            if (_bootShuttingDown)
            {
                return;
            }
            BootQueryResult reply = await Task.Run(QueryBootControl);
            if (_bootShuttingDown)
            {
                return;
            }
            if (reply.QueryError != 0)
            {
                SetBootConnectionFailure(FormatBootError(reply.QueryError));
                return;
            }
            BootNativeMethods.ValidateDevices(reply.Devices);
            _bootStateFresh = true;
            _bootLastConnectionError = string.Empty;
            BootDriverConnectionIndicator.Fill = Brushes.SeaGreen;
            BootDriverConnectionText.Text = $"부트 필터: 통신 정상 · 부착 {reply.Devices.Count}개";
            UpdateBootDevices(reply.Devices);
            if (_bootPendingStartDeviceId is ulong pendingId)
            {
                BootDeviceEntry? pendingDevice = _bootDevices.FirstOrDefault(device => device.Info.DeviceId == pendingId);
                if (pendingDevice is null || pendingDevice.Info.State != BootNativeMethods.Scanning)
                {
                    BootCommandStatusText.Text = pendingDevice is null
                        ? "시작 요청 대상 장치가 제거되었습니다. 다시 부착한 장치는 별도로 선택하십시오."
                        : $"시작 요청 이후 확인: 디스크 {pendingDevice.Info.DiskNumber} · {FormatBootState(pendingDevice.Info.State)} · NTSTATUS=0x{pendingDevice.Info.LastStatus:X8}";
                    _bootPendingStartDeviceId = null;
                }
            }
            if (reply.EventError == 0)
            {
                BootNativeMethods.ValidateEvents(reply.Events);
                AppendBootEvents(reply.Events, reply.ResolvedPaths);
            }
            else
            {
                BootEventStatusText.Text = $"이벤트 조회 실패: {FormatBootError(reply.EventError)}";
                UiLogger.Warn($"부트 이벤트 조회 실패 GetLastError={reply.EventError}");
            }
        }
        catch (Exception exception)
        {
            if (!_bootShuttingDown)
            {
                SetBootConnectionFailure(exception.Message);
            }
        }
        finally
        {
            _bootRefreshing = false;
            if (!_bootShuttingDown)
            {
                UpdateBootButtons();
            }
        }
    }

    private static BootQueryResult QueryBootControl()
    {
        BootNativeMethods.DeviceList devices = BootNativeMethods.CreateDeviceList();
        BootNativeMethods.EventBatch events = BootNativeMethods.CreateEventBatch();
        uint queryError = BootNativeMethods.UfBootQueryDevices(ref devices);
        uint eventError = queryError == 0 ? BootNativeMethods.UfBootReadEvents(ref events) : queryError;
        Dictionary<ulong, string> resolvedPaths = [];
        if (eventError == 0)
        {
            BootNativeMethods.ValidateEvents(events);
            Dictionary<(ulong Pid, ulong Created), string?> processPaths = [];
            for (int index = 0; index < events.Count; index++)
            {
                BootNativeMethods.BootEvent entry = events.Events[index];
                if (entry.PathStatus == 0 && entry.PathLength != 0)
                {
                    continue;
                }
                (ulong, ulong) key = (entry.ProcessId, entry.ProcessCreated);
                if (!processPaths.TryGetValue(key, out string? path))
                {
                    path = BootNativeMethods.TryGetMatchingProcessPath(entry.ProcessId, entry.ProcessCreated);
                    processPaths[key] = path;
                }
                if (path is not null)
                {
                    resolvedPaths[entry.Sequence] = path;
                }
            }
        }
        return new(queryError, eventError, devices, events, resolvedPaths);
    }

    private async Task RefreshBootCandidatesAsync()
    {
        try
        {
            string? selectedId = (BootCandidateList.SelectedItem as BootDiskCandidate)?.InstanceId;
            IReadOnlyList<BootDiskCandidate> candidates = await Task.Run(BootDriverInstaller.ListCandidates);
            if (_bootShuttingDown)
            {
                return;
            }
            _bootCandidates.Clear();
            foreach (BootDiskCandidate candidate in candidates)
            {
                _bootCandidates.Add(candidate);
            }
            BootCandidateList.SelectedItem = _bootCandidates.FirstOrDefault(candidate =>
                string.Equals(candidate.InstanceId, selectedId, StringComparison.OrdinalIgnoreCase));
            if (selectedId is null && _bootCandidates.Count != 0)
            {
                BootCandidateList.SelectedIndex = 0;
            }
            if (candidates.Count == 0)
            {
                BootInstallStatusText.Text = "지원 가능한 전용 데이터 VHDX를 찾지 못했습니다. VM에 시험 디스크를 연결한 뒤 새로 고침하십시오.";
            }
        }
        catch (Exception exception)
        {
            if (!_bootShuttingDown)
            {
                BootInstallStatusText.Text = $"시험 디스크 목록 조회 실패: {exception.Message}";
                UiLogger.Error("부트 시험 디스크 후보 조회 실패", exception);
            }
        }
    }

    private void UpdateBootDevices(BootNativeMethods.DeviceList list)
    {
        ulong? selectedId = (BootDeviceList.SelectedItem as BootDeviceEntry)?.Info.DeviceId;
        _bootUpdatingDevices = true;
        try
        {
            _bootDevices.Clear();
            for (int index = 0; index < list.Count; index++)
            {
                _bootDevices.Add(new(list.Devices[index]));
            }
            BootDeviceList.SelectedItem = _bootDevices.FirstOrDefault(device => device.Info.DeviceId == selectedId);
            if (selectedId is null && !_bootDeviceWasSelected && _bootDevices.Count != 0)
            {
                BootDeviceList.SelectedIndex = 0;
                _bootDeviceWasSelected = true;
            }
        }
        finally
        {
            _bootUpdatingDevices = false;
        }
        ShowSelectedBootDevice();
    }

    private void SetBootConnectionFailure(string message)
    {
        _bootStateFresh = false;
        BootDriverConnectionIndicator.Fill = Brushes.Firebrick;
        BootDriverConnectionText.Text = "부트 필터: 상태 확인 불가";
        BootProtectionStatusText.Text = $"보호 상태 확인 불가 · {message}";
        BootProtectionStatusText.Foreground = Brushes.DarkOrange;
        BootEventStatusText.Text = "이벤트 조회 대기 · 마지막 표시 이후의 보호 상태는 확인되지 않았습니다.";
        if (!string.Equals(_bootLastConnectionError, message, StringComparison.Ordinal))
        {
            UiLogger.Warn($"부트 드라이버 상태 확인 실패: {message}");
            _bootLastConnectionError = message;
        }
        UpdateBootButtons();
    }

    private void ShowSelectedBootDevice()
    {
        if (_bootUpdatingDevices || BootProtectionStatusText is null)
        {
            return;
        }
        _bootRanges.Clear();
        if (!_bootStateFresh)
        {
            UpdateBootButtons();
            return;
        }
        if (BootDeviceList.SelectedItem is not BootDeviceEntry device)
        {
            BootProtectionStatusText.Text = _bootDevices.Count == 0
                ? "부착된 디스크가 없습니다. 위 설치·필터 등록을 펼쳐 등록한 뒤 VHDX 다시 연결 또는 VM 재부팅 후 새로 고침하십시오."
                : "보호 상태를 확인할 디스크를 선택하십시오.";
            BootProtectionStatusText.Foreground = Brushes.DimGray;
            UpdateBootButtons();
            return;
        }
        BootNativeMethods.DeviceInfo info = device.Info;
        for (int index = 0; index < info.RangeCount; index++)
        {
            BootNativeMethods.Range range = info.Ranges[index];
            string end = range.Length <= ulong.MaxValue - range.Offset
                ? (range.Offset + range.Length).ToString("N0")
                : "잘못된 범위";
            _bootRanges.Add(new(FormatBootKind(range.Kind), range.Offset.ToString("N0"), range.Length.ToString("N0"), end));
        }
        BootProtectionStatusText.Text = $"디스크 {info.DiskNumber}: {FormatBootState(info.State)} · 보호 범위 {info.RangeCount}개 · 차단 {info.BlockedWrites:N0}회 · 정책 세대 {info.PolicyGeneration} · NTSTATUS=0x{info.LastStatus:X8}";
        BootProtectionStatusText.Foreground = info.State == BootNativeMethods.Active
            ? Brushes.SeaGreen
            : info.State is BootNativeMethods.Failed or BootNativeMethods.Unsupported ? Brushes.Firebrick : Brushes.DarkSlateGray;
        UpdateBootButtons();
    }

    private void UpdateBootButtons()
    {
        if (StartBootProtectionButton is null)
        {
            return;
        }
        bool available = _bootAbiValid && !_bootOperationRunning && !_bootRefreshing && !_bootShuttingDown;
        InstallBootDriverButton.IsEnabled = available;
        RefreshBootButton.IsEnabled = available;
        BootCandidateList.IsEnabled = available;
        AttachBootFilterButton.IsEnabled = available && BootCandidateList.SelectedItem is BootDiskCandidate;
        DetachBootFilterButton.IsEnabled = available && BootCandidateList.SelectedItem is BootDiskCandidate;
        BootDeviceList.IsEnabled = available;
        BootDeviceEntry? selected = BootDeviceList.SelectedItem as BootDeviceEntry;
        bool ready = available && _bootStateFresh && selected is not null;
        uint state = selected?.Info.State ?? BootNativeMethods.Removed;
        uint flags = selected?.Info.Flags ?? 0;
        StartBootProtectionButton.IsEnabled = ready &&
            (flags & (BootNativeMethods.FlagLabDisk | BootNativeMethods.FlagReady)) ==
            (BootNativeMethods.FlagLabDisk | BootNativeMethods.FlagReady) &&
            state is BootNativeMethods.Stopped or BootNativeMethods.Failed;
        StopBootProtectionButton.IsEnabled = ready && state is BootNativeMethods.Active or BootNativeMethods.Scanning;
    }

    private async void RefreshBoot_Click(object sender, RoutedEventArgs e) => await RefreshBootAsync(true);

    private void BootDeviceList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (BootDeviceList.SelectedItem is BootDeviceEntry)
        {
            _bootDeviceWasSelected = true;
        }
        ShowSelectedBootDevice();
    }

    private void BootCandidateList_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateBootButtons();

    private async void StartBootProtection_Click(object sender, RoutedEventArgs e) => await SetBootProtectionAsync(true);

    private async void StopBootProtection_Click(object sender, RoutedEventArgs e) => await SetBootProtectionAsync(false);

    private async Task SetBootProtectionAsync(bool enabled)
    {
        if (_bootOperationRunning || _bootRefreshing || !_bootStateFresh || _bootShuttingDown ||
            BootDeviceList.SelectedItem is not BootDeviceEntry selected)
        {
            return;
        }
        _bootOperationRunning = true;
        _bootPendingStartDeviceId = null;
        UpdateBootButtons();
        string operation = enabled ? "부트 영역 방어 시작" : "부트 영역 방어 정지";
        BootCommandStatusText.Text = $"{operation} 요청 중…";
        BootNativeMethods.SetRequest request = new()
        {
            Version = BootNativeMethods.Version,
            Size = (uint)Marshal.SizeOf<BootNativeMethods.SetRequest>(),
            DeviceId = selected.Info.DeviceId,
            ExpectedGeneration = selected.Info.PolicyGeneration,
            Enabled = enabled ? 1u : 0u
        };
        UiLogger.Info($"{operation} 요청 deviceId={request.DeviceId} generation={request.ExpectedGeneration}");
        try
        {
            BootSetResult result = await Task.Run(() =>
            {
                BootNativeMethods.DeviceInfo info = BootNativeMethods.CreateDeviceInfo();
                uint error = BootNativeMethods.UfBootSetProtection(in request, ref info);
                return new BootSetResult(error, info);
            });
            if (_bootShuttingDown)
            {
                return;
            }
            if (result.Error != 0)
            {
                BootCommandStatusText.Text = $"{operation} 실패: {FormatBootError(result.Error)} · 현재 상태를 다시 조회합니다.";
                SetBootConnectionFailure(FormatBootError(result.Error));
                UiLogger.Error($"{operation} 실패 GetLastError={result.Error}");
            }
            else
            {
                BootNativeMethods.ValidateDevice(result.Device);
                if (result.Device.DeviceId != request.DeviceId)
                {
                    throw new InvalidOperationException("부트 정책 응답의 대상 디스크가 요청과 다릅니다.");
                }
                int index = _bootDevices.IndexOf(selected);
                if (index >= 0)
                {
                    _bootDevices[index] = new(result.Device);
                    BootDeviceList.SelectedItem = _bootDevices[index];
                }
                _bootStateFresh = true;
                BootCommandStatusText.Text = result.Device.State == BootNativeMethods.Scanning
                    ? "시작 요청 접수 · 디스크 배치를 검사하고 있습니다. 방어 중 상태로 바뀌는지 확인하십시오."
                    : $"{operation} 응답: {FormatBootState(result.Device.State)}";
                if (enabled && result.Device.State == BootNativeMethods.Scanning)
                {
                    _bootPendingStartDeviceId = request.DeviceId;
                }
                ShowSelectedBootDevice();
                UiLogger.Info($"{operation} 응답 deviceId={result.Device.DeviceId} state={result.Device.State} generation={result.Device.PolicyGeneration} NTSTATUS=0x{result.Device.LastStatus:X8}");
            }
        }
        catch (Exception exception)
        {
            UiLogger.Error($"{operation} 예외", exception);
            if (!_bootShuttingDown)
            {
                BootCommandStatusText.Text = $"{operation} 실패: {exception.Message}";
                SetBootConnectionFailure(exception.Message);
            }
        }
        finally
        {
            _bootOperationRunning = false;
            if (!_bootShuttingDown)
            {
                UpdateBootButtons();
            }
        }
        await RefreshBootAsync(false);
    }

    private async void InstallBootDriver_Click(object sender, RoutedEventArgs e) =>
        await RunBootInstallOperationAsync("부트 드라이버 패키지 설치", BootDriverInstaller.InstallPackage);

    private async void AttachBootFilter_Click(object sender, RoutedEventArgs e)
    {
        if (BootCandidateList.SelectedItem is BootDiskCandidate candidate)
        {
            await RunBootInstallOperationAsync("시험 디스크 필터 등록", () => BootDriverInstaller.AttachFilter(candidate));
        }
    }

    private async void DetachBootFilter_Click(object sender, RoutedEventArgs e)
    {
        if (BootCandidateList.SelectedItem is BootDiskCandidate candidate)
        {
            await RunBootInstallOperationAsync("시험 디스크 필터 등록 해제", () => BootDriverInstaller.DetachFilter(candidate));
        }
    }

    private async Task RunBootInstallOperationAsync(string operation, Func<DriverOperationResult> action)
    {
        if (_bootOperationRunning || _bootRefreshing || _bootShuttingDown)
        {
            return;
        }
        _bootOperationRunning = true;
        UpdateBootButtons();
        BootInstallStatusText.Text = $"{operation} 처리 중…";
        UiLogger.Info($"{operation} 시작");
        try
        {
            DriverOperationResult result = await Task.Run(action);
            if (_bootShuttingDown)
            {
                return;
            }
            string errorText = result.LastError.HasValue ? $" · {FormatBootError(unchecked((uint)result.LastError.Value))}" : string.Empty;
            BootInstallStatusText.Text = result.Message + errorText +
                (result.RebootRequired ? " · VHDX 다시 연결 또는 VM 재부팅이 필요합니다." : string.Empty);
            UiLogger.Info($"{operation} 완료 success={result.Success} rebootRequired={result.RebootRequired} GetLastError={result.LastError?.ToString() ?? "없음"} message={result.Message}");
        }
        catch (Exception exception)
        {
            UiLogger.Error($"{operation} 예외", exception);
            if (!_bootShuttingDown)
            {
                BootInstallStatusText.Text = $"{operation} 실패: {exception.Message}";
            }
        }
        finally
        {
            _bootOperationRunning = false;
            if (!_bootShuttingDown)
            {
                UpdateBootButtons();
            }
        }
        string completedStatus = BootInstallStatusText.Text;
        await RefreshBootAsync(true);
        if (!_bootShuttingDown)
        {
            BootInstallStatusText.Text = completedStatus;
        }
    }

    private void AppendBootEvents(BootNativeMethods.EventBatch batch, IReadOnlyDictionary<ulong, string> resolvedPaths)
    {
        for (int index = 0; index < batch.Count; index++)
        {
            BootNativeMethods.BootEvent entry = batch.Events[index];
            bool kernelPath = entry.PathStatus == 0 && entry.PathLength != 0;
            string path = kernelPath ? entry.Path[..(int)entry.PathLength] : "확인 불가";
            string pathSource = kernelPath ? "커널" : $"커널 NTSTATUS=0x{entry.PathStatus:X8}";
            if (!kernelPath && resolvedPaths.TryGetValue(entry.Sequence, out string? resolvedPath))
            {
                path = resolvedPath;
                pathSource = $"사용자 모드 (생성 시각 일치) · {pathSource}";
            }
            BootDeviceEntry? device = _bootDevices.FirstOrDefault(candidate => candidate.Info.DeviceId == entry.DeviceId);
            BootEventLog log = new(
                FormatBootTime(entry.Time),
                entry.Action == 1 ? "쓰기 차단" : entry.Action == 2 ? "상태 변경" : $"구분 {entry.Action}",
                device is null ? $"ID {entry.DeviceId}" : $"디스크 {device.Info.DiskNumber}",
                FormatBootKind(entry.Kind),
                entry.ProcessId == 0 ? "미상" : entry.ProcessId.ToString(),
                path,
                entry.Offset.ToString("N0"),
                entry.Length.ToString("N0"),
                $"0x{entry.Status:X8}",
                entry.IoctlCode == 0 ? "—" : $"0x{entry.IoctlCode:X8}",
                entry.PolicyGeneration,
                entry.Sequence,
                entry.ProcessCreated == 0 ? "미상" : FormatBootTime(entry.ProcessCreated),
                pathSource);
            BootEventLogs.Insert(0, log);
            UiLogger.Info($"부트 이벤트 sequence={entry.Sequence} action={entry.Action} deviceId={entry.DeviceId} generation={entry.PolicyGeneration} pid={entry.ProcessId} created={entry.ProcessCreated} path={path} pathSource={pathSource} kernelPathStatus=0x{entry.PathStatus:X8} offset={entry.Offset} length={entry.Length} ioctl=0x{entry.IoctlCode:X8} NTSTATUS=0x{entry.Status:X8}");
        }
        while (BootEventLogs.Count > MaxLogCount)
        {
            BootEventLogs.RemoveAt(BootEventLogs.Count - 1);
        }
        BootEventStatusText.Text = $"표시 {BootEventLogs.Count:N0}/{MaxLogCount:N0}개 · 커널 누적 유실 {batch.Dropped:N0}개 · 최근 조회 {DateTime.Now:HH:mm:ss}";
    }

    private void ClearBootLog_Click(object sender, RoutedEventArgs e)
    {
        BootEventLogs.Clear();
        BootEventStatusText.Text = "화면 로그를 지웠습니다. 커널 보호 정책과 누적 차단 수는 유지됩니다.";
        UiLogger.Info("부트 이벤트 화면 목록 초기화");
    }

    private static string FormatBootState(uint state) => state switch
    {
        BootNativeMethods.Stopped => "정지",
        BootNativeMethods.Scanning => "영역 검사 중 (활성화 대기)",
        BootNativeMethods.Active => "방어 중",
        BootNativeMethods.Unsupported => "지원하지 않는 디스크",
        BootNativeMethods.Failed => "시작 실패",
        BootNativeMethods.Removed => "장치 제거됨",
        _ => "알 수 없음"
    };

    private static string FormatBootKind(uint kind) => kind switch
    {
        1 => "MBR",
        2 => "GPT",
        3 => "FAT32",
        4 => "NTFS",
        5 => "장치 제어",
        _ => "—"
    };

    private static string FormatBootTime(ulong value)
    {
        try
        {
            return value <= long.MaxValue ? DateTime.FromFileTimeUtc((long)value).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff") : "시각 미상";
        }
        catch (ArgumentOutOfRangeException)
        {
            return "시각 미상";
        }
    }

    private static string FormatBootError(uint error) => $"GetLastError={error} (0x{error:X8}, {new Win32Exception(unchecked((int)error)).Message})";

    private sealed record BootDeviceEntry(BootNativeMethods.DeviceInfo Info)
    {
        public string DisplayName => $"디스크 {Info.DiskNumber} · {Info.DiskBytes / 1048576d:N0} MiB · {FormatBootState(Info.State)} · ID {Info.DeviceId}";
    }

    private sealed record BootRangeEntry(string Kind, string Offset, string Length, string End);
    private sealed record BootQueryResult(uint QueryError, uint EventError, BootNativeMethods.DeviceList Devices,
        BootNativeMethods.EventBatch Events, IReadOnlyDictionary<ulong, string> ResolvedPaths);
    private sealed record BootSetResult(uint Error, BootNativeMethods.DeviceInfo Device);
}

public sealed record BootEventLog(string Time, string Action, string Device, string Kind, string ProcessId,
    string Path, string Offset, string Length, string Status, string Ioctl, ulong Generation,
    ulong Sequence, string ProcessCreated, string PathSource);
