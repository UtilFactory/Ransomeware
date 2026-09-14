using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Windows.Threading;

namespace RansomUtilFactory.UI;

public partial class MainWindow
{
    private const int MaxPendingFileEvents = 4000;
    private readonly ConcurrentQueue<(int ConnectionVersion, FileEventLog Log)> _pendingFileEvents = new();
    private int _pendingFileEventCount;
    private int _fileLogDrainScheduled;

    private void ReceiveFileEvent(IntPtr eventPointer, IntPtr context)
    {
        try
        {
            if (_closing || Dispatcher.HasShutdownStarted) return;
            NativeMethods.FileEventV2 fileEvent = Marshal.PtrToStructure<NativeMethods.FileEventV2>(eventPointer);
            if (fileEvent.Version != 2 || fileEvent.Size != Marshal.SizeOf<NativeMethods.FileEventV2>())
            {
                UiLogger.Warn("파일 이벤트 ABI 불일치로 표시하지 않습니다.");
                return;
            }
            FileEventLog log = new(
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                FileProtectionPresentation.Action(fileEvent.Action),
                fileEvent.ProcessId,
                string.IsNullOrWhiteSpace(fileEvent.Image) ? "(이미지 경로 미확인)" : fileEvent.Image,
                fileEvent.Path ?? string.Empty);

            // 부트 사건은 폴더/프로세스 등록 정책과 무관하게 원래 페이로드의 PID와 이미지를 표시한다.
            if (FileProtectionPresentation.IsBootEvent(fileEvent.Action))
                UiLogger.Warn($"{log.Action} action={fileEvent.Action} pid={log.ProcessId} image={log.Image} path={log.Path}");
            if (Interlocked.Increment(ref _pendingFileEventCount) <= MaxPendingFileEvents)
            {
                _pendingFileEvents.Enqueue((Volatile.Read(ref _fileConnectionVersion), log));
                ScheduleFileLogDrain();
            }
            else
            {
                Interlocked.Decrement(ref _pendingFileEventCount);
            }

            if (fileEvent.Action == 3)
            {
                _ = Task.Run(() =>
                {
                    try { ResolveProcessTrust(fileEvent); }
                    catch (Exception exception) { UiLogger.Error("프로세스 신뢰 응답 실패", exception); }
                });
            }
        }
        catch (Exception exception)
        {
            UiLogger.Error("파일 이벤트 수신 실패", exception);
        }
    }

    private void ScheduleFileLogDrain()
    {
        if (_closing || Dispatcher.HasShutdownStarted ||
            Interlocked.CompareExchange(ref _fileLogDrainScheduled, 1, 0) != 0) return;
        Dispatcher.BeginInvoke(DrainFileEventLogs, DispatcherPriority.Background);
    }

    private void DrainFileEventLogs()
    {
        for (int i = 0; i < 200 && _pendingFileEvents.TryDequeue(out var item); ++i)
        {
            Interlocked.Decrement(ref _pendingFileEventCount);
            if (_closing || !_connected || item.ConnectionVersion != _fileConnectionVersion) continue;
            EventLogs.Insert(0, item.Log);
            if (EventLogs.Count > MaxLogCount) EventLogs.RemoveAt(EventLogs.Count - 1);
        }
        Interlocked.Exchange(ref _fileLogDrainScheduled, 0);
        if (!_pendingFileEvents.IsEmpty) ScheduleFileLogDrain();
    }
}
