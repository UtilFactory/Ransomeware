using System.Windows;

using System.Threading.Tasks;

namespace RansomUtilFactory.UI;

public partial class App : Application
{
    public App()
    {
        UiLogger.Initialize();
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private static void OnDispatcherUnhandledException(
        object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        UiLogger.Error("WPF UI 처리 중 처리되지 않은 예외", e.Exception);
    }

    private static void OnUnhandledException(object sender,
        UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            UiLogger.Error($"프로세스 처리 중 처리되지 않은 예외 terminating={e.IsTerminating}", exception);
            return;
        }
        UiLogger.Error($"프로세스 처리 중 처리되지 않은 개체 예외 terminating={e.IsTerminating}");
    }

    private static void OnUnobservedTaskException(object? sender,
        UnobservedTaskExceptionEventArgs e)
    {
        UiLogger.Error("Task 처리 중 관찰되지 않은 예외", e.Exception);
        e.SetObserved();
    }
}
