using System.Windows;

namespace RansomUtilFactory.UI;

public partial class App : Application
{
    public App()
    {
        UiLogger.Initialize();
        DispatcherUnhandledException += OnDispatcherUnhandledException;
    }

    private static void OnDispatcherUnhandledException(
        object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        UiLogger.Error("WPF UI 처리 중 처리되지 않은 예외", e.Exception);
    }
}
