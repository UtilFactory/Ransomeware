using System.IO;
using log4net;
using log4net.Config;

namespace RansomUtilFactory.UI;

internal static class UiLogger
{
    private static readonly object Sync = new();
    private static ILog? _logger;

    internal static void Initialize()
    {
        lock (Sync)
        {
            if (_logger is not null)
            {
                return;
            }
            try
            {
                string logDirectory = Path.Combine(AppContext.BaseDirectory, "logs");
                Directory.CreateDirectory(logDirectory);
                log4net.GlobalContext.Properties["LogDirectory"] = logDirectory;
                string configPath = Path.Combine(AppContext.BaseDirectory, "log4net.config");
                if (File.Exists(configPath))
                {
                    XmlConfigurator.Configure(new FileInfo(configPath));
                }
                _logger = LogManager.GetLogger(typeof(UiLogger));
                _logger.Info("RansomUtilFactory.UI 로깅 초기화");
            }
            catch (Exception exception)
            {
                _logger ??= LogManager.GetLogger(typeof(UiLogger));
                System.Diagnostics.Debug.WriteLine($"WPF 로그 초기화 실패: {exception}");
            }
        }
    }

    internal static void Debug(string message)
    {
        GetLogger().Debug(message);
    }

    internal static void Info(string message)
    {
        GetLogger().Info(message);
    }

    internal static void Warn(string message)
    {
        GetLogger().Warn(message);
    }

    internal static void Error(string message)
    {
        GetLogger().Error(message);
    }

    internal static void Error(string message, Exception exception)
    {
        GetLogger().Error(message, exception);
    }

    private static ILog GetLogger()
    {
        if (_logger is null)
        {
            Initialize();
        }
        return _logger!;
    }
}
