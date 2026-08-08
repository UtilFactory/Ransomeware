using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace RansomUtilFactory.UI;

internal static class DriverInstaller
{
    private const string FileDriverServiceName = "UF_FileFilterFactory";
    private const int ErrorAlreadyExists = 183;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorNotFound = 1168;

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DiInstallDriverW(
        IntPtr window,
        string infPath,
        uint flags,
        [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DiUninstallDriverW(
        IntPtr window,
        string infPath,
        uint flags,
        [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterLoad(string filterName);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterUnload(string filterName);

    internal static DriverOperationResult InstallFileDriver()
    {
        string? infPath = FindFileDriverInf();
        if (infPath is null)
        {
            return new(false,
                "파일 드라이버 설치 패키지를 찾을 수 없습니다. 전체 솔루션을 Debug | x64로 다시 빌드하십시오.",
                false);
        }
        if (!DiInstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            return new(false, $"드라이버 패키지 설치 실패: {FormatError(error)}", rebootRequired);
        }

        int result = FilterLoad(FileDriverServiceName);
        int loadError = HResultToWin32(result);
        if (result < 0 &&
            loadError != ErrorAlreadyExists &&
            loadError != ErrorServiceAlreadyRunning)
        {
            return new(false,
                $"패키지는 설치했지만 미니필터를 로드하지 못했습니다: {FormatError(loadError)}",
                rebootRequired);
        }
        return new(true, "파일 드라이버를 설치하고 미니필터를 로드했습니다.", rebootRequired);
    }

    internal static DriverOperationResult LoadFileDriver()
    {
        int result = FilterLoad(FileDriverServiceName);
        int loadError = HResultToWin32(result);
        if (result < 0 &&
            loadError != ErrorAlreadyExists &&
            loadError != ErrorServiceAlreadyRunning)
        {
            return new(false, $"설치된 미니필터를 로드하지 못했습니다: {FormatError(loadError)}", false);
        }

        string message = loadError == ErrorAlreadyExists ||
                         loadError == ErrorServiceAlreadyRunning
            ? "파일 미니필터가 이미 로드되어 있습니다."
            : "설치된 파일 미니필터를 로드했습니다.";
        return new(true, message, false);
    }

    internal static DriverOperationResult UninstallFileDriver()
    {
        int unloadResult = FilterUnload(FileDriverServiceName);
        int unloadError = HResultToWin32(unloadResult);
        if (unloadResult < 0 && unloadError != ErrorServiceNotActive && unloadError != ErrorNotFound)
        {
            return new(false, $"미니필터 언로드 실패: {FormatError(unloadError)}", false);
        }

        string? infPath = FindFileDriverInf();
        if (infPath is null)
        {
            return new(false,
                "파일 드라이버 설치 패키지를 찾을 수 없어 제거를 계속할 수 없습니다.", false);
        }
        if (!DiUninstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return new(true, "설치된 파일 드라이버가 없습니다.", false);
            }
            return new(false, $"드라이버 패키지 제거 실패: {FormatError(error)}", rebootRequired);
        }
        return new(true, "파일 드라이버를 언로드하고 제거했습니다.", rebootRequired);
    }

    private static string? FindFileDriverInf()
    {
        string commonBin = Path.Combine(
            AppContext.BaseDirectory, "UF_FileFilterFactory.inf");
        if (File.Exists(commonBin))
        {
            return commonBin;
        }

        string packaged = Path.Combine(
            AppContext.BaseDirectory, "Drivers", "UF_FileFilterFactory", "UF_FileFilterFactory.inf");
        if (File.Exists(packaged))
        {
            return packaged;
        }

        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            foreach (string configuration in new[] { "Debug", "Release" })
            {
                string candidate = Path.Combine(
                    directory.FullName, "x64", configuration,
                    "UF_FileFilterFactory", "UF_FileFilterFactory.inf");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            directory = directory.Parent;
        }
        return null;
    }

    private static int HResultToWin32(int result)
    {
        return result >= 0 ? 0 : result & 0xFFFF;
    }

    private static string FormatError(int error)
    {
        return $"{error} ({new Win32Exception(error).Message})";
    }
}

internal sealed record DriverOperationResult(bool Success, string Message, bool RebootRequired);
