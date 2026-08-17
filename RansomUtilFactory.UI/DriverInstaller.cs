using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace RansomUtilFactory.UI;

internal static class DriverInstaller
{
    private const string FileDriverServiceName = "UF_FileFilterFactory";
    private const string ProcessDriverServiceName = "UF_ProcessFilterFactory";
    private const int ErrorAlreadyExists = 183;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorNotFound = 1168;
    private const int ErrorNotAllAssigned = 1300;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint PrivilegeEnabled = 0x00000002;
    private const string LoadDriverPrivilege = "SeLoadDriverPrivilege";
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceControlStop = 0x00000001;

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
            UiLogger.Error("드라이버 INF를 찾지 못함");
            return new(false,
                "파일 드라이버 설치 패키지를 찾을 수 없습니다. 전체 솔루션을 Debug | x64로 다시 빌드하십시오.",
                false);
        }
        UiLogger.Info($"드라이버 INF 설치 시작 path={infPath}");
        if (!DiInstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            UiLogger.Error($"DiInstallDriverW 실패 error={error}");
            return new(false, $"드라이버 패키지 설치 실패: {FormatError(error)}", rebootRequired);
        }

        if (!TryEnableLoadDriverPrivilege(out int privilegeError))
        {
            UiLogger.Error($"SeLoadDriverPrivilege 활성화 실패 error={privilegeError}");
            return new(false, $"드라이버 로드 권한을 활성화하지 못했습니다: {FormatError(privilegeError)}", rebootRequired);
        }
        int result = FilterLoad(FileDriverServiceName);
        int loadError = HResultToWin32(result);
        UiLogger.Info($"FilterLoad 결과 hresult={result} error={loadError}");
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
        if (!TryEnableLoadDriverPrivilege(out int privilegeError))
        {
            UiLogger.Error($"SeLoadDriverPrivilege 활성화 실패 error={privilegeError}");
            return new(false, $"드라이버 로드 권한을 활성화하지 못했습니다: {FormatError(privilegeError)}", false);
        }
        int result = FilterLoad(FileDriverServiceName);
        int loadError = HResultToWin32(result);
        UiLogger.Info($"설치된 미니필터 FilterLoad 결과 hresult={result} error={loadError}");
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
        UiLogger.Info("파일 드라이버 제거 작업 시작");
        if (!TryEnableLoadDriverPrivilege(out int privilegeError))
        {
            UiLogger.Error($"드라이버 언로드 권한 활성화 실패 error={privilegeError}");
            return new(false, $"드라이버 언로드 권한을 활성화하지 못했습니다: {FormatError(privilegeError)}", false);
        }
        int unloadResult = FilterUnload(FileDriverServiceName);
        int unloadError = HResultToWin32(unloadResult);
        UiLogger.Info($"FilterUnload 결과 hresult={unloadResult} error={unloadError}");
        if (unloadResult < 0 && unloadError != ErrorServiceNotActive && unloadError != ErrorNotFound)
        {
            UiLogger.Error($"미니필터 언로드 실패 error={unloadError}");
            return new(false, $"미니필터 언로드 실패: {FormatError(unloadError)}", false);
        }

        string? infPath = FindFileDriverInf();
        if (infPath is null)
        {
            UiLogger.Error("드라이버 제거 실패: INF를 찾지 못함");
            return new(false,
                "파일 드라이버 설치 패키지를 찾을 수 없어 제거를 계속할 수 없습니다.", false);
        }
        UiLogger.Info($"드라이버 INF 제거 시작 path={infPath}");
        if (!DiUninstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                UiLogger.Warn("드라이버 INF 제거 대상이 이미 없음");
                return new(true, "설치된 파일 드라이버가 없습니다.", false);
            }
            UiLogger.Error($"DiUninstallDriverW 실패 error={error}");
            return new(false, $"드라이버 패키지 제거 실패: {FormatError(error)}", rebootRequired);
        }
        UiLogger.Info($"파일 드라이버 제거 완료 rebootRequired={rebootRequired}");
        return new(true, "파일 드라이버를 언로드하고 제거했습니다.", rebootRequired);
    }

    internal static DriverOperationResult InstallProcessDriver()
    {
        string? infPath = FindProcessDriverInf();
        if (infPath is null)
        {
            return new(false,
                "프로세스 드라이버 설치 패키지를 찾을 수 없습니다. 전체 솔루션을 Debug | x64로 다시 빌드하십시오.",
                false);
        }
        if (!DiInstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            return new(false, $"프로세스 드라이버 패키지 설치 실패: {FormatError(error)}",
                rebootRequired);
        }
        DriverOperationResult startResult = LoadProcessDriver();
        return startResult.Success
            ? new(true, "프로세스 드라이버를 설치하고 로드했습니다.", rebootRequired)
            : new(false, $"패키지는 설치했지만 드라이버를 로드하지 못했습니다: {startResult.Message}",
                rebootRequired);
    }

    internal static DriverOperationResult LoadProcessDriver()
    {
        if (!TryEnableLoadDriverPrivilege(out int privilegeError))
        {
            return new(false,
                $"드라이버 로드 권한을 활성화하지 못했습니다: {FormatError(privilegeError)}", false);
        }
        int error = StartKernelDriver(ProcessDriverServiceName);
        if (error != 0 && error != ErrorServiceAlreadyRunning)
        {
            return new(false, $"프로세스 드라이버를 로드하지 못했습니다: {FormatError(error)}", false);
        }
        return new(true,
            error == ErrorServiceAlreadyRunning
                ? "프로세스 드라이버가 이미 로드되어 있습니다."
                : "설치된 프로세스 드라이버를 로드했습니다.",
            false);
    }

    internal static DriverOperationResult UninstallProcessDriver()
    {
        if (!TryEnableLoadDriverPrivilege(out int privilegeError))
        {
            return new(false,
                $"드라이버 언로드 권한을 활성화하지 못했습니다: {FormatError(privilegeError)}", false);
        }
        int stopError = StopKernelDriver(ProcessDriverServiceName);
        if (stopError != 0 && stopError != ErrorServiceNotActive &&
            stopError != ErrorServiceDoesNotExist)
        {
            return new(false, $"프로세스 드라이버 언로드 실패: {FormatError(stopError)}", false);
        }

        string? infPath = FindProcessDriverInf();
        if (infPath is null)
        {
            return new(false,
                "프로세스 드라이버 설치 패키지를 찾을 수 없어 제거를 계속할 수 없습니다.", false);
        }
        if (!DiUninstallDriverW(IntPtr.Zero, infPath, 0, out bool rebootRequired))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return new(true, "설치된 프로세스 드라이버가 없습니다.", false);
            }
            return new(false, $"프로세스 드라이버 패키지 제거 실패: {FormatError(error)}",
                rebootRequired);
        }
        return new(true, "프로세스 드라이버를 언로드하고 제거했습니다.", rebootRequired);
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

    private static string? FindProcessDriverInf()
    {
        string commonBin = Path.Combine(
            AppContext.BaseDirectory, "UF_ProcessFilterFactory.inf");
        if (File.Exists(commonBin))
        {
            return commonBin;
        }

        string packaged = Path.Combine(
            AppContext.BaseDirectory, "Drivers", "UF_ProcessFilterFactory",
            "UF_ProcessFilterFactory.inf");
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
                    "UF_ProcessFilterFactory", "UF_ProcessFilterFactory.inf");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            directory = directory.Parent;
        }
        return null;
    }

    private static int StartKernelDriver(string serviceName)
    {
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return Marshal.GetLastWin32Error();
        }
        try
        {
            IntPtr service = OpenService(manager, serviceName,
                ServiceStart | ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error();
            }
            try
            {
                return StartService(service, 0, IntPtr.Zero)
                    ? 0
                    : Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static int StopKernelDriver(string serviceName)
    {
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return Marshal.GetLastWin32Error();
        }
        try
        {
            IntPtr service = OpenService(manager, serviceName,
                ServiceStop | ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error();
            }
            try
            {
                ServiceStatus status = new();
                return ControlService(service, ServiceControlStop, ref status)
                    ? 0
                    : Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static bool TryEnableLoadDriverPrivilege(out int error)
    {
        error = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenAdjustPrivileges,
                out IntPtr token))
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }
        try
        {
            if (!LookupPrivilegeValue(null, LoadDriverPrivilege, out Luid luid))
            {
                error = Marshal.GetLastWin32Error();
                return false;
            }
            TokenPrivileges privileges = new()
            {
                PrivilegeCount = 1,
                Privilege = new LuidAndAttributes
                {
                    Luid = luid,
                    Attributes = PrivilegeEnabled
                }
            };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0,
                    IntPtr.Zero, IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                return false;
            }
            error = Marshal.GetLastWin32Error();
            return error == 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        internal uint LowPart;
        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        internal Luid Luid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        internal uint PrivilegeCount;
        internal LuidAndAttributes Privilege;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(
        string? systemName,
        string name,
        out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr serviceControlManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(
        IntPtr service,
        uint argumentCount,
        IntPtr arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(
        IntPtr service,
        uint control,
        ref ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);

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
