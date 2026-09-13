using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace RansomUtilFactory.UI;

// 진단 문자열은 상태의 유효성을 가정하지 않으며 실패 응답을 성공으로 해석하지 않는다.
internal static class FileProtectionDiagnostics
{
    internal const string Revision = "file-boot-ui-20260914.1";

    internal static string Command(bool? enabled) => enabled.HasValue
        ? enabled.Value ? "Start" : "Stop" : "Query";

    internal static string Error(uint error) => $"GetLastError={error} (0x{error:X8})";

    internal static string State(NativeMethods.BootProtectionState state) =>
        $"version={state.Version} size={state.Size} enabled={state.Enabled} protectedBytes={state.ProtectedBytes} " +
        $"inspectedWrites={state.InspectedWrites} blockedWrites={state.BlockedWrites} inspectionFailures={state.InspectionFailures}";

    internal static string ThreadIdentity() =>
        $"pid={Environment.ProcessId} nativeThreadId={GetCurrentThreadId()} managedThreadId={Environment.CurrentManagedThreadId}";

    internal static string RuntimeIdentity()
    {
        Assembly assembly = typeof(FileProtectionDiagnostics).Assembly;
        return $"diagnosticRevision={Revision} assembly=\"{assembly.FullName}\" " +
            $"assemblyPath=\"{assembly.Location}\" mvid={assembly.ManifestModule.ModuleVersionId:D} " +
            $"processPath=\"{Environment.ProcessPath}\" baseDirectory=\"{AppContext.BaseDirectory}\" " +
            $"runtime={Environment.Version} is64BitProcess={Environment.Is64BitProcess}";
    }

    internal static string LoadedNativeModule()
    {
        // 조회만 하며 DLL을 새로 로드하거나 초기화하지 않는다.
        using Process process = Process.GetCurrentProcess();
        foreach (ProcessModule module in process.Modules)
        {
            if (string.Equals(module.ModuleName, "uf_fltwarp.dll", StringComparison.OrdinalIgnoreCase))
                return $"loadedNativeModule=\"{module.FileName}\" moduleSize={module.ModuleMemorySize}";
        }
        return "loadedNativeModule=not-found";
    }

    internal static void LogDeploymentSnapshot(Action<string> log)
    {
        log("snapshotScope=on-disk-files notProofOfLoadedKernelImage=true 메모리에 로드된 SYS 버전의 증거가 아닙니다.");
        LogFileIdentity("deployment-dll", Path.Combine(AppContext.BaseDirectory, "uf_fltwarp.dll"), log);
        LogFileIdentity("deployment-sys", Path.Combine(AppContext.BaseDirectory, "UF_FileFilterFactory.sys"), log);
        LogFileIdentity("deployment-package-sys", Path.Combine(AppContext.BaseDirectory,
            "Drivers", "UF_FileFilterFactory", "UF_FileFilterFactory.sys"), log);
        try
        {
            using Process process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
                if (string.Equals(module.ModuleName, "uf_fltwarp.dll", StringComparison.OrdinalIgnoreCase))
                    LogFileIdentity("loaded-dll-file-on-disk", module.FileName, log);
        }
        catch (Exception exception)
        {
            log($"loadedModuleSnapshotFailed=true exception={exception}");
        }
        try
        {
            using RegistryKey? service = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\UF_FileFilterFactory", writable: false);
            string? rawPath = service?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            log($"service=UF_FileFilterFactory serviceFound={service is not null} imagePath=\"{rawPath}\"");
            string? path = NormalizeServiceImagePath(rawPath);
            if (path is not null) LogFileIdentity("service-image-on-disk", path, log);
            else log("label=service-image-on-disk snapshotSkipped=true reason=unknown-or-nonlocal-path");
        }
        catch (Exception exception)
        {
            log($"serviceSnapshotFailed=true exception={exception}");
        }
    }

    internal static string? NormalizeServiceImagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string candidate = path.Trim();
        if (candidate.Length >= 2 && candidate[0] == '"' && candidate[^1] == '"')
            candidate = candidate[1..^1];
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (candidate.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(windows, candidate[12..]);
        else if (candidate.StartsWith(@"%SystemRoot%\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(windows, candidate[13..]);
        else if (candidate.StartsWith(@"\??\", StringComparison.Ordinal))
            candidate = candidate[4..];
        return IsLocalDrivePath(candidate) ? candidate : null;
    }

    internal static bool IsLocalDrivePath(string path) => path.Length >= 3 &&
        char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' && !path.Contains('%');

    private static void LogFileIdentity(string label, string path, Action<string> log)
    {
        try
        {
            if (!IsLocalDrivePath(path) || new DriveInfo(path[..3]).DriveType != DriveType.Fixed)
            {
                log($"label={label} path=\"{path}\" snapshotSkipped=true reason=not-fixed-local-drive");
                return;
            }
            // UNC·장치 이름·네트워크 드라이브·재분석 지점은 진단 중 열지 않는다.
            string fullPath = Path.GetFullPath(path);
            string current = fullPath[..3];
            foreach (string part in fullPath[3..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, part);
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    log($"label={label} path=\"{fullPath}\" snapshotSkipped=true reason=reparse-point");
                    return;
                }
            }
            FileInfo before = new(fullPath);
            long size = before.Length;
            DateTime writeTime = before.LastWriteTimeUtc;
            if (size < 0 || size > 16 * 1024 * 1024)
            {
                log($"label={label} path=\"{fullPath}\" bytes={size} lastWriteUtc={writeTime:O} sha256Skipped=size-limit");
                return;
            }
            byte[] contents = new byte[checked((int)size)];
            using (FileStream stream = new(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                stream.ReadExactly(contents);
            FileInfo after = new(fullPath);
            string sha256 = Convert.ToHexString(SHA256.HashData(contents));
            log($"label={label} path=\"{fullPath}\" bytes={size} lastWriteUtc={writeTime:O} sha256={sha256} " +
                $"metadataStable={size == after.Length && writeTime == after.LastWriteTimeUtc}");
        }
        catch (Exception exception)
        {
            log($"label={label} path=\"{path}\" snapshotFailed=true exceptionType={exception.GetType().FullName} " +
                $"exceptionHResult=0x{exception.HResult:X8} message={exception.Message}");
        }
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentThreadId();
}
