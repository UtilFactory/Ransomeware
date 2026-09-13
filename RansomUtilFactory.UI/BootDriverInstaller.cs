using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace RansomUtilFactory.UI;

internal sealed record BootDiskCandidate(string InstanceId, string DisplayName, uint DiskNumber);

internal static class BootDriverInstaller
{
    private const string ServiceName = "UF_BootProtectionFactory";
    private const uint UpperFilters = 0x11;
    private static readonly Guid DiskInterface = new("53f56307-b6bf-11d0-94f2-00a0c91efb8b");

    internal static DriverOperationResult InstallPackage()
    {
        try
        {
            EnsureGuestAdmin();
            string inf = Path.Combine(AppContext.BaseDirectory, ServiceName + ".inf");
            if (!File.Exists(inf)) inf = Path.Combine(AppContext.BaseDirectory, "Drivers", ServiceName, ServiceName + ".inf");
            if (!File.Exists(inf)) throw new Win32Exception(2, "부트 보호 INF 패키지를 찾을 수 없습니다.");
            UiLogger.Info($"부트 보호 패키지 설치 시작 path={inf}");
            if (!DiInstallDriverW(IntPtr.Zero, inf, 0, out bool reboot)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new(true, "패키지를 설치했습니다. 시험 디스크를 선택해 필터를 등록한 다음 VHDX를 재부착하십시오.", reboot);
        }
        catch (Exception ex) { return Failure("부트 보호 패키지 설치", ex); }
    }

    internal static IReadOnlyList<BootDiskCandidate> ListCandidates()
    {
        HashSet<uint> systemDisks = GetSystemDisks();
        List<BootDiskCandidate> result = [];
        Guid guid = DiskInterface;
        IntPtr devices = SetupDiGetClassDevsW(ref guid, null, IntPtr.Zero, 0x12);
        if (devices == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            for (uint index = 0; ; index++)
            {
                DeviceInterfaceData iface = new() { Size = (uint)Marshal.SizeOf<DeviceInterfaceData>() };
                if (!SetupDiEnumDeviceInterfaces(devices, IntPtr.Zero, ref guid, index, ref iface))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 259) break;
                    throw new Win32Exception(error);
                }
                DeviceInfoData info = new() { Size = (uint)Marshal.SizeOf<DeviceInfoData>() };
                _ = SetupDiGetDeviceInterfaceDetailW(devices, ref iface, IntPtr.Zero, 0, out uint bytes, ref info);
                if (bytes < 8 || bytes > 65536) continue;
                IntPtr detail = Marshal.AllocHGlobal((int)bytes);
                try
                {
                    Marshal.WriteInt32(detail, 8);
                    if (!SetupDiGetDeviceInterfaceDetailW(devices, ref iface, detail, bytes, out _, ref info)) continue;
                    string? path = Marshal.PtrToStringUni(detail + 4);
                    if (path is null) continue;
                    using SafeFileHandle handle = CreateFileW(path, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                    if (handle.IsInvalid) continue;
                    byte[] descriptor = new byte[1024], number = new byte[12], length = new byte[8];
                    if (!DeviceIoControl(handle, 0x2d1400, new byte[12], 12, descriptor, 1024, out uint got, IntPtr.Zero) ||
                        got < 36 || BitConverter.ToUInt32(descriptor, 28) != 15 ||
                        !DeviceIoControl(handle, 0x2d1080, null, 0, number, 12, out got, IntPtr.Zero) || got < 12 ||
                        !DeviceIoControl(handle, 0x7405c, null, 0, length, 8, out got, IntPtr.Zero) || got < 8) continue;
                    uint diskNumber = BitConverter.ToUInt32(number, 4);
                    if (BitConverter.ToUInt32(number, 0) != 7 || systemDisks.Contains(diskNumber)) continue;
                    StringBuilder instance = new(1024);
                    if (!SetupDiGetDeviceInstanceIdW(devices, ref info, instance, (uint)instance.Capacity, out _)) continue;
                    string[] filters = ReadFilters(devices, ref info);
                    string marker = filters.Contains(ServiceName, StringComparer.OrdinalIgnoreCase) ? "필터 등록됨" : "미등록";
                    result.Add(new(instance.ToString(), $"디스크 {diskNumber} · {BitConverter.ToUInt64(length) / 1048576} MiB · VHDX · {marker}", diskNumber));
                }
                finally { Marshal.FreeHGlobal(detail); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(devices); }
        return result;
    }

    internal static DriverOperationResult AttachFilter(BootDiskCandidate candidate) => ChangeFilter(candidate, true);
    internal static DriverOperationResult DetachFilter(BootDiskCandidate candidate) => ChangeFilter(candidate, false);

    private static DriverOperationResult ChangeFilter(BootDiskCandidate candidate, bool attach)
    {
        try
        {
            EnsureGuestAdmin();
            // 번호가 재사용된 장치에 등록하지 않도록 인스턴스와 번호를 함께 다시 확인한다.
            if (!ListCandidates().Any(x => x.InstanceId.Equals(candidate.InstanceId, StringComparison.OrdinalIgnoreCase) &&
                x.DiskNumber == candidate.DiskNumber)) throw new Win32Exception(1167, "시험 디스크가 제거되거나 변경되었습니다. 새로고침하십시오.");
            if (attach)
            {
                using RegistryKey? service = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
                if (service?.GetValue("ImagePath") is not string) throw new Win32Exception(1060, "먼저 부트 보호 패키지를 설치하십시오.");
            }
            IntPtr devices = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
            if (devices == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                DeviceInfoData info = new() { Size = (uint)Marshal.SizeOf<DeviceInfoData>() };
                if (!SetupDiOpenDeviceInfoW(devices, candidate.InstanceId, IntPtr.Zero, 0, ref info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                string[] oldFilters = ReadFilters(devices, ref info);
                string[] newFilters = RewriteFilters(oldFilters, attach);
                if (!oldFilters.SequenceEqual(newFilters, StringComparer.OrdinalIgnoreCase))
                {
                    byte[]? buffer = newFilters.Length == 0 ? null : Encoding.Unicode.GetBytes(string.Join('\0', newFilters) + "\0\0");
                    UiLogger.Info($"부트 필터 등록 변경 attach={attach} disk={candidate.DiskNumber} instance={candidate.InstanceId} before={string.Join(',', oldFilters)} after={string.Join(',', newFilters)}");
                    if (!SetupDiSetDeviceRegistryPropertyW(devices, ref info, UpperFilters, buffer, (uint)(buffer?.Length ?? 0)))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (!ReadFilters(devices, ref info).SequenceEqual(newFilters, StringComparer.OrdinalIgnoreCase))
                        throw new Win32Exception(13, "필터 등록 후 검증에 실패했습니다.");
                }
                return new(true, attach
                    ? "선택한 VHDX에 필터를 등록했습니다. VHDX 재부착 후 커널 장치 목록을 새로고침하십시오. 방어 시작은 별도입니다."
                    : "선택한 VHDX의 필터 등록을 해제했습니다. 현재 부착된 필터는 VHDX를 분리할 때 해제됩니다.", false);
            }
            finally { SetupDiDestroyDeviceInfoList(devices); }
        }
        catch (Exception ex) { return Failure(attach ? "부트 필터 등록" : "부트 필터 등록 해제", ex); }
    }

    // 다른 드라이버의 순서를 보존하고 이 서비스 항목만 추가 또는 제거한다.
    internal static string[] RewriteFilters(string[] filters, bool attach)
    {
        if (attach) return filters.Contains(ServiceName, StringComparer.OrdinalIgnoreCase) ? filters : [.. filters, ServiceName];
        return filters.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
    }

    private static string[] ReadFilters(IntPtr devices, ref DeviceInfoData info)
    {
        byte[] data = new byte[65536];
        if (!SetupDiGetDeviceRegistryPropertyW(devices, ref info, UpperFilters, out uint type, data, (uint)data.Length, out uint bytes))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 13) return [];
            throw new Win32Exception(error);
        }
        if (type != 7 || bytes > data.Length || (bytes & 1) != 0 || bytes < 4 ||
            data[bytes - 1] != 0 || data[bytes - 2] != 0 || data[bytes - 3] != 0 || data[bytes - 4] != 0)
            throw new Win32Exception(13, "기존 UpperFilters 형식이 잘못되어 변경하지 않았습니다.");
        return Encoding.Unicode.GetString(data, 0, (int)bytes).Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    private static HashSet<uint> GetSystemDisks()
    {
        string root = Path.GetPathRoot(Environment.SystemDirectory) ?? throw new IOException("시스템 볼륨을 확인할 수 없습니다.");
        if (root.Length != 3 || root[1] != ':') throw new IOException("시스템 볼륨 형식을 지원하지 않습니다.");
        using SafeFileHandle volume = CreateFileW(@"\\.\" + root[..2], 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (volume.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        byte[] data = new byte[4096];
        if (!DeviceIoControl(volume, 0x560000, null, 0, data, (uint)data.Length, out uint bytes, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (bytes < 32) throw new Win32Exception(13);
        uint count = BitConverter.ToUInt32(data);
        if (count == 0 || count > 128 || 8 + count * 24 > bytes) throw new Win32Exception(13);
        HashSet<uint> disks = [];
        for (int i = 0; i < count; i++) disks.Add(BitConverter.ToUInt32(data, 8 + i * 24));
        return disks;
    }

    private static void EnsureGuestAdmin()
    {
        using RegistryKey? bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
        using RegistryKey? guest = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters");
        if (bios?.GetValue("SystemProductName") is not string product || product != "Virtual Machine" ||
            guest?.GetValue("PhysicalHostName") is not string host || string.IsNullOrWhiteSpace(host))
            throw new Win32Exception(50, "부트 보호 개발 드라이버 설치는 Hyper-V 시험 게스트에서 실행하십시오.");
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new Win32Exception(740);
    }

    private static DriverOperationResult Failure(string operation, Exception exception)
    {
        int? error = exception is Win32Exception win32 ? win32.NativeErrorCode : null;
        UiLogger.Error($"{operation} 실패 GetLastError={error?.ToString() ?? "없음"}", exception);
        return new(false, $"{operation} 실패: {exception.Message}", false, error);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceInfoData { internal uint Size; internal Guid ClassGuid; internal uint DevInst; internal IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceInterfaceData { internal uint Size; internal Guid InterfaceClassGuid; internal uint Flags; internal IntPtr Reserved; }
    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DiInstallDriverW(IntPtr window, string infPath, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevsW(ref Guid guid, string? enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr info, ref Guid guid, uint index, ref DeviceInterfaceData data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr set, ref DeviceInterfaceData iface, IntPtr detail, uint size, out uint required, ref DeviceInfoData info);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref DeviceInfoData info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr guid, IntPtr parent);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string id, IntPtr parent, uint flags, ref DeviceInfoData info);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref DeviceInfoData info, uint property, out uint type, byte[] buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref DeviceInfoData info, uint property, byte[]? buffer, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[]? input, uint inputBytes, byte[] output, uint outputBytes, out uint returned, IntPtr overlapped);
}
