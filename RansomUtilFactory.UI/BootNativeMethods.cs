using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace RansomUtilFactory.UI;

internal static class BootNativeMethods
{
    internal const uint Version = 1;
    internal const int MaxDevices = 32;
    internal const int MaxRanges = 64;
    internal const int MaxEvents = 32;
    internal const uint Stopped = 0;
    internal const uint Scanning = 1;
    internal const uint Active = 2;
    internal const uint Unsupported = 3;
    internal const uint Failed = 4;
    internal const uint Removed = 5;
    internal const uint FlagLabDisk = 1;
    internal const uint FlagReady = 2;

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct Range
    {
        internal ulong Offset;
        internal ulong Length;
        internal uint Kind;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct DeviceInfo
    {
        internal uint Version;
        internal uint Size;
        internal ulong DeviceId;
        internal ulong PolicyGeneration;
        internal ulong DiskBytes;
        internal ulong BlockedWrites;
        internal uint DiskNumber;
        internal uint SectorBytes;
        internal uint State;
        internal uint LastStatus;
        internal uint RangeCount;
        internal uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 200)]
        internal string InstanceId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxRanges)]
        internal Range[] Ranges;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct DeviceList
    {
        internal uint Version;
        internal uint Size;
        internal uint Count;
        internal uint Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxDevices)]
        internal DeviceInfo[] Devices;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct SetRequest
    {
        internal uint Version;
        internal uint Size;
        internal ulong DeviceId;
        internal ulong ExpectedGeneration;
        internal uint Enabled;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct BootEvent
    {
        internal uint Version;
        internal uint Size;
        internal ulong Sequence;
        internal ulong Time;
        internal ulong DeviceId;
        internal ulong PolicyGeneration;
        internal ulong ProcessId;
        internal ulong ProcessCreated;
        internal ulong Offset;
        internal ulong Length;
        internal uint IoctlCode;
        internal uint Action;
        internal uint Status;
        internal uint Kind;
        internal uint PathStatus;
        internal uint PathLength;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
        internal string Path;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct EventBatch
    {
        internal uint Version;
        internal uint Size;
        internal uint Count;
        internal uint Reserved;
        internal ulong Dropped;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxEvents)]
        internal BootEvent[] Events;
    }

    [DllImport("uf_bootwarp.dll", ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfBootQueryDevices([In, Out] ref DeviceList devices);

    [DllImport("uf_bootwarp.dll", ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfBootSetProtection(in SetRequest request, [In, Out] ref DeviceInfo device);

    [DllImport("uf_bootwarp.dll", ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfBootReadEvents([In, Out] ref EventBatch events);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out ulong creation, out ulong exit,
        out ulong kernel, out ulong user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags,
        StringBuilder image, ref uint length);

    internal static string? TryGetMatchingProcessPath(ulong processId, ulong processCreated)
    {
        if (processId == 0 || processId > uint.MaxValue || processCreated == 0)
        {
            return null;
        }
        // 동일 핸들의 생성 시각을 먼저 확인하여 PID가 재사용된 다른 프로세스의 경로를 표시하지 않는다.
        using SafeProcessHandle process = OpenProcess(0x1000, false, (uint)processId);
        if (process.IsInvalid || !GetProcessTimes(process, out ulong created, out _, out _, out _) ||
            created != processCreated)
        {
            return null;
        }
        StringBuilder image = new(32768);
        uint length = (uint)image.Capacity;
        return QueryFullProcessImageNameW(process, 0, image, ref length) && length != 0 && length < image.Capacity
            ? image.ToString()
            : null;
    }

    internal static DeviceInfo CreateDeviceInfo() => new()
    {
        Version = Version,
        Size = (uint)Marshal.SizeOf<DeviceInfo>(),
        InstanceId = string.Empty,
        Ranges = new Range[MaxRanges]
    };

    internal static DeviceList CreateDeviceList() => new()
    {
        Version = Version,
        Size = (uint)Marshal.SizeOf<DeviceList>(),
        Devices = Enumerable.Range(0, MaxDevices).Select(_ => CreateDeviceInfo()).ToArray()
    };

    internal static EventBatch CreateEventBatch() => new()
    {
        Version = Version,
        Size = (uint)Marshal.SizeOf<EventBatch>(),
        Events = Enumerable.Range(0, MaxEvents).Select(_ => new BootEvent { Path = string.Empty }).ToArray()
    };

    internal static void ValidateAbi()
    {
        ValidateSize<Range>(24);
        ValidateSize<DeviceInfo>(2000);
        ValidateSize<DeviceList>(64016);
        ValidateSize<SetRequest>(32);
        ValidateSize<BootEvent>(1136);
        ValidateSize<EventBatch>(36376);
        ValidateOffset<DeviceInfo>(nameof(DeviceInfo.InstanceId), 64);
        ValidateOffset<DeviceInfo>(nameof(DeviceInfo.Ranges), 464);
        ValidateOffset<DeviceList>(nameof(DeviceList.Devices), 16);
        ValidateOffset<SetRequest>(nameof(SetRequest.Enabled), 24);
        ValidateOffset<BootEvent>(nameof(BootEvent.Path), 96);
        ValidateOffset<EventBatch>(nameof(EventBatch.Events), 24);
    }

    internal static void ValidateDevice(DeviceInfo device)
    {
        if (device.Version != Version || device.Size != Marshal.SizeOf<DeviceInfo>() ||
            device.DeviceId == 0 || device.RangeCount > MaxRanges || device.State > Removed ||
            device.Ranges is null || device.Ranges.Length != MaxRanges)
        {
            throw new InvalidOperationException("부트 드라이버 장치 응답의 버전·크기·범위가 올바르지 않습니다.");
        }
    }

    internal static void ValidateDevices(DeviceList devices)
    {
        if (devices.Version != Version || devices.Size != Marshal.SizeOf<DeviceList>() ||
            devices.Count > MaxDevices || devices.Devices is null || devices.Devices.Length != MaxDevices)
        {
            throw new InvalidOperationException("부트 드라이버 목록 응답의 버전·크기·개수가 올바르지 않습니다.");
        }
        for (int index = 0; index < devices.Count; index++)
        {
            ValidateDevice(devices.Devices[index]);
        }
    }

    internal static void ValidateEvents(EventBatch batch)
    {
        if (batch.Version != Version || batch.Size != Marshal.SizeOf<EventBatch>() ||
            batch.Count > MaxEvents || batch.Events is null || batch.Events.Length != MaxEvents)
        {
            throw new InvalidOperationException("부트 드라이버 로그 응답의 버전·크기·개수가 올바르지 않습니다.");
        }
        for (int index = 0; index < batch.Count; index++)
        {
            BootEvent entry = batch.Events[index];
            if (entry.Version != Version || entry.Size != Marshal.SizeOf<BootEvent>() ||
                entry.PathLength >= 520 || entry.Path is null || entry.PathLength > entry.Path.Length)
            {
                throw new InvalidOperationException("부트 드라이버 로그의 버전·크기·문자열 길이가 올바르지 않습니다.");
            }
        }
    }

    private static void ValidateSize<T>(int expected) where T : struct
    {
        int actual = Marshal.SizeOf<T>();
        if (actual != expected)
        {
            throw new InvalidOperationException($"부트 통신 ABI 크기 불일치: {typeof(T).Name}, 예상={expected}, 실제={actual}");
        }
    }

    private static void ValidateOffset<T>(string field, int expected) where T : struct
    {
        if (Marshal.OffsetOf<T>(field).ToInt64() != expected)
        {
            throw new InvalidOperationException($"부트 통신 ABI 필드 위치 불일치: {typeof(T).Name}.{field}");
        }
    }
}
