using System.Runtime.InteropServices;
using System.Diagnostics;
using RansomUtilFactory.UI;

// 설치·장치 접근·드라이버 DLL 호출 없이 UI의 ABI와 필터 목록 변환, 현재 프로세스의 읽기 전용 식별을 검사한다.
int checks = 0;
int failures = 0;
void Check(bool result, string name)
{
    checks++;
    if (!result) failures++;
    Console.WriteLine($"{(result ? "PASS" : "FAIL")} {name}");
}
void Reject(Action action, string name)
{
    try { action(); Check(false, name); }
    catch (InvalidOperationException) { Check(true, name); }
}

BootNativeMethods.ValidateAbi();
Check(true, "six ABI sizes and six offsets");
BootNativeMethods.DeviceList list = BootNativeMethods.CreateDeviceList();
BootNativeMethods.ValidateDevices(list);
BootNativeMethods.EventBatch events = BootNativeMethods.CreateEventBatch();
BootNativeMethods.ValidateEvents(events);
Check(true, "empty device and event replies");

list.Count = BootNativeMethods.MaxDevices;
for (int index = 0; index < list.Count; index++)
{
    BootNativeMethods.DeviceInfo info = BootNativeMethods.CreateDeviceInfo();
    info.DeviceId = (ulong)index + 1;
    info.PolicyGeneration = 1000 + (ulong)index;
    info.DiskBytes = 1024 * 1024 * 1024;
    info.BlockedWrites = 0x123456789abcdef0;
    info.DiskNumber = (uint)index;
    info.SectorBytes = 4096;
    info.State = BootNativeMethods.Active;
    info.Flags = BootNativeMethods.FlagLabDisk | BootNativeMethods.FlagReady;
    info.InstanceId = new string('가', 199);
    info.RangeCount = BootNativeMethods.MaxRanges;
    for (int range = 0; range < info.RangeCount; range++)
    {
        info.Ranges[range] = new() { Offset = (ulong)range * 4096, Length = 4096, Kind = (uint)(range % 4 + 1) };
    }
    list.Devices[index] = info;
}
BootNativeMethods.DeviceList roundtripList = Roundtrip(list);
BootNativeMethods.ValidateDevices(roundtripList);
Check(roundtripList.Count == 32 && roundtripList.Devices[31].DeviceId == 32, "all 32 device entries marshal");
Check(roundtripList.Devices.All(item => item.InstanceId == new string('가', 199)), "maximum UTF16 instance strings marshal");
Check(roundtripList.Devices.All(item => item.Ranges[63].Offset == 63UL * 4096 && item.Ranges[63].Kind == 4), "all 64 nested ranges marshal");
Check(roundtripList.Devices[31].BlockedWrites == 0x123456789abcdef0 && roundtripList.Devices[31].PolicyGeneration == 1031, "64-bit device fields preserve high bits");

events.Count = BootNativeMethods.MaxEvents;
events.Dropped = 0xfedcba9876543210;
for (int index = 0; index < events.Count; index++)
{
    events.Events[index] = new()
    {
        Version = BootNativeMethods.Version,
        Size = (uint)Marshal.SizeOf<BootNativeMethods.BootEvent>(),
        Sequence = 1234 + (ulong)index,
        DeviceId = 9,
        ProcessId = 0x1234567812345678,
        ProcessCreated = 133000000000000000,
        Time = 134000000000000000,
        Offset = 0x100000000,
        Length = 4096,
        Path = new string('경', 519),
        PathLength = 519,
        Action = 1,
        Status = 0xc0000022,
        Kind = 4
    };
}
BootNativeMethods.EventBatch roundtripEvents = Roundtrip(events);
BootNativeMethods.ValidateEvents(roundtripEvents);
Check(roundtripEvents.Count == 32 && roundtripEvents.Events[31].Sequence == 1265, "all 32 events marshal");
Check(roundtripEvents.Dropped == 0xfedcba9876543210 && roundtripEvents.Events[31].ProcessId == 0x1234567812345678, "64-bit event and dropped fields preserve high bits");
Check(roundtripEvents.Events.All(item => item.Path == new string('경', 519)), "maximum 519-character event paths marshal");
Check(roundtripEvents.Events[31].Offset == 0x100000000 && roundtripEvents.Events[31].Status == 0xc0000022, "event range and NTSTATUS marshal");

BootNativeMethods.SetRequest request = new()
{
    Version = BootNativeMethods.Version,
    Size = 32,
    DeviceId = 0x1234567812345678,
    ExpectedGeneration = 0xfedcba98fedcba98,
    Enabled = 1
};
BootNativeMethods.SetRequest roundtripRequest = Roundtrip(request);
Check(roundtripRequest.DeviceId == request.DeviceId && roundtripRequest.ExpectedGeneration == request.ExpectedGeneration && roundtripRequest.Enabled == 1 && roundtripRequest.Reserved == 0, "SET target and generation marshal");

BootNativeMethods.DeviceList invalidList = BootNativeMethods.CreateDeviceList();
invalidList.Count = 33;
Reject(() => BootNativeMethods.ValidateDevices(invalidList), "device count overflow rejected");
invalidList.Count = 0;
invalidList.Version = 2;
Reject(() => BootNativeMethods.ValidateDevices(invalidList), "device list ABI version mismatch rejected");
invalidList.Version = 1;
invalidList.Size--;
Reject(() => BootNativeMethods.ValidateDevices(invalidList), "device list ABI size mismatch rejected");

BootNativeMethods.DeviceInfo invalidDevice = BootNativeMethods.CreateDeviceInfo();
Reject(() => BootNativeMethods.ValidateDevice(invalidDevice), "zero device identity rejected");
invalidDevice.DeviceId = 1;
invalidDevice.RangeCount = 65;
Reject(() => BootNativeMethods.ValidateDevice(invalidDevice), "range count overflow rejected");
invalidDevice.RangeCount = 0;
invalidDevice.State = 6;
Reject(() => BootNativeMethods.ValidateDevice(invalidDevice), "unknown protection state rejected");

BootNativeMethods.EventBatch invalidEvents = BootNativeMethods.CreateEventBatch();
invalidEvents.Count = 33;
Reject(() => BootNativeMethods.ValidateEvents(invalidEvents), "event count overflow rejected");
invalidEvents.Count = 1;
invalidEvents.Events[0] = events.Events[0];
invalidEvents.Events[0].PathLength = 520;
Reject(() => BootNativeMethods.ValidateEvents(invalidEvents), "unterminated maximum path rejected");
invalidEvents.Events[0].PathLength = 10;
invalidEvents.Events[0].Path = "short";
Reject(() => BootNativeMethods.ValidateEvents(invalidEvents), "path length exceeds supplied string rejected");
invalidEvents.Events[0].Path = string.Empty;
invalidEvents.Events[0].PathLength = 0;
invalidEvents.Events[0].PathStatus = 0xc0000225;
BootNativeMethods.ValidateEvents(invalidEvents);
Check(true, "unknown process path accepted as explicit status");
invalidEvents.Events[0].Version = 2;
Reject(() => BootNativeMethods.ValidateEvents(invalidEvents), "event ABI version mismatch rejected");

const string service = "UF_BootProtectionFactory";
string[] unrelated = ["OtherFilterA", "OtherFilterB"];
string[] attached = BootDriverInstaller.RewriteFilters(unrelated, true);
Check(attached.SequenceEqual(new[] { "OtherFilterA", "OtherFilterB", service }), "attach preserves unrelated filter order");
Check(unrelated.SequenceEqual(new[] { "OtherFilterA", "OtherFilterB" }), "attach does not mutate input list");
Check(BootDriverInstaller.RewriteFilters(attached, true).SequenceEqual(attached), "attach is idempotent");
string[] caseVariant = ["OtherFilterA", "uf_bootprotectionfactory", "OtherFilterB"];
Check(BootDriverInstaller.RewriteFilters(caseVariant, true).SequenceEqual(caseVariant), "attach recognizes existing case-insensitive service");
Check(BootDriverInstaller.RewriteFilters(caseVariant, false).SequenceEqual(unrelated), "detach preserves unrelated filters and order");
Check(BootDriverInstaller.RewriteFilters(unrelated, false).SequenceEqual(unrelated), "detach is idempotent");
Check(BootDriverInstaller.RewriteFilters([], true).SequenceEqual(new[] { service }) && BootDriverInstaller.RewriteFilters([service], false).Length == 0, "empty filter lists handled");
Check(BootDriverInstaller.RewriteFilters([service, "OtherFilterA", service.ToLowerInvariant()], false).SequenceEqual(new[] { "OtherFilterA" }), "detach removes only all own duplicate entries");

using Process current = Process.GetCurrentProcess();
ulong created = (ulong)current.StartTime.ToUniversalTime().ToFileTimeUtc();
Check(string.Equals(BootNativeMethods.TryGetMatchingProcessPath((ulong)current.Id, created),
    Environment.ProcessPath, StringComparison.OrdinalIgnoreCase), "matching process identity resolves its path");
Check(BootNativeMethods.TryGetMatchingProcessPath((ulong)current.Id, created + 1) is null,
    "mismatched creation time does not resolve reused PID");
Check(BootNativeMethods.TryGetMatchingProcessPath(0, created) is null &&
    BootNativeMethods.TryGetMatchingProcessPath((ulong)current.Id, 0) is null &&
    BootNativeMethods.TryGetMatchingProcessPath(ulong.MaxValue, created) is null,
    "unknown or unsupported process identity does not resolve path");

Console.WriteLine($"BootUiChecks: {checks} checks, {failures} failures. No driver installation or device I/O performed.");
return failures == 0 ? 0 : 1;

static T Roundtrip<T>(T value) where T : struct
{
    IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
    bool initialized = false;
    try
    {
        Marshal.StructureToPtr(value, buffer, false);
        initialized = true;
        return Marshal.PtrToStructure<T>(buffer);
    }
    finally
    {
        if (initialized) Marshal.DestroyStructure<T>(buffer);
        Marshal.FreeHGlobal(buffer);
    }
}

namespace RansomUtilFactory.UI
{
    internal static class UiLogger
    {
        internal static void Info(string message) => Console.WriteLine(message);
        internal static void Error(string message, Exception exception) => Console.WriteLine($"{message}: {exception.Message}");
    }

    internal sealed record DriverOperationResult(bool Success, string Message, bool RebootRequired, int? LastError = null);
}
