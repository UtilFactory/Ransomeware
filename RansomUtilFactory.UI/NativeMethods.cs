using System.Runtime.InteropServices;

namespace RansomUtilFactory.UI;

internal static class NativeMethods
{
    internal const uint ErrorSuccess = 0;
    internal const uint ErrorAlreadyExists = 183;
    internal const uint UfRuleMonitor = 1;
    internal const uint UfRuleAllowList = 2;
    internal const uint UfEventDenied = 2;

    internal static void ValidateAbi()
    {
        if (Marshal.SizeOf<PathInput>() != 16 ||
            Marshal.SizeOf<PolicyInput>() != 48 ||
            Marshal.SizeOf<FileEvent>() != 1592)
        {
            throw new PlatformNotSupportedException("uf_fltwarp 통신 구조체의 크기가 x64 ABI와 일치하지 않습니다.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PathInput
    {
        internal uint Mode;
        internal IntPtr DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PolicyInput
    {
        internal uint PathRuleCount;
        internal IntPtr PathRules;
        internal uint MonitorExceptionCount;
        internal IntPtr MonitorExceptions;
        internal uint AllowedImageCount;
        internal IntPtr AllowedImages;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FileEvent
    {
        internal uint Version;
        internal uint Size;
        internal uint ProcessId;
        internal uint DesiredAccess;
        internal uint Disposition;
        internal uint Action;
        internal uint PathLengthChars;
        internal uint ImageLengthChars;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
        internal string Path;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string Image;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EventCallback(IntPtr fileEvent, IntPtr context);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltInitialize();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfFltShutdown();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltConnect();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfFltDisconnect();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltReplacePolicy(ref PolicyInput policy);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltClearPolicy();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltStartEventReceiver(EventCallback callback, IntPtr context);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfFltStopEventReceiver();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern uint UfFltGetErrorMessage(
        uint errorCode,
        [Out] char[] message,
        uint messageChars);
}
