using System.Runtime.InteropServices;

namespace RansomUtilFactory.UI;

internal static class ProcessNativeMethods
{
    internal const uint ErrorSuccess = 0;
    internal const uint ErrorAlreadyExists = 183;
    internal const uint MatchFullPath = 1;
    internal const uint MatchImageName = 2;
    internal const uint EventCreate = 1;
    internal const uint EventExit = 2;
    internal const uint EventAccess = 3;
    internal const uint ActionBlocked = 2;

    internal static void ValidateAbi()
    {
        if (Marshal.SizeOf<RuleInput>() != 16 ||
            Marshal.SizeOf<PolicyInput>() != 16 ||
            Marshal.SizeOf<MessageHeader>() != 8 ||
            Marshal.SizeOf<StateReply>() != 40 ||
            Marshal.SizeOf<ProcessEvent>() != 600)
        {
            throw new PlatformNotSupportedException(
                "uf_procwarp 통신 구조체의 크기가 x64 ABI와 일치하지 않습니다.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RuleInput
    {
        internal uint RuleId;
        internal uint MatchMode;
        internal IntPtr Image;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PolicyInput
    {
        internal uint RuleCount;
        internal IntPtr Rules;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MessageHeader
    {
        internal uint Version;
        internal uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StateReply
    {
        internal MessageHeader Header;
        internal ulong PolicyGeneration;
        internal uint RuleCount;
        internal uint QueueDepth;
        internal ulong DroppedEvents;
        internal uint Connected;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ProcessEvent
    {
        internal MessageHeader Header;
        internal uint Type;
        internal uint Action;
        internal ulong Sequence;
        internal ulong SystemTime100ns;
        internal ulong PolicyGeneration;
        internal uint ProcessId;
        internal uint ParentProcessId;
        internal uint RequesterProcessId;
        internal uint TargetProcessId;
        internal uint Operation;
        internal uint OriginalDesiredAccess;
        internal uint DesiredAccess;
        internal uint RuleId;
        internal uint ImageLengthChars;
        internal uint Reserved;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string Image;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EventCallback(IntPtr processEvent, IntPtr context);

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcInitialize();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfProcShutdown();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcConnect();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfProcDisconnect();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcReplacePolicy(ref PolicyInput policy);

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcClearPolicy();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcQueryState(ref StateReply state);

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfProcStartEventReceiver(EventCallback callback, IntPtr context);

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfProcStopEventReceiver();

    [DllImport("uf_procwarp.dll", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode)]
    internal static extern uint UfProcGetErrorMessage(
        uint errorCode,
        [Out] char[] message,
        uint messageChars);
}
