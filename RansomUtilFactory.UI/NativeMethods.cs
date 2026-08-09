using System.Runtime.InteropServices;

using System.Text;

namespace RansomUtilFactory.UI;

internal static class NativeMethods
{
    internal const uint ErrorSuccess = 0;
    internal const uint ErrorAlreadyExists = 183;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint UfRuleMonitor = 1;
    internal const uint UfRuleProtected = 2;
    internal const uint UfEventDenied = 2;
    internal const ushort PfAccessRead = 0x0001;
    internal const ushort PfAccessWrite = 0x0002;
    internal const ushort PfAccessAll = 0x0003;
    internal const uint UfSignerMatchThumbprintSha256 = 1;
    internal const ushort UfProcessRuleFlagRequireCodeSignature = 0x0001;
    internal const ushort UfTrustAllow = 1;
    internal const ushort UfTrustDeny = 2;
    internal const uint UfRevocationTimeoutDeny = 0;
    internal const uint UfRevocationTimeoutAllowLocalTrust = 1;

    internal static void ValidateAbi()
    {
        if (Marshal.SizeOf<PathInput>() != 16 ||
            Marshal.SizeOf<PolicyInput>() != 48 ||
            Marshal.SizeOf<FileEvent>() != 1592 ||
            Marshal.SizeOf<FileEventV2>() != 1632 ||
            Marshal.SizeOf<PathInputV2>() != 16 ||
            Marshal.SizeOf<ProtectedProcessRule>() != 540 ||
            Marshal.SizeOf<SignerRule>() != 112 ||
            Marshal.SizeOf<PolicyInputV2>() != 88 ||
            Marshal.SizeOf<SignerIdentity>() != 632)
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct PathInputV2
    {
        internal uint RuleId;
        internal uint Mode;
        internal IntPtr DosPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ProtectedProcessRule
    {
        internal uint RuleId;
        internal uint FolderRuleId;
        internal uint SignerRuleId;
        internal ushort Access;
        internal ushort Reserved16;
        internal uint ImageLengthChars;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string Image;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SignerRule
    {
        internal uint RuleId;
        internal uint MatchType;
        internal uint SerialLengthBytes;
        internal uint Reserved;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] ThumbprintSha256;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] IssuerSha256;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] SerialNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PolicyInputV2
    {
        internal ulong PolicyGeneration;
        internal uint PathRuleCount;
        internal IntPtr PathRules;
        internal uint MonitorExceptionCount;
        internal IntPtr MonitorExceptions;
        internal uint ProtectedProcessRuleCount;
        internal IntPtr ProtectedProcesses;
        internal uint SignerRuleCount;
        internal IntPtr Signers;
        internal uint OnlineRevocationEnabled;
        internal uint RevocationTimeoutMilliseconds;
        internal uint RevocationTimeoutAction;
        internal uint TerminateOnRevoked;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SignerIdentity
    {
        internal uint Size;
        internal uint Trusted;
        internal uint SerialLengthBytes;
        internal uint Reserved;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] ThumbprintSha256;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] IssuerSha256;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        internal byte[] SerialNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string Subject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessTrustInput
    {
        internal ulong PolicyGeneration;
        internal ulong ProcessCreateTime;
        internal uint ProcessId;
        internal uint ProcessRuleId;
        internal ushort Access;
        internal ushort Decision;
        internal uint Temporary;
        internal IntPtr SignerIdentity;
    }

    internal static SignerIdentity CreateSignerIdentity()
    {
        return new SignerIdentity
        {
            Size = (uint)Marshal.SizeOf<SignerIdentity>(),
            ThumbprintSha256 = new byte[32],
            IssuerSha256 = new byte[32],
            SerialNumber = new byte[32],
            Subject = string.Empty
        };
    }

    internal static string? TryGetProcessImagePath(uint processId)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            StringBuilder buffer = new(1024);
            uint length = (uint)buffer.Capacity;
            return QueryFullProcessImageName(process, 0, buffer, ref length)
                ? buffer.ToString(0, (int)length)
                : null;
        }
        finally
        {
            CloseHandle(process);
        }
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FileEventV2
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

        internal uint Operation;
        internal uint FolderRuleId;
        internal uint ProcessRuleId;
        internal ushort RequestedAccess;
        internal ushort TrustDecision;
        internal uint Reserved;
        internal ulong ProcessCreateTime;
        internal ulong PolicyGeneration;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EventCallback(IntPtr fileEvent, IntPtr context);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EventCallbackV2(IntPtr fileEvent, IntPtr context);

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
    internal static extern uint UfFltReplacePolicyV2(ref PolicyInputV2 policy);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltSetProcessTrust(ref ProcessTrustInput trust);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltClearPolicy();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltStartEventReceiver(EventCallback callback, IntPtr context);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern uint UfFltStartEventReceiverV2(EventCallbackV2 callback, IntPtr context);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode)]
    internal static extern uint UfFltGetImageSignerIdentityWithTimeout(
        string imagePath,
        int onlineRevocation,
        uint timeoutMilliseconds,
        ref SignerIdentity identity);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        [Out] StringBuilder imagePath,
        ref uint imagePathLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void UfFltStopEventReceiver();

    [DllImport("uf_fltwarp.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal static extern uint UfFltGetErrorMessage(
        uint errorCode,
        [Out] char[] message,
        uint messageChars);
}
