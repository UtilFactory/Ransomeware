using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;

// 드라이버가 없는 환경에서 실제 DLL의 실패 경로와 수명을 검증한다. 드라이버 설치·정책 변경은 하지 않는다.
internal static class Program
{
    private const int DeviceListBytes = 64016, DeviceInfoBytes = 2000, EventBatchBytes = 36376;
    private static int checks, failures;
    private static readonly byte[] Sentinel = Enumerable.Repeat((byte)0xa5, DeviceListBytes).ToArray();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint QueryDelegate(IntPtr reply);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint SetDelegate(IntPtr request, IntPtr reply);

    private static int Main(string[] args)
    {
        if (args.Length > 1) { Console.Error.WriteLine("BootNativeChecks [uf_bootwarp.dll 절대 경로]"); return 2; }
        string path = args.Length == 1 ? Path.GetFullPath(args[0]) : Path.Combine(AppContext.BaseDirectory, "uf_bootwarp.dll");
        using (var probe = CreateFileW(@"\\.\UF_BootProtectionFactory", 0xc0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
        {
            int error = Marshal.GetLastWin32Error();
            if (!probe.IsInvalid || !Missing((uint)error))
            {
                Console.Error.WriteLine($"장치 부재 전용 시험입니다. 드라이버가 있거나 상태를 확인할 수 없어 실행하지 않습니다. GetLastError={error}");
                return 2;
            }
        }

        IntPtr module = NativeLibrary.Load(path);
        try
        {
            QueryDelegate query = Marshal.GetDelegateForFunctionPointer<QueryDelegate>(NativeLibrary.GetExport(module, "UfBootQueryDevices"));
            QueryDelegate events = Marshal.GetDelegateForFunctionPointer<QueryDelegate>(NativeLibrary.GetExport(module, "UfBootReadEvents"));
            SetDelegate set = Marshal.GetDelegateForFunctionPointer<SetDelegate>(NativeLibrary.GetExport(module, "UfBootSetProtection"));
            using Buffer list = new(DeviceListBytes), batch = new(EventBatchBytes), reply = new(DeviceInfoBytes), request = new(32);
            Check(query(IntPtr.Zero) == 87, "QUERY NULL 거부");
            Check(events(IntPtr.Zero) == 87, "EVENTS NULL 거부");
            Check(set(IntPtr.Zero, reply.Pointer) == 87, "SET NULL 입력 거부");
            SetRequest(request, 1, 32, 42, 1, 1, 0);
            Check(set(request.Pointer, IntPtr.Zero) == 87, "SET NULL 출력 거부");
            foreach ((uint version, uint size, ulong id, ulong generation, uint enabled, uint reserved) in new[]
            {
                (2u,32u,42ul,1ul,1u,0u), (1u,31u,42ul,1ul,1u,0u), (1u,32u,0ul,1ul,1u,0u),
                (1u,32u,42ul,1ul,2u,0u), (1u,32u,42ul,1ul,1u,1u)
            })
            {
                SetRequest(request, version, size, id, generation, enabled, reserved);
                Check(set(request.Pointer, reply.Pointer) == 87, $"SET 입력 검증 version={version} size={size} id={id} enabled={enabled} reserved={reserved}");
            }
            list.Fill();
            Check(Missing(query(list.Pointer)) && list.IsZero(), "QUERY 장치 없음과 출력 초기화");
            batch.Fill();
            Check(Missing(events(batch.Pointer)) && batch.IsZero(), "EVENTS 장치 없음과 출력 초기화");
            SetRequest(request, 1, 32, 42, 1, 1, 0);
            reply.Fill();
            Check(Missing(set(request.Pointer, reply.Pointer)) && reply.IsZero(), "SET 장치 없음과 출력 초기화");

            _ = query(list.Pointer);
            Check(GetProcessHandleCount(GetCurrentProcess(), out uint before), "핸들 기준 계측");
            Stopwatch clock = Stopwatch.StartNew();
            bool repeatOk = true;
            for (int i = 0; i < 64; i++)
            {
                list.Fill();
                repeatOk &= Missing(query(list.Pointer)) && list.IsZero();
            }
            clock.Stop();
            Check(repeatOk, "순차 QUERY 64회 오류 코드와 출력 보존");
            Check(clock.Elapsed < TimeSpan.FromSeconds(15), $"순차 실패 즉시 복귀 ({clock.ElapsedMilliseconds} ms)");

            (int calls, int unexpected, long maximumMs) = ParallelQueries(query);
            Check(calls == 384 && unexpected == 0, $"병렬 QUERY 16개 스레드·384회 정상 실패/ERROR_BUSY ({unexpected} unexpected)");
            Check(maximumMs < 5000, $"병렬 호출 최대 대기 ({maximumMs} ms)");
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            Thread.Sleep(100);
            Check(GetProcessHandleCount(GetCurrentProcess(), out uint after), "핸들 종료 계측");
            Check(after <= before + 8, $"작업·장치 핸들 회수 before={before} after={after}");
        }
        finally { NativeLibrary.Free(module); }

        Check(GetModuleHandleW("uf_bootwarp.dll") == IntPtr.Zero, "완료 후 DLL 모듈 참조 회수");
        bool reloadOk = true;
        for (int i = 0; i < 12; i++)
        {
            module = NativeLibrary.Load(path);
            try
            {
                QueryDelegate query = Marshal.GetDelegateForFunctionPointer<QueryDelegate>(NativeLibrary.GetExport(module, "UfBootQueryDevices"));
                using Buffer reply = new(DeviceListBytes);
                reloadOk &= Missing(query(reply.Pointer)) && reply.IsZero();
            }
            finally { NativeLibrary.Free(module); }
            reloadOk &= GetModuleHandleW("uf_bootwarp.dll") == IntPtr.Zero;
        }
        Check(reloadOk, "DLL 로드·호출·언로드 12회");
        Console.WriteLine($"Native checks={checks} failed={failures}; 커널 설치·정책 변경 없음. 실제 커널 timeout은 별도 VM 검증 대상입니다.");
        return failures == 0 ? 0 : 1;
    }

    private static (int Calls, int Unexpected, long MaximumMs) ParallelQueries(QueryDelegate query)
    {
        const int workers = 16;
        using CountdownEvent ready = new(workers);
        using ManualResetEventSlim start = new(false);
        ConcurrentQueue<Exception> errors = new();
        int calls = 0, unexpected = 0;
        long maximumMs = 0;
        Thread[] threads = Enumerable.Range(0, workers).Select(_ => new Thread(() =>
        {
            using Buffer reply = new(DeviceListBytes);
            ready.Signal(); start.Wait();
            try
            {
                for (int i = 0; i < 24; i++)
                {
                    reply.Fill();
                    Stopwatch clock = Stopwatch.StartNew();
                    uint result = query(reply.Pointer);
                    clock.Stop();
                    if ((!Missing(result) && result != 170) || !reply.IsZero()) Interlocked.Increment(ref unexpected);
                    Interlocked.Increment(ref calls);
                    long previous;
                    do { previous = Volatile.Read(ref maximumMs); }
                    while (clock.ElapsedMilliseconds > previous &&
                        Interlocked.CompareExchange(ref maximumMs, clock.ElapsedMilliseconds, previous) != previous);
                }
            }
            catch (Exception ex) { errors.Enqueue(ex); }
        }) { IsBackground = true }).ToArray();
        foreach (Thread thread in threads) thread.Start();
        ready.Wait(); start.Set();
        foreach (Thread thread in threads) thread.Join();
        return (calls, unexpected + errors.Count, maximumMs);
    }

    private static bool Missing(uint error) => error is 2 or 3;
    private static void Check(bool passed, string name)
    {
        checks++; if (!passed) failures++;
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {name}");
    }
    private static void SetRequest(Buffer buffer, uint version, uint size, ulong id, ulong generation, uint enabled, uint reserved)
    {
        Marshal.WriteInt32(buffer.Pointer, 0, (int)version);
        Marshal.WriteInt32(buffer.Pointer, 4, (int)size);
        Marshal.WriteInt64(buffer.Pointer, 8, (long)id);
        Marshal.WriteInt64(buffer.Pointer, 16, (long)generation);
        Marshal.WriteInt32(buffer.Pointer, 24, (int)enabled);
        Marshal.WriteInt32(buffer.Pointer, 28, (int)reserved);
    }
    private sealed class Buffer(int size) : IDisposable
    {
        internal IntPtr Pointer { get; } = Marshal.AllocHGlobal(size);
        internal void Fill() => Marshal.Copy(Sentinel, 0, Pointer, size);
        internal bool IsZero()
        {
            byte[] data = new byte[size];
            Marshal.Copy(Pointer, data, 0, size);
            return data.All(value => value == 0);
        }
        public void Dispose() => Marshal.FreeHGlobal(Pointer);
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessHandleCount(IntPtr process, out uint count);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string name);
}
