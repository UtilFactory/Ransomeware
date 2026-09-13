using System.Diagnostics;
using System.Runtime.InteropServices;

// 접속 API를 호출하지 않는 새 프로세스에서 입력 검증과 미연결 실패만 확인한다.
// 드라이버가 설치되어 있어도 이 시험은 커널 정책을 변경하지 않는다.
internal static class Program
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Query(IntPtr state);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Set(int enabled);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate int Connected();
    private static int checks, failures;
    private static void Check(bool valid, string label)
    {
        checks++; if (!valid) failures++;
        Console.WriteLine($"{(valid ? "PASS" : "FAIL")} {label}");
    }
    private static int Main(string[] args)
    {
        if (args.Length != 1) { Console.Error.WriteLine("FileBootNativeChecks <uf_fltwarp.dll 절대 경로>"); return 2; }
        nint module = NativeLibrary.Load(Path.GetFullPath(args[0]));
        nint buffer = Marshal.AllocHGlobal(56);
        try
        {
            Query query = Marshal.GetDelegateForFunctionPointer<Query>(NativeLibrary.GetExport(module, "UfFltQueryBootProtection"));
            Set set = Marshal.GetDelegateForFunctionPointer<Set>(NativeLibrary.GetExport(module, "UfFltSetBootProtection"));
            Connected connected = Marshal.GetDelegateForFunctionPointer<Connected>(NativeLibrary.GetExport(module, "UfFltIsConnected"));
            if (connected() != 0) throw new InvalidOperationException("미연결 전용 시험 조건을 만족하지 않습니다.");
            Check(query(0) == 87, "NULL 조회 출력 거부");
            foreach (int invalid in new[] { -1, 2, int.MinValue, int.MaxValue })
                Check(set(invalid) == 87, $"잘못된 Enabled={invalid} 거부");
            Check(set(0) == 6, "미연결 정지 요청 INVALID_HANDLE");
            Check(set(1) == 6, "미연결 시작 요청 INVALID_HANDLE");
            byte[] sentinel = Enumerable.Repeat((byte)0xa5, 56).ToArray();
            Marshal.Copy(sentinel, 0, buffer, 56);
            Check(query(buffer + 8) == 6, "미연결 조회 INVALID_HANDLE");
            byte[] result = new byte[56];
            Marshal.Copy(buffer, result, 0, 56);
            Check(result.Take(8).All(b => b == 0xa5) && result.Skip(48).All(b => b == 0xa5), "40바이트 출력 경계 보존");
            Check(result.Skip(8).Take(40).All(b => b == 0), "실패 시 전체 상태 초기화");
            Stopwatch watch = Stopwatch.StartNew();
            bool repeat = true;
            for (int i = 0; i < 64; i++) repeat &= query(buffer + 8) == 6;
            Check(repeat, "64회 미연결 조회 일관성");
            Check(watch.Elapsed < TimeSpan.FromSeconds(5), "미연결 요청 즉시 복귀");
            Check(connected() == 0, "시험 후에도 미연결");
        }
        finally { Marshal.FreeHGlobal(buffer); NativeLibrary.Free(module); }
        Console.WriteLine($"File boot native checks={checks} failed={failures}; no driver connection or policy change.");
        return failures == 0 ? 0 : 1;
    }
}
