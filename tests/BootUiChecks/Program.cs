using System.Reflection;
using System.Runtime.InteropServices;
using RansomUtilFactory.UI;

int checks = 0;
int failures = 0;
void Check(bool condition, string description)
{
    ++checks;
    if (!condition) ++failures;
    Console.WriteLine($"{(condition ? "통과" : "실패")}: {description}");
}
void Reject(NativeMethods.BootProtectionState state, string description)
{
    try { FileProtectionPresentation.ValidateState(state); Check(false, description); }
    catch (InvalidDataException) { Check(true, description); }
}

NativeMethods.ValidateAbi();
Check(Marshal.SizeOf<NativeMethods.BootProtectionState>() == 40, "선두 영역 상태 ABI 40바이트");
foreach ((string field, int offset) in new[]
{
    ("Version", 0), ("Size", 4), ("Enabled", 8), ("ProtectedBytes", 12),
    ("InspectedWrites", 16), ("BlockedWrites", 24), ("InspectionFailures", 32)
})
    Check(Marshal.OffsetOf<NativeMethods.BootProtectionState>(field).ToInt32() == offset, $"필드 {field} 오프셋 {offset}");
Check(Marshal.SizeOf<NativeMethods.FileEventV2>() == 1632, "기존 파일 V2 이벤트 ABI 유지");
NativeMethods.BootProtectionState state = NativeMethods.CreateBootProtectionState();
Check(state.Version == 2 && state.Size == 40 && state.Enabled == 0 && state.ProtectedBytes == 2048, "규약 V2·2 KiB·기본 정지 입력");
FileProtectionPresentation.ValidateState(state);
Check(FileProtectionPresentation.Status(state).StartsWith("정지"), "조회에서 확인된 정지 표시");
state.Enabled = 1;
state.InspectedWrites = ulong.MaxValue;
state.BlockedWrites = 2500;
state.InspectionFailures = 3;
FileProtectionPresentation.ValidateState(state);
Check(FileProtectionPresentation.Status(state).StartsWith("보호 중"), "조회에서 확인된 활성 표시");
Check(FileProtectionPresentation.Counters(state).Contains("검사 실패(통과) 3회"), "검사 실패는 통과로 표시");
IntPtr memory = Marshal.AllocHGlobal(40);
try
{
    Marshal.StructureToPtr(state, memory, false);
    NativeMethods.BootProtectionState copy = Marshal.PtrToStructure<NativeMethods.BootProtectionState>(memory);
    Check(copy.InspectedWrites == ulong.MaxValue && copy.BlockedWrites == 2500 && copy.InspectionFailures == 3, "64비트 카운터 왕복");
}
finally { Marshal.FreeHGlobal(memory); }
NativeMethods.BootProtectionState invalid = state;
invalid.Version = 1; Reject(invalid, "구버전 상태 거부");
invalid = state; invalid.Size = 32; Reject(invalid, "상태 크기 불일치 거부");
invalid = state; invalid.Enabled = 2; Reject(invalid, "활성 불리언 범위 검증");
invalid = state; invalid.ProtectedBytes = 4096; Reject(invalid, "다른 보호 범위를 2 KiB로 표시하지 않음");
Check(FileProtectionPresentation.Status(null).Contains("상태 미확인") &&
    !FileProtectionPresentation.Status(null).StartsWith("정지"), "실패·연결 해제는 정지가 아닌 미확인");
Check(FileProtectionPresentation.Counters(null).Contains("미확인"), "조회 실패 시 카운터 0으로 위장하지 않음");
Check(FileProtectionPresentation.Action(5) == "부트 영역 차단", "Action 5 차단");
Check(FileProtectionPresentation.Action(6) == "부트 검사 실패(통과)", "Action 6 실패·통과");
Check(FileProtectionPresentation.Action(99).StartsWith("알 수 없음"), "알 수 없는 Action을 차단으로 오인하지 않음");
Check(FileProtectionPresentation.Action(1) == "감시" && FileProtectionPresentation.Action(2) == "차단" &&
    FileProtectionPresentation.Action(3) == "검증 요청" && FileProtectionPresentation.Action(4) == "서명 폐기", "기존 Action 유지");
Check(FileProtectionPresentation.Error(1460).Contains("GetLastError=1460 (0x000005B4"), "시간 초과 코드 표시");
Check(FileProtectionPresentation.ErrorCode(new EntryPointNotFoundException()) == 127, "구 DLL 미지원 API 오류");
Check(FileProtectionPresentation.ErrorCode(new DllNotFoundException()) == 126, "DLL 없음 오류");
Check(FileProtectionPresentation.ErrorCode(new TimeoutException()) == 1460, "시간 초과 예외 코드");
foreach (string name in new[] { "UfFltSetBootProtection", "UfFltQueryBootProtection" })
{
    MethodInfo method = typeof(NativeMethods).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!;
    DllImportAttribute import = method.GetCustomAttribute<DllImportAttribute>()!;
    Check(import.Value == "uf_fltwarp.dll" && import.CallingConvention == CallingConvention.StdCall &&
        method.ReturnType == typeof(uint), $"{name}: 기존 DLL·stdcall·DWORD 반환");
}
MethodInfo set = typeof(NativeMethods).GetMethod("UfFltSetBootProtection", BindingFlags.Static | BindingFlags.NonPublic)!;
Check(set.GetParameters()[0].GetCustomAttribute<MarshalAsAttribute>()?.Value == UnmanagedType.Bool, "BOOL은 4바이트 마샬링");
MethodInfo query = typeof(NativeMethods).GetMethod("UfFltQueryBootProtection", BindingFlags.Static | BindingFlags.NonPublic)!;
Check(query.GetParameters()[0].ParameterType == typeof(NativeMethods.BootProtectionState).MakeByRefType(), "QUERY 상태 포인터 ABI");
Console.WriteLine($"BootUiChecks: {checks}개 검사, {failures}개 실패. 드라이버 설치·연결·디스크 I/O 없음.");
return failures == 0 ? 0 : 1;
