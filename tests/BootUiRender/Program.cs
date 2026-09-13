using System.Collections;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml.Linq;

internal static class Program
{
    private const BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("사용법: BootUiRender <RansomUtilFactory.UI.dll 전체 경로> <PNG 출력 폴더>");
            return 2;
        }
        try
        {
            string assemblyPath = Path.GetFullPath(args[0]);
            string directory = Path.GetDirectoryName(assemblyPath)!;
            string output = Path.GetFullPath(args[1]);
            Directory.CreateDirectory(output);
            AssemblyLoadContext.Default.Resolving += (_, name) =>
            {
                string path = Path.Combine(directory, name.Name + ".dll");
                return File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
            };
            Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
            // 실제 리소스만 읽고 자동 창 생성·드라이버 초기화는 실행하지 않는다.
            Application application = new();
            XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
            XElement resources = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "BootUiRender.App.xaml"))
                .Root!.Element(wpf + "Application.Resources")!;
            application.Resources = (ResourceDictionary)XamlReader.Parse(
                "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">" +
                string.Concat(resources.Elements().Select(element => element.ToString())) + "</ResourceDictionary>");
            Type windowType = assembly.GetType("RansomUtilFactory.UI.MainWindow", true)!;
            Window window = (Window)Activator.CreateInstance(windowType)!;
            window.RemoveHandler(FrameworkElement.LoadedEvent, Delegate.CreateDelegate(typeof(RoutedEventHandler),
                window, windowType.GetMethod("Window_Loaded", PrivateInstance)!));
            window.Closing -= (System.ComponentModel.CancelEventHandler)Delegate.CreateDelegate(
                typeof(System.ComponentModel.CancelEventHandler), window, windowType.GetMethod("Window_Closing", PrivateInstance)!);
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(window.Dispatcher));
            FrameworkElement root = (FrameworkElement)window.Content;
            root.DataContext = window;
            if (root is Panel panel) panel.Background = Brushes.White;
            window.Content = null;
            TabControl tabs = (TabControl)window.FindName("MainTabs");
            Check(tabs.Items.Count == 2 && ((TabItem)tabs.Items[0]).Header.ToString() == "파일 제어" &&
                ((TabItem)tabs.Items[1]).Header.ToString() == "프로세스 제어", "파일·프로세스 두 탭만 유지");
            Check(window.FindName("BootDriverConnectionIndicator") is null &&
                window.FindName("BootDeviceList") is null && window.FindName("InstallBootDriverButton") is null,
                "별도 디스크 연결·선택·설치 UI 없음");
            tabs.SelectedIndex = 0;
            SetField(window, "_connected", true);
            IList logs = (IList)windowType.GetProperty("EventLogs")!.GetValue(window)!;
            SendEvent(assembly, window, 5, 4321, @"C:\Test\unregistered-writer.exe");
            SendEvent(assembly, window, 6, 4322, @"C:\Test\inspection-failed.exe");
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Check(logs.Count == 2, "미등록 프로세스 부트 사건 두 종류 모두 표시");
            object failed = logs[0]!;
            Check((string)failed.GetType().GetProperty("Action")!.GetValue(failed)! == "부트 검사 실패(통과)" &&
                (string)failed.GetType().GetProperty("Image")!.GetValue(failed)! == @"C:\Test\inspection-failed.exe" &&
                (uint)failed.GetType().GetProperty("ProcessId")!.GetValue(failed)! == 4322,
                "검사 실패 통과·페이로드 PID·이미지 경로 보존");

            // 네이티브 진입 전 게이트를 잠가 중복 요청과 연결 변경 취소만 안전하게 검증한다.
            SemaphoreSlim gate = (SemaphoreSlim)windowType.GetField("_fileNativeGate", PrivateInstance)!.GetValue(window)!;
            gate.Wait();
            MethodInfo begin = windowType.GetMethod("BeginBootProtectionOperationAsync", PrivateInstance)!;
            Task pending = (Task)begin.Invoke(window, new object?[] { true })!;
            Task duplicate = (Task)begin.Invoke(window, new object?[] { false })!;
            Check(!pending.IsCompleted && duplicate.IsCompleted, "설정·조회 단일 실행과 중복 요청 거부");
            Check(!Button(window, "StartBootProtectionButton").IsEnabled &&
                !Button(window, "StopBootProtectionButton").IsEnabled &&
                !Button(window, "RefreshBootProtectionButton").IsEnabled, "진행 중 보호 버튼 모두 비활성");
            SetField(window, "_connected", false);
            SetField(window, "_fileConnectionVersion", 1);
            windowType.GetMethod("SetConnectionState", PrivateInstance)!.Invoke(window, new object[] { false });
            gate.Release();
            PumpUntil(pending);
            Check(Text(window, "BootProtectionStatusText").Text.StartsWith("상태 미확인") &&
                !Button(window, "StartBootProtectionButton").IsEnabled, "지연 결과가 연결 해제 후 상태를 복원하지 않음");
            Check(!(bool)windowType.GetField("_bootOperationRunning", PrivateInstance)!.GetValue(window)!, "취소 후 실행 중 상태 해제");
            SetField(window, "_closing", true);
            SendEvent(assembly, window, 5, 9999, @"C:\Test\late-event.exe");
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            Check(logs.Count == 2, "종료 중 지연 이벤트 무시");
            SetField(window, "_closing", false);

            for (int index = 0; index < 35; ++index)
            {
                object sample = logs[index % 2]!;
                logs.Add(sample);
            }
            foreach ((int width, int height) in new[] { (1120, 820), (900, 580) })
            {
                foreach (string state in new[] { "active", "stopped", "timeout", "disconnected" })
                {
                    bool connected = state != "disconnected";
                    SetText(window, "FileDriverConnectionText", connected ? "파일 필터: 연결됨" : "파일 필터: 연결 안 됨");
                    ((System.Windows.Shapes.Ellipse)window.FindName("FileDriverConnectionIndicator")).Fill = connected ? Brushes.Green : Brushes.DarkRed;
                    Text(window, "BootProtectionStatusText").Foreground = state == "active" ? Brushes.DarkGreen : state == "stopped" ? Brushes.DimGray : Brushes.DarkOrange;
                    SetText(window, "BootProtectionStatusText", state switch
                    {
                        "active" => "보호 중 · 선두 2 KiB 변경 비교",
                        "stopped" => "정지 · 선두 2 KiB 보호 꺼짐",
                        _ => "상태 미확인 · 보호가 정지했다는 뜻이 아닙니다."
                    });
                    SetText(window, "BootProtectionCountersText", state is "active" or "stopped"
                        ? "검사 12,345회 · 차단 123회 · 검사 실패(통과) 4회" : "검사·차단·검사 실패 횟수: 미확인");
                    SetText(window, "BootProtectionCommandText", state switch
                    {
                        "timeout" => "보호 시작 실패: GetLastError=1460 (0x000005B4, 제한 시간이 만료되었습니다.)\n상태 조회 실패: GetLastError=1460 · 자동 재설정하지 않습니다.",
                        "disconnected" => "파일 필터 연결 해제 · 보호 상태는 재연결 후 조회해야 합니다. 연결 해제는 보호 정지가 아닙니다.",
                        _ => "조회 결과를 표시합니다. 연결 해제·폴더 정책 초기화는 보호를 정지하지 않습니다."
                    });
                    Button(window, "StartBootProtectionButton").IsEnabled = connected && state != "active";
                    Button(window, "StopBootProtectionButton").IsEnabled = connected && state != "stopped";
                    Button(window, "RefreshBootProtectionButton").IsEnabled = connected;
                    Render(window, root, output, width, height, state);
                    if (state == "active") Render(window, root, output, width, height, state + "-events", showEvents: true);
                }
            }
            Check(!(bool)windowType.GetField("_fileInitialized", PrivateInstance)!.GetValue(window)!,
                "레이아웃 시험에서 네이티브 드라이버 초기화를 수행하지 않음");
            Console.WriteLine("BootUiRender: 10개 레이아웃과 합성 사건·중복 요청·지연 취소 검사 통과. 창 표시·드라이버 연결·설치·디스크 I/O 없음.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void SendEvent(Assembly assembly, Window window, uint action, uint pid, string image)
    {
        Type type = assembly.GetType("RansomUtilFactory.UI.NativeMethods+FileEventV2", true)!;
        object data = Activator.CreateInstance(type)!;
        foreach ((string name, object value) in new (string, object)[]
        {
            ("Version", 2u), ("Size", (uint)Marshal.SizeOf(type)), ("Action", action), ("ProcessId", pid),
            ("Image", image), ("ImageLengthChars", (uint)image.Length), ("Path", @"\Device\HarddiskVolume2"),
            ("PathLengthChars", 23u), ("Operation", 2u)
        }) type.GetField(name, PrivateInstance)!.SetValue(data, value);
        IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(type));
        try
        {
            Marshal.StructureToPtr(data, memory, false);
            window.GetType().GetMethod("ReceiveFileEvent", PrivateInstance)!.Invoke(window, new object[] { memory, IntPtr.Zero });
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static void PumpUntil(Task task)
    {
        DispatcherFrame frame = new();
        DateTime deadline = DateTime.UtcNow.AddSeconds(5);
        DispatcherTimer timer = new() { Interval = TimeSpan.FromMilliseconds(10) };
        timer.Tick += (_, _) => { if (task.IsCompleted || DateTime.UtcNow > deadline) frame.Continue = false; };
        timer.Start();
        Dispatcher.PushFrame(frame);
        timer.Stop();
        Check(task.IsCompletedSuccessfully, "취소 요청이 네이티브 호출 없이 완료");
    }

    private static void Render(Window window, FrameworkElement root, string output, int width, int height, string state, bool showEvents = false)
    {
        ScrollViewer scroll = (ScrollViewer)window.FindName("FileTabScrollViewer");
        scroll.ScrollToTop();
        root.InvalidateMeasure();
        Text(window, "BootProtectionCommandText").InvalidateMeasure();
        for (int pass = 0; pass < 2; ++pass)
        {
            root.Dispatcher.Invoke(() => { }, DispatcherPriority.DataBind);
            root.Measure(new Size(width, height));
            root.Arrange(new Rect(0, 0, width, height));
            root.UpdateLayout();
        }
        if (showEvents)
        {
            scroll.ScrollToBottom();
            root.UpdateLayout();
        }
        FrameworkElement content = (FrameworkElement)window.FindName("FileTabContent");
        foreach ((string left, string right) in new[]
        {
            ("StartBootProtectionButton", "StopBootProtectionButton"),
            ("StopBootProtectionButton", "RefreshBootProtectionButton")
        })
        {
            Rect first = Bounds(Button(window, left), content);
            Rect second = Bounds(Button(window, right), content);
            Check(!first.IntersectsWith(second) && first.Width > 0 && second.Width > 0 &&
                first.Left >= 0 && second.Right <= content.ActualWidth &&
                first.Top >= 0 && second.Bottom <= content.ActualHeight, $"버튼 겹침·잘림 없음 {width}x{height} {state}");
        }
        Rect log = Bounds((FrameworkElement)window.FindName("FileEventGrid"), content);
        Check(log.Height >= 70 && log.Bottom <= content.ActualHeight + 1, $"로그 높이·하단 영역 유지 {width}x{height} {state}");
        Check(content.ActualHeight <= scroll.ViewportHeight + 1 ||
            scroll.ScrollableHeight >= content.ActualHeight - scroll.ViewportHeight - 1, "작은 창 하단 스크롤 가능");
        RenderTargetBitmap bitmap = new(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(root);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string path = Path.Combine(output, $"file-boot-ui-{width}x{height}-{state}.png");
        using FileStream file = File.Create(path);
        encoder.Save(file);
        Console.WriteLine($"레이아웃 저장: {path}");
    }

    private static void Check(bool value, string description)
    {
        if (!value) throw new InvalidOperationException(description);
        Console.WriteLine($"통과: {description}");
    }
    private static void SetField(Window window, string name, object value) =>
        window.GetType().GetField(name, PrivateInstance)!.SetValue(window, value);
    private static TextBlock Text(Window window, string name) => (TextBlock)window.FindName(name);
    private static void SetText(Window window, string name, string value) => Text(window, name).Text = value;
    private static Button Button(Window window, string name) => (Button)window.FindName(name);
    private static Rect Bounds(FrameworkElement element, Visual root) =>
        element.TransformToAncestor(root).TransformBounds(new Rect(element.RenderSize));
}
