using System.Collections;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Markup;
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
            // 실제 App.xaml의 리소스만 읽어 자동 창 생성용 StartupUri를 등록하지 않는다.
            Application application = new();
            XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
            XElement resources = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "BootUiRender.App.xaml"))
                .Root!.Element(wpf + "Application.Resources")!;
            string resourceXaml = "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">" +
                string.Concat(resources.Elements().Select(element => element.ToString())) + "</ResourceDictionary>";
            application.Resources = (ResourceDictionary)XamlReader.Parse(resourceXaml);
            Type windowType = assembly.GetType("RansomUtilFactory.UI.MainWindow", true)!;
            Window window = (Window)Activator.CreateInstance(windowType)!;

            // 창을 띄우지 않으며, 혹시 레이아웃이 수명 주기 이벤트를 발생시켜도 드라이버 함수는 호출하지 않는다.
            MethodInfo loaded = windowType.GetMethod("Window_Loaded", PrivateInstance)!;
            window.RemoveHandler(FrameworkElement.LoadedEvent,
                Delegate.CreateDelegate(typeof(RoutedEventHandler), window, loaded));
            MethodInfo closing = windowType.GetMethod("Window_Closing", PrivateInstance)!;
            window.Closing -= (System.ComponentModel.CancelEventHandler)Delegate.CreateDelegate(
                typeof(System.ComponentModel.CancelEventHandler), window, closing);
            FrameworkElement root = (FrameworkElement)window.Content;
            root.DataContext = window;
            if (root is Panel panel) panel.Background = window.Background ?? Brushes.White;
            window.Content = null;
            // 창에서 분리한 뒤에도 실제 XAML의 ElementName 바인딩을 유지한다.
            NameScope names = new();
            names.RegisterName("BootTabScrollViewer", window.FindName("BootTabScrollViewer"));
            names.RegisterName("BootSetupExpander", window.FindName("BootSetupExpander"));
            NameScope.SetNameScope(root, names);
            TabControl tabs = Descendants(root).OfType<TabControl>().Single();
            tabs.SelectedIndex = 2;
            ((TabItem)tabs.Items[2]).Header = "부트 영역 방어 · 레이아웃 시험";
            SetText(window, "BootDriverConnectionText", "부트 필터: 통신 정상 · 부착 1개");
            ((System.Windows.Shapes.Ellipse)window.FindName("BootDriverConnectionIndicator")).Fill = Brushes.SeaGreen;
            ComboBox candidates = (ComboBox)window.FindName("BootCandidateList");
            candidates.ItemsSource = new[] { new { DisplayName = "디스크 2 · 256 MiB · VHDX · 필터 등록됨" } };
            candidates.SelectedIndex = 0;
            ComboBox devices = (ComboBox)window.FindName("BootDeviceList");
            devices.ItemsSource = new[] { new { DisplayName = "디스크 2 · 256 MiB · 방어 중 · ID 123456" } };
            devices.SelectedIndex = 0;
            ((DataGrid)window.FindName("BootRangeGrid")).ItemsSource = new[]
            {
                new { Kind = "MBR", Offset = "0", Length = "512", End = "512" },
                new { Kind = "NTFS", Offset = "1,048,576", Length = "8,192", End = "1,056,768" },
                new { Kind = "NTFS", Offset = "267,386,368", Length = "512", End = "267,386,880" }
            };
            ((DataGrid)window.FindName("BootEventGrid")).ItemsSource = Enumerable.Range(0, 40).Select(index => new
            {
                Time = "2026-09-14 17:20:30.123",
                Action = index % 5 == 0 ? "상태 변경" : "쓰기 차단",
                Device = "디스크 2",
                Kind = "NTFS",
                ProcessId = "12345",
                Path = @"C:\Users\시험사용자\Desktop\bin\UF_BootProtectionTest.exe",
                PathSource = "사용자 모드 (생성 시각 일치) · 커널 NTSTATUS=0xC0000225",
                Offset = "1,048,576",
                Length = "512",
                Status = "0xC0000022",
                Ioctl = "—",
                Generation = 7,
                Sequence = 40 - index,
                ProcessCreated = "2026-09-14 17:19:28.888"
            }).ToArray();
            SetText(window, "BootEventStatusText", "레이아웃 검증용 합성 데이터 · 표시 40/2,000개 · 커널 누적 유실 0개");
            foreach (string name in new[] { "InstallBootDriverButton", "RefreshBootButton", "AttachBootFilterButton", "DetachBootFilterButton", "StartBootProtectionButton", "StopBootProtectionButton" })
            {
                ((Button)window.FindName(name)).IsEnabled = true;
            }

            foreach ((int width, int height) in new[] { (1120, 720), (900, 580) })
            {
                SetText(window, "BootInstallStatusText", "선택한 VHDX에 필터를 등록했습니다. VHDX 재부착 후 커널 장치 목록을 새로 고침하십시오. 방어 시작은 별도입니다.");
                SetText(window, "BootProtectionStatusText", "디스크 2: 방어 중 · 보호 범위 3개 · 차단 123회 · 정책 세대 7 · NTSTATUS=0x00000000");
                SetText(window, "BootCommandStatusText", "부트 영역 방어 시작 응답: 방어 중");
                Render(window, root, output, width, height, "active");
                SetText(window, "BootProtectionStatusText", "보호 상태 확인 불가 · GetLastError=1460 (0x000005B4, 제한 시간이 만료되어 작업이 반환되었습니다.)");
                SetText(window, "BootCommandStatusText", "부트 영역 방어 시작 실패: GetLastError=1460 · 현재 상태를 다시 조회합니다. 마지막 응답만으로 정지를 판정하지 않습니다.");
                Render(window, root, output, width, height, "timeout");
            }
            ((Expander)window.FindName("BootSetupExpander")).IsExpanded = true;
            Render(window, root, output, 1120, 720, "setup-expanded");
            Render(window, root, output, 900, 580, "setup-expanded");
            if ((bool)windowType.GetField("_bootAbiValid", PrivateInstance)!.GetValue(window)! ||
                (bool)windowType.GetField("_bootRefreshing", PrivateInstance)!.GetValue(window)!)
            {
                throw new InvalidOperationException("레이아웃 시험 중 부트 컨트롤 초기화가 실행되었습니다.");
            }
            Console.WriteLine("BootUiRender: 6 layouts rendered. No Window.Show, Loaded handler, native driver connection or installation.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void SetText(Window window, string name, string value) =>
        ((TextBlock)window.FindName(name)).Text = value;

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        foreach (object child in LogicalTreeHelper.GetChildren(parent))
        {
            if (child is DependencyObject value)
            {
                yield return value;
                foreach (DependencyObject nested in Descendants(value)) yield return nested;
            }
        }
    }

    private static void Render(Window window, FrameworkElement root, string output,
        int width, int height, string state)
    {
        // StartupUri를 등록하지 않았고 창의 Loaded/Closing도 해제한 상태에서 데이터 바인딩을 반영한다.
        root.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.DataBind);
        root.Measure(new Size(width, height));
        root.Arrange(new Rect(0, 0, width, height));
        root.UpdateLayout();
        root.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.DataBind);
        root.Measure(new Size(width, height));
        root.Arrange(new Rect(0, 0, width, height));
        root.UpdateLayout();
        FrameworkElement content = (FrameworkElement)window.FindName("BootTabContent");
        bool setupExpanded = ((Expander)window.FindName("BootSetupExpander")).IsExpanded;
        foreach ((string left, string right) in new[]
        {
            ("InstallBootDriverButton", "RefreshBootButton"),
            ("AttachBootFilterButton", "DetachBootFilterButton"),
            ("StartBootProtectionButton", "StopBootProtectionButton")
        })
        {
            if (!setupExpanded && left != "StartBootProtectionButton") continue;
            Rect first = Bounds((FrameworkElement)window.FindName(left), content);
            Rect second = Bounds((FrameworkElement)window.FindName(right), content);
            if (first.IntersectsWith(second) || first.Width == 0 || second.Width == 0 ||
                first.Left < 0 || second.Right > content.ActualWidth || first.Top < 0 || second.Bottom > content.ActualHeight)
            {
                throw new InvalidOperationException($"버튼 겹침/잘림: {width}x{height} {left}, {right}");
            }
        }
        Rect eventBounds = Bounds((FrameworkElement)window.FindName("BootEventGrid"), content);
        if (eventBounds.Height < 70 || eventBounds.Bottom > content.ActualHeight)
        {
            throw new InvalidOperationException($"로그 영역이 너무 작거나 잘림: {width}x{height}, {eventBounds}");
        }
        ScrollViewer scroll = (ScrollViewer)window.FindName("BootTabScrollViewer");
        if (content.ActualHeight > scroll.ViewportHeight + 1 && scroll.ScrollableHeight < content.ActualHeight - scroll.ViewportHeight - 1)
        {
            throw new InvalidOperationException("작은 창에서 콘텐츠 하단까지 스크롤할 수 없습니다.");
        }
        RenderTargetBitmap bitmap = new(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(root);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string path = Path.Combine(output, $"boot-ui-{width}x{height}-{state}.png");
        using FileStream file = File.Create(path);
        encoder.Save(file);
        Console.WriteLine($"PASS layout {width}x{height} {state} eventHeight={eventBounds.Height:F1} -> {path}");
    }

    private static Rect Bounds(FrameworkElement element, Visual root) =>
        element.TransformToAncestor(root).TransformBounds(new Rect(element.RenderSize));
}
