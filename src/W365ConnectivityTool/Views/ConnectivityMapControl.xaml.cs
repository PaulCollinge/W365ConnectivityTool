using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using W365ConnectivityTool.Models;
using W365ConnectivityTool.ViewModels;

namespace W365ConnectivityTool.Views;

public partial class ConnectivityMapControl : UserControl
{
    // Connection state — drives line colors
    private bool _hasLocalGw;
    private bool _hasIsp;
    private bool _hasAfd;
    private bool _hasGateway;
    private bool _hasTurn;
    private bool _hasDns;
    private TestStatus _tcpStatus = TestStatus.NotRun;
    private TestStatus _turnStatus = TestStatus.NotRun;

    public ConnectivityMapControl()
    {
        InitializeComponent();
        Loaded += (_, _) => DrawConnections();
    }

    // ════════════════════════════════════════════════════════════════
    //  Public API — called from MainWindow when test results change
    // ════════════════════════════════════════════════════════════════

    public void UpdateFromResults(IEnumerable<TestResultViewModel> tests)
    {
        var lookup = tests.ToDictionary(t => t.Id, t => t);
        _tcpStatus = TestStatus.NotRun;
        _turnStatus = TestStatus.NotRun;

        UpdateClientCard(lookup);
        _hasLocalGw = UpdateLocalGwCard(lookup);
        _hasIsp = UpdateIspCard(lookup);
        _hasAfd = UpdateAfdCard(lookup);
        _hasGateway = UpdateGatewayCard(lookup);
        _hasTurn = UpdateTurnCard(lookup);
        _hasDns = UpdateDnsCard(lookup);
        UpdateSecurityBar(lookup);

        Dispatcher.InvokeAsync(DrawConnections, DispatcherPriority.Loaded);
    }

    // ════════════════════════════════════════════════════════════════
    //  Card Updates
    // ════════════════════════════════════════════════════════════════

    private void UpdateClientCard(Dictionary<string, TestResultViewModel> lookup)
    {
        string location = Environment.MachineName;
        string publicIp = "";
        var status = TestStatus.NotRun;

        if (TryGetTest(lookup, "10b", out var userLoc))
        {
            location = userLoc.ResultValue;
            status = userLoc.Status;
            // Extract public IP from DetailedInfo
            if (!string.IsNullOrWhiteSpace(userLoc.DetailedInfo))
            {
                foreach (var line in userLoc.DetailedInfo.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("Public IP:", StringComparison.OrdinalIgnoreCase))
                    {
                        publicIp = trimmed.Substring("Public IP:".Length).Trim();
                        break;
                    }
                }
            }
        }
        else if (TryGetTest(lookup, "01", out var loc01))
        {
            location = loc01.ResultValue;
            status = loc01.Status;
            if (!string.IsNullOrWhiteSpace(loc01.DetailedInfo))
            {
                foreach (var line in loc01.DetailedInfo.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("Public IP:", StringComparison.OrdinalIgnoreCase))
                    {
                        publicIp = trimmed.Substring("Public IP:".Length).Trim();
                        break;
                    }
                }
            }
        }

        ClientLocation.Text = $"\U0001f4cd {location}";
        ClientIp.Text = string.IsNullOrEmpty(publicIp) ? "" : $"\U0001f310 {publicIp}";

        // DNS hijack
        if (lookup.TryGetValue("10d", out var dnsH) && dnsH.Status != TestStatus.NotRun)
        {
            if (dnsH.Status == TestStatus.Warning)
            {
                ClientDns.Text = "⚠ DNS hijacking detected";
                ClientDns.Foreground = Brush_Amber;
                status = WorstStatus(status, TestStatus.Warning);
            }
            else
            {
                ClientDns.Text = "✓ DNS OK";
                ClientDns.Foreground = Brush_Green;
            }
        }
        else
            ClientDns.Text = "";

        ClientAccent.Background = StatusBrush(status);
    }

    private bool UpdateLocalGwCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "05", out var gw))
        {
            LocalGwDetail1.Text = "Awaiting results...";
            LocalGwDetail2.Text = "";
            LocalGwAccent.Background = StatusBrush(TestStatus.NotRun);
            return false;
        }

        // Extract gateway IP from DetailedInfo ("Gateway: x.x.x.x\n...")
        string gwIp = "";
        if (!string.IsNullOrWhiteSpace(gw.DetailedInfo))
        {
            foreach (var line in gw.DetailedInfo.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("Gateway:", StringComparison.OrdinalIgnoreCase))
                {
                    gwIp = trimmed.Substring("Gateway:".Length).Trim();
                    break;
                }
            }
        }

        LocalGwDetail1.Text = string.IsNullOrEmpty(gwIp) ? gw.ResultValue : gwIp;
        LocalGwDetail2.Text = gw.ResultValue;
        LocalGwAccent.Background = StatusBrush(gw.Status);
        return true;
    }

    private bool UpdateIspCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "06", out var isp))
        {
            IspDetail1.Text = "Awaiting results...";
            IspDetail2.Text = "";
            IspDetail3.Text = "";
            IspAccent.Background = StatusBrush(TestStatus.NotRun);
            return false;
        }

        IspDetail1.Text = isp.ResultValue;

        // Extract org/AS from DetailedInfo
        if (!string.IsNullOrWhiteSpace(isp.DetailedInfo))
        {
            foreach (var line in isp.DetailedInfo.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("AS:", StringComparison.OrdinalIgnoreCase))
                {
                    IspDetail2.Text = trimmed;
                    break;
                }
            }
        }
        else
            IspDetail2.Text = "";

        // Show internet egress city from GeoIP (test 10b or 01)
        string egressCity = "";
        if (TryGetTest(lookup, "10b", out var userLoc))
            egressCity = userLoc.ResultValue;
        else if (TryGetTest(lookup, "01", out var loc01))
            egressCity = loc01.ResultValue;

        IspDetail3.Text = string.IsNullOrEmpty(egressCity) ? "" : $"\U0001f4cd {egressCity}";

        IspAccent.Background = StatusBrush(isp.Status);
        return true;
    }

    private bool UpdateAfdCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "10e", out var egress))
        {
            AfdDetail1.Text = "Awaiting results...";
            AfdDetail2.Text = "";
            AfdAccent.Background = StatusBrush(TestStatus.NotRun);
            return false;
        }

        AfdDetail1.Text = egress.ResultValue;
        var status = egress.Status;

        if (lookup.TryGetValue("15", out var tls) && tls.Status == TestStatus.Warning)
        {
            AfdDetail2.Text = "⚠ TLS inspection detected";
            AfdDetail2.Foreground = Brush_Amber;
            status = WorstStatus(status, TestStatus.Warning);
        }
        else
            AfdDetail2.Text = "";

        // Extract HTTPS latency from DetailedInfo ("HTTPS: 200 (42ms)")
        if (!string.IsNullOrWhiteSpace(egress.DetailedInfo))
        {
            var latencyMatch = System.Text.RegularExpressions.Regex.Match(
                egress.DetailedInfo, @"HTTPS:.*?\((\d+)ms\)");
            if (latencyMatch.Success)
            {
                var ms = int.Parse(latencyMatch.Groups[1].Value);
                AfdLatency.Text = $"⏱ {ms}ms";
                SetLatencyBadgeColor(AfdLatencyBadge, AfdLatency, ms, isTcp: true);
                AfdLatencyBadge.Visibility = Visibility.Visible;
            }
            else
                AfdLatencyBadge.Visibility = Visibility.Collapsed;
        }
        else
            AfdLatencyBadge.Visibility = Visibility.Collapsed;

        AfdAccent.Background = StatusBrush(status);
        _tcpStatus = WorstStatus(_tcpStatus, status);
        return true;
    }

    private bool UpdateGatewayCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "13", out var gwLoc))
        {
            GwDetail1.Text = "Awaiting results...";
            GwDetail2.Text = "";
            GwAccent.Background = StatusBrush(TestStatus.NotRun);
            return false;
        }

        // ResultValue is e.g. "UK South (1.2.3.4)"
        GwDetail1.Text = gwLoc.ResultValue;
        var status = gwLoc.Status;

        if (TryGetTest(lookup, "12", out var gwLatency))
        {
            GwDetail2.Text = gwLatency.ResultValue;
            status = WorstStatus(status, gwLatency.Status);

            // Extract avg ms for latency badge
            var latencyMatch = System.Text.RegularExpressions.Regex.Match(
                gwLatency.ResultValue, @"(\d+)ms");
            if (latencyMatch.Success)
            {
                var ms = int.Parse(latencyMatch.Groups[1].Value);
                GwLatency.Text = $"⏱ {ms}ms";
                SetLatencyBadgeColor(GwLatencyBadge, GwLatency, ms, isTcp: true);
                GwLatencyBadge.Visibility = Visibility.Visible;
            }
            else
                GwLatencyBadge.Visibility = Visibility.Collapsed;
        }
        else
            GwLatencyBadge.Visibility = Visibility.Collapsed;

        if (lookup.TryGetValue("10", out var tcp) && tcp.Status != TestStatus.NotRun)
            status = WorstStatus(status, tcp.Status);

        GwAccent.Background = StatusBrush(status);
        _tcpStatus = WorstStatus(_tcpStatus, status);
        return true;
    }

    private bool UpdateTurnCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "11b", out var turnLoc))
        {
            TurnDetail1.Text = "Awaiting results...";
            TurnDetail2.Text = "";
            TurnAccent.Background = StatusBrush(TestStatus.NotRun);
            return false;
        }

        TurnDetail1.Text = turnLoc.ResultValue;
        var status = turnLoc.Status;

        if (lookup.TryGetValue("11", out var turnReach) && turnReach.Status != TestStatus.NotRun)
        {
            status = WorstStatus(status, turnReach.Status);
            TurnDetail2.Text = turnReach.Status == TestStatus.Passed
                ? "✓ Reachable (UDP 3478)"
                : turnReach.ResultValue;

            // Show reachability badge for TURN
            if (turnReach.Status == TestStatus.Passed)
            {
                TurnLatency.Text = "✓ Reachable";
                TurnLatencyBadge.Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xF4, 0xE8));
                TurnLatencyBadge.BorderBrush = Brush_Green;
                TurnLatency.Foreground = Brush_Green;
                TurnLatencyBadge.Visibility = Visibility.Visible;
            }
            else
            {
                TurnLatency.Text = "✗ Unreachable";
                TurnLatencyBadge.Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xD7, 0xDA));
                TurnLatencyBadge.BorderBrush = Brush_Red;
                TurnLatency.Foreground = Brush_Red;
                TurnLatencyBadge.Visibility = Visibility.Visible;
            }
        }
        else
        {
            TurnDetail2.Text = "";
            TurnLatencyBadge.Visibility = Visibility.Collapsed;
        }

        TurnAccent.Background = StatusBrush(status);
        _turnStatus = status;
        return true;
    }

    // ════════════════════════════════════════════════════════════════
    //  Security Status Bar
    // ════════════════════════════════════════════════════════════════

    private void UpdateSecurityBar(Dictionary<string, TestResultViewModel> lookup)
    {
        // ── TLS Inspection (test 15) ──
        if (TryGetTest(lookup, "15", out var tls))
        {
            if (tls.Status == TestStatus.Passed)
            {
                TlsIcon.Text = "\ud83d\udee1";
                TlsStatus.Text = "TLS: No inspection detected";
                SetSecurityBadge(TlsBadge, TlsStatus, isGood: true);
            }
            else
            {
                TlsIcon.Text = "\u26a0";
                TlsStatus.Text = "TLS INSPECTION DETECTED";
                SetSecurityBadge(TlsBadge, TlsStatus, isGood: false, isCritical: tls.Status == TestStatus.Failed);
            }
        }
        else
        {
            TlsIcon.Text = "\ud83d\udee1";
            TlsStatus.Text = "TLS: Checking...";
            SetSecurityBadge(TlsBadge, TlsStatus, isGood: true, isPending: true);
        }

        // ── Proxy/VPN/SWG (test 16) ──
        if (TryGetTest(lookup, "16", out var proxy))
        {
            if (proxy.Status == TestStatus.Passed)
            {
                ProxyIcon.Text = "\ud83d\udee1";
                ProxyStatus.Text = "VPN/SWG/Proxy: Not detected";
                SetSecurityBadge(ProxyBadge, ProxyStatus, isGood: true);
            }
            else
            {
                ProxyIcon.Text = "\u26a0";
                ProxyStatus.Text = proxy.ResultValue;
                SetSecurityBadge(ProxyBadge, ProxyStatus, isGood: false, isCritical: proxy.Status == TestStatus.Failed);
            }
        }
        else
        {
            ProxyIcon.Text = "\ud83d\udee1";
            ProxyStatus.Text = "VPN/SWG/Proxy: Checking...";
            SetSecurityBadge(ProxyBadge, ProxyStatus, isGood: true, isPending: true);
        }

        // Set overall bar background
        bool anyBad = false;
        if (TryGetTest(lookup, "15", out var t15) && t15.Status != TestStatus.Passed) anyBad = true;
        if (TryGetTest(lookup, "16", out var t16) && t16.Status != TestStatus.Passed) anyBad = true;
        SecurityBar.Background = new SolidColorBrush(anyBad
            ? Color.FromRgb(0xFF, 0xF3, 0xE0)   // light amber
            : Color.FromRgb(0xF0, 0xFF, 0xF0));  // light green
    }

    private static void SetSecurityBadge(Border badge, TextBlock label,
        bool isGood, bool isCritical = false, bool isPending = false)
    {
        if (isPending)
        {
            badge.Background = new SolidColorBrush(Color.FromRgb(0xF3, 0xF2, 0xF1));
            badge.BorderBrush = Brush_Grey;
            label.Foreground = Brush_Grey;
        }
        else if (isGood)
        {
            badge.Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xF4, 0xE8));
            badge.BorderBrush = Brush_Green;
            label.Foreground = Brush_Green;
        }
        else if (isCritical)
        {
            badge.Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xD7, 0xDA));
            badge.BorderBrush = Brush_Red;
            label.Foreground = Brush_Red;
        }
        else
        {
            badge.Background = new SolidColorBrush(Color.FromRgb(0xFF, 0xF3, 0xCD));
            badge.BorderBrush = Brush_Amber;
            label.Foreground = Brush_Amber;
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  Connection Lines + Arrowheads
    // ════════════════════════════════════════════════════════════════

    private void DiagramArea_SizeChanged(object sender, SizeChangedEventArgs e) => DrawConnections();

    private bool UpdateDnsCard(Dictionary<string, TestResultViewModel> lookup)
    {
        if (!TryGetTest(lookup, "02", out var dns))
        {
            DnsDetail1.Text = "Awaiting results...";
            DnsDetail2.Text = "";
            DnsDetail3.Text = "";
            DnsAccent.Background = StatusBrush(TestStatus.NotRun);
            DnsLatencyBadge.Visibility = Visibility.Collapsed;
            return false;
        }

        // Extract DNS server IP and name from DetailedInfo
        string dnsServerIp = "";
        string dnsServerName = "";
        if (!string.IsNullOrWhiteSpace(dns.DetailedInfo))
        {
            foreach (var line in dns.DetailedInfo.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("DNS Server:", StringComparison.OrdinalIgnoreCase))
                    dnsServerIp = trimmed.Substring("DNS Server:".Length).Trim();
                else if (trimmed.StartsWith("DNS Server Name:", StringComparison.OrdinalIgnoreCase))
                    dnsServerName = trimmed.Substring("DNS Server Name:".Length).Trim();
            }
        }

        // Show DNS server name (or IP if no name)
        if (!string.IsNullOrEmpty(dnsServerName))
        {
            DnsDetail1.Text = dnsServerName;
            DnsDetail2.Text = dnsServerIp;
        }
        else
        {
            DnsDetail1.Text = string.IsNullOrEmpty(dnsServerIp) ? "System DNS" : dnsServerIp;
            DnsDetail2.Text = "";
        }

        // Show DNS hijack status if available
        if (lookup.TryGetValue("10d", out var dnsH) && dnsH.Status != TestStatus.NotRun)
        {
            if (dnsH.Status == TestStatus.Warning || dnsH.Status == TestStatus.Failed)
            {
                DnsDetail3.Text = "\u26a0 DNS hijacking detected";
                DnsDetail3.Foreground = Brush_Amber;
            }
            else
            {
                DnsDetail3.Text = "\u2713 DNS integrity OK";
                DnsDetail3.Foreground = Brush_Green;
            }
        }
        else
            DnsDetail3.Text = "";

        // Latency badge from ResultValue (e.g. "42ms avg (80ms max)")
        var latencyMatch = System.Text.RegularExpressions.Regex.Match(
            dns.ResultValue, @"(\d+)ms avg");
        if (latencyMatch.Success)
        {
            var ms = int.Parse(latencyMatch.Groups[1].Value);
            DnsLatency.Text = $"\u23f1 {ms}ms avg";
            SetLatencyBadgeColor(DnsLatencyBadge, DnsLatency, ms, isTcp: true);
            DnsLatencyBadge.Visibility = Visibility.Visible;
        }
        else
            DnsLatencyBadge.Visibility = Visibility.Collapsed;

        DnsAccent.Background = StatusBrush(dns.Status);
        return true;
    }

    private void DrawConnections()
    {
        LinesCanvas.Children.Clear();
        if (!IsLoaded || DiagramArea.ActualWidth < 10) return;

        try
        {
            var tcpBrush = (_hasLocalGw || _hasIsp || _hasAfd || _hasGateway) ? Brush_Blue : Brush_LightGrey;
            var turnBrush = _hasTurn ? Brush_Orange : Brush_LightGrey;

            // ── Common path: Client → Local GW ──
            DrawArrow(
                GetEdge(ClientCard, 0.5, rightSide: true),
                GetEdge(LocalGwCard, 0.5, rightSide: false),
                tcpBrush, dashed: false, "");

            // ── Common path: Local GW → ISP ──
            DrawArrow(
                GetEdge(LocalGwCard, 0.5, rightSide: true),
                GetEdge(IspCard, 0.5, rightSide: false),
                tcpBrush, dashed: false, "");

            // ── Fan-out: ISP → AFD Edge (top) ──
            DrawArrow(
                GetEdge(IspCard, 0.3, rightSide: true),
                GetEdge(AfdCard, 0.5, rightSide: false),
                _hasAfd ? Brush_Blue : Brush_LightGrey, dashed: false, "TCP 443");

            // ── Fan-out: ISP → RD Gateway (middle) ──
            DrawArrow(
                GetEdge(IspCard, 0.5, rightSide: true),
                GetEdge(GatewayCard, 0.5, rightSide: false),
                _hasGateway ? Brush_Blue : Brush_LightGrey, dashed: false, "TCP 443");

            // ── Fan-out: ISP → TURN Relay (bottom, UDP) ──
            DrawArrow(
                GetEdge(IspCard, 0.7, rightSide: true),
                GetEdge(TurnCard, 0.5, rightSide: false),
                turnBrush, dashed: true, "UDP 3478");

            // ── Local GW → DNS card (downward) ──
            DrawArrow(
                GetBottomEdge(LocalGwCard, 0.5),
                GetTopEdge(DnsCard, 0.5),
                _hasDns ? Brush_Blue : Brush_LightGrey, dashed: false, "");
        }
        catch
        {
            // Layout not ready
        }
    }

    private Point GetEdge(FrameworkElement card, double yFraction, bool rightSide)
    {
        var topLeft = card.TranslatePoint(new Point(0, 0), LinesCanvas);
        double x = rightSide ? topLeft.X + card.ActualWidth : topLeft.X;
        double y = topLeft.Y + card.ActualHeight * yFraction;
        return new Point(x, y);
    }

    private Point GetBottomEdge(FrameworkElement card, double xFraction)
    {
        var topLeft = card.TranslatePoint(new Point(0, 0), LinesCanvas);
        return new Point(topLeft.X + card.ActualWidth * xFraction,
                         topLeft.Y + card.ActualHeight);
    }

    private Point GetTopEdge(FrameworkElement card, double xFraction)
    {
        var topLeft = card.TranslatePoint(new Point(0, 0), LinesCanvas);
        return new Point(topLeft.X + card.ActualWidth * xFraction, topLeft.Y);
    }

    private void DrawArrow(Point from, Point to, SolidColorBrush brush, bool dashed, string label)
    {
        // Inset slightly so lines don't touch card borders — direction-aware
        double dx = to.X - from.X;
        double dy = to.Y - from.Y;
        double len = Math.Sqrt(dx * dx + dy * dy);
        if (len > 8)
        {
            double inset = 4.0 / len;
            from = new Point(from.X + dx * inset, from.Y + dy * inset);
            to = new Point(to.X - dx * inset, to.Y - dy * inset);
        }

        // Main line
        var line = new Line
        {
            X1 = from.X, Y1 = from.Y,
            X2 = to.X, Y2 = to.Y,
            Stroke = brush,
            StrokeThickness = 2.5,
            StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round
        };
        if (dashed)
            line.StrokeDashArray = [6, 4];
        LinesCanvas.Children.Add(line);

        // Arrowhead
        double angle = Math.Atan2(to.Y - from.Y, to.X - from.X);
        double sz = 10, spread = Math.PI / 7;
        var arrow = new Polygon { Fill = brush };
        arrow.Points.Add(to);
        arrow.Points.Add(new Point(to.X - sz * Math.Cos(angle - spread),
                                   to.Y - sz * Math.Sin(angle - spread)));
        arrow.Points.Add(new Point(to.X - sz * Math.Cos(angle + spread),
                                   to.Y - sz * Math.Sin(angle + spread)));
        LinesCanvas.Children.Add(arrow);

        // Protocol label at midpoint
        var lbl = new TextBlock
        {
            Text = label,
            FontSize = 10,
            Foreground = brush,
            FontFamily = new FontFamily("Consolas"),
            FontWeight = FontWeights.SemiBold
        };
        lbl.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        double mx = (from.X + to.X) / 2;
        double my = (from.Y + to.Y) / 2;
        Canvas.SetLeft(lbl, mx - lbl.DesiredSize.Width / 2);
        Canvas.SetTop(lbl, my - lbl.DesiredSize.Height - 4);
        LinesCanvas.Children.Add(lbl);
    }

    // ════════════════════════════════════════════════════════════════
    //  Helpers
    // ════════════════════════════════════════════════════════════════

    private static bool TryGetTest(Dictionary<string, TestResultViewModel> lookup, string id,
        out TestResultViewModel test)
    {
        if (lookup.TryGetValue(id, out var t) && t.Status != TestStatus.NotRun)
        {
            test = t;
            return true;
        }
        test = null!;
        return false;
    }

    private static TestStatus WorstStatus(TestStatus a, TestStatus b)
    {
        int Rank(TestStatus s) => s switch
        {
            TestStatus.Failed => 4, TestStatus.Error => 4,
            TestStatus.Warning => 3, TestStatus.Running => 2,
            TestStatus.Passed => 1, _ => 0
        };
        return Rank(a) >= Rank(b) ? a : b;
    }

    /// <summary>
    /// Colors a latency badge green/amber/red based on the millisecond value.
    /// </summary>
    private static void SetLatencyBadgeColor(Border badge, TextBlock label, int ms, bool isTcp)
    {
        SolidColorBrush fg;
        Color bg;

        if (ms < (isTcp ? 50 : 100))
        {
            fg = Brush_Green;
            bg = Color.FromRgb(0xE8, 0xF4, 0xE8);
        }
        else if (ms < (isTcp ? 150 : 300))
        {
            fg = Brush_Amber;
            bg = Color.FromRgb(0xFF, 0xF3, 0xCD);
        }
        else
        {
            fg = Brush_Red;
            bg = Color.FromRgb(0xF8, 0xD7, 0xDA);
        }

        badge.Background = new SolidColorBrush(bg);
        badge.BorderBrush = fg;
        label.Foreground = fg;
    }

    // ════════════════════════════════════════════════════════════════
    //  Brushes
    // ════════════════════════════════════════════════════════════════

    private static readonly SolidColorBrush Brush_Green     = new(Color.FromRgb(0x10, 0x7C, 0x10));
    private static readonly SolidColorBrush Brush_Amber     = new(Color.FromRgb(0xFF, 0x8C, 0x00));
    private static readonly SolidColorBrush Brush_Red       = new(Color.FromRgb(0xD1, 0x34, 0x38));
    private static readonly SolidColorBrush Brush_Blue      = new(Color.FromRgb(0x00, 0x78, 0xD4));
    private static readonly SolidColorBrush Brush_Orange    = new(Color.FromRgb(0xFF, 0x8C, 0x00));
    private static readonly SolidColorBrush Brush_Grey      = new(Color.FromRgb(0x8A, 0x88, 0x86));
    private static readonly SolidColorBrush Brush_LightGrey = new(Color.FromRgb(0xC8, 0xC6, 0xC4));

    private static SolidColorBrush StatusBrush(TestStatus s) => s switch
    {
        TestStatus.Passed                    => Brush_Green,
        TestStatus.Warning                   => Brush_Amber,
        TestStatus.Failed or TestStatus.Error => Brush_Red,
        TestStatus.Running                   => Brush_Blue,
        _                                    => Brush_Grey
    };
}
