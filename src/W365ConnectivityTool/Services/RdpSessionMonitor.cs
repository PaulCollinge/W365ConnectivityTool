using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace W365ConnectivityTool.Services;

/// <summary>
/// Monitors RDP session state from the client machine.
/// Detects active sessions, transport type, and reads performance counters
/// when running inside a remote session.
/// </summary>
public static class RdpSessionMonitor
{
    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);
    private const int SM_REMOTESESSION = 0x1000;

    // ── Session Detection ──────────────────────────────────────────

    /// <summary>
    /// Returns true if this process is running inside a Remote Desktop session.
    /// </summary>
    public static bool IsRemoteSession()
    {
        try { return GetSystemMetrics(SM_REMOTESESSION) != 0; }
        catch { return false; }
    }

    /// <summary>
    /// Finds active RDP client processes on the local machine.
    /// </summary>
    public static List<RdpClientInfo> FindActiveRdpClients()
    {
        var clients = new List<RdpClientInfo>();

        var processNames = new (string name, string clientType)[]
        {
            ("msrdc", "Windows App (MSRDC)"),
            ("mstsc", "Remote Desktop Client (mstsc)"),
            ("DesktopClient", "AVD Desktop Client"),
        };

        foreach (var (name, clientType) in processNames)
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    clients.Add(new RdpClientInfo
                    {
                        ProcessName = $"{name}.exe",
                        Pid = p.Id,
                        ClientType = clientType,
                        StartTime = TryGetStartTime(p),
                        MainWindowTitle = TryGetWindowTitle(p)
                    });
                }
            }
            catch { /* access denied — non-fatal */ }
        }

        return clients;
    }

    private static DateTime? TryGetStartTime(Process p)
    {
        try { return p.StartTime; } catch { return null; }
    }

    private static string TryGetWindowTitle(Process p)
    {
        try { return p.MainWindowTitle ?? string.Empty; } catch { return string.Empty; }
    }

    // ── Transport Detection (Event Log) ────────────────────────────

    /// <summary>
    /// Reads the RDP client event log to determine the transport used for recent connections.
    /// Checks both TerminalServices-RDPClient and RdpCoreTS operational logs.
    /// </summary>
    public static TransportInfo GetTransportInfo()
    {
        var info = new TransportInfo();

        // 1. Try RdpCoreTS (available when inside a remote session on the host)
        ReadRdpCoreTsEvents(info);

        // 2. Try TerminalServices-RDPClient (available on the client machine)
        ReadRdpClientEvents(info);

        return info;
    }

    private static void ReadRdpCoreTsEvents(TransportInfo info)
    {
        try
        {
            const string logName = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
            var query = new EventLogQuery(logName, PathType.LogName,
                "*[System[(EventID=131 or EventID=140 or EventID=141 or EventID=142 or EventID=143) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");

            using var reader = new EventLogReader(query);

            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    int eventId = record.Id;
                    string message = TryGetEventMessage(record);

                    info.Events.Add(new TransportEvent
                    {
                        TimeCreated = record.TimeCreated ?? DateTime.MinValue,
                        EventId = eventId,
                        Message = message
                    });

                    switch (eventId)
                    {
                        case 131: // Connection accepted
                            info.HasConnection = true;
                            break;
                        case 140: // Transport negotiated — message contains transport type
                            info.TransportNegotiated = true;
                            info.NegotiatedTransport = message;
                            break;
                        case 141: // UDP connected
                            info.UdpConnected = true;
                            info.Protocol = "UDP (RDP Shortpath)";
                            break;
                        case 142: // UDP failed, TCP fallback
                            info.UdpFailed = true;
                            info.Protocol = "TCP (Reverse Connect)";
                            info.UdpFailReason = message;
                            break;
                        case 143: // Shortpath connected
                            info.ShortpathConnected = true;
                            info.Protocol = "UDP (RDP Shortpath)";
                            break;
                    }
                }
            }
        }
        catch { /* Log not available — expected on client-only machines */ }
    }

    private static void ReadRdpClientEvents(TransportInfo info)
    {
        try
        {
            const string logName = "Microsoft-Windows-TerminalServices-RDPClient/Operational";
            // Read connection-related events from last 24 hours
            var query = new EventLogQuery(logName, PathType.LogName,
                "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]");

            using var reader = new EventLogReader(query);

            EventRecord? record;
            int count = 0;
            while ((record = reader.ReadEvent()) != null && count < 200)
            {
                using (record)
                {
                    count++;
                    int eventId = record.Id;
                    string message = TryGetEventMessage(record);

                    // Event 1024: RDP connection started
                    // Event 1025: RDP connection ended
                    // Event 1026: RDP disconnected
                    // Event 1027: Transport connected
                    // Event 1029: Base transport type
                    if (eventId is 1024 or 1025 or 1026 or 1027 or 1029)
                    {
                        info.ClientEvents.Add(new TransportEvent
                        {
                            TimeCreated = record.TimeCreated ?? DateTime.MinValue,
                            EventId = eventId,
                            Message = message
                        });

                        if (eventId == 1024)
                        {
                            info.HasConnection = true;
                            info.LastConnectionTime = record.TimeCreated;
                        }
                    }

                    // Check for UDP-related messages
                    if (message.Contains("UDP", StringComparison.OrdinalIgnoreCase))
                    {
                        if (message.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                            message.Contains("connected", StringComparison.OrdinalIgnoreCase))
                        {
                            info.UdpConnected = true;
                            info.Protocol = "UDP (RDP Shortpath)";
                        }
                        else if (message.Contains("fail", StringComparison.OrdinalIgnoreCase))
                        {
                            info.UdpFailed = true;
                            if (string.IsNullOrEmpty(info.Protocol))
                                info.Protocol = "TCP (Reverse Connect)";
                        }
                    }
                }
            }
        }
        catch { /* Log not available — non-fatal */ }
    }

    private static string TryGetEventMessage(EventRecord record)
    {
        try { return record.FormatDescription() ?? string.Empty; }
        catch { return string.Empty; }
    }

    // ── Performance Counters (RemoteFX — inside remote session only) ──

    /// <summary>
    /// Reads RemoteFX performance counters. Only meaningful when running inside a remote session.
    /// </summary>
    public static RemoteFxMetrics? ReadRemoteFxCounters()
    {
        if (!IsRemoteSession()) return null;

        var metrics = new RemoteFxMetrics();

        // RemoteFX Network counters
        TryReadNetworkCounters(metrics);

        // RemoteFX Graphics counters
        TryReadGraphicsCounters(metrics);

        // User Input Delay
        TryReadInputDelay(metrics);

        return metrics;
    }

    private static void TryReadNetworkCounters(RemoteFxMetrics m)
    {
        try
        {
            if (!PerformanceCounterCategory.Exists("RemoteFX Network")) return;

            var cat = new PerformanceCounterCategory("RemoteFX Network");
            var instances = cat.GetInstanceNames();
            if (instances.Length == 0) return;

            var instance = instances[0]; // Use first (usually only) instance
            m.NetworkInstance = instance;

            m.TcpRtt = TryReadCounter("RemoteFX Network", "Current TCP RTT", instance);
            m.UdpRtt = TryReadCounter("RemoteFX Network", "Current UDP RTT", instance);
            m.UdpBandwidth = TryReadCounter("RemoteFX Network", "Current UDP Bandwidth", instance);
            m.HasNetworkCounters = true;
        }
        catch { /* Non-fatal */ }
    }

    private static void TryReadGraphicsCounters(RemoteFxMetrics m)
    {
        try
        {
            if (!PerformanceCounterCategory.Exists("RemoteFX Graphics")) return;

            var cat = new PerformanceCounterCategory("RemoteFX Graphics");
            var instances = cat.GetInstanceNames();
            if (instances.Length == 0) return;

            var instance = instances[0];
            m.GraphicsInstance = instance;

            m.InputFramesPerSec = TryReadCounter("RemoteFX Graphics", "Input Frames/Second", instance);
            m.OutputFramesPerSec = TryReadCounter("RemoteFX Graphics", "Output Frames/Second", instance);
            m.FramesSkippedNetwork = TryReadCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Network Resources", instance);
            m.FramesSkippedClient = TryReadCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Client Resources", instance);
            m.FramesSkippedServer = TryReadCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Server Resources", instance);
            m.AvgEncodingTime = TryReadCounter("RemoteFX Graphics", "Average Encoding Time", instance);
            m.FrameQuality = TryReadCounter("RemoteFX Graphics", "Frame Quality", instance);
            m.HasGraphicsCounters = true;
        }
        catch { /* Non-fatal */ }
    }

    private static void TryReadInputDelay(RemoteFxMetrics m)
    {
        try
        {
            if (!PerformanceCounterCategory.Exists("User Input Delay per Session")) return;

            var cat = new PerformanceCounterCategory("User Input Delay per Session");
            var instances = cat.GetInstanceNames();
            if (instances.Length == 0) return;

            // Read "Max" instance if available, otherwise first
            var instance = instances.Contains("Max") ? "Max" : instances[0];
            m.UserInputDelay = TryReadCounter("User Input Delay per Session", "Max Input Delay", instance);
            m.HasInputDelayCounter = true;
        }
        catch { /* Non-fatal */ }
    }

    private static float? TryReadCounter(string category, string counter, string instance)
    {
        try
        {
            using var pc = new PerformanceCounter(category, counter, instance, readOnly: true);
            pc.NextValue(); // First call initializes
            System.Threading.Thread.Sleep(100);
            return pc.NextValue();
        }
        catch { return null; }
    }

    // ── TCP Latency Sampling (for jitter from client side) ──────────

    /// <summary>
    /// Samples TCP connect latency to the gateway multiple times to compute jitter.
    /// Works from the physical client machine (no remote session needed).
    /// </summary>
    public static async Task<JitterResult> MeasureJitter(string hostname, int port, int sampleCount, CancellationToken ct)
    {
        var rtts = new List<double>();

        for (int i = 0; i < sampleCount; i++)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var sw = Stopwatch.StartNew();
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(hostname, port, cts.Token);
                sw.Stop();
                rtts.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch
            {
                // Skip failed sample
            }

            if (i < sampleCount - 1)
                await Task.Delay(250, ct); // 250ms between samples
        }

        if (rtts.Count < 2)
        {
            return new JitterResult
            {
                Samples = rtts,
                Success = false,
                Error = rtts.Count == 0 ? "All connection attempts failed" : "Insufficient samples for jitter calculation"
            };
        }

        // Calculate inter-arrival jitter (RFC 3550 style: mean of absolute consecutive differences)
        var consecutiveDiffs = new List<double>();
        for (int i = 1; i < rtts.Count; i++)
            consecutiveDiffs.Add(Math.Abs(rtts[i] - rtts[i - 1]));

        var mean = rtts.Average();
        var stdDev = Math.Sqrt(rtts.Select(x => Math.Pow(x - mean, 2)).Average());

        return new JitterResult
        {
            Samples = rtts,
            Success = true,
            MeanRtt = mean,
            MinRtt = rtts.Min(),
            MaxRtt = rtts.Max(),
            Jitter = consecutiveDiffs.Average(),   // Mean absolute consecutive difference
            StdDev = stdDev,                        // Standard deviation of all RTT samples
            P95Rtt = Percentile(rtts, 0.95)
        };
    }

    private static double Percentile(List<double> sorted, double percentile)
    {
        var ordered = sorted.OrderBy(x => x).ToList();
        int index = (int)Math.Ceiling(percentile * ordered.Count) - 1;
        return ordered[Math.Max(0, Math.Min(index, ordered.Count - 1))];
    }

    // ── STUN UDP Readiness Test ────────────────────────────────────

    /// <summary>
    /// Tests if UDP 3478 (STUN) is reachable and measures UDP round-trip time.
    /// This indicates whether RDP Shortpath can be established.
    /// </summary>
    public static async Task<StunReadinessResult> TestStunReadiness(CancellationToken ct)
    {
        var result = new StunReadinessResult();

        // Windows 365 TURN relay only — connections must resolve to 40.64.144.0/20 or 51.5.0.0/16
        foreach (var server in new[] { "world.relay.avd.microsoft.com" })
        {
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(server, ct);
                var ip = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
                bool inRange = EndpointConfiguration.IsInW365Range(ip);

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 3000;
                var serverEp = new System.Net.IPEndPoint(ip, 3478);

                // Build STUN Binding Request (RFC 5389)
                var stunRequest = BuildStunRequest();

                var sw = Stopwatch.StartNew();
                await udp.SendAsync(stunRequest, stunRequest.Length, serverEp);

                var receiveTask = udp.ReceiveAsync(ct);
                var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(3000, ct));

                if (completed == receiveTask.AsTask())
                {
                    sw.Stop();
                    var response = await receiveTask;

                    result.StunResults.Add(new StunServerResult
                    {
                        Server = server,
                        Ip = ip.ToString(),
                        Reachable = true,
                        RttMs = sw.Elapsed.TotalMilliseconds,
                        IsValidStun = IsValidStunResponse(response.Buffer),
                        InW365Range = inRange
                    });
                }
                else
                {
                    result.StunResults.Add(new StunServerResult
                    {
                        Server = server,
                        Ip = ip.ToString(),
                        Reachable = false,
                        Error = "Timeout (3s)",
                        InW365Range = inRange
                    });
                }
            }
            catch (Exception ex)
            {
                result.StunResults.Add(new StunServerResult
                {
                    Server = server,
                    Reachable = false,
                    Error = ex.Message
                });
            }
        }

        result.UdpReady = result.StunResults.Any(s => s.Reachable);
        return result;
    }

    private static byte[] BuildStunRequest()
    {
        var request = new byte[20];
        request[0] = 0x00; request[1] = 0x01; // Binding Request
        request[2] = 0x00; request[3] = 0x00; // Length: 0
        request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42; // Magic Cookie
        System.Security.Cryptography.RandomNumberGenerator.Fill(request.AsSpan(8, 12));
        return request;
    }

    private static bool IsValidStunResponse(byte[] data)
    {
        if (data.Length < 20) return false;
        var messageType = (data[0] << 8) | data[1];
        return messageType == 0x0101 && data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42;
    }
}

// ── Data Models ──────────────────────────────────────────────────

public class RdpClientInfo
{
    public string ProcessName { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string ClientType { get; set; } = string.Empty;
    public DateTime? StartTime { get; set; }
    public string MainWindowTitle { get; set; } = string.Empty;
}

public class TransportInfo
{
    public bool HasConnection { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public bool TransportNegotiated { get; set; }
    public string NegotiatedTransport { get; set; } = string.Empty;
    public bool UdpConnected { get; set; }
    public bool UdpFailed { get; set; }
    public string UdpFailReason { get; set; } = string.Empty;
    public bool ShortpathConnected { get; set; }
    public DateTime? LastConnectionTime { get; set; }
    public List<TransportEvent> Events { get; set; } = [];
    public List<TransportEvent> ClientEvents { get; set; } = [];
}

public class TransportEvent
{
    public DateTime TimeCreated { get; set; }
    public int EventId { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class RemoteFxMetrics
{
    public bool HasNetworkCounters { get; set; }
    public bool HasGraphicsCounters { get; set; }
    public bool HasInputDelayCounter { get; set; }

    public string NetworkInstance { get; set; } = string.Empty;
    public string GraphicsInstance { get; set; } = string.Empty;

    // Network
    public float? TcpRtt { get; set; }
    public float? UdpRtt { get; set; }
    public float? UdpBandwidth { get; set; }

    // Graphics
    public float? InputFramesPerSec { get; set; }
    public float? OutputFramesPerSec { get; set; }
    public float? FramesSkippedNetwork { get; set; }
    public float? FramesSkippedClient { get; set; }
    public float? FramesSkippedServer { get; set; }
    public float? AvgEncodingTime { get; set; }
    public float? FrameQuality { get; set; }

    // Input
    public float? UserInputDelay { get; set; }
}

public class JitterResult
{
    public List<double> Samples { get; set; } = [];
    public bool Success { get; set; }
    public string Error { get; set; } = string.Empty;
    public double MeanRtt { get; set; }
    public double MinRtt { get; set; }
    public double MaxRtt { get; set; }
    public double P95Rtt { get; set; }
    public double Jitter { get; set; }     // Mean absolute consecutive difference
    public double StdDev { get; set; }     // Standard deviation
}

public class StunReadinessResult
{
    public bool UdpReady { get; set; }
    public List<StunServerResult> StunResults { get; set; } = [];
}

public class StunServerResult
{
    public string Server { get; set; } = string.Empty;
    public string Ip { get; set; } = string.Empty;
    public bool Reachable { get; set; }
    public bool IsValidStun { get; set; }
    public double RttMs { get; set; }
    public string Error { get; set; } = string.Empty;
    public bool InW365Range { get; set; }
}
