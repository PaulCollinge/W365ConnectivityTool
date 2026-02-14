using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Services.Tests;

/// <summary>
/// Cloud Session tests — analyze active RDP sessions from the client machine.
/// These tests detect active sessions, read performance counters (when inside a
/// remote session), analyze transport protocol, measure jitter, and check UDP readiness.
/// </summary>

// ════════════════════════════════════════════════════════════════════
// ID 17 – Active RDP Session Detection
// ════════════════════════════════════════════════════════════════════
public class ActiveSessionDetectionTest : BaseTest
{
    public override string Id => "17";
    public override string Name => "Active RDP Session Detection";
    public override string Description => "Detects whether an RDP client (Windows App or mstsc) is running, and whether this tool is running inside a remote session. This determines which live metrics are available.";
    public override TestCategory Category => TestCategory.CloudSession;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var isRemote = RdpSessionMonitor.IsRemoteSession();
        var clients = RdpSessionMonitor.FindActiveRdpClients();

        sb.AppendLine($"Running inside Remote Desktop session: {(isRemote ? "Yes" : "No")}");
        sb.AppendLine();

        if (isRemote)
        {
            sb.AppendLine("ℹ This tool is running INSIDE a remote session (Cloud PC / Session Host).");
            sb.AppendLine("  RemoteFX performance counters are available for live session metrics.");
            sb.AppendLine($"  Machine: {Environment.MachineName}");
            sb.AppendLine($"  Session ID: {Process.GetCurrentProcess().SessionId}");

            result.Status = TestStatus.Passed;
            result.ResultValue = "Running inside remote session";
        }
        else if (clients.Count > 0)
        {
            sb.AppendLine($"Found {clients.Count} active RDP client process(es):");
            sb.AppendLine();

            foreach (var client in clients)
            {
                sb.AppendLine($"  Client: {client.ClientType}");
                sb.AppendLine($"  Process: {client.ProcessName} (PID {client.Pid})");
                if (client.StartTime.HasValue)
                    sb.AppendLine($"  Started: {client.StartTime:yyyy-MM-dd HH:mm:ss}");
                if (!string.IsNullOrEmpty(client.MainWindowTitle))
                    sb.AppendLine($"  Window: {client.MainWindowTitle}");
                sb.AppendLine();
            }

            sb.AppendLine("ℹ Active RDP client detected on this machine.");
            sb.AppendLine("  Session metrics are gathered from event logs and TCP probes.");
            sb.AppendLine("  For full RemoteFX counters, run this tool inside the Cloud PC.");

            result.Status = TestStatus.Passed;
            result.ResultValue = $"{clients.Count} active client(s) — {clients[0].ClientType}";
        }
        else
        {
            sb.AppendLine("No active RDP client processes found (msrdc.exe, mstsc.exe).");
            sb.AppendLine();
            sb.AppendLine("To analyze an active session:");
            sb.AppendLine("  1. Connect to your Cloud PC using Windows App or Remote Desktop");
            sb.AppendLine("  2. Re-run these tests while connected");
            sb.AppendLine();
            sb.AppendLine("Alternatively, run this tool INSIDE the Cloud PC for full");
            sb.AppendLine("RemoteFX performance counter access.");

            result.Status = TestStatus.Warning;
            result.ResultValue = "No active RDP session detected";
            result.RemediationText = "Connect to your Cloud PC and re-run to get live session metrics.";
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 17b – RDP Transport Protocol Detection
// ════════════════════════════════════════════════════════════════════
public class TransportProtocolTest : BaseTest
{
    public override string Id => "17b";
    public override string Name => "RDP Transport Protocol";
    public override string Description => "Detects whether the active RDP session is using UDP (RDP Shortpath) or TCP (Reverse Connect). UDP provides lower latency and better resilience.";
    public override TestCategory Category => TestCategory.CloudSession;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var transport = RdpSessionMonitor.GetTransportInfo();
        var isRemote = RdpSessionMonitor.IsRemoteSession();

        // Also check RemoteFX counters for UDP activity
        bool udpActive = false;
        if (isRemote)
        {
            var metrics = RdpSessionMonitor.ReadRemoteFxCounters();
            if (metrics?.UdpBandwidth is > 0)
            {
                udpActive = true;
                sb.AppendLine($"RemoteFX UDP Bandwidth: {metrics.UdpBandwidth:F0} KB/s (active)");
                if (metrics.UdpRtt.HasValue)
                    sb.AppendLine($"RemoteFX UDP RTT: {metrics.UdpRtt:F0} ms");
                if (metrics.TcpRtt.HasValue)
                    sb.AppendLine($"RemoteFX TCP RTT: {metrics.TcpRtt:F0} ms");
                sb.AppendLine();
            }
        }

        // Event log analysis
        if (transport.Events.Count > 0 || transport.ClientEvents.Count > 0)
        {
            sb.AppendLine("Event Log Analysis (last 24 hours):");
            sb.AppendLine("───────────────────────────────────");

            // RdpCoreTS events (server-side / inside remote session)
            if (transport.Events.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("RdpCoreTS Events:");
                foreach (var evt in transport.Events.OrderByDescending(e => e.TimeCreated).Take(10))
                {
                    string label = evt.EventId switch
                    {
                        131 => "Connection Accepted",
                        140 => "Transport Negotiated",
                        141 => "UDP Connected",
                        142 => "UDP Failed (TCP Fallback)",
                        143 => "RDP Shortpath Connected",
                        _ => $"Event {evt.EventId}"
                    };
                    sb.AppendLine($"  [{evt.TimeCreated:HH:mm:ss}] {label}");
                    if (!string.IsNullOrEmpty(evt.Message) && evt.Message.Length < 200)
                        sb.AppendLine($"    {evt.Message}");
                }
            }

            // Client-side events
            if (transport.ClientEvents.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("RDP Client Events:");
                foreach (var evt in transport.ClientEvents.OrderByDescending(e => e.TimeCreated).Take(10))
                {
                    string label = evt.EventId switch
                    {
                        1024 => "Connection Started",
                        1025 => "Connection Ended",
                        1026 => "Disconnected",
                        1027 => "Transport Connected",
                        1029 => "Base Transport Type",
                        _ => $"Event {evt.EventId}"
                    };
                    sb.AppendLine($"  [{evt.TimeCreated:HH:mm:ss}] {label}");
                    if (!string.IsNullOrEmpty(evt.Message) && evt.Message.Length < 200)
                        sb.AppendLine($"    {evt.Message}");
                }
            }
        }
        else
        {
            sb.AppendLine("No recent RDP connection events found in event logs.");
        }

        // Determine protocol
        if (udpActive || transport.ShortpathConnected || transport.UdpConnected)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "UDP (RDP Shortpath) ⚡";
            sb.AppendLine();
            sb.AppendLine("✓ Session is using UDP transport (RDP Shortpath).");
            sb.AppendLine("  This provides optimal latency and connection resilience.");
        }
        else if (transport.UdpFailed)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "TCP (UDP failed)";
            sb.AppendLine();
            sb.AppendLine("⚠ UDP connection failed — session fell back to TCP.");
            if (!string.IsNullOrEmpty(transport.UdpFailReason))
                sb.AppendLine($"  Reason: {transport.UdpFailReason}");
            sb.AppendLine("  TCP reverse connect adds latency via the AVD Gateway.");
            result.RemediationText = "UDP-based RDP Shortpath failed. Check that UDP 3478 is allowed outbound and that your NAT/firewall supports STUN. " +
                                     "If using a VPN, ensure it supports nested UDP or has a split-tunnel for AVD.";
            result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
        }
        else if (transport.HasConnection && !string.IsNullOrEmpty(transport.Protocol))
        {
            if (transport.Protocol.Contains("UDP"))
            {
                result.Status = TestStatus.Passed;
                result.ResultValue = "UDP (RDP Shortpath) ⚡";
            }
            else
            {
                result.Status = TestStatus.Warning;
                result.ResultValue = "TCP (Reverse Connect)";
                result.RemediationText = "Session appears to be using TCP transport. Enable RDP Shortpath for better performance.";
                result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
            }
        }
        else if (!transport.HasConnection)
        {
            result.Status = TestStatus.Skipped;
            result.ResultValue = "No recent connection detected";
            sb.AppendLine();
            sb.AppendLine("ℹ No RDP connection events found in the last 24 hours.");
            sb.AppendLine("  Connect to your Cloud PC and re-run to detect transport.");
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Unable to determine transport";
            sb.AppendLine();
            sb.AppendLine("ℹ Connection detected but transport type could not be determined.");
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 17c – UDP Readiness for RDP Shortpath
// ════════════════════════════════════════════════════════════════════
public class UdpReadinessTest : BaseTest
{
    public override string Id => "17c";
    public override string Name => "UDP Shortpath Readiness";
    public override string Description => "Tests if your network allows UDP traffic to Microsoft STUN/TURN servers. This determines whether RDP Shortpath (the preferred low-latency transport) can be used.";
    public override TestCategory Category => TestCategory.CloudSession;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var stunResult = await RdpSessionMonitor.TestStunReadiness(ct);

        sb.AppendLine("STUN/TURN Relay Reachability (UDP 3478):");
        sb.AppendLine($"Expected W365 IP ranges: {EndpointConfiguration.W365RangesDisplay}");
        sb.AppendLine("────────────────────────────────────");

        foreach (var s in stunResult.StunResults)
        {
            if (s.Reachable)
            {
                var stunLabel = s.IsValidStun ? "STUN response" : "UDP response";
                var rangeLabel = s.InW365Range ? "✓ W365 range" : "⚠ outside W365 range";
                sb.AppendLine($"  ✓ {s.Server} ({s.Ip}) — {stunLabel} in {s.RttMs:F0}ms [{rangeLabel}]");
            }
            else
            {
                sb.AppendLine($"  ✗ {s.Server}{(string.IsNullOrEmpty(s.Ip) ? "" : $" ({s.Ip})")} — {s.Error}");
            }
        }

        sb.AppendLine();

        if (stunResult.UdpReady)
        {
            var bestRtt = stunResult.StunResults.Where(s => s.Reachable).Min(s => s.RttMs);
            sb.AppendLine($"✓ UDP connectivity confirmed (best RTT: {bestRtt:F0}ms)");
            sb.AppendLine("  RDP Shortpath should be available for your connections.");
            sb.AppendLine();
            sb.AppendLine("RDP Shortpath modes:");
            sb.AppendLine("  • STUN (direct): Client ↔ Cloud PC via UDP hole-punching");
            sb.AppendLine("  • TURN (relayed): Client ↔ TURN relay ↔ Cloud PC");
            sb.AppendLine("  Both use UDP for lower latency than TCP reverse connect.");

            result.Status = TestStatus.Passed;
            result.ResultValue = $"UDP ready ({bestRtt:F0}ms)";
        }
        else
        {
            sb.AppendLine("✗ UDP connectivity to STUN servers failed.");
            sb.AppendLine("  RDP Shortpath will NOT be available — connections will use TCP.");
            sb.AppendLine();
            sb.AppendLine("Common causes:");
            sb.AppendLine("  • Firewall blocking outbound UDP 3478");
            sb.AppendLine("  • Network proxy intercepting UDP traffic");
            sb.AppendLine("  • VPN tunneling all traffic (no UDP passthrough)");
            sb.AppendLine("  • Corporate SWG blocking non-HTTP traffic");

            result.Status = TestStatus.Warning;
            result.ResultValue = "UDP blocked — RDP Shortpath unavailable";
            result.RemediationText = "UDP 3478 outbound is blocked. Without this, RDP Shortpath cannot be used and connections will fall back to TCP, " +
                                     "resulting in higher latency. Allow UDP 3478 outbound to Microsoft STUN/TURN relay servers.";
            result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 18 – Session Round-Trip Latency
// ════════════════════════════════════════════════════════════════════
public class SessionLatencyTest : BaseTest
{
    public override string Id => "18";
    public override string Name => "Session Round-Trip Latency";
    public override string Description => "Measures real-time round-trip latency. Inside a remote session, reads RemoteFX counters. On the physical device, uses TCP probes to the RD Gateway.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override int TimeoutSeconds => 45;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var isRemote = RdpSessionMonitor.IsRemoteSession();

        if (isRemote)
        {
            // Inside remote session — read RemoteFX Network counters
            await ReadRemoteFxLatency(result, sb, ct);
        }
        else
        {
            // On physical device — TCP probe latency to gateway
            await MeasureTcpLatency(result, sb, ct);
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }

    private static async Task ReadRemoteFxLatency(TestResult result, StringBuilder sb, CancellationToken ct)
    {
        sb.AppendLine("Source: RemoteFX Network performance counters (inside remote session)");
        sb.AppendLine();

        // Sample counters 3 times over 2 seconds for stability
        var tcpSamples = new List<float>();
        var udpSamples = new List<float>();

        for (int i = 0; i < 3; i++)
        {
            var metrics = RdpSessionMonitor.ReadRemoteFxCounters();
            if (metrics != null)
            {
                if (metrics.TcpRtt.HasValue) tcpSamples.Add(metrics.TcpRtt.Value);
                if (metrics.UdpRtt.HasValue) udpSamples.Add(metrics.UdpRtt.Value);
            }
            if (i < 2) await Task.Delay(700, ct);
        }

        if (tcpSamples.Count > 0)
        {
            var avgTcp = tcpSamples.Average();
            sb.AppendLine($"TCP RTT: {avgTcp:F0}ms (avg of {tcpSamples.Count} samples)");
            sb.AppendLine($"  Values: {string.Join(", ", tcpSamples.Select(s => $"{s:F0}ms"))}");
        }

        if (udpSamples.Count > 0)
        {
            var avgUdp = udpSamples.Average();
            sb.AppendLine($"UDP RTT: {avgUdp:F0}ms (avg of {udpSamples.Count} samples)");
            sb.AppendLine($"  Values: {string.Join(", ", udpSamples.Select(s => $"{s:F0}ms"))}");
        }

        if (tcpSamples.Count == 0 && udpSamples.Count == 0)
        {
            sb.AppendLine("⚠ RemoteFX Network counters not available.");
            sb.AppendLine("  This may indicate no active RDP transport or counters are disabled.");
            result.Status = TestStatus.Warning;
            result.ResultValue = "Counters unavailable";
            return;
        }

        // Use the active transport's RTT (prefer UDP if available)
        var primaryRtt = udpSamples.Count > 0 ? udpSamples.Average() : tcpSamples.Average();
        var transport = udpSamples.Count > 0 ? "UDP" : "TCP";

        SetLatencyStatus(result, primaryRtt, transport);
    }

    private static async Task MeasureTcpLatency(TestResult result, StringBuilder sb, CancellationToken ct)
    {
        var endpoint = EndpointConfiguration.GetBestGatewayEndpoint();
        var resolvedIps = await Dns.GetHostAddressesAsync(endpoint, ct);
        var ip = resolvedIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        bool inRange = ip != null && EndpointConfiguration.IsInW365Range(ip);

        sb.AppendLine("Source: TCP connect probes to RD Gateway");
        sb.AppendLine($"Endpoint: {endpoint}:{EndpointConfiguration.GatewayPort}");
        if (ip != null)
            sb.AppendLine($"Resolved IP: {ip} ({(inRange ? $"✓ within W365 range" : $"⚠ outside expected W365 ranges ({EndpointConfiguration.W365RangesDisplay})")})");
        sb.AppendLine("Samples: 10 (extended for accuracy)");
        sb.AppendLine();

        var rtts = new List<double>();
        for (int i = 0; i < 10; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var sw = Stopwatch.StartNew();
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(endpoint, EndpointConfiguration.GatewayPort, cts.Token);
                sw.Stop();
                rtts.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch { /* skip failed sample */ }

            if (i < 9) await Task.Delay(200, ct);
        }

        if (rtts.Count == 0)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Gateway unreachable";
            sb.AppendLine("✗ All TCP connection attempts failed.");
            result.RemediationText = "Cannot reach the RD Gateway to measure latency.";
            return;
        }

        var avg = rtts.Average();
        var min = rtts.Min();
        var max = rtts.Max();
        var p95 = Percentile(rtts, 0.95);

        sb.AppendLine($"Successful samples: {rtts.Count}/10");
        sb.AppendLine($"Min: {min:F0}ms | Avg: {avg:F0}ms | P95: {p95:F0}ms | Max: {max:F0}ms");
        sb.AppendLine($"Values: {string.Join(", ", rtts.Select(r => $"{r:F0}ms"))}");

        SetLatencyStatus(result, avg, "TCP");
    }

    private static void SetLatencyStatus(TestResult result, double avgMs, string transport)
    {
        result.ResultValue = $"{avgMs:F0}ms ({transport})";

        if (avgMs < 50)
        {
            result.Status = TestStatus.Passed;
        }
        else if (avgMs < 100)
        {
            result.Status = TestStatus.Passed;
            result.RemediationText = "Latency is acceptable but could be improved. Check network egress path.";
        }
        else if (avgMs < 200)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "Latency is above 100ms. Users may notice input lag. Check for proxy/VPN adding latency, " +
                                     "ensure traffic exits at the nearest network point, and verify UDP transport is available.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "Latency is very high (>200ms). Remote desktop will feel sluggish. " +
                                     "Investigate network routing, eliminate unnecessary hops (proxy, VPN), and ensure you're connecting to the nearest gateway region.";
        }
    }

    private static double Percentile(List<double> values, double p)
    {
        var ordered = values.OrderBy(x => x).ToList();
        int idx = (int)Math.Ceiling(p * ordered.Count) - 1;
        return ordered[Math.Max(0, Math.Min(idx, ordered.Count - 1))];
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 19 – Session Frame Rate & Bandwidth
// ════════════════════════════════════════════════════════════════════
public class SessionFrameRateTest : BaseTest
{
    public override string Id => "19";
    public override string Name => "Session Frame Rate & Bandwidth";
    public override string Description => "Reads RemoteFX Graphics performance counters for frame rate, encoding time, and frame quality. Available when running inside a remote session.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();

        if (!RdpSessionMonitor.IsRemoteSession())
        {
            sb.AppendLine("ℹ RemoteFX Graphics counters are only available inside a remote session.");
            sb.AppendLine();
            sb.AppendLine("To get frame rate and bandwidth data:");
            sb.AppendLine("  1. Connect to your Cloud PC");
            sb.AppendLine("  2. Run this tool inside the Cloud PC");
            sb.AppendLine("  3. These counters will show real-time graphics pipeline metrics");
            sb.AppendLine();
            sb.AppendLine("Available metrics inside remote session:");
            sb.AppendLine("  • Input/Output Frames per Second");
            sb.AppendLine("  • Frames Skipped (Network / Client / Server)");
            sb.AppendLine("  • Average Encoding Time");
            sb.AppendLine("  • Frame Quality (% of source)");
            sb.AppendLine("  • UDP Bandwidth");

            result.Status = TestStatus.Skipped;
            result.ResultValue = "Run inside Cloud PC for live data";
            result.DetailedInfo = sb.ToString().TrimEnd();
            return;
        }

        // Inside remote session — sample counters
        sb.AppendLine("Source: RemoteFX Graphics performance counters");
        sb.AppendLine();

        // Sample 3 times for stability
        RemoteFxMetrics? best = null;
        for (int i = 0; i < 3; i++)
        {
            var m = RdpSessionMonitor.ReadRemoteFxCounters();
            if (m != null) best = m;
            if (i < 2) await Task.Delay(700, ct);
        }

        if (best == null || !best.HasGraphicsCounters)
        {
            sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
            sb.AppendLine("  Session may be idle or counters may be disabled.");
            result.Status = TestStatus.Warning;
            result.ResultValue = "Counters unavailable";
            result.DetailedInfo = sb.ToString().TrimEnd();
            return;
        }

        // Frame rate
        if (best.InputFramesPerSec.HasValue)
            sb.AppendLine($"Input Frames/sec:  {best.InputFramesPerSec:F1}");
        if (best.OutputFramesPerSec.HasValue)
            sb.AppendLine($"Output Frames/sec: {best.OutputFramesPerSec:F1}");

        // Encoding
        if (best.AvgEncodingTime.HasValue)
        {
            var encTime = best.AvgEncodingTime.Value;
            var encStatus = encTime < 33 ? "✓ Good" : "⚠ High";
            sb.AppendLine($"Avg Encoding Time: {encTime:F1}ms ({encStatus}, target <33ms)");
        }

        // Quality
        if (best.FrameQuality.HasValue)
            sb.AppendLine($"Frame Quality:     {best.FrameQuality:F0}%");

        // Bandwidth
        if (best.UdpBandwidth.HasValue)
            sb.AppendLine($"UDP Bandwidth:     {best.UdpBandwidth:F0} KB/s");

        // Frame drops
        sb.AppendLine();
        sb.AppendLine("Frame Drop Analysis:");
        if (best.FramesSkippedNetwork.HasValue)
            sb.AppendLine($"  Skipped (Network):  {best.FramesSkippedNetwork:F1}/sec");
        if (best.FramesSkippedClient.HasValue)
            sb.AppendLine($"  Skipped (Client):   {best.FramesSkippedClient:F1}/sec");
        if (best.FramesSkippedServer.HasValue)
            sb.AppendLine($"  Skipped (Server):   {best.FramesSkippedServer:F1}/sec");

        // User input delay
        if (best.HasInputDelayCounter && best.UserInputDelay.HasValue)
        {
            sb.AppendLine();
            sb.AppendLine($"User Input Delay:  {best.UserInputDelay:F0}ms");
        }

        // Determine overall status
        float totalSkipped = (best.FramesSkippedNetwork ?? 0) + (best.FramesSkippedClient ?? 0) + (best.FramesSkippedServer ?? 0);
        float outputFps = best.OutputFramesPerSec ?? 30;
        float dropPct = outputFps > 0 ? totalSkipped / (outputFps + totalSkipped) * 100 : 0;

        if (best.AvgEncodingTime is > 33)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{best.OutputFramesPerSec:F0} fps, encoding slow ({best.AvgEncodingTime:F0}ms)";
            result.RemediationText = "Encoding time exceeds 33ms. This indicates the Cloud PC GPU/CPU is overloaded. Consider upgrading the Cloud PC SKU.";
        }
        else if (dropPct > 15)
        {
            result.Status = TestStatus.Warning;
            var bottleneck = GetBottleneck(best);
            result.ResultValue = $"{best.OutputFramesPerSec:F0} fps, {dropPct:F0}% frames dropped ({bottleneck})";
            result.RemediationText = $"Frame drop rate is high ({dropPct:F0}%). Primary bottleneck: {bottleneck}. " +
                                     "This causes stutter and poor user experience.";
        }
        else if (outputFps < 15 && outputFps > 0)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{best.OutputFramesPerSec:F0} fps (low)";
            result.RemediationText = "Frame rate is below 15 fps. This may be acceptable for static content but will cause choppy video and scrolling.";
        }
        else
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = $"{best.OutputFramesPerSec:F0} fps, {best.FrameQuality:F0}% quality";
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
    }

    private static string GetBottleneck(RemoteFxMetrics m)
    {
        float network = m.FramesSkippedNetwork ?? 0;
        float client = m.FramesSkippedClient ?? 0;
        float server = m.FramesSkippedServer ?? 0;

        if (network >= client && network >= server) return "network";
        if (client >= network && client >= server) return "client";
        return "server";
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 20 – Connection Jitter
// ════════════════════════════════════════════════════════════════════
public class ConnectionJitterTest : BaseTest
{
    public override string Id => "20";
    public override string Name => "Connection Jitter";
    public override string Description => "Measures jitter (variation in round-trip time) by sampling TCP latency 20 times. High jitter (>30ms) causes choppy remote desktop and poor Teams quality.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override int TimeoutSeconds => 45;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var endpoint = EndpointConfiguration.GetBestGatewayEndpoint();
        var resolvedIps = await Dns.GetHostAddressesAsync(endpoint, ct);
        var ip = resolvedIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        bool inRange = ip != null && EndpointConfiguration.IsInW365Range(ip);

        sb.AppendLine($"Endpoint: {endpoint}:{EndpointConfiguration.GatewayPort}");
        if (ip != null)
            sb.AppendLine($"Resolved IP: {ip} ({(inRange ? $"✓ within W365 range" : $"⚠ outside expected W365 ranges ({EndpointConfiguration.W365RangesDisplay})")})");
        sb.AppendLine("Samples: 20 TCP connect probes at 250ms intervals");
        sb.AppendLine();

        var jitterResult = await RdpSessionMonitor.MeasureJitter(
            endpoint, EndpointConfiguration.GatewayPort, 20, ct);

        if (!jitterResult.Success)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Measurement failed";
            sb.AppendLine($"✗ {jitterResult.Error}");
            result.RemediationText = "Could not measure jitter. Gateway may be unreachable.";
            result.DetailedInfo = sb.ToString().TrimEnd();
            return;
        }

        sb.AppendLine($"Successful samples: {jitterResult.Samples.Count}/20");
        sb.AppendLine();
        sb.AppendLine("Latency Statistics:");
        sb.AppendLine($"  Mean RTT:   {jitterResult.MeanRtt:F1}ms");
        sb.AppendLine($"  Min RTT:    {jitterResult.MinRtt:F1}ms");
        sb.AppendLine($"  Max RTT:    {jitterResult.MaxRtt:F1}ms");
        sb.AppendLine($"  P95 RTT:    {jitterResult.P95Rtt:F1}ms");
        sb.AppendLine();
        sb.AppendLine("Jitter Analysis:");
        sb.AppendLine($"  Jitter (mean abs diff):  {jitterResult.Jitter:F1}ms");
        sb.AppendLine($"  Std Deviation:           {jitterResult.StdDev:F1}ms");
        sb.AppendLine($"  RTT Spread (max-min):    {jitterResult.MaxRtt - jitterResult.MinRtt:F1}ms");
        sb.AppendLine();

        // RTT values
        sb.AppendLine("RTT Samples:");
        sb.Append("  ");
        for (int i = 0; i < jitterResult.Samples.Count; i++)
        {
            sb.Append($"{jitterResult.Samples[i]:F0}");
            if (i < jitterResult.Samples.Count - 1) sb.Append(", ");
        }
        sb.AppendLine(" (ms)");

        // Quality assessment
        sb.AppendLine();
        var jitter = jitterResult.Jitter;
        var spread = jitterResult.MaxRtt - jitterResult.MinRtt;

        if (jitter < 10)
        {
            sb.AppendLine("✓ Jitter is excellent (<10ms). Ideal for remote desktop and Teams.");
            result.Status = TestStatus.Passed;
            result.ResultValue = $"{jitter:F1}ms jitter (excellent)";
        }
        else if (jitter < 30)
        {
            sb.AppendLine("✓ Jitter is acceptable (<30ms). Good enough for remote desktop.");
            result.Status = TestStatus.Passed;
            result.ResultValue = $"{jitter:F1}ms jitter (good)";
        }
        else if (jitter < 60)
        {
            sb.AppendLine("⚠ Jitter is elevated (30-60ms). May cause occasional stutter.");
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{jitter:F1}ms jitter (elevated)";
            result.RemediationText = "Network jitter is elevated. This can cause intermittent stuttering in remote desktop sessions and poor Teams audio/video. " +
                                     "Common causes: Wi-Fi interference, congested network links, VPN overhead, or proxy-based TLS inspection.";
        }
        else
        {
            sb.AppendLine("✗ Jitter is very high (>60ms). This will significantly impact user experience.");
            result.Status = TestStatus.Failed;
            result.ResultValue = $"{jitter:F1}ms jitter (poor)";
            result.RemediationText = "Network jitter is very high. Users will experience choppy visuals, input lag spikes, and poor audio quality. " +
                                     "Investigate: Wi-Fi stability, switch to wired ethernet, check for bandwidth contention, disable VPN for RDP traffic, " +
                                     "and ensure the network path doesn't include TLS-inspecting proxies.";
        }

        // Extra guidance on spread
        if (spread > 100)
        {
            sb.AppendLine();
            sb.AppendLine($"⚠ RTT spread is {spread:F0}ms — some samples were much slower than others.");
            sb.AppendLine("  This suggests intermittent network congestion or route changes.");
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 21 – Frame Drops / Packet Loss
// ════════════════════════════════════════════════════════════════════
public class FrameDropTest : BaseTest
{
    public override string Id => "21";
    public override string Name => "Frame Drops & Packet Loss";
    public override string Description => "Detects frame drops from RemoteFX counters (inside session) or estimates packet loss from TCP probe failures (from physical device). Frame drops >15% at low fps indicate problems.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override int TimeoutSeconds => 30;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var sb = new StringBuilder();

        if (RdpSessionMonitor.IsRemoteSession())
        {
            await MeasureRemoteFxFrameDrops(result, sb, ct);
        }
        else
        {
            await EstimatePacketLoss(result, sb, ct);
        }

        result.DetailedInfo = sb.ToString().TrimEnd();
    }

    private static async Task MeasureRemoteFxFrameDrops(TestResult result, StringBuilder sb, CancellationToken ct)
    {
        sb.AppendLine("Source: RemoteFX Graphics performance counters (inside remote session)");
        sb.AppendLine();

        // Sample 3 times
        var samples = new List<RemoteFxMetrics>();
        for (int i = 0; i < 3; i++)
        {
            var m = RdpSessionMonitor.ReadRemoteFxCounters();
            if (m?.HasGraphicsCounters == true) samples.Add(m);
            if (i < 2) await Task.Delay(700, ct);
        }

        if (samples.Count == 0)
        {
            sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
            result.Status = TestStatus.Warning;
            result.ResultValue = "Counters unavailable";
            return;
        }

        var latest = samples.Last();
        var networkDrop = latest.FramesSkippedNetwork ?? 0;
        var clientDrop = latest.FramesSkippedClient ?? 0;
        var serverDrop = latest.FramesSkippedServer ?? 0;
        var totalDrop = networkDrop + clientDrop + serverDrop;
        var outputFps = latest.OutputFramesPerSec ?? 0;
        var inputFps = latest.InputFramesPerSec ?? 0;

        sb.AppendLine($"Input Frames/sec:     {inputFps:F1}");
        sb.AppendLine($"Output Frames/sec:    {outputFps:F1}");
        sb.AppendLine();
        sb.AppendLine("Frames Skipped/sec:");
        sb.AppendLine($"  Network resources:  {networkDrop:F1}");
        sb.AppendLine($"  Client resources:   {clientDrop:F1}");
        sb.AppendLine($"  Server resources:   {serverDrop:F1}");
        sb.AppendLine($"  Total:              {totalDrop:F1}");

        float dropPct = (outputFps + totalDrop) > 0
            ? totalDrop / (outputFps + totalDrop) * 100
            : 0;

        sb.AppendLine();
        sb.AppendLine($"Effective frame drop rate: {dropPct:F1}%");

        // Microsoft thresholds:
        // Low fps (<15): >15% = Poor, 10-15% = Okay, <10% = Good
        // High fps (>15): >50% = Poor, 20-50% = Okay, <20% = Good
        bool isLowFps = outputFps < 15;
        sb.AppendLine();
        sb.AppendLine($"Quality tier (Microsoft thresholds for {(isLowFps ? "low" : "high")} frame rate):");

        if (isLowFps)
        {
            if (dropPct < 10)
            {
                sb.AppendLine("  ✓ Good (< 10% at low fps)");
                result.Status = TestStatus.Passed;
                result.ResultValue = $"{dropPct:F0}% frame drops (good)";
            }
            else if (dropPct < 15)
            {
                sb.AppendLine("  ⚠ Okay (10-15% at low fps)");
                result.Status = TestStatus.Warning;
                result.ResultValue = $"{dropPct:F0}% frame drops (okay)";
            }
            else
            {
                sb.AppendLine("  ✗ Poor (>15% at low fps)");
                result.Status = TestStatus.Failed;
                result.ResultValue = $"{dropPct:F0}% frame drops (poor)";
            }
        }
        else
        {
            if (dropPct < 20)
            {
                sb.AppendLine("  ✓ Good (< 20% at high fps)");
                result.Status = TestStatus.Passed;
                result.ResultValue = $"{dropPct:F0}% frame drops (good)";
            }
            else if (dropPct < 50)
            {
                sb.AppendLine("  ⚠ Okay (20-50% at high fps)");
                result.Status = TestStatus.Warning;
                result.ResultValue = $"{dropPct:F0}% frame drops (okay)";
            }
            else
            {
                sb.AppendLine("  ✗ Poor (>50% at high fps)");
                result.Status = TestStatus.Failed;
                result.ResultValue = $"{dropPct:F0}% frame drops (poor)";
            }
        }

        if (totalDrop > 0)
        {
            var bottleneck = networkDrop >= clientDrop && networkDrop >= serverDrop ? "Network"
                           : clientDrop >= serverDrop ? "Client" : "Server";
            sb.AppendLine();
            sb.AppendLine($"Primary bottleneck: {bottleneck}");
            result.RemediationText = bottleneck switch
            {
                "Network" => "Frame drops are primarily due to insufficient network bandwidth. Check for " +
                             "network congestion, bandwidth throttling, or ensure UDP transport (RDP Shortpath) is enabled.",
                "Client" => "Frame drops are primarily due to client decode performance. The client device " +
                            "may have insufficient GPU/CPU resources. Close other resource-intensive applications.",
                "Server" => "Frame drops are primarily due to server-side encoding. The Cloud PC may be " +
                            "overloaded. Consider upgrading to a higher Cloud PC SKU with more CPU/GPU resources.",
                _ => "Check network, client, and server resources."
            };
        }
    }

    private static async Task EstimatePacketLoss(TestResult result, StringBuilder sb, CancellationToken ct)
    {
        sb.AppendLine("Source: TCP connect probe reliability (from physical device)");
        sb.AppendLine("ℹ For per-frame drop analysis, run this tool inside the Cloud PC.");
        sb.AppendLine();

        var endpoint = EndpointConfiguration.GetBestGatewayEndpoint();
        var resolvedIps = await Dns.GetHostAddressesAsync(endpoint, ct);
        var ip = resolvedIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        bool inRange = ip != null && EndpointConfiguration.IsInW365Range(ip);

        sb.AppendLine($"Endpoint: {endpoint}:{EndpointConfiguration.GatewayPort}");
        if (ip != null)
            sb.AppendLine($"Resolved IP: {ip} ({(inRange ? $"✓ within W365 range" : $"⚠ outside expected W365 ranges ({EndpointConfiguration.W365RangesDisplay})")})");
        sb.AppendLine("Probes: 15 TCP connection attempts");
        sb.AppendLine();

        int success = 0;
        int failure = 0;

        for (int i = 0; i < 15; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(3000);
                await tcp.ConnectAsync(endpoint, EndpointConfiguration.GatewayPort, cts.Token);
                success++;
            }
            catch
            {
                failure++;
            }

            if (i < 14) await Task.Delay(200, ct);
        }

        var lossRate = failure > 0 ? (double)failure / (success + failure) * 100 : 0;

        sb.AppendLine($"Successful: {success}/15");
        sb.AppendLine($"Failed:     {failure}/15");
        sb.AppendLine($"Loss rate:  {lossRate:F0}%");

        if (failure == 0)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "0% loss (15/15 successful)";
        }
        else if (lossRate < 5)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = $"{lossRate:F0}% loss";
        }
        else if (lossRate < 15)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{lossRate:F0}% loss";
            result.RemediationText = "Some connection attempts failed. This suggests intermittent connectivity issues " +
                                     "that may cause session drops or stutter. Check network stability.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = $"{lossRate:F0}% loss (significant)";
            result.RemediationText = "High connection failure rate detected. This indicates severe network reliability issues " +
                                     "that will cause frequent disconnections and poor user experience.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 22 – Teams Optimization on Cloud PC
// ════════════════════════════════════════════════════════════════════
public class CloudTeamsOptimizationTest : BaseTest
{
    public override string Id => "22";
    public override string Name => "Cloud PC Teams Optimization";
    public override string Description => "Checks whether Teams media optimization is properly configured on the Cloud PC/Session Host for optimal audio/video.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will verify the Teams media optimization (Slimcore)\n" +
                              "configuration on the virtual desktop side.";
        result.RemediationUrl = EndpointConfiguration.Docs.TeamsOptimization;
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 24 – VPN Connection Performance
// ════════════════════════════════════════════════════════════════════
public class VpnPerformanceTest : BaseTest
{
    public override string Id => "24";
    public override string Name => "VPN Connection Performance";
    public override string Description => "Evaluates the impact of VPN on connection performance. If connections are flaky over VPN or bandwidth is lower, suggests connecting without VPN.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will compare connection performance with and without VPN\n" +
                              "to determine if the VPN is negatively impacting the remote desktop experience.";
        return Task.CompletedTask;
    }
}
