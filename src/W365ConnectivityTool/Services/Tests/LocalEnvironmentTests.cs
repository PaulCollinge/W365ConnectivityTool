using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Services.Tests;

// ════════════════════════════════════════════════════════════════════
// ID 01 – Location of User
// ════════════════════════════════════════════════════════════════════
public class LocationTest : BaseTest
{
    public override string Id => "01";
    public override string Name => "User Location";
    public override string Description => "Determines the physical location of the user based on their public IP address. This contextualizes latency results.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        using var http = new HttpClient(new HttpClientHandler { DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials }) { Timeout = TimeSpan.FromSeconds(10) };
        var json = await EndpointConfiguration.FetchGeoIpJsonAsync(http, ct);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("city", out var cityProp) && !string.IsNullOrEmpty(cityProp.GetString()))
        {
            var city = cityProp.GetString();
            var country = root.TryGetProperty("country", out var countryProp) ? countryProp.GetString() : "Unknown";
            result.ResultValue = $"{city}, {country}";
            result.DetailedInfo = root.TryGetProperty("ip", out var ipProp) ? $"Public IP: {ipProp.GetString()}" : "";
            result.Status = TestStatus.Passed;
        }
        else
        {
            result.ResultValue = "Unable to determine location";
            result.Status = TestStatus.Warning;
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 02 – DNS Performance
// ════════════════════════════════════════════════════════════════════
public class DnsPerformanceTest : BaseTest
{
    public override string Id => "02";
    public override string Name => "DNS Performance";
    public override string Description => "Measures DNS resolution time for key Windows 365/AVD endpoints. Slow DNS can delay connection establishment.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var (dnsServerIp, dnsServerName) = GetSystemDnsServerInfo();
        var results = new List<(string host, double ms, IPAddress[] addresses)>();

        // Also include gateway FQDNs from discovered connections
        var testHosts = new List<string>(EndpointConfiguration.DnsTestHostnames);
        var connections = RdpFileParser.DiscoverConnections();
        var gatewayFqdns = connections
            .Where(c => c.GatewayHostname.EndsWith(".wvd.microsoft.com", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.GatewayHostname)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var gw in gatewayFqdns)
        {
            if (!testHosts.Contains(gw, StringComparer.OrdinalIgnoreCase))
                testHosts.Add(gw);
        }

        foreach (var hostname in testHosts)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var entry = await Dns.GetHostEntryAsync(hostname, ct);
                sw.Stop();
                results.Add((hostname, sw.Elapsed.TotalMilliseconds, entry.AddressList));
            }
            catch
            {
                results.Add((hostname, -1, []));
            }
        }

        var resolved = results.Where(r => r.ms >= 0).ToList();
        var avgMs = resolved.Count > 0 ? resolved.Average(r => r.ms) : 0;
        var maxMs = resolved.Count > 0 ? resolved.Max(r => r.ms) : 0;

        result.ResultValue = $"{avgMs:F0}ms avg ({maxMs:F0}ms max)";

        var details = new List<string>();
        details.Add($"DNS Server: {dnsServerIp}");
        if (!string.IsNullOrEmpty(dnsServerName) && dnsServerName != dnsServerIp)
            details.Add($"DNS Server Name: {dnsServerName}");
        details.Add("");
        foreach (var r in results)
        {
            if (r.ms >= 0)
                details.Add($"  {r.host}: {r.ms:F1}ms → {string.Join(", ", r.addresses.Select(a => a.ToString()))}");
            else
                details.Add($"  {r.host}: FAILED");
        }
        result.DetailedInfo = string.Join("\n", details);

        if (avgMs < 50)
            result.Status = TestStatus.Passed;
        else if (avgMs < 200)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "DNS resolution is slower than recommended. Consider using a faster DNS provider or checking DNS configuration.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "DNS resolution is critically slow and will impact connection times. Review DNS server configuration.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.DnsConfig;
    }

    private static (string ip, string name) GetSystemDnsServerInfo()
    {
        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            foreach (var adapter in adapters)
            {
                var dnsAddresses = adapter.GetIPProperties().DnsAddresses;
                if (dnsAddresses.Count > 0)
                {
                    var ip = string.Join(", ", dnsAddresses);
                    // Try reverse DNS on the first DNS server
                    string name = "";
                    try
                    {
                        var entry = Dns.GetHostEntry(dnsAddresses[0]);
                        if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != dnsAddresses[0].ToString())
                            name = entry.HostName;
                    }
                    catch { }
                    return (ip, name);
                }
            }
        }
        catch { }
        return ("Unknown", "");
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 03 – Wired/Wireless Connectivity
// ════════════════════════════════════════════════════════════════════
public class NetworkTypeTest : BaseTest
{
    public override string Id => "03";
    public override string Name => "Connection Type";
    public override string Description => "Detects whether the device is using a wired (Ethernet) or wireless (Wi-Fi) network connection.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var activeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .ToList();

        var types = new List<string>();
        var details = new List<string>();

        foreach (var iface in activeInterfaces)
        {
            var type = iface.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Ethernet => "Wired (Ethernet)",
                NetworkInterfaceType.Wireless80211 => "Wi-Fi",
                NetworkInterfaceType.GigabitEthernet => "Wired (Gigabit)",
                _ => iface.NetworkInterfaceType.ToString()
            };
            types.Add(type);
            details.Add($"  {iface.Name}: {type} — Speed: {FormatSpeed(iface.Speed)}");
        }

        if (types.Count == 0)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "No active network connection";
            result.RemediationText = "No active network interfaces detected. Check that a network cable is connected or Wi-Fi is enabled.";
        }
        else
        {
            result.ResultValue = string.Join(" + ", types.Distinct());
            result.DetailedInfo = string.Join("\n", details);
            result.Status = types.Any(t => t.Contains("Wired")) ? TestStatus.Passed : TestStatus.Warning;

            if (!types.Any(t => t.Contains("Wired")))
                result.RemediationText = "A wired connection is recommended for optimal performance. Consider switching from Wi-Fi to Ethernet if possible.";
        }

        return Task.CompletedTask;
    }

    private static string FormatSpeed(long bitsPerSecond)
    {
        if (bitsPerSecond <= 0) return "Unknown";
        if (bitsPerSecond >= 1_000_000_000) return $"{bitsPerSecond / 1_000_000_000.0:F0} Gbps";
        if (bitsPerSecond >= 1_000_000) return $"{bitsPerSecond / 1_000_000.0:F0} Mbps";
        return $"{bitsPerSecond / 1_000.0:F0} Kbps";
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 04 – Wi-Fi Signal Strength
// ════════════════════════════════════════════════════════════════════
public class WifiStrengthTest : BaseTest
{
    public override string Id => "04";
    public override string Name => "Wi-Fi Signal Strength";
    public override string Description => "Checks Wi-Fi signal quality and version. Poor signal leads to packet loss and latency.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        // Check if any wireless interface exists
        var hasWireless = NetworkInterface.GetAllNetworkInterfaces()
            .Any(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                      n.OperationalStatus == OperationalStatus.Up);

        if (!hasWireless)
        {
            result.Status = TestStatus.Skipped;
            result.ResultValue = "No Wi-Fi connection (wired)";
            result.DetailedInfo = "Device is using a wired connection. Wi-Fi signal test is not applicable.";
            return;
        }

        var netshOutput = await RunNetshAsync(ct);
        var parsed = ParseNetshOutput(netshOutput);

        if (parsed.SignalPercent.HasValue)
        {
            var signal = parsed.SignalPercent.Value;
            var dbm = (signal / 2.0) - 100; // Approximate conversion

            var quality = signal switch
            {
                >= 80 => "Excellent",
                >= 60 => "Good",
                >= 40 => "Fair",
                _ => "Poor"
            };

            result.ResultValue = $"{quality} ({signal}% / ~{dbm:F0} dBm)";
            result.DetailedInfo = $"SSID: {parsed.Ssid ?? "Unknown"}\n" +
                                  $"Radio Type: {parsed.RadioType ?? "Unknown"}\n" +
                                  $"Channel: {parsed.Channel ?? "Unknown"}\n" +
                                  $"Receive Rate: {parsed.ReceiveRate ?? "Unknown"}\n" +
                                  $"Transmit Rate: {parsed.TransmitRate ?? "Unknown"}";

            if (signal >= 60)
            {
                result.Status = TestStatus.Passed;
            }
            else if (signal >= 40)
            {
                result.Status = TestStatus.Warning;
                result.RemediationText = "Wi-Fi signal is fair. Consider moving closer to your access point or switching to a wired connection.";
            }
            else
            {
                result.Status = TestStatus.Failed;
                result.RemediationText = "Wi-Fi signal is poor and will significantly impact remote desktop performance. Move closer to the access point, switch to a 5GHz band, or use a wired connection.";
            }
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Unable to read Wi-Fi signal";
            result.DetailedInfo = netshOutput;
        }

        result.RemediationUrl = EndpointConfiguration.Docs.WifiPerformance;
    }

    private static async Task<string> RunNetshAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)!;
        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return output;
    }

    private static WifiInfo ParseNetshOutput(string output)
    {
        var info = new WifiInfo();
        var lines = output.Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("Signal", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(trimmed, @"(\d+)%");
                if (match.Success) info.SignalPercent = int.Parse(match.Groups[1].Value);
            }
            else if (trimmed.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && !trimmed.Contains("BSSID"))
                info.Ssid = trimmed.Split(':').LastOrDefault()?.Trim();
            else if (trimmed.StartsWith("Radio type", StringComparison.OrdinalIgnoreCase))
                info.RadioType = trimmed.Split(':').LastOrDefault()?.Trim();
            else if (trimmed.StartsWith("Channel", StringComparison.OrdinalIgnoreCase))
                info.Channel = trimmed.Split(':').LastOrDefault()?.Trim();
            else if (trimmed.StartsWith("Receive rate", StringComparison.OrdinalIgnoreCase))
                info.ReceiveRate = trimmed.Split(':').LastOrDefault()?.Trim();
            else if (trimmed.StartsWith("Transmit rate", StringComparison.OrdinalIgnoreCase))
                info.TransmitRate = trimmed.Split(':').LastOrDefault()?.Trim();
        }

        return info;
    }

    private class WifiInfo
    {
        public int? SignalPercent { get; set; }
        public string? Ssid { get; set; }
        public string? RadioType { get; set; }
        public string? Channel { get; set; }
        public string? ReceiveRate { get; set; }
        public string? TransmitRate { get; set; }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 05 – Latency to Local Router
// ════════════════════════════════════════════════════════════════════
public class RouterLatencyTest : BaseTest
{
    public override string Id => "05";
    public override string Name => "Local Router Latency";
    public override string Description => "Measures ping latency to the default gateway (local router). High local latency indicates a local network issue.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var gateway = GetDefaultGateway();
        if (gateway == null)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "No default gateway found";
            result.RemediationText = "No default gateway detected. Check your network configuration.";
            return;
        }

        using var ping = new Ping();
        var latencies = new List<long>();

        for (int i = 0; i < 5; i++)
        {
            var reply = await ping.SendPingAsync(gateway, 2000);
            if (reply.Status == IPStatus.Success)
                latencies.Add(reply.RoundtripTime);

            if (i < 4) await Task.Delay(200, ct);
        }

        if (latencies.Count == 0)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"Gateway {gateway} not responding to ping";
            result.DetailedInfo = "The default gateway does not respond to ICMP ping requests. This may be normal if ICMP is blocked.";
            return;
        }

        var avg = latencies.Average();
        var max = latencies.Max();

        result.ResultValue = $"{avg:F0}ms avg ({max}ms max)";
        result.DetailedInfo = $"Gateway: {gateway}\nPing responses: {latencies.Count}/5\nValues: {string.Join(", ", latencies.Select(l => $"{l}ms"))}";

        if (avg < 20)
            result.Status = TestStatus.Passed;
        else if (avg < 50)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "Local network latency is elevated (>20ms). Check for network congestion, Wi-Fi interference, or long cable runs.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "Local network latency is very high (>50ms). This will significantly impact remote desktop performance. Check physical network connections, switch to wired, or investigate local network issues.";
        }
    }

    private static IPAddress? GetDefaultGateway()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().GatewayAddresses)
            .Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(g => g.Address)
            .FirstOrDefault();
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 06 – ISP Detection
// ════════════════════════════════════════════════════════════════════
public class IspDetectionTest : BaseTest
{
    public override string Id => "06";
    public override string Name => "ISP Detection";
    public override string Description => "Identifies the Internet Service Provider used for connectivity. Helps identify poorly performing ISPs or incorrect network paths.";
    public override TestCategory Category => TestCategory.LocalEnvironment;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        using var http = new HttpClient(new HttpClientHandler { DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials }) { Timeout = TimeSpan.FromSeconds(10) };
        var json = await EndpointConfiguration.FetchGeoIpJsonAsync(http, ct);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // ipinfo.io returns a single "org" field containing ASN + ISP name
        // e.g. "AS5089 Virgin Media Limited"
        if (root.TryGetProperty("org", out var orgProp) && !string.IsNullOrEmpty(orgProp.GetString()))
        {
            var orgFull = orgProp.GetString()!;
            // Split "AS12345 ISP Name" into ASN and ISP
            var spaceIdx = orgFull.IndexOf(' ');
            var asn = spaceIdx > 0 ? orgFull[..spaceIdx] : orgFull;
            var isp = spaceIdx > 0 ? orgFull[(spaceIdx + 1)..] : orgFull;

            result.ResultValue = isp;
            result.DetailedInfo = $"Organization: {isp}\nAS: {asn}\n\n" +
                                  "Tip: Check https://downdetector.com to see if your ISP is currently experiencing issues.";
            result.Status = TestStatus.Passed;
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Unable to detect ISP";
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 07 – Local Bandwidth / Throughput
// ════════════════════════════════════════════════════════════════════
public class BandwidthTest : BaseTest
{
    public override string Id => "07";
    public override string Name => "Local Bandwidth";
    public override string Description => "Measures download/upload throughput using Speedtest.net (Ookla CLI) with Cloudflare as a fallback.";
    public override TestCategory Category => TestCategory.LocalEnvironment;
    public override TestPriority Priority => TestPriority.Important;
    public override int TimeoutSeconds => 120;

    private static readonly string SpeedtestDir = FindSpeedtestDir();

    private static string FindSpeedtestDir()
    {
        // 1. Next to the running exe (deployed scenario)
        var exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!;
        var candidate = Path.Combine(exeDir, "tools", "speedtest");
        if (Directory.Exists(candidate)) return candidate;

        // 2. Project root /tools/speedtest (development scenario)
        candidate = Path.Combine(exeDir, "..", "..", "..", "..", "tools", "speedtest");
        candidate = Path.GetFullPath(candidate);
        if (Directory.Exists(candidate)) return candidate;

        // 3. Default to %LOCALAPPDATA%\W365ConnectivityTool\speedtest
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "W365ConnectivityTool", "speedtest");
    }

    private static string SpeedtestExe => Path.Combine(SpeedtestDir, "speedtest.exe");

    private const string SpeedtestDownloadUrl =
        "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip";

    private const string CloudflareUrl = "https://speed.cloudflare.com/__down?bytes=10000000"; // 10MB

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();

        // ── Try Speedtest.net (Ookla CLI) first ──
        var speedtestResult = await RunSpeedtestCliAsync(details, ct);

        // ── Always run Cloudflare as a second data point ──
        var cloudflareResult = await RunCloudflareTestAsync(details, ct);

        // ── Evaluate results ──
        double bestDownMbps = 0;
        string bestSource = "none";

        if (speedtestResult != null)
        {
            bestDownMbps = speedtestResult.Value.DownMbps;
            bestSource = "Speedtest.net";
        }

        if (cloudflareResult != null && cloudflareResult.Value.Mbps > bestDownMbps)
        {
            bestDownMbps = cloudflareResult.Value.Mbps;
            bestSource = "Cloudflare";
        }

        if (bestDownMbps <= 0)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "All tests failed";
            result.DetailedInfo = string.Join("\n", details);
            result.RemediationText = "Could not reach any speed test servers. Check internet connectivity.";
            result.RemediationUrl = EndpointConfiguration.Docs.Bandwidth;
            return;
        }

        // Build summary
        if (speedtestResult != null)
        {
            result.ResultValue = $"↓ {speedtestResult.Value.DownMbps:F0} / ↑ {speedtestResult.Value.UpMbps:F0} Mbps (Speedtest.net)";
        }
        else
        {
            result.ResultValue = $"↓ {bestDownMbps:F1} Mbps ({bestSource})";
        }

        result.DetailedInfo = string.Join("\n", details);

        if (bestDownMbps >= 20)
        {
            result.Status = TestStatus.Passed;
        }
        else if (bestDownMbps >= 5)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "Bandwidth is below the recommended 20 Mbps for optimal remote desktop experience.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "Bandwidth is critically low (<5 Mbps) and will cause poor remote desktop performance.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.Bandwidth;
    }

    private record struct SpeedtestCliResult(
        double DownMbps, double UpMbps, double PingMs, double Jitter,
        string Isp, string Server, string ServerLocation, string ResultUrl);

    private async Task<SpeedtestCliResult?> RunSpeedtestCliAsync(List<string> details, CancellationToken ct)
    {
        try
        {
            // Auto-download Speedtest CLI if not present
            if (!File.Exists(SpeedtestExe))
            {
                await DownloadSpeedtestCliAsync(details, ct);
                if (!File.Exists(SpeedtestExe))
                {
                    details.Add("⚠ Speedtest CLI not available — skipping");
                    details.Add("");
                    return null;
                }
            }

            details.Add("── Speedtest.net (Ookla CLI) ──");

            var psi = new ProcessStartInfo
            {
                FileName = SpeedtestExe,
                Arguments = "--accept-license --accept-gdpr --format=json",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                details.Add("✗ Failed to start speedtest.exe");
                details.Add("");
                return null;
            }

            var outputTask = process.StandardOutput.ReadToEndAsync(ct);
            var errorTask = process.StandardError.ReadToEndAsync(ct);

            // 90 second timeout for the full speedtest
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(90_000);

            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(true); } catch { }
                details.Add("✗ Speedtest timed out (90s)");
                details.Add("");
                return null;
            }

            var json = await outputTask;

            if (string.IsNullOrWhiteSpace(json))
            {
                details.Add($"✗ No output from speedtest.exe");
                details.Add("");
                return null;
            }

            // Parse JSON results
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // bandwidth is in bytes/sec, convert to Mbps
            var downBps = root.GetProperty("download").GetProperty("bandwidth").GetInt64();
            var upBps = root.GetProperty("upload").GetProperty("bandwidth").GetInt64();
            var downMbps = downBps * 8.0 / 1_000_000;
            var upMbps = upBps * 8.0 / 1_000_000;
            var pingMs = root.GetProperty("ping").GetProperty("latency").GetDouble();
            var jitter = root.GetProperty("ping").GetProperty("jitter").GetDouble();

            var isp = root.GetProperty("isp").GetString() ?? "?";
            var server = root.GetProperty("server");
            var serverName = server.GetProperty("name").GetString() ?? "?";
            var serverLoc = server.GetProperty("location").GetString() ?? "?";
            var serverCountry = server.GetProperty("country").GetString() ?? "?";
            var resultUrl = root.GetProperty("result").GetProperty("url").GetString() ?? "";

            var isVpn = root.GetProperty("interface").GetProperty("isVpn").GetBoolean();
            var packetLoss = root.TryGetProperty("packetLoss", out var pl) ? pl.GetDouble() : -1;

            details.Add($"  Download: {downMbps:F1} Mbps");
            details.Add($"  Upload:   {upMbps:F1} Mbps");
            details.Add($"  Ping:     {pingMs:F1}ms (jitter: {jitter:F1}ms)");
            if (packetLoss >= 0)
                details.Add($"  Packet Loss: {packetLoss:F1}%");
            details.Add($"  ISP:      {isp}");
            details.Add($"  Server:   {serverName} ({serverLoc}, {serverCountry})");
            if (isVpn)
                details.Add($"  ⚠ VPN detected on active interface");
            if (!string.IsNullOrEmpty(resultUrl))
                details.Add($"  Result:   {resultUrl}");
            details.Add("");

            return new SpeedtestCliResult(downMbps, upMbps, pingMs, jitter,
                isp, serverName, serverLoc, resultUrl);
        }
        catch (Exception ex)
        {
            details.Add($"✗ Speedtest.net error: {ex.Message}");
            details.Add("");
            return null;
        }
    }

    private record struct CloudflareResult(double Mbps, long Bytes, double Seconds);

    private async Task<CloudflareResult?> RunCloudflareTestAsync(List<string> details, CancellationToken ct)
    {
        try
        {
            details.Add("── Cloudflare Speed Test ──");

            using var http = new HttpClient(new HttpClientHandler { DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials }) { Timeout = TimeSpan.FromSeconds(30) };
            var sw = Stopwatch.StartNew();

            using var response = await http.GetAsync(CloudflareUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            long totalBytes = 0;
            var buffer = new byte[81920];
            using var stream = await response.Content.ReadAsStreamAsync(ct);

            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer, ct)) > 0)
                totalBytes += bytesRead;

            sw.Stop();
            var mbps = (totalBytes * 8.0 / 1_000_000) / sw.Elapsed.TotalSeconds;

            details.Add($"  Download: {mbps:F1} Mbps ({totalBytes / 1_000_000.0:F1} MB in {sw.Elapsed.TotalSeconds:F1}s)");
            details.Add("");

            return new CloudflareResult(mbps, totalBytes, sw.Elapsed.TotalSeconds);
        }
        catch (Exception ex)
        {
            details.Add($"  ✗ Cloudflare error: {ex.Message}");
            details.Add("");
            return null;
        }
    }

    private async Task DownloadSpeedtestCliAsync(List<string> details, CancellationToken ct)
    {
        try
        {
            details.Add("Downloading Speedtest CLI...");
            Directory.CreateDirectory(SpeedtestDir);

            using var http = new HttpClient(new HttpClientHandler { DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials }) { Timeout = TimeSpan.FromSeconds(30) };
            var zipBytes = await http.GetByteArrayAsync(SpeedtestDownloadUrl, ct);

            var zipPath = Path.Combine(Path.GetTempPath(), "speedtest-cli.zip");
            await File.WriteAllBytesAsync(zipPath, zipBytes, ct);

            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, SpeedtestDir, true);
            File.Delete(zipPath);

            details.Add("✓ Speedtest CLI downloaded");
        }
        catch (Exception ex)
        {
            details.Add($"✗ Failed to download Speedtest CLI: {ex.Message}");
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 08 – NAT Type
// ════════════════════════════════════════════════════════════════════
public class NatTypeTest : BaseTest
{
    public override string Id => "08";
    public override string Name => "NAT Type";
    public override string Description => "Identifies the NAT type in use. Symmetric NAT prevents STUN-based direct connections, forcing TURN relay usage which increases latency.";
    public override TestCategory Category => TestCategory.UdpShortpath;
    public override TestPriority Priority => TestPriority.Important;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        try
        {
            var (natType, mappedAddress, mappedPort) = await PerformStunCheckAsync(ct);

            result.ResultValue = natType;
            result.DetailedInfo = $"STUN Server: {EndpointConfiguration.StunServer}:{EndpointConfiguration.StunPort}\n" +
                                  $"Mapped Address: {mappedAddress}:{mappedPort}";

            if (natType.Contains("Full Cone") || natType.Contains("Open"))
            {
                result.Status = TestStatus.Passed;
                result.RemediationText = "NAT type supports STUN-based direct connections (RDP Shortpath).";
            }
            else if (natType.Contains("Symmetric"))
            {
                result.Status = TestStatus.Warning;
                result.RemediationText = "Symmetric NAT detected. STUN-based direct connections (RDP Shortpath with public networks) will NOT work. " +
                                         "Traffic will use TURN relay instead, which adds latency. Consider changing NAT configuration if possible.";
            }
            else
            {
                result.Status = TestStatus.Passed;
                result.RemediationText = $"NAT type ({natType}) supports STUN-based connections.";
            }

            result.RemediationUrl = EndpointConfiguration.Docs.NatType;
        }
        catch (Exception ex)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Unable to determine NAT type";
            result.DetailedInfo = $"STUN check failed: {ex.Message}\nUDP may be blocked on port {EndpointConfiguration.StunPort}.";
            result.RemediationText = "Could not determine NAT type. This may indicate UDP is blocked on your network.";
        }
    }

    private static async Task<(string natType, string mappedAddress, int mappedPort)> PerformStunCheckAsync(CancellationToken ct)
    {
        var serverAddresses = await Dns.GetHostAddressesAsync(EndpointConfiguration.StunServer, ct);
        var serverIp = serverAddresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);

        using var udpClient = new UdpClient(0, AddressFamily.InterNetwork);
        udpClient.Client.ReceiveTimeout = 5000;

        var localEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Build STUN Binding Request (RFC 5389)
        var request = BuildStunBindingRequest();
        await udpClient.SendAsync(request, request.Length, new IPEndPoint(serverIp, EndpointConfiguration.StunPort));

        var receiveTask = udpClient.ReceiveAsync(ct);
        var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(5000, ct));

        if (completed != receiveTask.AsTask())
            throw new TimeoutException("STUN request timed out");

        var response = await receiveTask;
        var (mappedAddress, mappedPort) = ParseStunResponse(response.Buffer);

        // Determine NAT type by comparing local vs mapped
        string natType;
        if (mappedAddress == GetLocalIpAddress() && mappedPort == localEndpoint.Port)
            natType = "Open Internet (No NAT)";
        else if (mappedPort == localEndpoint.Port)
            natType = "Full Cone NAT";
        else
            natType = "Restricted/Port-Restricted NAT";

        // For full NAT type detection, we'd need a second STUN test to a different endpoint
        // and compare the mapped addresses. For now, this provides a useful indicator.

        return (natType, mappedAddress, mappedPort);
    }

    private static byte[] BuildStunBindingRequest()
    {
        var request = new byte[20];
        // Message Type: Binding Request (0x0001)
        request[0] = 0x00;
        request[1] = 0x01;
        // Message Length: 0
        request[2] = 0x00;
        request[3] = 0x00;
        // Magic Cookie (0x2112A442)
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xA4;
        request[7] = 0x42;
        // Transaction ID (12 cryptographically random bytes — RFC 5389 §6)
        System.Security.Cryptography.RandomNumberGenerator.Fill(request.AsSpan(8, 12));
        return request;
    }

    private static (string address, int port) ParseStunResponse(byte[] data)
    {
        // Skip header (20 bytes), parse attributes
        int offset = 20;
        while (offset < data.Length - 4)
        {
            int attrType = (data[offset] << 8) | data[offset + 1];
            int attrLen = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;

            // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            if (attrType == 0x0020 && attrLen >= 8)
            {
                // XOR-MAPPED-ADDRESS
                int port = ((data[offset + 2] << 8) | data[offset + 3]) ^ 0x2112;
                byte[] ip =
                [
                    (byte)(data[offset + 4] ^ 0x21),
                    (byte)(data[offset + 5] ^ 0x12),
                    (byte)(data[offset + 6] ^ 0xA4),
                    (byte)(data[offset + 7] ^ 0x42)
                ];
                return (new IPAddress(ip).ToString(), port);
            }
            else if (attrType == 0x0001 && attrLen >= 8)
            {
                // MAPPED-ADDRESS
                int port = (data[offset + 2] << 8) | data[offset + 3];
                byte[] ip = [data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]];
                return (new IPAddress(ip).ToString(), port);
            }

            offset += attrLen;
            // Pad to 4-byte boundary
            if (attrLen % 4 != 0) offset += 4 - (attrLen % 4);
        }

        throw new InvalidOperationException("No mapped address found in STUN response");
    }

    private static string GetLocalIpAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect("8.8.8.8", 80);
            return ((IPEndPoint)socket.LocalEndPoint!).Address.ToString();
        }
        catch
        {
            return "0.0.0.0";
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 09 – Local Machine Performance
// ════════════════════════════════════════════════════════════════════
public class MachinePerformanceTest : BaseTest
{
    public override string Id => "09";
    public override string Name => "Local Machine Performance";
    public override string Description => "Checks local CPU and memory usage. High resource usage on the physical device can degrade remote desktop performance.";
    public override TestCategory Category => TestCategory.LocalEnvironment;
    public override TestPriority Priority => TestPriority.Important;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll")]
    private static extern void GetSystemTimes(out long idleTime, out long kernelTime, out long userTime);

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        // CPU usage measurement
        GetSystemTimes(out long idleStart, out long kernelStart, out long userStart);
        await Task.Delay(1000, ct);
        GetSystemTimes(out long idleEnd, out long kernelEnd, out long userEnd);

        var idleDiff = idleEnd - idleStart;
        var kernelDiff = kernelEnd - kernelStart;
        var userDiff = userEnd - userStart;
        var totalDiff = kernelDiff + userDiff;
        var cpuPercent = totalDiff > 0 ? (1.0 - (double)idleDiff / totalDiff) * 100 : 0;

        // Memory usage
        var memInfo = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref memInfo);

        var totalMemGB = memInfo.ullTotalPhys / (1024.0 * 1024 * 1024);
        var usedMemGB = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024.0 * 1024 * 1024);
        var memPercent = memInfo.dwMemoryLoad;

        result.ResultValue = $"CPU: {cpuPercent:F0}% | Memory: {memPercent}%";
        result.DetailedInfo = $"CPU Usage: {cpuPercent:F1}%\n" +
                              $"Cores: {Environment.ProcessorCount}\n" +
                              $"Memory: {usedMemGB:F1} GB / {totalMemGB:F1} GB ({memPercent}% used)\n" +
                              $"Available Memory: {memInfo.ullAvailPhys / (1024.0 * 1024 * 1024):F1} GB";

        if (cpuPercent < 70 && memPercent < 80)
        {
            result.Status = TestStatus.Passed;
        }
        else if (cpuPercent < 90 && memPercent < 90)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "Local machine resources are elevated. Close unnecessary applications to improve remote desktop performance.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "Local machine is under heavy load. This will significantly impact remote desktop performance. Close resource-intensive applications before connecting.";
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10 – Teams Optimization Support
// ════════════════════════════════════════════════════════════════════
public class TeamsOptimizationTest : BaseTest
{
    public override string Id => "10t";
    public override string Name => "Teams Optimization";
    public override string Description => "Checks whether Teams media optimization (Slimcore) is available on this device for optimized audio/video in virtual desktop sessions.";
    public override TestCategory Category => TestCategory.LocalEnvironment;
    public override TestPriority Priority => TestPriority.Important;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var checks = new List<string>();
        bool slimcoreFound = false;
        bool windowsAppFound = false;

        // Check for Windows App / MSRDC
        var msrdcPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Remote Desktop", "msrdc.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Apps", "Remote Desktop", "msrdc.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows App", "msrdc.exe")
        };

        foreach (var path in msrdcPaths)
        {
            if (File.Exists(path))
            {
                windowsAppFound = true;
                checks.Add($"✓ Windows App/MSRDC found: {path}");
                break;
            }
        }

        if (!windowsAppFound)
            checks.Add("⚠ Windows App/MSRDC not found in default locations");

        // Check for Slimcore/Teams media optimization components
        var slimcorePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages"),
        };

        // Check registry for Teams optimization
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Teams\TeamsMediaOptimization");
            if (key != null)
            {
                slimcoreFound = true;
                checks.Add("✓ Teams Media Optimization registry key found");
            }
            else
            {
                checks.Add("— Teams Media Optimization registry key not found");
            }
        }
        catch
        {
            checks.Add("— Unable to check Teams optimization registry");
        }

        // Check for new Teams (SlimCore-based)
        try
        {
            var processes = Process.GetProcessesByName("ms-teams");
            if (processes.Length > 0)
            {
                slimcoreFound = true;
                checks.Add("✓ New Teams (Slimcore) process running");
            }
            else
            {
                var classicTeams = Process.GetProcessesByName("Teams");
                if (classicTeams.Length > 0)
                    checks.Add("⚠ Classic Teams detected — upgrade to New Teams for optimal performance");
                else
                    checks.Add("— Teams not currently running");
            }
        }
        catch
        {
            checks.Add("— Unable to check Teams processes");
        }

        result.DetailedInfo = string.Join("\n", checks);

        if (slimcoreFound)
        {
            result.ResultValue = "Teams Optimized (Slimcore)";
            result.Status = TestStatus.Passed;
        }
        else if (windowsAppFound)
        {
            result.ResultValue = "Windows App found — Teams optimization unconfirmed";
            result.Status = TestStatus.Warning;
            result.RemediationText = "Ensure New Teams is installed and media optimization is enabled for optimal audio/video experience.";
        }
        else
        {
            result.ResultValue = "Not detected";
            result.Status = TestStatus.Warning;
            result.RemediationText = "Install Windows App and New Teams for optimal media experience in remote desktop sessions.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TeamsOptimization;
        return Task.CompletedTask;
    }
}
