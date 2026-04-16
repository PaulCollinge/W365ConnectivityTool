// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

        // Parse locale-independently: use value patterns instead of localized key names.
        // The " : " separator format is consistent across all locales.
        foreach (var line in lines)
        {
            var colonIdx = line.IndexOf(" : ");
            if (colonIdx < 0) continue;
            var key = line.Substring(0, colonIdx).Trim();
            var value = line.Substring(colonIdx + 3).Trim();

            // Signal: value is always "<digits>%" (e.g. "85%")
            if (!info.SignalPercent.HasValue)
            {
                var match = Regex.Match(value, @"^(\d+)%$");
                if (match.Success) { info.SignalPercent = int.Parse(match.Groups[1].Value); continue; }
            }

            // Radio type: value contains "802.11" (universal protocol name)
            if (info.RadioType == null && value.Contains("802.11"))
            { info.RadioType = value; continue; }

            // SSID (not BSSID): key doesn't contain "BSSID", value isn't a MAC address
            if (info.Ssid == null && !key.Contains("BSSID", StringComparison.OrdinalIgnoreCase)
                && key.Contains("SSID", StringComparison.OrdinalIgnoreCase))
            { info.Ssid = value; continue; }

            // Channel: a small integer (1-165), appears after signal in the output
            if (info.Channel == null && info.SignalPercent.HasValue
                && int.TryParse(value, out var ch) && ch >= 1 && ch <= 165)
            { info.Channel = value; continue; }

            // Receive/Transmit rate: value contains "Mbps" (universal unit)
            if (info.ReceiveRate == null && value.Contains("Mbps") && !value.Contains("802.11"))
            { info.ReceiveRate = value; continue; }
            else if (info.ReceiveRate != null && info.TransmitRate == null && value.Contains("Mbps") && !value.Contains("802.11"))
            { info.TransmitRate = value; continue; }
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
    public override string Description => "Measures download throughput using Cloudflare and OVH HTTPS download endpoints.";
    public override TestCategory Category => TestCategory.LocalEnvironment;
    public override TestPriority Priority => TestPriority.Important;
    public override int TimeoutSeconds => 120;

    private static readonly (string Url, long ExpectedBytes)[] TestEndpoints =
    [
        ("https://speed.cloudflare.com/__down?bytes=25000000", 25_000_000L),
        ("https://speed.cloudflare.com/__down?bytes=10000000", 10_000_000L),
        ("https://speed.cloudflare.com/__down?bytes=5000000", 5_000_000L)
    ];

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();
        details.Add("── HTTPS Download Test ──");

        double bestMbps = 0;
        string bestSource = "";

        using var http = new HttpClient(new HttpClientHandler
        {
            DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials
        })
        { Timeout = TimeSpan.FromSeconds(30) };

        foreach (var (testUrl, _) in TestEndpoints)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                using var response = await http.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                response.EnsureSuccessStatusCode();

                long totalBytes = 0;
                var buffer = new byte[81920];
                using var stream = await response.Content.ReadAsStreamAsync(ct);
                var measureDuration = TimeSpan.FromSeconds(10);

                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(buffer, ct)) > 0)
                {
                    totalBytes += bytesRead;
                    if (sw.Elapsed > measureDuration) break;
                }
                sw.Stop();

                if (totalBytes < 50_000 || sw.Elapsed.TotalSeconds < 0.5)
                    continue;

                var sizeMB = totalBytes / (1024.0 * 1024.0);
                var mbps = (sizeMB * 8) / sw.Elapsed.TotalSeconds;
                var host = new Uri(testUrl).Host;

                details.Add($"  {host}: {mbps:F1} Mbps ({sizeMB:F1} MB in {sw.Elapsed.TotalSeconds:F1}s)");

                if (mbps > bestMbps)
                {
                    bestMbps = mbps;
                    bestSource = host;
                }

                if (totalBytes > 1_000_000) break;
            }
            catch (Exception ex)
            {
                details.Add($"  ✗ {new Uri(testUrl).Host}: {ex.Message}");
            }
        }

        details.Add("");

        if (bestMbps <= 0)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "All tests failed";
            result.DetailedInfo = string.Join("\n", details);
            result.RemediationText = "Could not reach any speed test servers. Check internet connectivity.";
            result.RemediationUrl = EndpointConfiguration.Docs.Bandwidth;
            return;
        }

        result.ResultValue = $"↓ {bestMbps:F1} Mbps ({bestSource})";
        result.DetailedInfo = string.Join("\n", details);

        if (bestMbps >= 20)
        {
            result.Status = TestStatus.Passed;
        }
        else if (bestMbps >= 5)
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
}

// ════════════════════════════════════════════════════════════════════
// ID 08 – NAT Type (Two-Server STUN Detection)
// ════════════════════════════════════════════════════════════════════
public class NatTypeTest : BaseTest
{
    public override string Id => "08";
    public override string Name => "NAT Type";
    public override string Description => "Identifies the NAT type using two-server STUN comparison. Symmetric NAT is standard for enterprise security and works reliably with TURN relay transport.";
    public override TestCategory Category => TestCategory.UdpShortpath;
    public override TestPriority Priority => TestPriority.Important;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();
        details.Add("Method: Two-server STUN comparison");
        details.Add("A single UDP socket sends STUN binding requests to two servers.");
        details.Add("If both return the same reflexive IP:port → Cone NAT (Shortpath works).");
        details.Add("If they differ → Symmetric NAT (TURN relay recommended).");
        details.Add("");

        // Resolve TURN relay via DNS round-robin to get two distinct IPs
        var turnHost = EndpointConfiguration.TurnRelayEndpoints[0];
        var turnIps = new HashSet<IPAddress>();

        for (int i = 0; i < 6 && turnIps.Count < 2; i++)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(turnHost, ct);
                foreach (var a in addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork))
                    turnIps.Add(a);
            }
            catch { }
            if (turnIps.Count < 2 && i < 5) await Task.Delay(200, ct);
        }

        var sortedIps = turnIps.OrderBy(ip => ip.ToString()).ToList();

        // Fallback: if DNS only returns one IP, try stun.azure.com
        if (sortedIps.Count < 2)
        {
            try
            {
                var fallbackAddrs = await Dns.GetHostAddressesAsync("stun.azure.com", ct);
                var fallbackIp = fallbackAddrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (fallbackIp != null && !sortedIps.Contains(fallbackIp))
                    sortedIps.Add(fallbackIp);
            }
            catch { }
        }

        if (sortedIps.Count < 2)
        {
            // Can't do two-server comparison — fall back to single-server with Google STUN
            details.Add($"⚠ Could not resolve two distinct TURN IPs from {turnHost}.");
            details.Add("Falling back to single-server STUN (cannot detect Symmetric NAT).");
            details.Add("");

            try
            {
                var mapped = await SendStunAndGetMapped(EndpointConfiguration.StunServer, EndpointConfiguration.StunPort, details, ct);
                if (mapped != null)
                {
                    result.Status = TestStatus.Passed;
                    result.ResultValue = $"UDP reachable — NAT type undetermined ({mapped})";
                    result.RemediationText = "STUN binding succeeded. RDP Shortpath should be available, but NAT type could not be classified (only one server responded).";
                }
                else
                {
                    result.Status = TestStatus.Warning;
                    result.ResultValue = "STUN failed — UDP may be blocked";
                    result.RemediationText = "Could not get a STUN response. UDP connectivity to STUN/TURN servers may be blocked.";
                }
            }
            catch (Exception ex)
            {
                result.Status = TestStatus.Warning;
                result.ResultValue = "Unable to determine NAT type";
                details.Add($"STUN failed: {ex.Message}");
            }

            result.DetailedInfo = string.Join("\n", details);
            result.RemediationUrl = EndpointConfiguration.Docs.NatType;
            return;
        }

        var stunIp1 = sortedIps[0];
        var stunIp2 = sortedIps[1];
        details.Add($"Server 1: {stunIp1} ({turnHost})");
        details.Add($"Server 2: {stunIp2} ({(turnIps.Contains(stunIp2) ? turnHost : "stun.azure.com")})");
        details.Add("");

        // Send STUN from the same local port to both servers
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        udp.Client.ReceiveTimeout = 5000;
        var localPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        details.Add($"Local UDP port: {localPort}");

        var mapped1 = await SendStunViaUdpClient(udp, new IPEndPoint(stunIp1, EndpointConfiguration.TurnRelayPort), details, $"Server 1 ({stunIp1})", ct);
        var mapped2 = await SendStunViaUdpClient(udp, new IPEndPoint(stunIp2, EndpointConfiguration.TurnRelayPort), details, $"Server 2 ({stunIp2})", ct);

        details.Add("");

        if (mapped1 == null && mapped2 == null)
        {
            details.Add("✗ Neither STUN server responded. UDP 3478 is likely blocked.");
            result.Status = TestStatus.Warning;
            result.ResultValue = "STUN failed — UDP 3478 may be blocked";
            result.RemediationText = "Could not reach STUN/TURN servers on UDP 3478. Ensure this port is allowed outbound.";
        }
        else if (mapped1 == null || mapped2 == null)
        {
            var working = mapped1 ?? mapped2;
            details.Add($"⚠ Only one server responded — reflexive endpoint: {working}");
            details.Add("NAT type cannot be determined with only one response, but UDP works.");
            result.Status = TestStatus.Passed;
            result.ResultValue = $"UDP reachable — NAT type undetermined ({working})";
            result.RemediationText = "STUN binding succeeded. RDP Shortpath should be available.";
        }
        else if (mapped1 == mapped2)
        {
            // Same reflexive endpoint = Endpoint-Independent Mapping (Cone NAT)
            var reflexIp = mapped1.Split(':')[0];
            var localAddrs = NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString())
                .ToHashSet();

            string natLabel;
            if (localAddrs.Contains(reflexIp))
            {
                natLabel = "Open Internet (No NAT)";
                details.Add($"✓ Reflexive IP {reflexIp} matches a local interface — no NAT detected.");
            }
            else
            {
                natLabel = "Cone NAT (Shortpath ready)";
                details.Add($"✓ Both servers returned the same reflexive endpoint: {mapped1}");
            }

            details.Add("");
            details.Add($"NAT Type: {natLabel}");
            details.Add("  Endpoint-Independent Mapping — the same external IP:port is used");
            details.Add("  regardless of destination. RDP Shortpath (STUN + TURN) will work.");

            result.Status = TestStatus.Passed;
            result.ResultValue = $"{natLabel} ({mapped1})";
            result.RemediationText = "NAT type supports STUN-based direct connections (RDP Shortpath).";
        }
        else
        {
            // Different reflexive endpoints = Symmetric NAT
            var ip1 = mapped1.Split(':')[0];
            var ip2 = mapped2.Split(':')[0];

            details.Add($"✗ Servers returned different reflexive endpoints:");
            details.Add($"    Server 1: {mapped1}");
            details.Add($"    Server 2: {mapped2}");
            details.Add("");

            if (ip1 != ip2)
                details.Add("NAT Type: Symmetric NAT (different external IP per destination)");
            else
                details.Add($"NAT Type: Symmetric NAT (same IP {ip1}, different ports)");

            details.Add("  ✓ This is STANDARD and EXPECTED in enterprise environments.");
            details.Add("  RDP Shortpath will use TURN relay for reliable UDP transport.");

            result.Status = TestStatus.Warning;
            result.ResultValue = "Symmetric NAT (Enterprise Standard) — TURN relay recommended";
            result.RemediationText = "Symmetric NAT detected. This is typical for enterprise environments and provides strong security. " +
                                     "Windows 365 will use TURN relay for reliable UDP transport. No action required.";
        }

        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = EndpointConfiguration.Docs.NatType;
    }

    /// <summary>
    /// Sends a STUN binding request via an existing UdpClient and returns the reflexive IP:port.
    /// Retries up to 2 times on timeout.
    /// </summary>
    private static async Task<string?> SendStunViaUdpClient(UdpClient udp, IPEndPoint server, List<string> details, string label, CancellationToken ct)
    {
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                var request = BuildStunBindingRequest();
                await udp.SendAsync(request, request.Length, server);

                var receiveTask = udp.ReceiveAsync(ct);
                var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(3000, ct));

                if (completed == receiveTask.AsTask())
                {
                    var response = await receiveTask;
                    if (response.Buffer.Length >= 20 && ((response.Buffer[0] << 8) | response.Buffer[1]) == 0x0101)
                    {
                        var mapped = ParseStunMappedAddress(response.Buffer);
                        if (mapped != null)
                        {
                            details.Add($"  {label}: reflexive = {mapped}" + (attempt > 1 ? $" (attempt {attempt})" : ""));
                            return mapped;
                        }
                    }
                    details.Add($"  {label}: invalid STUN response ({response.Buffer.Length} bytes)");
                    return null;
                }
                // Timeout — retry
            }
            catch { /* Send/receive error — retry */ }
        }

        details.Add($"  {label}: no response after 2 attempts");
        return null;
    }

    /// <summary>
    /// Sends a STUN binding request to a named server (single-shot fallback).
    /// </summary>
    private static async Task<string?> SendStunAndGetMapped(string host, int port, List<string> details, CancellationToken ct)
    {
        var serverAddresses = await Dns.GetHostAddressesAsync(host, ct);
        var serverIp = serverAddresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);

        using var udp = new UdpClient(0, AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = 5000;

        var request = BuildStunBindingRequest();
        await udp.SendAsync(request, request.Length, new IPEndPoint(serverIp, port));

        var receiveTask = udp.ReceiveAsync(ct);
        var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(5000, ct));

        if (completed == receiveTask.AsTask())
        {
            var response = await receiveTask;
            var mapped = ParseStunMappedAddress(response.Buffer);
            if (mapped != null)
            {
                details.Add($"  {host} ({serverIp}): reflexive = {mapped}");
                return mapped;
            }
        }

        details.Add($"  {host} ({serverIp}): no response");
        return null;
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

    /// <summary>
    /// Parses XOR-MAPPED-ADDRESS or MAPPED-ADDRESS from a STUN response.
    /// Returns "IP:port" string or null.
    /// </summary>
    private static string? ParseStunMappedAddress(byte[] data)
    {
        try
        {
            int offset = 20;
            while (offset + 4 <= data.Length)
            {
                int attrType = (data[offset] << 8) | data[offset + 1];
                int attrLen = (data[offset + 2] << 8) | data[offset + 3];

                if (attrType == 0x0020 && attrLen >= 8) // XOR-MAPPED-ADDRESS
                {
                    int port = ((data[offset + 6] << 8) | data[offset + 7]) ^ 0x2112;
                    byte[] ip =
                    [
                        (byte)(data[offset + 8] ^ 0x21),
                        (byte)(data[offset + 9] ^ 0x12),
                        (byte)(data[offset + 10] ^ 0xA4),
                        (byte)(data[offset + 11] ^ 0x42)
                    ];
                    return $"{new IPAddress(ip)}:{port}";
                }
                else if (attrType == 0x0001 && attrLen >= 8) // MAPPED-ADDRESS
                {
                    int port = (data[offset + 6] << 8) | data[offset + 7];
                    return $"{data[offset + 8]}.{data[offset + 9]}.{data[offset + 10]}.{data[offset + 11]}:{port}";
                }

                offset += 4 + attrLen;
                if (attrLen % 4 != 0) offset += 4 - (attrLen % 4);
            }
        }
        catch { }
        return null;
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
