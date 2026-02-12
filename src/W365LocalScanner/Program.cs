using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

[assembly: SupportedOSPlatform("windows")]

namespace W365LocalScanner;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        var outputPath = "W365ScanResults.json";
        if (args.Length > 0 && !args[0].StartsWith("-"))
        {
            // Validate output path — only allow local file paths, no UNC or path traversal
            var candidate = args[0];
            if (candidate.StartsWith(@"\\") || candidate.Contains(".."))
            {
                Console.WriteLine($"  Invalid output path: {candidate}");
                Console.WriteLine($"  Using default: {outputPath}");
            }
            else
            {
                outputPath = candidate;
            }
        }

        Console.WriteLine("╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║   Windows 365 / AVD Local Connectivity Scanner      ║");
        Console.WriteLine("╠══════════════════════════════════════════════════════╣");
        Console.WriteLine("║   Runs tests requiring local OS access.             ║");
        Console.WriteLine("║   Import results into the web diagnostics page.     ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.WriteLine();

        var results = new List<TestResult>();
        var tests = GetAllTests();

        for (int i = 0; i < tests.Count; i++)
        {
            var test = tests[i];
            Console.Write($"  [{i + 1}/{tests.Count}] {test.Name}... ");

            try
            {
                var sw = Stopwatch.StartNew();
                var testTask = test.Run();
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(60));

                if (await Task.WhenAny(testTask, timeoutTask) == timeoutTask)
                {
                    sw.Stop();
                    results.Add(new TestResult
                    {
                        Id = test.Id,
                        Name = test.Name,
                        Description = test.Description,
                        Category = test.Category,
                        Status = "Warning",
                        ResultValue = $"Timed out after 60s",
                        DetailedInfo = "The test did not complete within 60 seconds. This may indicate a network issue (hanging TLS handshake, unresponsive proxy, etc.).",
                        Duration = (int)sw.ElapsedMilliseconds
                    });
                    Console.WriteLine($"\u26A0 Timed out (60s)");
                    continue;
                }

                var result = await testTask;
                sw.Stop();
                result.Duration = (int)sw.ElapsedMilliseconds;
                results.Add(result);

                var icon = result.Status switch
                {
                    "Passed" => "\u2714",
                    "Warning" => "\u26A0",
                    "Failed" => "\u2718",
                    _ => "\u2022"
                };
                Console.WriteLine($"{icon} {result.Status} ({sw.ElapsedMilliseconds}ms)");
            }
            catch (Exception ex)
            {
                results.Add(new TestResult
                {
                    Id = test.Id,
                    Name = test.Name,
                    Description = test.Description,
                    Category = test.Category,
                    Status = "Error",
                    ResultValue = $"Error: {ex.Message}",
                    DetailedInfo = ex.ToString(),
                    Duration = 0
                });
                Console.WriteLine($"\u2718 Error: {ex.Message}");
            }
        }

        // Write JSON output
        var output = new ScanOutput
        {
            Timestamp = DateTime.UtcNow,
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            DotNetVersion = RuntimeInformation.FrameworkDescription,
            Results = results
        };

        var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.ScanOutput);
        await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8);

        Console.WriteLine();
        Console.WriteLine($"  Results saved to: {Path.GetFullPath(outputPath)}");

        // Auto-open browser with results via local redirect HTML
        // We create a temp HTML file that redirects via JavaScript, which:
        //  1. Preserves #hash fragments (Windows ShellExecute strips them from URLs)
        //  2. Sends BOTH ?zresults=compressed AND #results=uncompressed so the page
        //     works whether the CDN is serving the new or old version of app.js
        try
        {
            // Compress JSON with raw deflate, then URL-safe base64
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var deflate = new DeflateStream(ms, CompressionLevel.SmallestSize))
                {
                    deflate.Write(Encoding.UTF8.GetBytes(json));
                }
                compressed = ms.ToArray();
            }
            var compressedBase64 = Convert.ToBase64String(compressed)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            // Also create uncompressed URL-safe base64 for legacy #results= hash format
            var uncompressedBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            var cb = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var pageUrl = $"https://paulcollinge.github.io/W365ConnectivityTool/?_cb={cb}&zresults={compressedBase64}#results={uncompressedBase64}";

            Console.WriteLine($"  Compressed: {json.Length} → {compressed.Length} bytes (base64: {compressedBase64.Length} chars)");

            if (pageUrl.Length > 2_000_000) // Browser URL limit ~2MB
            {
                Console.WriteLine($"  Results too large for URL auto-import ({pageUrl.Length} chars).");
                Console.WriteLine($"  Drag and drop {Path.GetFullPath(outputPath)} onto the web page.");
                pageUrl = $"https://paulcollinge.github.io/W365ConnectivityTool/?_cb={cb}";
            }

            // Create a temporary HTML file that redirects via JavaScript
            // (JavaScript redirect preserves hash fragments unlike ShellExecute)
            var redirectHtml = $@"<!DOCTYPE html>
<html><head><title>Opening W365 Diagnostics...</title></head>
<body><p>Redirecting to results page...</p>
<script>window.location.replace({EscapeJsString(pageUrl)});</script>
</body></html>";

            var redirectPath = Path.Combine(Path.GetTempPath(), "W365ScanRedirect.html");
            await File.WriteAllTextAsync(redirectPath, redirectHtml, Encoding.UTF8);

            Console.WriteLine($"  Opening browser with results...");
            Process.Start(new ProcessStartInfo { FileName = redirectPath, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Error: {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine($"  Could not open browser. Import the JSON file manually:");
            Console.WriteLine($"    1. Open https://paulcollinge.github.io/W365ConnectivityTool/");
            Console.WriteLine($"    2. Drag and drop {Path.GetFullPath(outputPath)} onto the page");
        }
        Console.WriteLine();

        // Summary
        var passed = results.Count(r => r.Status == "Passed");
        var warned = results.Count(r => r.Status == "Warning");
        var failed = results.Count(r => r.Status == "Failed" || r.Status == "Error");
        Console.WriteLine($"  Summary: {passed} passed, {warned} warnings, {failed} failed");
        Console.WriteLine();

        return failed > 0 ? 1 : 0;
    }

    // ── Shared helpers ──────────────────────────────────────────────

    /// <summary>
    /// Determines the local IP the OS would use to reach a given target, then checks
    /// whether that IP belongs to any of the supplied VPN adapter interfaces.
    /// Returns (routedViaVpn, localIp, matchedAdapterName).
    /// </summary>
    static (bool routedViaVpn, string localIp, string? adapterName) CheckIfRoutedViaVpn(
        IPAddress targetIp, IEnumerable<NetworkInterface> vpnAdapters)
    {
        try
        {
            // Connect a UDP socket (no data sent) — the OS binds the local interface it would route through
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect(targetIp, 443);
            var localIp = ((IPEndPoint)sock.LocalEndPoint!).Address;

            // Collect all unicast IPs from VPN adapters
            foreach (var vpn in vpnAdapters)
            {
                var vpnIps = vpn.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address);

                if (vpnIps.Any(ip => ip.Equals(localIp)))
                    return (true, localIp.ToString(), vpn.Name);
            }

            return (false, localIp.ToString(), null);
        }
        catch
        {
            // If routing check fails, we can't confirm split tunnel — stay conservative
            return (true, "unknown", null);
        }
    }

    /// <summary>
    /// Returns a comma-separated list of IPv4 addresses assigned to a network adapter.
    /// </summary>
    static string GetAdapterIps(NetworkInterface adapter)
    {
        try
        {
            return string.Join(", ", adapter.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()));
        }
        catch { return ""; }
    }

    /// <summary>
    /// Parses the IPv4 routing table and checks which routes cover the key W365/AVD
    /// service CIDR ranges, reporting whether each range is routed via VPN or direct.
    /// </summary>
    /// <summary>
    /// Parses the IPv4 routing table and checks which routes cover the key W365/AVD
    /// service CIDR ranges. Returns a list of ranges that route via VPN (empty = all direct).
    /// </summary>
    static List<string> ProbeAvdServiceRanges(IList<NetworkInterface> vpnAdapters, StringBuilder sb)
    {
        var vpnCaughtRanges = new List<string>();
        try
        {
            // Collect VPN adapter interface IPs
            var vpnIfIps = new HashSet<string>();
            foreach (var vpn in vpnAdapters)
                foreach (var addr in vpn.GetIPProperties().UnicastAddresses)
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        vpnIfIps.Add(addr.Address.ToString());

            // Parse routing table
            var psi = new ProcessStartInfo("route", "print -4")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = proc!.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            var routes = ParseRouteTable(output);
            if (routes.Count == 0) { sb.AppendLine("\n  Could not parse routing table"); return vpnCaughtRanges; }

            // Target ranges
            var targets = new (string label, uint netAddr, int prefixLen)[]
            {
                ("40.64.144.0/20", IpToUint32(IPAddress.Parse("40.64.144.0")), 20),
                ("51.5.0.0/16",    IpToUint32(IPAddress.Parse("51.5.0.0")),    16),
            };

            sb.AppendLine("\n  W365/AVD service range routing (from routing table):");

            var directRanges = new List<string>();

            foreach (var (label, netAddr, prefixLen) in targets)
            {
                uint rangeMask = prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - prefixLen);

                // Find best route for a representative IP in the range
                uint probeIp = netAddr + 1;
                var bestRoute = FindBestRoute(routes, probeIp);

                bool bestViaVpn = bestRoute.HasValue && vpnIfIps.Contains(bestRoute.Value.ifIp);

                if (bestViaVpn) vpnCaughtRanges.Add(label);
                else directRanges.Add(label);

                if (bestRoute.HasValue)
                {
                    var r = bestRoute.Value;
                    string routeType = bestViaVpn ? "\u26A0" : "\u2714";
                    string via = bestViaVpn ? "VPN tunnel" : "direct";
                    sb.AppendLine($"    {routeType} {label}: routed {via} (best match: {r.destStr}/{r.prefixLen} via {r.gateway}, interface {r.ifIp}, metric {r.metric})");
                }
                else
                {
                    sb.AppendLine($"    ? {label}: no matching route found");
                }

                // Find any sub-routes or overlapping routes injected for this range
                var overlapping = routes
                    .Where(r =>
                    {
                        // Route falls within our target range
                        bool routeInsideRange = (r.dest & rangeMask) == netAddr && r.prefixLen >= prefixLen;
                        // Route covers our target range
                        uint routeMask2 = r.prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - r.prefixLen);
                        bool routeCoversRange = (netAddr & routeMask2) == r.dest && r.prefixLen <= prefixLen;
                        return routeInsideRange || routeCoversRange;
                    })
                    .Where(r => r.destStr != "0.0.0.0") // skip default route
                    .OrderByDescending(r => r.prefixLen)
                    .ToList();

                foreach (var r in overlapping)
                {
                    bool viaVpn = vpnIfIps.Contains(r.ifIp);
                    string marker;
                    if (viaVpn && !bestViaVpn)
                        marker = "VPN \u2014 overridden by more-specific direct route";
                    else if (viaVpn)
                        marker = "\u26A0 VPN";
                    else
                        marker = "\u2714 direct";
                    sb.AppendLine($"      route {r.destStr}/{r.prefixLen} via {r.gateway} (if {r.ifIp}, metric {r.metric}) [{marker}]");
                }
            }

            // Summary
            sb.AppendLine();
            if (vpnCaughtRanges.Count > 0)
            {
                sb.AppendLine($"  \u26A0 VPN tunnel is carrying W365/AVD traffic for: {string.Join(", ", vpnCaughtRanges)}");
                if (directRanges.Count > 0)
                    sb.AppendLine($"  \u2714 Split-tunnelled (direct) for: {string.Join(", ", directRanges)}");
            }
            else
            {
                sb.AppendLine($"  \u2714 No W365/AVD service traffic goes through the VPN tunnel");
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine($"\n  Could not analyze routing table: {ex.Message}");
        }
        return vpnCaughtRanges;
    }

    record struct RouteEntry(uint dest, int prefixLen, string gateway, string ifIp, int metric, string destStr);

    static List<RouteEntry> ParseRouteTable(string routePrintOutput)
    {
        var routes = new List<RouteEntry>();
        bool inTable = false;
        foreach (var rawLine in routePrintOutput.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("Network Destination")) { inTable = true; continue; }
            if (!inTable) continue;
            if (line.StartsWith("=") || string.IsNullOrWhiteSpace(line)) continue;
            if (line.StartsWith("Persistent") || line.StartsWith("Default")) break;

            // Fields: NetworkDestination  Netmask  Gateway  Interface  Metric
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) continue;

            if (!IPAddress.TryParse(parts[0], out var dest)) continue;
            if (!IPAddress.TryParse(parts[1], out var mask)) continue;

            uint destUint = IpToUint32(dest);
            uint maskUint = IpToUint32(mask);
            int prefix = MaskToPrefixLen(maskUint);

            if (!int.TryParse(parts[4], out int metric)) metric = 0;

            routes.Add(new RouteEntry(destUint, prefix, parts[2], parts[3], metric, parts[0]));
        }
        return routes;
    }

    static RouteEntry? FindBestRoute(List<RouteEntry> routes, uint destIp)
    {
        RouteEntry? best = null;
        int bestPrefix = -1;
        int bestMetric = int.MaxValue;

        foreach (var r in routes)
        {
            uint mask = r.prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - r.prefixLen);
            if ((destIp & mask) == r.dest)
            {
                if (r.prefixLen > bestPrefix || (r.prefixLen == bestPrefix && r.metric < bestMetric))
                {
                    best = r;
                    bestPrefix = r.prefixLen;
                    bestMetric = r.metric;
                }
            }
        }
        return best;
    }

    static uint IpToUint32(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
    }

    static int MaskToPrefixLen(uint mask)
    {
        int count = 0;
        while ((mask & 0x80000000) != 0) { count++; mask <<= 1; }
        return count;
    }

    /// <summary>
    /// Creates an HttpClient that forwards default proxy credentials (NTLM/Kerberos).
    /// Use this instead of bare "new HttpClient" so tests work behind authenticated proxies.
    /// </summary>
    static HttpClient CreateProxyAwareHttpClient(TimeSpan timeout, HttpClientHandler? customHandler = null)
    {
        var handler = customHandler ?? new HttpClientHandler();
        handler.DefaultProxyCredentials = CredentialCache.DefaultCredentials;
        return new HttpClient(handler) { Timeout = timeout };
    }

    /// <summary>
    /// Simple in-memory cache for GeoIP results keyed by IP (or "" for self).
    /// Prevents redundant API calls within a single scan run.
    /// </summary>
    static readonly Dictionary<string, JsonElement> _geoIpCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Fetches GeoIP data with cascading fallback across 4 providers and retry on 429.
    /// Providers: ipinfo.io → ipapi.co → ipwho.is → geojs.io
    /// Results are cached per IP for the duration of the scan.
    /// </summary>
    static async Task<JsonElement> FetchGeoIpAsync(string url, TimeSpan timeout)
    {
        // Extract IP from url for cache key (empty string = self)
        string cacheKey = "";
        if (url.StartsWith("https://ipinfo.io/") && url.EndsWith("/json") && url != "https://ipinfo.io/json")
            cacheKey = url.Replace("https://ipinfo.io/", "").Replace("/json", "");

        if (_geoIpCache.TryGetValue(cacheKey, out var cached))
            return cached;

        // Build provider URLs for this request (self vs specific IP)
        var providers = string.IsNullOrEmpty(cacheKey)
            ? new[]
            {
                "https://ipinfo.io/json",
                "https://ipapi.co/json",
                "https://ipwho.is/",
                "https://get.geojs.io/v1/ip/geo.json"
            }
            : new[]
            {
                $"https://ipinfo.io/{cacheKey}/json",
                $"https://ipapi.co/{cacheKey}/json",
                $"https://ipwho.is/{cacheKey}",
                $"https://get.geojs.io/v1/ip/geo/{cacheKey}.json"
            };

        using var http = CreateProxyAwareHttpClient(timeout);
        Exception? lastEx = null;

        foreach (var providerUrl in providers)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var response = await http.GetAsync(providerUrl);
                    if (response.StatusCode == (System.Net.HttpStatusCode)429)
                    {
                        // Rate limited — wait briefly then retry once, else move to next provider
                        if (attempt == 0)
                        {
                            await Task.Delay(1500);
                            continue;
                        }
                        throw new HttpRequestException($"429 Too Many Requests from {new Uri(providerUrl).Host}");
                    }
                    response.EnsureSuccessStatusCode();
                    var json = await response.Content.ReadAsStringAsync();
                    var element = JsonSerializer.Deserialize(json, ScanJsonContext.Default.JsonElement);
                    _geoIpCache[cacheKey] = element;
                    return element;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    break; // don't retry on non-429 errors, move to next provider
                }
            }
        }

        throw lastEx ?? new HttpRequestException("All GeoIP providers failed");
    }

    static List<TestDefinition> GetAllTests()
    {
        return
        [
            // ── Local Environment ──
            new("L-LE-04", "WiFi Signal Strength", "Measures wireless signal strength", "local", RunWifiStrength),
            new("L-LE-05", "Router/Gateway Latency", "Pings default gateway", "local", RunRouterLatency),
            new("L-LE-06", "Network Adapter Details", "Enumerates network adapters", "local", RunNetworkAdapters),
            new("L-LE-07", "Bandwidth Estimation", "Estimates available bandwidth", "local", RunBandwidthTest),
            new("L-LE-08", "Machine Performance", "Checks CPU, RAM, disk", "local", RunMachinePerformance),
            new("L-LE-09", "Teams Optimization", "Validates Teams AV redirect settings", "local", RunTeamsOptimization),

            // ── Endpoint Access ──
            new("L-EP-01", "Certificate Endpoints (Port 80)", "Tests TCP 80 connectivity to certificate endpoints", "endpoint", RunCertEndpointTest),

            // ── TCP Based RDP Connectivity ──
            new("L-TCP-04", "Gateway Connectivity", "Tests DNS, TCP, TLS, HTTP layers to gateways", "tcp", RunGatewayConnectivity),
            new("L-TCP-05", "DNS CNAME Chain Analysis", "Traces DNS CNAME chain for gateway", "tcp", RunDnsCnameChain),
            new("L-TCP-08", "DNS Hijacking Check", "Verifies gateway DNS resolves to legitimate Microsoft IPs", "tcp", RunDnsHijackingCheck),
            new("L-TCP-09", "Gateway Used", "Shows which gateway edge node and IP are being used", "tcp", RunGatewayUsed),
            new("L-TCP-06", "TLS Inspection Detection", "Validates TLS certificate chain", "tcp", RunTlsInspection),
            new("L-TCP-07", "Proxy / VPN / SWG Detection", "Detects proxy, VPN, SWG", "tcp", RunProxyVpnDetection),

            // ── UDP Based RDP Connectivity ──
            new("L-UDP-03", "TURN Relay Reachability (UDP 3478)", "Tests UDP to TURN relay", "udp", RunTurnRelay),
            new("L-UDP-04", "TURN Relay Location", "Geolocates the TURN relay server", "udp", RunTurnRelayLocation),
            new("L-UDP-06", "TURN TLS Inspection", "Checks TLS on TURN relay", "udp", RunTurnTlsInspection),
            new("L-UDP-07", "TURN Proxy/VPN Detection", "Detects UDP-blocking proxy/VPN", "udp", RunTurnProxyVpn),

            // ── Cloud Session ──
            new("L-CS-01", "Cloud PC Location", "Identifies Cloud PC Azure region", "cloud", RunCloudPcLocation),
            new("L-CS-02", "Cloud PC Latency", "Measures latency to Cloud PC", "cloud", RunCloudPcLatency),
            new("L-CS-03", "Session Throughput", "Estimates throughput", "cloud", RunSessionThroughput),
            new("L-CS-04", "Jitter Measurement", "Measures network jitter", "cloud", RunJitter),
            new("L-CS-05", "Packet Loss", "Detects packet loss", "cloud", RunPacketLoss),
        ];
    }

    // ═══════════════════════════════════════════
    //  ENDPOINT ACCESS TESTS
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunCertEndpointTest()
    {
        var result = new TestResult { Id = "L-EP-01", Name = "Certificate Endpoints (Port 80)", Category = "endpoint" };
        try
        {
            // Official AVD required FQDNs for end-user devices — TCP port 80 (Certificates)
            // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#end-user-devices
            var targets = new (string host, string wildcard)[]
            {
                ("eusaikpublish.microsoftaik.azure.net", "*.microsoftaik.azure.net"),
                ("www.microsoft.com", "www.microsoft.com"),
                ("eus.aikcertaia.microsoft.com", "*.aikcertaia.microsoft.com"),
                ("azcsprodeusaikpublish.blob.core.windows.net", "azcsprodeusaikpublish.blob.core.windows.net")
            };

            var sb = new StringBuilder();
            int passed = 0;
            foreach (var (host, wildcard) in targets)
            {
                try
                {
                    using var tcp = new TcpClient();
                    var sw = Stopwatch.StartNew();
                    var connectTask = tcp.ConnectAsync(host, 80);
                    if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask)
                    {
                        sw.Stop();
                        sb.AppendLine($"\u2714 {wildcard} ({host}:80) \u2014 Connected in {sw.ElapsedMilliseconds}ms");
                        passed++;
                    }
                    else
                    {
                        sb.AppendLine($"\u2718 {wildcard} ({host}:80) \u2014 Timeout (5s)");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"\u2718 {wildcard} ({host}:80) \u2014 {ex.Message}");
                }
            }

            result.ResultValue = $"{passed}/{targets.Length} certificate endpoints reachable on port 80";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = passed == targets.Length ? "Passed" : passed > 0 ? "Warning" : "Failed";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#end-user-devices";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ═══════════════════════════════════════════
    //  LOCAL ENVIRONMENT TESTS
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunWifiStrength()
    {
        var result = new TestResult { Id = "L-LE-04", Name = "WiFi Signal Strength", Category = "local" };
        try
        {
            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = await proc!.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (string.IsNullOrWhiteSpace(output) || output.Contains("not running"))
            {
                result.Status = "Skipped";
                result.ResultValue = "No wireless interface detected (wired connection)";
                return result;
            }

            // Check if there's a connected WiFi profile — "State" line should say "connected"
            var stateLine = output.Split('\n').FirstOrDefault(l => l.Trim().StartsWith("State"))?.Split(':').LastOrDefault()?.Trim();
            if (stateLine == null || !stateLine.Equals("connected", StringComparison.OrdinalIgnoreCase))
            {
                result.Status = "Skipped";
                result.ResultValue = "Not connected by WiFi";
                result.DetailedInfo = output.Trim();
                return result;
            }

            var lines = output.Split('\n');
            var signal = lines.FirstOrDefault(l => l.Trim().StartsWith("Signal"))?.Split(':').LastOrDefault()?.Trim();
            var ssid = lines.FirstOrDefault(l => l.Trim().StartsWith("SSID") && !l.Trim().StartsWith("BSSID"))?.Split(':').LastOrDefault()?.Trim();
            var radioType = lines.FirstOrDefault(l => l.Trim().StartsWith("Radio type"))?.Split(':').LastOrDefault()?.Trim();
            var channel = lines.FirstOrDefault(l => l.Trim().StartsWith("Channel"))?.Split(':').LastOrDefault()?.Trim();

            result.DetailedInfo = output.Trim();

            if (signal != null)
            {
                var pct = int.TryParse(signal.Replace("%", ""), out var s) ? s : 0;
                result.ResultValue = $"Signal: {signal}, SSID: {ssid ?? "N/A"}, Radio: {radioType ?? "N/A"}, Channel: {channel ?? "N/A"}";
                result.Status = pct >= 70 ? "Passed" : pct >= 40 ? "Warning" : "Failed";
                if (result.Status != "Passed")
                    result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/troubleshoot-windows-365-boot#networking-checks";
            }
            else
            {
                result.Status = "Skipped";
                result.ResultValue = "Not connected by WiFi (no signal data)";
            }
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.ResultValue = ex.Message;
        }
        return result;
    }

    static async Task<TestResult> RunRouterLatency()
    {
        var result = new TestResult { Id = "L-LE-05", Name = "Router/Gateway Latency", Category = "local" };
        try
        {
            // Find default gateway
            var gateway = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            if (gateway == null)
            {
                result.Status = "Warning";
                result.ResultValue = "No default gateway found";
                return result;
            }

            var ping = new Ping();
            var times = new List<long>();
            for (int i = 0; i < 5; i++)
            {
                var reply = await ping.SendPingAsync(gateway, 2000);
                if (reply.Status == IPStatus.Success)
                    times.Add(reply.RoundtripTime);
                await Task.Delay(200);
            }

            if (times.Count == 0)
            {
                result.Status = "Warning";
                result.ResultValue = $"Gateway {gateway} did not respond to ping";
                return result;
            }

            var avg = times.Average();
            result.ResultValue = $"Gateway {gateway}: avg {avg:F0}ms (min {times.Min()}ms, max {times.Max()}ms)";
            result.DetailedInfo = $"Gateway: {gateway}\nSamples: {times.Count}/5\n" +
                                  string.Join(", ", times.Select(t => $"{t}ms"));
            result.Status = avg < 20 ? "Passed" : avg < 50 ? "Warning" : "Failed";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static Task<TestResult> RunNetworkAdapters()
    {
        var result = new TestResult { Id = "L-LE-06", Name = "Network Adapter Details", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            int count = 0;
            foreach (var a in adapters)
            {
                count++;
                sb.AppendLine($"Adapter: {a.Name}");
                sb.AppendLine($"  Description: {a.Description}");
                sb.AppendLine($"  Type: {a.NetworkInterfaceType}");
                sb.AppendLine($"  Speed: {a.Speed / 1_000_000} Mbps");
                var ips = a.GetIPProperties().UnicastAddresses
                    .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(u => u.Address.ToString());
                sb.AppendLine($"  IPv4: {string.Join(", ", ips)}");
                sb.AppendLine();
            }

            result.ResultValue = $"{count} active adapter(s)";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = count > 0 ? "Passed" : "Warning";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    static async Task<TestResult> RunBandwidthTest()
    {
        var result = new TestResult { Id = "L-LE-07", Name = "Bandwidth Estimation", Category = "local" };
        try
        {
            // Try Ookla Speedtest CLI first (bundled in tools/speedtest/)
            var speedtestPath = Path.Combine(AppContext.BaseDirectory, "tools", "speedtest", "speedtest.exe");
            if (!File.Exists(speedtestPath))
                speedtestPath = Path.Combine(Directory.GetCurrentDirectory(), "tools", "speedtest", "speedtest.exe");

            if (File.Exists(speedtestPath))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = speedtestPath,
                    Arguments = "--accept-license --accept-gdpr --format=json",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi)!;
                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                if (proc.ExitCode == 0 && output.Contains("download"))
                {
                    using var doc = JsonDocument.Parse(output);
                    var root = doc.RootElement;
                    var dlBandwidth = root.GetProperty("download").GetProperty("bandwidth").GetDouble();
                    var ulBandwidth = root.GetProperty("upload").GetProperty("bandwidth").GetDouble();
                    var ping = root.GetProperty("ping").GetProperty("latency").GetDouble();
                    var server = root.GetProperty("server").GetProperty("name").GetString();
                    var dlMbps = dlBandwidth * 8 / 1_000_000;
                    var ulMbps = ulBandwidth * 8 / 1_000_000;

                    result.ResultValue = $"Download: {dlMbps:F1} Mbps | Upload: {ulMbps:F1} Mbps | Ping: {ping:F0}ms";
                    result.DetailedInfo = $"Speedtest by Ookla\nServer: {server}\nDownload: {dlMbps:F1} Mbps\nUpload: {ulMbps:F1} Mbps\nPing: {ping:F1} ms";
                    result.Status = dlMbps > 5 ? "Passed" : dlMbps > 1 ? "Warning" : "Failed";
                    if (result.Status != "Passed")
                        result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#bandwidth-requirements";
                    return result;
                }
            }

            // Fallback: streaming HTTPS download for 10 seconds
            Console.Write("(measuring ~10s) ");
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(30));
            http.DefaultRequestHeaders.Add("User-Agent", "W365ConnectivityTool/2.0");

            // Test URLs in order of preference (progressively smaller for resilience)
            var testUrls = new[]
            {
                ("https://speed.cloudflare.com/__down?bytes=25000000", 25_000_000L),
                ("https://speed.cloudflare.com/__down?bytes=10000000", 10_000_000L),
                ("https://proof.ovh.net/files/10Mb.dat", 10_000_000L)
            };

            double bestMbps = 0;
            string bestDetail = "";

            foreach (var (testUrl, expectedSize) in testUrls)
            {
                try
                {
                    // Streaming download - measure bytes received over time
                    var sw = Stopwatch.StartNew();
                    using var response = await http.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead);
                    response.EnsureSuccessStatusCode();

                    using var stream = await response.Content.ReadAsStreamAsync();
                    var buffer = new byte[65536]; // 64KB chunks
                    long totalBytes = 0;
                    int bytesRead;
                    var measureDuration = TimeSpan.FromSeconds(10);

                    while ((bytesRead = await stream.ReadAsync(buffer)) > 0)
                    {
                        totalBytes += bytesRead;
                        if (sw.Elapsed > measureDuration)
                            break; // Stop after 10 seconds regardless
                    }
                    sw.Stop();

                    if (totalBytes < 50_000 || sw.Elapsed.TotalSeconds < 0.5)
                        continue; // Too little data for reliable measurement

                    var sizeMB = totalBytes / (1024.0 * 1024.0);
                    var seconds = sw.Elapsed.TotalSeconds;
                    var mbps = (sizeMB * 8) / seconds;

                    if (mbps > bestMbps)
                    {
                        bestMbps = mbps;
                        bestDetail = $"Downloaded {sizeMB:F2} MB in {seconds:F1}s from {new Uri(testUrl).Host}";
                    }

                    // If we got a good measurement, no need to try other URLs
                    if (totalBytes > 1_000_000)
                        break;
                }
                catch { /* try next URL */ }
            }

            if (bestMbps > 0)
            {
                result.ResultValue = $"~{bestMbps:F1} Mbps (HTTPS streaming download test)";
                result.DetailedInfo = $"Measured via HTTPS streaming download.\n{bestDetail}\n\nFor more accurate results, install Ookla Speedtest CLI in tools/speedtest/";
                result.Status = bestMbps > 5 ? "Passed" : bestMbps > 1 ? "Warning" : "Failed";
            }
            else
            {
                result.Status = "Error";
                result.ResultValue = "Could not complete bandwidth test — all test URLs failed";
            }
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#bandwidth-requirements";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static Task<TestResult> RunMachinePerformance()
    {
        var result = new TestResult { Id = "L-LE-08", Name = "Machine Performance", Category = "local" };
        try
        {
            var procCount = Environment.ProcessorCount;
            var totalRam = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024.0 * 1024 * 1024);
            var osArch = RuntimeInformation.OSArchitecture;
            var procArch = RuntimeInformation.ProcessArchitecture;

            var sb = new StringBuilder();
            sb.AppendLine($"Processors: {procCount} logical cores");
            sb.AppendLine($"Total RAM: {totalRam:F1} GB");
            sb.AppendLine($"OS Architecture: {osArch}");
            sb.AppendLine($"Process Architecture: {procArch}");
            sb.AppendLine($"OS: {RuntimeInformation.OSDescription}");
            sb.AppendLine($".NET: {RuntimeInformation.FrameworkDescription}");

            result.ResultValue = $"{procCount} cores, {totalRam:F1} GB RAM, {osArch}";
            result.DetailedInfo = sb.ToString().Trim();

            // W365 thin client minimum: 2 cores, 4GB RAM
            result.Status = (procCount >= 2 && totalRam >= 3.5) ? "Passed" : "Warning";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    static Task<TestResult> RunTeamsOptimization()
    {
        var result = new TestResult { Id = "L-LE-09", Name = "Teams Optimization", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            bool teamsOptFound = false;

            // Check for Teams media optimization registry key
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Teams\MediaOptimization");
                if (key != null)
                {
                    teamsOptFound = true;
                    sb.AppendLine("Teams Media Optimization registry key found");
                }
            }
            catch { }

            // Check for AVD/W365 MsRdcWebRTCSvc.exe (WebRTC redirector service)
            var webrtcSvc = Process.GetProcessesByName("MsRdcWebRTCSvc");
            if (webrtcSvc.Length > 0)
            {
                teamsOptFound = true;
                sb.AppendLine($"WebRTC Redirector Service running (PID: {webrtcSvc[0].Id})");
            }
            else
            {
                sb.AppendLine("WebRTC Redirector Service (MsRdcWebRTCSvc) not running");
            }

            // Check for Windows App / Remote Desktop client
            var rdClients = new[] { "msrdcw", "mstsc", "ms-teams" };
            foreach (var name in rdClients)
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                    sb.AppendLine($"{name} running (PID: {procs[0].Id})");
            }

            result.ResultValue = teamsOptFound ? "Teams AV optimization components detected" : "No Teams optimization components found (not in a session)";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = "Passed"; // Not a failure condition outside a session
            result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ═══════════════════════════════════════════
    //  TCP TRANSPORT TESTS
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunGatewayConnectivity()
    {
        var result = new TestResult { Id = "L-TCP-04", Name = "Gateway Connectivity", Category = "tcp" };
        try
        {
            var targets = new[] {
                ("rdweb.wvd.microsoft.com", 443),
                ("client.wvd.microsoft.com", 443),
                ("login.microsoftonline.com", 443)
            };

            var sb = new StringBuilder();
            int passed = 0;
            var issues = new List<string>();

            using var httpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            foreach (var (host, port) in targets)
            {
                sb.AppendLine($"  {host}:{port}");

                // Layer 1: DNS
                System.Net.IPAddress[] addresses;
                try
                {
                    addresses = await System.Net.Dns.GetHostAddressesAsync(host);
                    sb.AppendLine($"    ✓ DNS → {string.Join(", ", addresses.Select(a => a.ToString()))}");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ DNS failed: {ex.Message}");
                    issues.Add($"{host}: DNS resolution failed");
                    sb.AppendLine();
                    continue;
                }

                // Layer 2: TCP
                try
                {
                    using var tcp = new TcpClient();
                    var sw = Stopwatch.StartNew();
                    using var cts = new CancellationTokenSource(5000);
                    await tcp.ConnectAsync(host, port, cts.Token);
                    sw.Stop();
                    sb.AppendLine($"    ✓ TCP connected in {sw.ElapsedMilliseconds}ms");
                }
                catch (OperationCanceledException)
                {
                    sb.AppendLine($"    ✗ TCP connection timed out (5s)");
                    issues.Add($"{host}: TCP port {port} blocked or timed out — check firewall rules");
                    sb.AppendLine();
                    continue;
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ TCP failed: {ex.InnerException?.Message ?? ex.Message}");
                    issues.Add($"{host}: TCP port {port} refused — firewall or port blocked");
                    sb.AppendLine();
                    continue;
                }

                // Layer 3: TLS + HTTP
                try
                {
                    var sw2 = Stopwatch.StartNew();
                    var response = await http.GetAsync($"https://{host}/");
                    sw2.Stop();
                    var code = (int)response.StatusCode;
                    sb.AppendLine($"    ✓ HTTPS {code} in {sw2.ElapsedMilliseconds}ms");
                    passed++;
                }
                catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
                {
                    sb.AppendLine($"    ✗ TLS handshake failed: {ex.InnerException.Message}");
                    issues.Add($"{host}: TLS handshake failed — possible TLS inspection or certificate issue");
                    sb.AppendLine();
                    continue;
                }
                catch (TaskCanceledException)
                {
                    sb.AppendLine($"    ✗ HTTPS request timed out (10s)");
                    issues.Add($"{host}: TCP connected but HTTPS timed out — possible proxy or DPI blocking");
                    sb.AppendLine();
                    continue;
                }
                catch (Exception ex)
                {
                    var inner = ex.InnerException?.Message ?? ex.Message;
                    sb.AppendLine($"    ✗ HTTPS failed: {inner}");
                    issues.Add($"{host}: TCP connected but HTTPS failed — {inner}");
                    sb.AppendLine();
                    continue;
                }

                sb.AppendLine();
            }

            if (issues.Count > 0)
            {
                sb.AppendLine("Issues found:");
                foreach (var issue in issues)
                    sb.AppendLine($"  ⚠ {issue}");
            }

            result.ResultValue = passed == targets.Length
                ? $"All {targets.Length} gateways fully reachable (DNS+TCP+HTTPS)"
                : $"{passed}/{targets.Length} gateways fully reachable";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = passed == targets.Length ? "Passed" : passed > 0 ? "Warning" : "Failed";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunDnsCnameChain()
    {
        var result = new TestResult { Id = "L-TCP-05", Name = "DNS CNAME Chain Analysis", Category = "tcp" };
        try
        {
            var host = "rdweb.wvd.microsoft.com";
            var psi = new ProcessStartInfo("nslookup", $"-type=CNAME {host}")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = await proc!.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            // Also do a regular DNS lookup to get the final IP
            var ips = await Dns.GetHostAddressesAsync(host);
            var ipStr = string.Join(", ", ips.Select(i => i.ToString()));

            var sb = new StringBuilder();
            sb.AppendLine($"Target: {host}");
            sb.AppendLine($"Resolved IPs: {ipStr}");
            sb.AppendLine();
            sb.AppendLine("CNAME lookup output:");
            sb.AppendLine(output.Trim());

            bool isPrivateLink = ips.Any(ip => IsPrivateIp(ip));
            bool hasAfdCname = output.Contains("afd", StringComparison.OrdinalIgnoreCase) ||
                               output.Contains("azurefd", StringComparison.OrdinalIgnoreCase);

            if (isPrivateLink)
            {
                result.ResultValue = $"Private Link detected \u2014 resolves to private IP ({ipStr})";
                result.Status = "Passed";
                sb.AppendLine("\nPrivate Link endpoint detected. Traffic routes via private network.");
            }
            else if (hasAfdCname)
            {
                result.ResultValue = $"Azure Front Door CNAME chain detected ({ipStr})";
                result.Status = "Passed";
                sb.AppendLine("\nAFD routing detected in CNAME chain. This is normal for public connections.");
            }
            else
            {
                result.ResultValue = $"Standard DNS resolution ({ipStr})";
                result.Status = "Passed";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunTlsInspection()
    {
        var result = new TestResult { Id = "L-TCP-06", Name = "TLS Inspection Detection", Category = "tcp" };
        try
        {
            var host = "rdweb.wvd.microsoft.com";
            var port = 443;
            var sb = new StringBuilder();
            bool intercepted = false;

            using var tcp = new TcpClient();
            using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(host, port, connectCts.Token);

            using var ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
            {
                if (cert is X509Certificate2 x509)
                {
                    sb.AppendLine($"Subject: {x509.Subject}");
                    sb.AppendLine($"Issuer: {x509.Issuer}");
                    sb.AppendLine($"Thumbprint: {x509.Thumbprint}");
                    sb.AppendLine($"Valid: {x509.NotBefore:d} - {x509.NotAfter:d}");
                    sb.AppendLine($"Policy Errors: {errors}");

                    // Check if issuer is expected
                    var issuer = x509.Issuer;
                    var expectedIssuers = new[] { "Microsoft", "DigiCert", "Microsoft Azure RSA TLS", "Microsoft Azure TLS" };
                    bool isExpected = expectedIssuers.Any(e => issuer.Contains(e, StringComparison.OrdinalIgnoreCase));

                    // Check for Private Link certs
                    bool isPrivateLink = x509.Subject.Contains("privatelink", StringComparison.OrdinalIgnoreCase);

                    if (!isExpected && !isPrivateLink)
                    {
                        intercepted = true;
                        sb.AppendLine("\n\u26A0 Certificate issuer is NOT a known Microsoft/DigiCert CA.");
                        sb.AppendLine("This suggests TLS inspection by a proxy, firewall, or SWG.");
                    }
                }
                return true; // Accept anyway for inspection
            });

            using var tlsCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, tlsCts.Token);
            sb.Insert(0, $"Host: {host}:{port}\n\n");

            result.ResultValue = intercepted
                ? "TLS inspection detected \u2014 non-Microsoft certificate issuer"
                : "No TLS inspection detected \u2014 certificate chain is valid";
            result.Status = intercepted ? "Warning" : "Passed";
            result.DetailedInfo = sb.ToString().Trim();
            if (intercepted)
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#tls-inspection";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static Task<TestResult> RunProxyVpnDetection()
    {
        var result = new TestResult { Id = "L-TCP-07", Name = "Proxy / VPN / SWG Detection", Category = "tcp" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();

            // System proxy
            var proxy = WebRequest.GetSystemWebProxy();
            var testUri = new Uri("https://rdweb.wvd.microsoft.com");
            var proxyUri = proxy.GetProxy(testUri);
            if (proxyUri != null && proxyUri != testUri)
            {
                issues.Add($"System proxy: {proxyUri}");
                sb.AppendLine($"\u26A0 System proxy detected: {proxyUri}");
            }
            else
            {
                sb.AppendLine("\u2714 No system proxy configured for AVD endpoints");
            }

            // WinHTTP proxy
            try
            {
                var psi = new ProcessStartInfo("netsh", "winhttp show proxy")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                var output = proc!.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                if (output.Contains("Direct access"))
                    sb.AppendLine("\u2714 WinHTTP: Direct access (no proxy)");
                else
                {
                    issues.Add("WinHTTP proxy configured");
                    sb.AppendLine($"\u26A0 WinHTTP proxy configured:\n{output.Trim()}");
                }
            }
            catch { sb.AppendLine("Could not check WinHTTP proxy"); }

            // Environment variables
            var envVars = new[] { "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY" };
            foreach (var v in envVars)
            {
                var val = Environment.GetEnvironmentVariable(v);
                if (!string.IsNullOrEmpty(val))
                {
                    issues.Add($"{v}={val}");
                    sb.AppendLine($"\u26A0 Environment: {v}={val}");
                }
            }

            // VPN adapters — detect presence, then check if RDP traffic actually routes through them
            var vpnAdapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                           (n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Virtual Private", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Cisco", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (vpnAdapters.Count > 0)
            {
                // List VPN adapters found
                foreach (var vpn in vpnAdapters)
                {
                    var vpnIpList = GetAdapterIps(vpn);
                    sb.AppendLine($"\u2139 VPN adapter detected: {vpn.Name} ({vpn.Description})");
                    if (!string.IsNullOrEmpty(vpnIpList))
                        sb.AppendLine($"    Adapter IPs: {vpnIpList}");
                }

                // Routing table is the authoritative source for what's routed via VPN
                var caught = ProbeAvdServiceRanges(vpnAdapters, sb);
                foreach (var range in caught)
                    issues.Add($"W365/AVD range {range} routes through VPN tunnel");

                // Also show single-IP probe as informational context
                try
                {
                    var gwIps = Dns.GetHostAddresses("rdweb.wvd.microsoft.com");
                    var gwIp = gwIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (gwIp != null)
                    {
                        var (routedViaVpn, localIp, _) = CheckIfRoutedViaVpn(gwIp, vpnAdapters);
                        if (routedViaVpn)
                            sb.AppendLine($"\n  \u26A0 Note: RDP gateway {gwIp} (rdweb.wvd.microsoft.com) routes via VPN interface {localIp}");
                        else
                            sb.AppendLine($"\n  \u2714 RDP gateway {gwIp} (rdweb.wvd.microsoft.com) routes direct via {localIp}");
                    }
                }
                catch { /* DNS or probe failed — non-critical since routing table already checked */ }
            }
            else
            {
                sb.AppendLine("\u2714 No VPN adapters detected");
            }

            // SWG / security processes
            var swgProcesses = new[] { "ZscalerService", "netskope", "iboss", "forcepoint", "mcafee", "symantec", "crowdstrike" };
            foreach (var name in swgProcesses)
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                {
                    issues.Add($"SWG process: {name}");
                    sb.AppendLine($"\u26A0 SWG/Security process running: {name} (PID: {procs[0].Id})");
                }
            }

            if (issues.Count == 0)
            {
                result.ResultValue = "No proxy, VPN, or SWG detected";
                result.Status = "Passed";
            }
            else
            {
                result.ResultValue = $"{issues.Count} proxy/VPN/SWG item(s) detected";
                result.Status = "Warning";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#proxy-configuration";
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ═══════════════════════════════════════════
    //  UDP BASED RDP CONNECTIVITY TESTS
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunTurnRelay()
    {
        var result = new TestResult { Id = "L-UDP-03", Name = "TURN Relay Reachability (UDP 3478)", Category = "udp" };
        try
        {
            var host = "world.relay.avd.microsoft.com";
            var port = 3478;
            var ips = await Dns.GetHostAddressesAsync(host);

            if (ips.Length == 0)
            {
                result.Status = "Failed";
                result.ResultValue = $"Could not resolve {host}";
                return result;
            }

            var ip = ips.First(i => i.AddressFamily == AddressFamily.InterNetwork);
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 3000;

            // Send a STUN binding request
            var stunRequest = BuildStunRequest();
            var endpoint = new IPEndPoint(ip, port);
            await udp.SendAsync(stunRequest, stunRequest.Length, endpoint);

            try
            {
                var receiveTask = udp.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(3000)) == receiveTask)
                {
                    var response = receiveTask.Result;
                    result.Status = "Passed";
                    result.ResultValue = $"TURN relay reachable at {ip}:{port} (UDP STUN response received)";
                    result.DetailedInfo = $"Host: {host}\nIP: {ip}\nPort: {port}\nResponse: {response.Buffer.Length} bytes";
                }
                else
                {
                    result.Status = "Warning";
                    result.ResultValue = $"TURN relay {ip}:{port} \u2014 no STUN response (UDP may be blocked)";
                    result.DetailedInfo = $"Host: {host}\nIP: {ip}\nSent STUN binding request but received no response.\nUDP port 3478 may be blocked by firewall.";
                    result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
                }
            }
            catch
            {
                result.Status = "Warning";
                result.ResultValue = $"TURN relay {ip}:{port} \u2014 UDP response timeout";
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunTurnRelayLocation()
    {
        var result = new TestResult { Id = "L-UDP-04", Name = "TURN Relay Location", Category = "udp" };
        try
        {
            var host = "world.relay.avd.microsoft.com";
            var ips = await Dns.GetHostAddressesAsync(host);
            var ip = ips.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork);

            if (ip == null)
            {
                result.Status = "Warning";
                result.ResultValue = "Could not resolve TURN relay";
                return result;
            }

            // GeoIP the relay IP
            var geo = await FetchGeoIpAsync($"https://ipinfo.io/{ip}/json", TimeSpan.FromSeconds(5));

            if (geo.TryGetProperty("city", out var cityProp))
            {
                var city = cityProp.GetString();
                var region = geo.TryGetProperty("region", out var rProp) ? rProp.GetString() : "";
                var country = geo.TryGetProperty("country", out var cProp) ? cProp.GetString() : "";
                result.ResultValue = $"TURN relay: {city}, {region}, {country} ({ip})";
                result.DetailedInfo = $"Host: {host}\nIP: {ip}\nLocation: {city}, {region}, {country}";
                result.Status = "Passed";
            }
            else
            {
                result.ResultValue = $"TURN relay IP: {ip} (location unknown)";
                result.Status = "Warning";
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunTurnTlsInspection()
    {
        var result = new TestResult { Id = "L-UDP-06", Name = "TURN TLS Inspection", Category = "udp" };
        try
        {
            // Test TLS to TURN relay over TCP 443 (TURN-TLS fallback)
            var host = "world.relay.avd.microsoft.com";
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(host, 443);
            if (await Task.WhenAny(connectTask, Task.Delay(5000)) != connectTask)
            {
                result.Status = "Warning";
                result.ResultValue = "Could not connect to TURN relay on TCP 443";
                return result;
            }

            var sb = new StringBuilder();
            bool intercepted = false;

            using var ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
            {
                if (cert is X509Certificate2 x509)
                {
                    sb.AppendLine($"Subject: {x509.Subject}");
                    sb.AppendLine($"Issuer: {x509.Issuer}");
                    var expected = new[] { "Microsoft", "DigiCert" };
                    bool isExpected = expected.Any(e => x509.Issuer.Contains(e, StringComparison.OrdinalIgnoreCase));
                    if (!isExpected)
                    {
                        intercepted = true;
                        sb.AppendLine("\u26A0 Non-Microsoft certificate \u2014 possible TLS inspection");
                    }
                }
                return true;
            });

            using var turnTlsCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, turnTlsCts.Token);
            result.ResultValue = intercepted ? "TLS inspection detected on TURN relay" : "No TLS inspection on TURN relay";
            result.Status = intercepted ? "Warning" : "Passed";
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex)
        {
            result.Status = "Warning";
            result.ResultValue = $"Could not test TURN TLS: {ex.Message}";
            result.DetailedInfo = "TURN relay TCP 443 may not be available. This is normal if only UDP 3478 is used.";
        }
        return result;
    }

    static Task<TestResult> RunTurnProxyVpn()
    {
        var result = new TestResult { Id = "L-UDP-07", Name = "TURN Proxy/VPN Detection", Category = "udp" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();

            // Check for VPN adapters — then verify if TURN traffic actually routes through them
            var vpnAdapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                           (n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Cisco", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                            n.Description.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (vpnAdapters.Count > 0)
            {
                // List VPN adapters found
                foreach (var vpn in vpnAdapters)
                {
                    var vpnIpList = GetAdapterIps(vpn);
                    sb.AppendLine($"\u2139 VPN adapter detected: {vpn.Name} ({vpn.Description})");
                    if (!string.IsNullOrEmpty(vpnIpList))
                        sb.AppendLine($"    Adapter IPs: {vpnIpList}");
                }

                // Routing table is the authoritative source for what's routed via VPN
                var caught = ProbeAvdServiceRanges(vpnAdapters, sb);
                foreach (var range in caught)
                    issues.Add($"W365/AVD range {range} routes through VPN tunnel");

                // Also show single-IP probe as informational context
                try
                {
                    var turnIps = Dns.GetHostAddresses("world.relay.avd.microsoft.com");
                    var turnIp = turnIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (turnIp != null)
                    {
                        var (routedViaVpn, localIp, _) = CheckIfRoutedViaVpn(turnIp, vpnAdapters);
                        if (routedViaVpn)
                            sb.AppendLine($"\n  \u26A0 Note: TURN relay {turnIp} (world.relay.avd.microsoft.com) routes via VPN interface {localIp}");
                        else
                            sb.AppendLine($"\n  \u2714 TURN relay {turnIp} (world.relay.avd.microsoft.com) routes direct via {localIp}");
                    }
                }
                catch { /* DNS or probe failed — non-critical since routing table already checked */ }
            }

            // Check if UDP 3478 outbound is likely blocked by checking Windows Firewall
            try
            {
                var psi = new ProcessStartInfo("netsh", "advfirewall firewall show rule name=all dir=out")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                var output = proc!.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                // Parse rule blocks and check for specific UDP 3478 block rules
                var ruleBlocks = output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
                bool found3478Block = false;
                foreach (var block in ruleBlocks)
                {
                    if (block.Contains("3478") &&
                        block.Contains("Block", StringComparison.OrdinalIgnoreCase) &&
                        block.Contains("UDP", StringComparison.OrdinalIgnoreCase))
                    {
                        found3478Block = true;
                        break;
                    }
                }
                if (found3478Block)
                {
                    issues.Add("Firewall rule blocks UDP 3478");
                    sb.AppendLine("\u26A0 Windows Firewall rule found that may block UDP 3478");
                }
                else
                {
                    sb.AppendLine("\u2714 No Windows Firewall rules blocking UDP 3478 detected");
                }
            }
            catch { sb.AppendLine("Could not check Windows Firewall rules"); }

            result.ResultValue = issues.Count == 0
                ? "No UDP-blocking proxy/VPN detected"
                : $"{issues.Count} potential UDP blocker(s) detected";
            result.Status = issues.Count == 0 ? "Passed" : "Warning";
            result.DetailedInfo = sb.ToString().Trim();
            if (issues.Count > 0)
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ═══════════════════════════════════════════
    //  CLOUD SESSION TESTS (stubs)
    // ═══════════════════════════════════════════

    static Task<TestResult> RunCloudPcLocation() => Task.FromResult(new TestResult
    {
        Id = "L-CS-01", Name = "Cloud PC Location", Category = "cloud",
        Status = "Skipped", ResultValue = "Requires active Cloud PC session"
    });

    static Task<TestResult> RunCloudPcLatency() => Task.FromResult(new TestResult
    {
        Id = "L-CS-02", Name = "Cloud PC Latency", Category = "cloud",
        Status = "Skipped", ResultValue = "Requires active Cloud PC session"
    });

    static Task<TestResult> RunSessionThroughput() => Task.FromResult(new TestResult
    {
        Id = "L-CS-03", Name = "Session Throughput", Category = "cloud",
        Status = "Skipped", ResultValue = "Requires active Cloud PC session"
    });

    static Task<TestResult> RunJitter() => Task.FromResult(new TestResult
    {
        Id = "L-CS-04", Name = "Jitter Measurement", Category = "cloud",
        Status = "Skipped", ResultValue = "Requires active Cloud PC session"
    });

    static Task<TestResult> RunPacketLoss() => Task.FromResult(new TestResult
    {
        Id = "L-CS-05", Name = "Packet Loss", Category = "cloud",
        Status = "Skipped", ResultValue = "Requires active Cloud PC session"
    });

    // ═══════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════

    static byte[] BuildStunRequest()
    {
        // STUN Binding Request (RFC 5389)
        var msg = new byte[20];
        // Type: Binding Request (0x0001)
        msg[0] = 0x00; msg[1] = 0x01;
        // Length: 0 (no attributes)
        msg[2] = 0x00; msg[3] = 0x00;
        // Magic Cookie
        msg[4] = 0x21; msg[5] = 0x12; msg[6] = 0xA4; msg[7] = 0x42;
        // Transaction ID (12 cryptographically random bytes per RFC 5389)
        System.Security.Cryptography.RandomNumberGenerator.Fill(msg.AsSpan(8, 12));
        return msg;
    }

    static string? ParseStunMappedAddress(byte[] data)
    {
        try
        {
            // Look for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            int offset = 20; // Skip header
            while (offset + 4 <= data.Length)
            {
                int attrType = (data[offset] << 8) | data[offset + 1];
                int attrLen = (data[offset + 2] << 8) | data[offset + 3];

                if (attrType == 0x0020 && attrLen >= 8) // XOR-MAPPED-ADDRESS
                {
                    int port = ((data[offset + 6] << 8) | data[offset + 7]) ^ 0x2112;
                    byte[] ip = new byte[4];
                    ip[0] = (byte)(data[offset + 8] ^ 0x21);
                    ip[1] = (byte)(data[offset + 9] ^ 0x12);
                    ip[2] = (byte)(data[offset + 10] ^ 0xA4);
                    ip[3] = (byte)(data[offset + 11] ^ 0x42);
                    return $"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}:{port}";
                }
                else if (attrType == 0x0001 && attrLen >= 8) // MAPPED-ADDRESS
                {
                    int port = (data[offset + 6] << 8) | data[offset + 7];
                    return $"{data[offset + 8]}.{data[offset + 9]}.{data[offset + 10]}.{data[offset + 11]}:{port}";
                }

                offset += 4 + attrLen;
                if (attrLen % 4 != 0) offset += 4 - (attrLen % 4); // Padding
            }
        }
        catch { }
        return null;
    }

    static async Task<TestResult> RunDnsHijackingCheck()
    {
        var result = new TestResult { Id = "L-TCP-08", Name = "DNS Hijacking Check", Category = "tcp" };
        try
        {
            var gateways = new[] { "rdweb.wvd.microsoft.com", "client.wvd.microsoft.com" };
            var sb = new StringBuilder();
            int passed = 0;
            var issues = new List<string>();

            // Known Microsoft/Azure public IP first-octet ranges
            // (covers Azure Front Door, Azure WAN, Azure infra)
            var knownAzureFirstOctets = new HashSet<byte> { 13, 20, 40, 51, 52, 65, 104, 131, 132, 134, 137, 138, 157, 168, 191, 204 };

            foreach (var host in gateways)
            {
                sb.AppendLine($"  {host}");

                IPAddress[] ips;
                try
                {
                    ips = await Dns.GetHostAddressesAsync(host);
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    \u2717 DNS resolution failed: {ex.Message}");
                    issues.Add($"{host}: DNS resolution failed");
                    sb.AppendLine();
                    continue;
                }

                // Check CNAME chain for AFD/PrivateLink indicators
                bool cnameHasAfd = false;
                bool cnameHasPrivateLink = false;
                try
                {
                    var psi = new ProcessStartInfo("nslookup", $"-type=CNAME {host}")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var proc = Process.Start(psi);
                    var nsOutput = await proc!.StandardOutput.ReadToEndAsync();
                    await proc.WaitForExitAsync();
                    cnameHasAfd = nsOutput.Contains("afd", StringComparison.OrdinalIgnoreCase) ||
                                  nsOutput.Contains("azurefd", StringComparison.OrdinalIgnoreCase);
                    cnameHasPrivateLink = nsOutput.Contains("privatelink", StringComparison.OrdinalIgnoreCase);
                }
                catch { /* nslookup unavailable, rely on other checks */ }

                // TLS cert validation as secondary check
                bool validCert = false;
                try
                {
                    using var tcp = new TcpClient();
                    using var cts = new CancellationTokenSource(5000);
                    await tcp.ConnectAsync(host, 443, cts.Token);
                    using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, _, errors) =>
                    {
                        if (cert is X509Certificate2 x509)
                        {
                            var issuer = x509.Issuer;
                            validCert = issuer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                                       issuer.Contains("DigiCert", StringComparison.OrdinalIgnoreCase);
                        }
                        return true;
                    });
                    await ssl.AuthenticateAsClientAsync(host);
                }
                catch { /* TLS check failed, rely on other signals */ }

                foreach (var ip in ips)
                {
                    bool isLoopback = IPAddress.IsLoopback(ip);
                    bool isLinkLocal = ip.ToString().StartsWith("169.254.");
                    bool isPrivate = IsPrivateIp(ip);
                    var bytes = ip.GetAddressBytes();
                    bool isKnownAzureRange = bytes.Length == 4 && knownAzureFirstOctets.Contains(bytes[0]);

                    // Reverse DNS
                    string rdns = "";
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(ip);
                        rdns = entry.HostName;
                    }
                    catch { rdns = "(no reverse DNS)"; }

                    bool isMicrosoft = rdns.Contains("microsoft", StringComparison.OrdinalIgnoreCase) ||
                                      rdns.Contains("msedge", StringComparison.OrdinalIgnoreCase) ||
                                      rdns.Contains("azure", StringComparison.OrdinalIgnoreCase) ||
                                      rdns.Contains("afd", StringComparison.OrdinalIgnoreCase) ||
                                      rdns.Contains("trafficmanager", StringComparison.OrdinalIgnoreCase);

                    if (isLoopback)
                    {
                        sb.AppendLine($"    \u2717 {ip} \u2192 LOOPBACK \u2014 DNS is hijacked!");
                        issues.Add($"{host}: resolves to loopback {ip}");
                    }
                    else if (isLinkLocal)
                    {
                        sb.AppendLine($"    \u2717 {ip} \u2192 LINK-LOCAL \u2014 DNS appears hijacked");
                        issues.Add($"{host}: resolves to link-local {ip}");
                    }
                    else if (isPrivate)
                    {
                        // Private IP — likely Private Link
                        if (cnameHasPrivateLink || validCert)
                            sb.AppendLine($"    \u2713 {ip} \u2192 Private Link (cert valid)");
                        else
                            sb.AppendLine($"    \u2713 {ip} \u2192 Private IP (likely Private Link)");
                    }
                    else if (isMicrosoft || isKnownAzureRange || cnameHasAfd || validCert)
                    {
                        // Known good: Microsoft rDNS, known Azure range, AFD CNAME, or valid MS cert
                        var reason = isMicrosoft ? rdns
                                   : isKnownAzureRange ? $"Azure IP range ({bytes[0]}.x.x.x)"
                                   : cnameHasAfd ? "AFD CNAME chain"
                                   : "valid Microsoft TLS cert";
                        sb.AppendLine($"    \u2713 {ip} \u2192 {reason}");
                    }
                    else
                    {
                        sb.AppendLine($"    \u26a0 {ip} \u2192 {rdns} \u2014 not a recognized Microsoft host");
                        issues.Add($"{host}: resolves to non-Microsoft IP {ip} ({rdns})");
                    }
                }

                if (!issues.Any(i => i.StartsWith(host)))
                    passed++;

                sb.AppendLine();
            }

            if (issues.Count > 0)
            {
                sb.AppendLine("Issues found:");
                foreach (var issue in issues)
                    sb.AppendLine($"  \u26a0 {issue}");
            }

            result.ResultValue = issues.Count == 0
                ? $"All {gateways.Length} gateways resolve to legitimate Microsoft IPs"
                : $"{issues.Count} potential DNS issue(s) detected";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = issues.Any(i => i.Contains("loopback") || i.Contains("link-local")) ? "Failed"
                          : issues.Count > 0 ? "Warning" : "Passed";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunGatewayUsed()
    {
        var result = new TestResult { Id = "L-TCP-09", Name = "Gateway Used", Category = "tcp" };
        try
        {
            var gateways = new[] { "rdweb.wvd.microsoft.com", "client.wvd.microsoft.com" };
            var sb = new StringBuilder();

            using var httpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                {
                    return true;
                },
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            // Fetch user's location via GeoIP
            string userCity = null, userCountry = null;
            double userLat = 0, userLon = 0;
            var gatewayLocations = new List<string>(); // collect for summary
            try
            {
                var userGeo = await FetchGeoIpAsync("https://ipinfo.io/json", TimeSpan.FromSeconds(5));
                if (userGeo.TryGetProperty("city", out var cityProp))
                {
                    userCity = cityProp.GetString();
                    userCountry = userGeo.TryGetProperty("country", out var cProp) ? cProp.GetString() : "";
                    // ipinfo.io returns loc as "lat,lon" string
                    if (userGeo.TryGetProperty("loc", out var locProp))
                    {
                        var parts = locProp.GetString()?.Split(',');
                        if (parts?.Length == 2)
                        {
                            double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLat);
                            double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLon);
                        }
                    }
                }
            }
            catch { /* user location is best-effort */ }

            foreach (var host in gateways)
            {
                sb.AppendLine($"  {host}");

                // Resolve IP
                IPAddress[] ips;
                try
                {
                    ips = await Dns.GetHostAddressesAsync(host);
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    IP: could not resolve ({ex.Message})");
                    sb.AppendLine();
                    continue;
                }

                var ip = ips.First();
                sb.AppendLine($"    IP: {ip}");

                // Reverse DNS for edge node identification
                try
                {
                    var entry = await Dns.GetHostEntryAsync(ip);
                    sb.AppendLine($"    Edge: {entry.HostName}");
                }
                catch
                {
                    sb.AppendLine($"    Edge: (no reverse DNS)");
                }

                // GeoIP the gateway IP to show location
                string gwCity = null, gwCountry = null;
                try
                {
                    var gwGeo = await FetchGeoIpAsync($"https://ipinfo.io/{ip}/json", TimeSpan.FromSeconds(5));
                    if (gwGeo.TryGetProperty("city", out var gwCityProp))
                    {
                        gwCity = gwCityProp.GetString();
                        gwCountry = gwGeo.TryGetProperty("country", out var gwCProp) ? gwCProp.GetString() : "";
                        double gwLat = 0, gwLon = 0;
                        if (gwGeo.TryGetProperty("loc", out var gwLocProp))
                        {
                            var parts = gwLocProp.GetString()?.Split(',');
                            if (parts?.Length == 2)
                            {
                                double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out gwLat);
                                double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out gwLon);
                            }
                        }

                        var locationStr = $"{gwCity}, {gwCountry}";
                        gatewayLocations.Add(locationStr);

                        // Compare with user location
                        if (userLat != 0 && userLon != 0)
                        {
                            var distKm = HaversineDistanceKm(userLat, userLon, gwLat, gwLon);
                            if (distKm < 300)
                                locationStr += $" \u2714 Near you ({userCity}, {userCountry}) — {distKm:0} km";
                            else if (distKm < 1000)
                                locationStr += $" \u2248 Moderate distance from you ({userCity}) — {distKm:0} km";
                            else
                                locationStr += $" \u26A0 Far from you ({userCity}, {userCountry}) — {distKm:0} km";
                        }

                        sb.AppendLine($"    Location: {locationStr}");
                    }
                }
                catch { /* GeoIP is best-effort */ }

                // CNAME chain via nslookup for AFD identification
                try
                {
                    var psi = new ProcessStartInfo("nslookup", $"-type=CNAME {host}")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var proc = Process.Start(psi);
                    var output = await proc!.StandardOutput.ReadToEndAsync();
                    await proc.WaitForExitAsync();

                    if (output.Contains("afd", StringComparison.OrdinalIgnoreCase) ||
                        output.Contains("azurefd", StringComparison.OrdinalIgnoreCase))
                    {
                        sb.AppendLine($"    Route: Azure Front Door");
                    }
                    else if (output.Contains("privatelink", StringComparison.OrdinalIgnoreCase))
                    {
                        sb.AppendLine($"    Route: Private Link");
                    }
                    else
                    {
                        sb.AppendLine($"    Route: Direct");
                    }
                }
                catch
                {
                    sb.AppendLine($"    Route: (could not determine)");
                }

                // TLS cert subject for the specific gateway
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(ip, 443);
                    using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                    await ssl.AuthenticateAsClientAsync(host);
                    var cert = ssl.RemoteCertificate as X509Certificate2;
                    if (cert != null)
                    {
                        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                        sb.AppendLine($"    Cert: {cn}");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    Cert: could not retrieve ({ex.InnerException?.Message ?? ex.Message})");
                }

                sb.AppendLine();
            }

            // Build result summary from cached gateway locations
            var summary = gatewayLocations.Distinct().ToList();
            result.ResultValue = summary.Any()
                ? $"Gateway edge: {string.Join(" / ", summary)}"
                : string.Join(", ", gateways.Select(g => { try { return $"{g} → {Dns.GetHostAddresses(g).First()}"; } catch { return g; } }));
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = "Passed";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static double HaversineDistanceKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double R = 6371; // Earth radius in km
        var dLat = (lat2 - lat1) * Math.PI / 180;
        var dLon = (lon2 - lon1) * Math.PI / 180;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                Math.Cos(lat1 * Math.PI / 180) * Math.Cos(lat2 * Math.PI / 180) *
                Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return R * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
    }

    static bool IsPrivateIp(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return false;
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127);
    }

    /// <summary>Escape a string as a JavaScript single-quoted literal.</summary>
    static string EscapeJsString(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length + 10);
        sb.Append('\'');
        foreach (var c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                default: sb.Append(c); break;
            }
        }
        sb.Append('\'');
        return sb.ToString();
    }
}

// ═══════════════════════════════════════════
//  MODELS
// ═══════════════════════════════════════════

class TestResult
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "NotRun";

    [JsonPropertyName("resultValue")]
    public string ResultValue { get; set; } = string.Empty;

    [JsonPropertyName("detailedInfo")]
    public string DetailedInfo { get; set; } = string.Empty;

    [JsonPropertyName("remediationUrl")]
    public string RemediationUrl { get; set; } = string.Empty;

    [JsonPropertyName("duration")]
    public int Duration { get; set; }
}

class ScanOutput
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("machineName")]
    public string MachineName { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("dotNetVersion")]
    public string DotNetVersion { get; set; } = string.Empty;

    [JsonPropertyName("results")]
    public List<TestResult> Results { get; set; } = [];
}

class TestDefinition
{
    public string Id { get; }
    public string Name { get; }
    public string Description { get; }
    public string Category { get; }
    public Func<Task<TestResult>> Run { get; }

    public TestDefinition(string id, string name, string description, string category, Func<Task<TestResult>> run)
    {
        Id = id;
        Name = name;
        Description = description;
        Category = category;
        Run = run;
    }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ScanOutput))]
[JsonSerializable(typeof(TestResult))]
[JsonSerializable(typeof(List<TestResult>))]
[JsonSerializable(typeof(JsonElement))]
internal partial class ScanJsonContext : JsonSerializerContext
{
}
