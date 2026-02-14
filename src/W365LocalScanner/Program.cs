using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
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

            // ── Live Connection Diagnostics ──
            new("17", "Active RDP Session Detection", "Detects remote session or RDP clients", "cloud", RunActiveSession),
            new("17b", "RDP Transport Protocol", "TCP vs UDP from event logs", "cloud", RunTransportProtocol),
            new("17c", "UDP Shortpath Readiness", "STUN test to TURN relay", "cloud", RunUdpReadiness),
            new("18", "Session Round-Trip Latency", "Measures RTT to Cloud PC", "cloud", RunSessionLatency),
            new("19", "Session Frame Rate & Bandwidth", "RemoteFX Graphics counters", "cloud", RunFrameRate),
            new("20", "Connection Jitter", "Measures network jitter", "cloud", RunJitter),
            new("21", "Frame Drops & Packet Loss", "Detects dropped frames and packet loss", "cloud", RunPacketLoss),
            new("22", "Cloud PC Teams Optimization", "Checks Teams AV redirection", "cloud", RunCloudTeamsOptimization),
            new("24", "VPN Connection Performance", "Detects VPN impact", "cloud", RunCloudVpnPerformance),
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
            var host = "afdfp-rdgateway-r1.wvd.microsoft.com";
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

            // Determine route by IP, not CNAME text — "privatelink-global" in the
            // CNAME chain is a standard Microsoft DNS zone, NOT actual Private Link.
            bool isPrivateLink = ips.Any(ip => IsPrivateIp(ip));

            if (isPrivateLink)
            {
                result.ResultValue = $"Private Link detected \u2014 resolves to private IP ({ipStr})";
                result.Status = "Passed";
                sb.AppendLine("\nPrivate Link endpoint detected. Traffic routes via private network.");
            }
            else
            {
                result.ResultValue = $"Azure Front Door routing ({ipStr})";
                result.Status = "Passed";
                sb.AppendLine("\nPublic connection via Azure Front Door / Traffic Manager. This is normal.");
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
    //  LIVE CONNECTION DIAGNOSTICS
    // ═══════════════════════════════════════════

    // ── P/Invoke for remote session detection ──
    [DllImport("user32.dll")]
    static extern int GetSystemMetrics(int nIndex);
    const int SM_REMOTESESSION = 0x1000;

    static bool IsRemoteSession()
    {
        try { return GetSystemMetrics(SM_REMOTESESSION) != 0; }
        catch { return false; }
    }

    static bool IsInW365Range(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        uint addr = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        // 40.64.144.0/20 → mask 0xFFFFF000
        uint net1 = (uint)(40 << 24 | 64 << 16 | 144 << 8);
        if ((addr & 0xFFFFF000) == net1) return true;
        // 51.5.0.0/16 → mask 0xFFFF0000
        uint net2 = (uint)(51 << 24 | 5 << 16);
        if ((addr & 0xFFFF0000) == net2) return true;
        return false;
    }

    static async Task<(string hostname, int port, IPAddress ip)?> GetValidatedGateway()
    {
        var gateways = new[] { "afdfp-rdgateway-r1.wvd.microsoft.com", "rdweb.wvd.microsoft.com", "client.wvd.microsoft.com" };
        foreach (var gw in gateways)
        {
            try
            {
                var ips = await Dns.GetHostAddressesAsync(gw);
                var ip = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ip != null && IsInW365Range(ip))
                    return (gw, 443, ip);
            }
            catch { }
        }
        return null;
    }

    // ── Test 17: Active RDP Session Detection ──
    static Task<TestResult> RunActiveSession()
    {
        var result = new TestResult { Id = "17", Name = "Active RDP Session Detection", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            bool isRemote = IsRemoteSession();

            sb.AppendLine($"Running inside Remote Desktop session: {(isRemote ? "Yes" : "No")}");

            if (isRemote)
            {
                sb.AppendLine();
                sb.AppendLine("This tool is running INSIDE a remote session (Cloud PC / Session Host).");
                sb.AppendLine("RemoteFX performance counters are available for live session metrics.");
                sb.AppendLine($"Machine: {Environment.MachineName}");
                sb.AppendLine($"Session ID: {Process.GetCurrentProcess().SessionId}");

                result.Status = "Passed";
                result.ResultValue = "Running inside remote session";
            }
            else
            {
                // Check for RDP client processes
                var clientNames = new (string name, string label)[]
                {
                    ("msrdc", "Windows App (MSRDC)"),
                    ("mstsc", "Remote Desktop Client (mstsc)"),
                    ("DesktopClient", "AVD Desktop Client"),
                };
                var clients = new List<string>();
                foreach (var (name, label) in clientNames)
                {
                    try
                    {
                        foreach (var p in Process.GetProcessesByName(name))
                        {
                            string title = "";
                            try { title = p.MainWindowTitle ?? ""; } catch { }
                            DateTime? started = null;
                            try { started = p.StartTime; } catch { }
                            clients.Add($"  {label} — PID {p.Id}{(started.HasValue ? $", started {started:HH:mm:ss}" : "")}{(string.IsNullOrEmpty(title) ? "" : $", window: {title}")}");
                        }
                    }
                    catch { }
                }

                if (clients.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine($"Found {clients.Count} active RDP client process(es):");
                    foreach (var c in clients)
                        sb.AppendLine(c);
                    sb.AppendLine();
                    sb.AppendLine("Active RDP client detected on this machine.");
                    sb.AppendLine("Session metrics are gathered from event logs and TCP probes.");
                    sb.AppendLine("For full RemoteFX counters, run this tool inside the Cloud PC.");

                    result.Status = "Passed";
                    result.ResultValue = $"{clients.Count} active client(s)";
                }
                else
                {
                    sb.AppendLine();
                    sb.AppendLine("No active RDP client processes found (msrdc.exe, mstsc.exe).");
                    sb.AppendLine();
                    sb.AppendLine("To analyze an active session:");
                    sb.AppendLine("  1. Connect to your Cloud PC using Windows App or Remote Desktop");
                    sb.AppendLine("  2. Re-run these tests while connected");

                    result.Status = "Warning";
                    result.ResultValue = "No active RDP session detected";
                    result.RemediationText = "Connect to your Cloud PC and re-run to get live session metrics.";
                }
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ── Test 17b: RDP Transport Protocol ──
    static Task<TestResult> RunTransportProtocol()
    {
        var result = new TestResult { Id = "17b", Name = "RDP Transport Protocol", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            bool udpConnected = false, udpFailed = false, shortpathConnected = false, hasConnection = false;
            string protocol = "";

            // 1. Try RdpCoreTS (inside remote session)
            try
            {
                const string logName = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
                var query = new EventLogQuery(logName, PathType.LogName,
                    "*[System[(EventID=131 or EventID=140 or EventID=141 or EventID=142 or EventID=143) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
                using var reader = new EventLogReader(query);
                EventRecord? record;
                int count = 0;
                sb.AppendLine("RdpCoreTS Events (last 24h):");
                while ((record = reader.ReadEvent()) != null && count < 15)
                {
                    using (record)
                    {
                        count++;
                        int eid = record.Id;
                        string msg = "";
                        try { msg = record.FormatDescription() ?? ""; } catch { }
                        string label = eid switch
                        {
                            131 => "Connection Accepted",
                            140 => "Transport Negotiated",
                            141 => "UDP Connected",
                            142 => "UDP Failed (TCP Fallback)",
                            143 => "RDP Shortpath Connected",
                            _ => $"Event {eid}"
                        };
                        sb.AppendLine($"  [{record.TimeCreated:HH:mm:ss}] {label}");
                        if (msg.Length is > 0 and < 200)
                            sb.AppendLine($"    {msg}");
                        if (eid == 131) hasConnection = true;
                        if (eid == 141) { udpConnected = true; protocol = "UDP (RDP Shortpath)"; }
                        if (eid == 142) { udpFailed = true; protocol = "TCP (Reverse Connect)"; }
                        if (eid == 143) { shortpathConnected = true; protocol = "UDP (RDP Shortpath)"; }
                    }
                }
                if (count == 0) sb.AppendLine("  (no events)");
            }
            catch { sb.AppendLine("RdpCoreTS log: not available (expected on client machines)"); }

            sb.AppendLine();

            // 2. Try TerminalServices-RDPClient (client machine)
            try
            {
                const string logName = "Microsoft-Windows-TerminalServices-RDPClient/Operational";
                var query = new EventLogQuery(logName, PathType.LogName,
                    "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]");
                using var reader = new EventLogReader(query);
                EventRecord? record;
                int count = 0;
                sb.AppendLine("RDP Client Events (last 24h):");
                while ((record = reader.ReadEvent()) != null && count < 200)
                {
                    using (record)
                    {
                        int eid = record.Id;
                        if (eid is 1024 or 1025 or 1026 or 1027 or 1029)
                        {
                            count++;
                            string msg = "";
                            try { msg = record.FormatDescription() ?? ""; } catch { }
                            string label = eid switch
                            {
                                1024 => "Connection Started",
                                1025 => "Connection Ended",
                                1026 => "Disconnected",
                                1027 => "Transport Connected",
                                1029 => "Base Transport Type",
                                _ => $"Event {eid}"
                            };
                            if (count <= 10) sb.AppendLine($"  [{record.TimeCreated:HH:mm:ss}] {label}");
                            if (eid == 1024) hasConnection = true;
                            if (msg.Contains("UDP", StringComparison.OrdinalIgnoreCase))
                            {
                                if (msg.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                                    msg.Contains("connected", StringComparison.OrdinalIgnoreCase))
                                { udpConnected = true; protocol = "UDP (RDP Shortpath)"; }
                                else if (msg.Contains("fail", StringComparison.OrdinalIgnoreCase))
                                { udpFailed = true; if (string.IsNullOrEmpty(protocol)) protocol = "TCP (Reverse Connect)"; }
                            }
                        }
                    }
                }
                if (count == 0) sb.AppendLine("  (no events)");
            }
            catch { sb.AppendLine("RDP Client log: not available"); }

            // Also check RemoteFX UDP bandwidth if inside remote session
            if (IsRemoteSession())
            {
                try
                {
                    if (PerformanceCounterCategory.Exists("RemoteFX Network"))
                    {
                        var cat = new PerformanceCounterCategory("RemoteFX Network");
                        var instances = cat.GetInstanceNames();
                        if (instances.Length > 0)
                        {
                            using var pc = new PerformanceCounter("RemoteFX Network", "Current UDP Bandwidth", instances[0], true);
                            pc.NextValue(); Thread.Sleep(100);
                            var bw = pc.NextValue();
                            if (bw > 0) { udpConnected = true; sb.AppendLine($"\nRemoteFX UDP Bandwidth: {bw:F0} KB/s (active)"); }
                        }
                    }
                }
                catch { }
            }

            sb.AppendLine();

            // Determine result
            if (udpConnected || shortpathConnected)
            {
                result.Status = "Passed";
                result.ResultValue = "UDP (RDP Shortpath) ⚡";
                sb.AppendLine("✓ Session is using UDP transport (RDP Shortpath).");
            }
            else if (udpFailed)
            {
                result.Status = "Warning";
                result.ResultValue = "TCP (UDP failed)";
                sb.AppendLine("⚠ UDP connection failed — session fell back to TCP.");
                result.RemediationText = "UDP-based RDP Shortpath failed. Check that UDP 3478 is allowed outbound.";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            else if (hasConnection && !string.IsNullOrEmpty(protocol))
            {
                result.Status = protocol.Contains("UDP") ? "Passed" : "Warning";
                result.ResultValue = protocol;
            }
            else if (!hasConnection)
            {
                result.Status = "Skipped";
                result.ResultValue = "No recent connection detected";
                sb.AppendLine("No RDP connection events found in the last 24 hours.");
                sb.AppendLine("Connect to your Cloud PC and re-run to detect transport.");
            }
            else
            {
                result.Status = "Warning";
                result.ResultValue = "Unable to determine transport";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ── Test 17c: UDP Shortpath Readiness ──
    static async Task<TestResult> RunUdpReadiness()
    {
        var result = new TestResult { Id = "17c", Name = "UDP Shortpath Readiness", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            var host = "world.relay.avd.microsoft.com";
            int port = 3478;
            sb.AppendLine($"STUN/TURN Relay: {host}:{port}");
            sb.AppendLine("Expected W365 IP ranges: 40.64.144.0/20, 51.5.0.0/16");
            sb.AppendLine();

            var addresses = await Dns.GetHostAddressesAsync(host);
            var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ip == null) { result.Status = "Failed"; result.ResultValue = "DNS resolution failed"; return result; }

            bool inRange = IsInW365Range(ip);
            sb.AppendLine($"Resolved: {ip} ({(inRange ? "✓ W365 range" : "⚠ outside W365 range")})");

            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 3000;
            var ep = new IPEndPoint(ip, port);
            var stunReq = BuildStunRequest();

            var sw = Stopwatch.StartNew();
            await udp.SendAsync(stunReq, stunReq.Length, ep);
            var recvTask = udp.ReceiveAsync();
            var completed = await Task.WhenAny(recvTask, Task.Delay(3000));

            if (completed == recvTask)
            {
                sw.Stop();
                var resp = await recvTask;
                bool validStun = resp.Buffer.Length >= 20 && ((resp.Buffer[0] << 8) | resp.Buffer[1]) == 0x0101;

                sb.AppendLine($"✓ {(validStun ? "STUN response" : "UDP response")} in {sw.Elapsed.TotalMilliseconds:F0}ms");
                sb.AppendLine();
                sb.AppendLine("✓ UDP connectivity confirmed. RDP Shortpath should be available.");
                sb.AppendLine();
                sb.AppendLine("RDP Shortpath modes:");
                sb.AppendLine("  • STUN (direct): Client ↔ Cloud PC via UDP hole-punching");
                sb.AppendLine("  • TURN (relayed): Client ↔ TURN relay ↔ Cloud PC");

                result.Status = "Passed";
                result.ResultValue = $"UDP ready ({sw.Elapsed.TotalMilliseconds:F0}ms)";
            }
            else
            {
                sb.AppendLine("✗ UDP connectivity to STUN server timed out (3s).");
                sb.AppendLine("  RDP Shortpath will NOT be available — connections will use TCP.");
                sb.AppendLine();
                sb.AppendLine("Common causes:");
                sb.AppendLine("  • Firewall blocking outbound UDP 3478");
                sb.AppendLine("  • VPN tunneling all traffic (no UDP passthrough)");
                sb.AppendLine("  • Corporate SWG blocking non-HTTP traffic");

                result.Status = "Warning";
                result.ResultValue = "UDP blocked — RDP Shortpath unavailable";
                result.RemediationText = "UDP 3478 outbound is blocked. Allow UDP 3478 outbound to Microsoft TURN relay servers.";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 18: Session Round-Trip Latency ──
    static async Task<TestResult> RunSessionLatency()
    {
        var result = new TestResult { Id = "18", Name = "Session Round-Trip Latency", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();

            if (IsRemoteSession())
            {
                sb.AppendLine("Source: RemoteFX Network performance counters (inside remote session)");
                sb.AppendLine();

                var tcpSamples = new List<float>();
                var udpSamples = new List<float>();

                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        if (PerformanceCounterCategory.Exists("RemoteFX Network"))
                        {
                            var cat = new PerformanceCounterCategory("RemoteFX Network");
                            var instances = cat.GetInstanceNames();
                            if (instances.Length > 0)
                            {
                                var inst = instances[0];
                                var tcp = TryReadPerfCounter("RemoteFX Network", "Current TCP RTT", inst);
                                var udpVal = TryReadPerfCounter("RemoteFX Network", "Current UDP RTT", inst);
                                if (tcp.HasValue) tcpSamples.Add(tcp.Value);
                                if (udpVal.HasValue) udpSamples.Add(udpVal.Value);
                            }
                        }
                    }
                    catch { }
                    if (i < 2) await Task.Delay(700);
                }

                if (tcpSamples.Count > 0)
                    sb.AppendLine($"TCP RTT: {tcpSamples.Average():F0}ms (avg of {tcpSamples.Count} samples)");
                if (udpSamples.Count > 0)
                    sb.AppendLine($"UDP RTT: {udpSamples.Average():F0}ms (avg of {udpSamples.Count} samples)");

                if (tcpSamples.Count == 0 && udpSamples.Count == 0)
                {
                    sb.AppendLine("⚠ RemoteFX Network counters not available.");
                    result.Status = "Warning";
                    result.ResultValue = "Counters unavailable";
                }
                else
                {
                    var primaryRtt = udpSamples.Count > 0 ? udpSamples.Average() : tcpSamples.Average();
                    var transport = udpSamples.Count > 0 ? "UDP" : "TCP";
                    result.ResultValue = $"{primaryRtt:F0}ms ({transport})";
                    result.Status = primaryRtt < 100 ? "Passed" : primaryRtt < 200 ? "Warning" : "Failed";
                    if (primaryRtt >= 100)
                        result.RemediationText = $"Latency is {primaryRtt:F0}ms. Check network egress path, proxy/VPN overhead.";
                }
            }
            else
            {
                // TCP probe to validated gateway
                var gw = await GetValidatedGateway();
                if (gw == null)
                {
                    sb.AppendLine("✗ No RD Gateway endpoint found within W365 IP ranges.");
                    sb.AppendLine("Expected ranges: 40.64.144.0/20, 51.5.0.0/16");
                    result.Status = "Skipped";
                    result.ResultValue = "No W365 gateway endpoint available";
                }
                else
                {
                    var (hostname, port, ip) = gw.Value;
                    sb.AppendLine("Source: TCP connect probes to RD Gateway");
                    sb.AppendLine($"Endpoint: {hostname}:{port}");
                    sb.AppendLine($"Resolved IP: {ip} (✓ within W365 range)");
                    sb.AppendLine("Samples: 10");
                    sb.AppendLine();

                    var rtts = new List<double>();
                    for (int i = 0; i < 10; i++)
                    {
                        try
                        {
                            var sw = Stopwatch.StartNew();
                            using var tcp = new TcpClient();
                            using var cts = new CancellationTokenSource(5000);
                            await tcp.ConnectAsync(hostname, port, cts.Token);
                            sw.Stop();
                            rtts.Add(sw.Elapsed.TotalMilliseconds);
                        }
                        catch { }
                        if (i < 9) await Task.Delay(200);
                    }

                    if (rtts.Count == 0)
                    {
                        result.Status = "Failed";
                        result.ResultValue = "Gateway unreachable";
                        sb.AppendLine("✗ All TCP connection attempts failed.");
                    }
                    else
                    {
                        var avg = rtts.Average();
                        sb.AppendLine($"Successful: {rtts.Count}/10");
                        sb.AppendLine($"Min: {rtts.Min():F0}ms | Avg: {avg:F0}ms | Max: {rtts.Max():F0}ms");
                        sb.AppendLine($"Values: {string.Join(", ", rtts.Select(r => $"{r:F0}ms"))}");

                        result.ResultValue = $"{avg:F0}ms (TCP)";
                        result.Status = avg < 100 ? "Passed" : avg < 200 ? "Warning" : "Failed";
                        if (avg >= 100)
                            result.RemediationText = $"Latency is {avg:F0}ms. Check for proxy/VPN adding latency.";
                    }
                }
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 19: Session Frame Rate & Bandwidth ──
    static async Task<TestResult> RunFrameRate()
    {
        var result = new TestResult { Id = "19", Name = "Session Frame Rate & Bandwidth", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();

            if (!IsRemoteSession())
            {
                sb.AppendLine("RemoteFX Graphics counters are only available inside a remote session.");
                sb.AppendLine();
                sb.AppendLine("To get frame rate and bandwidth data:");
                sb.AppendLine("  1. Connect to your Cloud PC");
                sb.AppendLine("  2. Run this tool inside the Cloud PC");
                sb.AppendLine();
                sb.AppendLine("Available metrics inside remote session:");
                sb.AppendLine("  • Input/Output Frames per Second");
                sb.AppendLine("  • Frames Skipped (Network / Client / Server)");
                sb.AppendLine("  • Average Encoding Time, Frame Quality");
                sb.AppendLine("  • UDP Bandwidth");

                result.Status = "Skipped";
                result.ResultValue = "Run inside Cloud PC for live data";
                result.DetailedInfo = sb.ToString().Trim();
                return result;
            }

            sb.AppendLine("Source: RemoteFX Graphics performance counters");
            sb.AppendLine();

            float? outputFps = null, inputFps = null, encTime = null, quality = null, udpBw = null;
            float? skipNet = null, skipClient = null, skipServer = null;

            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (PerformanceCounterCategory.Exists("RemoteFX Graphics"))
                    {
                        var cat = new PerformanceCounterCategory("RemoteFX Graphics");
                        var instances = cat.GetInstanceNames();
                        if (instances.Length > 0)
                        {
                            var inst = instances[0];
                            inputFps = TryReadPerfCounter("RemoteFX Graphics", "Input Frames/Second", inst) ?? inputFps;
                            outputFps = TryReadPerfCounter("RemoteFX Graphics", "Output Frames/Second", inst) ?? outputFps;
                            skipNet = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Network Resources", inst) ?? skipNet;
                            skipClient = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Client Resources", inst) ?? skipClient;
                            skipServer = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Server Resources", inst) ?? skipServer;
                            encTime = TryReadPerfCounter("RemoteFX Graphics", "Average Encoding Time", inst) ?? encTime;
                            quality = TryReadPerfCounter("RemoteFX Graphics", "Frame Quality", inst) ?? quality;
                        }
                    }
                    if (PerformanceCounterCategory.Exists("RemoteFX Network"))
                    {
                        var cat = new PerformanceCounterCategory("RemoteFX Network");
                        var instances = cat.GetInstanceNames();
                        if (instances.Length > 0)
                            udpBw = TryReadPerfCounter("RemoteFX Network", "Current UDP Bandwidth", instances[0]) ?? udpBw;
                    }
                }
                catch { }
                if (i < 2) await Task.Delay(700);
            }

            if (outputFps == null && inputFps == null)
            {
                sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
                sb.AppendLine("  Session may be idle or counters may be disabled.");
                result.Status = "Warning";
                result.ResultValue = "Counters unavailable";
            }
            else
            {
                if (inputFps.HasValue) sb.AppendLine($"Input Frames/sec:  {inputFps:F1}");
                if (outputFps.HasValue) sb.AppendLine($"Output Frames/sec: {outputFps:F1}");
                if (encTime.HasValue) sb.AppendLine($"Avg Encoding Time: {encTime:F1}ms {(encTime < 33 ? "✓ Good" : "⚠ High")}");
                if (quality.HasValue) sb.AppendLine($"Frame Quality:     {quality:F0}%");
                if (udpBw.HasValue) sb.AppendLine($"UDP Bandwidth:     {udpBw:F0} KB/s");
                sb.AppendLine();
                sb.AppendLine("Frame Drop Analysis:");
                if (skipNet.HasValue) sb.AppendLine($"  Skipped (Network): {skipNet:F1}/sec");
                if (skipClient.HasValue) sb.AppendLine($"  Skipped (Client):  {skipClient:F1}/sec");
                if (skipServer.HasValue) sb.AppendLine($"  Skipped (Server):  {skipServer:F1}/sec");

                float totalSkip = (skipNet ?? 0) + (skipClient ?? 0) + (skipServer ?? 0);
                float fps = outputFps ?? 30;
                float dropPct = fps > 0 ? totalSkip / (fps + totalSkip) * 100 : 0;

                if (encTime is > 33)
                {
                    result.Status = "Warning";
                    result.ResultValue = $"{outputFps:F0} fps, encoding slow ({encTime:F0}ms)";
                }
                else if (dropPct > 15)
                {
                    result.Status = "Warning";
                    result.ResultValue = $"{outputFps:F0} fps, {dropPct:F0}% frames dropped";
                }
                else
                {
                    result.Status = "Passed";
                    result.ResultValue = $"{outputFps:F0} fps{(quality.HasValue ? $", {quality:F0}% quality" : "")}";
                }
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 20: Connection Jitter ──
    static async Task<TestResult> RunJitter()
    {
        var result = new TestResult { Id = "20", Name = "Connection Jitter", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            var gw = await GetValidatedGateway();

            if (gw == null)
            {
                sb.AppendLine("✗ No RD Gateway endpoint found within W365 IP ranges.");
                sb.AppendLine("Expected ranges: 40.64.144.0/20, 51.5.0.0/16");
                sb.AppendLine("Connect to your Cloud PC at least once so gateway can be discovered.");
                result.Status = "Skipped";
                result.ResultValue = "No W365 gateway endpoint available";
                result.DetailedInfo = sb.ToString().Trim();
                return result;
            }

            var (hostname, port, ip) = gw.Value;
            sb.AppendLine($"Endpoint: {hostname}:{port}");
            sb.AppendLine($"Resolved IP: {ip} (✓ within W365 range)");
            sb.AppendLine("Samples: 20 TCP connect probes at 250ms intervals");
            sb.AppendLine();

            var rtts = new List<double>();
            for (int i = 0; i < 20; i++)
            {
                try
                {
                    var sw = Stopwatch.StartNew();
                    using var tcp = new TcpClient();
                    using var cts = new CancellationTokenSource(5000);
                    await tcp.ConnectAsync(hostname, port, cts.Token);
                    sw.Stop();
                    rtts.Add(sw.Elapsed.TotalMilliseconds);
                }
                catch { }
                if (i < 19) await Task.Delay(250);
            }

            if (rtts.Count < 2)
            {
                result.Status = "Failed";
                result.ResultValue = "Measurement failed";
                sb.AppendLine(rtts.Count == 0 ? "✗ All connection attempts failed" : "✗ Insufficient samples for jitter calculation");
                result.DetailedInfo = sb.ToString().Trim();
                return result;
            }

            var mean = rtts.Average();
            var min = rtts.Min();
            var max = rtts.Max();
            var stdDev = Math.Sqrt(rtts.Select(x => Math.Pow(x - mean, 2)).Average());

            var diffs = new List<double>();
            for (int i = 1; i < rtts.Count; i++)
                diffs.Add(Math.Abs(rtts[i] - rtts[i - 1]));
            var jitter = diffs.Average();

            sb.AppendLine($"Successful samples: {rtts.Count}/20");
            sb.AppendLine();
            sb.AppendLine("Latency Statistics:");
            sb.AppendLine($"  Mean RTT: {mean:F1}ms | Min: {min:F1}ms | Max: {max:F1}ms");
            sb.AppendLine();
            sb.AppendLine("Jitter Analysis:");
            sb.AppendLine($"  Jitter (mean abs diff): {jitter:F1}ms");
            sb.AppendLine($"  Std Deviation:          {stdDev:F1}ms");
            sb.AppendLine($"  RTT Spread (max-min):   {max - min:F1}ms");
            sb.AppendLine();
            sb.AppendLine($"RTT Samples: {string.Join(", ", rtts.Select(r => $"{r:F0}"))} (ms)");

            sb.AppendLine();
            if (jitter < 10)
            {
                result.Status = "Passed";
                result.ResultValue = $"{jitter:F1}ms jitter (excellent)";
                sb.AppendLine("✓ Jitter is excellent (<10ms). Ideal for remote desktop and Teams.");
            }
            else if (jitter < 30)
            {
                result.Status = "Passed";
                result.ResultValue = $"{jitter:F1}ms jitter (good)";
                sb.AppendLine("✓ Jitter is acceptable (<30ms). Good enough for remote desktop.");
            }
            else if (jitter < 60)
            {
                result.Status = "Warning";
                result.ResultValue = $"{jitter:F1}ms jitter (elevated)";
                sb.AppendLine("⚠ Jitter is elevated (30-60ms). May cause occasional stutter.");
                result.RemediationText = "Network jitter is elevated. Common causes: Wi-Fi interference, VPN overhead, or proxy-based TLS inspection.";
            }
            else
            {
                result.Status = "Failed";
                result.ResultValue = $"{jitter:F1}ms jitter (poor)";
                sb.AppendLine("✗ Jitter is very high (>60ms). This will significantly impact user experience.");
                result.RemediationText = "Network jitter is very high. Try: wired ethernet, disable VPN for RDP, check for bandwidth contention.";
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 21: Frame Drops & Packet Loss ──
    static async Task<TestResult> RunPacketLoss()
    {
        var result = new TestResult { Id = "21", Name = "Frame Drops & Packet Loss", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();

            if (IsRemoteSession())
            {
                sb.AppendLine("Source: RemoteFX Graphics performance counters (inside remote session)");
                sb.AppendLine();

                float? outFps = null, skipNet = null, skipClient = null, skipServer = null, inFps = null;
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        if (PerformanceCounterCategory.Exists("RemoteFX Graphics"))
                        {
                            var cat = new PerformanceCounterCategory("RemoteFX Graphics");
                            var instances = cat.GetInstanceNames();
                            if (instances.Length > 0)
                            {
                                var inst = instances[0];
                                inFps = TryReadPerfCounter("RemoteFX Graphics", "Input Frames/Second", inst) ?? inFps;
                                outFps = TryReadPerfCounter("RemoteFX Graphics", "Output Frames/Second", inst) ?? outFps;
                                skipNet = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Network Resources", inst) ?? skipNet;
                                skipClient = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Client Resources", inst) ?? skipClient;
                                skipServer = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Server Resources", inst) ?? skipServer;
                            }
                        }
                    }
                    catch { }
                    if (i < 2) await Task.Delay(700);
                }

                if (outFps == null)
                {
                    sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
                    result.Status = "Warning";
                    result.ResultValue = "Counters unavailable";
                }
                else
                {
                    float totalDrop = (skipNet ?? 0) + (skipClient ?? 0) + (skipServer ?? 0);
                    float fps = outFps ?? 0;
                    float dropPct = (fps + totalDrop) > 0 ? totalDrop / (fps + totalDrop) * 100 : 0;

                    sb.AppendLine($"Input Frames/sec:  {inFps:F1}");
                    sb.AppendLine($"Output Frames/sec: {fps:F1}");
                    sb.AppendLine($"Skipped (Network): {skipNet:F1}/sec");
                    sb.AppendLine($"Skipped (Client):  {skipClient:F1}/sec");
                    sb.AppendLine($"Skipped (Server):  {skipServer:F1}/sec");
                    sb.AppendLine($"Drop rate: {dropPct:F1}%");

                    if (dropPct < 10) { result.Status = "Passed"; result.ResultValue = $"{dropPct:F0}% frame drops (good)"; }
                    else if (dropPct < 20) { result.Status = "Warning"; result.ResultValue = $"{dropPct:F0}% frame drops (okay)"; }
                    else { result.Status = "Failed"; result.ResultValue = $"{dropPct:F0}% frame drops (poor)"; }
                }
            }
            else
            {
                // TCP probe reliability from physical device
                sb.AppendLine("Source: TCP connect probe reliability (from physical device)");
                sb.AppendLine("For per-frame drop analysis, run this tool inside the Cloud PC.");
                sb.AppendLine();

                var gw = await GetValidatedGateway();
                if (gw == null)
                {
                    sb.AppendLine("✗ No RD Gateway endpoint found within W365 IP ranges.");
                    result.Status = "Skipped";
                    result.ResultValue = "No W365 gateway endpoint available";
                }
                else
                {
                    var (hostname, port, ip) = gw.Value;
                    sb.AppendLine($"Endpoint: {hostname}:{port}");
                    sb.AppendLine($"Resolved IP: {ip} (✓ within W365 range)");
                    sb.AppendLine("Probes: 15 TCP connection attempts");
                    sb.AppendLine();

                    int success = 0, failure = 0;
                    for (int i = 0; i < 15; i++)
                    {
                        try
                        {
                            using var tcp = new TcpClient();
                            using var cts = new CancellationTokenSource(3000);
                            await tcp.ConnectAsync(hostname, port, cts.Token);
                            success++;
                        }
                        catch { failure++; }
                        if (i < 14) await Task.Delay(200);
                    }

                    var lossRate = failure > 0 ? (double)failure / (success + failure) * 100 : 0;
                    sb.AppendLine($"Successful: {success}/15");
                    sb.AppendLine($"Failed:     {failure}/15");
                    sb.AppendLine($"Loss rate:  {lossRate:F0}%");

                    if (failure == 0) { result.Status = "Passed"; result.ResultValue = "0% loss (15/15 successful)"; }
                    else if (lossRate < 5) { result.Status = "Passed"; result.ResultValue = $"{lossRate:F0}% loss"; }
                    else if (lossRate < 15) { result.Status = "Warning"; result.ResultValue = $"{lossRate:F0}% loss"; result.RemediationText = "Some connection attempts failed. Check network stability."; }
                    else { result.Status = "Failed"; result.ResultValue = $"{lossRate:F0}% loss (significant)"; result.RemediationText = "High connection failure rate detected."; }
                }
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 22: Cloud PC Teams Optimization ──
    static Task<TestResult> RunCloudTeamsOptimization()
    {
        var result = new TestResult { Id = "22", Name = "Cloud PC Teams Optimization", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            bool isRemote = IsRemoteSession();
            bool teamsOptFound = false;

            sb.AppendLine($"Running inside remote session: {(isRemote ? "Yes" : "No")}");
            sb.AppendLine();

            // Check IsWVDEnvironment registry
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Teams");
                if (key != null)
                {
                    var isWvd = key.GetValue("IsWVDEnvironment");
                    if (isWvd != null)
                    {
                        sb.AppendLine($"IsWVDEnvironment: {isWvd}");
                        teamsOptFound = true;
                    }
                }
            }
            catch { }

            // Check Teams Media Optimization
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Teams\MediaOptimization");
                if (key != null) { sb.AppendLine("Teams Media Optimization registry key found"); teamsOptFound = true; }
            }
            catch { }

            // Check WebRTC Redirector Service
            var webrtcSvc = Process.GetProcessesByName("MsRdcWebRTCSvc");
            if (webrtcSvc.Length > 0)
            {
                sb.AppendLine($"WebRTC Redirector Service running (PID: {webrtcSvc[0].Id})");
                teamsOptFound = true;
            }
            else
            {
                sb.AppendLine("WebRTC Redirector Service (MsRdcWebRTCSvc) not running");
            }

            // Check for Teams/Slimcore
            var teamsProcs = Process.GetProcessesByName("ms-teams");
            if (teamsProcs.Length > 0)
                sb.AppendLine($"Teams (new) running (PID: {teamsProcs[0].Id})");
            var teamsOld = Process.GetProcessesByName("Teams");
            if (teamsOld.Length > 0)
                sb.AppendLine($"Teams (classic) running (PID: {teamsOld[0].Id})");

            // Check for RDP clients (to see if AV redirect is possible)
            foreach (var name in new[] { "msrdc", "mstsc" })
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                    sb.AppendLine($"{name} running (PID: {procs[0].Id})");
            }

            if (isRemote && teamsOptFound)
            {
                result.Status = "Passed";
                result.ResultValue = "Teams AV optimization active";
            }
            else if (teamsOptFound)
            {
                result.Status = "Passed";
                result.ResultValue = "Teams optimization components detected";
            }
            else if (isRemote)
            {
                result.Status = "Warning";
                result.ResultValue = "No Teams optimization found";
                result.RemediationText = "Running inside a remote session but Teams media optimization is not configured. Install the WebRTC Redirector Service.";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = "Not in remote session — teams optimization checked locally";
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ── Test 24: VPN Connection Performance ──
    static async Task<TestResult> RunCloudVpnPerformance()
    {
        var result = new TestResult { Id = "24", Name = "VPN Connection Performance", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();

            // Detect VPN adapters
            var vpnAdapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                    (n.NetworkInterfaceType == NetworkInterfaceType.Ppp ||
                     n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Cisco", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Juniper", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("GlobalProtect", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Zscaler", StringComparison.OrdinalIgnoreCase) ||
                     n.Description.Contains("Netskope", StringComparison.OrdinalIgnoreCase) ||
                     n.Name.Contains("VPN", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (vpnAdapters.Count == 0)
            {
                sb.AppendLine("No VPN adapters detected.");
                sb.AppendLine();
                sb.AppendLine("✓ Direct network connection — no VPN overhead on RDP traffic.");
                result.Status = "Passed";
                result.ResultValue = "No VPN — direct connection";
                result.DetailedInfo = sb.ToString().Trim();
                return result;
            }

            sb.AppendLine($"VPN adapter(s) detected ({vpnAdapters.Count}):");
            foreach (var vpn in vpnAdapters)
            {
                var vpnIps = vpn.GetIPProperties().UnicastAddresses
                    .Select(a => a.Address.ToString()).ToList();
                sb.AppendLine($"  {vpn.Name} ({vpn.Description}) — IPs: {string.Join(", ", vpnIps)}");
            }
            sb.AppendLine();

            // Check if W365 traffic routes via VPN
            var vpnIfIps = new HashSet<string>();
            foreach (var vpn in vpnAdapters)
                foreach (var addr in vpn.GetIPProperties().UnicastAddresses)
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        vpnIfIps.Add(addr.Address.ToString());

            var vpnRanges = ProbeAvdServiceRanges(vpnAdapters, sb);

            if (vpnRanges.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine($"⚠ W365/AVD traffic routes via VPN for: {string.Join(", ", vpnRanges)}");
                sb.AppendLine("  This adds latency and may affect UDP transport (RDP Shortpath).");
                sb.AppendLine();
                sb.AppendLine("Recommended: Configure split-tunnel VPN to exclude these ranges:");
                sb.AppendLine("  40.64.144.0/20 (W365 Gateway)");
                sb.AppendLine("  51.5.0.0/16   (W365 Gateway)");
                sb.AppendLine("  world.relay.avd.microsoft.com:3478/UDP (TURN relay)");

                // Measure latency via VPN to quantify impact
                var gw = await GetValidatedGateway();
                if (gw != null)
                {
                    var (hostname, port, _) = gw.Value;
                    var rtts = new List<double>();
                    for (int i = 0; i < 5; i++)
                    {
                        try
                        {
                            var sw = Stopwatch.StartNew();
                            using var tcp = new TcpClient();
                            using var cts = new CancellationTokenSource(5000);
                            await tcp.ConnectAsync(hostname, port, cts.Token);
                            sw.Stop();
                            rtts.Add(sw.Elapsed.TotalMilliseconds);
                        }
                        catch { }
                        if (i < 4) await Task.Delay(200);
                    }
                    if (rtts.Count > 0)
                    {
                        sb.AppendLine();
                        sb.AppendLine($"Gateway latency via VPN: {rtts.Average():F0}ms avg ({string.Join(", ", rtts.Select(r => $"{r:F0}ms"))})");
                    }
                }

                result.Status = "Warning";
                result.ResultValue = $"VPN active — {vpnRanges.Count} range(s) routed via VPN";
                result.RemediationText = "W365 Gateway traffic is routed through VPN. Consider split-tunnel VPN to exclude AVD/W365 ranges for better performance.";
            }
            else
            {
                sb.AppendLine();
                sb.AppendLine("✓ VPN detected but W365/AVD ranges appear to be split-tunneled (direct routing).");
                result.Status = "Passed";
                result.ResultValue = "VPN active — split-tunneled (good)";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static float? TryReadPerfCounter(string category, string counter, string instance)
    {
        try
        {
            using var pc = new PerformanceCounter(category, counter, instance, readOnly: true);
            pc.NextValue();
            Thread.Sleep(100);
            return pc.NextValue();
        }
        catch { return null; }
    }

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
                    // "privatelink-global" is a standard Microsoft DNS zone for ALL connections;
                    // only match "privatelink" that is NOT followed by "-global"
                    cnameHasPrivateLink = nsOutput.Contains("privatelink", StringComparison.OrdinalIgnoreCase) &&
                                         !nsOutput.Contains("privatelink-global", StringComparison.OrdinalIgnoreCase);
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
            var gateways = new[] { "afdfp-rdgateway-r1.wvd.microsoft.com", "rdweb.wvd.microsoft.com", "client.wvd.microsoft.com" };
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

                // Determine route based on resolved IP — "privatelink-global" in CNAME
                // is a standard Microsoft DNS zone, NOT actual Private Link.
                // True Private Link resolves to a private RFC-1918 IP.
                if (IsPrivateIp(ip))
                {
                    sb.AppendLine($"    Route: Private Link");
                }
                else
                {
                    sb.AppendLine($"    Route: Azure Front Door");

                    // For AFD endpoints, the resolved IP is anycast so GeoIP shows the
                    // registration address (Redmond) rather than the actual edge node.
                    // The X-MSEdge-Ref response header contains the real PoP code.
                    try
                    {
                        var edgeResponse = await http.GetAsync($"https://{host}/");
                        if (edgeResponse.Headers.TryGetValues("X-MSEdge-Ref", out var edgeRefs))
                        {
                            var edgeRef = edgeRefs.FirstOrDefault() ?? "";
                            var popMatch = System.Text.RegularExpressions.Regex.Match(edgeRef, @"Ref B:\s*([A-Z]{2,5})\d*EDGE");
                            if (popMatch.Success)
                            {
                                var popCode = popMatch.Groups[1].Value;
                                var popCity = GetAfdPopLocation(popCode);
                                sb.AppendLine($"    AFD PoP: {popCode} — {popCity ?? "Unknown"}");
                                // Replace the GeoIP location in gatewayLocations with the PoP city
                                if (popCity != null && gatewayLocations.Count > 0)
                                {
                                    gatewayLocations[gatewayLocations.Count - 1] = popCity;
                                }
                            }
                        }
                    }
                    catch { /* X-MSEdge-Ref is best-effort */ }
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

    /// <summary>
    /// Maps Azure Front Door PoP codes to city names.
    /// Based on https://learn.microsoft.com/azure/frontdoor/edge-locations-by-abbreviation
    /// </summary>
    static string? GetAfdPopLocation(string popCode)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Europe
            ["LON"] = "London, UK", ["LHR"] = "London, UK", ["LTS"] = "London, UK",
            ["MAN"] = "Manchester, UK", ["EDG"] = "Edinburgh, UK",
            ["DUB"] = "Dublin, Ireland", ["AMS"] = "Amsterdam, NL",
            ["FRA"] = "Frankfurt, DE", ["BER"] = "Berlin, DE", ["MUC"] = "Munich, DE",
            ["PAR"] = "Paris, FR", ["MRS"] = "Marseille, FR",
            ["MAD"] = "Madrid, ES", ["BCN"] = "Barcelona, ES",
            ["MIL"] = "Milan, IT", ["ROM"] = "Rome, IT",
            ["ZRH"] = "Zurich, CH", ["GVA"] = "Geneva, CH",
            ["VIE"] = "Vienna, AT", ["CPH"] = "Copenhagen, DK",
            ["HEL"] = "Helsinki, FI", ["OSL"] = "Oslo, NO",
            ["STO"] = "Stockholm, SE", ["WAW"] = "Warsaw, PL",
            ["PRG"] = "Prague, CZ", ["BUD"] = "Budapest, HU",
            ["BUH"] = "Bucharest, RO", ["SOF"] = "Sofia, BG",
            ["ATH"] = "Athens, GR", ["LIS"] = "Lisbon, PT", ["BRU"] = "Brussels, BE",
            // North America
            ["IAD"] = "Ashburn, VA, US", ["DCA"] = "Washington DC, US",
            ["JFK"] = "New York, US", ["EWR"] = "Newark, NJ, US",
            ["BOS"] = "Boston, US", ["PHL"] = "Philadelphia, US",
            ["ATL"] = "Atlanta, US", ["MIA"] = "Miami, US",
            ["ORD"] = "Chicago, US", ["DFW"] = "Dallas, US",
            ["IAH"] = "Houston, US", ["PHX"] = "Phoenix, US",
            ["LAX"] = "Los Angeles, US", ["SJC"] = "San Jose, US",
            ["SEA"] = "Seattle, US", ["DEN"] = "Denver, US",
            ["MSP"] = "Minneapolis, US", ["SLC"] = "Salt Lake City, US",
            ["YYZ"] = "Toronto, CA", ["YUL"] = "Montreal, CA",
            ["YVR"] = "Vancouver, CA", ["QRO"] = "Queretaro, MX",
            // Asia Pacific
            ["SIN"] = "Singapore", ["HKG"] = "Hong Kong",
            ["NRT"] = "Tokyo, JP", ["KIX"] = "Osaka, JP",
            ["ICN"] = "Seoul, KR", ["TPE"] = "Taipei, TW",
            ["BOM"] = "Mumbai, IN", ["MAA"] = "Chennai, IN",
            ["DEL"] = "New Delhi, IN", ["HYD"] = "Hyderabad, IN",
            ["BNE"] = "Brisbane, AU", ["SYD"] = "Sydney, AU",
            ["MEL"] = "Melbourne, AU", ["PER"] = "Perth, AU",
            ["AKL"] = "Auckland, NZ",
            // Middle East & Africa
            ["JNB"] = "Johannesburg, ZA", ["CPT"] = "Cape Town, ZA",
            ["DXB"] = "Dubai, AE", ["AUH"] = "Abu Dhabi, AE",
            ["FJR"] = "Fujairah, AE", ["DOH"] = "Doha, QA",
            ["BAH"] = "Bahrain", ["TLV"] = "Tel Aviv, IL",
            ["RUH"] = "Riyadh, SA", ["JED"] = "Jeddah, SA",
            // South America
            ["GRU"] = "São Paulo, BR", ["GIG"] = "Rio de Janeiro, BR",
            ["CWB"] = "Curitiba, BR", ["SCL"] = "Santiago, CL",
            ["BOG"] = "Bogota, CO", ["EZE"] = "Buenos Aires, AR",
            ["LIM"] = "Lima, PE"
        };
        return map.TryGetValue(popCode, out var city) ? city : null;
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

    [JsonPropertyName("remediationText")]
    public string RemediationText { get; set; } = string.Empty;

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
