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

        // Determine whether to run Live Connection Diagnostics (cloud tests).
        // These take ~60s each to sample performance data.
        // Can be controlled via --include-cloud / --skip-cloud flags, or interactive prompt.
        bool includeCloud;
        if (args.Any(a => a.Equals("--include-cloud", StringComparison.OrdinalIgnoreCase)))
        {
            includeCloud = true;
        }
        else if (args.Any(a => a.Equals("--skip-cloud", StringComparison.OrdinalIgnoreCase)))
        {
            includeCloud = false;
        }
        else
        {
            Console.WriteLine("  Live Connection Diagnostics (latency, jitter, frame rate, packet loss,");
            Console.WriteLine("  TLS inspection, traffic routing, local egress) sample for ~60 seconds");
            Console.WriteLine("  each and take several minutes to complete.");
            Console.WriteLine();
            Console.Write("  Include Live Connection Diagnostics? [Y/n]: ");
            var key = Console.ReadLine()?.Trim();
            includeCloud = string.IsNullOrEmpty(key) || key.StartsWith("y", StringComparison.OrdinalIgnoreCase);
            Console.WriteLine();
        }

        var results = new List<TestResult>();
        var allTests = GetAllTests();
        var tests = includeCloud ? allTests : allTests.Where(t => t.Category != "cloud").ToList();

        if (!includeCloud)
        {
            Console.WriteLine($"  Skipping {allTests.Count - tests.Count} Live Connection Diagnostics tests.");
            Console.WriteLine("  Run with --include-cloud to include them, or re-run and press Y.");
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine($"  Running all {tests.Count} tests (including Live Connection Diagnostics).");
            Console.WriteLine();
        }

        for (int i = 0; i < tests.Count; i++)
        {
            var test = tests[i];
            Console.Write($"  [{i + 1}/{tests.Count}] {test.Name}... ");
            if (test.Id == "L-TCP-10")
                Console.Write("(traceroute — this may take 1-2 minutes) ");

            try
            {
                var sw = Stopwatch.StartNew();
                var testTask = test.Run();
                // Cloud tests sample for ~60s, so allow 90s for them plus overhead
                // Traceroute (L-TCP-10) can take up to 120s for multiple endpoints
                var testTimeout = test.Category == "cloud" ? 90 : test.Id == "L-TCP-10" ? 120 : 60;
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(testTimeout));

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
                        ResultValue = $"Timed out after {testTimeout}s",
                        DetailedInfo = $"The test did not complete within {testTimeout} seconds. This may indicate a network issue (hanging TLS handshake, unresponsive proxy, etc.).",
                        Duration = (int)sw.ElapsedMilliseconds
                    });
                    Console.WriteLine($"\u26A0 Timed out ({testTimeout}s)");
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
                // Traceroute prints sub-progress on separate lines, so start a new line for the final status
                if (test.Id == "L-TCP-10")
                    Console.Write("\n        ");
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

        // Print executive summary report
        PrintSummaryReport(results, includeCloud);

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

            var cb = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Build query-only URL with compressed data
            var directUrl = $"https://paulcollinge.github.io/W365ConnectivityTool/?_cb={cb}&zresults={compressedBase64}";

            Console.WriteLine($"  Compressed: {json.Length} → {compressed.Length} bytes (base64: {compressedBase64.Length} chars)");
            Console.WriteLine($"  URL length: {directUrl.Length} chars");

            if (directUrl.Length > 32_000) // Conservative URL length limit
            {
                Console.WriteLine($"  Results too large for URL auto-import ({directUrl.Length} chars).");
                Console.WriteLine($"  Drag and drop {Path.GetFullPath(outputPath)} onto the web page.");
                directUrl = $"https://paulcollinge.github.io/W365ConnectivityTool/?_cb={cb}";
            }

            // Also build uncompressed base64 for fallback hash
            var uncompressedBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            // Try multiple methods to open the browser — ShellExecute truncates long URLs
            bool opened = false;

            // Method 1: Find default browser exe via registry, launch directly
            // This bypasses ShellExecute's URL length limits
            if (!opened)
            {
                try
                {
                    var browserPath = GetDefaultBrowserPath();
                    if (!string.IsNullOrEmpty(browserPath) && File.Exists(browserPath))
                    {
                        Console.WriteLine($"  Opening via browser: {Path.GetFileName(browserPath)}");
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = browserPath,
                            Arguments = directUrl,
                            UseShellExecute = false
                        });
                        opened = true;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Browser direct launch failed: {ex.Message}");
                }
            }

            // Method 2: Use a local HTML redirect file with both compressed + uncompressed
            if (!opened)
            {
                try
                {
                    Console.WriteLine($"  Opening via redirect file...");
                    var fullUrl = $"{directUrl}#results={uncompressedBase64}";
                    var redirectHtml = $@"<!DOCTYPE html>
<html><head><title>Opening W365 Diagnostics...</title></head>
<body><p>Redirecting to results page...</p>
<script>window.location.replace({EscapeJsString(fullUrl)});</script>
<p><a href=""{System.Security.SecurityElement.Escape(fullUrl)}"">Click here if not redirected automatically</a></p>
</body></html>";
                    var redirectPath = Path.Combine(Path.GetTempPath(), "W365ScanRedirect.html");
                    await File.WriteAllTextAsync(redirectPath, redirectHtml, Encoding.UTF8);
                    Process.Start(new ProcessStartInfo { FileName = redirectPath, UseShellExecute = true });
                    opened = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Redirect file failed: {ex.Message}");
                }
            }

            // Method 3: ShellExecute with URL directly (last resort, may truncate)
            if (!opened)
            {
                Console.WriteLine($"  Opening via ShellExecute...");
                Process.Start(new ProcessStartInfo { FileName = directUrl, UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Error: {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine($"  Could not open browser. Import the JSON file manually:");
            Console.WriteLine($"    1. Open https://paulcollinge.github.io/W365ConnectivityTool/");
            Console.WriteLine($"    2. Drag and drop {Path.GetFullPath(outputPath)} onto the page");
        }
        Console.WriteLine();

        var failed = results.Count(r => r.Status == "Failed" || r.Status == "Error");
        return failed > 0 ? 1 : 0;
    }

    // ── Summary Report ──────────────────────────────────────────────

    /// <summary>
    /// Prints a structured executive summary after all tests, highlighting
    /// key findings, location pairings, and concerns.
    /// </summary>
    static void PrintSummaryReport(List<TestResult> results, bool includeCloud)
    {
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║                   SCAN SUMMARY                      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.WriteLine();

        // ── Test counts ──
        var passed = results.Count(r => r.Status == "Passed");
        var warned = results.Count(r => r.Status == "Warning");
        var failed = results.Count(r => r.Status == "Failed" || r.Status == "Error");
        Console.WriteLine($"  Tests run: {results.Count}   \u2714 {passed} passed   \u26A0 {warned} warnings   \u2718 {failed} failed");
        Console.WriteLine();

        // ── Key Findings ──
        Console.WriteLine("  ── Key Findings ─────────────────────────────────────");

        // Extract location info from Test 27 (Local Egress) if available
        var egressResult = results.FirstOrDefault(r => r.Id == "27");
        string? userLocation = null, gwLocation = null, turnLocation = null;
        string? gwDistance = null, turnDistance = null;

        if (egressResult != null && !string.IsNullOrEmpty(egressResult.DetailedInfo))
        {
            var lines = egressResult.DetailedInfo.Split('\n');
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("Your egress location:"))
                    userLocation = trimmed.Replace("Your egress location:", "").Trim();
                else if (trimmed.StartsWith("Location:") && gwLocation == null && !trimmed.Contains("TURN"))
                    gwLocation = trimmed.Replace("Location:", "").Trim();
                else if (trimmed.StartsWith("Distance from you:") && gwDistance == null)
                    gwDistance = trimmed.Replace("Distance from you:", "").Trim();
            }

            // Parse TURN section separately
            bool inTurn = false;
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Contains("TURN Relay"))
                    inTurn = true;
                if (inTurn && trimmed.StartsWith("Location:"))
                    turnLocation = trimmed.Replace("Location:", "").Trim();
                if (inTurn && trimmed.StartsWith("Distance from you:"))
                    turnDistance = trimmed.Replace("Distance from you:", "").Trim();
            }
        }

        if (userLocation != null)
            Console.WriteLine($"  User location:     {userLocation}");
        if (gwLocation != null)
            Console.WriteLine($"  RDP Gateway:       {gwLocation} ({gwDistance ?? "distance unknown"})");
        if (turnLocation != null)
            Console.WriteLine($"  TURN Relay:        {turnLocation} ({turnDistance ?? "distance unknown"})");

        if (userLocation == null && includeCloud)
            Console.WriteLine("  Location:          Could not determine (geo-IP unavailable)");
        if (!includeCloud && userLocation == null)
            Console.WriteLine("  Location:          Skipped (Live Connection Diagnostics not run)");

        // Location pairing assessment — continent-aware, avoids false alarms
        if (userLocation != null && (gwLocation != null || turnLocation != null))
        {
            Console.WriteLine();
            var userCountry = ExtractCountryCode(userLocation);
            var gwCountry = gwLocation != null ? ExtractCountryCode(gwLocation) : null;
            var turnCountry = turnLocation != null ? ExtractCountryCode(turnLocation) : null;

            bool gwConcern = gwCountry != null && !IsReasonablePairing(userCountry, gwCountry);
            bool turnConcern = turnCountry != null && !IsReasonablePairing(userCountry, turnCountry);

            if (gwConcern || turnConcern)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  \u26A0 Location pairing may not be optimal:");
                if (gwConcern)
                    Console.WriteLine($"    Gateway in {gwLocation} — consider checking VPN/proxy routing");
                if (turnConcern)
                    Console.WriteLine($"    TURN relay in {turnLocation} — may indicate non-local egress");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("  \u2714 Location pairing looks reasonable for your region");
            }
        }

        // Transport protocol
        var transportResult = results.FirstOrDefault(r => r.Id == "17b");
        if (transportResult != null && !string.IsNullOrEmpty(transportResult.ResultValue))
            Console.WriteLine($"  Transport:         {transportResult.ResultValue}");

        // Session latency
        var latencyResult = results.FirstOrDefault(r => r.Id == "18");
        if (latencyResult != null && !string.IsNullOrEmpty(latencyResult.ResultValue) && latencyResult.Status != "NotRun")
            Console.WriteLine($"  Session latency:   {latencyResult.ResultValue}");

        // Bandwidth
        var bwResult = results.FirstOrDefault(r => r.Id == "L-LE-08");
        if (bwResult != null && !string.IsNullOrEmpty(bwResult.ResultValue))
            Console.WriteLine($"  Bandwidth:         {bwResult.ResultValue}");

        // WiFi signal
        var wifiResult = results.FirstOrDefault(r => r.Id == "L-LE-04");
        if (wifiResult != null && wifiResult.Status == "Warning" && !string.IsNullOrEmpty(wifiResult.ResultValue))
            Console.WriteLine($"  WiFi:              {wifiResult.ResultValue}");

        Console.WriteLine();

        // ── Highlights & Concerns ──
        var concerns = results.Where(r => r.Status == "Failed" || r.Status == "Error").ToList();
        var warnings = results.Where(r => r.Status == "Warning").ToList();

        if (concerns.Count > 0 || warnings.Count > 0)
        {
            Console.WriteLine("  ── Highlights & Concerns ────────────────────────────");

            if (concerns.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  \u2718 Failed ({concerns.Count}):");
                foreach (var c in concerns)
                    Console.WriteLine($"    - {c.Name}: {Truncate(c.ResultValue, 70)}");
                Console.ResetColor();
            }

            if (warnings.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  \u26A0 Warnings ({warnings.Count}):");
                foreach (var w in warnings)
                    Console.WriteLine($"    - {w.Name}: {Truncate(w.ResultValue, 70)}");
                Console.ResetColor();
            }

            // TLS inspection concern
            var tlsResult = results.FirstOrDefault(r => r.Id == "25");
            if (tlsResult?.Status == "Warning" || tlsResult?.Status == "Failed")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine();
                Console.WriteLine("  \u26A0 TLS inspection detected on RDP gateway — this can degrade");
                Console.WriteLine("    performance and cause connection instability.");
                Console.ResetColor();
            }

            // VPN routing concern
            var vpnResult = results.FirstOrDefault(r => r.Id == "26");
            if (vpnResult?.Status == "Warning" || vpnResult?.Status == "Failed")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine();
                Console.WriteLine("  \u26A0 W365 traffic may be routing through VPN/SWG.");
                Console.WriteLine("    Microsoft recommends bypassing proxy/VPN for 40.64.144.0/20 & 51.5.0.0/16.");
                Console.ResetColor();
            }

            Console.WriteLine();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  \u2714 No concerns — all tests passed.");
            Console.ResetColor();
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Extracts the last comma-separated token as a country code from a location string
    /// like "London, England, GB" → "GB".
    /// </summary>
    static string ExtractCountryCode(string location)
    {
        var parts = location.Split(',');
        return parts[^1].Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Determines if a user↔service country pairing is reasonable.
    /// Uses broad groupings to avoid false alarms — e.g. UK user hitting
    /// Netherlands or Ireland gateways is normal.
    /// </summary>
    static bool IsReasonablePairing(string userCountry, string serviceCountry)
    {
        if (userCountry == serviceCountry) return true;

        // Define broad geographic regions where cross-country routing is expected
        var regions = new List<HashSet<string>>
        {
            // Western Europe — Azure regions in NL, IE, UK, FR, DE, CH, AT etc.
            new(StringComparer.OrdinalIgnoreCase) { "GB", "UK", "IE", "NL", "DE", "FR", "BE", "LU", "CH", "AT", "DK", "NO", "SE", "FI", "IS", "PT", "ES", "IT" },
            // Eastern Europe
            new(StringComparer.OrdinalIgnoreCase) { "PL", "CZ", "SK", "HU", "RO", "BG", "HR", "SI", "RS", "BA", "ME", "MK", "AL", "EE", "LV", "LT", "UA" },
            // North America
            new(StringComparer.OrdinalIgnoreCase) { "US", "CA", "MX" },
            // Asia Pacific — East
            new(StringComparer.OrdinalIgnoreCase) { "JP", "KR", "TW", "HK", "SG", "MY", "TH", "PH", "ID", "VN" },
            // Asia Pacific — South
            new(StringComparer.OrdinalIgnoreCase) { "IN", "LK", "BD", "PK" },
            // Middle East
            new(StringComparer.OrdinalIgnoreCase) { "AE", "SA", "QA", "BH", "KW", "OM", "IL", "JO" },
            // Oceania
            new(StringComparer.OrdinalIgnoreCase) { "AU", "NZ" },
            // South America
            new(StringComparer.OrdinalIgnoreCase) { "BR", "AR", "CL", "CO", "PE", "UY", "PY", "EC", "VE" },
            // Africa
            new(StringComparer.OrdinalIgnoreCase) { "ZA", "NG", "KE", "EG", "MA", "TN", "GH" }
        };

        foreach (var region in regions)
        {
            if (region.Contains(userCountry) && region.Contains(serviceCountry))
                return true;
        }

        return false;
    }

    static string Truncate(string s, int maxLength)
    {
        if (string.IsNullOrEmpty(s)) return "(no details)";
        return s.Length <= maxLength ? s : s[..(maxLength - 3)] + "...";
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
            new("L-TCP-04", "Gateway & Service Connectivity", "Tests AFD gateway discovery, RDP gateway reachability, RDWeb feed, and authentication endpoints", "tcp", RunGatewayConnectivity),
            new("L-TCP-05", "DNS CNAME Chain Analysis", "Traces DNS CNAME chain for gateway", "tcp", RunDnsCnameChain),
            new("L-TCP-08", "DNS Hijacking Check", "Verifies gateway DNS resolves to legitimate Microsoft IPs", "tcp", RunDnsHijackingCheck),
            new("L-TCP-09", "Gateway Used", "Shows which gateway edge node and IP are being used", "tcp", RunGatewayUsed),
            new("L-TCP-06", "TLS Inspection Detection", "Validates TLS certificate chain", "tcp", RunTlsInspection),
            new("L-TCP-07", "Proxy / VPN / SWG Detection", "Detects proxy, VPN, SWG", "tcp", RunProxyVpnDetection),
            new("L-TCP-10", "Network Path Trace", "ICMP traceroute to key W365/AVD endpoints", "tcp", RunNetworkPathTrace),

            // ── UDP Based RDP Connectivity ──
            new("L-UDP-03", "TURN Relay Reachability (UDP 3478)", "Tests UDP to TURN relay", "udp", RunTurnRelay),
            new("L-UDP-04", "TURN Relay Location", "Geolocates the TURN relay server", "udp", RunTurnRelayLocation),
            new("L-UDP-05", "STUN NAT Type Detection", "Two-server STUN test for NAT type and Shortpath readiness", "udp", RunStunNatType),
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
            new("25", "RDP TLS Inspection", "Checks for TLS interception on RDP gateway", "cloud", RunCloudTlsInspection),
            new("26", "RDP Traffic Routing", "Validates VPN/SWG bypass for RDP endpoints", "cloud", RunCloudTrafficRouting),
            new("27", "RDP Local Egress", "Checks traffic egresses locally to nearest gateway", "cloud", RunCloudLocalEgress),
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
        var result = new TestResult { Id = "L-TCP-04", Name = "Gateway & Service Connectivity", Category = "tcp" };
        try
        {
            // afdfp-rdgateway-r1.wvd.microsoft.com is Azure Front Door — NOT the RDP gateway.
            // AFD discovers the nearest regional RDP gateway (e.g. rdgateway-c221-UKS-r1.wvd.microsoft.com).
            // The actual gateway hostname is revealed in AFD's Set-Cookie Domain= header.
            var serviceEndpoints = new (string host, int port, string role)[] {
                ("rdweb.wvd.microsoft.com", 443, "RDWeb Feed Discovery"),
                ("login.microsoftonline.com", 443, "Authentication")
            };

            var sb = new StringBuilder();
            int passed = 0;
            bool afdOk = false;
            bool gatewayOk = false;
            string discoveredGateway = "";
            string serviceRegion = "";
            string afdPop = "";
            var issues = new List<string>();

            var cookieContainer = new System.Net.CookieContainer();
            using var httpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false,
                CookieContainer = cookieContainer,
                UseCookies = true
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            // ── Step 1: Query AFD to discover the actual RDP gateway ──
            var afdHost = "afdfp-rdgateway-r1.wvd.microsoft.com";
            sb.AppendLine($"  {afdHost}:443  [Gateway Discovery (AFD)]");
            try
            {
                var afdIps = await Dns.GetHostAddressesAsync(afdHost);
                sb.AppendLine($"    ✓ DNS → {string.Join(", ", afdIps.Select(a => a.ToString()))}");
                sb.AppendLine($"    → AFD edge IP (routes to nearest regional gateway)");

                var sw = Stopwatch.StartNew();
                var afdResp = await http.GetAsync($"https://{afdHost}/");
                sw.Stop();
                sb.AppendLine($"    ✓ HTTPS {(int)afdResp.StatusCode} in {sw.ElapsedMilliseconds}ms");
                afdOk = true;
                passed++;

                // Extract the actual gateway from Set-Cookie Domain= header
                if (afdResp.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        var domainMatch = System.Text.RegularExpressions.Regex.Match(
                            cookie, @"Domain=(rdgateway[^;]+\.wvd\.microsoft\.com)",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (domainMatch.Success)
                        {
                            discoveredGateway = domainMatch.Groups[1].Value;
                            break;
                        }
                    }
                }

                // Extract service region header
                if (afdResp.Headers.TryGetValues("x-ms-wvd-service-region", out var regionVals))
                    serviceRegion = regionVals.FirstOrDefault() ?? "";

                // Extract AFD PoP from X-MSEdge-Ref
                if (afdResp.Headers.TryGetValues("X-MSEdge-Ref", out var edgeRefs))
                {
                    var edgeRef = edgeRefs.FirstOrDefault() ?? "";
                    sb.AppendLine($"    → X-MSEdge-Ref: {edgeRef}");
                    // Parse PoP: "Ref B: LON04EDGE0816" → LON04EDGE0816
                    var popMatch = System.Text.RegularExpressions.Regex.Match(edgeRef, @"Ref B:\s*(\S+)");
                    if (popMatch.Success) afdPop = popMatch.Groups[1].Value;
                }

                if (!string.IsNullOrEmpty(discoveredGateway))
                {
                    sb.AppendLine($"    → Discovered gateway: {discoveredGateway}");
                    if (!string.IsNullOrEmpty(serviceRegion))
                        sb.AppendLine($"    → Service region: {serviceRegion}");
                    if (!string.IsNullOrEmpty(afdPop))
                        sb.AppendLine($"    → AFD PoP: {afdPop}");
                }
                else
                {
                    sb.AppendLine($"    → Could not extract gateway from AFD response");
                }
            }
            catch (Exception ex)
            {
                var msg = ex.InnerException?.Message ?? ex.Message;
                sb.AppendLine($"    ✗ Failed: {msg}");
                issues.Add($"{afdHost} (AFD): {msg}");
            }
            sb.AppendLine();

            // ── Step 2: Test the actual discovered gateway directly ──
            if (!string.IsNullOrEmpty(discoveredGateway))
            {
                sb.AppendLine($"  {discoveredGateway}:443  [RDP Gateway]");
                try
                {
                    var gwIps = await Dns.GetHostAddressesAsync(discoveredGateway);
                    sb.AppendLine($"    ✓ DNS → {string.Join(", ", gwIps.Select(a => a.ToString()))}");

                    bool inRange = gwIps.Any(ip => IsInW365Range(ip));
                    sb.AppendLine(inRange
                        ? $"    → IP in W365 range (40.64.144.0/20 or 51.5.0.0/16) ✓"
                        : $"    → IP NOT in expected W365 ranges");

                    using var tcp = new TcpClient();
                    var sw = Stopwatch.StartNew();
                    using var cts = new CancellationTokenSource(5000);
                    await tcp.ConnectAsync(discoveredGateway, 443, cts.Token);
                    sw.Stop();
                    sb.AppendLine($"    ✓ TCP connected in {sw.ElapsedMilliseconds}ms");

                    var sw2 = Stopwatch.StartNew();
                    var gwResp = await http.GetAsync($"https://{discoveredGateway}/");
                    sw2.Stop();
                    sb.AppendLine($"    ✓ HTTPS {(int)gwResp.StatusCode} in {sw2.ElapsedMilliseconds}ms");
                    gatewayOk = true;
                    passed++;
                }
                catch (OperationCanceledException)
                {
                    sb.AppendLine($"    ✗ TCP timed out (5s)");
                    issues.Add($"{discoveredGateway} (RDP Gateway): TCP blocked or timed out");
                }
                catch (Exception ex)
                {
                    var msg = ex.InnerException?.Message ?? ex.Message;
                    sb.AppendLine($"    ✗ Failed: {msg}");
                    issues.Add($"{discoveredGateway} (RDP Gateway): {msg}");
                }
                sb.AppendLine();
            }

            // ── Step 3: Test service endpoints ──
            foreach (var (host, port, role) in serviceEndpoints)
            {
                sb.AppendLine($"  {host}:{port}  [{role}]");
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(host);
                    sb.AppendLine($"    ✓ DNS → {string.Join(", ", addresses.Select(a => a.ToString()))}");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ DNS failed: {ex.Message}");
                    issues.Add($"{host} ({role}): DNS resolution failed");
                    sb.AppendLine();
                    continue;
                }

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
                    sb.AppendLine($"    ✗ TCP timed out (5s)");
                    issues.Add($"{host} ({role}): TCP port {port} blocked");
                    sb.AppendLine();
                    continue;
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ TCP failed: {ex.InnerException?.Message ?? ex.Message}");
                    issues.Add($"{host} ({role}): TCP port {port} refused");
                    sb.AppendLine();
                    continue;
                }

                try
                {
                    var sw2 = Stopwatch.StartNew();
                    var response = await http.GetAsync($"https://{host}/");
                    sw2.Stop();
                    sb.AppendLine($"    ✓ HTTPS {(int)response.StatusCode} in {sw2.ElapsedMilliseconds}ms");
                    passed++;
                }
                catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
                {
                    sb.AppendLine($"    ✗ TLS handshake failed: {ex.InnerException.Message}");
                    issues.Add($"{host} ({role}): TLS handshake failed — possible TLS inspection");
                    sb.AppendLine();
                    continue;
                }
                catch (TaskCanceledException)
                {
                    sb.AppendLine($"    ✗ HTTPS timed out (10s)");
                    issues.Add($"{host} ({role}): HTTPS timed out — possible proxy blocking");
                    sb.AppendLine();
                    continue;
                }
                catch (Exception ex)
                {
                    var inner = ex.InnerException?.Message ?? ex.Message;
                    sb.AppendLine($"    ✗ HTTPS failed: {inner}");
                    issues.Add($"{host} ({role}): {inner}");
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

            // Total endpoints: AFD + discovered gateway (if found) + 3 service endpoints
            int totalExpected = serviceEndpoints.Length + 1 + (string.IsNullOrEmpty(discoveredGateway) ? 0 : 1);
            var gwNote = !string.IsNullOrEmpty(discoveredGateway)
                ? $" → {discoveredGateway}"
                : "";
            var regionNote = !string.IsNullOrEmpty(serviceRegion) ? $" ({serviceRegion})" : "";

            if (gatewayOk && passed == totalExpected)
                result.ResultValue = $"Gateway {discoveredGateway}{regionNote} + {serviceEndpoints.Length} service endpoints OK";
            else if (afdOk && !string.IsNullOrEmpty(discoveredGateway) && !gatewayOk)
                result.ResultValue = $"AFD OK but gateway {discoveredGateway} UNREACHABLE{regionNote}";
            else if (afdOk && string.IsNullOrEmpty(discoveredGateway))
                result.ResultValue = $"AFD reachable but could not discover gateway — {passed}/{totalExpected} OK";
            else if (afdOk)
                result.ResultValue = $"Gateway discovered{gwNote}{regionNote} — {passed}/{totalExpected} endpoints OK";
            else
                result.ResultValue = $"AFD UNREACHABLE — cannot discover gateway — {passed}/{totalExpected} OK";

            result.DetailedInfo = sb.ToString().Trim();
            result.Status = gatewayOk && passed == totalExpected ? "Passed"
                          : afdOk && gatewayOk ? "Warning"
                          : afdOk ? "Warning"
                          : "Failed";
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
            var sb = new StringBuilder();
            var issues = new List<string>();

            // ── Part 1: AFD endpoint (gateway discovery service) ──
            var afdHost = "afdfp-rdgateway-r1.wvd.microsoft.com";
            sb.AppendLine($"═══ AFD Gateway Discovery Endpoint ═══");
            sb.AppendLine($"Target: {afdHost}");
            try
            {
                var psi = new ProcessStartInfo("nslookup", $"-type=CNAME {afdHost}")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                var output = await proc!.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var ips = await Dns.GetHostAddressesAsync(afdHost);
                var ipStr = string.Join(", ", ips.Select(i => i.ToString()));
                sb.AppendLine($"Resolved IPs: {ipStr}");
                sb.AppendLine($"CNAME chain:");
                sb.AppendLine(output.Trim());

                bool isPrivateLink = ips.Any(ip => IsPrivateIp(ip));
                sb.AppendLine(isPrivateLink
                    ? "\n→ Private Link detected (private IP)"
                    : "\n→ Azure Front Door routing (anycast) — normal");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  ✗ Failed: {ex.Message}");
                issues.Add($"AFD CNAME chain failed: {ex.Message}");
            }

            sb.AppendLine();

            // ── Part 2: Actual RDP Gateway (discovered from AFD) ──
            sb.AppendLine($"═══ Actual RDP Gateway ═══");
            var gwHost = await DiscoverRdpGatewayFromAfd();
            if (!string.IsNullOrEmpty(gwHost))
            {
                sb.AppendLine($"Target: {gwHost}");
                try
                {
                    var gwPsi = new ProcessStartInfo("nslookup", $"-type=CNAME {gwHost}")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var gwProc = Process.Start(gwPsi);
                    var gwOutput = await gwProc!.StandardOutput.ReadToEndAsync();
                    await gwProc.WaitForExitAsync();

                    var gwIps = await Dns.GetHostAddressesAsync(gwHost);
                    var gwIpStr = string.Join(", ", gwIps.Select(i => i.ToString()));
                    sb.AppendLine($"Resolved IPs: {gwIpStr}");
                    sb.AppendLine($"CNAME chain:");
                    sb.AppendLine(gwOutput.Trim());

                    // Extract region from FQDN
                    var regionCode = ExtractRegionFromGatewayFqdn(gwHost);
                    var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                    if (regionName != null)
                        sb.AppendLine($"\n→ Gateway region: {regionName} ({regionCode})");
                    else if (regionCode != null)
                        sb.AppendLine($"\n→ Gateway region code: {regionCode}");

                    bool gwIsPrivate = gwIps.Any(ip => IsPrivateIp(ip));
                    sb.AppendLine(gwIsPrivate
                        ? "→ Routes via private network"
                        : "→ Routes via public internet (unicast)");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"  ✗ Failed: {ex.Message}");
                    issues.Add($"Gateway CNAME chain failed: {ex.Message}");
                }
            }
            else
            {
                sb.AppendLine("  Could not discover RDP gateway from AFD");
                issues.Add("Gateway discovery failed — cannot trace RDP gateway DNS chain");
            }

            if (issues.Count > 0)
            {
                result.ResultValue = $"{issues.Count} issue(s) in DNS chain analysis";
                result.Status = "Warning";
            }
            else
            {
                var gwLabel = !string.IsNullOrEmpty(gwHost) ? $" + gateway {gwHost}" : "";
                result.ResultValue = $"AFD{gwLabel} — DNS chains verified";
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
            var sb = new StringBuilder();
            bool intercepted = false;

            // Discover the actual RDP gateway — this is the critical connection that must NOT be TLS-inspected
            var gwHost = await DiscoverRdpGatewayFromAfd();
            var host = gwHost ?? "rdweb.wvd.microsoft.com"; // fallback if discovery fails
            var port = 443;

            if (gwHost != null)
            {
                var regionCode = ExtractRegionFromGatewayFqdn(gwHost);
                var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                var regionLabel = regionName != null ? $" ({regionName})" : "";
                sb.AppendLine($"Discovered RDP Gateway: {gwHost}{regionLabel}");
            }
            else
            {
                sb.AppendLine($"⚠ Could not discover RDP gateway from AFD — falling back to rdweb.wvd.microsoft.com");
            }
            sb.AppendLine();

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
                        sb.AppendLine("\n⚠ Certificate issuer is NOT a known Microsoft/DigiCert CA.");
                        sb.AppendLine("This suggests TLS inspection by a proxy, firewall, or SWG.");
                        sb.AppendLine("W365 RDP gateway connections MUST NOT be TLS-inspected.");
                    }
                }
                return true; // Accept anyway for inspection
            });

            using var tlsCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, tlsCts.Token);
            sb.Insert(0, $"Host: {host}:{port}\n\n");

            result.ResultValue = intercepted
                ? $"TLS inspection detected on {host} — non-Microsoft certificate issuer"
                : $"No TLS inspection detected on {host}";
            result.Status = intercepted ? "Warning" : "Passed";
            result.DetailedInfo = sb.ToString().Trim();
            if (intercepted)
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#tls-inspection";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>
    /// Identifies known Microsoft/Azure backbone IPs when reverse DNS is unavailable.
    /// </summary>
    static string IdentifyMicrosoftHop(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return "";
        uint addr = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);

        // 104.44.0.0/16 — Microsoft WAN backbone (MSIT)
        if (b[0] == 104 && b[1] == 44) return "[Microsoft backbone]";
        // 104.40.0.0/13 — Azure compute
        if (b[0] == 104 && b[1] >= 40 && b[1] <= 47) return "[Azure]";
        // 40.64.0.0/10 — Azure / Microsoft
        if (b[0] == 40 && (b[1] & 0xC0) == 64) return "[Azure]";
        // 20.33.0.0/16 and similar — Azure networking
        if (b[0] == 20) return "[Azure]";
        // 13.64.0.0/11 — Azure
        if (b[0] == 13 && (b[1] & 0xE0) == 64) return "[Azure]";
        // 52.96.0.0/12 — Microsoft 365
        if (b[0] == 52 && b[1] >= 96 && b[1] <= 111) return "[Microsoft 365]";
        // 51.5.0.0/16 — AVD TURN relay
        if (b[0] == 51 && b[1] == 5) return "[AVD TURN relay range]";
        // 150.171.0.0/16 — Microsoft backbone
        if (b[0] == 150 && b[1] == 171) return "[Microsoft backbone]";
        // 4.0.0.0/8 parts — Microsoft (Level3/Microsoft)
        if (b[0] == 4 && b[1] >= 150) return "[Microsoft]";

        return "";
    }

    /// <summary>
    /// Resolves DNS CNAME chain for a hostname using system DNS, returning the chain and routing flags.
    /// </summary>
    static async Task<(List<string> chain, string? gsaIndicator)> ResolveDnsCnameChainAsync(string host)
    {
        var chain = new List<string>();
        string? gsaIndicator = null;

        try
        {
            // Use nslookup to get CNAME chain (system DNS doesn't expose CNAMEs in .NET)
            var psi = new ProcessStartInfo("nslookup", $"-type=any {host}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var outputTask = proc.StandardOutput.ReadToEndAsync();
                if (await Task.WhenAny(outputTask, Task.Delay(3000)) == outputTask)
                {
                    var output = await outputTask;
                    // Parse "canonical name = xxx" lines
                    foreach (var line in output.Split('\n'))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.Contains("canonical name", StringComparison.OrdinalIgnoreCase))
                        {
                            var parts = trimmed.Split('=');
                            if (parts.Length > 1)
                            {
                                var cname = parts[1].Trim().TrimEnd('.');
                                chain.Add(cname);
                            }
                        }
                    }
                }
                try { proc.Kill(); } catch { }
            }
        }
        catch { /* nslookup not available */ }

        // Check chain for GSA/Entra Private Access / SASE indicators
        var chainStr = string.Join(" ", chain).ToLowerInvariant();
        if (chainStr.Contains("globalsecureaccess") || chainStr.Contains("sse.microsoft") ||
            chainStr.Contains("edge.security.microsoft"))
        {
            gsaIndicator = "Microsoft Global Secure Access (Entra Private Access)";
        }
        else if (chainStr.Contains("zscaler") || chainStr.Contains("netskope") ||
                 chainStr.Contains("cloudflare-gateway") || chainStr.Contains("swg"))
        {
            gsaIndicator = "Third-party Secure Web Gateway";
        }
        else if (chainStr.Contains("proxy") || chainStr.Contains("forward"))
        {
            gsaIndicator = "Proxy/forward routing";
        }

        return (chain, gsaIndicator);
    }

    static async Task<TestResult> RunNetworkPathTrace()
    {
        var result = new TestResult { Id = "L-TCP-10", Name = "Network Path Trace", Category = "tcp" };
        try
        {
            var sb = new StringBuilder();
            var targets = new List<(string host, string role)>
            {
                ("afdfp-rdgateway-r1.wvd.microsoft.com", "RDP Gateway (AFD)"),
                ("rdweb.wvd.microsoft.com", "AVD Web Access"),
                ("login.microsoftonline.com", "Authentication"),
                ("world.relay.avd.microsoft.com", "TURN Relay"),
            };

            // Try to discover the actual regional RDP gateway and add it
            var gwHost = await DiscoverRdpGatewayFromAfd();
            if (!string.IsNullOrEmpty(gwHost))
            {
                targets.Insert(1, (gwHost, "RDP Gateway (Regional)"));
            }

            int completed = 0;
            int maxHops = 20;
            int probeTimeout = 1000;
            int maxConsecutiveTimeouts = 4;

            foreach (var (host, role) in targets)
            {
                Console.Write($"\n        Tracing {role}... ");
                sb.AppendLine($"╔══════════════════════════════════════════════════════════════");
                sb.AppendLine($"║  Traceroute: {role}");
                sb.AppendLine($"║  Target:     {host}");

                // DNS CNAME chain analysis — detect GSA/SASE routing
                var (cnameChain, gsaIndicator) = await ResolveDnsCnameChainAsync(host);
                if (cnameChain.Count > 0)
                {
                    sb.AppendLine($"║  DNS Chain:  {host}");
                    foreach (var cname in cnameChain)
                        sb.AppendLine($"║              → {cname}");
                }
                if (gsaIndicator != null)
                {
                    sb.AppendLine($"║  ⚠ Routed via: {gsaIndicator}");
                    sb.AppendLine($"║    Traffic is NOT going direct — routed through a security proxy");
                }

                IPAddress? targetIp;
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(host);
                    targetIp = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (targetIp == null)
                    {
                        sb.AppendLine($"║  ✗ No IPv4 address resolved");
                        sb.AppendLine($"╚══════════════════════════════════════════════════════════════");
                        sb.AppendLine();
                        Console.Write("✗");
                        continue;
                    }
                    sb.AppendLine($"║  Resolved:   {targetIp}");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"║  ✗ DNS failed: {ex.Message}");
                    sb.AppendLine($"╚══════════════════════════════════════════════════════════════");
                    sb.AppendLine();
                    Console.Write("✗");
                    continue;
                }

                sb.AppendLine($"╠──────────────────────────────────────────────────────────────");
                sb.AppendLine($"║  {"Hop",-4} {"IP Address",-18} {"RTT",-8} Hostname");
                sb.AppendLine($"║  {"───",-4} {"──────────",-18} {"───",-8} ────────");

                bool reached = false;
                var payload = new byte[32];
                int consecutiveTimeouts = 0;

                for (int ttl = 1; ttl <= maxHops; ttl++)
                {
                    var options = new PingOptions(ttl, true);
                    IPAddress? hopIp = null;
                    double rttMs = -1;

                    try
                    {
                        using var ping = new Ping();
                        var sw = Stopwatch.StartNew();
                        var reply = await ping.SendPingAsync(targetIp, probeTimeout, payload, options);
                        sw.Stop();
                        if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success)
                        {
                            hopIp = reply.Address;
                            // Use Stopwatch for sub-ms precision (reply.RoundtripTime is integer ms, rounds to 0 for fast hops)
                            rttMs = sw.Elapsed.TotalMilliseconds;
                            consecutiveTimeouts = 0;

                            if (reply.Status == IPStatus.Success)
                                reached = true;
                        }
                        else
                        {
                            consecutiveTimeouts++;
                        }
                    }
                    catch
                    {
                        consecutiveTimeouts++;
                    }

                    if (hopIp != null)
                    {
                        // Attempt reverse DNS with a short timeout
                        string hostName = "";
                        try
                        {
                            var dnsTask = Dns.GetHostEntryAsync(hopIp);
                            if (await Task.WhenAny(dnsTask, Task.Delay(500)) == dnsTask)
                            {
                                var entry = await dnsTask;
                                if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != hopIp.ToString())
                                    hostName = entry.HostName;
                            }
                        }
                        catch { /* Reverse DNS not available */ }

                        // If no reverse DNS, try to identify known Microsoft/Azure backbone IPs
                        if (string.IsNullOrEmpty(hostName))
                            hostName = IdentifyMicrosoftHop(hopIp);

                        string rttStr = rttMs < 1 ? $"{rttMs:F1}ms" : $"{Math.Round(rttMs)}ms";
                        sb.AppendLine($"║  {ttl,-4} {hopIp,-18} {rttStr,-8} {hostName}");
                    }
                    else
                    {
                        sb.AppendLine($"║  {ttl,-4} {"*",-18} {"*",-8}");
                    }

                    if (reached)
                    {
                        sb.AppendLine($"║  → Target reached at hop {ttl}");
                        break;
                    }

                    if (consecutiveTimeouts >= maxConsecutiveTimeouts)
                    {
                        sb.AppendLine($"║  → Stopped after {maxConsecutiveTimeouts} consecutive timeouts (ICMP likely blocked)");
                        break;
                    }
                }

                if (!reached)
                    sb.AppendLine($"║  → Target not reached within {maxHops} hops");
                else
                    completed++;

                sb.AppendLine($"╚══════════════════════════════════════════════════════════════");
                sb.AppendLine();
                Console.Write(reached ? "✓" : "✗");
            }

            result.ResultValue = $"{completed}/{targets.Count} endpoints traced successfully";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = completed == targets.Count ? "Passed" : completed > 0 ? "Warning" : "Failed";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunProxyVpnDetection()
    {
        var result = new TestResult { Id = "L-TCP-07", Name = "Proxy / VPN / SWG Detection", Category = "tcp" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();

            // Discover the actual RDP gateway for accurate probing
            var gwHost = await DiscoverRdpGatewayFromAfd();
            var probeHost = gwHost ?? "rdweb.wvd.microsoft.com";
            if (gwHost != null)
                sb.AppendLine($"Probing discovered RDP gateway: {gwHost}\n");
            else
                sb.AppendLine("⚠ Could not discover RDP gateway — probing rdweb.wvd.microsoft.com as fallback\n");

            // System proxy — check against the actual RDP gateway
            var proxy = WebRequest.GetSystemWebProxy();
            var testUri = new Uri($"https://{probeHost}");
            var proxyUri = proxy.GetProxy(testUri);
            if (proxyUri != null && proxyUri != testUri)
            {
                issues.Add($"System proxy: {proxyUri}");
                sb.AppendLine($"⚠ System proxy detected for {probeHost}: {proxyUri}");
            }
            else
            {
                sb.AppendLine($"✓ No system proxy configured for {probeHost}");
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
                    sb.AppendLine("✓ WinHTTP: Direct access (no proxy)");
                else
                {
                    issues.Add("WinHTTP proxy configured");
                    sb.AppendLine($"⚠ WinHTTP proxy configured:\n{output.Trim()}");
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
                    sb.AppendLine($"⚠ Environment: {v}={val}");
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
                    sb.AppendLine($"ℹ VPN adapter detected: {vpn.Name} ({vpn.Description})");
                    if (!string.IsNullOrEmpty(vpnIpList))
                        sb.AppendLine($"    Adapter IPs: {vpnIpList}");
                }

                // Routing table is the authoritative source for what's routed via VPN
                var caught = ProbeAvdServiceRanges(vpnAdapters, sb);
                foreach (var range in caught)
                    issues.Add($"W365/AVD range {range} routes through VPN tunnel");

                // Probe the actual discovered RDP gateway for VPN routing
                try
                {
                    var gwIps = Dns.GetHostAddresses(probeHost);
                    var gwIp = gwIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (gwIp != null)
                    {
                        var (routedViaVpn, localIp, _) = CheckIfRoutedViaVpn(gwIp, vpnAdapters);
                        if (routedViaVpn)
                        {
                            sb.AppendLine($"\n  ⚠ RDP gateway {gwIp} ({probeHost}) routes via VPN interface {localIp}");
                            issues.Add($"RDP gateway {probeHost} routes through VPN");
                        }
                        else
                            sb.AppendLine($"\n  ✓ RDP gateway {gwIp} ({probeHost}) routes direct via {localIp}");
                    }
                }
                catch { /* DNS or probe failed — non-critical since routing table already checked */ }
            }
            else
            {
                sb.AppendLine("✓ No VPN adapters detected");
            }

            // SWG / security processes
            var swgProcesses = new[] { "ZscalerService", "netskope", "iboss", "forcepoint", "mcafee", "symantec", "crowdstrike" };
            foreach (var name in swgProcesses)
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                {
                    issues.Add($"SWG process: {name}");
                    sb.AppendLine($"⚠ SWG/Security process running: {name} (PID: {procs[0].Id})");
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
        return result;
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
            var sw = Stopwatch.StartNew();
            await udp.SendAsync(stunRequest, stunRequest.Length, endpoint);

            try
            {
                var receiveTask = udp.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(3000)) == receiveTask)
                {
                    sw.Stop();
                    var rttMs = sw.ElapsedMilliseconds;
                    var response = receiveTask.Result;
                    result.Status = "Passed";
                    result.ResultValue = $"TURN relay reachable at {ip}:{port} — {rttMs}ms RTT";
                    result.DetailedInfo = $"Host: {host}\nIP: {ip}\nPort: {port}\nResponse: {response.Buffer.Length} bytes\nLatency: {rttMs}ms";
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

    // ── L-UDP-05: STUN NAT Type Detection ──
    // Replicates the methodology from Microsoft's Test-Shortpath.ps1 / avdnettest.exe:
    // Uses a single UdpClient to send STUN binding requests to two different servers,
    // compares the reflexive (XOR-MAPPED-ADDRESS) endpoints to determine NAT type.
    // Same reflexive endpoint = Cone NAT (Shortpath likely)
    // Different reflexive endpoints = Symmetric NAT (Shortpath unlikely)
    static async Task<TestResult> RunStunNatType()
    {
        var result = new TestResult { Id = "L-UDP-05", Name = "STUN NAT Type Detection", Category = "udp" };
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Method: Two-server STUN comparison (same as avdnettest.exe / Test-Shortpath.ps1)");
            sb.AppendLine("A single UDP socket sends STUN binding requests to two servers.");
            sb.AppendLine("If both return the same reflexive IP:port, NAT is cone-shaped (Shortpath works).");
            sb.AppendLine("If they differ, NAT is symmetric (Shortpath unlikely).");
            sb.AppendLine();

            // NOTE: This test uses external STUN servers purely for NAT type detection
            // (STUN compatibility check). These are NOT the W365 RDP connectivity endpoints.
            // W365 RDP uses 51.5.0.0/16 and world.relay.avd.microsoft.com for actual TURN relay.

            // Server 1: stun.azure.com (Microsoft's public STUN server — for NAT testing only)
            var stunHost1 = "stun.azure.com";
            IPAddress? stunIp1 = null;
            try
            {
                var dns1 = await Dns.GetHostAddressesAsync(stunHost1);
                stunIp1 = dns1.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            }
            catch { }

            if (stunIp1 == null)
            {
                // Fallback to known stun.azure.com IP for NAT testing
                sb.AppendLine($"⚠ DNS resolution of {stunHost1} failed, using fallback IP 20.202.22.68");
                stunIp1 = IPAddress.Parse("20.202.22.68");
            }
            else
            {
                sb.AppendLine($"Server 1: {stunHost1} → {stunIp1}");
            }

            // Server 2: stun1.l.google.com (independent STUN server — for NAT comparison)
            var stunHost2 = "stun1.l.google.com";
            int stunPort2 = 19302;
            IPAddress? stunIp2 = null;
            try
            {
                var dns2 = await Dns.GetHostAddressesAsync(stunHost2);
                stunIp2 = dns2.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            }
            catch { }

            if (stunIp2 == null)
            {
                sb.AppendLine($"⚠ DNS resolution of {stunHost2} failed, using fallback IP 142.250.31.127");
                stunIp2 = IPAddress.Parse("142.250.31.127");
            }
            else
            {
                sb.AppendLine($"Server 2: {stunHost2} → {stunIp2} (port {stunPort2})");
            }
            sb.AppendLine();

            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = 5000;
            var localPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
            sb.AppendLine($"Local UDP port: {localPort}");

            // Send STUN to server 1
            var mapped1 = await SendStunAndGetMapped(udp, new IPEndPoint(stunIp1, 3478), sb, "Server 1");
            // Send STUN to server 2
            var mapped2 = await SendStunAndGetMapped(udp, new IPEndPoint(stunIp2, stunPort2), sb, "Server 2");

            sb.AppendLine();

            if (mapped1 == null && mapped2 == null)
            {
                sb.AppendLine("✗ Neither STUN server responded.");
                sb.AppendLine("  UDP port 3478 is likely blocked by firewall, VPN, or SWG.");
                sb.AppendLine("  RDP Shortpath for public networks will NOT work.");
                result.Status = "Failed";
                result.ResultValue = "STUN failed — UDP 3478 blocked";
                result.RemediationText = "Allow outbound UDP 3478 to Microsoft STUN/TURN servers.";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            else if (mapped1 == null || mapped2 == null)
            {
                var working = mapped1 ?? mapped2;
                sb.AppendLine($"⚠ Only one STUN server responded (reflexive: {working}).");
                sb.AppendLine("  NAT type could not be fully determined.");
                sb.AppendLine("  STUN connectivity is partially available.");
                result.Status = "Warning";
                result.ResultValue = $"Partial STUN — reflexive {working}";
            }
            else if (mapped1 == mapped2)
            {
                sb.AppendLine($"✓ Both servers returned the same reflexive endpoint: {mapped1}");
                sb.AppendLine();
                sb.AppendLine("NAT Type: Cone (Endpoint-Independent Mapping)");
                sb.AppendLine("RDP Shortpath for public networks is LIKELY to work.");
                sb.AppendLine();
                sb.AppendLine("Shortpath modes available:");
                sb.AppendLine("  • STUN (direct): Client ↔ Cloud PC via UDP hole-punching");
                sb.AppendLine("  • TURN (relayed): Client ↔ TURN relay ↔ Cloud PC (fallback)");
                result.Status = "Passed";
                result.ResultValue = $"Cone NAT — Shortpath ready ({mapped1})";
            }
            else
            {
                sb.AppendLine($"✗ Servers returned different reflexive endpoints:");
                sb.AppendLine($"    Server 1: {mapped1}");
                sb.AppendLine($"    Server 2: {mapped2}");
                sb.AppendLine();
                sb.AppendLine("NAT Type: Symmetric (Endpoint-Dependent Mapping)");
                sb.AppendLine("RDP Shortpath via STUN (direct) is UNLIKELY to work.");
                sb.AppendLine("TURN relay fallback will still be used if available.");
                result.Status = "Warning";
                result.ResultValue = $"Symmetric NAT — Shortpath via STUN unlikely";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>
    /// Sends a STUN binding request and parses the XOR-MAPPED-ADDRESS from the response.
    /// Retries up to 3 times (same retry logic as Test-Shortpath.ps1).
    /// Returns the reflexive IP:port string, or null if no response.
    /// </summary>
    static async Task<string?> SendStunAndGetMapped(UdpClient udp, IPEndPoint server, StringBuilder sb, string label)
    {
        var stunReq = BuildStunRequest();
        const int maxAttempts = 3;

        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await udp.SendAsync(stunReq, stunReq.Length, server);
                var recvTask = udp.ReceiveAsync();
                if (await Task.WhenAny(recvTask, Task.Delay(3000)) == recvTask)
                {
                    var resp = await recvTask;
                    // Validate STUN response: type should be 0x0101 (Binding Success)
                    if (resp.Buffer.Length >= 20 && ((resp.Buffer[0] << 8) | resp.Buffer[1]) == 0x0101)
                    {
                        var mapped = ParseStunMappedAddress(resp.Buffer);
                        if (mapped != null)
                        {
                            sb.AppendLine($"  {label} ({server.Address}): reflexive = {mapped}" + (attempt > 1 ? $" (attempt {attempt})" : ""));
                            return mapped;
                        }
                    }
                    sb.AppendLine($"  {label} ({server.Address}): invalid STUN response ({resp.Buffer.Length} bytes)");
                    return null;
                }
                // Timeout — retry
            }
            catch
            {
                // Send/receive error — retry
            }
        }

        sb.AppendLine($"  {label} ({server.Address}): no response after {maxAttempts} attempts");
        return null;
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
        // 40.64.144.0/20 → mask 0xFFFFF000 (AFD signaling / connection broker)
        uint net1 = (uint)(40 << 24 | 64 << 16 | 144 << 8);
        if ((addr & 0xFFFFF000) == net1) return true;
        // 51.5.0.0/16 → mask 0xFFFF0000 (TURN relay infrastructure)
        uint net2 = (uint)(51 << 24 | 5 << 16);
        if ((addr & 0xFFFF0000) == net2) return true;
        return false;
    }

    /// <summary>
    /// Discovers the actual regional RDP gateway hostname from AFD's Set-Cookie Domain= header.
    /// Returns null if discovery fails. Each caller invokes this independently.
    /// </summary>
    static async Task<string?> DiscoverRdpGatewayFromAfd()
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(8), handler);
            var resp = await http.GetAsync("https://afdfp-rdgateway-r1.wvd.microsoft.com/");
            if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var m = System.Text.RegularExpressions.Regex.Match(
                        cookie, @"Domain=(rdgateway[^;]+\.wvd\.microsoft\.com)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success) return m.Groups[1].Value;
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Extracts the Azure region code from an RDP gateway FQDN.
    /// e.g. "rdgateway-c221-UKS-r1.wvd.microsoft.com" → "UKS"
    /// </summary>
    static string? ExtractRegionFromGatewayFqdn(string fqdn)
    {
        // Pattern: rdgateway-XXXX-REGION-rN.wvd.microsoft.com
        var m = System.Text.RegularExpressions.Regex.Match(
            fqdn, @"rdgateway-[^-]+-([A-Za-z]+\d*)-r\d+",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
    }

    /// <summary>
    /// Maps Azure region codes (from gateway FQDNs) to friendly names.
    /// </summary>
    static string? GetAzureRegionName(string regionCode)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Europe
            ["UKS"] = "UK South", ["UKW"] = "UK West",
            ["NEU"] = "North Europe (Ireland)", ["WEU"] = "West Europe (Netherlands)",
            ["FRC"] = "France Central", ["FRS"] = "France South",
            ["GWC"] = "Germany West Central", ["GN"] = "Germany North",
            ["NOE"] = "Norway East", ["NOW"] = "Norway West",
            ["SEW"] = "Sweden Central", ["SES"] = "Sweden South",
            ["CHN"] = "Switzerland North", ["CHW"] = "Switzerland West",
            ["ITA"] = "Italy North", ["SPE"] = "Spain Central",
            ["POC"] = "Poland Central",
            // North America
            ["EUS"] = "East US", ["EUS2"] = "East US 2",
            ["CUS"] = "Central US", ["NCUS"] = "North Central US",
            ["SCUS"] = "South Central US", ["WCUS"] = "West Central US",
            ["WUS"] = "West US", ["WUS2"] = "West US 2", ["WUS3"] = "West US 3",
            ["CC"] = "Canada Central", ["CE"] = "Canada East",
            // Asia Pacific
            ["SEA"] = "Southeast Asia (Singapore)", ["EA"] = "East Asia (Hong Kong)",
            ["JE"] = "Japan East", ["JW"] = "Japan West",
            ["KRC"] = "Korea Central", ["KRS"] = "Korea South",
            ["CIN"] = "Central India", ["SIN"] = "South India", ["WIN"] = "West India",
            ["AUE"] = "Australia East", ["AUSE"] = "Australia Southeast",
            ["AUC"] = "Australia Central",
            // Middle East & Africa
            ["SAE"] = "South Africa North", ["SAW"] = "South Africa West",
            ["UAE"] = "UAE North", ["UAW"] = "UAE Central",
            ["ILC"] = "Israel Central", ["QAC"] = "Qatar Central",
            // South America
            ["BRS"] = "Brazil South", ["BRSE"] = "Brazil Southeast"
        };
        return map.TryGetValue(regionCode, out var name) ? name : null;
    }

    static async Task<(string hostname, int port, IPAddress ip)?> GetValidatedGateway()
    {
        // First, try to discover the actual regional gateway from AFD's Set-Cookie header
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(8), handler);
            var resp = await http.GetAsync("https://afdfp-rdgateway-r1.wvd.microsoft.com/");
            if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var m = System.Text.RegularExpressions.Regex.Match(
                        cookie, @"Domain=(rdgateway[^;]+\.wvd\.microsoft\.com)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        var gwHost = m.Groups[1].Value;
                        var ips = await Dns.GetHostAddressesAsync(gwHost);
                        var ip = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                        if (ip != null) return (gwHost, 443, ip);
                    }
                }
            }
        }
        catch { /* Fall through to static list */ }

        // Fallback: try well-known endpoints (IPs may be in W365 range behind some network configs)
        var gateways = new[] { "afdfp-rdgateway-r1.wvd.microsoft.com", "rdweb.wvd.microsoft.com" };
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
    static async Task<TestResult> RunTransportProtocol()
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
                    "*[System[(EventID=131 or EventID=135 or EventID=137 or EventID=138 or EventID=140 or EventID=141 or EventID=142 or EventID=143) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
                using var reader = new EventLogReader(query);
                EventRecord? record;
                int count = 0;
                sb.AppendLine("RdpCoreTS Events (last 24h):");
                while ((record = reader.ReadEvent()) != null && count < 20)
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
                            135 => "Shortpath Connection Closing",
                            137 => "Shortpath Connecting",
                            138 => "Shortpath Connected",
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
                        if (eid is 137 or 138) { shortpathConnected = true; protocol = "UDP (RDP Shortpath)"; }
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
                        if (eid is 1024 or 1025 or 1026 or 1027 or 1029 or 1102 or 1103 or 1105)
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
                                1102 => "Multi-transport Initiated",
                                1103 => "Multi-transport Established",
                                1105 => "Multi-transport Info",
                                _ => $"Event {eid}"
                            };
                            if (count <= 15) sb.AppendLine($"  [{record.TimeCreated:HH:mm:ss}] {label}");
                            if (count <= 15 && msg.Length is > 0 and < 200)
                                sb.AppendLine($"    {msg}");
                            if (eid == 1024) hasConnection = true;
                            // Check for UDP transport indicators in message text
                            if (msg.Contains("UDP", StringComparison.OrdinalIgnoreCase) ||
                                msg.Contains("Shortpath", StringComparison.OrdinalIgnoreCase))
                            {
                                if (msg.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                                    msg.Contains("connected", StringComparison.OrdinalIgnoreCase) ||
                                    msg.Contains("established", StringComparison.OrdinalIgnoreCase) ||
                                    eid is 1103 or 1105)
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

            // 3. Check for active UDP connections to TURN relay (port 3478)
            // This is the most reliable indicator of Shortpath in use
            try
            {
                var udpListeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveUdpListeners();
                var udpConns = udpListeners.Where(ep => ep.Port == 3478 || ep.Port >= 49152).ToList();

                // Also check for established TCP connections to known TURN/gateway endpoints
                var tcpConns = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established)
                    .ToList();

                // Look for connections to TURN relay port 3478
                var turnConns = tcpConns.Where(c => c.RemoteEndPoint.Port == 3478).ToList();
                if (turnConns.Count > 0)
                {
                    sb.AppendLine($"\nActive TURN connections (port 3478): {turnConns.Count}");
                    foreach (var tc in turnConns.Take(3))
                        sb.AppendLine($"  → {tc.RemoteEndPoint}");
                    udpConnected = true;
                    protocol = "UDP (RDP Shortpath via TURN)";
                }
            }
            catch { /* netstat-like checks may require elevation */ }

            // 4. Check RemoteFX UDP bandwidth if inside remote session
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

            // Determine result from event logs / counters / active connections
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
                sb.AppendLine();
                sb.AppendLine("W365 supports three RDP connectivity methods:");
                sb.AppendLine("  1. TCP Reverse Connect (443) — always used initially");
                sb.AppendLine("  2. Relayed UDP via TURN (3478) — higher reliability, works on any NAT");
                sb.AppendLine("  3. Direct UDP via STUN — best-effort, may fail on symmetric NAT");
                sb.AppendLine();
                sb.AppendLine("Ensure UDP 3478 to 51.5.0.0/16 is allowed outbound and bypasses VPN/SWG.");
                result.RemediationText = "UDP-based RDP Shortpath failed. Ensure UDP 3478 outbound to 51.5.0.0/16 is allowed and bypasses VPN/SWG.";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/understanding-remote-desktop-protocol-traffic";
            }
            else if (hasConnection && !string.IsNullOrEmpty(protocol))
            {
                result.Status = protocol.Contains("UDP") ? "Passed" : "Warning";
                result.ResultValue = protocol;
            }
            else
            {
                // 5. Fallback: check gateway IP range (informational only)
                // NOTE: The AFD gateway range (40.64.144.0/20) is used for signaling/connection broker.
                // Even when RDP Shortpath is active, signaling still routes through AFD.
                // So this range does NOT mean Shortpath is disabled.
                var rangeResult = await DetectTransportFromGatewayRange(sb);
                if (rangeResult != null)
                {
                    if (rangeResult.Value.isUdp)
                    {
                        result.Status = "Passed";
                        result.ResultValue = "UDP (RDP Shortpath via TURN) ⚡";
                    }
                    else
                    {
                        // AFD gateway range is just signaling — don't warn about Shortpath
                        result.Status = "Passed";
                        result.ResultValue = "Connected via gateway";
                        sb.AppendLine();
                        sb.AppendLine("ℹ Gateway resolves to AFD signaling range (40.64.144.0/20).");
                        sb.AppendLine("  This is the signaling/connection broker path.");
                        sb.AppendLine("  Data transport may still use UDP (RDP Shortpath) once session is established.");
                        sb.AppendLine("  Run this test while connected to your Cloud PC for definitive transport detection.");
                    }
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
                    result.Status = "Passed";
                    result.ResultValue = "Connection detected — transport undetermined";
                    sb.AppendLine("ℹ RDP connection found but transport type could not be determined.");
                    sb.AppendLine("  Re-run while actively connected for more detailed results.");
                }
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>
    /// Determines transport protocol by resolving gateway hostnames and checking which W365 IP range they fall in.
    /// 40.64.144.0/20 = TCP (Reverse Connect via Azure Front Door gateway)
    /// 51.5.0.0/16    = UDP (RDP Shortpath via TURN relay infrastructure)
    /// </summary>
    static async Task<(bool isUdp, string ip, string hostname)?> DetectTransportFromGatewayRange(StringBuilder sb)
    {
        var gateways = new[] { "afdfp-rdgateway-r1.wvd.microsoft.com", "rdweb.wvd.microsoft.com", "client.wvd.microsoft.com" };
        sb.AppendLine("Gateway IP Range Analysis:");

        foreach (var gw in gateways)
        {
            try
            {
                var ips = await Dns.GetHostAddressesAsync(gw);
                var ip = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ip == null) continue;

                var b = ip.GetAddressBytes();
                uint addr = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);

                // 40.64.144.0/20 → TCP (AFD Gateway / Reverse Connect)
                uint net1 = (uint)(40 << 24 | 64 << 16 | 144 << 8);
                if ((addr & 0xFFFFF000) == net1)
                {
                    sb.AppendLine($"  {gw} → {ip} (40.64.144.0/20 = TCP Reverse Connect)");
                    return (isUdp: false, ip: ip.ToString(), hostname: gw);
                }

                // 51.5.0.0/16 → UDP (TURN Relay / RDP Shortpath)
                uint net2 = (uint)(51 << 24 | 5 << 16);
                if ((addr & 0xFFFF0000) == net2)
                {
                    sb.AppendLine($"  {gw} → {ip} (51.5.0.0/16 = UDP via TURN)");
                    return (isUdp: true, ip: ip.ToString(), hostname: gw);
                }

                sb.AppendLine($"  {gw} → {ip} (outside W365 ranges)");
            }
            catch { sb.AppendLine($"  {gw} → DNS resolution failed"); }
        }

        return null;
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

                // Sample for ~60 seconds (20 samples × 3s interval)
                const int rttSampleCount = 20;
                const int rttIntervalMs = 3000;
                for (int i = 0; i < rttSampleCount; i++)
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
                    if (i < rttSampleCount - 1) await Task.Delay(rttIntervalMs);
                }

                if (tcpSamples.Count > 0)
                {
                    sb.AppendLine($"TCP RTT: avg {tcpSamples.Average():F0}ms, min {tcpSamples.Min():F0}ms, max {tcpSamples.Max():F0}ms ({tcpSamples.Count} samples over ~60s)");
                    sb.AppendLine($"  Values: {string.Join(", ", tcpSamples.Select(s => $"{s:F0}ms"))}");
                }
                if (udpSamples.Count > 0)
                {
                    sb.AppendLine($"UDP RTT: avg {udpSamples.Average():F0}ms, min {udpSamples.Min():F0}ms, max {udpSamples.Max():F0}ms ({udpSamples.Count} samples over ~60s)");
                    sb.AppendLine($"  Values: {string.Join(", ", udpSamples.Select(s => $"{s:F0}ms"))}");
                }

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
                    sb.AppendLine("Samples: 30 TCP probes over ~60s");
                    sb.AppendLine();

                    // 30 probes × 2s interval = ~60 seconds of data
                    var rtts = new List<double>();
                    for (int i = 0; i < 30; i++)
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
                        if (i < 29) await Task.Delay(2000);
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
                        sb.AppendLine($"Successful: {rtts.Count}/30");
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

            // Collect samples over ~60 seconds for more representative data
            var outputFpsList = new List<float>();
            var inputFpsList = new List<float>();
            var encTimeList = new List<float>();
            var qualityList = new List<float>();
            var udpBwList = new List<float>();
            var skipNetList = new List<float>();
            var skipClientList = new List<float>();
            var skipServerList = new List<float>();

            const int fpsSampleCount = 20;
            const int fpsIntervalMs = 3000;
            for (int i = 0; i < fpsSampleCount; i++)
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
                            var v = TryReadPerfCounter("RemoteFX Graphics", "Input Frames/Second", inst); if (v.HasValue) inputFpsList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Output Frames/Second", inst); if (v.HasValue) outputFpsList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Network Resources", inst); if (v.HasValue) skipNetList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Client Resources", inst); if (v.HasValue) skipClientList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Server Resources", inst); if (v.HasValue) skipServerList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Average Encoding Time", inst); if (v.HasValue) encTimeList.Add(v.Value);
                            v = TryReadPerfCounter("RemoteFX Graphics", "Frame Quality", inst); if (v.HasValue) qualityList.Add(v.Value);
                        }
                    }
                    if (PerformanceCounterCategory.Exists("RemoteFX Network"))
                    {
                        var cat = new PerformanceCounterCategory("RemoteFX Network");
                        var instances = cat.GetInstanceNames();
                        if (instances.Length > 0)
                        {
                            var v = TryReadPerfCounter("RemoteFX Network", "Current UDP Bandwidth", instances[0]); if (v.HasValue) udpBwList.Add(v.Value);
                        }
                    }
                }
                catch { }
                if (i < fpsSampleCount - 1) await Task.Delay(fpsIntervalMs);
            }

            float? outputFps = outputFpsList.Count > 0 ? outputFpsList.Average() : null;
            float? inputFps = inputFpsList.Count > 0 ? inputFpsList.Average() : null;
            float? encTime = encTimeList.Count > 0 ? encTimeList.Average() : null;
            float? quality = qualityList.Count > 0 ? qualityList.Average() : null;
            float? udpBw = udpBwList.Count > 0 ? udpBwList.Average() : null;
            float? skipNet = skipNetList.Count > 0 ? skipNetList.Average() : null;
            float? skipClient = skipClientList.Count > 0 ? skipClientList.Average() : null;
            float? skipServer = skipServerList.Count > 0 ? skipServerList.Average() : null;

            if (outputFps == null && inputFps == null)
            {
                sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
                sb.AppendLine("  Session may be idle or counters may be disabled.");
                result.Status = "Warning";
                result.ResultValue = "Counters unavailable";
            }
            else
            {
                sb.AppendLine($"Sampled {fpsSampleCount} readings over ~{fpsSampleCount * fpsIntervalMs / 1000}s");
                sb.AppendLine();
                if (inputFps.HasValue) sb.AppendLine($"Input Frames/sec:  avg {inputFps:F1}, min {inputFpsList.Min():F1}, max {inputFpsList.Max():F1}");
                if (outputFps.HasValue) sb.AppendLine($"Output Frames/sec: avg {outputFps:F1}, min {outputFpsList.Min():F1}, max {outputFpsList.Max():F1}");
                if (encTime.HasValue) sb.AppendLine($"Avg Encoding Time: {encTime:F1}ms {(encTime < 33 ? "✓ Good" : "⚠ High")} (range {encTimeList.Min():F1}-{encTimeList.Max():F1}ms)");
                if (quality.HasValue) sb.AppendLine($"Frame Quality:     avg {quality:F0}% (range {qualityList.Min():F0}-{qualityList.Max():F0}%)");
                if (udpBw.HasValue) sb.AppendLine($"UDP Bandwidth:     avg {udpBw:F0} KB/s (range {udpBwList.Min():F0}-{udpBwList.Max():F0})");
                sb.AppendLine();
                sb.AppendLine("Frame Drop Analysis (averages over sample period):");
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
            sb.AppendLine("Samples: 60 TCP connect probes at 1s intervals (~60s)");
            sb.AppendLine();

            // 60 probes × 1s interval = ~60 seconds of jitter data
            var rtts = new List<double>();
            for (int i = 0; i < 60; i++)
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
                if (i < 59) await Task.Delay(1000);
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

            sb.AppendLine($"Successful samples: {rtts.Count}/60");
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

                // Sample over ~60 seconds for reliable frame drop statistics
                var outFpsList21 = new List<float>();
                var inFpsList21 = new List<float>();
                var skipNetList21 = new List<float>();
                var skipClientList21 = new List<float>();
                var skipServerList21 = new List<float>();

                const int dropSampleCount = 20;
                const int dropIntervalMs = 3000;
                for (int i = 0; i < dropSampleCount; i++)
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
                                var v = TryReadPerfCounter("RemoteFX Graphics", "Input Frames/Second", inst); if (v.HasValue) inFpsList21.Add(v.Value);
                                v = TryReadPerfCounter("RemoteFX Graphics", "Output Frames/Second", inst); if (v.HasValue) outFpsList21.Add(v.Value);
                                v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Network Resources", inst); if (v.HasValue) skipNetList21.Add(v.Value);
                                v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Client Resources", inst); if (v.HasValue) skipClientList21.Add(v.Value);
                                v = TryReadPerfCounter("RemoteFX Graphics", "Frames Skipped/Second - Insufficient Server Resources", inst); if (v.HasValue) skipServerList21.Add(v.Value);
                            }
                        }
                    }
                    catch { }
                    if (i < dropSampleCount - 1) await Task.Delay(dropIntervalMs);
                }

                if (outFpsList21.Count == 0)
                {
                    sb.AppendLine("⚠ RemoteFX Graphics counters not available.");
                    result.Status = "Warning";
                    result.ResultValue = "Counters unavailable";
                }
                else
                {
                    float outFps = outFpsList21.Average();
                    float inFps = inFpsList21.Count > 0 ? inFpsList21.Average() : 0;
                    float skipNet = skipNetList21.Count > 0 ? skipNetList21.Average() : 0;
                    float skipClient = skipClientList21.Count > 0 ? skipClientList21.Average() : 0;
                    float skipServer = skipServerList21.Count > 0 ? skipServerList21.Average() : 0;
                    float totalDrop = skipNet + skipClient + skipServer;
                    float fps = outFps;
                    float dropPct = (fps + totalDrop) > 0 ? totalDrop / (fps + totalDrop) * 100 : 0;

                    sb.AppendLine($"Sampled {outFpsList21.Count} readings over ~{dropSampleCount * dropIntervalMs / 1000}s");
                    sb.AppendLine();
                    sb.AppendLine($"Input Frames/sec:  avg {inFps:F1} (range {(inFpsList21.Count > 0 ? $"{inFpsList21.Min():F1}-{inFpsList21.Max():F1}" : "N/A")})");
                    sb.AppendLine($"Output Frames/sec: avg {fps:F1} (range {outFpsList21.Min():F1}-{outFpsList21.Max():F1})");
                    sb.AppendLine($"Skipped (Network): avg {skipNet:F1}/sec");
                    sb.AppendLine($"Skipped (Client):  avg {skipClient:F1}/sec");
                    sb.AppendLine($"Skipped (Server):  avg {skipServer:F1}/sec");
                    sb.AppendLine($"Drop rate: {dropPct:F1}% (averaged over sample period)");

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
                    sb.AppendLine("Probes: 60 TCP connection attempts over ~60s");
                    sb.AppendLine();

                    // 60 probes × 1s interval = ~60 seconds of loss data
                    int success = 0, failure = 0;
                    for (int i = 0; i < 60; i++)
                    {
                        try
                        {
                            using var tcp = new TcpClient();
                            using var cts = new CancellationTokenSource(3000);
                            await tcp.ConnectAsync(hostname, port, cts.Token);
                            success++;
                        }
                        catch { failure++; }
                        if (i < 59) await Task.Delay(1000);
                    }

                    var lossRate = failure > 0 ? (double)failure / (success + failure) * 100 : 0;
                    sb.AppendLine($"Successful: {success}/60");
                    sb.AppendLine($"Failed:     {failure}/60");
                    sb.AppendLine($"Loss rate:  {lossRate:F1}%");

                    if (failure == 0) { result.Status = "Passed"; result.ResultValue = "0% loss (60/60 successful)"; }
                    else if (lossRate < 5) { result.Status = "Passed"; result.ResultValue = $"{lossRate:F1}% loss"; }
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
                    // 30 probes × 2s interval = ~60 seconds of VPN latency data
                    var rtts = new List<double>();
                    for (int i = 0; i < 30; i++)
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
                        if (i < 29) await Task.Delay(2000);
                    }
                    if (rtts.Count > 0)
                    {
                        sb.AppendLine();
                        sb.AppendLine($"Gateway latency via VPN ({rtts.Count} samples over ~60s):");
                        sb.AppendLine($"  Min: {rtts.Min():F0}ms | Avg: {rtts.Average():F0}ms | Max: {rtts.Max():F0}ms");
                        sb.AppendLine($"  Values: {string.Join(", ", rtts.Select(r => $"{r:F0}ms"))}");
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

    // ── Test 25: RDP TLS Inspection Detection ──
    // Per https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp
    // TLS inspection of RDP traffic is not supported and must be disabled.
    // RDP uses nested encryption (TLS 1.3 transport + encrypted RDP session inside).
    // Inspection adds jitter, latency, reduces throughput, and provides no security benefit.
    static async Task<TestResult> RunCloudTlsInspection()
    {
        var result = new TestResult { Id = "25", Name = "RDP TLS Inspection", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Checking TLS certificate chains on W365 RDP endpoints for signs of interception.");
            sb.AppendLine("Per Microsoft: \"Inspection of RDP traffic is not supported. Disable TLS inspection");
            sb.AppendLine("for all required endpoints.\" RDP uses nested encryption — inspecting the outer");
            sb.AppendLine("TLS layer provides no security benefit but degrades performance.");
            sb.AppendLine();

            var endpoints = new (string host, int port, string desc)[]
            {
                ("afdfp-rdgateway-r1.wvd.microsoft.com", 443, "RDP Gateway (TCP Reverse Connect, 40.64.144.0/20)"),
                ("rdweb.wvd.microsoft.com", 443, "RDP Web (Connection Broker)"),
            };

            bool anyIntercepted = false;
            int checked_ = 0;

            foreach (var (host, port, desc) in endpoints)
            {
                sb.AppendLine($"── {desc} ──");
                sb.AppendLine($"Host: {host}:{port}");
                try
                {
                    bool intercepted = false;
                    string issuerInfo = "";
                    string subjectInfo = "";

                    using var tcp = new TcpClient();
                    using var cts = new CancellationTokenSource(10000);
                    await tcp.ConnectAsync(host, port, cts.Token);

                    using var ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
                    {
                        if (cert is X509Certificate2 x509)
                        {
                            subjectInfo = x509.Subject;
                            issuerInfo = x509.Issuer;
                            sb.AppendLine($"  Subject: {x509.Subject}");
                            sb.AppendLine($"  Issuer:  {x509.Issuer}");
                            sb.AppendLine($"  Valid:   {x509.NotBefore:d} - {x509.NotAfter:d}");
                            sb.AppendLine($"  Errors:  {errors}");

                            var expectedIssuers = new[] { "Microsoft", "DigiCert", "Microsoft Azure RSA TLS", "Microsoft Azure TLS", "Microsoft RSA TLS CA" };
                            bool isExpected = expectedIssuers.Any(e => issuerInfo.Contains(e, StringComparison.OrdinalIgnoreCase));
                            bool isPrivateLink = x509.Subject.Contains("privatelink", StringComparison.OrdinalIgnoreCase);

                            if (!isExpected && !isPrivateLink)
                            {
                                intercepted = true;
                                anyIntercepted = true;
                            }
                        }
                        return true;
                    });

                    using var tlsCts = new CancellationTokenSource(10000);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, tlsCts.Token);
                    sb.AppendLine($"  TLS:     {ssl.SslProtocol}");
                    checked_++;

                    if (intercepted)
                    {
                        sb.AppendLine($"  ✗ TLS INSPECTION DETECTED — certificate is NOT from Microsoft/DigiCert.");
                        sb.AppendLine($"    A proxy, firewall, or SWG is intercepting RDP traffic.");
                        sb.AppendLine($"    This adds latency, jitter, and reduces throughput with no security benefit.");
                    }
                    else
                    {
                        sb.AppendLine($"  ✓ Certificate chain is valid — no TLS inspection detected.");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"  ✗ Connection failed: {ex.Message}");
                }
                sb.AppendLine();
            }

            if (anyIntercepted)
            {
                result.Status = "Failed";
                result.ResultValue = "TLS inspection detected on RDP gateway";
                result.RemediationText = "TLS inspection of RDP traffic is not supported by Microsoft. " +
                    "Disable TLS inspection for 40.64.144.0/20 (TCP/443) and 51.5.0.0/16 (UDP/3478). " +
                    "RDP uses nested encryption — the inner session is already TLS 1.3 encrypted.";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp#1-disabling-tls-inspection";
            }
            else if (checked_ == 0)
            {
                result.Status = "Warning";
                result.ResultValue = "Could not check — endpoints unreachable";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = $"No TLS inspection — {checked_} endpoint(s) verified";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── Test 26: RDP Traffic Routing (VPN/SWG Bypass) ──
    // Per https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp
    // RDP traffic must bypass VPN and SWG tunnels. Key endpoints:
    //   40.64.144.0/20 TCP/443  — TCP-based RDP (Reverse Connect)
    //   51.5.0.0/16    UDP/3478 — UDP-based RDP (TURN relay / Shortpath)
    static Task<TestResult> RunCloudTrafficRouting()
    {
        var result = new TestResult { Id = "26", Name = "RDP Traffic Routing", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Validates that RDP traffic bypasses VPN, proxy, and SWG tunnels.");
            sb.AppendLine("Per Microsoft: \"Forced tunnel exceptions for RDP traffic are essential.\"");
            sb.AppendLine();
            sb.AppendLine("Required RDP endpoints (bypass these from VPN/SWG):");
            sb.AppendLine("  Row 1: 40.64.144.0/20  TCP/443  — TCP RDP (Reverse Connect via AFD)");
            sb.AppendLine("  Row 2: 51.5.0.0/16     UDP/3478 — UDP RDP (TURN relay / Shortpath)");
            sb.AppendLine();

            var issues = new List<string>();

            // ── 1. Check for VPN adapters and route analysis ──
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

            if (vpnAdapters.Count > 0)
            {
                sb.AppendLine("VPN/SWG adapters detected:");
                foreach (var vpn in vpnAdapters)
                    sb.AppendLine($"  {vpn.Name} ({vpn.Description})");
                sb.AppendLine();

                // Check routing table for both W365 subnets
                var caught = ProbeAvdServiceRanges(vpnAdapters, sb);
                if (caught.Count > 0)
                {
                    foreach (var range in caught)
                        issues.Add($"RDP range {range} routes through VPN/SWG tunnel");

                    sb.AppendLine();
                    sb.AppendLine("⚠ The following RDP subnet(s) are routed via VPN/SWG:");
                    foreach (var range in caught)
                        sb.AppendLine($"  ✗ {range}");
                    sb.AppendLine();
                    sb.AppendLine("Impact: Increased latency, jitter, reduced throughput, and potential");
                    sb.AppendLine("disconnects during initial logon when user-based tunnels activate.");
                    sb.AppendLine();
                    sb.AppendLine("Solution: Configure bypass/split-tunnel exceptions for:");
                    sb.AppendLine("  40.64.144.0/20  TCP/443");
                    sb.AppendLine("  51.5.0.0/16     UDP/3478");
                }
                else
                {
                    sb.AppendLine("✓ VPN/SWG detected but W365 RDP ranges are split-tunneled (bypassed).");
                }
            }
            else
            {
                sb.AppendLine("✓ No VPN/SWG adapters detected — traffic routes directly.");
            }

            // ── 2. Check system proxy for RDP endpoints ──
            sb.AppendLine();
            sb.AppendLine("── Proxy Check ──");
            try
            {
                var proxy = WebRequest.GetSystemWebProxy();
                var rdpEndpoints = new[]
                {
                    new Uri("https://afdfp-rdgateway-r1.wvd.microsoft.com"),
                    new Uri("https://rdweb.wvd.microsoft.com"),
                    new Uri("https://client.wvd.microsoft.com"),
                };
                foreach (var uri in rdpEndpoints)
                {
                    var proxyUri = proxy.GetProxy(uri);
                    if (proxyUri != null && proxyUri != uri)
                    {
                        issues.Add($"Proxy routes {uri.Host} via {proxyUri}");
                        sb.AppendLine($"  ✗ {uri.Host} → proxy {proxyUri}");
                    }
                    else
                    {
                        sb.AppendLine($"  ✓ {uri.Host} → direct (no proxy)");
                    }
                }
            }
            catch { sb.AppendLine("  Could not check proxy settings."); }

            // ── 3. Check for SWG agent processes ──
            sb.AppendLine();
            sb.AppendLine("── SWG / Security Agent Check ──");
            var swgProcesses = new (string name, string label)[]
            {
                ("ZscalerService", "Zscaler"),
                ("ZSATunnel", "Zscaler Tunnel"),
                ("netskope", "Netskope"),
                ("npa_service", "Netskope Private Access"),
                ("iboss", "iboss"),
                ("forcepoint", "Forcepoint"),
                ("PanGPS", "Palo Alto GlobalProtect"),
                ("PanGPA", "Palo Alto GlobalProtect"),
            };
            bool anySWG = false;
            foreach (var (name, label) in swgProcesses)
            {
                try
                {
                    var procs = Process.GetProcessesByName(name);
                    if (procs.Length > 0)
                    {
                        anySWG = true;
                        sb.AppendLine($"  ⚠ {label} running (PID {procs[0].Id})");
                        sb.AppendLine($"    Ensure RDP bypass is configured for 40.64.144.0/20 and 51.5.0.0/16");
                    }
                }
                catch { }
            }
            if (!anySWG)
                sb.AppendLine("  ✓ No SWG agents detected.");

            // ── 4. Check environment proxy vars ──
            var envVars = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" };
            foreach (var v in envVars)
            {
                var val = Environment.GetEnvironmentVariable(v);
                if (!string.IsNullOrEmpty(val))
                {
                    issues.Add($"Environment {v}={val}");
                    sb.AppendLine($"\n  ⚠ Environment variable {v}={val}");
                }
            }

            if (issues.Count == 0)
            {
                result.Status = "Passed";
                result.ResultValue = "RDP traffic routes directly — no VPN/SWG interception";
            }
            else
            {
                result.Status = "Warning";
                result.ResultValue = $"{issues.Count} routing issue(s) — RDP traffic may not be optimized";
                result.RemediationText = "RDP traffic should bypass VPN and SWG tunnels. " +
                    "Configure split-tunnel exceptions for 40.64.144.0/20 (TCP/443) and 51.5.0.0/16 (UDP/3478). " +
                    "Microsoft owns and manages both subnets — they are dedicated to W365/AVD.";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp#2-bypass-vpn-and-secure-web-gateway-tunnels";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ── Test 27: RDP Local Egress Validation ──
    // Per https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp
    // Traffic should egress locally to reach the nearest gateway/TURN relay.
    // Backhauling through a corporate network or distant proxy adds latency.
    static async Task<TestResult> RunCloudLocalEgress()
    {
        var result = new TestResult { Id = "27", Name = "RDP Local Egress", Category = "cloud" };
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Validates that RDP traffic egresses locally to the nearest W365 gateway.");
            sb.AppendLine("Per Microsoft: \"Local breakout to the internet as close as possible to the");
            sb.AppendLine("user prevents traffic from backhauling through corporate networks, VPNs, SWGs.\"");
            sb.AppendLine();

            // Get user's public IP and location
            string userCity = "", userRegion = "", userCountry = "", userOrg = "";
            double userLat = 0, userLon = 0;
            bool hasUserGeo = false;

            try
            {
                var userGeo = await FetchGeoIpAsync("https://ipinfo.io/json", TimeSpan.FromSeconds(5));
                userCity = userGeo.TryGetProperty("city", out var c) ? c.GetString() ?? "" : "";
                userRegion = userGeo.TryGetProperty("region", out var r) ? r.GetString() ?? "" : "";
                userCountry = userGeo.TryGetProperty("country", out var co) ? co.GetString() ?? "" : "";
                userOrg = userGeo.TryGetProperty("org", out var o) ? o.GetString() ?? "" : "";
                if (userGeo.TryGetProperty("loc", out var loc))
                {
                    var parts = loc.GetString()?.Split(',');
                    if (parts?.Length == 2 && double.TryParse(parts[0], out userLat) && double.TryParse(parts[1], out userLon))
                        hasUserGeo = true;
                }
                sb.AppendLine($"Your egress location: {userCity}, {userRegion}, {userCountry}");
                sb.AppendLine($"Your ISP/org: {userOrg}");
                sb.AppendLine();
            }
            catch
            {
                sb.AppendLine("⚠ Could not determine your public IP location.");
                sb.AppendLine();
            }

            // Check gateway location
            var gw = await GetValidatedGateway();
            if (gw != null)
            {
                var (hostname, port, ip) = gw.Value;
                sb.AppendLine($"── RDP Gateway (TCP Reverse Connect) ──");
                sb.AppendLine($"Host: {hostname}");
                sb.AppendLine($"IP:   {ip}");

                try
                {
                    var gwGeo = await FetchGeoIpAsync($"https://ipinfo.io/{ip}/json", TimeSpan.FromSeconds(5));
                    string gwCity = gwGeo.TryGetProperty("city", out var gc) ? gc.GetString() ?? "" : "";
                    string gwRegion = gwGeo.TryGetProperty("region", out var gr) ? gr.GetString() ?? "" : "";
                    string gwCountry = gwGeo.TryGetProperty("country", out var gco) ? gco.GetString() ?? "" : "";
                    sb.AppendLine($"Location: {gwCity}, {gwRegion}, {gwCountry}");

                    if (hasUserGeo && gwGeo.TryGetProperty("loc", out var gloc))
                    {
                        var parts = gloc.GetString()?.Split(',');
                        if (parts?.Length == 2 && double.TryParse(parts[0], out var gwLat) && double.TryParse(parts[1], out var gwLon))
                        {
                            var distKm = HaversineDistance(userLat, userLon, gwLat, gwLon);
                            sb.AppendLine($"Distance from you: ~{distKm:F0} km");

                            if (distKm > 1500)
                            {
                                sb.AppendLine("⚠ Gateway is far from your location — possible traffic backhauling.");
                                sb.AppendLine("  RDP traffic may be exiting through a remote corporate network or VPN.");
                            }
                            else
                            {
                                sb.AppendLine("✓ Gateway is near your location — traffic appears to egress locally.");
                            }
                        }
                    }
                }
                catch { sb.AppendLine("Could not geolocate gateway."); }
                sb.AppendLine();

                // Measure latency to gateway as a practical check
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
                    if (i < 4) await Task.Delay(500);
                }
                if (rtts.Count > 0)
                {
                    var avgRtt = rtts.Average();
                    sb.AppendLine($"Gateway latency: {avgRtt:F0}ms avg (min {rtts.Min():F0}ms, max {rtts.Max():F0}ms)");
                    if (avgRtt > 100)
                        sb.AppendLine("⚠ High latency — may indicate traffic is not egressing locally.");
                    else
                        sb.AppendLine("✓ Low latency — consistent with local egress.");
                }
            }
            else
            {
                sb.AppendLine("⚠ Could not resolve a validated W365 gateway.");
            }

            // Check TURN relay location
            sb.AppendLine();
            sb.AppendLine("── TURN Relay (UDP RDP Shortpath) ──");
            try
            {
                var turnHost = "world.relay.avd.microsoft.com";
                var turnIps = await Dns.GetHostAddressesAsync(turnHost);
                var turnIp = turnIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (turnIp != null)
                {
                    sb.AppendLine($"Host: {turnHost}");
                    sb.AppendLine($"IP:   {turnIp}");
                    try
                    {
                        var turnGeo = await FetchGeoIpAsync($"https://ipinfo.io/{turnIp}/json", TimeSpan.FromSeconds(5));
                        string tCity = turnGeo.TryGetProperty("city", out var tc) ? tc.GetString() ?? "" : "";
                        string tRegion = turnGeo.TryGetProperty("region", out var tr) ? tr.GetString() ?? "" : "";
                        string tCountry = turnGeo.TryGetProperty("country", out var tco) ? tco.GetString() ?? "" : "";
                        sb.AppendLine($"Location: {tCity}, {tRegion}, {tCountry}");

                        if (hasUserGeo && turnGeo.TryGetProperty("loc", out var tloc))
                        {
                            var parts = tloc.GetString()?.Split(',');
                            if (parts?.Length == 2 && double.TryParse(parts[0], out var tLat) && double.TryParse(parts[1], out var tLon))
                            {
                                var distKm = HaversineDistance(userLat, userLon, tLat, tLon);
                                sb.AppendLine($"Distance from you: ~{distKm:F0} km");

                                if (distKm > 1500)
                                    sb.AppendLine("⚠ TURN relay is far — possible backhauling or non-local egress.");
                                else
                                    sb.AppendLine("✓ TURN relay is near — local egress confirmed.");
                            }
                        }
                    }
                    catch { sb.AppendLine("Could not geolocate TURN relay."); }
                }
                else
                {
                    sb.AppendLine("⚠ Could not resolve TURN relay address.");
                }
            }
            catch (Exception ex) { sb.AppendLine($"TURN check failed: {ex.Message}"); }

            // Determine overall result
            var text = sb.ToString();
            if (text.Contains("⚠ Gateway is far") || text.Contains("⚠ TURN relay is far") || text.Contains("⚠ High latency"))
            {
                result.Status = "Warning";
                result.ResultValue = "Traffic may not be egressing locally";
                result.RemediationText = "RDP traffic appears to be backhauling through a remote network. " +
                    "Ensure local internet breakout for 40.64.144.0/20 and 51.5.0.0/16. " +
                    "This allows the nearest RDP Gateway or TURN relay to be selected.";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp#3-local-network-egress";
            }
            else if (gw == null)
            {
                result.Status = "Warning";
                result.ResultValue = "Could not validate egress path";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = "Traffic egresses locally — nearest gateway/relay in use";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>Haversine distance in km between two lat/lon points.</summary>
    static double HaversineDistance(double lat1, double lon1, double lat2, double lon2)
    {
        const double R = 6371; // Earth radius in km
        var dLat = (lat2 - lat1) * Math.PI / 180;
        var dLon = (lon2 - lon1) * Math.PI / 180;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                Math.Cos(lat1 * Math.PI / 180) * Math.Cos(lat2 * Math.PI / 180) *
                Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return R * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
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
            // Build dynamic endpoint list: rdweb + discovered RDP gateway
            var endpoints = new List<string> { "rdweb.wvd.microsoft.com" };
            var gwHost = await DiscoverRdpGatewayFromAfd();
            if (!string.IsNullOrEmpty(gwHost))
                endpoints.Add(gwHost);

            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(gwHost))
                sb.AppendLine($"Discovered RDP gateway: {gwHost}\n");
            else
                sb.AppendLine("⚠ Could not discover RDP gateway from AFD — checking rdweb only\n");

            int passed = 0;
            var issues = new List<string>();

            // Known Microsoft/Azure public IP first-octet ranges
            var knownAzureFirstOctets = new HashSet<byte> { 13, 20, 40, 51, 52, 65, 104, 131, 132, 134, 137, 138, 157, 168, 191, 204 };

            foreach (var host in endpoints)
            {
                sb.AppendLine($"  {host}");

                IPAddress[] ips;
                try
                {
                    ips = await Dns.GetHostAddressesAsync(host);
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ DNS resolution failed: {ex.Message}");
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
                        sb.AppendLine($"    ✗ {ip} → LOOPBACK — DNS is hijacked!");
                        issues.Add($"{host}: resolves to loopback {ip}");
                    }
                    else if (isLinkLocal)
                    {
                        sb.AppendLine($"    ✗ {ip} → LINK-LOCAL — DNS appears hijacked");
                        issues.Add($"{host}: resolves to link-local {ip}");
                    }
                    else if (isPrivate)
                    {
                        if (cnameHasPrivateLink || validCert)
                            sb.AppendLine($"    ✓ {ip} → Private Link (cert valid)");
                        else
                            sb.AppendLine($"    ✓ {ip} → Private IP (likely Private Link)");
                    }
                    else if (isMicrosoft || isKnownAzureRange || cnameHasAfd || validCert)
                    {
                        var reason = isMicrosoft ? rdns
                                   : isKnownAzureRange ? $"Azure IP range ({bytes[0]}.x.x.x)"
                                   : cnameHasAfd ? "AFD CNAME chain"
                                   : "valid Microsoft TLS cert";
                        sb.AppendLine($"    ✓ {ip} → {reason}");
                    }
                    else
                    {
                        sb.AppendLine($"    ⚠ {ip} → {rdns} — not a recognized Microsoft host");
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
                    sb.AppendLine($"  ⚠ {issue}");
            }

            result.ResultValue = issues.Count == 0
                ? $"All {endpoints.Count} endpoints resolve to legitimate Microsoft IPs"
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
            var sb = new StringBuilder();
            var issues = new List<string>();

            using var httpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            // ── Fetch user's location via GeoIP ──
            string userCity = null, userCountry = null;
            double userLat = 0, userLon = 0;
            try
            {
                var userGeo = await FetchGeoIpAsync("https://ipinfo.io/json", TimeSpan.FromSeconds(5));
                if (userGeo.TryGetProperty("city", out var cityProp))
                {
                    userCity = cityProp.GetString();
                    userCountry = userGeo.TryGetProperty("country", out var cProp) ? cProp.GetString() : "";
                    if (userGeo.TryGetProperty("loc", out var locProp))
                    {
                        var parts = locProp.GetString()?.Split(',');
                        if (parts?.Length == 2)
                        {
                            double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLat);
                            double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLon);
                        }
                    }
                    sb.AppendLine($"Your location: {userCity}, {userCountry}");
                    sb.AppendLine();
                }
            }
            catch { sb.AppendLine("Could not determine your location (GeoIP unavailable)\n"); }

            // ── Part 1: AFD Edge Location (anycast — use X-MSEdge-Ref for PoP) ──
            sb.AppendLine("═══ AFD Edge Location (Anycast) ═══");
            var afdHost = "afdfp-rdgateway-r1.wvd.microsoft.com";
            string afdPopCity = null;
            string discoveredGateway = null;

            try
            {
                var afdIps = await Dns.GetHostAddressesAsync(afdHost);
                sb.AppendLine($"  {afdHost}");
                sb.AppendLine($"    IP: {afdIps.First()} (anycast — cannot geolocate)");

                var afdResp = await http.GetAsync($"https://{afdHost}/");

                // Extract AFD PoP from X-MSEdge-Ref
                string edgeRef = "";
                if (afdResp.Headers.TryGetValues("X-MSEdge-Ref", out var edgeRefs))
                    edgeRef = edgeRefs.FirstOrDefault() ?? "";
                else if (afdResp.Headers.TryGetValues("x-azure-ref", out var azureRefs))
                    edgeRef = azureRefs.FirstOrDefault() ?? "";

                if (!string.IsNullOrEmpty(edgeRef))
                {
                    sb.AppendLine($"    Edge Ref: {edgeRef}");
                    var popMatch = System.Text.RegularExpressions.Regex.Match(
                        edgeRef, @"Ref\s+B:\s*([A-Z]{2,5})\d*Edge",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (popMatch.Success)
                    {
                        var popCode = popMatch.Groups[1].Value.ToUpperInvariant();
                        afdPopCity = GetAfdPopLocation(popCode);
                        var popLabel = afdPopCity != null ? $"{popCode} — {afdPopCity}" : popCode;
                        sb.AppendLine($"    AFD PoP: {popLabel}");

                        if (afdPopCity != null && userCity != null)
                            sb.AppendLine($"    → Your traffic egresses via AFD edge in {afdPopCity}");
                    }
                    else
                    {
                        sb.AppendLine($"    AFD PoP: could not parse from Edge Ref");
                    }
                }

                // Extract WVD service region
                if (afdResp.Headers.TryGetValues("x-ms-wvd-service-region", out var regionVals))
                {
                    var region = regionVals.FirstOrDefault();
                    if (!string.IsNullOrEmpty(region))
                        sb.AppendLine($"    Service Region: {region}");
                }

                // Extract discovered gateway from Set-Cookie
                if (afdResp.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        var domainMatch = System.Text.RegularExpressions.Regex.Match(
                            cookie, @"Domain=(rdgateway[^;]+\.wvd\.microsoft\.com)",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (domainMatch.Success)
                        {
                            discoveredGateway = domainMatch.Groups[1].Value;
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"    ✗ AFD unreachable: {ex.InnerException?.Message ?? ex.Message}");
                issues.Add("AFD endpoint unreachable");
            }

            sb.AppendLine();

            // ── Part 2: Actual RDP Gateway (unicast — CAN geolocate, FQDN has region) ──
            sb.AppendLine("═══ Actual RDP Gateway (Unicast) ═══");
            if (!string.IsNullOrEmpty(discoveredGateway))
            {
                sb.AppendLine($"  {discoveredGateway}");

                // Extract region from FQDN
                var regionCode = ExtractRegionFromGatewayFqdn(discoveredGateway);
                var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                if (regionName != null)
                    sb.AppendLine($"    Azure Region: {regionName} ({regionCode})");
                else if (regionCode != null)
                    sb.AppendLine($"    Azure Region Code: {regionCode}");

                try
                {
                    var gwIps = await Dns.GetHostAddressesAsync(discoveredGateway);
                    var gwIp = gwIps.First();
                    sb.AppendLine($"    IP: {gwIp}");

                    bool inRange = gwIps.Any(ip => IsInW365Range(ip));
                    if (inRange)
                        sb.AppendLine($"    → IP in W365 range ✓");

                    // Reverse DNS
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(gwIp);
                        sb.AppendLine($"    Reverse DNS: {entry.HostName}");
                    }
                    catch { sb.AppendLine($"    Reverse DNS: (none)"); }

                    // GeoIP for the unicast gateway IP — this IS meaningful (not anycast)
                    if (!IsPrivateIp(gwIp))
                    {
                        try
                        {
                            var gwGeo = await FetchGeoIpAsync($"https://ipinfo.io/{gwIp}/json", TimeSpan.FromSeconds(5));
                            if (gwGeo.TryGetProperty("city", out var gwCityProp))
                            {
                                var gwCity = gwCityProp.GetString();
                                var gwCountry = gwGeo.TryGetProperty("country", out var gwCProp) ? gwCProp.GetString() : "";
                                sb.AppendLine($"    GeoIP Location: {gwCity}, {gwCountry}");

                                // Compare gateway location to user location
                                if (userCity != null && gwGeo.TryGetProperty("loc", out var gwLocProp))
                                {
                                    var gwParts = gwLocProp.GetString()?.Split(',');
                                    if (gwParts?.Length == 2)
                                    {
                                        double.TryParse(gwParts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var gwLat);
                                        double.TryParse(gwParts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var gwLon);
                                        var distKm = HaversineDistanceKm(userLat, userLon, gwLat, gwLon);
                                        sb.AppendLine($"    Distance from you: {distKm:N0} km");
                                        if (distKm > 1500)
                                        {
                                            sb.AppendLine($"    ⚠ Gateway is far from your location — possible suboptimal routing");
                                            issues.Add($"Gateway is {distKm:N0} km from your location");
                                        }
                                    }
                                }
                            }
                        }
                        catch { sb.AppendLine($"    GeoIP: unavailable"); }
                    }
                    else
                    {
                        sb.AppendLine($"    Route: Private Link (private IP)");
                    }

                    // TLS cert
                    try
                    {
                        using var tcp = new TcpClient();
                        await tcp.ConnectAsync(gwIp, 443);
                        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                        await ssl.AuthenticateAsClientAsync(discoveredGateway);
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
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ DNS/connect failed: {ex.Message}");
                    issues.Add($"Cannot resolve/connect to gateway {discoveredGateway}");
                }
            }
            else
            {
                sb.AppendLine("  Could not discover RDP gateway from AFD Set-Cookie header");
                issues.Add("RDP gateway discovery failed");
            }

            // Build summary
            var summaryParts = new List<string>();
            if (afdPopCity != null)
                summaryParts.Add($"AFD PoP: {afdPopCity}");
            if (!string.IsNullOrEmpty(discoveredGateway))
            {
                var regionCode = ExtractRegionFromGatewayFqdn(discoveredGateway);
                var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                summaryParts.Add(regionName != null
                    ? $"Gateway: {regionName}"
                    : $"Gateway: {discoveredGateway}");
            }

            result.ResultValue = summaryParts.Any()
                ? string.Join(" | ", summaryParts)
                : "Could not determine gateway";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = issues.Count == 0 ? "Passed" : "Warning";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
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

    /// <summary>Find the default browser executable path from the Windows registry.</summary>
    static string? GetDefaultBrowserPath()
    {
        try
        {
            // Read the ProgId for HTTPS URLs from user choice
            using var userChoice = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            var progId = userChoice?.GetValue("ProgId") as string;
            if (string.IsNullOrEmpty(progId)) return null;

            // Get the shell\open\command for this ProgId
            using var cmdKey = Registry.ClassesRoot.OpenSubKey($@"{progId}\shell\open\command");
            var cmd = cmdKey?.GetValue(null) as string;
            if (string.IsNullOrEmpty(cmd)) return null;

            // Parse exe path from command like:
            //   "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument %1
            if (cmd.StartsWith('"'))
            {
                var end = cmd.IndexOf('"', 1);
                return end > 0 ? cmd[1..end] : null;
            }
            var space = cmd.IndexOf(' ');
            return space > 0 ? cmd[..space] : cmd;
        }
        catch
        {
            return null;
        }
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
