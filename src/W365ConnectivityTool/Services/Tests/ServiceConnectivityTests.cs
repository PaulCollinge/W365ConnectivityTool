using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Services.Tests;

// ════════════════════════════════════════════════════════════════════
// RDP file parser — extracts gateway info from local RDP files
// ════════════════════════════════════════════════════════════════════
public static class RdpFileParser
{
    /// <summary>
    /// Represents a parsed RDP connection entry.
    /// AfdHostname = the Azure Front Door endpoint (from gatewayhostname:s:)
    /// GatewayHostname = the actual RD Gateway (from full address:s:)
    /// </summary>
    public record RdpConnectionInfo(
        string? AfdHostname,        // e.g. afdfp-rdgateway-r0.wvd.microsoft.com
        int AfdPort,                // typically 443
        string GatewayHostname,     // e.g. rdgateway-r0.wvd.microsoft.com  (from "full address")
        string? Geo,                // e.g. GB
        string SourceFile,
        DateTime LastModified);

    /// <summary>
    /// Scans known Windows App / Remote Desktop client / Windows 365 RDP file
    /// locations and extracts gateway + AFD info from each.
    /// Returns distinct entries ordered by most recently modified.
    /// </summary>
    private static List<RdpConnectionInfo>? _cachedConnections;
    private static readonly object _cacheLock = new();

    /// <summary>
    /// Returns cached RDP connections, scanning only once per app lifetime.
    /// </summary>
    public static List<RdpConnectionInfo> DiscoverConnections()
    {
        lock (_cacheLock)
        {
            if (_cachedConnections != null) return _cachedConnections;
            _cachedConnections = DiscoverConnectionsInternal();
            return _cachedConnections;
        }
    }

    private static List<RdpConnectionInfo> DiscoverConnectionsInternal()
    {
        var results = new List<RdpConnectionInfo>();
        var searchPaths = EndpointConfiguration.GetRdpFileSearchPaths();

        foreach (var basePath in searchPaths)
        {
            if (!Directory.Exists(basePath)) continue;

            IEnumerable<string> rdpFiles;
            try
            {
                rdpFiles = Directory.EnumerateFiles(basePath, "*.rdp", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in rdpFiles)
            {
                try
                {
                    var lines = File.ReadAllLines(filePath);
                    string? afdHostname = null;    // gatewayhostname:s: field = AFD
                    string? fullAddress = null;    // full address:s: field  = actual RD Gateway
                    string? geo = null;

                    foreach (var line in lines)
                    {
                        if (line.StartsWith("gatewayhostname:s:", StringComparison.OrdinalIgnoreCase))
                            afdHostname = line["gatewayhostname:s:".Length..];
                        else if (line.StartsWith("full address:s:", StringComparison.OrdinalIgnoreCase))
                            fullAddress = line["full address:s:".Length..];
                        else if (line.StartsWith("geo:s:", StringComparison.OrdinalIgnoreCase))
                            geo = line["geo:s:".Length..];
                    }

                    if (string.IsNullOrWhiteSpace(fullAddress) && string.IsNullOrWhiteSpace(afdHostname))
                        continue;

                    // Parse AFD hostname — may include :port
                    string? afdHost = null;
                    var afdPort = 443;
                    if (!string.IsNullOrWhiteSpace(afdHostname))
                    {
                        afdHost = afdHostname;
                        var colonIdx = afdHostname.LastIndexOf(':');
                        if (colonIdx > 0 && int.TryParse(afdHostname[(colonIdx + 1)..], out var parsedPort))
                        {
                            afdHost = afdHostname[..colonIdx];
                            afdPort = parsedPort;
                        }
                    }

                    results.Add(new RdpConnectionInfo(
                        afdHost, afdPort,
                        fullAddress ?? "unknown",
                        geo,
                        filePath,
                        File.GetLastWriteTime(filePath)));
                }
                catch { /* skip unreadable files */ }
            }
        }

        // Return distinct by gateway hostname, most recently modified first
        return results
            .Where(r => r.GatewayHostname != "unknown")
            .GroupBy(r => r.GatewayHostname)
            .Select(g => g.OrderByDescending(x => x.LastModified).First())
            .OrderByDescending(r => r.LastModified)
            .ToList();
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10g – TCP Based Connectivity (gateway reachability)
// ════════════════════════════════════════════════════════════════════
public class GatewayReachabilityTest : BaseTest
{
    public override string Id => "10";
    public override string Name => "TCP Based Connectivity";
    public override string Description => "Resolves the RD Gateway via Traffic Manager (nearest region) and tests TCP 443 + TLS handshake to verify the gateway is reachable.";
    public override TestCategory Category => TestCategory.TcpTransport;

    internal const string GatewayFqdn = "rdgateway-r1.wvd.microsoft.com";
    internal const string GatewayFqdnFallback = "rdgateway-r0.wvd.microsoft.com";

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();
        details.Add("Resolving gateway via Traffic Manager...");
        details.Add("");

        string? connectedGateway = null;
        long? latencyMs = null;
        string? resolvedIp = null;
        string? cnameTarget = null;

        foreach (var fqdn in new[] { GatewayFqdn, GatewayFqdnFallback })
        {
            details.Add($"── {fqdn} ──");

            try
            {
                // DNS resolution — Traffic Manager routes to nearest region
                var addresses = await Dns.GetHostAddressesAsync(fqdn, ct);
                var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ipv4 == null)
                {
                    details.Add("  ✗ No IPv4 address resolved");
                    details.Add("");
                    continue;
                }

                resolvedIp = ipv4.ToString();

                // Get CNAME to show the regional gateway
                try
                {
                    var entry = await Dns.GetHostEntryAsync(fqdn, ct);
                    if (entry.HostName != fqdn)
                        cnameTarget = entry.HostName;
                }
                catch { /* non-fatal */ }

                details.Add($"  Resolved: {resolvedIp}{(cnameTarget != null ? $" (via {cnameTarget})" : "")}");

                // TCP 443 connect
                var sw = Stopwatch.StartNew();
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(ipv4, EndpointConfiguration.GatewayPort, cts.Token);
                sw.Stop();

                latencyMs = sw.ElapsedMilliseconds;
                connectedGateway = fqdn;
                details.Add($"  ✓ TCP 443 connected in {latencyMs}ms");

                // TLS handshake
                try
                {
                    using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = fqdn
                    }, cts.Token);
                    details.Add($"  ✓ TLS handshake successful ({ssl.SslProtocol})");
                }
                catch (Exception tlsEx)
                {
                    details.Add($"  ⚠ TLS handshake failed: {tlsEx.Message}");
                }

                details.Add("");
                break;
            }
            catch (OperationCanceledException)
            {
                details.Add("  ✗ Connection timed out (5s)");
                details.Add("");
            }
            catch (Exception ex)
            {
                details.Add($"  ✗ {ex.Message}");
                details.Add("");
            }
        }

        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;

        // Detect Private Link — resolved IP is a private address
        var isPrivateLink = resolvedIp != null && IsPrivateLinkIp(resolvedIp);

        if (connectedGateway != null)
        {
            result.Status = TestStatus.Passed;
            var plNote = isPrivateLink ? " [Private Link]" : "";
            result.ResultValue = $"Connected — {latencyMs}ms ({resolvedIp}){plNote}";
            if (isPrivateLink)
                result.DetailedInfo += "\n\nℹ Private Link detected — gateway resolved to a private IP.\n" +
                                       "This is a supported configuration. TCP connectivity was verified via the private endpoint.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Cannot reach gateway";
            result.RemediationText = isPrivateLink
                ? "TCP 443 connection to the AVD gateway private endpoint failed. " +
                  "Verify Private Link connectivity and that the private endpoint is healthy."
                : "TCP 443 connection to the AVD gateway failed. " +
                  "Ensure your firewall allows TCP 443 to *.wvd.microsoft.com (40.64.144.0/20).";
        }
    }

    private static bool IsPrivateLinkIp(string ip)
    {
        return ip.StartsWith("10.") ||
               ip.StartsWith("192.168.") ||
               System.Text.RegularExpressions.Regex.IsMatch(ip, @"^172\.(1[6-9]|2[0-9]|3[01])\.");
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10b – User Location (geo-IP lookup of user's public IP)
// ════════════════════════════════════════════════════════════════════
public class UserLocationTest : BaseTest
{
    public override string Id => "10b";
    public override string Name => "User Location";
    public override string Description => "Determines the user's physical location via public IP geo-lookup. Compare with Network Egress and Gateway locations to detect backhauled traffic.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var json = await http.GetStringAsync(EndpointConfiguration.GeoIpApiUrl, ct);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("status", out var status) && status.GetString() == "success")
        {
            var city = root.GetProperty("city").GetString();
            var region = root.TryGetProperty("regionName", out var regionVal) ? regionVal.GetString() : null;
            var country = root.GetProperty("country").GetString();
            var ip = root.GetProperty("query").GetString();
            var isp = root.TryGetProperty("isp", out var ispVal) ? ispVal.GetString() : null;

            result.ResultValue = $"{city}, {country}";
            result.DetailedInfo = $"Public IP: {ip}\n" +
                                  $"Location: {city}, {region}, {country}\n" +
                                  (isp != null ? $"ISP: {isp}\n" : "");

            // Emit lat/lon for the connectivity map
            if (root.TryGetProperty("lat", out var latVal) && root.TryGetProperty("lon", out var lonVal))
            {
                result.DetailedInfo += $"GeoData: lat={latVal.GetDouble():F4},lon={lonVal.GetDouble():F4}\n";
            }

            result.DetailedInfo += "\nThis is where your public IP address geolocates to.\n" +
                                  "Compare with Network Egress Location to verify traffic exits locally.";
            result.Status = TestStatus.Passed;
        }
        else
        {
            result.ResultValue = "Unable to determine location";
            result.Status = TestStatus.Warning;
            result.RemediationText = "Geo-IP lookup failed. This is informational only.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10e – Network Egress Location (where does your internet traffic exit?)
// ════════════════════════════════════════════════════════════════════
public class NetworkEgressLocationTest : BaseTest
{
    public override string Id => "10e";
    public override string Name => "Network Egress Location";
    public override string Description => "Detects where your internet traffic enters the Microsoft network. The AFD edge PoP reveals your true internet egress point — if it doesn't match your physical location, traffic is being backhauled.";
    public override TestCategory Category => TestCategory.TcpTransport;

    internal const string AfdFqdn = "afdfp-rdgateway-r1.wvd.microsoft.com";

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();
        details.Add($"Endpoint: {AfdFqdn}");

        // Detect Private Link — if AFD FQDN resolves to a private IP, these checks aren't applicable
        try
        {
            var plAddresses = await Dns.GetHostAddressesAsync(AfdFqdn, ct);
            var plIp = plAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (plIp != null)
            {
                var bytes = plIp.GetAddressBytes();
                if (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168))
                {
                    details.Add($"Resolved IP: {plIp} (private)");
                    details.Add("");
                    details.Add("ℹ Private Link detected — AFD FQDN resolves to a private endpoint.");
                    details.Add("Network egress location cannot be determined via AFD headers");
                    details.Add("when traffic routes through Private Link.");
                    result.Status = TestStatus.Passed;
                    result.ResultValue = "Private Link — egress test N/A";
                    result.DetailedInfo = string.Join("\n", details);
                    result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
                    return;
                }
            }
        }
        catch { /* non-fatal, continue with normal test */ }

        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var sw = Stopwatch.StartNew();
            var response = await http.GetAsync($"https://{AfdFqdn}/", ct);
            sw.Stop();

            details.Add($"HTTPS: {(int)response.StatusCode} ({sw.ElapsedMilliseconds}ms)");

            // Parse X-MSEdge-Ref for PoP code — this reveals the AFD edge node
            // that received the request, i.e. where the user's traffic exits to the internet
            if (response.Headers.TryGetValues("X-MSEdge-Ref", out var edgeRefs))
            {
                var edgeRef = edgeRefs.FirstOrDefault() ?? "";
                details.Add($"X-MSEdge-Ref: {edgeRef}");

                var refBMatch = System.Text.RegularExpressions.Regex.Match(
                    edgeRef, @"Ref B:\s*([A-Z]{2,5})\d*EDGE");
                if (refBMatch.Success)
                {
                    var popCode = refBMatch.Groups[1].Value;
                    var popCity = AfdEgressLocationTest.GetPopLocation(popCode);
                    var popCountry = AfdEgressLocationTest.GetPopCountryCode(popCode);

                    details.Add($"AFD PoP: {popCode}");
                    details.Add($"Edge location: {popCity ?? "Unknown"}");
                    if (popCountry != null)
                        details.Add($"Country: {AfdEgressLocationTest.GetPopCountryName(popCode) ?? popCountry}");

                    details.Add("");
                    details.Add("The AFD PoP is the nearest Microsoft edge node to your");
                    details.Add("internet egress point. If this doesn't match your physical");
                    details.Add("location, your traffic may be backhauled via VPN/proxy/SASE.");

                    result.Status = TestStatus.Passed;
                    result.ResultValue = $"{popCode} — {popCity ?? "Unknown"}";
                }
                else
                {
                    details.Add("⚠ Could not extract PoP code from X-MSEdge-Ref header");
                    result.Status = TestStatus.Warning;
                    result.ResultValue = "PoP code not found in header";
                    result.RemediationText = "The AFD response did not contain a recognisable PoP code.";
                }
            }
            else
            {
                details.Add("⚠ No X-MSEdge-Ref header in response");
                result.Status = TestStatus.Warning;
                result.ResultValue = "No edge header returned";
                result.RemediationText = "The AFD endpoint did not return an X-MSEdge-Ref header.";
            }
        }
        catch (Exception ex)
        {
            details.Add($"✗ Request failed: {ex.Message}");
            result.Status = TestStatus.Failed;
            result.ResultValue = "Cannot reach AFD endpoint";
            result.RemediationText = "Could not connect to the AFD endpoint. Check firewall rules for *.wvd.microsoft.com on TCP 443.";
        }

        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10f – AFD Service Location (which AVD backend region?)
// ════════════════════════════════════════════════════════════════════
public class AfdServiceLocationTest : BaseTest
{
    public override string Id => "10f";
    public override string Name => "AFD Location";
    public override string Description => "Shows which AVD service region Azure Front Door routes your connection to, based on the x-ms-wvd-service-region response header.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();
        details.Add($"Endpoint: {NetworkEgressLocationTest.AfdFqdn}");

        // Detect Private Link — if AFD FQDN resolves to a private IP, headers may differ
        try
        {
            var plAddresses = await Dns.GetHostAddressesAsync(NetworkEgressLocationTest.AfdFqdn, ct);
            var plIp = plAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (plIp != null)
            {
                var bytes = plIp.GetAddressBytes();
                if (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168))
                {
                    details.Add($"Resolved IP: {plIp} (private)");
                    details.Add("");
                    details.Add("ℹ Private Link detected — AFD FQDN resolves to a private endpoint.");
                    details.Add("Service region detection via AFD headers is not applicable");
                    details.Add("when traffic routes through Private Link.");
                    result.Status = TestStatus.Passed;
                    result.ResultValue = "Private Link — service region test N/A";
                    result.DetailedInfo = string.Join("\n", details);
                    result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
                    return;
                }
            }
        }
        catch { /* non-fatal, continue with normal test */ }

        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var response = await http.GetAsync($"https://{NetworkEgressLocationTest.AfdFqdn}/", ct);

            // Extract x-ms-wvd-service-region
            if (response.Headers.TryGetValues("x-ms-wvd-service-region", out var regionValues))
            {
                var serviceRegion = regionValues.FirstOrDefault();
                var regionName = AfdEgressLocationTest.GetAzureRegionName(serviceRegion);
                var regionCountry = AfdEgressLocationTest.GetAzureRegionCountryCode(serviceRegion);

                details.Add($"Service region code: {serviceRegion}");
                details.Add($"Region: {regionName ?? "Unknown"}");
                if (regionCountry != null)
                    details.Add($"Country: {regionCountry}");

                // Also extract backend gateway from Set-Cookie domain
                if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    var cookieStr = string.Join("; ", cookies);
                    var domainMatch = System.Text.RegularExpressions.Regex.Match(cookieStr, @"Domain=([^;,\s]+)");
                    if (domainMatch.Success)
                    {
                        details.Add($"Backend host: {domainMatch.Groups[1].Value}");
                    }
                }

                details.Add("");
                details.Add("This is the AVD service region that Azure Front Door");
                details.Add("has routed your connection to.");

                result.Status = TestStatus.Passed;
                result.ResultValue = $"{serviceRegion} — {regionName ?? "Unknown"}";
            }
            else
            {
                details.Add("⚠ No x-ms-wvd-service-region header in response");
                result.Status = TestStatus.Warning;
                result.ResultValue = "Service region header not found";
                result.RemediationText = "The AFD response did not include a service region header.";
            }
        }
        catch (Exception ex)
        {
            details.Add($"✗ Request failed: {ex.Message}");
            result.Status = TestStatus.Failed;
            result.ResultValue = "Cannot reach AFD endpoint";
            result.RemediationText = "Could not connect to the AFD endpoint. Check firewall rules for *.wvd.microsoft.com on TCP 443.";
        }

        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10d – DNS Hijacking Check for TCP-based connectivity
// ════════════════════════════════════════════════════════════════════
public class DnsHijackingTest : BaseTest
{
    public override string Id => "10d";
    public override string Name => "DNS Hijacking Check";
    public override string Description => "Verifies that gateway DNS resolves to the expected Azure IP range (40.64.144.0/20). Detects DNS hijacking (e.g. by GSA/SASE) and identifies Private Link configurations.";
    public override TestCategory Category => TestCategory.TcpTransport;

    // 40.64.144.0/20 = 40.64.144.0 – 40.64.159.255
    private const uint ExpectedRangeStart = (40u << 24) | (64u << 16) | (144u << 8);  // 40.64.144.0
    private const uint ExpectedRangeMask  = 0xFFFFF000u; // /20

    private static uint IpToUint(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static bool IsInExpectedRange(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        return (IpToUint(ip) & ExpectedRangeMask) == (ExpectedRangeStart & ExpectedRangeMask);
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||                                       // 10.0.0.0/8
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || // 172.16.0.0/12
               (bytes[0] == 192 && bytes[1] == 168);                    // 192.168.0.0/16
    }

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var connections = RdpFileParser.DiscoverConnections();
        var gatewayFqdns = connections
            .Where(c => c.GatewayHostname.EndsWith(".wvd.microsoft.com", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.GatewayHostname)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (gatewayFqdns.Count == 0)
        {
            // Fall back to well-known gateways
            gatewayFqdns = ["rdgateway-r0.wvd.microsoft.com", "rdgateway-r1.wvd.microsoft.com"];
        }

        var details = new List<string>();
        var allOk = true;
        var anyHijacked = false;
        var anyPrivateLink = false;

        foreach (var fqdn in gatewayFqdns)
        {
            details.Add($"── {fqdn} ──");

            try
            {
                // Step 1: Get full CNAME chain to detect privatelink
                var cnameChain = await GetCnameChainAsync(fqdn, ct);
                var hasPrivateLinkCname = cnameChain.Any(c =>
                    c.Contains(".privatelink.", StringComparison.OrdinalIgnoreCase));

                if (cnameChain.Count > 0)
                    details.Add($"  CNAME chain: {fqdn} → {string.Join(" → ", cnameChain)}");

                // Step 2: Resolve to IP
                var addresses = await Dns.GetHostAddressesAsync(fqdn, ct);
                var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

                if (ipv4 == null)
                {
                    details.Add("  ✗ No IPv4 address resolved");
                    allOk = false;
                    continue;
                }

                details.Add($"  Resolved IP: {ipv4}");

                // Step 3: Classify the result
                if (IsInExpectedRange(ipv4))
                {
                    details.Add($"  ✓ IP is within expected range 40.64.144.0/20");
                    details.Add("");
                }
                else if (IsPrivateIp(ipv4) && hasPrivateLinkCname)
                {
                    // Private Link — legitimate scenario
                    anyPrivateLink = true;
                    details.Add($"  ℹ Private Link detected — private IP {ipv4} with privatelink CNAME");
                    details.Add($"    This is a supported configuration for Private Link environments.");
                    details.Add("");
                }
                else if (IsPrivateIp(ipv4))
                {
                    // Private IP but no privatelink CNAME — possible DNS override
                    anyPrivateLink = true;
                    allOk = false;
                    details.Add($"  ⚠ Private IP {ipv4} without privatelink CNAME — verify this is intentional");
                    details.Add($"    Could be Private Link without standard CNAME, or DNS override.");
                    details.Add("");
                }
                else
                {
                    // Public IP but NOT in expected range — DNS hijacking
                    anyHijacked = true;
                    allOk = false;
                    details.Add($"  ✗ IP {ipv4} is NOT in expected range 40.64.144.0/20");
                    details.Add($"    DNS appears to be hijacked — possibly by a GSA/SASE/SWG solution");
                    details.Add($"    redirecting gateway traffic through a proxy.");
                    details.Add("");
                }
            }
            catch (Exception ex)
            {
                details.Add($"  ✗ DNS resolution failed: {ex.Message}");
                details.Add("");
                allOk = false;
            }
        }

        details.Add($"Expected IP range: 40.64.144.0/20 (40.64.144.0 – 40.64.159.255)");
        result.DetailedInfo = string.Join("\n", details);

        if (anyHijacked)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "DNS hijacking detected";
            result.RemediationText = "Gateway DNS is resolving to IPs outside the expected Azure range. " +
                "This typically means a Global Secure Access (GSA), SASE, or SWG solution is intercepting gateway traffic. " +
                "This can cause connection failures or poor performance. Exclude *.wvd.microsoft.com from DNS interception.";
        }
        else if (anyPrivateLink)
        {
            result.Status = allOk ? TestStatus.Passed : TestStatus.Warning;
            result.ResultValue = "Private Link configuration detected";
            result.RemediationText = allOk
                ? "Gateway resolves via Private Link — this is a supported configuration."
                : "Private IP detected but CNAME chain doesn't follow standard Private Link pattern. Verify configuration.";
        }
        else if (allOk)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "DNS integrity verified ✓";
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Some gateways could not be verified";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }

    /// <summary>
    /// Walks the CNAME chain for an FQDN by doing iterative CNAME lookups.
    /// </summary>
    private static async Task<List<string>> GetCnameChainAsync(string fqdn, CancellationToken ct)
    {
        var chain = new List<string>();
        var current = fqdn;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };

        for (int i = 0; i < 10; i++) // max 10 hops
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var entry = await Dns.GetHostEntryAsync(current, ct);
                if (entry.HostName != current && !seen.Contains(entry.HostName))
                {
                    chain.Add(entry.HostName);
                    seen.Add(entry.HostName);
                    current = entry.HostName;
                }
                else
                {
                    break;
                }
            }
            catch
            {
                break;
            }
        }

        return chain;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 10a – AFD Egress Location
// ════════════════════════════════════════════════════════════════════
public class AfdEgressLocationTest : BaseTest
{
    public override string Id => "10a";
    public override string Name => "AFD Egress Location";
    public override string Description => "Connects to the Azure Front Door (AFD) endpoint and reads the X-MSEdge-Ref header to determine which AFD PoP (Point of Presence) handled the request. A non-local PoP indicates internet egress from a distant location.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var connections = RdpFileParser.DiscoverConnections();
        var details = new List<string>();

        // Collect unique AFD hostnames
        var afdEndpoints = connections
            .Where(c => !string.IsNullOrWhiteSpace(c.AfdHostname))
            .Select(c => (Host: c.AfdHostname!, Port: c.AfdPort, Geo: c.Geo))
            .GroupBy(a => a.Host, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        if (afdEndpoints.Count == 0)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "No AFD endpoints found";
            result.DetailedInfo = "No RDP files with gatewayhostname (AFD) field found.\nConnect via Windows App at least once to generate RDP files.";
            return;
        }

        // Get user's own geo location for comparison
        string? userCountry = null;
        string? userCity = null;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var geoJson = await http.GetStringAsync(EndpointConfiguration.GeoIpApiUrl, ct);
            using var doc = JsonDocument.Parse(geoJson);
            var root = doc.RootElement;
            if (root.TryGetProperty("country", out var c)) userCountry = c.GetString();
            if (root.TryGetProperty("city", out var ci)) userCity = ci.GetString();
        }
        catch { /* geo lookup failure is non-fatal */ }

        details.Add($"User location: {userCity ?? "?"}, {userCountry ?? "?"}");
        details.Add("");

        var allLocal = true;
        var anySuccess = false;

        foreach (var afd in afdEndpoints)
        {
            details.Add($"AFD Endpoint: {afd.Host}:{afd.Port}");
            details.Add($"  RDP geo hint: {afd.Geo ?? "unknown"}");

            try
            {
                // Make HTTPS request to AFD and read the response headers
                using var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

                var sw = Stopwatch.StartNew();
                var response = await http.GetAsync($"https://{afd.Host}/", ct);
                sw.Stop();

                details.Add($"  HTTPS response: {(int)response.StatusCode} ({sw.ElapsedMilliseconds}ms)");
                anySuccess = true;

                // Extract X-MSEdge-Ref — contains PoP code in "Ref B: <POP>EDGE..."
                string? popCode = null;
                string? popCity = null;
                if (response.Headers.TryGetValues("X-MSEdge-Ref", out var edgeRefs))
                {
                    var edgeRef = edgeRefs.FirstOrDefault() ?? "";
                    details.Add($"  X-MSEdge-Ref: {edgeRef}");

                    // Parse PoP from "Ref B: LON04EDGE0820" format
                    var refBMatch = System.Text.RegularExpressions.Regex.Match(edgeRef, @"Ref B:\s*([A-Z]{2,5})\d*EDGE");
                    if (refBMatch.Success)
                    {
                        popCode = refBMatch.Groups[1].Value;
                        popCity = GetPopLocation(popCode);
                        details.Add($"  AFD PoP code: {popCode}");
                        details.Add($"  AFD PoP location: {popCity ?? "Unknown"}");
                    }
                }

                // Extract x-ms-wvd-service-region — e.g. "UKS" (UK South)
                string? serviceRegion = null;
                if (response.Headers.TryGetValues("x-ms-wvd-service-region", out var regionValues))
                {
                    serviceRegion = regionValues.FirstOrDefault();
                    var regionName = GetAzureRegionName(serviceRegion);
                    details.Add($"  WVD service region: {serviceRegion} ({regionName})");
                }

                // Extract gateway info from Set-Cookie domain
                if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    var cookieStr = string.Join("; ", cookies);
                    var domainMatch = System.Text.RegularExpressions.Regex.Match(cookieStr, @"Domain=([^;,\s]+)");
                    if (domainMatch.Success)
                    {
                        details.Add($"  Backend gateway: {domainMatch.Groups[1].Value}");
                    }
                }

                // Determine if egress is local
                var isLocal = IsEgressLocal(popCode, popCity, afd.Geo, userCountry);

                if (isLocal)
                {
                    details.Add($"  ✓ AFD edge is local — egress looks correct");
                }
                else if (popCode != null)
                {
                    details.Add($"  ⚠ AFD edge may NOT be local");
                    details.Add($"    AFD PoP: {popCode} ({popCity ?? "?"})");
                    details.Add($"    Expected geo: {afd.Geo ?? "?"} / {userCountry ?? "?"}");
                    allLocal = false;
                }
                else
                {
                    details.Add($"  ⚠ Could not determine AFD edge location from headers");
                }
            }
            catch (Exception ex)
            {
                details.Add($"  ✗ Error: {ex.Message}");
            }

            details.Add("");
        }

        result.DetailedInfo = string.Join("\n", details);

        if (!anySuccess)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Cannot reach AFD endpoints";
            result.RemediationText = "Azure Front Door is unreachable. Check firewall rules for TCP 443 to *.wvd.microsoft.com.";
        }
        else if (allLocal)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "AFD egress is local";
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "Non-local AFD egress detected";
            result.RemediationText = "Your traffic is reaching a distant Azure Front Door edge node. This suggests non-local internet egress (e.g. VPN/proxy backhauling traffic to another country). For best performance, ensure internet traffic exits locally near the user.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }

    /// <summary>
    /// Checks whether the detected PoP is local to the user based on geo hint and country.
    /// </summary>
    private static bool IsEgressLocal(string? popCode, string? popCity, string? geoHint, string? userCountry)
    {
        if (popCode == null) return true; // can't determine, assume OK

        // Check if PoP code maps to the same country as the RDP geo hint
        if (geoHint != null)
        {
            var popCountry = GetPopCountryCode(popCode);
            if (popCountry != null && popCountry.Equals(geoHint, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Check if PoP city/country matches user's country
        if (userCountry != null && popCity != null)
        {
            var popCountryName = GetPopCountryName(popCode);
            if (popCountryName != null && userCountry.Contains(popCountryName, StringComparison.OrdinalIgnoreCase))
                return true;
            if (popCountryName != null && popCountryName.Contains(userCountry, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Maps Azure Front Door PoP codes to city names.
    /// Based on https://learn.microsoft.com/azure/frontdoor/edge-locations-by-abbreviation
    /// </summary>
    internal static string? GetPopLocation(string? popCode)
    {
        if (popCode == null) return null;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Europe
            ["LON"] = "London, UK", ["LHR"] = "London, UK", ["LTS"] = "London, UK",
            ["MAN"] = "Manchester, UK", ["EDG"] = "Edinburgh, UK",
            ["DUB"] = "Dublin, Ireland", ["AMS"] = "Amsterdam, Netherlands",
            ["FRA"] = "Frankfurt, Germany", ["BER"] = "Berlin, Germany",
            ["MUC"] = "Munich, Germany", ["PAR"] = "Paris, France",
            ["MRS"] = "Marseille, France", ["MAD"] = "Madrid, Spain",
            ["BCN"] = "Barcelona, Spain", ["MIL"] = "Milan, Italy",
            ["ROM"] = "Rome, Italy", ["ZRH"] = "Zurich, Switzerland",
            ["GVA"] = "Geneva, Switzerland", ["VIE"] = "Vienna, Austria",
            ["CPH"] = "Copenhagen, Denmark", ["HEL"] = "Helsinki, Finland",
            ["OSL"] = "Oslo, Norway", ["STO"] = "Stockholm, Sweden",
            ["WAW"] = "Warsaw, Poland", ["PRG"] = "Prague, Czech Republic",
            ["BUD"] = "Budapest, Hungary", ["BUH"] = "Bucharest, Romania",
            ["SOF"] = "Sofia, Bulgaria", ["ATH"] = "Athens, Greece",
            ["LIS"] = "Lisbon, Portugal", ["BRU"] = "Brussels, Belgium",
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
            ["YYZ"] = "Toronto, Canada", ["YUL"] = "Montreal, Canada",
            ["YVR"] = "Vancouver, Canada", ["QRO"] = "Queretaro, Mexico",
            // Asia Pacific
            ["SIN"] = "Singapore", ["HKG"] = "Hong Kong",
            ["NRT"] = "Tokyo, Japan", ["KIX"] = "Osaka, Japan",
            ["ICN"] = "Seoul, South Korea", ["TPE"] = "Taipei, Taiwan",
            ["BOM"] = "Mumbai, India", ["MAA"] = "Chennai, India",
            ["DEL"] = "New Delhi, India", ["HYD"] = "Hyderabad, India",
            ["BNE"] = "Brisbane, Australia", ["SYD"] = "Sydney, Australia",
            ["MEL"] = "Melbourne, Australia", ["PER"] = "Perth, Australia",
            ["AKL"] = "Auckland, New Zealand",
            // Middle East & Africa
            ["JNB"] = "Johannesburg, South Africa", ["CPT"] = "Cape Town, South Africa",
            ["DXB"] = "Dubai, UAE", ["AUH"] = "Abu Dhabi, UAE",
            ["FJR"] = "Fujairah, UAE", ["DOH"] = "Doha, Qatar",
            ["BAH"] = "Bahrain", ["TLV"] = "Tel Aviv, Israel",
            ["RUH"] = "Riyadh, Saudi Arabia", ["JED"] = "Jeddah, Saudi Arabia",
            // South America
            ["GRU"] = "São Paulo, Brazil", ["GIG"] = "Rio de Janeiro, Brazil",
            ["CWB"] = "Curitiba, Brazil", ["SCL"] = "Santiago, Chile",
            ["BOG"] = "Bogota, Colombia", ["EZE"] = "Buenos Aires, Argentina",
            ["LIM"] = "Lima, Peru"
        };
        return map.TryGetValue(popCode, out var city) ? city : null;
    }

    /// <summary>
    /// Maps PoP code to 2-letter country code for comparison with RDP geo hint.
    /// </summary>
    internal static string? GetPopCountryCode(string? popCode)
    {
        if (popCode == null) return null;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["LON"] = "GB", ["LHR"] = "GB", ["LTS"] = "GB", ["MAN"] = "GB", ["EDG"] = "GB",
            ["DUB"] = "IE", ["AMS"] = "NL", ["FRA"] = "DE", ["BER"] = "DE", ["MUC"] = "DE",
            ["PAR"] = "FR", ["MRS"] = "FR", ["MAD"] = "ES", ["BCN"] = "ES",
            ["MIL"] = "IT", ["ROM"] = "IT", ["ZRH"] = "CH", ["GVA"] = "CH",
            ["VIE"] = "AT", ["CPH"] = "DK", ["HEL"] = "FI", ["OSL"] = "NO",
            ["STO"] = "SE", ["WAW"] = "PL", ["PRG"] = "CZ", ["BUD"] = "HU",
            ["BUH"] = "RO", ["SOF"] = "BG", ["ATH"] = "GR", ["LIS"] = "PT", ["BRU"] = "BE",
            ["IAD"] = "US", ["DCA"] = "US", ["JFK"] = "US", ["EWR"] = "US",
            ["BOS"] = "US", ["PHL"] = "US", ["ATL"] = "US", ["MIA"] = "US",
            ["ORD"] = "US", ["DFW"] = "US", ["IAH"] = "US", ["PHX"] = "US",
            ["LAX"] = "US", ["SJC"] = "US", ["SEA"] = "US", ["DEN"] = "US",
            ["MSP"] = "US", ["SLC"] = "US",
            ["YYZ"] = "CA", ["YUL"] = "CA", ["YVR"] = "CA", ["QRO"] = "MX",
            ["SIN"] = "SG", ["HKG"] = "HK", ["NRT"] = "JP", ["KIX"] = "JP",
            ["ICN"] = "KR", ["TPE"] = "TW",
            ["BOM"] = "IN", ["MAA"] = "IN", ["DEL"] = "IN", ["HYD"] = "IN",
            ["BNE"] = "AU", ["SYD"] = "AU", ["MEL"] = "AU", ["PER"] = "AU",
            ["AKL"] = "NZ",
            ["JNB"] = "ZA", ["CPT"] = "ZA", ["DXB"] = "AE", ["AUH"] = "AE",
            ["FJR"] = "AE", ["DOH"] = "QA", ["BAH"] = "BH", ["TLV"] = "IL",
            ["RUH"] = "SA", ["JED"] = "SA",
            ["GRU"] = "BR", ["GIG"] = "BR", ["CWB"] = "BR",
            ["SCL"] = "CL", ["BOG"] = "CO", ["EZE"] = "AR", ["LIM"] = "PE"
        };
        return map.TryGetValue(popCode, out var code) ? code : null;
    }

    /// <summary>
    /// Maps PoP code to country name for comparison with user's geo-IP country.
    /// </summary>
    internal static string? GetPopCountryName(string? popCode)
    {
        var code = GetPopCountryCode(popCode);
        if (code == null) return null;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["GB"] = "United Kingdom", ["IE"] = "Ireland", ["NL"] = "Netherlands",
            ["DE"] = "Germany", ["FR"] = "France", ["ES"] = "Spain", ["IT"] = "Italy",
            ["CH"] = "Switzerland", ["AT"] = "Austria", ["DK"] = "Denmark",
            ["FI"] = "Finland", ["NO"] = "Norway", ["SE"] = "Sweden",
            ["PL"] = "Poland", ["CZ"] = "Czech Republic", ["HU"] = "Hungary",
            ["RO"] = "Romania", ["BG"] = "Bulgaria", ["GR"] = "Greece",
            ["PT"] = "Portugal", ["BE"] = "Belgium",
            ["US"] = "United States", ["CA"] = "Canada", ["MX"] = "Mexico",
            ["SG"] = "Singapore", ["HK"] = "Hong Kong", ["JP"] = "Japan",
            ["KR"] = "South Korea", ["TW"] = "Taiwan",
            ["IN"] = "India", ["AU"] = "Australia", ["NZ"] = "New Zealand",
            ["ZA"] = "South Africa", ["AE"] = "United Arab Emirates",
            ["QA"] = "Qatar", ["BH"] = "Bahrain", ["IL"] = "Israel", ["SA"] = "Saudi Arabia",
            ["BR"] = "Brazil", ["CL"] = "Chile", ["CO"] = "Colombia",
            ["AR"] = "Argentina", ["PE"] = "Peru"
        };
        return map.TryGetValue(code, out var name) ? name : null;
    }

    /// <summary>
    /// Maps Azure region short codes (from x-ms-wvd-service-region header) to friendly names.
    /// </summary>
    internal static string GetAzureRegionName(string? regionCode)
    {
        if (regionCode == null) return "Unknown";
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["UKS"] = "UK South", ["UKW"] = "UK West",
            ["NEU"] = "North Europe (Ireland)", ["WEU"] = "West Europe (Netherlands)",
            ["EUS"] = "East US", ["EUS2"] = "East US 2",
            ["WUS"] = "West US", ["WUS2"] = "West US 2", ["WUS3"] = "West US 3",
            ["CUS"] = "Central US", ["NCUS"] = "North Central US", ["SCUS"] = "South Central US",
            ["WCUS"] = "West Central US",
            ["CC"] = "Canada Central", ["CE"] = "Canada East",
            ["FRC"] = "France Central", ["FRS"] = "France South",
            ["GWC"] = "Germany West Central", ["GN"] = "Germany North",
            ["NOE"] = "Norway East", ["NOW"] = "Norway West",
            ["SEW"] = "Sweden Central", ["SES"] = "Sweden South",
            ["SZN"] = "Switzerland North", ["SZW"] = "Switzerland West",
            ["JPC"] = "Japan Central", ["JPE"] = "Japan East", ["JPW"] = "Japan West",
            ["KRC"] = "Korea Central", ["KRS"] = "Korea South",
            ["EAU"] = "East Australia", ["SEAU"] = "Southeast Australia",
            ["SEA"] = "Southeast Asia (Singapore)", ["EA"] = "East Asia (Hong Kong)",
            ["CI"] = "Central India", ["WI"] = "West India", ["SI"] = "South India",
            ["BRS"] = "Brazil South", ["BRSE"] = "Brazil Southeast",
            ["SAN"] = "South Africa North", ["SAW"] = "South Africa West",
            ["UAEN"] = "UAE North", ["UAEC"] = "UAE Central",
            ["QAC"] = "Qatar Central"
        };
        return map.TryGetValue(regionCode, out var name) ? name : regionCode;
    }

    /// <summary>
    /// Maps Azure region short codes to 2-letter country codes for cross-validation.
    /// </summary>
    internal static string? GetAzureRegionCountryCode(string? regionCode)
    {
        if (regionCode == null) return null;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["UKS"] = "GB", ["UKW"] = "GB",
            ["NEU"] = "IE", ["WEU"] = "NL",
            ["EUS"] = "US", ["EUS2"] = "US", ["WUS"] = "US", ["WUS2"] = "US", ["WUS3"] = "US",
            ["CUS"] = "US", ["NCUS"] = "US", ["SCUS"] = "US", ["WCUS"] = "US",
            ["CC"] = "CA", ["CE"] = "CA",
            ["FRC"] = "FR", ["FRS"] = "FR",
            ["GWC"] = "DE", ["GN"] = "DE",
            ["NOE"] = "NO", ["NOW"] = "NO",
            ["SEW"] = "SE", ["SES"] = "SE",
            ["SZN"] = "CH", ["SZW"] = "CH",
            ["JPC"] = "JP", ["JPE"] = "JP", ["JPW"] = "JP",
            ["KRC"] = "KR", ["KRS"] = "KR",
            ["EAU"] = "AU", ["SEAU"] = "AU",
            ["SEA"] = "SG", ["EA"] = "HK",
            ["CI"] = "IN", ["WI"] = "IN", ["SI"] = "IN",
            ["BRS"] = "BR", ["BRSE"] = "BR",
            ["SAN"] = "ZA", ["SAW"] = "ZA",
            ["UAEN"] = "AE", ["UAEC"] = "AE",
            ["QAC"] = "QA"
        };
        return map.TryGetValue(regionCode, out var code) ? code : null;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 11b – TURN Relay Location
// ════════════════════════════════════════════════════════════════════
public class TurnRelayLocationTest : BaseTest
{
    public override string Id => "11b";
    public override string Name => "TURN Relay Location";
    public override string Description => "Identifies which TURN relay you are routed to via Traffic Manager performance routing. The CNAME chain reveals the assigned Azure region.";
    public override TestCategory Category => TestCategory.UdpShortpath;

    /// <summary>
    /// Maps Azure cloudapp region slugs (e.g. "uksouth") to friendly display names.
    /// </summary>
    private static string GetCloudAppRegionName(string slug)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["uksouth"] = "UK South", ["ukwest"] = "UK West",
            ["northeurope"] = "North Europe (Ireland)", ["westeurope"] = "West Europe (Netherlands)",
            ["eastus"] = "East US", ["eastus2"] = "East US 2",
            ["westus"] = "West US", ["westus2"] = "West US 2", ["westus3"] = "West US 3",
            ["centralus"] = "Central US", ["northcentralus"] = "North Central US",
            ["southcentralus"] = "South Central US", ["westcentralus"] = "West Central US",
            ["canadacentral"] = "Canada Central", ["canadaeast"] = "Canada East",
            ["francecentral"] = "France Central", ["francesouth"] = "France South",
            ["germanywestcentral"] = "Germany West Central", ["germanynorth"] = "Germany North",
            ["norwayeast"] = "Norway East", ["norwaywest"] = "Norway West",
            ["swedencentral"] = "Sweden Central", ["swedensouth"] = "Sweden South",
            ["switzerlandnorth"] = "Switzerland North", ["switzerlandwest"] = "Switzerland West",
            ["japaneast"] = "Japan East", ["japanwest"] = "Japan West",
            ["koreacentral"] = "Korea Central", ["koreasouth"] = "Korea South",
            ["australiaeast"] = "Australia East", ["australiasoutheast"] = "Australia Southeast",
            ["southeastasia"] = "Southeast Asia (Singapore)", ["eastasia"] = "East Asia (Hong Kong)",
            ["centralindia"] = "Central India", ["westindia"] = "West India", ["southindia"] = "South India",
            ["brazilsouth"] = "Brazil South", ["brazilsoutheast"] = "Brazil Southeast",
            ["southafricanorth"] = "South Africa North", ["southafricawest"] = "South Africa West",
            ["uaenorth"] = "UAE North", ["uaecentral"] = "UAE Central",
            ["qatarcentral"] = "Qatar Central"
        };
        return map.TryGetValue(slug, out var name) ? name : slug;
    }

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var endpoint = EndpointConfiguration.TurnRelayEndpoints[0]; // world.relay.avd.microsoft.com
        var details = new List<string>();
        details.Add($"FQDN: {endpoint}");

        try
        {
            // Resolve to get the IP
            var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
            var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4 == null)
            {
                result.Status = TestStatus.Warning;
                result.ResultValue = "No IPv4 address resolved";
                result.DetailedInfo = string.Join("\n", details);
                return;
            }

            var relayIp = ipv4.ToString();
            details.Add($"IP: {relayIp}");

            // Use nslookup to trace the CNAME chain.
            // world.relay.avd.microsoft.com
            //   → worldaz-relay-avd.trafficmanager.net (Traffic Manager)
            //   → a-tr-avdpb-ukso-03.uksouth.cloudapp.azure.com (regional relay)
            string? resolvedHost = null;
            string? trafficManagerCname = null;
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo("nslookup", endpoint)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = System.Diagnostics.Process.Start(psi)!;
                var output = await proc.StandardOutput.ReadToEndAsync(ct);
                await proc.WaitForExitAsync(ct);

                // Parse "Name:" line for the final resolved hostname
                var nameMatch = System.Text.RegularExpressions.Regex.Match(
                    output, @"Name:\s+(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (nameMatch.Success)
                    resolvedHost = nameMatch.Groups[1].Value.TrimEnd('.');

                // Parse "Aliases:" section for the Traffic Manager CNAME
                var tmMatch = System.Text.RegularExpressions.Regex.Match(
                    output, @"(\S+\.trafficmanager\.net)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (tmMatch.Success)
                    trafficManagerCname = tmMatch.Groups[1].Value.TrimEnd('.');
            }
            catch { /* nslookup parse is non-fatal */ }

            if (trafficManagerCname != null)
                details.Add($"Traffic Manager: {trafficManagerCname}");
            if (resolvedHost != null)
                details.Add($"Regional host: {resolvedHost}");

            // Extract region from cloudapp hostname: *.{region}.cloudapp.azure.com
            string? regionSlug = null;
            string? regionName = null;
            if (resolvedHost != null)
            {
                var regionMatch = System.Text.RegularExpressions.Regex.Match(
                    resolvedHost, @"\.([a-z]+)\.cloudapp\.azure\.com$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (regionMatch.Success)
                {
                    regionSlug = regionMatch.Groups[1].Value;
                    regionName = GetCloudAppRegionName(regionSlug);
                    details.Add($"Region: {regionName}");
                }
            }

            details.Add("");
            details.Add("Traffic Manager uses performance-based routing to direct");
            details.Add("you to the nearest TURN relay. The resolved hostname");
            details.Add("reveals the assigned Azure region.");

            result.Status = TestStatus.Passed;
            if (regionName != null)
                result.ResultValue = $"{regionName} ({relayIp})";
            else if (resolvedHost != null)
                result.ResultValue = $"{resolvedHost} ({relayIp})";
            else
                result.ResultValue = relayIp;

            result.DetailedInfo = string.Join("\n", details);
            result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
        }
        catch (Exception ex)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Cannot resolve TURN relay";
            result.RemediationText = $"Failed to resolve {endpoint}: {ex.Message}";
            result.DetailedInfo = string.Join("\n", details);
            result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 11 – TURN Relay Reachable
// ════════════════════════════════════════════════════════════════════
public class TurnRelayTest : BaseTest
{
    public override string Id => "11";
    public override string Name => "TURN Relay Reachable";
    public override string Description => "Sends a STUN Binding Request to the TURN relay (world.relay.avd.microsoft.com:3478). A valid STUN response confirms the relay is accessible via UDP.";
    public override TestCategory Category => TestCategory.UdpShortpath;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var successes = new List<string>();
        var failures = new List<string>();

        foreach (var endpoint in EndpointConfiguration.TurnRelayEndpoints)
        {
            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 5000;

                // Resolve hostname to IP
                var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
                var ip = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                var serverEp = new IPEndPoint(ip, EndpointConfiguration.TurnRelayPort);

                // Build and send STUN Binding Request (RFC 5389)
                var stunRequest = BuildStunBindingRequest();
                await udp.SendAsync(stunRequest, stunRequest.Length, serverEp);

                // Wait for STUN Binding Response
                var receiveTask = udp.ReceiveAsync(ct);
                var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(5000, ct));

                if (completed == receiveTask.AsTask())
                {
                    var response = await receiveTask;
                    var isStunResponse = IsValidStunResponse(response.Buffer);

                    if (isStunResponse)
                        successes.Add($"✓ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — STUN Binding Response received");
                    else
                        successes.Add($"✓ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — UDP response received (non-STUN)");
                }
                else
                {
                    failures.Add($"⚠ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — no STUN response (timeout)");
                }
            }
            catch (SocketException)
            {
                failures.Add($"✗ {endpoint}:{EndpointConfiguration.TurnRelayPort} — UDP blocked");
            }
            catch (Exception ex)
            {
                failures.Add($"✗ {endpoint}:{EndpointConfiguration.TurnRelayPort} — {ex.Message}");
            }
        }

        result.DetailedInfo = $"TURN relay: world.relay.avd.microsoft.com:3478\nTest method: STUN Binding Request (RFC 5389)\n\n{string.Join("\n", successes.Concat(failures))}";

        if (successes.Count > 0)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "Reachable (STUN response confirmed)";
        }
        else if (failures.All(f => f.Contains("timeout")))
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "No STUN response from TURN relay";
            result.RemediationText = "TURN relay did not respond to STUN Binding Request. UDP 3478 may be filtered. RDP Shortpath via TURN may not be available, which could impact performance.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "TURN relay unreachable";
            result.RemediationText = "Cannot reach TURN relay server. Ensure UDP port 3478 is allowed to world.relay.avd.microsoft.com. Without TURN, RDP connections may have degraded performance and reliability.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
    }

    /// <summary>
    /// Builds a 20-byte STUN Binding Request per RFC 5389.
    /// </summary>
    private static byte[] BuildStunBindingRequest()
    {
        var request = new byte[20];
        // Message Type: Binding Request (0x0001)
        request[0] = 0x00; request[1] = 0x01;
        // Message Length: 0 (no attributes)
        request[2] = 0x00; request[3] = 0x00;
        // Magic Cookie: 0x2112A442
        request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42;
        // Transaction ID: 12 random bytes
        Random.Shared.NextBytes(request.AsSpan(8, 12));
        return request;
    }

    /// <summary>
    /// Validates that the response is a STUN Binding Success Response (0x0101) with correct magic cookie.
    /// </summary>
    private static bool IsValidStunResponse(byte[] data)
    {
        if (data.Length < 20) return false;
        // Check message type: Binding Success Response = 0x0101
        var messageType = (data[0] << 8) | data[1];
        if (messageType != 0x0101) return false;
        // Check magic cookie: 0x2112A442
        return data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 12 – Latency to Gateway
// ════════════════════════════════════════════════════════════════════
public class GatewayLatencyTest : BaseTest
{
    public override string Id => "12";
    public override string Name => "Gateway Latency";
    public override string Description => "Measures TCP connection latency to the RD Gateway. High latency indicates suboptimal routing or network path issues.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        // Use the Traffic Manager FQDN directly (resolves to nearest gateway)
        var endpoint = GatewayReachabilityTest.GatewayFqdn;
        var latencies = new List<double>();

        for (int i = 0; i < 5; i++)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(endpoint, EndpointConfiguration.GatewayPort, cts.Token);
                sw.Stop();
                latencies.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch
            {
                // Connection failed — skip this attempt
            }

            if (i < 4) await Task.Delay(200, ct);
        }

        if (latencies.Count == 0)
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "Gateway unreachable";
            result.RemediationText = "Cannot establish TCP connection to the RD Gateway. Check firewall and network configuration.";
            return;
        }

        var avg = latencies.Average();
        var min = latencies.Min();
        var max = latencies.Max();

        result.ResultValue = $"{avg:F0}ms avg";
        result.DetailedInfo = $"Endpoint: {endpoint}:{EndpointConfiguration.GatewayPort}\n" +
                              $"Samples: {latencies.Count}/5\n" +
                              $"Min: {min:F0}ms | Avg: {avg:F0}ms | Max: {max:F0}ms\n" +
                              $"Values: {string.Join(", ", latencies.Select(l => $"{l:F0}ms"))}";

        if (avg < 50)
        {
            result.Status = TestStatus.Passed;
        }
        else if (avg < 150)
        {
            result.Status = TestStatus.Warning;
            result.RemediationText = "Gateway latency is above 50ms. Ensure traffic is egressing from the nearest network exit point. Check for proxy/VPN adding latency.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.RemediationText = "Gateway latency is very high. This will noticeably impact remote desktop responsiveness. Check network routing, ensure no proxy/VPN is in use for RDP traffic, and verify you're connecting to the nearest gateway region.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 13 – Gateway Location (via Traffic Manager resolution)
// ════════════════════════════════════════════════════════════════════
public class GatewayLocationTest : BaseTest
{
    public override string Id => "13";
    public override string Name => "Gateway Location";
    public override string Description => "Identifies which RD Gateway you are routed to via Traffic Manager performance routing. The gateway CNAME reveals the assigned Azure region.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var details = new List<string>();

        foreach (var fqdn in new[] { GatewayReachabilityTest.GatewayFqdn, GatewayReachabilityTest.GatewayFqdnFallback })
        {
            details.Add($"FQDN: {fqdn}");

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(fqdn, ct);
                var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ipv4 == null)
                {
                    details.Add("  ✗ No IPv4 address resolved");
                    continue;
                }

                var gatewayIp = ipv4.ToString();
                details.Add($"  IP: {gatewayIp}");

                // Detect Private Link — private IP won't have Traffic Manager CNAMEs
                var ipBytes = ipv4.GetAddressBytes();
                if (ipBytes[0] == 10 || (ipBytes[0] == 172 && ipBytes[1] >= 16 && ipBytes[1] <= 31) || (ipBytes[0] == 192 && ipBytes[1] == 168))
                {
                    details.Add("  ℹ Private Link detected — gateway resolves to private IP");
                    details.Add("  Traffic Manager region detection is not applicable via Private Link.");
                    details.Add("  The gateway location is determined by the Private Link endpoint.");
                    result.Status = TestStatus.Passed;
                    result.ResultValue = $"Private Link ({gatewayIp})";
                    result.DetailedInfo = string.Join("\n", details);
                    result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
                    return;
                }

                // .NET GetHostEntry resolves to the final A-record hostname, skipping
                // intermediate CNAMEs. We need the Traffic Manager CNAME which contains
                // the regional gateway name (e.g. mrs-uksr1c223-rdgateway-prod...).
                // Use nslookup to query the CNAME chain.
                string? regionalCname = null;
                var tmFqdn = fqdn.Replace(".wvd.microsoft.com", "-prod.trafficmanager.net");
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo("nslookup", $"-type=CNAME {tmFqdn}")
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var proc = System.Diagnostics.Process.Start(psi)!;
                    var output = await proc.StandardOutput.ReadToEndAsync(ct);
                    await proc.WaitForExitAsync(ct);

                    // Parse "canonical name = mrs-uksr1c223-rdgateway-prod..."
                    var cnameMatch = System.Text.RegularExpressions.Regex.Match(
                        output, @"canonical name\s*=\s*(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (cnameMatch.Success)
                    {
                        regionalCname = cnameMatch.Groups[1].Value.TrimEnd('.');
                        details.Add($"  Traffic Manager: {tmFqdn}");
                        details.Add($"  Regional CNAME: {regionalCname}");
                    }
                }
                catch { /* non-fatal */ }

                // Extract region from CNAME (e.g. mrs-uksr1c228-rdgateway-prod...)
                string? gatewayRegion = null;
                string? regionName = null;
                string? gatewayInstance = null;
                if (regionalCname != null)
                {
                    var regionMatch = System.Text.RegularExpressions.Regex.Match(
                        regionalCname, @"-([a-z]{2,6})r(\d+)c(\d+)-rdgateway", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (regionMatch.Success)
                    {
                        gatewayRegion = regionMatch.Groups[1].Value.ToUpperInvariant();
                        regionName = AfdEgressLocationTest.GetAzureRegionName(gatewayRegion);
                        var ring = regionMatch.Groups[2].Value;
                        var cluster = regionMatch.Groups[3].Value;
                        gatewayInstance = $"Ring {ring}, Cluster {cluster}";
                        details.Add($"  Region: {regionName ?? gatewayRegion}");
                        details.Add($"  Gateway instance: {gatewayInstance}");
                    }
                }

                details.Add("");
                details.Add("Traffic Manager uses performance-based routing to direct");
                details.Add("you to the nearest RD Gateway. The CNAME reveals the");
                details.Add("assigned gateway and its Azure region.");

                result.Status = TestStatus.Passed;
                if (regionName != null)
                    result.ResultValue = $"{regionName} ({gatewayIp})";
                else if (gatewayRegion != null)
                    result.ResultValue = $"{gatewayRegion} ({gatewayIp})";
                else
                    result.ResultValue = $"{gatewayIp}{(regionalCname != null ? $" ({regionalCname})" : "")}";

                result.DetailedInfo = string.Join("\n", details);
                result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
                return;
            }
            catch (Exception ex)
            {
                details.Add($"  ✗ {ex.Message}");
            }

            details.Add("");
        }

        // Both FQDNs failed
        result.Status = TestStatus.Failed;
        result.ResultValue = "Cannot resolve gateway";
        result.RemediationText = "Failed to resolve the RD Gateway FQDN. Check DNS and firewall rules for *.wvd.microsoft.com.";
        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = EndpointConfiguration.Docs.NetworkRequirements;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 14 – Indirect RDP Connectivity (via TURN)
// ════════════════════════════════════════════════════════════════════
public class IndirectRdpTest : BaseTest
{
    public override string Id => "14";
    public override string Name => "Indirect RDP (TURN)";
    public override string Description => "Validates TURN relay connectivity by sending a STUN Binding Request and checking for a valid response. A successful STUN response confirms indirect RDP via TURN is available.";
    public override TestCategory Category => TestCategory.UdpShortpath;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        bool stunSuccess = false;
        var details = new List<string>();

        foreach (var endpoint in EndpointConfiguration.TurnRelayEndpoints)
        {
            try
            {
                using var udp = new UdpClient();

                // Resolve hostname to IP
                var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
                var ip = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                var serverEp = new IPEndPoint(ip, EndpointConfiguration.TurnRelayPort);

                // Send STUN Binding Request
                var request = BuildStunBindingRequest();
                var sw = Stopwatch.StartNew();
                await udp.SendAsync(request, request.Length, serverEp);

                var receiveTask = udp.ReceiveAsync(ct);
                var completed = await Task.WhenAny(receiveTask.AsTask(), Task.Delay(5000, ct));

                if (completed == receiveTask.AsTask())
                {
                    sw.Stop();
                    var response = await receiveTask;

                    if (IsValidStunResponse(response.Buffer))
                    {
                        stunSuccess = true;
                        details.Add($"✓ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — STUN Binding Response in {sw.ElapsedMilliseconds}ms");
                    }
                    else
                    {
                        stunSuccess = true; // Got a response, even if not clean STUN
                        details.Add($"✓ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — UDP response received in {sw.ElapsedMilliseconds}ms (non-standard STUN)");
                    }
                }
                else
                {
                    details.Add($"⚠ {endpoint} ({ip}):{EndpointConfiguration.TurnRelayPort} — no STUN response (timeout)");
                }
            }
            catch (Exception ex)
            {
                details.Add($"✗ {endpoint}:{EndpointConfiguration.TurnRelayPort} — {ex.Message}");
            }
        }

        result.DetailedInfo = $"Test method: STUN Binding Request to TURN relay\n\n{string.Join("\n", details)}";

        if (stunSuccess)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "Indirect RDP (TURN) available";
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = "TURN connectivity not confirmed";
            result.RemediationText = "Unable to get a STUN response from the TURN relay. Ensure UDP port 3478 is allowed outbound to world.relay.avd.microsoft.com. Without TURN, RDP Shortpath may not be available.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
    }

    private static byte[] BuildStunBindingRequest()
    {
        var request = new byte[20];
        request[0] = 0x00; request[1] = 0x01; // Binding Request
        request[2] = 0x00; request[3] = 0x00; // Length: 0
        request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42; // Magic Cookie
        Random.Shared.NextBytes(request.AsSpan(8, 12));
        return request;
    }

    private static bool IsValidStunResponse(byte[] data)
    {
        if (data.Length < 20) return false;
        var messageType = (data[0] << 8) | data[1];
        if (messageType != 0x0101) return false;
        return data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 15 – TLS Inspection on RDP Connectivity
// ════════════════════════════════════════════════════════════════════
public class TlsInspectionTest : BaseTest
{
    public override string Id => "15";
    public override string Name => "TLS Inspection Check";
    public override string Description => "Verifies the TLS certificate on the RD Gateway connection is issued by the expected authority. If not, TLS inspection (e.g. by a proxy/firewall) is occurring, which degrades performance.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var endpoint = EndpointConfiguration.GetBestGatewayEndpoint();
        X509Certificate2? serverCert = null;

        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(10_000);
            await tcp.ConnectAsync(endpoint, EndpointConfiguration.GatewayPort, cts.Token);

            using var sslStream = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
            {
                if (cert != null)
                    serverCert = new X509Certificate2(cert);
                return true; // Accept any cert for inspection purposes
            });

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint
            }, ct);
        }
        catch (Exception ex)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = $"TLS handshake failed: {ex.Message}";
            return;
        }

        if (serverCert == null)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = "No certificate received";
            return;
        }

        var issuer = serverCert.Issuer;
        var subject = serverCert.Subject;
        var thumbprint = serverCert.Thumbprint;
        var expiry = serverCert.NotAfter;

        result.DetailedInfo = $"Subject: {subject}\n" +
                              $"Issuer: {issuer}\n" +
                              $"Thumbprint: {thumbprint}\n" +
                              $"Valid Until: {expiry:yyyy-MM-dd}\n" +
                              $"Endpoint: {endpoint}:{EndpointConfiguration.GatewayPort}";

        // Detect Private Link — private endpoints may present Azure Private Link
        // certificates rather than the expected Microsoft/DigiCert gateway certs
        var isPrivateLink = subject.Contains("privatelink", StringComparison.OrdinalIgnoreCase) ||
                            issuer.Contains("Private", StringComparison.OrdinalIgnoreCase);

        // Also check if the resolved IP is private (PL endpoint)
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
            var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ip != null)
            {
                var bytes = ip.GetAddressBytes();
                if (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168))
                    isPrivateLink = true;
            }
        }
        catch { /* non-fatal */ }

        var isExpectedIssuer = EndpointConfiguration.ExpectedCertIssuers
            .Any(expected => issuer.Contains(expected, StringComparison.OrdinalIgnoreCase));

        if (isExpectedIssuer)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "No TLS inspection detected";
        }
        else if (isPrivateLink)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "Private Link endpoint — different cert expected";
            result.DetailedInfo += "\n\nℹ The certificate issuer differs from the standard gateway cert, " +
                                   "but this endpoint appears to be a Private Link private endpoint. " +
                                   "Private Link endpoints use different certificates — this is expected and not TLS inspection.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "TLS inspection detected!";
            result.RemediationText = $"The TLS certificate for the RD Gateway is issued by '{issuer}' instead of the expected Microsoft/DigiCert authority. " +
                                     "This indicates TLS inspection (SSL break-and-inspect) is being performed on RDP traffic. " +
                                     "This dramatically impacts performance and reliability with no security benefit for encrypted RDP traffic. " +
                                     "Exclude Windows 365/AVD traffic from TLS inspection immediately.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TlsInspection;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 16 – Proxy/VPN/SWG Detection
// ════════════════════════════════════════════════════════════════════
public class ProxyVpnDetectionTest : BaseTest
{
    public override string Id => "16";
    public override string Name => "Proxy/VPN/SWG Detection";
    public override string Description => "Detects whether RDP traffic is being routed through proxies, VPNs, or Secure Web Gateways (e.g. Zscaler). These severely impact RDP performance and should be bypassed.";
    public override TestCategory Category => TestCategory.TcpTransport;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var issues = new List<string>();
        var details = new List<string>();

        // 1. Check system proxy settings
        var proxy = WebRequest.DefaultWebProxy;
        var testUri = new Uri($"https://{EndpointConfiguration.GetBestGatewayEndpoint()}");
        var proxyUri = proxy?.GetProxy(testUri);

        if (proxyUri != null && proxyUri != testUri)
        {
            issues.Add($"System proxy detected: {proxyUri}");
            details.Add($"✗ Proxy configured for gateway traffic: {proxyUri}");
        }
        else
        {
            details.Add("✓ No system proxy detected for gateway traffic");
        }

        // 2. Check environment variables for proxy
        var proxyEnvVars = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY" };
        foreach (var envVar in proxyEnvVars)
        {
            var value = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrEmpty(value))
            {
                if (envVar == "NO_PROXY")
                {
                    details.Add($"ℹ {envVar} environment variable set: {value}");
                    // Check if AVD endpoints are in the exclusion list
                    if (value.Contains(".wvd.microsoft.com", StringComparison.OrdinalIgnoreCase) ||
                        value.Contains(".microsoft.com", StringComparison.OrdinalIgnoreCase))
                        details.Add("  ✓ AVD endpoints appear in NO_PROXY exclusion list");
                    else
                        details.Add("  ⚠ AVD endpoints (*.wvd.microsoft.com) not in NO_PROXY — proxy will be used");
                }
                else
                {
                    issues.Add($"Environment proxy: {envVar}={value}");
                    details.Add($"✗ {envVar} environment variable set: {value}");
                }
            }
        }

        // 2b. Check WinHTTP proxy (often different from WinINET/system proxy)
        try
        {
            var psi = new ProcessStartInfo("netsh", "winhttp show proxy")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync(ct);
                await proc.WaitForExitAsync(ct);
                if (output.Contains("Direct access", StringComparison.OrdinalIgnoreCase))
                {
                    details.Add("✓ WinHTTP proxy: Direct access (no proxy)");
                }
                else
                {
                    var proxyLine = output.Split('\n')
                        .FirstOrDefault(l => l.Contains("Proxy Server", StringComparison.OrdinalIgnoreCase));
                    if (proxyLine != null)
                    {
                        issues.Add($"WinHTTP proxy configured: {proxyLine.Trim()}");
                        details.Add($"⚠ WinHTTP {proxyLine.Trim()}");
                    }

                    var bypassLine = output.Split('\n')
                        .FirstOrDefault(l => l.Contains("Bypass List", StringComparison.OrdinalIgnoreCase));
                    if (bypassLine != null)
                        details.Add($"  Bypass: {bypassLine.Trim()}");
                }
            }
        }
        catch { details.Add("— Could not check WinHTTP proxy settings"); }

        // 2c. Check for PAC/WPAD auto-configuration
        try
        {
            using var regKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (regKey != null)
            {
                var autoConfigUrl = regKey.GetValue("AutoConfigURL") as string;
                var proxyEnable = regKey.GetValue("ProxyEnable") as int? ?? 0;
                var proxyServer = regKey.GetValue("ProxyServer") as string;
                var proxyOverride = regKey.GetValue("ProxyOverride") as string;

                if (!string.IsNullOrEmpty(autoConfigUrl))
                {
                    issues.Add($"PAC file configured: {autoConfigUrl}");
                    details.Add($"⚠ PAC file (auto-config URL): {autoConfigUrl}");
                    details.Add("  PAC files can selectively route AVD traffic through proxy.");
                    details.Add("  Ensure *.wvd.microsoft.com is excluded in the PAC script.");
                }
                else
                {
                    details.Add("✓ No PAC file configured");
                }

                if (proxyEnable == 1 && !string.IsNullOrEmpty(proxyServer))
                {
                    details.Add($"ℹ WinINET proxy: {proxyServer}");
                    if (!string.IsNullOrEmpty(proxyOverride))
                        details.Add($"  Bypass list: {proxyOverride}");
                }
            }
        }
        catch { details.Add("— Could not read Internet Settings registry"); }

        // 2d. Check WPAD via DNS (wpad.<domain>)
        try
        {
            var domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrEmpty(domain))
            {
                try
                {
                    var wpadAddrs = await Dns.GetHostAddressesAsync($"wpad.{domain}", ct);
                    if (wpadAddrs.Length > 0)
                    {
                        details.Add($"⚠ WPAD DNS record found: wpad.{domain} → {wpadAddrs[0]}");
                        details.Add("  WPAD auto-discovery may route traffic through a proxy.");
                    }
                }
                catch
                {
                    details.Add($"✓ No WPAD DNS record for wpad.{domain}");
                }
            }
        }
        catch { /* non-fatal */ }

        // 2e. Test proxy authentication — if proxy requires auth, HttpClient calls will fail with 407
        if (proxyUri != null && proxyUri != testUri)
        {
            try
            {
                using var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy(proxyUri) { UseDefaultCredentials = false },
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                var proxyResponse = await http.GetAsync($"https://{EndpointConfiguration.GetBestGatewayEndpoint()}/", ct);

                if (proxyResponse.StatusCode == System.Net.HttpStatusCode.ProxyAuthenticationRequired)
                {
                    issues.Add("Proxy requires authentication (HTTP 407)");
                    details.Add("✗ Proxy requires authentication — HTTP requests without credentials will fail");
                }
                else
                {
                    details.Add($"ℹ Proxy responded: HTTP {(int)proxyResponse.StatusCode} (no auth required)");
                }
            }
            catch (Exception ex)
            {
                details.Add($"— Proxy auth test inconclusive: {ex.Message}");
            }
        }

        // 3. Check for VPN adapters
        var vpnAdapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        (n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Virtual Private", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("TAP-", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Cisco AnyConnect", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("GlobalProtect", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                         n.NetworkInterfaceType == NetworkInterfaceType.Ppp))
            .ToList();

        if (vpnAdapters.Count > 0)
        {
            foreach (var adapter in vpnAdapters)
            {
                issues.Add($"VPN adapter: {adapter.Description}");
                details.Add($"⚠ VPN adapter active: {adapter.Name} ({adapter.Description})");
            }
        }
        else
        {
            details.Add("✓ No VPN adapters detected");
        }

        // 4. Check for known SWG processes
        var swgProcesses = new Dictionary<string, string>
        {
            ["ZSATunnel"] = "Zscaler",
            ["ZSAService"] = "Zscaler",
            ["zscaler"] = "Zscaler",
            ["PanGPS"] = "Palo Alto GlobalProtect",
            ["PanGPA"] = "Palo Alto GlobalProtect",
            ["CiscoAnyConnect"] = "Cisco AnyConnect",
            ["vpnagent"] = "Cisco AnyConnect",
            ["NordVPN"] = "NordVPN",
            ["openvpn"] = "OpenVPN",
            ["netskope"] = "Netskope"
        };

        foreach (var (processName, productName) in swgProcesses)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length > 0)
                {
                    issues.Add($"SWG/VPN software detected: {productName}");
                    details.Add($"⚠ {productName} process running ({processName})");
                }
            }
            catch { /* Process access denied — skip */ }
        }

        if (!issues.Any(i => i.Contains("SWG")))
            details.Add("✓ No known SWG processes detected");

        // 5. Perform a traceroute-style check to see if traffic goes through known proxies
        await CheckTraceRouteAsync(details, ct);

        result.DetailedInfo = string.Join("\n", details);

        if (issues.Count == 0)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "No proxy/VPN/SWG detected";
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{issues.Count} issue(s) detected";
            result.RemediationText = "RDP traffic should be routed directly to the service, bypassing proxies, VPNs, and Secure Web Gateways (SWGs). " +
                                     "Configure split tunneling or exclusions for Windows 365/AVD traffic to avoid severe performance impact.\n\n" +
                                     "Issues found:\n• " + string.Join("\n• ", issues);
        }

        result.RemediationUrl = EndpointConfiguration.Docs.ProxyConfig;
    }

    private static async Task CheckTraceRouteAsync(List<string> details, CancellationToken ct)
    {
        try
        {
            var gateway = EndpointConfiguration.GetBestGatewayEndpoint();
            var addresses = await Dns.GetHostAddressesAsync(gateway, ct);
            if (addresses.Length == 0) return;

            var target = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);

            using var ping = new Ping();
            var hopDetails = new List<string>();

            for (int ttl = 1; ttl <= 5; ttl++)
            {
                var options = new PingOptions(ttl, true);
                var reply = await ping.SendPingAsync(target, 2000, new byte[32], options);

                if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success)
                {
                    hopDetails.Add($"  Hop {ttl}: {reply.Address} ({reply.RoundtripTime}ms)");

                    if (reply.Status == IPStatus.Success) break;
                }
                else
                {
                    hopDetails.Add($"  Hop {ttl}: * (no response)");
                }
            }

            if (hopDetails.Count > 0)
            {
                details.Add("\nFirst 5 hops to gateway:");
                details.AddRange(hopDetails);
            }
        }
        catch { /* Traceroute failed — non-critical */ }
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 11c – TLS Inspection on TURN/UDP Path
// ════════════════════════════════════════════════════════════════════
public class TurnTlsInspectionTest : BaseTest
{
    public override string Id => "11c";
    public override string Name => "TLS Inspection (TURN Path)";
    public override string Description => "Verifies the TLS certificate on the TURN relay HTTPS endpoint (TCP 443) is issued by the expected authority. TLS inspection on this path prevents Shortpath negotiation.";
    public override TestCategory Category => TestCategory.UdpShortpath;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var endpoint = EndpointConfiguration.TurnRelayEndpoints[0]; // world.relay.avd.microsoft.com
        X509Certificate2? serverCert = null;

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
            var ip = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(10_000);
            await tcp.ConnectAsync(ip, 443, cts.Token);

            using var sslStream = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
            {
                if (cert != null)
                    serverCert = new X509Certificate2(cert);
                return true; // Accept any cert for inspection purposes
            });

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint
            }, ct);
        }
        catch (Exception ex)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = $"TLS handshake failed: {ex.Message}";
            return;
        }

        if (serverCert == null)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = "No certificate received";
            return;
        }

        var issuer = serverCert.Issuer;
        var subject = serverCert.Subject;
        var thumbprint = serverCert.Thumbprint;
        var expiry = serverCert.NotAfter;

        result.DetailedInfo = $"Subject: {subject}\n" +
                              $"Issuer: {issuer}\n" +
                              $"Thumbprint: {thumbprint}\n" +
                              $"Valid Until: {expiry:yyyy-MM-dd}\n" +
                              $"Endpoint: {endpoint}:443";

        var isExpectedIssuer = EndpointConfiguration.ExpectedCertIssuers
            .Any(expected => issuer.Contains(expected, StringComparison.OrdinalIgnoreCase));

        if (isExpectedIssuer)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "No TLS inspection detected on TURN path";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = "TLS inspection detected on TURN path!";
            result.RemediationText = $"The TLS certificate for the TURN relay is issued by '{issuer}' instead of the expected Microsoft/DigiCert authority. " +
                                     "This indicates TLS inspection (SSL break-and-inspect) is being performed on the RDP Shortpath negotiation path. " +
                                     "This will prevent UDP Shortpath from being established, forcing fallback to TCP. " +
                                     "Exclude *.relay.avd.microsoft.com from TLS inspection.";
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 11d – Proxy/VPN/SWG Detection for UDP Path
// ════════════════════════════════════════════════════════════════════
public class TurnProxyVpnDetectionTest : BaseTest
{
    public override string Id => "11d";
    public override string Name => "Proxy/VPN/SWG Detection (UDP Path)";
    public override string Description => "Detects whether UDP traffic to the TURN relay may be blocked or intercepted by proxies, VPNs, or Secure Web Gateways. These prevent RDP Shortpath from being established.";
    public override TestCategory Category => TestCategory.UdpShortpath;

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var issues = new List<string>();
        var details = new List<string>();

        // 1. Check if UDP 3478 is reachable (direct STUN test)
        try
        {
            var endpoint = EndpointConfiguration.TurnRelayEndpoints[0];
            var addresses = await Dns.GetHostAddressesAsync(endpoint, ct);
            var ip = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 5000;
            var serverEp = new System.Net.IPEndPoint(ip, EndpointConfiguration.TurnRelayPort);

            // Send a STUN binding request
            var stunRequest = new byte[] { 0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
            await udp.SendAsync(stunRequest, stunRequest.Length, serverEp);

            var receiveTask = udp.ReceiveAsync();
            if (await Task.WhenAny(receiveTask, Task.Delay(5000, ct)) == receiveTask)
            {
                details.Add($"✓ UDP {EndpointConfiguration.TurnRelayPort} reachable — STUN response received from {endpoint}");
            }
            else
            {
                issues.Add("UDP 3478 blocked or filtered");
                details.Add($"✗ UDP {EndpointConfiguration.TurnRelayPort} blocked — no STUN response from {endpoint}");
            }
        }
        catch (Exception ex)
        {
            issues.Add($"UDP test failed: {ex.Message}");
            details.Add($"✗ UDP test error: {ex.Message}");
        }

        // 2. Check for VPN adapters that may block/tunnel UDP
        var vpnAdapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        (n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Virtual Private", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("TAP-", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Cisco AnyConnect", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("GlobalProtect", StringComparison.OrdinalIgnoreCase) ||
                         n.Description.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                         n.NetworkInterfaceType == NetworkInterfaceType.Ppp))
            .ToList();

        if (vpnAdapters.Count > 0)
        {
            foreach (var adapter in vpnAdapters)
            {
                issues.Add($"VPN adapter may block UDP: {adapter.Description}");
                details.Add($"⚠ VPN adapter active: {adapter.Name} ({adapter.Description}) — may tunnel/block UDP");
            }
        }
        else
        {
            details.Add("✓ No VPN adapters detected");
        }

        // 3. Check for known SWG processes that typically block UDP
        var swgProcesses = new Dictionary<string, string>
        {
            ["ZSATunnel"] = "Zscaler",
            ["ZSAService"] = "Zscaler",
            ["zscaler"] = "Zscaler",
            ["PanGPS"] = "Palo Alto GlobalProtect",
            ["PanGPA"] = "Palo Alto GlobalProtect",
            ["CiscoAnyConnect"] = "Cisco AnyConnect",
            ["vpnagent"] = "Cisco AnyConnect",
            ["netskope"] = "Netskope"
        };

        foreach (var (processName, productName) in swgProcesses)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length > 0)
                {
                    issues.Add($"SWG detected: {productName} — typically blocks UDP");
                    details.Add($"⚠ {productName} process running ({processName}) — typically blocks UDP Shortpath");
                }
            }
            catch { /* Process access denied — skip */ }
        }

        if (!issues.Any(i => i.Contains("SWG")))
            details.Add("✓ No known SWG processes detected");

        // 4. Check Windows Firewall for UDP 3478 block rules
        try
        {
            var psi = new ProcessStartInfo("netsh", "advfirewall firewall show rule name=all dir=out")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync(ct);
                await proc.WaitForExitAsync(ct);

                if (output.Contains("3478") || output.Contains("UDP") && output.Contains("Block"))
                {
                    details.Add("⚠ Windows Firewall has outbound rules that may affect UDP 3478");
                }
                else
                {
                    details.Add("✓ No obvious Windows Firewall blocks for UDP");
                }
            }
        }
        catch { details.Add("— Could not check Windows Firewall rules"); }

        result.DetailedInfo = string.Join("\n", details);

        if (issues.Count == 0)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = "No UDP blocking detected";
        }
        else
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{issues.Count} issue(s) — Shortpath may fail";
            result.RemediationText = "RDP Shortpath requires unimpeded UDP connectivity to the TURN relay on port 3478. " +
                                     "VPNs, SWGs, and firewalls that block or tunnel UDP will prevent Shortpath, forcing TCP fallback with higher latency.\n\n" +
                                     "Issues found:\n• " + string.Join("\n• ", issues);
        }

        result.RemediationUrl = EndpointConfiguration.Docs.TurnRelay;
    }
}

// ════════════════════════════════════════════════════════════════════
// Endpoint Access — checks all required end-user device FQDNs
// https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices
// ════════════════════════════════════════════════════════════════════
public class EndpointAccessTest : BaseTest
{
    public override string Id => "23";
    public override string Name => "Required Endpoint Access";
    public override string Description => "Checks connectivity to all required FQDNs for Azure Virtual Desktop end-user devices per Microsoft documentation.";
    public override TestCategory Category => TestCategory.EndpointAccess;

    /// <summary>
    /// Required FQDN endpoints for end-user devices.
    /// For wildcard entries the exemplar host is used for testing.
    /// </summary>
    private static readonly (string Fqdn, string TestHost, int Port, string Purpose)[] RequiredEndpoints =
    [
        // ── Authentication ──
        ("login.microsoftonline.com",          "login.microsoftonline.com",          443, "Authentication to Microsoft Online Services"),

        // ── AVD Service traffic ──
        ("*.wvd.microsoft.com",                "rdweb.wvd.microsoft.com",            443, "AVD service traffic"),

        // ── Troubleshooting / Diagnostics ──
        ("*.servicebus.windows.net",           "wvd-eventhubs-weu-prod.servicebus.windows.net", 443, "Troubleshooting data"),

        // ── Microsoft FWLinks & URL shortener ──
        ("go.microsoft.com",                   "go.microsoft.com",                   443, "Microsoft FWLinks"),
        ("aka.ms",                             "aka.ms",                             443, "Microsoft URL shortener"),

        // ── Documentation & Privacy ──
        ("learn.microsoft.com",                "learn.microsoft.com",                443, "Documentation"),
        ("privacy.microsoft.com",              "privacy.microsoft.com",              443, "Privacy statement"),

        // ── Office CDN (Windows Desktop client updates) ──
        ("*.cdn.office.net",                   "statics.teams.cdn.office.net",       443, "Automatic updates (Windows Desktop)"),

        // ── Graph ──
        ("graph.microsoft.com",                "graph.microsoft.com",                443, "Service traffic"),

        // ── Connection center ──
        ("windows.cloud.microsoft",            "windows.cloud.microsoft",            443, "Connection center"),
        ("windows365.microsoft.com",           "windows365.microsoft.com",           443, "Service traffic"),
        ("ecs.office.com",                     "ecs.office.com",                     443, "Connection center"),

        // ── Telemetry ──
        ("*.events.data.microsoft.com",        "v10.events.data.microsoft.com",      443, "Client telemetry"),

        // ── Certificates (port 80) ──
        ("*.microsoftaik.azure.net",           "azcsprodeusaikpublish.microsoftaik.azure.net", 80, "Certificates"),
        ("www.microsoft.com",                  "www.microsoft.com",                  80,  "Certificates"),
        ("*.aikcertaia.microsoft.com",         "eus.aikcertaia.microsoft.com",       80,  "Certificates"),
        ("azcsprodeusaikpublish.blob.core.windows.net", "azcsprodeusaikpublish.blob.core.windows.net", 80, "Certificates"),
    ];

    protected override async Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        var passed  = new List<string>();
        var failed  = new List<string>();
        var details = new List<string>();

        details.Add("Required FQDNs for end-user devices");
        details.Add("Source: https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices");
        details.Add("");

        using var http = new HttpClient(new HttpClientHandler
        {
            // Accept any cert — we're testing reachability, not validity
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AllowAutoRedirect = false
        })
        { Timeout = TimeSpan.FromSeconds(10) };

        // Run all checks in parallel (bounded)
        var tasks = RequiredEndpoints.Select(async ep =>
        {
            var (fqdn, testHost, port, purpose) = ep;
            var label = fqdn == testHost ? fqdn : $"{fqdn} (→ {testHost})";

            try
            {
                var scheme = port == 443 ? "https" : "http";
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(10_000);

                // First try HTTP(S) request
                try
                {
                    var response = await http.GetAsync($"{scheme}://{testHost}", cts.Token);
                    return (Fqdn: fqdn, Label: label, Port: port, Purpose: purpose,
                            Ok: true, Detail: $"HTTP {(int)response.StatusCode}");
                }
                catch
                {
                    // Fall back to raw TCP connect
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(testHost, port, cts.Token);
                    return (Fqdn: fqdn, Label: label, Port: port, Purpose: purpose,
                            Ok: true, Detail: "TCP connected");
                }
            }
            catch (Exception ex)
            {
                var msg = ex is OperationCanceledException ? "Timed out" : ex.InnerException?.Message ?? ex.Message;
                return (Fqdn: fqdn, Label: label, Port: port, Purpose: purpose,
                        Ok: false, Detail: msg);
            }
        }).ToArray();

        var results = await Task.WhenAll(tasks);

        foreach (var r in results)
        {
            var portLabel = $":{r.Port}";
            if (r.Ok)
            {
                passed.Add(r.Fqdn);
                details.Add($"  ✓ {r.Label}{portLabel} — {r.Detail}  ({r.Purpose})");
            }
            else
            {
                failed.Add(r.Fqdn);
                details.Add($"  ✗ {r.Label}{portLabel} — {r.Detail}  ({r.Purpose})");
            }
        }

        details.Add("");
        details.Add($"Result: {passed.Count}/{results.Length} endpoints reachable");

        result.DetailedInfo = string.Join("\n", details);
        result.RemediationUrl = "https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices";

        if (failed.Count == 0)
        {
            result.Status = TestStatus.Passed;
            result.ResultValue = $"All {passed.Count} endpoints reachable";
        }
        else if (passed.Count > failed.Count)
        {
            result.Status = TestStatus.Warning;
            result.ResultValue = $"{failed.Count} of {results.Length} endpoint(s) blocked";
            result.RemediationText = $"The following required FQDNs are unreachable: {string.Join(", ", failed)}. " +
                                     "Ensure your firewall/proxy allows access to all required endpoints.";
        }
        else
        {
            result.Status = TestStatus.Failed;
            result.ResultValue = $"{failed.Count} of {results.Length} endpoint(s) blocked";
            result.RemediationText = "Most required AVD endpoints are unreachable. Your firewall or proxy may be blocking " +
                                     "Azure Virtual Desktop traffic. Review the required FQDN list and update your network rules.";
        }
    }
}
