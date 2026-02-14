using System.IO;
using System.Net;
using System.Net.Http;

namespace W365ConnectivityTool.Services;

/// <summary>
/// Centralized configuration of Windows 365 / AVD service endpoints used for connectivity testing.
/// Based on publicly documented required URLs: https://learn.microsoft.com/windows-365/enterprise/requirements-network
/// </summary>
public static class EndpointConfiguration
{
    // ── Windows 365 Gateway IP Ranges ──
    // All RDP connections from Windows 365 clients are destined for these ranges ONLY.
    // 40.64.144.0/20  = Windows 365 / AVD Gateway infrastructure
    // 51.5.0.0/16     = Windows 365 / AVD Gateway infrastructure (newer range)
    public static readonly (IPAddress Network, int PrefixLength)[] W365GatewayRanges =
    [
        (IPAddress.Parse("40.64.144.0"), 20),   // 40.64.144.0 – 40.64.159.255
        (IPAddress.Parse("51.5.0.0"), 16),      // 51.5.0.0 – 51.5.255.255
    ];

    /// <summary>
    /// Tests whether an IP address is within the documented Windows 365 gateway IP ranges.
    /// </summary>
    public static bool IsInW365Range(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var ipBytes = ip.GetAddressBytes();

        foreach (var (network, prefixLength) in W365GatewayRanges)
        {
            var netBytes = network.GetAddressBytes();
            int fullBytes = prefixLength / 8;
            int remainBits = prefixLength % 8;

            bool match = true;
            for (int i = 0; i < fullBytes && match; i++)
                match = ipBytes[i] == netBytes[i];

            if (match && remainBits > 0)
            {
                byte mask = (byte)(0xFF << (8 - remainBits));
                match = (ipBytes[fullBytes] & mask) == (netBytes[fullBytes] & mask);
            }

            if (match) return true;
        }
        return false;
    }

    /// <summary>
    /// Returns a human-readable string of the W365 gateway IP ranges.
    /// </summary>
    public static string W365RangesDisplay => "40.64.144.0/20, 51.5.0.0/16";

    /// <summary>
    /// Resolves and validates a gateway endpoint for Cloud Session probes.
    /// Only returns endpoints whose resolved IPs fall within W365 gateway ranges.
    /// Tries each discovered RDP connection's GatewayHostname and AfdHostname.
    /// Returns null if no valid endpoint is found — callers must NOT probe non-W365 IPs.
    /// </summary>
    public static async Task<ValidatedEndpoint?> GetValidatedGatewayForProbes(CancellationToken ct)
    {
        var connections = Tests.RdpFileParser.DiscoverConnections();

        foreach (var conn in connections)
        {
            // Try the full address (actual RD Gateway) first — resolves to W365 IP ranges
            var validated = await ValidateEndpointInRange(conn.GatewayHostname, GatewayPort, ct);
            if (validated != null) return validated;

            // Try the AFD hostname (Azure Front Door → gateway backend)
            if (conn.AfdHostname != null)
            {
                validated = await ValidateEndpointInRange(conn.AfdHostname, conn.AfdPort, ct);
                if (validated != null) return validated;
            }
        }

        return null; // No endpoint found within W365 ranges
    }

    private static async Task<ValidatedEndpoint?> ValidateEndpointInRange(string hostname, int port, CancellationToken ct)
    {
        try
        {
            var ips = await System.Net.Dns.GetHostAddressesAsync(hostname, ct);
            var ip = ips.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (ip != null && IsInW365Range(ip))
                return new ValidatedEndpoint(hostname, port, ip);
        }
        catch { /* DNS failure — skip this endpoint */ }
        return null;
    }

    /// <summary>
    /// A resolved gateway endpoint validated as being within W365 IP ranges.
    /// </summary>
    public record ValidatedEndpoint(string Hostname, int Port, IPAddress ResolvedIp);

    /// <summary>
    /// Returns the TURN relay endpoint for UDP/STUN/RDP Shortpath probes.
    /// This is the only valid UDP endpoint for measuring RDP transport readiness.
    /// </summary>
    public const string TurnRelayProbeEndpoint = "world.relay.avd.microsoft.com";
    public const int TurnRelayProbePort = 3478;

    // ── Authentication ──
    public static readonly string[] AuthEndpoints =
    [
        "login.microsoftonline.com",
        "login.windows.net"
    ];

    // ── AVD / Windows 365 Service ──
    public static readonly string[] ServiceEndpoints =
    [
        "rdweb.wvd.microsoft.com",
        "client.wvd.microsoft.com",
        "rdbroker.wvd.microsoft.com"
    ];

    // ── RD Gateway ──
    // The real gateway hostname is extracted from local RDP files (gatewayhostname field)
    // e.g. afdfp-rdgateway-r0.wvd.microsoft.com:443
    // Fallback generic endpoints if no RDP files are found.
    public const int GatewayPort = 443;
    public const string FallbackGatewayEndpoint = "rdweb.wvd.microsoft.com";
    public static readonly string[] FallbackGatewayEndpoints =
    [
        "rdweb.wvd.microsoft.com",
        "client.wvd.microsoft.com"
    ];

    /// <summary>
    /// Returns the best known actual RD Gateway hostname (from "full address" in RDP files),
    /// falling back to a generic endpoint if no RDP files are found.
    /// </summary>
    public static string GetBestGatewayEndpoint()
    {
        var connections = Tests.RdpFileParser.DiscoverConnections();
        return connections.Count > 0 ? connections[0].GatewayHostname : FallbackGatewayEndpoint;
    }

    // ── RDP File locations (Windows App, Remote Desktop client, Windows 365) ──
    public static string[] GetRdpFileSearchPaths()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var paths = new List<string>
        {
            Path.Combine(localAppData, "Microsoft", "Windows365", "RdpFiles"),
            Path.Combine(localAppData, "rdclientwpf")
        };

        // Find Windows 365 / Windows App Client MSIX package folders specifically
        // (avoid scanning the entire Packages directory)
        var packagesDir = Path.Combine(localAppData, "Packages");
        if (Directory.Exists(packagesDir))
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(packagesDir))
                {
                    var name = Path.GetFileName(dir);
                    if (name.StartsWith("MicrosoftCorporationII.Windows365", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("MicrosoftCorporationII.WindowsAppClient", StringComparison.OrdinalIgnoreCase))
                    {
                        paths.Add(dir);
                    }
                }
            }
            catch { /* access denied is non-fatal */ }
        }

        return paths.ToArray();
    }

    // ── TURN Relay ──
    // TURN relay endpoint: world.relay.avd.microsoft.com (UDP 3478)
    public static readonly string[] TurnRelayEndpoints =
    [
        "world.relay.avd.microsoft.com"
    ];
    public const int TurnRelayPort = 3478;

    // ── STUN Servers (for NAT type detection) ──
    public const string StunServer = "stun.l.google.com";
    public const int StunPort = 19302;

    // ── Geo-IP API (HTTPS required for secure transport) ──
    public const string GeoIpApiUrl = "https://ipinfo.io/json";
    public const string GeoIpFallbackUrl = "https://ipapi.co/json";
    public const string GeoIpFallback2Url = "https://ipwho.is/";
    public const string GeoIpFallback3Url = "https://get.geojs.io/v1/ip/geo.json";

    private static readonly string[] GeoIpProviders = [GeoIpApiUrl, GeoIpFallbackUrl, GeoIpFallback2Url, GeoIpFallback3Url];

    /// <summary>
    /// Fetches GeoIP JSON with cascading fallback across 4 providers and 429 retry.
    /// Providers: ipinfo.io → ipapi.co → ipwho.is → geojs.io
    /// </summary>
    public static async Task<string> FetchGeoIpJsonAsync(HttpClient http, CancellationToken ct)
    {
        Exception? lastEx = null;
        foreach (var providerUrl in GeoIpProviders)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var response = await http.GetAsync(providerUrl, ct);
                    if (response.StatusCode == (System.Net.HttpStatusCode)429)
                    {
                        if (attempt == 0) { await Task.Delay(1500, ct); continue; }
                        break; // move to next provider
                    }
                    response.EnsureSuccessStatusCode();
                    return await response.Content.ReadAsStringAsync(ct);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    lastEx = ex;
                    break; // move to next provider
                }
            }
        }
        throw lastEx ?? new HttpRequestException("All GeoIP providers failed");
    }

    // ── DNS Test targets ──
    public static readonly string[] DnsTestHostnames =
    [
        "rdweb.wvd.microsoft.com",
        "login.microsoftonline.com",
        "client.wvd.microsoft.com"
    ];

    // ── Azure Status ──
    public const string AzureStatusUrl = "https://status.azure.com/en-gb/status";
    public const string ServiceHealthApiUrl = "https://management.azure.com"; // Requires auth so we use status page

    // ── TLS Certificate validation ──
    // Expected certificate issuers for RDP gateway connections
    public static readonly string[] ExpectedCertIssuers =
    [
        "Microsoft",
        "DigiCert",
        "Microsoft Azure RSA TLS Issuing CA",
        "Microsoft Azure TLS Issuing CA"
    ];

    // ── Documentation Links ──
    public static class Docs
    {
        public const string NetworkRequirements = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
        public const string DnsConfig = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#dns-requirements";
        public const string ProxyConfig = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#proxy-configuration";
        public const string TlsInspection = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#tls-inspection";
        public const string Bandwidth = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#bandwidth-requirements";
        public const string AvdRequiredUrls = "https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint";
        public const string TurnRelay = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
        public const string TeamsOptimization = "https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd";
        public const string NatType = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=public-networks#network-address-translation-and-firewalls";
        public const string WifiPerformance = "https://learn.microsoft.com/windows-365/enterprise/troubleshoot-windows-365-boot#networking-checks";
        public const string ServiceHealth = "https://status.azure.com";
    }
}
