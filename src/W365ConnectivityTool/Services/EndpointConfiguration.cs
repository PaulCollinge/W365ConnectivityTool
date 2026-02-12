using System.IO;
using System.Net.Http;

namespace W365ConnectivityTool.Services;

/// <summary>
/// Centralized configuration of Windows 365 / AVD service endpoints used for connectivity testing.
/// Based on publicly documented required URLs: https://learn.microsoft.com/windows-365/enterprise/requirements-network
/// </summary>
public static class EndpointConfiguration
{
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
