// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
using System.Text.RegularExpressions;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

[assembly: SupportedOSPlatform("windows")]

namespace W365LocalScanner;

class Program
{
    // ── Static field: are we running in Cloud PC mode? ──
    static bool _isCloudPcMode = false;
    static string? _azureVmRegion = null;
    static string? _azureVmName = null;
    // "cloudpc", "avd", or null (unknown / client mode)
    static string? _hostType = null;

    // ── Session Watch (continuous monitoring) — strictly opt-in, default OFF.
    //    When enabled, a full run-once snapshot runs FIRST (unchanged), then a
    //    separate lightweight sampler loop monitors the live path. ──
    static bool _watchEnabled = false;
    static int _watchDurationSeconds = 300; // 0 = until stopped (Ctrl+C)
    static int _watchIntervalSeconds = 3;   // seconds between samples

    // ── Headless mode (--no-browser): strictly opt-in, default OFF.
    //    Runs every test and writes W365ScanResults.json exactly as normal, but
    //    suppresses the automatic browser tab. Intended for unattended/agent
    //    invocations (RDAgent on Cloud PC / Session Host) that consume the JSON
    //    directly. The default interactive behaviour is unchanged. ──
    static bool _noBrowser = false;

    // ── Self-host (Microsoft-internal) endpoint check: runs AUTOMATICALLY, but ONLY
    //    when the device proves it is a Microsoft-internal machine (corp-AD domain
    //    join or Entra join to the Microsoft tenant — see IsMicrosoftInternalDevice).
    //    An extra test (L-TCP-11 / C-TCP-10) probes the internal self-host/dogfood
    //    AVD endpoints (deschutes-sh, *.wvdselfhost.microsoft.com). External
    //    customers can never see or run it. ──

    // ── Dashboard location. The ONLY runtime coupling between the scanner and
    //    the web dashboard: the scanner opens this URL (with the results encoded
    //    in the URL hash) after a scan. To rehost the dashboard (e.g. to an
    //    MS-owned site), change this single value and ship a new signed release.
    //    Trailing slash is required. ──
    const string DashboardBaseUrl = "https://paulcollinge.github.io/W365ConnectivityTool/";

    // ── Compressed, base64url-encoded run-once snapshot payload (the same
    //    #zresults= blob OpenBrowserWithResults embeds in the snapshot tab).
    //    Cached here so that when Session Watch completes and opens its own
    //    browser tab, that tab can ALSO carry the full snapshot — otherwise the
    //    watch tab's "Snapshot" sub-tab would be blank (no results were ever
    //    loaded into that page). Set once in OpenBrowserWithResults. ──
    static string? _snapshotResultsB64 = null;

    // ── Cached AFD-discovered RDP gateway (set once, reused by all tests) ──
    static string? _cachedGatewayHost = null;
    static string? _cachedGatewayDetail = null;

    // ── When the slow traceroute (L-TCP-10) runs concurrently in the background,
    //    suppress its inline per-hop console output so it doesn't tangle with the
    //    [i/N] progress lines of the foreground tests. Its detailed report is still
    //    captured in the TestResult. ──
    static bool _traceConsoleSilent = false;

    // ── Dynamic Service Tags WVD subnet → region lookup ──
    static List<(uint network, uint mask, string region)>? _wvdSubnets = null;
    const string ServiceTagsDownloadPage = "https://www.microsoft.com/en-us/download/details.aspx?id=56519";

    /// <summary>
    /// Discovers the current Azure Service Tags JSON and builds a prefix → region
    /// lookup table for WindowsVirtualDesktop.* entries (IPv4 only). Falls back
    /// to the newest local cache before using the hard-coded tables downstream.
    /// </summary>
    static async Task InitServiceTagsLookupAsync()
    {
        Exception? refreshError = null;
        try
        {
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(20));
            var (json, sourceUrl, publishedDate) = await DownloadCurrentServiceTagsJsonAsync(http);
            _wvdSubnets = ParseServiceTagsSubnets(json);
            CacheServiceTagsJson(json, publishedDate);
        }
        catch (Exception ex)
        {
            refreshError = ex;
        }

        if (_wvdSubnets != null) return;

        var cached = TryLoadCachedServiceTagsJson();
        if (cached != null)
        {
            try
            {
                _wvdSubnets = ParseServiceTagsSubnets(cached.Value.json);
                var ageDays = cached.Value.publishedDate == null
                    ? null
                    : (int?)Math.Max(0, (DateTime.UtcNow.Date - cached.Value.publishedDate.Value.Date).Days);
                Console.WriteLine(ageDays != null
                    ? $"  Warning: Azure Service Tags refresh failed ({refreshError?.Message}); using cached table from {cached.Value.publishedDate:yyyy-MM-dd} ({ageDays} days old)."
                    : $"  Warning: Azure Service Tags refresh failed ({refreshError?.Message}); using cached table {Path.GetFileName(cached.Value.path)}.");
                Console.WriteLine();
                return;
            }
            catch (Exception ex)
            {
                refreshError = ex;
            }
        }

        Console.WriteLine($"  Warning: Azure Service Tags could not be loaded ({refreshError?.Message ?? "unknown error"}).");
        Console.WriteLine("  Falling back to built-in W365/AVD range tables; region and DNS-hijack verdicts may be less current.");
        Console.WriteLine();
    }

    static async Task<(string json, string sourceUrl, DateTime? publishedDate)> DownloadCurrentServiceTagsJsonAsync(HttpClient http)
    {
        var page = await http.GetStringAsync(ServiceTagsDownloadPage);
        var matches = Regex.Matches(page, @"https://download\.microsoft\.com/[^""']*ServiceTags_Public_(\d{8})\.json")
            .Cast<Match>()
            .Select(m => new
            {
                Url = WebUtility.HtmlDecode(m.Value),
                Published = TryParseServiceTagsDate(m.Groups[1].Value)
            })
            .Where(m => m.Published != null)
            .GroupBy(m => m.Url)
            .Select(g => g.First())
            .OrderByDescending(m => m.Published)
            .ToList();

        if (matches.Count == 0)
            throw new InvalidOperationException("current Service Tags download link was not found");

        var latest = matches[0];
        var json = await http.GetStringAsync(latest.Url);
        return (json, latest.Url, latest.Published);
    }

    static List<(uint network, uint mask, string region)> ParseServiceTagsSubnets(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var entries = new List<(uint network, uint mask, string region)>();

        foreach (var value in doc.RootElement.GetProperty("values").EnumerateArray())
        {
            var name = value.GetProperty("name").GetString() ?? "";
            if (!name.StartsWith("WindowsVirtualDesktop.", StringComparison.OrdinalIgnoreCase))
                continue;
            var props = value.GetProperty("properties");
            var region = props.GetProperty("region").GetString() ?? "";
            if (string.IsNullOrEmpty(region)) continue;

            foreach (var prefix in props.GetProperty("addressPrefixes").EnumerateArray())
            {
                var cidr = prefix.GetString();
                if (cidr == null || cidr.Contains(':')) continue; // skip IPv6
                var parts = cidr.Split('/');
                if (parts.Length != 2) continue;
                if (!IPAddress.TryParse(parts[0], out var addr)) continue;
                if (!int.TryParse(parts[1], out var prefixLen)) continue;
                if (prefixLen < 0 || prefixLen > 32) continue;
                var bytes = addr.GetAddressBytes();
                uint net = (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
                uint m = prefixLen == 0 ? 0 : ~((1u << (32 - prefixLen)) - 1);
                entries.Add((net & m, m, region));
            }
        }

        if (entries.Count == 0)
            throw new InvalidOperationException("Service Tags JSON contained no WindowsVirtualDesktop IPv4 prefixes");

        // Sort by mask descending (longest prefix first) for correct matching
        entries.Sort((a, b) => b.mask.CompareTo(a.mask));
        return entries;
    }

    static string ServiceTagsCacheDirectory()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root)) root = Path.GetTempPath();
        return Path.Combine(root, "W365ConnectivityTool", "service-tags");
    }

    static void CacheServiceTagsJson(string json, DateTime? publishedDate)
    {
        if (publishedDate == null) return;
        try
        {
            var dir = ServiceTagsCacheDirectory();
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, $"ServiceTags_Public_{publishedDate:yyyyMMdd}.json");
            File.WriteAllText(path, json, Encoding.UTF8);
        }
        catch { /* cache is best-effort */ }
    }

    static (string json, string path, DateTime? publishedDate)? TryLoadCachedServiceTagsJson()
    {
        try
        {
            var dir = ServiceTagsCacheDirectory();
            if (!Directory.Exists(dir)) return null;
            foreach (var path in Directory.GetFiles(dir, "ServiceTags_Public_*.json")
                         .Select(p => new { Path = p, Date = TryExtractServiceTagsDate(p) })
                         .OrderByDescending(x => x.Date ?? DateTime.MinValue))
            {
                try
                {
                    return (File.ReadAllText(path.Path, Encoding.UTF8), path.Path, path.Date);
                }
                catch { /* try next cache file */ }
            }
        }
        catch { }
        return null;
    }

    static DateTime? TryExtractServiceTagsDate(string value)
    {
        var m = Regex.Match(value, @"ServiceTags_Public_(\d{8})\.json", RegexOptions.IgnoreCase);
        return m.Success ? TryParseServiceTagsDate(m.Groups[1].Value) : null;
    }

    static DateTime? TryParseServiceTagsDate(string yyyymmdd)
    {
        if (yyyymmdd.Length != 8) return null;
        if (!int.TryParse(yyyymmdd.Substring(0, 4), out var year)) return null;
        if (!int.TryParse(yyyymmdd.Substring(4, 2), out var month)) return null;
        if (!int.TryParse(yyyymmdd.Substring(6, 2), out var day)) return null;
        try
        {
            return new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Looks up any IP against the dynamically-loaded Service Tags WVD subnet table.
    /// Returns the Azure region identifier (e.g. "uksouth") or null.
    /// </summary>
    static string? LookupWvdRegionFromServiceTags(IPAddress ip)
    {
        if (_wvdSubnets == null || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;
        var bytes = ip.GetAddressBytes();
        uint addr = (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
        foreach (var (network, mask, region) in _wvdSubnets)
        {
            if ((addr & mask) == network)
                return region;
        }
        return null;
    }

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

        // ── Session Watch flags (strictly opt-in) ──
        //   --watch [5m|300s|until-stopped]   bare --watch defaults to 5 minutes
        //   --interval [Ns]                   default 3s, clamped 2–60s
        // No flag = today's run-once behaviour, byte-for-byte unchanged.
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.Equals("--watch", StringComparison.OrdinalIgnoreCase) || a.StartsWith("--watch=", StringComparison.OrdinalIgnoreCase))
            {
                _watchEnabled = true;
                string? val = a.Contains('=')
                    ? a.Split('=', 2)[1]
                    : (i + 1 < args.Length && !args[i + 1].StartsWith("-") ? args[i + 1] : null);
                _watchDurationSeconds = ParseWatchDuration(val);
            }
            else if (a.Equals("--interval", StringComparison.OrdinalIgnoreCase) || a.StartsWith("--interval=", StringComparison.OrdinalIgnoreCase))
            {
                string? val = a.Contains('=')
                    ? a.Split('=', 2)[1]
                    : (i + 1 < args.Length && !args[i + 1].StartsWith("-") ? args[i + 1] : null);
                _watchIntervalSeconds = ParseWatchInterval(val);
            }
            else if (a.Equals("--no-browser", StringComparison.OrdinalIgnoreCase)
                  || a.Equals("--headless", StringComparison.OrdinalIgnoreCase))
            {
                _noBrowser = true;
            }
        }

        // ── Cloud PC / AVD mode detection ──
        // Explicit flag overrides auto-detection.
        bool forceCloudPc = args.Any(a => a.Equals("--cloudpc", StringComparison.OrdinalIgnoreCase));
        bool forceAvd = args.Any(a => a.Equals("--avd", StringComparison.OrdinalIgnoreCase));
        if (forceCloudPc)
        {
            _isCloudPcMode = true;
            _hostType = "cloudpc";
        }
        else if (forceAvd)
        {
            _isCloudPcMode = true;
            _hostType = "avd";
        }
        else
        {
            // Auto-detect: probe Azure IMDS (only available inside Azure VMs)
            try
            {
                using var imdsClient = new HttpClient();
                imdsClient.DefaultRequestHeaders.Add("Metadata", "true");
                imdsClient.Timeout = TimeSpan.FromSeconds(3);
                var imdsResp = await imdsClient.GetAsync(
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"); // DevSkim: ignore DS137138 - Azure IMDS is HTTP-only by design (link-local)
                if (imdsResp.IsSuccessStatusCode)
                {
                    var imdsJson = await imdsResp.Content.ReadAsStringAsync();
                    var imdsDoc = JsonDocument.Parse(imdsJson);
                    var compute = imdsDoc.RootElement.GetProperty("compute");
                    _azureVmRegion = compute.TryGetProperty("location", out var loc) ? loc.GetString() : null;
                    _azureVmName = compute.TryGetProperty("name", out var vn) ? vn.GetString() : null;
                    var vmSize = compute.TryGetProperty("vmSize", out var vs) ? vs.GetString() ?? "" : "";
                    var resourceGroup = compute.TryGetProperty("resourceGroupName", out var rg) ? rg.GetString() ?? "" : "";
                    var provider = compute.TryGetProperty("provider", out var pv) ? pv.GetString() ?? "" : "";
                    var tags = compute.TryGetProperty("tags", out var tg) ? tg.GetString() ?? "" : "";

                    // Read image offer & SKU for definitive Cloud PC vs AVD detection
                    var offer = compute.TryGetProperty("offer", out var ofVal) ? ofVal.GetString() ?? "" : "";
                    var sku = compute.TryGetProperty("sku", out var skVal) ? skVal.GetString() ?? "" : "";
                    var publisher = compute.TryGetProperty("publisher", out var pb) ? pb.GetString() ?? "" : "";

                    // 1. IMDS offer/sku containing "cpc" is definitive Cloud PC signal
                    // 2. VM size "_cpc" or name/RG/tags patterns are strong Cloud PC signals
                    // 3. Registry HKLM\SOFTWARE\Microsoft\Windows 365 is definitive
                    // 4. Publisher "MicrosoftWindowsDesktop" with offer containing "windows-ent-cpc" is definitive
                    var isLikelyCloudPc = offer.Contains("cpc", StringComparison.OrdinalIgnoreCase)
                        || sku.Contains("cpc", StringComparison.OrdinalIgnoreCase)
                        || vmSize.Contains("_cpc", StringComparison.OrdinalIgnoreCase)
                        || (_azureVmName?.Contains("cloudpc", StringComparison.OrdinalIgnoreCase) ?? false)
                        || (_azureVmName?.Contains("w365", StringComparison.OrdinalIgnoreCase) ?? false)
                        || resourceGroup.Contains("cloudpc", StringComparison.OrdinalIgnoreCase)
                        || resourceGroup.Contains("w365", StringComparison.OrdinalIgnoreCase)
                        || tags.Contains("CloudPC", StringComparison.OrdinalIgnoreCase)
                        || tags.Contains("Windows365", StringComparison.OrdinalIgnoreCase)
                        || provider.Contains("DesktopVirtualization", StringComparison.OrdinalIgnoreCase);

                    // Check W365 registry key as additional definitive signal
                    bool hasW365Registry = false;
                    try
                    {
                        using var w365Key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows 365");
                        hasW365Registry = w365Key != null;
                    }
                    catch { /* Registry access may be restricted */ }

                    if (isLikelyCloudPc || hasW365Registry)
                    {
                        _isCloudPcMode = true;
                        _hostType = "cloudpc";
                    }
                    else if (resourceGroup.Contains("wvd", StringComparison.OrdinalIgnoreCase)
                          || resourceGroup.Contains("avd", StringComparison.OrdinalIgnoreCase)
                          || tags.Contains("AVD", StringComparison.OrdinalIgnoreCase)
                          || tags.Contains("WVD", StringComparison.OrdinalIgnoreCase)
                          || tags.Contains("SessionHost", StringComparison.OrdinalIgnoreCase))
                    {
                        // Looks like an AVD session host — still run server-side tests
                        _isCloudPcMode = true;
                        _hostType = "avd";
                    }
                    else
                    {
                        // Azure VM but can't determine type — show what we found and ask user
                        Console.WriteLine($"  Azure VM detected: {_azureVmName ?? "unknown"} ({vmSize}) in {_azureVmRegion ?? "unknown"}");
                        Console.WriteLine($"    offer={offer} sku={sku} publisher={publisher}");
                        Console.WriteLine($"    rg={resourceGroup} tags={tags}");
                        Console.WriteLine($"    registry W365={hasW365Registry}");
                        Console.Write("  Is this a Cloud PC (C) or AVD Session Host (A)? [C/a/skip]: ");
                        var key = Console.ReadLine()?.Trim();
                        if (key != null && key.StartsWith("a", StringComparison.OrdinalIgnoreCase))
                        {
                            _isCloudPcMode = true;
                            _hostType = "avd";
                        }
                        else if (key != null && key.StartsWith("s", StringComparison.OrdinalIgnoreCase))
                        {
                            _isCloudPcMode = false;
                        }
                        else
                        {
                            _isCloudPcMode = true;
                            _hostType = "cloudpc";
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"  IMDS returned {(int)imdsResp.StatusCode} — running in client mode");
                }
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("  IMDS probe timed out (169.254.169.254 unreachable)");
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"  IMDS probe failed ({ex.InnerException?.Message ?? ex.Message})");
            }
            catch { /* Not in Azure — client mode */ }

            // ── Fallback detection when IMDS is unavailable (VPN/firewall blocking link-local) ──
            //
            // Important: registry keys like HKLM\SOFTWARE\Microsoft\Windows 365 are also
            // created on regular laptops by the **Windows 365 client app** (Windows App).
            // RDInfraAgent / RDAgentBootLoader are similarly available outside CPC images
            // when admins install Remote Desktop tooling. Treating any of these as a
            // standalone CPC signal mis-flags client laptops as Cloud PCs, which then
            // cascades through the dashboard (mode=cloudpc, CPC cards populated from
            // laptop data, "run the local scanner" CTA still showing). Require an
            // Azure-VM-only corroborating signal (WindowsAzureGuestAgent service) before
            // accepting the registry/service hints below.
            if (!_isCloudPcMode)
            {
                bool isAzureVm = false;
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController("WindowsAzureGuestAgent");
                    _ = sc.Status; // Throws if service doesn't exist
                    isAzureVm = true;
                }
                catch { /* Not an Azure VM */ }

                if (!isAzureVm)
                {
                    Console.WriteLine("  Running in client mode");
                    Console.WriteLine("  Tip: If this is a Cloud PC where IMDS is blocked, use --cloudpc flag");
                }
                else
                {
                    bool detectedViaFallback = false;
                    string fallbackSignal = "";

                    // 1. Registry: Windows 365 key — only meaningful on an Azure VM
                    //    (on laptops it's left behind by the W365 client app).
                    try
                    {
                        using var w365Key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows 365");
                        if (w365Key != null)
                        {
                            detectedViaFallback = true;
                            _hostType = "cloudpc";
                            fallbackSignal = "Azure VM + registry HKLM\\SOFTWARE\\Microsoft\\Windows 365";
                        }
                    }
                    catch { /* Registry access restricted */ }

                    // 2. Registry: RDInfraAgent key (AVD/W365 infrastructure agent)
                    if (!detectedViaFallback)
                    {
                        try
                        {
                            using var rdKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\RDInfraAgent");
                            if (rdKey != null)
                            {
                                detectedViaFallback = true;
                                _hostType = "cloudpc"; // Default to CPC, refine below
                                fallbackSignal = "Azure VM + registry HKLM\\SOFTWARE\\Microsoft\\RDInfraAgent";

                                // Check if it's specifically an AVD host
                                var isTemp = rdKey.GetValue("IsRegisteredAsSessionHost");
                                if (isTemp != null && isTemp.ToString() == "1")
                                {
                                    _hostType = "avd";
                                }
                            }
                        }
                        catch { /* Registry access restricted */ }
                    }

                    // 3. Service: RDAgentBootLoader (present on Cloud PCs and AVD session hosts)
                    if (!detectedViaFallback)
                    {
                        try
                        {
                            using var sc = new System.ServiceProcess.ServiceController("RDAgentBootLoader");
                            _ = sc.Status; // Throws if service doesn't exist
                            detectedViaFallback = true;
                            _hostType = "cloudpc";
                            fallbackSignal = "Azure VM + service RDAgentBootLoader";
                        }
                        catch { /* Service not found */ }
                    }

                    // 4. Azure VM with no CPC/AVD-specific signal — ask the user
                    if (!detectedViaFallback)
                    {
                        Console.WriteLine("  Azure VM detected via Guest Agent (IMDS unreachable — VPN may be blocking link-local)");
                        Console.Write("  Is this a Cloud PC (C) or AVD Session Host (A)? [C/a/skip]: ");
                        var key = Console.ReadLine()?.Trim();
                        if (key != null && key.StartsWith("a", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedViaFallback = true;
                            _hostType = "avd";
                            fallbackSignal = "Azure VM + user confirmed AVD";
                        }
                        else if (key == null || !key.StartsWith("s", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedViaFallback = true;
                            _hostType = "cloudpc";
                            fallbackSignal = "Azure VM + user confirmed Cloud PC";
                        }
                    }

                    if (detectedViaFallback)
                    {
                        _isCloudPcMode = true;
                        Console.WriteLine($"  Detected as {(_hostType == "avd" ? "AVD Session Host" : "Cloud PC")} via {fallbackSignal}");
                        if (_azureVmRegion == null)
                        {
                            Console.WriteLine("  Note: Azure region unknown (IMDS unavailable). Location tests may be limited.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("  Running in client mode");
                    }
                }
            }
        }

        if (_isCloudPcMode)
        {
            var hostLabel = _hostType == "avd" ? "AVD Session Host" : "Cloud PC";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════╗");
            Console.WriteLine($"║   {hostLabel,-18} Connectivity Scanner           ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════╣");
            Console.WriteLine($"║   Running on {hostLabel,-20} — tests the        ║");
            Console.WriteLine("║   server-side connectivity back to the RDP Gateway  ║");
            Console.WriteLine("║   and TURN relay. Import results into the web       ║");
            Console.WriteLine("║   dashboard alongside client-side results.          ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════╝");
            Console.ResetColor();
            if (_azureVmRegion != null)
                Console.WriteLine($"  Azure region: {_azureVmRegion}  VM: {_azureVmName ?? "unknown"}  Type: {hostLabel}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════╗");
            Console.WriteLine("║   Windows 365 / AVD Local Connectivity Scanner      ║");
            Console.WriteLine($"║   Version {typeof(Program).Assembly.GetName().Version?.ToString() ?? "?"}{"".PadRight(42 - (typeof(Program).Assembly.GetName().Version?.ToString()?.Length ?? 1))}║");
            Console.WriteLine("╠══════════════════════════════════════════════════════╣");
            Console.WriteLine("║   Runs tests requiring local OS access.             ║");
            Console.WriteLine("║   Import results into the web diagnostics page.     ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════╝");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Determine whether to run Live Connection Diagnostics (cloud tests).
        // These take ~60s each to sample performance data.
        // In Cloud PC mode, live connection diagnostics are skipped (no active RDP session on the server).
        // Can be controlled via --include-cloud / --skip-cloud flags, or interactive prompt.
        bool includeCloud;
        if (_isCloudPcMode)
        {
            includeCloud = false; // Cloud PC mode doesn't run live session tests
        }
        else if (args.Any(a => a.Equals("--include-cloud", StringComparison.OrdinalIgnoreCase)))
        {
            includeCloud = true;
        }
        else if (args.Any(a => a.Equals("--skip-cloud", StringComparison.OrdinalIgnoreCase)))
        {
            includeCloud = false;
        }
        else if (Console.IsInputRedirected)
        {
            // Unattended (stdin redirected / piped / CI): never block on an
            // interactive prompt. Default to running every test ("exactly as
            // normal"); callers can still opt out with --skip-cloud.
            // NOTE: --no-browser does NOT skip this prompt — it only suppresses
            // the auto-opened browser tab, so an interactive user is still asked.
            includeCloud = true;
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

        // Load Service Tags for dynamic IP → region lookups (non-blocking, silent fallback)
        await InitServiceTagsLookupAsync();

        var allTests = _isCloudPcMode ? GetCloudPcTests() : GetAllTests();
        var tests = includeCloud ? allTests : allTests.Where(t => t.Category != "cloud").ToList();

        // Microsoft-internal devices automatically include the self-host endpoint
        // checks (L-TCP-11 / C-TCP-10). Print a one-line confirmation so an internal
        // tester knows they engaged; customers never register these tests, so they
        // see nothing here.
        if (allTests.Any(t => t.Id == "L-TCP-11" || t.Id == "C-TCP-10"))
        {
            Console.WriteLine("  Microsoft-internal device detected — self-host endpoint checks (L-TCP-11/C-TCP-10) included.");
            Console.WriteLine();
        }

        if (_isCloudPcMode)
        {
            var testLabel = _hostType == "avd" ? "AVD session host" : "Cloud PC";
            Console.WriteLine($"  Running {tests.Count} {testLabel} connectivity tests.");
            Console.WriteLine();
        }
        else if (!includeCloud)
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

        // The traceroute test (L-TCP-10) is slow (1-2 min). Kick it off FIRST as a
        // background task so its runtime overlaps every other test instead of adding
        // to the total. Its inline per-hop console output is suppressed while
        // backgrounded; we await it after the foreground tests finish, then add its
        // result before writing the JSON and opening the browser ONCE (results data
        // is passed in the URL hash, which a process-launched tab can't receive after
        // the fact — so the tab must open only after every result, traceroute
        // included, is present).
        var traceTest = tests.FirstOrDefault(t => t.Id == "L-TCP-10");
        Task<TestResult>? traceTask = null;
        if (traceTest != null)
        {
            _traceConsoleSilent = true;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  [bg] {traceTest.Name} started in background (traceroute runs while the other tests execute)");
            Console.ResetColor();
            Console.WriteLine();
            traceTask = RunSingleTestToResult(traceTest);
        }

        var foregroundCount = tests.Count - (traceTest != null ? 1 : 0);
        int shown = 0;
        for (int i = 0; i < tests.Count; i++)
        {
            var test = tests[i];
            if (traceTest != null && test.Id == traceTest.Id)
                continue; // running in the background
            shown++;
            WriteTestLabel(shown, foregroundCount, test.Name);
            await RunSingleTest(test, results);
        }

        // Wait for the background traceroute to finish (it usually overlaps fully
        // with the foreground tests, so this rarely blocks for long).
        if (traceTask != null)
        {
            WriteTestLabel("bg", "Finalising Network Path Trace");
            var traceResult = await traceTask;
            results.Add(traceResult);
            WriteStatusLine(traceResult.Status, traceResult.Duration);
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.WriteLine(_noBrowser
            ? "  All tests complete — results written (headless mode, browser suppressed)"
            : "  All tests complete — opening results in browser...");
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.ResetColor();

        await WriteResultsJson(outputPath, results);
        if (!_noBrowser)
            await OpenBrowserWithResults(outputPath, results);

        // Print executive summary report
        PrintSummaryReport(results, includeCloud);

        // ── Optional continuous monitoring (Session Watch) ──
        // Strictly opt-in. Runs AFTER the full run-once snapshot so the default
        // run-once path (JSON, browser tab, exit code) is byte-for-byte unchanged.
        if (_watchEnabled)
        {
            // Explicit --watch on the command line: honour it verbatim, no prompt.
            try { await RunWatchMode(); }
            catch (Exception ex) { Console.WriteLine($"  [watch] aborted: {ex.Message}"); }
        }
        else if (!Console.IsInputRedirected)
        {
            // Interactive console and --watch wasn't passed: offer a continuous
            // Session Watch. Default is N, so just pressing Enter keeps today's
            // behaviour (scan once and finish). When stdin is redirected
            // (headless / piped / CI) this whole block is skipped, so the
            // automated exit path is unchanged. --no-browser does NOT skip this
            // offer — it only suppresses the auto-opened browser tab, so an
            // interactive user gets the choice on every run.
            if (ConnectionLooksVolatile(results, out var volatileReason))
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  {volatileReason}");
                Console.WriteLine("  A single scan can't tell a stable setup from one that flaps between runs.");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("  Session Watch can monitor this connection over time to catch");
                Console.WriteLine("  intermittent issues a single scan misses (VPN route flapping,");
                Console.WriteLine("  gateway re-steering, jitter/loss bursts, DNS drift, egress changes).");
            }
            Console.Write("  Run a continuous Session Watch now? [y/N] ");
            var answer = Console.ReadLine();
            if (answer != null && answer.Trim().StartsWith("y", StringComparison.OrdinalIgnoreCase))
            {
                _watchDurationSeconds = PromptWatchDuration();
                try { await RunWatchMode(); }
                catch (Exception ex) { Console.WriteLine($"  [watch] aborted: {ex.Message}"); }
            }
        }

        Console.WriteLine();

        var failed = results.Count(r => r.Status == "Failed" || r.Status == "Error");
        return failed > 0 ? 1 : 0;
    }

    // ── Helper: Run a single test with timeout and logging ──
    static async Task RunSingleTest(TestDefinition test, List<TestResult> results)
    {
        var result = await RunSingleTestToResult(test);
        results.Add(result);
        WriteStatusLine(result.Status, result.Duration);
    }

    // ── Helper: Write a left-aligned "[ n/N] Test name ......" progress label
    //    with a dot leader so the status verdicts that follow line up neatly. ──
    static void WriteTestLabel(int index, int total, string name)
        => WriteTestLabel($"{index,2}/{total}", name);

    static void WriteTestLabel(string counter, string name)
    {
        const int targetWidth = 62;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  [{counter}] ");
        Console.ResetColor();
        Console.Write(name + " ");
        int used = 2 + 1 + counter.Length + 2 + name.Length + 1; // "  [" + counter + "] " + name + " "
        if (used < targetWidth)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(new string('.', targetWidth - used) + " ");
            Console.ResetColor();
        }
    }

    // ── Helper: Write a colored status verdict + dimmed duration on the current
    //    line (green Passed / yellow Warning / red Failed / gray Skipped). ──
    static void WriteStatusLine(string status, int durationMs)
    {
        var (icon, color) = status switch
        {
            "Passed" => ("\u2714", ConsoleColor.Green),
            "Warning" => ("\u26A0", ConsoleColor.Yellow),
            "Failed" => ("\u2718", ConsoleColor.Red),
            "Error" => ("\u2718", ConsoleColor.Red),
            "Info" => ("\u2139", ConsoleColor.Cyan),
            "Skipped" => ("\u2022", ConsoleColor.DarkGray),
            _ => ("\u2022", ConsoleColor.Gray)
        };
        Console.ForegroundColor = color;
        Console.Write($"{icon} {status}");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ({durationMs}ms)");
        Console.ResetColor();
    }

    // ── Helper: Run a test, applying the per-test timeout, and RETURN its result
    //    without printing or appending. Used directly for the backgrounded
    //    traceroute and via RunSingleTest for the foreground tests. ──
    static async Task<TestResult> RunSingleTestToResult(TestDefinition test)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            var testTask = test.Run();
            var testTimeout = test.Category == "cloud" ? 90 : test.Id is "L-TCP-10" ? 120 : test.Id is "L-TCP-07" or "L-UDP-07" ? 120 : 60;
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(testTimeout));

            if (await Task.WhenAny(testTask, timeoutTask) == timeoutTask)
            {
                sw.Stop();
                return new TestResult
                {
                    Id = test.Id,
                    Name = test.Name,
                    Description = test.Description,
                    Category = test.Category,
                    Status = "Warning",
                    ResultValue = $"Timed out after {testTimeout}s",
                    DetailedInfo = $"The test did not complete within {testTimeout} seconds. This may indicate a network issue (hanging TLS handshake, unresponsive proxy, etc.).",
                    Duration = (int)sw.ElapsedMilliseconds
                };
            }

            var result = await testTask;
            sw.Stop();
            result.Duration = (int)sw.ElapsedMilliseconds;
            return result;
        }
        catch (Exception ex)
        {
            return new TestResult
            {
                Id = test.Id,
                Name = test.Name,
                Description = test.Description,
                Category = test.Category,
                Status = "Error",
                ResultValue = $"Error: {ex.Message}",
                DetailedInfo = ex.ToString(),
                Duration = 0
            };
        }
    }

    // ── Helper: Write results JSON file ──
    static async Task WriteResultsJson(string outputPath, List<TestResult> results)
    {
        var output = new ScanOutput
        {
            Timestamp = DateTime.UtcNow,
            ScannerVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown",
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            DotNetVersion = RuntimeInformation.FrameworkDescription,
            ScanMode = _isCloudPcMode ? "cloudpc" : "client",
            HostType = _isCloudPcMode ? (_hostType ?? "cloudpc") : null,
            AzureRegion = _isCloudPcMode ? _azureVmRegion : null,
            Results = results
        };

        var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.ScanOutput);
        await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8);
        Console.WriteLine($"  Results saved to: {Path.GetFullPath(outputPath)}");
    }

    // ── Helper: Open browser with compressed results ──
    static async Task OpenBrowserWithResults(string outputPath, List<TestResult> results)
    {
        var output = new ScanOutput
        {
            Timestamp = DateTime.UtcNow,
            ScannerVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown",
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            DotNetVersion = RuntimeInformation.FrameworkDescription,
            ScanMode = _isCloudPcMode ? "cloudpc" : "client",
            HostType = _isCloudPcMode ? (_hostType ?? "cloudpc") : null,
            AzureRegion = _isCloudPcMode ? _azureVmRegion : null,
            Results = results
        };

        var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.ScanOutput);

        try
        {
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

            // Cache the snapshot payload so a subsequent Session Watch tab can
            // carry it too (keeps the watch tab's Snapshot sub-tab populated).
            _snapshotResultsB64 = compressedBase64;

            var cb = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var modeParam = _isCloudPcMode ? $"&mode={(_hostType ?? "cloudpc")}" : "";
            var baseUrl = $"{DashboardBaseUrl}?_cb={cb}{modeParam}";
            var hashUrl = $"{baseUrl}#zresults={compressedBase64}";

            Console.WriteLine($"  Compressed: {json.Length} \u2192 {compressed.Length} bytes (base64: {compressedBase64.Length} chars)");

            bool opened = false;

            // Method 1: Direct browser exe launch (preserves hash fragments)
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
                            Arguments = hashUrl,
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

            // Method 2: Local HTML redirect file
            if (!opened)
            {
                try
                {
                    Console.WriteLine($"  Opening via redirect file...");
                    var redirectHtml = $@"<!DOCTYPE html>
<html><head><title>Opening W365 Diagnostics...</title></head>
<body><p>Redirecting to results page...</p>
<script>window.location.replace({EscapeJsString(hashUrl)});</script>
<p><a href=""{System.Security.SecurityElement.Escape(hashUrl)}"">Click here if not redirected automatically</a></p>
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

            // Method 3: ShellExecute fallback
            if (!opened)
            {
                Console.WriteLine($"  Opening via ShellExecute (hash stripped \u2014 use drag-and-drop)...");
                Process.Start(new ProcessStartInfo { FileName = baseUrl, UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Error: {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine($"  Could not open browser. Import the JSON file manually:");
            Console.WriteLine($"    1. Open {DashboardBaseUrl}");
            Console.WriteLine($"    2. Drag and drop {Path.GetFullPath(outputPath)} onto the page");
        }
    }

    // ── Summary Report ──────────────────────────────────────────────

    /// <summary>
    /// Prints a structured executive summary after all tests, highlighting
    /// key findings, location pairings, and concerns.
    /// </summary>
    static void PrintSummaryReport(List<TestResult> results, bool includeCloud)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║                   SCAN SUMMARY                      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        // ── Test counts ──
        var passed = results.Count(r => r.Status == "Passed");
        var warned = results.Count(r => r.Status == "Warning");
        var failed = results.Count(r => r.Status == "Failed" || r.Status == "Error");
        var infoed = results.Count(r => r.Status == "Info");
        Console.Write($"  Tests run: {results.Count}   ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"\u2714 {passed} passed");
        Console.ResetColor();
        Console.Write("   ");
        Console.ForegroundColor = warned > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
        Console.Write($"\u26A0 {warned} warnings");
        Console.ResetColor();
        Console.Write("   ");
        Console.ForegroundColor = failed > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
        Console.Write($"\u2718 {failed} failed");
        Console.ResetColor();
        if (infoed > 0)
        {
            Console.Write("   ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"\u2139 {infoed} info");
            Console.ResetColor();
        }
        Console.WriteLine();
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
                else if ((trimmed.StartsWith("Distance from egress:") || trimmed.StartsWith("Distance from you:")) && gwDistance == null)
                    gwDistance = trimmed.Replace("Distance from egress:", "").Replace("Distance from you:", "").Trim();
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
                if (inTurn && (trimmed.StartsWith("Distance from egress:") || trimmed.StartsWith("Distance from you:")))
                    turnDistance = trimmed.Replace("Distance from egress:", "").Replace("Distance from you:", "").Trim();
            }
        }

        if (userLocation != null)
            Console.WriteLine($"  RDP Egress:        {userLocation}");
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
                    Console.WriteLine($"    Gateway in {gwLocation} — AFD steered you to a non-local gateway (nearest region(s) likely at capacity at connect time; service-side, usually transient)");
                if (turnConcern)
                    Console.WriteLine($"    TURN relay (DNS) in {turnLocation} — indicates non-local DNS resolvers (does not affect session — TURN is assigned by gateway via CRLB)");
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
    /// Finds all active network adapters that appear to be VPN connections.
    /// Detects PPP adapters (Azure VPN, Always-On VPN, SSTP, IKEv2, L2TP, PPTP),
    /// keyword-matched adapters (name or description), and known vendor adapters.
    /// </summary>
    static List<NetworkInterface> FindVpnAdapters()
    {
        var keywords = new[] {
            "VPN", "Virtual Private", "Cisco", "AnyConnect", "Palo Alto", "GlobalProtect",
            "Fortinet", "FortiClient", "WireGuard", "TAP-Windows", "OpenVPN", "TUN",
            "Pulse Secure", "Juniper", "SonicWall", "Check Point", "NetMotion",
            "Zscaler", "Cloudflare WARP", "NordVPN", "Tailscale", "ZeroTier",
            "Wintun", "PANGP", "SoftEther", "Tunnel"
        };

        // IPv6 transition pseudo-adapters that Windows installs by default. Their
        // descriptions match the "Tunnel" keyword above (e.g. "Teredo Tunneling
        // Pseudo-Interface") but they are NOT VPNs — flagging them as such caused
        // false "VPN/SWG detected" verdicts on stock Cloud PCs / Windows machines.
        var transitionExclusions = new[] { "Teredo", "isatap", "6to4" };

        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Where(n =>
            {
                var desc = n.Description ?? "";
                var name = n.Name ?? "";

                // Exclude IPv6 transition pseudo-adapters first — these match
                // "Tunnel" but are not VPNs.
                if (transitionExclusions.Any(k =>
                        desc.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                        name.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    return false;

                // PPP adapters are almost always VPN connections (Azure VPN, SSTP, IKEv2, L2TP, PPTP, RAS)
                if (n.NetworkInterfaceType == NetworkInterfaceType.Ppp) return true;

                // Check both Name and Description for known VPN keywords
                return keywords.Any(k =>
                    desc.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                    name.Contains(k, StringComparison.OrdinalIgnoreCase));
            })
            .ToList();
    }

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
    /// service CIDR ranges. Returns:
    ///   vpnCaught — sub-CIDRs that egress via a *recognised* VPN adapter, and
    ///   diverted  — sub-CIDRs that egress via an interface that is neither the
    ///               primary physical egress nor a recognised VPN adapter (i.e. a
    ///               tunnel whose adapter name we couldn't classify).
    /// Both empty = the whole range routes direct.
    /// </summary>
    static (List<string> vpnCaught, List<string> diverted) ProbeAvdServiceRanges(IList<NetworkInterface> vpnAdapters, StringBuilder sb, HashSet<string>? offendingIfIps = null)
    {
        var vpnCaughtRanges = new List<string>();
        var divertedRanges = new List<string>();
        try
        {
            // Collect VPN adapter interface IPs
            var vpnIfIps = new HashSet<string>();
            foreach (var vpn in vpnAdapters)
                foreach (var addr in vpn.GetIPProperties().UnicastAddresses)
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        vpnIfIps.Add(addr.Address.ToString());

            // Determine the PRIMARY physical egress interface (the one the OS uses
            // to reach the general internet). Any W365 route that egresses on a
            // different, non-VPN-named interface is "diverted" — likely an
            // unrecognised tunnel. If we cannot determine the primary egress
            // (offline, etc.) we leave the set empty and skip the diverted check
            // to avoid false positives.
            var primaryEgressIps = GetPrimaryEgressIfIps();

            // Parse routing table
            var psi = new ProcessStartInfo("route", "print -4")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = proc!.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            var routes = ParseRouteTable(output);
            if (routes.Count == 0) { sb.AppendLine("\n  Could not parse routing table"); return (vpnCaughtRanges, divertedRanges); }

            // Target ranges
            var targets = new (string label, uint netAddr, int prefixLen)[]
            {
                ("40.64.144.0/20", IpToUint32(IPAddress.Parse("40.64.144.0")), 20),
                ("51.5.0.0/16",    IpToUint32(IPAddress.Parse("51.5.0.0")),    16),
            };

            sb.AppendLine("\n  W365/AVD service range routing (from routing table):");

            var fullyDirectRanges = new List<string>();   // entire prefix routes direct
            var partiallyCaught   = new List<string>();    // prefix has SOME sub-range via VPN
            var divertedNotes     = new List<string>();    // prefix has a diverted (unrecognised) egress

            foreach (var (label, netAddr, prefixLen) in targets)
            {
                uint rangeStart = netAddr;
                uint rangeEnd   = prefixLen == 0 ? 0xFFFFFFFF : netAddr | (0xFFFFFFFF >> prefixLen);

                // Exclude the prefix's NETWORK and directed-BROADCAST addresses
                // from the capture sweep — neither is a usable AVD unicast
                // endpoint. The directed broadcast is the all-ones HOST address of
                // the prefix (e.g. 40.64.159.255 for 40.64.144.0/20, NOT always
                // x.x.255.255). Windows auto-creates an on-link /32 "Local" route
                // for that broadcast on every subnet a VPN advertises; that /32
                // wins LPM over the direct exclusion route,
                // so counting it as "carried via VPN" is a false positive that
                // flips the whole verdict to "Intercepting RDP traffic" even
                // though no W365 session traffic ever targets the broadcast.
                uint sweepStart = rangeStart;
                uint sweepEnd   = rangeEnd;
                if (prefixLen is > 0 and <= 30 && rangeEnd > rangeStart + 1)
                {
                    sweepStart = rangeStart + 1;
                    sweepEnd   = rangeEnd - 1;
                }

                // Exact longest-prefix-match sweep across the WHOLE prefix so a
                // partial tunnel capture (a VPN route that covers only part of the
                // range, possibly excluding the network address) can never be
                // missed. The winning route for an address only changes at the
                // start of a route that intersects the range (and just after one
                // ends), so evaluating LPM at each such breakpoint classifies
                // 100% of the range without enumerating every address.
                var breakpoints = new SortedSet<uint> { sweepStart };
                foreach (var rt in routes)
                {
                    uint rMask = rt.prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - rt.prefixLen);
                    uint rStart = rt.dest;
                    uint rEnd   = rt.prefixLen == 0 ? 0xFFFFFFFF : rt.dest | ~rMask;
                    if (rEnd < sweepStart || rStart > sweepEnd) continue; // no overlap
                    if (rStart > sweepStart) breakpoints.Add(rStart);
                    if (rEnd < sweepEnd)     breakpoints.Add(rEnd + 1);
                }

                var bpList = breakpoints.Where(b => b >= sweepStart && b <= sweepEnd)
                                        .OrderBy(b => b).ToList();

                // Classify each contiguous segment by its winning route, merging
                // adjacent segments that share the same verdict AND egress interface.
                //   kind 0 = direct (primary physical egress)
                //   kind 1 = recognised VPN adapter
                //   kind 2 = diverted: egresses on a non-primary, non-VPN interface
                //            (likely a tunnel whose adapter name we can't classify)
                var segments = new List<(uint start, uint end, int kind, RouteEntry? route)>();
                for (int i = 0; i < bpList.Count; i++)
                {
                    uint segStart = bpList[i];
                    uint segEnd   = (i + 1 < bpList.Count) ? bpList[i + 1] - 1 : sweepEnd;
                    var win = FindBestRoute(routes, segStart);
                    int kind = ClassifyEgress(win, vpnIfIps, primaryEgressIps);

                    if (segments.Count > 0)
                    {
                        var prev = segments[^1];
                        if (prev.kind == kind && prev.end + 1 == segStart
                            && (prev.route?.ifIp) == (win?.ifIp))
                        {
                            segments[^1] = (prev.start, segEnd, kind, prev.route);
                            continue;
                        }
                    }
                    segments.Add((segStart, segEnd, kind, win));
                }

                var vpnSegments      = segments.Where(s => s.kind == 1).ToList();
                var divertedSegments = segments.Where(s => s.kind == 2).ToList();
                var directSegments   = segments.Where(s => s.kind == 0 && s.route.HasValue).ToList();
                bool noRoute         = segments.All(s => !s.route.HasValue);

                // Anything NOT on the primary direct path is "not bypassed".
                var notBypassedSegments = segments.Where(s => s.kind == 1 || s.kind == 2).ToList();

                // Record the egress interface IP of every off-direct-path segment so
                // the caller can attribute the capture to a SPECIFIC tunnel when more
                // than one VPN adapter is active (multi-tunnel scenarios).
                if (offendingIfIps != null)
                    foreach (var s in notBypassedSegments)
                        if (s.route.HasValue && !string.IsNullOrEmpty(s.route.Value.ifIp))
                            offendingIfIps.Add(s.route.Value.ifIp);

                // Build the precise CIDR lists for what is / isn't bypassed.
                var vpnCidrs      = vpnSegments.SelectMany(s => IntervalToCidrs(s.start, s.end)).ToList();
                var divertedCidrs = divertedSegments.SelectMany(s => IntervalToCidrs(s.start, s.end)).ToList();
                var notBypassedCidrs = notBypassedSegments.SelectMany(s => IntervalToCidrs(s.start, s.end)).ToList();
                var directCidrs   = directSegments.SelectMany(s => IntervalToCidrs(s.start, s.end)).ToList();

                if (notBypassedSegments.Count == 0)
                {
                    // Entire prefix routes direct (or has no route at all).
                    if (noRoute)
                        sb.AppendLine($"    ? {label}: no matching route found");
                    else
                    {
                        var r = directSegments[0].route!.Value;
                        sb.AppendLine($"    \u2714 {label}: ENTIRE range routed direct (e.g. via {r.gateway}, if {r.ifIp}, metric {r.metric})");
                        fullyDirectRanges.Add(label);
                    }
                }
                else if (directSegments.Count == 0)
                {
                    // The whole prefix is captured off the direct path.
                    var capLabel = vpnSegments.Count > 0 && divertedSegments.Count == 0 ? "VPN tunnel"
                                 : divertedSegments.Count > 0 && vpnSegments.Count == 0 ? "an unrecognised non-primary interface"
                                 : "VPN tunnel / diverted interface";
                    var r = notBypassedSegments[0].route!.Value;
                    sb.AppendLine($"    \u26A0 {label}: ENTIRE range routed via {capLabel} (via {r.gateway}, if {r.ifIp}, metric {r.metric})");
                    sb.AppendLine($"        \u26A0 NOT bypassed (all off the direct path): {label}");
                    foreach (var s in divertedSegments)
                        sb.AppendLine($"          diverted: {Uint32ToIp(s.start)}\u2013{Uint32ToIp(s.end)} (route {s.route!.Value.destStr}/{s.route.Value.prefixLen} via {s.route.Value.gateway}, if {s.route.Value.ifIp}) \u2014 interface not a named VPN; verify it is not a tunnel");
                    foreach (var c in vpnCidrs) vpnCaughtRanges.Add(c);
                    foreach (var c in divertedCidrs) { divertedRanges.Add(c); divertedNotes.Add(label); }
                }
                else
                {
                    // PARTIAL — some of the prefix leaks off the direct path.
                    // Spell out exactly which sub-CIDRs are not bypassed.
                    sb.AppendLine($"    \u26A0 {label}: PARTIALLY routed off the direct path \u2014 split is incomplete");
                    sb.AppendLine($"        \u26A0 NOT bypassed: {string.Join(", ", notBypassedCidrs)}");
                    sb.AppendLine($"        \u2714 bypassed (direct): {string.Join(", ", directCidrs)}");
                    foreach (var s in vpnSegments)
                    {
                        var r = s.route!.Value;
                        sb.AppendLine($"          via VPN: {Uint32ToIp(s.start)}\u2013{Uint32ToIp(s.end)} (route {r.destStr}/{r.prefixLen} via {r.gateway}, if {r.ifIp}, metric {r.metric})");
                    }
                    foreach (var s in divertedSegments)
                    {
                        var r = s.route!.Value;
                        sb.AppendLine($"          diverted: {Uint32ToIp(s.start)}\u2013{Uint32ToIp(s.end)} (route {r.destStr}/{r.prefixLen} via {r.gateway}, if {r.ifIp}, metric {r.metric}) \u2014 interface not a named VPN; verify it is not a tunnel");
                    }
                    // Record the precise captured CIDRs so the verdict reflects the leak.
                    foreach (var c in vpnCidrs)
                        vpnCaughtRanges.Add($"{c} (within {label})");
                    foreach (var c in divertedCidrs)
                        divertedRanges.Add($"{c} (within {label})");
                    if (vpnSegments.Count > 0) partiallyCaught.Add(label);
                    if (divertedSegments.Count > 0) divertedNotes.Add(label);
                }
            }

            // Summary
            sb.AppendLine();
            if (vpnCaughtRanges.Count > 0 || divertedRanges.Count > 0)
            {
                if (vpnCaughtRanges.Count > 0)
                    sb.AppendLine($"  \u26A0 VPN tunnel is carrying W365/AVD traffic for: {string.Join(", ", vpnCaughtRanges)}");
                if (divertedRanges.Count > 0)
                    sb.AppendLine($"  \u26A0 W365/AVD traffic egresses via an UNRECOGNISED non-primary interface for: {string.Join(", ", divertedRanges)} \u2014 this is not your direct internet path; confirm whether it is a VPN/SWG tunnel.");
                if (fullyDirectRanges.Count > 0)
                    sb.AppendLine($"  \u2714 Fully split-tunnelled (direct) for: {string.Join(", ", fullyDirectRanges)}");
                if (partiallyCaught.Count > 0 || divertedNotes.Count > 0)
                {
                    var incomplete = partiallyCaught.Concat(divertedNotes).Distinct().ToList();
                    sb.AppendLine($"  \u26A0 Split tunnelling is INCOMPLETE for: {string.Join(", ", incomplete)} \u2014 add the CIDRs listed above to the VPN/SWG bypass/exclude list.");
                }
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
        return (vpnCaughtRanges, divertedRanges);
    }

    /// <summary>
    /// Classifies the egress of a winning route: 0 = direct (primary physical
    /// egress / unknown-but-not-diverted), 1 = recognised VPN adapter,
    /// 2 = diverted (a specific route egressing on a non-primary, non-VPN
    /// interface — likely an unrecognised tunnel). The diverted check is
    /// suppressed when the primary egress is unknown, when the winning route is
    /// the default route, or when the egress is loopback/link-local — to keep
    /// false positives near zero.
    /// </summary>
    static int ClassifyEgress(RouteEntry? win, HashSet<string> vpnIfIps, HashSet<string> primaryEgressIps)
    {
        if (!win.HasValue) return 0;
        var r = win.Value;
        if (vpnIfIps.Contains(r.ifIp)) return 1;
        if (primaryEgressIps.Count == 0) return 0;           // can't determine primary — don't guess
        if (primaryEgressIps.Contains(r.ifIp)) return 0;     // on the direct path
        if (r.prefixLen == 0) return 0;                      // default route — not a specific injection
        if (r.ifIp.StartsWith("169.254.") || r.ifIp == "127.0.0.1" || r.ifIp == "0.0.0.0") return 0;
        return 2;                                            // specific route, off the primary, not a named VPN
    }

    /// <summary>
    /// Returns the set of IPv4 addresses on the interface the OS uses to reach the
    /// general internet (the "primary" egress). Used to distinguish a direct path
    /// from a diverted/tunnelled one. Empty set = could not determine.
    /// </summary>
    static HashSet<string> GetPrimaryEgressIfIps()
    {
        var set = new HashSet<string>();
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect(IPAddress.Parse("8.8.8.8"), 443); // no packets sent; just binds the egress
            var localIp = ((IPEndPoint)sock.LocalEndPoint!).Address.ToString();
            set.Add(localIp);
            // Add every IPv4 address on the SAME adapter, so secondary IPs on the
            // primary NIC also count as the direct path.
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                var ips = ni.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString()).ToList();
                if (ips.Contains(localIp))
                    foreach (var ip in ips) set.Add(ip);
            }
        }
        catch { /* offline or blocked — leave empty so the diverted check is skipped */ }
        return set;
    }

    record struct RouteEntry(uint dest, int prefixLen, string gateway, string ifIp, int metric, string destStr);

    static List<RouteEntry> ParseRouteTable(string routePrintOutput)
    {
        var routes = new List<RouteEntry>();
        // Parse locale-independently: skip header/separator lines and detect route data
        // by checking whether the first field is a valid IPv4 address.
        foreach (var rawLine in routePrintOutput.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("=") || string.IsNullOrWhiteSpace(line)) continue;

            // Fields: NetworkDestination  Netmask  Gateway  Interface  Metric
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) continue;

            if (!IPAddress.TryParse(parts[0], out var dest) || dest.AddressFamily != AddressFamily.InterNetwork) continue;
            if (!IPAddress.TryParse(parts[1], out var mask) || mask.AddressFamily != AddressFamily.InterNetwork) continue;

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

    static string Uint32ToIp(uint ip)
        => $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

    /// <summary>
    /// Decomposes an inclusive [start, end] IPv4 interval into the minimal set of
    /// aligned CIDR blocks that exactly cover it. Used to report precisely which
    /// sub-ranges of a W365/AVD prefix are (or are not) bypassed.
    /// </summary>
    static List<string> IntervalToCidrs(uint start, uint end)
    {
        var cidrs = new List<string>();
        ulong cur = start;
        ulong last = end;
        while (cur <= last)
        {
            // Largest block aligned to 'cur' is bounded by its trailing-zero count.
            int prefix = cur == 0 ? 0 : 32 - System.Numerics.BitOperations.TrailingZeroCount((uint)cur);
            // Shrink the block (increase prefix) until it fits within the remaining range.
            while ((cur + (1UL << (32 - prefix)) - 1) > last) prefix++;
            cidrs.Add($"{Uint32ToIp((uint)cur)}/{prefix}");
            cur += 1UL << (32 - prefix);
        }
        return cidrs;
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
        var tests = new List<TestDefinition>
        {
            // ── Local Environment ──
            new("L-LE-04", "WiFi Signal Strength", "Measures wireless signal strength", "local", RunWifiStrength),
            new("L-LE-05", "Router/Gateway Latency", "Pings default gateway", "local", RunRouterLatency),
            new("L-LE-06", "Network Adapter Details", "Enumerates network adapters", "local", RunNetworkAdapters),
            new("L-LE-07", "Bandwidth Estimation", "Estimates available bandwidth", "local", RunBandwidthTest),
            new("L-LE-08", "Machine Performance", "Checks CPU, RAM, disk", "local", RunMachinePerformance),
            new("L-LE-09", "Teams Optimization", "Validates Teams AV redirect settings", "local", RunTeamsOptimization),
            new("L-LE-10", "Windows Firewall Audit", "Checks for firewall rules blocking W365 ports", "local", RunFirewallAudit),
            new("L-LE-11", "RDP Group Policy Check", "Checks for GP/registry settings affecting RDP", "local", RunRdpGroupPolicyCheck),
            new("L-LE-12", "WiFi Channel Congestion", "Scans nearby WiFi networks for channel congestion", "local", RunWifiChannelCongestion),
            new("L-LE-13", "RDP Client Version", "Checks installed Windows App / Remote Desktop client version", "local", RunRdpClientVersion),
            new("L-LE-14", "DNS Server Identification", "Identifies configured and active DNS resolvers and classifies provider", "local", RunDnsServerIdentification),
            new("L-LE-15", "Path MTU Discovery", "Discovers maximum transmission unit to key W365/AVD endpoints", "local", RunPathMtuDiscovery),
            new("L-LE-16", "NIC Driver Analysis", "Analyzes network adapter drivers for age and known issues impacting connectivity", "local", RunNicDriverAnalysis),
            new("L-LE-17", "Network Stack Agents", "Inventories VPN/SWG/proxy/security agents in the host network stack that can affect RDP Shortpath UDP (informational)", "local", RunNetworkStackAgents),

            // ── Endpoint Access ──
            new("L-EP-01", "Certificate Endpoints (Port 80)", "Tests TCP 80 connectivity to certificate endpoints", "endpoint", RunCertEndpointTest),
            new("L-EP-02", "Browser-Blocked Endpoints", "Tests required endpoints that browsers block via tracker-prevention (e.g. *.events.data.microsoft.com)", "endpoint", RunBrowserBlockedEndpointsTest),

            // ── TCP Based RDP Connectivity ──
            new("L-TCP-03", "DNS Resolution Performance", "Measures pure DNS resolution time for key W365 endpoints", "tcp", RunDnsPerformance),
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
        };

        // Microsoft-internal self-host endpoint probe. Added AUTOMATICALLY only when
        // this device proves it is a Microsoft-internal machine, so external
        // customers never see or run it.
        if (IsMicrosoftInternalDevice())
            tests.Add(new("L-TCP-11", "Self-Host Endpoint Connectivity (Internal)",
                "Tests Microsoft-internal self-host AVD/Cloud PC endpoints (deschutes-sh, wvdselfhost AFD gateways) — internal testers only", "tcp", RunSelfHostConnectivity));

        return tests;
    }

    // ── Cloud PC test suite (runs on the Cloud PC itself) ──
    static List<TestDefinition> GetCloudPcTests()
    {
        var tests = new List<TestDefinition>
        {
            // ── Cloud PC Environment ──
            new("C-LE-01", "Cloud PC Location", "Identifies Azure region and public IP of the Cloud PC", "cloudpc-env", RunCpcLocation),
            new("C-LE-02", "Cloud PC Network Info", "Shows network adapters and ISP on the Cloud PC", "cloudpc-env", RunCpcNetworkInfo),
            new("C-LE-05", "Network Stack Agents (Cloud PC)", "Inventories VPN/SWG/proxy/security agents in the Cloud PC network stack that can affect RDP Shortpath UDP (informational)", "cloudpc-env", RunCpcNetworkStackAgents),

            // ── Cloud PC → Gateway/TURN Connectivity ──
            new("C-TCP-04", "Gateway Connectivity (Cloud PC)", "Tests RDP Gateway reachability from Cloud PC", "cloudpc-tcp", RunCpcGatewayConnectivity),
            new("C-TCP-05", "DNS CNAME Chain (Cloud PC)", "Validates DNS chain from Cloud PC", "cloudpc-tcp", RunCpcDnsCnameChain),
            new("C-TCP-06", "TLS Inspection (Cloud PC)", "Checks for TLS interception on Cloud PC", "cloudpc-tcp", RunCpcTlsInspection),
            new("C-TCP-07", "Proxy / VPN / SWG (Cloud PC)", "Detects proxy, VPN, SWG on Cloud PC", "cloudpc-tcp", RunCpcProxyVpnDetection),
            new("C-TCP-08", "DNS Hijacking (Cloud PC)", "Verifies gateway DNS resolves to Microsoft IPs from Cloud PC", "cloudpc-tcp", RunCpcDnsHijackingCheck),
            new("C-TCP-09", "Gateway Used (Cloud PC)", "Shows gateway endpoint reached from Cloud PC", "cloudpc-tcp", RunCpcGatewayUsed),

            // ── Cloud PC → TURN Relay ──
            new("C-UDP-03", "TURN Relay (Cloud PC)", "Tests UDP to TURN relay from Cloud PC", "cloudpc-udp", RunCpcTurnRelay),
            new("C-UDP-04", "TURN Relay Location (Cloud PC)", "Geolocates TURN relay from Cloud PC", "cloudpc-udp", RunCpcTurnRelayLocation),
            new("C-UDP-07", "TURN Proxy/VPN (Cloud PC)", "Detects UDP-blocking proxy/VPN from Cloud PC", "cloudpc-udp", RunCpcTurnProxyVpn),

            // ── Cloud PC RDP Egress Validation ──
            new("C-NET-01", "Azure IMDS Metadata", "Reads VM metadata from Azure Instance Metadata Service", "cloudpc-env", RunCpcImdsMetadata),
            new("C-NET-02", "RDP Egress in Azure", "Checks that RDP traffic to Gateway/TURN stays within Azure", "cloudpc-tcp", RunCpcRdpEgressInAzure),

            // ── Azure Fabric (WireServer + IMDS) ──
            // Probes that surface third-party EDR / WFP / proxy / NSG interference with the
            // Azure fabric communication IPs (168.63.129.16 and 169.254.169.254). A failure
            // of these frequently manifests elsewhere as Guest Agent heartbeat loss,
            // provisioning failure, or extension-install failure on the Cloud PC.
            // Ref: https://learn.microsoft.com/azure/virtual-desktop/azurecommunicationips
            new("C-AZ-01", "Azure Fabric: WireServer TCP (168.63.129.16:80)", "TCP reachability to the Azure WireServer endpoint", "cloudpc-azure", RunCpcAzureFabricWireServerTcp),
            new("C-AZ-02", "Azure Fabric: WireServer HTTP (GoalState)", "HTTP GET to WireServer — detects proxy interception and silent blocks", "cloudpc-azure", RunCpcAzureFabricWireServerHttp),
            new("C-AZ-03", "Azure Fabric: Instance Metadata Service (IMDS)", "HTTP GET to 169.254.169.254 with 'Metadata: true' header — verifies IMDS reachability and that headers are not being stripped by a proxy", "cloudpc-azure", RunCpcAzureFabricImds),

            // ── Cloud PC Shortpath Config ──
            new("C-LE-04", "Shortpath Managed Config", "Checks RDP Shortpath for managed networks prerequisites on session host", "cloudpc-env", RunCpcShortpathManagedConfig),

            // ── Cloud PC Endpoint & Speed ──
            // Note: C-EP-01 was removed in v1.10.1 — it duplicated a subset of C-EP-02
            // (Session Host Required Endpoints), which is the authoritative list.
            new("C-EP-02", "Session Host Required Endpoints", "Tests all required FQDNs for AVD/W365 session hosts", "cloudpc-env", RunCpcRequiredEndpoints),
            new("C-LE-03", "CPC Connection Speed", "Estimates network throughput from within the Cloud PC", "cloudpc-env", RunCpcConnectionSpeed),
        };

        // Microsoft-internal self-host probe (Cloud PC side). Added AUTOMATICALLY only
        // when this Cloud PC proves it is Microsoft-internal, so normal customer
        // Cloud PCs are unaffected.
        if (IsMicrosoftInternalDevice())
            tests.Add(new("C-TCP-10", "Self-Host Endpoint Connectivity (Cloud PC, Internal)",
                "Tests Microsoft-internal self-host endpoints (deschutes-sh, wvdselfhost AFD gateways) from the Cloud PC — internal testers only", "cloudpc-tcp", RunCpcSelfHostConnectivity));

        return tests;
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
                        sb.AppendLine($"\u2714 {wildcard}:80 \u2014 Connected in {sw.ElapsedMilliseconds}ms");
                        passed++;
                    }
                    else
                    {
                        sb.AppendLine($"\u2718 {wildcard}:80 \u2014 Timeout (5s)");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"\u2718 {wildcard}:80 \u2014 {ex.Message}");
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

    /// <summary>
    /// L-EP-02: Probes required endpoints that browsers block via built-in
    /// tracker-prevention lists. These hosts are fully reachable over the
    /// network but browser fetch() is cancelled by the browser itself before
    /// any DNS/TCP occurs, so the web-based B-EP-01 check cannot verify them.
    /// The scanner is not subject to tracker-prevention and probes via raw TCP.
    /// </summary>
    static async Task<TestResult> RunBrowserBlockedEndpointsTest()
    {
        var result = new TestResult { Id = "L-EP-02", Name = "Browser-Blocked Endpoints", Category = "endpoint" };
        try
        {
            // Microsoft OneDS telemetry hosts are on Edge / Chrome / Firefox
            // tracker-blocking lists. Probe a representative subdomain for the
            // *.events.data.microsoft.com wildcard.
            // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#end-user-devices
            var targets = new (string host, int port, string wildcard, string purpose)[]
            {
                ("watson.events.data.microsoft.com", 443, "*.events.data.microsoft.com", "Client telemetry (OneDS)")
            };

            var sb = new StringBuilder();
            int passed = 0;
            foreach (var (host, port, wildcard, purpose) in targets)
            {
                try
                {
                    using var tcp = new TcpClient();
                    var sw = Stopwatch.StartNew();
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await tcp.ConnectAsync(host, port, cts.Token);
                    sw.Stop();
                    sb.AppendLine($"\u2714 {wildcard}:{port} \u2014 {purpose} \u2014 Connected in {sw.ElapsedMilliseconds}ms");
                    passed++;
                }
                catch (OperationCanceledException)
                {
                    sb.AppendLine($"\u2718 {wildcard}:{port} \u2014 {purpose} \u2014 Timeout (5s)");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"\u2718 {wildcard}:{port} \u2014 {purpose} \u2014 {ex.InnerException?.Message ?? ex.Message}");
                }
            }
            sb.AppendLine();
            sb.AppendLine("These endpoints cannot be probed from a browser because Edge, Chrome");
            sb.AppendLine("and Firefox ship built-in tracker-blocking lists that cancel fetch()");
            sb.AppendLine("to them regardless of CSP, redirect, or response type. Raw TCP from");
            sb.AppendLine("the scanner is not subject to tracker-prevention and reflects the real");
            sb.AppendLine("network reachability.");

            result.ResultValue = $"{passed}/{targets.Length} browser-blocked endpoints reachable (via scanner)";
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

    /// <summary>
    /// Checks whether a Wi-Fi adapter is connected using the .NET NetworkInterface API (locale-independent).
    /// </summary>
    static bool IsWifiConnected()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Any(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                      n.OperationalStatus == OperationalStatus.Up);
    }

    /// <summary>
    /// Parses netsh wlan show interfaces output locale-independently.
    /// Field names are localized but the colon-separated format and value patterns are universal.
    /// </summary>
    static (string? signal, string? ssid, string? radioType, string? channel) ParseNetshWlanFields(string output)
    {
        string? signal = null, ssid = null, radioType = null, channel = null;
        var lines = output.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            // All fields use " : " as key-value separator
            var colonIdx = line.IndexOf(" : ");
            if (colonIdx < 0) continue;
            var value = line.Substring(colonIdx + 3).Trim();

            // Signal: value is always "<digits>%" (e.g. "85%")
            if (signal == null && Regex.IsMatch(value, @"^\d+%$"))
            { signal = value; continue; }

            // Radio type: value always contains "802.11" (e.g. "802.11ax", "802.11ac")
            if (radioType == null && value.Contains("802.11"))
            { radioType = value; continue; }

            // SSID (not BSSID): key does NOT contain "BSSID" and value is not a MAC address
            // BSSID values look like "aa:bb:cc:dd:ee:ff"
            var key = line.Substring(0, colonIdx).Trim();
            if (ssid == null && key.Length <= 10 && !key.Contains("BSSID", StringComparison.OrdinalIgnoreCase)
                && !Regex.IsMatch(value, @"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
                && key.Contains("SSID", StringComparison.OrdinalIgnoreCase))
            { ssid = value; continue; }

            // Channel: value is a small integer (1-165).
            // Some WLAN drivers emit Channel before Signal, so don't make this order-dependent.
            if (channel == null && int.TryParse(value, out var ch) && ch >= 1 && ch <= 165)
            { channel = value; continue; }
        }
        return (signal, ssid, radioType, channel);
    }

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

            if (string.IsNullOrWhiteSpace(output))
            {
                result.Status = "Skipped";
                result.ResultValue = "No wireless interface detected (wired connection)";
                return result;
            }

            // Check Wi-Fi connection state using .NET API (locale-independent)
            if (!IsWifiConnected())
            {
                result.Status = "Skipped";
                result.ResultValue = "Not connected by WiFi";
                result.DetailedInfo = output.Trim();
                return result;
            }

            // Parse fields locale-independently by value patterns
            var (signal, ssid, radioType, channel) = ParseNetshWlanFields(output);

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
            // Azure VNet gateways block ICMP — this test is only meaningful on the client device.
            if (IsRemoteSession())
            {
                result.Status = "Skipped";
                result.ResultValue = "Running inside Cloud PC — Azure VNet gateway does not respond to ICMP";
                result.DetailedInfo = "Gateway latency cannot be measured inside a Cloud PC.\nRun the scanner on your physical client device to test local network latency to your router.";
                return result;
            }

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

            using var ping = new Ping();
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
            var sb = new StringBuilder();
            sb.AppendLine($"Gateway: {gateway}");
            sb.AppendLine($"Samples: {times.Count}/5");
            sb.AppendLine(string.Join(", ", times.Select(t => $"{t}ms")));

            // ── Router/Gateway Identification ──
            string routerModel = null;
            try
            {
                // 1. Reverse DNS — often reveals device hostname (e.g. "fritz.box", "router.asus.com")
                string reverseDns = null;
                try
                {
                    var entry = await Dns.GetHostEntryAsync(gateway);
                    if (entry.HostName != gateway.ToString())
                        reverseDns = entry.HostName;
                }
                catch { }

                // 2. MAC OUI lookup — get gateway MAC from ARP cache, map OUI prefix to manufacturer
                string macAddress = null;
                string ouiManufacturer = null;
                try
                {
                    var arpOutput = await RunProcessAsync("arp", $"-a {gateway}");
                    if (arpOutput != null)
                    {
                        // Parse ARP output for MAC address (works across all locales — MAC format is universal)
                        var macMatch = Regex.Match(arpOutput, @"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", RegexOptions.IgnoreCase);
                        if (macMatch.Success)
                        {
                            macAddress = macMatch.Value.ToUpperInvariant().Replace('-', ':');
                            var oui = macAddress.Substring(0, 8); // "AA:BB:CC"
                            ouiManufacturer = LookupMacOui(oui);
                        }
                    }
                }
                catch { }

                // 3. UPnP SSDP Discovery — query for Internet Gateway Device to get model info
                string upnpModel = null;
                string upnpManufacturer = null;
                string upnpFriendlyName = null;
                try
                {
                    var ssdpResult = await DiscoverUpnpGateway(gateway, TimeSpan.FromSeconds(3));
                    if (ssdpResult != null)
                    {
                        upnpModel = ssdpResult.Value.Model;
                        upnpManufacturer = ssdpResult.Value.Manufacturer;
                        upnpFriendlyName = ssdpResult.Value.FriendlyName;
                    }
                }
                catch { }

                // Build router identification section
                sb.AppendLine();
                sb.AppendLine("═══ Router/Gateway Identification ═══");

                if (reverseDns != null)
                    sb.AppendLine($"  Hostname: {reverseDns}");
                if (macAddress != null)
                    sb.AppendLine($"  MAC Address: {macAddress}");
                if (ouiManufacturer != null)
                    sb.AppendLine($"  MAC Vendor: {ouiManufacturer}");
                if (upnpFriendlyName != null)
                    sb.AppendLine($"  UPnP Name: {upnpFriendlyName}");
                if (upnpManufacturer != null)
                    sb.AppendLine($"  UPnP Manufacturer: {upnpManufacturer}");
                if (upnpModel != null)
                    sb.AppendLine($"  UPnP Model: {upnpModel}");

                // Build a concise router model description for the summary
                if (upnpModel != null)
                    routerModel = upnpManufacturer != null ? $"{upnpManufacturer} {upnpModel}" : upnpModel;
                else if (upnpFriendlyName != null)
                    routerModel = upnpFriendlyName;
                else if (ouiManufacturer != null && reverseDns != null)
                    routerModel = $"{ouiManufacturer} ({reverseDns})";
                else if (ouiManufacturer != null)
                    routerModel = ouiManufacturer;
                else if (reverseDns != null)
                    routerModel = reverseDns;

                if (routerModel == null && macAddress == null && reverseDns == null)
                    sb.AppendLine("  Could not identify router (UPnP disabled, ARP empty, no PTR record)");
            }
            catch { }

            var routerSuffix = routerModel != null ? $" [{routerModel}]" : "";
            result.ResultValue = $"Gateway {gateway}: avg {avg:F0}ms (min {times.Min()}ms, max {times.Max()}ms){routerSuffix}";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = avg < 20 ? "Passed" : avg < 50 ? "Warning" : "Failed";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>Run an external process and capture stdout.</summary>
    static async Task<string?> RunProcessAsync(string fileName, string arguments, int timeoutMs = 5000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return null;
            var output = await proc.StandardOutput.ReadToEndAsync();
            using var cts = new CancellationTokenSource(timeoutMs);
            await proc.WaitForExitAsync(cts.Token);
            return output;
        }
        catch { return null; }
    }

    /// <summary>Parsed Windows Firewall rule from registry (locale-independent, no process spawning).</summary>
    record struct FwRule(string Name, string Dir, string Action, int Protocol, string LocalPort);

    /// <summary>Read firewall rules from the Windows Firewall registry store.
    /// Avoids spawning powershell.exe which triggers Defender behavioural heuristics.</summary>
    static List<FwRule> ReadFirewallRulesFromRegistry()
    {
        var rules = new List<FwRule>();
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (key == null) return rules;

            foreach (var valueName in key.GetValueNames())
            {
                var data = key.GetValue(valueName) as string;
                if (string.IsNullOrEmpty(data)) continue;

                string? name = null;
                bool active = false;
                string dir = "", action = "";
                int protocol = 0; // 6=TCP, 17=UDP, 256=Any
                string localPort = "Any";

                foreach (var part in data.Split('|'))
                {
                    if (part.StartsWith("Name=", StringComparison.OrdinalIgnoreCase))
                        name = part[5..];
                    else if (part.StartsWith("Active=", StringComparison.OrdinalIgnoreCase))
                        active = part[7..].Equals("TRUE", StringComparison.OrdinalIgnoreCase);
                    else if (part.StartsWith("Dir=", StringComparison.OrdinalIgnoreCase))
                        dir = part[4..];
                    else if (part.StartsWith("Action=", StringComparison.OrdinalIgnoreCase))
                        action = part[7..];
                    else if (part.StartsWith("Protocol=", StringComparison.OrdinalIgnoreCase))
                        int.TryParse(part[9..], out protocol);
                    else if (part.StartsWith("LPort=", StringComparison.OrdinalIgnoreCase))
                        localPort = part[6..];
                }

                if (name != null && active)
                    rules.Add(new FwRule(name, dir, action, protocol, localPort));
            }
        }
        catch { }
        return rules;
    }

    /// <summary>Check if a firewall rule's port field matches a given port number.</summary>
    static bool FwPortMatches(string rulePort, int targetPort)
    {
        if (string.IsNullOrEmpty(rulePort) || rulePort.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return true;
        foreach (var segment in rulePort.Split(','))
        {
            var s = segment.Trim();
            if (s == targetPort.ToString()) return true;
            // Handle ranges like "1000-2000"
            var dash = s.IndexOf('-');
            if (dash > 0 && int.TryParse(s[..dash], out var lo) && int.TryParse(s[(dash + 1)..], out var hi)
                && targetPort >= lo && targetPort <= hi)
                return true;
        }
        return false;
    }

    /// <summary>UPnP SSDP discovery result.</summary>
    record struct UpnpDeviceInfo(string? FriendlyName, string? Manufacturer, string? Model);

    /// <summary>Discover UPnP Internet Gateway Device via SSDP M-SEARCH.</summary>
    static async Task<UpnpDeviceInfo?> DiscoverUpnpGateway(IPAddress gatewayIp, TimeSpan timeout)
    {
        // Send SSDP M-SEARCH for Internet Gateway Device
        var searchTarget = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
        var mSearch = $"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
                      $"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {searchTarget}\r\n\r\n";
        var mSearchBytes = Encoding.ASCII.GetBytes(mSearch);

        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;
        var multicastEndpoint = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);

        // Also try unicast directly to the gateway (some routers only respond to unicast)
        var unicastEndpoint = new IPEndPoint(gatewayIp, 1900);

        await udp.SendAsync(mSearchBytes, mSearchBytes.Length, multicastEndpoint);
        await udp.SendAsync(mSearchBytes, mSearchBytes.Length, unicastEndpoint);

        // Collect responses — ONLY accept responses from the gateway IP itself.
        // Other devices (Hue bridges, smart TVs, etc.) also respond to SSDP multicast
        // but are not the router.
        string? locationUrl = null;
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var receiveTask = udp.ReceiveAsync();
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero) break;
                if (await Task.WhenAny(receiveTask, Task.Delay(remaining)) != receiveTask) break;
                var response = await receiveTask;

                // Ignore responses from devices that are NOT the gateway
                if (!response.RemoteEndPoint.Address.Equals(gatewayIp))
                    continue;

                var text = Encoding.ASCII.GetString(response.Buffer);
                // Extract LOCATION header
                var locMatch = Regex.Match(text, @"LOCATION:\s*(https?://\S+)", RegexOptions.IgnoreCase);
                if (locMatch.Success)
                {
                    locationUrl = locMatch.Groups[1].Value.Trim();
                    break;
                }
            }
            catch (SocketException) { break; }
            catch { break; }
        }

        if (locationUrl == null) return null;

        // Validate URL points to the gateway IP specifically (not some other LAN device)
        if (!Uri.TryCreate(locationUrl, UriKind.Absolute, out var locationUri)) return null;
        if (locationUri.Scheme != "http" && locationUri.Scheme != "https") return null;
        if (!IPAddress.TryParse(locationUri.Host, out var locationIp)) return null;
        if (!locationIp.Equals(gatewayIp)) return null; // Must be the gateway, not another device

        // Fetch device description XML
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            var xml = await http.GetStringAsync(locationUrl);

            // Parse key fields from the XML (simple regex — avoids XML parser dependency issues with malformed docs)
            var friendly = Regex.Match(xml, @"<friendlyName>([^<]+)</friendlyName>", RegexOptions.IgnoreCase);
            var mfr = Regex.Match(xml, @"<manufacturer>([^<]+)</manufacturer>", RegexOptions.IgnoreCase);
            var model = Regex.Match(xml, @"<modelName>([^<]+)</modelName>", RegexOptions.IgnoreCase);
            var modelDesc = Regex.Match(xml, @"<modelDescription>([^<]+)</modelDescription>", RegexOptions.IgnoreCase);

            return new UpnpDeviceInfo(
                friendly.Success ? friendly.Groups[1].Value.Trim() : null,
                mfr.Success ? mfr.Groups[1].Value.Trim() : null,
                model.Success ? model.Groups[1].Value.Trim() :
                    (modelDesc.Success ? modelDesc.Groups[1].Value.Trim() : null)
            );
        }
        catch { return null; }
    }

    /// <summary>Look up MAC OUI prefix to manufacturer name.</summary>
    static string? LookupMacOui(string oui)
    {
        // Common router/networking equipment OUI prefixes (IEEE MA-L assignments)
        // Format: "AA:BB:CC" → "Manufacturer"
        var ouiMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // AVM (FRITZ!Box)
            ["24:4B:03"] = "AVM (FRITZ!Box)", ["3C:A6:2F"] = "AVM (FRITZ!Box)", ["44:4E:6D"] = "AVM (FRITZ!Box)",
            ["B0:F2:08"] = "AVM (FRITZ!Box)", ["C8:0E:14"] = "AVM (FRITZ!Box)", ["E0:28:6D"] = "AVM (FRITZ!Box)",
            ["2C:91:AB"] = "AVM (FRITZ!Box)", ["DC:39:6F"] = "AVM (FRITZ!Box)", ["A8:6B:AD"] = "AVM (FRITZ!Box)",
            // TP-Link
            ["50:C7:BF"] = "TP-Link", ["60:32:B1"] = "TP-Link", ["98:DA:C4"] = "TP-Link",
            ["B0:4E:26"] = "TP-Link", ["C0:06:C3"] = "TP-Link", ["C4:E9:84"] = "TP-Link",
            ["F4:F2:6D"] = "TP-Link", ["AC:84:C6"] = "TP-Link", ["30:B5:C2"] = "TP-Link",
            ["E8:48:B8"] = "TP-Link", ["1C:3B:F3"] = "TP-Link", ["54:AF:97"] = "TP-Link",
            // Netgear
            ["28:80:88"] = "Netgear", ["44:94:FC"] = "Netgear", ["6C:B0:CE"] = "Netgear",
            ["84:1B:5E"] = "Netgear", ["A0:21:B7"] = "Netgear", ["C4:04:15"] = "Netgear",
            ["E0:46:9A"] = "Netgear", ["E4:F4:C6"] = "Netgear", ["20:E5:2A"] = "Netgear",
            ["B0:7F:B9"] = "Netgear", ["CC:40:D0"] = "Netgear", ["9C:3D:CF"] = "Netgear",
            // Linksys (Belkin)
            ["20:AA:4B"] = "Linksys", ["C0:56:27"] = "Linksys", ["58:6D:8F"] = "Linksys",
            ["14:91:82"] = "Linksys", ["6C:72:20"] = "Linksys", ["E8:9F:80"] = "Linksys",
            // ASUS
            ["04:D9:F5"] = "ASUS", ["10:C3:7B"] = "ASUS", ["1C:87:2C"] = "ASUS",
            ["2C:FD:A1"] = "ASUS", ["38:D5:47"] = "ASUS", ["50:46:5D"] = "ASUS",
            ["78:24:AF"] = "ASUS", ["AC:9E:17"] = "ASUS", ["F0:2F:74"] = "ASUS",
            ["B0:6E:BF"] = "ASUS", ["70:8B:CD"] = "ASUS", ["24:4B:FE"] = "ASUS",
            // Ubiquiti
            ["04:18:D6"] = "Ubiquiti", ["24:A4:3C"] = "Ubiquiti", ["68:72:51"] = "Ubiquiti",
            ["78:8A:20"] = "Ubiquiti", ["80:2A:A8"] = "Ubiquiti", ["B4:FB:E4"] = "Ubiquiti",
            ["DC:9F:DB"] = "Ubiquiti", ["F4:92:BF"] = "Ubiquiti", ["E0:63:DA"] = "Ubiquiti",
            ["FC:EC:DA"] = "Ubiquiti", ["18:E8:29"] = "Ubiquiti", ["74:83:C2"] = "Ubiquiti",
            // Cisco / Meraki
            ["00:0C:29"] = "Cisco", ["00:1B:0D"] = "Cisco", ["58:97:1E"] = "Cisco",
            ["D4:AD:71"] = "Cisco (Meraki)", ["0C:8D:DB"] = "Cisco (Meraki)", ["AC:17:02"] = "Cisco (Meraki)",
            ["E8:55:B4"] = "Cisco (Meraki)", ["34:56:FE"] = "Cisco (Meraki)",
            // Huawei
            ["00:E0:FC"] = "Huawei", ["48:46:FB"] = "Huawei", ["88:CE:FA"] = "Huawei",
            ["CC:A2:23"] = "Huawei", ["20:F3:A3"] = "Huawei", ["70:8A:09"] = "Huawei",
            ["AC:CF:85"] = "Huawei", ["E4:68:A3"] = "Huawei", ["B4:30:52"] = "Huawei",
            // D-Link
            ["1C:7E:E5"] = "D-Link", ["28:10:7B"] = "D-Link", ["78:54:2E"] = "D-Link",
            ["B8:A3:86"] = "D-Link", ["C8:BE:19"] = "D-Link", ["F0:B4:D2"] = "D-Link",
            // MikroTik
            ["08:55:31"] = "MikroTik", ["2C:C8:1B"] = "MikroTik", ["48:8F:5A"] = "MikroTik",
            ["4C:5E:0C"] = "MikroTik", ["6C:3B:6B"] = "MikroTik", ["B8:69:F4"] = "MikroTik",
            ["CC:2D:E0"] = "MikroTik", ["D4:CA:6D"] = "MikroTik", ["E4:8D:8C"] = "MikroTik",
            // Synology
            ["00:11:32"] = "Synology", ["BC:6A:29"] = "Synology",
            // Google (Nest WiFi / Google WiFi)
            ["48:01:C5"] = "Google (Nest WiFi)", ["F4:F5:D8"] = "Google (Nest WiFi)",
            ["A4:77:33"] = "Google (Nest WiFi)", ["54:60:09"] = "Google (Nest WiFi)",
            // Apple (AirPort)
            ["70:56:81"] = "Apple (AirPort)", ["34:36:3B"] = "Apple (AirPort)",
            ["40:30:04"] = "Apple", ["F0:D1:A9"] = "Apple",
            // BT (Home Hub / Smart Hub)
            ["E8:65:D4"] = "BT (Home Hub)", ["08:36:C9"] = "BT (Home Hub)",
            // Sky (UK)
            ["CC:49:37"] = "Sky (UK)", ["D4:B9:2F"] = "Sky (UK)",
            // Virgin Media
            ["1C:E1:92"] = "Virgin Media", ["58:23:8C"] = "Virgin Media",
            // Arris / Motorola / CommScope
            ["20:3D:66"] = "Arris", ["F8:E4:FB"] = "Arris", ["00:1D:D1"] = "Arris",
            ["F8:8B:37"] = "Arris", ["44:E1:37"] = "Arris",
            // Eero (Amazon)
            ["50:01:BB"] = "Eero", ["F8:BB:BF"] = "Eero",
            // ZTE
            ["54:22:F8"] = "ZTE", ["44:F4:36"] = "ZTE", ["DC:02:8E"] = "ZTE",
            // Zyxel
            ["40:4A:03"] = "Zyxel", ["B0:B2:DC"] = "Zyxel", ["E4:18:6B"] = "Zyxel",
            // Juniper
            ["88:E0:F3"] = "Juniper", ["00:05:85"] = "Juniper", ["2C:21:31"] = "Juniper",
            // HPE / Aruba
            ["00:0B:86"] = "Aruba Networks", ["D8:C7:C8"] = "Aruba Networks",
            ["20:4C:03"] = "Aruba Networks", ["94:B4:0F"] = "Aruba Networks",
            // Fortinet
            ["00:09:0F"] = "Fortinet", ["70:4C:A5"] = "Fortinet", ["08:5B:0E"] = "Fortinet",
            // Palo Alto Networks
            ["00:1B:17"] = "Palo Alto Networks", ["08:66:1F"] = "Palo Alto Networks",
            // SonicWall
            ["00:06:B1"] = "SonicWall", ["C0:EA:E4"] = "SonicWall",
            // Sophos
            ["00:1A:8C"] = "Sophos", ["B4:74:9F"] = "Sophos",
            // Vodafone Station
            ["38:71:DE"] = "Vodafone", ["5C:F2:86"] = "Vodafone",
            // Deutsche Telekom (Speedport)
            ["00:1A:2A"] = "Deutsche Telekom (Speedport)", ["74:31:70"] = "Deutsche Telekom (Speedport)",
            // Swisscom (Internet Box)
            ["44:FE:3B"] = "Swisscom", ["5C:49:79"] = "Swisscom",
        };

        return ouiMap.TryGetValue(oui, out var manufacturer) ? manufacturer : null;
    }

    static async Task<TestResult> RunNetworkAdapters()
    {
        var result = new TestResult { Id = "L-LE-06", Name = "Network Adapter Details", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            int count = 0;
            var allDnsServers = new List<string>();   // collect unique DNS server IPs across adapters

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

                // DNS servers configured on this adapter
                var dnsAddrs = a.GetIPProperties().DnsAddresses
                    .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                    .Select(d => d.ToString())
                    .ToList();
                if (dnsAddrs.Count > 0)
                {
                    sb.AppendLine($"  DNS Servers: {string.Join(", ", dnsAddrs)}");
                    foreach (var dns in dnsAddrs)
                        if (!allDnsServers.Contains(dns))
                            allDnsServers.Add(dns);
                }
                sb.AppendLine();
            }

            // Attempt reverse DNS (PTR) lookup on each DNS server to get its name
            if (allDnsServers.Count > 0)
            {
                sb.AppendLine("═══ DNS Servers ═══");
                foreach (var dnsIp in allDnsServers)
                {
                    string name = "";
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(dnsIp);
                        if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != dnsIp)
                            name = entry.HostName;
                    }
                    catch { /* PTR lookup failed — that's fine */ }

                    sb.AppendLine(string.IsNullOrEmpty(name)
                        ? $"  {dnsIp}"
                        : $"  {dnsIp} ({name})");
                }
            }

            result.ResultValue = $"{count} active adapter(s)";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = count > 0 ? "Passed" : "Warning";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunBandwidthTest()
    {
        var result = new TestResult { Id = "L-LE-07", Name = "Bandwidth Estimation", Category = "local" };
        try
        {
            // Streaming HTTPS download test (~10 seconds)
            Console.Write("(measuring ~10s) ");
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(30));
            http.DefaultRequestHeaders.Add("User-Agent", "W365ConnectivityTool/2.0");

            // Test URLs in order of preference (progressively smaller for resilience)
            var testUrls = new[]
            {
                ("https://speed.cloudflare.com/__down?bytes=25000000", 25_000_000L),
                ("https://speed.cloudflare.com/__down?bytes=10000000", 10_000_000L),
                ("https://speed.cloudflare.com/__down?bytes=5000000", 5_000_000L)
            };

            double bestMbps = 0;
            string bestDetail = "";
            var attemptLog = new List<string>();

            foreach (var (testUrl, expectedSize) in testUrls)
            {
                var host = new Uri(testUrl).Host;
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

                    if (totalBytes < 50_000)
                    {
                        attemptLog.Add($"  \u26A0 {host}: only {totalBytes} bytes in {sw.Elapsed.TotalSeconds:F2}s \u2014 too little data, trying next");
                        continue;
                    }
                    // Note: do NOT reject short-elapsed measurements. On fast links (>=400 Mbps)
                    // a 25 MB payload can complete in well under 0.5s; a previous guard against
                    // sub-0.5s measurements caused every URL to be rejected on fast connections.
                    // 50 KB minimum is enough to compute a meaningful Mbps figure.

                    var sizeMB = totalBytes / (1024.0 * 1024.0);
                    var seconds = sw.Elapsed.TotalSeconds;
                    var mbps = (sizeMB * 8) / seconds;

                    if (mbps > bestMbps)
                    {
                        bestMbps = mbps;
                        bestDetail = $"Downloaded {sizeMB:F2} MB in {seconds:F1}s from {host}";
                    }
                    attemptLog.Add($"  \u2714 {host}: {mbps:F1} Mbps ({sizeMB:F2} MB / {seconds:F1}s)");

                    // If we got a good measurement, no need to try other URLs
                    if (totalBytes > 1_000_000)
                        break;
                }
                catch (HttpRequestException hex)
                {
                    // Capture WHY each URL failed so the user can act on it
                    var inner = hex.InnerException?.Message ?? hex.Message;
                    attemptLog.Add($"  \u2718 {host}: {inner}");
                }
                catch (TaskCanceledException)
                {
                    attemptLog.Add($"  \u2718 {host}: timeout (30s)");
                }
                catch (Exception ex)
                {
                    attemptLog.Add($"  \u2718 {host}: {ex.GetType().Name}: {ex.Message}");
                }
            }

            var detailLog = "Bandwidth attempts (per test URL):\n" + string.Join("\n", attemptLog);

            if (bestMbps > 0)
            {
                result.ResultValue = $"~{bestMbps:F1} Mbps (HTTPS download test)";
                result.DetailedInfo = $"Measured via HTTPS streaming download.\n{bestDetail}\n\n{detailLog}";
                result.Status = bestMbps > 5 ? "Passed" : bestMbps > 1 ? "Warning" : "Failed";
            }
            else
            {
                result.Status = "Error";
                result.ResultValue = "Could not measure bandwidth \u2014 all test URLs failed";
                result.DetailedInfo = detailLog
                    + "\n\nThis test downloads from speed.cloudflare.com. If every attempt failed,"
                    + "\nyour network is blocking that host (DNS filter, proxy denylist, captive"
                    + "\nportal, or strict outbound firewall). The browser-side B-LE-03 test uses"
                    + "\nin-page resources and is unaffected, so a green B-LE-03 + red L-LE-07"
                    + "\nspecifically indicates Cloudflare reachability is restricted, not that"
                    + "\nthe link is slow.";
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
    //  WINDOWS FIREWALL AUDIT
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunFirewallAudit()
    {
        var result = new TestResult { Id = "L-LE-10", Name = "Windows Firewall Audit", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();

            // Check if firewall is enabled
            var psi = new ProcessStartInfo("netsh", "advfirewall show allprofiles state")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var fwOutput = await proc!.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            sb.AppendLine("═══ Firewall Profile State ═══");
            sb.AppendLine(fwOutput.Trim());
            sb.AppendLine();

            // Check for blocking rules on key ports using Windows Firewall registry (locale-independent, no powershell)
            var portsToCheck = new[] {
                (443, "TCP", "HTTPS (RDP gateway, AFD, auth)"),
                (3478, "UDP", "TURN relay (UDP Shortpath)"),
                (80, "TCP", "Certificate endpoints (CRL/OCSP)")
            };

            sb.AppendLine("═══ Outbound Blocking Rules ═══");
            try
            {
                // Read firewall rules directly from registry — avoids spawning powershell.exe
                var allRules = ReadFirewallRulesFromRegistry();
                var outboundBlocks = allRules
                    .Where(r => r.Dir.Equals("Out", StringComparison.OrdinalIgnoreCase)
                             && r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var rule in outboundBlocks)
                {
                    foreach (var (port, proto, desc) in portsToCheck)
                    {
                        int protoNum = proto == "TCP" ? 6 : proto == "UDP" ? 17 : 0;
                        bool matchesProto = rule.Protocol == 256 || rule.Protocol == protoNum;
                        bool matchesPort = FwPortMatches(rule.LocalPort, port);

                        if (matchesPort && matchesProto)
                        {
                            var issue = $"Outbound {proto} {port} ({desc}) blocked by rule: {rule.Name}";
                            issues.Add(issue);
                            sb.AppendLine($"  ✗ {issue}");
                        }
                    }
                }

                // Also check if msrdcw or mstsc is explicitly blocked by rule name
                var rdpPatterns = new[] { "Remote Desktop", "RDP", "msrdc", "mstsc" };
                var rdpBlocks = outboundBlocks
                    .Where(r => rdpPatterns.Any(p => r.Name.Contains(p, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (rdpBlocks.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("═══ RDP Application Block Rules ═══");
                    foreach (var rule in rdpBlocks)
                    {
                        sb.AppendLine($"  DisplayName : {rule.Name}");
                        issues.Add("Outbound firewall rule explicitly blocks RDP client application");
                    }
                }
            }
            catch { sb.AppendLine("  Could not enumerate firewall blocking rules"); }

            if (issues.Count == 0)
            {
                sb.AppendLine("  ✓ No outbound blocking rules found for W365 required ports");
            }

            result.DetailedInfo = sb.ToString().Trim();
            if (issues.Count == 0)
            {
                result.Status = "Passed";
                result.ResultValue = "No firewall rules blocking W365 required ports (TCP 443, UDP 3478, TCP 80)";
            }
            else
            {
                result.Status = "Warning";
                result.ResultValue = $"{issues.Count} blocking rule{(issues.Count > 1 ? "s" : "")} found: {string.Join("; ", issues.Take(3))}";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network";
                result.RemediationText = "Review Windows Firewall outbound rules. Ensure TCP 443 and UDP 3478 are not blocked for W365 endpoints.";
            }
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.ResultValue = ex.Message;
        }
        return result;
    }

    // ═══════════════════════════════════════════
    //  RDP GROUP POLICY CHECK
    // ═══════════════════════════════════════════

    static Task<TestResult> RunRdpGroupPolicyCheck()
    {
        var result = new TestResult { Id = "L-LE-11", Name = "RDP Group Policy Check", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();

            // Check Terminal Services policies
            string[] policyPaths = {
                @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
            };

            sb.AppendLine("═══ Terminal Services Group Policy ═══");

            foreach (var path in policyPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(path);
                    if (key == null) continue;

                    sb.AppendLine($"  Registry: HKLM\\{path}");
                    var valueNames = key.GetValueNames();
                    foreach (var name in valueNames)
                    {
                        var value = key.GetValue(name);
                        sb.AppendLine($"    {name} = {value}");
                    }

                    // Check for specific problematic policies
                    // fClientDisableUDP = 1 disables UDP transport
                    var udpDisabled = key.GetValue("fClientDisableUDP");
                    if (udpDisabled != null && Convert.ToInt32(udpDisabled) == 1)
                    {
                        issues.Add("UDP transport disabled by Group Policy (fClientDisableUDP=1)");
                    }

                    // SelectTransport: 1 = UDP+TCP, 2 = TCP only
                    var selectTransport = key.GetValue("SelectTransport");
                    if (selectTransport != null && Convert.ToInt32(selectTransport) == 2)
                    {
                        issues.Add("Transport forced to TCP-only by Group Policy (SelectTransport=2)");
                    }

                    // fDenyTSConnections = 1 blocks all RDP
                    var denyConn = key.GetValue("fDenyTSConnections");
                    if (denyConn != null && Convert.ToInt32(denyConn) == 1)
                    {
                        issues.Add("Remote Desktop connections denied by policy (fDenyTSConnections=1)");
                    }

                    // SecurityLayer: 0=RDP, 1=Negotiate, 2=TLS
                    var secLayer = key.GetValue("SecurityLayer");
                    if (secLayer != null)
                    {
                        var secVal = Convert.ToInt32(secLayer);
                        if (secVal == 0) issues.Add("RDP Security Layer set to 'RDP Security' (SecurityLayer=0) — less secure than TLS");
                    }

                    // MaxCompressionLevel
                    var compression = key.GetValue("MaxCompressionLevel");
                    if (compression != null && Convert.ToInt32(compression) == 0)
                    {
                        issues.Add("RDP compression disabled by policy (MaxCompressionLevel=0)");
                    }

                    // AVC444ModePreferred / AVCHardwareEncodePreferred
                    var avc = key.GetValue("AVC444ModePreferred");
                    if (avc != null) sb.AppendLine($"    → AVC 4:4:4 mode: {(Convert.ToInt32(avc) == 1 ? "Preferred" : "Not preferred")}");

                    sb.AppendLine();
                }
                catch { /* registry path not accessible */ }
            }

            // Check RDP Shortpath policy (newer path for AVD/W365)
            try
            {
                using var shortpathKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client");
                if (shortpathKey != null)
                {
                    var useUdp = shortpathKey.GetValue("fClientDisableUDP");
                    if (useUdp != null && Convert.ToInt32(useUdp) == 1)
                    {
                        if (!issues.Any(i => i.Contains("fClientDisableUDP")))
                            issues.Add("Client UDP disabled by policy under Client subkey (fClientDisableUDP=1)");
                    }
                }
            }
            catch { }

            // Check for RDP client autoupdate policy
            try
            {
                using var msrdcKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\MSRDC\Policies");
                if (msrdcKey != null)
                {
                    sb.AppendLine("═══ MSRDC Client Policies ═══");
                    foreach (var name in msrdcKey.GetValueNames())
                    {
                        sb.AppendLine($"    {name} = {msrdcKey.GetValue(name)}");
                    }
                    sb.AppendLine();
                }
            }
            catch { }

            if (issues.Count == 0)
            {
                result.Status = "Passed";
                result.ResultValue = "No restrictive RDP Group Policies detected";
                sb.AppendLine("  ✓ No problematic Terminal Services policies found");
            }
            else
            {
                result.Status = "Warning";
                result.ResultValue = string.Join("; ", issues);
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/configure-rdp-shortpath";
                result.RemediationText = "Review Group Policy settings under Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services.";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return Task.FromResult(result);
    }

    // ═══════════════════════════════════════════
    //  WIFI CHANNEL CONGESTION
    // ═══════════════════════════════════════════

    static async Task<TestResult> RunWifiChannelCongestion()
    {
        var result = new TestResult { Id = "L-LE-12", Name = "WiFi Channel Congestion", Category = "local" };
        try
        {
            // First check if we're on WiFi at all
            var ifPsi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var ifProc = Process.Start(ifPsi);
            var ifOutput = await ifProc!.StandardOutput.ReadToEndAsync();
            await ifProc.WaitForExitAsync();

            if (string.IsNullOrWhiteSpace(ifOutput))
            {
                result.Status = "Skipped";
                result.ResultValue = "No wireless interface detected (wired connection)";
                return result;
            }

            // Check Wi-Fi connection state using .NET API (locale-independent)
            if (!IsWifiConnected())
            {
                result.Status = "Skipped";
                result.ResultValue = "Not connected by WiFi";
                return result;
            }

            // Get current channel and band using locale-independent parser
            var (_, mySsid, myBand, myChannel) = ParseNetshWlanFields(ifOutput);
            var ifLines = ifOutput.Split('\n');
            var myBssid = ifLines.FirstOrDefault(l => l.Contains(" : ") && Regex.IsMatch(l.Split(new[] { " : " }, 2, StringSplitOptions.None).LastOrDefault()?.Trim() ?? "", @"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"))
                ?.Split(new[] { " : " }, 2, StringSplitOptions.None).LastOrDefault()?.Trim();

            int currentChannel = int.TryParse(myChannel, out var ch) ? ch : 0;

            // Scan nearby networks
            var psi = new ProcessStartInfo("netsh", "wlan show networks mode=bssid")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = await proc!.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            var sb = new StringBuilder();
            sb.AppendLine($"═══ Your Connection ═══");
            sb.AppendLine($"  SSID: {mySsid ?? "N/A"}");
            sb.AppendLine($"  BSSID: {myBssid ?? "N/A"}");
            sb.AppendLine($"  Channel: {myChannel ?? "N/A"}");
            sb.AppendLine($"  Radio: {myBand ?? "N/A"}");
            sb.AppendLine();

            // Parse nearby networks — each BSSID block
            var networks = new List<(string ssid, int channel, int signal, string band)>();
            string currentSsid = "";
            var bssidBlocks = output.Split(new[] { "BSSID" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var block in bssidBlocks)
            {
                var blockLines = block.Split('\n');

                // Parse fields locale-independently using value patterns
                string? blockSsid = null, blockSig = null, blockCh = null, blockRadio = null;
                foreach (var bLine in blockLines)
                {
                    var cIdx = bLine.IndexOf(" : ");
                    if (cIdx < 0) continue;
                    var bKey = bLine.Substring(0, cIdx).Trim();
                    var bVal = bLine.Substring(cIdx + 3).Trim();

                    if (blockSsid == null && !Regex.IsMatch(bVal, @"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
                        && bKey.Length <= 10 && !bKey.Contains("BSSID", StringComparison.OrdinalIgnoreCase)
                        && !Regex.IsMatch(bVal, @"^\d+%$") && !bVal.Contains("802.11"))
                    { blockSsid = bVal; continue; }

                    if (blockSig == null && Regex.IsMatch(bVal, @"^\d+%$"))
                    { blockSig = bVal; continue; }

                    if (blockRadio == null && bVal.Contains("802.11"))
                    { blockRadio = bVal; continue; }

                    if (blockCh == null && blockSig != null && int.TryParse(bVal, out var chVal) && chVal >= 1 && chVal <= 165)
                    { blockCh = bVal; continue; }
                }

                if (blockSsid != null) currentSsid = blockSsid;

                if (blockCh != null && int.TryParse(blockCh, out var c) && blockSig != null)
                {
                    var sig = int.TryParse(blockSig.Replace("%", ""), out var s) ? s : 0;
                    networks.Add((currentSsid, c, sig, blockRadio ?? ""));
                }
            }

            // Count networks on same channel
            int sameChannel = currentChannel > 0 ? networks.Count(n => n.channel == currentChannel) : 0;

            // Count overlapping channels (2.4 GHz channels 1-13 overlap ±2)
            int overlapping = 0;
            bool is24Ghz = currentChannel > 0 && currentChannel <= 14;
            if (is24Ghz)
            {
                overlapping = networks.Count(n => n.channel > 0 && n.channel <= 14 && Math.Abs(n.channel - currentChannel) <= 2 && n.channel != currentChannel);
            }

            // Channel usage histogram
            var channelCounts = networks.GroupBy(n => n.channel).OrderBy(g => g.Key).ToList();
            sb.AppendLine($"═══ Nearby Networks: {networks.Count} total ═══");
            sb.AppendLine();
            sb.AppendLine("Channel usage:");
            foreach (var g in channelCounts)
            {
                var marker = g.Key == currentChannel ? " ← YOUR CHANNEL" : "";
                sb.AppendLine($"  Ch {g.Key,3}: {g.Count()} network{(g.Count() > 1 ? "s" : "")} (strongest: {g.Max(n => n.signal)}%){marker}");
            }

            sb.AppendLine();
            sb.AppendLine("Strongest networks on your channel:");
            var sameChNetworks = networks.Where(n => n.channel == currentChannel).OrderByDescending(n => n.signal).Take(5);
            foreach (var n in sameChNetworks)
            {
                sb.AppendLine($"  {n.ssid,-24} Signal: {n.signal}%  Radio: {n.band}");
            }

            result.DetailedInfo = sb.ToString().Trim();

            if (currentChannel == 0)
            {
                result.Status = "Skipped";
                result.ResultValue = "Could not determine WiFi channel";
            }
            else if (sameChannel >= 6)
            {
                result.Status = "Warning";
                result.ResultValue = $"{sameChannel} networks on channel {currentChannel} — heavy congestion. {(is24Ghz ? $"{overlapping} additional overlapping networks." : "")}";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/troubleshoot-windows-365-boot#networking-checks";
                result.RemediationText = is24Ghz
                    ? "Consider switching to 5 GHz band or using channels 1, 6, or 11 (non-overlapping 2.4 GHz channels). A wired Ethernet connection eliminates WiFi congestion entirely."
                    : "Consider using a less congested 5 GHz channel. Many routers have auto-channel selection that can be configured.";
            }
            else if (sameChannel >= 3)
            {
                result.Status = "Passed";
                result.ResultValue = $"{sameChannel} networks on channel {currentChannel} — moderate density. {(is24Ghz ? $"{overlapping} overlapping." : "")} Total: {networks.Count} nearby networks.";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = $"{sameChannel} network{(sameChannel > 1 ? "s" : "")} on channel {currentChannel} — low congestion. Total: {networks.Count} nearby networks.";
            }
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.ResultValue = ex.Message;
        }
        return result;
    }

    // ═══════════════════════════════════════════
    //  RDP CLIENT VERSION CHECK
    // ═══════════════════════════════════════════

    /// <summary>
    /// L-LE-13: Detects installed Windows App / MSRDC / MSTSC and checks version currency.
    /// Version history from https://learn.microsoft.com/en-us/windows-app/whats-new?tabs=windows
    /// </summary>
    static async Task<TestResult> RunRdpClientVersion()
    {
        var result = new TestResult { Id = "L-LE-13", Name = "RDP Client Version", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            string? primaryClient = null;
            Version? primaryVersion = null;
            bool foundAny = false;

            // ── 1. Windows App (Store MSIX) — MicrosoftCorporationII.Windows365 ──
            try
            {
                // Read MSIX package version from registry (avoids spawning powershell.exe)
                using var pkgKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages");
                if (pkgKey != null)
                {
                    foreach (var subKeyName in pkgKey.GetSubKeyNames())
                    {
                        if (subKeyName.Contains("MicrosoftCorporationII.Windows365", StringComparison.OrdinalIgnoreCase))
                        {
                            // Package key format: MicrosoftCorporationII.Windows365_1.2.3.4_x64__8wekyb3d8bbwe
                            var parts = subKeyName.Split('_');
                            if (parts.Length >= 2 && Version.TryParse(parts[1], out var waVer))
                            {
                                sb.AppendLine($"Windows App (Store): {waVer}");
                                primaryClient = "Windows App";
                                primaryVersion = waVer;
                                foundAny = true;
                            }
                            break;
                        }
                    }
                }
            }
            catch { /* Registry query failed — not installed or access denied */ }

            // ── 2. Standalone MSRDC installer (non-Store) ──
            if (!foundAny)
            {
                var msrdcPaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Apps\Remote Desktop\msrdcw.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Remote Desktop\msrdcw.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Remote Desktop\msrdcw.exe"),
                };
                foreach (var p in msrdcPaths)
                {
                    if (File.Exists(p))
                    {
                        var fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(p);
                        if (Version.TryParse(fvi.FileVersion?.Split(' ')[0], out var msrdcVer))
                        {
                            sb.AppendLine($"Remote Desktop Client (standalone): {msrdcVer}");
                            sb.AppendLine($"  Path: {p}");
                            if (primaryClient == null) { primaryClient = "MSRDC"; primaryVersion = msrdcVer; }
                            foundAny = true;
                        }
                        break;
                    }
                }
            }

            // ── 3. Built-in MSTSC (always present) ──
            var mstscPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstsc.exe");
            if (File.Exists(mstscPath))
            {
                var fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(mstscPath);
                if (Version.TryParse(fvi.FileVersion?.Split(' ')[0], out var mstscVer))
                {
                    sb.AppendLine($"Built-in RDP Client (mstsc.exe): {mstscVer}");
                    if (primaryClient == null) { primaryClient = "mstsc"; primaryVersion = mstscVer; }
                    foundAny = true;
                }
            }

            // ── Version currency check (N-3 policy) ──
            // Published PUBLIC releases of Windows App for Windows, newest first.
            // Source: https://learn.microsoft.com/en-us/windows-app/whats-new?tabs=windows
            // Policy: latest (N) = up to date (Passed); N-1..N-3 = update available
            //         (Warning, still within support window); N-4 or older = unsupported
            //         (Failed). N-3 currently equals Microsoft's published
            //         "Minimum supported version" (2.0.1071.0).
            // To refresh: prepend new public releases as Microsoft ships them.
            var publishedWindowsApp = new (Version ver, string date)[]
            {
                (new Version(2, 0, 1193, 0), "2026-06-10"),  // N    (Minimum supported per MS: 2.0.1071.0)
                (new Version(2, 0, 1186, 0), "2026-05-26"),  // N-1
                (new Version(2, 0, 1129, 0), "2026-05-05"),  // N-2
                (new Version(2, 0, 1071, 0), "2026-04-24"),  // N-3  <- minimum supported
                (new Version(2, 0, 1070, 0), "2026-04-14"),  // N-4  (fails)
                (new Version(2, 0, 1069, 0), "2026-04-07"),
                (new Version(2, 0,  964, 0), "2026-02-10"),
                (new Version(2, 0,  918, 0), "2026-01-22"),
                (new Version(2, 0,  916, 0), "2026-01-14"),
                (new Version(2, 0,  866, 0), "2025-12-16"),
                (new Version(2, 0,  804, 0), "2025-11-12"),
                (new Version(2, 0,  757, 0), "2025-10-23"),
            };
            var latestKnownWindowsApp = publishedWindowsApp[0].ver;
            var latestDate = publishedWindowsApp[0].date;
            // N-3 = the 4th-newest published release (or the oldest we know about if the
            // list is shorter). Anything older than this (N-4+) is unsupported.
            int n3Index = Math.Min(3, publishedWindowsApp.Length - 1);
            var minimumSupported = publishedWindowsApp[n3Index].ver;

            if (primaryClient == "Windows App" && primaryVersion != null)
            {
                sb.AppendLine();

                if (primaryVersion >= latestKnownWindowsApp)
                {
                    sb.AppendLine($"\u2714 Running latest known version (released {latestDate})");
                    result.Status = "Passed";
                    result.ResultValue = $"Windows App {primaryVersion} \u2014 up to date";
                }
                else if (primaryVersion >= minimumSupported)
                {
                    sb.AppendLine($"\u26a0 Update available: latest known version is {latestKnownWindowsApp} (released {latestDate})");
                    sb.AppendLine($"  Within the supported window (N-3 minimum is {minimumSupported}).");
                    result.Status = "Warning";
                    result.ResultValue = $"Windows App {primaryVersion} \u2014 update available";
                    result.RemediationUrl = "https://learn.microsoft.com/windows-app/whats-new?tabs=windows";
                }
                else
                {
                    sb.AppendLine($"\u2718 Older than N-3 \u2014 below minimum supported version ({minimumSupported})");
                    sb.AppendLine($"  Latest known: {latestKnownWindowsApp} (released {latestDate})");
                    result.Status = "Failed";
                    result.ResultValue = $"Windows App {primaryVersion} \u2014 below minimum supported (older than N-3)";
                    result.RemediationUrl = "https://learn.microsoft.com/windows-app/whats-new?tabs=windows";
                }
            }
            else if (primaryClient == "mstsc" && primaryVersion != null)
            {
                sb.AppendLine();
                sb.AppendLine("\u26a0 Only the built-in RDP client (mstsc.exe) is installed.");
                sb.AppendLine("  Windows App is recommended for the best Windows 365 / AVD experience.");
                sb.AppendLine("  It supports RDP Shortpath, Teams AV redirect, and auto-updates.");
                result.Status = "Warning";
                result.ResultValue = $"mstsc.exe only — Windows App recommended";
                result.RemediationUrl = "https://learn.microsoft.com/windows-app/get-started-connect-devices-desktops-apps";
            }
            else if (!foundAny)
            {
                result.Status = "Warning";
                result.ResultValue = "No RDP client detected";
                sb.AppendLine("Could not detect any RDP client installation.");
                result.RemediationUrl = "https://learn.microsoft.com/windows-app/get-started-connect-devices-desktops-apps";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = $"{primaryClient} {primaryVersion}";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ═══════════════════════════════════════════
    //  DNS SERVER IDENTIFICATION
    // ═══════════════════════════════════════════

    /// <summary>
    /// L-LE-14: Identifies configured DNS servers, classifies the provider, and detects encrypted DNS.
    /// </summary>
    static async Task<TestResult> RunDnsServerIdentification()
    {
        var result = new TestResult { Id = "L-LE-14", Name = "DNS Server Identification", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var dnsServers = new List<(string ip, string adapterName)>();

            // ── 1. Collect DNS servers from all active adapters ──
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            foreach (var a in adapters)
            {
                var dnsAddrs = a.GetIPProperties().DnsAddresses
                    .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                    .Select(d => d.ToString())
                    .ToList();
                foreach (var dns in dnsAddrs)
                    dnsServers.Add((dns, a.Name));
            }

            // Deduplicate by IP
            var uniqueDns = dnsServers
                .GroupBy(d => d.ip)
                .Select(g => (ip: g.Key, adapters: string.Join(", ", g.Select(x => x.adapterName).Distinct())))
                .ToList();

            if (uniqueDns.Count == 0)
            {
                result.Status = "Warning";
                result.ResultValue = "No DNS servers configured";
                result.DetailedInfo = "No IPv4 DNS servers found on any active network adapter.";
                return result;
            }

            sb.AppendLine($"Configured DNS servers: {uniqueDns.Count}");
            sb.AppendLine();

            var warnings = new List<string>();
            var providers = new List<string>();

            foreach (var (ip, adapterNames) in uniqueDns)
            {
                sb.AppendLine($"DNS Server: {ip}");
                sb.AppendLine($"  Adapter(s): {adapterNames}");

                // Classify the DNS provider
                var classification = ClassifyDnsServer(ip);
                sb.AppendLine($"  Provider: {classification}");
                providers.Add(classification);

                // Reverse DNS lookup
                try
                {
                    var entry = await Dns.GetHostEntryAsync(ip);
                    if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != ip)
                        sb.AppendLine($"  Hostname: {entry.HostName}");
                }
                catch { /* PTR lookup failed */ }

                // Test responsiveness — resolve a known good domain
                try
                {
                    var sw = Stopwatch.StartNew();
                    await Dns.GetHostEntryAsync("login.microsoftonline.com");
                    sw.Stop();
                    sb.AppendLine($"  Response time: {sw.ElapsedMilliseconds}ms (login.microsoftonline.com)");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"  Response: FAILED ({ex.Message})");
                    warnings.Add($"{ip} failed to resolve login.microsoftonline.com");
                }

                sb.AppendLine();
            }

            // ── 2. Detect actual resolver via whoami-style check ──
            // Detect actual resolver via DNS-over-HTTPS whoami (avoids spawning nslookup)
            sb.AppendLine("═══ Actual Resolver Detection ═══");
            try
            {
                using var dohHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
                // Google DoH: resolve o-o.myaddr.l.google.com TXT → returns resolver's IP
                var dohResp = await dohHttp.GetStringAsync("https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT");
                var txtMatch = Regex.Match(dohResp, @"""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""");
                if (txtMatch.Success)
                {
                    var resolverEgressIp = txtMatch.Groups[1].Value;
                    sb.AppendLine($"Resolver egress IP (as seen by Google): {resolverEgressIp}");
                    var resolverClass = ClassifyDnsServer(resolverEgressIp);
                    sb.AppendLine($"Resolver classification: {resolverClass}");

                    // Check if this differs from configured DNS
                    if (!uniqueDns.Any(d => d.ip == resolverEgressIp))
                    {
                        // Differentiate the two common patterns:
                        //   (a) Configured DNS is RFC1918 (router/DHCP) but the resolver
                        //       egress IP is public — almost always means the local
                        //       router/firewall is forwarding upstream to a public resolver
                        //       (typical of consumer routers, captive networks, mobile/transit
                        //       gateways). This is normal, not encrypted DNS.
                        //   (b) Configured DNS is public but resolver egress differs — could
                        //       indicate DoH/DoT or a transparent DNS interception by a SWG.
                        bool allConfiguredArePrivate = uniqueDns.Count > 0
                            && uniqueDns.All(d => IsPrivateIp(d.ip));
                        bool resolverIsPublic = !IsPrivateIp(resolverEgressIp);
                        if (allConfiguredArePrivate && resolverIsPublic)
                        {
                            sb.AppendLine("Note: Local router/DHCP DNS forwards upstream to a public resolver (typical of consumer/transit/mobile gateways).");
                        }
                        else
                        {
                            sb.AppendLine("Note: Resolver egress IP differs from configured DNS — DNS forwarding, encrypted DNS (DoH/DoT), or a SWG transparent DNS proxy may be in use.");
                        }
                    }
                }
                else
                {
                    sb.AppendLine("Could not determine resolver egress IP (TXT record not found)");
                }
            }
            catch { sb.AppendLine("Resolver detection query failed"); }

            // ── 3. Check Windows Encrypted DNS (DoH) settings via registry ──
            sb.AppendLine();
            sb.AppendLine("═══ Encrypted DNS (DoH) ═══");
            bool dohDetected = false;
            try
            {
                // Windows 11+ stores DoH config per-interface in HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters
                using var dohKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters");
                if (dohKey != null)
                {
                    foreach (var iface in dohKey.GetSubKeyNames())
                    {
                        foreach (var subPath in new[] { @"DohInterfaceSettings\Doh", @"DohInterfaceSettings\Doh6" })
                        {
                            using var dohSub = dohKey.OpenSubKey($@"{iface}\{subPath}");
                            if (dohSub != null)
                            {
                                foreach (var serverKey in dohSub.GetSubKeyNames())
                                {
                                    using var srvKey = dohSub.OpenSubKey(serverKey);
                                    var flags = srvKey?.GetValue("DohFlags");
                                    if (flags != null)
                                    {
                                        var flagVal = Convert.ToInt32(flags);
                                        // DohFlags: 1 = automatic (fallback), 2 = mandatory DoH
                                        var mode = flagVal switch
                                        {
                                            1 => "Automatic (DoH with fallback)",
                                            2 => "Mandatory DoH only",
                                            _ => $"Flags={flagVal}"
                                        };
                                        sb.AppendLine($"  DoH configured for {serverKey}: {mode}");
                                        dohDetected = true;
                                    }
                                }
                            }
                        }
                    }
                }
                if (!dohDetected)
                    sb.AppendLine("  No DNS-over-HTTPS configuration detected");
            }
            catch { sb.AppendLine("  Could not read DoH registry settings"); }

            // ── 4. Set status ──
            var providerSummary = string.Join(", ", providers.Distinct());
            if (warnings.Count > 0)
            {
                result.Status = "Warning";
                result.ResultValue = $"{providerSummary} — {warnings.Count} issue(s)";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = providerSummary;
                if (dohDetected) result.ResultValue += " (DoH enabled)";
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>Classify a DNS server IP into a known provider.</summary>
    static string ClassifyDnsServer(string ip)
    {
        return ip switch
        {
            // Google Public DNS
            "8.8.8.8" or "8.8.4.4" => "Google Public DNS",
            // Cloudflare
            "1.1.1.1" or "1.0.0.1" => "Cloudflare DNS",
            "1.1.1.2" or "1.0.0.2" => "Cloudflare DNS (Malware filter)",
            "1.1.1.3" or "1.0.0.3" => "Cloudflare DNS (Family filter)",
            // Quad9
            "9.9.9.9" or "149.112.112.112" => "Quad9 (Malware filter)",
            "9.9.9.10" or "149.112.112.10" => "Quad9 (No filter)",
            // OpenDNS / Cisco Umbrella
            "208.67.222.222" or "208.67.220.220" => "OpenDNS / Cisco Umbrella",
            "208.67.222.123" or "208.67.220.123" => "OpenDNS FamilyShield",
            // Azure DNS (used inside Azure VMs)
            "168.63.129.16" => "Azure Internal DNS",
            // Zscaler common ranges
            _ when ip.StartsWith("165.225.") || ip.StartsWith("104.129.") || ip.StartsWith("136.226.") => "Zscaler Cloud DNS",
            // Private RFC1918 ranges — likely corporate/router DNS
            _ when IsPrivateIp(ip) => "Private/Corporate DNS",
            // Anything else — unknown public
            _ => "Public DNS"
        };
    }

    static bool IsPrivateIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        var bytes = addr.GetAddressBytes();
        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254);
    }

    /// <summary>
    /// Classify an ISP/org string into a network type. Returns (type, warning) or null.
    /// Detects satellite, aircraft WiFi, hotel, and other high-latency connections.
    /// </summary>
    static (string type, string? warning)? ClassifyNetworkType(string org)
    {
        var lower = org.ToLowerInvariant();

        // Satellite Internet providers (500-800ms+ RTT)
        string[] satPatterns = ["inmarsat", "viasat", "hughesnet", "starlink", "ses s.a", "eutelsat",
            "telesat", "oneweb", "iridium", "globalstar", "thuraya", "bgan", "ses astra",
            "sky muster", "tooway", "konnect", "cobham satcom"];
        if (satPatterns.Any(p => lower.Contains(p)))
            return ("Satellite Internet", "Satellite connections have 500-800ms+ latency. RDP sessions will be noticeably laggy and UDP Shortpath may not work reliably.");

        // Aircraft WiFi (satellite-backed)
        string[] aircraftPatterns = ["gogo", "panasonic avionics", "global eagle", "anuvu",
            "thales inflyt", "inflyt", "smartsky", "honeywell aerospace",
            "sitaonair", "sita onair", "aeromobile", "boingo wireless", "a2n"];
        if (aircraftPatterns.Any(p => lower.Contains(p)))
            return ("Aircraft WiFi", "Aircraft WiFi uses satellite backhaul with 600ms+ latency, packet loss, and bandwidth caps. RDP will be severely degraded.");

        // Hotel/guest WiFi
        string[] hotelPatterns = ["nomadix", "guest-tek", "guesttek", "ruckus hospitality"];
        if (hotelPatterns.Any(p => lower.Contains(p)))
            return ("Hotel/Guest WiFi", "Hotel/guest WiFi may have bandwidth caps, high latency, or blocking of UDP traffic.");

        return null;
    }

    // ═══════════════════════════════════════════
    //  PATH MTU DISCOVERY
    // ═══════════════════════════════════════════

    /// <summary>
    /// L-LE-15: Discovers the path MTU to key W365/AVD endpoints using DF-bit ping binary search.
    /// </summary>
    static async Task<TestResult> RunPathMtuDiscovery()
    {
        var result = new TestResult { Id = "L-LE-15", Name = "Path MTU Discovery", Category = "local" };
        try
        {
            var sb = new StringBuilder();

            // ── Build target list: default gateway + reliable public ICMP responders ──
            // Cloud endpoints (AFD, TURN) often block/filter ICMP so can't be used for MTU probing.
            // Instead we test the actual network path segments that matter.
            var targets = new List<(IPAddress ip, string label)>();

            // 1. Default gateway — tests local segment MTU (VPN/tunnel impact)
            var gw = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
            if (gw != null)
                targets.Add((gw.Address, "Default Gateway"));

            // 2. Public DNS — tests Internet path MTU (ISP/WAN segment)
            targets.Add((IPAddress.Parse("8.8.8.8"), "Google DNS (Internet path)"));
            targets.Add((IPAddress.Parse("1.1.1.1"), "Cloudflare DNS (Internet path)"));

            int minMtu = int.MaxValue;
            int testedCount = 0;
            var issues = new List<string>();

            foreach (var (targetIp, label) in targets)
            {
                sb.AppendLine($"Target: {label} ({targetIp})");

                const int icmpOverhead = 28; // IP header (20) + ICMP header (8)
                int lo = 0, hi = 1472;       // 1472 + 28 = 1500 (standard Ethernet)
                int bestPayload = -1;

                using var ping = new Ping();
                var options = new PingOptions { DontFragment = true, Ttl = 128 };

                // Verify host responds to ICMP at all (tiny payload)
                bool respondsAtAll = await TestPingPayload(ping, targetIp, 1, options);
                if (!respondsAtAll)
                {
                    sb.AppendLine($"  No ICMP response — skipped");
                    sb.AppendLine();
                    continue;
                }

                // Test standard Ethernet payload first
                bool standardWorks = await TestPingPayload(ping, targetIp, hi, options);
                if (standardWorks)
                {
                    bestPayload = hi;
                    sb.AppendLine($"  MTU: ≥1500 (standard Ethernet — OK)");
                    minMtu = Math.Min(minMtu, 1500);
                }
                else
                {
                    // Binary search for max payload
                    while (lo <= hi)
                    {
                        int mid = (lo + hi) / 2;
                        bool ok = await TestPingPayload(ping, targetIp, mid, options);
                        if (ok)
                        {
                            bestPayload = mid;
                            lo = mid + 1;
                        }
                        else
                        {
                            hi = mid - 1;
                        }
                    }

                    if (bestPayload >= 0)
                    {
                        int mtu = bestPayload + icmpOverhead;
                        sb.AppendLine($"  Path MTU: {mtu} bytes (payload {bestPayload} + {icmpOverhead} overhead)");

                        if (mtu < 1280)
                        {
                            sb.AppendLine($"  ✘ MTU below 1280 — will cause fragmentation and likely connection failures");
                            issues.Add($"{label}: MTU {mtu} (critically low)");
                        }
                        else if (mtu < 1400)
                        {
                            sb.AppendLine($"  ⚠ MTU below 1400 — may cause UDP Shortpath fragmentation");
                            issues.Add($"{label}: MTU {mtu} (suboptimal for Shortpath)");
                        }
                        else
                        {
                            sb.AppendLine($"  ✓ MTU adequate for RDP traffic");
                        }
                        minMtu = Math.Min(minMtu, mtu);
                    }
                    else
                    {
                        sb.AppendLine($"  ✘ Responds to ping but all DF-bit probes failed");
                        issues.Add($"{label}: DF-bit probes failed");
                    }
                }

                testedCount++;
                sb.AppendLine();
            }

            // ── Adapter MTU check (local interface) ──
            // An MTU below 1500 on a physical adapter is often legitimate:
            //   1492 = PPPoE (UK FTTC/FTTP, many DSL/fibre ISPs)
            //   1480 = GRE / IP-in-IP / 6in4
            //   1452 = PPPoE over an additional tag
            //   1428 = PPPoE + IPSec
            //   1380-1400 = typical VPN tunnel
            // We only report it as an issue when path-MTU probes to the
            // probed Internet targets actually showed reduced PMTU below 1400
            // (already captured as "critically low"/issues above). On a 1492
            // PPPoE link with full path MTU, the adapter value is informational.
            sb.AppendLine("═══ Local Interface MTU ═══");
            var activeAdapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                    && n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork));

            foreach (var a in activeAdapters)
            {
                var ipProps = a.GetIPProperties();
                var ipv4Props = ipProps.GetIPv4Properties();
                if (ipv4Props != null)
                {
                    int mtu = ipv4Props.Mtu;
                    sb.AppendLine($"  {a.Name}: Interface MTU = {mtu}");
                    if (mtu < 1500)
                    {
                        // 1492 has multiple legitimate causes — PPPoE is only one of them.
                        // Mobile / transit / bonded-cellular gateways and many carrier
                        // L2TP/MPLS access products clamp to ~1492 too. Naming PPPoE
                        // specifically misleads users on those networks; describe the
                        // observation generically and list common causes.
                        string explanation = mtu switch
                        {
                            1492 => "common on PPPoE access (UK FTTC/FTTP, many DSL/fibre ISPs) and on mobile / transit / bonded-cellular gateways — usually expected, not a problem",
                            1480 => "GRE / IP-in-IP tunnel \u2014 typical for some corporate networks",
                            1452 => "PPPoE with additional VLAN tag",
                            1428 => "PPPoE + IPSec",
                            < 1400 => "very low \u2014 likely VPN tunnel or aggressive QoS clamping; may impact RDP",
                            _ => "non-standard \u2014 may be VPN, tunnel, or carrier-side clamping"
                        };
                        bool benign = mtu == 1492 || mtu == 1480 || mtu == 1452;
                        // Only flag as an issue if the local MTU is genuinely low AND
                        // the path-MTU probes did not already pass for the targets.
                        bool pathMtuOk = !issues.Any(i => i.Contains("critically low") || i.Contains("DF-bit probes failed"));
                        if (benign && pathMtuOk)
                        {
                            sb.AppendLine($"    \u2139 {explanation}");
                        }
                        else if (mtu >= 1400 && pathMtuOk)
                        {
                            sb.AppendLine($"    \u2139 {explanation}");
                        }
                        else
                        {
                            sb.AppendLine($"    \u26A0 {explanation}");
                            if (!issues.Any(i => i.Contains("Interface MTU")))
                                issues.Add($"Interface MTU {mtu} on {a.Name}");
                        }
                    }
                }
            }

            // ── Set status ──
            if (testedCount == 0)
            {
                result.Status = "Warning";
                result.ResultValue = "Could not test any target";
            }
            else if (issues.Any(i => i.Contains("critically low")))
            {
                result.Status = "Failed";
                result.ResultValue = minMtu < int.MaxValue ? $"Path MTU {minMtu} — critically low" : "MTU issues detected";
                result.RemediationUrl = "https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            else if (issues.Count > 0)
            {
                result.Status = "Warning";
                result.ResultValue = minMtu < int.MaxValue ? $"Path MTU {minMtu} — {issues.Count} issue(s)" : $"{issues.Count} MTU issue(s)";
                result.RemediationUrl = "https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = minMtu < int.MaxValue ? $"Path MTU ≥{minMtu} — OK" : "All targets OK";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>Send a single DF-bit ping with the given payload size. Returns true if reply received.</summary>
    static async Task<bool> TestPingPayload(Ping ping, IPAddress target, int payloadSize, PingOptions options)
    {
        try
        {
            var buffer = new byte[payloadSize];
            var reply = await ping.SendPingAsync(target, 2000, buffer, options);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    // ═══════════════════════════════════════════
    //  NIC DRIVER ANALYSIS
    // ═══════════════════════════════════════════

    /// <summary>Driver info read from the network adapter class registry key.</summary>
    record NicDriverInfo(string Description, string Provider, string Version, DateTime? Date);

    /// <summary>Network adapter class GUID — stable across all Windows versions.</summary>
    const string NetAdapterClassGuid = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    /// <summary>
    /// Reads NIC driver details from the registry class key.
    /// Returns description, provider, version, and date for every installed network adapter driver.
    /// </summary>
    static List<NicDriverInfo> ReadNicDriversFromRegistry()
    {
        var drivers = new List<NicDriverInfo>();
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(NetAdapterClassGuid);
            if (classKey == null) return drivers;

            foreach (var subKeyName in classKey.GetSubKeyNames())
            {
                // Subkeys are numbered "0000", "0001", etc. — skip "Properties"
                if (!int.TryParse(subKeyName, out _)) continue;

                try
                {
                    using var sub = classKey.OpenSubKey(subKeyName);
                    if (sub == null) continue;

                    var desc = sub.GetValue("DriverDesc") as string;
                    if (string.IsNullOrEmpty(desc)) continue;

                    var provider = sub.GetValue("ProviderName") as string ?? "unknown";
                    var version = sub.GetValue("DriverVersion") as string ?? "unknown";
                    var dateStr = sub.GetValue("DriverDate") as string;

                    DateTime? driverDate = null;
                    if (!string.IsNullOrEmpty(dateStr))
                    {
                        // Registry stores DriverDate as "M-D-YYYY" (US format)
                        if (DateTime.TryParseExact(dateStr,
                            new[] { "M-d-yyyy", "MM-dd-yyyy", "M/d/yyyy", "yyyy-MM-dd" },
                            System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.None, out var parsed))
                        {
                            driverDate = parsed;
                        }
                    }
                    drivers.Add(new NicDriverInfo(desc, provider, version, driverDate));
                }
                catch { /* Skip inaccessible subkey */ }
            }
        }
        catch { /* Registry access failed entirely */ }
        return drivers;
    }

    /// <summary>
    /// Known problematic NIC driver patterns. Each entry: (description substring, max safe version, issue description).
    /// Version comparison is done with <see cref="CompareDriverVersions"/>.
    /// </summary>
    static readonly (string descPattern, string? maxBadVersion, string issue)[] KnownDriverIssues =
    [
        // Realtek RTL8168/8111 — TCP checksum offload bugs cause packet corruption & retransmits
        ("RTL8168", "10.044",
            "Realtek RTL8168/8111 drivers before v10.045 have TCP checksum offload bugs that cause packet corruption. Update driver or disable 'TCP Checksum Offload' in adapter advanced settings"),

        ("RTL8111", "10.044",
            "Realtek RTL8111/8168 drivers before v10.045 have TCP checksum offload bugs that cause packet corruption. Update driver or disable 'TCP Checksum Offload' in adapter advanced settings"),

        // Intel I225-V — link drops under sustained load (fixed in later driver versions)
        ("I225-V", "1.0.2.17",
            "Intel I225-V early drivers have known link-drop issues under sustained load. Update to the latest Intel LAN driver"),

        // Intel I226-V — similar early-driver instability
        ("I226-V", "1.0.2.17",
            "Intel I226-V early drivers have known instability. Update to the latest Intel LAN driver"),

        // Killer Networking — Advanced Stream Detect can deprioritize RDP traffic
        ("Killer", null,
            "Intel Killer networking adapters use Advanced Stream Detect which can deprioritize RDP/UDP traffic. If experiencing poor session quality, disable 'Advanced Stream Detect' in Killer Control Center"),

        // Cisco AnyConnect — MTU issues with UDP can break RDP Shortpath
        ("Cisco AnyConnect", null,
            "Cisco AnyConnect virtual adapter can fragment UDP packets and interfere with RDP Shortpath. If UDP connectivity fails, check AnyConnect MTU settings"),
    ];

    /// <summary>
    /// Compares two dotted version strings numerically (e.g. "10.044" vs "10.045").
    /// Returns negative if a &lt; b, 0 if equal, positive if a &gt; b.
    /// </summary>
    static int CompareDriverVersions(string a, string b)
    {
        var pa = a.Split('.').Select(s => int.TryParse(s, out var v) ? v : 0).ToArray();
        var pb = b.Split('.').Select(s => int.TryParse(s, out var v) ? v : 0).ToArray();
        int len = Math.Max(pa.Length, pb.Length);
        for (int i = 0; i < len; i++)
        {
            int va = i < pa.Length ? pa[i] : 0;
            int vb = i < pb.Length ? pb[i] : 0;
            if (va != vb) return va.CompareTo(vb);
        }
        return 0;
    }

    /// <summary>
    /// Checks a driver against the known-issue database.
    /// Returns a warning string if matched, null otherwise.
    /// </summary>
    static string? CheckKnownDriverIssue(NicDriverInfo driver)
    {
        foreach (var (descPattern, maxBadVersion, issue) in KnownDriverIssues)
        {
            if (driver.Description.Contains(descPattern, StringComparison.OrdinalIgnoreCase))
            {
                // If a max-bad-version is specified, only warn if driver version is at or below it
                if (maxBadVersion != null && driver.Version != "unknown")
                {
                    if (CompareDriverVersions(driver.Version, maxBadVersion) > 0)
                        continue; // Driver is newer than the problematic range
                }
                return issue;
            }
        }
        return null;
    }

    /// <summary>
    /// L-LE-16: Analyzes NIC drivers for age and known issues that can impact RDP connectivity.
    /// </summary>
    static async Task<TestResult> RunNicDriverAnalysis()
    {
        await Task.CompletedTask; // Sync work only (registry reads)
        var result = new TestResult { Id = "L-LE-16", Name = "NIC Driver Analysis", Category = "local" };
        try
        {
            var sb = new StringBuilder();
            var activeAdapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                         && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToList();

            var driverInfos = ReadNicDriversFromRegistry();

            int analyzed = 0;
            int warnings = 0;

            foreach (var adapter in activeAdapters)
            {
                // Match active adapter to registry driver info by description.
                // Windows appends " #2", " #3" etc. to Description when multiple instances
                // of the same adapter exist, but the registry stores the base name only.
                var adapterDesc = System.Text.RegularExpressions.Regex.Replace(
                    adapter.Description, @"\s+#\d+$", "");
                var driverInfo = driverInfos.FirstOrDefault(d =>
                    string.Equals(d.Description, adapterDesc, StringComparison.OrdinalIgnoreCase));

                if (driverInfo == null) continue;
                analyzed++;

                sb.AppendLine($"═══ {adapter.Name} ═══");
                sb.AppendLine($"  Driver: {driverInfo.Description}");
                sb.AppendLine($"  Provider: {driverInfo.Provider}");
                sb.AppendLine($"  Version: {driverInfo.Version}");
                sb.AppendLine($"  Date: {driverInfo.Date?.ToString("yyyy-MM-dd") ?? "unknown"}");

                // Check driver age (informational only — old drivers are usually fine;
                // most NIC vendors release updates infrequently and Windows Update keeps
                // working drivers in place. Only surface as Info, never as a Warning,
                // unless paired with a known-issue match below.)
                if (driverInfo.Date.HasValue)
                {
                    var ageDays = (DateTime.Now - driverInfo.Date.Value).TotalDays;
                    if (ageDays > 730) // > 2 years
                    {
                        var years = ageDays / 365.25;
                        sb.AppendLine($"  ℹ Driver dates to {driverInfo.Date.Value:yyyy-MM} ({years:F1} years old). This is usually fine; if you experience instability, check the manufacturer's website for an update.");
                    }
                }

                // Check known problematic drivers — these are the only conditions that
                // should produce a Warning verdict for this test.
                var issue = CheckKnownDriverIssue(driverInfo);
                if (issue != null)
                {
                    sb.AppendLine($"  ⚠ Known issue: {issue}");
                    warnings++;
                }

                sb.AppendLine();
            }

            if (analyzed == 0)
            {
                result.Status = "Info";
                result.ResultValue = "No active adapters matched to registry driver records";
                result.DetailedInfo = "Could not read driver details from registry. This is non-critical.";
            }
            else
            {
                result.ResultValue = warnings == 0
                    ? $"{analyzed} driver(s) analyzed — no known issues"
                    : $"{analyzed} driver(s) analyzed — {warnings} warning(s)";
                result.DetailedInfo = sb.ToString().Trim();
                result.Status = warnings == 0 ? "Passed" : "Warning";
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
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
                            // Cache for all subsequent tests
                            _cachedGatewayHost = discoveredGateway;
                            _cachedGatewayDetail = "AFD Set-Cookie header (cached from L-TCP-04)";
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

                    // Region identification: prefer FQDN, supplement with Service Tags
                    var gwRegionCode = ExtractRegionFromGatewayFqdn(discoveredGateway);
                    var gwRegionName = gwRegionCode != null ? GetAzureRegionName(gwRegionCode) : null;
                    var gwFirstIp = gwIps.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gwFirstIp != null)
                    {
                        var stRegion = LookupGatewayRegion(gwFirstIp);
                        var stFriendly = stRegion != null ? (GetAzureRegionFriendlyName(stRegion) ?? stRegion) : null;
                        var displayRegion = gwRegionName ?? stFriendly;
                        if (displayRegion != null)
                            sb.AppendLine($"    → Gateway region (Service Tags): {displayRegion}");
                        if (gwRegionName != null && stFriendly != null && !string.Equals(gwRegionName, stFriendly, StringComparison.OrdinalIgnoreCase))
                            sb.AppendLine($"    → Note: FQDN says {gwRegionName}, Service Tags subnet says {stFriendly}");
                    }
                    else if (gwRegionName != null)
                    {
                        sb.AppendLine($"    → Gateway region: {gwRegionName}");
                    }

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

    // ── Microsoft-internal device gate ───────────────────────────────────────
    //  Decides whether THIS device is a Microsoft-internal machine so the
    //  self-host endpoint probe (L-TCP-11 / C-TCP-10) can never run for an
    //  external customer. This is the SOLE gate — the checks run automatically
    //  on internal devices. Two independent corroborating signals (either suffices):
    //    (a) the device is joined to a Microsoft corporate AD domain, OR
    //    (b) the device is Entra-joined to the Microsoft corporate tenant.
    static bool? _isMicrosoftInternalCache = null;
    static bool IsMicrosoftInternalDevice()
    {
        if (_isMicrosoftInternalCache.HasValue) return _isMicrosoftInternalCache.Value;
        bool internalDevice = false;

        // (a) Corporate AD domain join — e.g. redmond.corp.microsoft.com
        try
        {
            var domain = System.Net.NetworkInformation.IPGlobalProperties
                .GetIPGlobalProperties().DomainName ?? "";
            if (domain.EndsWith("corp.microsoft.com", StringComparison.OrdinalIgnoreCase)
                || domain.Equals("microsoft.com", StringComparison.OrdinalIgnoreCase))
                internalDevice = true;
        }
        catch { }

        // (b) Entra (AAD) join to the Microsoft corporate tenant
        if (!internalDevice)
        {
            try
            {
                const string MicrosoftTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47";
                using var joinInfo = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo");
                if (joinInfo != null)
                {
                    foreach (var subName in joinInfo.GetSubKeyNames())
                    {
                        using var sub = joinInfo.OpenSubKey(subName);
                        if (sub?.GetValue("TenantId") is string tid
                            && string.Equals(tid, MicrosoftTenantId, StringComparison.OrdinalIgnoreCase))
                        {
                            internalDevice = true;
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        _isMicrosoftInternalCache = internalDevice;
        return internalDevice;
    }

    // Extracts the CN from an X.509 distinguished name for readable output.
    static string ExtractCertCn(string dn)
    {
        if (string.IsNullOrEmpty(dn)) return "(unknown)";
        var m = System.Text.RegularExpressions.Regex.Match(dn, @"CN=([^,]+)");
        return m.Success ? m.Groups[1].Value.Trim() : dn;
    }

    // Heuristic TLS-inspection signal for self-host endpoints. Legitimate Microsoft
    // endpoint certificates are issued by Microsoft's own public CAs or well-known
    // public CAs. An issuer outside that set — or a chain the OS won't validate — is
    // the signature of an inline TLS-inspecting proxy/SWG (this catches an inspection
    // CA even when it has been installed into the machine trust store).
    static bool IsLikelyTlsInterception(string issuer, bool chainValid)
    {
        string[] trusted = { "Microsoft", "DigiCert", "Baltimore", "GlobalSign", "Entrust", "Amazon" };
        bool issuerTrusted = trusted.Any(t => (issuer ?? "").IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);
        return !issuerTrusted || !chainValid;
    }

    // ── L-TCP-11: Self-host (Microsoft-internal) endpoint connectivity ───────
    //  Probes the internal self-host/dogfood AVD/Cloud PC control-plane and
    //  gateway endpoints (the *.wvdselfhost.microsoft.com / deschutes-sh set
    //  the Windows App checks), which differ from the public *.wvd.microsoft.com
    //  endpoints. Only ever registered for Microsoft-internal devices, where it
    //  runs automatically (see GetAllTests + IsMicrosoftInternalDevice).
    static async Task<TestResult> RunSelfHostConnectivity()
    {
        var result = new TestResult { Id = "L-TCP-11", Name = "Self-Host Endpoint Connectivity (Internal)", Category = "tcp" };
        try
        {
            var endpoints = new (string host, int port, string role)[]
            {
                ("deschutes-sh.microsoft.com", 443, "Cloud PC control plane (Deschutes self-host)"),
                ("afdfp-rdgateway-r0.wvdselfhost.microsoft.com", 443, "RDP Gateway AFD (self-host r0)"),
                ("afdfp-rdgateway-r1.wvdselfhost.microsoft.com", 443, "RDP Gateway AFD (self-host r1)"),
            };

            var sb = new StringBuilder();
            sb.AppendLine("Microsoft-internal self-host (dogfood) endpoints — internal testers only.");
            sb.AppendLine("These are the self-host equivalents of the public *.wvd.microsoft.com control plane.");
            sb.AppendLine();

            int passed = 0;
            var issues = new List<string>();
            var intercepted = new List<string>();

            var capturedCerts = new System.Collections.Concurrent.ConcurrentDictionary<string, (string issuer, bool chainValid)>();
            using var httpHandler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (req, cert, _, errors) =>
                {
                    if (cert != null && req?.RequestUri != null)
                        capturedCerts[req.RequestUri.Host] = (cert.Issuer, errors == System.Net.Security.SslPolicyErrors.None);
                    return true; // measure reachability regardless of trust
                }
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            foreach (var (host, port, role) in endpoints)
            {
                sb.AppendLine($"  {host}:{port}  [{role}]");
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(host);
                    sb.AppendLine($"    ✓ DNS → {string.Join(", ", addrs.Select(a => a.ToString()))}");

                    var sw = Stopwatch.StartNew();
                    var resp = await http.GetAsync($"https://{host}/");
                    sw.Stop();
                    sb.AppendLine($"    ✓ HTTPS {(int)resp.StatusCode} in {sw.ElapsedMilliseconds}ms");
                    passed++;

                    if (capturedCerts.TryGetValue(host, out var ci))
                    {
                        sb.AppendLine($"    → Cert issuer: {ExtractCertCn(ci.issuer)}");
                        if (IsLikelyTlsInterception(ci.issuer, ci.chainValid))
                        {
                            sb.AppendLine("    ⚠ Issuer is not a recognized Microsoft/public CA — possible TLS inspection");
                            intercepted.Add(host);
                        }
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ {ex.GetType().Name}: {ex.Message}");
                    issues.Add($"{host}: {ex.Message}");
                }
                sb.AppendLine();
            }

            if (intercepted.Count > 0)
            {
                sb.AppendLine($"⚠ Possible TLS inspection on: {string.Join(", ", intercepted)}");
                sb.AppendLine("  An inline proxy/SWG presenting its own certificate can break self-host RDP.");
            }
            if (issues.Count > 0)
            {
                sb.AppendLine("Note: these self-host endpoints are publicly resolvable (deschutes-sh →");
                sb.AppendLine("public Microsoft IPs, the wvdselfhost AFD gateways → the same public anycast");
                sb.AppendLine("edge as production), so they are reachable from the open internet — not");
                sb.AppendLine("corpnet-only. A failure here points to a real block on this network (DNS");
                sb.AppendLine("filtering, firewall, or proxy/SWG) or the endpoint being temporarily down,");
                sb.AppendLine("not simply being off-corpnet.");
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.ResultValue = intercepted.Count > 0
                ? $"{passed}/{endpoints.Length} reachable — possible TLS inspection on {intercepted.Count}"
                : $"{passed}/{endpoints.Length} self-host endpoints reachable";
            result.Status = passed < endpoints.Length ? (passed > 0 ? "Warning" : "Failed")
                          : intercepted.Count > 0 ? "Warning"
                          : "Passed";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ── C-TCP-10: Self-host (Microsoft-internal) endpoint connectivity, Cloud PC side ──
    //  Same confirmed self-host endpoint set as the client test (L-TCP-11), but
    //  measured FROM the Cloud PC / session host. Surfaces a self-host control-plane
    //  or gateway block that the public *.wvd.microsoft.com tests cannot see. Only
    //  ever registered for opted-in Microsoft-internal Cloud PCs (see GetCloudPcTests).
    static async Task<TestResult> RunCpcSelfHostConnectivity()
    {
        var result = new TestResult { Id = "C-TCP-10", Name = "Self-Host Endpoint Connectivity (Cloud PC, Internal)", Category = "cloudpc-tcp" };
        try
        {
            var endpoints = new (string host, int port, string role)[]
            {
                ("deschutes-sh.microsoft.com", 443, "Cloud PC control plane (Deschutes self-host)"),
                ("afdfp-rdgateway-r0.wvdselfhost.microsoft.com", 443, "RDP Gateway AFD (self-host r0)"),
                ("afdfp-rdgateway-r1.wvdselfhost.microsoft.com", 443, "RDP Gateway AFD (self-host r1)"),
            };

            var sb = new StringBuilder();
            sb.AppendLine("Microsoft-internal self-host (dogfood) endpoints, probed from the Cloud PC.");
            sb.AppendLine("Surfaces a self-host control-plane/gateway block invisible to the public endpoint tests.");
            sb.AppendLine();

            int passed = 0;
            var issues = new List<string>();
            var intercepted = new List<string>();

            var capturedCerts = new System.Collections.Concurrent.ConcurrentDictionary<string, (string issuer, bool chainValid)>();
            using var httpHandler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (req, cert, _, errors) =>
                {
                    if (cert != null && req?.RequestUri != null)
                        capturedCerts[req.RequestUri.Host] = (cert.Issuer, errors == System.Net.Security.SslPolicyErrors.None);
                    return true; // measure reachability regardless of trust
                }
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(10), httpHandler);

            foreach (var (host, port, role) in endpoints)
            {
                sb.AppendLine($"  {host}:{port}  [{role}]");
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(host);
                    sb.AppendLine($"    ✓ DNS → {string.Join(", ", addrs.Select(a => a.ToString()))}");

                    var sw = Stopwatch.StartNew();
                    var resp = await http.GetAsync($"https://{host}/");
                    sw.Stop();
                    sb.AppendLine($"    ✓ HTTPS {(int)resp.StatusCode} in {sw.ElapsedMilliseconds}ms");
                    passed++;

                    if (capturedCerts.TryGetValue(host, out var ci))
                    {
                        sb.AppendLine($"    → Cert issuer: {ExtractCertCn(ci.issuer)}");
                        if (IsLikelyTlsInterception(ci.issuer, ci.chainValid))
                        {
                            sb.AppendLine("    ⚠ Issuer is not a recognized Microsoft/public CA — possible TLS inspection");
                            intercepted.Add(host);
                        }
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"    ✗ {ex.GetType().Name}: {ex.Message}");
                    issues.Add($"{host}: {ex.Message}");
                }
                sb.AppendLine();
            }

            if (intercepted.Count > 0)
            {
                sb.AppendLine($"⚠ Possible TLS inspection on: {string.Join(", ", intercepted)}");
                sb.AppendLine("  An inline proxy/SWG presenting its own certificate can break self-host RDP.");
            }

            result.DetailedInfo = sb.ToString().Trim();
            result.ResultValue = intercepted.Count > 0
                ? $"{passed}/{endpoints.Length} reachable — possible TLS inspection on {intercepted.Count}"
                : $"{passed}/{endpoints.Length} self-host endpoints reachable from Cloud PC";
            result.Status = passed < endpoints.Length ? (passed > 0 ? "Warning" : "Failed")
                          : intercepted.Count > 0 ? "Warning"
                          : "Passed";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    static async Task<TestResult> RunDnsPerformance()
    {
        var result = new TestResult { Id = "L-TCP-03", Name = "DNS Resolution Performance", Category = "tcp" };
        try
        {
            var hosts = new[]
            {
                "rdweb.wvd.microsoft.com",
                "login.microsoftonline.com",
                "client.wvd.microsoft.com",
                "world.relay.avd.microsoft.com",
                "afdfp-rdgateway-r1.wvd.microsoft.com",
            };

            var sb = new StringBuilder();
            sb.AppendLine("Pure DNS resolution timing using Dns.GetHostAddressesAsync()");
            sb.AppendLine("(no TCP/TLS overhead — raw resolver round-trip only)");
            sb.AppendLine();

            var timings = new List<long>();

            foreach (var host in hosts)
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(host);
                    sw.Stop();
                    var ms = sw.ElapsedMilliseconds;
                    timings.Add(ms);
                    var firstIp = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? "no IPv4";
                    sb.AppendLine($"  {ms,6}ms  {host} → {firstIp}");
                }
                catch (Exception ex)
                {
                    sw.Stop();
                    sb.AppendLine($"  {"ERR",6}     {host} — {ex.Message}");
                }
            }

            sb.AppendLine();

            if (timings.Count == 0)
            {
                result.Status = "Failed";
                result.ResultValue = "DNS resolution failed for all endpoints";
                result.DetailedInfo = sb.ToString().Trim();
                return result;
            }

            var avg = (long)timings.Average();
            var max = timings.Max();
            sb.AppendLine($"Average: {avg}ms  |  Slowest: {max}ms  |  Resolved: {timings.Count}/{hosts.Length}");

            if (timings.Count < hosts.Length)
                sb.AppendLine($"⚠ {hosts.Length - timings.Count} host(s) failed to resolve — check DNS server availability.");

            result.ResultValue = $"Avg {avg}ms DNS ({timings.Count}/{hosts.Length} resolved)";
            result.DetailedInfo = sb.ToString().Trim();
            result.Status = avg > 1000 ? "Failed" : avg > 500 ? "Warning" : "Passed";

            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#dns-requirements";
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
                var (afdChain, afdGsa) = await ResolveDnsCnameChainAsync(afdHost);

                var ips = await Dns.GetHostAddressesAsync(afdHost);
                var ipStr = string.Join(", ", ips.Select(i => i.ToString()));
                sb.AppendLine($"Resolved IPs: {ipStr}");

                if (afdChain.Count > 0)
                {
                    sb.AppendLine("CNAME chain:");
                    string prev = afdHost;
                    foreach (var cname in afdChain)
                    {
                        sb.AppendLine($"  {prev}");
                        sb.AppendLine($"    → {cname}");
                        prev = cname;
                    }
                }
                else
                {
                    sb.AppendLine("CNAME chain: (direct A record — no CNAMEs)");
                }

                if (afdGsa != null)
                {
                    sb.AppendLine($"\n⚠ Routing: {afdGsa}");
                    issues.Add($"AFD CNAME chain routed via {afdGsa}");
                }

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
            var (gwHost, gwDiscoveryMethod) = await DiscoverRdpGatewayFromAfd();
            if (!string.IsNullOrEmpty(gwHost))
            {
                sb.AppendLine($"Target: {gwHost}");
                sb.AppendLine($"Discovery: {gwDiscoveryMethod}");
                try
                {
                    var (gwChain, gwGsa) = await ResolveDnsCnameChainAsync(gwHost);

                    var gwIps = await Dns.GetHostAddressesAsync(gwHost);
                    var gwIpStr = string.Join(", ", gwIps.Select(i => i.ToString()));
                    sb.AppendLine($"Resolved IPs: {gwIpStr}");

                    if (gwChain.Count > 0)
                    {
                        sb.AppendLine("CNAME chain:");
                        string prev = gwHost;
                        foreach (var cname in gwChain)
                        {
                            sb.AppendLine($"  {prev}");
                            sb.AppendLine($"    → {cname}");
                            prev = cname;
                        }
                    }
                    else
                    {
                        sb.AppendLine("CNAME chain: (direct A record — no CNAMEs)");
                    }

                    if (gwGsa != null)
                    {
                        sb.AppendLine($"\n⚠ Routing: {gwGsa}");
                        issues.Add($"Gateway CNAME chain routed via {gwGsa}");
                    }

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
                sb.AppendLine($"  Could not discover RDP gateway from AFD");
                if (!string.IsNullOrEmpty(gwDiscoveryMethod))
                    sb.AppendLine($"  Reason: {gwDiscoveryMethod}");
                sb.AppendLine($"  Note: Gateway discovery requires a reachable AFD endpoint.");
                sb.AppendLine($"  A proxy, firewall, or GSA may prevent cookie-based discovery.");
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

    /// <summary>
    /// Known root CA thumbprints used by Microsoft Azure TLS certificates.
    /// If the chain terminates at a root NOT in this set, TLS inspection is occurring.
    /// </summary>
    static readonly HashSet<string> KnownMicrosoftRootCaThumbprints = new(StringComparer.OrdinalIgnoreCase)
    {
        // DigiCert Global Root G2
        "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
        // DigiCert Global Root CA
        "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",
        // Baltimore CyberTrust Root
        "D4DE20D05E66FC53FE1A50882C78DB2852CAE474",
        // Microsoft RSA Root Certificate Authority 2017
        "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",
        // Microsoft ECC Root Certificate Authority 2017
        "999A64C37FF47D9FAB95F14769891460EEC4C3C5",
        // DigiCert Global Root G3
        "7E04DE896A3E666D00E687D33FFAD93BE83D349E",
        // Microsoft Azure RSA TLS Issuing CA 03 (intermediate, but commonly the deepest visible)
        // kept as fallback — if the root matches we skip intermediate checks
    };

    static async Task<TestResult> RunTlsInspection()
    {
        var result = new TestResult { Id = "L-TCP-06", Name = "TLS Inspection Detection", Category = "tcp" };
        try
        {
            var sb = new StringBuilder();
            bool intercepted = false;
            string? interceptReason = null;

            // Discover the actual RDP gateway — this is the critical connection that must NOT be TLS-inspected
            var (gwHost, _) = await DiscoverRdpGatewayFromAfd();
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

            X509Certificate2? leafCert = null;
            using var ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
            {
                if (cert is X509Certificate2 x509)
                {
                    leafCert = new X509Certificate2(x509); // clone to use after callback

                    sb.AppendLine($"Subject: {x509.Subject}");
                    sb.AppendLine($"Issuer: {x509.Issuer}");
                    sb.AppendLine($"Thumbprint: {x509.Thumbprint}");
                    sb.AppendLine($"Valid: {x509.NotBefore:d} - {x509.NotAfter:d}");
                    sb.AppendLine($"Policy Errors: {errors}");
                }
                return true; // Accept anyway for inspection
            });

            using var tlsCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, tlsCts.Token);
            sb.Insert(0, $"Host: {host}:{port}\n\n");

            // Build and validate the certificate chain
            if (leafCert != null)
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags; // We're inspecting, not enforcing
                chain.Build(leafCert);

                // Show the full chain for diagnostics
                sb.AppendLine($"\nCertificate chain ({chain.ChainElements.Count} elements):");
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var el = chain.ChainElements[i].Certificate;
                    var selfSigned = el.Subject == el.Issuer;
                    sb.AppendLine($"  [{i}] {el.Subject}{(selfSigned ? " [ROOT]" : "")}");
                    sb.AppendLine($"       Thumbprint: {el.Thumbprint}");
                }

                // Check 1: Does the chain root match a known Microsoft/DigiCert root CA?
                var rootCert = chain.ChainElements[^1].Certificate;
                bool rootTrusted = KnownMicrosoftRootCaThumbprints.Contains(rootCert.Thumbprint);

                // Check 2: Private Link certs are legitimate non-standard chains
                bool isPrivateLink = leafCert.Subject.Contains("privatelink", StringComparison.OrdinalIgnoreCase);

                if (!rootTrusted && !isPrivateLink)
                {
                    intercepted = true;
                    interceptReason = rootCert.Subject == rootCert.Issuer
                        ? $"Root CA '{rootCert.Subject}' (thumbprint {rootCert.Thumbprint}) is not a known Microsoft/DigiCert CA"
                        : $"Chain does not terminate at a trusted root — leaf issuer: {leafCert.Issuer}";
                    sb.AppendLine($"\n⚠ {interceptReason}");
                    sb.AppendLine("This indicates TLS inspection by a proxy, firewall, SWG, or network emulator.");
                    sb.AppendLine("W365 RDP gateway connections MUST NOT be TLS-inspected.");
                }
                else if (isPrivateLink)
                {
                    sb.AppendLine("\nℹ Private Link certificate detected — this is a legitimate non-standard chain.");
                }

                leafCert.Dispose();
            }

            result.ResultValue = intercepted
                ? $"TLS inspection detected — {interceptReason}"
                : $"None — certificates direct from Microsoft";
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
        // 40.64.144.0/20 — RDP Gateway (use Service Tags for region)
        if (b[0] == 40 && b[1] == 64 && b[2] >= 144 && b[2] <= 159)
        {
            var region = LookupGatewayRegion(ip);
            if (region != null)
            {
                var friendly = GetAzureRegionFriendlyName(region);
                return friendly != null ? $"[RDP Gateway — {friendly}]" : $"[RDP Gateway — {region}]";
            }
            return "[RDP Gateway range]";
        }
        // 40.64.0.0/10 — Azure / Microsoft
        if (b[0] == 40 && (b[1] & 0xC0) == 64) return "[Azure]";
        // 20.33.0.0/16 and similar — Azure networking
        if (b[0] == 20) return "[Azure]";
        // 13.64.0.0/11 — Azure
        if (b[0] == 13 && (b[1] & 0xE0) == 64) return "[Azure]";
        // 52.96.0.0/12 — Microsoft 365
        if (b[0] == 52 && b[1] >= 96 && b[1] <= 111) return "[Microsoft 365]";
        // 51.5.0.0/16 — AVD TURN relay (use Service Tags for region)
        if (b[0] == 51 && b[1] == 5)
        {
            var region = LookupTurnRelayRegion(ip);
            if (region != null)
            {
                var friendly = GetAzureRegionFriendlyName(region);
                return friendly != null ? $"[AVD TURN relay — {friendly}]" : $"[AVD TURN relay — {region}]";
            }
            return "[AVD TURN relay range]";
        }
        // 150.171.0.0/16 — Microsoft backbone
        if (b[0] == 150 && b[1] == 171) return "[Microsoft backbone]";
        // 4.0.0.0/8 parts — Microsoft (Level3/Microsoft)
        if (b[0] == 4 && b[1] >= 150) return "[Microsoft]";

        return "";
    }

    /// <summary>
    /// Resolves DNS CNAME chain for a hostname using .NET DNS APIs, returning the chain and routing flags.
    /// Uses Dns.GetHostEntryAsync to walk the CNAME chain without spawning external processes.
    /// </summary>
    static async Task<(List<string> chain, string? gsaIndicator)> ResolveDnsCnameChainAsync(string host)
    {
        var chain = new List<string>();
        string? gsaIndicator = null;

        try
        {
            // Walk the CNAME chain using .NET DNS — each GetHostEntryAsync returns
            // the canonical name, so we iterate until it stops changing.
            var current = host;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };

            for (int i = 0; i < 10; i++) // max 10 hops
            {
                using var cts = new CancellationTokenSource(3000);
                try
                {
                    var entry = await Dns.GetHostEntryAsync(current, cts.Token);
                    if (!string.IsNullOrEmpty(entry.HostName) &&
                        !entry.HostName.Equals(current, StringComparison.OrdinalIgnoreCase) &&
                        !seen.Contains(entry.HostName))
                    {
                        var cname = entry.HostName.TrimEnd('.');
                        chain.Add(cname);
                        seen.Add(cname);
                        current = cname;
                    }
                    else
                    {
                        break;
                    }
                }
                catch { break; }
            }
        }
        catch { /* DNS resolution not available */ }

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
            var (gwHost, _) = await DiscoverRdpGatewayFromAfd();
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
                if (!_traceConsoleSilent) Console.Write($"\n        Tracing {role}... ");
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
                        if (!_traceConsoleSilent) Console.Write("✗");
                        continue;
                    }
                    sb.AppendLine($"║  Resolved:   {targetIp}");
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"║  ✗ DNS failed: {ex.Message}");
                    sb.AppendLine($"╚══════════════════════════════════════════════════════════════");
                    sb.AppendLine();
                    if (!_traceConsoleSilent) Console.Write("✗");
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
                if (!_traceConsoleSilent) Console.Write(reached ? "✓" : "✗");
            }

            if (completed == 0)
            {
                result.ResultValue = $"0/{targets.Count} endpoints traced — ICMP blocked on network (informational only)";
            }
            else
            {
                result.ResultValue = $"{completed}/{targets.Count} endpoints traced successfully";
            }
            result.DetailedInfo = sb.ToString().Trim();
            // Traceroute is purely informational — ICMP blocking is extremely common on
            // corporate networks and does not indicate any connectivity issue.
            result.Status = "Passed";
        }
        catch (Exception ex) { result.Status = "Passed"; result.ResultValue = $"Traceroute unavailable: {ex.Message}"; }
        return result;
    }

    /// <summary>
    /// Inspects RDP-client-specific proxy settings — distinct from the
    /// system/WinINET proxy because MSRDC / Windows App / mstsc each honour
    /// their own overrides. Returns human-readable lines for the test
    /// detailedInfo; lines prefixed "⚠" represent active overrides.
    /// </summary>
    static List<string> InspectRdpClientProxyConfig()
    {
        var lines = new List<string>();

        // 1. Remote Desktop Connection (mstsc) — HKCU Terminal Server Client
        //    RDGClientTransport=1 forces HTTP/TS Gateway; ProxySettings blob
        //    contains any per-connection proxy overrides for RDS sessions.
        try
        {
            using var tsc = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Terminal Server Client");
            if (tsc != null)
            {
                var transport = tsc.GetValue("RDGClientTransport");
                if (transport is int t)
                {
                    var desc = t switch
                    {
                        0 => "Auto (HTTP fallback if UDP fails)",
                        1 => "HTTP only (via RD Gateway)",
                        _ => $"unknown ({t})"
                    };
                    lines.Add($"mstsc RDGClientTransport: {desc}");
                    if (t == 1) lines.Add("⚠ mstsc forced to HTTP-only — UDP shortpath disabled");
                }
            }
        }
        catch { /* best-effort */ }

        // 2. Windows App / AVD store client — stores proxy under Packages
        //    (Microsoft.Windows365 / Microsoft.RemoteDesktop). The packaged
        //    app config is per-user; if any pack has ProxyUrl or UseProxy set
        //    it overrides the system proxy for RDP sessions from that client.
        try
        {
            var pkgRoots = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\CloudPC",
                @"Software\Microsoft\RdClientRadc",
                @"Software\Microsoft\Terminal Server Client\RdpFileMru"
            };
            foreach (var root in pkgRoots)
            {
                using var k = Registry.CurrentUser.OpenSubKey(root);
                if (k == null) continue;
                foreach (var name in new[] { "ProxyUrl", "ProxyServer", "UseProxy", "HttpProxy" })
                {
                    var v = k.GetValue(name);
                    if (v != null && !string.IsNullOrWhiteSpace(v.ToString()))
                        lines.Add($"⚠ {root}\\{name}={v}");
                }
            }
        }
        catch { /* best-effort */ }

        // 3. Global machine-wide RDP policy — HKLM\SOFTWARE\Policies\Microsoft\
        //    Windows NT\Terminal Services holds admin-deployed proxy overrides.
        try
        {
            using var pol = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services");
            if (pol != null)
            {
                foreach (var name in new[] { "fUseProxy", "ProxyName", "ProxyType" })
                {
                    var v = pol.GetValue(name);
                    if (v != null) lines.Add($"⚠ Policy: {name}={v}");
                }
            }
        }
        catch { /* best-effort */ }

        if (lines.Count == 0)
            lines.Add("✓ No RDP-client-specific proxy overrides found");

        return lines;
    }

    /// <summary>
    /// Opens an actual TCP connection to the proxy and sends an HTTP CONNECT
    /// request for host:port. Returns whether the proxy accepted the tunnel.
    /// This is the only way to know a declared proxy can actually reach the
    /// RDP gateway — firewalls and ACLs frequently block specific destinations.
    /// </summary>
    static async Task<(bool Ok, string Message)> ProbeProxyConnectAsync(
        Uri proxy, string targetHost, int targetPort, TimeSpan timeout)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeout);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(proxy.Host, proxy.Port, cts.Token);
            var stream = tcp.GetStream();
            var req = $"CONNECT {targetHost}:{targetPort} HTTP/1.1\r\n" +
                      $"Host: {targetHost}:{targetPort}\r\n" +
                      $"User-Agent: W365LocalScanner\r\n\r\n";
            var bytes = Encoding.ASCII.GetBytes(req);
            await stream.WriteAsync(bytes, cts.Token);

            // Read status line + headers (up to 4 KB)
            var buf = new byte[4096];
            int read = await stream.ReadAsync(buf, cts.Token);
            if (read <= 0) return (false, "✗ Proxy closed connection without responding");
            var resp = Encoding.ASCII.GetString(buf, 0, read);
            var firstLine = resp.Split('\n')[0].Trim();

            // HTTP/1.1 200 Connection Established = success (any 2xx technically)
            if (System.Text.RegularExpressions.Regex.IsMatch(firstLine, @"^HTTP/1\.[01]\s+2\d\d"))
                return (true, $"✓ Proxy CONNECT accepted → {targetHost}:{targetPort} ({firstLine})");
            return (false, $"✗ Proxy rejected CONNECT: {firstLine}");
        }
        catch (OperationCanceledException)
        {
            return (false, $"✗ Proxy CONNECT to {targetHost}:{targetPort} timed out after {timeout.TotalSeconds:0}s");
        }
        catch (Exception ex)
        {
            return (false, $"✗ Proxy CONNECT failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ── Network-stack agents (VPN / SWG / proxy / endpoint-security) ──
    // Components that insert themselves into the host networking path (WFP callout
    // drivers, NDIS filters, LSPs, per-user UDP source-port assignment). Their
    // PRESENCE is reported as a neutral inventory ONLY — it is never treated as a
    // fault and never judged against a version. They are listed because they CAN
    // affect the in-session RDP Shortpath UDP socket independently of routing or
    // reachability — the blind spot where TURN/UDP reachability probes pass green
    // yet the live session quietly falls back to TCP. If a user has Shortpath/UDP
    // problems, these are the first components to update with the vendor or rule
    // out. (Process names are best-effort; an unmatched name simply isn't listed.)
    //
    // Some agents are pure filter/kernel drivers with NO persistent user-mode
    // process to match — most notably the Palo Alto Terminal Server (TS) Agent,
    // which loads its driver at boot and rewrites per-user UDP source ports
    // (breaking RDP Shortpath) yet is "not technically a network-stack
    // application" and so was invisible to a process-only scan. For those,
    // detect INSTALLATION via the Uninstall registry (DisplayName + Publisher):
    // the driver sits in the path from boot regardless of any running process.
    //
    // proc      = running process image name (empty = no user process to match;
    //             rely on installed-product detection instead).
    // label     = display label.
    // uninstall = substring matching the product's Uninstall-key DisplayName —
    //             used both to recover a version when the running binary's file
    //             version is unreadable (SYSTEM/session-0 services) AND, for
    //             driverAgent entries, to detect the installed product itself.
    // publisher = optional Uninstall Publisher substring, to disambiguate a
    //             generic DisplayName (e.g. "Terminal Server Agent").
    // driverAgent = true when the component is a filter/kernel driver that is in
    //             the network stack whenever INSTALLED (even with no running
    //             process); such entries are inventoried on installation.
    static readonly (string proc, string label, string uninstall, string publisher, bool driverAgent)[] _networkStackAgents =
    {
        // VPN clients
        ("PanGPS",                    "Palo Alto GlobalProtect",           "GlobalProtect",       "",           false),
        ("vpnagent",                  "Cisco AnyConnect / Secure Client",  "AnyConnect",          "",           false),
        ("acwebsecagent",             "Cisco AnyConnect Web Security",     "Web Security",        "",           false),
        ("FortiSSLVPNdaemon",         "FortiClient SSL VPN",               "FortiClient",         "",           false),
        ("FortiClient",               "FortiClient",                       "FortiClient",         "",           false),
        ("openvpn",                   "OpenVPN",                           "OpenVPN",             "",           false),
        ("wireguard",                 "WireGuard",                         "WireGuard",           "",           false),
        ("tailscaled",                "Tailscale",                         "Tailscale",           "",           false),
        // SWG / proxy / secure-access agents
        ("ZscalerService",            "Zscaler",                           "Zscaler",             "",           false),
        ("ZSATunnel",                 "Zscaler Tunnel",                    "Zscaler",             "",           false),
        ("stAgentSvc",                "Netskope",                          "Netskope",            "",           false),
        ("warp-svc",                  "Cloudflare WARP",                   "Cloudflare WARP",     "",           false),
        ("acumbrellaagent",           "Cisco Umbrella",                    "Umbrella",            "",           false),
        ("iboss",                     "iboss",                             "iboss",               "",           false),
        ("FA_Scheduler",              "Forcepoint",                        "Forcepoint",          "",           false),
        ("GlobalSecureAccessClient",  "Microsoft Global Secure Access",    "Global Secure Access","",           false),
        // Endpoint security with network filtering
        ("CSFalconService",           "CrowdStrike Falcon",                "CrowdStrike",         "",           false),
        ("SentinelAgent",             "SentinelOne",                       "Sentinel",            "",           false),
        // Filter/kernel-driver agents — detected when INSTALLED (no user process)
        ("",                          "Palo Alto Terminal Server Agent",   "Terminal Server Agent","Palo Alto", true),
    };

    /// <summary>Best-effort version of a running agent: the running binary's file
    /// version first (most accurate), falling back to the installed product's
    /// Uninstall registry DisplayVersion. Returns null if neither is readable
    /// (e.g. the service runs cross-session and we lack rights to its module).</summary>
    static string? TryGetAgentVersion(Process proc, string uninstallKeyword)
    {
        try
        {
            var fv = proc.MainModule?.FileVersionInfo;
            var v = fv?.FileVersion ?? fv?.ProductVersion;
            if (!string.IsNullOrWhiteSpace(v)) return v.Trim();
        }
        catch { /* Win32Exception (access denied) for elevated/cross-session services — fall through */ }

        if (!string.IsNullOrEmpty(uninstallKeyword))
        {
            foreach (var root in new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            })
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(root);
                    if (key == null) continue;
                    foreach (var sub in key.GetSubKeyNames())
                    {
                        using var k = key.OpenSubKey(sub);
                        if (k?.GetValue("DisplayName") is string name &&
                            name.Contains(uninstallKeyword, StringComparison.OrdinalIgnoreCase) &&
                            k.GetValue("DisplayVersion") is string dv &&
                            !string.IsNullOrWhiteSpace(dv))
                            return dv.Trim();
                    }
                }
                catch { }
            }
        }
        return null;
    }

    /// <summary>Finds an installed product in the Uninstall registry by DisplayName
    /// substring (plus an optional Publisher substring to disambiguate a generic
    /// name such as "Terminal Server Agent"). Returns the matched DisplayName,
    /// DisplayVersion (or null) and Publisher (or null) of the first match, else
    /// null. Used to inventory filter/kernel-driver agents that sit in the network
    /// stack from boot and therefore have no matching user-mode process to detect
    /// (e.g. the Palo Alto Terminal Server Agent).</summary>
    static (string displayName, string? version, string? publisher)? FindInstalledAgent(string displayNameKeyword, string publisherKeyword)
    {
        foreach (var root in new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(root);
                if (key == null) continue;
                foreach (var sub in key.GetSubKeyNames())
                {
                    using var k = key.OpenSubKey(sub);
                    if (k?.GetValue("DisplayName") is not string name) continue;
                    if (!name.Contains(displayNameKeyword, StringComparison.OrdinalIgnoreCase)) continue;
                    var publisher = k.GetValue("Publisher") as string;
                    if (!string.IsNullOrEmpty(publisherKeyword) &&
                        (publisher == null || !publisher.Contains(publisherKeyword, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    var version = k.GetValue("DisplayVersion") as string;
                    return (name, string.IsNullOrWhiteSpace(version) ? null : version.Trim(), publisher);
                }
            }
            catch { }
        }
        return null;
    }
    // Words stripped when computing a component's de-dup key, so the same product
    // detected via different signals (running process label vs installed DisplayName
    // vs NDIS binding DisplayName) collapses to one entry — e.g. "Microsoft Global
    // Secure Access" (process) and "Global Secure Access Client" (binding) both key
    // to "globalsecureaccess".
    static readonly HashSet<string> _agentNoiseWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft","inc","incorporated","corp","corporation","ltd","llc","co",
        "client","driver","service","svc","agent","networks","network","the","for",
    };

    /// <summary>Normalises a product/component name to a vendor key for de-duplication:
    /// lower-cased, punctuation removed, generic noise words dropped.</summary>
    static string NormAgentKey(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var tokens = Regex.Split(s.ToLowerInvariant(), @"[^a-z0-9]+")
            .Where(t => t.Length > 0 && !_agentNoiseWords.Contains(t));
        return string.Concat(tokens);
    }

    /// <summary>Holistic, vendor-AGNOSTIC view of what is actually bound into the
    /// network stack: enumerates enabled NDIS bindings via WMI
    /// (ROOT\StandardCimv2 : MSFT_NetAdapterBindingSettingData — the class behind
    /// Get-NetAdapterBinding, readable without elevation). Microsoft inbox
    /// primitives use the "ms_" ComponentID prefix (ms_tcpip, ms_pacer, ms_server,
    /// …) and are excluded, leaving third-party LWF/protocol drivers (VPN adapters,
    /// SWG/inspection filters, packet drivers) that we would otherwise need a
    /// per-product entry to know about. Returns distinct (componentId, displayName).
    /// Best-effort: returns empty if WMI is unavailable.</summary>
    static List<(string componentId, string displayName)> EnumerateNdisBoundComponents()
    {
        var list = new List<(string, string)>();
        try
        {
            var scope = new ManagementScope(@"\\.\ROOT\StandardCimv2");
            scope.Connect();
            var query = new ObjectQuery(
                "SELECT ComponentID, DisplayName, Enabled FROM MSFT_NetAdapterBindingSettingData");
            using var searcher = new ManagementObjectSearcher(scope, query);
            using var results = searcher.Get();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementBaseObject mo in results)
            {
                try
                {
                    if (mo["Enabled"] is bool enabled && !enabled) continue;
                    var cid = mo["ComponentID"] as string ?? "";
                    if (string.IsNullOrEmpty(cid)) continue;
                    if (cid.StartsWith("ms_", StringComparison.OrdinalIgnoreCase)) continue; // Microsoft inbox
                    if (!seen.Add(cid)) continue;
                    var dn = mo["DisplayName"] as string ?? cid;
                    list.Add((cid, dn));
                }
                finally { mo.Dispose(); }
            }
        }
        catch { /* WMI unavailable / class missing — holistic binding sweep skipped */ }
        return list;
    }

    /// <summary>Neutral inventory of network-stack components (VPN / SWG / proxy /
    /// endpoint-security) that can sit in the host networking path and affect RDP
    /// Shortpath UDP. PRESENCE IS NOT A FAULT and no version is judged — the row
    /// always passes and exists purely so that, if Shortpath/UDP is degraded, the
    /// user can see exactly which inline components are candidates to update or rule
    /// out (the blind spot where reachability probes pass yet the session falls
    /// back to TCP).</summary>
    static TestResult BuildNetworkStackAgents(string id, string name, string category)
    {
        var result = new TestResult { Id = id, Name = name, Category = category };
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Inventory of VPN / SWG / proxy / endpoint-security components that sit in the");
            sb.AppendLine("host network stack (WFP callouts, NDIS filters, LSPs, per-user UDP port");
            sb.AppendLine("assignment). These CAN affect RDP Shortpath UDP independently of routing or");
            sb.AppendLine("reachability — the case where UDP/TURN reachability probes pass yet the live");
            sb.AppendLine("session falls back to TCP.");
            sb.AppendLine();
            sb.AppendLine("Presence is informational only: it is NOT a fault and no version is judged.");
            sb.AppendLine("Detection is holistic — it combines three signals so a component is caught");
            sb.AppendLine("regardless of how it inserts itself:");
            sb.AppendLine("  1. running user-mode agents (known VPN/SWG/security processes);");
            sb.AppendLine("  2. installed filter/kernel-driver products with no user process");
            sb.AppendLine("     (e.g. the Palo Alto Terminal Server Agent, detected via the");
            sb.AppendLine("     Uninstall registry — it is in the stack from boot yet runs no app);");
            sb.AppendLine("  3. every non-Microsoft component actually BOUND to a network adapter");
            sb.AppendLine("     (NDIS bindings via WMI) — a vendor-agnostic sweep that surfaces");
            sb.AppendLine("     similar products we have no explicit entry for.");
            sb.AppendLine("If this tool reports no issues yet network problems persist, check these");
            sb.AppendLine("components for updates — or temporarily remove them — to test whether the");
            sb.AppendLine("network issues still occur without them in the stack.");
            sb.AppendLine();

            // Merge the three signals, de-duplicated by vendor key so a component
            // seen via more than one signal is listed once (running > installed >
            // bound, by first-write order below).
            var found = new List<string>();
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Register(string label, string evidence, string dedupSource)
            {
                var key = NormAgentKey(dedupSource);
                if (key.Length == 0 || !seenKeys.Add(key)) return;
                found.Add(label);
                sb.AppendLine($"  • {label}  [{evidence}]");
            }

            // (1) + (2): known agents — running process first, else installed driver.
            foreach (var agent in _networkStackAgents)
            {
                Process[] procs = Array.Empty<Process>();
                if (!string.IsNullOrEmpty(agent.proc))
                {
                    try { procs = Process.GetProcessesByName(agent.proc); }
                    catch { procs = Array.Empty<Process>(); }
                }
                if (procs.Length > 0)
                {
                    var verStr = TryGetAgentVersion(procs[0], agent.uninstall);
                    var label = verStr != null ? $"{agent.label} (v{verStr})" : agent.label;
                    Register(label, $"running — process {agent.proc}, PID {procs[0].Id}", agent.label);
                    continue;
                }
                // Filter/kernel-driver agents: detect via the INSTALLED product even
                // when no user process matches. The driver sits in the network stack
                // from boot regardless of any UI/service process — this is the case
                // that made the Palo Alto Terminal Server Agent invisible to a
                // process-only scan (a driver, "not technically a network-stack
                // application", that still rewrites per-user UDP source ports).
                if (agent.driverAgent && !string.IsNullOrEmpty(agent.uninstall))
                {
                    var inst = FindInstalledAgent(agent.uninstall, agent.publisher);
                    if (inst != null)
                    {
                        var label = inst.Value.version != null ? $"{agent.label} (v{inst.Value.version})" : agent.label;
                        var pub = string.IsNullOrEmpty(inst.Value.publisher) ? "" : $" by {inst.Value.publisher}";
                        Register(label, $"installed — \"{inst.Value.displayName}\"{pub}; filter/kernel driver, in the stack even with no running process", agent.label);
                    }
                }
            }

            // (3): holistic NDIS binding sweep — any non-Microsoft-inbox component
            // bound to a network adapter, whether or not we have an entry for it.
            foreach (var (componentId, displayName) in EnumerateNdisBoundComponents())
            {
                var label = string.IsNullOrWhiteSpace(displayName) ? componentId : displayName;
                Register(label, $"NDIS-bound network component (ComponentID {componentId})", label);
            }

            if (found.Count == 0)
            {
                sb.AppendLine("  ✓ None detected.");
                result.ResultValue = "No inline network-stack components detected";
            }
            else
            {
                result.ResultValue = found.Count == 1
                    ? $"1 network-stack component present ({found[0]})"
                    : $"{found.Count} network-stack components present";
            }
            result.Status = "Info";
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex)
        {
            result.Status = "Info";
            result.ResultValue = $"Agent inventory unavailable: {ex.Message}";
        }
        return result;
    }

    static Task<TestResult> RunNetworkStackAgents()
        => Task.FromResult(BuildNetworkStackAgents("L-LE-17", "Network Stack Agents", "local"));

    static Task<TestResult> RunCpcNetworkStackAgents()
        => Task.FromResult(BuildNetworkStackAgents("C-LE-05", "Network Stack Agents (Cloud PC)", "cloudpc-env"));

    static async Task<TestResult> RunProxyVpnDetection()
    {
        var result = new TestResult { Id = "L-TCP-07", Name = "Proxy / VPN / SWG Detection", Category = "tcp" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();     // Confirmed to intercept RDP traffic
            var detected = new List<string>();   // Present on system but RDP bypasses them

            // Discover the actual RDP gateway for accurate probing
            var (gwHost, _) = await DiscoverRdpGatewayFromAfd();
            var probeHost = gwHost ?? "rdweb.wvd.microsoft.com";
            if (gwHost != null)
                sb.AppendLine($"Probing discovered RDP gateway: {gwHost}\n");
            else
                sb.AppendLine("⚠ Could not discover RDP gateway — probing rdweb.wvd.microsoft.com as fallback\n");

            // System proxy — check against the actual RDP gateway
            // Wrapped in Task.Run with timeout because GetProxy() can trigger slow WPAD
            // auto-discovery through VPN tunnels (e.g. resolving wpad.corp.microsoft.com)
            var testUri = new Uri($"https://{probeHost}");
            try
            {
                var proxyCheckTask = Task.Run(() =>
                {
                    var p = WebRequest.GetSystemWebProxy();
                    return p.GetProxy(testUri);
                });
                if (await Task.WhenAny(proxyCheckTask, Task.Delay(10000)) == proxyCheckTask)
                {
                    var proxyUri = proxyCheckTask.Result;
                    if (proxyUri != null && proxyUri != testUri)
                    {
                        issues.Add($"System proxy: {proxyUri}");
                        sb.AppendLine($"⚠ System proxy detected for {probeHost}: {proxyUri}");
                    }
                    else
                    {
                        sb.AppendLine($"✓ No system proxy configured for {probeHost}");
                    }
                }
                else
                {
                    sb.AppendLine($"⚠ System proxy check timed out (WPAD auto-discovery may be slow through VPN)");
                }
            }
            catch { sb.AppendLine("Could not check system proxy"); }

            // WinHTTP proxy — read from registry (locale-independent)
            try
            {
                // The WinHttpSettings binary value at offset 8 contains proxy flags:
                // 0x01 = direct access, 0x03 = manual proxy configured
                // Alternatively, the DefaultConnectionSettings value works the same way.
                bool winHttpProxyDetected = false;
                string winHttpDetail = "";
                using var connKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
                var winHttpBytes = connKey?.GetValue("WinHttpSettings") as byte[];
                if (winHttpBytes != null && winHttpBytes.Length > 8)
                {
                    // Byte 8 is the flags: bit 0x02 means manual proxy is set
                    if ((winHttpBytes[8] & 0x02) != 0)
                    {
                        winHttpProxyDetected = true;
                        // Bytes 12..12+N contain the proxy string (length at offset 12, string at 12+4)
                        if (winHttpBytes.Length > 15)
                        {
                            int proxyLen = BitConverter.ToInt32(winHttpBytes, 12);
                            if (proxyLen > 0 && winHttpBytes.Length >= 16 + proxyLen)
                                winHttpDetail = System.Text.Encoding.ASCII.GetString(winHttpBytes, 16, proxyLen);
                        }
                    }
                }

                if (winHttpProxyDetected)
                {
                    issues.Add("WinHTTP proxy configured");
                    sb.AppendLine($"⚠ WinHTTP proxy configured: {winHttpDetail}");
                }
                else
                {
                    sb.AppendLine("✓ WinHTTP: Direct access (no proxy)");
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

            // ── RDP client-specific proxy config ──
            // The MSRDC / Windows App / mstsc clients each have their own proxy
            // knobs. What the system-wide proxy says is only a default — the
            // client can override it and bypass will differ accordingly. Report
            // the RDP-client view explicitly so operators can distinguish
            // "system is configured for a proxy" from "the RDP client will
            // actually use the proxy".
            try
            {
                var rdpProxy = InspectRdpClientProxyConfig();
                if (rdpProxy.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("RDP client proxy configuration:");
                    foreach (var line in rdpProxy) sb.AppendLine($"  {line}");
                    // Only promote to issues if the RDP client has a non-direct setting
                    if (rdpProxy.Any(l => l.StartsWith("⚠", StringComparison.Ordinal)))
                        issues.Add("RDP client proxy override");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Could not inspect RDP client proxy config: {ex.Message}");
            }

            // ── Live CONNECT probe through detected proxy ──
            // If the system proxy is configured for the RDP gateway, prove it
            // actually works by opening a real HTTP CONNECT tunnel through it.
            // This catches the common "proxy is declared but blocks AVD FQDNs"
            // failure that otherwise only surfaces mid-RDP-session as a hang.
            try
            {
                var systemProxy = WebRequest.GetSystemWebProxy();
                var proxyForRdp = systemProxy?.GetProxy(testUri);
                if (proxyForRdp != null && proxyForRdp != testUri)
                {
                    sb.AppendLine();
                    sb.AppendLine($"Live proxy verification ({proxyForRdp.Host}:{proxyForRdp.Port}):");
                    var verify = await ProbeProxyConnectAsync(proxyForRdp, probeHost, 443, TimeSpan.FromSeconds(8));
                    sb.AppendLine($"  {verify.Message}");
                    if (!verify.Ok)
                    {
                        issues.Add($"Proxy CONNECT to {probeHost}:443 failed");
                        // Remediation URL already set below when issues.Count > 0
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  Live proxy verification skipped: {ex.Message}");
            }

            // ── DNS-layer interception check (SWG DNS hijack) ──
            // The routing-table analysis below is structurally blind to SWGs
            // (e.g. Global Secure Access, Zscaler, Netskope) that acquire traffic
            // by hijacking DNS + capturing the flow with WFP filters BELOW the
            // routing table, rather than by injecting routes. Such an SWG returns
            // a synthetic/relay IP for the FQDN; that IP then follows the normal
            // default route, so a route-only check reports "direct" — a false green.
            //
            // The deterministic, vendor-agnostic signal: the W365 RDP gateway and
            // TURN relay have KNOWN published service ranges. We do NOT assume any
            // particular SWG synthetic range (those vary by vendor/tenant/version).
            // Instead we resolve the FQDN we KNOW must land in 40.64.144.0/20 (RDP
            // gateway) or 51.5.0.0/16 (TURN relay); if it resolves OUTSIDE that
            // range, DNS is being rewritten and the flow is captured at the
            // DNS/WFP layer — which the route check cannot see.
            bool dnsHijackDetected = false;
            try
            {
                var dnsTargets = new List<(string fqdn, uint net, int prefix, string rangeText, string label)>();
                if (gwHost != null)
                    dnsTargets.Add((gwHost, IpToUint32(IPAddress.Parse("40.64.144.0")), 20, "40.64.144.0/20", "RDP gateway"));
                dnsTargets.Add(("world.relay.avd.microsoft.com", IpToUint32(IPAddress.Parse("51.5.0.0")), 16, "51.5.0.0/16", "TURN relay"));

                sb.AppendLine();
                sb.AppendLine("DNS integrity (expected-range check — catches SWG DNS hijacking):");
                foreach (var (fqdn, net, prefix, rangeText, label) in dnsTargets)
                {
                    try
                    {
                        var addrs = Dns.GetHostAddresses(fqdn);
                        var v4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                        if (v4 == null)
                        {
                            sb.AppendLine($"  {label} {fqdn}: no IPv4 answer — check skipped");
                            continue;
                        }
                        uint expStart = net;
                        uint expEnd = prefix == 0 ? 0xFFFFFFFF : net | (0xFFFFFFFF >> prefix);
                        uint ipU = IpToUint32(v4);
                        if (ipU >= expStart && ipU <= expEnd)
                        {
                            sb.AppendLine($"  ✓ {label} {fqdn} → {v4} is within its expected range {rangeText} (DNS not hijacked)");
                        }
                        else
                        {
                            // Outside this build's hard-coded range. Before crying
                            // "hijack", corroborate against the authoritative,
                            // self-updating Azure Service Tags WindowsVirtualDesktop
                            // table (_wvdSubnets): AVD adds gateway/relay ranges over
                            // time that the hard-coded CIDR doesn't know about. A
                            // genuine SWG synthetic IP (private / CGNAT / vendor range)
                            // is NEVER in that table, so a service-tag hit means a
                            // legitimate (newer) Microsoft range — NOT a hijack. Only
                            // flag when the IP is in NEITHER. If the table failed to
                            // load (offline), LookupWvdRegionFromServiceTags returns
                            // null and we fall back to the hard-coded-range verdict.
                            var stRegion = LookupWvdRegionFromServiceTags(v4);
                            if (stRegion != null)
                            {
                                sb.AppendLine($"  ✓ {label} {fqdn} → {v4} is outside the hard-coded {rangeText} but IS a published AVD service-tag range (region {stRegion}) — legitimate, not a hijack.");
                            }
                            else
                            {
                                dnsHijackDetected = true;
                                issues.Add($"DNS hijack: {label} {fqdn} resolves to {v4} (outside {rangeText} and not in any AVD service tag)");
                                sb.AppendLine($"  ⚠ {label} {fqdn} → {v4} is OUTSIDE its expected range {rangeText} AND not in any published AVD service-tag range.");
                                sb.AppendLine($"      DNS is being rewritten — the FQDN is pointed at a synthetic/relay IP by an SWG (e.g. Global Secure Access, Zscaler). The traffic is captured at the DNS/WFP layer, BELOW the routing table, so the route-based bypass check cannot see it. RDP traffic for this endpoint is being intercepted regardless of what the routing table shows.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        sb.AppendLine($"  {label} {fqdn}: resolution failed — {ex.Message}");
                    }
                }
            }
            catch { /* non-critical: route checks below still run */ }

            // VPN adapters — detect presence, then check if RDP traffic actually routes through them
            var vpnAdapters = FindVpnAdapters();
            // Hoisted so the post-detection summary block (below) can tell whether
            // we positively confirmed RDP-gateway bypass via the routing table.
            bool rdpGwDirect = false;

            if (vpnAdapters.Count > 0)
            {
                // List VPN adapters found — tracked as detections, promoted to issues only if routing confirms interception
                foreach (var vpn in vpnAdapters)
                {
                    var vpnIpList = GetAdapterIps(vpn);
                    detected.Add($"VPN: {vpn.Name} ({vpn.Description})");
                    sb.AppendLine($"ℹ VPN adapter detected: {vpn.Name} ({vpn.Description})");
                    if (!string.IsNullOrEmpty(vpnIpList))
                        sb.AppendLine($"    Adapter IPs: {vpnIpList}");
                }
            }
            else
            {
                sb.AppendLine("ℹ No named VPN adapter detected — analysing the routing table anyway in case a tunnel uses an unrecognised adapter");
            }

            // Routing table is the authoritative source for what's routed via VPN.
            // Run this ALWAYS (not only when a named VPN adapter was found): a SWG /
            // VPN whose adapter name isn't in our keyword list still injects routes,
            // and the sweep flags any W365 range that egresses on a non-primary
            // interface as "diverted" even when we couldn't name the adapter.
            var caughtRanges = new List<string>();
            var divertedRanges = new List<string>();
            var offendingIfIps = new HashSet<string>();
            {
                var (caught, diverted) = ProbeAvdServiceRanges(vpnAdapters, sb, offendingIfIps);
                caughtRanges = caught;
                divertedRanges = diverted;
                foreach (var range in caught)
                    issues.Add($"W365/AVD range {range} routes through VPN tunnel");
                foreach (var d in diverted)
                    issues.Add($"W365/AVD range {d} diverts via an unrecognised non-primary interface");

                // Probe the actual discovered RDP gateway for VPN routing (only
                // meaningful when we have a named adapter to compare against).
                if (vpnAdapters.Count > 0)
                {
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
                                if (!string.IsNullOrEmpty(localIp)) offendingIfIps.Add(localIp);
                            }
                            else
                            {
                                sb.AppendLine($"\n  ✓ RDP gateway {gwIp} ({probeHost}) routes direct via {localIp}");
                                rdpGwDirect = true;
                            }
                        }
                    }
                    catch { /* DNS or probe failed — non-critical since routing table already checked */ }
                }

                // Summary: if VPN detected but all W365 ranges and RDP gateway route direct
                if (vpnAdapters.Count > 0 && caught.Count == 0 && diverted.Count == 0 && rdpGwDirect && !dnsHijackDetected)
                    sb.AppendLine("\n  ✓ VPN is active but RDP traffic correctly bypasses it (split-tunnel)");
            }

            // SWG / security processes — tracked as detections; only routing/proxy evidence promotes to issues
            var swgProcesses = new[] { "ZscalerService", "netskope", "iboss", "forcepoint", "mcafee", "symantec", "crowdstrike", "GlobalSecureAccessClient" };
            foreach (var name in swgProcesses)
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                {
                    detected.Add($"SWG: {name}");
                    sb.AppendLine($"ℹ SWG/Security process running: {name} (PID: {procs[0].Id})");
                }
            }

            // ── Per-solution summary ──
            // When more than one VPN/SWG solution is active at once (e.g. Microsoft
            // GSA + Azure VPN), enumerate each one explicitly and state whether it
            // intercepts W365/RDP traffic, so the user can see at a glance which
            // solution (if any) is the problem rather than a single merged verdict.
            var swgEntries = detected.Where(d => d.StartsWith("SWG:", StringComparison.OrdinalIgnoreCase)).ToList();
            int solutionCount = vpnAdapters.Count + swgEntries.Count;
            if (solutionCount > 1)
            {
                sb.AppendLine();
                sb.AppendLine($"══ Detected security solutions ({solutionCount}) ══");
                int n = 0;
                foreach (var vpn in vpnAdapters)
                {
                    n++;
                    var vpnIps = vpn.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(a => a.Address.ToString())
                        .ToHashSet();
                    // Attribute capture to THIS adapter: a W365 range was off the
                    // direct path AND egressed on one of this adapter's IPs.
                    bool thisVpnIntercepts = vpnIps.Overlaps(offendingIfIps);
                    sb.AppendLine($"  {n}. VPN tunnel: {vpn.Name} ({vpn.Description})");
                    if (thisVpnIntercepts)
                    {
                        sb.AppendLine("       ⚠ ISSUE: this tunnel carries W365/RDP traffic — add the W365/AVD ranges to its bypass/exclude list.");
                        if (caughtRanges.Count > 0)
                            sb.AppendLine($"         W365 ranges via tunnel: {string.Join(", ", caughtRanges)}");
                        if (divertedRanges.Count > 0)
                            sb.AppendLine($"         Diverted ranges: {string.Join(", ", divertedRanges)}");
                    }
                    else if ((caughtRanges.Count > 0 || divertedRanges.Count > 0) && offendingIfIps.Count > 0)
                    {
                        sb.AppendLine("       ✓ No issue — W365/RDP traffic is captured, but by a DIFFERENT tunnel, not this one (this adapter's IPs are not the egress).");
                    }
                    else
                    {
                        sb.AppendLine("       ✓ No issue — RDP gateway & W365 ranges bypass this tunnel (split-tunnel).");
                    }
                }
                foreach (var s in swgEntries)
                {
                    n++;
                    var label = s.Substring(s.IndexOf(':') + 1).Trim();
                    bool isGsa = label.Contains("GlobalSecureAccess", StringComparison.OrdinalIgnoreCase);
                    sb.AppendLine($"  {n}. SWG/security agent: {label}");
                    if (dnsHijackDetected && isGsa)
                        sb.AppendLine("       ⚠ ISSUE: GSA is acquiring W365 traffic — the RDP gateway / TURN FQDN resolves to a synthetic IP (DNS hijack). Exclude the W365/AVD FQDNs from the GSA forwarding profile.");
                    else if (isGsa)
                        sb.AppendLine("       ✓ No issue — GSA acquires traffic by DNS interception, and the DNS-integrity check above confirms the RDP gateway & TURN FQDNs resolve to genuine Microsoft IPs (not GSA synthetic addresses). GSA is NOT capturing W365 traffic.");
                    else if (dnsHijackDetected)
                        sb.AppendLine("       ⚠ ISSUE: a DNS hijack was detected — W365 FQDNs are being resolved to a synthetic IP by this agent.");
                    else
                        sb.AppendLine("       ✓ No issue — DNS-integrity check passed and no proxy/captured route detected; this agent is not intercepting W365 traffic.");
                }
            }

            if (issues.Count == 0 && detected.Count == 0)
            {
                result.ResultValue = "No proxy, VPN, or SWG detected";
                result.Status = "Passed";
            }
            else if (issues.Count == 0 && detected.Count > 0)
            {
                // Distinguish three cases:
                //   1. VPN adapter present AND we positively confirmed RDP gateway
                //      routes direct (rdpGwDirect && caught.Count == 0) — real
                //      split-tunnel evidence; the existing "VPN is active but RDP
                //      traffic correctly bypasses it (split-tunnel)" line above
                //      already wrote that to the body.
                //   2. SWG agent process present, no VPN adapter — we have NOT
                //      probed any traffic-capturing tunnel; the agent may simply
                //      be running without a forwarding profile attached. Saying
                //      "split-tunnel" overstates the evidence.
                //   3. Mix — describe accurately.
                var vpnAdapterNames = detected
                    .Where(d => d.StartsWith("VPN:", StringComparison.OrdinalIgnoreCase))
                    .Select(d => {
                        var rest = d.Substring(d.IndexOf(':') + 1).Trim();
                        var pIdx = rest.IndexOf('(');
                        return pIdx > 0 ? rest.Substring(0, pIdx).Trim() : rest;
                    }).ToList();
                var swgProcNames = detected
                    .Where(d => d.StartsWith("SWG:", StringComparison.OrdinalIgnoreCase))
                    .Select(d => d.Substring(d.IndexOf(':') + 1).Trim())
                    .ToList();

                if (vpnAdapterNames.Count > 0 && rdpGwDirect)
                {
                    var summary = string.Join(", ", vpnAdapterNames);
                    if (swgProcNames.Count > 0) summary += " + SWG: " + string.Join(", ", swgProcNames);
                    result.ResultValue = $"VPN active ({summary}) — RDP correctly bypassed (split-tunnel verified)";
                }
                else if (vpnAdapterNames.Count > 0)
                {
                    // VPN adapter exists but we couldn't positively confirm bypass for the
                    // RDP gateway IP via the routing-table check above.
                    var summary = string.Join(", ", vpnAdapterNames);
                    result.ResultValue = $"VPN active ({summary}) — bypass for RDP gateway not confirmed";
                }
                else
                {
                    // SWG-only: process is present but no VPN/tunnel adapter and no
                    // captured route. State the fact, do not claim split-tunnel.
                    var summary = string.Join(", ", swgProcNames);
                    result.ResultValue = $"SWG agent present ({summary}) — no traffic-capturing tunnel detected";
                }
                result.Status = "Passed";
            }
            else
            {
                // Build a human-readable interceptor summary from the actual issues
                var interceptorNames = new List<string>();
                foreach (var issue in issues)
                {
                    if (issue.StartsWith("System proxy:", StringComparison.OrdinalIgnoreCase))
                        interceptorNames.Add("System proxy");
                    else if (issue.Contains("WinHTTP", StringComparison.OrdinalIgnoreCase))
                        interceptorNames.Add("WinHTTP proxy");
                    else if (issue.Contains("routes through VPN", StringComparison.OrdinalIgnoreCase))
                    {
                        // Find which VPN adapter is doing the routing
                        var vpnName = detected.FirstOrDefault(d => d.StartsWith("VPN:"));
                        interceptorNames.Add(vpnName != null
                            ? vpnName.Substring(4).Trim().Split('(')[0].Trim()
                            : "VPN tunnel");
                    }
                    else if (issue.Contains("HTTP_PROXY", StringComparison.OrdinalIgnoreCase) ||
                             issue.Contains("HTTPS_PROXY", StringComparison.OrdinalIgnoreCase) ||
                             issue.Contains("ALL_PROXY", StringComparison.OrdinalIgnoreCase))
                        interceptorNames.Add("Proxy env vars");
                    else if (issue.Contains("diverts via an unrecognised non-primary interface", StringComparison.OrdinalIgnoreCase))
                        interceptorNames.Add("Diverted route (unrecognised interface)");
                    else if (issue.StartsWith("DNS hijack:", StringComparison.OrdinalIgnoreCase))
                        interceptorNames.Add("SWG DNS hijack");
                }
                var uniqueInterceptors = interceptorNames.Distinct().ToList();
                var interceptorLabel = uniqueInterceptors.Count > 0
                    ? string.Join(", ", uniqueInterceptors)
                    : $"{issues.Count} item(s)";

                result.ResultValue = $"Intercepting RDP traffic ({interceptorLabel})";
                result.Status = "Warning";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/requirements-network#proxy-configuration";
                if (detected.Count > 0)
                    sb.AppendLine($"\n  ℹ Also present but not intercepting RDP: {string.Join("; ", detected)}");
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

            // Send a STUN binding request. UDP has no transport-layer retransmission, so a single
            // unACKed datagram lost on a lossy path would falsely read as "UDP 3478 blocked" — a
            // CRITICAL "Shortpath dead" verdict off one dropped packet. Retry up to 3× and validate
            // the STUN Binding Success (0x0101) response, mirroring L-UDP-05, so transient loss can't
            // produce a phantom block. A genuine block still gets no valid response on all attempts.
            var stunRequest = BuildStunRequest();
            var endpoint = new IPEndPoint(ip, port);
            const int maxAttempts = 3;
            long rttMs = 0;
            int responseBytes = 0;
            bool reachable = false;

            for (int attempt = 1; attempt <= maxAttempts && !reachable; attempt++)
            {
                try
                {
                    var sw = Stopwatch.StartNew();
                    await udp.SendAsync(stunRequest, stunRequest.Length, endpoint);
                    var receiveTask = udp.ReceiveAsync();
                    if (await Task.WhenAny(receiveTask, Task.Delay(3000)) == receiveTask)
                    {
                        var response = await receiveTask;
                        // Validate it is a STUN Binding Success Response (0x0101), not a stray datagram.
                        if (response.Buffer.Length >= 20 && ((response.Buffer[0] << 8) | response.Buffer[1]) == 0x0101)
                        {
                            sw.Stop();
                            rttMs = sw.ElapsedMilliseconds;
                            responseBytes = response.Buffer.Length;
                            reachable = true;
                        }
                    }
                    // else: timeout — retry
                }
                catch
                {
                    // Send/receive error — retry
                }
            }

            if (reachable)
            {
                result.Status = "Passed";
                result.ResultValue = $"TURN relay reachable at {ip}:{port} — {rttMs}ms RTT";
                result.DetailedInfo = $"Host: {host}\nIP: {ip}\nPort: {port}\nResponse: {responseBytes} bytes\nLatency: {rttMs}ms\n\nNote: This tests UDP 3478 reachability via DNS-resolved IP. The actual session TURN relay is assigned by the RDP gateway (via CRLB anycast), not by client DNS.";
            }
            else
            {
                result.Status = "Failed";
                result.ResultValue = $"TURN relay {ip}:{port} — UDP 3478 blocked (RDP Shortpath will not work)";
                result.DetailedInfo = $"Host: {host}\nIP: {ip}\nSent {maxAttempts} STUN binding requests but received no valid response, so outbound UDP 3478 is blocked by a firewall or network policy.\n\nImpact: RDP Shortpath (the low-latency UDP transport) cannot be established. RDP will fall back to TCP over the gateway (port 443) so a session can still be made, but the experience is significantly degraded — higher latency, poor resilience to packet loss, and choppy video/scrolling. For a good W365 experience, UDP 3478 must be open.\n\nFix: allow outbound UDP 3478 to turn.azure.com / the AVD TURN range (51.5.0.0/16) through all firewalls and network security appliances.";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
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

            // Primary: Use Azure Service Tags subnet→region mapping (authoritative)
            var azureRegion = LookupTurnRelayRegion(ip);
            if (azureRegion != null)
            {
                var friendlyName = GetAzureRegionFriendlyName(azureRegion);
                var label = friendlyName != null ? $"{friendlyName} ({azureRegion})" : azureRegion;
                result.ResultValue = $"TURN relay (DNS): {label} ({ip})";
                result.DetailedInfo = $"Host: {host}\nIP: {ip}\nAzure Region: {label}\nSource: Azure Service Tags (subnet mapping)\n\nNote: This is the TURN relay returned by client DNS (Azure Traffic Manager). The actual session TURN relay is assigned by the RDP gateway via CRLB anycast routing, which selects the nearest relay based on network proximity — not DNS. A mismatch between this location and your region indicates non-local DNS resolvers but does not affect session quality.";
                result.Status = "Passed";
            }
            else
            {
                // Fallback: GeoIP for IPs outside the known 51.5.0.0/16 range
                try
                {
                    var geo = await FetchGeoIpAsync($"https://ipinfo.io/{ip}/json", TimeSpan.FromSeconds(5));
                    if (geo.TryGetProperty("city", out var cityProp))
                    {
                        var city = cityProp.GetString();
                        var region = geo.TryGetProperty("region", out var rProp) ? rProp.GetString() : "";
                        var country = geo.TryGetProperty("country", out var cProp) ? cProp.GetString() : "";
                        result.ResultValue = $"TURN relay (DNS): {city}, {region}, {country} ({ip})";
                        result.DetailedInfo = $"Host: {host}\nIP: {ip}\nLocation: {city}, {region}, {country}\nSource: GeoIP (IP not in known Service Tags subnets)\n\nNote: This is the TURN relay returned by client DNS. The actual session TURN relay is assigned by the RDP gateway via CRLB anycast, not by client DNS.";
                        result.Status = "Passed";
                    }
                    else
                    {
                        result.ResultValue = $"TURN relay IP: {ip} (location unknown)";
                        result.Status = "Warning";
                    }
                }
                catch
                {
                    result.ResultValue = $"TURN relay IP: {ip} (region lookup failed)";
                    result.Status = "Warning";
                }
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>
    /// Looks up a TURN relay IP against the Azure Service Tags WVDRelays subnet table.
    /// Returns the Azure region name (e.g. "uksouth") or null if not matched.
    /// Uses dynamic Service Tags if available, falls back to hardcoded table.
    /// </summary>
    static string? LookupTurnRelayRegion(IPAddress ip)
    {
        // Try dynamic Service Tags first
        var dynamic = LookupWvdRegionFromServiceTags(ip);
        if (dynamic != null) return dynamic;

        // Fallback: hardcoded subnet → Azure region mapping from Microsoft Service Tags (WVDRelays / 51.5.0.0/16)
        // Derived from: https://www.microsoft.com/en-us/download/details.aspx?id=56519
        var subnets = new (byte secondOctet, byte thirdOctet, int prefixLen, string region)[]
        {
            // /23 entries (cover 2× /24 blocks)
            (5, 0, 23, "southcentralus"),    // 51.5.0.0/23
            (5, 2, 23, "eastus2"),           // 51.5.2.0/23
            (5, 4, 23, "uksouth"),           // 51.5.4.0/23
            (5, 8, 23, "southindia"),        // 51.5.8.0/23
            (5, 16, 23, "centralindia"),     // 51.5.16.0/23
            (5, 28, 23, "germanywc"),        // 51.5.28.0/23
            (5, 30, 23, "westindia"),        // 51.5.30.0/23
            (5, 38, 23, "eastus"),           // 51.5.38.0/23
            (5, 40, 23, "northcentralus"),   // 51.5.40.0/23

            // /24 entries
            (5, 6, 24, "uksouth"),           // 51.5.6.0/24
            (5, 7, 24, "southindia"),        // 51.5.7.0/24
            (5, 10, 24, "southindia"),       // 51.5.10.0/24
            (5, 11, 24, "westeurope"),       // 51.5.11.0/24
            (5, 12, 24, "westeurope"),       // 51.5.12.0/24
            (5, 13, 24, "brazilsouth"),      // 51.5.13.0/24
            (5, 14, 24, "brazilsouth"),      // 51.5.14.0/24
            (5, 15, 24, "centralindia"),     // 51.5.15.0/24
            (5, 18, 24, "ukwest"),           // 51.5.18.0/24
            (5, 19, 24, "uaenorth"),         // 51.5.19.0/24
            (5, 20, 24, "northeurope"),      // 51.5.20.0/24
            (5, 21, 24, "southeastasia"),    // 51.5.21.0/24
            (5, 22, 24, "southeastasia"),    // 51.5.22.0/24
            (5, 23, 24, "westus"),           // 51.5.23.0/24
            (5, 24, 24, "centralus"),        // 51.5.24.0/24
            (5, 25, 24, "eastasia"),         // 51.5.25.0/24
            (5, 26, 24, "canadacentral"),    // 51.5.26.0/24
            (5, 27, 24, "centralfrance"),    // 51.5.27.0/24
            (5, 32, 24, "australiaeast"),    // 51.5.32.0/24
            (5, 33, 24, "japaneast"),        // 51.5.33.0/24
            (5, 34, 24, "japaneast"),        // 51.5.34.0/24
            (5, 35, 24, "japanwest"),        // 51.5.35.0/24
            (5, 36, 24, "japanwest"),        // 51.5.36.0/24
            (5, 37, 24, "australiasoutheast"), // 51.5.37.0/24
            (5, 42, 24, "southafricanorth"), // 51.5.42.0/24
            (5, 43, 24, "southafricawest"),  // 51.5.43.0/24
            (5, 44, 24, "uaecentral"),       // 51.5.44.0/24
            (5, 45, 24, "westcentralus"),    // 51.5.45.0/24
            (5, 46, 24, "westus"),           // 51.5.46.0/24
            (5, 47, 24, "westus3"),          // 51.5.47.0/24
            (5, 48, 24, "canadaeast"),       // 51.5.48.0/24
            (5, 49, 24, "norwaye"),          // 51.5.49.0/24
            (5, 50, 24, "australiacentral"), // 51.5.50.0/24
            (5, 51, 24, "koreacentral"),     // 51.5.51.0/24
            (5, 52, 24, "koreasouth"),       // 51.5.52.0/24
            (5, 53, 24, "switzerlandn"),     // 51.5.53.0/24
            (5, 54, 24, "eastus2euap"),      // 51.5.54.0/24 (canary)
            (5, 55, 24, "israelcentral"),    // 51.5.55.0/24
            (5, 56, 24, "mexicocentral"),    // 51.5.56.0/24
            (5, 57, 24, "spaincentral"),     // 51.5.57.0/24
            (5, 58, 24, "taiwannorth"),      // 51.5.58.0/24
            (5, 59, 24, "newzealandnorth"),  // 51.5.59.0/24
            (5, 60, 24, "italynorth"),       // 51.5.60.0/24
            (5, 61, 24, "polandcentral"),    // 51.5.61.0/24
            (5, 62, 24, "swedencentral"),    // 51.5.62.0/24
            (5, 63, 24, "newzealandnorth"),  // 51.5.63.0/24
            (5, 64, 24, "taiwannorthwest"),  // 51.5.64.0/24
            (5, 65, 24, "swedencentral"),    // 51.5.65.0/24
            (5, 66, 24, "swedensouth"),      // 51.5.66.0/24
            (5, 67, 24, "southfrance"),      // 51.5.67.0/24
            (5, 68, 24, "germanyn"),         // 51.5.68.0/24
            (5, 69, 24, "switzerlandw"),     // 51.5.69.0/24
            (5, 70, 24, "norwayw"),          // 51.5.70.0/24
            (5, 71, 24, "westus2"),          // 51.5.71.0/24
            (5, 72, 24, "chilec"),           // 51.5.72.0/24
        };

        var bytes = ip.GetAddressBytes();
        if (bytes[0] != 51) return null;

        // Check /23 first (more specific for ranges that span 2× /24)
        foreach (var (_, third, prefixLen, region) in subnets)
        {
            if (prefixLen == 23 && bytes[1] == 5)
            {
                // /23 means the third octet matches with bit 0 masked off
                if ((bytes[2] & 0xFE) == (third & 0xFE))
                    return region;
            }
        }
        // Then check /24
        foreach (var (_, third, prefixLen, region) in subnets)
        {
            if (prefixLen == 24 && bytes[1] == 5 && bytes[2] == third)
                return region;
        }

        return null; // IP in 51.x range but not in known WVDRelays subnets
    }

    /// <summary>
    /// Looks up an RDP Gateway IP against the Azure Service Tags WindowsVirtualDesktop subnet table.
    /// Returns the Azure region name (e.g. "uksouth") or null if not matched.
    /// Uses dynamic Service Tags if available, falls back to hardcoded table.
    /// </summary>
    static string? LookupGatewayRegion(IPAddress ip)
    {
        // Try dynamic Service Tags first
        var dynamic = LookupWvdRegionFromServiceTags(ip);
        if (dynamic != null) return dynamic;

        // Fallback: hardcoded subnet → Azure region mapping from Microsoft Service Tags (WindowsVirtualDesktop / 40.64.144.0/20)
        // Derived from: https://www.microsoft.com/en-us/download/details.aspx?id=56519
        // Each entry: (offset from 40.64.144.0, prefix length, region)
        var subnets = new (int offset, int prefixLen, string region)[]
        {
            // /27 entries (32 IPs each)
            (0, 27, "southcentralus"),       // 40.64.144.0/27
            (32, 27, "westeurope"),           // 40.64.144.32/27
            (64, 27, "northeurope"),          // 40.64.144.64/27
            (1024, 27, "germanyn"),           // 40.64.148.0/27
            (1056, 27, "eastus2"),            // 40.64.148.32/27
            (1088, 27, "uksouth"),            // 40.64.148.64/27
            (1120, 27, "southindia"),         // 40.64.148.96/27
            (1152, 27, "brazilsouth"),        // 40.64.148.128/27
            (1216, 27, "centralindia"),       // 40.64.148.192/27
            (1248, 27, "ukwest"),             // 40.64.148.224/27
            (1280, 27, "uaenorth"),           // 40.64.149.0/27
            (1312, 27, "southeastasia"),      // 40.64.149.32/27
            (1344, 27, "westus2"),            // 40.64.149.64/27
            (1376, 27, "centralus"),          // 40.64.149.96/27
            (1408, 27, "eastasia"),           // 40.64.149.128/27
            (1440, 27, "canadacentral"),      // 40.64.149.160/27
            (1472, 27, "centralfrance"),      // 40.64.149.192/27
            (1504, 27, "germanywc"),          // 40.64.149.224/27
            (1536, 27, "westindia"),          // 40.64.150.0/27
            (1568, 27, "australiaeast"),      // 40.64.150.32/27
            (1600, 27, "japaneast"),          // 40.64.150.64/27
            (1632, 27, "japanwest"),          // 40.64.150.96/27
            (1664, 27, "australiasoutheast"), // 40.64.150.128/27
            (1696, 27, "eastus"),             // 40.64.150.160/27
            (1728, 27, "northcentralus"),     // 40.64.150.192/27
            (1760, 27, "southafricanorth"),   // 40.64.150.224/27
            (1792, 27, "southafricawest"),    // 40.64.151.0/27
            (1824, 27, "uaecentral"),         // 40.64.151.32/27
            (1856, 27, "westcentralus"),      // 40.64.151.64/27
            (1888, 27, "westus"),             // 40.64.151.96/27
            (1920, 27, "westus3"),            // 40.64.151.128/27
            (1952, 27, "canadaeast"),         // 40.64.151.160/27
            (1984, 27, "norwaye"),            // 40.64.151.192/27
            (2016, 27, "australiacentral"),   // 40.64.151.224/27
            (2048, 27, "koreacentral"),       // 40.64.152.0/27
            (2080, 27, "koreasouth"),         // 40.64.152.32/27
            (2112, 27, "switzerlandn"),       // 40.64.152.64/27
            (2144, 27, "jioindiawest"),       // 40.64.152.96/27
            (2176, 27, "israelcentral"),      // 40.64.152.128/27
            (2208, 27, "mexicocentral"),      // 40.64.152.160/27
            (2240, 27, "spaincentral"),       // 40.64.152.192/27
            (2272, 27, "taiwannorth"),        // 40.64.152.224/27
            (2304, 27, "newzealandnorth"),    // 40.64.153.0/27
            (2336, 27, "taiwannorthwest"),    // 40.64.153.32/27
            (2368, 27, "swedencentral"),      // 40.64.153.64/27
            (2400, 27, "swedensouth"),        // 40.64.153.96/27
            (2432, 27, "southfrance"),        // 40.64.153.128/27
            (2464, 27, "switzerlandw"),       // 40.64.153.160/27
            (2496, 27, "norwayw"),            // 40.64.153.192/27
            (2528, 27, "italynorth"),         // 40.64.153.224/27
            (2560, 27, "polandcentral"),      // 40.64.154.0/27
            (2592, 27, "chilec"),             // 40.64.154.32/27
            // /28 entries (16 IPs each)
            (160, 28, "taiwannorth"),         // 40.64.144.160/28
            (256, 28, "eastus2"),             // 40.64.145.0/28
            (272, 28, "uksouth"),             // 40.64.145.16/28
            (288, 28, "southindia"),          // 40.64.145.32/28
            (304, 28, "southcentralus"),      // 40.64.145.48/28
            (320, 28, "brazilsouth"),         // 40.64.145.64/28
            (336, 28, "centralindia"),        // 40.64.145.80/28
            (352, 28, "ukwest"),              // 40.64.145.96/28
            (368, 28, "uaenorth"),            // 40.64.145.112/28
            (384, 28, "westeurope"),          // 40.64.145.128/28
            (400, 28, "southeastasia"),       // 40.64.145.144/28
            (416, 28, "westus2"),             // 40.64.145.160/28
            (432, 28, "centralus"),           // 40.64.145.176/28
            (448, 28, "eastasia"),            // 40.64.145.192/28
            (464, 28, "canadacentral"),       // 40.64.145.208/28
            (480, 28, "centralfrance"),       // 40.64.145.224/28
            (496, 28, "germanywc"),           // 40.64.145.240/28
            (512, 28, "westindia"),           // 40.64.146.0/28
            (528, 28, "australiaeast"),       // 40.64.146.16/28
            (544, 28, "japaneast"),           // 40.64.146.32/28
            (560, 28, "japanwest"),           // 40.64.146.48/28
            (576, 28, "australiasoutheast"),  // 40.64.146.64/28
            (592, 28, "eastus"),              // 40.64.146.80/28
            (608, 28, "northcentralus"),      // 40.64.146.96/28
            (624, 28, "southafricanorth"),    // 40.64.146.112/28
            (640, 28, "southafricawest"),     // 40.64.146.128/28
            (656, 28, "uaecentral"),          // 40.64.146.144/28
            (672, 28, "westcentralus"),       // 40.64.146.160/28
            (688, 28, "westus"),              // 40.64.146.176/28
            (704, 28, "westus3"),             // 40.64.146.192/28
            (720, 28, "canadaeast"),          // 40.64.146.208/28
            (736, 28, "norwaye"),             // 40.64.146.224/28
            (752, 28, "australiacentral"),    // 40.64.146.240/28
            (768, 28, "koreacentral"),        // 40.64.147.0/28
            (784, 28, "koreasouth"),          // 40.64.147.16/28
            (800, 28, "switzerlandn"),        // 40.64.147.32/28
            (816, 28, "jioindiawest"),        // 40.64.147.48/28
            (832, 28, "northeurope"),         // 40.64.147.64/28
            // /29 entries (8 IPs each)
            (128, 29, "swedensouth"),         // 40.64.144.128/29
            (136, 29, "swedencentral"),       // 40.64.144.136/29
            (144, 29, "taiwannorthwest"),     // 40.64.144.144/29
            (152, 29, "newzealandnorth"),     // 40.64.144.152/29
            (168, 29, "taiwannorth"),         // 40.64.144.168/29
            (176, 29, "spaincentral"),        // 40.64.144.176/29
            (184, 29, "mexicocentral"),       // 40.64.144.184/29
            (192, 29, "eastus2"),             // 40.64.144.192/29
            (200, 29, "uksouth"),             // 40.64.144.200/29
            (208, 29, "southindia"),          // 40.64.144.208/29
            (216, 29, "southeastasia"),       // 40.64.144.216/29
            (224, 29, "brazilsouth"),         // 40.64.144.224/29
            (232, 29, "centralindia"),        // 40.64.144.232/29
            (240, 29, "ukwest"),              // 40.64.144.240/29
            (248, 29, "israelcentral"),       // 40.64.144.248/29
            (960, 29, "southfrance"),         // 40.64.147.192/29
            (968, 29, "germanyn"),            // 40.64.147.200/29
            (976, 29, "switzerlandw"),        // 40.64.147.208/29
            (984, 29, "norwayw"),             // 40.64.147.216/29
            (1000, 29, "chilec"),             // 40.64.147.232/29
            (1008, 29, "polandcentral"),      // 40.64.147.240/29
            (1016, 29, "italynorth"),         // 40.64.147.248/29
            // /30 entries (4 IPs each)
            (928, 30, "eastus2euap"),         // 40.64.147.160/30
        };

        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return null;

        // Check if IP is in 40.64.144.0/20 (40.64.144.0 – 40.64.159.255)
        if (bytes[0] != 40 || bytes[1] != 64 || bytes[2] < 144 || bytes[2] > 159) return null;

        // Compute offset from 40.64.144.0
        int offset = (bytes[2] - 144) * 256 + bytes[3];

        // Longest-prefix-match: check /30, then /29, /28, /27
        foreach (int pfx in new[] { 30, 29, 28, 27 })
        {
            int hostBits = 32 - pfx;
            int mask = ~((1 << hostBits) - 1) & 0xFFF; // mask off host bits within /20
            int maskedOffset = offset & mask;

            foreach (var (entryOffset, entryPfx, region) in subnets)
            {
                if (entryPfx == pfx && entryOffset == maskedOffset)
                    return region;
            }
        }

        return null; // IP in 40.64.144.0/20 but not in known WVD subnets
    }

    /// <summary>
    /// Maps Azure region identifiers (from Service Tags) to official Microsoft display names.
    /// Source: https://learn.microsoft.com/azure/reliability/regions-list
    /// </summary>
    static string? GetAzureRegionFriendlyName(string region)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Europe
            ["uksouth"] = "UK South",
            ["ukwest"] = "UK West",
            ["northeurope"] = "North Europe",
            ["westeurope"] = "West Europe",
            ["centralfrance"] = "France Central",   // Service Tags alias for francecentral
            ["southfrance"] = "France South",       // Service Tags alias for francesouth
            ["germanywc"] = "Germany West Central", // Service Tags alias for germanywestcentral
            ["germanyn"] = "Germany North",         // Service Tags alias for germanynorth
            ["norwaye"] = "Norway East",            // Service Tags alias for norwayeast
            ["norwayw"] = "Norway West",            // Service Tags alias for norwaywest
            ["swedencentral"] = "Sweden Central",
            ["swedensouth"] = "Sweden South",
            ["switzerlandn"] = "Switzerland North",  // Service Tags alias for switzerlandnorth
            ["switzerlandw"] = "Switzerland West",   // Service Tags alias for switzerlandwest
            ["italynorth"] = "Italy North",
            ["spaincentral"] = "Spain Central",
            ["polandcentral"] = "Poland Central",
            // North America
            ["eastus"] = "East US",
            ["eastus2"] = "East US 2",
            ["eastus2euap"] = "East US 2 EUAP",
            ["centralus"] = "Central US",
            ["northcentralus"] = "North Central US",
            ["southcentralus"] = "South Central US",
            ["westcentralus"] = "West Central US",
            ["westus"] = "West US",
            ["westus2"] = "West US 2",
            ["westus3"] = "West US 3",
            ["canadacentral"] = "Canada Central",
            ["canadaeast"] = "Canada East",
            ["mexicocentral"] = "Mexico Central",
            ["chilec"] = "Chile Central",            // Service Tags alias for chilecentral
            // Asia Pacific
            ["southeastasia"] = "Southeast Asia",
            ["eastasia"] = "East Asia",
            ["japaneast"] = "Japan East",
            ["japanwest"] = "Japan West",
            ["koreacentral"] = "Korea Central",
            ["koreasouth"] = "Korea South",
            ["centralindia"] = "Central India",
            ["southindia"] = "South India",
            ["westindia"] = "West India",
            ["australiaeast"] = "Australia East",
            ["australiasoutheast"] = "Australia Southeast",
            ["australiacentral"] = "Australia Central",
            ["taiwannorth"] = "Taiwan North",
            ["taiwannorthwest"] = "Taiwan Northwest",
            ["newzealandnorth"] = "New Zealand North",
            // Middle East & Africa
            ["southafricanorth"] = "South Africa North",
            ["southafricawest"] = "South Africa West",
            ["uaenorth"] = "UAE North",
            ["uaecentral"] = "UAE Central",
            ["israelcentral"] = "Israel Central",
            ["jioindiawest"] = "Jio India West",
            // South America
            ["brazilsouth"] = "Brazil South",
        };
        return map.TryGetValue(region, out var name) ? name : null;
    }

    // ── L-UDP-05: STUN NAT Type Detection ──
    // Uses a single UdpClient to send STUN binding requests to two different servers,
    // compares the reflexive (XOR-MAPPED-ADDRESS) endpoints to determine NAT type.
    // Same reflexive endpoint = Cone NAT (Shortpath likely)
    // Different reflexive endpoints = Symmetric NAT (Shortpath unlikely)
    //
    // Both servers are resolved from world.turn.wvd.microsoft.com (51.5.0.0/16).
    // TURN servers support STUN Binding per RFC 5766, and these IPs are already
    // required for W365 connectivity — no extra firewall rules needed.
    static async Task<TestResult> RunStunNatType()
    {
        var result = new TestResult { Id = "L-UDP-05", Name = "STUN NAT Type Detection", Category = "udp" };
        try
        {
            // Azure VM outbound NAT is always Endpoint-Dependent (Symmetric) — this is expected and
            // does not affect TURN relay connectivity. The test is only useful on the client device.
            if (IsRemoteSession())
            {
                result.Status = "Passed";
                result.ResultValue = "Not applicable — Azure VM NAT is always Symmetric (expected)";
                result.DetailedInfo = "This test is not meaningful when run inside a Cloud PC (Azure VM).\n" +
                    "Azure's outbound NAT is always Endpoint-Dependent (Symmetric), which is normal.\n" +
                    "TURN relay connectivity is confirmed separately by L-UDP-03.\n\n" +
                    "Run the scanner on your physical client device to classify the client-side NAT type.";
                return result;
            }

            var sb = new StringBuilder();
            sb.AppendLine("Method: Two-server STUN comparison");
            sb.AppendLine("A single UDP socket sends STUN binding requests to two servers.");
            sb.AppendLine("If both return the same reflexive IP:port, NAT is cone-shaped (Shortpath works).");
            sb.AppendLine("If they differ, NAT is symmetric (Shortpath unlikely).");
            sb.AppendLine();

            // Resolve world.turn.wvd.microsoft.com to get TURN relay IPs in 51.5.0.0/16.
            // These servers support STUN Binding (RFC 5766) on UDP 3478.
            // Using only Microsoft TURN IPs avoids requiring third-party endpoints.
            var turnHost = "world.turn.wvd.microsoft.com";
            var turnIps = new HashSet<IPAddress>();

            // Resolve multiple times to collect round-robin IPs
            for (int i = 0; i < 6; i++)
            {
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(turnHost);
                    foreach (var a in addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork))
                        turnIps.Add(a);
                }
                catch { }
                if (turnIps.Count >= 2) break;
                await Task.Delay(200); // Brief pause to allow DNS round-robin rotation
            }

            var sortedIps = turnIps.OrderBy(ip => ip.ToString()).ToList();

            if (sortedIps.Count < 2)
            {
                // Fallback: if DNS only returns one IP, try stun.azure.com as Server 2
                sb.AppendLine($"DNS: {turnHost} resolved to {(sortedIps.Count == 0 ? "nothing" : sortedIps[0].ToString())}");
                sb.AppendLine("⚠ Could not resolve two distinct TURN IPs from DNS round-robin.");

                if (sortedIps.Count == 0)
                {
                    sb.AppendLine($"  DNS resolution of {turnHost} failed completely.");
                    sb.AppendLine("  Check DNS and firewall allow 51.5.0.0/16 on UDP 3478.");
                    result.Status = "Failed";
                    result.ResultValue = $"DNS failed — cannot resolve {turnHost}";
                    result.RemediationText = $"Ensure {turnHost} resolves and UDP 3478 to 51.5.0.0/16 is allowed.";
                    result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
                    result.DetailedInfo = sb.ToString().Trim();
                    return result;
                }

                // Try stun.azure.com as a second server
                sb.AppendLine("  Falling back to stun.azure.com as Server 2.");
                try
                {
                    var fallbackAddrs = await Dns.GetHostAddressesAsync("stun.azure.com");
                    var fallbackIp = fallbackAddrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (fallbackIp != null && !sortedIps.Contains(fallbackIp))
                        sortedIps.Add(fallbackIp);
                }
                catch { }

                if (sortedIps.Count < 2)
                {
                    sb.AppendLine("  stun.azure.com also failed to resolve.");
                    result.Status = "Warning";
                    result.ResultValue = "Only one STUN server IP available — cannot compare";
                    result.DetailedInfo = sb.ToString().Trim();
                    return result;
                }
            }

            var stunIp1 = sortedIps[0];
            var stunIp2 = sortedIps[1];

            sb.AppendLine($"Server 1: {stunIp1} ({turnHost})");
            sb.AppendLine($"Server 2: {stunIp2} ({(sortedIps.Count > 1 && turnIps.Contains(stunIp2) ? turnHost : "stun.azure.com")})");
            if (sortedIps.Count > 2)
                sb.AppendLine($"  (also resolved: {string.Join(", ", sortedIps.Skip(2))})");
            sb.AppendLine();

            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = 5000;
            var localPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
            sb.AppendLine($"Local UDP port: {localPort}");

            // Send STUN to server 1
            var mapped1 = await SendStunAndGetMapped(udp, new IPEndPoint(stunIp1, 3478), sb, $"Server 1 ({stunIp1})");
            // Send STUN to server 2
            var mapped2 = await SendStunAndGetMapped(udp, new IPEndPoint(stunIp2, 3478), sb, $"Server 2 ({stunIp2})");

            sb.AppendLine();

            if (mapped1 == null && mapped2 == null)
            {
                sb.AppendLine("✗ Neither STUN server responded.");
                sb.AppendLine("  UDP port 3478 is blocked by firewall, VPN, or SWG.");
                sb.AppendLine("  RDP Shortpath for public networks will NOT work — RDP falls back to TCP via the gateway (port 443).");
                sb.AppendLine("  A session can still be made over TCP, but the experience is significantly degraded (higher latency, poor under packet loss).");
                result.Status = "Failed";
                result.ResultValue = "STUN failed — UDP 3478 blocked (RDP Shortpath will not work)";
                result.RemediationText = "Allow outbound UDP 3478 to Microsoft STUN/TURN servers so RDP Shortpath can be used.";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
            }
            else if (mapped1 == null || mapped2 == null)
            {
                var working = mapped1 ?? mapped2;
                var okIp = mapped1 != null ? stunIp1 : stunIp2;
                var failIp = mapped1 == null ? stunIp1 : stunIp2;
                sb.AppendLine($"⚠ Only one STUN server responded — reflexive endpoint: {working}");
                sb.AppendLine($"  Responding:     {okIp} ({turnHost})");
                sb.AppendLine($"  Non-responding: {failIp} ({turnHost})");
                sb.AppendLine();
                sb.AppendLine("NAT Type: Cannot determine (need two server responses to compare)");
                sb.AppendLine();
                sb.AppendLine("However, STUN binding DID succeed, which confirms:");
                sb.AppendLine("  • Outbound UDP 3478 to 51.5.0.0/16 is NOT fully blocked");
                sb.AppendLine("  • RDP Shortpath via TURN relay should work");
                sb.AppendLine("  • STUN direct hole-punching may also work (NAT type unknown)");
                sb.AppendLine();
                sb.AppendLine("NAT type reference (for when both servers respond):");
                sb.AppendLine("  Full Cone          — Any host can send to the mapped port             ✓ Shortpath");
                sb.AppendLine("  Restricted Cone     — Only hosts the client contacted can reply       ✓ Shortpath");
                sb.AppendLine("  Port-Restricted Cone — Only the exact host:port can reply             ✓ Shortpath");
                sb.AppendLine("  Symmetric           — Different mapping per destination               ✗ STUN fails");
                result.Status = "Warning";
                result.ResultValue = $"Partial STUN — NAT type undetermined ({working})";
                result.RemediationText = $"TURN server {failIp} did not respond to STUN. UDP works but NAT type could not be classified.";
            }
            else if (mapped1 == mapped2)
            {
                // Same reflexive IP:port from both servers = Endpoint-Independent Mapping
                // This means the NAT is "cone-shaped". We can't distinguish Full Cone vs
                // Restricted Cone vs Port-Restricted Cone with STUN alone (that requires
                // the server to probe from alternate IPs/ports), but all three support
                // RDP Shortpath equally well.

                // Check if reflexive IP matches a local interface (= no NAT / direct)
                var reflexIp = mapped1!.Split(':')[0];
                var localAddrs = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .ToHashSet();

                string natLabel;
                if (localAddrs.Contains(reflexIp))
                {
                    natLabel = "Open Internet (No NAT)";
                    sb.AppendLine($"✓ Reflexive IP {reflexIp} matches a local interface — no NAT detected.");
                }
                else
                {
                    natLabel = "Cone NAT (Full Cone / Restricted Cone / Port-Restricted Cone)";
                    sb.AppendLine($"✓ Both servers returned the same reflexive endpoint: {mapped1}");
                    sb.AppendLine($"  Server 1: {stunIp1} ({turnHost})");
                    sb.AppendLine($"  Server 2: {stunIp2} ({turnHost})");
                }
                sb.AppendLine();
                sb.AppendLine($"NAT Type: {natLabel}");
                sb.AppendLine("  Endpoint-Independent Mapping — the same external IP:port is used");
                sb.AppendLine("  regardless of destination. This is the best NAT type for P2P/UDP.");
                sb.AppendLine();
                sb.AppendLine("RDP Shortpath for public networks is LIKELY to work.");
                sb.AppendLine();
                sb.AppendLine("Shortpath modes available:");
                sb.AppendLine("  • STUN (direct): Client ↔ Cloud PC via UDP hole-punching ✓");
                sb.AppendLine("  • TURN (relayed): Client ↔ TURN relay ↔ Cloud PC (fallback) ✓");
                sb.AppendLine();
                sb.AppendLine("NAT type reference:");
                sb.AppendLine("  Full Cone          — Any host can send to the mapped port             ✓ Shortpath");
                sb.AppendLine("  Restricted Cone     — Only hosts the client contacted can reply       ✓ Shortpath");
                sb.AppendLine("  Port-Restricted Cone — Only the exact host:port can reply             ✓ Shortpath");
                sb.AppendLine("  Symmetric           — Different mapping per destination               ✗ STUN fails");
                result.Status = "Passed";
                result.ResultValue = $"{natLabel} — Shortpath ready ({mapped1})";
            }
            else
            {
                // Different reflexive endpoints = Endpoint-Dependent Mapping
                var ip1 = mapped1!.Split(':')[0];
                var ip2 = mapped2!.Split(':')[0];
                var port1 = mapped1.Split(':')[1];
                var port2 = mapped2.Split(':')[1];

                sb.AppendLine($"✗ Servers returned different reflexive endpoints:");
                sb.AppendLine($"    Server 1 ({stunIp1}):  {mapped1}");
                sb.AppendLine($"    Server 2 ({stunIp2}):  {mapped2}");
                sb.AppendLine();

                // Differentiate true Symmetric NAT (one egress path, different mapping per
                // destination) from split-egress paths caused by a SWG/ZTNA agent (e.g.
                // Microsoft Global Secure Access). W365 ranges (51.5.0.0/16, 40.64.144.0/20)
                // are typically excluded from SWG forwarding profiles, while the fallback
                // Server 2 (stun.azure.com, broader Azure) is NOT excluded — so the two
                // reflexive IPs come from two different network paths, not from NAT remapping.
                // Heuristic: SWG agent process running AND one reflexive IP is in a Microsoft
                // cloud-egress range while the other is not → reclassify as split-egress.
                bool ipsDiffer = ip1 != ip2;
                string? swgAgent = null;
                if (ipsDiffer)
                {
                    var swgProcessNames = new[] { "GlobalSecureAccessClient", "ZscalerService", "netskope", "iboss", "forcepoint" };
                    foreach (var n in swgProcessNames)
                    {
                        try { if (Process.GetProcessesByName(n).Length > 0) { swgAgent = n; break; } } catch { }
                    }
                }

                // "Microsoft/Azure cloud-egress" /8 prefixes — reflexive IPs from SWG egress
                // most commonly land here. Conservative list; 104.x deliberately excluded
                // because it's shared with consumer ISPs (e.g. Charter / Spectrum).
                static bool IsCloudEgressIp(string ip) =>
                    ip.StartsWith("13.") || ip.StartsWith("20.") || ip.StartsWith("40.") ||
                    ip.StartsWith("52.") || ip.StartsWith("51.") || ip.StartsWith("4.") ||
                    ip.StartsWith("23.");

                bool oneIpIsCloud = ipsDiffer && (IsCloudEgressIp(ip1) ^ IsCloudEgressIp(ip2));
                bool splitEgressLikely = swgAgent != null && ipsDiffer && oneIpIsCloud;

                if (splitEgressLikely)
                {
                    sb.AppendLine($"Detected: SWG/ZTNA agent running ({swgAgent}).");
                    sb.AppendLine("One reflexive IP is in a Microsoft cloud-egress range, the other is not.");
                    sb.AppendLine();
                    sb.AppendLine("Most likely cause: SPLIT EGRESS PATHS (not Symmetric NAT).");
                    sb.AppendLine("  The W365 TURN range (51.5.0.0/16) is typically excluded from the SWG");
                    sb.AppendLine("  forwarding profile, so STUN to TURN egresses via your ISP directly.");
                    sb.AppendLine("  General Azure traffic (stun.azure.com fallback) IS forwarded via the");
                    sb.AppendLine("  SWG tunnel, so it egresses from a Microsoft cloud IP.");
                    sb.AppendLine("  → Different reflexive IPs reflect two NETWORK PATHS, not NAT remapping.");
                    sb.AppendLine();
                    sb.AppendLine("This means RDP Shortpath behaviour is NOT determined by this test:");
                    sb.AppendLine("  • Actual NAT type on the W365 path is undetermined here.");
                    sb.AppendLine("  • TURN relay reachability (L-UDP-03) is the real indicator.");
                    sb.AppendLine("  • Direct STUN hole-punching may still work depending on the real NAT.");
                    result.Status = "Passed";
                    result.ResultValue = $"SWG split-tunneling correct — W365 UDP path healthy (TURN confirmed by L-UDP-03)";
                    result.RemediationText = "No action required. SWG split-tunneling for W365 is correctly configured. TURN relay reachability (L-UDP-03) confirms the UDP path is healthy.";
                }
                else if (ipsDiffer)
                {
                    sb.AppendLine("NAT Type: Symmetric NAT (different external IP per destination)");
                    sb.AppendLine("  The NAT assigns a completely different public IP per destination.");
                    sb.AppendLine("  This typically indicates multi-WAN, load-balanced egress, or enterprise security.");
                    sb.AppendLine("  ✓ This is STANDARD and EXPECTED in corporate environments.");
                    sb.AppendLine();
                    sb.AppendLine("RDP Shortpath will use TURN relay for reliable UDP connectivity.");
                    sb.AppendLine("TURN relay provides excellent performance in enterprise environments.");
                    sb.AppendLine();
                    sb.AppendLine("NAT type reference:");
                    sb.AppendLine("  Full Cone          — Any host can send to the mapped port             ✓ Shortpath");
                    sb.AppendLine("  Restricted Cone     — Only hosts the client contacted can reply       ✓ Shortpath");
                    sb.AppendLine("  Port-Restricted Cone — Only the exact host:port can reply             ✓ Shortpath");
                    sb.AppendLine("  Symmetric           — Different mapping per destination               ✗ STUN fails ← YOU ARE HERE");
                    result.Status = "Passed";
                    result.ResultValue = $"Symmetric NAT (enterprise standard) — UDP Shortpath via TURN relay";
                    result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/understanding-remote-desktop-protocol-traffic#known-challenges-with-direct-rdp-shortpath-using-stun";
                }
                else
                {
                    sb.AppendLine($"NAT Type: Symmetric NAT (same IP {ip1}, but port {port1} vs {port2})");
                    sb.AppendLine("  The NAT assigns a different external port per destination.");
                    sb.AppendLine("  This is Endpoint-Dependent Mapping (Symmetric NAT).");
                    sb.AppendLine("  ✓ This is STANDARD and EXPECTED in corporate environments.");
                    sb.AppendLine();
                    sb.AppendLine("RDP Shortpath will use TURN relay for reliable UDP connectivity.");
                    sb.AppendLine("TURN relay provides excellent performance in enterprise environments.");
                    sb.AppendLine();
                    sb.AppendLine("NAT type reference:");
                    sb.AppendLine("  Full Cone          — Any host can send to the mapped port             ✓ Shortpath");
                    sb.AppendLine("  Restricted Cone     — Only hosts the client contacted can reply       ✓ Shortpath");
                    sb.AppendLine("  Port-Restricted Cone — Only the exact host:port can reply             ✓ Shortpath");
                    sb.AppendLine("  Symmetric           — Different mapping per destination               ✗ STUN fails ← YOU ARE HERE");
                    result.Status = "Passed";
                    result.ResultValue = $"Symmetric NAT (enterprise standard) — UDP Shortpath via TURN relay";
                    result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/understanding-remote-desktop-protocol-traffic#known-challenges-with-direct-rdp-shortpath-using-stun";
                }
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

    static async Task<TestResult> RunTurnProxyVpn()
    {
        var result = new TestResult { Id = "L-UDP-07", Name = "TURN Proxy/VPN Detection", Category = "udp" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();      // Confirmed to intercept UDP/TURN traffic
            var detected = new List<string>();    // Present on system but UDP/TURN bypasses them

            // Check for VPN adapters — then verify if TURN traffic actually routes through them
            var vpnAdapters = FindVpnAdapters();

            if (vpnAdapters.Count > 0)
            {
                // List VPN adapters found — tracked as detections, promoted to issues only if routing confirms interception
                foreach (var vpn in vpnAdapters)
                {
                    var vpnIpList = GetAdapterIps(vpn);
                    detected.Add($"VPN: {vpn.Name} ({vpn.Description})");
                    sb.AppendLine($"\u2139 VPN adapter detected: {vpn.Name} ({vpn.Description})");
                    if (!string.IsNullOrEmpty(vpnIpList))
                        sb.AppendLine($"    Adapter IPs: {vpnIpList}");
                }

                // Routing table is the authoritative source for what's routed via VPN
                var (caught, diverted) = ProbeAvdServiceRanges(vpnAdapters, sb);
                foreach (var range in caught)
                    issues.Add($"W365/AVD range {range} routes through VPN tunnel");
                foreach (var range in diverted)
                    issues.Add($"W365/AVD range {range} diverts via an unrecognised non-primary interface");

                // Also show single-IP probe as informational context
                bool turnDirect = false;
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
                        {
                            sb.AppendLine($"\n  \u2714 TURN relay {turnIp} (world.relay.avd.microsoft.com) routes direct via {localIp}");
                            turnDirect = true;
                        }
                    }
                }
                catch { /* DNS or probe failed — non-critical since routing table already checked */ }

                // Summary: if VPN detected but all W365 ranges and TURN relay route direct
                if (caught.Count == 0 && diverted.Count == 0 && turnDirect)
                    sb.AppendLine("\n  \u2714 VPN is active but UDP/TURN traffic correctly bypasses it (split-tunnel)");
            }

            // Check if UDP 3478 outbound is likely blocked by checking Windows Firewall registry
            try
            {
                // Read firewall rules from registry — avoids spawning powershell.exe
                var allRules = ReadFirewallRulesFromRegistry();
                bool found3478Block = allRules.Any(r =>
                    r.Dir.Equals("Out", StringComparison.OrdinalIgnoreCase) &&
                    r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase) &&
                    (r.Protocol == 17 || r.Protocol == 256) && // UDP or Any
                    FwPortMatches(r.LocalPort, 3478));

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

            if (issues.Count == 0 && detected.Count == 0)
            {
                result.ResultValue = "No UDP-blocking proxy/VPN detected";
                result.Status = "Passed";
            }
            else if (issues.Count == 0 && detected.Count > 0)
            {
                // Include adapter names in the result value
                var names = detected.Select(d => d.Contains(':') ? d.Substring(d.IndexOf(':') + 1).Trim() : d).ToList();
                var shortNames = names.Select(n => {
                    var pIdx = n.IndexOf('(');
                    return pIdx > 0 ? n.Substring(0, pIdx).Trim() : n;
                }).ToList();
                result.ResultValue = $"VPN detected ({string.Join(", ", shortNames)}) — UDP/TURN correctly bypassed (split-tunnel)";
                result.Status = "Passed";
            }
            else
            {
                result.ResultValue = $"{issues.Count} potential UDP blocker(s) detected";
                result.Status = "Warning";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks";
                if (detected.Count > 0)
                    sb.AppendLine($"\n  \u2139 Also present but not intercepting UDP: {string.Join("; ", detected)}");
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
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
    static async Task<(string? host, string? detail)> DiscoverRdpGatewayFromAfd()
    {
        // Return cached gateway if already discovered (e.g. by L-TCP-04)
        if (_cachedGatewayHost != null)
            return (_cachedGatewayHost, _cachedGatewayDetail);

        var gwPattern = new System.Text.RegularExpressions.Regex(
            @"(rdgateway[\w-]+\.wvd\.microsoft\.com)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        // Method 1: Set-Cookie Domain= header (standard AFD routing)
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            using var http = CreateProxyAwareHttpClient(TimeSpan.FromSeconds(8), handler);
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft-WVD/1.0");
            var resp = await http.GetAsync("https://afdfp-rdgateway-r1.wvd.microsoft.com/");

            // Check Set-Cookie headers (primary method)
            if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var m = System.Text.RegularExpressions.Regex.Match(
                        cookie, @"Domain=(rdgateway[^;]+\.wvd\.microsoft\.com)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success) { _cachedGatewayHost = m.Groups[1].Value; _cachedGatewayDetail = "AFD Set-Cookie header"; return (_cachedGatewayHost, _cachedGatewayDetail); }
                }
            }

            // Check all response headers for gateway hostname pattern
            foreach (var header in resp.Headers)
            {
                foreach (var val in header.Value)
                {
                    var hm = gwPattern.Match(val);
                    if (hm.Success) { _cachedGatewayHost = hm.Groups[1].Value; _cachedGatewayDetail = $"AFD response header ({header.Key})"; return (_cachedGatewayHost, _cachedGatewayDetail); }
                }
            }

            // Check response body for gateway hostname pattern
            try
            {
                var body = await resp.Content.ReadAsStringAsync();
                if (!string.IsNullOrEmpty(body))
                {
                    var bm = gwPattern.Match(body);
                    if (bm.Success) { _cachedGatewayHost = bm.Groups[1].Value; _cachedGatewayDetail = "AFD response body"; return (_cachedGatewayHost, _cachedGatewayDetail); }
                }
            }
            catch { }

            // Check Location header for redirect to gateway
            if (resp.Headers.Location != null)
            {
                var loc = resp.Headers.Location.ToString();
                var lm = gwPattern.Match(loc);
                if (lm.Success) { _cachedGatewayHost = lm.Groups[1].Value; _cachedGatewayDetail = "AFD redirect Location"; return (_cachedGatewayHost, _cachedGatewayDetail); }
            }

            return (null, $"AFD responded HTTP {(int)resp.StatusCode} but no gateway hostname found in headers or body");
        }
        catch (Exception ex)
        {
            return (null, $"AFD request failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts the Azure region code from an RDP gateway FQDN.
    /// The region code is the short alpha token immediately before the "-rN" role
    /// suffix. Handles BOTH the classic format and the newer host-pool format:
    ///   rdgateway-c221-UKS-r1.wvd.microsoft.com           → UKS
    ///   rdgateway-host-green-c220-weu-r1.wvd...           → WEU  (verified live)
    /// The cluster token (c220) can't match (no 2+ leading letters) and the longer
    /// middle tokens (host, green) aren't immediately followed by "-rN".
    /// </summary>
    static string? ExtractRegionFromGatewayFqdn(string fqdn)
    {
        var m = System.Text.RegularExpressions.Regex.Match(
            fqdn, @"rdgateway[\w-]*?-([A-Za-z]{2,4}\d?)-r\d+(?:\.|$)",
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
            // Europe — display names per https://learn.microsoft.com/azure/reliability/regions-list
            ["UKS"] = "UK South", ["UKW"] = "UK West",
            ["NEU"] = "North Europe", ["WEU"] = "West Europe",
            ["FRC"] = "France Central", ["FRS"] = "France South",
            ["GWC"] = "Germany West Central", ["GN"] = "Germany North",
            ["NOE"] = "Norway East", ["NOW"] = "Norway West",
            ["SEW"] = "Sweden Central", ["SES"] = "Sweden South",
            ["CHN"] = "Switzerland North", ["CHW"] = "Switzerland West",
            ["ITA"] = "Italy North", ["SPE"] = "Spain Central", ["ESC"] = "Spain Central",
            ["POC"] = "Poland Central",
            // North America
            ["EUS"] = "East US", ["EUS2"] = "East US 2",
            ["CUS"] = "Central US", ["NCUS"] = "North Central US",
            ["SCUS"] = "South Central US", ["WCUS"] = "West Central US",
            ["WUS"] = "West US", ["WUS2"] = "West US 2", ["WUS3"] = "West US 3",
            ["CC"] = "Canada Central", ["CE"] = "Canada East",
            // Asia Pacific
            ["SEA"] = "Southeast Asia", ["EA"] = "East Asia",
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
        // First, try to discover the actual regional gateway via AFD
        try
        {
            var (gwHost, _) = await DiscoverRdpGatewayFromAfd();
            if (!string.IsNullOrEmpty(gwHost))
            {
                var ips = await Dns.GetHostAddressesAsync(gwHost);
                var ip = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ip != null) return (gwHost, 443, ip);
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
            string shortpathType = "";     // "Managed (direct UDP 3390)", "Managed (ICE/STUN)", "Public (TURN relay)"
            string shortpathEndpoint = ""; // IP:port of the Shortpath peer

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
                        if (msg.Length is > 0 and < 300)
                            sb.AppendLine($"    {msg}");
                        if (eid == 131) hasConnection = true;
                        if (eid is 137 or 138 or 143)
                        {
                            shortpathConnected = true;
                            protocol = "UDP (RDP Shortpath)";
                            // Event 138/143 message often contains the transport endpoint IP:port
                            // e.g. "Shortpath connected to 10.0.0.5:3390" or "...to 51.5.x.x:3478"
                            // Extract IP to classify managed vs public
                            var ipMatch = Regex.Match(msg, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)");
                            if (ipMatch.Success)
                            {
                                var spIp = ipMatch.Groups[1].Value;
                                var spPort = int.Parse(ipMatch.Groups[2].Value);
                                shortpathEndpoint = $"{spIp}:{spPort}";
                                if (IsPrivateIp(spIp))
                                {
                                    shortpathType = spPort == 3390 ? "Managed (RDP Shortpath for managed networks, direct UDP 3390 — optional)" : $"Managed (ICE/STUN, port {spPort})";
                                    protocol = $"UDP Shortpath — {shortpathType}";
                                }
                                else
                                {
                                    shortpathType = spPort == 3478 ? "Public (TURN relay)" : $"Public (port {spPort})";
                                    protocol = $"UDP Shortpath — {shortpathType}";
                                }
                            }
                        }
                        if (eid == 141) { udpConnected = true; protocol = "UDP (RDP Shortpath)"; }
                        if (eid == 142) { udpFailed = true; protocol = "TCP (Reverse Connect)"; }
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
                            // Detect UDP transport using event IDs (locale-independent)
                            // Event 1103 = Multi-transport Established (UDP connected)
                            // Event 1105 = Multi-transport Info (UDP status update)
                            if (eid is 1103 or 1105)
                            {
                                udpConnected = true;
                                protocol = "UDP (RDP Shortpath)";
                            }
                            // Also check message text for "UDP"/"Shortpath" as supplementary signal
                            else if (msg.Contains("UDP", StringComparison.OrdinalIgnoreCase) ||
                                msg.Contains("Shortpath", StringComparison.OrdinalIgnoreCase))
                            {
                                // Event 1102 = Multi-transport Initiated means UDP was attempted
                                if (eid == 1102)
                                { udpConnected = true; protocol = "UDP (RDP Shortpath)"; }
                                else if (msg.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                                         msg.Contains("Fehler", StringComparison.OrdinalIgnoreCase))
                                { udpFailed = true; if (string.IsNullOrEmpty(protocol)) protocol = "TCP (Reverse Connect)"; }
                            }
                        }
                    }
                }
                if (count == 0) sb.AppendLine("  (no events)");
            }
            catch { sb.AppendLine("RDP Client log: not available"); }

            // 3. Check for active network connections indicating Shortpath type
            // - TURN relay: UDP to 51.5.x.x:3478 or TCP to port 3478
            // - Managed (legacy): UDP to private IP on port 3390
            // - Managed (ICE/STUN): UDP to private IP on ephemeral port
            try
            {
                // Check for UDP listeners using .NET API (avoids spawning netstat.exe)
                var udpListeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveUdpListeners();
                
                if (udpListeners.Any(ep => ep.Port == 3390))
                {
                    sb.AppendLine($"\n  UDP listener on port 3390 detected — RDP Shortpath for managed networks (optional; only used on managed/private networks, most W365 deployments do not require it)");
                }
                
                // Check established TCP connections for TURN relay or gateway
                var tcpConns = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established)
                    .ToList();

                // TURN relay connections (port 3478)
                var turnConns = tcpConns.Where(c => c.RemoteEndPoint.Port == 3478).ToList();
                if (turnConns.Count > 0)
                {
                    sb.AppendLine($"\nActive TURN connections (port 3478): {turnConns.Count}");
                    foreach (var tc in turnConns.Take(3))
                        sb.AppendLine($"  → {tc.RemoteEndPoint}");
                    udpConnected = true;
                    if (string.IsNullOrEmpty(shortpathType))
                    {
                        shortpathType = "Public (TURN relay)";
                        protocol = "UDP Shortpath — Public (TURN relay)";
                    }
                }

                // Connections to port 3390 = managed Shortpath (legacy listener)
                var managedLegacyConns = tcpConns.Where(c => c.RemoteEndPoint.Port == 3390).ToList();
                if (managedLegacyConns.Count > 0)
                {
                    sb.AppendLine($"\nActive connections to port 3390 (RDP Shortpath for managed networks — optional): {managedLegacyConns.Count}");
                    sb.AppendLine($"  Note: port 3390 is RDP Shortpath for managed/private networks only. It is NOT essential — most W365 deployments use public Shortpath (UDP 3478) or TCP fallback.");
                    foreach (var mc in managedLegacyConns.Take(3))
                        sb.AppendLine($"  → {mc.RemoteEndPoint}");
                    shortpathConnected = true;
                    shortpathType = "Managed (RDP Shortpath for managed networks, direct UDP 3390 — optional)";
                    protocol = "UDP Shortpath — Managed (RDP Shortpath for managed networks, direct UDP 3390 — optional)";
                }

                // Connections to RDP gateway on 443 with private remote IPs could indicate managed network
                var privateRdpConns = tcpConns.Where(c =>
                    c.RemoteEndPoint.Port == 443 && IsPrivateIp(c.RemoteEndPoint.Address.ToString())).ToList();
                if (privateRdpConns.Count > 0 && !shortpathConnected)
                {
                    sb.AppendLine($"\nTCP 443 to private IPs: {privateRdpConns.Count} (internal gateway/proxy)");
                    foreach (var pc in privateRdpConns.Take(3))
                        sb.AppendLine($"  → {pc.RemoteEndPoint}");
                }
            }
            catch { /* netstat/connection checks may require elevation */ }

            // 4. Check RemoteFX UDP bandwidth if inside remote session
            if (IsRemoteSession())
            {
                try
                {
                    if (PerfCategoryExists("RemoteFX Network"))
                    {
                        var cat = PerfCategory("RemoteFX Network");
                        var instances = cat.GetInstanceNames();
                        if (instances.Length > 0)
                        {
                            var bw = TryReadPerfCounter("RemoteFX Network", "Current UDP Bandwidth", instances[0]);
                            if (bw != null && bw > 0) { udpConnected = true; sb.AppendLine($"\nRemoteFX UDP Bandwidth: {bw:F0} KB/s (active)"); }
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
                if (!string.IsNullOrEmpty(shortpathType))
                {
                    result.ResultValue = $"UDP Shortpath — {shortpathType} ⚡";
                    sb.AppendLine($"\n✓ Session is using UDP transport (RDP Shortpath).");
                    sb.AppendLine($"  Type: {shortpathType}");
                    if (!string.IsNullOrEmpty(shortpathEndpoint))
                        sb.AppendLine($"  Endpoint: {shortpathEndpoint}");
                    if (shortpathType.Contains("Managed"))
                        sb.AppendLine("  ✓ Direct private connectivity — lowest latency path");
                    else
                        sb.AppendLine("  ✓ Relayed via TURN — good, but managed network may offer lower latency");
                }
                else
                {
                    result.ResultValue = "UDP (RDP Shortpath) ⚡";
                    sb.AppendLine("\n✓ Session is using UDP transport (RDP Shortpath).");
                }
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

            // Retry up to 3× and validate the STUN Binding Success (0x0101) response. UDP has no
            // retransmission, so a single lost datagram on a lossy path would otherwise read as
            // "UDP blocked / Shortpath unavailable". A genuine block still gets no valid response
            // across all attempts. Mirrors L-UDP-03 / L-UDP-05.
            const int maxAttempts = 3;
            bool reachable = false;
            bool validStun = false;
            double rttMs = 0;

            for (int attempt = 1; attempt <= maxAttempts && !reachable; attempt++)
            {
                var sw = Stopwatch.StartNew();
                await udp.SendAsync(stunReq, stunReq.Length, ep);
                var recvTask = udp.ReceiveAsync();
                var completed = await Task.WhenAny(recvTask, Task.Delay(3000));
                if (completed == recvTask)
                {
                    sw.Stop();
                    var resp = await recvTask;
                    validStun = resp.Buffer.Length >= 20 && ((resp.Buffer[0] << 8) | resp.Buffer[1]) == 0x0101;
                    if (validStun)
                    {
                        rttMs = sw.Elapsed.TotalMilliseconds;
                        reachable = true;
                    }
                    // non-STUN datagram — treat as not-yet-confirmed, retry
                }
                // else: timeout — retry
            }

            if (reachable)
            {
                sb.AppendLine($"✓ STUN response in {rttMs:F0}ms");
                sb.AppendLine();
                sb.AppendLine("✓ UDP connectivity confirmed. RDP Shortpath should be available.");
                sb.AppendLine();
                sb.AppendLine("RDP Shortpath modes:");
                sb.AppendLine("  • STUN (direct): Client ↔ Cloud PC via UDP hole-punching");
                sb.AppendLine("  • TURN (relayed): Client ↔ TURN relay ↔ Cloud PC");

                result.Status = "Passed";
                result.ResultValue = $"UDP ready ({rttMs:F0}ms)";
            }
            else
            {
                sb.AppendLine($"✗ UDP connectivity to STUN server timed out after {maxAttempts} attempts (3s each).");
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
                        if (PerfCategoryExists("RemoteFX Network"))
                        {
                            var cat = PerfCategory("RemoteFX Network");
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
                    var tcpUnique = tcpSamples.Select(s => (int)s).Distinct().Count();
                    sb.AppendLine($"TCP RTT: avg {tcpSamples.Average():F0}ms, min {tcpSamples.Min():F0}ms, max {tcpSamples.Max():F0}ms ({tcpSamples.Count} samples over ~60s)");
                    sb.AppendLine($"  Values: {string.Join(", ", tcpSamples.Select(s => $"{s:F0}ms"))}");
                    if (tcpUnique == 1)
                        sb.AppendLine($"  ⚠ Counter did not update during sampling — RemoteFX RTT counters refresh infrequently; value represents a single measurement.");
                }
                if (udpSamples.Count > 0)
                {
                    var udpUnique = udpSamples.Select(s => (int)s).Distinct().Count();
                    sb.AppendLine($"UDP RTT: avg {udpSamples.Average():F0}ms, min {udpSamples.Min():F0}ms, max {udpSamples.Max():F0}ms ({udpSamples.Count} samples over ~60s)");
                    sb.AppendLine($"  Values: {string.Join(", ", udpSamples.Select(s => $"{s:F0}ms"))}");
                    if (udpUnique == 1)
                        sb.AppendLine($"  ⚠ Counter did not update during sampling — RemoteFX RTT counters refresh infrequently; value represents a single measurement.");
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
                    sb.AppendLine("Source: TCP connect probes to RD Gateway (path proxy — not actual session RTT).");
                    sb.AppendLine("For true session round-trip latency, run this tool inside the Cloud PC.");
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

                        result.ResultValue = $"{avg:F0}ms (TCP path proxy)";
                        result.Status = avg < 100 ? "Passed" : avg < 200 ? "Warning" : "Failed";
                        if (avg >= 100)
                            result.RemediationText = $"TCP-handshake RTT to gateway is {avg:F0}ms. This is a path-quality proxy; actual RDP session RTT may differ. Check for proxy/VPN adding latency.";
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
                    if (PerfCategoryExists("RemoteFX Graphics"))
                    {
                        var cat = PerfCategory("RemoteFX Graphics");
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
                    if (PerfCategoryExists("RemoteFX Network"))
                    {
                        var cat = PerfCategory("RemoteFX Network");
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
            sb.AppendLine("Source: TCP connect probes to RD Gateway (path proxy — not actual session jitter).");
            sb.AppendLine("For true session UDP jitter, run this tool inside the Cloud PC.");
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
                        if (PerfCategoryExists("RemoteFX Graphics"))
                        {
                            var cat = PerfCategory("RemoteFX Graphics");
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
                // TCP probe reliability from physical device.
                // NOTE: this is a TCP-handshake stability proxy, not real frame/UDP loss.
                // A network with packet loss on the RDP UDP stream but stable TCP handshakes
                // would still report 0% here. Run inside the Cloud PC for true frame stats.
                sb.AppendLine("Source: TCP connect handshake stability (from physical device).");
                sb.AppendLine("This measures path-stability via TCP handshakes; it is NOT a measurement of RDP UDP frame loss.");
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

                    if (failure == 0) { result.Status = "Passed"; result.ResultValue = "TCP path stable (60/60 handshakes)"; }
                    else if (lossRate < 5) { result.Status = "Passed"; result.ResultValue = $"{lossRate:F1}% TCP handshake failures"; }
                    else if (lossRate < 15) { result.Status = "Warning"; result.ResultValue = $"{lossRate:F0}% TCP handshake failures"; result.RemediationText = "Some TCP handshakes to the gateway failed. This is a path-stability proxy — actual RDP UDP frame loss may differ. Check network stability."; }
                    else { result.Status = "Failed"; result.ResultValue = $"{lossRate:F0}% TCP handshake failures (significant)"; result.RemediationText = "High TCP connection failure rate. Path to gateway is unstable; this strongly suggests RDP UDP frame loss as well."; }
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

            var (vpnRanges, divertedRanges) = ProbeAvdServiceRanges(vpnAdapters, sb);

            if (vpnRanges.Count > 0 || divertedRanges.Count > 0)
            {
                var notBypassed = vpnRanges.Concat(divertedRanges).ToList();
                sb.AppendLine();
                sb.AppendLine($"⚠ W365/AVD traffic is NOT bypassed for: {string.Join(", ", notBypassed)}");
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
                result.ResultValue = $"VPN active — {vpnRanges.Count + divertedRanges.Count} range(s) not bypassed";
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
                    "RDP uses nested encryption — the inner session is already TLS 1.3 encrypted."; // DevSkim: ignore DS440001 - documentation string, not protocol configuration
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
                var (caught, diverted) = ProbeAvdServiceRanges(vpnAdapters, sb);
                if (caught.Count > 0 || diverted.Count > 0)
                {
                    foreach (var range in caught)
                        issues.Add($"RDP range {range} routes through VPN/SWG tunnel");
                    foreach (var range in diverted)
                        issues.Add($"RDP range {range} diverts via an unrecognised non-primary interface");

                    sb.AppendLine();
                    sb.AppendLine("⚠ The following RDP subnet(s) are NOT bypassed:");
                    foreach (var range in caught)
                        sb.AppendLine($"  ✗ {range} (via VPN/SWG tunnel)");
                    foreach (var range in diverted)
                        sb.AppendLine($"  ✗ {range} (via unrecognised non-primary interface — verify it is not a tunnel)");
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

            // Get public-IP egress location. This reflects where traffic breaks out,
            // not necessarily the device's physical/GPS location.
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
                    if (parts?.Length == 2 && double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLat) && double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out userLon))
                        hasUserGeo = true;
                }
                sb.AppendLine($"Your egress location: {userCity}, {userRegion}, {userCountry}");
                if (hasUserGeo)
                    sb.AppendLine($"Egress coordinates: {userLat:F4}, {userLon:F4}");
                sb.AppendLine("Note: This is the public IP breakout location, not device GPS.");
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

                // Service Tags region lookup (authoritative) — preferred over GeoIP
                string gwServiceTagRegion = null;
                if (IPAddress.TryParse(ip.ToString(), out var gwParsedIp))
                {
                    var stRegion = LookupGatewayRegion(gwParsedIp);
                    if (stRegion != null)
                    {
                        var stFriendly = GetAzureRegionFriendlyName(stRegion) ?? stRegion;
                        gwServiceTagRegion = stFriendly;
                        sb.AppendLine($"Location: {stFriendly}");
                    }
                }

                try
                {
                    var gwGeo = await FetchGeoIpAsync($"https://ipinfo.io/{ip}/json", TimeSpan.FromSeconds(5));
                    string gwCity = gwGeo.TryGetProperty("city", out var gc) ? gc.GetString() ?? "" : "";
                    string gwRegion = gwGeo.TryGetProperty("region", out var gr) ? gr.GetString() ?? "" : "";
                    string gwCountry = gwGeo.TryGetProperty("country", out var gco) ? gco.GetString() ?? "" : "";
                    sb.AppendLine($"{(gwServiceTagRegion != null ? "GeoIP" : "Location")}: {gwCity}, {gwRegion}, {gwCountry}");

                    if (hasUserGeo && gwGeo.TryGetProperty("loc", out var gloc))
                    {
                        var parts = gloc.GetString()?.Split(',');
                        if (parts?.Length == 2 && double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var gwLat) && double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var gwLon))
                        {
                            var distKm = HaversineDistance(userLat, userLon, gwLat, gwLon);
                            sb.AppendLine($"Gateway coordinates: {gwLat:F4}, {gwLon:F4}");
                            sb.AppendLine($"Distance from egress: {FormatDistance(distKm)}");

                            // The RD gateway is chosen by Azure Front Door from live GLOBAL
                            // gateway load/latency, keyed off the client's egress — it is NOT
                            // a function of the user's VPN/routing (that shows up as egress far
                            // from the device) nor the Cloud PC region. A non-local gateway
                            // therefore points at the service side: the nearest region(s) were
                            // most likely at capacity / shedding load at connect time.
                            bool gwCrossCountry = !string.IsNullOrWhiteSpace(gwCountry)
                                && !string.IsNullOrWhiteSpace(userCountry)
                                && !gwCountry.Equals(userCountry, StringComparison.OrdinalIgnoreCase);
                            if (distKm > 1500 || (gwCrossCountry && distKm > 1000))
                            {
                                sb.AppendLine($"⚠ AFD selected a gateway {FormatDistance(distKm)} from your egress" +
                                    (gwCrossCountry ? $" (gateway in {gwCountry}, egress in {userCountry})." : "."));
                                sb.AppendLine("  AFD picks the optimal gateway from live global load/latency; a non-local");
                                sb.AppendLine("  choice usually means your nearest region(s) were at capacity at connect time.");
                                sb.AppendLine("  Service-side and typically transient — re-running later may pick a closer gateway.");
                            }
                            else
                            {
                                sb.AppendLine("✓ AFD selected a gateway near your egress location.");
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
                        // High RTT alone is NOT a non-local-egress signal. Constrained access
                        // links (mobile/transit/satellite Wi-Fi) routinely produce >100ms even
                        // when the gateway is geographically adjacent. Egress locality is
                        // judged from gateway distance above; latency is reported here only
                        // as informational context for test 18 (Session Round-Trip Latency).
                        sb.AppendLine("ℹ Elevated TCP RTT — see test 18 (Session Latency) and L-LE-07 (Bandwidth) for access-link assessment.");
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
                            if (parts?.Length == 2 && double.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var tLat) && double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var tLon))
                            {
                                var distKm = HaversineDistance(userLat, userLon, tLat, tLon);
                                sb.AppendLine($"TURN coordinates: {tLat:F4}, {tLon:F4}");
                                sb.AppendLine($"Distance from egress: {FormatDistance(distKm)}");

                                if (distKm > 1500)
                                    sb.AppendLine("ℹ DNS-resolved TURN relay is far — indicates non-local DNS resolvers. The actual session TURN relay is assigned by the RDP gateway via CRLB anycast and is not affected.");
                                else
                                    sb.AppendLine("✓ DNS-resolved TURN relay is near your location.");
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

            // Determine overall result. Egress locality is judged ONLY from
            // geographic proximity (gateway distance > 1500 km from egress);
            // latency is reported in the body but does not flip the verdict —
            // a constrained access link (train/mobile/satellite Wi-Fi) can
            // produce 100ms+ RTT against a gateway 0 km away.
            var text = sb.ToString();
            if (text.Contains("⚠ Gateway is far"))
            {
                result.Status = "Warning";
                result.ResultValue = "Traffic may not be egressing locally";
                result.RemediationText = "RDP gateway traffic appears to be backhauling through a remote network. " +
                    "Ensure local internet breakout for 40.64.144.0/20 (TCP/443). " +
                    "The TURN relay (51.5.0.0/16, UDP/3478) is assigned by the gateway via CRLB anycast and is not affected by client DNS or egress location.";
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

    static string FormatDistance(double kilometers)
    {
        var miles = kilometers * 0.621371;
        return $"~{kilometers:F0} km ({miles:F0} mi)";
    }

    static float? TryReadPerfCounter(string category, string counter, string instance)
    {
        try
        {
            var localCat = GetLocalizedPerfName(category) ?? category;
            var localCounter = GetLocalizedPerfName(counter) ?? counter;
            using var pc = new PerformanceCounter(localCat, localCounter, instance, readOnly: true);
            pc.NextValue();
            Thread.Sleep(100);
            return pc.NextValue();
        }
        catch { return null; }
    }

    static bool PerfCategoryExists(string englishName)
    {
        var localName = GetLocalizedPerfName(englishName) ?? englishName;
        return PerformanceCounterCategory.Exists(localName);
    }

    static PerformanceCounterCategory PerfCategory(string englishName)
    {
        var localName = GetLocalizedPerfName(englishName) ?? englishName;
        return new PerformanceCounterCategory(localName);
    }

    /// <summary>
    /// Maps an English performance counter/category name to the current locale's name
    /// by reading Perflib registry keys. Returns null if mapping is not found (falls back to English).
    /// </summary>
    static string? GetLocalizedPerfName(string englishName)
    {
        try
        {
            // Read English name→index mapping from the 009 (English) Perflib key
            using var enKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009");
            var enCounters = enKey?.GetValue("Counter") as string[];
            if (enCounters == null) return null;

            // Find the index for the English name (entries are: index, name, index, name, ...)
            int? idx = null;
            for (int i = 0; i < enCounters.Length - 1; i += 2)
            {
                if (enCounters[i + 1].Equals(englishName, StringComparison.OrdinalIgnoreCase))
                {
                    idx = int.Parse(enCounters[i]);
                    break;
                }
            }
            if (idx == null) return null;

            // Map index to current locale name
            using var locKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage");
            var locCounters = locKey?.GetValue("Counter") as string[];
            if (locCounters == null) return null;

            for (int i = 0; i < locCounters.Length - 1; i += 2)
            {
                if (locCounters[i] == idx.ToString())
                    return locCounters[i + 1];
            }
        }
        catch { }
        return null;
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
            var (gwHost, _) = await DiscoverRdpGatewayFromAfd();
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
                    // Walk CNAME chain using .NET DNS (avoids spawning nslookup)
                    var current = host;
                    var cnamesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };
                    for (int hop = 0; hop < 10; hop++)
                    {
                        var entry = await Dns.GetHostEntryAsync(current);
                        if (!string.IsNullOrEmpty(entry.HostName) &&
                            !entry.HostName.Equals(current, StringComparison.OrdinalIgnoreCase) &&
                            !cnamesSeen.Contains(entry.HostName))
                        {
                            var cname = entry.HostName.TrimEnd('.');
                            cnamesSeen.Add(cname);
                            if (cname.Contains("afd", StringComparison.OrdinalIgnoreCase) ||
                                cname.Contains("azurefd", StringComparison.OrdinalIgnoreCase))
                                cnameHasAfd = true;
                            if (cname.Contains("privatelink", StringComparison.OrdinalIgnoreCase) &&
                                !cname.Contains("privatelink-global", StringComparison.OrdinalIgnoreCase))
                                cnameHasPrivateLink = true;
                            current = cname;
                        }
                        else break;
                    }
                }
                catch { /* DNS walk failed, rely on other checks */ }

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

            // ── Fetch egress location via GeoIP ──
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
                    sb.AppendLine($"Your egress location: {userCity}, {userCountry}");
                    sb.AppendLine($"Egress coordinates: {userLat:F4}, {userLon:F4}");
                    sb.AppendLine("Note: This is public IP geolocation, not device GPS.");
                    sb.AppendLine();
                }
            }
            catch { sb.AppendLine("Could not determine your egress location (GeoIP unavailable)\n"); }

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

                // Use cached gateway from L-TCP-04 (avoids non-deterministic AFD re-discovery)
                discoveredGateway = _cachedGatewayHost;
                if (discoveredGateway == null)
                {
                    // Fallback: extract from this call's Set-Cookie if cache wasn't populated
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
                                _cachedGatewayHost = discoveredGateway;
                                _cachedGatewayDetail = "AFD Set-Cookie header (from L-TCP-09)";
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"    ✗ AFD unreachable: {ex.InnerException?.Message ?? ex.Message}");
                // Still try cached gateway even if this AFD call failed
                discoveredGateway = _cachedGatewayHost;
                if (discoveredGateway == null)
                    issues.Add("AFD endpoint unreachable");
            }

            sb.AppendLine();

            // ── Part 2: Actual RDP Gateway (unicast — CAN geolocate, FQDN has region) ──
            sb.AppendLine("═══ Actual RDP Gateway (Unicast) ═══");
            string gatewayDisplayRegion = null; // for summary line
            if (!string.IsNullOrEmpty(discoveredGateway))
            {
                sb.AppendLine($"  {discoveredGateway}");

                // Extract region from FQDN
                var regionCode = ExtractRegionFromGatewayFqdn(discoveredGateway);
                var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                if (regionName != null)
                {
                    sb.AppendLine($"    Azure Region: {regionName} ({regionCode})");
                    gatewayDisplayRegion = regionName;
                }
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

                    // Service Tags region lookup — supplementary to FQDN region
                    var gwIpv4 = gwIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    string serviceTagsRegion = null;
                    if (gwIpv4 != null)
                    {
                        var stRegion = LookupGatewayRegion(gwIpv4);
                        if (stRegion != null)
                        {
                            var stFriendly = GetAzureRegionFriendlyName(stRegion) ?? stRegion;
                            serviceTagsRegion = stFriendly;
                            if (gatewayDisplayRegion == null)
                                gatewayDisplayRegion = stFriendly;
                            if (regionName != null && !string.Equals(regionName, stFriendly, StringComparison.OrdinalIgnoreCase))
                                sb.AppendLine($"    Note: Service Tags subnet maps this IP to {stFriendly} (FQDN region used for display)");
                        }
                    }
                    // Always write the Location: line (web UI reads this for the badge)
                    if (gatewayDisplayRegion != null)
                        sb.AppendLine($"    Location: {gatewayDisplayRegion}");

                    // Reverse DNS
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(gwIp);
                        sb.AppendLine($"    Reverse DNS: {entry.HostName}");
                    }
                    catch { sb.AppendLine($"    Reverse DNS: (none)"); }

                    // GeoIP for the unicast gateway IP — supplementary to Service Tags
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
                                        sb.AppendLine($"    Gateway coordinates: {gwLat:F4}, {gwLon:F4}");
                                        sb.AppendLine($"    Distance from egress: {FormatDistance(distKm)}");
                                        // The gateway is AFD-selected from live GLOBAL gateway load/latency,
                                        // keyed off the egress — NOT the user's VPN/routing or the CPC region.
                                        // A non-local choice means the nearest region(s) were most likely at
                                        // capacity / shedding load at connect time (service-side, transient).
                                        bool gwCrossCountry = !string.IsNullOrWhiteSpace(gwCountry)
                                            && !string.IsNullOrWhiteSpace(userCountry)
                                            && !gwCountry.Equals(userCountry, StringComparison.OrdinalIgnoreCase);
                                        if (distKm > 1500 || (gwCrossCountry && distKm > 1000))
                                        {
                                            sb.AppendLine($"    ⚠ AFD selected a gateway {FormatDistance(distKm)} from your egress" +
                                                (gwCrossCountry ? $" (gateway in {gwCountry}, egress in {userCountry})." : "."));
                                            sb.AppendLine($"      AFD picks the optimal gateway from live global load/latency; a non-local");
                                            sb.AppendLine($"      choice usually means your nearest region(s) were at capacity at connect time.");
                                            sb.AppendLine($"      Service-side and typically transient — re-running later may pick a closer gateway.");
                                            issues.Add($"AFD selected a non-local gateway ({FormatDistance(distKm)} from egress{(gwCrossCountry ? $", in {gwCountry}" : "")}) — likely transient load-based steering");
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
                if (gatewayDisplayRegion != null)
                    summaryParts.Add($"Gateway: {gatewayDisplayRegion}");
                else
                {
                    var regionCode = ExtractRegionFromGatewayFqdn(discoveredGateway);
                    var regionName = regionCode != null ? GetAzureRegionName(regionCode) : null;
                    summaryParts.Add(regionName != null
                        ? $"Gateway: {regionName}"
                        : $"Gateway: {discoveredGateway}");
                }
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
            ["BL"] = "Boydton, VA, US",
            ["IAD"] = "Ashburn, VA, US", ["DCA"] = "Washington DC, US",
            ["JFK"] = "New York, US", ["EWR"] = "Newark, NJ, US", ["TEB"] = "Teterboro, NJ, US",
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

    // ═══════════════════════════════════════════
    //  CLOUD PC TEST IMPLEMENTATIONS
    // ═══════════════════════════════════════════

    /// <summary>C-LE-01: Cloud PC Location — identifies Azure region and public IP.</summary>
    static async Task<TestResult> RunCpcLocation()
    {
        var result = new TestResult { Id = "C-LE-01", Name = "Cloud PC Location", Category = "cloudpc-env" };
        try
        {
            var sb = new StringBuilder();

            // Azure region from IMDS (already fetched in Main)
            if (_azureVmRegion != null)
                sb.AppendLine($"Azure Region: {_azureVmRegion}");
            if (_azureVmName != null)
                sb.AppendLine($"VM Name: {_azureVmName}");

            // Public IP via GeoIP
            var geo = await FetchGeoIpAsync("https://ipinfo.io/json", TimeSpan.FromSeconds(5));
            string city = geo.TryGetProperty("city", out var c) ? c.GetString() ?? "" : "";
            string region = geo.TryGetProperty("region", out var rn) ? rn.GetString() ?? "" : "";
            string country = geo.TryGetProperty("country", out var co) ? co.GetString() ?? "" : "";
            string ip = geo.TryGetProperty("ip", out var q) ? q.GetString() ?? "" : "";

            sb.AppendLine($"Public IP: {ip}");
            sb.AppendLine($"Location: {city}, {region}, {country}");
            if (_azureVmRegion != null)
            {
                sb.AppendLine($"Source: IMDS (Azure Region: {_azureVmRegion})");
            }
            else
            {
                sb.AppendLine($"Source: GeoIP (IMDS unavailable)");
                if (_isCloudPcMode)
                    sb.AppendLine($"⚠ GeoIP may show VPN exit point, not the actual Azure region");
            }

            var locText = _azureVmRegion != null
                ? $"{_azureVmRegion} ({city}, {country})"
                : $"{city}, {region}, {country}";

            result.Status = "Passed";
            result.ResultValue = locText;
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>C-LE-02: Cloud PC Network Info — adapters and ISP.</summary>
    static async Task<TestResult> RunCpcNetworkInfo()
    {
        var result = new TestResult { Id = "C-LE-02", Name = "Cloud PC Network Info", Category = "cloudpc-env" };
        try
        {
            var sb = new StringBuilder();
            var geo = await FetchGeoIpAsync("https://ipinfo.io/json", TimeSpan.FromSeconds(5));
            string org = geo.TryGetProperty("org", out var orgVal) ? orgVal.GetString() ?? "" : "";
            string hostname = geo.TryGetProperty("hostname", out var hostVal) ? hostVal.GetString() ?? "" : "";
            string ip = geo.TryGetProperty("ip", out var ipVal) ? ipVal.GetString() ?? "" : "";

            sb.AppendLine($"Public IP: {ip}");
            sb.AppendLine($"Organisation: {org}");
            if (!string.IsNullOrEmpty(hostname))
                sb.AppendLine($"Hostname: {hostname}");
            sb.AppendLine();

            // Network adapters
            var nics = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
            foreach (var nic in nics)
            {
                sb.AppendLine($"Adapter: {nic.Name} ({nic.Description})");
                sb.AppendLine($"  Type: {nic.NetworkInterfaceType}");
                sb.AppendLine($"  Speed: {nic.Speed / 1_000_000} Mbps");
                var ipProps = nic.GetIPProperties();
                foreach (var addr in ipProps.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
                    sb.AppendLine($"  IPv4: {addr.Address}");
            }

            bool isMicrosoft = org.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
                || org.Contains("Azure", StringComparison.OrdinalIgnoreCase);

            result.Status = "Passed";
            result.ResultValue = org;

            // Classify network type for high-latency warnings
            var netType = ClassifyNetworkType(org);
            if (netType != null)
            {
                sb.AppendLine();
                sb.AppendLine($"Network Type: {netType.Value.type}");
                if (netType.Value.warning != null)
                {
                    sb.AppendLine($"⚠ {netType.Value.warning}");
                    result.Status = "Warning";
                    result.ResultValue = $"{org} ({netType.Value.type})";
                }
            }
            else if (!isMicrosoft)
            {
                sb.AppendLine();
                sb.AppendLine("Note: Network org is not Microsoft/Azure. General internet traffic may be routed via VPN/proxy — this is expected if Entra Private Access or similar is configured.");
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>C-TCP-04: Gateway Connectivity from Cloud PC — reuses existing RunGatewayConnectivity.</summary>
    static async Task<TestResult> RunCpcGatewayConnectivity()
    {
        var r = await RunGatewayConnectivity();
        r.Id = "C-TCP-04"; r.Name = "Gateway Connectivity (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-TCP-05: DNS CNAME Chain from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcDnsCnameChain()
    {
        var r = await RunDnsCnameChain();
        r.Id = "C-TCP-05"; r.Name = "DNS CNAME Chain (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-TCP-06: TLS Inspection Detection from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcTlsInspection()
    {
        var r = await RunTlsInspection();
        r.Id = "C-TCP-06"; r.Name = "TLS Inspection (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-TCP-07: Proxy / VPN / SWG Detection from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcProxyVpnDetection()
    {
        var r = await RunProxyVpnDetection();
        r.Id = "C-TCP-07"; r.Name = "Proxy / VPN / SWG (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-TCP-08: DNS Hijacking Check from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcDnsHijackingCheck()
    {
        var r = await RunDnsHijackingCheck();
        r.Id = "C-TCP-08"; r.Name = "DNS Hijacking (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-TCP-09: Gateway Used from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcGatewayUsed()
    {
        var r = await RunGatewayUsed();
        r.Id = "C-TCP-09"; r.Name = "Gateway Used (Cloud PC)"; r.Category = "cloudpc-tcp";
        return r;
    }

    /// <summary>C-UDP-03: TURN Relay from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcTurnRelay()
    {
        var r = await RunTurnRelay();
        r.Id = "C-UDP-03"; r.Name = "TURN Relay (Cloud PC)"; r.Category = "cloudpc-udp";
        return r;
    }

    /// <summary>C-UDP-04: TURN Relay Location from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcTurnRelayLocation()
    {
        var r = await RunTurnRelayLocation();
        r.Id = "C-UDP-04"; r.Name = "TURN Relay Location (Cloud PC)"; r.Category = "cloudpc-udp";
        return r;
    }

    /// <summary>C-UDP-07: TURN Proxy/VPN from Cloud PC — reuses existing.</summary>
    static async Task<TestResult> RunCpcTurnProxyVpn()
    {
        var r = await RunTurnProxyVpn();
        r.Id = "C-UDP-07"; r.Name = "TURN Proxy/VPN (Cloud PC)"; r.Category = "cloudpc-udp";
        return r;
    }

    /// <summary>C-NET-01: Azure IMDS Metadata — reads VM metadata from the Instance Metadata Service.</summary>
    static async Task<TestResult> RunCpcImdsMetadata()
    {
        var result = new TestResult { Id = "C-NET-01", Name = "Azure IMDS Metadata", Category = "cloudpc-env" };
        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Metadata", "true");
            client.Timeout = TimeSpan.FromSeconds(5);
            var resp = await client.GetAsync(
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01"); // DevSkim: ignore DS137138 - Azure IMDS is HTTP-only by design (link-local)

            if (!resp.IsSuccessStatusCode)
            {
                result.Status = "Warning";
                result.ResultValue = $"IMDS returned {resp.StatusCode}";
                return result;
            }

            var json = await resp.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(json);
            var compute = doc.RootElement.GetProperty("compute");
            var network = doc.RootElement.GetProperty("network");

            var sb = new StringBuilder();
            string vmName = compute.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            string vmSize = compute.TryGetProperty("vmSize", out var s) ? s.GetString() ?? "" : "";
            string location = compute.TryGetProperty("location", out var l) ? l.GetString() ?? "" : "";
            string subId = compute.TryGetProperty("subscriptionId", out var sub) ? sub.GetString() ?? "" : "";
            string rgName = compute.TryGetProperty("resourceGroupName", out var rg) ? rg.GetString() ?? "" : "";
            string offer = compute.TryGetProperty("offer", out var of) ? of.GetString() ?? "" : "";
            string sku = compute.TryGetProperty("sku", out var sk) ? sk.GetString() ?? "" : "";
            string publisher = compute.TryGetProperty("publisher", out var pb) ? pb.GetString() ?? "" : "";

            sb.AppendLine($"VM Name: {vmName}");
            sb.AppendLine($"VM Size: {vmSize}");
            sb.AppendLine($"Azure Region: {location}");
            sb.AppendLine($"Resource Group: {rgName}");
            sb.AppendLine($"Subscription: {subId}");
            if (!string.IsNullOrEmpty(publisher))
                sb.AppendLine($"Image: {publisher}/{offer}/{sku}");

            // Cloud PC vs AVD detection summary
            var typeLabel = _hostType == "avd" ? "AVD Session Host" : _hostType == "cloudpc" ? "Cloud PC" : "Unknown";
            sb.AppendLine($"Host Type: {typeLabel}");

            // Extract private IP from network interface
            try
            {
                var iface = network.GetProperty("interface");
                if (iface.GetArrayLength() > 0)
                {
                    var ipv4 = iface[0].GetProperty("ipv4").GetProperty("ipAddress");
                    if (ipv4.GetArrayLength() > 0)
                    {
                        string privateIp = ipv4[0].TryGetProperty("privateIpAddress", out var pip) ? pip.GetString() ?? "" : "";
                        string publicIp = ipv4[0].TryGetProperty("publicIpAddress", out var pubip) ? pubip.GetString() ?? "" : "";
                        sb.AppendLine($"Private IP: {privateIp}");
                        if (!string.IsNullOrEmpty(publicIp))
                            sb.AppendLine($"Public IP (IMDS): {publicIp}");
                    }
                }
            }
            catch { sb.AppendLine("Could not parse network interface data."); }

            result.Status = "Passed";
            var typeTag = _hostType == "avd" ? "AVD" : "W365";
            result.ResultValue = $"{typeTag} — {location} — {vmSize}";
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (HttpRequestException)
        {
            result.Status = "Warning";
            if (_isCloudPcMode)
            {
                result.ResultValue = "IMDS blocked — VPN may be intercepting link-local traffic";
                result.DetailedInfo = "Azure Instance Metadata Service (IMDS) at 169.254.169.254 was not reachable.\n" +
                    "This Cloud PC was detected via registry/service, but IMDS is blocked.\n\n" +
                    "This typically happens when a VPN routes link-local addresses (169.254.x.x)\n" +
                    "through the tunnel instead of keeping them local.\n\n" +
                    "Azure Region and VM details are unavailable.\n" +
                    "To get full metadata, temporarily disconnect the VPN and re-run.";
            }
            else
            {
                result.ResultValue = "IMDS not available — may not be an Azure VM";
                result.DetailedInfo = "Azure Instance Metadata Service (IMDS) at 169.254.169.254 was not reachable.\nThis endpoint is only available inside Azure VMs.";
            }
        }
        catch (TaskCanceledException)
        {
            result.Status = "Warning";
            if (_isCloudPcMode)
            {
                result.ResultValue = "IMDS timed out — VPN may be intercepting link-local traffic";
                result.DetailedInfo = "Azure IMDS at 169.254.169.254 timed out after 5 seconds.\n" +
                    "This Cloud PC was detected via registry/service, but IMDS is unreachable.\n\n" +
                    "VPN software (e.g. Unifi Teleport) can route link-local addresses through the tunnel.\n" +
                    "To get full metadata, temporarily disconnect the VPN and re-run.";
            }
            else
            {
                result.ResultValue = "IMDS timed out";
                result.DetailedInfo = "Azure IMDS at 169.254.169.254 did not respond within 5 seconds.";
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ═══════════════════════════════════════════
    //  AZURE FABRIC TESTS (Cloud PC side)
    // ═══════════════════════════════════════════
    //
    // These tests target the Azure communication IPs that the Guest Agent,
    // extension framework and VM-bootstrap code rely on. A blocked or
    // intercepted path to these endpoints is a very common root cause of
    // Cloud PC provisioning failure, Guest Agent heartbeat loss and
    // Windows-365 extension install failure — symptoms which otherwise
    // surface nowhere in the W365 connectivity signal.
    //
    // Reference: https://learn.microsoft.com/azure/virtual-desktop/azurecommunicationips
    //
    // Note: 168.63.129.16:32526 (HostGAPlugin) is NOT probed — Azure's own
    // WFP filters intentionally restrict that port to the Guest Agent
    // process, so a non-allowlisted probe would always see WSAEACCES on a
    // healthy VM. We probe 168.63.129.16:80 (HTTP) and 169.254.169.254
    // instead — both are open to any process and will catch the same class
    // of interference (proxy intercept, EDR/WFP block, VPN route hijack).

    private const string AzureFabricDocsUrl =
        "https://learn.microsoft.com/azure/virtual-desktop/azurecommunicationips";

    /// <summary>
    /// Returns a pre-filled "Skipped" result when the scanner is clearly not
    /// running inside an Azure VM. `_azureVmRegion` is populated at startup
    /// only when IMDS responds; if it's null, the Azure fabric IPs
    /// (168.63.129.16, 169.254.169.254) are fundamentally unroutable from
    /// this host and any probe failure is a false positive. The tests are
    /// intended to run as part of the --cloudpc suite *inside* a Cloud PC.
    /// </summary>
    static TestResult? AzureFabricNotApplicable(string id, string name)
    {
        if (_azureVmRegion != null) return null; // in Azure — run the real test
        return new TestResult
        {
            Id = id,
            Name = name,
            Category = "cloudpc-azure",
            Status = "Skipped",
            ResultValue = "Not applicable — this host is not an Azure VM",
            DetailedInfo =
                "The Azure fabric communication IPs (168.63.129.16, 169.254.169.254)\n" +
                "are only reachable from inside an Azure VM. The Instance Metadata\n" +
                "Service did not respond at startup, so the scanner is not running\n" +
                "inside an Azure VM and these tests do not apply.\n\n" +
                "Run 'W365LocalScanner.exe --cloudpc' from inside the Cloud PC to\n" +
                "exercise these probes against real fabric endpoints."
        };
    }

    /// <summary>
    /// Checks whether an exception chain ends in a socket-level access-denied
    /// (WSAEACCES / error 10013) — the signature fingerprint of a local WFP /
    /// EDR / host-firewall block, as opposed to a timeout or remote refusal.
    /// </summary>
    static bool IsWsaEAccess(Exception ex)
    {
        for (Exception? e = ex; e != null; e = e.InnerException)
        {
            if (e is SocketException se && (int)se.SocketErrorCode == 10013) return true;
        }
        return false;
    }

    private const string WsaEAccessResultValue =
        "WireServer port restricted to Guest Agent (WFP filter) — expected on modern Cloud PC images";

    private const string WsaEAccessDetailedInfo =
        "WSAEACCES (10013) means the socket was refused by a Windows Filtering Platform\n" +
        "filter — not by the network. On modern Azure / Cloud PC images Microsoft itself\n" +
        "ships WFP filters that restrict WireServer (168.63.129.16) traffic to the Guest\n" +
        "Agent process (WaAppAgent / RDAgent) by design. A user-mode probe therefore\n" +
        "sees WSAEACCES on a perfectly healthy Cloud PC and the result is informational,\n" +
        "not a failure.\n\n" +
        "This becomes a real problem only if WireServer is broken end-to-end — which\n" +
        "surfaces as Guest Agent heartbeat failures, extension install errors, or\n" +
        "provisioning timeouts. If those are absent, this warning can be safely ignored.\n\n" +
        "If you DO see Guest Agent / extension symptoms alongside this, the typical\n" +
        "third-party causes are:\n" +
        "  \u2022 Endpoint protection / EDR (CrowdStrike, SentinelOne, Defender ASR, Symantec,\n" +
        "    Trend, Sophos, Cortex XDR) with a host-firewall rule against 168.63.129.16\n" +
        "  \u2022 Windows Firewall custom outbound block rule (GPO or Intune)\n" +
        "  \u2022 VPN client WFP filter redirecting or denying the fabric IP\n" +
        "  \u2022 Corrupt Azure Guest Agent WFP filter set (reinstall GA to reset)\n\n" +
        "To inspect the WFP filter set: 'netsh wfp show state file=wfp.xml' then search\n" +
        "wfp.xml for 168.63.129.16. Microsoft-shipped filters list providerName as\n" +
        "'Microsoft Corporation' / 'Azure Networking'; third-party filters name the\n" +
        "product (e.g. 'CrowdStrike Falcon Sensor').";

    /// <summary>
    /// C-AZ-01: Raw TCP connect to 168.63.129.16:80. A healthy Cloud PC
    /// completes this in single-digit milliseconds. Failure = network path
    /// blocked (NSG, third-party firewall, EDR host-firewall, VPN route
    /// hijack, or WFP filter installed by endpoint protection).
    /// </summary>
    static async Task<TestResult> RunCpcAzureFabricWireServerTcp()
    {
        var skip = AzureFabricNotApplicable("C-AZ-01",
            "Azure Fabric: WireServer TCP (168.63.129.16:80)");
        if (skip != null) return skip;

        var result = new TestResult
        {
            Id = "C-AZ-01",
            Name = "Azure Fabric: WireServer TCP (168.63.129.16:80)",
            Category = "cloudpc-azure"
        };
        try
        {
            using var tcp = new TcpClient();
            var sw = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync("168.63.129.16", 80, cts.Token);
            sw.Stop();

            result.Status = "Passed";
            result.ResultValue = $"WireServer reachable ({sw.ElapsedMilliseconds}ms)";
            var sb = new StringBuilder();
            sb.AppendLine($"\u2714 168.63.129.16:80 connected in {sw.ElapsedMilliseconds}ms");
            sb.AppendLine();
            sb.AppendLine("168.63.129.16 is Azure's WireServer — a fabric-only virtual public IP every");
            sb.AppendLine("Azure VM / Cloud PC uses to talk to the host for Guest Agent heartbeat,");
            sb.AppendLine("extension management, DHCP, and IMDS-adjacent bootstrap services.");
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (OperationCanceledException)
        {
            result.Status = "Failed";
            result.ResultValue = "Timeout (5s) connecting to 168.63.129.16:80";
            result.DetailedInfo =
                "The Azure WireServer is unreachable over TCP 80 from this Cloud PC.\n" +
                "This typically indicates:\n" +
                "  \u2022 Third-party EDR / host firewall blocking 168.63.129.16\n" +
                "  \u2022 NSG or Azure Firewall rule denying the fabric IP\n" +
                "  \u2022 VPN / ZTNA client route-hijacking non-RFC1918 addresses\n" +
                "  \u2022 Custom route to a dead next-hop\n" +
                "Guest Agent heartbeat, extension install and provisioning all depend on this path.";
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (SocketException ex) when ((int)ex.SocketErrorCode == 10013 /* WSAEACCES */)
        {
            // Microsoft itself ships WFP filters on modern Cloud PC images that restrict
            // WireServer to the Guest Agent process. WSAEACCES from a user-mode probe is
            // therefore expected baseline, not a failure. Surface as Warning so it stays
            // visible (in case Guest Agent symptoms also appear) without flagging healthy
            // CPCs as broken.
            result.Status = "Warning";
            result.ResultValue = WsaEAccessResultValue;
            result.DetailedInfo = WsaEAccessDetailedInfo;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (Exception ex)
        {
            result.Status = "Failed";
            result.ResultValue = ex.InnerException?.Message ?? ex.Message;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        return result;
    }

    /// <summary>
    /// C-AZ-02: HTTP GET to WireServer's version endpoint. Catches transparent
    /// proxies that intercept fabric traffic and return their own HTML error
    /// page instead of the Azure XML version list.
    /// </summary>
    static async Task<TestResult> RunCpcAzureFabricWireServerHttp()
    {
        var skip = AzureFabricNotApplicable("C-AZ-02",
            "Azure Fabric: WireServer HTTP (GoalState)");
        if (skip != null) return skip;

        var result = new TestResult
        {
            Id = "C-AZ-02",
            Name = "Azure Fabric: WireServer HTTP (GoalState)",
            Category = "cloudpc-azure"
        };
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            // Version probe per Azure fabric spec — same URL the Guest Agent uses.
            var req = new HttpRequestMessage(HttpMethod.Get,
                "http://168.63.129.16/?comp=versions"); // DevSkim: ignore DS137138 - WireServer is HTTP-only (link-local fabric IP)
            req.Headers.TryAddWithoutValidation("x-ms-version", "2012-11-30");

            var sw = Stopwatch.StartNew();
            var resp = await client.SendAsync(req);
            sw.Stop();
            var body = await resp.Content.ReadAsStringAsync();

            // WireServer returns XML like: <Versions><Preferred>...<Supported>
            bool looksLikeWireServer =
                resp.IsSuccessStatusCode &&
                body.Contains("<Versions", StringComparison.OrdinalIgnoreCase) &&
                body.Contains("Supported", StringComparison.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            sb.AppendLine($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} in {sw.ElapsedMilliseconds}ms");
            sb.AppendLine($"Content-Type: {resp.Content.Headers.ContentType}");
            sb.AppendLine($"Body length: {body.Length} bytes");
            if (body.Length > 0)
            {
                var preview = body.Length > 300 ? body.Substring(0, 300) + "..." : body;
                sb.AppendLine();
                sb.AppendLine("── Response preview ──");
                sb.AppendLine(preview);
            }

            if (looksLikeWireServer)
            {
                result.Status = "Passed";
                result.ResultValue = $"WireServer responded with Azure version list ({sw.ElapsedMilliseconds}ms)";
            }
            else if (resp.IsSuccessStatusCode)
            {
                // 2xx but body is not Azure XML — almost certainly a transparent proxy
                // returning its own OK page.
                result.Status = "Failed";
                result.ResultValue = "Response body is NOT Azure WireServer XML — likely a transparent proxy intercepting fabric traffic";
                result.RemediationUrl = AzureFabricDocsUrl;
            }
            else
            {
                result.Status = "Failed";
                result.ResultValue = $"WireServer returned HTTP {(int)resp.StatusCode}";
                result.RemediationUrl = AzureFabricDocsUrl;
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (TaskCanceledException)
        {
            result.Status = "Failed";
            result.ResultValue = "Timeout (5s) calling http://168.63.129.16/?comp=versions";
            result.DetailedInfo =
                "No HTTP response from WireServer. If C-AZ-01 (raw TCP) passed, this suggests a\n" +
                "proxy or inspection layer is accepting the connection and then hanging the\n" +
                "request. If C-AZ-01 also failed, see that test's remediation.";
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (Exception ex) when (IsWsaEAccess(ex))
        {
            // See C-AZ-01 — same rationale.
            result.Status = "Warning";
            result.ResultValue = WsaEAccessResultValue;
            result.DetailedInfo = WsaEAccessDetailedInfo;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (Exception ex)
        {
            result.Status = "Failed";
            result.ResultValue = ex.InnerException?.Message ?? ex.Message;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        return result;
    }

    /// <summary>
    /// C-AZ-03: HTTP GET to IMDS with the mandatory 'Metadata: true' header.
    /// Distinguishes network blocks from header-stripping proxies by inspecting
    /// the response body and status code. Overlaps slightly with C-NET-01
    /// (which parses the full metadata document) but focuses specifically on
    /// detecting interference rather than on enumerating VM properties.
    /// </summary>
    static async Task<TestResult> RunCpcAzureFabricImds()
    {
        var skip = AzureFabricNotApplicable("C-AZ-03",
            "Azure Fabric: Instance Metadata Service (IMDS)");
        if (skip != null) return skip;

        var result = new TestResult
        {
            Id = "C-AZ-03",
            Name = "Azure Fabric: Instance Metadata Service (IMDS)",
            Category = "cloudpc-azure"
        };
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            client.DefaultRequestHeaders.Add("Metadata", "true");

            var sw = Stopwatch.StartNew();
            var resp = await client.GetAsync(
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01"); // DevSkim: ignore DS137138 - IMDS is HTTP-only (link-local)
            sw.Stop();
            var body = await resp.Content.ReadAsStringAsync();

            bool looksLikeImds =
                resp.IsSuccessStatusCode &&
                (resp.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true) &&
                body.Contains("\"compute\"", StringComparison.Ordinal);

            var sb = new StringBuilder();
            sb.AppendLine($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} in {sw.ElapsedMilliseconds}ms");
            sb.AppendLine($"Content-Type: {resp.Content.Headers.ContentType}");

            if (looksLikeImds)
            {
                result.Status = "Passed";
                result.ResultValue = $"IMDS reachable and returning metadata ({sw.ElapsedMilliseconds}ms)";
                sb.AppendLine();
                sb.AppendLine("IMDS is reachable, 'Metadata: true' header is preserved end-to-end,");
                sb.AppendLine("and the response is genuine Azure metadata JSON.");
            }
            else if (resp.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {
                // IMDS returns 400 when the Metadata header is missing / stripped.
                // Since we send it, a 400 means a proxy is mutating headers.
                result.Status = "Failed";
                result.ResultValue = "IMDS returned 400 — 'Metadata: true' header appears to be stripped by a proxy";
                result.RemediationUrl = AzureFabricDocsUrl;
            }
            else if (resp.IsSuccessStatusCode && !looksLikeImds)
            {
                result.Status = "Failed";
                result.ResultValue = "Response body is NOT Azure IMDS JSON — likely a transparent proxy intercepting 169.254.169.254";
                sb.AppendLine();
                sb.AppendLine("── Response preview ──");
                sb.AppendLine(body.Length > 300 ? body.Substring(0, 300) + "..." : body);
                result.RemediationUrl = AzureFabricDocsUrl;
            }
            else
            {
                result.Status = "Failed";
                result.ResultValue = $"IMDS returned HTTP {(int)resp.StatusCode}";
                result.RemediationUrl = AzureFabricDocsUrl;
            }
            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (TaskCanceledException)
        {
            result.Status = "Failed";
            result.ResultValue = "Timeout (5s) contacting IMDS at 169.254.169.254";
            result.DetailedInfo =
                "IMDS is link-local to every Azure VM and should respond in ~1ms. A timeout\n" +
                "typically indicates:\n" +
                "  \u2022 A VPN client route-hijacking 169.254.0.0/16\n" +
                "  \u2022 Host firewall / EDR blocking 169.254.169.254\n" +
                "  \u2022 The VM is not actually hosted in Azure (test not applicable)";
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (Exception ex) when (IsWsaEAccess(ex))
        {
            result.Status = "Failed";
            result.ResultValue = "Access denied (WSAEACCES) \u2014 local filter blocking IMDS";
            result.DetailedInfo = WsaEAccessDetailedInfo;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (HttpRequestException ex)
        {
            result.Status = "Failed";
            result.ResultValue = ex.InnerException?.Message ?? ex.Message;
            result.RemediationUrl = AzureFabricDocsUrl;
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.ResultValue = ex.Message;
        }
        return result;
    }


    /// <summary>
    /// C-NET-02: RDP Egress in Azure — checks that Cloud PC traffic to RDP Gateway
    /// and TURN relay exits from an Azure IP range (not routed outside via VPN/SWG).
    /// Only checks the RDP path, not general internet egress which may legitimately
    /// go through on-prem proxies.
    /// </summary>
    static async Task<TestResult> RunCpcRdpEgressInAzure()
    {
        var result = new TestResult { Id = "C-NET-02", Name = "RDP Egress in Azure", Category = "cloudpc-tcp" };
        try
        {
            var sb = new StringBuilder();
            var concerns = new List<string>();
            var knownAzureFirstOctets = new HashSet<byte> { 13, 20, 40, 51, 52, 65, 104, 131, 132, 134, 137, 138, 157, 168, 191, 204 };

            // 1. Check RDP Gateway egress
            sb.AppendLine("── RDP Gateway Egress ──");
            string? gwHost = null;
            try
            {
                var (discoveredHost, detail) = await DiscoverRdpGatewayFromAfd();
                gwHost = discoveredHost ?? "rdweb.wvd.microsoft.com";
                sb.AppendLine($"Gateway: {gwHost}");

                var gwIps = await Dns.GetHostAddressesAsync(gwHost);
                var gwIp = gwIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (gwIp != null)
                {
                    sb.AppendLine($"Gateway IP: {gwIp}");
                    bool isW365 = IsInW365Range(gwIp);
                    var gwRegion = LookupGatewayRegion(gwIp);
                    bool isKnownAzure = gwIp.GetAddressBytes().Length == 4 && knownAzureFirstOctets.Contains(gwIp.GetAddressBytes()[0]);

                    if (isW365)
                    {
                        sb.AppendLine($"✓ Gateway IP is in W365 range{(gwRegion != null ? $" ({gwRegion})" : "")}");
                    }
                    else if (isKnownAzure)
                    {
                        sb.AppendLine("✓ Gateway IP is in known Azure range");
                    }
                    else
                    {
                        sb.AppendLine("⚠ Gateway IP is NOT in a known Azure range — traffic may be routed outside Azure");
                        concerns.Add("Gateway");
                    }

                    // Check which local interface would route to this IP
                    var vpnAdapters = FindVpnAdapters();

                    if (vpnAdapters.Count > 0)
                    {
                        var (routedViaVpn, localIp, adapterName) = CheckIfRoutedViaVpn(gwIp, vpnAdapters);
                        sb.AppendLine($"Local route: {localIp}");
                        if (routedViaVpn)
                        {
                            sb.AppendLine($"⚠ Traffic to Gateway routes via VPN adapter: {adapterName}");
                            concerns.Add("VPN-routed Gateway");
                        }
                        else
                        {
                            sb.AppendLine("✓ Traffic to Gateway does not route via VPN adapter");
                        }
                    }
                }
            }
            catch (Exception ex) { sb.AppendLine($"Gateway check failed: {ex.Message}"); }

            sb.AppendLine();

            // 2. Check TURN Relay egress
            sb.AppendLine("── TURN Relay Egress ──");
            try
            {
                var turnHost = "world.relay.avd.microsoft.com";
                var turnIps = await Dns.GetHostAddressesAsync(turnHost);
                var turnIp = turnIps.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                sb.AppendLine($"TURN Host: {turnHost}");

                if (turnIp != null)
                {
                    sb.AppendLine($"TURN IP: {turnIp}");
                    bool isW365 = IsInW365Range(turnIp);
                    var turnRegion = LookupTurnRelayRegion(turnIp);
                    bool isKnownAzure = turnIp.GetAddressBytes().Length == 4 && knownAzureFirstOctets.Contains(turnIp.GetAddressBytes()[0]);

                    if (isW365)
                    {
                        sb.AppendLine($"✓ TURN IP is in W365 range{(turnRegion != null ? $" ({turnRegion})" : "")}");
                    }
                    else if (isKnownAzure)
                    {
                        sb.AppendLine("✓ TURN IP is in known Azure range");
                    }
                    else
                    {
                        sb.AppendLine("⚠ TURN IP is NOT in a known Azure range — traffic may be routed outside Azure");
                        concerns.Add("TURN");
                    }

                    // VPN routing check
                    var vpnAdapters = FindVpnAdapters();

                    if (vpnAdapters.Count > 0)
                    {
                        var (routedViaVpn, localIp, adapterName) = CheckIfRoutedViaVpn(turnIp, vpnAdapters);
                        sb.AppendLine($"Local route: {localIp}");
                        if (routedViaVpn)
                        {
                            sb.AppendLine($"⚠ Traffic to TURN routes via VPN adapter: {adapterName}");
                            concerns.Add("VPN-routed TURN");
                        }
                        else
                        {
                            sb.AppendLine("✓ Traffic to TURN does not route via VPN adapter");
                        }
                    }
                }
                else
                {
                    sb.AppendLine("⚠ Could not resolve TURN relay address");
                }
            }
            catch (Exception ex) { sb.AppendLine($"TURN check failed: {ex.Message}"); }

            // 3. Compare Azure region of the Cloud PC with gateway/relay region
            if (_azureVmRegion != null)
            {
                sb.AppendLine();
                sb.AppendLine($"── Region Comparison ──");
                sb.AppendLine($"Cloud PC region: {_azureVmRegion}");
                // The gateway/turn region lookups above will show nearby region info
            }

            result.DetailedInfo = sb.ToString().Trim();
            if (concerns.Count > 0)
            {
                result.Status = "Warning";
                result.ResultValue = $"RDP traffic may egress outside Azure: {string.Join(", ", concerns)}";
                result.RemediationText = "RDP traffic from the Cloud PC appears to be routed outside Azure via VPN/SWG. " +
                    "Ensure that 40.64.144.0/20 (Gateway) and 51.5.0.0/16 (TURN) are excluded from VPN tunnel on the Cloud PC. " +
                    "These ranges should route directly within the Azure network.";
                result.RemediationUrl = "https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp#3-local-network-egress";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = "RDP traffic stays within Azure — no VPN/SWG routing detected";
            }
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>
    /// C-EP-02: Session Host Required Endpoints — tests all required FQDNs from the Microsoft docs.
    /// AVD base list + W365-specific registration endpoints when _hostType == "cloudpc".
    /// Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines
    /// </summary>
    static async Task<TestResult> RunCpcRequiredEndpoints()
    {
        var isCpc = _hostType == "cloudpc";
        // Cloud PC and AVD session hosts share the same required-endpoint list,
        // but "Session Host" is an AVD term — on a Cloud PC we call the machine
        // the "Cloud PC" itself. Use a single hostLabel to keep the test name,
        // group headers and result summary consistent with the detected host.
        var hostLabel = isCpc ? "Cloud PC" : "Session Host";
        var requiredGroup = $"{hostLabel} Required";
        var optionalGroup = $"{hostLabel} Optional";
        var healthPurpose = $"{hostLabel} health monitoring (Azure wireserver)";

        var result = new TestResult { Id = "C-EP-02", Name = $"{hostLabel} Required Endpoints", Category = "cloudpc-env" };
        try
        {
            var endpoints = new List<(string host, int port, string purpose, string group)>();

            // ── AVD base endpoints (apply to both AVD and W365) ──
            // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines
            // TCP 443 — Core service traffic
            endpoints.Add(("login.microsoftonline.com", 443, "Authentication to Microsoft Online Services", requiredGroup));
            endpoints.Add(("rdweb.wvd.microsoft.com", 443, "Service traffic / TCP RDP", requiredGroup));
            endpoints.Add(("catalogartifact.azureedge.net", 443, "Azure Marketplace", requiredGroup));
            endpoints.Add(("gcs.prod.monitoring.core.windows.net", 443, "Agent monitoring", requiredGroup));
            endpoints.Add(("mrsglobalsteus2prod.blob.core.windows.net", 443, "Agent/SXS stack updates", requiredGroup));
            endpoints.Add(("wvdportalstorageblob.blob.core.windows.net", 443, "Azure portal support", requiredGroup));
            endpoints.Add(("aka.ms", 443, "Microsoft URL shortener", requiredGroup));
            endpoints.Add(("login.windows.net", 443, "Sign-in to Microsoft Online Services", optionalGroup));

            // Wildcard service-traffic endpoints from the AVD/W365 required-FQDN
            // list. Each wildcard below has no canonical apex, so we probe a
            // known-good real exemplar hostname under it to verify the firewall
            // rule for the wildcard is open. Reachability of the exemplar proves
            // the *.<domain> rule resolves and connects; a failure means the
            // wildcard is being blocked.
            // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines
            endpoints.Add(("prod-r1.windows.cloud.microsoft", 443,
                "Service traffic", requiredGroup));
            endpoints.Add(("shprf.sh.service.windows.cloud.microsoft", 443,
                "Service traffic", requiredGroup));
            endpoints.Add(("sash.cloudpc.windows.static.microsoft", 443,
                "Service traffic", requiredGroup));

            // *.prod.warm.ingest.monitor.core.windows.net — Log Analytics / Azure Monitor
            // ingestion wildcard. The real hostnames follow the pattern
            // "{region}-{n}.prod.warm.ingest.monitor.core.windows.net" where {n} is
            // 0, 1, or 2 depending on the region's cluster. Not every region has
            // -1 (e.g. ukwest is -0 only) and some regions (westeurope, eastasia,
            // koreacentral, japanwest, australiasoutheast) route to a neighbouring
            // region and have no {region}-N subdomain of their own. Additionally,
            // some regional warm-ingest clusters (e.g. ukwest-0 as of 2026)
            // silently drop raw TCP SYN from arbitrary clients — they only answer
            // authenticated agent connections through an Azure-internal path — so
            // a TCP timeout against the VM's local region does not imply the
            // *wildcard* firewall rule is blocked.
            //
            // Strategy:
            //   1. Probe {region}-0/-1/-2 in the VM's own region (DNS-resolved).
            //      If the cluster answers, use that as the exemplar.
            //   2. If none of them resolve OR (at probe time) the local exemplar
            //      fails with a timeout, retry against eastus-0 and westus-0 as
            //      canaries. Success on either proves the wildcard firewall rule
            //      is open — which is what this check is actually trying to
            //      establish. The fallback happens later, during the main probe.
            var monitorRegion = _azureVmRegion ?? "eastus";
            string? monitorExemplar = null;
            foreach (var suffix in new[] { "-0", "-1", "-2" })
            {
                var candidate = $"{monitorRegion}{suffix}.prod.warm.ingest.monitor.core.windows.net";
                try
                {
                    var addrs = await System.Net.Dns.GetHostAddressesAsync(candidate);
                    if (addrs != null && addrs.Length > 0) { monitorExemplar = candidate; break; }
                }
                catch { /* NXDOMAIN — try next suffix */ }
            }
            monitorExemplar ??= "eastus-0.prod.warm.ingest.monitor.core.windows.net";
            endpoints.Add((monitorExemplar, 443,
                "Agent diagnostics", requiredGroup));

            // TCP 80 — Health monitoring and certificates
            endpoints.Add(("168.63.129.16", 80, healthPurpose, requiredGroup));
            endpoints.Add(("168.63.129.16", 32526, healthPurpose, requiredGroup));
            endpoints.Add(("oneocsp.microsoft.com", 80, "CRL/OCSP certificate revocation", requiredGroup));
            endpoints.Add(("ctldl.windowsupdate.com", 80, "Certificate trust list updates", requiredGroup));
            // AIK / device-attestation certificate endpoints (TCP 80). These are
            // on the session-host required table but each is a wildcard with no
            // canonical apex, so probe a known-good exemplar under each. Same
            // exemplars used by the client-mode L-EP-01 check; included here so a
            // Cloud PC / session-host scan (which runs GetCloudPcTests, not the
            // L-* client tests) still verifies them.
            // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines
            endpoints.Add(("www.microsoft.com", 80, "Certificates", requiredGroup));
            endpoints.Add(("eusaikpublish.microsoftaik.azure.net", 80, "Certificates", requiredGroup));
            endpoints.Add(("eus.aikcertaia.microsoft.com", 80, "Certificates", requiredGroup));
            endpoints.Add(("azcsprodeusaikpublish.blob.core.windows.net", 80, "Certificates", requiredGroup));

            // TCP 1688
            endpoints.Add(("azkms.core.windows.net", 1688, "Windows KMS activation", requiredGroup));

            // ── W365-specific registration endpoints ──
            if (_hostType == "cloudpc")
            {
                endpoints.Add(("cpcsaamssa1prodprap01.infra.windows365.microsoft.com", 443,
                    "W365 infrastructure (*.infra.windows365.microsoft.com)", "W365 Registration"));
                endpoints.Add(("login.live.com", 443, "Microsoft account authentication", "W365 Registration"));
                endpoints.Add(("enterpriseregistration.windows.net", 443, "Device registration", "W365 Registration"));
                endpoints.Add(("global.azure-devices-provisioning.net", 443, "IoT provisioning (TCP 443)", "W365 Registration"));
                endpoints.Add(("global.azure-devices-provisioning.net", 5671, "IoT provisioning (AMQP 5671)", "W365 Registration"));

                // IoT Hub endpoints — 443 + 5671 each
                var iotHubs = new[]
                {
                    "hm-iot-in-prod-prap01", "hm-iot-in-prod-prau01", "hm-iot-in-prod-preu01",
                    "hm-iot-in-prod-prna01", "hm-iot-in-prod-prna02",
                    "hm-iot-in-2-prod-preu01", "hm-iot-in-2-prod-prna01",
                    "hm-iot-in-3-prod-preu01", "hm-iot-in-3-prod-prna01",
                    "hm-iot-in-4-prod-prna01"
                };
                foreach (var hub in iotHubs)
                {
                    var host = $"{hub}.azure-devices.net";
                    endpoints.Add((host, 443, $"IoT Hub {hub} (TCP 443)", "W365 IoT Hub"));
                    endpoints.Add((host, 5671, $"IoT Hub {hub} (AMQP 5671)", "W365 IoT Hub"));
                }
            }

            // Pre-flight warmup. The first TCP connection a self-extracted
            // single-file exe makes pays some one-time cost (IP stack config,
            // WFP/MDE callout registration, first-use of the socket layer)
            // that subsequent connections don't. Historically this showed up
            // as the wireserver probe \u2014 often the first one to complete in
            // the parallel fan-out \u2014 timing out on perfectly healthy CPCs.
            // Do a single sequential connection up front to warm the stack.
            // ~10ms on a healthy VM; if it fails fast we still proceed to
            // the full fan-out (the soft-endpoint logic handles the result).
            try
            {
                using var warm = new TcpClient();
                using var warmCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await warm.ConnectAsync("168.63.129.16", 80, warmCts.Token);
            }
            catch { /* swallow \u2014 the real probe below will record the result */ }

            // Run all checks in parallel (with a conservative concurrency limit
            // to avoid thread-pool starvation on machines with behavioural
            // network filters like Defender for Endpoint).
            //
            // Per-attempt timeout is 8s, with a single retry on timeout only.
            // Other socket errors (ConnectionRefused, HostUnreachable, etc.)
            // are not retried because they aren't transient. Timeout is the
            // only failure mode consistent with contention/cold-start.
            const int PerAttemptTimeoutMs = 8000;
            async Task<(bool ok, long ms, string? err)> TryConnectAsync(string host, int port)
            {
                using var tcp = new TcpClient();
                using var cts = new CancellationTokenSource(PerAttemptTimeoutMs);
                var sw = Stopwatch.StartNew();
                try
                {
                    await tcp.ConnectAsync(host, port, cts.Token);
                    sw.Stop();
                    return (true, sw.ElapsedMilliseconds, null);
                }
                catch (OperationCanceledException)
                {
                    return (false, 0L, $"Timeout ({PerAttemptTimeoutMs / 1000}s)");
                }
                catch (Exception ex)
                {
                    return (false, 0L, ex.InnerException?.Message ?? ex.Message);
                }
            }

            var semaphore = new SemaphoreSlim(6);
            var tasks = endpoints.Select(async ep =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var attempt = await TryConnectAsync(ep.host, ep.port);
                    // Retry once on timeout only.
                    if (!attempt.ok && attempt.err != null && attempt.err.StartsWith("Timeout"))
                    {
                        var retry = await TryConnectAsync(ep.host, ep.port);
                        if (retry.ok) attempt = retry;
                    }
                    return (ep, ok: attempt.ok, ms: attempt.ms, err: attempt.err);
                }
                finally { semaphore.Release(); }
            }).ToArray();

            var results = await Task.WhenAll(tasks);

            // Monitor-ingest fallback: if the VM's local-region warm-ingest
            // exemplar timed out, retry against canary regions. Success against
            // any canary proves the *.prod.warm.ingest.monitor.core.windows.net
            // wildcard firewall rule is open — which is what this check is
            // trying to establish. Some regional clusters (e.g. ukwest-0 as
            // observed Apr 2026) silently drop raw TCP SYN from arbitrary
            // probers even on a perfectly healthy CPC, and we should not fail
            // the whole session-host verdict on that.
            for (int i = 0; i < results.Length; i++)
            {
                var r = results[i];
                if (r.ok || !r.ep.host.EndsWith(".prod.warm.ingest.monitor.core.windows.net",
                                                 StringComparison.OrdinalIgnoreCase))
                    continue;
                foreach (var canary in new[] {
                    "eastus-0.prod.warm.ingest.monitor.core.windows.net",
                    "westus-0.prod.warm.ingest.monitor.core.windows.net" })
                {
                    if (string.Equals(canary, r.ep.host, StringComparison.OrdinalIgnoreCase)) continue;
                    var c = await TryConnectAsync(canary, 443);
                    if (c.ok)
                    {
                        results[i] = (r.ep, ok: true, ms: c.ms,
                            err: $"via-canary:{canary} ({c.ms}ms) — local region cluster refused probe");
                        break;
                    }
                }
            }

            // For 168.63.129.16:80 the user-mode probe will legitimately be
            // denied by the Azure Guest Agent's WFP filters (it restricts
            // wireserver access to SYSTEM). We therefore cannot prove
            // reachability by connecting ourselves. Instead, look at the
            // agent's own log (WaAppAgent.log) \u2014 the agent rewrites it every
            // ~30s when it successfully polls wireserver goal state. A recent
            // modification time is strong positive evidence that the agent is
            // actively heartbeating RIGHT NOW, which proves wireserver is
            // reachable from SYSTEM (including through any on-host filter such
            // as Zscaler/MDE/GSA that might otherwise break it). Only promote
            // the synthetic result to pass when that evidence is present.
            static (bool healthy, string detail) CheckAgentHeartbeat()
            {
                try
                {
                    var logPath = @"C:\WindowsAzure\Logs\WaAppAgent.log";
                    var fi = new FileInfo(logPath);
                    if (!fi.Exists) return (false, "WaAppAgent.log not present");
                    var ageSec = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalSeconds;
                    if (ageSec <= 180)
                        return (true, $"WaAppAgent.log updated {(int)ageSec}s ago");
                    return (false, $"WaAppAgent.log last updated {(int)ageSec}s ago (stale)");
                }
                catch (Exception ex)
                {
                    return (false, $"cannot read agent log: {ex.Message}");
                }
            }
            var (agentHealthy, agentDetail) = CheckAgentHeartbeat();
            if (agentHealthy)
            {
                for (int i = 0; i < results.Length; i++)
                {
                    var r = results[i];
                    if (r.ep.host == "168.63.129.16" && !r.ok)
                    {
                        results[i] = (r.ep, ok: true, ms: 0L, err: "via-agent:" + agentDetail);
                    }
                }
            }

            // Endpoints flagged as "soft": their failure doesn't single-handedly
            // fail the overall verdict, but IS still surfaced as a finding and
            // contributes to a Warning if other checks are fine.
            //
            // 168.63.129.16:80 is the Azure "wireserver" \u2014 a link-local IP used
            // for DHCP options, the guest-agent control plane, and session-host
            // health reporting. On a stock Azure VM it is reachable from
            // user-mode processes by design; a TCP timeout here almost always
            // indicates a local block, not a platform issue. Most common causes:
            //   - an outbound Windows Firewall rule applied by an Intune
            //     configuration profile or a hardened CPC security baseline,
            //   - an EDR / network-isolation policy (MDE, Crowdstrike,
            //     SentinelOne) restricting egress to link-local addresses,
            //   - a custom proxy/host-based policy rewriting or dropping
            //     traffic to RFC-reserved prefixes.
            // The guest agent uses a privileged code path and often still works
            // while user-mode is blocked, which is why CPCs "look fine" despite
            // this failing \u2014 but session-host health reporting relies on this
            // endpoint and can silently degrade. It is worth investigating.
            bool IsSoft((string host, int port, string purpose, string group) e)
                => e.host == "168.63.129.16";
            string SoftNote((string host, int port, string purpose, string group) e, string? err)
            {
                if (e.host != "168.63.129.16") return "";
                var lower = (err ?? "").ToLowerInvariant();
                // WSAEACCES (10013): socket forbidden by access permissions. On an
                // Azure VM / Cloud PC this is the EXPECTED result for user-mode
                // code. The Azure Windows Guest Agent (WaAppAgent, WFP provider
                // {308b401f-3aa1-4444-94b2-2298d7dd312f}) installs persistent
                // filters at provisioning that deny 168.63.129.16:80 to every
                // principal and then permit only NT AUTHORITY\\SYSTEM. The
                // session-host health traffic this IP carries is performed by
                // the guest agent (running as SYSTEM); user-mode reachability
                // is not required and would in fact be a security regression.
                if (lower.Contains("forbidden") || lower.Contains("access permissions") || lower.Contains("10013"))
                {
                    return "Expected. The Azure Windows Guest Agent locks 168.63.129.16:80 down to NT AUTHORITY\\SYSTEM via persistent WFP filters at VM provisioning, so user-mode processes correctly receive WSAEACCES. Session-host health reporting is performed by the guest agent (SYSTEM) and is unaffected by this probe result. No action required.";
                }
                if (lower.Contains("timeout") || lower.Contains("timed out"))
                {
                    return "Azure VMs should be able to reach the wireserver from SYSTEM. A timeout (rather than the expected 'access forbidden' from the Azure Guest Agent's WFP filters) suggests a broader outbound block \u2014 check Windows Firewall rules, Intune endpoint-security profiles, Global Secure Access traffic-forwarding profiles, and any EDR/network-isolation policy scoped to 168.63.129.16.";
                }
                return "Probe failed locally. Expected result from user-mode is 'access forbidden' (Azure Guest Agent's WFP lockdown); anything else suggests an additional block beyond the platform baseline.";
            }

            // Group and format output
            var sb = new StringBuilder();
            int passed = 0, total = 0;
            string? currentGroup = null;

            // Map wildcard-exemplar hosts to the wildcard FQDN they represent so
            // the detail mirrors the official required-FQDN table. The exemplar
            // host used to probe each wildcard rule is an implementation detail
            // and is hidden; real (non-wildcard) FQDNs are shown as-is.
            static string Display(string host) => host switch
            {
                "rdweb.wvd.microsoft.com" => "*.wvd.microsoft.com",
                "prod-r1.windows.cloud.microsoft" => "*.windows.cloud.microsoft",
                "shprf.sh.service.windows.cloud.microsoft" => "*.service.windows.cloud.microsoft",
                "sash.cloudpc.windows.static.microsoft" => "*.windows.static.microsoft",
                "eusaikpublish.microsoftaik.azure.net" => "*.microsoftaik.azure.net",
                "eus.aikcertaia.microsoft.com" => "*.aikcertaia.microsoft.com",
                _ when host.EndsWith(".prod.warm.ingest.monitor.core.windows.net", StringComparison.OrdinalIgnoreCase)
                    => "*.prod.warm.ingest.monitor.core.windows.net",
                _ => host
            };

            foreach (var r in results.OrderBy(x => x.ep.group).ThenBy(x => x.ep.host).ThenBy(x => x.ep.port))
            {
                if (r.ep.group != currentGroup)
                {
                    if (currentGroup != null) sb.AppendLine();
                    sb.AppendLine($"\u2550\u2550 {r.ep.group} \u2550\u2550");
                    currentGroup = r.ep.group;
                }
                var disp = Display(r.ep.host);
                var soft = IsSoft(r.ep);
                if (r.ok)
                {
                    if (soft && r.err != null && r.err.StartsWith("via-agent:"))
                    {
                        var detail = r.err.Substring("via-agent:".Length);
                        sb.AppendLine($"  \u2714 {disp}:{r.ep.port} \u2014 {r.ep.purpose} (verified via guest-agent heartbeat: {detail})");
                    }
                    else if (r.err != null && r.err.StartsWith("via-canary:"))
                    {
                        sb.AppendLine($"  \u2714 {disp}:{r.ep.port} \u2014 {r.ep.purpose} (wildcard verified {r.err.Substring("via-canary:".Length)})");
                    }
                    else
                    {
                        sb.AppendLine($"  \u2714 {disp}:{r.ep.port} \u2014 {r.ep.purpose} ({r.ms}ms)");
                    }
                    if (!soft) passed++;
                }
                else if (soft)
                {
                    // Expected on Azure VMs: the Guest Agent's WFP filters deny
                    // user-mode access to 168.63.129.16:80. Show as informational
                    // and do NOT count toward pass/fail or warning.
                    var lower = (r.err ?? "").ToLowerInvariant();
                    bool expected = lower.Contains("forbidden") || lower.Contains("access permissions") || lower.Contains("10013");
                    var glyph = expected ? "\u2714" : "\u2139";
                    var tail  = expected ? " (expected: Guest Agent lockdown)" : $" \u2014 {r.err}";
                    sb.AppendLine($"  {glyph} {disp}:{r.ep.port} \u2014 {r.ep.purpose}{tail}");
                    var note = SoftNote(r.ep, r.err);
                    if (!string.IsNullOrEmpty(note)) sb.AppendLine($"      note: {note}");
                }
                else
                {
                    sb.AppendLine($"  \u2718 {disp}:{r.ep.port} \u2014 {r.ep.purpose} \u2014 {r.err}");
                }
                if (!soft) total++;
            }

            // Note untestable wildcard entries
            sb.AppendLine();
            sb.AppendLine("\u2550\u2550 Other Wildcard Rules (optional, not probed) \u2550\u2550");
            sb.AppendLine("  \u2139 *.events.data.microsoft.com:443 \u2014 Telemetry (optional)");
            sb.AppendLine("  \u2139 *.prod.do.dsp.mp.microsoft.com:443 \u2014 Windows Update (optional)");
            sb.AppendLine("  \u2139 *.sfx.ms:443 \u2014 OneDrive client updates (optional)");
            sb.AppendLine("  \u2139 *.digicert.com:80 \u2014 Certificate revocation (optional)");
            sb.AppendLine("  \u2139 *.azure-dns.com / *.azure-dns.net:443 \u2014 Azure DNS (optional)");
            sb.AppendLine("  \u2139 *eh.servicebus.windows.net:443 \u2014 Event Hub diagnostic settings (optional)");
            sb.AppendLine("  Ensure these wildcard rules are configured in your firewall/proxy.");

            result.ResultValue = $"{passed}/{total} {hostLabel} endpoints reachable";
            result.DetailedInfo = sb.ToString().Trim();
            // Count any soft endpoints that failed UNEXPECTEDLY (i.e. not the
            // Azure Guest Agent's SYSTEM-only lockdown, which produces WSAEACCES
            // and is the designed behaviour on every Azure VM / Cloud PC).
            var softFailed = results.Count(r =>
            {
                if (!IsSoft(r.ep) || r.ok) return false;
                var l = (r.err ?? "").ToLowerInvariant();
                bool expected = l.Contains("forbidden") || l.Contains("access permissions") || l.Contains("10013");
                return !expected;
            });
            if (passed < total - 2) result.Status = "Failed";
            else if (passed < total || softFailed > 0) result.Status = "Warning";
            else result.Status = "Passed";
            if (result.Status != "Passed")
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines";
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    /// <summary>C-LE-03: Connection speed from Cloud PC — reuses bandwidth estimation test.</summary>
    static async Task<TestResult> RunCpcConnectionSpeed()
    {
        var r = await RunBandwidthTest();
        r.Id = "C-LE-03"; r.Name = "CPC Connection Speed"; r.Category = "cloudpc-env";
        return r;
    }

    // ═══════════════════════════════════════════
    //  SHORTPATH MANAGED NETWORK CONFIG CHECK
    // ═══════════════════════════════════════════

    /// <summary>
    /// C-LE-04: Checks RDP Shortpath for managed networks prerequisites on the session host.
    /// Validates registry config, UDP 3390 listener, and Windows Firewall inbound rule.
    /// </summary>
    static async Task<TestResult> RunCpcShortpathManagedConfig()
    {
        var result = new TestResult { Id = "C-LE-04", Name = "Shortpath Managed Config", Category = "cloudpc-env" };
        try
        {
            var sb = new StringBuilder();
            var issues = new List<string>();
            var info = new List<string>();

            // ── 1. Registry: RDP Shortpath for managed networks ──
            sb.AppendLine("══ Registry Configuration ══");
            bool legacyListenerEnabled = false;
            int configuredPort = 3390;

            try
            {
                using var tsKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
                if (tsKey != null)
                {
                    // ICE-based Shortpath (modern) — enabled by default since Windows 11 24H2 / Server 2025
                    // fUseUDPPortRedirector=1 enables the legacy direct-port listener (3390)
                    var useRedirector = tsKey.GetValue("fUseUDPPortRedirector");
                    if (useRedirector != null && Convert.ToInt32(useRedirector) == 1)
                    {
                        legacyListenerEnabled = true;
                        sb.AppendLine("  fUseUDPPortRedirector = 1 (legacy listener ENABLED)");
                        info.Add("RDP Shortpath for managed networks (legacy UDP 3390 listener) enabled — optional, only used on managed/private networks");
                    }
                    else
                    {
                        sb.AppendLine("  fUseUDPPortRedirector = 0 or not set (legacy listener disabled)");
                        sb.AppendLine("    ICE/STUN-based Shortpath may still work on supported OS versions");
                    }

                    // Custom port override
                    var portVal = tsKey.GetValue("UdpRedirectorPort");
                    if (portVal != null)
                    {
                        configuredPort = Convert.ToInt32(portVal);
                        sb.AppendLine($"  UdpRedirectorPort = {configuredPort}");
                    }
                    else if (legacyListenerEnabled)
                    {
                        sb.AppendLine($"  UdpRedirectorPort = 3390 (default — RDP Shortpath for managed networks; optional, only used on managed/private networks)");
                    }

                    // ICE candidate disabling check
                    var disableStun = tsKey.GetValue("ICEControl");
                    if (disableStun != null && Convert.ToInt32(disableStun) == 2)
                    {
                        sb.AppendLine("  ICEControl = 2 (ICE/STUN Shortpath DISABLED by policy)");
                        issues.Add("ICE/STUN Shortpath disabled by ICEControl=2");
                    }
                }
                else
                {
                    sb.AppendLine("  Registry key not found (RDP-Tcp WinStation)");
                }
            }
            catch (Exception ex) { sb.AppendLine($"  Registry read error: {ex.Message}"); }

            // Also check Group Policy override path
            try
            {
                using var gpKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services");
                if (gpKey != null)
                {
                    var gpUdpRedirector = gpKey.GetValue("fUseUDPPortRedirector");
                    if (gpUdpRedirector != null)
                    {
                        sb.AppendLine($"  GP Override: fUseUDPPortRedirector = {gpUdpRedirector}");
                        if (Convert.ToInt32(gpUdpRedirector) == 1)
                            legacyListenerEnabled = true;
                    }

                    var gpSelectTransport = gpKey.GetValue("SelectTransport");
                    if (gpSelectTransport != null && Convert.ToInt32(gpSelectTransport) == 2)
                    {
                        sb.AppendLine("  GP: SelectTransport = 2 (TCP only — ALL Shortpath disabled!)");
                        issues.Add("Group Policy forces TCP-only transport");
                    }

                    var gpDisableUdp = gpKey.GetValue("fClientDisableUDP");
                    if (gpDisableUdp != null && Convert.ToInt32(gpDisableUdp) == 1)
                    {
                        sb.AppendLine("  GP: fClientDisableUDP = 1 (UDP disabled for clients)");
                        issues.Add("Group Policy disables UDP transport");
                    }
                }
            }
            catch { /* GP key may not exist */ }

            sb.AppendLine();

            // ── 2. UDP listener check (only for legacy 3390 mode) ──
            if (legacyListenerEnabled)
            {
                sb.AppendLine($"══ UDP {configuredPort} Listener ══");
                try
                {
                    // Use .NET API to check for UDP listener (avoids spawning netstat.exe)
                    var udpListeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                        .GetActiveUdpListeners();
                    var matchingListeners = udpListeners.Where(ep => ep.Port == configuredPort).ToList();

                    if (matchingListeners.Count > 0)
                    {
                        sb.AppendLine($"  ✓ UDP port {configuredPort} is actively listening");
                        foreach (var ep in matchingListeners.Take(3))
                            sb.AppendLine($"    UDP  {ep.Address}:{ep.Port}");
                        info.Add($"UDP {configuredPort} listening");
                    }
                    else
                    {
                        sb.AppendLine($"  ✘ UDP port {configuredPort} is NOT listening");
                        sb.AppendLine($"    The RDP service may need to be restarted after enabling fUseUDPPortRedirector");
                        issues.Add($"UDP {configuredPort} not listening (restart RDP service?)");
                    }
                }
                catch (Exception ex) { sb.AppendLine($"  Listener check error: {ex.Message}"); }
                sb.AppendLine();
            }

            // ── 3. Windows Firewall: inbound UDP rule ──
            sb.AppendLine("══ Windows Firewall ══");
            try
            {
                // Read firewall rules from registry — avoids spawning powershell.exe
                var allRules = ReadFirewallRulesFromRegistry();
                var inboundAllows = allRules
                    .Where(r => r.Dir.Equals("In", StringComparison.OrdinalIgnoreCase)
                             && r.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                // Check for inbound allow rules matching Shortpath/RDP by name
                var shortpathPatterns = new[] { "Shortpath", "RDP", "3390", "Remote Desktop" };
                var matchingRules = inboundAllows
                    .Where(r => shortpathPatterns.Any(p => r.Name.Contains(p, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                bool foundRule = false;
                if (matchingRules.Count > 0)
                {
                    sb.AppendLine("  Matching inbound allow rules:");
                    foreach (var rule in matchingRules.Take(12))
                        sb.AppendLine($"    DisplayName : {rule.Name}");
                    foundRule = true;
                }

                // Also check specifically for port-based rule
                var portRules = inboundAllows
                    .Where(r => (r.Protocol == 17 || r.Protocol == 256) && // UDP or Any
                                FwPortMatches(r.LocalPort, configuredPort))
                    .ToList();

                if (portRules.Count > 0)
                {
                    sb.AppendLine($"  ✓ Inbound UDP {configuredPort} explicitly allowed:");
                    foreach (var rule in portRules.Take(5))
                        sb.AppendLine($"    {rule.Name}");
                    info.Add($"Firewall allows inbound UDP {configuredPort}");
                }
                else if (legacyListenerEnabled)
                {
                    sb.AppendLine($"  ⚠ No explicit inbound allow rule found for UDP {configuredPort}");
                    sb.AppendLine($"    Legacy Shortpath listener is enabled but firewall may block incoming connections");
                    issues.Add($"No firewall rule for inbound UDP {configuredPort}");
                }
                else if (!foundRule)
                {
                    sb.AppendLine("  No specific Shortpath firewall rules found (may not be needed for ICE/STUN mode)");
                }
            }
            catch (Exception ex) { sb.AppendLine($"  Firewall check error: {ex.Message}"); }

            sb.AppendLine();

            // ── 4. OS version check for ICE/STUN support ──
            sb.AppendLine("══ ICE/STUN Shortpath Support ══");
            var osVer = Environment.OSVersion.Version;
            // ICE-based Shortpath is supported on:
            //   Windows 11 22H2+ (build 22621+)
            //   Windows Server 2022 with KB5035857+
            //   Windows Server 2025+ (build 26100+)
            if (osVer.Build >= 26100)
            {
                sb.AppendLine($"  ✓ Windows Server 2025+ (build {osVer.Build}) — ICE Shortpath supported natively");
                info.Add("ICE Shortpath supported");
            }
            else if (osVer.Build >= 22621)
            {
                sb.AppendLine($"  ✓ Windows 11 22H2+ (build {osVer.Build}) — ICE Shortpath supported");
                info.Add("ICE Shortpath supported");
            }
            else if (osVer.Build >= 20348)
            {
                sb.AppendLine($"  ⚠ Windows Server 2022 (build {osVer.Build}) — ICE Shortpath requires KB5035857+");
                sb.AppendLine("    Check Windows Update for the latest cumulative update");
                // Not an issue per se — may be patched
            }
            else
            {
                sb.AppendLine($"  ⚠ Build {osVer.Build} — ICE Shortpath may not be supported on this OS version");
                sb.AppendLine("    Consider upgrading to Windows 11 22H2+ or Server 2025");
            }

            // ── Set status ──
            if (issues.Any(i => i.Contains("TCP-only") || i.Contains("disables UDP")))
            {
                result.Status = "Failed";
                result.ResultValue = "Shortpath blocked by Group Policy";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/configure-rdp-shortpath?tabs=managed-networks";
            }
            else if (issues.Any(i => i.Contains("ICE/STUN Shortpath disabled")))
            {
                result.Status = "Failed";
                result.ResultValue = "ICE/STUN Shortpath disabled (ICEControl=2)";
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/configure-rdp-shortpath?tabs=managed-networks";
            }
            else if (issues.Count > 0)
            {
                result.Status = "Warning";
                result.ResultValue = string.Join("; ", issues.Take(2));
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/configure-rdp-shortpath?tabs=managed-networks";
            }
            else if (legacyListenerEnabled)
            {
                result.Status = "Passed";
                result.ResultValue = $"Legacy listener (UDP {configuredPort}) + ICE/STUN ready";
            }
            else
            {
                result.Status = "Passed";
                result.ResultValue = "ICE/STUN Shortpath ready (modern mode)";
            }

            result.DetailedInfo = sb.ToString().Trim();
        }
        catch (Exception ex) { result.Status = "Error"; result.ResultValue = ex.Message; }
        return result;
    }

    // ════════════════════════════════════════════════════════════════
    //  SESSION WATCH — continuous lightweight monitoring (opt-in)
    //  Run-once snapshot is NEVER altered by anything in this region.
    // ════════════════════════════════════════════════════════════════

    /// <summary>Parses the --watch duration token. Returns seconds, or 0 for "until stopped".</summary>
    static int ParseWatchDuration(string? val)
    {
        if (string.IsNullOrWhiteSpace(val)) return 300; // bare --watch = 5 minutes
        val = val.Trim().ToLowerInvariant();
        if (val is "until-stopped" or "until" or "forever" or "0" or "inf" or "infinite") return 0;
        int mult = 1;
        if (val.EndsWith("h")) { mult = 3600; val = val[..^1]; }
        else if (val.EndsWith("m")) { mult = 60; val = val[..^1]; }
        else if (val.EndsWith("s")) { val = val[..^1]; }
        if (int.TryParse(val, out var n) && n > 0)
            return Math.Clamp(n * mult, 30, 8 * 3600); // 30s floor, 8h ceiling
        return 300;
    }

    /// <summary>Parses the --interval token (seconds). Clamped to 2–60s.</summary>
    static int ParseWatchInterval(string? val)
    {
        if (string.IsNullOrWhiteSpace(val)) return 3;
        val = val.Trim().ToLowerInvariant();
        if (val.EndsWith("s")) val = val[..^1];
        if (int.TryParse(val, out var n) && n > 0) return Math.Clamp(n, 2, 60);
        return 3;
    }

    /// <summary>
    /// Interactive prompt asking how long the continuous Session Watch should run.
    /// Returns a duration in seconds (0 = until Ctrl+C). Reuses ParseWatchDuration
    /// for free-form input (e.g. "10m", "90s", "until") and clamping; empty input
    /// accepts the default (5 minutes).
    /// </summary>
    static int PromptWatchDuration()
    {
        Console.WriteLine();
        Console.WriteLine("  How long should it run?");
        Console.WriteLine("    [1] 5 minutes   (default)");
        Console.WriteLine("    [2] 30 minutes");
        Console.WriteLine("    [3] Until I press Ctrl+C");
        Console.WriteLine("    or type a duration like 10m / 90s / 2h");
        Console.Write("  Choice [1]: ");
        var raw = Console.ReadLine();
        if (raw == null) return 300;
        raw = raw.Trim();
        if (raw.Length == 0 || raw == "1") return 300;
        if (raw == "2") return 1800;
        if (raw == "3") return 0;
        // Anything else: treat as a free-form duration token (clamped 30s–8h).
        return ParseWatchDuration(raw);
    }

    // Detects whether the run-once snapshot is the kind of result a single
    // point-in-time read can't be trusted to represent — specifically a VPN/SWG
    // that is intercepting or ambiguously routing W365/RDP traffic. Used to offer
    // the optional post-scan Session Watch. Deterministic; reads only the
    // L-TCP-07 / L-UDP-07 verdicts the snapshot already produced (no re-thresholding,
    // and a clean Passed split-tunnel never triggers it — avoids crying wolf).
    static bool ConnectionLooksVolatile(List<TestResult> results, out string reason)
    {
        reason = "";
        foreach (var id in new[] { "L-TCP-07", "L-UDP-07" })
        {
            var r = results.FirstOrDefault(x => x.Id == id);
            if (r == null) continue;
            if (r.Status == "Warning" || r.Status == "Failed")
            {
                var what = string.IsNullOrWhiteSpace(r.ResultValue) ? r.Name : r.ResultValue;
                reason = $"\u26A0 The snapshot flagged routing/tunnel interference: {what}";
                return true;
            }
        }
        return false;
    }

    static async Task RunWatchMode()
    {
        int duration = _watchDurationSeconds;
        int interval = _watchIntervalSeconds;

        // Non-interactive guard: an unbounded watch needs an interactive console
        // to be stopped (Ctrl+C). If stdin is redirected (headless / piped), bound
        // it so the process can never hang forever waiting for a stop that can't come.
        if (duration == 0 && Console.IsInputRedirected)
        {
            duration = 300;
            Console.WriteLine("  [watch] No interactive console (stdin redirected) — bounding watch to 5 minutes.");
        }

        // Reuse the gateway discovered during the run-once snapshot.
        var gatewayHost = _cachedGatewayHost;
        if (string.IsNullOrEmpty(gatewayHost))
        {
            try { var (gw, _) = await DiscoverRdpGatewayFromAfd(); gatewayHost = gw; } catch { }
        }
        if (string.IsNullOrEmpty(gatewayHost)) gatewayHost = "rdweb.wvd.microsoft.com";

        IPAddress? gatewayIp = null;
        try { gatewayIp = (await Dns.GetHostAddressesAsync(gatewayHost)).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork); } catch { }

        const string stunHost = "world.relay.avd.microsoft.com";
        IPEndPoint? stunEp = null;
        try
        {
            var sip = (await Dns.GetHostAddressesAsync(stunHost)).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (sip != null) stunEp = new IPEndPoint(sip, 3478);
        }
        catch { }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║                  SESSION WATCH                       ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine($"  Monitoring gateway : {gatewayHost}{(gatewayIp != null ? $" ({gatewayIp})" : "")}");
        Console.WriteLine($"  TURN/STUN relay    : {stunHost}:3478");
        Console.WriteLine($"  Interval           : {interval}s");
        Console.WriteLine($"  Duration           : {(duration == 0 ? "until stopped (Ctrl+C)" : FormatDuration(TimeSpan.FromSeconds(duration)))}");
        Console.WriteLine($"  Tier 1 (verdict)   : W365 route fingerprint");
        Console.WriteLine($"  Tier 2 (context)   : gateway RTT, UDP RTT/jitter/loss, DNS, egress IP, adapter/gateway/DNS changes");
        Console.WriteLine();
        if (duration == 0) Console.WriteLine("  Press Ctrl+C to stop and write the timeline.");
        Console.WriteLine();

        var samples = new List<WatchSample>();
        var events = new List<WatchEvent>();
        const int maxSamples = 5000; // ring-buffer cap (memory bound for long/unbounded runs)

        var start = DateTime.UtcNow;
        var startSw = Stopwatch.StartNew();

        // Graceful Ctrl+C stop (interactive only).
        bool stop = false;
        ConsoleCancelEventHandler? handler = null;
        if (!Console.IsInputRedirected)
        {
            handler = (_, e) => { e.Cancel = true; stop = true; };
            Console.CancelKeyPress += handler;
        }

        string? prevRouteHash = null;
        string? prevEgress = null;
        EnvFingerprint? prevEnv = null;
        int routeChangeCount = 0;
        var gatewayBaseline = new List<double>();
        int sampleNum = 0;

        try
        {
            while (!stop)
            {
                double elapsed = startSw.Elapsed.TotalSeconds;
                if (duration > 0 && elapsed >= duration) break;
                sampleNum++;
                var ts = DateTime.UtcNow;

                // Lightweight probes (sequential to keep system load minimal).
                double? gwRtt = gatewayIp != null ? await SampleTcpConnectRtt(gatewayIp, 443) : null;
                var (sRtt, jitter, loss, egress) = stunEp != null
                    ? await SampleStunBurst(stunEp)
                    : ((double?)null, (double?)null, (double?)null, (string?)null);
                double? dns = await SampleDnsResolve(gatewayHost);
                string routeHash = SampleRelevantRouteFingerprint(gatewayIp != null ? IpToUint32(gatewayIp) : null);
                var env = CaptureEnvFingerprint();

                var anomalies = new List<string>();

                // ── Tier 1: W365 route change (verdict-driving) ──
                bool routeChanged = false;
                if (prevRouteHash != null && routeHash != "unknown" && routeHash != prevRouteHash)
                {
                    routeChanged = true;
                    routeChangeCount++;
                    anomalies.Add("route");
                    var sev = routeChangeCount >= 2 ? "critical" : "warning";
                    events.Add(new WatchEvent
                    {
                        ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = sev, Track = "route",
                        Message = $"W365-relevant route set changed (change #{routeChangeCount}) — the gateway/exclusion routing shifted (direct ⇄ tunnel)."
                    });
                }
                if (routeHash != "unknown") prevRouteHash = routeHash;

                // ── Tier 2: transport quality (context, non-verdict) ──
                if (gwRtt.HasValue)
                {
                    if (gatewayBaseline.Count >= 3)
                    {
                        var baseMed = Median(gatewayBaseline);
                        if (gwRtt.Value > Math.Max(baseMed * 1.8, baseMed + 40) && gwRtt.Value > 60)
                        {
                            anomalies.Add("gatewayRtt");
                            events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = "warning", Track = "gatewayRtt",
                                Message = $"Gateway RTT spiked to {gwRtt.Value:F0}ms (baseline ~{baseMed:F0}ms)." });
                        }
                    }
                    if (gatewayBaseline.Count < 20) gatewayBaseline.Add(gwRtt.Value);
                }
                else
                {
                    anomalies.Add("gatewayRtt");
                    events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = "warning", Track = "gatewayRtt",
                        Message = "Gateway TCP 443 connect failed/timed out." });
                }

                if (jitter.HasValue && jitter.Value > 30)
                {
                    anomalies.Add("jitter");
                    events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = jitter.Value > 50 ? "critical" : "warning", Track = "jitter",
                        Message = $"UDP jitter {jitter.Value:F0}ms to TURN relay — RDP Shortpath quality degraded." });
                }

                if (loss.HasValue && loss.Value > 2)
                {
                    anomalies.Add("loss");
                    events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = loss.Value > 5 ? "critical" : "warning", Track = "loss",
                        Message = $"UDP packet loss {loss.Value:F0}% to TURN relay (UDP 3478)." });
                }

                if (dns.HasValue && dns.Value > 300)
                {
                    anomalies.Add("dns");
                    events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = dns.Value > 800 ? "critical" : "warning", Track = "dns",
                        Message = $"DNS resolution slow ({dns.Value:F0}ms) for {gatewayHost}." });
                }

                if (egress != null && prevEgress != null && egress != prevEgress)
                {
                    anomalies.Add("egress");
                    events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "anomaly", Severity = "warning", Track = "egress",
                        Message = $"Egress IP changed: {prevEgress} → {egress} (re-NAT / VPN reconnect / PoP change)." });
                }
                if (egress != null) prevEgress = egress;

                // ── Tier 2 context: environment changes (explain the Tier 1 flip) ──
                if (prevEnv.HasValue)
                {
                    var p = prevEnv.Value;
                    if (p.VpnAdapters != env.VpnAdapters)
                        events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "context", Severity = "info", Track = "vpnAdapter",
                            Message = DescribeChange("VPN/tunnel adapter", p.VpnAdapters, env.VpnAdapters) });
                    if (p.DefaultGateways != env.DefaultGateways)
                        events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "context", Severity = "info", Track = "defaultGateway",
                            Message = DescribeChange("Default gateway", p.DefaultGateways, env.DefaultGateways) });
                    if (p.DnsServers != env.DnsServers)
                        events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "context", Severity = "info", Track = "dnsServer",
                            Message = DescribeChange("DNS servers", p.DnsServers, env.DnsServers) });
                    if (p.Adapters != env.Adapters)
                        events.Add(new WatchEvent { ElapsedSeconds = Math.Round(elapsed, 1), Timestamp = ts, Kind = "context", Severity = "info", Track = "adapters",
                            Message = DescribeChange("Active adapters", p.Adapters, env.Adapters) });
                }
                prevEnv = env;

                var sample = new WatchSample
                {
                    Timestamp = ts,
                    ElapsedSeconds = Math.Round(elapsed, 1),
                    GatewayRttMs = gwRtt.HasValue ? Math.Round(gwRtt.Value, 1) : null,
                    StunRttMs = sRtt.HasValue ? Math.Round(sRtt.Value, 1) : null,
                    JitterMs = jitter.HasValue ? Math.Round(jitter.Value, 1) : null,
                    LossPct = loss.HasValue ? Math.Round(loss.Value, 1) : null,
                    DnsMs = dns.HasValue ? Math.Round(dns.Value, 1) : null,
                    RouteHash = routeHash,
                    EgressIp = egress,
                    RouteChanged = routeChanged,
                    Anomalies = anomalies
                };
                samples.Add(sample);
                if (samples.Count > maxSamples) samples.RemoveAt(0);

                PrintWatchSampleLine(sampleNum, sample);

                // Wait the interval, but break promptly on stop / duration end.
                for (int w = 0; w < interval * 10 && !stop; w++)
                {
                    if (duration > 0 && startSw.Elapsed.TotalSeconds >= duration) break;
                    await Task.Delay(100);
                }
            }
        }
        finally
        {
            if (handler != null) Console.CancelKeyPress -= handler;
        }

        // ── Verdict ──
        int critEvents = events.Count(e => e.Severity == "critical");
        int warnEvents = events.Count(e => e.Severity == "warning");
        string verdict, summary;
        if (routeChangeCount >= 2)
        {
            verdict = "intermittent-fault";
            summary = $"Intermittent fault confirmed: the W365-relevant routing changed {routeChangeCount} times during the watch — the session path is flapping (typically a VPN/SWG reconnecting and reprogramming routes).";
        }
        else if (routeChangeCount == 1)
        {
            verdict = "changed";
            summary = "The W365 routing path changed once during the watch — a single transition (e.g. a VPN connecting or disconnecting). Review the timeline for the correlated context event.";
        }
        else if (critEvents > 0)
        {
            verdict = "degraded";
            summary = $"Transport quality degraded during the watch ({critEvents} critical, {warnEvents} warning events) although the W365 route stayed stable.";
        }
        else if (warnEvents > 0)
        {
            verdict = "warning";
            summary = $"Minor variability observed ({warnEvents} warning events); the W365 route stayed stable throughout.";
        }
        else
        {
            verdict = "stable";
            summary = $"Stable for the full watch ({samples.Count} samples over {FormatDuration(startSw.Elapsed)}). No route changes or quality anomalies.";
        }

        var output = new WatchOutput
        {
            Timestamp = start,
            EndTimestamp = DateTime.UtcNow,
            ScannerVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown",
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            ScanMode = _isCloudPcMode ? "cloudpc" : "client",
            HostType = _isCloudPcMode ? (_hostType ?? "cloudpc") : null,
            AzureRegion = _isCloudPcMode ? _azureVmRegion : null,
            GatewayHost = gatewayHost,
            StunHost = stunHost,
            IntervalSeconds = interval,
            RequestedDurationSeconds = _watchDurationSeconds,
            RouteChangeCount = routeChangeCount,
            Verdict = verdict,
            Summary = summary,
            Samples = samples,
            Events = events
        };

        await WriteWatchTimeline(output);
        PrintWatchSummary(output);
        if (!_noBrowser)
            await OpenBrowserWithWatch(output);
    }

    /// <summary>Per-sample environment fingerprint used to detect context changes.</summary>
    readonly record struct EnvFingerprint(string VpnAdapters, string DefaultGateways, string DnsServers, string Adapters);

    static EnvFingerprint CaptureEnvFingerprint()
    {
        var vpn = new List<string>();
        var gws = new SortedSet<string>(StringComparer.Ordinal);
        var dns = new SortedSet<string>(StringComparer.Ordinal);
        var adapters = new SortedSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = ni.GetIPProperties();
                var v4 = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString()).ToList();
                if (v4.Count == 0) continue;
                adapters.Add(ni.Name);
                bool isVpn = ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel
                    || ni.NetworkInterfaceType == NetworkInterfaceType.Ppp
                    || Regex.IsMatch(ni.Name + " " + ni.Description,
                        "vpn|azvpn|tunnel|wireguard|zscaler|globalprotect|anyconnect|tailscale|gsa|private access|forticlient|openvpn",
                        RegexOptions.IgnoreCase);
                if (isVpn) vpn.Add($"{ni.Name}[{string.Join(",", v4)}]");
                foreach (var g in props.GatewayAddresses.Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                    gws.Add(g.Address.ToString());
                foreach (var d in props.DnsAddresses.Where(d => d.AddressFamily == AddressFamily.InterNetwork))
                    dns.Add(d.ToString());
            }
        }
        catch { }
        vpn.Sort(StringComparer.Ordinal);
        return new EnvFingerprint(
            string.Join(",", vpn),
            string.Join(",", gws),
            string.Join(",", dns),
            string.Join(",", adapters));
    }

    static async Task<double?> SampleTcpConnectRtt(IPAddress ip, int port)
    {
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            var sw = Stopwatch.StartNew();
            var connectTask = sock.ConnectAsync(ip, port);
            if (await Task.WhenAny(connectTask, Task.Delay(3000)) == connectTask && sock.Connected)
            {
                sw.Stop();
                return sw.Elapsed.TotalMilliseconds;
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Sends a short burst of STUN binding requests to measure UDP RTT, jitter,
    /// loss, and the reflexive egress IP in a single cheap sample.
    /// </summary>
    static async Task<(double? rttMs, double? jitterMs, double? lossPct, string? egress)> SampleStunBurst(IPEndPoint stunEp, int count = 5)
    {
        var rtts = new List<double>();
        string? egress = null;
        int sent = 0, recv = 0;
        try
        {
            using var udp = new UdpClient();
            for (int i = 0; i < count; i++)
            {
                sent++;
                var req = BuildStunRequest();
                var sw = Stopwatch.StartNew();
                try
                {
                    await udp.SendAsync(req, req.Length, stunEp);
                    using var cts = new CancellationTokenSource(600);
                    var res = await udp.ReceiveAsync(cts.Token);
                    sw.Stop();
                    recv++;
                    rtts.Add(sw.Elapsed.TotalMilliseconds);
                    var mapped = ParseStunMappedAddress(res.Buffer);
                    if (mapped != null) egress = mapped.Split(':')[0];
                }
                catch { /* lost / timed out */ }
                await Task.Delay(15);
            }
        }
        catch { }
        if (sent == 0) return (null, null, null, null);
        double loss = 100.0 * (sent - recv) / sent;
        double? mean = rtts.Count > 0 ? rtts.Average() : null;
        double? jitter = null;
        if (rtts.Count >= 2)
        {
            double s = 0;
            for (int i = 1; i < rtts.Count; i++) s += Math.Abs(rtts[i] - rtts[i - 1]);
            jitter = s / (rtts.Count - 1);
        }
        return (mean, jitter, loss, egress);
    }

    static async Task<double?> SampleDnsResolve(string host)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            var addrs = await Dns.GetHostAddressesAsync(host);
            sw.Stop();
            return addrs.Length > 0 ? sw.Elapsed.TotalMilliseconds : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Hashes ONLY the W365-relevant routes (default route, the 40.64.0.0/13
    /// supernet, the 40.64.144.0/20 and 51.5.0.0/16 exclusions, and the resolved
    /// gateway /32). This isolates the signal that actually affects the session
    /// from unrelated route-table churn.
    /// </summary>
    static string SampleRelevantRouteFingerprint(uint? gatewayIp)
    {
        try
        {
            // Read the IPv4 forwarding table via the in-process Win32 API rather than
            // spawning `route print -4`. On some machines `route.exe` blocks for ~25s,
            // which would consume the entire sample interval; GetIpForwardTable returns
            // in well under a millisecond and never spawns a process.
            var routes = EnumerateForwardRoutesFast();
            if (routes.Count == 0) return "unknown";

            var targets = new (uint net, int len)[]
            {
                (IpToUint32(IPAddress.Parse("40.64.0.0")), 13),
                (IpToUint32(IPAddress.Parse("40.64.144.0")), 20),
                (IpToUint32(IPAddress.Parse("51.5.0.0")), 16),
            };

            var relevant = new List<string>();
            foreach (var r in routes)
            {
                bool keep = r.prefixLen == 0; // default route
                if (!keep)
                    foreach (var (net, len) in targets)
                        if (CidrsOverlap(r.dest, r.prefixLen, net, len)) { keep = true; break; }
                if (!keep && gatewayIp.HasValue)
                {
                    uint mask = r.prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - r.prefixLen);
                    if ((gatewayIp.Value & mask) == r.dest) keep = true;
                }
                if (keep)
                    relevant.Add($"{r.destStr}/{r.prefixLen} via {r.gateway} dev {r.ifIp} m{r.metric}");
            }
            relevant.Sort(StringComparer.Ordinal);
            var canonical = string.Join("\n", relevant);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
            return hash[..12];
        }
        catch { return "unknown"; }
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MIB_IPFORWARDROW
    {
        public uint dwForwardDest;
        public uint dwForwardMask;
        public uint dwForwardPolicy;
        public uint dwForwardNextHop;
        public uint dwForwardIfIndex;
        public uint dwForwardType;
        public uint dwForwardProto;
        public uint dwForwardAge;
        public uint dwForwardNextHopAS;
        public uint dwForwardMetric1;
        public uint dwForwardMetric2;
        public uint dwForwardMetric3;
        public uint dwForwardMetric4;
        public uint dwForwardMetric5;
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

    /// <summary>
    /// Reads the IPv4 forwarding table directly via the Win32 IP Helper API.
    /// Returns the same <see cref="RouteEntry"/> shape as <c>ParseRouteTable</c> so it
    /// can be a drop-in source, but with no process spawn (sub-millisecond) — used by
    /// the Session Watch sampler where <c>route.exe</c>'s occasional ~25s stalls would
    /// otherwise dominate the sample interval.
    /// </summary>
    static List<RouteEntry> EnumerateForwardRoutesFast()
    {
        var result = new List<RouteEntry>();
        int size = 0;
        // First call sizes the buffer (returns ERROR_INSUFFICIENT_BUFFER).
        GetIpForwardTable(IntPtr.Zero, ref size, true);
        if (size == 0) return result;
        IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpForwardTable(buffer, ref size, true) != 0) return result; // 0 == NO_ERROR
            int numEntries = System.Runtime.InteropServices.Marshal.ReadInt32(buffer);

            // Map interface index -> primary IPv4 address so the canonical route string
            // matches the "dev <ifIp>" form used by the route-print parser.
            var ifMap = new Dictionary<uint, string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    try
                    {
                        var props = ni.GetIPProperties();
                        var v4p = props.GetIPv4Properties();
                        if (v4p == null) continue;
                        var addr = props.UnicastAddresses
                            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                        if (addr != null) ifMap[(uint)v4p.Index] = addr.Address.ToString();
                    }
                    catch { }
                }
            }
            catch { }

            int rowSize = System.Runtime.InteropServices.Marshal.SizeOf<MIB_IPFORWARDROW>();
            IntPtr rowPtr = buffer + 4; // skip the leading dwNumEntries field
            for (int i = 0; i < numEntries; i++)
            {
                var row = System.Runtime.InteropServices.Marshal.PtrToStructure<MIB_IPFORWARDROW>(rowPtr + i * rowSize);
                uint dest = IpToUint32(new IPAddress(row.dwForwardDest));
                uint mask = IpToUint32(new IPAddress(row.dwForwardMask));
                int prefixLen = MaskToPrefixLen(mask);
                string gateway = Uint32ToIp(IpToUint32(new IPAddress(row.dwForwardNextHop)));
                ifMap.TryGetValue(row.dwForwardIfIndex, out var ifIp);
                result.Add(new RouteEntry(dest, prefixLen, gateway, ifIp ?? "", (int)row.dwForwardMetric1, Uint32ToIp(dest)));
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    static bool CidrsOverlap(uint a, int aLen, uint b, int bLen)
    {
        int minLen = Math.Min(aLen, bLen);
        uint mask = minLen == 0 ? 0 : 0xFFFFFFFF << (32 - minLen);
        return (a & mask) == (b & mask);
    }

    static double Median(List<double> xs)
    {
        if (xs.Count == 0) return 0;
        var s = xs.OrderBy(x => x).ToList();
        int n = s.Count;
        return n % 2 == 1 ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2.0;
    }

    static string FormatDuration(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}h{t.Minutes}m"
        : t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes}m{t.Seconds}s"
        : $"{t.Seconds}s";

    static string DescribeChange(string what, string before, string after)
    {
        if (string.IsNullOrEmpty(before) && !string.IsNullOrEmpty(after)) return $"{what} appeared: {after}";
        if (!string.IsNullOrEmpty(before) && string.IsNullOrEmpty(after)) return $"{what} disappeared: {before}";
        return $"{what} changed: '{before}' → '{after}'";
    }

    static void PrintWatchSampleLine(int n, WatchSample s)
    {
        var parts = new List<string>
        {
            $"#{n,-4}{s.ElapsedSeconds,6:F0}s",
            s.GatewayRttMs.HasValue ? $"gw {s.GatewayRttMs.Value,5:F0}ms" : "gw   --  ",
            s.StunRttMs.HasValue   ? $"udp {s.StunRttMs.Value,4:F0}ms" : "udp  -- ",
            s.JitterMs.HasValue    ? $"jit {s.JitterMs.Value,3:F0}ms" : "jit -- ",
            s.LossPct.HasValue     ? $"loss {s.LossPct.Value,3:F0}%" : "loss --",
            s.DnsMs.HasValue       ? $"dns {s.DnsMs.Value,4:F0}ms" : "dns  -- ",
        };
        var line = "  " + string.Join("  ", parts);
        if (s.RouteChanged)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            line += "  ⚠ ROUTE CHANGED";
        }
        else if (s.Anomalies.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            line += "  ⚠ " + string.Join(",", s.Anomalies);
        }
        Console.WriteLine(line);
        Console.ResetColor();
    }

    static void PrintWatchSummary(WatchOutput o)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.WriteLine("  SESSION WATCH SUMMARY");
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.ResetColor();
        Console.WriteLine($"  Samples:        {o.Samples.Count}  (every {o.IntervalSeconds}s)");
        Console.WriteLine($"  Route changes:  {o.RouteChangeCount}");
        Console.WriteLine($"  Events:         {o.Events.Count}");
        var color = o.Verdict switch
        {
            "intermittent-fault" => ConsoleColor.Red,
            "degraded" => ConsoleColor.Red,
            "changed" => ConsoleColor.Yellow,
            "warning" => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = color;
        Console.WriteLine($"  Verdict:        {o.Verdict.ToUpperInvariant()}");
        Console.ResetColor();
        Console.WriteLine($"  {o.Summary}");
        Console.WriteLine();
    }

    static async Task WriteWatchTimeline(WatchOutput output)
    {
        try
        {
            var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.WatchOutput);
            const string path = "W365WatchTimeline.json";
            await File.WriteAllTextAsync(path, json, Encoding.UTF8);
            Console.WriteLine($"  Watch timeline saved to: {Path.GetFullPath(path)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Could not write watch timeline: {ex.Message}");
        }
    }

    static async Task OpenBrowserWithWatch(WatchOutput output)
    {
        var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.WatchOutput);
        try
        {
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var deflate = new DeflateStream(ms, CompressionLevel.SmallestSize))
                {
                    deflate.Write(Encoding.UTF8.GetBytes(json));
                }
                compressed = ms.ToArray();
            }
            var b64 = Convert.ToBase64String(compressed)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            var cb = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var baseUrl = $"{DashboardBaseUrl}?_cb={cb}&view=watch";
            // BOTH payloads live in the URL HASH (the fragment after '#'), which is
            // NEVER sent to the server — so GitHub Pages can't reject the request
            // with HTTP 414 "URI Too Long" no matter how large the snapshot is.
            // zwatch MUST come first so the dashboard's position-0 watch detectors
            // (`hash.indexOf('#zwatch=')===0`) fire; the run-once snapshot is then
            // appended as an &zresults= sub-param so the watch tab's "Snapshot"
            // sub-tab shows the full results instead of being blank.
            var hashUrl = $"{baseUrl}#zwatch={b64}";
            if (!string.IsNullOrEmpty(_snapshotResultsB64))
                hashUrl += $"&zresults={_snapshotResultsB64}";

            Console.WriteLine($"  Opening Watch timeline in browser...");

            bool opened = false;
            try
            {
                var browserPath = GetDefaultBrowserPath();
                if (!string.IsNullOrEmpty(browserPath) && File.Exists(browserPath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = browserPath,
                        Arguments = hashUrl,
                        UseShellExecute = false
                    });
                    opened = true;
                }
            }
            catch { }

            if (!opened)
            {
                try
                {
                    var redirectHtml = $@"<!DOCTYPE html>
<html><head><title>Opening W365 Watch...</title></head>
<body><p>Redirecting to Watch timeline...</p>
<script>window.location.replace({EscapeJsString(hashUrl)});</script>
<p><a href=""{System.Security.SecurityElement.Escape(hashUrl)}"">Click here if not redirected automatically</a></p>
</body></html>";
                    var redirectPath = Path.Combine(Path.GetTempPath(), "W365WatchRedirect.html");
                    await File.WriteAllTextAsync(redirectPath, redirectHtml, Encoding.UTF8);
                    Process.Start(new ProcessStartInfo { FileName = redirectPath, UseShellExecute = true });
                    opened = true;
                }
                catch { }
            }

            if (!opened)
            {
                Console.WriteLine("  Could not auto-open the browser. Drag W365WatchTimeline.json onto the dashboard.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Could not open Watch view: {ex.Message}");
            Console.WriteLine($"  Drag W365WatchTimeline.json onto {DashboardBaseUrl}");
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

    [JsonPropertyName("scannerVersion")]
    public string ScannerVersion { get; set; } = string.Empty;

    [JsonPropertyName("machineName")]
    public string MachineName { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("dotNetVersion")]
    public string DotNetVersion { get; set; } = string.Empty;

    [JsonPropertyName("scanMode")]
    public string ScanMode { get; set; } = "client";

    [JsonPropertyName("hostType")]
    public string? HostType { get; set; }

    [JsonPropertyName("azureRegion")]
    public string? AzureRegion { get; set; }

    [JsonPropertyName("results")]
    public List<TestResult> Results { get; set; } = [];
}

// ── Session Watch timeline models ──────────────────────────────────

class WatchOutput
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "watch-timeline";

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("endTimestamp")]
    public DateTime EndTimestamp { get; set; }

    [JsonPropertyName("scannerVersion")]
    public string ScannerVersion { get; set; } = string.Empty;

    [JsonPropertyName("machineName")]
    public string MachineName { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("scanMode")]
    public string ScanMode { get; set; } = "client";

    [JsonPropertyName("hostType")]
    public string? HostType { get; set; }

    [JsonPropertyName("azureRegion")]
    public string? AzureRegion { get; set; }

    [JsonPropertyName("gatewayHost")]
    public string GatewayHost { get; set; } = string.Empty;

    [JsonPropertyName("stunHost")]
    public string StunHost { get; set; } = string.Empty;

    [JsonPropertyName("intervalSeconds")]
    public int IntervalSeconds { get; set; }

    [JsonPropertyName("requestedDurationSeconds")]
    public int RequestedDurationSeconds { get; set; }

    [JsonPropertyName("routeChangeCount")]
    public int RouteChangeCount { get; set; }

    [JsonPropertyName("verdict")]
    public string Verdict { get; set; } = "stable";

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("samples")]
    public List<WatchSample> Samples { get; set; } = [];

    [JsonPropertyName("events")]
    public List<WatchEvent> Events { get; set; } = [];
}

class WatchSample
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("elapsedSeconds")]
    public double ElapsedSeconds { get; set; }

    [JsonPropertyName("gatewayRttMs")]
    public double? GatewayRttMs { get; set; }

    [JsonPropertyName("stunRttMs")]
    public double? StunRttMs { get; set; }

    [JsonPropertyName("jitterMs")]
    public double? JitterMs { get; set; }

    [JsonPropertyName("lossPct")]
    public double? LossPct { get; set; }

    [JsonPropertyName("dnsMs")]
    public double? DnsMs { get; set; }

    [JsonPropertyName("routeHash")]
    public string RouteHash { get; set; } = string.Empty;

    [JsonPropertyName("egressIp")]
    public string? EgressIp { get; set; }

    [JsonPropertyName("routeChanged")]
    public bool RouteChanged { get; set; }

    [JsonPropertyName("anomalies")]
    public List<string> Anomalies { get; set; } = [];
}

class WatchEvent
{
    [JsonPropertyName("elapsedSeconds")]
    public double ElapsedSeconds { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "info";

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "info";

    [JsonPropertyName("track")]
    public string Track { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
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
[JsonSerializable(typeof(WatchOutput))]
[JsonSerializable(typeof(WatchSample))]
[JsonSerializable(typeof(WatchEvent))]
[JsonSerializable(typeof(List<WatchSample>))]
[JsonSerializable(typeof(List<WatchEvent>))]
internal partial class ScanJsonContext : JsonSerializerContext
{
}
