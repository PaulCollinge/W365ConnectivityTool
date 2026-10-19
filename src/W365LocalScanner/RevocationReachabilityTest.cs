using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace W365LocalScanner;

partial class Program
{
    private const int RevocationProbeTimeoutMs = 10_000;
    private const int RevocationBodyCapBytes = 64 * 1024;

    // HTTPS endpoints whose certificate chains are sampled. Together they
    // cover every issuing CA family the session-host and Arc required lists
    // use today (DigiCert G2, Microsoft TLS G2 RSA/ECC, and the Microsoft TLS
    // RSA Root G2 cross-certificate issued by DigiCert Global Root G2).
    private static readonly string[] RevocationSampleHosts =
    [
        "login.microsoftonline.com",
        "rdweb.wvd.microsoft.com",
        "gcs.prod.monitoring.core.windows.net",
        "mrsglobalsteus2prod.blob.core.windows.net",
        "catalogartifact.azureedge.net",
        "prod-r1.windows.cloud.microsoft",
        "sash.cloudpc.windows.static.microsoft"
    ];

    private static readonly string[] PublicRootMarkers =
        ["DigiCert", "Microsoft", "Baltimore", "GlobalSign", "Entrust"];

    static Task<TestResult> RunRevocationReachability() =>
        RunRevocationReachability(WinHttpProxyConfiguration.Read(), NativeCertificateRetrieval.FetchAsync);

    /// <param name="winHttp">Machine WinHTTP route used for the primary probe.</param>
    /// <param name="nativeFetch">
    /// Windows-native (cryptnet) retrieval used to cross-check failures, or
    /// null to skip it. Injectable so tests can simulate either outcome.
    /// </param>
    internal static async Task<TestResult> RunRevocationReachability(
        WinHttpProxyConfiguration winHttp,
        Func<Uri, int, Task<NativeFetchResult>>? nativeFetch)
    {
        var result = new TestResult
        {
            Id = "C-PKI-01",
            Name = "Certificate Revocation Endpoints",
            Category = "cloudpc-env"
        };

        var clients = new Dictionary<string, HttpClient>(StringComparer.Ordinal);
        try
        {
            bool authoritative = winHttp.Available;
            var captured = new ConcurrentDictionary<string, X509Certificate2[]>(StringComparer.OrdinalIgnoreCase);

            bool CaptureChain(HttpRequestMessage request, X509Certificate2? _, X509Chain? chain, SslPolicyErrors errors)
            {
                if (request.RequestUri != null && chain != null && chain.ChainElements.Count > 0)
                {
                    captured[request.RequestUri.Host] = chain.ChainElements
                        .Select(element => new X509Certificate2(element.Certificate.RawData))
                        .ToArray();
                }
                return errors == SslPolicyErrors.None;
            }

            // Chain collection may authenticate to the proxy as the signed-in
            // user (it only fetches public certificates). Revocation probes
            // must not: SYSTEM services cannot use the user's proxy
            // credentials, so a 407 there is a real finding.
            HttpClient ClientFor(Uri uri, bool authenticate, out string routeLabel)
            {
                Uri? proxy;
                if (winHttp.Available)
                {
                    var route = winHttp.Resolve(uri);
                    proxy = route.UseProxy ? route.ProxyUri : null;
                    routeLabel = proxy != null
                        ? $"via {ArcProxyConfiguration.FormatProxyForDisplay(proxy)}"
                        : "direct";
                }
                else
                {
                    var resolved = WebRequest.GetSystemWebProxy().GetProxy(uri);
                    proxy = resolved != null && resolved != uri ? resolved : null;
                    routeLabel = (proxy != null
                        ? $"via {ArcProxyConfiguration.FormatProxyForDisplay(proxy)}"
                        : "direct") + ", invoking-user route";
                }

                var key = (proxy?.AbsoluteUri ?? "direct") + (authenticate ? "|auth" : "|anon");
                lock (clients)
                {
                    if (clients.TryGetValue(key, out var existing))
                        return existing;

                    var handler = new HttpClientHandler
                    {
                        AutomaticDecompression = DecompressionMethods.All,
                        ClientCertificateOptions = ClientCertificateOption.Manual,
                        ServerCertificateCustomValidationCallback = CaptureChain
                    };
                    if (proxy != null)
                        handler.Proxy = new WebProxy(proxy) { Credentials = authenticate ? CredentialCache.DefaultCredentials : null };
                    else
                        handler.UseProxy = false;

                    var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                    clients[key] = client;
                    return client;
                }
            }

            // ── 1. Collect the chains the endpoints actually present ──
            var hosts = new List<string>(RevocationSampleHosts);
            if (IsHybridHost())
            {
                var region = (_arcMetadata?.Location ?? "eastus").Replace(" ", "").ToLowerInvariant();
                hosts.AddRange(ArcEndpointCatalog.Build(new(false, null, null, null), region)
                    .Where(endpoint => endpoint.Port == 443)
                    .Select(endpoint => endpoint.Host));
            }
            hosts = hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            var collectionErrors = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var gate = new SemaphoreSlim(6))
            {
                await Task.WhenAll(hosts.Select(async host =>
                {
                    await gate.WaitAsync();
                    try
                    {
                        var uri = new Uri($"https://{host}/");
                        var client = ClientFor(uri, authenticate: true, out var route);
                        using var cts = new CancellationTokenSource(RevocationProbeTimeoutMs);
                        using var request = new HttpRequestMessage(HttpMethod.Head, uri);
                        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                    }
                    catch (Exception ex) when (!captured.ContainsKey(host))
                    {
                        collectionErrors[host] = ex is OperationCanceledException
                            ? $"timeout ({RevocationProbeTimeoutMs / 1000}s)"
                            : ex.InnerException?.Message ?? ex.Message;
                    }
                    catch
                    {
                        // The chain was captured during the handshake; a later
                        // HTTP-level failure doesn't matter for this test.
                    }
                    finally
                    {
                        gate.Release();
                    }
                }));
            }

            // ── 2. Group by issuing CA + URL set ──
            var targets = new Dictionary<string, RevocationTarget>(StringComparer.Ordinal);
            var inspectedHosts = new List<string>();
            foreach (var (host, chain) in captured.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                var root = chain[^1];
                if (!PublicRootMarkers.Any(marker => root.Subject.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                    inspectedHosts.Add($"{host} (chain ends at '{root.GetNameInfo(X509NameType.SimpleName, false)}')");

                for (int i = 0; i < chain.Length - 1; i++)
                {
                    var subject = chain[i];
                    var issuer = chain[i + 1];
                    var urls = RevocationAnalysis.ExtractUrls(subject);
                    if (urls.Count == 0)
                        continue;

                    // Group by issuing CA. Microsoft partitions its CRLs, so
                    // sibling leaves list different CRL URLs on the same hosts;
                    // merging keeps one section per CA instead of one per leaf.
                    var key = issuer.Thumbprint;
                    if (!targets.TryGetValue(key, out var target))
                    {
                        target = new RevocationTarget(subject, issuer);
                        targets[key] = target;
                    }
                    foreach (var url in urls)
                    {
                        if (!target.Urls.Contains(url))
                            target.Urls.Add(url);
                    }
                    target.UsedBy.Add(host);
                    target.Subjects.Add(i == 0
                        ? $"{host} server certificate"
                        : subject.GetNameInfo(X509NameType.SimpleName, false));
                }
            }

            // ── 3. Probe each unique URL on the machine route ──
            var probeCache = new ConcurrentDictionary<string, Lazy<Task<RevocationProbeResult>>>(StringComparer.Ordinal);
            using var probeGate = new SemaphoreSlim(8);

            // A proxy that silently drops a host drops every URL on it. Probe
            // each host once while its state is unknown, and reuse a
            // connection-level failure (timeout / unreachable) for the other
            // URLs on that host instead of paying the timeout per URL.
            // Content-level blocks stay per-URL because proxies filter paths.
            var routeHosts = new HostProbeMemo<RevocationProbeResult>();
            var nativeHosts = new HostProbeMemo<NativeFetchResult>();

            async Task<RevocationProbeResult> FetchOnRouteAsync(
                Uri uri,
                byte[]? ocspRequest,
                Func<int, string?, byte[], RevocationProbeResult> classify)
            {
                await probeGate.WaitAsync();
                var client = ClientFor(uri, authenticate: false, out var route);
                var stopwatch = Stopwatch.StartNew();
                try
                {
                    using var cts = new CancellationTokenSource(RevocationProbeTimeoutMs);
                    using var request = new HttpRequestMessage(ocspRequest == null ? HttpMethod.Get : HttpMethod.Post, uri);
                    if (ocspRequest != null)
                    {
                        request.Content = new ByteArrayContent(ocspRequest);
                        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
                    }
                    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                    var body = await ReadCappedAsync(response, RevocationBodyCapBytes, cts.Token);
                    stopwatch.Stop();
                    var classified = classify((int)response.StatusCode, response.Content.Headers.ContentType?.MediaType, body);
                    return classified with { Detail = $"{classified.Detail} ({stopwatch.ElapsedMilliseconds}ms, {route})" };
                }
                catch (OperationCanceledException)
                {
                    return new(RevocationProbeOutcome.Timeout,
                        $"no response within {RevocationProbeTimeoutMs / 1000}s ({route}) — silently dropped");
                }
                catch (Exception ex)
                {
                    return new(RevocationProbeOutcome.Unreachable, $"{ex.InnerException?.Message ?? ex.Message} ({route})");
                }
                finally
                {
                    probeGate.Release();
                }
            }

            Task<RevocationProbeResult> FetchAsync(
                Uri uri,
                byte[]? ocspRequest,
                Func<int, string?, byte[], RevocationProbeResult> classify) =>
                routeHosts.RunAsync(
                    uri.Host,
                    () => FetchOnRouteAsync(uri, ocspRequest, classify),
                    r => r.Outcome == RevocationProbeOutcome.Valid,
                    r => r.Outcome is RevocationProbeOutcome.Timeout or RevocationProbeOutcome.Unreachable,
                    r => r with { Detail = $"{r.Detail} [same host as an earlier request; not retried]" });

            async Task<NativeFetchResult> FetchNativeAsync(Uri uri)
            {
                await probeGate.WaitAsync();
                try
                {
                    return await nativeFetch!(uri, RevocationProbeTimeoutMs);
                }
                finally
                {
                    probeGate.Release();
                }
            }

            // A failure on the static WinHTTP route may only mean Windows
            // reaches the URL another way (WPAD/PAC). Ask Windows' own
            // certificate retrieval before reporting a block, so the result
            // reflects what the chain engine experiences.
            async Task<RevocationProbeResult> FetchWithCrossCheckAsync(
                Uri uri,
                byte[]? ocspRequest,
                Func<int, string?, byte[], RevocationProbeResult> classify)
            {
                var routed = await FetchAsync(uri, ocspRequest, classify);
                if (routed.Outcome == RevocationProbeOutcome.Valid || nativeFetch == null)
                    return routed;

                var nativeUri = ocspRequest == null ? uri : RevocationAnalysis.BuildOcspGetUri(uri, ocspRequest);
                var native = await nativeHosts.RunAsync(
                    nativeUri.Host,
                    () => FetchNativeAsync(nativeUri),
                    n => n.Success,
                    n => !n.Success && NativeCertificateRetrieval.IsConnectionFailure(n.Error),
                    n => n with { Error = $"{n.Error} [same host as an earlier request; not retried]" });

                if (!native.Success)
                    return routed with { Detail = $"{routed.Detail}; Windows certificate retrieval (cryptnet) also failed: {native.Error}" };

                var confirmed = classify(200, null, native.Body);
                if (confirmed.Outcome != RevocationProbeOutcome.Valid)
                    return routed with { Detail = $"{routed.Detail}; Windows certificate retrieval (cryptnet) also returned non-revocation data: {confirmed.Detail}" };

                // cryptnet ran as the signed-in user, so its success proves
                // reachability with the user's proxy settings/credentials, not
                // for SYSTEM services.
                var why = routed.Detail.Contains("HTTP 407", StringComparison.Ordinal)
                    ? "with the signed-in user's proxy credentials; the machine route requires proxy authentication, which SYSTEM services can only answer as the computer account"
                    : "with the signed-in user's proxy settings (PAC/WPAD); the static machine WinHTTP route failed";
                return new(RevocationProbeOutcome.UserContextOnly,
                    $"{confirmed.Detail} by Windows certificate retrieval {why}: {routed.Detail}");
            }

            static async Task<RevocationProbeResult> NeverThrowAsync(Func<Task<RevocationProbeResult>> probe)
            {
                try
                {
                    return await probe();
                }
                catch (Exception ex)
                {
                    return new(RevocationProbeOutcome.Unreachable, $"probe could not be performed: {ex.Message}");
                }
            }

            Task<RevocationProbeResult> Probe(RevocationTarget target, RevocationUrl url)
            {
                var cacheKey = url.Kind switch
                {
                    RevocationUrlKind.Ocsp => $"ocsp|{url.Uri.AbsoluteUri}|{target.Issuer.Thumbprint}",
                    _ => $"{url.Kind}|{url.Uri.AbsoluteUri}"
                };
                return probeCache.GetOrAdd(cacheKey, _ => new Lazy<Task<RevocationProbeResult>>(() => NeverThrowAsync(() => url.Kind switch
                {
                    RevocationUrlKind.Ocsp => FetchWithCrossCheckAsync(url.Uri,
                        RevocationAnalysis.BuildOcspRequest(target.Subject, target.Issuer),
                        RevocationAnalysis.ClassifyOcspResponse),
                    RevocationUrlKind.Crl => FetchWithCrossCheckAsync(url.Uri, null,
                        (status, type, body) => RevocationAnalysis.ClassifyCrlResponse(status, type, body, target.Issuer.SubjectName)),
                    _ => FetchAsync(url.Uri, null,
                        (status, type, body) => RevocationAnalysis.ClassifyIssuerCertificateResponse(status, type, body, target.Issuer.SubjectName))
                }))).Value;
            }

            var tierTasks = targets.Values.Select(async target =>
            {
                var probes = await Task.WhenAll(target.Urls.Select(async url => (url, await Probe(target, url))));
                return (target, tier: new RevocationTier(
                    target.Issuer.GetNameInfo(X509NameType.SimpleName, false),
                    target.UsedBy.ToList(),
                    probes));
            });
            var tiers = (await Task.WhenAll(tierTasks))
                .OrderBy(t => t.tier.IssuerName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // ── 4. Verdict + report ──
            var outcome = RevocationAnalysis.Assess(tiers.Select(t => t.tier).ToList(), authoritative);
            var sb = new StringBuilder();
            sb.AppendLine(winHttp.Available
                ? winHttp.IsDirect
                    ? "Route: machine WinHTTP (direct). Windows downloads OCSP/CRL data for SYSTEM services (AVD agent, Windows Update, code-signing checks) on this route."
                    : $"Route: machine WinHTTP proxy {ArcProxyConfiguration.FormatProxyForDisplay(winHttp.ProxyValue)}. Windows downloads OCSP/CRL data for SYSTEM services (AVD agent, Windows Update, code-signing checks) on this route."
                : $"Route: invoking-user proxy settings (machine WinHTTP route unavailable: {winHttp.Error}). Results are indicative only.");
            sb.AppendLine($"Certificate chains collected: {captured.Count}/{hosts.Count} sampled endpoints. Responses are validated by content, so proxy block pages cannot pass; failures are re-checked with Windows' own certificate retrieval (cryptnet, which applies WPAD/PAC) before being reported.");

            sb.AppendLine();
            sb.AppendLine("\u2550\u2550 Revocation endpoints by issuing CA \u2550\u2550");
            foreach (var (target, tier) in tiers)
            {
                sb.AppendLine($"  {tier.IssuerName}");
                sb.AppendLine($"    checks: {string.Join(", ", target.Subjects.Take(4))}{(target.Subjects.Count > 4 ? $" (+{target.Subjects.Count - 4} more)" : "")}");
                foreach (var (url, probe) in tier.Probes.OrderBy(p => p.Url.Kind))
                {
                    var glyph = probe.Outcome == RevocationProbeOutcome.Valid ? "\u2714"
                        : url.Kind == RevocationUrlKind.CaIssuers || probe.Outcome == RevocationProbeOutcome.UserContextOnly ? "\u2139"
                        : "\u2718";
                    var label = url.Kind switch
                    {
                        RevocationUrlKind.Ocsp => "OCSP",
                        RevocationUrlKind.Crl => "CRL ",
                        _ => "AIA "
                    };
                    var note = url.Kind == RevocationUrlKind.CaIssuers && probe.Outcome != RevocationProbeOutcome.Valid
                        ? " [informational: only needed when a server omits an intermediate]"
                        : "";
                    sb.AppendLine($"    {glyph} {label} {url.Uri} \u2014 {probe.Detail}{note}");
                }
            }

            var hostStates = tiers
                .SelectMany(t => t.tier.Probes)
                .Where(p => p.Url.Kind != RevocationUrlKind.CaIssuers)
                .GroupBy(p => p.Url.Uri.Host, StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (hostStates.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("\u2550\u2550 Revocation hosts used by these chains (outbound TCP 80) \u2550\u2550");
                foreach (var host in hostStates)
                {
                    bool ok = host.All(p => p.Result.Outcome == RevocationProbeOutcome.Valid);
                    bool userOnly = !ok && host.All(p => p.Result.Outcome is RevocationProbeOutcome.Valid or RevocationProbeOutcome.UserContextOnly);
                    var listing = RevocationAnalysis.ClassifyAvdListing(host.Key) switch
                    {
                        RevocationAnalysis.AvdListing.Required => "AVD required",
                        RevocationAnalysis.AvdListing.Optional => "AVD optional (*.digicert.com)",
                        _ => "not in AVD list; backup location"
                    };
                    sb.AppendLine(ok
                        ? $"  \u2714 {host.Key} [{listing}]"
                        : userOnly
                            ? $"  \u2139 {host.Key} [{listing}] \u2014 reachable only with the signed-in user's proxy context"
                            : $"  \u2718 {host.Key} [{listing}] \u2014 unreachable on this route");
                }
            }

            if (!collectionErrors.IsEmpty)
            {
                sb.AppendLine();
                sb.AppendLine("\u2550\u2550 Chains not collected (see C-EP-02 for reachability) \u2550\u2550");
                foreach (var (host, error) in collectionErrors.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase))
                    sb.AppendLine($"  \u2139 {host} \u2014 {error}");
            }

            if (inspectedHosts.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("\u2550\u2550 TLS inspection \u2550\u2550");
                foreach (var host in inspectedHosts)
                    sb.AppendLine($"  \u26A0 {host} \u2014 the revocation endpoints above include the inspection CA's, not Microsoft's.");
            }

            result.Status = outcome.Status;
            result.ResultValue = outcome.Summary;
            result.DetailedInfo = sb.ToString().TrimEnd();
            if (outcome.Remediation != null)
            {
                result.RemediationText = outcome.Remediation;
                result.RemediationUrl = "https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines";
            }

            foreach (var chain in captured.Values)
                foreach (var certificate in chain)
                    certificate.Dispose();
        }
        catch (Exception ex)
        {
            result.Status = "Error";
            result.ResultValue = ex.Message;
        }
        finally
        {
            foreach (var client in clients.Values)
                client.Dispose();
        }
        return result;
    }

    private static async Task<byte[]> ReadCappedAsync(HttpResponseMessage response, int cap, CancellationToken token)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        var buffer = new byte[cap];
        int total = 0;
        while (total < cap)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total, cap - total), token);
            if (read == 0)
                break;
            total += read;
        }
        return buffer[..total];
    }

    private sealed class RevocationTarget(X509Certificate2 subject, X509Certificate2 issuer)
    {
        internal X509Certificate2 Subject { get; } = subject;
        internal X509Certificate2 Issuer { get; } = issuer;
        internal List<RevocationUrl> Urls { get; } = [];
        internal SortedSet<string> UsedBy { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal SortedSet<string> Subjects { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
