using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

/// <summary>
/// Runs the full C-PKI-01 runner against live Microsoft/DigiCert endpoints
/// through a local test proxy that reproduces customer proxy behaviour.
/// Opt in with W365_LIVE_TESTS=1 (requires outbound internet).
/// </summary>
[TestClass]
[TestCategory("Live")]
public sealed class RevocationReachabilityLiveTests
{
    [TestMethod]
    public async Task AllRevocationTrafficForwardedPasses()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(_ => ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);

        Assert.AreEqual("Passed", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, $"via http://127.0.0.1:{proxy.Port}");
        Assert.IsTrue(proxy.Requests.Any(r => r.StartsWith("CONNECT ")), "chains must be collected through the proxy");
        Assert.IsTrue(proxy.Requests.Any(r => r.StartsWith("POST oneocsp.microsoft.com")), "OCSP must go through the proxy");
        Assert.IsTrue(proxy.Requests.Any(r => r.StartsWith("GET crl3.digicert.com")), "CRLs must go through the proxy");
    }

    [TestMethod]
    public async Task BoschScenarioDigiCertBlockPageIsDetected()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.BlockPage200
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);

        Assert.AreEqual("Warning", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.ResultValue, "offline");
        StringAssert.Contains(result.ResultValue, "ocsp.digicert.com");
        StringAssert.Contains(result.ResultValue, "crl3.digicert.com");
        Assert.IsFalse(result.ResultValue.Contains("microsoft.com"), result.ResultValue);
        StringAssert.Contains(result.DetailedInfo, "not an OCSP response");
        StringAssert.Contains(result.DetailedInfo, "not a CRL");
        StringAssert.Contains(result.DetailedInfo, "\u2718 crl3.digicert.com");
        StringAssert.Contains(result.DetailedInfo, "\u2714 oneocsp.microsoft.com");
        Assert.IsFalse(result.RemediationText.Contains("15 seconds"), "a fast block page is not a stall");
    }

    [TestMethod]
    public async Task OnlyUnpublishedBackupHostsBlockedIsInfoNotWarning()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.Equals("crl2.microsoft.com", StringComparison.OrdinalIgnoreCase)
            || host.Equals("caissuers.microsoft.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.BlockPage200
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);

        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.ResultValue, "not in the AVD endpoint list");
        StringAssert.Contains(result.DetailedInfo, "\u2718 crl2.microsoft.com [not in AVD list; backup location]");
        StringAssert.Contains(result.DetailedInfo, "\u2714 oneocsp.microsoft.com [AVD required]");
    }

    [TestMethod]
    public async Task ProxyDenyIsDetected()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.Deny403
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);

        Assert.AreEqual("Warning", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "HTTP 403");
    }

    [TestMethod]
    public async Task SilentDropIsReportedAsStallWithinBoundedTime()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.Blackhole
                : ProxyPolicy.Forward);

        var stopwatch = Stopwatch.StartNew();
        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);
        stopwatch.Stop();

        Assert.AreEqual("Warning", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "silently dropped");
        StringAssert.Contains(result.RemediationText, "15 seconds");
        Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(60), $"took {stopwatch.Elapsed}");
    }

    [TestMethod]
    public async Task UnreachableProxyIsReportedNotCrashed()
    {
        RequireLive();
        int closedPort;
        using (var probe = new MiniHttpProxy(_ => ProxyPolicy.Forward))
            closedPort = probe.Port;

        var result = await Program.RunRevocationReachability(ProxyRoute(closedPort), WindowsAlsoBlocked);

        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "Chains not collected");
    }

    [TestMethod]
    public async Task StaticRouteBlockedButWindowsReachesItIsNotReportedAsBlock()
    {
        // WPAD/PAC estate: the static WinHTTP route fails, but Windows' own
        // certificate retrieval (real cryptnet, direct on this machine)
        // succeeds. That must not be reported as a revocation block.
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.BlockPage200
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), NativeCertificateRetrieval.FetchAsync);

        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.ResultValue, "only with this user's proxy context");
        StringAssert.Contains(result.DetailedInfo, "with the signed-in user's proxy settings (PAC/WPAD)");
    }

    [TestMethod]
    public async Task ProxyAuthenticationOnRevocationHostsIsAFindingAndNoCredentialsAreSent()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.RequireAuth
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsAlsoBlocked);

        Assert.AreEqual("Warning", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "HTTP 407");
        Assert.IsFalse(
            proxy.Requests.Any(r => r.Contains("digicert.com") && r.Contains("+credentials")),
            "revocation probes must not authenticate as the user: " + string.Join("; ", proxy.Requests));
    }

    [TestMethod]
    public async Task ProxyAuthenticationSatisfiedOnlyByUserIsInfoNotPass()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.RequireAuth
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), NativeCertificateRetrieval.FetchAsync);

        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "with the signed-in user's proxy credentials");
        StringAssert.Contains(result.DetailedInfo, "\u2139 ocsp.digicert.com");
    }

    [TestMethod]
    public async Task WindowsRetrievalFetchesRealCrlAndOcspOverGet()
    {
        RequireLive();
        var (leaf, issuer) = await FetchLeafAndIssuerAsync("login.microsoftonline.com");
        var ocspUrl = RevocationAnalysis.ExtractUrls(leaf).First(u => u.Kind == RevocationUrlKind.Ocsp).Uri;
        var crlUrl = RevocationAnalysis.ExtractUrls(leaf).First(u => u.Kind == RevocationUrlKind.Crl).Uri;

        var crl = await NativeCertificateRetrieval.FetchAsync(crlUrl, 10_000);
        var ocsp = await NativeCertificateRetrieval.FetchAsync(
            RevocationAnalysis.BuildOcspGetUri(ocspUrl, RevocationAnalysis.BuildOcspRequest(leaf, issuer)), 10_000);

        Assert.IsTrue(crl.Success, crl.Error);
        Assert.AreEqual(RevocationProbeOutcome.Valid,
            RevocationAnalysis.ClassifyCrlResponse(200, null, crl.Body, issuer.SubjectName).Outcome);
        Assert.IsTrue(ocsp.Success, ocsp.Error);
        var ocspResult = RevocationAnalysis.ClassifyOcspResponse(200, null, ocsp.Body);
        Assert.AreEqual(RevocationProbeOutcome.Valid, ocspResult.Outcome);
        StringAssert.Contains(ocspResult.Detail, "successful");
    }

    [TestMethod]
    public async Task WindowsRetrievalReportsUnresolvableHost()
    {
        RequireLive();

        var result = await NativeCertificateRetrieval.FetchAsync(new Uri("http://w365-nonexistent.invalid/x.crl"), 10_000);

        Assert.IsFalse(result.Success);
        Assert.IsFalse(string.IsNullOrWhiteSpace(result.Error));
    }

    [TestMethod]
    public async Task WorstCaseRevocationBlackholeStaysBounded()
    {
        // Proxy silently drops all revocation hosts AND Windows retrieval
        // also times out: every URL costs a full route timeout plus a full
        // native timeout. The test must still finish in bounded time.
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.Contains("ocsp", StringComparison.OrdinalIgnoreCase)
            || host.StartsWith("crl", StringComparison.OrdinalIgnoreCase)
            || host.Contains("cacerts", StringComparison.OrdinalIgnoreCase)
            || host.Contains("caissuers", StringComparison.OrdinalIgnoreCase)
            || host.Equals("www.microsoft.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.Blackhole
                : ProxyPolicy.Forward);

        var stopwatch = Stopwatch.StartNew();
        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsTimesOut);
        stopwatch.Stop();

        Console.WriteLine($"WORST-CASE revocation blackhole: {stopwatch.Elapsed.TotalSeconds:F1}s, {result.Status}: {result.ResultValue}");
        Assert.AreEqual("Warning", result.Status, result.DetailedInfo);
        Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(60), $"took {stopwatch.Elapsed}");
    }

    [TestMethod]
    public async Task WorstCaseEverythingBlackholedStaysBounded()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(_ => ProxyPolicy.Blackhole);

        var stopwatch = Stopwatch.StartNew();
        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port), WindowsTimesOut);
        stopwatch.Stop();

        Console.WriteLine($"WORST-CASE total blackhole: {stopwatch.Elapsed.TotalSeconds:F1}s, {result.Status}: {result.ResultValue}");
        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        Assert.IsTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(60), $"took {stopwatch.Elapsed}");
    }

    private static async Task<NativeFetchResult> WindowsTimesOut(Uri uri, int timeoutMs)
    {
        await Task.Delay(timeoutMs);
        return new NativeFetchResult(false, [], "timed out");
    }

    private static Task<NativeFetchResult> WindowsAlsoBlocked(Uri uri, int timeoutMs) =>
        Task.FromResult(new NativeFetchResult(false, [], "HTTP 403 (simulated: Windows retrieval blocked too)"));

    private static async Task<(X509Certificate2 Leaf, X509Certificate2 Issuer)> FetchLeafAndIssuerAsync(string host)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, 443);
        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(host);
        var leaf = new X509Certificate2(ssl.RemoteCertificate!);
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(leaf);
        return (leaf, new X509Certificate2(chain.ChainElements[1].Certificate.RawData));
    }

    private static void RequireLive()
    {
        if (Environment.GetEnvironmentVariable("W365_LIVE_TESTS") != "1")
            Assert.Inconclusive("Set W365_LIVE_TESTS=1 to run live-network tests.");
    }

    private static WinHttpProxyConfiguration ProxyRoute(int port)
    {
        var bytes = new List<byte>([0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0]);
        Append(bytes, $"127.0.0.1:{port}");
        Append(bytes, null);
        Append(bytes, null);
        return WinHttpProxyConfiguration.Parse([.. bytes]);
    }

    private static void Append(List<byte> bytes, string? value)
    {
        var encoded = value == null ? [] : Encoding.ASCII.GetBytes(value);
        bytes.AddRange(BitConverter.GetBytes(encoded.Length));
        bytes.AddRange(encoded);
    }
}
