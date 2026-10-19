using System.Diagnostics;
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

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port));

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

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port));

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
    public async Task ProxyDenyIsDetected()
    {
        RequireLive();
        using var proxy = new MiniHttpProxy(host =>
            host.EndsWith("digicert.com", StringComparison.OrdinalIgnoreCase)
                ? ProxyPolicy.Deny403
                : ProxyPolicy.Forward);

        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port));

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
        var result = await Program.RunRevocationReachability(ProxyRoute(proxy.Port));
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

        var result = await Program.RunRevocationReachability(ProxyRoute(closedPort));

        Assert.AreEqual("Info", result.Status, result.DetailedInfo);
        StringAssert.Contains(result.DetailedInfo, "Chains not collected");
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
