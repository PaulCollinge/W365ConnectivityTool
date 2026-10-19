using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class HostProbeMemoTests
{
    [TestMethod]
    public async Task ConnectionFailureIsProbedOnceAndReusedForTheSameHost()
    {
        var memo = new HostProbeMemo<string>();
        int calls = 0;
        async Task<string> Probe()
        {
            Interlocked.Increment(ref calls);
            await Task.Delay(200);
            return "timeout";
        }

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            memo.RunAsync("crl3.digicert.com", Probe, r => r == "ok", r => r == "timeout", r => r + " (reused)")));

        Assert.AreEqual(1, calls, "a dead host must only pay the timeout once");
        Assert.AreEqual(9, results.Count(r => r == "timeout (reused)"));
    }

    [TestMethod]
    public async Task ContentBlocksAreNotReusedBecauseProxiesFilterByPath()
    {
        var memo = new HostProbeMemo<string>();
        int calls = 0;
        Task<string> Probe() { Interlocked.Increment(ref calls); return Task.FromResult("blocked"); }

        for (int i = 0; i < 3; i++)
            await memo.RunAsync("crl2.microsoft.com", Probe, r => r == "ok", r => r == "timeout", r => r + " (reused)");

        Assert.AreEqual(3, calls);
    }

    [TestMethod]
    public async Task HealthyHostRunsConcurrentlyAfterFirstSuccess()
    {
        var memo = new HostProbeMemo<string>();
        await memo.RunAsync("oneocsp.microsoft.com", () => Task.FromResult("ok"), r => r == "ok", r => false, r => r);
        int inFlight = 0, peak = 0;
        async Task<string> Probe()
        {
            int now = Interlocked.Increment(ref inFlight);
            InterlockedMax(ref peak, now);
            await Task.Delay(100);
            Interlocked.Decrement(ref inFlight);
            return "ok";
        }

        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
            memo.RunAsync("oneocsp.microsoft.com", Probe, r => r == "ok", r => false, r => r)));

        Assert.IsTrue(peak > 1, $"healthy hosts must not be serialised (peak {peak})");
    }

    [TestMethod]
    public async Task HostsAreIndependentAndCaseInsensitive()
    {
        var memo = new HostProbeMemo<string>();
        await memo.RunAsync("OCSP.DIGICERT.COM", () => Task.FromResult("timeout"), r => r == "ok", r => r == "timeout", r => r + " (reused)");

        var sameHost = await memo.RunAsync("ocsp.digicert.com", () => Task.FromResult("ok"), r => r == "ok", r => r == "timeout", r => r + " (reused)");
        var otherHost = await memo.RunAsync("crl3.digicert.com", () => Task.FromResult("ok"), r => r == "ok", r => r == "timeout", r => r + " (reused)");

        Assert.AreEqual("timeout (reused)", sameHost);
        Assert.AreEqual("ok", otherHost);
    }

    [DataTestMethod]
    [DataRow("timed out", true)]
    [DataRow("cannot connect", true)]
    [DataRow("DNS name not resolved", true)]
    [DataRow("HTTP 403", false)]
    [DataRow(null, false)]
    public void NativeConnectionFailuresAreRecognised(string? error, bool expected)
    {
        Assert.AreEqual(expected, NativeCertificateRetrieval.IsConnectionFailure(error));
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while ((current = Volatile.Read(ref target)) < value
               && Interlocked.CompareExchange(ref target, value, current) != current)
        {
        }
    }
}
