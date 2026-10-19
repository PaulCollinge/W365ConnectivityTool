using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class WarmIngestCandidatesTests
{
    [TestMethod]
    public void RegionCandidatesPreferSharedThenNumberedSlots()
    {
        var candidates = WarmIngestCandidates.ForRegion("West Europe");

        CollectionAssert.AreEqual(
            new[]
            {
                "westeurope-shared.prod.warm.ingest.monitor.core.windows.net",
                "westeurope-0.prod.warm.ingest.monitor.core.windows.net",
                "westeurope-1.prod.warm.ingest.monitor.core.windows.net",
                "westeurope-2.prod.warm.ingest.monitor.core.windows.net"
            },
            candidates.ToArray());
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void MissingRegionHasNoRegionalCandidates(string? region)
    {
        Assert.AreEqual(0, WarmIngestCandidates.ForRegion(region).Count);
    }

    [TestMethod]
    public void CanariesExcludeLocalRegionAndNeverUseRetiredNumberedEastUsNames()
    {
        var canaries = WarmIngestCandidates.Canaries("westeurope");

        Assert.IsFalse(canaries.Any(c => c.StartsWith("westeurope", StringComparison.Ordinal)));
        CollectionAssert.Contains(canaries.ToArray(), "eastus-shared.prod.warm.ingest.monitor.core.windows.net");
        CollectionAssert.Contains(canaries.ToArray(), "uksouth-shared.prod.warm.ingest.monitor.core.windows.net");
        Assert.AreEqual(
            "eastus-shared.prod.warm.ingest.monitor.core.windows.net",
            canaries[0],
            "the first canary must be the always-published -shared name");
    }

    [TestMethod]
    public void CanariesWithoutRegionCoverAllCanaryRegions()
    {
        var canaries = WarmIngestCandidates.Canaries(null);

        Assert.AreEqual(12, canaries.Count);
    }

    [DataTestMethod]
    [DataRow("westeurope-shared.prod.warm.ingest.monitor.core.windows.net", true)]
    [DataRow("UKSOUTH-0.PROD.WARM.INGEST.MONITOR.CORE.WINDOWS.NET", true)]
    [DataRow("gcs.prod.monitoring.core.windows.net", false)]
    public void RecognisesWarmIngestHosts(string host, bool expected)
    {
        Assert.AreEqual(expected, WarmIngestCandidates.IsWarmIngestHost(host));
    }
}
