using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class HybridDiagnosticSemanticsTests
{
    [DataTestMethod]
    [DataRow(0, "Info")]
    [DataRow(1, "Info")]
    [DataRow(2, "Passed")]
    public void RdpEgressRequiresBothPathsForPassed(int verifiedPaths, string expected)
    {
        var outcome = HybridDiagnosticSemantics.AssessRdpEgress(
            verifiedPaths,
            concernCount: 0,
            isHybrid: true,
            concernSummary: "");

        Assert.AreEqual(expected, outcome.Status);
    }

    [TestMethod]
    public void RdpEgressConcernOverridesVerifiedPaths()
    {
        var outcome = HybridDiagnosticSemantics.AssessRdpEgress(
            verifiedPaths: 2,
            concernCount: 1,
            isHybrid: true,
            concernSummary: "VPN-routed TURN");

        Assert.AreEqual("Warning", outcome.Status);
        StringAssert.Contains(outcome.Summary, "VPN-routed TURN");
    }

    [TestMethod]
    public void TurnRouteCannotPassWhenDnsAndRoutesAreUnverified()
    {
        var outcome = HybridDiagnosticSemantics.AssessTurnRoute(
            issueCount: 0,
            detectedVpnCount: 0,
            serviceRangesVerified: false,
            turnDnsResolved: false,
            detectedVpnNames: "");

        Assert.AreEqual("Info", outcome.Status);
        StringAssert.Contains(outcome.Summary, "DNS is unavailable");
    }

    [TestMethod]
    public void TurnRoutePassesWhenDnsResolvesWithoutLocalBlockers()
    {
        var outcome = HybridDiagnosticSemantics.AssessTurnRoute(
            issueCount: 0,
            detectedVpnCount: 0,
            serviceRangesVerified: false,
            turnDnsResolved: true,
            detectedVpnNames: "");

        Assert.AreEqual("Passed", outcome.Status);
    }

    [TestMethod]
    public void TurnRouteWarnsForConfirmedBlocker()
    {
        var outcome = HybridDiagnosticSemantics.AssessTurnRoute(
            issueCount: 1,
            detectedVpnCount: 0,
            serviceRangesVerified: true,
            turnDnsResolved: true,
            detectedVpnNames: "");

        Assert.AreEqual("Warning", outcome.Status);
    }
}
