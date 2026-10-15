using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class AvdPrivateLinkAnalysisTests
{
    private const string Host =
        "12345678-1234-1234-1234-123456789abc.afdfp-rdgateway.wvd.microsoft.com";

    [TestMethod]
    public void PrivateOnlyAvdDnsActivatesPrivateLinkHandling()
    {
        var assessment = AvdPrivateLinkAssessment.Assess(
            Host,
            [IPAddress.Parse("10.20.30.40")],
            "12345678-1234-1234-1234-123456789abc.privatelink.wvd.microsoft.com");

        Assert.IsTrue(assessment.IsPrivateLinkDetected);
        Assert.IsTrue(assessment.UsesPrivateRoute);
        Assert.IsTrue(assessment.HasPrivateLinkDnsName);
        Assert.IsTrue(assessment.HasPrivateAddresses);
        Assert.IsFalse(assessment.HasPublicAddresses);
        StringAssert.Contains(assessment.Description, "AVD Private Link confirmed");
    }

    [TestMethod]
    public void PublicAvdDnsDoesNotActivatePrivateLinkHandling()
    {
        var assessment = AvdPrivateLinkAssessment.Assess(
            Host,
            [IPAddress.Parse("40.64.145.10")]);

        Assert.IsFalse(assessment.IsPrivateLinkDetected);
        Assert.IsFalse(assessment.UsesPrivateRoute);
        Assert.IsFalse(assessment.HasPrivateAddresses);
        Assert.IsTrue(assessment.HasPublicAddresses);
        Assert.IsNull(assessment.GetRouteWarning(machineRouteUsesProxy: true));
    }

    [TestMethod]
    public void MixedDnsIsWarningAndDoesNotSwitchToPrivateLink()
    {
        var assessment = AvdPrivateLinkAssessment.Assess(
            Host,
            [IPAddress.Parse("10.20.30.40"), IPAddress.Parse("40.64.145.10")]);

        Assert.IsFalse(assessment.IsPrivateLinkDetected);
        Assert.IsFalse(assessment.UsesPrivateRoute);
        StringAssert.Contains(
            assessment.GetRouteWarning(machineRouteUsesProxy: false),
            "mixed private and public");
    }

    [TestMethod]
    public void PrivateEndpointSelectedThroughProxyIsWarning()
    {
        var assessment = AvdPrivateLinkAssessment.Assess(
            Host,
            [IPAddress.Parse("192.168.20.15")]);

        Assert.IsTrue(assessment.UsesPrivateRoute);
        Assert.IsFalse(assessment.IsPrivateLinkDetected);
        StringAssert.Contains(
            assessment.GetRouteWarning(machineRouteUsesProxy: true),
            "WinHTTP route sends this endpoint through a proxy");
        Assert.IsNull(assessment.GetRouteWarning(machineRouteUsesProxy: false));
    }

    [TestMethod]
    public void SinkholeAddressDoesNotActivatePrivateLink()
    {
        var assessment = AvdPrivateLinkAssessment.Assess(
            Host,
            [IPAddress.Loopback, IPAddress.Parse("169.254.10.20")]);

        Assert.IsFalse(assessment.IsPrivateLinkDetected);
        Assert.IsTrue(assessment.HasUnroutableAddresses);
        StringAssert.Contains(
            assessment.GetRouteWarning(machineRouteUsesProxy: false),
            "sinkhole");
    }

    [TestMethod]
    public void ArcPrivateLinkHostIsNotAvdCandidate()
    {
        Assert.IsTrue(AvdPrivateLinkAssessment.IsCandidateHost(Host));
        Assert.IsTrue(AvdPrivateLinkAssessment.IsCandidateHost("rdweb.wvd.microsoft.com"));
        Assert.IsFalse(AvdPrivateLinkAssessment.IsCandidateHost("gbl.his.arc.azure.com"));
        Assert.IsFalse(AvdPrivateLinkAssessment.IsCandidateHost("privatelink.guestconfiguration.azure.com"));
    }
}
