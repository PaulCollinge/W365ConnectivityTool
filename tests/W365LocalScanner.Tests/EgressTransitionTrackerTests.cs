using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class EgressTransitionTrackerTests
{
    [TestMethod]
    public void FirstAddressAndUnchangedAddressProduceNoEvent()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);

        var first = tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var unchanged = tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);

        Assert.AreEqual(EgressTransitionKind.None, first.Kind);
        Assert.AreEqual(EgressTransitionKind.None, unchanged.Kind);
        Assert.AreEqual(1, unchanged.ObservedAddressCount);
    }

    [TestMethod]
    public void CloudPcPoolAddressIsReportedOnceThenRotationIsSuppressed()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);

        tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var discovered = tracker.Observe("20.0.0.2", routeChanged: false, environmentChanged: false);
        var returned = tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var knownRotation = tracker.Observe("20.0.0.2", routeChanged: false, environmentChanged: false);

        Assert.AreEqual(EgressTransitionKind.PoolAddressObserved, discovered.Kind);
        Assert.AreEqual(2, discovered.ObservedAddressCount);
        Assert.AreEqual(EgressTransitionKind.None, returned.Kind);
        Assert.AreEqual(EgressTransitionKind.None, knownRotation.Kind);
    }

    [TestMethod]
    public void ClientEgressChangeRemainsAWarning()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: false);

        tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var decision = tracker.Observe("20.0.0.2", routeChanged: false, environmentChanged: false);

        Assert.AreEqual(EgressTransitionKind.Warning, decision.Kind);
        Assert.AreEqual("20.0.0.1", decision.PreviousAddress);
        Assert.AreEqual("20.0.0.2", decision.CurrentAddress);
    }

    [DataTestMethod]
    [DataRow(true, false)]
    [DataRow(false, true)]
    [DataRow(true, true)]
    public void CorrelatedCloudPcEgressChangeIsAWarning(bool routeChanged, bool environmentChanged)
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);

        tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var decision = tracker.Observe("20.0.0.2", routeChanged, environmentChanged);

        Assert.AreEqual(EgressTransitionKind.Warning, decision.Kind);
    }

    [TestMethod]
    public void CorrelatedReturnToKnownPoolAddressIsAWarning()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);

        tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        tracker.Observe("20.0.0.2", routeChanged: false, environmentChanged: false);
        var decision = tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: true);

        Assert.AreEqual(EgressTransitionKind.Warning, decision.Kind);
    }

    [TestMethod]
    public void MissingStunResponseDoesNotResetPriorAddress()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: false);

        tracker.Observe("20.0.0.1", routeChanged: false, environmentChanged: false);
        var missing = tracker.Observe(null, routeChanged: false, environmentChanged: false);
        var changed = tracker.Observe("20.0.0.2", routeChanged: false, environmentChanged: false);

        Assert.AreEqual(EgressTransitionKind.None, missing.Kind);
        Assert.AreEqual(EgressTransitionKind.Warning, changed.Kind);
        Assert.AreEqual("20.0.0.1", changed.PreviousAddress);
    }

    [TestMethod]
    public void ObservedTimelinePoolProducesNoWarnings()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);
        string[] addresses =
        [
            "20.215.92.79",
            "74.248.252.11",
            "20.215.92.79",
            "74.248.72.180",
            "74.248.72.180",
            "134.112.2.141",
            "20.215.92.79",
            "134.112.2.141",
            "74.248.252.11",
            "74.248.72.180"
        ];

        var decisions = addresses
            .Select(address => tracker.Observe(address, routeChanged: false, environmentChanged: false))
            .ToList();

        Assert.AreEqual(0, decisions.Count(d => d.Kind == EgressTransitionKind.Warning));
        Assert.AreEqual(3, decisions.Count(d => d.Kind == EgressTransitionKind.PoolAddressObserved));
        Assert.AreEqual(4, decisions[^1].ObservedAddressCount);
    }

    [TestMethod]
    public void LongRunningCloudPcPoolRotationDoesNotAccumulateWarnings()
    {
        var tracker = new EgressTransitionTracker(allowPoolRotation: true);
        string[] pool = ["20.0.0.1", "20.0.0.2", "20.0.0.3", "20.0.0.4"];
        int warnings = 0;
        int poolDiscoveries = 0;

        for (int i = 0; i < 5000; i++)
        {
            var decision = tracker.Observe(
                pool[i % pool.Length],
                routeChanged: false,
                environmentChanged: false);
            if (decision.Kind == EgressTransitionKind.Warning) warnings++;
            if (decision.Kind == EgressTransitionKind.PoolAddressObserved) poolDiscoveries++;
        }

        Assert.AreEqual(0, warnings);
        Assert.AreEqual(pool.Length - 1, poolDiscoveries);
    }

    [DataTestMethod]
    [DataRow("â€”", "—")]
    [DataRow("âœ“", "✓")]
    [DataRow("â•â• Registry â•â•", "══ Registry ══")]
    [DataRow("AVD-HYBRID Ã¢â‚¬â€ westeurope", "AVD-HYBRID — westeurope")]
    public void MojibakeRepairRestoresUtf8Characters(string input, string expected)
    {
        Assert.AreEqual(expected, TextEncodingRepair.Repair(input));
    }

    [TestMethod]
    public void MojibakeRepairPreservesCorrectUnicode()
    {
        const string input = "══ Arc Control Plane ══ — ✓";

        Assert.AreEqual(input, TextEncodingRepair.Repair(input));
    }

    [DataTestMethod]
    [DataRow("Café Räume", "Café Räume")]
    [DataRow("naïveté", "naïveté")]
    [DataRow("Bosch GmbH — München", "Bosch GmbH — München")]
    [DataRow("", "")]
    public void MojibakeRepairDoesNotCorruptLegitimateExtendedText(string input, string expected)
    {
        Assert.AreEqual(expected, TextEncodingRepair.Repair(input));
    }

    [TestMethod]
    public void MojibakeRepairHandlesEmptyString()
    {
        Assert.AreEqual(string.Empty, TextEncodingRepair.Repair(string.Empty));
    }

    [TestMethod]
    public void MojibakeRepairIsIdempotent()
    {
        const string input = "â€”";
        var once = TextEncodingRepair.Repair(input);
        var twice = TextEncodingRepair.Repair(once);

        Assert.AreEqual("—", once);
        Assert.AreEqual(once, twice);
    }

    [TestMethod]
    public void AgentDownloadAssessmentFailsBlockedOrUntrustedPayloads()
    {
        Assert.AreEqual(
            AgentDownloadVerdict.Failed,
            AgentDownloadAssessment.Assess(false, true, false, true, false));
        Assert.AreEqual(
            AgentDownloadVerdict.Failed,
            AgentDownloadAssessment.Assess(true, false, false, true, false));
        Assert.AreEqual(
            AgentDownloadVerdict.Failed,
            AgentDownloadAssessment.Assess(true, true, false, true, true));
        Assert.AreEqual(
            AgentDownloadVerdict.Failed,
            AgentDownloadAssessment.Assess(true, true, true, false, false));
    }

    [TestMethod]
    public void AgentDownloadAssessmentDistinguishesInspectionFromCleanTls()
    {
        Assert.AreEqual(
            AgentDownloadVerdict.Warning,
            AgentDownloadAssessment.Assess(true, true, true, true, false));
        Assert.AreEqual(
            AgentDownloadVerdict.Passed,
            AgentDownloadAssessment.Assess(true, true, false, true, false));
    }

    [DataTestMethod]
    [DataRow("text/html", "MZ", true)]
    [DataRow("application/octet-stream", "<!DOCTYPE html><title>Blocked</title>", true)]
    [DataRow("application/octet-stream", "<html><body>Proxy block</body></html>", true)]
    [DataRow("application/octet-stream", "MZ\u0090\0", false)]
    public void AgentDownloadAssessmentRecognizesHtmlBlockPages(
        string contentType,
        string sample,
        bool expected)
    {
        Assert.AreEqual(
            expected,
            AgentDownloadAssessment.LooksLikeHtml(Encoding.UTF8.GetBytes(sample), contentType));
    }

    [TestMethod]
    public void AgentDownloadAssessmentRecognizesWindowsInstallerPayload()
    {
        byte[] msi = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00];
        byte[] executable = [0x4D, 0x5A, 0x90, 0x00];

        Assert.IsTrue(AgentDownloadAssessment.LooksLikeMsi(msi));
        Assert.IsFalse(AgentDownloadAssessment.LooksLikeMsi(executable));
        Assert.IsFalse(AgentDownloadAssessment.LooksLikeMsi([]));
    }

    [TestMethod]
    public void ArcProxyConfigurationUsesDocumentedPrecedence()
    {
        var agentConfigured = ArcProxyConfiguration.Create(
            "http://agent-proxy.contoso.com:8080",
            null,
            "http://machine-proxy.contoso.com:8080");
        var machineConfigured = ArcProxyConfiguration.Create(
            null,
            null,
            "http://machine-proxy.contoso.com:8080");
        var direct = ArcProxyConfiguration.Create(null, null, null);
        var endpoint = new Uri("https://gbl.his.arc.azure.com/agent.msi");

        Assert.AreEqual("agent proxy.url", agentConfigured.SourceDescription);
        Assert.AreEqual("agent-proxy.contoso.com", agentConfigured.Resolve(endpoint).ProxyUri?.Host);
        Assert.AreEqual("machine HTTPS_PROXY", machineConfigured.SourceDescription);
        Assert.AreEqual("machine-proxy.contoso.com", machineConfigured.Resolve(endpoint).ProxyUri?.Host);
        Assert.AreEqual("direct", direct.SourceDescription);
        Assert.IsFalse(direct.Resolve(endpoint).UseProxy);
    }

    [DataTestMethod]
    [DataRow("Arc", "https://gbl.his.arc.azure.com/agent.msi", true)]
    [DataRow("ARM, Arc", "https://westeurope.guestconfiguration.azure.com/extension", true)]
    [DataRow("ARM", "https://management.azure.com/subscriptions", true)]
    [DataRow("AAD", "https://login.microsoftonline.com/tenant/oauth2", true)]
    [DataRow("ArcData", "https://sql.westeurope.arcdataservices.com/path", true)]
    [DataRow("Arc", "https://aka.ms/AzureConnectedMachineAgent", false)]
    [DataRow("Arc", "https://example.com/his.arc.azure.com/path", false)]
    public void ArcProxyConfigurationAppliesServiceBypass(
        string bypass,
        string endpoint,
        bool expected)
    {
        var configuration = ArcProxyConfiguration.Create(
            "http://proxy.contoso.com:8080",
            bypass,
            null);

        Assert.AreEqual(expected, configuration.ShouldBypass(new Uri(endpoint)));
        Assert.AreEqual(!expected, configuration.Resolve(new Uri(endpoint)).UseProxy);
    }

    [TestMethod]
    public void ArcProxyConfigurationRedactsCredentials()
    {
        var configuration = ArcProxyConfiguration.Create(
            "http://secret-user:secret-password@proxy.contoso.com:8080",
            null,
            null);

        Assert.AreEqual("http://proxy.contoso.com:8080", configuration.AgentProxyDisplay);
        Assert.IsFalse(configuration.AgentProxyDisplay!.Contains("secret", StringComparison.Ordinal));
    }

    [TestMethod]
    public void ArcProxyConfigurationRedactsMalformedProxyCredentials()
    {
        var configuration = ArcProxyConfiguration.Create(
            "secret-user:secret-password@proxy.contoso.com:8080",
            null,
            null);

        Assert.AreEqual("<redacted>@proxy.contoso.com:8080", configuration.AgentProxyDisplay);
        Assert.IsFalse(configuration.AgentProxyDisplay!.Contains("secret", StringComparison.Ordinal));
    }

    [DataTestMethod]
    [DataRow("gbl.his.arc.azure.com", true)]
    [DataRow("westeurope.his.arc.azure.com", true)]
    [DataRow("agentserviceapi.guestconfiguration.azure.com", true)]
    [DataRow("guestnotificationservice.azure.com", false)]
    [DataRow("management.azure.com", false)]
    [DataRow("his.arc.azure.com.example.com", false)]
    public void ArcProxyConfigurationIdentifiesPrivateLinkCapableHosts(
        string host,
        bool expected)
    {
        Assert.AreEqual(expected, ArcProxyConfiguration.IsPrivateLinkCapableHost(host));
    }

    [TestMethod]
    public void ArcPrivateLinkAssessmentAcceptsPrivateDirectRoute()
    {
        var assessment = ArcPrivateLinkAssessment.Assess(
            [System.Net.IPAddress.Parse("10.20.30.40")]);

        Assert.IsTrue(assessment.HasPrivateAddresses);
        Assert.IsFalse(assessment.HasPublicAddresses);
        Assert.IsNull(assessment.GetRouteWarning(viaProxy: false, expectsPrivateRoute: true));
        StringAssert.Contains(assessment.Description, "private-only");
    }

    [TestMethod]
    public void ArcPrivateLinkAssessmentWarnsWhenPrivateAddressUsesProxy()
    {
        var assessment = ArcPrivateLinkAssessment.Assess(
            [System.Net.IPAddress.Parse("172.20.1.5")]);

        StringAssert.Contains(
            assessment.GetRouteWarning(viaProxy: true, expectsPrivateRoute: false),
            "through a proxy");
    }

    [TestMethod]
    public void ArcPrivateLinkAssessmentWarnsWhenBypassResolvesPublicly()
    {
        var assessment = ArcPrivateLinkAssessment.Assess(
            [System.Net.IPAddress.Parse("20.40.60.80")]);

        StringAssert.Contains(
            assessment.GetRouteWarning(viaProxy: false, expectsPrivateRoute: true),
            "no private address");
    }

    [TestMethod]
    public void ArcPrivateLinkAssessmentWarnsOnSplitDnsAnswers()
    {
        var assessment = ArcPrivateLinkAssessment.Assess(
            [
                System.Net.IPAddress.Parse("10.20.30.40"),
                System.Net.IPAddress.Parse("20.40.60.80")
            ]);

        Assert.IsTrue(assessment.HasPrivateAddresses);
        Assert.IsTrue(assessment.HasPublicAddresses);
        StringAssert.Contains(
            assessment.GetRouteWarning(viaProxy: false, expectsPrivateRoute: false),
            "mixed private and public");
    }

    [DataTestMethod]
    [DataRow("127.0.0.1")]
    [DataRow("169.254.10.20")]
    [DataRow("::1")]
    [DataRow("fe80::1")]
    public void ArcPrivateLinkAssessmentRejectsSinkholeAddresses(string address)
    {
        var assessment = ArcPrivateLinkAssessment.Assess(
            [System.Net.IPAddress.Parse(address)]);

        Assert.IsTrue(assessment.HasUnroutableAddresses);
        Assert.IsFalse(assessment.HasPrivateAddresses);
        StringAssert.Contains(
            assessment.GetRouteWarning(viaProxy: false, expectsPrivateRoute: true),
            "possible DNS sinkhole");
    }
}
