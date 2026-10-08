using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class FirewallRuleAnalysisTests
{
    [TestMethod]
    public void CodexLoopbackRuleIsExcludedFromExternalTrafficAnalysis()
    {
        var rule = Rule(
            name: "codex_sandbox_offline_block_loopback_udp",
            remoteAddresses: "127.0.0.0/8,::/127");

        Assert.IsTrue(FirewallRuleAnalysis.IsLoopbackOnly(rule));
    }

    [TestMethod]
    public void RuleNameAloneDoesNotExcludeExternalBlock()
    {
        var rule = Rule(
            name: "codex_sandbox_offline_block_outbound",
            remoteAddresses: "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255");

        Assert.IsFalse(FirewallRuleAnalysis.IsLoopbackOnly(rule));
    }

    [DataTestMethod]
    [DataRow("443", 443, true)]
    [DataRow("80,443", 443, true)]
    [DataRow("1000-4000", 3478, true)]
    [DataRow("Any", 443, true)]
    [DataRow("*", 443, true)]
    [DataRow("80", 443, false)]
    public void PortMatchingSupportsFirewallPortFormats(string rulePort, int targetPort, bool expected)
    {
        Assert.AreEqual(expected, FirewallRuleAnalysis.PortMatches(rulePort, targetPort));
    }

    private static FirewallRule Rule(string name, string remoteAddresses)
    {
        return new FirewallRule(
            name,
            Direction: "Out",
            Action: "Block",
            Protocol: 17,
            LocalPort: "Any",
            RemotePort: "Any",
            remoteAddresses);
    }
}
