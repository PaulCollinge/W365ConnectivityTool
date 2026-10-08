using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class FirewallRuleAnalysisTests
{
    [TestMethod]
    public void WindowsRegistryCodexRuleIsExcludedEndToEnd()
    {
        const string data = "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=17|"
            + "RA4=127.0.0.0/255.0.0.0|RA6=::/127|"
            + "Name=codex_sandbox_offline_block_loopback_udp|";

        var rule = FirewallRuleAnalysis.ParseRegistryRule(data);

        Assert.IsTrue(rule.HasValue);
        Assert.AreEqual("127.0.0.0/255.0.0.0,::/127", rule.Value.RemoteAddresses);
        Assert.IsTrue(FirewallRuleAnalysis.IsLoopbackOnly(rule.Value));
    }

    [TestMethod]
    public void WindowsRegistryExternalCodexRuleIsNotExcludedEndToEnd()
    {
        const string data = "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=256|"
            + "RA4=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255|"
            + "RA6=::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|"
            + "Name=codex_sandbox_offline_block_outbound|";

        var rule = FirewallRuleAnalysis.ParseRegistryRule(data);

        Assert.IsTrue(rule.HasValue);
        Assert.IsFalse(FirewallRuleAnalysis.IsLoopbackOnly(rule.Value));
    }

    [TestMethod]
    public void DisabledRegistryRuleIsIgnored()
    {
        const string data = "v2.30|Action=Block|Active=FALSE|Dir=Out|Protocol=17|"
            + "RA4=127.0.0.0/255.0.0.0|Name=disabled|";

        Assert.IsFalse(FirewallRuleAnalysis.ParseRegistryRule(data).HasValue);
    }

    [TestMethod]
    public void CodexLoopbackRuleIsExcludedFromExternalTrafficAnalysis()
    {
        var rule = Rule(
            name: "codex_sandbox_offline_block_loopback_udp",
            remoteAddresses: "127.0.0.0/255.0.0.0,::/127");

        Assert.IsTrue(FirewallRuleAnalysis.IsLoopbackOnly(rule));
    }

    [DataTestMethod]
    [DataRow("127.0.0.0/8")]
    [DataRow("127.0.0.0/255.0.0.0")]
    [DataRow("127.0.0.0-127.255.255.255")]
    [DataRow("::/127")]
    [DataRow("::1/128")]
    [DataRow("127.0.0.1,::1")]
    [DataRow("127.0.0.0/8,::/127")]
    [DataRow("127.0.0.0/255.0.0.0,::/127")]
    public void LoopbackAddressFormatsAreExcluded(string remoteAddresses)
    {
        Assert.IsTrue(FirewallRuleAnalysis.IsLoopbackOnly(Rule("loopback", remoteAddresses)));
    }

    [DataTestMethod]
    [DataRow("")]
    [DataRow("Any")]
    [DataRow("*")]
    [DataRow("::")]
    [DataRow("::/0")]
    [DataRow("::/126")]
    [DataRow("::2/128")]
    [DataRow("2001:db8::1/128")]
    [DataRow("127.0.0.0/7")]
    [DataRow("127.0.0.0/33")]
    [DataRow("127.0.0.0/254.0.0.0")]
    [DataRow("127.0.0.0/255.0.255.0")]
    [DataRow("127.0.0.0/8,10.0.0.0/8")]
    [DataRow("127.0.0.0/8,2001:db8::1/128")]
    public void ExternalOrInvalidAddressFormatsAreNotExcluded(string remoteAddresses)
    {
        Assert.IsFalse(FirewallRuleAnalysis.IsLoopbackOnly(Rule("external", remoteAddresses)));
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
