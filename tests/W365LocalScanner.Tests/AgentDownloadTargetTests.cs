using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class AgentDownloadTargetTests
{
    [TestMethod]
    public void HybridDownloadTargetsContainOnlyDocumentedArcInstaller()
    {
        var targets = Program.HybridAgentDownloadTargets();

        Assert.AreEqual(1, targets.Count);
        Assert.AreEqual("Azure Connected Machine Agent", targets[0].Label);
        Assert.AreEqual("https://aka.ms/AzureConnectedMachineAgent", targets[0].Url);
        Assert.IsTrue(targets[0].UseArcAgentRoute);
        Assert.IsFalse(targets.Any(target =>
            target.Url.Contains("go.microsoft.com", StringComparison.OrdinalIgnoreCase)));
    }
}
