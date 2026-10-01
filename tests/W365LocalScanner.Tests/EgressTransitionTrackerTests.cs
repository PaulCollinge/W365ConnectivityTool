using Microsoft.VisualStudio.TestTools.UnitTesting;

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
}
