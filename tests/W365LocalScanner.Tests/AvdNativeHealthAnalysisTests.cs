using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class AvdNativeHealthAnalysisTests
{
    private const string SharedHost =
        "westeurope-shared.prod.warm.ingest.monitor.core.windows.net";
    private const string QosHost =
        "westeurope-qos.prod.warm.ingest.monitor.core.windows.net";

    [TestMethod]
    public void UrlToolParsesHealthFailureDespiteSuccessfulProcessExitSemantics()
    {
        var snapshot = AvdUrlToolSnapshot.Parse($"""
            Azure Virtual Desktop Agent URL Tool
            Version 1.0.15732.100

            UrlsAccessibleCheck :  Outcome: HealthCheckFailed

            Accessible URLs:
            ======================================================
            gcs.prod.monitoring.core.windows.net

            NOT Accessible URLs:
            ======================================================
            {SharedHost}
            {QosHost}

            Acquired on:10/9/2026 10:35:17 AM UTC
            """);

        Assert.IsTrue(snapshot.Parsed);
        Assert.IsTrue(snapshot.HealthCheckFailed);
        Assert.AreEqual("HealthCheckFailed", snapshot.Outcome);
        CollectionAssert.AreEquivalent(
            new[] { SharedHost, QosHost },
            snapshot.InaccessibleUrls.ToArray());
        Assert.AreEqual(
            new DateTimeOffset(2026, 10, 9, 10, 35, 17, TimeSpan.Zero),
            snapshot.AcquiredAt);
    }

    [TestMethod]
    public void UrlToolUnknownFormatDoesNotBecomeSuccess()
    {
        var snapshot = AvdUrlToolSnapshot.Parse("A future tool changed its output format.");

        Assert.IsFalse(snapshot.Parsed);
        Assert.IsFalse(snapshot.HealthCheckFailed);
        Assert.IsNotNull(snapshot.ParseError);
        Assert.AreEqual(0, snapshot.AccessibleUrls.Count);
        Assert.AreEqual(0, snapshot.InaccessibleUrls.Count);
    }

    [TestMethod]
    public void UrlToolRequiresFreshAcquisitionTimeForAuthoritativeUse()
    {
        var now = new DateTimeOffset(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
        var stale = new AvdUrlToolSnapshot(
            true,
            "HealthCheckFailed",
            now.AddHours(-2),
            [],
            [SharedHost],
            null);
        var missingTimestamp = stale with { AcquiredAt = null };
        var current = stale with { AcquiredAt = now.AddMinutes(-30) };

        Assert.IsFalse(stale.IsFresh(now, TimeSpan.FromMinutes(90)));
        Assert.IsFalse(missingTimestamp.IsFresh(now, TimeSpan.FromMinutes(90)));
        Assert.IsTrue(current.IsFresh(now, TimeSpan.FromMinutes(90)));
    }

    [TestMethod]
    public void SyntheticExemplarNeverCollidesWithNativeHost()
    {
        var nativeHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "eastus-0.prod.warm.ingest.monitor.core.windows.net"
        };

        var exemplar = AvdUrlToolSnapshot.SelectSyntheticWarmIngestExemplar(
            "eastus-0.prod.warm.ingest.monitor.core.windows.net",
            nativeHosts);

        Assert.AreEqual(
            "westus-0.prod.warm.ingest.monitor.core.windows.net",
            exemplar);
    }

    [TestMethod]
    public void UrlToolStoresOnlyHostsAndDropsSensitiveUrlComponents()
    {
        var snapshot = AvdUrlToolSnapshot.Parse($"""
            UrlsAccessibleCheck : Outcome: HealthCheckFailed
            NOT Accessible URLs:
            https://{SharedHost}/collect?sv=1&sig=SECRET&registrationToken=TOKEN
            """);

        Assert.AreEqual(1, snapshot.InaccessibleUrls.Count);
        Assert.AreEqual(SharedHost, snapshot.InaccessibleUrls[0]);
        Assert.IsFalse(snapshot.InaccessibleUrls[0].Contains("SECRET", StringComparison.Ordinal));
        Assert.IsFalse(snapshot.InaccessibleUrls[0].Contains("TOKEN", StringComparison.Ordinal));
    }

    [TestMethod]
    public void EventsUseLatestObservationPerHost()
    {
        var firstFailure = new DateTimeOffset(2026, 10, 9, 9, 5, 0, TimeSpan.Zero);
        var summary = AvdHealthEventSummary.Analyze(
        [
            new(3702, firstFailure, $"NOT Accessible URLs:\n{SharedHost}"),
            new(3701, firstFailure.AddMinutes(30), $"Accessible URLs:\n{SharedHost}"),
            new(3702, firstFailure.AddMinutes(60), $"NOT Accessible URLs:\n{QosHost}")
        ]);

        var shared = summary.HostStates.Single(state => state.Host == SharedHost);
        var qos = summary.HostStates.Single(state => state.Host == QosHost);

        Assert.IsTrue(shared.IsAccessible);
        Assert.IsNull(shared.FailureStartedAt);
        Assert.IsFalse(qos.IsAccessible);
        Assert.AreEqual(firstFailure.AddMinutes(60), qos.FailureStartedAt);
    }

    [TestMethod]
    public void RepeatedFailurePreservesBeginningOfCurrentFailurePeriod()
    {
        var firstFailure = new DateTimeOffset(2026, 10, 7, 10, 0, 0, TimeSpan.Zero);
        var summary = AvdHealthEventSummary.Analyze(
        [
            new(3702, firstFailure, SharedHost),
            new(3702, firstFailure.AddMinutes(30), SharedHost),
            new(3702, firstFailure.AddMinutes(60), SharedHost)
        ]);

        var state = summary.HostStates.Single();
        Assert.IsFalse(state.IsAccessible);
        Assert.AreEqual(firstFailure, state.FailureStartedAt);
        Assert.AreEqual(firstFailure.AddMinutes(60), state.LatestObservedAt);
    }

    [TestMethod]
    public void StaleFailuresAreNotAuthoritative()
    {
        var now = new DateTimeOffset(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
        var summary = AvdHealthEventSummary.Analyze(
        [
            new(3702, now.AddHours(-2), SharedHost)
        ]);

        Assert.AreEqual(0, summary.FreshFailures(now, TimeSpan.FromMinutes(90)).Count);
    }

    [TestMethod]
    public void LocalizedEventTextStillExtractsExactHosts()
    {
        var hosts = AvdUrlToolSnapshot.ExtractHosts(
            $"Nicht erreichbare URLs:\r\n{SharedHost}\r\n{QosHost}");

        CollectionAssert.AreEquivalent(
            new[] { SharedHost, QosHost },
            hosts.ToArray());
    }

    [TestMethod]
    public void EmptyEventsRemainNoEvidence()
    {
        var summary = AvdHealthEventSummary.Analyze([]);

        Assert.AreEqual(0, summary.HostStates.Count);
        Assert.IsNull(summary.LatestObservedAt);
        Assert.AreEqual(
            0,
            summary.FreshFailures(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(90)).Count);
    }

    [TestMethod]
    public void NativeFailureOverridesSuccessfulBasicTransport()
    {
        var assessment = AvdEndpointAssessment.Assess(
            nativeAccessible: false,
            nativeSource: "Microsoft AVD Agent URL Tool",
            transportSucceeded: true,
            transportDetail: "HTTPS 404 via machine WinHTTP proxy");

        Assert.IsFalse(assessment.IsAccessible);
        StringAssert.Contains(assessment.Detail, "required URL inaccessible");
        StringAssert.Contains(assessment.Detail, "basic HTTPS transport succeeded");
        StringAssert.Contains(assessment.Detail, "HTTPS 404");
    }

    [TestMethod]
    public void NativeSuccessCanOverrideSyntheticProbeLimitation()
    {
        var assessment = AvdEndpointAssessment.Assess(
            nativeAccessible: true,
            nativeSource: "Microsoft AVD Agent URL Tool",
            transportSucceeded: false,
            transportDetail: "invoking-user DNS unavailable");

        Assert.IsTrue(assessment.IsAccessible);
        StringAssert.Contains(assessment.Detail, "reports accessible");
        StringAssert.Contains(assessment.Detail, "synthetic transport probe failed");
    }
}
