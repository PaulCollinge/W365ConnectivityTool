using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Services.Tests;

/// <summary>
/// Stub tests that require an active Cloud PC/Session Host connection.
/// These will be implemented in Phase 2 when cloud-side testing is available.
/// </summary>

// ════════════════════════════════════════════════════════════════════
// ID 17 – Location of Cloud PC / Session Host
// ════════════════════════════════════════════════════════════════════
public class CloudPcLocationTest : BaseTest
{
    public override string Id => "17";
    public override string Name => "Cloud PC Location";
    public override string Description => "Shows the Azure region of the Cloud PC/Session Host. Combined with user location, this contextualizes expected latency.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "Connect to your Cloud PC and re-run this test to see the Azure region location.";
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 18 – Latency to Cloud PC / Session Host
// ════════════════════════════════════════════════════════════════════
public class CloudPcLatencyTest : BaseTest
{
    public override string Id => "18";
    public override string Name => "Cloud PC Latency";
    public override string Description => "Measures round-trip latency between the physical device and the Cloud PC/Session Host during an active session.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will show the round-trip latency to your virtual desktop.";
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 19 – Throughput to Cloud PC / Session Host
// ════════════════════════════════════════════════════════════════════
public class CloudPcThroughputTest : BaseTest
{
    public override string Id => "19";
    public override string Name => "Cloud PC Throughput";
    public override string Description => "Measures available throughput between the physical device and Cloud PC/Session Host during an active session.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will measure end-to-end throughput to your virtual desktop.\n" +
                              "Compare with local bandwidth to identify bottlenecks in the connection.";
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 20 – Jitter
// ════════════════════════════════════════════════════════════════════
public class JitterTest : BaseTest
{
    public override string Id => "20";
    public override string Name => "Connection Jitter";
    public override string Description => "Measures packet arrival interval variation (jitter) on the connection. High jitter (>30ms) causes poor user experience for real-time RDP traffic.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will measure jitter on the RDP connection.\n" +
                              "Jitter above 30ms is considered problematic for real-time desktop traffic.\n" +
                              "Common causes include non-optimized network paths, proxies, or TLS inspection.";
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 21 – Packet Loss
// ════════════════════════════════════════════════════════════════════
public class PacketLossTest : BaseTest
{
    public override string Id => "21";
    public override string Name => "Packet Loss";
    public override string Description => "Measures packet loss on the connection to the Cloud PC/Session Host. Loss above 5% severely impacts real-time RDP traffic quality.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will measure packet loss on the RDP connection.\n" +
                              "Packet loss above 5% is problematic for real-time media traffic.\n" +
                              "Causes include congested network links, faulty hardware, or Wi-Fi interference.";
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 22 – Teams Optimization on Cloud PC
// ════════════════════════════════════════════════════════════════════
public class CloudTeamsOptimizationTest : BaseTest
{
    public override string Id => "22";
    public override string Name => "Cloud PC Teams Optimization";
    public override string Description => "Checks whether Teams media optimization is properly configured on the Cloud PC/Session Host for optimal audio/video.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will verify the Teams media optimization (Slimcore)\n" +
                              "configuration on the virtual desktop side.";
        result.RemediationUrl = EndpointConfiguration.Docs.TeamsOptimization;
        return Task.CompletedTask;
    }
}

// ════════════════════════════════════════════════════════════════════
// ID 24 – VPN Connection Performance
// ════════════════════════════════════════════════════════════════════
public class VpnPerformanceTest : BaseTest
{
    public override string Id => "24";
    public override string Name => "VPN Connection Performance";
    public override string Description => "Evaluates the impact of VPN on connection performance. If connections are flaky over VPN or bandwidth is lower, suggests connecting without VPN.";
    public override TestCategory Category => TestCategory.CloudSession;
    public override TestPriority Priority => TestPriority.Important;
    public override bool RequiresActiveSession => true;

    protected override Task ExecuteAsync(TestResult result, CancellationToken ct)
    {
        result.Status = TestStatus.Skipped;
        result.ResultValue = "Requires active session";
        result.DetailedInfo = "This test requires an active connection to a Cloud PC or Session Host.\n" +
                              "While connected, this will compare connection performance with and without VPN\n" +
                              "to determine if the VPN is negatively impacting the remote desktop experience.";
        return Task.CompletedTask;
    }
}
