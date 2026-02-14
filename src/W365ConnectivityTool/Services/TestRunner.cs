using W365ConnectivityTool.Models;
using W365ConnectivityTool.Services.Tests;

namespace W365ConnectivityTool.Services;

/// <summary>
/// Orchestrates all connectivity tests, running them in logical order and reporting progress.
/// </summary>
public class TestRunner
{
    private readonly List<IConnectivityTest> _tests;

    public event Action<TestResult>? TestStarted;
    public event Action<TestResult>? TestCompleted;
    public event Action<int, int>? ProgressChanged;
    public event Action? AllTestsCompleted;

    public TestRunner()
    {
        _tests = CreateTests();
    }

    public IReadOnlyList<IConnectivityTest> Tests => _tests;

    /// <summary>
    /// Run all tests sequentially with progress reporting.
    /// </summary>
    public async Task<List<TestResult>> RunAllAsync(CancellationToken ct = default)
    {
        var results = new List<TestResult>();
        int completed = 0;

        foreach (var test in _tests)
        {
            ct.ThrowIfCancellationRequested();

            var placeholder = new TestResult
            {
                Id = test.Id,
                Name = test.Name,
                Description = test.Description,
                Category = test.Category,
                Priority = test.Priority,
                RequiresActiveSession = test.RequiresActiveSession,
                Status = TestStatus.Running
            };

            TestStarted?.Invoke(placeholder);

            var result = await test.RunAsync(ct);
            results.Add(result);
            completed++;

            TestCompleted?.Invoke(result);
            ProgressChanged?.Invoke(completed, _tests.Count);
        }

        AllTestsCompleted?.Invoke();
        return results;
    }

    /// <summary>
    /// Run a single test by ID.
    /// </summary>
    public async Task<TestResult?> RunSingleAsync(string testId, CancellationToken ct = default)
    {
        var test = _tests.FirstOrDefault(t => t.Id == testId);
        if (test == null) return null;

        var placeholder = new TestResult
        {
            Id = test.Id,
            Name = test.Name,
            Status = TestStatus.Running
        };
        TestStarted?.Invoke(placeholder);

        var result = await test.RunAsync(ct);
        TestCompleted?.Invoke(result);
        return result;
    }

    /// <summary>
    /// Creates all test instances in the order they should be executed.
    /// </summary>
    private static List<IConnectivityTest> CreateTests()
    {
        return
        [
            // Endpoint Access (run first — validates all required FQDNs are reachable)
            new EndpointAccessTest(),

            // Local Environment Tests (IDs 01-07, 09-10)
            new LocationTest(),
            new DnsPerformanceTest(),
            new NetworkTypeTest(),
            new WifiStrengthTest(),
            new RouterLatencyTest(),
            new IspDetectionTest(),
            new BandwidthTest(),
            new MachinePerformanceTest(),
            new TeamsOptimizationTest(),

            // Service Connectivity Tests — ordered diagnostic flow
            new GatewayReachabilityTest(),      // 1. TCP Based Connectivity
            new UserLocationTest(),             // 2. User Location
            new NetworkEgressLocationTest(),    // 3. Network Egress Location
            new AfdServiceLocationTest(),       // 4. AFD Location
            new GatewayLocationTest(),          // 5. Gateway Location
            new GatewayLatencyTest(),           // 6. Gateway Latency
            new DnsHijackingTest(),
            new TlsInspectionTest(),
            new ProxyVpnDetectionTest(),

            // RDP Shortpath (UDP) Tests
            new TurnRelayTest(),                // TURN Relay Reachable (first)
            new TurnRelayLocationTest(),
            new NatTypeTest(),
            new IndirectRdpTest(),
            new TurnTlsInspectionTest(),
            new TurnProxyVpnDetectionTest(),

            // Cloud Session Tests — live session analysis (IDs 17-22, 24)
            new ActiveSessionDetectionTest(),
            new TransportProtocolTest(),
            new UdpReadinessTest(),
            new SessionLatencyTest(),
            new SessionFrameRateTest(),
            new ConnectionJitterTest(),
            new FrameDropTest(),
            new CloudTeamsOptimizationTest(),
            new VpnPerformanceTest()
        ];
    }

    /// <summary>
    /// Generate a summary of test results for export.
    /// </summary>
    public static TestSummary GenerateSummary(List<TestResult> results)
    {
        return new TestSummary
        {
            Timestamp = DateTime.UtcNow,
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            TotalTests = results.Count,
            Passed = results.Count(r => r.Status == TestStatus.Passed),
            Warnings = results.Count(r => r.Status == TestStatus.Warning),
            Failed = results.Count(r => r.Status == TestStatus.Failed),
            Errors = results.Count(r => r.Status == TestStatus.Error),
            Skipped = results.Count(r => r.Status == TestStatus.Skipped),
            Results = results
        };
    }
}

public class TestSummary
{
    public DateTime Timestamp { get; set; }
    public string MachineName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public int TotalTests { get; set; }
    public int Passed { get; set; }
    public int Warnings { get; set; }
    public int Failed { get; set; }
    public int Errors { get; set; }
    public int Skipped { get; set; }
    public List<TestResult> Results { get; set; } = [];
}
