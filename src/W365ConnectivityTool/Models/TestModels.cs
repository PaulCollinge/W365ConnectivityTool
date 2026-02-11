namespace W365ConnectivityTool.Models;

/// <summary>
/// Status of a connectivity test.
/// </summary>
public enum TestStatus
{
    NotRun,
    Running,
    Passed,
    Warning,
    Failed,
    Skipped,
    Error
}

/// <summary>
/// Logical category grouping for tests.
/// </summary>
public enum TestCategory
{
    EndpointAccess,
    LocalEnvironment,
    TcpTransport,
    UdpShortpath,
    CloudSession
}

/// <summary>
/// Priority level: 0 = critical, 1 = important.
/// </summary>
public enum TestPriority
{
    Critical = 0,
    Important = 1
}

/// <summary>
/// Represents the result of a single connectivity test.
/// </summary>
public class TestResult
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public TestCategory Category { get; set; }
    public TestPriority Priority { get; set; }
    public TestStatus Status { get; set; } = TestStatus.NotRun;
    public string ResultValue { get; set; } = "Not tested";
    public string DetailedInfo { get; set; } = string.Empty;
    public string RemediationUrl { get; set; } = string.Empty;
    public string RemediationText { get; set; } = string.Empty;
    public bool RequiresActiveSession { get; set; }
    public TimeSpan Duration { get; set; }
}
