using System.Diagnostics;
using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Services.Tests;

/// <summary>
/// Contract for all connectivity tests.
/// </summary>
public interface IConnectivityTest
{
    string Id { get; }
    string Name { get; }
    string Description { get; }
    TestCategory Category { get; }
    TestPriority Priority { get; }
    bool RequiresActiveSession { get; }
    Task<TestResult> RunAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Base class providing common test execution scaffolding.
/// </summary>
public abstract class BaseTest : IConnectivityTest
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract TestCategory Category { get; }
    public virtual TestPriority Priority => TestPriority.Critical;
    public virtual bool RequiresActiveSession => false;

    /// <summary>
    /// Per-test timeout in seconds. Override to allow longer-running tests (e.g. bandwidth).
    /// </summary>
    public virtual int TimeoutSeconds => 30;

    public async Task<TestResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var result = CreateResult();
        var sw = Stopwatch.StartNew();

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(TimeoutSeconds));
            await ExecuteAsync(result, cts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = $"Timed out ({TimeoutSeconds}s)";
        }
        catch (OperationCanceledException)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = "Test cancelled";
        }
        catch (Exception ex)
        {
            result.Status = TestStatus.Error;
            result.ResultValue = $"Error: {ex.Message}";
            result.DetailedInfo = ex.ToString();
        }
        finally
        {
            sw.Stop();
            result.Duration = sw.Elapsed;
        }

        return result;
    }

    protected abstract Task ExecuteAsync(TestResult result, CancellationToken cancellationToken);

    private TestResult CreateResult()
    {
        return new TestResult
        {
            Id = Id,
            Name = Name,
            Description = Description,
            Category = Category,
            Priority = Priority,
            RequiresActiveSession = RequiresActiveSession,
            Status = TestStatus.Running
        };
    }
}
