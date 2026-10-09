using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;

namespace W365LocalScanner;

internal sealed record ServiceProxyEvidence(
    string Account,
    bool QuerySucceeded,
    bool MatchesMachineProxy,
    string Output,
    string? Error);

internal sealed record AvdNativeHealthEvidence(
    string? UrlToolPath,
    string? UrlToolVersion,
    AvdUrlToolSnapshot? UrlTool,
    string? UrlToolError,
    AvdHealthEventSummary Events,
    string? EventLogError,
    IReadOnlyList<ServiceProxyEvidence> ServiceProxies)
{
    internal static AvdNativeHealthEvidence Unavailable(string error) =>
        new(null, null, null, error, new([], null), null, []);
}

internal static class AvdNativeHealthCollector
{
    private static readonly TimeSpan UrlToolTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(8);
    private const int MaximumCapturedCharacters = 1_048_576;

    internal static async Task<AvdNativeHealthEvidence> CollectAsync(
        WinHttpProxyConfiguration machineProxy)
    {
        var eventResult = ReadHealthEvents();
        var serviceProxyTask = ReadServiceProxiesAsync(machineProxy);
        var urlToolResult = await RunUrlToolAsync();
        var serviceProxies = await serviceProxyTask;

        return new(
            urlToolResult.Path,
            urlToolResult.Version,
            urlToolResult.Snapshot,
            urlToolResult.Error,
            eventResult.Summary,
            eventResult.Error,
            serviceProxies);
    }

    private static async Task<(
        string? Path,
        string? Version,
        AvdUrlToolSnapshot? Snapshot,
        string? Error)> RunUrlToolAsync()
    {
        string? path;
        try
        {
            path = FindNewestUrlTool();
        }
        catch (Exception ex)
        {
            return (null, null, null, $"Could not search for WVDAgentUrlTool.exe: {ex.Message}");
        }

        if (path == null)
            return (null, null, null, "WVDAgentUrlTool.exe was not found");

        string? version = null;
        try
        {
            version = FileVersionInfo.GetVersionInfo(path).FileVersion;
        }
        catch (Exception ex)
        {
            version = $"unavailable ({ex.Message})";
        }

        var execution = await RunProcessAsync(path, [], Path.GetTempPath(), UrlToolTimeout);
        if (!execution.Started)
            return (path, version, null, execution.Error);
        if (execution.TimedOut)
            return (path, version, null, $"WVDAgentUrlTool.exe timed out after {UrlToolTimeout.TotalSeconds:0}s");

        var output = string.Join(
            Environment.NewLine,
            new[] { execution.StandardOutput, execution.StandardError }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
        var snapshot = AvdUrlToolSnapshot.Parse(output);
        if (!snapshot.Parsed)
        {
            var exit = execution.ExitCode.HasValue ? $"exit code {execution.ExitCode}" : "unknown exit code";
            return (path, version, snapshot, $"{snapshot.ParseError} ({exit})");
        }

        return (path, version, snapshot, null);
    }

    private static string? FindNewestUrlTool()
    {
        var rdInfraRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Microsoft RDInfra");
        if (!Directory.Exists(rdInfraRoot))
            return null;

        return Directory
            .EnumerateFiles(rdInfraRoot, "WVDAgentUrlTool.exe", SearchOption.AllDirectories)
            .Select(path =>
            {
                Version? version = null;
                bool microsoftBinary = false;
                try
                {
                    var metadata = FileVersionInfo.GetVersionInfo(path);
                    Version.TryParse(metadata.FileVersion, out version);
                    microsoftBinary = metadata.CompanyName?.Contains(
                        "Microsoft",
                        StringComparison.OrdinalIgnoreCase) == true;
                }
                catch
                {
                    // Unverifiable candidates are excluded below.
                }

                DateTime lastWrite;
                try { lastWrite = File.GetLastWriteTimeUtc(path); }
                catch { lastWrite = DateTime.MinValue; }
                return (path, version, lastWrite, microsoftBinary);
            })
            .Where(item => item.microsoftBinary)
            .OrderByDescending(item => item.version)
            .ThenByDescending(item => item.lastWrite)
            .Select(item => item.path)
            .FirstOrDefault();
    }

    private static (
        AvdHealthEventSummary Summary,
        string? Error) ReadHealthEvents()
    {
        try
        {
            const string queryText =
                "*[System[Provider[@Name='WVD-Agent'] and " +
                "(EventID=3701 or EventID=3702) and " +
                "TimeCreated[timediff(@SystemTime) <= 172800000]]]";
            var query = new EventLogQuery("Application", PathType.LogName, queryText)
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(query);
            var observations = new List<AvdHealthEventObservation>();

            while (observations.Count < 500)
            {
                using var record = reader.ReadEvent();
                if (record == null)
                    break;

                var rawValues = record.Properties
                    .Select(property => property.Value?.ToString())
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .ToArray();
                string message = string.Join(Environment.NewLine, rawValues);
                try
                {
                    var formatted = record.FormatDescription();
                    if (!string.IsNullOrWhiteSpace(formatted))
                        message = string.Join(Environment.NewLine, message, formatted);
                }
                catch
                {
                    // Raw event properties remain available when provider resources are missing.
                }

                var createdAt = record.TimeCreated.HasValue
                    ? new DateTimeOffset(record.TimeCreated.Value).ToUniversalTime()
                    : DateTimeOffset.MinValue;
                var hostsOnly = string.Join(
                    Environment.NewLine,
                    AvdUrlToolSnapshot.ExtractHosts(message));
                observations.Add(new(record.Id, createdAt, hostsOnly));
            }

            return (AvdHealthEventSummary.Analyze(observations), null);
        }
        catch (Exception ex)
        {
            return (new([], null), $"Could not read WVD-Agent events: {ex.Message}");
        }
    }

    private static async Task<IReadOnlyList<ServiceProxyEvidence>> ReadServiceProxiesAsync(
        WinHttpProxyConfiguration machineProxy)
    {
        var tasks = new[] { "LOCALSYSTEM", "NETWORKSERVICE" }
            .Select(account => ReadServiceProxyAsync(account, machineProxy))
            .ToArray();
        return await Task.WhenAll(tasks);
    }

    private static async Task<ServiceProxyEvidence> ReadServiceProxyAsync(
        string account,
        WinHttpProxyConfiguration machineProxy)
    {
        var execution = await RunProcessAsync(
            "bitsadmin.exe",
            ["/util", "/getieproxy", account],
            null,
            CommandTimeout);
        var output = string.Join(
            Environment.NewLine,
            new[] { execution.StandardOutput, execution.StandardError }
                .Where(value => !string.IsNullOrWhiteSpace(value)))
            .Trim();

        if (!execution.Started)
            return new(account, false, false, output, execution.Error);
        if (execution.TimedOut)
            return new(account, false, false, output, "bitsadmin query timed out");
        if (execution.ExitCode != 0)
            return new(account, false, false, output, $"bitsadmin exited with code {execution.ExitCode}");

        bool matches = !machineProxy.IsDirect
            && machineProxy.Available
            && !string.IsNullOrWhiteSpace(machineProxy.ProxyValue)
            && output.Contains(machineProxy.ProxyValue, StringComparison.OrdinalIgnoreCase);
        return new(account, true, matches, output, null);
    }

    private static async Task<ProcessExecution> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory,
        TimeSpan timeout)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory ?? string.Empty,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Exception ex)
        {
            return new(false, false, null, string.Empty, string.Empty, ex.Message);
        }

        if (process == null)
            return new(false, false, null, string.Empty, string.Empty, $"Could not start {fileName}");

        using (process)
        {
            process.StandardInput.Close();
            var stdoutTask = ReadBoundedAsync(process.StandardOutput);
            var stderrTask = ReadBoundedAsync(process.StandardError);
            using var timeoutSource = new CancellationTokenSource(timeout);
            try
            {
                await process.WaitForExitAsync(timeoutSource.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
                catch (Exception ex)
                {
                    process.StandardOutput.Close();
                    process.StandardError.Close();
                    return new(
                        true,
                        true,
                        null,
                        string.Empty,
                        string.Empty,
                        $"Timed out and could not terminate {fileName}: {ex.Message}");
                }

                return new(
                    true,
                    true,
                    null,
                    await stdoutTask,
                    await stderrTask,
                    null);
            }

            return new(
                true,
                false,
                process.ExitCode,
                await stdoutTask,
                await stderrTask,
                null);
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var buffer = new char[4096];
        var builder = new StringBuilder();
        bool truncated = false;
        while (true)
        {
            int read = await reader.ReadAsync(buffer);
            if (read == 0)
                break;

            int remaining = MaximumCapturedCharacters - builder.Length;
            if (remaining > 0)
                builder.Append(buffer, 0, Math.Min(read, remaining));
            if (read > remaining)
                truncated = true;
        }

        if (truncated)
            builder.AppendLine().Append("[output truncated]");
        return builder.ToString();
    }

    private sealed record ProcessExecution(
        bool Started,
        bool TimedOut,
        int? ExitCode,
        string StandardOutput,
        string StandardError,
        string? Error);
}
