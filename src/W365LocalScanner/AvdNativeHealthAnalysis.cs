using System.Globalization;
using System.Text.RegularExpressions;

namespace W365LocalScanner;

internal sealed record AvdUrlToolSnapshot(
    bool Parsed,
    string? Outcome,
    DateTimeOffset? AcquiredAt,
    IReadOnlyList<string> AccessibleUrls,
    IReadOnlyList<string> InaccessibleUrls,
    string? ParseError)
{
    internal bool HealthCheckFailed =>
        InaccessibleUrls.Count > 0
        || string.Equals(Outcome, "HealthCheckFailed", StringComparison.OrdinalIgnoreCase);

    internal bool IsFresh(DateTimeOffset now, TimeSpan maximumAge)
    {
        if (!AcquiredAt.HasValue)
            return false;

        var age = now.ToUniversalTime() - AcquiredAt.Value.ToUniversalTime();
        return age >= TimeSpan.FromMinutes(-5) && age <= maximumAge;
    }

    internal static string SelectSyntheticWarmIngestExemplar(
        string? preferredHost,
        IReadOnlySet<string> nativeHosts)
    {
        var candidates = new[]
        {
            preferredHost,
            "eastus-0.prod.warm.ingest.monitor.core.windows.net",
            "westus-0.prod.warm.ingest.monitor.core.windows.net",
            "eastus-1.prod.warm.ingest.monitor.core.windows.net",
            "westus-1.prod.warm.ingest.monitor.core.windows.net",
            "eastus-2.prod.warm.ingest.monitor.core.windows.net",
            "westus-2.prod.warm.ingest.monitor.core.windows.net"
        };

        return candidates
            .Where(host => !string.IsNullOrWhiteSpace(host))
            .Select(host => host!)
            .First(host => !nativeHosts.Contains(host));
    }

    internal static AvdUrlToolSnapshot Parse(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return new(false, null, null, [], [], "The URL Tool produced no output");

        string? outcome = null;
        DateTimeOffset? acquiredAt = null;
        var accessible = new List<string>();
        var inaccessible = new List<string>();
        List<string>? activeSection = null;

        foreach (var rawLine in output.Replace("\r", "").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.All(ch => ch == '='))
                continue;

            var outcomeMatch = Regex.Match(
                line,
                @"UrlsAccessibleCheck\s*:\s*Outcome\s*:\s*(?<outcome>[^\s]+)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (outcomeMatch.Success)
            {
                outcome = outcomeMatch.Groups["outcome"].Value;
                activeSection = null;
                continue;
            }

            if (line.Equals("Accessible URLs:", StringComparison.OrdinalIgnoreCase))
            {
                activeSection = accessible;
                continue;
            }

            if (line.Equals("NOT Accessible URLs:", StringComparison.OrdinalIgnoreCase))
            {
                activeSection = inaccessible;
                continue;
            }

            if (line.StartsWith("Acquired on:", StringComparison.OrdinalIgnoreCase))
            {
                var value = line["Acquired on:".Length..].Trim();
                value = Regex.Replace(
                    value,
                    @"\s+UTC$",
                    " +00:00",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (DateTimeOffset.TryParse(
                        value,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var timestamp)
                    || DateTimeOffset.TryParse(
                        value,
                        CultureInfo.CurrentCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out timestamp))
                {
                    acquiredAt = timestamp;
                }
                activeSection = null;
                continue;
            }

            if (activeSection != null && TryNormalizeHost(line, out var host))
                activeSection.Add(host);
        }

        var accessibleUrls = accessible
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var inaccessibleUrls = inaccessible
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        bool parsed = outcome != null || accessibleUrls.Length > 0 || inaccessibleUrls.Length > 0;

        return new(
            parsed,
            outcome,
            acquiredAt,
            accessibleUrls,
            inaccessibleUrls,
            parsed ? null : "The URL Tool output did not contain recognizable health-check fields");
    }

    internal static bool IsWarmIngestHost(string host) =>
        host.EndsWith(
            ".prod.warm.ingest.monitor.core.windows.net",
            StringComparison.OrdinalIgnoreCase);

    internal static IReadOnlyList<string> ExtractHosts(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return [];

        return Regex.Matches(
                message,
                @"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])",
                RegexOptions.CultureInvariant)
            .Select(match => match.Value.TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool TryNormalizeHost(string value, out string host)
    {
        host = string.Empty;
        var candidate = value.Trim().TrimEnd('.');
        if (candidate.Length == 0)
            return false;

        if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            candidate = uri.Host;
        else
            candidate = candidate.Split('/', '\\', ':')[0];

        if (Uri.CheckHostName(candidate) != UriHostNameType.Dns)
            return false;

        host = candidate.ToLowerInvariant();
        return true;
    }
}

internal sealed record AvdHealthEventObservation(
    int EventId,
    DateTimeOffset CreatedAt,
    string Message);

internal sealed record AvdHealthHostState(
    string Host,
    bool IsAccessible,
    DateTimeOffset LatestObservedAt,
    DateTimeOffset? FailureStartedAt);

internal sealed record AvdHealthEventSummary(
    IReadOnlyList<AvdHealthHostState> HostStates,
    DateTimeOffset? LatestObservedAt)
{
    internal IReadOnlyList<AvdHealthHostState> FreshFailures(
        DateTimeOffset now,
        TimeSpan maximumAge) =>
        HostStates
            .Where(state =>
                !state.IsAccessible
                && now - state.LatestObservedAt >= TimeSpan.Zero
                && now - state.LatestObservedAt <= maximumAge)
            .ToArray();

    internal static AvdHealthEventSummary Analyze(
        IEnumerable<AvdHealthEventObservation> observations)
    {
        var states = new Dictionary<string, AvdHealthHostState>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset? latestObservedAt = null;

        foreach (var observation in observations.OrderBy(item => item.CreatedAt))
        {
            if (observation.EventId is not (3701 or 3702))
                continue;

            bool isAccessible = observation.EventId == 3701;
            latestObservedAt = latestObservedAt == null || observation.CreatedAt > latestObservedAt
                ? observation.CreatedAt
                : latestObservedAt;

            foreach (var host in AvdUrlToolSnapshot.ExtractHosts(observation.Message))
            {
                states.TryGetValue(host, out var previous);
                DateTimeOffset? failureStartedAt = isAccessible
                    ? null
                    : previous is { IsAccessible: false }
                        ? previous.FailureStartedAt ?? previous.LatestObservedAt
                        : observation.CreatedAt;

                states[host] = new(
                    host,
                    isAccessible,
                    observation.CreatedAt,
                    failureStartedAt);
            }
        }

        return new(
            states.Values
                .OrderBy(state => state.Host, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            latestObservedAt);
    }
}

internal sealed record AvdEndpointAssessment(
    bool IsAccessible,
    string Detail)
{
    internal static AvdEndpointAssessment Assess(
        bool nativeAccessible,
        string nativeSource,
        bool transportSucceeded,
        string transportDetail)
    {
        if (nativeAccessible)
        {
            var transport = transportSucceeded
                ? transportDetail
                : $"synthetic transport probe failed: {transportDetail}";
            return new(
                true,
                $"{nativeSource} reports accessible; {transport}");
        }

        var basicTransport = transportSucceeded
            ? $"basic HTTPS transport succeeded ({transportDetail})"
            : $"basic HTTPS transport also failed ({transportDetail})";
        return new(
            false,
            $"{nativeSource} reports this required URL inaccessible; {basicTransport}");
    }
}
