namespace W365LocalScanner;

/// <summary>
/// Candidate hostnames under *.prod.warm.ingest.monitor.core.windows.net.
/// Azure Monitor renamed its warm-ingest clusters: every region now publishes
/// "{region}-shared", while only some keep numbered "{region}-N" slots
/// (verified Oct 2026: eastus-0/1/2 and westus-0/1 are NXDOMAIN, eastus-shared
/// and westeurope-shared resolve). Callers must still DNS-validate each
/// candidate, because names keep changing.
/// </summary>
internal static class WarmIngestCandidates
{
    internal const string Suffix = ".prod.warm.ingest.monitor.core.windows.net";

    private static readonly string[] CanaryRegions = ["eastus", "westeurope", "uksouth"];

    internal static IReadOnlyList<string> ForRegion(string? region)
    {
        var normalized = Normalize(region);
        if (normalized == null)
            return [];
        return
        [
            $"{normalized}-shared{Suffix}",
            $"{normalized}-0{Suffix}",
            $"{normalized}-1{Suffix}",
            $"{normalized}-2{Suffix}"
        ];
    }

    /// <summary>
    /// Cross-region canaries used to prove the wildcard rule is open when the
    /// local region's hosts are unavailable. Excludes the local region so a
    /// canary result is genuinely independent evidence.
    /// </summary>
    internal static IReadOnlyList<string> Canaries(string? excludeRegion)
    {
        var excluded = Normalize(excludeRegion);
        return CanaryRegions
            .Where(r => !string.Equals(r, excluded, StringComparison.OrdinalIgnoreCase))
            .SelectMany(ForRegion)
            .ToList();
    }

    internal static bool IsWarmIngestHost(string host) =>
        host.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase);

    private static string? Normalize(string? region)
    {
        if (string.IsNullOrWhiteSpace(region))
            return null;
        var compact = new string(region.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        return compact.Length == 0 ? null : compact;
    }
}
