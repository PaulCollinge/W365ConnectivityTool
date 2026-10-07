namespace W365LocalScanner;

internal static class HybridTimeSyncAnalysis
{
    internal static bool HasSynchronizedSource(string? source, int? leapIndicator)
    {
        if (string.IsNullOrWhiteSpace(source)
            || !leapIndicator.HasValue
            || leapIndicator.Value is < 0 or > 2)
            return false;

        return !source.Equals("Local CMOS Clock", StringComparison.OrdinalIgnoreCase)
            && !source.Equals("Free-running System Clock", StringComparison.OrdinalIgnoreCase)
            && !source.Equals("unknown", StringComparison.OrdinalIgnoreCase);
    }
}
