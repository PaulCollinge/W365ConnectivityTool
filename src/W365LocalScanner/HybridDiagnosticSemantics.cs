namespace W365LocalScanner;

internal readonly record struct DiagnosticOutcome(
    string Status,
    string Summary,
    string? Remediation = null);

internal static class HybridDiagnosticSemantics
{
    internal static DiagnosticOutcome AssessRdpEgress(
        int verifiedPaths,
        int concernCount,
        bool isHybrid,
        string concernSummary)
    {
        if (concernCount > 0)
        {
            return new(
                "Warning",
                $"RDP traffic may use an unintended route: {concernSummary}",
                "Ensure 40.64.144.0/20 (Gateway) and 51.5.0.0/16 (TURN) use the intended direct route and aren't captured by a VPN/SWG.");
        }

        if (verifiedPaths == 0)
        {
            return new(
                "Info",
                "RDP egress inconclusive — gateway and TURN names were unavailable to local DNS",
                "Use C-TCP-04 for the proxy-routed gateway result and C-UDP-03 for the direct TURN DNS/UDP requirement.");
        }

        if (verifiedPaths < 2)
        {
            return new(
                "Info",
                $"RDP egress partially verified ({verifiedPaths}/2 paths resolved)",
                "Review the unresolved gateway or TURN path before concluding that all RDP traffic follows the intended route.");
        }

        return new(
            "Passed",
            isHybrid
                ? "RDP service destinations resolve to Azure and avoid detected VPN/SWG routes"
                : "RDP traffic stays within Azure — no VPN/SWG routing detected");
    }

    internal static DiagnosticOutcome AssessTurnRoute(
        int issueCount,
        int detectedVpnCount,
        bool serviceRangesVerified,
        bool turnDnsResolved,
        string detectedVpnNames)
    {
        if (issueCount > 0)
        {
            return new(
                "Warning",
                $"{issueCount} potential UDP blocker(s) detected",
                "Review the detailed routes and allow direct UDP 3478 to 51.5.0.0/16.");
        }

        if (detectedVpnCount > 0)
        {
            return serviceRangesVerified
                ? new("Passed", $"VPN detected ({detectedVpnNames}) — AVD service ranges bypass it")
                : new("Info", $"VPN detected ({detectedVpnNames}) — TURN route unverified");
        }

        return turnDnsResolved
            ? new("Passed", "No local UDP blocker detected; TURN DNS resolves")
            : new(
                "Info",
                "No local UDP blocker found, but TURN DNS is unavailable",
                "Allow direct DNS resolution for world.relay.avd.microsoft.com and use C-UDP-03 to verify UDP 3478.");
    }
}
