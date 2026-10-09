namespace W365LocalScanner;

internal sealed record AgentDownloadTarget(
    string Label,
    string Url,
    bool UseArcAgentRoute);
