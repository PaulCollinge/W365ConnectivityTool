using System.Text.Json;

namespace W365LocalScanner;

internal sealed record ArcGatewaySnapshot(
    bool IsGateway,
    string? GatewayUrl,
    string? LocalProxyUrl,
    string? UpstreamProxyUrl)
{
    internal static ArcGatewaySnapshot Parse(string? configuredConnectionType, string? showJson)
    {
        bool isGateway = configuredConnectionType?.Trim()
            .Equals("gateway", StringComparison.OrdinalIgnoreCase) == true;
        string? gatewayUrl = null;
        string? localProxyUrl = null;
        string? upstreamProxyUrl = null;

        if (!string.IsNullOrWhiteSpace(showJson))
        {
            foreach (string candidate in GetJsonCandidates(showJson))
            {
                try
                {
                    using var document = JsonDocument.Parse(candidate);
                    Visit(document.RootElement, null);
                    break;
                }
                catch (JsonException)
                {
                    // Try the extracted JSON body when older agents add diagnostic text.
                }
            }
        }

        return new(isGateway, gatewayUrl, localProxyUrl, upstreamProxyUrl);

        void Visit(JsonElement element, string? propertyName)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                        Visit(property.Value, property.Name);
                    break;
                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                        Visit(item, propertyName);
                    break;
                case JsonValueKind.String:
                    Inspect(propertyName, element.GetString());
                    break;
            }
        }

        void Inspect(string? propertyName, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;

            string key = NormalizeKey(propertyName);
            string trimmed = value.Trim();
            if (key.Contains("connectiontype", StringComparison.Ordinal)
                && trimmed.Equals("gateway", StringComparison.OrdinalIgnoreCase))
            {
                isGateway = true;
            }

            if (!TryNormalizeUri(trimmed, out var uri))
                return;

            if (uri.Host.EndsWith(".gw.arc.azure.com", StringComparison.OrdinalIgnoreCase))
            {
                gatewayUrl ??= uri.GetLeftPart(UriPartial.Authority);
                isGateway = true;
            }

            if (uri.IsLoopback && uri.Port == 40343)
                localProxyUrl ??= uri.GetLeftPart(UriPartial.Authority);

            if (key.Contains("upstreamproxy", StringComparison.Ordinal) && !uri.IsLoopback)
                upstreamProxyUrl ??= uri.GetLeftPart(UriPartial.Authority);
        }
    }

    private static string NormalizeKey(string? value) =>
        new((value ?? string.Empty)
            .Where(char.IsLetterOrDigit)
            .Select(char.ToLowerInvariant)
            .ToArray());

    private static IEnumerable<string> GetJsonCandidates(string output)
    {
        yield return output;

        int start = output.IndexOf('{');
        int end = output.LastIndexOf('}');
        if (start >= 0 && end > start && (start != 0 || end != output.Length - 1))
            yield return output[start..(end + 1)];
    }

    private static bool TryNormalizeUri(string value, out Uri uri)
    {
        string candidate = value.Contains("://", StringComparison.Ordinal)
            ? value
            : $"https://{value}";
        return Uri.TryCreate(candidate, UriKind.Absolute, out uri!)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            && !string.IsNullOrWhiteSpace(uri.Host);
    }
}

internal readonly record struct ArcEndpointRequirement(
    string Host,
    int Port,
    string Purpose,
    string Group);

internal static class ArcEndpointCatalog
{
    internal static IReadOnlyList<ArcEndpointRequirement> Build(
        ArcGatewaySnapshot gateway,
        string region)
    {
        string? normalizedRegion = string.IsNullOrWhiteSpace(region)
            ? null
            : region.Replace(" ", "").ToLowerInvariant();

        if (gateway.IsGateway)
        {
            var endpoints = new List<ArcEndpointRequirement>();
            if (Uri.TryCreate(gateway.GatewayUrl, UriKind.Absolute, out var gatewayUri))
            {
                endpoints.Add(new(
                    gatewayUri.Host,
                    443,
                    "Azure Arc Gateway endpoint (TLS inspection must be bypassed)",
                    "Arc Gateway Required"));
            }

            endpoints.AddRange(
            [
                new("management.azure.com", 443,
                    "Azure Resource Manager control channel", "Arc Gateway Required"),
                new("login.microsoftonline.com", 443,
                    "Global Microsoft Entra token endpoint", "Arc Gateway Required"),
                new("gbl.his.arc.azure.com", 443,
                    "Global Azure Arc agent service", "Arc Gateway Required"),
                new("download.microsoft.com", 443,
                    "Windows Azure Connected Machine agent installation package", "Arc Gateway Required")
            ]);
            if (normalizedRegion != null)
            {
                endpoints.Add(new(
                    $"{normalizedRegion}.login.microsoft.com", 443,
                    "Regional Microsoft Entra token endpoint", "Arc Gateway Required"));
                endpoints.Add(new(
                    $"{normalizedRegion}.his.arc.azure.com", 443,
                    "Regional Azure Arc control channel", "Arc Gateway Required"));
            }
            return endpoints;
        }

        var classicEndpoints = new List<ArcEndpointRequirement>
        {
            new("gbl.his.arc.azure.com", 443,
                "Arc hybrid-identity service — proves *.his.arc.azure.com", "Arc Control Plane"),
            new("agentserviceapi.guestconfiguration.azure.com", 443,
                "Arc extension management (*.guestconfiguration.azure.com)", "Arc Control Plane"),
            new("guestnotificationservice.azure.com", 443,
                "Arc notification service (extensions + connectivity)", "Arc Control Plane"),
            new("login.microsoftonline.com", 443,
                "Global Microsoft Entra token endpoint used by the Arc agent", "Arc Control Plane"),
            new("management.azure.com", 443,
                "Azure Resource Manager (connect/disconnect + goal-state)", "Arc Control Plane"),
            new("pas.windows.net", 443,
                "Microsoft Entra ID (PAS)", "Arc Control Plane")
        };
        if (normalizedRegion != null)
        {
            classicEndpoints.Add(new(
                $"{normalizedRegion}.login.microsoft.com", 443,
                "Regional Entra token endpoint (*.login.microsoft.com)", "Arc Control Plane"));
        }
        return classicEndpoints;
    }
}
