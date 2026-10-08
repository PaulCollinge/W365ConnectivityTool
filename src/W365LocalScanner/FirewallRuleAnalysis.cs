using System.Net;

namespace W365LocalScanner;

internal readonly record struct FirewallRule(
    string Name,
    string Direction,
    string Action,
    int Protocol,
    string LocalPort,
    string RemotePort,
    string RemoteAddresses);

internal static class FirewallRuleAnalysis
{
    internal static bool PortMatches(string rulePort, int targetPort)
    {
        if (string.IsNullOrEmpty(rulePort)
            || rulePort.Equals("Any", StringComparison.OrdinalIgnoreCase)
            || rulePort == "*")
            return true;

        foreach (var segment in rulePort.Split(','))
        {
            var value = segment.Trim();
            if (value == targetPort.ToString())
                return true;

            var dash = value.IndexOf('-');
            if (dash > 0
                && int.TryParse(value[..dash], out var low)
                && int.TryParse(value[(dash + 1)..], out var high)
                && targetPort >= low
                && targetPort <= high)
                return true;
        }

        return false;
    }

    internal static bool IsLoopbackOnly(FirewallRule rule)
    {
        if (string.IsNullOrWhiteSpace(rule.RemoteAddresses)
            || rule.RemoteAddresses.Equals("Any", StringComparison.OrdinalIgnoreCase)
            || rule.RemoteAddresses == "*")
            return false;

        var ranges = rule.RemoteAddresses.Split(
            ',',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return ranges.Length > 0 && ranges.All(IsLoopbackRange);
    }

    private static bool IsLoopbackRange(string value)
    {
        if (value.Equals("LocalHost", StringComparison.OrdinalIgnoreCase))
            return true;

        var dash = value.IndexOf('-');
        if (dash > 0)
        {
            return IPAddress.TryParse(value[..dash], out var low)
                && IPAddress.TryParse(value[(dash + 1)..], out var high)
                && IPAddress.IsLoopback(low)
                && IPAddress.IsLoopback(high);
        }

        var slash = value.IndexOf('/');
        if (slash > 0 && int.TryParse(value[(slash + 1)..], out var prefixLength))
        {
            if (!IPAddress.TryParse(value[..slash], out var network))
                return false;

            byte[] bytes = network.GetAddressBytes();
            return bytes.Length switch
            {
                4 => prefixLength >= 8 && bytes[0] == 127,
                16 => prefixLength >= 127 && bytes.All(b => b == 0),
                _ => false
            };
        }

        return IPAddress.TryParse(value, out var address)
            && (IPAddress.IsLoopback(address) || address.Equals(IPAddress.IPv6Any));
    }
}
