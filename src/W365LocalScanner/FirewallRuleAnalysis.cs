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
    internal static FirewallRule? ParseRegistryRule(string data)
    {
        string? name = null;
        bool active = false;
        string direction = "";
        string action = "";
        int protocol = 0;
        string localPort = "Any";
        string remotePort = "Any";
        var remoteAddresses = new List<string>();

        foreach (var part in data.Split('|'))
        {
            if (part.StartsWith("Name=", StringComparison.OrdinalIgnoreCase))
                name = part[5..];
            else if (part.StartsWith("Active=", StringComparison.OrdinalIgnoreCase))
                active = part[7..].Equals("TRUE", StringComparison.OrdinalIgnoreCase);
            else if (part.StartsWith("Dir=", StringComparison.OrdinalIgnoreCase))
                direction = part[4..];
            else if (part.StartsWith("Action=", StringComparison.OrdinalIgnoreCase))
                action = part[7..];
            else if (part.StartsWith("Protocol=", StringComparison.OrdinalIgnoreCase))
                int.TryParse(part[9..], out protocol);
            else if (part.StartsWith("LPort=", StringComparison.OrdinalIgnoreCase))
                localPort = part[6..];
            else if (part.StartsWith("RPort=", StringComparison.OrdinalIgnoreCase))
                remotePort = part[6..];
            else if (part.StartsWith("RA4=", StringComparison.OrdinalIgnoreCase)
                  || part.StartsWith("RA6=", StringComparison.OrdinalIgnoreCase))
                remoteAddresses.Add(part[4..]);
        }

        if (name == null || !active)
            return null;

        return new FirewallRule(
            name,
            direction,
            action,
            protocol,
            localPort,
            remotePort,
            string.Join(',', remoteAddresses));
    }

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
        if (slash > 0)
        {
            if (!IPAddress.TryParse(value[..slash], out var network))
                return false;

            byte[] bytes = network.GetAddressBytes();
            return bytes.Length switch
            {
                4 => TryGetIpv4PrefixLength(value[(slash + 1)..], out var ipv4Prefix)
                    && ipv4Prefix >= 8
                    && bytes[0] == 127,
                16 => int.TryParse(value[(slash + 1)..], out var ipv6Prefix)
                    && ipv6Prefix is >= 127 and <= 128
                    && bytes[..15].All(b => b == 0)
                    && bytes[15] <= 1,
                _ => false
            };
        }

        return IPAddress.TryParse(value, out var address)
            && IPAddress.IsLoopback(address);
    }

    private static bool TryGetIpv4PrefixLength(string value, out int prefixLength)
    {
        if (int.TryParse(value, out prefixLength))
            return prefixLength is >= 0 and <= 32;

        prefixLength = 0;
        if (!IPAddress.TryParse(value, out var mask))
            return false;

        byte[] bytes = mask.GetAddressBytes();
        if (bytes.Length != 4)
            return false;

        bool sawZero = false;
        foreach (byte current in bytes)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                bool isSet = (current & (1 << bit)) != 0;
                if (sawZero && isSet)
                    return false;

                if (isSet)
                    prefixLength++;
                else
                    sawZero = true;
            }
        }

        return true;
    }
}
