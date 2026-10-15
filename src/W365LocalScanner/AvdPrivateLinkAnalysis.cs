using System.Net;
using System.Net.Sockets;

namespace W365LocalScanner;

internal sealed class AvdPrivateLinkAssessment
{
    internal string Host { get; }
    internal IReadOnlyList<IPAddress> Addresses { get; }
    internal bool HasPrivateAddresses { get; }
    internal bool HasPublicAddresses { get; }
    internal bool HasUnroutableAddresses { get; }
    internal string? CanonicalHost { get; }
    internal bool HasPrivateLinkDnsName { get; }
    internal bool UsesPrivateRoute =>
        HasPrivateAddresses && !HasPublicAddresses && !HasUnroutableAddresses;
    internal bool IsPrivateLinkDetected =>
        UsesPrivateRoute && HasPrivateLinkDnsName;
    internal string Description { get; }

    private AvdPrivateLinkAssessment(
        string host,
        IReadOnlyList<IPAddress> addresses,
        bool hasPrivateAddresses,
        bool hasPublicAddresses,
        bool hasUnroutableAddresses,
        string? canonicalHost)
    {
        Host = host;
        Addresses = addresses;
        HasPrivateAddresses = hasPrivateAddresses;
        HasPublicAddresses = hasPublicAddresses;
        HasUnroutableAddresses = hasUnroutableAddresses;
        CanonicalHost = string.IsNullOrWhiteSpace(canonicalHost)
            ? null
            : canonicalHost.TrimEnd('.');
        HasPrivateLinkDnsName =
            CanonicalHost?.EndsWith(
                ".privatelink.wvd.microsoft.com",
                StringComparison.OrdinalIgnoreCase) == true
            || CanonicalHost?.EndsWith(
                ".privatelink-global.wvd.microsoft.com",
                StringComparison.OrdinalIgnoreCase) == true;

        string classification = hasUnroutableAddresses
            ? "contains unroutable/possible sinkhole addresses"
            : hasPrivateAddresses && hasPublicAddresses
                ? "mixed private/public"
                : hasPrivateAddresses
                    ? HasPrivateLinkDnsName
                        ? $"private-only (AVD Private Link confirmed by {CanonicalHost})"
                        : "private-only (probable AVD Private Link; CNAME evidence unavailable)"
                    : hasPublicAddresses
                        ? "public-only"
                        : "no usable addresses";
        Description = $"{classification} [{string.Join(", ", addresses.Take(6))}]";
    }

    internal static bool IsCandidateHost(string host) =>
        !string.IsNullOrWhiteSpace(host)
        && host.TrimEnd('.').EndsWith(
            ".wvd.microsoft.com",
            StringComparison.OrdinalIgnoreCase);

    internal static AvdPrivateLinkAssessment Assess(
        string host,
        IEnumerable<IPAddress> addresses,
        string? canonicalHost = null)
    {
        var unique = addresses.Distinct().ToArray();
        bool hasUnroutable = unique.Any(IsUnroutable);
        bool hasPrivate = unique.Any(address => !IsUnroutable(address) && IsPrivate(address));
        bool hasPublic = unique.Any(address => !IsUnroutable(address) && !IsPrivate(address));
        return new(host, unique, hasPrivate, hasPublic, hasUnroutable, canonicalHost);
    }

    internal string? GetRouteWarning(bool machineRouteUsesProxy)
    {
        if (HasUnroutableAddresses)
            return "DNS returned loopback or link-local addresses, indicating a possible DNS sinkhole.";
        if (HasPrivateAddresses && HasPublicAddresses)
            return "DNS returned mixed private and public addresses for an AVD service endpoint; Private Link routing is ambiguous.";
        if (UsesPrivateRoute && machineRouteUsesProxy)
            return "A private-only AVD route was detected, but the machine WinHTTP route sends this endpoint through a proxy. If this is AVD Private Link, add an appropriate proxy bypass so the AVD services can use the routed private endpoint directly.";
        return null;
    }

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6SiteLocal || (address.GetAddressBytes()[0] & 0xFE) == 0xFC;
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return false;

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168);
    }

    private static bool IsUnroutable(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return true;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6LinkLocal || address.Equals(IPAddress.IPv6None);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return true;

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 0 || (bytes[0] == 169 && bytes[1] == 254);
    }
}
