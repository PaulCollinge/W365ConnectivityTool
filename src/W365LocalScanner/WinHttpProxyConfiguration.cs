using Microsoft.Win32;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace W365LocalScanner;

internal sealed record WinHttpProxyRoute(bool UseProxy, Uri? ProxyUri, string Description);

internal sealed class WinHttpProxyConfiguration : IWebProxy
{
    internal bool Available { get; }
    internal bool IsDirect { get; }
    internal string? ProxyValue { get; }
    internal string? BypassValue { get; }
    internal string? Error { get; }
    public ICredentials? Credentials { get; set; }

    private WinHttpProxyConfiguration(
        bool available,
        bool isDirect,
        string? proxyValue,
        string? bypassValue,
        string? error)
    {
        Available = available;
        IsDirect = isDirect;
        ProxyValue = Normalize(proxyValue);
        BypassValue = Normalize(bypassValue);
        Error = error;
    }

    internal static WinHttpProxyConfiguration Read()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
            return Parse(key?.GetValue("WinHttpSettings") as byte[]);
        }
        catch (Exception ex)
        {
            return Unavailable($"Could not read WinHTTP settings: {ex.Message}");
        }
    }

    internal static WinHttpProxyConfiguration Parse(byte[]? settings)
    {
        if (settings == null || settings.Length < 12)
            return Unavailable("WinHTTP settings were not available");

        byte flags = settings[8];
        bool hasManualProxy = (flags & 0x02) != 0;
        bool hasAutoConfiguration = (flags & 0x0C) != 0;
        if (hasAutoConfiguration && !hasManualProxy)
            return Unavailable("WinHTTP uses automatic proxy discovery, which this probe cannot reproduce");

        int offset = 12;
        if (!TryReadString(settings, ref offset, out var proxy))
            return Unavailable("WinHTTP proxy settings were malformed");
        if (!TryReadString(settings, ref offset, out var bypass))
            bypass = null;

        if (hasManualProxy)
        {
            if (string.IsNullOrWhiteSpace(proxy))
                return Unavailable("WinHTTP reports a manual proxy but no proxy address");
            return new(true, false, proxy, bypass, null);
        }

        return new(true, true, null, bypass, null);
    }

    internal WinHttpProxyRoute Resolve(Uri endpoint)
    {
        if (!Available)
            return new(false, null, Error ?? "WinHTTP route unavailable");
        if (ShouldBypass(endpoint))
            return new(false, null, $"machine WinHTTP bypass applies to {endpoint.Host}");
        if (IsDirect)
            return new(false, null, "machine WinHTTP direct access");

        var proxy = SelectProxy(endpoint);
        return proxy == null
            ? new(false, null, $"machine WinHTTP has no {endpoint.Scheme} proxy")
            : new(true, proxy, "machine WinHTTP proxy");
    }

    internal bool ShouldBypass(Uri endpoint)
    {
        if (string.IsNullOrWhiteSpace(BypassValue))
            return false;

        foreach (var entry in BypassValue.Split(
                     [';', ','],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (entry.Equals("<local>", StringComparison.OrdinalIgnoreCase)
                && !endpoint.Host.Contains('.'))
                return true;
            if (WildcardMatches(entry, endpoint.Host))
                return true;
        }
        return false;
    }

    public Uri GetProxy(Uri destination) =>
        Resolve(destination).ProxyUri ?? destination;

    public bool IsBypassed(Uri host) =>
        !Resolve(host).UseProxy;

    private Uri? SelectProxy(Uri endpoint)
    {
        if (string.IsNullOrWhiteSpace(ProxyValue))
            return null;

        string? selected = null;
        foreach (var entry in ProxyValue.Split(
                     ';',
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int separator = entry.IndexOf('=');
            if (separator < 0)
            {
                selected ??= entry;
                continue;
            }

            var scheme = entry[..separator].Trim();
            if (scheme.Equals(endpoint.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                selected = entry[(separator + 1)..].Trim();
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(selected))
            return null;
        if (!selected.Contains("://", StringComparison.Ordinal))
            selected = $"http://{selected}";
        return Uri.TryCreate(selected, UriKind.Absolute, out var proxy)
            && proxy.Scheme is "http" or "https"
            && !string.IsNullOrWhiteSpace(proxy.Host)
                ? proxy
                : null;
    }

    private static bool TryReadString(byte[] settings, ref int offset, out string? value)
    {
        value = null;
        if (settings.Length < offset + 4)
            return false;
        int length = BitConverter.ToInt32(settings, offset);
        offset += 4;
        if (length < 0 || settings.Length < offset + length)
            return false;
        value = length == 0 ? null : Encoding.ASCII.GetString(settings, offset, length);
        offset += length;
        return true;
    }

    private static bool WildcardMatches(string pattern, string host)
    {
        var normalized = pattern.Trim();
        if (normalized.Length == 0)
            return false;
        var regex = "^" + Regex.Escape(normalized).Replace(@"\*", ".*") + "$";
        return Regex.IsMatch(host, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static WinHttpProxyConfiguration Unavailable(string error) =>
        new(false, false, null, null, error);

    private static string? Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
