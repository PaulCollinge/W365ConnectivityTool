using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class WinHttpProxyConfigurationTests
{
    [TestMethod]
    public void ManualProxyRoutesHttpAndHttpsThroughMachineProxy()
    {
        var configuration = WinHttpProxyConfiguration.Parse(
            BuildSettings(0x03, "proxy.contoso.com:8080", null));

        var http = configuration.Resolve(new Uri("http://oneocsp.microsoft.com/"));
        var https = configuration.Resolve(new Uri("https://rdweb.wvd.microsoft.com/"));

        Assert.IsTrue(configuration.Available);
        Assert.IsTrue(http.UseProxy);
        Assert.AreEqual("proxy.contoso.com", http.ProxyUri?.Host);
        Assert.IsTrue(https.UseProxy);
        Assert.AreEqual(8080, https.ProxyUri?.Port);
    }

    [TestMethod]
    public void SchemeSpecificProxyUsesMatchingEntry()
    {
        var configuration = WinHttpProxyConfiguration.Parse(
            BuildSettings(
                0x03,
                "http=http-proxy.contoso.com:8080;https=https-proxy.contoso.com:8443",
                null));

        Assert.AreEqual(
            "http-proxy.contoso.com",
            configuration.Resolve(new Uri("http://oneocsp.microsoft.com/")).ProxyUri?.Host);
        Assert.AreEqual(
            "https-proxy.contoso.com",
            configuration.Resolve(new Uri("https://rdweb.wvd.microsoft.com/")).ProxyUri?.Host);
    }

    [TestMethod]
    public void BypassListProducesDirectAuthoritativeRoute()
    {
        var configuration = WinHttpProxyConfiguration.Parse(
            BuildSettings(0x03, "proxy.contoso.com:8080", "*.wvd.microsoft.com;<local>"));

        var route = configuration.Resolve(new Uri("https://rdweb.wvd.microsoft.com/"));

        Assert.IsFalse(route.UseProxy);
        StringAssert.Contains(route.Description, "bypass");
    }

    [TestMethod]
    public void DirectConfigurationIsAvailableAndAuthoritative()
    {
        var configuration = WinHttpProxyConfiguration.Parse(BuildSettings(0x01, null, null));

        var route = configuration.Resolve(new Uri("https://rdweb.wvd.microsoft.com/"));

        Assert.IsTrue(configuration.Available);
        Assert.IsTrue(configuration.IsDirect);
        Assert.IsFalse(route.UseProxy);
        StringAssert.Contains(route.Description, "direct");
    }

    [TestMethod]
    public void AutoDiscoveryWithoutStaticProxyIsUnavailable()
    {
        var configuration = WinHttpProxyConfiguration.Parse(BuildSettings(0x09, null, null));

        Assert.IsFalse(configuration.Available);
        StringAssert.Contains(configuration.Error, "automatic proxy");
    }

    private static byte[] BuildSettings(byte flags, string? proxy, string? bypass)
    {
        var bytes = new List<byte>([0, 0, 0, 0, 0, 0, 0, 0, flags, 0, 0, 0]);
        Append(bytes, proxy);
        Append(bytes, bypass);
        Append(bytes, null);
        return [.. bytes];
    }

    private static void Append(List<byte> bytes, string? value)
    {
        var encoded = value == null ? [] : Encoding.ASCII.GetBytes(value);
        bytes.AddRange(BitConverter.GetBytes(encoded.Length));
        bytes.AddRange(encoded);
    }
}
