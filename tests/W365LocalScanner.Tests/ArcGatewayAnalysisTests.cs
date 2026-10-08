using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class ArcGatewayAnalysisTests
{
    [TestMethod]
    public void ParseDetectsGatewayRouteFromAgentStatus()
    {
        const string json = """
            {
              "connectionType": "gateway",
              "usingHttpsProxy": "http://localhost:40343",
              "upstreamProxy": "http://rb-proxy.example.com:8080",
              "gatewayUrl": "https://bosch-weu.gw.arc.azure.com"
            }
            """;

        var snapshot = ArcGatewaySnapshot.Parse(null, json);

        Assert.IsTrue(snapshot.IsGateway);
        Assert.AreEqual("https://bosch-weu.gw.arc.azure.com", snapshot.GatewayUrl);
        Assert.AreEqual("http://localhost:40343", snapshot.LocalProxyUrl);
        Assert.AreEqual("http://rb-proxy.example.com:8080", snapshot.UpstreamProxyUrl);
    }

    [TestMethod]
    public void ParseUsesConfiguredConnectionTypeWhenStatusOmitsIt()
    {
        var snapshot = ArcGatewaySnapshot.Parse(
            "gateway",
            """{"usingHttpsProxy":"http://127.0.0.1:40343"}""");

        Assert.IsTrue(snapshot.IsGateway);
        Assert.AreEqual("http://127.0.0.1:40343", snapshot.LocalProxyUrl);
    }

    [TestMethod]
    public void ParseExtractsJsonFromOlderAgentDiagnosticOutput()
    {
        const string output = """
            INFO: collecting Azure Connected Machine Agent status
            {"Connection":{"Type":"Gateway"},"Gateway":{"Url":"https://bosch-weu.gw.arc.azure.com"},"Proxy":{"Local":"http://localhost:40343"}}
            INFO: status collection complete
            """;

        var snapshot = ArcGatewaySnapshot.Parse(null, output);

        Assert.IsTrue(snapshot.IsGateway);
        Assert.AreEqual("https://bosch-weu.gw.arc.azure.com", snapshot.GatewayUrl);
        Assert.AreEqual("http://localhost:40343", snapshot.LocalProxyUrl);
    }

    [TestMethod]
    public void ParseDoesNotInferGatewayFromUnrelatedUrls()
    {
        var snapshot = ArcGatewaySnapshot.Parse(
            "direct",
            """{"proxyUrl":"http://proxy.example.com:8080","serviceUrl":"https://gbl.his.arc.azure.com"}""");

        Assert.IsFalse(snapshot.IsGateway);
        Assert.IsNull(snapshot.GatewayUrl);
        Assert.IsNull(snapshot.LocalProxyUrl);
    }

    [TestMethod]
    public void GatewayCatalogUsesDocumentedReducedWindowsEndpointSet()
    {
        var gateway = new ArcGatewaySnapshot(
            true,
            "https://bosch-weu.gw.arc.azure.com",
            "http://localhost:40343",
            "http://rb-proxy.example.com:8080");

        var endpoints = ArcEndpointCatalog.Build(gateway, "westeurope");
        var hosts = endpoints.Select(endpoint => endpoint.Host).ToArray();

        CollectionAssert.Contains(hosts, "bosch-weu.gw.arc.azure.com");
        CollectionAssert.Contains(hosts, "management.azure.com");
        CollectionAssert.Contains(hosts, "login.microsoftonline.com");
        CollectionAssert.Contains(hosts, "westeurope.login.microsoft.com");
        CollectionAssert.Contains(hosts, "gbl.his.arc.azure.com");
        CollectionAssert.Contains(hosts, "westeurope.his.arc.azure.com");
        CollectionAssert.Contains(hosts, "download.microsoft.com");
        CollectionAssert.DoesNotContain(hosts, "packages.microsoft.com");
        CollectionAssert.DoesNotContain(hosts, "agentserviceapi.guestconfiguration.azure.com");
        CollectionAssert.DoesNotContain(hosts, "guestnotificationservice.azure.com");
        CollectionAssert.DoesNotContain(hosts, "pas.windows.net");
        Assert.IsTrue(endpoints.All(endpoint => endpoint.Group == "Arc Gateway Required"));
    }

    [TestMethod]
    public void DirectCatalogRetainsClassicArcEndpoints()
    {
        var endpoints = ArcEndpointCatalog.Build(
            new(false, null, null, null),
            "westeurope");
        var hosts = endpoints.Select(endpoint => endpoint.Host).ToArray();

        CollectionAssert.Contains(hosts, "agentserviceapi.guestconfiguration.azure.com");
        CollectionAssert.Contains(hosts, "guestnotificationservice.azure.com");
        CollectionAssert.Contains(hosts, "pas.windows.net");
        CollectionAssert.DoesNotContain(hosts, "westeurope.his.arc.azure.com");
    }

    [TestMethod]
    public void GatewayCatalogDoesNotInventRegionWhenProjectionIsUnavailable()
    {
        var endpoints = ArcEndpointCatalog.Build(
            new(true, "https://bosch-weu.gw.arc.azure.com", null, null),
            "");
        var hosts = endpoints.Select(endpoint => endpoint.Host).ToArray();

        CollectionAssert.DoesNotContain(hosts, "eastus.login.microsoft.com");
        CollectionAssert.DoesNotContain(hosts, "eastus.his.arc.azure.com");
        CollectionAssert.Contains(hosts, "gbl.his.arc.azure.com");
    }

    [TestMethod]
    public void GatewayLocalProxyBecomesAuthoritativeAgentRoute()
    {
        var gateway = new ArcGatewaySnapshot(
            true,
            "https://bosch-weu.gw.arc.azure.com",
            "http://localhost:40343",
            "http://rb-proxy.example.com:8080");
        var configuration = ArcProxyConfiguration.Create(
            gateway.LocalProxyUrl,
            null,
            gateway.UpstreamProxyUrl,
            gateway);

        var route = configuration.Resolve(new Uri("https://gbl.his.arc.azure.com"));

        Assert.IsTrue(route.UseProxy);
        Assert.AreEqual("localhost", route.ProxyUri?.Host);
        Assert.AreEqual(40343, route.ProxyUri?.Port);
        Assert.AreEqual("Arc Gateway local proxy", configuration.SourceDescription);
    }
}
