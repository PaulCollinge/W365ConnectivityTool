/**
 * Endpoint configuration matching the .NET application.
 * Based on: https://learn.microsoft.com/windows-365/enterprise/requirements-network
 */
const EndpointConfig = {

    // Authentication endpoints
    authEndpoints: [
        'login.microsoftonline.com'
    ],

    // AVD / Windows 365 Service endpoints
    serviceEndpoints: [
        'rdweb.wvd.microsoft.com',
        'client.wvd.microsoft.com',
        'rdbroker.wvd.microsoft.com'
    ],

    // RD Gateway
    gatewayEndpoints: [
        'afdfp-rdgateway-r1.wvd.microsoft.com',
        'rdweb.wvd.microsoft.com',
        'client.wvd.microsoft.com'
    ],

    // TURN Relay
    turnRelayEndpoints: [
        'world.relay.avd.microsoft.com'
    ],
    turnRelayPort: 3478,

    // Geo-IP (must be HTTPS for GitHub Pages)
    // Order used in browser-tests.js: ipinfo.io (primary) → freeipapi.com → ipwho.is
    geoIpPrimaryUrl: 'https://ipinfo.io/json',
    geoIpFallbackUrl: 'https://freeipapi.com/api/json',
    geoIpFallback2Url: 'https://get.geojs.io/v1/ip/geo.json',

    // Required FQDNs for end-user devices (Azure cloud)
    // Source: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices
    // Only includes HTTPS (port 443) endpoints testable from a browser.
    // Wildcard entries (*.wvd.microsoft.com etc.) tested via known subdomains.
    requiredEndpoints: [
        { url: 'login.microsoftonline.com', purpose: 'Authentication', port: 443 },
        { url: 'rdweb.wvd.microsoft.com', purpose: 'Service traffic (*.wvd.microsoft.com)', port: 443 },
        { url: 'client.wvd.microsoft.com', purpose: 'Service traffic (*.wvd.microsoft.com)', port: 443 },
        { url: 'rdbroker.wvd.microsoft.com', purpose: 'Service traffic (*.wvd.microsoft.com)', port: 443 },
        { url: 'go.microsoft.com', purpose: 'Microsoft FWLinks', port: 443 },
        { url: 'aka.ms', purpose: 'Microsoft URL shortener', port: 443 },
        { url: 'learn.microsoft.com', purpose: 'Documentation', port: 443 },
        { url: 'privacy.microsoft.com', purpose: 'Privacy statement', port: 443 },
        { url: 'graph.microsoft.com', purpose: 'Service traffic', port: 443 },
        { url: 'windows.cloud.microsoft', purpose: 'Connection center', port: 443 },
        { url: 'windows365.microsoft.com', purpose: 'Service traffic', port: 443 },
        { url: 'ecs.office.com', purpose: 'Connection center', port: 443 },
        // Wildcard exemplars (specific hosts representing *.wildcard patterns)
        { url: 'microsoft.servicebus.windows.net', purpose: 'Troubleshooting data (*.servicebus.windows.net)', port: 443 },
        { url: 'statics.teams.cdn.office.net', purpose: 'Automatic updates (*.cdn.office.net)', port: 443 },
        { url: 'watson.events.data.microsoft.com', purpose: 'Client telemetry (*.events.data.microsoft.com)', port: 443 }
        // Port 80 certificate endpoints — cannot be tested from browser (mixed-content blocked).
        // Tested by the local scanner on TCP port 80 as required by official docs:
        //   *.microsoftaik.azure.net, www.microsoft.com,
        //   *.aikcertaia.microsoft.com, azcsprodeusaikpublish.blob.core.windows.net
    ],

    // Documentation links
    docs: {
        networkRequirements: 'https://learn.microsoft.com/windows-365/enterprise/requirements-network',
        dnsConfig: 'https://learn.microsoft.com/windows-365/enterprise/requirements-network#dns-requirements',
        proxyConfig: 'https://learn.microsoft.com/windows-365/enterprise/requirements-network#proxy-configuration',
        tlsInspection: 'https://learn.microsoft.com/windows-365/enterprise/requirements-network#tls-inspection',
        bandwidth: 'https://learn.microsoft.com/windows-365/enterprise/requirements-network#bandwidth-requirements',
        avdRequiredUrls: 'https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint',
        turnRelay: 'https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=managed-networks',
        teamsOptimization: 'https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd',
        natType: 'https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath?tabs=public-networks'
    },

    // Test categories matching the .NET enum
    categories: {
        EndpointAccess: 'endpoint',
        LocalEnvironment: 'local',
        TcpTransport: 'tcp',
        UdpShortpath: 'udp',
        CloudSession: 'cloud'
    }
};
