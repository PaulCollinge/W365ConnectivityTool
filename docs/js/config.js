/**
 * Endpoint configuration matching the .NET application.
 * Based on: https://learn.microsoft.com/windows-365/enterprise/requirements-network
 */
const EndpointConfig = {

    // Authentication endpoints
    authEndpoints: [
        'login.microsoftonline.com',
        'login.windows.net'
    ],

    // AVD / Windows 365 Service endpoints
    serviceEndpoints: [
        'rdweb.wvd.microsoft.com',
        'client.wvd.microsoft.com',
        'rdbroker.wvd.microsoft.com'
    ],

    // RD Gateway
    gatewayEndpoints: [
        'rdweb.wvd.microsoft.com',
        'client.wvd.microsoft.com'
    ],

    // TURN Relay
    turnRelayEndpoints: [
        'world.relay.avd.microsoft.com'
    ],
    turnRelayPort: 3478,

    // Geo-IP
    geoIpApiUrl: 'http://ip-api.com/json/?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon',

    // Required URLs for endpoint access testing (subset testable via HTTPS fetch)
    requiredEndpoints: [
        { url: 'login.microsoftonline.com', purpose: 'Authentication', port: 443 },
        { url: 'login.windows.net', purpose: 'Authentication', port: 443 },
        { url: 'rdweb.wvd.microsoft.com', purpose: 'AVD Web Client', port: 443 },
        { url: 'client.wvd.microsoft.com', purpose: 'AVD Client Service', port: 443 },
        { url: 'rdbroker.wvd.microsoft.com', purpose: 'AVD Connection Broker', port: 443 },
        { url: 'go.microsoft.com', purpose: 'Microsoft Redirects', port: 443 },
        { url: 'aka.ms', purpose: 'Microsoft Short URLs', port: 443 },
        { url: 'learn.microsoft.com', purpose: 'Documentation/Config', port: 443 },
        { url: 'portal.azure.com', purpose: 'Azure Portal', port: 443 },
        { url: 'windows.net', purpose: 'Azure Services', port: 443 }
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
