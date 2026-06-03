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

    // RD Gateway (AFD discovery endpoint)
    gatewayEndpoints: [
        'afdfp-rdgateway-r1.wvd.microsoft.com',
        'rdweb.wvd.microsoft.com'
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
        { url: 'statics.teams.cdn.office.net', purpose: 'Automatic updates (*.cdn.office.net)', port: 443 }
        // *.events.data.microsoft.com — cannot be tested from the browser.
        // Every mainstream browser (Edge, Chrome, Firefox) bundles a built-in
        // tracking-prevention blocklist that includes Microsoft's OneDS
        // telemetry domains. fetch() is silently cancelled with TypeError
        // even though the host is fully reachable over TCP/TLS. Verified
        // via external tools (ping/psping/HttpWebRequest) that the endpoint
        // responds normally — the block is enforced in the browser, not
        // on the network. This endpoint is in the AVD "Other Endpoints"
        // (optional) section; the Local Scanner has no browser constraint
        // and can probe it directly if definitive verification is needed.
        //
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
        natType: 'https://learn.microsoft.com/windows-365/enterprise/understanding-remote-desktop-protocol-traffic#known-challenges-with-direct-rdp-shortpath-using-stun'
    },

    // Test categories matching the .NET enum
    categories: {
        EndpointAccess: 'endpoint',
        LocalEnvironment: 'local',
        TcpTransport: 'tcp',
        UdpShortpath: 'udp',
        CloudSession: 'cloud'
    },

    // Load-bearing sentinels shared between browser-tests.js (writer) and
    // app.js (mergeBrowserBlockedEndpointResult). They describe the
    // placeholder block that B-EP-01 emits for *.events.data.microsoft.com
    // (which the browser cannot probe) so app.js can locate and replace it
    // when the scanner supplies an L-EP-02 result. Keeping them in config
    // prevents the two files from drifting out of sync.
    browserBlocked: {
        // Unique substring used by the merge to find the pending headline
        // segment. Matched by ".includes()", so partial/whole-phrase matches
        // both work — keep the token distinctive enough to be unambiguous.
        headlineMarker: '*.events.data.microsoft.com',
        // Start-of-section heading in the detail block. Kept as a full
        // string so a simple indexOf locates the block to replace.
        detailMarker: '\u2550\u2550 Endpoint not tested from browser \u2550\u2550',
        // Separator used when joining headline segments.
        headlineSeparator: ' \u2022 '
    }
};

// ═══════════════════════════════════════════════════════════════════
//  THRESHOLDS — single source of truth for the AI-analysis / Key
//  Findings summary and the Session Quality Score.
// ───────────────────────────────────────────────────────────────────
//  WHY THIS EXISTS: the Key Findings panel, the AI-analysis correlation
//  engine and the 0-100 Quality Score all judge the SAME metrics
//  (latency, jitter, loss, gateway RTT, WiFi, bandwidth). Historically
//  each carried its own inline magic numbers, so changing one boundary
//  silently left the others on the old value — producing summaries that
//  contradicted the score (and each other). Centralising the
//  critical/warning boundaries here means every summary surface reads
//  the same numbers and can never drift apart.
//
//  SCOPE — what belongs here vs. what does NOT:
//    • Belongs here: the experience-quality boundaries the *summary*
//      surfaces use (this file is consumed only by JS).
//    • Does NOT belong here: per-test pass/fail verdicts set by the C#
//      scanner or by browser-tests.js. Those measure the *connectivity*
//      bar (does it work at all), which is deliberately more lenient
//      than the *experience* bar the summary measures. Do not "align"
//      them to these numbers — they answer a different question and the
//      gap between the two bars is intentional.
//
//  Units are noted per field. All boundaries are "worse-than" edges
//  (e.g. latency.critical = 200 means avg > 200 ms is Critical).
// ═══════════════════════════════════════════════════════════════════
const THRESHOLDS = {
    // WiFi signal strength (%). LOWER is worse, so these are floors:
    // sig < critical → Critical, sig < warning → Warning.
    wifiSignal:     { critical: 40, warning: 60 },

    // Local gateway / router round-trip (ms), test L-LE-05. HIGHER is worse.
    gatewayLatency: { critical: 50, warning: 20 },

    // Bandwidth (Mbps). LOWER is worse, so these are floors:
    // mbps < critical → Critical, mbps < warning → Warning.
    bandwidth:      { critical: 5, warning: 10 },

    // Session round-trip latency (ms), test 18. HIGHER is worse.
    sessionLatency: { critical: 200, warning: 100 },

    // Connection jitter (ms), test 20. HIGHER is worse.
    jitter:         { critical: 60, warning: 30 },

    // Packet / frame loss (%), test 21. HIGHER is worse.
    packetLoss:     { critical: 15, warning: 5 },

    // Session Quality Score (0-100) label bands. A score at or above the
    // band (with the finding gates applied in showAnalysisPanel) earns the
    // label. These are the same numbers the ring colour keys off.
    scoreLabels:    { excellent: 95, good: 80, fair: 50 }
};
