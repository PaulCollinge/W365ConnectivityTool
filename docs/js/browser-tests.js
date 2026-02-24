/**
 * Browser-based connectivity tests for Windows 365 / AVD.
 * These tests use only browser APIs (fetch, WebRTC, Performance API, etc.)
 */

// ═════════════════════════════════════════════════════
//  Test definitions: what runs in-browser vs local-only
// ═════════════════════════════════════════════════════

const ALL_TESTS = [
    // ── Required Endpoint Access ──
    {
        id: 'B-EP-01', name: 'Required Endpoint Reachability',
        description: 'Tests HTTPS connectivity to all required Windows 365 / AVD service endpoints',
        category: 'endpoint', source: 'browser', run: testEndpointReachability
    },
    {
        id: 'L-EP-01', name: 'Certificate Endpoints (Port 80)',
        description: 'Tests TCP port 80 connectivity to certificate endpoints (requires Local Scanner)',
        category: 'endpoint', source: 'local'
    },

    // ── Local Environment ──
    {
        id: 'B-LE-01', name: 'User Location',
        description: 'Detects your geographic location and public IP via GeoIP lookup',
        category: 'local', source: 'browser', run: testUserLocation
    },
    {
        id: 'B-LE-02', name: 'ISP Detection',
        description: 'Identifies your Internet Service Provider and network organisation',
        category: 'local', source: 'browser', run: testIspDetection
    },
    {
        id: 'B-LE-03', name: 'Connection Speed',
        description: 'Measures actual download throughput via multi-sample speed test',
        category: 'local', source: 'browser', run: testConnectionSpeed
    },
    {
        id: 'L-LE-04', name: 'WiFi Signal Strength',
        description: 'Measures wireless signal strength and channel (requires Local Scanner)',
        category: 'local', source: 'local'
    },
    {
        id: 'L-LE-05', name: 'Router/Gateway Latency',
        description: 'Pings default gateway to measure local network latency (requires Local Scanner)',
        category: 'local', source: 'local'
    },
    {
        id: 'L-LE-06', name: 'Network Adapter Details',
        description: 'Enumerates network adapters, speeds, and configuration (requires Local Scanner)',
        category: 'local', source: 'local'
    },
    {
        id: 'L-LE-07', name: 'Bandwidth Estimation',
        description: 'Measures available bandwidth via socket-level speed test (requires Local Scanner)',
        category: 'local', source: 'local'
    },
    {
        id: 'L-LE-08', name: 'Machine Performance',
        description: 'Checks CPU, RAM, and disk performance (requires Local Scanner)',
        category: 'local', source: 'local'
    },
    {
        id: 'L-LE-09', name: 'Teams Optimization',
        description: 'Validates Teams AV redirect / media optimization settings (requires Local Scanner)',
        category: 'local', source: 'local'
    },

    // ── TCP Based RDP Connectivity ──
    {
        id: 'B-TCP-03', name: 'DNS Resolution Performance',
        description: 'Measures DNS lookup time for key service endpoints',
        category: 'tcp', source: 'browser', run: testDnsPerformance
    },
    {
        id: 'L-TCP-04', name: 'Gateway & Service Connectivity',
        description: 'Tests AFD gateway discovery, RDP gateway reachability, RDWeb feed, and authentication endpoints (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'B-TCP-02', name: 'AFD Connectivity',
        description: 'Tests connectivity to Azure Front Door and measures latency to the AFD edge',
        category: 'tcp', source: 'browser', run: testGatewayLatency
    },
    {
        id: 'L-TCP-09', name: 'Gateway Used',
        description: 'Shows which gateway edge node, IP, routing method (AFD/Private Link), and cert are in use (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'L-TCP-08', name: 'DNS Hijacking Check',
        description: 'Verifies gateway DNS resolves to legitimate Microsoft IPs, not hijacked (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'L-TCP-05', name: 'DNS CNAME Chain Analysis',
        description: 'Traces full DNS resolution chain for AFD/Private Link detection (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'B-TCP-04', name: 'DNS & Routing Analysis',
        description: 'DNS CNAME chain resolution and HTTPS timing to key RDP endpoints (for full ICMP traceroute, use Local Scanner)',
        category: 'tcp', source: 'browser', run: testNetworkPathTrace
    },
    {
        id: 'L-TCP-06', name: 'TLS Inspection Detection',
        description: 'Validates certificate chain for TLS interception by proxies/firewalls (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'L-TCP-07', name: 'Proxy / VPN / SWG Detection',
        description: 'Detects system proxy, WinHTTP, PAC/WPAD, VPN adapters, SWG processes (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },

    // ── UDP Based RDP Connectivity ──
    {
        id: 'B-UDP-02', name: 'NAT Type Detection',
        description: 'Analyses ICE candidates to determine NAT type and STUN compatibility',
        category: 'udp', source: 'browser', run: testNatType
    },
    {
        id: 'B-UDP-01', name: 'STUN Connectivity',
        description: 'Tests STUN server reachability and gathers ICE candidates',
        category: 'udp', source: 'browser', run: testWebRtcStun
    },
    {
        id: 'L-UDP-03', name: 'TURN Relay Reachability (UDP 3478)',
        description: 'Tests raw UDP socket to TURN relay on port 3478 (requires Local Scanner)',
        category: 'udp', source: 'local'
    },
    {
        id: 'L-UDP-04', name: 'TURN Relay Location',
        description: 'Resolves TURN relay IP and geolocates the relay server (requires Local Scanner)',
        category: 'udp', source: 'local'
    },
    {
        id: 'L-UDP-05', name: 'STUN NAT Type Detection',
        description: 'Two-server STUN test for NAT type and Shortpath readiness (requires Local Scanner)',
        category: 'udp', source: 'local'
    },
    {
        id: 'L-UDP-06', name: 'TURN TLS Inspection',
        description: 'Checks for TLS interception on TURN relay connections (requires Local Scanner)',
        category: 'udp', source: 'local'
    },
    {
        id: 'L-UDP-07', name: 'TURN Proxy/VPN Detection',
        description: 'Detects proxies or VPNs that may block UDP TURN traffic (requires Local Scanner)',
        category: 'udp', source: 'local'
    },

    // ── Live Connection Diagnostics (requires desktop tool + active Cloud PC session) ──
    {
        id: '17', name: 'Active RDP Session Detection',
        description: 'Detects whether you are in a remote session or have RDP clients running',
        category: 'cloud', source: 'local'
    },
    {
        id: '17b', name: 'RDP Transport Protocol',
        description: 'Identifies TCP vs UDP transport from RDP event logs and RemoteFX counters',
        category: 'cloud', source: 'local'
    },
    {
        id: '17c', name: 'UDP Shortpath Readiness',
        description: 'STUN binding test to TURN relay for UDP shortpath availability',
        category: 'cloud', source: 'local'
    },
    {
        id: '18', name: 'Session Round-Trip Latency',
        description: 'Measures RTT via RemoteFX counters (in-session) or validated W365 gateway probes',
        category: 'cloud', source: 'local'
    },
    {
        id: '19', name: 'Session Frame Rate & Bandwidth',
        description: 'Reads RemoteFX Graphics counters for FPS, encoding quality, and bandwidth',
        category: 'cloud', source: 'local'
    },
    {
        id: '20', name: 'Connection Jitter',
        description: 'Measures network jitter via 20-sample TCP probes to validated W365 gateways',
        category: 'cloud', source: 'local'
    },
    {
        id: '21', name: 'Frame Drops & Packet Loss',
        description: 'Detects dropped frames from RemoteFX counters or TCP loss to W365 gateways',
        category: 'cloud', source: 'local'
    },
    {
        id: '22', name: 'Cloud PC Teams Optimization',
        description: 'Checks Teams media optimization and AV redirection status',
        category: 'cloud', source: 'local'
    },
    {
        id: '24', name: 'VPN Connection Performance',
        description: 'Detects VPN impact on Cloud PC connection quality',
        category: 'cloud', source: 'local'
    },
    {
        id: '25', name: 'RDP TLS Inspection',
        description: 'Checks for TLS interception on RDP gateway — inspection is not supported and degrades performance',
        category: 'cloud', source: 'local'
    },
    {
        id: '26', name: 'RDP Traffic Routing',
        description: 'Validates that RDP traffic bypasses VPN, proxy, and SWG tunnels for optimal performance',
        category: 'cloud', source: 'local'
    },
    {
        id: '27', name: 'RDP Local Egress',
        description: 'Checks that traffic egresses locally to the nearest W365 gateway and TURN relay',
        category: 'cloud', source: 'local'
    }
];


// ═════════════════════════════════════════════════════
//  Shared helpers
// ═════════════════════════════════════════════════════

let _geoCache = null;

/** Clear the GeoIP cache so the next fetchGeoIp() call fetches fresh data. */
function resetGeoCache() { _geoCache = null; }

async function fetchGeoIp() {
    if (_geoCache) return _geoCache;
    // Primary: ipinfo.io (most accurate city-level geo, HTTPS, CORS-friendly)
    try {
        const r = await fetch(EndpointConfig.geoIpPrimaryUrl, { signal: AbortSignal.timeout(8000), cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        if (data.ip) {
            const [lat, lon] = (data.loc || '0,0').split(',').map(Number);
            _geoCache = {
                status: 'success',
                query: data.ip,
                country: data.country || 'Unknown',
                regionName: data.region || 'Unknown',
                city: data.city || 'Unknown',
                lat: lat,
                lon: lon,
                isp: data.org || 'Unknown',
                org: data.org || 'Unknown',
                as: data.org || 'Unknown'
            };
            return _geoCache;
        }
    } catch (e) { console.warn('GeoIP primary (ipinfo.io) failed:', e.message); }
    // Fallback 1: freeipapi.com
    try {
        const r = await fetch(EndpointConfig.geoIpFallbackUrl, { signal: AbortSignal.timeout(8000), cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        if (data.ipAddress) {
            _geoCache = {
                status: 'success',
                query: data.ipAddress,
                country: data.countryCode || data.countryName || 'Unknown',
                regionName: data.regionName || 'Unknown',
                city: data.cityName || 'Unknown',
                lat: data.latitude || 0,
                lon: data.longitude || 0,
                isp: data.isp || 'Unknown',
                org: data.isp || 'Unknown',
                as: 'Unknown'
            };
            return _geoCache;
        }
    } catch (e) { console.warn('GeoIP fallback 1 (freeipapi.com) failed:', e.message); }
    // Fallback 2: geojs.io (HTTPS, CORS-friendly, generous rate limits)
    try {
        const r = await fetch(EndpointConfig.geoIpFallback2Url, { signal: AbortSignal.timeout(8000), cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        if (data.ip) {
            _geoCache = {
                status: 'success',
                query: data.ip,
                country: data.country_code || data.country || 'Unknown',
                regionName: data.region || 'Unknown',
                city: data.city || 'Unknown',
                lat: parseFloat(data.latitude) || 0,
                lon: parseFloat(data.longitude) || 0,
                isp: data.organization || 'Unknown',
                org: data.organization || 'Unknown',
                as: data.organization_name || 'Unknown'
            };
            return _geoCache;
        }
    } catch (e) { console.warn('GeoIP fallback 2 (geojs.io) failed:', e.message); }
    // Fallback 3: ipwho.is
    try {
        const r = await fetch('https://ipwho.is/', { signal: AbortSignal.timeout(8000), cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        if (data.success !== false) {
            _geoCache = {
                status: 'success',
                query: data.ip,
                country: data.country_code || data.country,
                regionName: data.region,
                city: data.city,
                lat: data.latitude,
                lon: data.longitude,
                isp: data.connection?.isp || 'Unknown',
                org: data.connection?.org || data.connection?.isp || 'Unknown',
                as: data.connection?.asn ? `AS${data.connection.asn}` : 'Unknown'
            };
            return _geoCache;
        }
    } catch (e) { console.warn('GeoIP fallback 3 (ipwho.is) failed:', e.message); }
    console.error('All GeoIP providers failed');
    return null;
}

function makeResult(test, status, value, detail, duration, remediation) {
    return {
        id: test.id,
        name: test.name,
        description: test.description,
        category: test.category,
        source: test.source,
        status,           // 'Passed' | 'Warning' | 'Failed' | 'Error' | 'Skipped'
        resultValue: value,
        detailedInfo: detail || '',
        duration: duration || 0,
        remediationUrl: remediation || ''
    };
}


// ═════════════════════════════════════════════════════
//  Browser Test Implementations
// ═════════════════════════════════════════════════════

// ── Endpoint Reachability ──
// Tests connectivity using a two-phase approach:
//   Phase 1: no-cors GET — opaque response = reachable.
//   Phase 2: If phase 1 throws TypeError (not timeout), measure elapsed time.
//            A fast error (< 3s) means the server responded but CORS blocked
//            reading it — the endpoint IS reachable.  A slow error likely means
//            a genuine network problem (DNS, TCP, TLS).
async function testEndpointReachability(test) {
    const t0 = performance.now();
    const results = [];
    let anyFailed = false;

    const checks = EndpointConfig.requiredEndpoints.map(async (ep) => {
        const url = `https://${ep.url}/`;
        const start = performance.now();
        try {
            await fetch(url, {
                method: 'GET',
                mode: 'no-cors',
                cache: 'no-store',
                signal: AbortSignal.timeout(10000)
            });
            const elapsed = Math.round(performance.now() - start);
            results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Reachable', time: elapsed });
        } catch (e) {
            const elapsed = Math.round(performance.now() - start);
            if (e.name === 'AbortError' || e.name === 'TimeoutError') {
                results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Timeout', time: elapsed });
                anyFailed = true;
            } else if (elapsed < 3000) {
                // Fast TypeError = server responded but browser blocked reading
                // the response (no CORS headers).  The endpoint IS reachable.
                results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Reachable', time: elapsed, note: 'no CORS headers' });
            } else {
                // Slow TypeError — likely a genuine network issue
                results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Unreachable', time: elapsed });
                anyFailed = true;
            }
        }
    });

    await Promise.all(checks);
    const duration = Math.round(performance.now() - t0);

    const reachable = results.filter(r => r.status === 'Reachable').length;
    const detail = results.map(r => {
        const icon = r.status === 'Reachable' ? '\u2714' : '\u2716';
        const timing = r.time > 0 ? ` (${r.time}ms)` : '';
        const note = r.note ? ` [${r.note}]` : '';
        return `${icon} ${r.endpoint} (${r.purpose}) - ${r.status}${timing}${note}`;
    }).join('\n');

    const status = anyFailed ? (reachable === 0 ? 'Failed' : 'Warning') : 'Passed';
    const value = `${reachable}/${results.length} endpoints reachable (browser check)`;

    return makeResult(test, status, value, detail, duration, EndpointConfig.docs.avdRequiredUrls);
}

// ── User Location ──
async function testUserLocation(test) {
    const t0 = performance.now();
    const geo = await fetchGeoIp();
    const duration = Math.round(performance.now() - t0);

    if (!geo) {
        return makeResult(test, 'Warning', 'Could not determine location',
            'GeoIP lookup failed. This may be blocked by a firewall or proxy.', duration);
    }

    const value = `${geo.city}, ${geo.regionName}, ${geo.country}`;
    const detail = `Public IP: ${geo.query}\nLocation: ${geo.city}, ${geo.regionName}, ${geo.country}\nCoordinates: ${geo.lat}, ${geo.lon}`;
    return makeResult(test, 'Passed', value, detail, duration);
}

// ── ISP Detection ──
async function testIspDetection(test) {
    const t0 = performance.now();
    const geo = await fetchGeoIp();
    const duration = Math.round(performance.now() - t0);

    if (!geo) {
        return makeResult(test, 'Warning', 'Could not detect ISP', 'GeoIP lookup failed.', duration);
    }

    const value = `${geo.isp}`;
    const detail = `ISP: ${geo.isp}\nOrganisation: ${geo.org}\nAS: ${geo.as}`;
    return makeResult(test, 'Passed', value, detail, duration);
}

// ── Connection Speed (download-based) ──
async function testConnectionSpeed(test) {
    const t0 = performance.now();
    const lines = [];

    // Use multiple CDN-hosted files of increasing size to gauge throughput.
    // These are public, cache-busted fetches to well-known CDN endpoints.
    const probes = [
        { label: 'Small (100 KB)',  url: 'https://speed.cloudflare.com/__down?bytes=102400',   bytes: 102400 },
        { label: 'Medium (1 MB)',   url: 'https://speed.cloudflare.com/__down?bytes=1048576',  bytes: 1048576 },
        { label: 'Large (5 MB)',    url: 'https://speed.cloudflare.com/__down?bytes=5242880',  bytes: 5242880 },
    ];

    const samples = [];

    for (const probe of probes) {
        try {
            const cacheBust = `&_cb=${Date.now()}-${Math.random().toString(36).slice(2)}`;
            const fetchUrl = probe.url + cacheBust;
            const start = performance.now();
            const resp = await fetch(fetchUrl, { cache: 'no-store', mode: 'cors' });
            if (!resp.ok) { lines.push(`${probe.label}: HTTP ${resp.status}`); continue; }

            // Read the full response body to ensure we measure complete download
            const blob = await resp.blob();
            const elapsed = (performance.now() - start) / 1000; // seconds
            const actualBytes = blob.size || probe.bytes;
            const mbps = ((actualBytes * 8) / elapsed) / 1e6;

            samples.push({ label: probe.label, mbps, elapsed, bytes: actualBytes });
            lines.push(`${probe.label}: ${mbps.toFixed(2)} Mbps (${actualBytes.toLocaleString()} bytes in ${elapsed.toFixed(2)}s)`);
        } catch (e) {
            lines.push(`${probe.label}: failed — ${e.message}`);
        }
    }

    const duration = Math.round(performance.now() - t0);

    // Use the largest successful sample as the best estimate (most reliable at higher speeds)
    const best = samples.length > 0 ? samples[samples.length - 1] : null;

    // Network Information API as supplementary context
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
        lines.push('');
        lines.push('— Browser Network Info API (indicative only, capped ~10 Mbps) —');
        lines.push(`Effective Type: ${conn.effectiveType || 'unknown'}`);
        if (conn.downlink) lines.push(`API Downlink: ${conn.downlink} Mbps`);
        if (conn.rtt) lines.push(`API RTT: ${conn.rtt}ms`);
        if (conn.saveData) lines.push('Data Saver: enabled');
    }

    if (!best) {
        return makeResult(test, 'Warning', 'Speed test failed — could not download test files',
            lines.join('\n'), duration, EndpointConfig.docs.bandwidth);
    }

    // W365 bandwidth guidance: minimum 1.5 Mbps, recommended ≥10 Mbps for good experience
    let status, verdict;
    if (best.mbps >= 20) {
        status = 'Passed';
        verdict = `${best.mbps.toFixed(1)} Mbps — excellent for Cloud PC`;
    } else if (best.mbps >= 10) {
        status = 'Passed';
        verdict = `${best.mbps.toFixed(1)} Mbps — good for Cloud PC`;
    } else if (best.mbps >= 1.5) {
        status = 'Warning';
        verdict = `${best.mbps.toFixed(1)} Mbps — may limit Cloud PC experience`;
    } else {
        status = 'Warning';
        verdict = `${best.mbps.toFixed(1)} Mbps — below minimum for Cloud PC (1.5 Mbps)`;
    }

    return makeResult(test, status, verdict, lines.join('\n'), duration,
        best.mbps < 10 ? EndpointConfig.docs.bandwidth : '');
}
// ── AFD Connectivity ──
// Azure Front Door PoP codes → city names
const AFD_POP_MAP = {
    // UK & Ireland
    'LHR': 'London', 'MAN': 'Manchester', 'DUB': 'Dublin',
    // Europe
    'AMS': 'Amsterdam', 'FRA': 'Frankfurt', 'PAR': 'Paris', 'MAD': 'Madrid',
    'MIL': 'Milan', 'ZRH': 'Zurich', 'VIE': 'Vienna', 'CPH': 'Copenhagen',
    'HEL': 'Helsinki', 'OSL': 'Oslo', 'STO': 'Stockholm', 'WAW': 'Warsaw',
    'BUD': 'Budapest', 'PRG': 'Prague', 'BER': 'Berlin', 'MRS': 'Marseille',
    'LIS': 'Lisbon', 'ATH': 'Athens', 'SOF': 'Sofia', 'BUH': 'Bucharest',
    'ZAG': 'Zagreb', 'BEG': 'Belgrade', 'BTS': 'Bratislava',
    // US
    'IAD': 'Washington DC', 'JFK': 'New York', 'EWR': 'Newark',
    'ATL': 'Atlanta', 'MIA': 'Miami', 'ORD': 'Chicago', 'DFW': 'Dallas',
    'LAX': 'Los Angeles', 'SJC': 'San Jose', 'SEA': 'Seattle',
    'DEN': 'Denver', 'PHX': 'Phoenix', 'SLC': 'Salt Lake City',
    'MSP': 'Minneapolis', 'BOS': 'Boston', 'CLT': 'Charlotte',
    'HOU': 'Houston', 'QRO': 'Querétaro',
    // Canada
    'YYZ': 'Toronto', 'YUL': 'Montreal', 'YVR': 'Vancouver',
    // Asia Pacific
    'SIN': 'Singapore', 'HKG': 'Hong Kong', 'NRT': 'Tokyo',
    'KIX': 'Osaka', 'ICN': 'Seoul', 'BOM': 'Mumbai', 'MAA': 'Chennai',
    'DEL': 'Delhi', 'BLR': 'Bangalore', 'HYD': 'Hyderabad',
    'KUL': 'Kuala Lumpur', 'BKK': 'Bangkok', 'CGK': 'Jakarta',
    'MNL': 'Manila', 'TPE': 'Taipei',
    // Australia & NZ
    'SYD': 'Sydney', 'MEL': 'Melbourne', 'PER': 'Perth', 'AKL': 'Auckland',
    // Middle East & Africa
    'DXB': 'Dubai', 'AUH': 'Abu Dhabi', 'DOH': 'Doha',
    'JNB': 'Johannesburg', 'CPT': 'Cape Town', 'NBO': 'Nairobi',
    // South America
    'GRU': 'São Paulo', 'GIG': 'Rio de Janeiro', 'SCL': 'Santiago',
    'BOG': 'Bogotá', 'EZE': 'Buenos Aires', 'LIM': 'Lima',
};

async function testGatewayLatency(test) {
    const t0 = performance.now();
    const ep = EndpointConfig.gatewayEndpoints[0];
    const lines = [];
    let connected = false;
    let afdPop = '';
    let afdPopCity = '';
    let serviceRegion = '';
    let edgeRef = '';
    let latencyMs = 0;
    let cnameChain = [];
    let edgeIp = '';

    // Step 1: Try regular fetch (CORS) to read AFD response headers
    try {
        const start = performance.now();
        const resp = await fetch(`https://${ep}/?_t=${Date.now()}`, {
            cache: 'no-store',
            signal: AbortSignal.timeout(10000)
        });
        latencyMs = Math.round(performance.now() - start);
        connected = true;

        // Read AFD headers — X-MSEdge-Ref contains the PoP code
        edgeRef = resp.headers.get('X-MSEdge-Ref') || resp.headers.get('x-azure-ref') || '';
        serviceRegion = resp.headers.get('x-ms-wvd-service-region') || '';

        // Parse 3-letter PoP code from X-MSEdge-Ref
        if (edgeRef) {
            const popMatch = edgeRef.match(/Ref\s+B:\s*([A-Z]{2,5})\d*Edge/i);
            if (popMatch) {
                afdPop = popMatch[1].toUpperCase();
                afdPopCity = AFD_POP_MAP[afdPop] || '';
            }
        }
    } catch (e) {
        // CORS blocked — fall back to no-cors
    }

    // Step 2: If CORS fetch failed, try no-cors for connectivity only
    if (!connected) {
        try {
            const start = performance.now();
            await fetch(`https://${ep}/?_t=${Date.now()}`, {
                method: 'HEAD', mode: 'no-cors', cache: 'no-store',
                signal: AbortSignal.timeout(10000)
            });
            latencyMs = Math.round(performance.now() - start);
            connected = true;
        } catch (e) {
            lines.push(`✗ AFD connectivity: FAILED — ${e.message || 'connection error'}`);
        }
    }

    // Step 3: Resolve CNAME chain via DoH to show routing path
    try {
        const dnsResp = await fetch(`https://dns.google/resolve?name=${ep}&type=A`, {
            signal: AbortSignal.timeout(5000)
        });
        const dnsData = await dnsResp.json();
        if (dnsData.Answer) {
            for (const rec of dnsData.Answer) {
                if (rec.type === 5) { // CNAME
                    cnameChain.push(rec.data.replace(/\.$/, ''));
                } else if (rec.type === 1) { // A record
                    edgeIp = rec.data;
                }
            }
        }
    } catch (e) { /* DoH unavailable */ }

    // Build detail output
    if (afdPopCity) {
        lines.push(`╔══════════════════════════════════════════════════╗`);
        lines.push(`║  AFD Edge: ${afdPopCity} (${afdPop})`.padEnd(49) + `║`);
        lines.push(`╚══════════════════════════════════════════════════╝`);
    }

    lines.push(`Endpoint: ${ep}`);
    if (connected) lines.push(`Status: ✓ Connected (${latencyMs}ms)`);

    if (afdPopCity) {
        lines.push(`AFD PoP: ${afdPopCity} (${afdPop})`);
    } else if (afdPop) {
        lines.push(`AFD PoP: ${afdPop}`);
    }
    if (serviceRegion) lines.push(`Service Region: ${serviceRegion}`);
    if (edgeRef) lines.push(`Edge Ref: ${edgeRef}`);

    // Show DNS resolution chain
    if (cnameChain.length > 0 || edgeIp) {
        lines.push('');
        lines.push(`DNS Resolution Chain:`);
        lines.push(`  ${ep}`);
        for (const cname of cnameChain) {
            lines.push(`  → ${cname}`);
        }
        if (edgeIp) lines.push(`  → ${edgeIp} (anycast)`);
    }

    // Note about edge location if we couldn't get it from headers
    if (connected && !afdPop) {
        lines.push('');
        lines.push(`Edge location: see Local Scanner results (L-TCP-09 Gateway Used)`);
    }

    // Step 4: Resource Timing info
    if (connected && typeof performance !== 'undefined' && performance.getEntriesByType) {
        const entries = performance.getEntriesByType('resource')
            .filter(e => e.name.includes(ep))
            .sort((a, b) => b.startTime - a.startTime);
        if (entries.length > 0) {
            const entry = entries[0];
            if (entry.nextHopProtocol) {
                lines.push(`Protocol: ${entry.nextHopProtocol}`);
            }
        }
    }

    // Step 5: Additional latency samples
    if (connected) {
        const times = [latencyMs];
        for (let i = 0; i < 2; i++) {
            try {
                const s = performance.now();
                await fetch(`https://${ep}/?_t=${Date.now()}_${i}`, {
                    method: 'HEAD', mode: 'no-cors', cache: 'no-store',
                    signal: AbortSignal.timeout(8000)
                });
                times.push(Math.round(performance.now() - s));
            } catch (e) { times.push(-1); }
            await new Promise(r => setTimeout(r, 200));
        }
        const valid = times.filter(t => t > 0);
        const avg = Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
        lines.push(`Latency: avg ${avg}ms over ${valid.length} samples`);
    }

    const duration = Math.round(performance.now() - t0);

    if (!connected) {
        return makeResult(test, 'Failed', 'AFD unreachable',
            lines.join('\n'), duration, EndpointConfig.docs.networkRequirements);
    }

    let value;
    if (afdPopCity) {
        value = `✓ ${afdPopCity} (${afdPop}) — ${latencyMs}ms`;
    } else if (afdPop) {
        value = `✓ PoP: ${afdPop} — ${latencyMs}ms`;
    } else {
        value = `✓ Connected — ${latencyMs}ms`;
    }
    return makeResult(test, 'Passed', value, lines.join('\n'), duration);
}

// ── DNS Performance ──
async function testDnsPerformance(test) {
    const t0 = performance.now();

    // Use Resource Timing API if available
    const targets = ['login.microsoftonline.com', 'rdweb.wvd.microsoft.com', 'client.wvd.microsoft.com'];
    const results = [];

    for (const host of targets) {
        const url = `https://${host}/?_dns_t=${Date.now()}`;
        try {
            const start = performance.now();
            await fetch(url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(8000) });
            const elapsed = Math.round(performance.now() - start);
            results.push({ host, time: elapsed, status: 'OK' });
        } catch (e) {
            const elapsed = Math.round(performance.now() - (t0 + results.length * 100));
            results.push({ host, time: elapsed, status: 'Error' });
        }
    }

    const duration = Math.round(performance.now() - t0);
    const valid = results.filter(r => r.status === 'OK');
    const times = valid.map(r => r.time);
    const avg = times.length > 0 ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : -1;

    const detail = results.map(r => `${r.host}: ${r.time}ms (${r.status})`).join('\n') +
        '\n\nNote: Timing includes DNS + TCP + TLS. For pure DNS timing, use the Local Scanner.';

    let status = 'Passed';
    if (avg > 500 || avg < 0) status = 'Warning';
    else if (avg > 1000) status = 'Failed';

    const value = avg > 0 ? `Avg ${avg}ms (DNS+TLS) across ${valid.length} endpoints` : 'Could not measure';
    return makeResult(test, status, value, detail, duration, EndpointConfig.docs.dnsConfig);
}

// ── STUN Connectivity ──
async function testWebRtcStun(test) {
    const t0 = performance.now();

    if (typeof RTCPeerConnection === 'undefined') {
        return makeResult(test, 'Failed', 'WebRTC not supported',
            'Your browser does not support WebRTC. STUN/TURN tests cannot run.',
            Math.round(performance.now() - t0));
    }

    try {
        const candidates = await gatherIceCandidates({
            iceServers: [{ urls: 'stun:stun.azure.com:3478' }]
        }, 5000);

        const duration = Math.round(performance.now() - t0);
        const srflx = candidates.filter(c => c.type === 'srflx');
        const host = candidates.filter(c => c.type === 'host');

        const detail = candidates.map(c =>
            `Type: ${c.type} | Address: ${c.address}:${c.port} | Protocol: ${c.protocol}`
        ).join('\n');

        if (srflx.length > 0) {
            const reflexive = srflx[0];
            return makeResult(test, 'Passed',
                `STUN OK \u2014 Reflexive address: ${reflexive.address}`,
                `Server-reflexive candidates found (STUN working).\nReflexive IP: ${reflexive.address}\n\n${detail}`,
                duration);
        } else if (host.length > 0) {
            return makeResult(test, 'Warning',
                'STUN returned only host candidates',
                `No server-reflexive candidates. STUN may be blocked.\n\n${detail}`,
                duration, EndpointConfig.docs.natType);
        } else {
            return makeResult(test, 'Failed', 'No ICE candidates gathered',
                'WebRTC ICE gathering returned no candidates. STUN is likely blocked.',
                duration, EndpointConfig.docs.natType);
        }
    } catch (e) {
        return makeResult(test, 'Error', `WebRTC error: ${e.message}`,
            e.stack || e.message, Math.round(performance.now() - t0));
    }
}

// ── NAT Type Detection ──
// Uses two different STUN servers in separate PeerConnections to compare
// reflexive IP:port mappings. Same mapping = Cone NAT; different = Symmetric.
// A single STUN server cannot distinguish symmetric from port-restricted cone.
async function testNatType(test) {
    const t0 = performance.now();

    if (typeof RTCPeerConnection === 'undefined') {
        return makeResult(test, 'Failed', 'WebRTC not supported',
            'Cannot detect NAT type without WebRTC.', Math.round(performance.now() - t0));
    }

    try {
        // Use a SINGLE PeerConnection with BOTH STUN servers so the browser
        // sends STUN binding requests from the SAME local socket to two
        // different destinations.  For a Cone NAT (endpoint-independent
        // mapping) the reflexive address is identical for both servers, so the
        // browser de-duplicates and reports only ONE srflx candidate.  For a
        // Symmetric NAT (endpoint-dependent mapping) the two servers see
        // different reflexive ports, producing TWO distinct srflx candidates.
        //
        // The old code used two separate PeerConnections — each created its
        // own socket, so even a Cone NAT would show different ports → always
        // reported "Symmetric".  Fixed now.

        const stunServers = [
            'stun:stun.azure.com:3478',
            'stun:stun.l.google.com:19302'
        ];

        const candidates = await gatherIceCandidates({
            iceServers: stunServers.map(url => ({ urls: url }))
        }, 6000);

        const duration = Math.round(performance.now() - t0);

        const isIPv4 = (addr) => addr && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addr);
        const srflx = candidates.filter(c => c.type === 'srflx' && isIPv4(c.address));
        const allHost = candidates.filter(c => c.type === 'host');

        let natType = 'Unknown';
        let status = 'Warning';
        let detail = '';

        if (srflx.length === 0 && allHost.length === 0) {
            natType = 'Blocked';
            status = 'Failed';
            detail = 'No ICE candidates gathered. UDP is likely fully blocked.';
        } else if (srflx.length === 0) {
            natType = 'STUN Blocked';
            status = 'Warning';
            detail = 'Only host candidates available. STUN is blocked \u2014 RDP Shortpath may require TURN relay.\n' +
                'Host candidates:\n' + allHost.map(c => `  ${c.address}:${c.port}`).join('\n');
        } else {
            // Group srflx by their base socket (relatedAddress:relatedPort).
            // Within each group, count distinct reflexive address:port pairs.
            const byBase = {};
            for (const c of srflx) {
                const base = (c.relatedAddress && c.relatedPort)
                    ? `${c.relatedAddress}:${c.relatedPort}`
                    : 'default';
                if (!byBase[base]) byBase[base] = new Set();
                byBase[base].add(`${c.address}:${c.port}`);
            }

            detail += 'Server-reflexive candidates (from single socket to 2 STUN servers):\n';
            let symmetric = false;
            for (const [base, endpoints] of Object.entries(byBase)) {
                const arr = [...endpoints];
                detail += `  Local base ${base}:\n`;
                arr.forEach(ep => { detail += `    Reflexive: ${ep}\n`; });
                if (arr.length > 1) symmetric = true;
            }
            detail += '\n';

            if (symmetric) {
                natType = 'Symmetric NAT';
                status = 'Warning';
                detail += 'Endpoint-dependent port mapping detected (Symmetric NAT).\n' +
                    'Different STUN servers see different reflexive ports from the same local socket.\n' +
                    'Direct STUN hole-punching is unlikely to succeed.\n' +
                    'RDP Shortpath will use TURN relay instead (still UDP, still good).';
            } else {
                natType = 'Cone NAT \u2014 STUN connectivity supported';
                status = 'Passed';
                const ep = [...Object.values(byBase)[0]][0];
                detail += `Consistent reflexive mapping: ${ep}\n` +
                    'Both STUN servers see the same external IP:port from the same local socket.\n' +
                    'NAT preserves endpoint-independent mapping (Cone NAT).\n' +
                    'This is compatible with STUN \u2014 RDP Shortpath (UDP) should work well.\n\n' +
                    'NAT sub-type: Full Cone, Restricted Cone, or Port-Restricted Cone\n' +
                    '(all are compatible with RDP Shortpath via STUN/TURN).';
            }
        }

        detail += '\n\nAll ICE candidates:\n' + candidates.map(c =>
            `  ${c.type}: ${c.address}:${c.port} (${c.protocol})` +
            (c.relatedAddress ? ` raddr=${c.relatedAddress}:${c.relatedPort}` : '')
        ).join('\n');

        return makeResult(test, status, natType, detail, duration,
            status !== 'Passed' ? EndpointConfig.docs.natType : '');
    } catch (e) {
        return makeResult(test, 'Error', `NAT detection error: ${e.message}`,
            e.stack || e.message, Math.round(performance.now() - t0));
    }
}


// ── DNS & Routing Analysis ──
// Uses Google DNS-over-HTTPS to resolve full CNAME chains for key RDP endpoints,
// then times HTTPS connectivity to each. Shows how DNS routes traffic through
// AFD, Traffic Manager, and Private Link. For full ICMP traceroute (hop-by-hop),
// use the Local Scanner test L-TCP-10.
/**
 * Azure Service Tags subnet→region lookup for TURN relay IPs (51.5.0.0/16).
 * Source: ServiceTags_Public JSON → AzureCloud.{region} entries for WVDRelays.
 * Returns Azure region identifier (e.g. 'uksouth') or null.
 */
function lookupTurnRelayRegion(ip) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p[0] !== 51 || p[1] !== 5) return null;
    const c = p[2]; // third octet
    // /23 ranges (third octet with bit 0 masked)
    const r23 = {
        0:'southcentralus', 2:'eastus2', 4:'uksouth', 8:'southindia',
        16:'centralindia', 28:'germanywc', 30:'westindia', 38:'eastus', 40:'northcentralus'
    };
    const masked = c & 0xFE;
    if (r23[masked] !== undefined) return r23[masked];
    // /24 ranges
    const r24 = {
        6:'uksouth', 7:'southindia', 10:'southindia', 11:'westeurope', 12:'westeurope',
        13:'brazilsouth', 14:'brazilsouth', 15:'centralindia', 18:'ukwest', 19:'uaenorth',
        20:'northeurope', 21:'southeastasia', 22:'southeastasia', 23:'westus', 24:'centralus',
        25:'eastasia', 26:'canadacentral', 27:'centralfrance', 32:'australiaeast',
        33:'japaneast', 34:'japaneast', 35:'japanwest', 36:'japanwest',
        37:'australiasoutheast', 42:'southafricanorth', 43:'southafricawest',
        44:'uaecentral', 45:'westcentralus', 46:'westus', 47:'westus3', 48:'canadaeast',
        49:'norwaye', 50:'australiacentral', 51:'koreacentral', 52:'koreasouth',
        53:'switzerlandn', 54:'eastus2euap', 55:'israelcentral', 56:'mexicocentral',
        57:'spaincentral', 58:'taiwannorth', 59:'newzealandnorth', 60:'italynorth',
        61:'polandcentral', 62:'swedencentral', 63:'newzealandnorth', 64:'taiwannorthwest',
        65:'swedencentral', 66:'swedensouth', 67:'southfrance', 68:'germanyn',
        69:'switzerlandw', 70:'norwayw', 71:'westus2', 72:'chilec'
    };
    return r24[c] || null;
}

/**
 * Looks up an RDP Gateway IP in 40.64.144.0/20 against Azure Service Tags.
 * Returns Azure region identifier (e.g. 'uksouth') or null.
 */
function lookupGatewayRegion(ip) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p[0] !== 40 || p[1] !== 64 || p[2] < 144 || p[2] > 159) return null;
    const offset = (p[2] - 144) * 256 + p[3];
    // /30 (mask off 2 host bits)
    const r30 = {928:'eastus2euap'};
    let m = offset & 0xFFFC;
    if (r30[m]) return r30[m];
    // /29 (mask off 3 host bits)
    const r29 = {
        128:'swedensouth', 136:'swedencentral', 144:'taiwannorthwest', 152:'newzealandnorth',
        168:'taiwannorth', 176:'spaincentral', 184:'mexicocentral', 192:'eastus2',
        200:'uksouth', 208:'southindia', 216:'southeastasia', 224:'brazilsouth',
        232:'centralindia', 240:'ukwest', 248:'israelcentral',
        960:'southfrance', 968:'germanyn', 976:'switzerlandw', 984:'norwayw',
        1000:'chilec', 1008:'polandcentral', 1016:'italynorth'
    };
    m = offset & 0xFFF8;
    if (r29[m]) return r29[m];
    // /28 (mask off 4 host bits)
    const r28 = {
        160:'taiwannorth', 256:'eastus2', 272:'uksouth', 288:'southindia',
        304:'southcentralus', 320:'brazilsouth', 336:'centralindia', 352:'ukwest',
        368:'uaenorth', 384:'westeurope', 400:'southeastasia', 416:'westus2',
        432:'centralus', 448:'eastasia', 464:'canadacentral', 480:'centralfrance',
        496:'germanywc', 512:'westindia', 528:'australiaeast', 544:'japaneast',
        560:'japanwest', 576:'australiasoutheast', 592:'eastus', 608:'northcentralus',
        624:'southafricanorth', 640:'southafricawest', 656:'uaecentral',
        672:'westcentralus', 688:'westus', 704:'westus3', 720:'canadaeast',
        736:'norwaye', 752:'australiacentral', 768:'koreacentral', 784:'koreasouth',
        800:'switzerlandn', 816:'jioindiawest', 832:'northeurope'
    };
    m = offset & 0xFFF0;
    if (r28[m]) return r28[m];
    // /27 (mask off 5 host bits)
    const r27 = {
        0:'southcentralus', 32:'westeurope', 64:'northeurope',
        1024:'germanyn', 1056:'eastus2', 1088:'uksouth', 1120:'southindia',
        1152:'brazilsouth', 1216:'centralindia', 1248:'ukwest', 1280:'uaenorth',
        1312:'southeastasia', 1344:'westus2', 1376:'centralus', 1408:'eastasia',
        1440:'canadacentral', 1472:'centralfrance', 1504:'germanywc', 1536:'westindia',
        1568:'australiaeast', 1600:'japaneast', 1632:'japanwest',
        1664:'australiasoutheast', 1696:'eastus', 1728:'northcentralus',
        1760:'southafricanorth', 1792:'southafricawest', 1824:'uaecentral',
        1856:'westcentralus', 1888:'westus', 1920:'westus3', 1952:'canadaeast',
        1984:'norwaye', 2016:'australiacentral', 2048:'koreacentral', 2080:'koreasouth',
        2112:'switzerlandn', 2144:'jioindiawest', 2176:'israelcentral',
        2208:'mexicocentral', 2240:'spaincentral', 2272:'taiwannorth',
        2304:'newzealandnorth', 2336:'taiwannorthwest', 2368:'swedencentral',
        2400:'swedensouth', 2432:'southfrance', 2464:'switzerlandw', 2496:'norwayw',
        2528:'italynorth', 2560:'polandcentral', 2592:'chilec'
    };
    m = offset & 0xFFE0;
    if (r27[m]) return r27[m];
    return null;
}

/**
 * Maps Azure region identifiers to friendly display names.
 */
function getAzureRegionFriendlyName(region) {
    // Official display names per https://learn.microsoft.com/azure/reliability/regions-list
    const map = {
        uksouth:'UK South', ukwest:'UK West',
        northeurope:'North Europe', westeurope:'West Europe',
        centralfrance:'France Central', southfrance:'France South',
        germanywc:'Germany West Central', germanyn:'Germany North',
        norwaye:'Norway East', norwayw:'Norway West',
        swedencentral:'Sweden Central', swedensouth:'Sweden South',
        switzerlandn:'Switzerland North', switzerlandw:'Switzerland West',
        italynorth:'Italy North', spaincentral:'Spain Central', polandcentral:'Poland Central',
        eastus:'East US', eastus2:'East US 2', eastus2euap:'East US 2 EUAP',
        centralus:'Central US', northcentralus:'North Central US',
        southcentralus:'South Central US', westcentralus:'West Central US',
        westus:'West US', westus2:'West US 2', westus3:'West US 3',
        canadacentral:'Canada Central', canadaeast:'Canada East',
        mexicocentral:'Mexico Central', chilec:'Chile Central',
        southeastasia:'Southeast Asia', eastasia:'East Asia',
        japaneast:'Japan East', japanwest:'Japan West',
        koreacentral:'Korea Central', koreasouth:'Korea South',
        centralindia:'Central India', southindia:'South India', westindia:'West India',
        australiaeast:'Australia East', australiasoutheast:'Australia Southeast',
        australiacentral:'Australia Central',
        taiwannorth:'Taiwan North', taiwannorthwest:'Taiwan Northwest',
        newzealandnorth:'New Zealand North',
        southafricanorth:'South Africa North', southafricawest:'South Africa West',
        uaenorth:'UAE North', uaecentral:'UAE Central', israelcentral:'Israel Central',
        jioindiawest:'Jio India West',
        brazilsouth:'Brazil South'
    };
    return map[region] || null;
}

/**
 * Identifies known Microsoft/Azure IP ranges when reverse DNS is unavailable.
 */
function identifyMicrosoftIp(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p))) return '';
    const [a, b] = parts;
    if (a === 104 && b === 44) return '[Microsoft backbone]';
    if (a === 104 && b >= 40 && b <= 47) return '[Azure]';
    if (a === 40 && b === 64 && parts[2] >= 144 && parts[2] <= 159) {
        const region = lookupGatewayRegion(ip);
        if (region) {
            const friendly = getAzureRegionFriendlyName(region);
            return friendly ? `[RDP Gateway — ${friendly}]` : `[RDP Gateway — ${region}]`;
        }
        return '[RDP Gateway range]';
    }
    if (a === 40 && (b & 0xC0) === 64) return '[Azure]';
    if (a === 20) return '[Azure]';
    if (a === 13 && (b & 0xE0) === 64) return '[Azure]';
    if (a === 52 && b >= 96 && b <= 111) return '[Microsoft 365]';
    if (a === 51 && b === 5) {
        const region = lookupTurnRelayRegion(ip);
        if (region) {
            const friendly = getAzureRegionFriendlyName(region);
            return friendly ? `[AVD TURN relay — ${friendly}]` : `[AVD TURN relay — ${region}]`;
        }
        return '[AVD TURN relay range]';
    }
    if (a === 150 && b === 171) return '[Microsoft backbone]';
    if (a === 4 && b >= 150) return '[Microsoft]';
    return '';
}

async function testNetworkPathTrace(test) {
    const t0 = performance.now();
    const lines = [];
    lines.push('ℹ For full hop-by-hop ICMP traceroute, run the Local Scanner (L-TCP-10)');
    lines.push('');

    const targets = [
        { host: 'afdfp-rdgateway-r1.wvd.microsoft.com', label: 'RDP Gateway (AFD)' },
        { host: 'rdweb.wvd.microsoft.com',               label: 'AVD Web Access' },
        { host: 'client.wvd.microsoft.com',               label: 'AVD Client Service' },
        { host: 'login.microsoftonline.com',              label: 'Authentication' },
        { host: 'world.relay.avd.microsoft.com',          label: 'TURN Relay' },
        { host: 'windows.cloud.microsoft',                label: 'Connection Center' }
    ];

    let ok = 0;
    let warn = 0;

    for (const target of targets) {
        lines.push(`╔══ ${target.label} ══`);
        lines.push(`║  Host: ${target.host}`);

        // Step 1: DNS chain via DoH
        let finalIp = '';
        let cnameChain = [];
        try {
            const dnsResp = await fetch(
                `https://dns.google/resolve?name=${target.host}&type=A`,
                { signal: AbortSignal.timeout(5000), cache: 'no-store' }
            );
            if (dnsResp.ok) {
                const dnsData = await dnsResp.json();
                if (dnsData.Answer) {
                    for (const rec of dnsData.Answer) {
                        if (rec.type === 5) { // CNAME
                            cnameChain.push(rec.data.replace(/\.$/, ''));
                        } else if (rec.type === 1) { // A
                            finalIp = rec.data;
                        }
                    }
                }
                if (cnameChain.length > 0) {
                    lines.push(`║  DNS Chain:`);
                    lines.push(`║    ${target.host}`);
                    for (const cname of cnameChain) {
                        lines.push(`║    → ${cname}`);
                    }
                    if (finalIp) lines.push(`║    → ${finalIp}`);
                } else if (finalIp) {
                    lines.push(`║  Resolved: ${finalIp}`);
                } else {
                    lines.push(`║  DNS: No A records found`);
                    warn++;
                }
                // Check for routing indicators
                const chainStr = cnameChain.join(' ').toLowerCase();

                // GSA / SASE / SWG detection
                if (chainStr.includes('globalsecureaccess') || chainStr.includes('sse.microsoft') ||
                    chainStr.includes('edge.security.microsoft')) {
                    lines.push(`║  ⚠ Routed via: Microsoft Global Secure Access (Entra Private Access)`);
                    lines.push(`║    Traffic is NOT going direct — routed through a security proxy`);
                    warn++;
                } else if (chainStr.includes('zscaler')) {
                    lines.push(`║  ⚠ Routed via: Zscaler Secure Web Gateway`);
                    lines.push(`║    Traffic is NOT going direct — routed through a security proxy`);
                    warn++;
                } else if (chainStr.includes('netskope')) {
                    lines.push(`║  ⚠ Routed via: Netskope Secure Web Gateway`);
                    lines.push(`║    Traffic is NOT going direct — routed through a security proxy`);
                    warn++;
                } else if (chainStr.includes('cloudflare-gateway') || chainStr.includes('swg')) {
                    lines.push(`║  ⚠ Routed via: Third-party Secure Web Gateway`);
                    lines.push(`║    Traffic is NOT going direct — routed through a security proxy`);
                    warn++;
                }

                // Label final IP if it's a known Microsoft range
                if (finalIp) {
                    const msLabel = identifyMicrosoftIp(finalIp);
                    if (msLabel) {
                        lines.push(`║  ℹ IP identified: ${finalIp} ${msLabel}`);
                    }
                }

                // "privatelink" appears in standard Microsoft DNS chains even on public paths.
                // Only flag Private Link if the final IP is actually a private/RFC1918 address.
                if (chainStr.includes('privatelink')) {
                    const isPrivateIp = finalIp && /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(finalIp);
                    if (isPrivateIp) {
                        lines.push(`║  ⚠ Private Link ACTIVE — resolves to private IP ${finalIp}`);
                    } else {
                        lines.push(`║  ℹ Private Link CNAME present (standard — public IP, not active)`);
                    }
                }
                if (chainStr.includes('trafficmanager')) {
                    lines.push(`║  ℹ Traffic Manager routing detected`);
                }
                if (chainStr.includes('azurefd') || chainStr.includes('afd') || chainStr.includes('edgekey')) {
                    lines.push(`║  ℹ Azure Front Door / CDN routing detected`);
                }
            } else {
                lines.push(`║  DNS: DoH query failed (HTTP ${dnsResp.status})`);
            }
        } catch (e) {
            lines.push(`║  DNS: DoH unavailable (${e.message})`);
        }

        // Step 2: HTTPS timing
        try {
            const start = performance.now();
            await fetch(`https://${target.host}/?_trace=${Date.now()}`, {
                method: 'HEAD', mode: 'no-cors', cache: 'no-store',
                signal: AbortSignal.timeout(10000)
            });
            const ms = Math.round(performance.now() - start);
            lines.push(`║  HTTPS: ✓ ${ms}ms`);

            // Check Resource Timing for protocol info
            if (typeof performance !== 'undefined' && performance.getEntriesByType) {
                const entries = performance.getEntriesByType('resource')
                    .filter(e => e.name.includes(target.host))
                    .sort((a, b) => b.startTime - a.startTime);
                if (entries.length > 0 && entries[0].nextHopProtocol) {
                    lines.push(`║  Protocol: ${entries[0].nextHopProtocol}`);
                }
            }

            ok++;
        } catch (e) {
            const ms = Math.round(performance.now() - t0);
            lines.push(`║  HTTPS: ✗ Failed (${e.message})`);
            warn++;
        }

        // Step 3: Also resolve AAAA (IPv6) — useful for dual-stack diagnostics
        try {
            const dns6Resp = await fetch(
                `https://dns.google/resolve?name=${target.host}&type=AAAA`,
                { signal: AbortSignal.timeout(3000), cache: 'no-store' }
            );
            if (dns6Resp.ok) {
                const dns6Data = await dns6Resp.json();
                const aaaa = dns6Data.Answer?.filter(r => r.type === 28).map(r => r.data) || [];
                if (aaaa.length > 0) {
                    lines.push(`║  IPv6: ${aaaa[0]}`);
                }
            }
        } catch (e) { /* IPv6 lookup optional */ }

        lines.push(`╚${'═'.repeat(50)}`);
        lines.push('');
    }

    const duration = Math.round(performance.now() - t0);
    const value = `${ok}/${targets.length} endpoints analysed`;
    const status = warn > 0 ? 'Warning' : 'Passed';

    return makeResult(test, status, value, lines.join('\n'), duration);
}


// ═════════════════════════════════════════════════════
//  WebRTC Helper
// ═════════════════════════════════════════════════════

function gatherIceCandidates(config, timeoutMs) {
    return new Promise((resolve) => {
        const candidates = [];
        const pc = new RTCPeerConnection(config);

        // Need a data channel or media to trigger ICE
        pc.createDataChannel('test');

        const timer = setTimeout(() => {
            pc.close();
            resolve(candidates);
        }, timeoutMs);

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                const c = event.candidate;
                // Parse the candidate string for details
                const parsed = parseCandidate(c);
                if (parsed) candidates.push(parsed);
            }
        };

        pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === 'complete') {
                clearTimeout(timer);
                pc.close();
                resolve(candidates);
            }
        };

        pc.createOffer()
            .then(offer => pc.setLocalDescription(offer))
            .catch(() => {
                clearTimeout(timer);
                pc.close();
                resolve(candidates);
            });
    });
}

function parseCandidate(candidate) {
    try {
        // Use the RTCIceCandidate properties directly
        return {
            type: candidate.type || 'unknown',
            address: candidate.address || candidate.ip || extractField(candidate.candidate, 4),
            port: candidate.port || parseInt(extractField(candidate.candidate, 5)) || 0,
            protocol: candidate.protocol || extractField(candidate.candidate, 2) || 'unknown',
            relatedAddress: candidate.relatedAddress || extractRelated(candidate.candidate, 'raddr') || '',
            relatedPort: candidate.relatedPort || parseInt(extractRelated(candidate.candidate, 'rport')) || 0,
            raw: candidate.candidate
        };
    } catch {
        return null;
    }
}

function extractRelated(candidateStr, field) {
    if (!candidateStr) return '';
    const idx = candidateStr.indexOf(field);
    if (idx < 0) return '';
    const parts = candidateStr.substring(idx).split(' ');
    return parts.length > 1 ? parts[1] : '';
}

function extractField(candidateStr, index) {
    if (!candidateStr) return '';
    const parts = candidateStr.split(' ');
    return parts.length > index ? parts[index] : '';
}
