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
        id: 'B-LE-03', name: 'Connection Type',
        description: 'Detects network connection type and effective bandwidth via Network Information API',
        category: 'local', source: 'browser', run: testConnectionType
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
        id: 'L-TCP-04', name: 'Gateway Connectivity',
        description: 'Tests DNS → TCP → TLS → HTTPS layers to RD Gateway endpoints, pinpoints failures (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'B-TCP-02', name: 'Gateway Latency',
        description: 'Measures round-trip time to RD Gateway via fetch timing',
        category: 'tcp', source: 'browser', run: testGatewayLatency
    },
    {
        id: 'L-TCP-08', name: 'DNS Hijacking Check',
        description: 'Verifies gateway DNS resolves to legitimate Microsoft IPs, not hijacked (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'L-TCP-09', name: 'Gateway Used',
        description: 'Shows which gateway edge node, IP, routing method (AFD/Private Link), and cert are in use (requires Local Scanner)',
        category: 'tcp', source: 'local'
    },
    {
        id: 'L-TCP-05', name: 'DNS CNAME Chain Analysis',
        description: 'Traces full DNS resolution chain for AFD/Private Link detection (requires Local Scanner)',
        category: 'tcp', source: 'local'
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

async function fetchGeoIp() {
    if (_geoCache) return _geoCache;
    // Primary: ipinfo.io (most accurate city-level geo, HTTPS, CORS-friendly)
    try {
        const r = await fetch(EndpointConfig.geoIpPrimaryUrl, { signal: AbortSignal.timeout(8000) });
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
        const r = await fetch(EndpointConfig.geoIpFallbackUrl, { signal: AbortSignal.timeout(8000) });
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
        const r = await fetch(EndpointConfig.geoIpFallback2Url, { signal: AbortSignal.timeout(8000) });
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
        const r = await fetch('https://ipwho.is/', { signal: AbortSignal.timeout(8000) });
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

// ── Connection Type ──
async function testConnectionType(test) {
    const t0 = performance.now();
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;

    if (!conn) {
        return makeResult(test, 'Warning', 'Network Information API not available',
            'Your browser does not support the Network Information API. Use Chrome/Edge for this test.',
            Math.round(performance.now() - t0));
    }

    const type = conn.effectiveType || 'unknown';
    const downlink = conn.downlink ? `${conn.downlink} Mbps` : 'unknown';
    const rtt = conn.rtt ? `${conn.rtt}ms` : 'unknown';
    const saveData = conn.saveData ? 'Yes' : 'No';
    const duration = Math.round(performance.now() - t0);

    const value = `${type.toUpperCase()} - ${downlink} downlink, ${rtt} RTT`;
    const detail = `Effective Type: ${type}\nDownlink: ${downlink}\nRTT: ${rtt}\nData Saver: ${saveData}`;

    const slow = type === 'slow-2g' || type === '2g' || (conn.rtt && conn.rtt > 300);
    return makeResult(test, slow ? 'Warning' : 'Passed', value, detail, duration,
        slow ? EndpointConfig.docs.bandwidth : '');
}
// ── Gateway Latency ──
async function testGatewayLatency(test) {
    const t0 = performance.now();
    const ep = EndpointConfig.gatewayEndpoints[0];
    const times = [];

    // Run 5 fetch attempts and measure timing
    for (let i = 0; i < 5; i++) {
        try {
            const start = performance.now();
            await fetch(`https://${ep}/?_t=${Date.now()}`, {
                method: 'HEAD', mode: 'no-cors', cache: 'no-store',
                signal: AbortSignal.timeout(8000)
            });
            times.push(Math.round(performance.now() - start));
        } catch (e) {
            times.push(-1);
        }
        // Small delay between probes
        await new Promise(r => setTimeout(r, 200));
    }

    const duration = Math.round(performance.now() - t0);
    const valid = times.filter(t => t > 0);

    if (valid.length === 0) {
        return makeResult(test, 'Failed', 'Could not measure gateway latency',
            'All fetch attempts failed.', duration, EndpointConfig.docs.networkRequirements);
    }

    const avg = Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
    const min = Math.min(...valid);
    const max = Math.max(...valid);
    const detail = `Endpoint: ${ep}\nSamples: ${valid.length}/5\nMin: ${min}ms | Avg: ${avg}ms | Max: ${max}ms\n\nNote: Browser fetch latency includes TLS overhead; actual RDP latency will differ.`;

    let status = 'Passed';
    if (avg > 200) status = 'Failed';
    else if (avg > 100) status = 'Warning';

    const value = `Avg ${avg}ms (min ${min}ms, max ${max}ms)`;
    return makeResult(test, status, value, detail, duration,
        status !== 'Passed' ? EndpointConfig.docs.networkRequirements : '');
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
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
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
        // Gather candidates from two independent STUN servers
        const stunServers = [
            'stun:stun.l.google.com:19302',
            'stun:stun1.l.google.com:19302'
        ];

        const [candidates1, candidates2] = await Promise.all([
            gatherIceCandidates({ iceServers: [{ urls: stunServers[0] }] }, 5000),
            gatherIceCandidates({ iceServers: [{ urls: stunServers[1] }] }, 5000)
        ]);

        const duration = Math.round(performance.now() - t0);

        // Filter to IPv4 server-reflexive only (ignore host, relay, and IPv6)
        const isIPv4 = (addr) => addr && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addr);
        const srflx1 = candidates1.filter(c => c.type === 'srflx' && isIPv4(c.address));
        const srflx2 = candidates2.filter(c => c.type === 'srflx' && isIPv4(c.address));
        const allHost = candidates1.filter(c => c.type === 'host');
        const allCandidates = [...candidates1, ...candidates2.filter(c2 =>
            !candidates1.some(c1 => c1.type === c2.type && c1.address === c2.address && c1.port === c2.port))];

        let natType = 'Unknown';
        let status = 'Warning';
        let detail = '';

        if (srflx1.length === 0 && srflx2.length === 0 && allHost.length === 0) {
            natType = 'Blocked';
            status = 'Failed';
            detail = 'No candidates gathered from either STUN server. UDP is likely fully blocked.';
        } else if (srflx1.length === 0 && srflx2.length === 0) {
            natType = 'STUN Blocked';
            status = 'Warning';
            detail = 'Only host candidates available. STUN is blocked \u2014 RDP Shortpath may require TURN relay.\n' +
                'Host candidates:\n' + allHost.map(c => `  ${c.address}:${c.port}`).join('\n');
        } else if (srflx1.length === 0 || srflx2.length === 0) {
            // Only one server returned reflexive — can't compare, but STUN partially works
            const working = srflx1.length > 0 ? srflx1 : srflx2;
            natType = 'Cone NAT (partial STUN)';
            status = 'Passed';
            detail = `Reflexive IP: ${working[0].address}:${working[0].port}\n` +
                'One STUN server returned reflexive candidates. NAT allows STUN \u2014 RDP Shortpath should work.';
        } else {
            // Compare reflexive mappings from both servers
            // Sort by port to get consistent comparison
            const ref1 = srflx1.sort((a, b) => a.port - b.port)[0];
            const ref2 = srflx2.sort((a, b) => a.port - b.port)[0];

            detail += `STUN Server 1 (${stunServers[0]}):\n`;
            detail += `  Reflexive: ${ref1.address}:${ref1.port}\n`;
            detail += `STUN Server 2 (${stunServers[1]}):\n`;
            detail += `  Reflexive: ${ref2.address}:${ref2.port}\n\n`;

            if (ref1.address !== ref2.address) {
                // Different IPs — likely symmetric NAT or multi-homed
                natType = 'Symmetric NAT';
                status = 'Warning';
                detail += `Different reflexive IPs: ${ref1.address} vs ${ref2.address}\n` +
                    'Symmetric NAT detected \u2014 direct STUN P2P may not work.\n' +
                    'RDP Shortpath will use TURN relay instead (still UDP, still good).';
            } else if (ref1.port !== ref2.port) {
                // Same IP, different ports — symmetric NAT (endpoint-dependent mapping)
                natType = 'Symmetric NAT';
                status = 'Warning';
                detail += `Same reflexive IP but different ports: ${ref1.address}:${ref1.port} vs :${ref2.port}\n` +
                    'Endpoint-dependent port mapping detected (Symmetric NAT).\n' +
                    'RDP Shortpath will use TURN relay instead (still UDP, still good).';
            } else {
                // Same IP and port — Cone NAT (full, restricted, or port-restricted)
                // All cone types support STUN-based connectivity for RDP Shortpath
                natType = 'Cone NAT \u2014 STUN connectivity supported';
                status = 'Passed';
                detail += `Consistent reflexive mapping: ${ref1.address}:${ref1.port}\n` +
                    'NAT preserves the same external IP:port for different destinations.\n' +
                    'This is compatible with STUN \u2014 RDP Shortpath (UDP) should work well.\n\n' +
                    'NAT sub-type: Full Cone, Restricted Cone, or Port-Restricted Cone\n' +
                    '(all are compatible with RDP Shortpath via STUN/TURN).';
            }
        }

        detail += '\n\nAll unique candidates:\n' + allCandidates.map(c =>
            `  ${c.type}: ${c.address}:${c.port} (${c.protocol})`
        ).join('\n');

        return makeResult(test, status, natType, detail, duration,
            status !== 'Passed' ? EndpointConfig.docs.natType : '');
    } catch (e) {
        return makeResult(test, 'Error', `NAT detection error: ${e.message}`,
            e.stack || e.message, Math.round(performance.now() - t0));
    }
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
            raw: candidate.candidate
        };
    } catch {
        return null;
    }
}

function extractField(candidateStr, index) {
    if (!candidateStr) return '';
    const parts = candidateStr.split(' ');
    return parts.length > index ? parts[index] : '';
}
