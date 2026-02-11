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

    // ── TCP Based RDP ──
    {
        id: 'B-TCP-01', name: 'Gateway HTTPS Reachability',
        description: 'Tests HTTPS fetch connectivity to RD Gateway endpoints',
        category: 'tcp', source: 'browser', run: testGatewayReachability
    },
    {
        id: 'B-TCP-02', name: 'Gateway Latency',
        description: 'Measures round-trip time to RD Gateway via fetch timing',
        category: 'tcp', source: 'browser', run: testGatewayLatency
    },
    {
        id: 'B-TCP-03', name: 'DNS Resolution Performance',
        description: 'Measures DNS lookup time for key service endpoints',
        category: 'tcp', source: 'browser', run: testDnsPerformance
    },
    {
        id: 'L-TCP-04', name: 'Raw TCP Port Connectivity',
        description: 'Tests raw TCP socket connections to gateway ports (requires Local Scanner)',
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

    // ── RDP Shortpath (UDP) ──
    {
        id: 'B-UDP-01', name: 'WebRTC / STUN Connectivity',
        description: 'Tests STUN server reachability and gathers ICE candidates via WebRTC',
        category: 'udp', source: 'browser', run: testWebRtcStun
    },
    {
        id: 'B-UDP-02', name: 'NAT Type Detection (WebRTC)',
        description: 'Analyses ICE candidates to determine NAT type and reflexive address',
        category: 'udp', source: 'browser', run: testNatType
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
        id: 'L-UDP-05', name: 'UDP NAT Type (Socket)',
        description: 'Performs STUN-based NAT type detection via raw UDP socket (requires Local Scanner)',
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

    // ── Cloud Session ──
    {
        id: 'L-CS-01', name: 'Cloud PC Location',
        description: 'Identifies the Azure region hosting the Cloud PC (requires Local Scanner)',
        category: 'cloud', source: 'local'
    },
    {
        id: 'L-CS-02', name: 'Cloud PC Latency',
        description: 'Measures round-trip latency to the Cloud PC (requires Local Scanner)',
        category: 'cloud', source: 'local'
    },
    {
        id: 'L-CS-03', name: 'Session Throughput',
        description: 'Estimates available throughput to the Cloud PC (requires Local Scanner)',
        category: 'cloud', source: 'local'
    },
    {
        id: 'L-CS-04', name: 'Jitter Measurement',
        description: 'Measures network jitter to the Cloud PC (requires Local Scanner)',
        category: 'cloud', source: 'local'
    },
    {
        id: 'L-CS-05', name: 'Packet Loss',
        description: 'Detects packet loss on the path to the Cloud PC (requires Local Scanner)',
        category: 'cloud', source: 'local'
    }
];


// ═════════════════════════════════════════════════════
//  Shared helpers
// ═════════════════════════════════════════════════════

let _geoCache = null;

async function fetchGeoIp() {
    if (_geoCache) return _geoCache;
    // Primary: ipwho.is (HTTPS, no key required)
    try {
        const r = await fetch(EndpointConfig.geoIpApiUrl);
        const data = await r.json();
        if (data.success !== false) {
            _geoCache = {
                status: 'success',
                query: data.ip,
                country: data.country,
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
    } catch (e) { /* try fallback */ }
    // Fallback: ipapi.co
    try {
        const r = await fetch(EndpointConfig.geoIpFallbackUrl);
        const data = await r.json();
        if (data.ip) {
            _geoCache = {
                status: 'success',
                query: data.ip,
                country: data.country_name,
                regionName: data.region,
                city: data.city,
                lat: data.latitude,
                lon: data.longitude,
                isp: data.org || 'Unknown',
                org: data.org || 'Unknown',
                as: data.asn || 'Unknown'
            };
            return _geoCache;
        }
    } catch (e) { /* both failed */ }
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
async function testEndpointReachability(test) {
    const t0 = performance.now();
    const results = [];
    let allPassed = true;
    let anyFailed = false;

    const checks = EndpointConfig.requiredEndpoints.map(async (ep) => {
        const url = `https://${ep.url}/`;
        try {
            const start = performance.now();
            const response = await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-store',
                signal: AbortSignal.timeout(8000)
            });
            const elapsed = Math.round(performance.now() - start);
            results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Reachable', time: elapsed });
        } catch (e) {
            // no-cors fetch may fail for various reasons but a TypeError with 'failed'
            // usually means the endpoint is truly unreachable
            if (e.name === 'AbortError' || e.name === 'TimeoutError') {
                results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Timeout', time: -1 });
                anyFailed = true;
            } else {
                // For no-cors, a TypeError is expected for some endpoints but they may still be reachable
                results.push({ endpoint: ep.url, purpose: ep.purpose, status: 'Check (CORS limited)', time: -1 });
                allPassed = false;
            }
        }
    });

    await Promise.all(checks);
    const duration = Math.round(performance.now() - t0);

    const reachable = results.filter(r => r.status === 'Reachable').length;
    const detail = results.map(r =>
        `${r.status === 'Reachable' ? '\u2714' : '\u26A0'} ${r.endpoint} (${r.purpose}) - ${r.status}${r.time > 0 ? ' (' + r.time + 'ms)' : ''}`
    ).join('\n');

    const status = anyFailed ? 'Failed' : (allPassed ? 'Passed' : 'Warning');
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

// ── Gateway HTTPS Reachability ──
async function testGatewayReachability(test) {
    const t0 = performance.now();
    const endpoints = EndpointConfig.gatewayEndpoints;
    const results = [];

    for (const ep of endpoints) {
        try {
            const start = performance.now();
            await fetch(`https://${ep}/`, { method: 'HEAD', mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(8000) });
            results.push({ host: ep, status: 'Reachable', time: Math.round(performance.now() - start) });
        } catch (e) {
            results.push({ host: ep, status: e.name === 'AbortError' ? 'Timeout' : 'Error', time: -1 });
        }
    }

    const duration = Math.round(performance.now() - t0);
    const reachable = results.filter(r => r.status === 'Reachable');
    const detail = results.map(r => `${r.host}: ${r.status}${r.time > 0 ? ' (' + r.time + 'ms)' : ''}`).join('\n');

    if (reachable.length === 0) {
        return makeResult(test, 'Failed', 'No gateway endpoints reachable via HTTPS',
            detail, duration, EndpointConfig.docs.networkRequirements);
    }

    return makeResult(test, 'Passed', `${reachable.length}/${results.length} gateways reachable`,
        detail, duration);
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

// ── WebRTC / STUN Connectivity ──
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

// ── NAT Type Detection (WebRTC) ──
async function testNatType(test) {
    const t0 = performance.now();

    if (typeof RTCPeerConnection === 'undefined') {
        return makeResult(test, 'Failed', 'WebRTC not supported',
            'Cannot detect NAT type without WebRTC.', Math.round(performance.now() - t0));
    }

    try {
        const candidates = await gatherIceCandidates({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        }, 5000);

        const duration = Math.round(performance.now() - t0);
        const srflx = candidates.filter(c => c.type === 'srflx');
        const host = candidates.filter(c => c.type === 'host');
        const relay = candidates.filter(c => c.type === 'relay');

        let natType = 'Unknown';
        let status = 'Warning';
        let detail = '';

        if (srflx.length === 0 && host.length === 0) {
            natType = 'Blocked / Symmetric';
            status = 'Failed';
            detail = 'No candidates gathered. UDP is likely fully blocked.';
        } else if (srflx.length === 0) {
            natType = 'Symmetric / UDP Blocked';
            status = 'Warning';
            detail = 'Only host candidates available. STUN is blocked \u2014 RDP Shortpath may not work.\n' +
                'Host candidates:\n' + host.map(c => `  ${c.address}:${c.port}`).join('\n');
        } else {
            // Check if multiple srflx candidates have different IPs (indicates symmetric NAT)
            const uniqueIps = new Set(srflx.map(c => c.address));
            if (uniqueIps.size > 1) {
                natType = 'Possible Symmetric NAT';
                status = 'Warning';
                detail = `Multiple reflexive IPs detected: ${[...uniqueIps].join(', ')}\n` +
                    'Symmetric NAT may reduce RDP Shortpath effectiveness.';
            } else {
                natType = 'Cone NAT (Full Cone / Restricted)';
                status = 'Passed';
                detail = `Reflexive IP: ${srflx[0].address}\n` +
                    'NAT appears compatible with RDP Shortpath.';
            }
        }

        detail += '\n\nAll candidates:\n' + candidates.map(c =>
            `  ${c.type}: ${c.address}:${c.port} (${c.protocol})`
        ).join('\n');

        detail += '\n\nNote: For precise STUN-based NAT classification, use the Local Scanner.';

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
