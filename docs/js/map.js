/**
 * Connectivity Map — updates the network flow diagram cards from test results.
 * Mirrors the WPF ConnectivityMapControl logic for the web dashboard.
 */

function updateConnectivityMap(results) {
    const lookup = {};
    for (const r of results) {
        lookup[r.id] = r;
    }

    updateMapClientCard(lookup);
    updateMapLocalGwCard(lookup);
    updateMapIspCard(lookup);
    updateMapAfdCard(lookup);
    updateMapRdGwCard(lookup);
    updateMapTurnCard(lookup);
    updateMapDnsCard(lookup);
    updateMapSecurityBar(lookup);
}

// ── Card helpers ──

/** Convert a 2-letter ISO country code to its flag emoji (regional indicators). */
function countryCodeToFlag(code) {
    if (!code || code.length !== 2) return '';
    const upper = code.toUpperCase();
    const cp1 = 0x1F1E6 + (upper.charCodeAt(0) - 65);
    const cp2 = 0x1F1E6 + (upper.charCodeAt(1) - 65);
    return String.fromCodePoint(cp1, cp2);
}

/**
 * Prepend a country flag emoji to a location string like "London, GB".
 * Handles both 2-letter codes and full country names by trying a lookup first.
 */
function addFlag(locationStr) {
    if (!locationStr) return locationStr;
    const parts = locationStr.split(',');
    if (parts.length < 2) return locationStr;
    const last = parts[parts.length - 1].trim();
    // 2-letter country code?
    if (/^[A-Z]{2}$/.test(last)) {
        return `${countryCodeToFlag(last)} ${locationStr}`;
    }
    return locationStr;
}

function setAccentStatus(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = 'map-card-accent';
    if (status === 'Passed') el.classList.add('status-passed');
    else if (status === 'Warning') el.classList.add('status-warning');
    else if (status === 'Failed' || status === 'Error') el.classList.add('status-failed');
    else if (status === 'Running') el.classList.add('status-running');
}

function setText(elementId, text) {
    const el = document.getElementById(elementId);
    if (el) el.textContent = text || '';
}

function setBadge(elementId, text, cssClass) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (!text) {
        el.classList.add('hidden');
        return;
    }
    el.textContent = text;
    el.className = 'map-card-badge ' + cssClass;
}

function latencyClass(ms, isTcp) {
    if (isTcp) {
        if (ms < 50) return 'latency-good';
        if (ms < 150) return 'latency-medium';
        return 'latency-bad';
    }
    // UDP thresholds
    if (ms < 100) return 'latency-good';
    if (ms < 300) return 'latency-medium';
    return 'latency-bad';
}

function worstStatus(a, b) {
    const order = { 'Failed': 0, 'Error': 0, 'Warning': 1, 'Running': 2, 'Passed': 3, 'NotRun': 4, 'Pending': 5 };
    const aVal = order[a] ?? 5;
    const bVal = order[b] ?? 5;
    return aVal <= bVal ? a : b;
}

function extractLine(detailedInfo, prefix) {
    if (!detailedInfo) return '';
    for (const line of detailedInfo.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.toLowerCase().startsWith(prefix.toLowerCase())) {
            return trimmed.substring(prefix.length).trim();
        }
    }
    return '';
}

// ── Client Card ──
function updateMapClientCard(lookup) {
    let location = '';
    let publicIp = '';
    let status = 'NotRun';

    const userLoc = lookup['B-LE-01'];
    if (userLoc && userLoc.status !== 'NotRun') {
        location = userLoc.resultValue || '';
        status = userLoc.status;
        publicIp = extractLine(userLoc.detailedInfo, 'Public IP:');
    }

    setText('map-client-location', location ? addFlag(location) : 'Awaiting results...');
    setText('map-client-ip', publicIp ? `🌐 ${publicIp}` : '');
    setAccentStatus('map-client-accent', status);
}

// ── Local Gateway Card ──
function updateMapLocalGwCard(lookup) {
    const gw = lookup['L-LE-05'];
    if (!gw || gw.status === 'NotRun' || gw.status === 'Pending') {
        setText('map-localgw-detail', 'Awaiting local scan...');
        setText('map-localgw-detail2', '');
        setAccentStatus('map-localgw-accent', 'NotRun');
        return;
    }

    const gwIp = extractLine(gw.detailedInfo, 'Gateway:');
    setText('map-localgw-detail', gwIp || gw.resultValue || '');
    setText('map-localgw-detail2', gw.resultValue || '');
    setAccentStatus('map-localgw-accent', gw.status);
}

// ── ISP Card ──
function updateMapIspCard(lookup) {
    const isp = lookup['B-LE-02'];
    if (!isp || isp.status === 'NotRun') {
        setText('map-isp-detail', 'Awaiting results...');
        setText('map-isp-detail2', '');
        setText('map-isp-detail3', '');
        setAccentStatus('map-isp-accent', 'NotRun');
        return;
    }

    setText('map-isp-detail', isp.resultValue || '');

    const asInfo = extractLine(isp.detailedInfo, 'AS:');
    setText('map-isp-detail2', asInfo);

    // Show egress city from GeoIP
    const userLoc = lookup['B-LE-01'];
    const egressCity = userLoc ? userLoc.resultValue : '';
    setText('map-isp-detail3', egressCity ? `📍 ${addFlag(egressCity)}` : '');

    setAccentStatus('map-isp-accent', isp.status);
}

// ── AFD Edge Card ──
function updateMapAfdCard(lookup) {
    const reach = lookup['L-TCP-04'] || lookup['B-TCP-02'];
    const latency = lookup['B-TCP-02'];
    const gwUsed = lookup['L-TCP-09'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';

    if (reach && reach.status !== 'NotRun') {
        status = reach.status;
        detail1 = reach.status === 'Passed' ? '✓ HTTPS reachable' : reach.resultValue || 'Unreachable';
    }

    // Extract route type from L-TCP-09
    if (gwUsed && gwUsed.detailedInfo) {
        const route = extractLine(gwUsed.detailedInfo, 'Route:');
        if (route) detail1 = `✓ Via ${route}`;

        // Show location as a badge
        const locLine = extractGatewayLocation(gwUsed.detailedInfo);
        if (locLine) {
            setBadge('map-afd-loc-badge', `📍 ${addFlag(locLine)}`, 'location-badge');
        }
    }

    setText('map-afd-detail', detail1);

    // Latency badge
    if (latency && latency.resultValue) {
        const match = latency.resultValue.match(/(\d+)\s*ms/);
        if (match) {
            const ms = parseInt(match[1]);
            setBadge('map-afd-badge', `⏱ ${ms}ms`, latencyClass(ms, true));
        }
    }

    setAccentStatus('map-afd-accent', status);
}

// ── RD Gateway Card ──
function updateMapRdGwCard(lookup) {
    const tcpPorts = lookup['L-TCP-04'];
    const latency = lookup['B-TCP-02'];
    const gwUsed = lookup['L-TCP-09'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';

    if (tcpPorts && tcpPorts.status !== 'NotRun' && tcpPorts.status !== 'Pending') {
        status = tcpPorts.status;
        detail1 = tcpPorts.resultValue || '';
    } else if (latency && latency.status !== 'NotRun') {
        status = latency.status;
        detail1 = latency.status === 'Passed' ? '✓ Gateway reachable' : latency.resultValue || '';
    }

    // Show gateway location + proximity as badges from L-TCP-09
    if (gwUsed && gwUsed.detailedInfo) {
        const locInfo = extractGatewayLocationWithProximity(gwUsed.detailedInfo);
        if (locInfo.location) {
            setBadge('map-rdgw-loc-badge', `📍 ${addFlag(locInfo.location)}`, 'location-badge');
        }
        if (locInfo.proximity) {
            if (locInfo.proximity.includes('✔') || locInfo.proximity.includes('Near')) {
                setBadge('map-rdgw-prox-badge', '✔ Near', 'proximity-near');
            } else if (locInfo.proximity.includes('⚠') || locInfo.proximity.includes('Far')) {
                setBadge('map-rdgw-prox-badge', '⚠ Far', 'proximity-far');
            } else if (locInfo.proximity.includes('≈') || locInfo.proximity.includes('Moderate')) {
                setBadge('map-rdgw-prox-badge', '≈ Moderate', 'proximity-moderate');
            }
        }
    }

    if (latency && latency.resultValue) {
        const match = latency.resultValue.match(/(\d+)\s*ms/);
        if (match) {
            const ms = parseInt(match[1]);
            setBadge('map-rdgw-badge', `⏱ ${ms}ms`, latencyClass(ms, true));
        }
    }

    setText('map-rdgw-detail', detail1);
    setAccentStatus('map-rdgw-accent', status);
}

// ── TURN Relay Card ──
function updateMapTurnCard(lookup) {
    const stunTest = lookup['B-UDP-01'];
    const turnReach = lookup['L-UDP-03'];
    const turnLoc = lookup['L-UDP-04'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';

    if (turnReach && turnReach.status !== 'NotRun' && turnReach.status !== 'Pending') {
        status = turnReach.status;
        if (turnReach.status === 'Passed') {
            detail1 = '✓ Reachable (UDP 3478)';
        } else {
            detail1 = '✗ Unreachable (UDP 3478)';
        }
    } else if (stunTest && stunTest.status !== 'NotRun') {
        detail1 = stunTest.status === 'Passed' ? '✓ STUN OK' : stunTest.resultValue || '';
        status = stunTest.status;
    }

    // Location badge from L-UDP-04
    if (turnLoc && turnLoc.status !== 'NotRun' && turnLoc.status !== 'Pending') {
        const locMatch = (turnLoc.resultValue || '').match(/TURN relay:\s*(.+?)\s*\(/);
        const city = locMatch ? locMatch[1] : '';
        if (city) {
            setBadge('map-turn-loc-badge', `📍 ${addFlag(city)}`, 'location-badge');
        }
        status = worstStatus(status, turnLoc.status);
    }

    // Reachability badge
    if (turnReach && turnReach.status !== 'NotRun' && turnReach.status !== 'Pending') {
        if (turnReach.status === 'Passed') {
            setBadge('map-turn-badge', '✓ Reachable', 'status-ok');
        } else {
            setBadge('map-turn-badge', '✗ Unreachable', 'status-fail');
        }
    }

    setText('map-turn-detail', detail1);
    setAccentStatus('map-turn-accent', status);
}

// ── DNS Card ──
function updateMapDnsCard(lookup) {
    const dnsPerf = lookup['B-TCP-03'];
    const dnsCname = lookup['L-TCP-05'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';
    let detail2 = '';

    if (dnsPerf && dnsPerf.status !== 'NotRun') {
        status = dnsPerf.status;
        detail1 = dnsPerf.resultValue || '';

        // Extract avg latency for badge
        const match = (dnsPerf.resultValue || '').match(/(\d+)\s*ms/);
        if (match) {
            const ms = parseInt(match[1]);
            setBadge('map-dns-badge', `⏱ ${ms}ms`, latencyClass(ms, true));
        }
    }

    if (dnsCname && dnsCname.status !== 'NotRun' && dnsCname.status !== 'Pending') {
        detail2 = dnsCname.resultValue || '';
        status = worstStatus(status, dnsCname.status);
    }

    setText('map-dns-detail', detail1);
    setText('map-dns-detail2', detail2);
    setAccentStatus('map-dns-accent', status);
}

// ── Helper: extract location from gateway detailedInfo ──
function extractGatewayLocation(detailedInfo) {
    if (!detailedInfo) return '';
    const match = detailedInfo.match(/Location:\s*([^\n\r]+)/i);
    if (!match) return '';
    // Strip proximity suffix (everything after ✔/≈/⚠)
    return match[1].replace(/\s*[✔≈⚠].*/g, '').trim();
}

function extractGatewayLocationWithProximity(detailedInfo) {
    if (!detailedInfo) return { location: '', proximity: '' };
    const match = detailedInfo.match(/Location:\s*([^\n\r]+)/i);
    if (!match) return { location: '', proximity: '' };
    const full = match[1].trim();
    // Split at proximity indicator
    const proxMatch = full.match(/(.+?)\s+([✔≈⚠].+)/);
    if (proxMatch) return { location: proxMatch[1].trim(), proximity: proxMatch[2].trim() };
    return { location: full, proximity: '' };
}

// ── Security Status Bar ──
function updateMapSecurityBar(lookup) {
    const tls = lookup['L-TCP-06'];
    const proxy = lookup['L-TCP-07'];
    const dns = lookup['L-TCP-08'];
    const gwUsed = lookup['L-TCP-09'];
    const bar = document.getElementById('map-security-bar');

    // Helper: update a single security badge
    function updateSecBadge(id, test, labels) {
        const badge = document.getElementById(id);
        const icon = document.getElementById(id + '-icon');
        const text = document.getElementById(id + '-text');
        if (!badge || !icon || !text) return;

        if (test && test.status !== 'NotRun' && test.status !== 'Pending') {
            if (test.status === 'Passed') {
                icon.textContent = '✓';
                text.textContent = labels.pass;
                badge.className = 'security-badge';
            } else {
                icon.textContent = '✗';
                text.textContent = labels.fail;
                badge.className = 'security-badge ' + (test.status === 'Failed' ? 'fail' : 'warn');
            }
        } else {
            icon.textContent = '·';
            text.textContent = labels.pending;
            badge.className = 'security-badge pending';
        }
    }

    updateSecBadge('sec-tls-badge', tls, {
        pass: 'No TLS Inspection',
        fail: 'TLS Inspection Detected',
        pending: 'TLS Inspection'
    });

    updateSecBadge('sec-dns-badge', dns, {
        pass: 'No DNS Hijacking',
        fail: 'DNS Hijacking Detected',
        pending: 'DNS Hijacking'
    });

    updateSecBadge('sec-proxy-badge', proxy, {
        pass: 'No VPN / SWG / Proxy',
        fail: proxy ? (proxy.resultValue || 'VPN/SWG/Proxy Detected') : '',
        pending: 'VPN / SWG / Proxy'
    });

    // Gateway proximity badge
    const gwBadge = document.getElementById('sec-gw-badge');
    const gwIcon = document.getElementById('sec-gw-badge-icon');
    const gwText = document.getElementById('sec-gw-badge-text');
    if (gwBadge && gwIcon && gwText) {
        if (gwUsed && gwUsed.status !== 'NotRun' && gwUsed.status !== 'Pending') {
            const info = extractGatewayLocationWithProximity(gwUsed.detailedInfo);
            if (info.proximity && (info.proximity.includes('✔') || info.proximity.includes('Near'))) {
                gwIcon.textContent = '✓';
                gwText.textContent = 'Gateway Near You';
                gwBadge.className = 'security-badge';
            } else if (info.proximity && (info.proximity.includes('⚠') || info.proximity.includes('Far'))) {
                gwIcon.textContent = '✗';
                gwText.textContent = 'Gateway Far Away';
                gwBadge.className = 'security-badge warn';
            } else if (info.proximity) {
                gwIcon.textContent = '≈';
                gwText.textContent = 'Gateway Moderate Distance';
                gwBadge.className = 'security-badge warn';
            } else if (info.location) {
                gwIcon.textContent = '✓';
                gwText.textContent = `Gateway: ${info.location}`;
                gwBadge.className = 'security-badge';
            } else {
                gwIcon.textContent = '·';
                gwText.textContent = 'Gateway Proximity';
                gwBadge.className = 'security-badge pending';
            }
        } else {
            gwIcon.textContent = '·';
            gwText.textContent = 'Gateway Proximity';
            gwBadge.className = 'security-badge pending';
        }
    }

    // Overall bar background — any warning/fail?
    const checks = [tls, proxy, dns];
    const anyBad = checks.some(t => t && t.status !== 'Passed' && t.status !== 'NotRun' && t.status !== 'Pending' && t.status !== 'Skipped');
    if (bar) {
        bar.className = 'map-security-bar' + (anyBad ? ' has-warning' : '');
    }
}
