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

    setText('map-client-location', location || 'Awaiting results...');
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
    setText('map-isp-detail3', egressCity ? `📍 ${egressCity}` : '');

    setAccentStatus('map-isp-accent', isp.status);
}

// ── AFD Edge Card ──
function updateMapAfdCard(lookup) {
    // Use Gateway HTTPS reachability and Gateway Latency browser tests
    const reach = lookup['B-TCP-01'];
    const latency = lookup['B-TCP-02'];
    const tlsInspect = lookup['L-TCP-06'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';
    let detail2 = '';

    if (reach && reach.status !== 'NotRun') {
        status = reach.status;
        detail1 = reach.status === 'Passed' ? '✓ HTTPS reachable' : reach.resultValue || 'Unreachable';
    }

    if (tlsInspect && tlsInspect.status === 'Warning') {
        detail2 = '⚠ TLS inspection detected';
        status = worstStatus(status, 'Warning');
    }

    setText('map-afd-detail', detail1);
    const d2El = document.getElementById('map-afd-detail2');
    if (d2El) {
        d2El.textContent = detail2;
        d2El.className = detail2 ? 'map-card-detail warning-text' : 'map-card-detail';
    }

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

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';
    let detail2 = '';

    if (tcpPorts && tcpPorts.status !== 'NotRun' && tcpPorts.status !== 'Pending') {
        status = tcpPorts.status;
        detail1 = tcpPorts.resultValue || '';
    } else if (latency && latency.status !== 'NotRun') {
        status = latency.status;
        detail1 = latency.status === 'Passed' ? '✓ Gateway reachable' : latency.resultValue || '';
    }

    if (latency && latency.resultValue) {
        detail2 = latency.resultValue;
        const match = latency.resultValue.match(/(\d+)\s*ms/);
        if (match) {
            const ms = parseInt(match[1]);
            setBadge('map-rdgw-badge', `⏱ ${ms}ms`, latencyClass(ms, true));
        }
    }

    setText('map-rdgw-detail', detail1);
    setText('map-rdgw-detail2', detail2);
    setAccentStatus('map-rdgw-accent', status);
}

// ── TURN Relay Card ──
function updateMapTurnCard(lookup) {
    const stunTest = lookup['B-UDP-01'];
    const turnReach = lookup['L-UDP-03'];
    const turnLoc = lookup['L-UDP-04'];

    let status = 'NotRun';
    let detail1 = 'Awaiting results...';
    let detail2 = '';

    if (turnLoc && turnLoc.status !== 'NotRun' && turnLoc.status !== 'Pending') {
        detail1 = turnLoc.resultValue || '';
        status = turnLoc.status;
    } else if (stunTest && stunTest.status !== 'NotRun') {
        detail1 = stunTest.resultValue || '';
        status = stunTest.status;
    }

    if (turnReach && turnReach.status !== 'NotRun' && turnReach.status !== 'Pending') {
        status = worstStatus(status, turnReach.status);
        if (turnReach.status === 'Passed') {
            detail2 = '✓ Reachable (UDP 3478)';
            setBadge('map-turn-badge', '✓ Reachable', 'status-ok');
        } else {
            detail2 = '✗ Unreachable (UDP 3478)';
            setBadge('map-turn-badge', '✗ Unreachable', 'status-fail');
        }
    } else if (stunTest && stunTest.status !== 'NotRun') {
        detail2 = stunTest.status === 'Passed' ? '✓ STUN OK' : stunTest.resultValue || '';
    }

    setText('map-turn-detail', detail1);
    setText('map-turn-detail2', detail2);
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

// ── Security Status Bar ──
function updateMapSecurityBar(lookup) {
    const tls = lookup['L-TCP-06'];
    const proxy = lookup['L-TCP-07'];
    const bar = document.getElementById('map-security-bar');

    // TLS badge
    const tlsBadge = document.getElementById('sec-tls-badge');
    const tlsIcon = document.getElementById('sec-tls-icon');
    const tlsText = document.getElementById('sec-tls-text');

    if (tls && tls.status !== 'NotRun' && tls.status !== 'Pending') {
        if (tls.status === 'Passed') {
            tlsIcon.textContent = '🛡';
            tlsText.textContent = 'TLS: No inspection detected';
            tlsBadge.className = 'security-badge';
        } else {
            tlsIcon.textContent = '⚠';
            tlsText.textContent = 'TLS INSPECTION DETECTED';
            tlsBadge.className = 'security-badge ' + (tls.status === 'Failed' ? 'fail' : 'warn');
        }
    } else {
        tlsIcon.textContent = '🛡';
        tlsText.textContent = 'TLS: Checking...';
        tlsBadge.className = 'security-badge pending';
    }

    // Proxy badge
    const proxyBadge = document.getElementById('sec-proxy-badge');
    const proxyIcon = document.getElementById('sec-proxy-icon');
    const proxyText = document.getElementById('sec-proxy-text');

    if (proxy && proxy.status !== 'NotRun' && proxy.status !== 'Pending') {
        if (proxy.status === 'Passed') {
            proxyIcon.textContent = '🛡';
            proxyText.textContent = 'VPN/SWG/Proxy: Not detected';
            proxyBadge.className = 'security-badge';
        } else {
            proxyIcon.textContent = '⚠';
            proxyText.textContent = proxy.resultValue || 'VPN/SWG/Proxy detected';
            proxyBadge.className = 'security-badge ' + (proxy.status === 'Failed' ? 'fail' : 'warn');
        }
    } else {
        proxyIcon.textContent = '🛡';
        proxyText.textContent = 'VPN/SWG/Proxy: Checking...';
        proxyBadge.className = 'security-badge pending';
    }

    // Overall bar background
    const anyBad = (tls && tls.status !== 'Passed' && tls.status !== 'NotRun' && tls.status !== 'Pending') ||
                   (proxy && proxy.status !== 'Passed' && proxy.status !== 'NotRun' && proxy.status !== 'Pending');
    if (bar) {
        bar.className = 'map-security-bar' + (anyBad ? ' has-warning' : '');
    }
}
