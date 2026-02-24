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

/**
 * Extract a 2-letter ISO country code from a location string like "London, GB"
 * or "Marseille, Provence, FR (51.5.67.23)".
 * Returns lowercase code (e.g. "gb") for use with flag CDN, or '' if not found.
 */
function extractCountryCode(locationStr) {
    if (!locationStr) return '';
    // Try to find a standalone 2-letter code: ", XX" at end or ", XX (" before parenthetical
    const m = locationStr.match(/,\s*([A-Z]{2})\s*(?:\(|$)/);
    if (m) return m[1].toLowerCase();
    // Fallback: last CSV part is exactly 2 uppercase letters
    const parts = locationStr.split(',');
    if (parts.length < 2) return '';
    const last = parts[parts.length - 1].trim();
    if (/^[A-Z]{2}$/.test(last)) return last.toLowerCase();
    return '';
}

/**
 * Azure region friendly names → ISO country codes.
 * Shared by both map.js and app.js for flag resolution.
 */
const AZURE_REGION_TO_COUNTRY = {
    'uk south':'gb','uk west':'gb',
    'north europe':'ie','west europe':'nl',
    'france central':'fr','france south':'fr',
    'germany west central':'de','germany north':'de',
    'norway east':'no','norway west':'no',
    'sweden central':'se','sweden south':'se',
    'switzerland north':'ch','switzerland west':'ch',
    'italy north':'it','spain central':'es','poland central':'pl',
    'east us':'us','east us 2':'us','east us 2 euap':'us',
    'central us':'us','north central us':'us','south central us':'us',
    'west central us':'us','west us':'us','west us 2':'us','west us 3':'us',
    'canada central':'ca','canada east':'ca','mexico central':'mx',
    'chile central':'cl','brazil south':'br',
    'southeast asia':'sg','east asia':'hk',
    'japan east':'jp','japan west':'jp',
    'korea central':'kr','korea south':'kr',
    'central india':'in','south india':'in','west india':'in',
    'jio india west':'in',
    'australia east':'au','australia southeast':'au','australia central':'au',
    'taiwan north':'tw','taiwan northwest':'tw',
    'new zealand north':'nz',
    'south africa north':'za','south africa west':'za',
    'uae north':'ae','uae central':'ae','israel central':'il',
    'qatar central':'qa'
};

/** AFD PoP 3-letter airport codes → ISO country codes */
const AFD_POP_TO_COUNTRY = {
    'LHR':'gb','MAN':'gb','DUB':'ie',
    'AMS':'nl','FRA':'de','PAR':'fr','MAD':'es','MIL':'it','ZRH':'ch',
    'VIE':'at','CPH':'dk','HEL':'fi','OSL':'no','STO':'se','WAW':'pl',
    'BUD':'hu','PRG':'cz','BER':'de','MRS':'fr','LIS':'pt','ATH':'gr',
    'SOF':'bg','BUH':'ro','ZAG':'hr','BEG':'rs','BTS':'sk',
    'IAD':'us','JFK':'us','EWR':'us','ATL':'us','MIA':'us','ORD':'us',
    'DFW':'us','LAX':'us','SJC':'us','SEA':'us','DEN':'us','PHX':'us',
    'SLC':'us','MSP':'us','BOS':'us','CLT':'us','HOU':'us','QRO':'mx',
    'YYZ':'ca','YUL':'ca','YVR':'ca',
    'SIN':'sg','HKG':'hk','NRT':'jp','KIX':'jp','ICN':'kr',
    'BOM':'in','MAA':'in','DEL':'in','BLR':'in','HYD':'in',
    'KUL':'my','BKK':'th','CGK':'id','MNL':'ph','TPE':'tw',
    'SYD':'au','MEL':'au','PER':'au','AKL':'nz',
    'DXB':'ae','AUH':'ae','DOH':'qa','JNB':'za','CPT':'za','NBO':'ke',
    'GRU':'br','GIG':'br','SCL':'cl','BOG':'co','EZE':'ar','LIM':'pe'
};

/**
 * Resolve a country code from any location string format:
 *   1. ", XX" suffix (GeoIP: "Cardiff, GB")
 *   2. AFD PoP airport code ("LHR — London", "London (LHR)", "LHR")
 *   3. Azure region friendly name ("UK South", "UK South (uksouth)")
 *   4. Prefixed strings ("TURN relay: UK South (uksouth) (51.5.x.x)")
 * Returns lowercase 2-letter code or ''.
 */
function resolveCountryCode(locationStr) {
    if (!locationStr) return '';
    // 1. Standard ", XX" country code
    const cc = extractCountryCode(locationStr);
    if (cc) return cc;
    // 2. AFD PoP code: "(LHR)" or "LHR — City" or bare "LHR"
    const parenMatch = locationStr.match(/\(([A-Z]{3})\)/);
    if (parenMatch && AFD_POP_TO_COUNTRY[parenMatch[1]]) return AFD_POP_TO_COUNTRY[parenMatch[1]];
    const dashMatch = locationStr.match(/^([A-Z]{3})\s*[—–-]\s*/);
    if (dashMatch && AFD_POP_TO_COUNTRY[dashMatch[1]]) return AFD_POP_TO_COUNTRY[dashMatch[1]];
    const bare = locationStr.trim();
    if (/^[A-Z]{3}$/.test(bare) && AFD_POP_TO_COUNTRY[bare]) return AFD_POP_TO_COUNTRY[bare];
    // 3. Strip common prefixes and trailing IPs
    let clean = locationStr.replace(/^(?:TURN relay|RDP Gateway|Gateway|AFD Edge|AFD PoP):\s*/i, '').trim();
    clean = clean.replace(/\s*\([\d.]+\)\s*$/, '').trim();
    const lower = clean.toLowerCase();
    if (AZURE_REGION_TO_COUNTRY[lower]) return AZURE_REGION_TO_COUNTRY[lower];
    // 4. Partial match — string starts with a known region name
    for (const [region, code] of Object.entries(AZURE_REGION_TO_COUNTRY)) {
        if (lower.startsWith(region)) return code;
    }
    return '';
}

/**
 * Create a small flag <img> element for a 2-letter country code.
 * Uses flagcdn.com (free, no key required, CDN-backed).
 */
function createFlagImg(code) {
    if (!code) return null;
    const img = document.createElement('img');
    img.src = `https://flagcdn.com/20x15/${code}.png`;
    img.alt = code.toUpperCase();
    img.width = 20;
    img.height = 15;
    img.className = 'country-flag';
    img.onerror = function() { this.style.display = 'none'; };
    return img;
}

/**
 * Set text on an element, prepending a country flag image if a 2-letter code is found.
 */
function setFlaggedText(elementId, text) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = '';
    const code = resolveCountryCode(text);
    if (code) {
        const flag = createFlagImg(code);
        if (flag) el.appendChild(flag);
        el.appendChild(document.createTextNode(' ' + text));
    } else {
        el.textContent = text || '';
    }
}

/**
 * Set badge content with optional country flag image.
 */
function setFlaggedBadge(elementId, text, cssClass, locationStr) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (!text) {
        el.classList.add('hidden');
        return;
    }
    el.textContent = '';
    el.className = 'map-card-badge ' + cssClass;
    const code = resolveCountryCode(locationStr || text);
    if (code) {
        const flag = createFlagImg(code);
        if (flag) el.appendChild(flag);
        el.appendChild(document.createTextNode(' ' + text.replace('📍 ', '')));
    } else {
        el.textContent = text;
    }
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

    setFlaggedText('map-client-location', location || 'Awaiting results...');
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
    setFlaggedText('map-isp-detail3', egressCity ? `📍 ${egressCity}` : '');

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
        if (route) {
            const isPrivateLink = route.toLowerCase().includes('private');
            const isAfd = route.toLowerCase().includes('front door') || route.toLowerCase().includes('afd');
            const routeClass = isPrivateLink ? 'route-privatelink' : isAfd ? 'route-afd' : 'route-direct';
            const icon = isPrivateLink ? '🔒' : isAfd ? '⚡' : '🔗';
            setBadge('map-afd-route-badge', `${icon} ${route}`, routeClass);
        }

        // Show location as a badge — prefer AFD PoP (from X-MSEdge-Ref) over GeoIP Location
        const popLine = extractLine(gwUsed.detailedInfo, 'AFD PoP:');
        const locLine = (popLine && !popLine.toLowerCase().includes('could not parse'))
            ? popLine.replace(/^[A-Z]{2,5}\s*—\s*/, '')   // strip PoP code prefix e.g. "LHR — "
            : extractGatewayLocation(gwUsed.detailedInfo);
        if (locLine) {
            setFlaggedBadge('map-afd-loc-badge', `📍 ${locLine}`, 'location-badge', locLine);
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
    // Use rdweb/client location (not the AFD anycast IP which GeoIP maps to Redmond)
    if (gwUsed && gwUsed.detailedInfo) {
        const locInfo = extractRdGwLocationWithProximity(gwUsed.detailedInfo);
        if (locInfo.location) {
            setFlaggedBadge('map-rdgw-loc-badge', `📍 ${locInfo.location}`, 'location-badge', locInfo.location);
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

    // Location badge from L-UDP-04 (scanner)
    if (turnLoc && turnLoc.status !== 'NotRun' && turnLoc.status !== 'Pending') {
        const locMatch = (turnLoc.resultValue || '').match(/TURN relay:\s*(.+?)\s*\(/);
        const city = locMatch ? locMatch[1] : '';
        if (city) {
            setFlaggedBadge('map-turn-loc-badge', `📍 ${city}`, 'location-badge', city);
        }
        status = worstStatus(status, turnLoc.status);
    } else if (stunTest && stunTest.status === 'Passed') {
        // No scanner data — do a browser-based relay geolocation via DoH + GeoIP
        geolocateTurnRelay();
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

/**
 * Browser-based TURN relay geolocation: resolves world.relay.avd.microsoft.com
 * via DoH, then uses Azure Service Tags subnet mapping for region (authoritative),
 * falling back to ipinfo.io geolocation.
 * Only called when scanner L-UDP-04 data is not available.
 */
let _turnGeoRunning = false;
async function geolocateTurnRelay() {
    if (_turnGeoRunning) return;
    _turnGeoRunning = true;
    try {
        // Step 1: Resolve TURN relay IP via Google DoH
        const dnsResp = await fetch(
            'https://dns.google/resolve?name=world.relay.avd.microsoft.com&type=A',
            { signal: AbortSignal.timeout(5000), cache: 'no-store' }
        );
        if (!dnsResp.ok) return;
        const dnsData = await dnsResp.json();
        const aRecord = dnsData.Answer?.find(r => r.type === 1);
        if (!aRecord) return;
        const relayIp = aRecord.data;

        // Step 2a: Try Azure Service Tags lookup (authoritative, no external call needed)
        const azureRegion = (typeof lookupTurnRelayRegion === 'function') ? lookupTurnRelayRegion(relayIp) : null;
        if (azureRegion) {
            const friendly = (typeof getAzureRegionFriendlyName === 'function') ? getAzureRegionFriendlyName(azureRegion) : null;
            const label = friendly ? `${friendly} (${azureRegion})` : azureRegion;
            setFlaggedBadge('map-turn-loc-badge', `📍 ${label}`, 'location-badge', label);
            return;
        }

        // Step 2b: Fallback to GeoIP for IPs outside known Service Tags subnets
        const geoResp = await fetch(
            `https://ipinfo.io/${relayIp}/json`,
            { signal: AbortSignal.timeout(5000), cache: 'no-store' }
        );
        if (!geoResp.ok) return;
        const geo = await geoResp.json();
        if (!geo.city) return;

        const locStr = `${geo.city}, ${geo.region || ''}, ${geo.country || ''}`.replace(/, ,/g, ',');
        setFlaggedBadge('map-turn-loc-badge', `📍 ${locStr}`, 'location-badge', locStr);
    } catch { /* best-effort */ }
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
// L-TCP-09 detailedInfo contains multiple endpoint blocks. The first is the AFD
// endpoint (anycast — GeoIP is wrong), followed by rdweb/client (regional GW).
// extractGatewayLocation returns the first Location: line (AFD block).
// extractRdGwLocation skips the AFD block and returns the rdweb/client location.
function extractGatewayLocation(detailedInfo) {
    if (!detailedInfo) return '';
    const match = detailedInfo.match(/Location:\s*([^\n\r]+)/i);
    if (!match) return '';
    return match[1].replace(/\s*[✔≈⚠].*/g, '').trim();
}

function extractGatewayLocationWithProximity(detailedInfo) {
    if (!detailedInfo) return { location: '', proximity: '' };
    const match = detailedInfo.match(/Location:\s*([^\n\r]+)/i);
    if (!match) return { location: '', proximity: '' };
    const full = match[1].trim();
    const proxMatch = full.match(/(.+?)\s+([✔≈⚠].+)/);
    if (proxMatch) return { location: proxMatch[1].trim(), proximity: proxMatch[2].trim() };
    return { location: full, proximity: '' };
}

// Extract location for RD Gateway (rdweb/client endpoint, not AFD)
// Prefers authoritative "Location:" from Service Tags (e.g. "UK South") over GeoIP city names.
function extractRdGwLocationWithProximity(detailedInfo) {
    if (!detailedInfo) return { location: '', proximity: '' };

    // First check for Service Tags-sourced location in the RDP Gateway block
    // L-TCP-09 outputs "    Location: UK South" from Service Tags, and
    // "    GeoIP Location: Cardiff, GB" as supplementary. Prefer the non-GeoIP one.
    const gwBlock = detailedInfo.match(/═══ Actual RDP Gateway[\s\S]*?(?=═══|$)/i);
    if (gwBlock) {
        // Look for "Location:" that is NOT "GeoIP Location:"
        const stMatch = gwBlock[0].match(/^\s*Location:\s*([^\n\r]+)/m);
        if (stMatch && !stMatch[0].includes('GeoIP')) {
            const full = stMatch[1].trim();
            const proxMatch = full.match(/(.+?)\s+([✔≈⚠].+)/);
            if (proxMatch) return { location: proxMatch[1].trim(), proximity: proxMatch[2].trim() };
            return { location: full, proximity: '' };
        }
    }

    // Fallback: find all Location: lines — the 2nd+ are rdweb/client (regional gateway)
    const matches = [...detailedInfo.matchAll(/Location:\s*([^\n\r]+)/gi)];
    // Use the second match (rdweb) if available, otherwise fall back to first
    const locMatch = matches.length > 1 ? matches[1] : matches[0];
    if (!locMatch) return { location: '', proximity: '' };
    const full = locMatch[1].trim();
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
            const info = extractRdGwLocationWithProximity(gwUsed.detailedInfo);
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
