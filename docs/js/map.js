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
    updateMapLatencyLabels(lookup);

    // Cloud PC right-side cards — show when CPC mode active OR imported scanner data
    const isCpcMode = (typeof cloudPcMode !== 'undefined' && cloudPcMode);
    const hasImportedCpc = results.some(r => r.source === 'cloudpc' && r.id === 'C-NET-01');
    if (hasImportedCpc || isCpcMode) {
        const mapDiagram = document.querySelector('.map-diagram');
        if (mapDiagram) mapDiagram.classList.add('has-cloudpc');
        updateMapCloudPcCard(lookup);
        updateMapAzureCard(lookup);
    }
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
    'LHR':'gb','LTS':'gb','LON':'gb','MAN':'gb','EDG':'gb','DUB':'ie',
    'AMS':'nl','FRA':'de','BER':'de','MUC':'de','PAR':'fr','MRS':'fr',
    'MAD':'es','BCN':'es','MIL':'it','ROM':'it','ZRH':'ch','GVA':'ch',
    'VIE':'at','CPH':'dk','HEL':'fi','OSL':'no','STO':'se','WAW':'pl',
    'BUD':'hu','PRG':'cz','LIS':'pt','ATH':'gr','BRU':'be',
    'SOF':'bg','BUH':'ro','ZAG':'hr','BEG':'rs','BTS':'sk',
    'IAD':'us','DCA':'us','JFK':'us','EWR':'us','TEB':'us','ATL':'us','MIA':'us','ORD':'us',
    'DFW':'us','LAX':'us','SJC':'us','SEA':'us','DEN':'us','PHX':'us',
    'SLC':'us','MSP':'us','BOS':'us','CLT':'us','HOU':'us','PHL':'us','IAH':'us','QRO':'mx',
    'YYZ':'ca','YUL':'ca','YVR':'ca',
    'SIN':'sg','HKG':'hk','NRT':'jp','KIX':'jp','ICN':'kr',
    'BOM':'in','MAA':'in','DEL':'in','BLR':'in','HYD':'in',
    'KUL':'my','BKK':'th','CGK':'id','MNL':'ph','TPE':'tw',
    'SYD':'au','MEL':'au','PER':'au','BNE':'au','AKL':'nz',
    'DXB':'ae','AUH':'ae','FJR':'ae','DOH':'qa','BAH':'bh',
    'RUH':'sa','JED':'sa','TLV':'il',
    'JNB':'za','CPT':'za','NBO':'ke',
    'GRU':'br','GIG':'br','CWB':'br','SCL':'cl','BOG':'co','EZE':'ar','LIM':'pe'
};

/** Country code aliases — non-ISO codes that appear in GeoIP / scanner data */
const COUNTRY_CODE_ALIASES = { 'uk': 'gb' };

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
    const code = _resolveCountryCodeInner(locationStr);
    return COUNTRY_CODE_ALIASES[code] || code;
}

function _resolveCountryCodeInner(locationStr) {
    // 1. Standard ", XX" country code
    const cc = extractCountryCode(locationStr);
    if (cc) return cc;
    // 2. AFD PoP code: "(LHR)" or "LHR — City" or bare "LHR"
    const parenMatch = locationStr.match(/\(([A-Z]{3})\)/);
    if (parenMatch && AFD_POP_TO_COUNTRY[parenMatch[1]]) return AFD_POP_TO_COUNTRY[parenMatch[1]];
    const dashMatch = locationStr.match(/^([A-Z]{2,5})\s*[—–-]\s*/);
    if (dashMatch && AFD_POP_TO_COUNTRY[dashMatch[1]]) return AFD_POP_TO_COUNTRY[dashMatch[1]];
    const bare = locationStr.trim();
    if (/^[A-Z]{2,5}$/.test(bare) && AFD_POP_TO_COUNTRY[bare]) return AFD_POP_TO_COUNTRY[bare];
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
    // Support both map-card-accent and device-accent classes
    el.className = el.className.includes('device-accent') ? 'device-accent' : 'map-card-accent';
    if (status === 'Passed') el.classList.add('status-passed');
    else if (status === 'Warning') el.classList.add('status-warning');
    else if (status === 'Failed' || status === 'Error') el.classList.add('status-failed');
    else if (status === 'Running') el.classList.add('status-running');
}

function setDeviceDot(dotId, status) {
    const dot = document.getElementById(dotId);
    if (!dot) return;
    const color = status === 'Passed' ? '#3fb950'
        : status === 'Warning' ? '#d29922'
        : status === 'Failed' || status === 'Error' ? '#f85149'
        : status === 'Running' ? '#58a6ff'
        : '#484f58';
    dot.setAttribute('fill', color);
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
        if (ms < 100) return 'latency-good';
        if (ms < 200) return 'latency-medium';
        return 'latency-bad';
    }
    // UDP thresholds
    if (ms < 150) return 'latency-good';
    if (ms < 300) return 'latency-medium';
    return 'latency-bad';
}

/** Return a human-friendly health word for a latency value. */
function latencyLabel(ms, type) {
    if (type === 'gw') return ms < 20 ? 'Healthy' : ms < 50 ? 'Moderate' : 'Poor';
    if (type === 'udp') return ms < 150 ? 'Healthy' : ms < 300 ? 'Moderate' : 'Poor';
    if (type === 'dns') return ms < 80 ? 'Healthy' : ms < 200 ? 'Moderate' : 'Poor';
    // tcp default
    return ms < 100 ? 'Healthy' : ms < 200 ? 'Moderate' : 'Poor';
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

// ── OS Detection for client icon ──
function detectClientOS() {
    const ua = navigator.userAgent || '';
    const p = navigator.platform || '';
    if (/Mac/i.test(p) || /Mac/i.test(ua)) return 'mac';
    if (/Linux/i.test(p) && !/Android/i.test(ua)) return 'linux';
    return 'win'; // default Windows
}

function setClientOSIcon() {
    const os = detectClientOS();
    const win = document.getElementById('os-icon-win');
    const mac = document.getElementById('os-icon-mac');
    const linux = document.getElementById('os-icon-linux');
    if (win) win.style.display = os === 'win' ? '' : 'none';
    if (mac) mac.style.display = os === 'mac' ? '' : 'none';
    if (linux) linux.style.display = os === 'linux' ? '' : 'none';
    // Title stays as "Client (This device)" — OS shown via icon only
}

// Run OS detection immediately
setClientOSIcon();

// ── Client Card ──
function updateMapClientCard(lookup) {
    let location = '';
    let publicIp = '';
    let status = 'NotRun';

    const userLoc = lookup['B-LE-01'] || lookup['C-LE-01'];
    if (userLoc && userLoc.status !== 'NotRun') {
        location = userLoc.resultValue || '';
        status = userLoc.status;
        publicIp = extractLine(userLoc.detailedInfo, 'Public IP:');
    }

    setFlaggedText('map-client-location', location || 'Awaiting results...');
    setText('map-client-ip', publicIp ? `🌐 ${publicIp}` : '');
    setAccentStatus('map-client-accent', status);
    setDeviceDot('device-status-dot', status);
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
    setDeviceDot('device-gw-dot', gw.status);
}

// ── Well-known ISP domain map ──
const ISP_DOMAINS = {
    'cloudflare':'cloudflare.com','comcast':'comcast.com','xfinity':'comcast.com',
    'at&t':'att.com','att':'att.com','verizon':'verizon.com','spectrum':'spectrum.com',
    'charter':'spectrum.com','cox':'cox.com','t-mobile':'t-mobile.com','tmobile':'t-mobile.com',
    'sprint':'sprint.com','centurylink':'centurylink.com','lumen':'lumen.com',
    'frontier':'frontier.com','windstream':'windstream.com','mediacom':'mediacom.com',
    'optimum':'optimum.net','altice':'altice.com','suddenlink':'suddenlink.com',
    'google':'google.com','google fiber':'fiber.google.com','amazon':'amazon.com',
    'aws':'aws.amazon.com','microsoft':'microsoft.com','azure':'azure.microsoft.com',
    'akamai':'akamai.com','fastly':'fastly.com',
    'bt':'bt.com','british telecom':'bt.com','sky':'sky.com','sky broadband':'sky.com',
    'virgin media':'virginmedia.com','vodafone':'vodafone.com','talktalk':'talktalk.co.uk',
    'plusnet':'plus.net','ee':'ee.co.uk','three':'three.co.uk','o2':'o2.co.uk',
    'orange':'orange.com','free':'free.fr','sfr':'sfr.fr','bouygues':'bouyguestelecom.fr',
    'deutsche telekom':'telekom.de','telekom':'telekom.de','telefonica':'telefonica.com',
    'movistar':'movistar.com','swisscom':'swisscom.ch','proximus':'proximus.be',
    'kpn':'kpn.com','ziggo':'ziggo.nl','telia':'telia.com','telenor':'telenor.com',
    'telstra':'telstra.com.au','optus':'optus.com.au','tpg':'tpg.com.au','nbn':'nbnco.com.au',
    'bell':'bell.ca','rogers':'rogers.com','telus':'telus.com','shaw':'shaw.ca',
    'jio':'jio.com','airtel':'airtel.in','bsnl':'bsnl.co.in','vi':'myvi.in',
    'ntt':'ntt.com','softbank':'softbank.jp','kddi':'kddi.com','au':'au.com',
    'singtel':'singtel.com','starhub':'starhub.com',
    'china telecom':'chinatelecom.com.cn','china unicom':'chinaunicom.com',
    'china mobile':'chinamobile.com',
    'etisalat':'etisalat.ae','du':'du.ae','stc':'stc.com.sa','zain':'zain.com',
    'mtn':'mtn.com','safaricom':'safaricom.co.ke',
    'claro':'claro.com','telmex':'telmex.com','oi':'oi.com.br','vivo':'vivo.com.br',
    'cogent':'cogentco.com','hurricane electric':'he.net','level 3':'lumen.com',
    'zayo':'zayo.com','tata communications':'tatacommunications.com',
    'rackspace':'rackspace.com','digitalocean':'digitalocean.com','linode':'linode.com',
    'ovh':'ovh.com','hetzner':'hetzner.com','scaleway':'scaleway.com',
    'oracle':'oracle.com','ibm':'ibm.com','alibaba':'alibabacloud.com'
};

function guessIspDomain(ispName) {
    if (!ispName) return null;
    // Strip AS number prefix (e.g. "AS13335 Cloudflare, Inc." -> "Cloudflare, Inc.")
    const cleaned = ispName.replace(/^AS\d+\s*/i, '').replace(/[,.]\s*(Inc|LLC|Ltd|Corp|Co|SA|GmbH|AG|NV|BV|Pty|Plc)\.?$/i, '').trim();
    const lower = cleaned.toLowerCase();
    // Check known mapping
    for (const [key, domain] of Object.entries(ISP_DOMAINS)) {
        if (lower.includes(key)) return domain;
    }
    // Heuristic: turn name into domain guess (e.g. "Acme Telecom" -> "acmetelecom.com")
    const slug = lower.replace(/[^a-z0-9]/g, '');
    return slug ? slug + '.com' : null;
}

function setIspLogo(ispName) {
    const img = document.getElementById('isp-logo-img');
    if (!img) return;
    const domain = guessIspDomain(ispName);
    if (!domain) { img.style.display = 'none'; return; }
    // Use Clearbit Logo API (returns 128px square logo)
    const url = `https://logo.clearbit.com/${domain}?size=80`;
    img.src = url;
    img.style.display = 'block';
    img.onerror = function() {
        // Fallback to Google favicons
        this.src = `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
        this.onerror = function() { this.style.display = 'none'; };
    };
}

// ── ISP Card ──
function updateMapIspCard(lookup) {
    const isp = lookup['B-LE-02'] || lookup['C-LE-02'];
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
    const userLoc = lookup['B-LE-01'] || lookup['C-LE-01'];
    const egressCity = userLoc ? userLoc.resultValue : '';
    setFlaggedText('map-isp-detail3', egressCity ? `📍 ${egressCity}` : '');

    setAccentStatus('map-isp-accent', isp.status);
    setDeviceDot('device-isp-dot', isp.status);
    setIspLogo(isp.resultValue);
}

// ── AFD Edge Card ──
function updateMapAfdCard(lookup) {
    const reach = lookup['L-TCP-04'] || lookup['B-TCP-02'] || lookup['C-TCP-04'];
    const latency = lookup['B-TCP-02'] || lookup['C-TCP-04'];
    const gwUsed = lookup['L-TCP-09'] || lookup['C-TCP-09'];

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
            const health = latencyLabel(ms, 'tcp');
            setBadge('map-afd-badge', `⏱ ${ms}ms · ${health}`, latencyClass(ms, true));
        }
    }

    setAccentStatus('map-afd-accent', status);
}

// ── RD Gateway Card ──
function updateMapRdGwCard(lookup) {
    const tcpPorts = lookup['L-TCP-04'];
    const latency = lookup['B-TCP-02'] || lookup['C-TCP-04'];
    const gwUsed = lookup['L-TCP-09'] || lookup['C-TCP-09'];

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
            const health = latencyLabel(ms, 'tcp');
            setBadge('map-rdgw-badge', `⏱ ${ms}ms · ${health}`, latencyClass(ms, true));
        }
    }

    setText('map-rdgw-detail', detail1);
    setAccentStatus('map-rdgw-accent', status);
}

// ── TURN Relay Card ──
function updateMapTurnCard(lookup) {
    const stunTest = lookup['B-UDP-01'] || lookup['C-UDP-03'];
    const turnReach = lookup['L-UDP-03'];
    const turnLoc = lookup['L-UDP-04'] || lookup['C-UDP-04'];

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
    const dnsPerf = lookup['B-TCP-03'] || lookup['C-TCP-05'];
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
            const health = latencyLabel(ms, 'dns');
            setBadge('map-dns-badge', `⏱ ${ms}ms · ${health}`, latencyClass(ms, true));
        }
    }

    if (dnsCname && dnsCname.status !== 'NotRun' && dnsCname.status !== 'Pending') {
        detail2 = dnsCname.resultValue || '';
        status = worstStatus(status, dnsCname.status);
    }

    setText('map-dns-detail', detail1);
    setText('map-dns-detail2', detail2);
    setAccentStatus('map-dns-accent', status);
    setDeviceDot('device-dns-dot', status);
}
function updateMapLatencyLabels(lookup) {
    function setLL(id, ms, type) {
        const el = document.getElementById(id);
        if (!el) return;
        if (ms == null || isNaN(ms)) { el.textContent = ''; return; }
        const msText = ms < 1 ? '<1ms' : ms + 'ms';
        const health = latencyLabel(ms, type);
        el.textContent = `${msText} · ${health}`;
        el.classList.remove('lat-good', 'lat-warn', 'lat-bad');
        el.classList.add(latencyClassLine(ms, type));
    }

    // Local GW: L-LE-05 "Gateway X.X.X.X: avg Nms"
    const gw05 = lookup['L-LE-05'];
    let gwMs = null;
    if (gw05 && gw05.resultValue) {
        const m = gw05.resultValue.match(/avg\s+(\d+)ms/);
        if (m) gwMs = parseInt(m[1]);
    }
    setLL('map-lat-gw', gwMs, 'gw');

    // AFD Edge: B-TCP-02 "Latency: avg Nms" or resultValue "— Nms"
    const afd02 = lookup['B-TCP-02'] || lookup['C-TCP-04'];
    let afdMs = null;
    if (afd02 && afd02.detailedInfo) {
        const latLine = afd02.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
        if (latLine) {
            const m = latLine.match(/avg\s+(\d+)ms/);
            if (m) afdMs = parseInt(m[1]);
        }
    }
    if (afdMs == null && afd02 && afd02.resultValue) {
        const m = afd02.resultValue.match(/(\d+)\s*ms/);
        if (m) afdMs = parseInt(m[1]);
    }
    setLL('map-lat-afd', afdMs, 'tcp');

    // RD Gateway: L-TCP-04 "[RDP Gateway]" → "TCP connected in Nms"
    const tcp04 = lookup['L-TCP-04'];
    let rdgwMs = null;
    if (tcp04 && tcp04.detailedInfo) {
        const lines = tcp04.detailedInfo.split('\n');
        const gwIdx = lines.findIndex(l => l.includes('[RDP Gateway]'));
        if (gwIdx >= 0) {
            for (let i = gwIdx; i < Math.min(gwIdx + 5, lines.length); i++) {
                const m = lines[i].match(/TCP connected in (\d+)ms/);
                if (m) { rdgwMs = parseInt(m[1]); break; }
            }
        }
    }
    setLL('map-lat-rdgw', rdgwMs, 'tcp');

    // TURN Relay: L-UDP-03 "Latency: Nms" or resultValue "Nms RTT"
    const turn03 = lookup['L-UDP-03'];
    let turnMs = null;
    if (turn03 && turn03.detailedInfo) {
        const latLine = turn03.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
        if (latLine) {
            const m = latLine.match(/(\d+)\s*ms/);
            if (m) turnMs = parseInt(m[1]);
        }
    }
    if (turnMs == null && turn03 && turn03.resultValue) {
        const m = turn03.resultValue.match(/(\d+)\s*ms/);
        if (m) turnMs = parseInt(m[1]);
    }
    setLL('map-lat-turn', turnMs, 'udp');
}

function latencyClassLine(ms, type) {
    if (type === 'gw') return ms < 20 ? 'lat-good' : ms < 50 ? 'lat-warn' : 'lat-bad';
    if (type === 'udp') return ms < 150 ? 'lat-good' : ms < 300 ? 'lat-warn' : 'lat-bad';
    return ms < 100 ? 'lat-good' : ms < 200 ? 'lat-warn' : 'lat-bad';
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

// ═══════════════════════════════════════════════════════════
//  Azure region inference from geo-IP coordinates
// ═══════════════════════════════════════════════════════════
const AZURE_REGIONS = [
    { name: 'UK South',             code: 'uksouth',             lat: 51.51, lon: -0.13 },
    { name: 'UK West',              code: 'ukwest',              lat: 51.48, lon: -3.18 },
    { name: 'North Europe',         code: 'northeurope',         lat: 53.35, lon: -6.26 },
    { name: 'West Europe',          code: 'westeurope',          lat: 52.37, lon:  4.89 },
    { name: 'France Central',       code: 'francecentral',       lat: 48.86, lon:  2.35 },
    { name: 'France South',         code: 'francesouth',         lat: 43.30, lon:  5.37 },
    { name: 'Germany West Central', code: 'germanywestcentral',  lat: 50.11, lon:  8.68 },
    { name: 'Switzerland North',    code: 'switzerlandnorth',    lat: 47.38, lon:  8.54 },
    { name: 'Switzerland West',     code: 'switzerlandwest',     lat: 46.20, lon:  6.14 },
    { name: 'Norway East',          code: 'norwayeast',          lat: 59.91, lon: 10.75 },
    { name: 'Sweden Central',       code: 'swedencentral',       lat: 60.67, lon: 17.14 },
    { name: 'Italy North',          code: 'italynorth',          lat: 45.46, lon:  9.19 },
    { name: 'Poland Central',       code: 'polandcentral',       lat: 52.23, lon: 21.01 },
    { name: 'Spain Central',        code: 'spaincentral',        lat: 40.42, lon: -3.70 },
    { name: 'East US',              code: 'eastus',              lat: 37.43, lon:-79.07 },
    { name: 'East US 2',            code: 'eastus2',             lat: 36.68, lon:-78.17 },
    { name: 'Central US',           code: 'centralus',           lat: 41.88, lon:-93.10 },
    { name: 'North Central US',     code: 'northcentralus',      lat: 41.88, lon:-87.63 },
    { name: 'South Central US',     code: 'southcentralus',      lat: 29.42, lon:-98.49 },
    { name: 'West US',              code: 'westus',              lat: 37.78, lon:-122.42 },
    { name: 'West US 2',            code: 'westus2',             lat: 47.23, lon:-119.85 },
    { name: 'West US 3',            code: 'westus3',             lat: 33.45, lon:-112.07 },
    { name: 'Canada Central',       code: 'canadacentral',       lat: 43.65, lon:-79.38 },
    { name: 'Canada East',          code: 'canadaeast',          lat: 46.82, lon:-71.22 },
    { name: 'Brazil South',         code: 'brazilsouth',         lat:-23.55, lon:-46.63 },
    { name: 'East Asia',            code: 'eastasia',            lat: 22.40, lon: 114.11 },
    { name: 'Southeast Asia',       code: 'southeastasia',       lat:  1.35, lon: 103.82 },
    { name: 'Japan East',           code: 'japaneast',           lat: 35.69, lon: 139.69 },
    { name: 'Japan West',           code: 'japanwest',           lat: 34.69, lon: 135.50 },
    { name: 'Korea Central',        code: 'koreacentral',        lat: 37.57, lon: 126.98 },
    { name: 'Korea South',          code: 'koreasouth',          lat: 35.18, lon: 129.08 },
    { name: 'Central India',        code: 'centralindia',        lat: 18.52, lon:  73.86 },
    { name: 'South India',          code: 'southindia',          lat: 13.08, lon:  80.27 },
    { name: 'West India',           code: 'westindia',           lat: 19.08, lon:  72.88 },
    { name: 'Australia East',       code: 'australiaeast',       lat:-33.87, lon: 151.21 },
    { name: 'Australia Southeast',  code: 'australiasoutheast',  lat:-37.81, lon: 144.96 },
    { name: 'Australia Central',    code: 'australiacentral',    lat:-35.28, lon: 149.13 },
    { name: 'UAE North',            code: 'uaenorth',            lat: 25.28, lon:  55.30 },
    { name: 'South Africa North',   code: 'southafricanorth',    lat:-26.20, lon:  28.05 },
    { name: 'Qatar Central',        code: 'qatarcentral',        lat: 25.29, lon:  51.53 },
    { name: 'Israel Central',       code: 'israelcentral',       lat: 31.77, lon:  35.22 },
];

/**
 * Given lat/lon (from geo-IP), find the nearest Azure region.
 * Returns { name, code } or null if coordinates are missing.
 */
function inferAzureRegion(lat, lon) {
    if (lat == null || lon == null || (lat === 0 && lon === 0)) return null;
    let best = null, bestDist = Infinity;
    for (const r of AZURE_REGIONS) {
        const dLat = r.lat - lat, dLon = r.lon - lon;
        const dist = dLat * dLat + dLon * dLon; // squared Euclidean is fine for nearest
        if (dist < bestDist) { bestDist = dist; best = r; }
    }
    return best;
}

/**
 * Extract coordinates from a C-LE-01 / B-LE-01 detailedInfo string.
 * Expected format: "Coordinates: 51.4500, -0.9500"
 */
function extractCoords(detailedInfo) {
    if (!detailedInfo) return null;
    const m = detailedInfo.match(/Coordinates:\s*([-\d.]+),\s*([-\d.]+)/);
    if (!m) return null;
    return { lat: parseFloat(m[1]), lon: parseFloat(m[2]) };
}

// ═══════════════════════════════════════════════════════════
//  Cloud PC right-side map cards
// ═══════════════════════════════════════════════════════════

function updateMapCloudPcCard(lookup) {
    const loc = lookup['C-LE-01'] || lookup['B-LE-01'];
    const net = lookup['C-LE-02'] || lookup['B-LE-02'];
    const imds = lookup['C-NET-01'];
    const title = document.getElementById('map-cpc-title');
    const locEl = document.getElementById('map-cpc-location');
    const ipEl = document.getElementById('map-cpc-ip');
    const dot = document.getElementById('device-cpc-dot');
    const accent = document.getElementById('map-cpc-accent');

    if (loc && loc.status === 'Passed' && loc.resultValue) {
        // Prefer Azure region inferred from coordinates over raw geo-IP city
        const coords = extractCoords(loc.detailedInfo);
        const azRegion = coords ? inferAzureRegion(coords.lat, coords.lon) : null;
        if (azRegion) {
            if (locEl) locEl.textContent = azRegion.name;
        } else {
            if (locEl) locEl.textContent = loc.resultValue;
        }
        // Extract IP from detailed info
        if (ipEl && loc.detailedInfo) {
            const ipMatch = loc.detailedInfo.match(/Public IP:\s*([\d.]+)/);
            if (ipMatch) ipEl.textContent = ipMatch[1];
        }
        if (dot) dot.setAttribute('fill', '#3fb950');
        if (accent) accent.style.background = 'linear-gradient(180deg, rgba(63,185,80,0.5), transparent)';
    } else if (loc && loc.status === 'Error') {
        if (locEl) locEl.textContent = 'Error detecting location';
        if (dot) dot.setAttribute('fill', '#f85149');
        if (accent) accent.style.background = 'linear-gradient(180deg, rgba(248,81,73,0.5), transparent)';
    }

    // Show VM name if available from IMDS
    if (imds && imds.status === 'Passed' && imds.detailedInfo && title) {
        const vmMatch = imds.detailedInfo.match(/VM Name:\s*(\S+)/);
        if (vmMatch) title.textContent = vmMatch[1];
    }
}

function updateMapAzureCard(lookup) {
    const loc = lookup['C-LE-01'] || lookup['B-LE-01'];
    const net = lookup['C-LE-02'] || lookup['B-LE-02'];
    const egress = lookup['C-NET-02'];
    const imds = lookup['C-NET-01'];
    const detail = document.getElementById('map-azure-detail');
    const detail2 = document.getElementById('map-azure-detail2');
    const dot = document.getElementById('device-azure-dot');
    const accent = document.getElementById('map-azure-accent');

    // Show Azure region from IMDS, or infer from geo-IP coordinates
    if (imds && imds.status === 'Passed' && imds.detailedInfo) {
        const regionMatch = imds.detailedInfo.match(/Azure Region:\s*(\S+)/);
        if (regionMatch && detail) detail.textContent = regionMatch[1];
    } else if (loc && loc.detailedInfo) {
        // Infer Azure region from geo-IP coordinates
        const coords = extractCoords(loc.detailedInfo);
        const azRegion = coords ? inferAzureRegion(coords.lat, coords.lon) : null;
        if (azRegion && detail) detail.textContent = azRegion.name;
    }

    // Show org/ISP info
    if (net && net.status === 'Passed' && net.resultValue) {
        if (detail2) detail2.textContent = net.resultValue;
        // Set status from ISP data when no egress check available
        if (!egress) {
            if (dot) dot.setAttribute('fill', '#3fb950');
            if (accent) accent.style.background = 'linear-gradient(180deg, rgba(63,185,80,0.5), transparent)';
        }
    }

    // Overall status based on egress check
    if (egress) {
        if (egress.status === 'Passed') {
            if (dot) dot.setAttribute('fill', '#3fb950');
            if (accent) accent.style.background = 'linear-gradient(180deg, rgba(63,185,80,0.5), transparent)';
        } else if (egress.status === 'Warning') {
            if (dot) dot.setAttribute('fill', '#d29922');
            if (accent) accent.style.background = 'linear-gradient(180deg, rgba(210,153,34,0.5), transparent)';
        } else if (egress.status === 'Failed' || egress.status === 'Error') {
            if (dot) dot.setAttribute('fill', '#f85149');
            if (accent) accent.style.background = 'linear-gradient(180deg, rgba(248,81,73,0.5), transparent)';
        }
    }
}
