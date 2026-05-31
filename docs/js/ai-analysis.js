/**
 * Built-in Analysis Engine — rule-based expert system that analyses
 * W365 connectivity scan results and produces a prioritised diagnostic
 * report directly in the browser.  No external API required.
 */

// ═══════════════════════════════════════════════════════════════════
//  Severity helpers
// ═══════════════════════════════════════════════════════════════════
const SEV = { CRITICAL: 'critical', WARNING: 'warning', INFO: 'info' };

function finding(severity, title, detail, remediation) {
    return { severity, title, detail, remediation };
}

// ═══════════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════════
function parseMs(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*ms/i);
    return m ? parseFloat(m[1]) : NaN;
}
function parseMbps(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*Mbps/i);
    return m ? parseFloat(m[1]) : NaN;
}
function parsePct(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*%/);
    return m ? parseFloat(m[1]) : NaN;
}
function parseSignal(str) {
    if (!str) return NaN;
    const m = str.match(/([\d]+)\s*%/);
    return m ? parseInt(m[1], 10) : NaN;
}

// ═══════════════════════════════════════════════════════════════════
//  Spike detector
// ═══════════════════════════════════════════════════════════════════
function detectLatencySpikes(sampleLine) {
    // Parse all positive latency values. Allow up to 60 000 ms so genuine
    // timeouts / severe hangs still participate in the median calculation.
    const nums = (sampleLine.match(/[\d.]+/g) || []).map(Number).filter(n => n > 0 && n < 60000);
    if (nums.length < 10) return null;

    const sorted = [...nums].sort((a, b) => a - b);
    // Proper median — average the two middle elements for even-length samples
    const mid = Math.floor(sorted.length / 2);
    const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    const threshold = Math.max(median * 3, 200);
    const spikePositions = [];
    nums.forEach((v, i) => { if (v > threshold) spikePositions.push(i); });
    if (spikePositions.length < 2) return null;

    const gaps = [];
    for (let i = 1; i < spikePositions.length; i++) gaps.push(spikePositions[i] - spikePositions[i - 1]);
    const avgGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const isRegular = gaps.length > 0 && gaps.every(g => Math.abs(g - avgGap) <= 2);

    const spikeVals = spikePositions.map(i => nums[i]);
    const avgSpike = Math.round(spikeVals.reduce((a, b) => a + b, 0) / spikeVals.length);
    const maxSpike = Math.max(...spikeVals);

    return {
        count: spikePositions.length,
        avgMs: avgSpike,
        maxMs: maxSpike,
        periodic: isRegular && spikePositions.length >= 3,
        gapSamples: Math.round(avgGap),
        medianMs: Math.round(median),
        threshold: Math.round(threshold)
    };
}

// ═══════════════════════════════════════════════════════════════════
//  Satellite / aviation WiFi detector
//  Returns true when results indicate the client is on a satellite or
//  in-flight internet connection.  High jitter, symmetric NAT, and
//  large gateway distances are expected and should not be flagged as
//  network faults on these connections.
// ═══════════════════════════════════════════════════════════════════
const SATELLITE_ISP_KEYWORDS = [
    'intelsat','viasat','ka-sat','panasonic avionics','anuvu',
    'global eagle','gogo','smartsky','oneweb','starlink','telesat',
    'ses network','eutelsat','iridium','Hughes network','hughesnet'
];
const INFLIGHT_SSID_PATTERNS = [
    /^bawi-fi$/i, /^gogo\b/i, /inflight/i, /airborne/i,
    /^ua[_ -]wifi$/i, /^aa[_ -]wifi/i, /^dl[_ -]wifi/i, /southwest.*wifi/i,
    /^swa[_ -]wifi/i, /^jetblue/i, /^spirit.*wifi/i, /^_wifi.*airlines/i
];

// SSID-independent confirmation distance for a satellite uplink. A satellite
// link hands traffic to a teleport / ground station that is typically
// hundreds–thousands of km from the user, whereas a satellite ISP's
// ground-based ENTERPRISE service egresses locally. Combined with a satellite
// ISP name, a GPS→egress separation beyond this threshold is the SSID-free
// signature of an actual satellite/in-flight link — essential because travel
// routers and MiFi devices present the user's OWN SSID (never an airline
// SSID), which defeats INFLIGHT_SSID_PATTERNS matching.
const SATELLITE_MIN_EGRESS_KM = 1000;

// On-train Wi-Fi SSIDs across major European/UK/US passenger rail operators.
// Used purely for the connectivity-map easter egg + an informational note —
// nothing about test interpretation depends on it (cf. INFLIGHT_SSID_PATTERNS,
// which feeds latency/jitter context-aware findings).
const TRAIN_SSID_PATTERNS = [
    /^wifionice$/i,         // Deutsche Bahn ICE
    /^wifi@db$/i,           // DB Regio
    /^ice[ _-]?portal$/i,   // DB ICE Portal
    /^_trenitalia/i,        // Trenitalia
    /^o?bb[ _-]?wlan/i,     // ÖBB Railjet
    /^sbb[ _-]?free/i,      // SBB / Swiss Federal Railways
    /^ns[ _-]?internet$/i,  // Nederlandse Spoorwegen
    /^thalys/i,             // Thalys / Eurostar
    /^eurostar/i,
    /^tgv[ _-]?inoui/i,     // SNCF TGV inOui
    /^sncf[ _-]?wifi/i,
    /^renfe[ _-]?wifi/i,    // Renfe
    /^avanti[ _-]?free/i,   // Avanti West Coast
    /^lner[ _-]?free/i,     // LNER
    /^gwr[ _-]?wifi/i,      // Great Western Railway
    /^cross[ _-]?country/i,
    /^amtrak[ _-]?wifi/i,
    /^via[ _-]?wifi/i,      // Via Rail Canada
    /wifi[ _-]?on[ _-]?board/i
];

function detectSatelliteConnection(results) {
    // Satellite/aircraft detection requires BOTH conditions to be true:
    //   1. Live browser ISP (B-LE-02) matches a known satellite/aviation provider name
    //   2. Local scanner WiFi (L-LE-04) reports an SSID that matches an in-flight pattern
    //
    // Satellite ISPs (e.g. Intelsat, Eutelsat) also provide ground-based enterprise
    // links — ISP name alone causes false positives on corporate networks.
    // Without scanner SSID data to positively confirm an aircraft SSID, we do NOT flag.

    // Condition 1: live browser ISP must match a satellite keyword
    const browserIsp = results.find(x => x.id === 'B-LE-02' && x.source === 'browser');
    if (!browserIsp ||
        browserIsp.status === 'NotRun' ||
        browserIsp.status === 'Pending' ||
        browserIsp.status === 'Skipped') {
        return false;
    }
    const ispLower = (browserIsp.resultValue || '').toLowerCase();
    if (!SATELLITE_ISP_KEYWORDS.some(kw => ispLower.includes(kw))) return false;

    // Condition 2 (any ONE confirms a LIVE satellite/in-flight link, ruling out
    // a satellite ISP's ground-based enterprise service):
    //   (a) scanner WiFi SSID matches a known in-flight pattern, OR
    //   (b) the network egress surfaces a long way from the device GPS fix
    //       (>= SATELLITE_MIN_EGRESS_KM) — the SSID-independent satellite
    //       signature. The large-distance gate is also what guards against a
    //       false positive on a corporate ground station, which egresses
    //       locally (small GPS→egress separation).
    const wifiResult = results.find(r => r.id === 'L-LE-04');
    if (wifiResult &&
        wifiResult.status !== 'NotRun' &&
        wifiResult.status !== 'Pending' &&
        wifiResult.status !== 'Skipped') {
        const ssidMatch = (wifiResult.resultValue || '').match(/SSID:\s*([^,]+)/i);
        const ssid = ssidMatch ? ssidMatch[1].trim() : '';
        if (ssid && INFLIGHT_SSID_PATTERNS.some(p => p.test(ssid))) return true; // path (a)
    }

    // path (b): satellite ISP + large GPS→egress separation (works through
    // travel routers / MiFi where the SSID is the user's own).
    const distKm = typeof gpsEgressDistanceKm === 'function' ? gpsEgressDistanceKm(results) : null;
    if (distKm != null && distKm >= SATELLITE_MIN_EGRESS_KM) return true;

    return false;
}

// Rail Wi-Fi detection. Two paths:
//   1. Local scanner provides L-LE-04 with an SSID matching a known train pattern.
//   2. No scanner SSID, but the live browser ISP (B-LE-02) is Icomera, the
//      dominant operator of multi-WAN bonded gateways on European/UK rolling
//      stock. Used carefully — Icomera also provides bus/coach Wi-Fi — so we
//      gate on "no aircraft SSID match" and treat ISP-only matches as
//      "probably train" for the easter egg only.
function detectTrainConnection(results) {
    const wifiResult = results.find(r => r.id === 'L-LE-04');
    if (wifiResult && wifiResult.status !== 'NotRun' && wifiResult.status !== 'Pending' && wifiResult.status !== 'Skipped') {
        const m = (wifiResult.resultValue || '').match(/SSID:\s*([^,]+)/i);
        const ssid = m ? m[1].trim() : '';
        if (ssid && TRAIN_SSID_PATTERNS.some(p => p.test(ssid))) return true;
    }

    // ISP fallback — Icomera is the giveaway for European trains, but only
    // accept it when no inflight SSID is present (avoid mis-labelling planes
    // that happen to use Icomera's regional ground service).
    if (typeof detectSatelliteConnection === 'function' && detectSatelliteConnection(results)) return false;

    const isp = results.find(r => r.id === 'B-LE-02' && r.source === 'browser');
    if (isp && isp.status !== 'NotRun' && isp.status !== 'Pending' && isp.status !== 'Skipped') {
        if (/icomera|nomad\s+digital|hotsplots|gosmart\s*media/i.test(isp.resultValue || '')) {
            return true;
        }
    }
    return false;
}

// Great-circle distance (km) between the device's GPS fix and its network
// egress point. Reuses the global helpers defined in map.js / app.js at
// runtime (all scripts are loaded before any analysis runs). Returns null
// when either coordinate is unavailable.
function gpsEgressDistanceKm(results) {
    const byId = id => results.find(x => x.id === id);

    // 1. Coordinate-based computation (most precise) — only works when the
    //    stored detailedInfo carries both coordinate lines.
    if (typeof extractCoordinatesFromDetailedInfo === 'function' &&
        typeof haversineDistanceKm === 'function') {
        const gpsSrc = byId('B-LE-01');
        const gpsCoords = gpsSrc ? extractCoordinatesFromDetailedInfo(gpsSrc.detailedInfo) : null;
        if (gpsCoords) {
            let egressCoords = null;
            const egress27 = byId('27');
            if (egress27) egressCoords = extractCoordinatesFromDetailedInfo(egress27.detailedInfo, ['Egress coordinates:']);
            if (!egressCoords) {
                const ispGeo = byId('B-LE-02') || byId('C-LE-02');
                if (ispGeo) egressCoords = extractCoordinatesFromDetailedInfo(ispGeo.detailedInfo, ['Egress coordinates:']);
            }
            if (egressCoords) {
                return haversineDistanceKm(gpsCoords.lat, gpsCoords.lon, egressCoords.lat, egressCoords.lon);
            }
        }
    }

    // 2. Fallback: parse the pre-computed distance line that B-LE-02 writes
    //    ("GPS to egress: ~5006 km") or the rendered map badge. This catches
    //    browser-only / imported runs where the egress coordinates weren't
    //    persisted but the distance string was — the same data the map's
    //    GPS→egress banner is built from, so the detector fires whenever the
    //    banner does.
    const parseKm = (s) => {
        if (!s) return null;
        const m = s.match(/(?:GPS\s*(?:to|→|->)\s*egress|GPS→egress)[^\d]*?(\d[\d,]*)\s*km/i);
        return m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
    };
    const ispGeo = byId('B-LE-02') || byId('C-LE-02');
    const fromDetail = parseKm(ispGeo && ispGeo.detailedInfo);
    if (fromDetail != null) return fromDetail;
    // Rendered map badge (DOM) — authoritative when the map used its async
    // GeoIP fallback to compute the distance.
    if (typeof document !== 'undefined') {
        const badge = document.getElementById('map-isp-distance-badge');
        const fromBadge = parseKm(badge && badge.textContent);
        if (fromBadge != null) return fromBadge;
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════
//  Upstream / router-level tunnel detector
//  Catches the case where traffic is hairpinned through a remote site by a
//  tunnel that lives UPSTREAM of the PC (e.g. a travel router running
//  WireGuard, or ISP backhaul). Such a tunnel is INVISIBLE to the OS network
//  stack: the route-table check (L-TCP-07) sees clean direct routing because
//  there is no local VPN adapter. The only device-observable evidence is a
//  large GPS→egress separation with NO local tunnel and NO satellite/in-flight
//  signal. Returns { distanceKm } when matched, else false.
// ═══════════════════════════════════════════════════════════════════
const UPSTREAM_TUNNEL_MIN_KM = 500;
// Maximum positional uncertainty (km) of the device location fix for the
// GPS→egress distance to be trustworthy. A browser geolocation obtained with
// enableHighAccuracy:false is frequently a coarse WiFi/IP estimate (sometimes a
// vendor default such as the Redmond campus) that can sit hundreds/thousands of
// km from the user. Comparing such a fix to the egress IP's location is
// circular and produces phantom "tunnel" verdicts (e.g. a hotel guest whose
// laptop reports a stale office location while egressing via the hotel's real
// local ISP). Only trust the distance when the fix is at least city-grade.
const DEVICE_FIX_MAX_ACCURACY_KM = 25;

// Parse the "Accuracy: ~N km" / "Accuracy: ~N m" line emitted into B-LE-01.
// Returns accuracy in km, or null when not present (older runs / IP-only fix).
function deviceFixAccuracyKm(results) {
    const loc = results.find(x => x.id === 'B-LE-01');
    if (!loc || !loc.detailedInfo) return null;
    const m = loc.detailedInfo.match(/Accuracy:\s*~?\s*([\d.]+)\s*(km|m)\b/i);
    if (!m) return null;
    const val = parseFloat(m[1]);
    if (isNaN(val)) return null;
    return /km/i.test(m[2]) ? val : val / 1000;
}

// True only when the DEVICE coordinates came from a genuine on-device
// positioning fix (real GPS or WiFi trilateration). The user-location test
// records the source in B-LE-01 detailedInfo. Two sources carry real device
// coordinates:
//   • "Browser Geolocation (GPS/WiFi)"     — coords + city both from the device
//   • "Browser coordinates + GeoIP city"   — REAL device coords, only the city
//                                             label fell back to GeoIP
// Reject the purely IP-derived source ("GeoIP (IP-based …)"), whose position is
// computed FROM the egress IP, making a device-vs-egress comparison circular.
function deviceFixIsRealGeolocation(results) {
    const loc = results.find(x => x.id === 'B-LE-01');
    if (!loc || !loc.detailedInfo) return false;
    const m = loc.detailedInfo.match(/Source:\s*(.+)/i);
    if (!m) return false;
    const src = m[1];
    if (/IP-based|GeoIP \(IP/i.test(src)) return false;
    return /Browser Geolocation \(GPS\/WiFi\)|Browser coordinates/i.test(src);
}

// Speed of light in a VACUUM (~300 km/ms) — the absolute physical ceiling on
// signal propagation. Real fibre runs ~200 km/ms and routed paths slower still,
// so using the vacuum figure gives the SMALLEST latency a given distance could
// conceivably add. That makes the gate below maximally conservative: it only
// fires when a distance is impossible even at light-speed, so it can never
// suppress a genuine remote tunnel (whose RTT is always high enough).
const LIGHT_KM_PER_MS = 300;

// Smallest credible SINGLE network round-trip time (ms) provable from results,
// returned as an UPPER BOUND (we never under-estimate, so we never wrongly
// suppress). Each source measures one or more round trips; we divide by the
// minimum number of round trips it must contain to get a safe per-RTT ceiling.
function minNetworkRttUpperBoundMs(results) {
    const byId = id => results.find(x => x.id === id);
    const cand = [];
    // B-TCP-02: "HTTPS RTT (TCP + TLS handshake): avg N ms" — TCP(1)+TLS(>=1)
    // is at least two round trips, so the per-RTT ceiling is N/2.
    const tcp02 = byId('B-TCP-02');
    if (tcp02 && tcp02.detailedInfo) {
        const m = tcp02.detailedInfo.match(/HTTPS RTT[^:]*:\s*avg\s*(\d+(?:\.\d+)?)\s*ms/i);
        if (m) cand.push(parseFloat(m[1]) / 2);
    }
    // B-EP-01 endpoint reachability "Reachable (N ms)" — a connect includes
    // TCP(1)+TLS(1) >= two round trips → per-RTT ceiling N/2.
    const ep01 = byId('B-EP-01');
    if (ep01 && ep01.detailedInfo) {
        let best = Infinity, mm; const re = /Reachable\s*\((\d+(?:\.\d+)?)\s*ms\)/gi;
        while ((mm = re.exec(ep01.detailedInfo)) !== null) best = Math.min(best, parseFloat(mm[1]));
        if (isFinite(best)) cand.push(best / 2);
    }
    // B-TCP-03 per-endpoint "host: N ms (OK)" — DNS+TCP+TLS >= two round trips.
    const tcp03 = byId('B-TCP-03');
    if (tcp03 && tcp03.detailedInfo) {
        let best = Infinity, mm; const re = /:\s*(\d+(?:\.\d+)?)\s*ms\s*\(OK\)/gi;
        while ((mm = re.exec(tcp03.detailedInfo)) !== null) best = Math.min(best, parseFloat(mm[1]));
        if (isFinite(best)) cand.push(best / 2);
    }
    if (!cand.length) return null;
    return Math.min(...cand);
}

function detectUpstreamTunnel(results) {
    // Cases already explained by dedicated detectors are not "upstream tunnel".
    if (typeof detectSatelliteConnection === 'function' && detectSatelliteConnection(results)) return false;
    if (typeof detectTrainConnection === 'function' && detectTrainConnection(results)) return false;

    // Require a measurable, large GPS→egress separation.
    const distKm = gpsEgressDistanceKm(results);
    if (distKm == null || distKm < UPSTREAM_TUNNEL_MIN_KM) return false;

    // The distance is only meaningful if the DEVICE location is a genuine
    // on-device fix (real GPS/WiFi). An IP-derived position is computed FROM the
    // egress IP, so a "mismatch" against the egress is just two GeoIP providers
    // disagreeing about the same IP (e.g. one places a Comcast IP in WA, another
    // in PA) — NOT a tunnel. This is the exact hotel false-positive: the device
    // showed Redmond (an IP centroid) while a different provider placed the
    // egress IP elsewhere. Require a real geolocation source first.
    if (!deviceFixIsRealGeolocation(results)) return false;

    // Even a "browser" fix can be IP-assisted (coarse). Require a city-grade or
    // better accuracy: a real GPS/WiFi fix is sub-kilometre to a few km, whereas
    // an IP-assisted fix is reported at tens of km or worse. If accuracy is
    // unknown OR coarse, suppress — better to miss a real upstream tunnel than
    // to tell a hotel/coffee-shop user they have a phantom one.
    const accKm = deviceFixAccuracyKm(results);
    if (accKm == null || accKm > DEVICE_FIX_MAX_ACCURACY_KM) return false;

    // ── Egress-side reality check (physics) ───────────────────────────────
    // The accuracy gate above only validates the DEVICE position. The other half
    // of the distance — the EGRESS location — is a GeoIP lookup of an ISP IP and
    // is routinely wrong by hundreds/thousands of km: large carriers (Comcast,
    // etc.) register IP blocks centrally, far from the physical PoP the user
    // actually egresses through. That alone fabricates a phantom "tunnel" for a
    // user whose device fix is perfectly accurate (e.g. a hotel guest in Redmond
    // whose Comcast IP geolocates to Pennsylvania, ~3,800 km away).
    //
    // A genuine hairpin through a site `distKm` away MUST add at least
    // 2·distKm/c to EVERY round trip. At the speed of light in vacuum that floor
    // is 2·distKm/300 ms — a hard physical limit nothing can beat. If the latency
    // we actually measured is below that floor, no packet could have reached an
    // egress that far away and returned, so the distance is a GeoIP artefact, not
    // a tunnel. This can only suppress impossible distances, never a real remote
    // tunnel (whose RTT is always large enough to clear the floor).
    const minRtt = minNetworkRttUpperBoundMs(results);
    if (minRtt != null) {
        const hairpinFloorMs = (2 * distKm) / LIGHT_KM_PER_MS;
        if (minRtt < hairpinFloorMs) return false;
    }

    // If the scanner ran and L-TCP-07 found a LOCAL VPN/SWG adapter capturing or
    // diverting traffic, that is the (already-reported) cause — not an
    // upstream-only tunnel. When the scanner hasn't run, L-TCP-07 is absent and
    // we cannot inspect local adapters; the distance signal still stands and the
    // finding wording flags the ambiguity.
    const vpn = results.find(x => x.id === 'L-TCP-07');
    if (vpn) {
        const detail = (vpn.detailedInfo || '');
        const resVal = (vpn.resultValue || '');
        const localTunnel = /VPN tunnel is carrying W365\/AVD traffic|routes via VPN interface|egresses via an UNRECOGNISED non-primary interface|VPN adapter detected|VPN\/SWG detected|VPN active/i.test(detail) || /\bVPN\b/i.test(resVal);
        if (localTunnel) return false;
    }

    return { distanceKm: distKm, scannerRan: !!vpn };
}

// ═══════════════════════════════════════════════════════════════════
//  Core analysis engine
// ═══════════════════════════════════════════════════════════════════
function runAnalysisEngine(results) {
    if (!results || results.length === 0) return [];

    const r = id => results.find(x => x.id === id);
    const findings = [];

    const isSatellite = detectSatelliteConnection(results);

    // ── 0. Satellite / in-flight WiFi context ──
    if (isSatellite) {
        const ispResult = r('B-LE-02') || r('C-LE-02');
        const ispName = ispResult ? ispResult.resultValue.replace(/^AS\d+\s*/i, '') : 'Satellite provider';
        // Teleport / ground-station distance — surfaced so the user understands a
        // far egress on a satellite link is expected, NOT a VPN hairpin.
        const satDistKm = typeof gpsEgressDistanceKm === 'function' ? gpsEgressDistanceKm(results) : null;
        const distSentence = (satDistKm != null && satDistKm >= SATELLITE_MIN_EGRESS_KM)
            ? ` Your traffic surfaces ~${Math.round(satDistKm).toLocaleString()} km from your physical location — that is the satellite teleport / ground station, which is normal for a satellite uplink and is NOT evidence of a VPN.`
            : '';
        // If the scanner inspected the routing table and the W365/AVD ranges
        // egress directly (not via a local VPN/SWG tunnel), confirm the
        // split-tunnel is correct. This is the key reassurance for travel-router
        // / WireGuard setups: a tunnel may exist on an upstream device, but W365
        // is correctly excluded so RDP egresses over the local/satellite path.
        const satVpn = r('L-TCP-07');
        const w365Direct = satVpn && /ENTIRE range routed direct|No W365\/AVD service traffic goes through the VPN tunnel/i.test(satVpn.detailedInfo || '');
        const splitSentence = w365Direct
            ? ' The local routing table shows the Windows 365 / AVD ranges (40.64.144.0/20, 51.5.0.0/16) egressing directly — so if an upstream travel router or VPN is in use, W365 is correctly split-tunnelled around it.'
            : '';
        findings.push(finding(SEV.INFO, 'Satellite / in-flight internet detected',
            `ISP identified as ${ispName}. Satellite and in-flight connections have inherent characteristics — high base latency (typically 500–700 ms RTT), symmetric NAT, and variable jitter — that are not network faults.${distSentence}${splitSentence}`,
            'For best Cloud PC experience on satellite/aircraft WiFi: ensure UDP 3478 is open for TURN relay fallback, avoid bandwidth-heavy background apps, and expect occasional freezes during turbulence/handover. TCP-based sessions (via RD Gateway) stay connected even when UDP/STUN fails.'));

        // Satellite-aware metric context. On a satellite/in-flight uplink a high
        // TURN RTT and a modest/variable throughput are EXPECTED — the dedicated
        // tests rightly Pass on reachability, but the headline numbers can alarm
        // a user who doesn't know the link is satellite. Surface them here as
        // context, guarded by isSatellite so they can NEVER false-positive on a
        // terrestrial link. Read only from results[] (no thresholds escalated).
        const satTurn = r('L-UDP-03');
        if (satTurn) {
            const turnRtt = parseMs(satTurn.resultValue);
            if (!isNaN(turnRtt) && turnRtt >= 400) {
                findings.push(finding(SEV.INFO, 'TURN relay latency is high — expected on satellite',
                    `The TURN relay (UDP 3478) responded in ${Math.round(turnRtt)} ms. On a satellite/in-flight link this is the inherent propagation delay (geostationary hops add ~500–600 ms round-trip), not a relay fault — UDP 3478 reachability itself passed. RDP Shortpath will still prefer this UDP path over TCP because it absorbs jitter better.`,
                    'No action — this latency is a property of the satellite link, not your configuration. It will drop back to normal on a terrestrial connection.'));
            }
        }
        const satBw = r('L-LE-07') || r('B-LE-03');
        if (satBw) {
            const bwMatch = (satBw.resultValue || '').match(/([\d.]+)\s*Mbps/i);
            const bwMbps = bwMatch ? parseFloat(bwMatch[1]) : NaN;
            if (!isNaN(bwMbps)) {
                findings.push(finding(SEV.INFO, 'Throughput reflects a shared satellite uplink',
                    `Measured throughput was ~${bwMbps.toFixed(1)} Mbps via a short burst download. Satellite/in-flight links are shared and bursty, so a single download test can over- or under-state what a sustained Cloud PC session gets — actual session bandwidth (and the relay path specifically) is usually lower and more variable than this figure suggests.`,
                    'For a smoother session on satellite, close bandwidth-heavy background apps and prefer a lower display resolution / 30 fps to reduce the bitrate the link must sustain.'));
            }
        }
    }

    // ── 0b. Upstream / router-level tunnel (remote egress hairpin) ──
    // Fires independently of the egress test status: the giveaway is a large
    // GPS→egress distance with no LOCAL VPN adapter and no satellite signal —
    // i.e. a tunnel that lives upstream of this device (travel router / ISP
    // backhaul) and is therefore invisible to the OS routing table.
    const upstreamTunnel = detectUpstreamTunnel(results);
    if (upstreamTunnel) {
        const egressIspResult = r('B-LE-02') || r('C-LE-02');
        const egressIsp = egressIspResult ? egressIspResult.resultValue.replace(/^AS\d+\s*/i, '') : '';
        const distStr = typeof formatDistanceKmMi === 'function'
            ? formatDistanceKmMi(upstreamTunnel.distanceKm)
            : `~${Math.round(upstreamTunnel.distanceKm)} km`;
        const ispStr = egressIsp ? ` (egress ISP: ${egressIsp})` : '';
        const ambiguity = upstreamTunnel.scannerRan
            ? 'The local scanner confirmed no VPN adapter exists on this device, so the tunnelling is happening on an upstream device.'
            : 'No local VPN adapter could be inspected (run the Local Scanner to confirm). If this device has no VPN client of its own, the tunnelling is happening on an upstream device.';
        findings.push(finding(SEV.WARNING, 'Upstream / router-level tunnel — remote egress detected',
            `Your traffic exits the internet ${distStr} from your physical location${ispStr}, but no VPN adapter is present on this PC. ${ambiguity} ` +
            'This is the signature of a router-level VPN (for example a travel router running WireGuard) or ISP backhaul: Windows 365 / RDP traffic is hairpinned through that remote site, adding round-trip latency to every packet.',
            'Split-tunnel Windows 365 at the upstream device so RDP egresses locally: exclude the W365 ranges (40.64.144.0/20 TCP/443 and 51.5.0.0/16 UDP/3478) and FQDNs (*.wvd.microsoft.com, *.infra.windows365.microsoft.com, turn.azure.com) from the router/VPN tunnel — or disable the tunnel for the Cloud PC session.'));
    }

    // ── 1. WiFi signal ──
    const wifi = r('L-LE-04');
    if (wifi) {
        const sig = parseSignal(wifi.resultValue);
        if (!isNaN(sig)) {
            if (sig < 40) {
                findings.push(finding(SEV.CRITICAL, 'Poor WiFi signal',
                    `Signal strength is ${sig}% — below the recommended 60% minimum. This will cause packet loss, retransmissions and intermittent disconnects.`,
                    'Move closer to the access point, remove physical obstructions, or switch to a 5 GHz band. If possible, use a wired Ethernet connection for Cloud PC sessions.'));
            } else if (sig < 60) {
                findings.push(finding(SEV.WARNING, 'Marginal WiFi signal',
                    `Signal strength is ${sig}% — below the recommended 60% minimum.`,
                    'Consider moving closer to the access point or switching to 5 GHz. Wired Ethernet is always preferred for Cloud PC use.'));
            }
        }
    }

    // ── 2. Gateway / router latency ──
    const gwLat = r('L-LE-05');
    if (gwLat) {
        const avg = parseMs(gwLat.resultValue);
        if (!isNaN(avg)) {
            if (avg > 50) {
                findings.push(finding(SEV.CRITICAL, 'Very high gateway latency',
                    `Average latency to your local gateway is ${avg.toFixed(0)} ms — this should be < 5 ms on a healthy network. Every packet to Azure inherits this local delay.`,
                    'Check for WiFi interference, network congestion, or a malfunctioning router. Try rebooting the router, using a wired connection, or bypassing any consumer mesh/extender nodes.'));
            } else if (avg > 20) {
                findings.push(finding(SEV.WARNING, 'Elevated gateway latency',
                    `Average latency to your gateway is ${avg.toFixed(0)} ms (ideal is < 5 ms). This adds delay to every Azure round-trip.`,
                    'A wired connection or 5 GHz WiFi band may help. If the issue persists, check the router and local network for congestion.'));
            }
        }
    }

    // ── 3. Bandwidth ──
    // Prefer L-LE-07 (local scanner) but fall back to B-LE-03 (browser) when the
    // local test errored or returned an unparseable value. Without this fallback,
    // a blocked speed.cloudflare.com on the scanner side silently suppresses the
    // bandwidth finding even though the browser test had a perfectly good number.
    const bwLocal = r('L-LE-07');
    const bwBrowser = r('B-LE-03');
    let bw = null;
    let bwSource = '';
    if (bwLocal && bwLocal.status !== 'Error' && bwLocal.status !== 'Skipped') {
        const m = parseMbps(bwLocal.resultValue);
        if (!isNaN(m)) { bw = bwLocal; bwSource = 'local scanner'; }
    }
    if (!bw && bwBrowser) {
        const m = parseMbps(bwBrowser.resultValue);
        if (!isNaN(m)) { bw = bwBrowser; bwSource = 'browser test'; }
    }
    // Surface the local error itself if local errored AND we had to use browser (or had nothing).
    if (bwLocal && bwLocal.status === 'Error') {
        findings.push(finding(SEV.INFO, 'Local bandwidth test errored',
            `The local scanner bandwidth probe (L-LE-07) failed: ${bwLocal.resultValue}. ${bw ? `Using the browser test (${bwSource}) instead.` : 'No bandwidth measurement available.'}`,
            'Check the L-LE-07 detail for the underlying cause (proxy block, DNS failure, TLS inspection on speed.cloudflare.com, etc.). This does not necessarily indicate a Cloud PC problem.'));
    }
    if (bw) {
        const mbps = parseMbps(bw.resultValue);
        if (!isNaN(mbps)) {
            if (mbps < 5) {
                findings.push(finding(SEV.CRITICAL, 'Very low bandwidth',
                    `Bandwidth is only ${mbps.toFixed(1)} Mbps (${bwSource}) — well below the 20 Mbps recommended for a good Cloud PC experience. Video, screen updates and file transfers will be severely impacted.`,
                    'Use a wired connection if on WiFi. Contact your ISP if bandwidth is consistently below plan speeds.'));
            } else if (mbps < 10) {
                findings.push(finding(SEV.WARNING, 'Low bandwidth',
                    `Bandwidth is ${mbps.toFixed(1)} Mbps (${bwSource}) — below the 20 Mbps recommended for optimal Cloud PC performance.`,
                    'Ensure other bandwidth-heavy activities are minimised during Cloud PC use. A wired Ethernet connection can improve throughput stability.'));
            }
        }
    }

    // ── 4. Machine performance ──
    const perf = r('L-LE-08');
    if (perf && (perf.status === 'Warning' || perf.status === 'Failed')) {
        findings.push(finding(perf.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'Client machine performance concern',
            perf.resultValue,
            'Close unnecessary applications, check for high CPU/memory usage in Task Manager, ensure the device is not thermally throttling, and verify that GPU drivers are up to date.'));
    }

    // ── 5. TLS inspection ──
    const tls = r('L-TCP-06');
    if (tls && tls.status !== 'Passed' && tls.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection detected',
            `A TLS-intercepting proxy (SSL inspection / MITM) is modifying the certificate chain for Windows 365 gateway connections. ${tls.resultValue}`,
            'Windows 365 RDP traffic must not be TLS-inspected. Add *.wvd.microsoft.com, *.infra.windows365.microsoft.com, and turn.azure.com to your proxy\'s SSL bypass list. See https://learn.microsoft.com/windows-365/enterprise/requirements-network'));
    }
    const tlsUdp = r('L-UDP-06');
    if (tlsUdp && tlsUdp.status !== 'Passed' && tlsUdp.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection on TURN relay',
            `TURN relay traffic (UDP 3478) is being TLS-inspected. ${tlsUdp.resultValue}`,
            'Add turn.azure.com to your proxy\'s SSL bypass / certificate pinning exception list.'));
    }
    const tlsRdp = r('25');
    if (tlsRdp && tlsRdp.status !== 'Passed' && tlsRdp.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection on live RDP session',
            `Active RDP session traffic is being TLS-intercepted. ${tlsRdp.resultValue}`,
            'This will cause disconnects and session instability. Exempt all Windows 365 FQDNs from SSL inspection immediately.'));
    }

    // ── 6. DNS hijacking ──
    const dnsHijack = r('L-TCP-08');
    if (dnsHijack && dnsHijack.status !== 'Passed' && dnsHijack.status !== 'Skipped') {
        findings.push(finding(SEV.WARNING, 'DNS hijacking detected',
            `DNS responses are being modified — queries for non-existent domains are not returning NXDOMAIN. ${dnsHijack.resultValue}`,
            'Verify DNS resolver configuration. Use a direct DNS resolver (e.g. 8.8.8.8 or corporate DNS) and confirm NXDOMAIN is returned for non-existent domains.'));
    }

    // ── 7. VPN / Proxy / SWG ──
    // L-TCP-07 is authoritative: the scanner walks the routing table, finds the
    // longest-prefix match for 40.64.144.0/20, 51.5.0.0/16 and the resolved RDP
    // gateway IP, and reports whether the chosen interface IP belongs to a
    // tunnel adapter. We key the verdict off the actual marker strings it emits
    // rather than fuzzy substring matching against resultValue.
    const vpn = r('L-TCP-07');
    if (vpn) {
        const detail = (vpn.detailedInfo || '');
        const resVal = (vpn.resultValue || '');
        const tunnelCarriesRdp = /VPN tunnel is carrying W365\/AVD traffic|routes via VPN interface/i.test(detail);
        const tunnelBypassesRdp = /No W365\/AVD service traffic goes through the VPN tunnel|VPN is active but RDP traffic correctly bypasses it|routes direct via|Split-tunnelled \(direct\)/i.test(detail);
        const tunnelDivertsRdp = /egresses via an UNRECOGNISED non-primary interface|diverts via an unrecognised non-primary interface/i.test(detail) || /unrecognised interface/i.test(resVal);
        const vpnDetected = /VPN adapter detected|VPN\/SWG detected|VPN active/i.test(detail) || /\bVPN\b/i.test(resVal);

        // Pull the precise captured CIDRs from the routing analysis so the finding
        // names exactly what is NOT being bypassed (not just the interceptor name).
        const grabRanges = (re) => {
            const m = detail.match(re);
            if (!m) return [];
            return m[1].split('\u2014')[0].split(',').map(s => s.trim()).filter(Boolean);
        };
        const caughtCidrs = grabRanges(/VPN tunnel is carrying W365\/AVD traffic for:\s*([^\n]+)/i);
        const divertedCidrs = grabRanges(/egresses via an UNRECOGNISED non-primary interface for:\s*([^\n]+)/i);

        if (tunnelCarriesRdp) {
            const caughtStr = caughtCidrs.length ? ` Captured by the tunnel: ${caughtCidrs.join(', ')}.` : '';
            findings.push(finding(SEV.CRITICAL, 'VPN tunnel is carrying Windows 365 RDP traffic',
                `The local routing table shows W365/AVD ranges or the resolved RDP gateway IP routing through a VPN/SASE tunnel adapter.${caughtStr} ${resVal}`,
                'Configure split tunnelling to exclude Windows 365 ranges (40.64.144.0/20 TCP/443 and 51.5.0.0/16 UDP/3478) and FQDNs (*.wvd.microsoft.com, *.infra.windows365.microsoft.com, turn.azure.com) from the VPN tunnel. See https://learn.microsoft.com/windows-365/enterprise/azure-network-connections'));
        } else if (tunnelDivertsRdp) {
            const divertedStr = divertedCidrs.length ? ` Diverted ranges: ${divertedCidrs.join(', ')}.` : '';
            findings.push(finding(SEV.WARNING, 'Windows 365 traffic diverts via an unrecognised interface',
                `The routing table shows W365/AVD ranges egressing on an interface that is neither your direct internet path nor a named VPN adapter \u2014 most likely a VPN/SWG tunnel whose adapter name wasn't recognised.${divertedStr} ${resVal}`,
                'Confirm what that interface is. If it is a VPN/SWG tunnel, add the listed Windows 365 CIDRs (40.64.144.0/20, 51.5.0.0/16) and FQDNs (*.wvd.microsoft.com, *.infra.windows365.microsoft.com, turn.azure.com) to its bypass/exclude list. See https://learn.microsoft.com/windows-365/enterprise/azure-network-connections'));
        } else if (vpnDetected && tunnelBypassesRdp) {
            findings.push(finding(SEV.INFO, 'VPN detected \u2014 correctly split-tunnelled',
                'A VPN/SASE adapter is active, but the local routing table confirms Windows 365 ranges and the RDP gateway IP route outside the tunnel. This is the recommended configuration.',
                null));
        } else if (vpnDetected && vpn.status !== 'Passed' && vpn.status !== 'Skipped') {
            // VPN present, route-table evidence inconclusive
            findings.push(finding(SEV.WARNING, 'VPN detected \u2014 split tunnelling not confirmed',
                `A VPN connection is active and route-table evidence for W365 traffic is inconclusive. ${resVal}`,
                'Configure split tunnelling to exclude Windows 365 FQDNs (*.wvd.microsoft.com, *.infra.windows365.microsoft.com, turn.azure.com) from the VPN tunnel. See https://learn.microsoft.com/windows-365/enterprise/azure-network-connections'));
        }
    }
    const vpnPerf = r('24');
    if (vpnPerf && vpnPerf.status !== 'Passed' && vpnPerf.status !== 'Skipped') {
        findings.push(finding(vpnPerf.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'VPN is degrading session performance',
            vpnPerf.resultValue,
            'VPN routing is adding measurable latency to the RDP session. Enable split tunnelling for W365 traffic or disconnect the VPN during Cloud PC use.'));
    }

    // ── 8. Proxy / SWG detection from DNS routing ──
    // If a SWG vendor appears in B-TCP-04 DNS routing AND a route-table verdict
    // already fired in section 7 above (CRITICAL or INFO bypass), don't double-
    // up. Only emit the generic INFO when section 7 was silent.
    const dnsRoute = r('B-TCP-04');
    if (dnsRoute && dnsRoute.detailedInfo) {
        const detail = dnsRoute.detailedInfo.toLowerCase();
        const swgNames = ['zscaler', 'netskope', 'globalsecureaccess', 'cloudflare-gateway', 'swg', 'menlo'];
        const detectedSwg = swgNames.find(s => detail.includes(s));
        const alreadyHandled = findings.some(f =>
            /carrying Windows 365 RDP traffic|correctly split-tunnelled|split tunnelling not confirmed/i.test(f.title));
        if (detectedSwg && !alreadyHandled) {
            findings.push(finding(SEV.INFO, `Secure Web Gateway detected (${detectedSwg})`,
                'A SWG vendor name appears in DNS resolution chains for Windows 365 endpoints. The route-table check (L-TCP-07) did not produce a definitive verdict on whether RDP traffic transits the SWG.',
                'Verify L-TCP-07 details and confirm Windows 365 endpoints are in the SWG bypass/direct policy.'));
        }
        // Private Link
        if (detail.includes('privatelink') && (detail.includes('10.') || detail.match(/172\.(1[6-9]|2\d|3[01])/) || detail.includes('192.168.'))) {
            findings.push(finding(SEV.INFO, 'Azure Private Link in use',
                'DNS resolution is routing through Private Link endpoints (RFC 1918 IPs). This is the expected corporate configuration.',
                null));
        }
    }

    // ── 9. NAT type ──
    const nat = r('L-UDP-05') || r('B-UDP-02');
    if (nat && !isSatellite) {
        const val = (nat.resultValue || '').toLowerCase();
        if (val.includes('multiple egress paths') || val.includes('split egress')) {
            findings.push(finding(SEV.INFO, 'Multiple network egress paths (SWG/ZTNA)',
                'A Secure Web Gateway / ZTNA agent (e.g. Microsoft Global Secure Access) is forwarding some Azure traffic through its tunnel while W365 traffic egresses directly via the ISP. The two STUN servers returned different reflexive IPs because they reached the internet via two different paths — this is NOT Symmetric NAT.',
                'No action required. The W365 TURN/RDP ranges are correctly excluded from the SWG forwarding profile (best practice). TURN reachability (L-UDP-03) confirms the UDP path is healthy.'));
        } else if (val.includes('symmetric')) {
            findings.push(finding(SEV.INFO, 'Symmetric NAT (Standard Enterprise Security)',
                'Your network uses Symmetric NAT, which is typical for enterprise environments and provides strong security. Windows 365 will use TURN relay for reliable UDP connectivity.',
                'This is normal and expected behavior. TURN relay provides excellent performance and reliability. No action required.'));
        } else if (val.includes('blocked') || nat.status === 'Failed') {
            findings.push(finding(SEV.WARNING, 'UDP connectivity limited',
                'UDP STUN is not available. Windows 365 requires TURN relay (UDP 3478) for optimal performance.',
                'Ensure outbound UDP port 3478 to turn.azure.com is open. TURN relay is critical for good Windows 365 performance in all environments.'));
        }
    } else if (nat && isSatellite) {
        // On satellite, symmetric NAT is standard CGN — only flag if STUN is fully blocked
        const val = (nat.resultValue || '').toLowerCase();
        if ((val.includes('blocked') || nat.status === 'Failed') && !val.includes('symmetric')) {
            findings.push(finding(SEV.WARNING, 'UDP connectivity limited',
                'UDP STUN is not available. Windows 365 requires TURN relay (UDP 3478) for optimal performance.',
                'Ensure outbound UDP port 3478 to turn.azure.com is open. TURN relay is critical for good Windows 365 performance in all environments.'));
        }
    }

    // ── 10. TURN reachability ──
    const turn = r('L-UDP-03');
    const turnUnreachable = turn && (turn.status === 'Failed' || turn.status === 'Error' ||
        (turn.status === 'Warning' && /unreachable|timed out|timeout|blocked/i.test(turn.resultValue || '')));
    if (turnUnreachable) {
        findings.push(finding(SEV.CRITICAL, 'RDP Shortpath unavailable — UDP 3478 blocked',
            `TURN relay on UDP 3478 did not respond, so RDP Shortpath (the low-latency UDP transport) cannot be established. RDP will fall back to TCP over the gateway, so a session can still be made — but the experience is significantly degraded: higher latency, poor resilience to packet loss, and choppy video/scrolling. For a good W365 experience this must be fixed. ${turn.resultValue}`,
            'Allow outbound UDP 3478 to turn.azure.com / the AVD TURN range (51.5.0.0/16) through all firewalls and network security appliances.'));
    }

    // ── 11. Session latency (Test 18) ──
    const session = r('18');
    if (session) {
        const avg = parseMs(session.resultValue);
        if (!isNaN(avg)) {
            if (avg > 200) {
                findings.push(finding(SEV.CRITICAL, 'Very high session latency',
                    `Average round-trip time is ${avg.toFixed(0)} ms — well above the 100 ms threshold for a good experience. Users will notice significant input lag and sluggish response.`,
                    'Check if traffic is being routed through a VPN or proxy. Verify that the Cloud PC provisioning region is geographically close to the user. High gateway latency (L-LE-05) compounds this issue.'));
            } else if (avg > 100) {
                findings.push(finding(SEV.WARNING, 'Elevated session latency',
                    `Average RTT is ${avg.toFixed(0)} ms. Latency above 100 ms becomes noticeable during interactive work (typing, mouse movement).`,
                    'Ensure traffic egresses locally (not hairpinned through a VPN or distant proxy). Check Cloud PC region alignment with the user\'s physical location.'));
            }
        }
        // Check for spikes in detailed samples
        if (session.detailedInfo) {
            const valLine = session.detailedInfo.split('\n').find(l => l.startsWith('Values:') || l.includes('RTT Samples:'));
            if (valLine) {
                const spikes = detectLatencySpikes(valLine);
                if (spikes && spikes.periodic) {
                    findings.push(finding(SEV.CRITICAL, 'Periodic latency spikes detected',
                        `${spikes.count} regular spikes averaging ${spikes.avgMs} ms (peak ${spikes.maxMs} ms) every ~${spikes.gapSamples} samples against a baseline median of ${spikes.medianMs} ms. This pattern is characteristic of WiFi driver background scanning or power management cycling.`,
                        'Open Device Manager \u2192 WiFi adapter \u2192 Properties \u2192 Advanced. Disable Power Saving Mode, set Roaming Aggressiveness to Lowest, disable U-APSD. If using Intel AX200/AX201/AX211, these settings are in the Intel driver properties. Alternatively, use a wired Ethernet connection.'));
                } else if (spikes && spikes.count >= 3) {
                    findings.push(finding(SEV.WARNING, 'Latency spikes detected',
                        `${spikes.count} latency spikes exceeding ${spikes.threshold} ms detected (avg ${spikes.avgMs} ms, peak ${spikes.maxMs} ms). The spikes are irregular and do not follow a periodic pattern.`,
                        'Monitor with a continuous ping to the gateway to identify when spikes occur. Check WiFi stability and competing bandwidth usage.'));
                }
            }
        }
    }

    // ── 12. Jitter (Test 20) ──
    const jitter = r('20');
    if (jitter) {
        const j = parseMs(jitter.resultValue);
        if (!isNaN(j)) {
            if (isSatellite) {
                // Satellite / in-flight links have inherently high jitter — contextualise rather than alarm
                if (j > 60) {
                    findings.push(finding(SEV.WARNING, 'High jitter — expected on satellite/in-flight WiFi',
                        `Connection jitter is ${j.toFixed(1)} ms. Satellite and in-flight internet links have inherently variable latency due to the long propagation path and shared bandwidth. This is expected and is not a network fault.`,
                        'Jitter on satellite WiFi cannot be reduced at the endpoint. TURN relay fallback (UDP) will help absorb bursts. For critical sessions, connect via ground-based WiFi or cellular.'));
                }
                // Don't flag <60ms jitter at all on satellite — it would be noise
            } else {
                if (j > 60) {
                    findings.push(finding(SEV.CRITICAL, 'Very high jitter',
                        `Connection jitter is ${j.toFixed(1)} ms — far above the 30 ms warning threshold. This causes inconsistent frame delivery, visual stuttering, and audio glitches.`,
                        'High jitter is usually caused by WiFi instability, network congestion, or a saturated uplink. Use a wired connection, reduce competing traffic, and check for QoS issues on the local network.'));
                } else if (j > 30) {
                    findings.push(finding(SEV.WARNING, 'Elevated jitter',
                        `Connection jitter is ${j.toFixed(1)} ms — above the 30 ms threshold for smooth experience.`,
                        'Check for WiFi interference or competing bandwidth-intensive activities on the same network.'));
                }
            }
        }
    }

    // ── 13. Packet loss / Frame drops (Test 21) ──
    const loss = r('21');
    if (loss) {
        const pct = parsePct(loss.resultValue);
        if (!isNaN(pct)) {
            if (pct > 15) {
                findings.push(finding(SEV.CRITICAL, 'Severe packet loss',
                    `Packet / frame loss is ${pct.toFixed(1)}% — this will cause visible screen corruption, freezing, and frequent disconnects.`,
                    'Check WiFi signal strength and network adapter drivers. On wired connections, try a different cable or switch port.'));
            } else if (pct > 5) {
                findings.push(finding(SEV.WARNING, 'Packet loss detected',
                    `${pct.toFixed(1)}% packet / frame loss — above the 5% threshold. Users may experience occasional freezes or visual artefacts.`,
                    'Monitor for WiFi interference or network congestion peaks. Ensure the network adapter driver is up to date.'));
            }
        }
    }

    // ── 14. Transport protocol (Test 17b) ──
    const transport = r('17b');
    if (transport) {
        const val = (transport.resultValue || '').toLowerCase();
        if (val.includes('tcp')) {
            findings.push(finding(SEV.WARNING, 'Session using TCP transport',
                'The session is using TCP instead of UDP Shortpath. TCP adds latency due to head-of-line blocking and retransmissions, resulting in a less responsive experience.',
                'Ensure UDP 3478 outbound is open, NAT type allows it, and TURN relay is reachable. UDP Shortpath is enabled by default in Windows 365 \u2014 verify no GPO is disabling it.'));
        }
        // Check for disconnects — only flag NETWORK-level disconnects, not
        // normal session-end events. ClientActiveX Reason= 3 means "remote
        // disconnect by server" (normal session end / sign-out) and must not
        // be treated as a fault. Real network drops surface as RdpCoreTS
        // codes 16644 / 4616 or as repeated reconnects in a short window.
        if (transport.detailedInfo) {
            const lines = transport.detailedInfo.split('\n');
            const networkDropCodes = /\b(?:16644|4616|2308|2825|3334|264)\b/;
            const reasonMatches = lines.map(l => {
                const m = l.match(/Reason=\s*(\d+)/i);
                return m ? parseInt(m[1], 10) : null;
            }).filter(n => n !== null);
            // Reason codes that indicate network-related disconnects on the
            // ClientActiveX path (per RDP client SDK):
            //   0 = unknown / network failure
            //   1 = local disconnect (often timeout-driven)
            // Reason codes that are NORMAL and must NOT trigger a finding:
            //   2 = user-initiated remote disconnect
            //   3 = server-initiated disconnect (sign-out, idle timeout policy)
            const networkReasons = reasonMatches.filter(n => n === 0 || n === 1);
            const hasNetworkDropCode = networkDropCodes.test(transport.detailedInfo);
            const reconnectStarts = lines.filter(l => /Connection Started/i.test(l)).length;

            if (hasNetworkDropCode || networkReasons.length > 0 || reconnectStarts >= 4) {
                const evidence = [];
                if (hasNetworkDropCode) evidence.push('RdpCoreTS network-drop code present');
                if (networkReasons.length > 0) evidence.push(`ClientActiveX Reason=${networkReasons.join(',')} (network-related)`);
                if (reconnectStarts >= 4) evidence.push(`${reconnectStarts} reconnect attempts in the captured log window`);
                findings.push(finding(SEV.WARNING, 'Network-level session disconnects detected',
                    `Evidence: ${evidence.join('; ')}. RDP event logs indicate the session has been dropped by the network, not by the user or server.`,
                    'Check WiFi stability, VPN keepalive settings, and idle-timeout policies. RdpCoreTS code 16644 indicates transport timeout; 4616 indicates network-level disconnect.'));
            }
        }
    }

    // ── 15. UDP Shortpath readiness (Test 17c) ──
    const udpReady = r('17c');
    if (udpReady && (udpReady.status === 'Failed' || udpReady.status === 'Warning')) {
        if ((udpReady.resultValue || '').toLowerCase().includes('blocked')) {
            findings.push(finding(SEV.WARNING, 'UDP Shortpath blocked',
                `UDP Shortpath is not available: ${udpReady.resultValue}. The session will use TCP, which is less responsive.`,
                'Open outbound UDP 3478 to turn.azure.com. Check for firewall rules, DPI appliances, or carrier-grade NAT blocking UDP.'));
        }
    }

    // ── 16. RDP traffic routing (Test 26) ──
    const rdpRoute = r('26');
    if (rdpRoute && rdpRoute.status !== 'Passed' && rdpRoute.status !== 'Skipped') {
        findings.push(finding(rdpRoute.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'RDP traffic not routing optimally',
            rdpRoute.resultValue,
            'Verify split tunnelling is configured for W365 endpoints. Check if a proxy is intercepting RDP WebSocket traffic.'));
    }

    // ── 17. Egress analysis (Test 27) ──
    const egress = r('27');
    if (egress && egress.status !== 'Passed' && egress.status !== 'Skipped') {
        if (isSatellite) {
            // Satellite gateway GeoIP is the ground-station location, not the user's physical
            // location. Distance warnings between GPS location and satellite egress are expected.
            findings.push(finding(SEV.INFO, 'Gateway distance — expected on satellite/in-flight WiFi',
                `${egress.resultValue} — On satellite and in-flight internet, traffic exits through the provider's ground station, which may be far from the device's GPS location. This is normal and not a routing problem.`,
                'No action needed. Satellite internet routes through fixed ground stations regardless of aircraft position.'));
        } else {
            // Distinguish two completely different failure modes:
            //   (a) Geographic: gateway is far from egress (real backhaul/VPN hairpin).
            //       Body contains "⚠ Gateway is far".
            //   (b) Constrained access link: gateway is local but the access link is slow
            //       (mobile/transit Wi-Fi, congested home broadband). The "may not be
            //       egressing locally" verdict in older scanner builds could fire on
            //       latency alone — do not parrot that as "split-tunnel" remediation,
            //       since rerouting will make nothing better.
            const detail = (egress.detailedInfo || '');
            const isReallyNonLocal = /⚠\s*Gateway is far/i.test(detail);
            const isLocalGw = /✓\s*Gateway is near your egress location/i.test(detail);
            const bwMbps = bw ? parseMbps(bw.resultValue) : NaN;
            const isConstrainedLink = !isNaN(bwMbps) && bwMbps < 5;

            if (isReallyNonLocal) {
                findings.push(finding(egress.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
                    'Non-local egress detected',
                    `RDP traffic appears to be backhauling: ${egress.resultValue}`,
                    'Configure split tunnelling so W365 traffic exits directly from the user\'s local internet connection.'));
            } else if (isLocalGw && isConstrainedLink) {
                findings.push(finding(SEV.WARNING, 'Constrained access network',
                    `Gateway is geographically local (egress and gateway in the same city) but the access link is the bottleneck (${bwMbps.toFixed(1)} Mbps). This is typical of mobile, transit (train/aircraft) or congested Wi-Fi — rerouting traffic will not improve it.`,
                    'Use a wired or higher-bandwidth Wi-Fi network if available. Avoid bandwidth-heavy background activity during the session.'));
            } else if (isLocalGw) {
                // Gateway local, link not measurably constrained — most likely a transient
                // probe outlier; surface as informational so the user isn't alarmed.
                findings.push(finding(SEV.INFO, 'Gateway local, transient latency observed',
                    `${egress.resultValue} — gateway is geographically adjacent to your egress; latency variance is most likely access-link or path congestion rather than a routing/backhaul problem.`,
                    null));
            } else {
                // Original generic fallback for builds that don't emit the geo markers.
                findings.push(finding(egress.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
                    'Non-local egress detected',
                    `RDP traffic is not egressing locally: ${egress.resultValue}`,
                    'Configure split tunnelling so W365 traffic exits directly from the user\'s local internet connection.'));
            }
        }
    }

    // ── 18. Endpoint reachability ──
    const ep = r('L-EP-01') || r('B-EP-01');
    if (ep && (ep.status === 'Failed' || ep.status === 'Error')) {
        findings.push(finding(SEV.CRITICAL, 'Required endpoints unreachable',
            `One or more required Windows 365 endpoints are not reachable. ${ep.resultValue}`,
            'Check firewall rules, proxy configuration, and DNS resolution. See https://learn.microsoft.com/windows-365/enterprise/requirements-network for the full endpoint list.'));
    } else if (ep && ep.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'Some endpoints have connectivity issues',
            ep.resultValue,
            'Review the detailed endpoint list for timeouts or slow responses. Partial failures can cause intermittent login or session issues.'));
    }

    // ── 19. DNS performance ──
    // Prefer L-TCP-03 (scanner — pure DNS timing); fall back to B-TCP-03 (browser — DNS+TCP+TLS combined)
    const dns = r('L-TCP-03') || r('B-TCP-03');
    const dnsIsPure = !!r('L-TCP-03');
    if (dns) {
        const avg = parseMs(dns.resultValue);
        if (!isNaN(avg) && avg > 1000) {
            findings.push(finding(SEV.CRITICAL, 'Very slow DNS resolution',
                `DNS resolution is averaging ${avg.toFixed(0)} ms${dnsIsPure ? '' : ' (includes TCP+TLS overhead)'} — this delays every new connection and service discovery operation.`,
                'Check DNS server responsiveness. Consider using a faster resolver or reducing DNS chain depth. Verify no DNS sinkhole or inspection is adding delay.'));
        } else if (!isNaN(avg) && avg > 500) {
            findings.push(finding(SEV.WARNING, 'Slow DNS resolution',
                `DNS resolution averaging ${avg.toFixed(0)} ms${dnsIsPure ? '' : ' (includes TCP+TLS overhead)'} — above the 500 ms target.`,
                'Check DNS server load and network path to the resolver.'));
        }
    }

    // ── 20. Teams optimisation ──
    const teams = r('L-LE-09') || r('22');
    if (teams && teams.status !== 'Passed' && teams.status !== 'Skipped') {
        findings.push(finding(SEV.INFO, 'Teams optimisation not configured',
            teams.resultValue,
            'For the best Teams experience in a Cloud PC, enable Teams AV redirection. See https://learn.microsoft.com/windows-365/enterprise/teams-on-cloud-pc'));
    }

    // ── 21. No active session warning ──
    const activeSession = r('17');
    if (activeSession && activeSession.status === 'Warning') {
        findings.push(finding(SEV.INFO, 'No active Cloud PC session detected',
            'Live connection diagnostics (latency, jitter, packet loss) require an active RDP session. Those tests were skipped.',
            'Connect to your Cloud PC via the Windows 365 app or windows365.microsoft.com, then re-run the scan for full analysis.'));
    }

    // ── 22. Frame rate / encoding (Test 19) ──
    const frames = r('19');
    if (frames && (frames.status === 'Warning' || frames.status === 'Failed')) {
        findings.push(finding(frames.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'Frame rate or encoding issues',
            frames.resultValue,
            'High encoding time (>33 ms per frame) indicates GPU or CPU overload on the Cloud PC. Check for GPU driver updates in the Cloud PC, reduce display resolution, or close GPU-intensive applications.'));
    }

    // ── 23. Windows Firewall blocking ──
    const firewall = r('L-LE-10');
    if (firewall && firewall.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'Windows Firewall blocking W365 ports',
            firewall.resultValue,
            firewall.remediationText || 'Review Windows Firewall outbound rules. Ensure TCP 443 and UDP 3478 are not blocked.'));
    }

    // ── 24. RDP Group Policy restrictions ──
    const gpo = r('L-LE-11');
    if (gpo && gpo.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'Restrictive RDP Group Policy detected',
            gpo.resultValue,
            gpo.remediationText || 'Review Terminal Services group policies. Ensure UDP transport is not disabled.'));
    }

    // ── 25. WiFi channel congestion ──
    const wifiCh = r('L-LE-12');
    if (wifiCh && wifiCh.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'WiFi channel congestion',
            wifiCh.resultValue,
            wifiCh.remediationText || 'Switch to 5 GHz band or use a less congested channel. A wired connection eliminates WiFi congestion entirely.'));
    }

    // ═══════════════════════════════════════════════════════════════
    //  Cloud PC server-side rules (C-* tests)
    // ═══════════════════════════════════════════════════════════════

    // CPC-1: RDP egress leaving Azure backbone
    const cpcEgress = r('C-NET-02');
    if (cpcEgress && cpcEgress.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'Cloud PC RDP egress leaving Azure',
            cpcEgress.resultValue || 'RDP traffic from the Cloud PC is routed outside Azure backbone.',
            'Check for VPN/proxy/SWG configuration on the Cloud PC that is routing RDP traffic outside Azure. RDP should stay within the Azure backbone for optimal performance.'));
    } else if (cpcEgress && cpcEgress.status === 'Failed') {
        findings.push(finding(SEV.CRITICAL, 'Cloud PC RDP egress outside Azure',
            cpcEgress.resultValue || 'RDP traffic is leaving the Azure backbone — this adds latency and reduces reliability.',
            'Remove VPN/proxy configuration that routes RDP traffic outside Azure. Configure split tunnelling to exempt RDP destinations.'));
    }

    // CPC-2: TLS inspection on Cloud PC outbound
    const cpcTls = r('C-TCP-06');
    if (cpcTls && (cpcTls.status === 'Warning' || cpcTls.status === 'Failed')) {
        findings.push(finding(SEV.WARNING, 'TLS inspection on Cloud PC',
            'TLS interception detected on the Cloud PC outbound path. This is not supported for RDP connections and degrades performance.',
            'Exempt RDP gateway traffic (*.wvd.microsoft.com) from TLS inspection on any proxy/SWG configured on the Cloud PC.'));
    }

    // CPC-3: Proxy/VPN on Cloud PC affecting RDP
    const cpcProxy = r('C-TCP-07');
    if (cpcProxy && (cpcProxy.status === 'Warning' || cpcProxy.status === 'Failed')) {
        findings.push(finding(SEV.WARNING, 'Proxy/VPN detected on Cloud PC',
            cpcProxy.resultValue || 'A VPN, proxy, or SWG is active on the Cloud PC network path.',
            'If this is Entra Private Access or Zscaler for general traffic, that is expected. Ensure RDP traffic to W365 gateways is excluded.'));
    }

    // CPC-4: DNS hijacking on Cloud PC
    const cpcDns = r('C-TCP-08');
    if (cpcDns && (cpcDns.status === 'Warning' || cpcDns.status === 'Failed')) {
        findings.push(finding(SEV.WARNING, 'DNS hijacking on Cloud PC',
            cpcDns.resultValue || 'DNS resolution on the Cloud PC is being intercepted.',
            'Check the DNS configuration on the Cloud PC virtual network. Ensure it uses Azure DNS or corporate DNS without interception.'));
    }

    // CPC-5: Cloud PC network info — not Microsoft/Azure ISP
    const cpcNet = r('C-LE-02');
    if (cpcNet && cpcNet.status === 'Passed' && cpcNet.resultValue) {
        const orgVal = cpcNet.resultValue.toLowerCase();
        if (!orgVal.includes('microsoft') && !orgVal.includes('azure')) {
            findings.push(finding(SEV.INFO, 'Cloud PC network is not Azure-native',
                `Cloud PC network organization: ${cpcNet.resultValue}. This may indicate the VNet is peered to an external network.`,
                'If this is expected (e.g., ExpressRoute/peering), no action needed. Otherwise verify the Cloud PC virtual network configuration.'));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Cross-rule correlation (only fire when multiple signals align)
    // ═══════════════════════════════════════════════════════════════

    // Correlation 1: Poor WiFi + high gateway latency = WiFi is the bottleneck
    const wifiSig = wifi ? parseSignal(wifi.resultValue) : NaN;
    const gwAvg = gwLat ? parseMs(gwLat.resultValue) : NaN;
    if (!isNaN(wifiSig) && wifiSig < 60 && !isNaN(gwAvg) && gwAvg > 20) {
        findings.push(finding(SEV.CRITICAL, 'WiFi is the network bottleneck',
            `WiFi signal is ${wifiSig}% and gateway latency is ${gwAvg.toFixed(0)} ms. The weak wireless link is adding measurable delay to every Azure round-trip.`,
            'Use a wired Ethernet connection, or move closer to the access point. This will reduce both gateway latency and jitter.'));
    }

    // Correlation 2: Symmetric NAT + TURN unreachable = no UDP path at all
    const natVal = nat ? (nat.resultValue || '').toLowerCase() : '';
    const turnFailed = turnUnreachable;
    if (natVal.includes('symmetric') && turnFailed) {
        findings.push(finding(SEV.CRITICAL, 'No UDP path available',
            'NAT type is Symmetric and TURN relay is unreachable. There is no UDP path — the session will use TCP only, with higher latency and no Shortpath benefit.',
            'Open outbound UDP 3478 to turn.azure.com. If behind CGNAT, contact your ISP. Consider a wired connection that bypasses the NAT.'));
    }

    // Correlation 3: GPO disabling UDP + TCP transport detected = policy-caused TCP fallback
    const gpoUdpDisabled = gpo && gpo.status === 'Warning' && (gpo.resultValue || '').toLowerCase().includes('udp');
    const transportVal = transport ? (transport.resultValue || '').toLowerCase() : '';
    if (gpoUdpDisabled && transportVal.includes('tcp')) {
        findings.push(finding(SEV.CRITICAL, 'Group Policy forcing TCP transport',
            'A Group Policy setting is disabling UDP transport, and the active session is confirmed using TCP. This is a policy-caused degradation.',
            'Remove the fClientDisableUDP=1 or SelectTransport=2 policy. See https://learn.microsoft.com/azure/virtual-desktop/configure-rdp-shortpath'));
    }

    // Correlation 4: High latency + non-local egress = traffic routing issue.
    // Only fire when test 27 actually identified geographic backhaul ("Gateway
    // is far"). Latency on a constrained access link to a geographically local
    // gateway is NOT a routing problem and the split-tunnel remediation will
    // make nothing better — those are surfaced separately above.
    const sessionAvg = session ? parseMs(session.resultValue) : NaN;
    const egressDetail = egress ? (egress.detailedInfo || '') : '';
    const egressIsGeoBackhaul = egress
        && (egress.status === 'Failed' || egress.status === 'Warning')
        && /⚠\s*Gateway is far/i.test(egressDetail);
    if (!isNaN(sessionAvg) && sessionAvg > 100 && egressIsGeoBackhaul) {
        findings.push(finding(SEV.CRITICAL, 'High latency due to non-local egress',
            `Session latency is ${sessionAvg.toFixed(0)} ms and RDP traffic is backhauling through a remote gateway. The indirect routing path is adding significant delay.`,
            'Configure split tunnelling so W365 traffic exits directly from the user\'s local internet connection.'));
    }

    // Correlation 5: Firewall blocking UDP 3478 + TURN unreachable
    const fwBlocksUdp = firewall && firewall.status === 'Warning' && (firewall.resultValue || '').includes('3478');
    if (fwBlocksUdp && turnFailed) {
        findings.push(finding(SEV.CRITICAL, 'Local firewall blocking TURN relay',
            'Windows Firewall has an outbound rule blocking UDP 3478, and TURN relay is unreachable. The local firewall is the root cause.',
            'Remove or disable the outbound firewall rule blocking UDP 3478. Run: netsh advfirewall firewall add rule name="Allow W365 TURN" dir=out action=allow protocol=UDP remoteport=3478'));
    }

    // Correlation 6: Client gateway mismatch vs Cloud PC gateway
    const clientGw = r('L-TCP-09');
    const cpcGw = r('C-TCP-09');
    if (clientGw && cpcGw && clientGw.status === 'Passed' && cpcGw.status === 'Passed') {
        const clientGwVal = (clientGw.resultValue || '').toLowerCase();
        const cpcGwVal = (cpcGw.resultValue || '').toLowerCase();
        if (clientGwVal && cpcGwVal && clientGwVal !== cpcGwVal) {
            findings.push(finding(SEV.INFO, 'Different gateways for Client and Cloud PC',
                `Client connects to: ${clientGw.resultValue}\nCloud PC connects to: ${cpcGw.resultValue}\nThis is expected if they are in different regions.`,
                null));
        }
    }

    // Correlation 7: Both client and Cloud PC have proxy/VPN
    const clientProxy = r('L-TCP-07');
    if (clientProxy && cpcProxy && clientProxy.status !== 'Passed' && cpcProxy.status !== 'Passed') {
        findings.push(finding(SEV.WARNING, 'Proxy/VPN on both client and Cloud PC',
            'Both the client device and the Cloud PC have proxy or VPN detected. This means RDP traffic traverses two proxy layers, doubling overhead.',
            'Review if both proxies are necessary. Typically only the client side needs web filtering — the Cloud PC should have direct Azure network access.'));
    }

    // Correlation 8: DNS resolver region mismatch — corporate DNS in a different region
    // The client resolves world.relay.avd.microsoft.com via ATM for ICE candidate gathering,
    // but the actual session TURN relay is assigned by the RDP gateway via CRLB anycast.
    // A DNS mismatch indicates non-local DNS but does not affect session TURN relay selection.
    const userLoc = r('B-LE-01') || r('L-LE-01');
    const adapters = r('L-LE-06');
    const turnLoc = r('L-UDP-04');
    if (userLoc && adapters && adapters.detailedInfo) {
        const userCountry = ((userLoc.resultValue || '').match(/,\s*([A-Z]{2})\s*$/i) || [])[1];
        // Extract DNS server hostnames from adapter details
        const dnsHostnames = (adapters.detailedInfo.match(/\(([^)]*\.internal[^)]*)\)/gi) || [])
            .map(m => m.replace(/[()]/g, '').trim());
        if (userCountry && dnsHostnames.length > 0) {
            // Check if DNS hostname contains a country/region code that differs from user location
            const dnsRegionHints = dnsHostnames.map(h => {
                const parts = h.toLowerCase().split('.');
                // Look for segments like "uk1", "us2", "eu1", "ap1" etc.
                return parts.find(p => /^(uk|us|eu|ap|jp|au|de|fr|nl|sg|in|br|za|ae|ca|kr)\d*$/.test(p));
            }).filter(Boolean);
            if (dnsRegionHints.length > 0) {
                const userCC = userCountry.toLowerCase();
                const DNS_CC_MAP = {'uk':'gb','us':'us','eu':'eu','ap':'sg','jp':'jp','au':'au','de':'de',
                                    'fr':'fr','nl':'nl','sg':'sg','in':'in','br':'br','za':'za','ae':'ae',
                                    'ca':'ca','kr':'kr'};
                const dnsRegion = dnsRegionHints[0].replace(/\d+$/, '');
                const dnsCC = DNS_CC_MAP[dnsRegion] || dnsRegion;
                // Simple mismatch: DNS region code doesn't match user country
                const isMismatch = dnsCC !== userCC &&
                    !(dnsCC === 'eu' && ['gb','de','fr','nl','ie','be','at','ch','se','no','dk','fi','es','it','pt','pl','cz'].includes(userCC));
                if (isMismatch) {
                    const dnsNames = dnsHostnames.slice(0, 2).join(', ');
                    findings.push(finding(SEV.WARNING,
                        'DNS servers are in a different region from user',
                        `Your DNS servers (${dnsNames}) appear to be in the "${dnsRegion.toUpperCase()}" region, but you are located in ${userCountry}. `
                        + 'Client DNS resolves world.relay.avd.microsoft.com via Azure Traffic Manager, which returns a TURN relay based on DNS resolver location. '
                        + 'However, the actual RDP session TURN relay is assigned by the RDP gateway via CRLB anycast routing based on network proximity — not client DNS. '
                        + 'This DNS mismatch does not affect session quality, but indicates your DNS resolvers are not local to the user.',
                        'This is informational — session TURN relay selection is not affected. If other ATM-routed services are impacted, consider using DNS resolvers local to the user, or public resolvers with EDNS Client Subnet support.'));
                }
            }
        }
    }

    // Correlation 9: Scanner vs browser TURN relay region mismatch
    // The scanner uses OS DNS (may go through VPN/corporate DNS) while the browser
    // uses the SWG/local DNS. If they get different TURN regions, DNS routing is split.
    const browserTurnRoute = r('B-TCP-04');
    if (turnLoc && browserTurnRoute && turnLoc.status === 'Passed') {
        const scannerTurnVal = (turnLoc.resultValue || '').toLowerCase();
        const browserDetail = (browserTurnRoute.detailedInfo || '').toLowerCase();
        // Extract TURN relay region from browser DNS chain (e.g. "southindia.cloudapp.azure.com")
        const browserTurnMatch = browserDetail.match(/turn relay[\s\S]*?([\w]+)\.cloudapp\.azure\.com/);
        const scannerRegionMatch = scannerTurnVal.match(/(\w+)\s*\(/); // e.g. "UK South (uksouth)"
        if (browserTurnMatch && scannerRegionMatch) {
            const browserRegion = browserTurnMatch[1].toLowerCase();
            const scannerRegion = scannerTurnVal;
            // Check if they reference different Azure regions
            if (!scannerRegion.includes(browserRegion)) {
                findings.push(finding(SEV.WARNING,
                    'TURN relay differs between scanner and browser',
                    `Scanner resolved TURN relay to: ${turnLoc.resultValue}\n`
                    + `Browser resolved TURN relay to: ${browserRegion} region\n`
                    + 'This happens when the scanner uses corporate DNS (via VPN) while the browser resolves via a local SWG/proxy. '
                    + 'However, the actual RDP session TURN relay is assigned by the RDP gateway via CRLB anycast — not by client DNS resolution. '
                    + 'This mismatch indicates different DNS paths but does not affect session TURN relay selection.',
                    'This is informational. The session TURN relay is correctly assigned regardless of client DNS. The mismatch indicates different DNS resolver paths between the scanner (OS DNS) and browser (SWG/local DNS).'));
            }
        }
    }

    // Correlation 10: TLS inspection + specific proxy vendor correlation
    // Only fires when the TLS test ITSELF reports inspection (resultValue
    // contains "TLS inspection detected") OR the cert-chain detail names a
    // SWG vendor. Previously this would fire on any non-Passed TLS test
    // combined with a vendor name in the ISP string, which mis-attributed
    // unrelated TLS handshake failures (port blocks, expired certs, timeouts)
    // as vendor-driven SSL inspection.
    const browserIsp = r('B-LE-02');
    const tlsTestsAll = [r('L-TCP-06'), r('L-UDP-06'), r('25')].filter(Boolean);
    const tlsInspected = tlsTestsAll.filter(t => {
        const rv = (t.resultValue || '').toLowerCase();
        return rv.includes('tls inspection detected') || rv.includes('tls-intercept');
    });
    if (tlsInspected.length > 0) {
        const ispVal = (browserIsp && browserIsp.resultValue || '').toLowerCase();
        const allTlsDetail = tlsInspected.map(t => (t.detailedInfo || t.resultValue || '')).join(' ').toLowerCase();
        const vendorMap = {
            'zscaler':   { name: 'Zscaler',   guide: 'In ZIA, go to Administration > SSL Inspection Policy, add *.wvd.microsoft.com and *.avd.microsoft.com to the bypass list. Also bypass 40.64.144.0/20 and 51.5.0.0/16 by destination IP. See: https://techcommunity.microsoft.com/discussions/windows365discussions/optimizing-rdp-connectivity-for-windows-365/3554327' },
            'netskope':  { name: 'Netskope',  guide: 'In the Netskope admin console, add *.wvd.microsoft.com and *.avd.microsoft.com to the SSL Do Not Decrypt policy. Bypass 40.64.144.0/20 and 51.5.0.0/16.' },
            'palo alto': { name: 'Palo Alto', guide: 'In Panorama/Prisma Access, add *.wvd.microsoft.com and *.avd.microsoft.com to the SSL Decryption exclusion list. Bypass 40.64.144.0/20 and 51.5.0.0/16.' },
            'forcepoint':{ name: 'Forcepoint',guide: 'Add *.wvd.microsoft.com and *.avd.microsoft.com to the SSL inspection bypass list in your Forcepoint policy. Bypass 40.64.144.0/20 and 51.5.0.0/16.' }
        };
        // Prefer evidence found IN the cert chain (allTlsDetail) over the ISP
        // hint, which only proves the vendor handles the IP-info HTTPS request.
        const vendorInChain = Object.keys(vendorMap).find(v => allTlsDetail.includes(v));
        const vendorInIsp = Object.keys(vendorMap).find(v => ispVal.includes(v));
        const detectedVendor = vendorInChain || vendorInIsp;
        if (detectedVendor) {
            const vendor = vendorMap[detectedVendor];
            // Only state the vendor *is* inspecting RDP when the vendor's name
            // appears in the actual intercepted certificate chain. If we only
            // saw the vendor in B-LE-02 (ISP string), that proves the HTTPS
            // egress path goes via that vendor's PoP — it does NOT prove that
            // vendor is the one re-signing the RDP TLS handshake. Title must
            // match the strength of the underlying signal.
            const evidenceNote = vendorInChain
                ? `${vendor.name} appears in the intercepted certificate chain.`
                : `The TLS test detected interception; ${vendor.name} is on the HTTPS egress path (B-LE-02). Vendor attribution is inferred from the ISP string, not proven by the certificate chain — the inspector could be a different device on the path.`;
            const title = vendorInChain
                ? `${vendor.name} is TLS-inspecting W365 RDP traffic`
                : `Possible TLS inspection by ${vendor.name} (vendor inferred from ISP)`;
            findings.push(finding(SEV.CRITICAL,
                title,
                `${evidenceNote} Microsoft does not support TLS inspection of RDP traffic — it adds latency and jitter with no security benefit, since RDP uses nested TLS encryption.`,
                vendor.guide));
        } else {
            // TLS inspection confirmed but vendor unidentified — still surface it
            findings.push(finding(SEV.CRITICAL,
                'TLS inspection of W365 RDP traffic detected',
                'A TLS-intercepting proxy is re-signing certificates for Windows 365 gateway and/or TURN relay connections. The specific vendor could not be identified from the certificate chain.',
                'Identify the inspection device and add *.wvd.microsoft.com, *.infra.windows365.microsoft.com and turn.azure.com to its SSL bypass list.'));
        }
    }

    // Correlation 11: Gateway region instability (multiple different gateways in one scan)
    const gwTests = ['L-TCP-04', 'L-TCP-05', 'L-TCP-06', 'L-TCP-08', 'L-TCP-09', '18', '20', '21']
        .map(id => r(id)).filter(Boolean);
    const gwRegions = new Set();
    for (const t of gwTests) {
        const combined = ((t.resultValue || '') + ' ' + (t.detailedInfo || '')).toLowerCase();
        // Match gateway FQDN patterns like rdgateway-c210-SIN-r1 or region codes in parens
        const fqdnMatches = combined.match(/rdgateway-\w+-(\w+)-r\d/g) || [];
        for (const m of fqdnMatches) {
            const region = m.match(/rdgateway-\w+-(\w+)-r\d/)[1].toUpperCase();
            gwRegions.add(region);
        }
    }
    if (gwRegions.size > 1) {
        const regions = [...gwRegions].join(', ');
        findings.push(finding(SEV.INFO,
            `Multiple gateway regions detected (${regions})`,
            `During this scan, Azure Front Door routed to ${gwRegions.size} different gateway regions: ${regions}. `
            + 'This is normal AFD load-balancing behaviour — AFD may distribute requests across nearby backend regions. '
            + 'If one region is significantly farther than others, check that your egress location is consistent during the scan.',
            null));
    }

    // Correlation 12: SASE-specific remediation when detected as ISP
    // Combines three independent signals so the verdict reflects what the tool
    // actually observed about RDP traffic, not just an ISP string match:
    //   (a) B-LE-02 — browser ISP/ASN string (HTTPS egress only)
    //   (b) L-TCP-07 — local route-table inspection of 40.64.144.0/20 and
    //       51.5.0.0/16 plus the resolved RDP gateway IP. This is authoritative
    //       for "does the SASE client's tunnel adapter capture RDP?"
    //   (c) L-TCP-06 / L-UDP-06 / 25 — TLS chain on RDP endpoints. A clean
    //       Microsoft chain proves SSL inspection is NOT decrypting RDP.
    if (browserIsp && browserIsp.status === 'Passed') {
        const ispVal = (browserIsp.resultValue || '').toLowerCase();
        const saseVendors = {
            'zscaler':    { name: 'Zscaler' },
            'netskope':   { name: 'Netskope' },
            'cloudflare': { name: 'Cloudflare Gateway' }
        };
        const detectedSase = Object.keys(saseVendors).find(v => ispVal.includes(v));
        if (detectedSase) {
            const sase = saseVendors[detectedSase];
            // Skip if a TLS-inspection finding for this vendor already fired (Correlation 10)
            const alreadyFlagged = findings.some(f => f.title.toLowerCase().includes(sase.name.toLowerCase()) && f.severity === 'critical');
            if (!alreadyFlagged) {
                // Authoritative signal: route-table evidence from L-TCP-07
                const proxyVpn = r('L-TCP-07');
                const pvDetail = ((proxyVpn && (proxyVpn.detailedInfo || proxyVpn.resultValue)) || '');
                const tunnelCarriesRdp = /VPN tunnel is carrying W365\/AVD traffic|RDP gateway [^\n]+ routes via VPN interface/i.test(pvDetail);
                const tunnelBypassesRdp = /No W365\/AVD service traffic goes through the VPN tunnel|RDP gateway [^\n]+ routes direct via|VPN is active but RDP traffic correctly bypasses it|Split-tunnelled \(direct\)/i.test(pvDetail);

                // Corroborating signal: TLS chains on RDP endpoints
                const rdpTlsTests = [r('L-TCP-06'), r('L-UDP-06'), r('25')].filter(Boolean);
                const rdpTlsClean = rdpTlsTests.length > 0 && rdpTlsTests.every(t => t.status === 'Passed');

                let title, severity, detail;
                const recommend = 'See https://learn.microsoft.com/windows-365/enterprise/optimization-of-rdp for full RDP optimization guidance.';

                if (tunnelCarriesRdp) {
                    // Definitive: route table shows the SASE adapter capturing W365 ranges
                    severity = SEV.CRITICAL;
                    title = `${sase.name} tunnel is carrying Windows 365 RDP traffic`;
                    detail = `The local routing table shows W365/AVD ranges (40.64.144.0/20 and/or 51.5.0.0/16) or the resolved RDP gateway IP routing through the ${sase.name} tunnel adapter. `
                        + 'RDP traffic should bypass SASE tunnels — tunneling adds latency and can break UDP/3478 transport. '
                        + 'See L-TCP-07 details for the exact routes observed.';
                } else if (tunnelBypassesRdp && rdpTlsClean) {
                    // Definitive: routes direct AND TLS chain on RDP endpoints is unmodified Microsoft
                    severity = SEV.INFO;
                    title = `${sase.name} detected, but RDP traffic bypasses it correctly`;
                    detail = `${sase.name} is on your HTTPS egress path (resolved as ISP via B-LE-02), but the local routing table (L-TCP-07) shows W365/AVD ranges and the RDP gateway routing direct, and TLS chains on RDP endpoints are unmodified Microsoft certificates. `
                        + 'This is the supported configuration: SASE for general internet, direct egress for RDP.';
                } else if (tunnelBypassesRdp) {
                    // Routes direct, but TLS evidence inconclusive
                    severity = SEV.INFO;
                    title = `${sase.name} detected; RDP appears to route direct`;
                    detail = `${sase.name} is on your HTTPS egress path. The local routing table (L-TCP-07) shows W365/AVD ranges and the RDP gateway routing outside the ${sase.name} tunnel adapter, which indicates correct bypass for the route-table layer. `
                        + 'TLS chain corroboration on RDP endpoints was inconclusive (some checks did not pass) — verify L-TCP-06 / L-UDP-06 separately to rule out inline SSL inspection.';
                } else {
                    // No L-TCP-07 evidence (test missing or didn't run) — fall back to verification prompt
                    severity = SEV.INFO;
                    title = `${sase.name} detected as network proxy`;
                    detail = `${sase.name} resolved as your ISP (B-LE-02), meaning at least your HTTPS traffic to the IP-info service exited via a ${sase.name} PoP. `
                        + 'The route-table check (L-TCP-07) did not produce a definitive verdict on RDP, so verify manually: '
                        + '(1) RDP traffic (40.64.144.0/20 TCP/443, 51.5.0.0/16 UDP/3478) is in the bypass/direct policy, '
                        + '(2) SSL inspection is disabled for *.wvd.microsoft.com and *.avd.microsoft.com, '
                        + '(3) DNS for *.avd.microsoft.com resolves at the local PoP (not a remote corporate resolver).';
                }

                findings.push(finding(severity, title, detail, recommend));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Session Quality Score (0-100)
    // ═══════════════════════════════════════════════════════════════
    const qualityScore = computeQualityScore(results);

    // ── 26. Overall health summary (always add) ──
    const failed = results.filter(x => x.status === 'Failed' || x.status === 'Error').length;
    const warned = results.filter(x => x.status === 'Warning').length;
    const passed = results.filter(x => x.status === 'Passed').length;
    const total = results.length;

    if (failed === 0 && warned === 0) {
        findings.push(finding(SEV.INFO, 'All tests passed',
            `${passed} of ${total} tests passed with no warnings or failures. Your connectivity to Windows 365 looks healthy.`,
            null));
    }

    // Sort: critical first, then warning, then info
    const order = { critical: 0, warning: 1, info: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);

    return { findings, qualityScore };
}

// ═══════════════════════════════════════════════════════════════════
//  Session Quality Score — weighted 0-100
// ═══════════════════════════════════════════════════════════════════
function computeQualityScore(results) {
    const r = id => results.find(x => x.id === id);
    let score = 100;
    // A confident numeric score requires at least one SESSION-QUALITY signal
    // that actually reflects the WAN/RDP path: round-trip latency (18), jitter
    // (20), packet loss (21) or the negotiated transport (17b). Gateway latency
    // (L-LE-05) is LAN-LOCAL only — on a browser-only run it measures the hop to
    // the local router (e.g. 8 ms to a travel router) and says NOTHING about an
    // 800 ms satellite WAN path. Scoring "Good / 100" off the LAN hop alone is
    // misleading, so gateway latency may ADJUST the score but can never be the
    // sole basis for asserting one.
    let hasSessionData = false;

    // Latency (weight: 35 points)
    const session = r('18');
    if (session) {
        const avg = parseMs(session.resultValue);
        if (!isNaN(avg)) {
            hasSessionData = true;
            if (avg > 200) score -= 35;
            else if (avg > 150) score -= 25;
            else if (avg > 100) score -= 15;
            else if (avg > 50) score -= 5;
        }
    }

    // Jitter (weight: 20 points)
    const jitter = r('20');
    if (jitter) {
        const j = parseMs(jitter.resultValue);
        if (!isNaN(j)) {
            hasSessionData = true;
            if (j > 60) score -= 20;
            else if (j > 30) score -= 12;
            else if (j > 15) score -= 5;
        }
    }

    // Packet loss (weight: 25 points)
    const loss = r('21');
    if (loss) {
        const pct = parsePct(loss.resultValue);
        if (!isNaN(pct)) {
            hasSessionData = true;
            if (pct > 15) score -= 25;
            else if (pct > 5) score -= 15;
            else if (pct > 1) score -= 5;
        }
    }

    // Transport protocol (weight: 10 points)
    const transport = r('17b');
    if (transport) {
        hasSessionData = true;
        const val = (transport.resultValue || '').toLowerCase();
        if (val.includes('tcp')) score -= 10;
    }

    // Gateway latency (weight: 10 points — local network health).
    // Adjusts the score but does NOT, on its own, qualify as session data.
    const gw = r('L-LE-05');
    if (gw) {
        const avg = parseMs(gw.resultValue);
        if (!isNaN(avg)) {
            if (avg > 50) score -= 10;
            else if (avg > 20) score -= 5;
        }
    }

    return { score: Math.max(0, score), hasData: hasSessionData };
}

// ═══════════════════════════════════════════════════════════════════
//  UI: render analysis panel
// ═══════════════════════════════════════════════════════════════════
function launchAiAnalysis() {
    if (!allResults || allResults.length === 0) {
        alert('No test results available. Run tests or import scanner results first.');
        return;
    }

    const { findings, qualityScore } = runAnalysisEngine(allResults);
    showAnalysisPanel(findings, qualityScore);
}

function showAnalysisPanel(findings, qualityScore) {
    // Remove any existing panel
    const existing = document.getElementById('analysis-panel-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'analysis-panel-overlay';
    overlay.className = 'analysis-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) closeAnalysisPanel(); };

    const criticals = findings.filter(f => f.severity === 'critical');
    const warnings = findings.filter(f => f.severity === 'warning');
    const infos = findings.filter(f => f.severity === 'info');

    const sevIcon = (sev) => {
        switch (sev) {
            case 'critical': return '<span class="analysis-icon analysis-icon-critical">\u2718</span>';
            case 'warning':  return '<span class="analysis-icon analysis-icon-warning">\u26A0</span>';
            case 'info':     return '<span class="analysis-icon analysis-icon-info">\u2139</span>';
        }
    };

    const renderFinding = (f) => {
        const remHtml = f.remediation
            ? `<div class="analysis-remediation"><strong>Recommendation:</strong> ${escapeHtml(f.remediation)}</div>`
            : '';
        return `
            <div class="analysis-finding analysis-finding-${f.severity}">
                <div class="analysis-finding-header">
                    ${sevIcon(f.severity)}
                    <span class="analysis-finding-title">${escapeHtml(f.title)}</span>
                </div>
                <div class="analysis-finding-detail">${escapeHtml(f.detail)}</div>
                ${remHtml}
            </div>`;
    };

    // Summary badge counts
    const summaryHtml = `
        <div class="analysis-summary">
            ${criticals.length > 0 ? `<span class="analysis-badge badge-critical">${criticals.length} Critical</span>` : ''}
            ${warnings.length > 0 ? `<span class="analysis-badge badge-warning">${warnings.length} Warning${warnings.length > 1 ? 's' : ''}</span>` : ''}
            ${infos.length > 0 ? `<span class="analysis-badge badge-info">${infos.length} Info</span>` : ''}
            ${criticals.length === 0 && warnings.length === 0 ? '<span class="analysis-badge badge-healthy">\u2714 Healthy</span>' : ''}
        </div>`;

    const findingsHtml = findings.map(renderFinding).join('');

    // Quality score ring HTML
    let qualityHtml = '';
    if (qualityScore && qualityScore.hasData) {
        const s = qualityScore.score;
        // Label is gated by both score and the presence of analysis findings,
        // so a perfect numeric score on the session metrics doesn't read
        // "Good" while scanner-side warnings (driver age, MTU, etc.) sit
        // unacknowledged in the same panel.
        const hasCriticals = findings.some(f => f.severity === SEV.CRITICAL);
        const hasWarnings = findings.some(f => f.severity === SEV.WARNING);
        let label;
        if (s >= 95 && !hasCriticals && !hasWarnings) label = 'Excellent';
        else if (s >= 80 && !hasCriticals) label = 'Good';
        else if (s >= 50 && !hasCriticals) label = 'Fair';
        else label = 'Poor';
        const color = label === 'Excellent' ? '#10b981'
                    : label === 'Good'      ? '#22c55e'
                    : label === 'Fair'      ? '#eab308'
                    :                          '#ef4444';
        const radius = 54;
        const circumference = 2 * Math.PI * radius;
        const dashoffset = circumference - (s / 100) * circumference;
        qualityHtml = `
            <div class="quality-score-section">
                <div class="quality-ring">
                    <svg width="128" height="128" viewBox="0 0 128 128">
                        <circle class="quality-ring-bg" cx="64" cy="64" r="${radius}" />
                        <circle class="quality-ring-fg" cx="64" cy="64" r="${radius}"
                            stroke="${color}"
                            stroke-dasharray="${circumference}"
                            stroke-dashoffset="${dashoffset}"
                            transform="rotate(-90 64 64)" />
                    </svg>
                    <div class="quality-ring-text" style="color:${color}">${s}</div>
                </div>
                <div class="quality-label">${label}</div>
                <div class="quality-sublabel">Session Quality Score</div>
            </div>`;
    }

    overlay.innerHTML = `
        <div class="analysis-panel">
            <div class="analysis-panel-header">
                <div class="analysis-panel-title">
                    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                        <path d="M9 1L1 5l8 4 8-4-8-4z" stroke="currentColor" stroke-width="1.4" fill="none"/>
                        <path d="M1 13l8 4 8-4M1 9l8 4 8-4" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                    </svg>
                    Connectivity Analysis
                </div>
                <button class="analysis-close" onclick="closeAnalysisPanel()" title="Close">\u2715</button>
            </div>
            ${qualityHtml}
            ${summaryHtml}
            <div class="analysis-findings">
                ${findingsHtml}
            </div>
            <div class="analysis-copilot">
                <div class="analysis-copilot-info">
                    <strong>Want deeper analysis?</strong> Copy the full diagnostic report and paste into Microsoft Copilot for AI-powered root-cause analysis.
                </div>
                <button class="btn btn-ai" onclick="copilotAnalysis(this)">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="1.8" fill="none"/><path d="M12 8v4l3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    Copy &amp; Open Copilot
                </button>
            </div>
            <div class="analysis-footer">
                <button class="btn btn-secondary" onclick="copyAnalysisText()">Copy as Text</button>
                <button class="btn btn-secondary" onclick="closeAnalysisPanel()">Close</button>
            </div>
        </div>`;

    document.body.appendChild(overlay);

    // Animate in
    requestAnimationFrame(() => {
        overlay.classList.add('show');
    });
}

function closeAnalysisPanel() {
    const overlay = document.getElementById('analysis-panel-overlay');
    if (overlay) {
        overlay.classList.remove('show');
        setTimeout(() => overlay.remove(), 300);
    }
}

function copyAnalysisText() {
    const { findings } = runAnalysisEngine(allResults);
    const lines = findings.map(f => {
        const sev = f.severity.toUpperCase();
        let text = `[${sev}] ${f.title}\n${f.detail}`;
        if (f.remediation) text += `\nRecommendation: ${f.remediation}`;
        return text;
    });
    const fullText = `W365 Connectivity Analysis \u2014 ${new Date().toLocaleString()}\n${'='.repeat(50)}\n\n${lines.join('\n\n')}`;

    navigator.clipboard.writeText(fullText).then(() => {
        const btn = document.querySelector('.analysis-footer .btn-secondary');
        if (btn) { const orig = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = orig, 1500); }
    }).catch(() => {});
}

// ═══════════════════════════════════════════════════════════════════
//  Copilot integration: copy full report + instructions, open Copilot
// ═══════════════════════════════════════════════════════════════════
async function copilotAnalysis(btn) {
    if (!allResults || allResults.length === 0) return;

    // Show generating state
    const origHtml = btn.innerHTML;
    btn.innerHTML = 'Generating report...';
    btn.disabled = true;

    try {
        // Build the full export text (same as Export Text button)
        const exportText = await generateExportText();

        // Prepend Copilot instructions
        const instructions = [
            'I ran a Windows 365 / Azure Virtual Desktop connectivity scan from my physical device.',
            'Please analyse the full diagnostic report below and provide:',
            '1. Root-cause analysis of any failures or warnings',
            '2. Specific remediation steps (commands, settings, registry keys where applicable)',
            '3. Whether the issue is at the client, local network, ISP, or Azure edge',
            'Only highlight issues you have high confidence on based on the data. Do not guess or speculate about what might be wrong.',
            'Be concise but thorough. Reference Microsoft Learn docs where helpful.',
            '',
            '---',
            ''
        ].join('\n');

        const prompt = instructions + exportText;

        await navigator.clipboard.writeText(prompt);
        btn.innerHTML = '\u2714 Copied! Paste into Copilot with Ctrl+V';
        btn.classList.add('btn-copied');
        btn.disabled = false;
        setTimeout(() => {
            btn.innerHTML = origHtml;
            btn.classList.remove('btn-copied');
        }, 4000);
        setTimeout(() => {
            window.open('https://copilot.microsoft.com/', '_blank', 'noopener,noreferrer');
        }, 600);
    } catch (e) {
        btn.innerHTML = origHtml;
        btn.disabled = false;
        // Clipboard failed — build a fallback prompt
        const exportText = await generateExportText();
        const instructions = 'I ran a Windows 365 connectivity scan. Please analyse the report below and provide root-cause analysis and remediation steps.\n\n---\n\n';
        showPromptModal(instructions + exportText);
    }
}

function showPromptModal(prompt) {
    const overlay = document.createElement('div');
    overlay.className = 'analysis-overlay show';
    overlay.style.zIndex = '10001';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    overlay.innerHTML = `
        <div class="analysis-panel" style="transform:translateX(0)">
            <div class="analysis-panel-header">
                <div class="analysis-panel-title">Copy Prompt for Copilot</div>
                <button class="analysis-close" onclick="this.closest('.analysis-overlay').remove()" title="Close">\u2715</button>
            </div>
            <p style="padding:16px 24px;color:var(--text-secondary);font-size:13px;margin:0">
                Clipboard access was blocked. Select all text below (Ctrl+A), copy it (Ctrl+C),
                then paste it into <a href="https://copilot.microsoft.com/" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">Microsoft Copilot</a>.
            </p>
            <textarea readonly style="flex:1;margin:0 24px 16px;padding:12px;background:var(--bg-surface);color:var(--text-primary);border:1px solid var(--border-default);border-radius:var(--r-sm);font-family:monospace;font-size:12px;resize:none;box-sizing:border-box"></textarea>
            <div class="analysis-footer">
                <button class="btn btn-ai" onclick="window.open('https://copilot.microsoft.com/','_blank','noopener,noreferrer');this.closest('.analysis-overlay').remove()">Open Copilot</button>
            </div>
        </div>`;

    document.body.appendChild(overlay);
    // Populate the textarea via .value so the browser's text node handling
    // guarantees safety regardless of prompt content. Previously we used
    // innerHTML interpolation with a partial < -> &lt; escape which missed
    // & and was inconsistent with the rest of the file's escaping.
    const ta = overlay.querySelector('textarea');
    if (ta) ta.value = prompt;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
