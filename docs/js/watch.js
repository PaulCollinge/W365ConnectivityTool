// ─────────────────────────────────────────────────────────────────────────────
//  Session Watch view  (docs/js/watch.js)
//
//  Renders a completed continuous-monitoring capture produced by the scanner's
//  `--watch` mode (WatchOutput JSON). Delivered as an ISOLATED DOM island so it
//  never touches the snapshot import / Cloud-PC bootstrap path in app.js:
//    • The scanner opens  ...?view=watch#zwatch=<deflate-raw base64url>
//    • An early inline script in index.html adds `html.watch-mode` (pre-paint),
//      which hides <main> and shows #watch-view via CSS (no flash).
//    • This module decodes the payload and renders it.
//    • Dragging a W365WatchTimeline.json onto the page also routes here
//      (app.js detects type:"watch-timeline" and calls renderWatchTimeline).
//
//  The dashboard is a PURE RENDERER of scanner-authoritative data: the verdict,
//  summary and per-event findings come straight from the WatchOutput. We never
//  re-threshold the samples to invent our own verdict — threshold guide-lines on
//  the sparklines are cosmetic only; anomaly bands are positioned from the
//  scanner's events[] (elapsedSeconds + track + severity).
// ─────────────────────────────────────────────────────────────────────────────
(function () {
    'use strict';

    // Visual track definitions. `warn`/`bad` drive only the cosmetic threshold
    // guide-line and the "now" value colour — NOT the verdict (which is the
    // scanner's). `evTracks` lists the scanner event.track names that map here.
    const TRACKS = [
        { id: 'rtt',   t: 'Gateway RTT',      s: 'rdgateway · TCP 443',   unit: 'ms', key: 'gatewayRttMs', warn: 120, bad: 250, evTracks: ['gatewayRtt'], fmt: v => Math.round(v) },
        { id: 'jit',   t: 'Jitter',           s: 'TURN relay · variance', unit: 'ms', key: 'jitterMs',     warn: 30,  bad: 50,  evTracks: ['jitter'],     fmt: v => Math.round(v) },
        { id: 'loss',  t: 'UDP loss',         s: 'TURN relay · 3478',     unit: '%',  key: 'lossPct',      warn: 2,   bad: 5,   evTracks: ['loss'],       fmt: v => (v != null ? v.toFixed(1) : '—') },
        { id: 'dns',   t: 'DNS resolve',      s: 'OS resolver',           unit: 'ms', key: 'dnsMs',        warn: 300, bad: 800, evTracks: ['dns'],        fmt: v => Math.round(v) },
        { id: 'route', t: 'Route-table hash', s: 'W365 prefixes · LPM',   unit: '',   key: 'routeHash',    isRoute: true,  evTracks: ['route'] },
        { id: 'egr',   t: 'Egress IP',        s: 'public reflexive',      unit: '',   key: 'egressIp',     isEgress: true, evTracks: ['egress'] },
    ];

    const SEV_CLASS = { critical: 'bad', warning: 'warn', info: 'info' };

    let _rendered = false;

    // ── Entry points ──────────────────────────────────────────────────────────

    // True only when an actual watch PAYLOAD is in the URL. A bare ?view=watch
    // (e.g. a refreshed/bookmarked link after the payload was stripped) is NOT a
    // watch URL — it must fall through to the snapshot so the default view is
    // never locked out.
    function isWatchUrl() {
        try {
            const params = new URLSearchParams(window.location.search);
            const hash = window.location.hash || '';
            return params.has('zwatch')
                || hash.indexOf('#zwatch=') === 0;
        } catch { return false; }
    }

    async function initWatchFromUrl() {
        if (!isWatchUrl()) return;
        // Make sure the snapshot UI is hidden even if the early class wasn't set.
        document.documentElement.classList.add('watch-mode');

        let raw = null;
        try {
            const params = new URLSearchParams(window.location.search);
            const hash = window.location.hash || '';
            if (params.has('zwatch')) raw = params.get('zwatch');
            else if (hash.indexOf('#zwatch=') === 0) raw = hash.substring('#zwatch='.length);
        } catch { /* ignore */ }

        if (!raw) { renderWatchError('No watch data found in the link. Drag W365WatchTimeline.json onto this page.'); return; }

        try {
            // Reuse app.js's hardened decoder (deflate-raw + zip-bomb guards).
            const output = await decodeCompressedHash(raw);
            // Strip the payload AND the view=watch param from the URL. Leaving
            // view=watch behind would mean a refresh/bookmark lands on a watch URL
            // with no data and shows an error instead of the snapshot. A clean URL
            // means a refresh returns to the default snapshot view.
            history.replaceState(null, '', window.location.pathname);
            renderWatchTimeline(output);
        } catch (e) {
            renderWatchError('Could not read the watch link: ' + (e && e.message ? e.message : e)
                + '. Drag W365WatchTimeline.json onto this page instead.');
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    function renderWatchTimeline(output) {
        if (!output || typeof output !== 'object') { renderWatchError('Empty watch data.'); return; }
        const samples = Array.isArray(output.samples) ? output.samples : [];
        const events  = Array.isArray(output.events)  ? output.events  : [];

        document.documentElement.classList.add('watch-mode');
        const host = document.getElementById('watch-view');
        if (!host) return;
        host.hidden = false;
        showTabs('watch');

        const lastEl = samples.length ? (samples[samples.length - 1].elapsedSeconds || 0) : 0;
        const reqDur = output.requestedDurationSeconds || 0;

        host.innerHTML = `
          <div class="watch-wrap">
            <div class="watch-head">
              <div>
                <h2><span class="watch-ico">◷</span> Session Watch</h2>
                <p class="watch-sub">Continuous capture of the transport-sensitive probes over time — surfacing the
                  <b>intermittent</b> faults a single scan can't: VPN route flapping, gateway re-steering, jitter
                  bursts, DNS drift and egress changes.</p>
              </div>
            </div>

            <div class="watch-panel">
              <div class="watch-meta">
                <div class="wm"><span class="k">Machine</span><span class="v" id="w-machine"></span></div>
                <div class="wm"><span class="k">Gateway</span><span class="v" id="w-gateway"></span></div>
                <div class="wm"><span class="k">TURN relay</span><span class="v" id="w-stun"></span></div>
                <div class="wm"><span class="k">Captured</span><span class="v" id="w-when"></span></div>
              </div>
              <div class="watch-status">
                <div class="wstat"><div class="k">Window</div><div class="v" id="w-elapsed"></div></div>
                <div class="wstat"><div class="k">Samples</div><div class="v" id="w-samples"></div></div>
                <div class="wstat"><div class="k">Interval</div><div class="v" id="w-interval"></div></div>
                <div class="wstat"><div class="k">Anomalies</div><div class="v" id="w-anoms"></div></div>
                <div class="wstat"><div class="k">Route changes</div><div class="v" id="w-routes"></div></div>
              </div>
            </div>

            <div class="watch-verdict" id="w-verdict"></div>

            <div class="watch-panel">
              <h3 class="watch-sec">Timeline</h3>
              <div id="w-tracks"></div>
              <div class="watch-legend">
                <span><i style="background:var(--accent)"></i> metric</span>
                <span><i style="background:var(--red-border)"></i> anomaly window</span>
                <span><i class="thr"></i> threshold (cosmetic)</span>
              </div>
            </div>

            <div class="watch-panel">
              <h3 class="watch-sec">Findings over time <span class="watch-pill" id="w-findcount"></span></h3>
              <div id="w-findings"></div>
            </div>

            <div class="watch-foot">
              Captured by the W365 scanner <code id="w-ver"></code> in <code>--watch</code> mode.
              Verdict, summary and findings are produced by the scanner; this view renders them.
            </div>
          </div>`;

        // Meta
        text('w-machine', output.machineName || '—');
        text('w-gateway', output.gatewayHost || '—');
        text('w-stun', (output.stunHost || '—') + (output.stunHost ? ':3478' : ''));
        text('w-when', output.timestamp ? formatWhen(output.timestamp) : '—');
        text('w-ver', output.scannerVersion ? ('v' + output.scannerVersion) : '');

        // Status
        text('w-elapsed', fmtDur(lastEl) + (reqDur ? (' / ' + fmtDur(reqDur)) : ''));
        text('w-samples', String(samples.length));
        text('w-interval', (output.intervalSeconds || '?') + 's');
        const anomCount = events.filter(e => e.kind === 'anomaly').length;
        const aEl = setVal('w-anoms', String(anomCount), anomCount ? 'var(--yellow)' : 'var(--text-primary)');
        const rc = output.routeChangeCount || 0;
        setVal('w-routes', String(rc), rc ? 'var(--red)' : 'var(--text-primary)');

        renderVerdict(output);
        renderTracks(samples, events);
        renderFindings(events, samples);

        _rendered = true;
    }

    function renderVerdict(output) {
        const el = document.getElementById('w-verdict');
        if (!el) return;
        const v = (output.verdict || 'stable').toLowerCase();
        let cls = 'ok', icon = '✔';
        if (v === 'intermittent-fault' || v === 'degraded') { cls = 'bad'; icon = '●'; }
        else if (v === 'changed' || v === 'warning')        { cls = 'warn'; icon = '▲'; }
        el.className = 'watch-verdict ' + cls;
        // Render the scanner's summary verbatim (authoritative). Severity is
        // conveyed by the icon + colour, so we don't prepend a generated title
        // (which would duplicate summaries that already lead with the verdict).
        const summary = output.summary || verdictTitle(v) + '.';
        el.innerHTML = `<span class="big">${icon}</span><div>${escapeHtml(summary)}</div>`;
    }

    function verdictTitle(v) {
        switch (v) {
            case 'intermittent-fault': return 'Intermittent fault confirmed';
            case 'degraded':           return 'Transport quality degraded';
            case 'changed':            return 'Route path changed';
            case 'warning':            return 'Minor variability observed';
            default:                   return 'Stable';
        }
    }

    function renderTracks(samples, events) {
        const wrap = document.getElementById('w-tracks');
        if (!wrap) return;
        wrap.innerHTML = '';
        const n = samples.length;
        const lastT = n ? (samples[n - 1].elapsedSeconds || 0) : 1;
        const firstT = n ? (samples[0].elapsedSeconds || 0) : 0;
        const span = Math.max(1, lastT - firstT);

        TRACKS.forEach(k => {
            const row = document.createElement('div');
            row.className = 'wtrack';

            // Current (last sample) value + colour.
            let nowText = '—', nowColor = 'var(--text-primary)';
            if (n) {
                const last = samples[n - 1];
                if (k.isRoute) {
                    const changed = !!last.routeChanged;
                    nowText = changed ? 'changed' : 'stable';
                    nowColor = changed ? 'var(--red)' : 'var(--green)';
                } else if (k.isEgress) {
                    nowText = last.egressIp || '—';
                } else {
                    const val = last[k.key];
                    nowText = (val == null) ? '—' : k.fmt(val);
                    if (val != null) nowColor = val > k.bad ? 'var(--red)' : (val > k.warn ? 'var(--yellow)' : 'var(--text-primary)');
                }
            }

            row.innerHTML = `
              <div class="wt-name"><span class="t">${k.t}</span><span class="s">${k.s}</span></div>
              <div class="wt-spark"><svg viewBox="0 0 100 46" preserveAspectRatio="none">
                  ${k.warn != null && !k.isRoute && !k.isEgress ? '<line class="wt-thr" x1="0" x2="100" />' : ''}
                  <path fill="none" stroke="var(--accent)" stroke-width="1.4" /></svg></div>
              <div class="wt-now"><span style="color:${nowColor}">${escapeHtml(String(nowText))}</span><small>${k.unit || ''}</small></div>`;
            wrap.appendChild(row);

            const sp = row.querySelector('.wt-spark');
            const path = sp.querySelector('path');
            const thr = sp.querySelector('.wt-thr');

            // Build the metric polyline.
            const series = sampleSeries(samples, k);
            if (series.pts.length) {
                path.setAttribute('d', buildPath(series.pts, series.lo, series.hi, k));
                if (thr && k.warn != null && series.hi > series.lo) {
                    const y = 44 - ((k.warn - series.lo) / (series.hi - series.lo)) * 40;
                    if (y > 2 && y < 44) thr.setAttribute('y1', y.toFixed(2)), thr.setAttribute('y2', y.toFixed(2));
                    else thr.remove();
                } else if (thr) { thr.remove(); }
            }

            // Anomaly bands from scanner events for this track.
            events.filter(e => k.evTracks.indexOf(e.track) >= 0).forEach(e => {
                const x = ((((e.elapsedSeconds || 0)) - firstT) / span) * 100;
                const band = document.createElement('div');
                band.className = 'wt-band ' + (SEV_CLASS[e.severity] || 'warn');
                band.style.left = Math.max(0, Math.min(98, x)).toFixed(1) + '%';
                band.title = e.message || '';
                sp.appendChild(band);
            });
        });
    }

    // Returns { pts:[{x,y}], lo, hi } for a numeric track, or step series for
    // route/egress (0/1 against the first observed value).
    function sampleSeries(samples, k) {
        const pts = [];
        if (k.isRoute || k.isEgress) {
            const firstKey = k.isRoute ? (samples[0] && samples[0].routeHash) : (samples[0] && samples[0].egressIp);
            samples.forEach((s, i) => {
                const cur = k.isRoute ? s.routeHash : s.egressIp;
                pts.push({ x: i, y: (cur && cur !== firstKey) ? 1 : 0 });
            });
            return { pts, lo: 0, hi: 1 };
        }
        const ys = [];
        samples.forEach((s, i) => {
            const v = s[k.key];
            if (v != null) { pts.push({ x: i, y: v }); ys.push(v); }
        });
        if (!ys.length) return { pts: [], lo: 0, hi: 1 };
        let lo = Math.min.apply(null, ys);
        let hi = Math.max.apply(null, ys);
        // Pad so a flat line sits mid-band and the warn line is visible.
        hi = Math.max(hi, k.warn != null ? k.warn * 1.05 : hi);
        lo = Math.min(lo, 0);
        if (hi - lo < 1) hi = lo + 1;
        return { pts, lo, hi };
    }

    function buildPath(pts, lo, hi, k) {
        const n = pts.length;
        const span = Math.max(1, hi - lo);
        const denom = Math.max(1, (pts[n - 1].x - pts[0].x));
        return pts.map((p, i) => {
            const x = ((p.x - pts[0].x) / denom) * 100;
            let y;
            if (k.isRoute || k.isEgress) y = p.y ? 8 : 38;
            else y = 44 - ((p.y - lo) / span) * 40;
            y = Math.max(2, Math.min(44, y));
            // single point → tiny horizontal tick so it's visible
            if (n === 1) return `M0,${y.toFixed(2)} L100,${y.toFixed(2)}`;
            return `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`;
        }).join(' ');
    }

    // Metric key + formatter per anomaly track (route/egress have no scalar).
    const METRIC_KEY = { gatewayRtt: 'gatewayRttMs', jitter: 'jitterMs', loss: 'lossPct', dns: 'dnsMs' };
    function fmtMetric(track, v) {
        if (v == null) return '—';
        return track === 'loss' ? (v.toFixed(1) + '%') : (Math.round(v) + 'ms');
    }

    // Derive occurrence statistics for one anomaly track from the scanner's OWN
    // per-sample `anomalies[]` tags (authoritative — no re-thresholding here).
    // Returns counts, episode (contiguous-burst) grouping, peak and baseline.
    function trackStats(track, samples) {
        const key = METRIC_KEY[track];
        const idxs = [];
        samples.forEach((s, i) => {
            const a = Array.isArray(s.anomalies) ? s.anomalies : [];
            if (a.indexOf(track) >= 0) idxs.push(i);
        });
        // Group into episodes; a gap of a single clean sample still counts as one
        // burst (a brief flicker mid-event), a longer gap starts a new burst.
        const eps = [];
        let cur = null;
        idxs.forEach(i => {
            if (cur && i - cur.end <= 2) cur.end = i;
            else { cur = { start: i, end: i }; eps.push(cur); }
        });
        let peak = null, peakIdx = -1;
        if (key) idxs.forEach(i => { const v = samples[i][key]; if (v != null && (peak == null || v > peak)) { peak = v; peakIdx = i; } });
        let baseline = null;
        if (key) {
            const vals = samples.map(s => s[key]).filter(v => v != null).sort((a, b) => a - b);
            if (vals.length) baseline = vals[Math.floor(vals.length / 2)];
        }
        return { key, count: idxs.length, episodes: eps.length, idxs, eps, peak, peakIdx, baseline };
    }

    // Pick the most representative message for a track: the event nearest the peak
    // sample (or the worst-severity event when no peak), so the card text matches
    // the headline number we show.
    function repEvent(trackEvents, peakElapsed) {
        if (!trackEvents.length) return null;
        if (peakElapsed != null) {
            let best = trackEvents[0], bd = Infinity;
            trackEvents.forEach(e => { const d = Math.abs((e.elapsedSeconds || 0) - peakElapsed); if (d < bd) { bd = d; best = e; } });
            return best;
        }
        const order = { critical: 0, warning: 1, info: 2 };
        return trackEvents.slice().sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3))[0];
    }

    function frequencyBadge(count, episodes) {
        if (count <= 1) return { txt: 'one-off spike', cls: 'warn' };
        if (episodes <= 1) return { txt: 'sustained · ' + count + '×', cls: 'bad' };
        return { txt: 'recurring · ' + episodes + ' bursts', cls: 'bad' };
    }

    function renderFindings(events, samples) {
        const wrap = document.getElementById('w-findings');
        const countEl = document.getElementById('w-findcount');
        if (!wrap) return;
        samples = Array.isArray(samples) ? samples : [];
        const N = samples.length;
        const anomalies = events.filter(e => e.kind === 'anomaly');
        const contexts  = events.filter(e => e.kind !== 'anomaly');
        if (!events.length) {
            if (countEl) countEl.style.display = 'none';
            wrap.innerHTML = '<div class="watch-empty">No anomalies or context changes were recorded during the capture — the connection stayed stable throughout.</div>';
            return;
        }

        const cards = [];
        let anomalyCardCount = 0;

        // One card per anomaly TRACK, summarising how many of the N samples it hit
        // (so the user can tell a one-off blip from a sustained or recurring fault).
        const tracks = [];
        anomalies.forEach(e => { if (tracks.indexOf(e.track) < 0) tracks.push(e.track); });
        tracks.forEach(track => {
            const trackEvents = anomalies.filter(e => e.track === track);
            const st = trackStats(track, samples);

            // Backward-compat: older captures may not carry per-sample anomaly tags.
            // Fall back to rendering each event individually (legacy behaviour).
            if (st.count === 0) {
                trackEvents.forEach(e => { cards.push(simpleCard(e, e.elapsedSeconds || 0)); anomalyCardCount++; });
                return;
            }
            anomalyCardCount++;

            const peakElapsed = st.peakIdx >= 0 ? (samples[st.peakIdx].elapsedSeconds || 0) : null;
            const rep = repEvent(trackEvents, peakElapsed);
            const firstEl = samples[st.idxs[0]].elapsedSeconds || 0;
            const lastEl  = samples[st.idxs[st.idxs.length - 1]].elapsedSeconds || 0;
            const span = lastEl - firstEl;
            const worst = (trackEvents.some(e => e.severity === 'critical')) ? 'bad' : 'warn';
            const badge = frequencyBadge(st.count, st.episodes);

            const bits = [];
            bits.push(`<b>${st.count}</b> of ${N} samples`);
            if (N) bits.push(Math.round((st.count / N) * 100) + '% of capture');
            if (span > 0) bits.push('over ' + fmtDur(span));
            else bits.push('single sample at +' + fmtDur(firstEl));
            if (st.peak != null && st.baseline != null)
                bits.push('peak ' + fmtMetric(track, st.peak) + ' vs baseline ' + fmtMetric(track, st.baseline));

            const timeLabel = span > 0
                ? ('+' + fmtDur(firstEl) + ' → +' + fmtDur(lastEl))
                : ('+' + fmtDur(firstEl));

            cards.push({
                sortEl: peakElapsed != null ? peakElapsed : firstEl,
                html: `<div class="wfind ${worst}">
                    <span class="dot"></span>
                    <div class="body">
                      <div class="h">${escapeHtml(trackLabel(track))}
                        <span class="kindtag anomaly">anomaly</span>
                        <span class="freqtag ${badge.cls}">${escapeHtml(badge.txt)}</span></div>
                      <div class="d">${escapeHtml(rep ? (rep.message || '') : '')}</div>
                      <div class="meta">${bits.join(' &middot; ')}</div>
                    </div>
                    <div class="time">${escapeHtml(timeLabel)}</div>
                  </div>`
            });
        });

        // Context changes (VPN/gateway/DNS/adapter) stay as individual cards.
        contexts.forEach(e => cards.push(simpleCard(e, e.elapsedSeconds || 0)));

        // Newest first.
        cards.sort((a, b) => (b.sortEl || 0) - (a.sortEl || 0));
        wrap.innerHTML = cards.map(c => c.html).join('');
        if (countEl) {
            if (anomalyCardCount) { countEl.textContent = String(anomalyCardCount); countEl.style.display = ''; }
            else countEl.style.display = 'none';
        }
    }

    // A plain single-event card (context events, or legacy anomalies with no
    // per-sample tags). Mirrors the original findings markup.
    function simpleCard(e, sortEl) {
        const sev = SEV_CLASS[e.severity] || 'info';
        const kind = e.kind === 'context' ? 'context' : 'anomaly';
        return {
            sortEl,
            html: `<div class="wfind ${sev}">
                <span class="dot"></span>
                <div class="body">
                  <div class="h">${escapeHtml(trackLabel(e.track))} <span class="kindtag ${kind}">${kind}</span></div>
                  <div class="d">${escapeHtml(e.message || '')}</div>
                </div>
                <div class="time">+${fmtDur(e.elapsedSeconds || 0)}</div>
              </div>`
        };
    }

    function trackLabel(track) {
        const map = {
            route: 'W365 route change', gatewayRtt: 'Gateway RTT', jitter: 'UDP jitter',
            loss: 'UDP packet loss', dns: 'DNS resolution', egress: 'Egress IP',
            vpnAdapter: 'VPN/tunnel adapter', defaultGateway: 'Default gateway',
            dnsServer: 'DNS servers', adapters: 'Active adapters'
        };
        return map[track] || (track || 'Event');
    }

    function renderWatchError(msg) {
        document.documentElement.classList.add('watch-mode');
        const host = document.getElementById('watch-view');
        if (!host) return;
        host.hidden = false;
        showTabs('watch');
        host.innerHTML = `<div class="watch-wrap"><div class="watch-panel">
            <div class="watch-verdict warn"><span class="big">▲</span><div>${escapeHtml(msg)}</div></div>
          </div></div>`;
    }

    // ── Tab bar (Snapshot ⇄ Watch) ────────────────────────────────────────────

    function showTabs(active) {
        const tabs = document.getElementById('view-tabs');
        if (!tabs) return;
        tabs.hidden = false;
        tabs.querySelectorAll('.view-tab').forEach(btn => {
            btn.classList.toggle('is-active', btn.dataset.view === active);
        });
    }

    function wireTabs() {
        const tabs = document.getElementById('view-tabs');
        if (!tabs) return;
        tabs.addEventListener('click', (e) => {
            const btn = e.target.closest('.view-tab');
            if (!btn) return;
            const view = btn.dataset.view;
            if (view === 'snapshot') document.documentElement.classList.remove('watch-mode');
            else document.documentElement.classList.add('watch-mode');
            tabs.querySelectorAll('.view-tab').forEach(b => b.classList.toggle('is-active', b === btn));
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function text(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
    function setVal(id, v, color) { const el = document.getElementById(id); if (el) { el.textContent = v; if (color) el.style.color = color; } return el; }

    function fmtDur(sec) {
        sec = Math.round(sec || 0);
        const m = Math.floor(sec / 60), s = sec % 60;
        return m > 0 ? `${m}:${String(s).padStart(2, '0')}` : `${s}s`;
    }

    function formatWhen(ts) {
        try { const d = new Date(ts); return d.toLocaleString(); } catch { return String(ts); }
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ── Boot ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        wireTabs();
        initWatchFromUrl();
    });

    // Expose for app.js drag-drop routing.
    window.renderWatchTimeline = renderWatchTimeline;
    window.isWatchUrl = isWatchUrl;
})();
