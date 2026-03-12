/**
 * Main application logic: orchestrates browser tests, import, and result merging.
 */

// Import diagnostic log (set up by inline script in index.html)
function ilog(msg) { if (window._importLog) window._importLog(msg); else console.log('[W365]', msg); }

// Global error handler — show JS errors visibly so import issues are not silent
window.onerror = function(msg, url, line, col, error) {
    console.error('Global error:', msg, url, line, col, error);
    ilog('JS ERROR: ' + msg + ' at ' + url + ':' + line);
    const info = document.getElementById('info-banner');
    if (info) {
        info.classList.remove('hidden');
        info.querySelector('.info-text').innerHTML =
            `<strong>JavaScript error:</strong> ${msg} (${url}:${line})`;
    }
};
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    ilog('ASYNC ERROR: ' + (event.reason?.message || event.reason));
    const info = document.getElementById('info-banner');
    if (info) {
        info.classList.remove('hidden');
        info.querySelector('.info-text').innerHTML =
            `<strong>Async error:</strong> ${event.reason?.message || event.reason}`;
    }
});

// All collected results (browser + imported)
let allResults = [];
let isRunning = false;
let _importedScanTimestamp = '';   // when the imported scanner data was captured
let _importedMachineName = '';     // machine name from imported scanner data
let cloudPcMode = false;           // true when user toggles Cloud PC Mode
let hostType = null;               // 'cloudpc', 'avd', or null (determines labels)

// Map browser test IDs to their Cloud PC equivalents
const BROWSER_TO_CPC_ID = {
    'B-EP-01': 'C-EP-01',
    'B-LE-01': 'C-LE-01',
    'B-LE-02': 'C-LE-02',
    'B-LE-03': 'C-LE-03',
    'B-TCP-02': 'C-TCP-04',
    'B-TCP-03': 'C-TCP-05',
    'B-TCP-04': 'C-TCP-09',
    'B-UDP-01': 'C-UDP-03',
    'B-UDP-02': 'C-UDP-04'
};

// ── Cross-tab communication (bidirectional sync) ──
// When the scanner opens a NEW tab with results, both tabs exchange data:
//   New tab  → sends scanner results  → Existing tab
//   Existing tab → sends browser results back → New tab
// Result: BOTH tabs end up with complete data (browser + local).
const scannerChannel = new BroadcastChannel('w365-scanner-results');
let isNewScannerTab = false; // true if this tab was opened by the scanner with ?zresults=

scannerChannel.onmessage = (event) => {
    const msg = event.data;
    if (!msg?.type) return;

    if (msg.type === 'scanner-results') {
        // We're an EXISTING tab — import the scanner's local results
        console.log('Received scanner results from new tab via BroadcastChannel');
        processImportedData(msg.payload);
        // Send our browser results back so the new tab also has them
        const browserResults = allResults.filter(r => r.source === 'browser');
        if (browserResults.length > 0) {
            console.log(`Sending ${browserResults.length} browser results back to new tab`);
            scannerChannel.postMessage({ type: 'browser-results', payload: browserResults });
        }
    } else if (msg.type === 'browser-results' && isNewScannerTab) {
        // We're the NEW tab — merge in browser results from the existing tab
        console.log(`Received ${msg.payload?.length ?? 0} browser results from existing tab`);
        const browserResults = msg.payload || [];
        for (const br of browserResults) {
            // Only add if we don't already have a result for this test
            if (!allResults.some(r => r.id === br.id)) {
                br.source = 'browser';
                allResults.push(br);
                updateTestUI(br.id, br);
            }
        }
        updateSummary(allResults);
        updateCategoryBadges(allResults);
        updateConnectivityMap(allResults);
        updateSatelliteBanner(allResults);
        updateKeyFindings(allResults);
        updateExportButton();
        // Show confirmation
        const info = document.getElementById('info-banner');
        if (info) {
            info.classList.remove('hidden');
            const infoText = info.querySelector('.info-text');
            infoText.textContent = '';
            const strong = document.createElement('strong');
            strong.textContent = 'Browser test results synced from your other tab.';
            infoText.appendChild(strong);
            infoText.appendChild(document.createTextNode(
                ` All ${allResults.length} results (browser + local) are shown below.`));
        }
    }
};

// Fallback: listen for localStorage changes from other tabs
window.addEventListener('storage', (event) => {
    if (event.key === 'w365-scanner-results' && event.newValue) {
        try {
            const data = JSON.parse(event.newValue);
            console.log('Received scanner results from another tab via localStorage');
            processImportedData(data);
        } catch (e) {
            console.error('Failed to parse localStorage scanner results:', e);
        }
    }
});

// ── Initialize on page load ──
document.addEventListener('DOMContentLoaded', () => {
    ilog('DOMContentLoaded fired, initializing...');
    renderTestList();
    ilog('renderTestList done, ' + ALL_TESTS.length + ' tests rendered');
    checkForAutoImport();
    setupDragDrop();

    // Auto-detect Cloud PC environment (IMDS probe)
    detectCloudPcEnvironment().then(result => {
        if (result.detected) {
            if (result.hostType) {
                hostType = result.hostType;
                ilog(`Auto-detected host type: ${result.hostType}`);
            }
            const toggle = document.getElementById('cpc-mode-toggle');
            if (toggle) toggle.checked = true;
            toggleCloudPcMode(true);
            // Update host-type selector to match detected value
            const sel = document.getElementById('host-type-select');
            if (sel && result.hostType) sel.value = result.hostType;
            // If we couldn't determine type, show the picker banner
            if (!result.hostType) {
                const picker = document.getElementById('host-type-picker');
                if (picker) picker.classList.remove('hidden');
                ilog('Host type unknown — showing picker banner');
            }
            ilog('CPC Mode auto-enabled');
        }
    });

    ilog('Init complete');
});

// ── Handle hash changes (e.g. browser reuses existing tab) ──
window.addEventListener('hashchange', () => {
    checkForAutoImport();
});

// ── Drag-and-drop import ──
function setupDragDrop() {
    document.body.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    document.body.addEventListener('drop', async (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (!file || !file.name.endsWith('.json')) return;
        try {
            const text = await file.text();
            const data = JSON.parse(text);
            processImportedData(data);
        } catch (err) {
            console.error('Drag-drop import failed:', err);
        }
    });
}


// ── Cloud PC environment auto-detection ──
// Probes the Azure IMDS endpoint (169.254.169.254). First tries to read the full
// response (to distinguish Cloud PC vs AVD). Falls back to no-cors reachability.
async function detectCloudPcEnvironment() {
    // First, try full CORS read with Metadata header (works from file:// or relaxed envs)
    try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 3000);
        const resp = await fetch('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', {
            headers: { 'Metadata': 'true' },
            signal: ctrl.signal
        });
        clearTimeout(t);
        if (resp.ok) {
            const meta = await resp.json();
            const offer = (meta.offer || '').toLowerCase();
            const sku   = (meta.sku   || '').toLowerCase();
            const vmSz  = (meta.vmSize || '').toLowerCase();
            const isCpc = offer.includes('cpc') || sku.includes('cpc') || vmSz.includes('_cpc');
            const ht = isCpc ? 'cloudpc' : 'avd';  // If IMDS is reachable but no CPC indicators → AVD
            ilog(`IMDS metadata read — offer=${meta.offer}, sku=${meta.sku}, vmSize=${meta.vmSize} → hostType=${ht}`);
            return { detected: true, hostType: ht, meta };
        }
    } catch { /* CORS or mixed content blocked — expected from https:// pages */ }
    // Fallback: opaque no-cors probe (just reachability)
    try {
        const ctrl2 = new AbortController();
        const t2 = setTimeout(() => ctrl2.abort(), 3000);
        await fetch('http://169.254.169.254/metadata/instance?api-version=2021-02-01', {
            mode: 'no-cors',
            signal: ctrl2.signal
        });
        clearTimeout(t2);
        ilog('IMDS reachable (opaque) — Azure VM detected, hostType unknown');
        return { detected: true, hostType: null };
    } catch {
        ilog('IMDS not reachable — not an Azure VM environment');
        return { detected: false, hostType: null };
    }
}

// ── Host label helper ──
function hostLabel() {
    return hostType === 'avd' ? 'AVD Session Host' : 'Cloud PC';
}
function hostLabelShort() {
    return hostType === 'avd' ? 'AVD Host' : 'Cloud PC';
}

// ── Host-type dropdown handler ──
function onHostTypeChanged(value) {
    hostType = value; // 'cloudpc' or 'avd'
    ilog('Host type changed to: ' + value);
    // Hide picker banner if showing
    const picker = document.getElementById('host-type-picker');
    if (picker) picker.classList.add('hidden');
    updateHostTypeLabels();
    // Re-render key findings if we have results
    if (allResults.length > 0) {
        updateKeyFindings(allResults);
    }
}

// ── Host-type picker (shown when IMDS detected but type unknown) ──
function pickHostType(type) {
    hostType = type;
    ilog('User selected host type: ' + type);
    // Hide the picker banner
    const picker = document.getElementById('host-type-picker');
    if (picker) picker.classList.add('hidden');
    // Sync the dropdown
    const sel = document.getElementById('host-type-select');
    if (sel) sel.value = type;
    // Update all labels
    updateHostTypeLabels();
    // Re-render key findings if we have results
    if (allResults.length > 0) {
        updateKeyFindings(allResults);
    }
}

// ── Update all host-type-sensitive labels in the UI ──
function updateHostTypeLabels() {
    const label = hostLabel();
    const short = hostLabelShort();
    // Map card title
    const cpcTitle = document.getElementById('map-cpc-title');
    if (cpcTitle) cpcTitle.textContent = cloudPcMode ? `${short} (this device)` : short;
    // Map CPC badge
    const cpcBadge = document.getElementById('cpc-detected-badge');
    if (cpcBadge) cpcBadge.textContent = `☁ ${label} Detected`;
    // CPC toggle label
    const toggleLabel = document.getElementById('cpc-toggle-label');
    if (toggleLabel) toggleLabel.textContent = `${short} Mode`;
    // CPC diagnostics section header
    const cpcSectionTitle = document.querySelector('.cloudpc-header .live-title');
    if (cpcSectionTitle) cpcSectionTitle.textContent = `${label} Diagnostics`;
    const cpcSectionSub = document.querySelector('.cloudpc-header .live-subtitle');
    if (cpcSectionSub) cpcSectionSub.textContent = `Connectivity tests run from within the ${label} (Azure VM)`;
    // CPC diagnostics info bar
    const cpcInfoBar = document.querySelector('#cloudpc-info-bar span:last-child');
    if (cpcInfoBar) cpcInfoBar.innerHTML = `Run the scanner inside the ${label} with <code>--cloudpc</code> or it will auto-detect Azure VMs. Import the results to see the server-side view.`;
    // Live Connection subtitle
    const liveSub = document.querySelector('#live-diagnostics-section .live-subtitle');
    if (liveSub) liveSub.textContent = `Real-time analysis of your active ${label} session`;
    // Live Connection info bar
    const liveInfo = document.querySelector('#cloud-info-bar span:last-child');
    if (liveInfo) liveInfo.textContent = `Run the desktop tool while connected to your ${label}, or from within the ${label} session itself.`;
    // SVG label inside Cloud PC card
    const svgText = document.querySelector('#map-cloudpc .device-svg text');
    if (svgText) svgText.textContent = short;
    // Run button
    const btn = document.getElementById('btn-run-all');
    if (btn && !isRunning && cloudPcMode) {
        const hasResults = allResults.some(r => r.source === 'cloudpc' || r.source === 'browser');
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M3 1.5v11l9-5.5L3 1.5z" fill="currentColor"/></svg> ' +
            (hasResults ? `Re-run ${short} Tests` : `Run ${short} Tests`);
    }
}

// ── Cloud PC Mode toggle ──
function toggleCloudPcMode(enabled) {
    cloudPcMode = enabled;
    const clientSections = ['cat-endpoint', 'cat-local', 'cat-tcp', 'cat-udp'];
    const cpcSection = document.getElementById('cloudpc-diagnostics-section');
    const mapContainer = document.getElementById('connectivity-map');
    const btn = document.getElementById('btn-run-all');

    if (enabled) {
        // Hide client-side test sections
        clientSections.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
        // Show host-type selector
        const htSel = document.getElementById('host-type-select');
        if (htSel) {
            htSel.classList.remove('hidden');
            if (hostType) htSel.value = hostType;
        }
        // Show Cloud PC diagnostics section (always visible — no longer toggled hidden)
        if (cpcSection) {
            const cpcInfoBar = document.getElementById('cloudpc-info-bar');
            if (cpcInfoBar) cpcInfoBar.style.display = 'none';
        }
        if (mapContainer) mapContainer.classList.add('cpc-only-active');
        // Show CPC detected badge in map header
        const cpcBadge = document.getElementById('cpc-detected-badge');
        if (cpcBadge) cpcBadge.classList.remove('hidden');
        // Switch map to CPC layout: hide left-side, show right-side Cloud PC + Azure
        const mapDiagram = document.querySelector('.map-diagram');
        if (mapDiagram) {
            mapDiagram.classList.add('cpc-mode');
            mapDiagram.classList.remove('has-cloudpc');
        }
        // Update button text
        if (btn && !isRunning) {
            const hasResults = allResults.some(r => r.source === 'cloudpc' || r.source === 'browser');
            const label = hostLabelShort();
            btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M3 1.5v11l9-5.5L3 1.5z" fill="currentColor"/></svg> ' +
                (hasResults ? `Re-run ${label} Tests` : `Run ${label} Tests`);
        }
        // Apply host-type-aware labels
        updateHostTypeLabels();
    } else {
        // Show client-side test sections
        clientSections.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.remove('hidden');
        });
        // Hide CPC section info bar if we have imported CPC data
        const hasImportedCpc = allResults.some(r => r.source === 'cloudpc' && r.category === 'cloudpc');
        if (cpcSection && hasImportedCpc) {
            const cpcInfoBar = document.getElementById('cloudpc-info-bar');
            if (cpcInfoBar) cpcInfoBar.style.display = 'none';
        }
        // Restore map
        if (mapContainer) mapContainer.classList.remove('cpc-only-active');
        // Hide CPC detected badge
        const cpcBadge = document.getElementById('cpc-detected-badge');
        if (cpcBadge) cpcBadge.classList.add('hidden');
        // Hide host-type selector
        const htSel = document.getElementById('host-type-select');
        if (htSel) htSel.classList.add('hidden');
        // Restore normal map layout
        const mapDiagram = document.querySelector('.map-diagram');
        if (mapDiagram) {
            mapDiagram.classList.remove('cpc-mode');
            // Remove CPC reveal markers
            mapDiagram.querySelectorAll('.cpc-revealed').forEach(el => el.classList.remove('cpc-revealed'));
        }
        // Restore Cloud PC card title
        const cpcTitle = document.getElementById('map-cpc-title');
        if (cpcTitle) cpcTitle.textContent = hostLabelShort();
        // Remove right-side cards unless imported CPC data exists
        const hasImportedCpcData = allResults.some(r => r.source === 'cloudpc' && r.id === 'C-NET-01');
        if (!hasImportedCpcData) {
            if (mapDiagram) mapDiagram.classList.remove('has-cloudpc');
        }
        // Restore button text
        if (btn && !isRunning) {
            const hasResults = allResults.some(r => r.source === 'browser');
            btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M3 1.5v11l9-5.5L3 1.5z" fill="currentColor"/></svg> ' +
                (hasResults ? 'Re-run Browser Tests' : 'Run Browser Tests');
        }
    }
}


// ── Run all browser tests ──
async function runAllBrowserTests() {
    if (isRunning) return;
    isRunning = true;

    const btn = document.getElementById('btn-run-all');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">\u27F3</span> Running...';

    // Hide info banner and map (map reveals after tests finish)
    document.getElementById('info-banner').classList.add('hidden');
    const mapContainer = document.getElementById('connectivity-map');
    if (mapContainer) mapContainer.classList.add('hidden');

    const browserTests = ALL_TESTS.filter(t => t.source === 'browser' && t.run);
    const total = browserTests.length;
    let completed = 0;

    // Reset filter to 'all' at start of scan
    setResultFilter('all');
    const filterBar = document.getElementById('filter-bar');
    if (filterBar) filterBar.classList.add('hidden');

    // Reset browser results (keep imported scanner results — never drop _fromImport data)
    if (cloudPcMode) {
        allResults = allResults.filter(r => r._fromImport || r.source === 'local' || r.source === 'browser');
    } else {
        allResults = allResults.filter(r => r._fromImport || r.source === 'local' || r.source === 'cloudpc');
    }

    // Clear GeoIP and user-location caches so location is re-fetched fresh
    if (typeof resetGeoCache === 'function') resetGeoCache();
    if (typeof resetUserLocCache === 'function') resetUserLocCache();

    // Show progress
    updateProgress(0, total, browserTests[0]?.name);

    for (const test of browserTests) {
        // In Cloud PC mode, map B-* IDs to C-* IDs
        const targetId = cloudPcMode ? (BROWSER_TO_CPC_ID[test.id] || test.id) : test.id;
        setTestRunning(targetId);
        updateProgress(completed, total, test.name);

        try {
            const result = await test.run(test);
            if (cloudPcMode) {
                result.id = targetId;
                result.source = 'cloudpc';
                result.category = 'cloudpc';
            } else {
                result.source = 'browser';
            }
            allResults.push(result);
            updateTestUI(targetId, result);
        } catch (err) {
            const errorResult = {
                id: targetId,
                name: test.name,
                category: cloudPcMode ? 'cloudpc' : test.category,
                source: cloudPcMode ? 'cloudpc' : 'browser',
                status: 'Error',
                resultValue: `Error: ${err.message}`,
                detailedInfo: err.stack || err.message,
                duration: 0
            };
            allResults.push(errorResult);
            updateTestUI(targetId, errorResult);
        }

        completed++;
        updateProgress(completed, total);
    }

    hideProgress();

    // Reveal the map now that we have results
    if (mapContainer) mapContainer.classList.remove('hidden');

    updateSummary(allResults);
    updateCategoryBadges(allResults);
    updateConnectivityMap(allResults);
    updateSatelliteBanner(allResults);
    updateKeyFindings(allResults);
    updateExportButton();

    // Only show download banner if no scanner results have been imported
    const hasLocalResults = allResults.some(r => r.source === 'local');
    if (!hasLocalResults) showDownloadBanner();

    btn.disabled = false;
    if (cloudPcMode) {
        btn.innerHTML = `<span class="btn-icon">\u25B6</span> Re-run ${hostLabelShort()} Tests`;
    } else {
        btn.innerHTML = '<span class="btn-icon">\u25B6</span> Re-run Browser Tests';
    }

    // Restore CPC card visibility — browser tests can disturb state when cloudPcMode flipped mid-run
    restoreCpcCards();

    isRunning = false;
}

// ── Import local scanner results from file picker ──
async function importLocalResults(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const data = JSON.parse(text);
        processImportedData(data);
    } catch (e) {
        alert(`Error reading file: ${e.message}`);
    }

    // Reset file input so same file can be re-imported
    event.target.value = '';
}

// ── Auto-import from URL query param or hash ──
// Scanner opens browser with ?zresults=COMPRESSED (query param survives Windows ShellExecute)
// Also supports legacy #zresults= and #results= hash formats
async function checkForAutoImport() {
    const params = new URLSearchParams(window.location.search);
    const hash = window.location.hash;
    let data = null;
    let source = '';

    // Show immediate feedback that import is starting
    const info = document.getElementById('info-banner');
    const hasZResults = params.has('zresults');
    const hasHashZ = hash.startsWith('#zresults=');
    const hasHashR = hash.startsWith('#results=');

    ilog('checkForAutoImport: zresults=' + hasZResults + ' hashZ=' + hasHashZ + ' hashR=' + hasHashR);
    ilog('  search.length=' + window.location.search.length + ' hash.length=' + hash.length);

    if (!hasZResults && !hasHashZ && !hasHashR) {
        ilog('No import data found in URL, skipping auto-import');
        return;
    }

    // Show importing status
    if (info) {
        info.classList.remove('hidden');
        info.querySelector('.info-text').innerHTML =
            '<strong>Importing scanner results...</strong> Decompressing data.';
    }

    try {
        if (hasZResults) {
            const raw = params.get('zresults');
            ilog('zresults param: ' + raw.length + ' chars');
            try {
                data = await decodeCompressedHash(raw);
                source = 'query-compressed';
                ilog('Decompression OK: ' + (data?.results?.length ?? 0) + ' results');
            } catch (compressErr) {
                ilog('Compressed import FAILED: ' + compressErr.message);
                console.warn('Compressed import failed, trying uncompressed hash fallback:', compressErr);
                // Fallback: try uncompressed #results= hash (scanner sends both)
                if (hash.startsWith('#results=')) {
                    const hashRaw = hash.substring('#results='.length);
                    data = decodeUncompressedHash(hashRaw);
                    source = 'hash-fallback';
                } else {
                    throw compressErr; // No fallback available, re-throw
                }
            }
        } else if (hasHashZ) {
            const raw = hash.substring('#zresults='.length);
            data = await decodeCompressedHash(raw);
            source = 'hash-compressed';
        } else if (hasHashR) {
            const raw = hash.substring('#results='.length);
            data = decodeUncompressedHash(raw);
            source = 'hash-uncompressed';
        }

        // Clear the URL so it doesn't re-import on refresh / bookmarking
        history.replaceState(null, '', window.location.pathname);

        ilog('Auto-import (' + source + '): parsed ' + (data.results?.length ?? 0) + ' results');
        console.log(`Auto-import (${source}): parsed ${data.results?.length ?? 0} results`);

        // Mark this as a scanner-opened tab so we accept browser-results replies
        isNewScannerTab = true;

        // Process scanner results immediately on THIS tab
        ilog('Calling processImportedData...');
        processImportedData(data);
        ilog('processImportedData complete');

        // Broadcast to any existing tabs so they also get the scanner results
        // (and can send back their browser results)
        try {
            scannerChannel.postMessage({ type: 'scanner-results', payload: data });
            // Also write to localStorage as a fallback signal
            localStorage.setItem('w365-scanner-results', JSON.stringify(data));
            localStorage.removeItem('w365-scanner-results');
        } catch (broadcastErr) {
            console.warn('Could not broadcast to other tabs:', broadcastErr);
        }

        // Auto-run browser tests so the scanner tab has complete results
        // (don't rely solely on cross-tab sync from an existing tab)
        runAllBrowserTests();
    } catch (e) {
        ilog('AUTO-IMPORT FAILED: ' + (e.message || e));
        console.error('Auto-import from URL failed:', e);
        // Show a helpful message to the user instead of failing silently
        if (info) {
            info.classList.remove('hidden');
            info.querySelector('.info-text').innerHTML =
                `<strong>Auto-import failed:</strong> ${e.message || e}. ` +
                `Please drag and drop the <strong>W365ScanResults.json</strong> file onto this page, ` +
                `or open the file manually from the folder where you ran the scanner.`;
        }
        // Clear the hash
        history.replaceState(null, '', window.location.pathname + window.location.search);
    }
}

// ── Decode compressed hash (deflate-raw → JSON) ──
async function decodeCompressedHash(raw) {
    let base64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (base64.length % 4)) % 4;
    if (pad > 0) base64 += '='.repeat(pad);

    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

    // Use DecompressionStream with a timeout to detect hangs
    const decompressPromise = (async () => {
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        writer.write(bytes);
        writer.close();

        const reader = ds.readable.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
        const decompressed = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            decompressed.set(chunk, offset);
            offset += chunk.length;
        }
        return new TextDecoder().decode(decompressed);
    })();

    const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('DecompressionStream timed out after 10s')), 10000)
    );

    const json = await Promise.race([decompressPromise, timeoutPromise]);
    ilog('Decompressed: ' + bytes.length + ' → ' + json.length + ' chars');
    console.log(`Auto-import (compressed): decompressed ${bytes.length} → ${json.length} bytes`);
    let parsed = JSON.parse(json);
    ilog('Parsed JSON: ' + (parsed.results?.length ?? parsed.r?.length ?? 0) + ' results, machine=' + (parsed.machineName || 'unknown'));

    // Expand compact share-link format (_f:2) back to standard import format
    if (parsed._f === 2 && Array.isArray(parsed.r)) {
        const STATUS_EXPAND = { P:'Passed', F:'Failed', W:'Warning', I:'Info', N:'NotRun', E:'Pending', X:'Error' };
        parsed = {
            timestamp: parsed.ts,
            machineName: parsed.mn || 'SharedLink',
            scanMode: parsed.sm || undefined,
            azureRegion: parsed.ar || undefined,
            results: parsed.r.map(c => ({
                id: c.i,
                status: STATUS_EXPAND[c.s] || c.s,
                resultValue: c.v || '',
                detailedInfo: c.d || '',
                duration: c.t || 0
            }))
        };
        ilog('Expanded compact format: ' + parsed.results.length + ' results');
    }

    return parsed;
}

// ── Decode uncompressed hash (plain base64 → JSON) ──
function decodeUncompressedHash(raw) {
    let base64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (base64.length % 4)) % 4;
    if (pad > 0) base64 += '='.repeat(pad);
    const json = atob(base64);
    console.log(`Auto-import (uncompressed): decoded ${json.length} chars`);
    return JSON.parse(json);
}

// ── Shared import logic ──
function processImportedData(data) {
    ilog('processImportedData called. data type=' + typeof data + ', has results=' + Array.isArray(data?.results) + ', count=' + (data?.results?.length ?? 'N/A'));
    // The local scanner outputs: { timestamp, machineName, scanMode, azureRegion, results: [...] }
    let localResults = [];
    if (Array.isArray(data.results)) {
        localResults = data.results;
    } else if (Array.isArray(data)) {
        localResults = data;
    } else {
        alert('Invalid results file. Expected JSON with a "results" array.');
        return;
    }

    // Detect Cloud PC vs AVD session host
    const isCloudPcImport = data.scanMode === 'cloudpc';
    if (isCloudPcImport) {
        // Read hostType from scanner output (cloudpc, avd, or absent for older builds)
        if (data.hostType === 'avd') {
            hostType = 'avd';
            ilog('AVD Session Host scan detected. Azure region: ' + (data.azureRegion || 'unknown'));
        } else {
            hostType = 'cloudpc';
            ilog('Cloud PC scan detected. Azure region: ' + (data.azureRegion || 'unknown'));
        }
        // Also try to infer from C-NET-01 IMDS result if hostType wasn't in the JSON
        if (!data.hostType) {
            const imdsResult = localResults.find(r => r.id === 'C-NET-01');
            if (imdsResult) {
                const rv = (imdsResult.resultValue || '').toLowerCase();
                const di = (imdsResult.detailedInfo || '').toLowerCase();
                if (rv.startsWith('avd') || di.includes('host type: avd')) {
                    hostType = 'avd';
                } else if (!rv.includes('cpc') && !di.includes('cpc') && !di.includes('host type: cloud pc')) {
                    // IMDS exists but no CPC indicators — likely AVD
                    if (di.includes('host type:')) hostType = di.includes('avd') ? 'avd' : 'cloudpc';
                }
            }
        }
        updateHostTypeLabels();
        // Sync host-type dropdown and hide picker banner
        const htSel = document.getElementById('host-type-select');
        if (htSel) htSel.value = hostType;
        const picker = document.getElementById('host-type-picker');
        if (picker) picker.classList.add('hidden');
    }

    // Remember when the scanner data was captured
    if (data.timestamp) {
        try { _importedScanTimestamp = new Date(data.timestamp).toLocaleString(); } catch { _importedScanTimestamp = String(data.timestamp); }
    }

    // Remember machine name from imported data
    if (data.machineName) {
        _importedMachineName = String(data.machineName);
    }

    // Legacy ID mapping: older scanner builds used L-CS-* IDs for cloud tests.
    // Remap them to the current numeric IDs so they match ALL_TESTS.
    const LEGACY_ID_MAP = {
        'L-CS-01': '17',   // Active RDP Session Detection
        'L-CS-02': '18',   // Session Round-Trip Latency
        'L-CS-03': '19',   // Session Frame Rate & Bandwidth
        'L-CS-04': '20',   // Connection Jitter
        'L-CS-05': '21'    // Frame Drops & Packet Loss
    };
    let remappedCount = 0;
    for (const lr of localResults) {
        const sid = String(lr.id);
        if (LEGACY_ID_MAP[sid]) {
            ilog('Remapping legacy ID ' + sid + ' → ' + LEGACY_ID_MAP[sid]);
            lr.id = LEGACY_ID_MAP[sid];
            remappedCount++;
        }
    }
    if (remappedCount > 0) ilog('Remapped ' + remappedCount + ' legacy L-CS-* IDs to numeric IDs');

    // Map local scanner IDs to our test list
    const allIds = localResults.map(r => r.id);
    const cloudIds = localResults.filter(r => (r.category||'').toLowerCase() === 'cloud').map(r => r.id);
    ilog('Processing ' + localResults.length + ' results. IDs: ' + allIds.join(', '));
    ilog('Cloud-category results: ' + (cloudIds.length > 0 ? cloudIds.join(', ') : 'NONE'));
    let importedCount = 0;
    let cloudCount = 0;
    for (const lr of localResults) {
        try {
            // Remove any existing result with this ID (coerce to string for safety)
            const lrId = String(lr.id);
            allResults = allResults.filter(r => String(r.id) !== lrId);

            const mapped = {
                id: lrId,
                name: lr.name || lrId,
                description: lr.description || '',
                category: lr.category || mapCategoryFromId(lrId),
                source: isCloudPcImport ? 'cloudpc' : (lr.source || 'local'),
                _fromImport: true,
                status: lr.status || 'Passed',
                resultValue: lr.resultValue || lr.result || '',
                detailedInfo: lr.detailedInfo || lr.details || '',
                duration: lr.duration || 0,
                remediationUrl: lr.remediationUrl || '',
                remediationText: lr.remediationText || ''
            };

            // Normalize scanner's specific cloudpc sub-categories to dashboard 'cloudpc'
            if (mapped.category && mapped.category.startsWith('cloudpc-'))
                mapped.category = 'cloudpc';

            allResults.push(mapped);

            // Update UI - find matching test definition or create inline
            const testDef = ALL_TESTS.find(t => String(t.id) === lrId);
            if (testDef) {
                if (mapped.category === 'cloud') {
                    ilog('  Cloud test ' + lrId + ': status=' + mapped.status + ', val=' + (mapped.resultValue || '').substring(0,80));
                }
                updateTestUI(lrId, mapped);
                if (mapped.category === 'cloud') cloudCount++;
            } else {
                ilog('  No ALL_TESTS match for id="' + lrId + '" (type=' + typeof lr.id + ', cat=' + mapped.category + ')');
                // Scanner version is newer than page — dynamically create a card
                console.warn(`Import: No test definition for ${lrId}, creating card dynamically`);
                const dynDef = { id: lrId, name: lr.name || lrId, description: lr.description || '', source: 'local', category: mapped.category };
                const container = document.getElementById(`tests-${mapped.category}`);
                if (container) {
                    const el = createTestElement(dynDef, mapped);
                    container.appendChild(el);
                }
            }

            importedCount++;
        } catch (itemErr) {
            console.error(`Import: Error processing result ${lr?.id}:`, itemErr);
        }
    }

    ilog('Import done: ' + importedCount + ' total, ' + cloudCount + ' cloud tests matched ALL_TESTS');

    // Build the set of imported IDs (used in stale-card loop below)
    const importedIds = new Set(localResults.map(r => String(r.id)));

    // Update summary and badges
    updateSummary(allResults);
    updateCategoryBadges(allResults);

    // Reveal the map (hidden until first test run or import)
    const mapContainer = document.getElementById('connectivity-map');
    if (mapContainer) mapContainer.classList.remove('hidden');

    updateConnectivityMap(allResults);
    updateSatelliteBanner(allResults);
    updateKeyFindings(allResults);
    updateExportButton();
    const info = document.getElementById('info-banner');
    info.classList.remove('hidden');
    const machineName = data.machineName ? escapeHtml(String(data.machineName)) : '';
    const scanTime = data.timestamp ? escapeHtml(new Date(data.timestamp).toLocaleString()) : '';
    const importLabel = isCloudPcImport ? `${hostLabelShort()} scan` : 'local scan';
    info.querySelector('.info-text').innerHTML =
        `<strong>Imported ${importedCount} ${importLabel} results.</strong> ` +
        (machineName ? `Machine: ${machineName}. ` : '') +
        (data.azureRegion ? `Azure Region: ${escapeHtml(data.azureRegion)}. ` : '') +
        (scanTime ? `Scanned: ${scanTime}. ` : '') +
        'Combined results are shown below.';

    // Hide download banner if we have local results
    if (importedCount > 0) hideDownloadBanner();

    // Cloud PC section is always visible — just manage the info bar
    const cloudPcSection = document.getElementById('cloudpc-diagnostics-section');
    const hasCloudPcResults = allResults.some(r => r.category === 'cloudpc');
    if (cloudPcSection) {
        const cpcInfoBar = document.getElementById('cloudpc-info-bar');
        if (cpcInfoBar) cpcInfoBar.style.display = hasCloudPcResults ? 'none' : '';
    }

    // Show the extended map with Cloud PC cards if Cloud PC data present
    if (hasCloudPcResults) {
        const mapDiagram = document.querySelector('.map-diagram');
        if (mapDiagram) mapDiagram.classList.add('has-cloudpc');
    }

    // Hide the cloud info bar if we imported any cloud results
    const hasCloudResults = allResults.some(r => r.category === 'cloud' && (r.source === 'local' || r.source === 'cloudpc'));
    if (hasCloudResults) {
        const cloudInfoBar = document.getElementById('cloud-info-bar');
        if (cloudInfoBar) cloudInfoBar.style.display = 'none';
    }

    // Restore any C-* cards that were hidden by a previous stale-card pass
    // (Section is always visible now, so individual card display matters)
    for (const test of ALL_TESTS) {
        if (test.source === 'cloudpc') {
            const el = document.getElementById(`test-${test.id}`);
            if (el) { el.style.display = ''; el.classList.remove('hidden'); }
            continue;
        }
        if (test.source !== 'local') continue;
        if (importedIds.has(String(test.id))) continue;
        const el = document.getElementById(`test-${test.id}`);
        if (el) el.style.display = 'none';
    }

    // Final pass: ensure all C-* cards are visible (belt-and-suspenders)
    restoreCpcCards();
}

/**
 * Ensure all Cloud PC test cards are visible in the DOM.
 * Called after any operation that could inadvertently hide them.
 */
function restoreCpcCards() {
    for (const test of ALL_TESTS) {
        if (test.source !== 'cloudpc') continue;
        const el = document.getElementById(`test-${test.id}`);
        if (el) { el.style.display = ''; el.classList.remove('hidden'); }
    }
}

// ── Helpers ──
function mapCategoryFromId(id) {
    if (!id) return 'local';
    // Cloud PC tests (C-* prefix)
    if (id.startsWith('C-')) return 'cloudpc';
    if (id.includes('-EP-')) return 'endpoint';
    if (id.includes('-LE-')) return 'local';
    if (id.includes('-TCP-')) return 'tcp';
    if (id.includes('-UDP-')) return 'udp';
    if (id.includes('-CS-')) return 'cloud';
    // WPF Cloud Session test IDs (17, 17b, 17c, 18-24)
    const num = parseInt(id);
    if (num >= 17 && num <= 24) return 'cloud';
    if (id === '17b' || id === '17c') return 'cloud';
    return 'local';
}

// Helper: extract VPN/SWG names from resultValue "VPN detected (Name) — ..." or detailedInfo
function extractVpnNames(tests) {
    const names = new Set();
    for (const t of tests) {
        if (!t) continue;
        // Try resultValue first: "VPN/SWG detected (Name1, Name2) — ..."
        const rvMatch = (t.resultValue || '').match(/detected\s*\(([^)]+)\)/i);
        if (rvMatch) {
            rvMatch[1].split(',').map(s => s.trim()).filter(Boolean).forEach(n => names.add(n));
        }
        // Also check detailedInfo for "VPN adapter detected: Name (Desc)" or "SWG process running: Name (PID: ...)"
        if (t.detailedInfo) {
            t.detailedInfo.split('\n')
                .filter(l => /VPN adapter detected:|SWG.*process running:/i.test(l))
                .forEach(l => {
                    const m = l.match(/(?:detected|running):\s*([^\s(]+(?:\s+[^\s(]+)*)/i);
                    if (m) {
                        let name = m[1].trim();
                        name = name.replace(/\s*\(.*$/, '').trim();
                        if (name) names.add(name);
                    }
                });
        }
    }
    return [...names];
}

// ── Export results as a text report ──
async function generateExportText() {
    if (allResults.length === 0) return '';

    // Always fetch fresh location at export time — use shared resolver
    const freshLoc = await fetchUserLocation();

    // Update the B-LE-01 result in allResults with fresh data
    if (freshLoc) {
        const freshLocStr = freshLoc.source === 'browser'
            ? `${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}`
            : `${freshLoc.region}, ${freshLoc.country}`;
        const freshDetail = `Public IP: ${freshLoc.ip}\nLocation: ${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}\nCoordinates: ${freshLoc.lat}, ${freshLoc.lon}\nSource: ${freshLoc.source === 'browser' ? 'Browser Geolocation' : 'GeoIP'}`;
        const existing = allResults.find(r => r.id === 'B-LE-01');
        if (existing) {
            existing.resultValue = freshLocStr;
            existing.detailedInfo = freshDetail;
            existing.status = 'Passed';
            updateTestUI('B-LE-01', existing);
        }
    }

    const lines = [];
    const divider = '═'.repeat(72);
    const thinDiv = '─'.repeat(72);

    lines.push(divider);
    lines.push('  Windows 365 Connectivity Diagnostics — Text Report');
    lines.push(divider);
    lines.push(`  Generated: ${new Date().toLocaleString()}`);
    lines.push(`  User Agent: ${navigator.userAgent}`);

    // Current user location — fresh data just fetched above
    if (freshLoc) {
        const locLabel = freshLoc.source === 'browser'
            ? `${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}`
            : `${freshLoc.region}, ${freshLoc.country}`;
        lines.push(`  Location:   ${locLabel} (${freshLoc.source === 'browser' ? 'GPS/WiFi' : 'GeoIP'})`);
        lines.push(`  Public IP:  ${freshLoc.ip}`);
    } else {
        const userLocResult = allResults.find(r => r.id === 'B-LE-01' && r.status === 'Passed');
        if (userLocResult) {
            lines.push(`  Location:   ${userLocResult.resultValue}`);
            const pubIp = (userLocResult.detailedInfo || '').split('\n')
                .find(l => l.startsWith('Public IP:'));
            if (pubIp) lines.push(`  ${pubIp}`);
        }
    }

    // Note when scanner data was captured (may differ from current location)
    const scannerResults = allResults.filter(r => r.source === 'local');
    if (scannerResults.length > 0 && _importedScanTimestamp) {
        lines.push(`  Scanner data from: ${_importedScanTimestamp}`);
        // Warn if scanner location differs from current fresh location
        if (freshLoc) {
            const currentRegion = freshLoc.region.toLowerCase();
            const test27 = scannerResults.find(r => r.id === '27');
            if (test27 && test27.detailedInfo) {
                const egressLine = test27.detailedInfo.split('\n')
                    .find(l => l.trim().startsWith('Your egress location:'));
                if (egressLine) {
                    const scannerLoc = egressLine.replace(/.*Your egress location:\s*/i, '').trim();
                    if (scannerLoc && !scannerLoc.toLowerCase().includes(currentRegion)) {
                        lines.push(`  ⚠ Scanner was run from: ${scannerLoc}`);
                        lines.push(`    Current location differs — re-run the scanner for accurate results.`);
                    }
                }
            }
        }
    }

    lines.push('');

    // Summary counts
    const passed = allResults.filter(r => r.status === 'Passed').length;
    const warnings = allResults.filter(r => r.status === 'Warning').length;
    const failed = allResults.filter(r => r.status === 'Failed' || r.status === 'Error').length;
    const skipped = allResults.filter(r => r.status === 'Skipped').length;

    lines.push(`  Summary: ${allResults.length} tests — ${passed} passed, ${warnings} warnings, ${failed} failed` +
        (skipped > 0 ? `, ${skipped} skipped` : ''));
    lines.push('');

    // ── Connectivity Overview (quick-glance summary) ──
    lines.push(divider);
    lines.push('  Connectivity Overview');
    lines.push(divider);
    lines.push('');

    // Helper: find a result by ID
    const r = id => allResults.find(x => x.id === id);

    // 1. User Location
    if (freshLoc) {
        const locLabel = freshLoc.source === 'browser'
            ? `${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}`
            : `${freshLoc.region}, ${freshLoc.country}`;
        lines.push(`  User Location:     ${locLabel}  (IP: ${freshLoc.ip})`);
    } else {
        const loc = r('B-LE-01');
        lines.push(`  User Location:     ${loc ? loc.resultValue : 'Unknown'}`);
    }

    // 2. RDP Egress Location (prefer test 27, fallback to L-TCP-09 "Your location:")
    const egress27 = r('27');
    if (egress27 && egress27.detailedInfo) {
        const eLine = egress27.detailedInfo.split('\n').find(l => l.trim().startsWith('Your egress location:'));
        lines.push(`  RDP Egress:        ${eLine ? eLine.replace(/.*Your egress location:\s*/i, '').trim() : egress27.resultValue}`);
    } else {
        // Fallback: L-TCP-09 (Gateway Used) includes the scanner's own GeoIP as "Your location:"
        const gw09f = r('L-TCP-09');
        if (gw09f && gw09f.detailedInfo) {
            const locLine = gw09f.detailedInfo.split('\n').find(l => l.trim().startsWith('Your location:'));
            if (locLine) {
                lines.push(`  RDP Egress:        ${locLine.replace(/.*Your location:\s*/i, '').trim()}  (scanner GeoIP)`);
            } else {
                lines.push(`  RDP Egress:        (requires Local Scanner)`);
            }
        } else {
            lines.push(`  RDP Egress:        (requires Local Scanner)`);
        }
    }

    // 3. AFD Location (prefer scanner L-TCP-09, fallback to browser B-TCP-02)
    const gw09 = r('L-TCP-09');
    const afd02 = r('B-TCP-02');
    if (gw09 && gw09.detailedInfo) {
        const popLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('AFD PoP:'));
        if (popLine) {
            lines.push(`  AFD Edge PoP:      ${popLine.replace(/.*AFD PoP:\s*/i, '').trim()}`);
        } else if (afd02) {
            lines.push(`  AFD Edge PoP:      ${afd02.resultValue}`);
        } else {
            lines.push(`  AFD Edge PoP:      Unknown`);
        }
    } else if (afd02) {
        lines.push(`  AFD Edge PoP:      ${afd02.resultValue}`);
    } else {
        lines.push(`  AFD Edge PoP:      (not tested)`);
    }

    // 4. Gateway Location & Latency (from L-TCP-09 + L-TCP-04)
    if (gw09 && gw09.detailedInfo) {
        const regionLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('Azure Region:'));
        const geoLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('GeoIP Location:'));
        const distLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('Distance from you:'));
        const regionVal = regionLine ? regionLine.replace(/.*Azure Region:\s*/i, '').trim() : '';
        const geoVal = geoLine ? geoLine.replace(/.*GeoIP Location:\s*/i, '').trim() : '';
        let gwSummary = regionVal || geoVal || gw09.resultValue;
        if (geoVal && regionVal) gwSummary = `${regionVal}  (${geoVal})`;
        if (distLine) gwSummary += `  — ${distLine.replace(/.*Distance from you:\s*/i, '').trim()}`;
        // try to find TCP latency from L-TCP-04
        const gw04 = r('L-TCP-04');
        if (gw04 && gw04.detailedInfo) {
            const tcpLine = gw04.detailedInfo.split('\n').find(l => l.includes('[RDP Gateway]'));
            if (tcpLine) {
                const latLine = gw04.detailedInfo.split('\n')
                    .slice(gw04.detailedInfo.split('\n').indexOf(tcpLine))
                    .find(l => l.trim().match(/TCP connected in \d+ms/));
                if (latLine) {
                    const ms = latLine.match(/(\d+)ms/);
                    if (ms) gwSummary += `  — TCP ${ms[1]}ms`;
                }
            }
        }
        lines.push(`  RDP Gateway:       ${gwSummary}`);
    } else {
        lines.push(`  RDP Gateway:       (requires Local Scanner)`);
    }

    // 5. TURN Relay Location & Latency (L-UDP-04 + L-UDP-03)
    const turn04 = r('L-UDP-04');
    if (turn04 && turn04.status !== 'Skipped') {
        let turnSummary = turn04.resultValue || 'Unknown';
        const turn03 = r('L-UDP-03');
        if (turn03 && turn03.status === 'Passed') {
            // Parse latency from L-UDP-03 detailedInfo ("Latency: 12ms") or resultValue ("— 12ms RTT")
            let latMs = '';
            if (turn03.detailedInfo) {
                const latLine = turn03.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
                if (latLine) latMs = latLine.replace(/.*Latency:\s*/i, '').trim();
            }
            if (!latMs) {
                const rttMatch = (turn03.resultValue || '').match(/(\d+)\s*ms\s*RTT/i);
                if (rttMatch) latMs = `${rttMatch[1]}ms`;
            }
            if (latMs) turnSummary += `  — ${latMs} RTT`;
        }
        lines.push(`  TURN Relay:        ${turnSummary}`);
    } else {
        lines.push(`  TURN Relay:        (requires Local Scanner)`);
    }

    lines.push('');

    // 6. TCP (RDP) Security Report
    // Browser-native proxy detection for the text report
    let reportHttpIp = freshLoc?.ip || '';
    if (!reportHttpIp) {
        const locR = r('B-LE-01');
        if (locR?.detailedInfo) {
            const m = locR.detailedInfo.match(/Public IP:\s*(\S+)/);
            if (m) reportHttpIp = m[1];
        }
    }
    let reportStunIp = '';
    const stunR = r('B-UDP-01');
    if (stunR?.detailedInfo) {
        const m = stunR.detailedInfo.match(/Reflexive IP:\s*(\S+)/);
        if (m) reportStunIp = m[1];
    }

    const tcpTls = r('L-TCP-06');
    const tcpDns = r('L-TCP-08');
    const tcpVpn = r('L-TCP-07');

    // GeoIP the STUN IP to distinguish CGNAT from proxy
    let reportStunCountry = '';
    let reportStunCity = '';
    let reportHttpCountry = freshLoc?.country || '';
    let reportHttpCity = freshLoc?.source === 'browser' ? (freshLoc?.city || '') : '';
    let reportIsSplitPath = false;
    if (reportHttpIp && reportStunIp && reportHttpIp !== reportStunIp) {
        try {
            const geoResp = await fetch(`https://ipinfo.io/${reportStunIp}/json`, {
                signal: AbortSignal.timeout(5000), cache: 'no-store'
            });
            if (geoResp.ok) {
                const geoData = await geoResp.json();
                reportStunCountry = geoData.country || '';
                reportStunCity = geoData.city || '';
            }
        } catch (e) { /* GeoIP lookup failed */ }
        // Different countries = proxy; same country = CGNAT
        if (reportStunCountry && reportHttpCountry &&
            reportStunCountry.toUpperCase() !== reportHttpCountry.toUpperCase()) {
            reportIsSplitPath = true;
        }
    }

    if (tcpTls || tcpDns || tcpVpn || (reportHttpIp && reportStunIp)) {
        lines.push(`  TCP-based RDP Path Optimisation:`);
        if (tcpTls) {
            const icon = tcpTls.status === 'Passed' ? '✓' : '⚠';
            lines.push(`    ${icon} TLS Inspection:   ${tcpTls.resultValue}`);
        }
        if (tcpDns) {
            const icon = tcpDns.status === 'Passed' ? '✓' : '⚠';
            lines.push(`    ${icon} DNS Hijacking:    ${tcpDns.resultValue}`);
        }
        if (tcpVpn) {
            // Smart display: prefer showing VPN detection status over raw resultValue
            const turnVpnRef = r('L-UDP-07') || r('C-UDP-07');
            const vpnNamesReport = extractVpnNames([tcpVpn, turnVpnRef]);
            const tcpTimedOutR = /timed out/i.test(tcpVpn.resultValue);
            if (tcpTimedOutR && vpnNamesReport.length > 0) {
                // TCP timed out but VPN detected via UDP — show the VPN name
                lines.push(`    ✓ Proxy/VPN/SWG:    VPN detected (${vpnNamesReport.join(', ')}) — RDP correctly bypassed (split-tunnel)`);
                lines.push(`                        (TCP test timed out — VPN status inferred from UDP test)`);
            } else if (tcpTimedOutR) {
                lines.push(`    ⚠ Proxy/VPN/SWG:    ${tcpVpn.resultValue}`);
            } else if (tcpVpn.status === 'Passed' && vpnNamesReport.length > 0 && !/detected/i.test(tcpVpn.resultValue)) {
                // Passed but resultValue doesn't mention VPN (old scanner) — fill in from detailedInfo
                lines.push(`    ✓ Proxy/VPN/SWG:    VPN detected (${vpnNamesReport.join(', ')}) — RDP correctly bypassed`);
            } else {
                const icon = tcpVpn.status === 'Passed' ? '✓' : '⚠';
                lines.push(`    ${icon} Proxy/VPN/SWG:    ${tcpVpn.resultValue}`);
            }
        }
        if (reportHttpIp && reportStunIp) {
            if (reportHttpIp === reportStunIp) {
                lines.push(`    ✓ Split-path:         No proxy / split-path routing detected`);
            } else if (reportIsSplitPath) {
                lines.push(`    ⚠ Split-path:         Proxy / split-path routing detected`);
                lines.push(`                          HTTP: ${reportHttpIp} [${reportHttpCity}, ${reportHttpCountry}]`);
                lines.push(`                          STUN: ${reportStunIp} [${reportStunCity}, ${reportStunCountry}]`);
            } else {
                lines.push(`    ✓ Split-path:         No proxy detected (CGNAT: different IPs, same country)`);
            }
        }
    } else {
        lines.push(`  TCP-based RDP Path Optimisation:  (requires Local Scanner or STUN test)`);
    }

    lines.push('');

    // 7. TURN (UDP) Security Report
    // Detect CGNAT in text report too
    let reportIsCgnat = false;
    if (reportHttpIp && reportStunIp && reportHttpIp !== reportStunIp &&
        reportStunCountry && reportHttpCountry &&
        reportStunCountry.toUpperCase() === reportHttpCountry.toUpperCase()) {
        reportIsCgnat = true;
    }

    const turnTls = r('L-UDP-06');
    const turnVpn = r('L-UDP-07');

    // NAT type line for text report — prefer scanner L-UDP-05, fall back to B-UDP-02
    const reportNatSrc = r('L-UDP-05') || r('B-UDP-02');
    let reportNatLine = '';
    if (reportNatSrc) {
        const nv = reportNatSrc.resultValue || '';
        const nlc = nv.toLowerCase();
        const nsrc = r('L-UDP-05') ? 'Scanner' : 'Browser';
        let nIcon, nLabel;
        if (nlc.includes('cone') || nlc.includes('open internet')) {
            nIcon = '✓';
            nLabel = nlc.includes('open internet') ? 'Open Internet (No NAT)' : 'Cone NAT — Shortpath ready';
        } else if (nlc.includes('symmetric')) {
            nIcon = '✗';
            nLabel = 'Symmetric NAT — STUN hole-punching unlikely';
        } else if (nlc.includes('stun ok')) {
            nIcon = '✓';
            nLabel = 'STUN OK — UDP connectivity confirmed';
        } else if (nlc.includes('blocked') || nlc.includes('failed')) {
            nIcon = '✗';
            nLabel = 'STUN unavailable (typical in enterprise) — TURN relay will be used';
        } else {
            nIcon = '⚠';
            nLabel = nv;
        }
        reportNatLine = `    ${nIcon} NAT Type:         ${nLabel} [${nsrc}]`;
    }

    if (reportNatLine || turnTls || turnVpn || reportIsSplitPath || reportIsCgnat) {
        lines.push(`  UDP-based RDP Path Optimisation:`);
        if (reportNatLine) lines.push(reportNatLine);
        if (turnTls) {
            const icon = turnTls.status === 'Passed' ? '✓' : '⚠';
            lines.push(`    ${icon} TLS Inspection:   ${turnTls.resultValue}`);
        }
        if (turnVpn) {
            // Smart display: show VPN name even if resultValue uses old format
            const vpnNamesUdpReport = extractVpnNames([turnVpn]);
            if (turnVpn.status === 'Passed' && vpnNamesUdpReport.length > 0 && !/detected/i.test(turnVpn.resultValue)) {
                lines.push(`    ✓ Proxy/VPN/SWG:    VPN detected (${vpnNamesUdpReport.join(', ')}) — UDP correctly bypassed`);
            } else {
                const icon = turnVpn.status === 'Passed' ? '✓' : '⚠';
                lines.push(`    ${icon} Proxy/VPN/SWG:    ${turnVpn.resultValue}`);
            }
        }
        if (reportIsSplitPath) {
            lines.push(`    ✓ UDP bypasses HTTP proxy (direct egress via ${reportStunIp})`);
        }
        if (reportIsCgnat) {
            const natR = r('B-UDP-02');
            const natType = natR?.resultValue || '';
            const isSymmetric = natType.toLowerCase().includes('symmetric');
            if (isSymmetric) {
                lines.push(`    ⚠ CGNAT:              Carrier-Grade NAT detected — Symmetric NAT confirmed`);
                lines.push(`                          STUN hole-punching unavailable; RDP Shortpath will use TURN relay`);
            } else if (natR && natR.status === 'Passed') {
                lines.push(`    ✓ CGNAT:              Detected but NAT mapping is Cone — STUN should work`);
            } else {
                lines.push(`    ⚠ CGNAT:              Carrier-Grade NAT detected — may limit STUN connectivity`);
                lines.push(`                          RDP Shortpath may fall back to TURN relay`);
            }
        }
    } else if (reportIsSplitPath) {
        lines.push(`  UDP-based RDP Path Optimisation:`);
        lines.push(`    ✓ UDP bypasses HTTP proxy (direct egress via ${reportStunIp})`);
    } else {
        lines.push(`  UDP-based RDP Path Optimisation:  (requires Local Scanner or STUN test)`);
    }

    lines.push('');

    // Group by category
    const categoryNames = {
        local: 'Local Environment',
        endpoint: 'Required Endpoints',
        tcp: 'TCP / Transport',
        udp: 'UDP / TURN / STUN',
        cloud: 'Live Connection Diagnostics',
        cloudpc: `${hostLabel()} Diagnostics`
    };
    const categories = ['local', 'endpoint', 'tcp', 'udp', 'cloud', 'cloudpc'];

    for (const cat of categories) {
        const catResults = allResults.filter(r => r.category === cat);
        if (catResults.length === 0) continue;

        lines.push(divider);
        lines.push(`  ${categoryNames[cat] || cat}`);
        lines.push(divider);
        lines.push('');

        for (const r of catResults) {
            const icon = r.status === 'Passed' ? '✓' :
                         r.status === 'Warning' ? '⚠' :
                         r.status === 'Failed' || r.status === 'Error' ? '✗' :
                         r.status === 'Skipped' ? '—' : '?';
            const dur = r.duration ? ` (ran in ${r.duration}ms)` : '';
            const src = r.source === 'cloudpc' ? ` [${hostLabelShort()}]` : r.source === 'local' ? ' [Local Scanner]' : ' [Browser]';

            lines.push(`  ${icon} [${r.status.toUpperCase()}] ${r.id} — ${r.name}${dur}${src}`);
            if (r.resultValue) {
                lines.push(`    Result: ${r.resultValue}`);
            }
            if (r.detailedInfo) {
                const detailLines = r.detailedInfo.split('\n');
                for (const dl of detailLines) {
                    lines.push(`    ${dl}`);
                }
            }
            lines.push('');
        }
    }

    lines.push(thinDiv);
    lines.push('  End of report');
    lines.push(thinDiv);

    return lines.join('\n');
}

async function exportTextReport() {
    const text = await generateExportText();
    if (!text) return;
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `W365-Diagnostics-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ── Enable the export button when results are available ──
function updateExportButton() {
    const hasResults = allResults.length > 0;
    const btn = document.getElementById('btn-export-text');
    if (btn) {
        btn.disabled = !hasResults;
        btn.title = !hasResults ? 'Run tests first' : `Export ${allResults.length} results as text`;
    }
    const jsonBtn = document.getElementById('btn-export-json');
    if (jsonBtn) {
        jsonBtn.disabled = !hasResults;
        jsonBtn.title = !hasResults ? 'Run tests first' : `Export ${allResults.length} results as JSON`;
    }
    const linkBtn = document.getElementById('btn-copy-link');
    if (linkBtn) {
        linkBtn.disabled = !hasResults;
        linkBtn.title = !hasResults ? 'Run tests first' : 'Copy shareable link to clipboard';
    }
    const aiBtn = document.getElementById('btn-ai-analysis');
    if (aiBtn) {
        aiBtn.disabled = !hasResults;
        aiBtn.title = !hasResults ? 'Run tests first' : 'Analyze results with Microsoft Copilot';
    }
    const sendItBtn = document.getElementById('btn-send-it');
    if (sendItBtn) {
        sendItBtn.disabled = !hasResults;
        sendItBtn.title = !hasResults ? 'Run tests first' : 'Download results and open email to IT';
    }
    const csvBtn = document.getElementById('btn-export-csv');
    if (csvBtn) {
        csvBtn.disabled = !hasResults;
        csvBtn.title = !hasResults ? 'Run tests first' : `Export ${allResults.length} results as CSV (Excel)`;
    }
    const compareBtn = document.getElementById('btn-compare');
    if (compareBtn) {
        compareBtn.disabled = !hasResults;
        compareBtn.title = !hasResults ? 'Run tests first to enable comparison' : 'Load a baseline JSON file to compare before/after';
    }
    // Show re-test button if there are failed/warned browser tests
    const retestBtn = document.getElementById('btn-retest');
    if (retestBtn) {
        const failedBrowser = allResults.filter(r =>
            r.source === 'browser' && (r.status === 'Failed' || r.status === 'Error' || r.status === 'Warning'));
        if (failedBrowser.length > 0 && !isRunning) {
            retestBtn.style.display = '';
            retestBtn.disabled = false;
            retestBtn.title = `Re-test ${failedBrowser.length} failed/warned browser tests`;
        } else {
            retestBtn.style.display = 'none';
        }
    }
    // Auto-save to history when we have results
    if (hasResults) saveResultsToHistory();
    // Update history bar
    updateHistoryBar();
    // Remediation checklist
    updateRemediationPanel();
    // Filter bar
    updateFilterBar();
}

// ═══════════════════════════════════════════════════════════════════
//  JSON Export
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
//  Send Results to IT (mailto: with JSON download)
// ═══════════════════════════════════════════════════════════════════
function sendResultsToIT() {
    if (allResults.length === 0) return;

    const critical = allResults.filter(r => r.status === 'Failed' || r.status === 'Error').length;
    const warnings = allResults.filter(r => r.status === 'Warning').length;
    const passed   = allResults.filter(r => r.status === 'Passed').length;
    const total    = allResults.length;

    const machineName = _importedMachineName || 'Unknown Device';
    const dateStr     = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    const filename    = `W365-Diagnostics-${machineName.replace(/[^a-zA-Z0-9_-]/g, '_')}-${new Date().toISOString().slice(0, 10)}.json`;

    // Build status label for subject line
    let statusLabel = 'All Tests Passed';
    if (critical > 0) statusLabel = `${critical} Critical Issue${critical > 1 ? 's' : ''}`;
    else if (warnings > 0) statusLabel = `${warnings} Warning${warnings > 1 ? 's' : ''}`;

    // Critical/warning details for the body
    const issueLines = allResults
        .filter(r => r.status === 'Failed' || r.status === 'Error' || r.status === 'Warning')
        .map(r => `  [${r.status.toUpperCase()}] ${r.name}: ${r.resultValue || ''}`.trimEnd())
        .join('\n');

    const subject = encodeURIComponent(`W365 Connectivity Results — ${machineName} — ${statusLabel} — ${dateStr}`);
    const body = encodeURIComponent(
        `Hi IT Team,\n\n` +
        `A Windows 365 connectivity scan has been completed on this device.\n\n` +
        `Device:   ${machineName}\n` +
        `Date:     ${dateStr}\n` +
        `Results:  ${critical} Critical, ${warnings} Warning, ${passed} Passed (${total} total)\n\n` +
        (issueLines ? `Issues found:\n${issueLines}\n\n` : '') +
        `Please find the full diagnostic JSON report attached (${filename}).\n\n` +
        `To view the results, import the JSON file into the W365 Connectivity Tool web dashboard.\n\n` +
        `Regards`
    );

    // Download the JSON file first so the user can attach it
    const output = {
        timestamp: new Date().toISOString(),
        machineName,
        userAgent: navigator.userAgent,
        scannerTimestamp: _importedScanTimestamp || null,
        results: allResults.map(r => ({
            id: r.id, name: r.name, category: r.category, source: r.source,
            status: r.status, resultValue: r.resultValue || '',
            detailedInfo: r.detailedInfo || '', duration: r.duration || 0,
            remediationUrl: r.remediationUrl || '', remediationText: r.remediationText || ''
        }))
    };
    const blob = new Blob([JSON.stringify(output, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    // Open mailto: after a short delay to let the download start
    setTimeout(() => {
        window.location.href = `mailto:?subject=${subject}&body=${body}`;
    }, 300);
}

// ═══════════════════════════════════════════════════════════════════
//  CSV Export
// ═══════════════════════════════════════════════════════════════════
function exportCsvReport() {
    if (allResults.length === 0) return;

    const machineName = _importedMachineName || 'Unknown';
    const scanDate    = _importedScanTimestamp || new Date().toLocaleString();

    // Wrap a value safely for CSV (quote and escape internal quotes)
    const csv = val => {
        const s = String(val ?? '').replace(/\r?\n/g, ' ').replace(/"/g, '""');
        return `"${s}"`;
    };

    const headers = ['Machine', 'Scan Date', 'Test ID', 'Test Name', 'Category', 'Source', 'Status', 'Result', 'Detail', 'Remediation'];
    const rows = allResults.map(r => [
        csv(machineName),
        csv(scanDate),
        csv(r.id),
        csv(r.name),
        csv(r.category),
        csv(r.source),
        csv(r.status),
        csv(r.resultValue),
        csv(r.detailedInfo),
        csv(r.remediationText)
    ].join(','));

    // Prepend UTF-8 BOM so Excel opens with correct encoding
    const content = '\uFEFF' + [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `W365-Diagnostics-${machineName.replace(/[^a-zA-Z0-9_-]/g, '_')}-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportJsonReport() {
    if (allResults.length === 0) return;
    const output = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        scannerTimestamp: _importedScanTimestamp || null,
        results: allResults.map(r => ({
            id: r.id,
            name: r.name,
            category: r.category,
            source: r.source,
            status: r.status,
            resultValue: r.resultValue || '',
            detailedInfo: r.detailedInfo || '',
            duration: r.duration || 0,
            remediationUrl: r.remediationUrl || '',
            remediationText: r.remediationText || ''
        }))
    };
    const json = JSON.stringify(output, null, 2);
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `W365-Diagnostics-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ═══════════════════════════════════════════════════════════════════
//  Copy Shareable Link
// ═══════════════════════════════════════════════════════════════════
async function copyShareLink() {
    if (allResults.length === 0) return;
    const btn = document.getElementById('btn-copy-link');
    const origHtml = btn.innerHTML;

    try {
        btn.innerHTML = 'Compressing...';
        btn.disabled = true;

        // Status → single char mapping (saves ~6 chars per result)
        const STATUS_MAP = { Passed:'P', Failed:'F', Warning:'W', Info:'I', NotRun:'N', Pending:'E', Error:'X' };

        // Build a compact payload — drop derivable fields (name, category,
        // remediationUrl/Text are in ALL_TESTS), use short keys, skip unrun tests,
        // and cap detailedInfo to keep the URL within browser limits.
        const MAX_DETAIL = 400;  // chars per test
        const compactResults = allResults
            .filter(r => r.status && r.status !== 'NotRun')
            .map(r => {
                const obj = {
                    i: r.id,
                    s: STATUS_MAP[r.status] || r.status,
                    v: r.resultValue || ''
                };
                let d = r.detailedInfo || '';
                if (d.length > MAX_DETAIL) d = d.substring(0, MAX_DETAIL) + '…[truncated]';
                if (d) obj.d = d;
                if (r.duration) obj.t = r.duration;
                return obj;
            });

        const payload = { _f: 2, ts: new Date().toISOString(), r: compactResults };
        const json = JSON.stringify(payload);

        // Compress with deflate-raw
        const cs = new CompressionStream('deflate-raw');
        const writer = cs.writable.getWriter();
        writer.write(new TextEncoder().encode(json));
        writer.close();

        const reader = cs.readable.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const compressed = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) { compressed.set(chunk, offset); offset += chunk.length; }

        // Base64url encode
        let b64 = btoa(String.fromCharCode(...compressed));
        b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        const shareUrl = `${location.origin}${location.pathname}?zresults=${b64}`;

        // Practical URL limit — proxies/servers often reject >8 KB
        if (shareUrl.length > 32000) {
            btn.innerHTML = 'Link too large — use Export instead';
            btn.disabled = false;
            setTimeout(() => { btn.innerHTML = origHtml; }, 3000);
            return;
        }

        await navigator.clipboard.writeText(shareUrl);
        btn.innerHTML = '\u2714 Link copied!';
        btn.classList.add('btn-copied');
        setTimeout(() => { btn.innerHTML = origHtml; btn.classList.remove('btn-copied'); btn.disabled = false; }, 2000);
    } catch (e) {
        console.error('Copy link failed:', e);
        btn.innerHTML = 'Failed to copy';
        btn.disabled = false;
        setTimeout(() => { btn.innerHTML = origHtml; }, 2000);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Re-test Failed Items
// ═══════════════════════════════════════════════════════════════════
async function retestFailedItems() {
    if (isRunning) return;
    isRunning = true;

    const retestBtn = document.getElementById('btn-retest');
    if (retestBtn) { retestBtn.disabled = true; retestBtn.innerHTML = '<span class="btn-icon">\u27F3</span> Re-testing...'; }

    // Find browser tests that failed or warned
    const failedIds = new Set(
        allResults
            .filter(r => r.source === 'browser' && (r.status === 'Failed' || r.status === 'Error' || r.status === 'Warning'))
            .map(r => r.id)
    );

    const testsToRerun = ALL_TESTS.filter(t => t.source === 'browser' && t.run && failedIds.has(t.id));
    if (testsToRerun.length === 0) { isRunning = false; return; }

    const total = testsToRerun.length;
    let completed = 0;

    updateProgress(0, total, testsToRerun[0]?.name);

    for (const test of testsToRerun) {
        setTestRunning(test.id);
        updateProgress(completed, total, test.name);

        // Remove old result
        allResults = allResults.filter(r => r.id !== test.id);

        try {
            const result = await test.run(test);
            result.source = 'browser';
            allResults.push(result);
            updateTestUI(test.id, result);
            updateConnectivityMap(allResults);
            updateSatelliteBanner(allResults);
        } catch (err) {
            const errorResult = {
                id: test.id, name: test.name, category: test.category, source: 'browser',
                status: 'Error', resultValue: `Error: ${err.message}`,
                detailedInfo: err.stack || err.message, duration: 0
            };
            allResults.push(errorResult);
            updateTestUI(test.id, errorResult);
        }
        completed++;
        updateProgress(completed, total);
    }

    hideProgress();
    updateSummary(allResults);
    updateCategoryBadges(allResults);
    updateConnectivityMap(allResults);
    updateSatelliteBanner(allResults);
    updateKeyFindings(allResults);
    updateExportButton();

    if (retestBtn) {
        retestBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 7a6 6 0 0111.6-2M13 7a6 6 0 01-11.6 2" stroke="currentColor" stroke-width="1.2" fill="none" stroke-linecap="round"/><path d="M13 1v4h-4M1 13V9h4" stroke="currentColor" stroke-width="1.2" fill="none" stroke-linecap="round"/></svg> Re-test Failed';
    }
    isRunning = false;
}

// ═══════════════════════════════════════════════════════════════════
//  Historical Comparison (localStorage)
// ═══════════════════════════════════════════════════════════════════
const HISTORY_KEY = 'w365-results-history';
const MAX_HISTORY = 10;

// ═══════════════════════════════════════════════════════════════════
//  Before / After Comparison
// ═══════════════════════════════════════════════════════════════════
async function importBaselineResults(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        const baselineResults = Array.isArray(data.results) ? data.results : (Array.isArray(data) ? data : null);
        if (!baselineResults) { alert('Invalid baseline file. Expected a W365 Connectivity JSON export.'); return; }
        const baselineMachine = data.machineName || 'Baseline';
        const baselineDate   = data.timestamp ? new Date(data.timestamp).toLocaleString() : file.name;
        renderComparison(baselineResults, baselineMachine, baselineDate);
    } catch (e) {
        alert(`Error reading baseline file: ${e.message}`);
    }
    event.target.value = '';
}

function renderComparison(baselineResults, baselineMachine, baselineDate) {
    const panel   = document.getElementById('compare-panel');
    const metaEl  = document.getElementById('compare-meta');
    const summaryEl = document.getElementById('compare-summary');
    const gridEl  = document.getElementById('compare-grid');
    if (!panel || !gridEl) return;

    const esc = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    // Status severity rank: lower = better
    const rank = status => ({ Passed: 0, Info: 1, Warning: 2, Failed: 3, Error: 3 }[status] ?? 4);

    const statusIcon = status => ({ Passed: '✓', Warning: '⚠', Failed: '✗', Error: '!', Skipped: '—' }[status] ?? '?');

    // Index current results by test ID
    const currentById = {};
    for (const r of allResults) currentById[r.id] = r;

    // Build comparison rows for tests that appear in both
    let fixed = 0, regressed = 0, unchanged = 0;
    const rows = [];

    for (const before of baselineResults) {
        const after = currentById[before.id];
        if (!after) continue;
        const rBefore = rank(before.status);
        const rAfter  = rank(after.status);
        let change = 'unchanged';
        if (rAfter < rBefore) { change = 'fixed'; fixed++; }
        else if (rAfter > rBefore) { change = 'regressed'; regressed++; }
        else unchanged++;
        rows.push({ before, after, change });
    }

    // Sort: regressions first, then fixed, then unchanged
    const order = { regressed: 0, fixed: 1, unchanged: 2 };
    rows.sort((a, b) => order[a.change] - order[b.change]);

    // Meta line
    const currentMachine = _importedMachineName || 'Current';
    metaEl.textContent = `Baseline: ${baselineMachine} (${baselineDate})  →  Current: ${currentMachine}`;

    // Summary chips
    summaryEl.innerHTML = [
        fixed      ? `<span class="compare-stat fixed">✓ ${fixed} Fixed</span>` : '',
        regressed  ? `<span class="compare-stat regressed">↑ ${regressed} Regressed</span>` : '',
        unchanged  ? `<span class="compare-stat unchanged">— ${unchanged} Unchanged</span>` : ''
    ].join('');

    // Table
    const headerRow = `<div class="compare-row compare-head">
        <span class="compare-name">Test</span>
        <span class="compare-val">Before</span>
        <span class="compare-val">After</span>
        <span class="compare-badge">Change</span>
    </div>`;

    const dataRows = rows.map(({ before, after, change }) => {
        const badgeHtml = change === 'fixed'
            ? `<span class="compare-badge fixed">✓ Fixed</span>`
            : change === 'regressed'
                ? `<span class="compare-badge regressed">↑ Worse</span>`
                : `<span class="compare-badge unchanged">—</span>`;
        return `<div class="compare-row row-${change}">
            <span class="compare-name">${esc(before.name)}</span>
            <span class="compare-val">${statusIcon(before.status)} ${esc(before.resultValue)}</span>
            <span class="compare-val">${statusIcon(after.status)} ${esc(after.resultValue)}</span>
            ${badgeHtml}
        </div>`;
    }).join('');

    gridEl.innerHTML = headerRow + dataRows;
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function clearComparison() {
    const panel = document.getElementById('compare-panel');
    if (panel) panel.classList.add('hidden');
}

// ═══════════════════════════════════════════════════════════════════
//  Result Filter Bar
// ═══════════════════════════════════════════════════════════════════
function updateFilterBar() {
    const bar = document.getElementById('filter-bar');
    const grid = document.getElementById('test-results');
    if (!bar || !grid) return;

    const hasResults = allResults.some(r => r.status && r.status !== 'NotRun' && r.status !== 'Pending');
    if (!hasResults) { bar.classList.add('hidden'); return; }

    bar.classList.remove('hidden');
    updateFilterCount();
}

function setResultFilter(filter) {
    const grid = document.getElementById('test-results');
    if (!grid) return;

    grid.dataset.filter = filter;

    // Update button active states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    updateFilterCount();
}

function updateFilterCount() {
    const countEl = document.getElementById('filter-count');
    if (!countEl) return;
    const grid = document.getElementById('test-results');
    const filter = grid?.dataset.filter || 'all';
    if (filter === 'all') { countEl.textContent = ''; return; }

    const FILTER_STATUSES = {
        failed:  ['failed', 'error'],
        warning: ['warning'],
        passed:  ['passed'],
        pending: ['pending', 'not-run']
    };
    const statuses = FILTER_STATUSES[filter] || [];
    const visible = document.querySelectorAll(`#test-results .test-item`);
    let shown = 0;
    visible.forEach(el => { if (statuses.includes(el.dataset.status)) shown++; });
    countEl.textContent = `${shown} test${shown !== 1 ? 's' : ''}`;
}

// ═══════════════════════════════════════════════════════════════════
//  Remediation Checklist
// ═══════════════════════════════════════════════════════════════════
function updateRemediationPanel() {
    const panel   = document.getElementById('remediation-panel');
    const listEl  = document.getElementById('rem-list');
    const countEl = document.getElementById('rem-count');
    if (!panel || !listEl) return;

    const FAILED = ['Failed', 'Error'];

    // Collect tests that have a problem status AND remediation text
    const actionable = allResults.filter(r =>
        (FAILED.includes(r.status) || r.status === 'Warning') &&
        r.remediationText && r.remediationText.trim()
    );

    if (actionable.length === 0) {
        panel.classList.add('hidden');
        return;
    }

    // Deduplicate by remediation text; keep the worst-severity entry
    const seen = new Map();
    for (const r of actionable) {
        const key = r.remediationText.trim();
        const existing = seen.get(key);
        if (!existing) {
            seen.set(key, r);
        } else if (FAILED.includes(r.status) && !FAILED.includes(existing.status)) {
            seen.set(key, r); // upgrade Warning → Failed
        }
    }

    // Sort: Failed/Error first, then Warning
    const items = [...seen.values()].sort((a, b) =>
        (FAILED.includes(a.status) ? 0 : 1) - (FAILED.includes(b.status) ? 0 : 1)
    );

    const esc = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    listEl.innerHTML = items.map(r => {
        const isFailed = FAILED.includes(r.status);
        const badgeCls  = isFailed ? 'rem-badge-fail' : 'rem-badge-warn';
        const badgeText = isFailed ? 'Failed' : 'Warning';
        const anchorId  = `test-${r.id}`;
        const scrollJs  = `document.getElementById('${esc(anchorId)}')?.scrollIntoView({behavior:'smooth',block:'center'})`;
        return `<li class="rem-item" onclick="${scrollJs}" title="Click to jump to test">
            <span class="rem-badge ${badgeCls}">${badgeText}</span>
            <span class="rem-test-id">${esc(r.id)}</span>
            <div class="rem-body">
                <span class="rem-test-name">${esc(r.name || r.id)}</span>
                <span class="rem-text">${esc(r.remediationText)}</span>
            </div>
            <span class="rem-arrow">→</span>
        </li>`;
    }).join('');

    const failCount = items.filter(r => FAILED.includes(r.status)).length;
    const warnCount = items.length - failCount;
    const parts = [];
    if (failCount) parts.push(`${failCount} failed`);
    if (warnCount) parts.push(`${warnCount} warning${warnCount > 1 ? 's' : ''}`);
    countEl.textContent = parts.join(', ');
    panel.classList.remove('hidden');
}

function saveResultsToHistory() {
    if (allResults.length === 0) return;
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const entry = {
            timestamp: new Date().toISOString(),
            scannerTimestamp: _importedScanTimestamp || null,
            summary: {
                total: allResults.length,
                passed: allResults.filter(r => r.status === 'Passed').length,
                warnings: allResults.filter(r => r.status === 'Warning').length,
                failed: allResults.filter(r => r.status === 'Failed' || r.status === 'Error').length,
            },
            // Store key metrics for comparison (not full results to save space)
            metrics: extractKeyMetrics(allResults)
        };

        // Don't save duplicate if last entry has same metric fingerprint
        if (history.length > 0) {
            const last = history[0];
            if (JSON.stringify(last.metrics) === JSON.stringify(entry.metrics)) return;
        }

        history.unshift(entry);
        if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) {
        console.warn('Failed to save history:', e);
    }
}

function extractKeyMetrics(results) {
    const r = id => results.find(x => x.id === id);
    const metrics = {};

    // WiFi signal
    const wifi = r('L-LE-04');
    if (wifi && wifi.status !== 'Skipped') {
        const m = (wifi.resultValue || '').match(/(\d+)%/);
        if (m) metrics.wifiSignal = parseInt(m[1]);
    }

    // Gateway latency
    const gw = r('L-LE-05');
    if (gw) {
        const m = (gw.resultValue || '').match(/([\d.]+)\s*ms/i);
        if (m) metrics.gatewayLatency = parseFloat(m[1]);
    }

    // Bandwidth
    const bw = r('L-LE-07') || r('B-LE-03');
    if (bw) {
        const m = (bw.resultValue || '').match(/([\d.]+)\s*Mbps/i);
        if (m) metrics.bandwidth = parseFloat(m[1]);
    }

    // Session latency
    const session = r('18');
    if (session) {
        const m = (session.resultValue || '').match(/([\d.]+)\s*ms/i);
        if (m) metrics.sessionLatency = parseFloat(m[1]);
    }

    // Jitter
    const jitter = r('20');
    if (jitter) {
        const m = (jitter.resultValue || '').match(/([\d.]+)\s*ms/i);
        if (m) metrics.jitter = parseFloat(m[1]);
    }

    // Packet loss
    const loss = r('21');
    if (loss) {
        const m = (loss.resultValue || '').match(/([\d.]+)%/);
        if (m) metrics.packetLoss = parseFloat(m[1]);
    }

    // NAT type
    const nat = r('L-UDP-05') || r('B-UDP-02');
    if (nat) metrics.natType = nat.resultValue || '';

    // Transport
    const transport = r('17b');
    if (transport) metrics.transport = transport.resultValue || '';

    // Pass/fail counts
    metrics.passed = results.filter(r => r.status === 'Passed').length;
    metrics.failed = results.filter(r => r.status === 'Failed' || r.status === 'Error').length;
    metrics.warnings = results.filter(r => r.status === 'Warning').length;

    return metrics;
}

function updateHistoryBar() {
    const bar = document.getElementById('history-bar');
    const select = document.getElementById('history-select');
    if (!bar || !select) return;

    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        if (history.length < 2) { bar.classList.add('hidden'); return; }

        // Show bar and populate dropdown (skip first entry = current)
        bar.classList.remove('hidden');
        select.innerHTML = '<option value="">Compare with previous scan...</option>';
        for (let i = 1; i < history.length; i++) {
            const h = history[i];
            const date = new Date(h.timestamp).toLocaleString();
            const summary = `${h.summary.passed}P / ${h.summary.warnings}W / ${h.summary.failed}F`;
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = `${date} — ${summary}`;
            select.appendChild(opt);
        }
    } catch (e) {
        bar.classList.add('hidden');
    }
}

function loadHistoryEntry(index) {
    const diffEl = document.getElementById('history-diff');
    if (!diffEl || !index) { if (diffEl) diffEl.classList.add('hidden'); return; }

    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const current = history[0];
        const previous = history[parseInt(index)];
        if (!current || !previous) return;

        const diffs = [];
        const cm = current.metrics;
        const pm = previous.metrics;

        function compareStat(label, currVal, prevVal, unit, lowerIsBetter) {
            if (currVal == null || prevVal == null) return;
            const delta = currVal - prevVal;
            if (Math.abs(delta) < 0.1) return;
            const improved = lowerIsBetter ? delta < 0 : delta > 0;
            const arrow = improved ? '\u2193' : '\u2191';
            const cls = improved ? 'diff-improved' : 'diff-degraded';
            const sign = delta > 0 ? '+' : '';
            diffs.push(`<div class="diff-item ${cls}"><span class="diff-arrow">${arrow}</span>${label}: ${prevVal}${unit} \u2192 ${currVal}${unit} <span class="diff-delta">(${sign}${delta.toFixed(1)}${unit})</span></div>`);
        }

        compareStat('WiFi Signal', cm.wifiSignal, pm.wifiSignal, '%', false);
        compareStat('Gateway Latency', cm.gatewayLatency, pm.gatewayLatency, ' ms', true);
        compareStat('Bandwidth', cm.bandwidth, pm.bandwidth, ' Mbps', false);
        compareStat('Session Latency', cm.sessionLatency, pm.sessionLatency, ' ms', true);
        compareStat('Jitter', cm.jitter, pm.jitter, ' ms', true);
        compareStat('Packet Loss', cm.packetLoss, pm.packetLoss, '%', true);

        // Pass/fail counts
        if (cm.passed !== pm.passed || cm.failed !== pm.failed || cm.warnings !== pm.warnings) {
            diffs.push(`<div class="diff-item diff-neutral">Overall: ${pm.passed}P/${pm.warnings}W/${pm.failed}F \u2192 ${cm.passed}P/${cm.warnings}W/${cm.failed}F</div>`);
        }

        if (diffs.length === 0) {
            diffEl.innerHTML = '<div class="diff-item diff-neutral">No significant changes detected.</div>';
        } else {
            diffEl.innerHTML = diffs.join('');
        }
        diffEl.classList.remove('hidden');
    } catch (e) {
        diffEl.classList.add('hidden');
    }
}

function clearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    const bar = document.getElementById('history-bar');
    if (bar) bar.classList.add('hidden');
}

// ── Satellite / Aircraft WiFi banner ──
function updateSatelliteBanner(results) {
    const banner = document.getElementById('satellite-banner');
    if (!banner) return;
    // Re-show if previously auto-hidden (don't override manual dismiss)
    if (typeof detectSatelliteConnection !== 'function') return;
    if (detectSatelliteConnection(results)) {
        // Populate the detail line with ISP name
        const ispResult = results.find(r => r.id === 'B-LE-02' || r.id === 'C-LE-02');
        const ispName = ispResult ? ispResult.resultValue.replace(/^AS\d+\s*/i, '') : '';
        const wifiResult = results.find(r => r.id === 'L-LE-04');
        const ssidMatch = wifiResult ? (wifiResult.resultValue || '').match(/SSID:\s*([^,]+)/i) : null;
        const ssid = ssidMatch ? ssidMatch[1].trim() : '';
        const detail = document.getElementById('satellite-banner-detail');
        if (detail) {
            const parts = [];
            if (ssid) parts.push(`SSID: ${ssid}`);
            if (ispName) parts.push(`ISP: ${ispName}`);
            detail.textContent = parts.length
                ? parts.join('  ·  ') + ' — results contextualised below.'
                : 'Some results will differ from normal broadband — this is expected.';
        }
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

// ── Key Findings panel (prominent at-a-glance RDP optimization summary) ──
async function updateKeyFindings(results) {
    const panel = document.getElementById('key-findings');
    const grid = document.getElementById('kf-grid');
    if (!panel || !grid) return;

    const r = id => results.find(x => x.id === id);
    const esc = s => s ? s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
    const hasAny = results.some(x => x.status && x.status !== 'NotRun' && x.status !== 'Pending');
    if (!hasAny) return;

    const rows = [];
    let issues = 0, warnings = 0;

    function flagImg(locationStr) {
        const cc = typeof resolveCountryCode === 'function' ? resolveCountryCode(locationStr || '') : '';
        if (!cc) return '';
        return `<img src="https://flagcdn.com/20x15/${cc}.png" alt="${cc.toUpperCase()}" width="20" height="15" class="country-flag" onerror="this.style.display='none'"> `;
    }
    function tag(cls, text) {
        return `<span class="kf-tag kf-tag-${cls}">${text}</span>`;
    }
    function add(cls, label, value, sub) {
        rows.push({ cls, label, value, sub: sub || '' });
        if (cls === 'kf-error') issues++;
        else if (cls === 'kf-issue') warnings++;
    }

    // ── 1. Your Location ──
    const loc = r('B-LE-01') || r('C-LE-01');
    if (loc && loc.status === 'Passed' && loc.resultValue && !loc.resultValue.includes('Unknown')) {
        const ip = extractLine(loc.detailedInfo, 'Public IP:');
        add('kf-info', 'Your Location',
            flagImg(loc.resultValue) + esc(loc.resultValue) + (ip ? ` · <span class="kf-sub">${esc(ip)}</span>` : ''));
    }

    // ── 1b. Host Type (Cloud PC vs AVD — only when running on session host) ──
    if (cloudPcMode) {
        const imds = r('C-NET-01');
        const label = hostType === 'avd' ? 'AVD Session Host' : 'Cloud PC (Windows 365)';
        let detail = '';
        if (imds && imds.detailedInfo) {
            const vmSize = extractLine(imds.detailedInfo, 'VM Size:');
            const region = extractLine(imds.detailedInfo, 'Azure Region:');
            const image = extractLine(imds.detailedInfo, 'Image:');
            const parts = [];
            if (region) parts.push(region);
            if (vmSize) parts.push(vmSize);
            if (image) parts.push(`<span class="kf-sub">${esc(image)}</span>`);
            detail = parts.join(' · ');
        }
        add('kf-info', 'Host Type', label + (detail ? ` · ${detail}` : ''));
    }

    // ── 2. RDP Egress ──
    const egress27 = r('27');
    const gw09 = r('L-TCP-09') || r('C-TCP-09');
    if (egress27 && egress27.detailedInfo) {
        const eLine = egress27.detailedInfo.split('\n').find(l => l.trim().startsWith('Your egress location:'));
        const val = eLine ? eLine.replace(/.*Your egress location:\s*/i, '').trim() : egress27.resultValue;
        if (val) add('kf-info', 'RDP Egress', flagImg(val) + esc(val));
    } else if (gw09 && gw09.detailedInfo) {
        const locLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('Your location:'));
        if (locLine) {
            const val = locLine.replace(/.*Your location:\s*/i, '').trim();
            add('kf-info', 'RDP Egress', flagImg(val) + esc(val));
        }
    }

    // ── 3. AFD Edge PoP ──
    const afd = r('B-TCP-02') || r('C-TCP-04');
    let afdPop = '';
    let afdLat = '';
    if (gw09 && gw09.detailedInfo) {
        const popLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('AFD PoP:'));
        if (popLine) afdPop = popLine.replace(/.*AFD PoP:\s*/i, '').trim();
    }
    if (!afdPop && afd) {
        if (afd.detailedInfo) {
            const popLine = afd.detailedInfo.split('\n').find(l => l.trim().startsWith('AFD PoP:'));
            if (popLine) afdPop = popLine.replace(/.*AFD PoP:\s*/i, '').trim();
        }
        if (!afdPop) afdPop = (afd.resultValue || '').replace(/^[✓✗⚠]\s*/, '').replace(/\s*[—–-]\s*\d+ms$/, '').trim();
    }
    if (afd && afd.detailedInfo) {
        const latLine = afd.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
        if (latLine) { const m = latLine.match(/avg\s+(\d+)ms/); if (m) afdLat = m[1] + 'ms'; }
    }
    if (afdPop || (afd && afd.status !== 'NotRun' && afd.status !== 'Pending')) {
        if (!afd || afd.status === 'Passed' || afd.status === 'Warning') {
            const latPart = afdLat ? ` · ${afdLat}` : '';
            add('kf-pass', 'AFD Edge', flagImg(afdPop) + esc(afdPop || 'Connected') + latPart);
        } else {
            add('kf-error', 'AFD Edge', 'Unreachable — TCP 443 to Azure Front Door failed');
        }
    }

    // ── 4. RDP Gateway ──
    if (gw09 && gw09.detailedInfo) {
        const regionVal = extractLine(gw09.detailedInfo, 'Azure Region:');
        const geoVal = extractLine(gw09.detailedInfo, 'GeoIP Location:');
        const distVal = extractLine(gw09.detailedInfo, 'Distance from you:');
        let gwStr = regionVal || geoVal || gw09.resultValue || '';
        if (geoVal && regionVal) gwStr = `${regionVal} (${geoVal})`;
        // TCP latency
        const gw04 = r('L-TCP-04');
        let latMs = '';
        if (gw04 && gw04.detailedInfo) {
            const lines = gw04.detailedInfo.split('\n');
            const gwIdx = lines.findIndex(l => l.includes('[RDP Gateway]'));
            if (gwIdx >= 0) {
                const tcpLine = lines.slice(gwIdx).find(l => l.trim().match(/TCP connected in \d+ms/));
                if (tcpLine) { const m = tcpLine.match(/(\d+)ms/); if (m) latMs = m[1] + 'ms TCP'; }
            }
        }
        const parts = [flagImg(geoVal || regionVal) + esc(gwStr)];
        if (latMs) parts[0] += ` · ${latMs}`;
        // Proximity indicator
        if (distVal) {
            const isNearby = distVal.includes('✔') || distVal.toLowerCase().includes('nearby');
            const isFar = distVal.includes('⚠') || distVal.toLowerCase().includes('far');
            if (isNearby) parts[0] += ' ' + tag('pass', '✔ Nearby');
            else if (isFar) parts[0] += ' ' + tag('warn', '⚠ Far');
        }
        add('kf-pass', 'RDP Gateway', parts[0], distVal && !distVal.includes('✔') && !distVal.includes('⚠') ? esc(distVal) : '');
    }

    // ── 5. TURN Relay ──
    const turn04 = r('L-UDP-04') || r('C-UDP-04');
    if (turn04 && turn04.status !== 'Skipped' && turn04.resultValue) {
        const turnLoc = turn04.resultValue;
        const turn03 = r('L-UDP-03') || r('C-UDP-03');
        let lat = '';
        if (turn03 && turn03.status === 'Passed') {
            if (turn03.detailedInfo) {
                const latLine = turn03.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
                if (latLine) lat = latLine.replace(/.*Latency:\s*/i, '').trim();
            }
            if (!lat) { const m = (turn03.resultValue || '').match(/(\d+)\s*ms/); if (m) lat = m[1] + 'ms'; }
        }
        const latPart = lat ? ` · ${esc(lat)}` : '';
        if (turn03 && turn03.status === 'Failed') {
            add('kf-error', 'TURN Relay', 'Unreachable — UDP 3478 blocked');
        } else {
            add('kf-pass', 'TURN Relay', flagImg(turnLoc) + esc(turnLoc) + latPart);
        }
    }

    // ── 6. NAT Type & Shortpath ──
    const natType = r('L-UDP-05') || r('B-UDP-02');
    if (natType && natType.status !== 'NotRun' && natType.status !== 'Pending') {
        const val = (natType.resultValue || '').toLowerCase();
        const src = r('L-UDP-05') ? 'Scanner' : 'Browser';
        if (val.includes('cone') || val.includes('open internet')) {
            const label = val.includes('open internet') ? 'Open Internet (No NAT)' : 'Cone NAT';
            add('kf-pass', 'NAT Type', label + ' ' + tag('pass', 'Shortpath Ready'), `Source: ${src}`);
        } else if (val.includes('symmetric')) {
            add('kf-issue', 'NAT Type', 'Symmetric NAT ' + tag('warn', 'TURN Fallback'), `STUN hole-punching unlikely · Source: ${src}`);
        } else if (val.includes('blocked') || val.includes('failed')) {
            add('kf-info', 'NAT Type', 'STUN unavailable ' + tag('info', 'TURN relay used'), `Source: ${src}`);
        } else if (val.includes('stun ok') || val.includes('partial')) {
            add('kf-pass', 'NAT Type', esc(natType.resultValue || 'STUN OK'), `Source: ${src}`);
        } else {
            add('kf-info', 'NAT Type', esc(natType.resultValue || 'Unknown'), `Source: ${src}`);
        }
    }

    // ── 6b. Split-path Routing (HTTP TCP egress vs STUN UDP egress) ──
    {
        let httpEgressIp = '', httpCountry = '', httpCity = '';
        const locResult = r('B-LE-01');
        if (locResult?.detailedInfo) {
            const mIp = locResult.detailedInfo.match(/Public IP:\s*(\S+)/);
            if (mIp) httpEgressIp = mIp[1];
            const rvParts = (locResult.resultValue || '').split(',').map(s => s.trim());
            if (rvParts.length >= 2) httpCountry = rvParts[rvParts.length - 1];
            if (rvParts.length >= 3) httpCity = rvParts[0];
        }
        let stunReflexiveIp = '';
        const stunResult = r('B-UDP-01');
        if (stunResult?.detailedInfo) {
            const m = stunResult.detailedInfo.match(/Reflexive IP:\s*(\S+)/);
            if (m) stunReflexiveIp = m[1];
        }
        if (httpEgressIp && stunReflexiveIp) {
            if (httpEgressIp === stunReflexiveIp) {
                // Same IP — no split-path (don't show, it's noise when everything is fine)
            } else {
                // IPs differ — GeoIP the STUN IP to distinguish CGNAT vs proxy
                let stunCountry = '', stunCity = '';
                try {
                    const geoResp = await fetch(`https://ipinfo.io/${stunReflexiveIp}/json`, {
                        signal: AbortSignal.timeout(5000), cache: 'no-store'
                    });
                    if (geoResp.ok) {
                        const geoData = await geoResp.json();
                        stunCountry = geoData.country || '';
                        stunCity = geoData.city || '';
                    }
                } catch { /* GeoIP lookup failed */ }

                if (stunCountry && httpCountry &&
                    stunCountry.toUpperCase() === httpCountry.toUpperCase()) {
                    // Same country — CGNAT
                    const natVal = (natType?.resultValue || '').toLowerCase();
                    if (natVal.includes('symmetric')) {
                        add('kf-issue', 'CGNAT', 'Carrier-Grade NAT detected — Symmetric NAT confirmed',
                            'STUN hole-punching unavailable; RDP Shortpath will use TURN relay');
                    } else {
                        add('kf-info', 'CGNAT', 'Carrier-Grade NAT detected — NAT traversal still possible',
                            `HTTP: ${esc(httpEgressIp)} · STUN: ${esc(stunReflexiveIp)} (same country)`);
                    }
                } else if (stunCountry && httpCountry) {
                    // Different countries — split-path proxy
                    add('kf-error', 'Split Routing',
                        `🔺 TCP/UDP taking different paths — HTTP proxy or SWG likely`,
                        `HTTP: ${esc(httpEgressIp)} [${esc(httpCity)}, ${esc(httpCountry)}] · STUN: ${esc(stunReflexiveIp)} [${esc(stunCity)}, ${esc(stunCountry)}]`);
                } else if (httpEgressIp !== stunReflexiveIp) {
                    add('kf-info', 'Split Routing',
                        `Different egress IPs detected (may be CGNAT)`,
                        `HTTP: ${esc(httpEgressIp)} · STUN: ${esc(stunReflexiveIp)}`);
                }
            }
        }
    }

    // ── 7. VPN / Proxy / SWG ──
    const rdpOptLink = '<a href="https://learn.microsoft.com/en-us/windows-365/enterprise/optimization-of-rdp" target="_blank" rel="noopener">RDP optimization guide</a>';
    const vpnTcp = r('L-TCP-07') || r('C-TCP-07');
    const vpnUdp = r('L-UDP-07') || r('C-UDP-07');

    if (vpnTcp && vpnTcp.status !== 'NotRun' && vpnTcp.status !== 'Pending') {
        const tcpPass = vpnTcp.status === 'Passed';
        const udpPass = !vpnUdp || vpnUdp.status === 'Passed';
        const tcpTimedOut = !tcpPass && /timed out/i.test(vpnTcp.resultValue);
        const udpTimedOut = vpnUdp && vpnUdp.status !== 'Passed' && /timed out/i.test(vpnUdp.resultValue);
        const vpnNames = extractVpnNames([vpnTcp, vpnUdp]);
        const vpnNameStr = vpnNames.length ? vpnNames.map(n => esc(n)).join(', ') : '';
        // If VPN names were found in any test data (resultValue or detailedInfo) and tests passed,
        // the VPN is present but RDP is being correctly bypassed (otherwise status would be Warning).
        const vpnDetectedAnywhere = vpnNames.length > 0;
        if (tcpTimedOut && udpPass) {
            // TCP test timed out but UDP is clean — infer VPN status from UDP
            const udpBypassed = vpnDetectedAnywhere ||
                (vpnUdp && /bypassed|split-tunnel/i.test(vpnUdp.resultValue));
            if (udpBypassed) {
                add('kf-pass', 'VPN / Proxy',
                    `✓ ${vpnNameStr ? vpnNameStr + ' — ' : ''}RDP correctly bypassed (split-tunnel)`,
                    (vpnNameStr ? `VPN detected: ${vpnNameStr}<br>` : '') +
                    'TCP test timed out (slow WPAD auto-discovery) — UDP path confirmed split-tunnel<br>' + `See ${rdpOptLink}`);
            } else {
                add('kf-pass', 'VPN / Proxy', 'None detected — direct routing',
                    'Note: TCP test timed out (slow WPAD auto-discovery) — UDP path confirmed clean');
            }
        } else if (tcpPass && udpPass) {
            // Check if VPN/SWG was detected but RDP correctly bypasses it
            const bypassed = vpnDetectedAnywhere ||
                /bypassed|split-tunnel/i.test(vpnTcp.resultValue) ||
                             (vpnUdp && /bypassed|split-tunnel/i.test(vpnUdp.resultValue));
            if (bypassed) {
                add('kf-pass', 'VPN / Proxy',
                    `✓ ${vpnNameStr ? vpnNameStr + ' — ' : ''}RDP correctly bypassed (split-tunnel)`,
                    (vpnNameStr ? `VPN/SWG detected: ${vpnNameStr}<br>` : '') +
                    `Both TCP and UDP paths bypass VPN — split-tunnel working correctly<br>See ${rdpOptLink}`);
            } else {
                add('kf-pass', 'VPN / Proxy', 'None detected — direct routing');
            }
        } else {
            const vpnDetail = vpnNameStr ? `Detected: ${vpnNameStr}` : '';
            // If both tests timed out (not a proxy/VPN issue — just slow checks)
            if (tcpTimedOut && udpTimedOut) {
                add('kf-pass', 'VPN / Proxy', '⚠ Tests timed out — could not determine',
                    'Both TCP and UDP VPN/proxy detection tests timed out. This typically indicates slow WPAD auto-discovery or firewall rule enumeration.<br>' + `See ${rdpOptLink}`);
            } else {
                // Check if one path is bypassed but the other isn't
                const tcpBypassed = tcpPass && /bypassed|split-tunnel/i.test(vpnTcp.resultValue);
                const udpBypassed = vpnUdp && vpnUdp.status === 'Passed' && /bypassed|split-tunnel/i.test(vpnUdp.resultValue);
                const which = [];
                if (!tcpPass && !tcpTimedOut) which.push('TCP' + (udpBypassed ? ' (UDP bypassed ✓)' : ''));
                if (vpnUdp && vpnUdp.status !== 'Passed' && !udpTimedOut) which.push('UDP' + (tcpBypassed ? ' (TCP bypassed ✓)' : ''));
                if (which.length > 0) {
                    add('kf-error', 'VPN / Proxy',
                        `🔺 Intercepting ${which.join(' & ')} path — causes higher latency, reduced performance &amp; reliability`,
                        (vpnDetail ? vpnDetail + '<br>' : '') + `See ${rdpOptLink}`);
                } else {
                    // One timed out but the other has real issues — show generic warning
                    add('kf-error', 'VPN / Proxy',
                        '⚠ Proxy/VPN/SWG issues detected',
                        (vpnDetail ? vpnDetail + '<br>' : '') + `See ${rdpOptLink}`);
                }
            }
        }
    }

    // ── 8. TLS Inspection ──
    const tlsTcp = r('L-TCP-06');
    const tlsUdp = r('L-UDP-06');
    if (tlsTcp && tlsTcp.status !== 'NotRun' && tlsTcp.status !== 'Pending') {
        const tcpClean = tlsTcp.status === 'Passed';
        const udpClean = !tlsUdp || tlsUdp.status === 'Passed' || tlsUdp.status === 'NotRun';
        if (tcpClean && udpClean) {
            add('kf-pass', 'TLS Inspection', 'None — certificates direct from Microsoft');
        } else {
            const paths = [];
            if (!tcpClean) paths.push('TCP');
            if (tlsUdp && tlsUdp.status !== 'Passed' && tlsUdp.status !== 'NotRun') paths.push('UDP');
            add('kf-error', 'TLS Inspection',
                `🔺 Detected on ${paths.join(' & ')} — decrypting/re-encrypting adds latency and degrades reliability`,
                `See ${rdpOptLink}`);
        }
    }

    // ── 9. DNS ──
    const dns03 = r('B-TCP-03');
    const dnsHijack = r('L-TCP-08');
    if (dns03 && dns03.status !== 'NotRun' && dns03.status !== 'Pending') {
        let dnsLatMs = null;
        if (dns03.detailedInfo) {
            const m = dns03.detailedInfo.match(/avg\s+(\d+)ms/i) || dns03.detailedInfo.match(/(\d+)\s*ms/);
            if (m) dnsLatMs = parseInt(m[1]);
        }
        const hijacked = dnsHijack && dnsHijack.status !== 'Passed' && dnsHijack.status !== 'NotRun' && dnsHijack.status !== 'Pending';
        if (hijacked) {
            add('kf-error', 'DNS', 'Hijacking detected — responses being altered');
        } else if (dnsLatMs != null && dnsLatMs > 100) {
            add('kf-issue', 'DNS', `Slow — ${dnsLatMs}ms avg (delays connection setup)`);
        } else if (dns03.status === 'Passed') {
            add('kf-pass', 'DNS', `Healthy${dnsLatMs != null ? ` · ${dnsLatMs}ms` : ''}`);
        } else {
            add('kf-issue', 'DNS', esc(dns03.resultValue || 'Issues detected'));
        }
    }

    // ── 10. Local Network ──
    const gw05 = r('L-LE-05');
    const wifi = r('L-LE-04');
    const wifiCh = r('L-LE-12');
    const localParts = [];
    let localCls = 'kf-pass';
    if (gw05 && gw05.status !== 'NotRun' && gw05.status !== 'Pending') {
        let gwMs = null;
        if (gw05.resultValue) { const m = gw05.resultValue.match(/(\d+)\s*ms/); if (m) gwMs = parseInt(m[1]); }
        if (gwMs != null) {
            if (gwMs >= 50) { localParts.push(`${gwMs}ms to gateway (high)`); localCls = 'kf-issue'; }
            else localParts.push(`${gwMs}ms to gateway`);
        }
    }
    if (wifi && wifi.status === 'Warning') {
        localParts.push('Weak WiFi signal');
        localCls = 'kf-issue';
    } else if (wifi && wifi.status === 'Passed') {
        localParts.push('WiFi OK');
    }
    if (wifiCh && wifiCh.status === 'Warning') {
        localParts.push('WiFi congestion');
        localCls = 'kf-issue';
    }
    if (localParts.length > 0) {
        add(localCls, 'Local Network', localParts.join(' · '));
    }

    // ── Render ──
    if (rows.length === 0) return;

    grid.innerHTML = rows.map(it =>
        `<div class="kf-row ${it.cls}">` +
            `<span class="kf-dot"></span>` +
            `<span class="kf-row-label">${it.label}</span>` +
            `<span class="kf-row-val">${it.value}${it.sub ? `<br><span class="kf-sub">${it.sub}</span>` : ''}</span>` +
        `</div>`
    ).join('');

    // Overall verdict
    const verdict = document.getElementById('kf-verdict');
    if (verdict) {
        if (issues > 0) {
            verdict.textContent = `${issues} issue${issues > 1 ? 's' : ''} need attention`;
            verdict.className = 'kf-verdict kf-fail';
        } else if (warnings > 0) {
            verdict.textContent = `${warnings} warning${warnings > 1 ? 's' : ''}`;
            verdict.className = 'kf-verdict kf-warn';
        } else {
            verdict.textContent = 'Looking good';
            verdict.className = 'kf-verdict kf-good';
        }
    }

    panel.classList.remove('hidden');
}
