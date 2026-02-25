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
        updateConnectivityOverview(allResults);
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

// ── Run all browser tests ──
async function runAllBrowserTests() {
    if (isRunning) return;
    isRunning = true;

    const btn = document.getElementById('btn-run-all');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">\u27F3</span> Running...';

    // Hide info banner
    document.getElementById('info-banner').classList.add('hidden');

    const browserTests = ALL_TESTS.filter(t => t.source === 'browser' && t.run);
    const total = browserTests.length;
    let completed = 0;

    // Reset browser results (keep imported local results)
    allResults = allResults.filter(r => r.source === 'local');

    // Clear GeoIP and user-location caches so location is re-fetched fresh
    if (typeof resetGeoCache === 'function') resetGeoCache();
    if (typeof resetUserLocCache === 'function') resetUserLocCache();

    // Show progress
    updateProgress(0, total, browserTests[0]?.name);

    for (const test of browserTests) {
        setTestRunning(test.id);
        updateProgress(completed, total, test.name);

        try {
            const result = await test.run(test);
            result.source = 'browser';
            allResults.push(result);
            updateTestUI(test.id, result);
            updateConnectivityMap(allResults);
        } catch (err) {
            const errorResult = {
                id: test.id,
                name: test.name,
                category: test.category,
                source: 'browser',
                status: 'Error',
                resultValue: `Error: ${err.message}`,
                detailedInfo: err.stack || err.message,
                duration: 0
            };
            allResults.push(errorResult);
            updateTestUI(test.id, errorResult);
            updateConnectivityMap(allResults);
        }

        completed++;
        updateProgress(completed, total);
    }

    hideProgress();
    updateSummary(allResults);
    updateCategoryBadges(allResults);
    updateConnectivityMap(allResults);
    updateConnectivityOverview(allResults);
    updateExportButton();

    // Only show download banner if no scanner results have been imported
    const hasLocalResults = allResults.some(r => r.source === 'local');
    if (!hasLocalResults) showDownloadBanner();

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">\u25B6</span> Re-run Browser Tests';
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
    const parsed = JSON.parse(json);
    ilog('Parsed JSON: ' + (parsed.results?.length ?? 0) + ' results, machine=' + (parsed.machineName || 'unknown'));
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
    // The local scanner outputs: { timestamp, machineName, results: [...] }
    let localResults = [];
    if (Array.isArray(data.results)) {
        localResults = data.results;
    } else if (Array.isArray(data)) {
        localResults = data;
    } else {
        alert('Invalid results file. Expected JSON with a "results" array.');
        return;
    }

    // Remember when the scanner data was captured
    if (data.timestamp) {
        try { _importedScanTimestamp = new Date(data.timestamp).toLocaleString(); } catch { _importedScanTimestamp = String(data.timestamp); }
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
                source: 'local',
                status: lr.status || 'Passed',
                resultValue: lr.resultValue || lr.result || '',
                detailedInfo: lr.detailedInfo || lr.details || '',
                duration: lr.duration || 0,
                remediationUrl: lr.remediationUrl || '',
                remediationText: lr.remediationText || ''
            };

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
    // Update summary and badges
    updateSummary(allResults);
    updateCategoryBadges(allResults);
    updateConnectivityMap(allResults);
    updateConnectivityOverview(allResults);
    updateExportButton();
    const info = document.getElementById('info-banner');
    info.classList.remove('hidden');
    const machineName = data.machineName ? escapeHtml(String(data.machineName)) : '';
    const scanTime = data.timestamp ? escapeHtml(new Date(data.timestamp).toLocaleString()) : '';
    info.querySelector('.info-text').innerHTML =
        `<strong>Imported ${importedCount} local scan results.</strong> ` +
        (machineName ? `Machine: ${machineName}. ` : '') +
        (scanTime ? `Scanned: ${scanTime}. ` : '') +
        'Combined results are shown below.';

    // Hide download banner if we have local results
    if (importedCount > 0) hideDownloadBanner();

    // Hide the cloud info bar if we imported any cloud results
    const hasCloudResults = allResults.some(r => r.category === 'cloud' && r.source === 'local');
    if (hasCloudResults) {
        const cloudInfoBar = document.getElementById('cloud-info-bar');
        if (cloudInfoBar) cloudInfoBar.style.display = 'none';
    }

    // Hide stale "Requires Local Scanner" cards whose IDs weren't in the import.
    // This handles scanner versions that use different IDs (e.g. L-CS-01 vs 17).
    const importedIds = new Set(localResults.map(r => String(r.id)));
    for (const test of ALL_TESTS) {
        if (test.source !== 'local') continue;
        if (importedIds.has(String(test.id))) continue;
        // This test was NOT in the scanner output — hide the placeholder card
        const el = document.getElementById(`test-${test.id}`);
        if (el) el.style.display = 'none';
    }
}

// ── Helpers ──
function mapCategoryFromId(id) {
    if (!id) return 'local';
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
            const icon = tcpVpn.status === 'Passed' ? '✓' : '⚠';
            lines.push(`    ${icon} Proxy/VPN/SWG:    ${tcpVpn.resultValue}`);
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
            nLabel = 'STUN blocked — UDP 3478 unreachable';
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
            const icon = turnVpn.status === 'Passed' ? '✓' : '⚠';
            lines.push(`    ${icon} Proxy/VPN/SWG:    ${turnVpn.resultValue}`);
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
        cloud: 'Live Connection Diagnostics'
    };
    const categories = ['local', 'endpoint', 'tcp', 'udp', 'cloud'];

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
            const src = r.source === 'local' ? ' [Local Scanner]' : ' [Browser]';

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
}

// ═══════════════════════════════════════════════════════════════════
//  JSON Export
// ═══════════════════════════════════════════════════════════════════
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

        // Build a compact payload (same format as the scanner)
        const payload = {
            timestamp: new Date().toISOString(),
            machineName: 'WebExport',
            results: allResults.map(r => ({
                id: r.id, name: r.name, category: r.category,
                status: r.status, resultValue: r.resultValue || '',
                detailedInfo: r.detailedInfo || '', duration: r.duration || 0,
                remediationUrl: r.remediationUrl || '', remediationText: r.remediationText || ''
            }))
        };
        const json = JSON.stringify(payload);

        // Compress with deflate-raw (same as scanner)
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

        // Check URL length — most browsers support ~65k, but warn if very large
        if (shareUrl.length > 60000) {
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
    updateConnectivityOverview(allResults);
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

// ── Connectivity Overview panel (quick-glance summary above the map) ──
async function updateConnectivityOverview(results) {
    const panel = document.getElementById('connectivity-overview');
    if (!panel || results.length === 0) return;

    const r = id => results.find(x => x.id === id);
    const esc = s => s ? s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';

    // Use shared resolveCountryCode from map.js (handles ", XX", AFD PoP codes,
    // Azure region names, and prefixed TURN/Gateway strings)
    const getCountryCode = resolveCountryCode;

    // Set a large flag image in a dedicated flag element
    function setCardFlag(flagElId, countryCode) {
        const el = document.getElementById(flagElId);
        if (!el || !countryCode) { if (el) el.innerHTML = ''; return; }
        el.innerHTML = `<img src="https://flagcdn.com/40x30/${countryCode}.png" alt="${countryCode.toUpperCase()}" width="40" height="30" onerror="this.style.display='none'">`;
    }

    // Helper: build an HTML string with a country-flag <img> prepended if a 2-letter code is found
    function flagHtml(locationStr) {
        const code = resolveCountryCode(locationStr || '');
        if (!code) return '';
        return `<img src="https://flagcdn.com/20x15/${code}.png" alt="${code.toUpperCase()}" width="20" height="15" class="country-flag" onerror="this.style.display='none'"> `;
    }

    // setVal that prepends a flag when the value looks like a location string
    const setVal = (elId, html, locationStr) => {
        const el = document.getElementById(elId);
        if (!el) return;
        el.innerHTML = (locationStr ? flagHtml(locationStr) : '') + html;
    };

    let hasContent = false;

    // 1. User Location — use shared resolver (browser geolocation + GeoIP)
    resetUserLocCache();
    const freshLoc = await fetchUserLocation();
    if (freshLoc) {
        // Show city only when from browser geolocation (GeoIP city is ISP-registered, often wrong)
        const locStr = freshLoc.source === 'browser'
            ? `${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}`
            : `${freshLoc.region}, ${freshLoc.country}`;
        // Also refresh B-LE-01 in allResults so the map stays in sync
        const existing = allResults.find(x => x.id === 'B-LE-01');
        if (existing) {
            existing.resultValue = locStr;
            existing.detailedInfo = `Public IP: ${freshLoc.ip}\nLocation: ${freshLoc.city}, ${freshLoc.region}, ${freshLoc.country}\nCoordinates: ${freshLoc.lat}, ${freshLoc.lon}\nSource: ${freshLoc.source === 'browser' ? 'Browser Geolocation' : 'GeoIP'}`;
            existing.status = 'Passed';
            updateTestUI('B-LE-01', existing);
            updateConnectivityMap(allResults);
        }
        setVal('ov-user-location-val',
            esc(locStr) + `  <span class="ov-dim">(IP: ${esc(freshLoc.ip)})</span>`,
            locStr);
        hasContent = true;
    } else {
        const userLoc = r('B-LE-01');
        if (userLoc && userLoc.status === 'Passed') {
            const ip = extractLine(userLoc.detailedInfo, 'Public IP:');
            setVal('ov-user-location-val',
                esc(userLoc.resultValue) + (ip ? `  <span class="ov-dim">(IP: ${esc(ip)})</span>` : ''),
                userLoc.resultValue);
            hasContent = true;
        }
    }

    // 2. RDP Egress (test 27, fallback to L-TCP-09 "Your location:")
    const egress27 = r('27');
    if (egress27 && egress27.detailedInfo) {
        const eLine = egress27.detailedInfo.split('\n').find(l => l.trim().startsWith('Your egress location:'));
        const egressVal = eLine ? eLine.replace(/.*Your egress location:\s*/i, '').trim() : egress27.resultValue;
        setVal('ov-rdp-egress-val', esc(egressVal), egressVal);
        hasContent = true;
    } else {
        const gw09f = r('L-TCP-09');
        if (gw09f && gw09f.detailedInfo) {
            const locLine = gw09f.detailedInfo.split('\n').find(l => l.trim().startsWith('Your location:'));
            if (locLine) {
                const locVal = locLine.replace(/.*Your location:\s*/i, '').trim();
                setVal('ov-rdp-egress-val', esc(locVal) + ' <span class="ov-dim">(scanner GeoIP)</span>', locVal);
                hasContent = true;
            } else {
                setVal('ov-rdp-egress-val', '<span class="ov-dim">Requires Local Scanner</span>');
            }
        } else {
            setVal('ov-rdp-egress-val', '<span class="ov-dim">Requires Local Scanner</span>');
        }
    }

    // 3. AFD Edge PoP (L-TCP-09 or B-TCP-02)
    const gw09 = r('L-TCP-09');
    const afd02 = r('B-TCP-02');
    let afdPopStr = '';

    // Helper: extract clean AFD PoP string from B-TCP-02 detailedInfo or resultValue
    function getAfdPopFromBrowser(test) {
        if (!test) return '';
        if (test.detailedInfo) {
            const popLine = test.detailedInfo.split('\n').find(l => l.trim().startsWith('AFD PoP:'));
            if (popLine) return popLine.replace(/.*AFD PoP:\s*/i, '').trim();
        }
        // Strip "✓ " prefix and " — Nms" suffix from resultValue
        return (test.resultValue || '').replace(/^[✓✗⚠]\s*/, '').replace(/\s*[—–-]\s*\d+ms$/, '').trim();
    }

    if (gw09 && gw09.detailedInfo) {
        const popLine = gw09.detailedInfo.split('\n').find(l => l.trim().startsWith('AFD PoP:'));
        if (popLine) {
            afdPopStr = popLine.replace(/.*AFD PoP:\s*/i, '').trim();
            setVal('ov-afd-pop-val', esc(afdPopStr));
            hasContent = true;
        } else if (afd02) {
            afdPopStr = getAfdPopFromBrowser(afd02);
            setVal('ov-afd-pop-val', esc(afdPopStr));
            hasContent = true;
        }
    } else if (afd02 && afd02.status !== 'NotRun') {
        afdPopStr = getAfdPopFromBrowser(afd02);
        setVal('ov-afd-pop-val', esc(afdPopStr));
        hasContent = true;
    }
    // Set AFD card flag from PoP airport code
    setCardFlag('ov-afd-flag', getCountryCode(afdPopStr));
    // AFD latency from B-TCP-02
    if (afd02 && afd02.detailedInfo) {
        const afdLatLine = afd02.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
        if (afdLatLine) {
            const avgMatch = afdLatLine.match(/avg\s+(\d+)ms/);
            if (avgMatch) setVal('ov-afd-latency-val', `${avgMatch[1]}ms`);
        } else {
            const statusLine = afd02.detailedInfo.split('\n').find(l => l.includes('Connected'));
            if (statusLine) {
                const msMatch = statusLine.match(/(\d+)ms/);
                if (msMatch) setVal('ov-afd-latency-val', `${msMatch[1]}ms`);
            }
        }
    }

    // 4. RDP Gateway Location & Latency
    if (gw09 && gw09.detailedInfo) {
        const regionVal = extractLine(gw09.detailedInfo, 'Azure Region:');
        const geoVal = extractLine(gw09.detailedInfo, 'GeoIP Location:');
        const distVal = extractLine(gw09.detailedInfo, 'Distance from you:');
        let gwLocHtml = esc(regionVal || geoVal || gw09.resultValue);
        const gwLoc = geoVal || regionVal || '';  // for flag
        if (geoVal && regionVal) gwLocHtml = `${esc(regionVal)} <span class="ov-dim">(${esc(geoVal)})</span>`;
        if (distVal) gwLocHtml += `<br><span class="ov-dim">${esc(distVal)}</span>`;

        setVal('ov-rdp-gateway-val', gwLocHtml);
        setCardFlag('ov-gateway-flag', getCountryCode(gwLoc));

        // TCP latency from L-TCP-04
        const gw04 = r('L-TCP-04');
        if (gw04 && gw04.detailedInfo) {
            const tcpLine = gw04.detailedInfo.split('\n').find(l => l.includes('[RDP Gateway]'));
            if (tcpLine) {
                const latLine = gw04.detailedInfo.split('\n')
                    .slice(gw04.detailedInfo.split('\n').indexOf(tcpLine))
                    .find(l => l.trim().match(/TCP connected in \d+ms/));
                if (latLine) {
                    const ms = latLine.match(/(\d+)ms/);
                    if (ms) setVal('ov-rdp-gateway-latency-val', `${ms[1]}ms TCP`);
                }
            }
        }
        hasContent = true;
    } else {
        setVal('ov-rdp-gateway-val', '<span class="ov-dim">Requires Local Scanner</span>');
    }

    // 5. TURN Relay Location & Latency
    const turn04 = r('L-UDP-04');
    if (turn04 && turn04.status !== 'Skipped') {
        const turnLoc = turn04.resultValue || 'Unknown';
        setVal('ov-turn-relay-val', esc(turnLoc));
        setCardFlag('ov-turn-flag', getCountryCode(turnLoc));

        const turn03 = r('L-UDP-03');
        if (turn03 && turn03.status === 'Passed') {
            let latMs = '';
            if (turn03.detailedInfo) {
                const latLine = turn03.detailedInfo.split('\n').find(l => l.trim().startsWith('Latency:'));
                if (latLine) latMs = latLine.replace(/.*Latency:\s*/i, '').trim();
            }
            if (!latMs) {
                const rttMatch = (turn03.resultValue || '').match(/(\d+)\s*ms\s*RTT/i);
                if (rttMatch) latMs = `${rttMatch[1]}ms`;
            }
            if (latMs) setVal('ov-turn-relay-latency-val', `${esc(latMs)} RTT`);
        }
        hasContent = true;
    } else {
        setVal('ov-turn-relay-val', '<span class="ov-dim">Requires Local Scanner</span>');
    }

    // 6. TCP-based RDP Path Optimization
    // Browser-native split-path detection: compare HTTP egress IP vs STUN reflexive IP.
    // HTTP fetch goes through the browser's proxy stack (TCP); STUN uses raw UDP.
    // If the two IPs differ AND geolocate to different countries,
    // an HTTP proxy/SWG is routing TCP traffic differently from UDP.
    // Note: CGNAT (common on French ISPs etc.) can assign different public IPs
    // to TCP vs UDP from the same ISP — that's NOT a proxy.
    // This is distinct from L-TCP-07/L-UDP-07 which check the specific RDP path
    // from the scanner side; this check uses browser-level egress comparison.
    let splitPathTcpHtml = '';
    let splitPathUdpHtml = '';
    let httpEgressIp = freshLoc?.ip || '';
    let httpCountry = freshLoc?.country || '';
    let httpCity = freshLoc?.source === 'browser' ? (freshLoc?.city || '') : '';
    if (!httpEgressIp) {
        const locResult = r('B-LE-01');
        if (locResult?.detailedInfo) {
            const m = locResult.detailedInfo.match(/Public IP:\s*(\S+)/);
            if (m) httpEgressIp = m[1];
        }
    }
    let stunReflexiveIp = '';
    const stunResult = r('B-UDP-01');
    if (stunResult?.detailedInfo) {
        const m = stunResult.detailedInfo.match(/Reflexive IP:\s*(\S+)/);
        if (m) stunReflexiveIp = m[1];
    }
    let isCgnat = false;
    let isSplitPath = false;
    if (httpEgressIp && stunReflexiveIp) {
        if (httpEgressIp === stunReflexiveIp) {
            splitPathTcpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>Split-path routing not detected</div>`;
            splitPathUdpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>Split-path routing not detected</div>`;
        } else {
            // IPs differ — could be CGNAT or a real proxy. GeoIP the STUN IP to compare.
            let stunCountry = '';
            let stunCity = '';
            try {
                const geoResp = await fetch(`https://ipinfo.io/${stunReflexiveIp}/json`, {
                    signal: AbortSignal.timeout(5000), cache: 'no-store'
                });
                if (geoResp.ok) {
                    const geoData = await geoResp.json();
                    stunCountry = geoData.country || '';
                    stunCity = geoData.city || '';
                }
            } catch (e) { /* GeoIP lookup failed — fall through */ }

            if (stunCountry && httpCountry &&
                stunCountry.toUpperCase() === httpCountry.toUpperCase()) {
                // Same country — CGNAT, not a proxy
                isCgnat = true;
                splitPathTcpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>Split-path routing not detected</div>`;
                splitPathUdpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>Split-path routing not detected</div>`;
            } else if (stunCountry && httpCountry) {
                // Different countries — likely a proxy/VPN/SWG
                isSplitPath = true;
                const detail = `<span class="ov-dim">(HTTP: ${esc(httpEgressIp)} [${esc(httpCity)}, ${esc(httpCountry)}] · STUN: ${esc(stunReflexiveIp)} [${esc(stunCity)}, ${esc(stunCountry)}])</span>`;
                splitPathTcpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-warn">⚠</span>Split-path routing detected ${detail}</div>`;
                splitPathUdpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>UDP bypasses HTTP proxy (direct egress) ${detail}</div>`;
            } else {
                // Couldn't GeoIP the STUN IP — show informational only
                const detail = `<span class="ov-dim">(HTTP: ${esc(httpEgressIp)}, STUN: ${esc(stunReflexiveIp)} — may be CGNAT)</span>`;
                splitPathTcpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-dim">ℹ</span>Different egress IPs ${detail}</div>`;
                splitPathUdpHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-dim">ℹ</span>Different egress IPs ${detail}</div>`;
            }
        }
    }

    const tcpTls = r('L-TCP-06');
    const tcpDns = r('L-TCP-08');
    const tcpVpn = r('L-TCP-07');
    if (tcpTls || tcpDns || tcpVpn || splitPathTcpHtml) {
        const items = [];
        if (tcpTls) items.push(buildCheckLine('TLS inspection', tcpTls));
        if (tcpDns) items.push(buildCheckLine('DNS hijacking', tcpDns));
        if (tcpVpn) items.push(buildCheckLine('VPN / SWG / Proxy use', tcpVpn));
        if (splitPathTcpHtml) items.push(splitPathTcpHtml);
        setVal('ov-tcp-path-val', items.join(''));
        hasContent = true;
    } else {
        setVal('ov-tcp-path-val', '<span class="ov-dim">Requires Local Scanner or STUN test</span>');
    }

    // 7. UDP-based RDP Path Optimization
    const turnTls = r('L-UDP-06');
    const turnVpn = r('L-UDP-07');

    // NAT type line — prefer scanner L-UDP-05 (accurate), fall back to browser B-UDP-02
    let natTypeHtml = '';
    const scannerNat = r('L-UDP-05');
    const browserNat = r('B-UDP-02');
    const natSource = scannerNat || browserNat;
    if (natSource) {
        const val = natSource.resultValue || '';
        const lc = val.toLowerCase();
        const src = scannerNat ? 'Scanner' : 'Browser';
        let icon, cls, label;
        if (lc.includes('cone') || lc.includes('open internet')) {
            icon = '✓'; cls = 'ov-pass';
            label = lc.includes('open internet') ? 'Open Internet (No NAT)'
                  : 'Cone NAT — Shortpath ready';
        } else if (lc.includes('symmetric')) {
            icon = '✗'; cls = 'ov-fail';
            label = 'Symmetric NAT — STUN hole-punching unlikely';
        } else if (lc.includes('stun ok')) {
            icon = '✓'; cls = 'ov-pass';
            label = 'STUN OK — UDP connectivity confirmed';
        } else if (lc.includes('partial')) {
            icon = '⚠'; cls = 'ov-warn';
            label = 'Partial STUN — NAT type undetermined';
        } else if (lc.includes('blocked') || lc.includes('failed')) {
            icon = '✗'; cls = 'ov-fail';
            label = 'STUN blocked — UDP 3478 unreachable';
        } else {
            icon = '⚠'; cls = 'ov-warn';
            label = val;
        }
        natTypeHtml = `<div class="ov-check-line"><span class="ov-status-icon ${cls}">${icon}</span>NAT Type: ${esc(label)} <span class="ov-dim">[${src}]</span></div>`;
    }

    // Build CGNAT warning for UDP if detected
    let cgnatHtml = '';
    if (isCgnat) {
        // Cross-reference with NAT type result
        const natResult = browserNat;
        const natType = natResult?.resultValue || '';
        const isSymmetric = natType.toLowerCase().includes('symmetric');
        if (isSymmetric) {
            cgnatHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-warn">⚠</span>Carrier-Grade NAT (CGNAT) detected — Symmetric NAT confirmed</div>`
                + `<div class="ov-check-line ov-dim" style="padding-left:1.4em;">STUN hole-punching unavailable; RDP Shortpath will use TURN relay</div>`;
        } else if (natResult && natResult.status === 'Passed') {
            cgnatHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>CGNAT detected but NAT is Cone — STUN should work</div>`;
        } else {
            cgnatHtml = `<div class="ov-check-line"><span class="ov-status-icon ov-warn">⚠</span>Carrier-Grade NAT (CGNAT) detected — may limit STUN connectivity</div>`
                + `<div class="ov-check-line ov-dim" style="padding-left:1.4em;">RDP Shortpath may fall back to TURN relay</div>`;
        }
    }

    if (natTypeHtml || turnTls || turnVpn || splitPathUdpHtml || cgnatHtml) {
        const items = [];
        if (natTypeHtml) items.push(natTypeHtml);
        if (turnTls) items.push(buildCheckLine('TLS inspection', turnTls));
        if (turnVpn) items.push(buildCheckLine('VPN / SWG / Proxy use', turnVpn));
        if (splitPathUdpHtml) items.push(splitPathUdpHtml);
        if (cgnatHtml) items.push(cgnatHtml);
        setVal('ov-udp-path-val', items.join(''));
        hasContent = true;
    } else {
        setVal('ov-udp-path-val', '<span class="ov-dim">Requires Local Scanner or STUN test</span>');
    }

    // Overall verdict
    if (hasContent) {
        panel.classList.remove('hidden');
        const failed = results.filter(r => r.status === 'Failed' || r.status === 'Error').length;
        const warnings = results.filter(r => r.status === 'Warning').length;
        const verdictEl = document.getElementById('overview-verdict');
        if (verdictEl) {
            if (failed > 0) {
                verdictEl.textContent = `${failed} issue${failed > 1 ? 's' : ''} found`;
                verdictEl.className = 'overview-verdict verdict-fail';
            } else if (warnings > 0) {
                verdictEl.textContent = `${warnings} warning${warnings > 1 ? 's' : ''}`;
                verdictEl.className = 'overview-verdict verdict-warn';
            } else {
                verdictEl.textContent = 'All checks passed';
                verdictEl.className = 'overview-verdict verdict-good';
            }
        }
    }
}

/** Build a descriptive check line like "✓ TLS inspection not detected" */
function buildCheckLine(label, result) {
    if (result.status === 'Passed') {
        return `<div class="ov-check-line"><span class="ov-status-icon ov-pass">✓</span>${label} not detected</div>`;
    } else if (result.status === 'Warning') {
        return `<div class="ov-check-line"><span class="ov-status-icon ov-warn">⚠</span>${label} detected</div>`;
    } else {
        return `<div class="ov-check-line"><span class="ov-status-icon ov-fail">✗</span>${label} detected</div>`;
    }
}
