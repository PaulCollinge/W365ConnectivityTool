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

    // Show progress
    updateProgress(0, total);

    for (const test of browserTests) {
        setTestRunning(test.id);

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
function exportTextReport() {
    if (allResults.length === 0) return;

    const lines = [];
    const divider = '═'.repeat(72);
    const thinDiv = '─'.repeat(72);

    lines.push(divider);
    lines.push('  Windows 365 Connectivity Diagnostics — Text Report');
    lines.push(divider);
    lines.push(`  Generated: ${new Date().toLocaleString()}`);
    lines.push(`  User Agent: ${navigator.userAgent}`);

    // Current user location from the B-LE-01 browser test (live GeoIP)
    const userLocResult = allResults.find(r => r.id === 'B-LE-01' && r.status === 'Passed');
    if (userLocResult) {
        lines.push(`  Location:   ${userLocResult.resultValue}`);
        const pubIp = (userLocResult.detailedInfo || '').split('\n')
            .find(l => l.startsWith('Public IP:'));
        if (pubIp) lines.push(`  ${pubIp}`);
    }

    // Note when scanner data was captured (may differ from current location)
    const scannerResults = allResults.filter(r => r.source === 'local');
    if (scannerResults.length > 0 && _importedScanTimestamp) {
        lines.push(`  Scanner data from: ${_importedScanTimestamp}`);
        // Warn if scanner location differs from browser location
        if (userLocResult) {
            const browserLoc = (userLocResult.resultValue || '').toLowerCase();
            const test27 = scannerResults.find(r => r.id === '27');
            if (test27 && test27.detailedInfo) {
                const egressLine = test27.detailedInfo.split('\n')
                    .find(l => l.trim().startsWith('Your egress location:'));
                if (egressLine) {
                    const scannerLoc = egressLine.replace(/.*Your egress location:\s*/i, '').trim();
                    if (scannerLoc && !browserLoc.includes(scannerLoc.split(',')[0].trim().toLowerCase())) {
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

    const text = lines.join('\n');
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
    const btn = document.getElementById('btn-export-text');
    if (btn) {
        btn.disabled = allResults.length === 0;
        btn.title = allResults.length === 0 ? 'Run tests first' : `Export ${allResults.length} results as text`;
    }
}
