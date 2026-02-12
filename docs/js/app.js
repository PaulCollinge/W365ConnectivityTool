/**
 * Main application logic: orchestrates browser tests, import, and result merging.
 */

// All collected results (browser + imported)
let allResults = [];
let isRunning = false;

// ── Cross-tab communication ──
// When the scanner opens a NEW browser tab with results, the new tab
// broadcasts results to any EXISTING tabs via BroadcastChannel.
// If an existing tab acknowledges receipt, the new tab closes itself
// so the user stays on the tab that already has browser test results.
const scannerChannel = new BroadcastChannel('w365-scanner-results');
let isRelayTab = false; // true if this tab was opened by the scanner and an existing tab took the results

scannerChannel.onmessage = (event) => {
    if (event.data?.type === 'scanner-results') {
        // We're an existing tab receiving results from the new tab
        console.log('Received scanner results from another tab via BroadcastChannel');
        processImportedData(event.data.payload);
        // Acknowledge so the new tab knows it can close
        scannerChannel.postMessage({ type: 'ack' });
        // Try to bring this tab to front
        window.focus();
    } else if (event.data?.type === 'ack' && isRelayTab) {
        // We're the new tab and an existing tab confirmed receipt — close ourselves
        console.log('Existing tab acknowledged receipt, closing this relay tab');
        document.body.innerHTML = `
            <div style="display:flex;justify-content:center;align-items:center;height:100vh;
                        font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9">
                <div style="text-align:center;padding:2em">
                    <div style="font-size:2em;margin-bottom:0.5em">✅</div>
                    <h2>Scanner results sent to your existing tab</h2>
                    <p style="color:#8b949e">You can close this tab.</p>
                </div>
            </div>`;
        // Attempt to close (works in some browsers for non-script-opened tabs)
        setTimeout(() => window.close(), 1000);
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
    renderTestList();
    checkForAutoImport();
    setupDragDrop();
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

    try {
        if (params.has('zresults')) {
            // Query-param compressed format (preferred — works with ShellExecute)
            const raw = params.get('zresults');
            data = await decodeCompressedHash(raw);
            source = 'query';
        } else if (hash.startsWith('#zresults=')) {
            // Hash compressed format (legacy)
            const raw = hash.substring('#zresults='.length);
            data = await decodeCompressedHash(raw);
            source = 'hash';
        } else if (hash.startsWith('#results=')) {
            // Hash uncompressed format (legacy)
            const raw = hash.substring('#results='.length);
            data = decodeUncompressedHash(raw);
            source = 'hash';
        } else {
            return;
        }

        // Clear the URL so it doesn't re-import on refresh / bookmarking
        history.replaceState(null, '', window.location.pathname);

        console.log(`Auto-import (${source}): parsed ${data.results?.length ?? 0} results`);

        // Mark ourselves as a relay tab — we'll try to hand off to an existing tab
        isRelayTab = true;

        // Broadcast to any existing tabs so they get the results
        try {
            scannerChannel.postMessage({ type: 'scanner-results', payload: data });
            // Also write to localStorage as a fallback signal
            localStorage.setItem('w365-scanner-results', JSON.stringify(data));
            localStorage.removeItem('w365-scanner-results');
        } catch (broadcastErr) {
            console.warn('Could not broadcast to other tabs:', broadcastErr);
        }

        // Wait briefly for an ack from an existing tab.
        // If no ack arrives, this is the only tab — process results here.
        await new Promise(resolve => setTimeout(resolve, 800));
        if (isRelayTab) {
            // No ack received — no existing tab is listening
            console.log('No existing tab responded, processing results in this tab');
            isRelayTab = false;
            processImportedData(data);
        }
    } catch (e) {
        console.error('Auto-import from URL failed:', e);
        // Show a helpful message to the user instead of failing silently
        const info = document.getElementById('info-banner');
        info.classList.remove('hidden');
        info.querySelector('.info-text').innerHTML =
            `<strong>Auto-import failed.</strong> The scanner results could not be loaded from the URL. ` +
            `Please drag and drop the <strong>W365ScanResults.json</strong> file onto this page, ` +
            `or open the file manually from the folder where you ran the scanner.`;
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
    const json = new TextDecoder().decode(decompressed);
    console.log(`Auto-import (compressed): decompressed ${bytes.length} → ${json.length} bytes`);
    return JSON.parse(json);
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

    // Map local scanner IDs to our test list
    let importedCount = 0;
    for (const lr of localResults) {
        // Remove any existing result with this ID
        allResults = allResults.filter(r => r.id !== lr.id);

        const mapped = {
            id: lr.id,
            name: lr.name || lr.id,
            description: lr.description || '',
            category: lr.category || mapCategoryFromId(lr.id),
            source: 'local',
            status: lr.status || 'Passed',
            resultValue: lr.resultValue || lr.result || '',
            detailedInfo: lr.detailedInfo || lr.details || '',
            duration: lr.duration || 0,
            remediationUrl: lr.remediationUrl || ''
        };

        allResults.push(mapped);

        // Update UI - find matching test definition or create inline
        const testDef = ALL_TESTS.find(t => t.id === lr.id);
        if (testDef) {
            updateTestUI(lr.id, mapped);
        } else {
            console.warn(`Import: No test definition found for ${lr.id}`);
        }

        importedCount++;
    }

    // Update summary and badges
    updateSummary(allResults);
    updateCategoryBadges(allResults);
    updateConnectivityMap(allResults);

    // Show confirmation
    const info = document.getElementById('info-banner');
    info.classList.remove('hidden');
    info.querySelector('.info-text').innerHTML =
        `<strong>Imported ${importedCount} local scan results.</strong> ` +
        (data.machineName ? `Machine: ${data.machineName}. ` : '') +
        (data.timestamp ? `Scanned: ${new Date(data.timestamp).toLocaleString()}. ` : '') +
        'Combined results are shown below.';

    // Hide download banner if we have local results
    if (importedCount > 0) hideDownloadBanner();
}

// ── Helpers ──
function mapCategoryFromId(id) {
    if (!id) return 'local';
    if (id.includes('-EP-')) return 'endpoint';
    if (id.includes('-LE-')) return 'local';
    if (id.includes('-TCP-')) return 'tcp';
    if (id.includes('-UDP-')) return 'udp';
    if (id.includes('-CS-')) return 'cloud';
    return 'local';
}
