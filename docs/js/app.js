/**
 * Main application logic: orchestrates browser tests, import, and result merging.
 */

// All collected results (browser + imported)
let allResults = [];
let isRunning = false;

// ── Initialize on page load ──
document.addEventListener('DOMContentLoaded', () => {
    renderTestList();
    checkForAutoImport();
    setupDragDrop();
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

// ── Auto-import from URL hash (scanner opens browser with #results=BASE64) ──
function checkForAutoImport() {
    const hash = window.location.hash;
    if (!hash || !hash.startsWith('#results=')) return;

    try {
        const raw = hash.substring('#results='.length);
        // Handle URL-safe base64 (replace - with +, _ with /) and restore padding
        let base64 = raw.replace(/-/g, '+').replace(/_/g, '/');
        // Restore padding removed by scanner
        const pad = (4 - (base64.length % 4)) % 4;
        if (pad > 0) base64 += '='.repeat(pad);
        const json = atob(base64);
        const data = JSON.parse(json);

        // Clear the hash so it doesn't re-import on refresh / bookmarking
        history.replaceState(null, '', window.location.pathname + window.location.search);

        console.log(`Auto-import: decoded ${json.length} chars, parsed ${data.results?.length ?? 0} results`);
        processImportedData(data);
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
