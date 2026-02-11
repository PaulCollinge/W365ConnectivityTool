/**
 * Main application logic: orchestrates browser tests, import, and result merging.
 */

// All collected results (browser + imported)
let allResults = [];
let isRunning = false;

// ── Initialize on page load ──
document.addEventListener('DOMContentLoaded', () => {
    renderTestList();
});

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
        }

        completed++;
        updateProgress(completed, total);
    }

    hideProgress();
    updateSummary(allResults);
    updateCategoryBadges(allResults);
    showDownloadBanner();

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">\u25B6</span> Re-run Browser Tests';
    isRunning = false;
}

// ── Import local scanner results ──
async function importLocalResults(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const data = JSON.parse(text);

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
        // The local scanner uses the same ID scheme (L-LE-04, L-TCP-04, etc.)
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
            }

            importedCount++;
        }

        // Update summary and badges
        updateSummary(allResults);
        updateCategoryBadges(allResults);

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

    } catch (e) {
        alert(`Error reading file: ${e.message}`);
    }

    // Reset file input so same file can be re-imported
    event.target.value = '';
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
