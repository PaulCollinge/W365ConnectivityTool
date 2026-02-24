/**
 * UI rendering and DOM manipulation for the connectivity diagnostics page.
 */

/**
 * Enrich a result value string with a country flag if a 2-letter ISO code is found.
 * Looks for patterns like ", XX (" or ", XX" at end where XX is a country code.
 * Returns an HTML string (safe — the text portion is escaped).
 */
function enrichResultWithFlag(text) {
    if (!text) return '';
    const escaped = escapeHtml(text);
    // Match 2-letter country code before parenthetical or at end: ", FR (" or ", GB"
    const m = text.match(/,\s*([A-Z]{2})\s*(?:\(|$)/);
    if (m) {
        const code = m[1].toLowerCase();
        const flagHtml = `<img src="https://flagcdn.com/20x15/${code}.png" alt="${m[1]}" width="20" height="15" class="country-flag" onerror="this.style.display='none'">`;
        // Insert flag before the country code
        const insertPos = escaped.indexOf(m[0]);
        if (insertPos >= 0) {
            return escaped.substring(0, insertPos + 2) + flagHtml + ' ' + escaped.substring(insertPos + 2);
        }
    }
    return escaped;
}

const STATUS_ICONS = {
    'Passed': '\u2714',
    'Warning': '\u26A0',
    'Failed': '\u2718',
    'Error': '\u2718',
    'Running': '\u27F3',
    'NotRun': '\u2014',
    'Skipped': '\u2014',
    'Pending': '\u231B'
};

const STATUS_CLASSES = {
    'Passed': 'passed',
    'Warning': 'warning',
    'Failed': 'failed',
    'Error': 'error',
    'Running': 'running',
    'NotRun': 'not-run',
    'Skipped': 'skipped',
    'Pending': 'pending'
};

/**
 * Render all test definitions into the category containers (initial state).
 */
function renderTestList() {
    const containers = {
        endpoint: document.getElementById('tests-endpoint'),
        local: document.getElementById('tests-local'),
        tcp: document.getElementById('tests-tcp'),
        udp: document.getElementById('tests-udp'),
        cloud: document.getElementById('tests-cloud')
    };

    // Clear
    Object.values(containers).forEach(c => c.innerHTML = '');

    for (const test of ALL_TESTS) {
        const el = createTestElement(test, {
            status: test.source === 'local' ? 'Pending' : 'NotRun',
            resultValue: test.source === 'local' ? 'Requires Local Scanner' : 'Not tested',
            detailedInfo: '',
            duration: 0
        });
        containers[test.category].appendChild(el);
    }
}

/**
 * Create a DOM element for a single test result.
 */
function createTestElement(test, result) {
    const div = document.createElement('div');
    div.className = 'test-item';
    div.id = `test-${test.id}`;

    const statusClass = STATUS_CLASSES[result.status] || 'not-run';
    const statusIcon = STATUS_ICONS[result.status] || '\u2014';

    const sourceBadge = test.source === 'browser'
        ? '<span class="test-source-badge browser">Browser</span>'
        : '<span class="test-source-badge local">Local</span>';

    div.innerHTML = `
        <div class="test-status-icon ${statusClass}">${statusIcon}</div>
        <div class="test-info">
            <div class="test-name">
                ${test.name}
                ${sourceBadge}
            </div>
            <div class="test-description">${test.description}</div>
            ${result.resultValue ? `<div class="test-result-value">${enrichResultWithFlag(result.resultValue)}</div>` : ''}
            ${result.detailedInfo ? `<div class="test-details" id="details-${test.id}">${escapeHtml(result.detailedInfo)}</div>` : ''}
            ${result.remediationUrl ? `<div class="test-remediation"><a href="${result.remediationUrl}" target="_blank">📖 View documentation</a></div>` : ''}
        </div>
        <div class="test-meta">
            ${result.duration > 0 ? `<span class="test-duration" title="Test execution time">⏱ ${result.duration}ms</span>` : ''}
            ${result.detailedInfo ? `<button class="test-expand" onclick="toggleDetails('${test.id}')">Details</button>` : ''}
        </div>
    `;

    return div;
}

/**
 * Update a single test's UI after it completes.
 */
function updateTestUI(testId, result) {
    const el = document.getElementById(`test-${testId}`);
    if (!el) {
        if (typeof ilog === 'function') ilog('updateTestUI: NO element found for test-' + testId);
        return;
    }
    if (typeof ilog === 'function') ilog('updateTestUI: FOUND element test-' + testId + ', status=' + result.status + ', val=' + (result.resultValue || '').substring(0,60));

    const test = ALL_TESTS.find(t => t.id === testId) || { id: testId, name: result.name || testId, source: 'local', description: '' };

    const statusClass = STATUS_CLASSES[result.status] || 'not-run';
    const statusIcon = STATUS_ICONS[result.status] || '\u2014';

    const sourceBadge = test.source === 'browser'
        ? '<span class="test-source-badge browser">Browser</span>'
        : '<span class="test-source-badge local">Local</span>';

    el.innerHTML = `
        <div class="test-status-icon ${statusClass}">${statusIcon}</div>
        <div class="test-info">
            <div class="test-name">
                ${test.name}
                ${sourceBadge}
            </div>
            <div class="test-description">${test.description}</div>
            ${result.resultValue ? `<div class="test-result-value">${enrichResultWithFlag(result.resultValue)}</div>` : ''}
            ${result.detailedInfo ? `<div class="test-details" id="details-${testId}">${escapeHtml(result.detailedInfo)}</div>` : ''}
            ${result.remediationUrl ? `<div class="test-remediation"><a href="${result.remediationUrl}" target="_blank">📖 View documentation</a></div>` : ''}
            ${result.remediationText ? `<div class="test-remediation-text">${escapeHtml(result.remediationText)}</div>` : ''}
        </div>
        <div class="test-meta">
            ${result.duration > 0 ? `<span class="test-duration" title="Test execution time">⏱ ${result.duration}ms</span>` : ''}
            ${result.detailedInfo ? `<button class="test-expand" onclick="toggleDetails('${testId}')">Details</button>` : ''}
        </div>
    `;
}

/**
 * Set a test to "Running" state.
 */
function setTestRunning(testId) {
    updateTestUI(testId, {
        status: 'Running',
        resultValue: 'Running...',
        detailedInfo: '',
        duration: 0
    });
}

/**
 * Update the summary bar.
 */
function updateSummary(results) {
    const bar = document.getElementById('summary-bar');
    bar.classList.remove('hidden');

    const allResults = [...results];
    // Count pending (local-only tests not yet imported)
    const localOnlyTests = ALL_TESTS.filter(t => t.source === 'local');
    const importedIds = results.map(r => r.id);
    const pending = localOnlyTests.filter(t => !importedIds.includes(t.id));
    const skipped = results.filter(r => r.status === 'Skipped').length;

    document.getElementById('summary-total').textContent = results.length + pending.length;
    document.getElementById('summary-passed').textContent = results.filter(r => r.status === 'Passed').length;
    document.getElementById('summary-warnings').textContent = results.filter(r => r.status === 'Warning').length;
    document.getElementById('summary-failed').textContent = results.filter(r => r.status === 'Failed' || r.status === 'Error').length;
    // Show number of pending OR skipped in the 'Needs Local Scan' slot
    const pendingEl = document.getElementById('summary-pending');
    const pendingLabel = pendingEl.parentElement.querySelector('.summary-label');
    if (pending.length > 0) {
        pendingEl.textContent = pending.length;
        pendingLabel.textContent = 'Needs Local Scan';
    } else if (skipped > 0) {
        pendingEl.textContent = skipped;
        pendingLabel.textContent = 'Skipped';
    } else {
        pendingEl.textContent = '0';
        pendingLabel.textContent = 'Needs Local Scan';
    }
}

/**
 * Update progress bar with current test info.
 */
function updateProgress(current, total, testName) {
    const container = document.getElementById('progress-container');
    container.classList.remove('hidden');

    const fill = document.getElementById('progress-fill');
    const pct = Math.round((current / total) * 100);
    fill.style.width = `${pct}%`;

    // Update header elements
    let label = container.querySelector('.progress-label');
    let count = container.querySelector('.progress-count');
    let nameEl = container.querySelector('.progress-test-name');

    // If the new layout elements don't exist yet, create them
    if (!label) {
        const header = document.createElement('div');
        header.className = 'progress-header';
        label = document.createElement('span');
        label.className = 'progress-label';
        count = document.createElement('span');
        count.className = 'progress-count';
        header.appendChild(label);
        header.appendChild(count);
        container.insertBefore(header, container.firstChild);

        nameEl = document.createElement('div');
        nameEl.className = 'progress-test-name';
        container.appendChild(nameEl);
    }

    label.textContent = 'Running Tests…';
    count.textContent = `${current} / ${total} (${pct}%)`;
    if (testName) {
        nameEl.textContent = `▸ ${testName}`;
    }
}

function hideProgress() {
    document.getElementById('progress-container').classList.add('hidden');
}

/**
 * Show or hide the download banner.
 */
function showDownloadBanner() {
    document.getElementById('download-banner').classList.remove('hidden');
}

function hideDownloadBanner() {
    document.getElementById('download-banner').classList.add('hidden');
}

/**
 * Update category badges.
 */
function updateCategoryBadges(results) {
    const categories = { endpoint: [], local: [], tcp: [], udp: [], cloud: [] };
    results.forEach(r => {
        if (categories[r.category]) categories[r.category].push(r);
    });

    for (const [cat, catResults] of Object.entries(categories)) {
        const badge = document.getElementById(`badge-${cat}`);
        if (!badge) continue;

        if (catResults.length === 0) {
            badge.textContent = '';
            badge.style.background = '';
            badge.style.color = '';
            continue;
        }

        const failed = catResults.filter(r => r.status === 'Failed' || r.status === 'Error').length;
        const warned = catResults.filter(r => r.status === 'Warning').length;
        const passed = catResults.filter(r => r.status === 'Passed').length;

        const skipped = catResults.filter(r => r.status === 'Skipped').length;

        if (failed > 0) {
            badge.textContent = `${failed} failed`;
            badge.style.background = 'var(--red-bg)';
            badge.style.color = 'var(--red)';
        } else if (warned > 0) {
            badge.textContent = `${warned} warning${warned > 1 ? 's' : ''}`;
            badge.style.background = 'var(--yellow-bg)';
            badge.style.color = '#92400e';
        } else if (passed > 0) {
            badge.textContent = `${passed} passed`;
            badge.style.background = 'var(--green-bg)';
            badge.style.color = 'var(--green)';
        } else if (skipped > 0) {
            badge.textContent = `${skipped} skipped`;
            badge.style.background = 'var(--bg-surface)';
            badge.style.color = 'var(--text-muted)';
        }
    }

    // Update NAT type banner in UDP section
    updateNatTypeBanner(results);
}

/**
 * Update the NAT type banner displayed below the UDP category header.
 * Prefers scanner L-UDP-05 (accurate two-server comparison) over browser B-UDP-02.
 */
function updateNatTypeBanner(results) {
    const banner = document.getElementById('nat-type-banner');
    if (!banner) return;

    const scannerNat = results.find(r => r.id === 'L-UDP-05');
    const browserNat = results.find(r => r.id === 'B-UDP-02');
    const natResult = scannerNat || browserNat;

    if (!natResult) {
        banner.classList.remove('visible');
        return;
    }

    const val = (natResult.resultValue || '').toLowerCase();
    const source = scannerNat ? 'Local Scanner' : 'Browser';
    let icon, label, cssClass;

    if (val.includes('open internet')) {
        icon = '🌐'; label = 'Open Internet — No NAT detected'; cssClass = 'nat-cone';
    } else if (val.includes('cone')) {
        icon = '✓'; label = 'Cone NAT — RDP Shortpath via STUN is available'; cssClass = 'nat-cone';
    } else if (val.includes('symmetric')) {
        icon = '✗'; label = 'Symmetric NAT — STUN hole-punching unlikely, TURN relay used'; cssClass = 'nat-symmetric';
    } else if (val.includes('stun ok')) {
        icon = '✓'; label = 'STUN OK — UDP connectivity confirmed'; cssClass = 'nat-cone';
    } else if (val.includes('partial')) {
        icon = '⚠'; label = 'Partial STUN — NAT type could not be determined'; cssClass = 'nat-warn';
    } else if (val.includes('blocked') || val.includes('failed')) {
        icon = '✗'; label = 'STUN Blocked — UDP 3478 unreachable'; cssClass = 'nat-blocked';
    } else {
        icon = '⚠'; label = natResult.resultValue || 'Unknown'; cssClass = 'nat-warn';
    }

    banner.className = `nat-type-banner visible ${cssClass}`;
    banner.innerHTML = `<span class="nat-icon">${icon}</span><span class="nat-label">${label}<span class="nat-source">[${source}]</span></span>`;
}

/**
 * Toggle details panel for a test.
 */
function toggleDetails(testId) {
    const details = document.getElementById(`details-${testId}`);
    if (details) {
        details.classList.toggle('expanded');
    }
}

/**
 * Escape HTML entities.
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
