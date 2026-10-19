// ── Proxy / firewall blocked-URL triage ──
// Classifies hostnames copied from a proxy or firewall block log against the
// AVD session-host and Azure Arc endpoint lists, plus the certificate
// revocation hosts measured by scanner test C-PKI-01. Runs entirely in the
// browser: nothing typed here is sent anywhere.
//
// Sources:
//   https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint#session-host-virtual-machines
//   https://learn.microsoft.com/azure/azure-arc/servers/network-requirements

const TRIAGE_CATEGORIES = {
    required: { rank: 0, label: 'Required', css: 'triage-required', action: 'Allow' },
    revocation: { rank: 1, label: 'Certificate revocation', css: 'triage-revocation', action: 'Allow (TCP 80)' },
    optional: { rank: 2, label: 'Optional', css: 'triage-optional', action: 'Allow if the feature is used' },
    undocumented: { rank: 3, label: 'Microsoft, undocumented for AVD', css: 'triage-undocumented', action: 'Confirm with Microsoft' },
    unknown: { rank: 4, label: 'Not in the AVD / Arc lists', css: 'triage-unknown', action: 'Investigate' }
};

const TRIAGE_CATALOG = [
    // AVD session host — required
    { pattern: 'login.microsoftonline.com', category: 'required', purpose: 'Microsoft Entra authentication (AVD and Arc)' },
    { pattern: '*.wvd.microsoft.com', category: 'required', purpose: 'AVD service traffic, including TCP-based RDP' },
    { pattern: 'catalogartifact.azureedge.net', category: 'required', purpose: 'Azure Marketplace' },
    { pattern: '*.prod.warm.ingest.monitor.core.windows.net', category: 'required', purpose: 'AVD agent diagnostics (Azure Monitor)' },
    { pattern: 'gcs.prod.monitoring.core.windows.net', category: 'required', purpose: 'AVD agent monitoring' },
    { pattern: 'mrsglobalsteus2prod.blob.core.windows.net', category: 'required', purpose: 'AVD agent and side-by-side stack updates' },
    { pattern: 'wvdportalstorageblob.blob.core.windows.net', category: 'required', purpose: 'Azure portal support' },
    { pattern: 'oneocsp.microsoft.com', category: 'required', purpose: 'Certificate revocation (OCSP)' },
    { pattern: 'www.microsoft.com', category: 'required', purpose: 'Certificates (CRL / issuer downloads)' },
    { pattern: '*.aikcertaia.microsoft.com', category: 'required', purpose: 'Device attestation certificates' },
    { pattern: 'azcsprodeusaikpublish.blob.core.windows.net', category: 'required', purpose: 'Device attestation certificates' },
    { pattern: '*.microsoftaik.azure.net', category: 'required', purpose: 'Device attestation certificates' },
    { pattern: 'ctldl.windowsupdate.com', category: 'required', purpose: 'Certificate trust list updates' },
    { pattern: 'aka.ms', category: 'required', purpose: 'Microsoft URL shortener (session host deployment)' },
    { pattern: '*.service.windows.cloud.microsoft', category: 'required', purpose: 'AVD service traffic' },
    { pattern: '*.windows.cloud.microsoft', category: 'required', purpose: 'AVD service traffic' },
    { pattern: '*.windows.static.microsoft', category: 'required', purpose: 'AVD service traffic' },
    // Azure Arc Connected Machine agent — required
    { pattern: '*.login.microsoft.com', category: 'required', purpose: 'Regional Entra token endpoint (Arc agent)' },
    { pattern: 'pas.windows.net', category: 'required', purpose: 'Microsoft Entra ID (Arc agent)' },
    { pattern: 'management.azure.com', category: 'required', purpose: 'Azure Resource Manager (Arc connect / disconnect)' },
    { pattern: '*.his.arc.azure.com', category: 'required', purpose: 'Arc metadata and hybrid identity service' },
    { pattern: '*.guestconfiguration.azure.com', category: 'required', purpose: 'Arc extension management and guest configuration' },
    { pattern: 'guestnotificationservice.azure.com', category: 'required', purpose: 'Arc notification service' },
    { pattern: '*.guestnotificationservice.azure.com', category: 'required', purpose: 'Arc notification service' },
    { pattern: 'azgn*.servicebus.windows.net', category: 'required', purpose: 'Arc notification service' },
    { pattern: 'download.microsoft.com', category: 'required', purpose: 'Arc agent installer (install and automatic upgrade)' },
    // Certificate revocation hosts used by the chains of the required endpoints
    { pattern: 'crl2.microsoft.com', category: 'optional', purpose: 'Backup CRL location named in Microsoft TLS certificates; not in the AVD endpoint list. Windows uses it only if oneocsp.microsoft.com and www.microsoft.com fail, so it is not required while those are allowed' },
    { pattern: 'caissuers.microsoft.com', category: 'optional', purpose: 'Backup issuer-certificate location named in Microsoft TLS certificates; not in the AVD endpoint list. Only used if a server omits an intermediate and www.microsoft.com is unavailable' },
    { pattern: '*.digicert.com', category: 'revocation', purpose: 'OCSP / CRL for DigiCert Global Root G2/G3 and the Microsoft TLS root cross-certificates. Optional in the AVD list, but every sampled AVD and Arc certificate chain depends on it' },
    // Optional
    { pattern: 'login.windows.net', category: 'optional', purpose: 'Sign-in to Microsoft Online Services and Microsoft 365' },
    { pattern: '*.events.data.microsoft.com', category: 'optional', purpose: 'Telemetry' },
    { pattern: 'www.msftconnecttest.com', category: 'optional', purpose: 'Internet connectivity detection' },
    { pattern: '*.prod.do.dsp.mp.microsoft.com', category: 'optional', purpose: 'Windows Update' },
    { pattern: '*.sfx.ms', category: 'optional', purpose: 'OneDrive client updates' },
    { pattern: '*.azure-dns.com', category: 'optional', purpose: 'Azure DNS resolution' },
    { pattern: '*.azure-dns.net', category: 'optional', purpose: 'Azure DNS resolution' },
    { pattern: '*eh.servicebus.windows.net', category: 'optional', purpose: 'Event Hub diagnostic settings' },
    { pattern: 'dc.services.visualstudio.com', category: 'optional', purpose: 'Arc agent telemetry (not used by agent 1.24+)' },
    { pattern: '*.waconazure.com', category: 'optional', purpose: 'Windows Admin Center (Arc)' },
    { pattern: 'dls.microsoft.com', category: 'optional', purpose: 'Arc licence validation (hotpatching / pay-as-you-go)' },
    { pattern: 'azkms.core.windows.net', category: 'optional', purpose: 'Azure KMS activation \u2014 Azure VMs only; hybrid hosts activate through your own KMS / MAK' },
    // Microsoft-owned but not on the AVD / Arc lists
    {
        pattern: /^maupdateaccount\d*\.blob\.core\.windows\.net$/,
        display: 'maupdateaccount*.blob.core.windows.net',
        category: 'undocumented',
        purpose: 'Microsoft-owned storage family (maupdateaccount, maupdateaccount2\u201312) listed in Microsoft\u2019s App Service Environment and HDInsight dependency lists alongside Geneva monitoring endpoints \u2014 most likely Geneva Monitoring Agent packages. Not in the AVD or Arc lists; AVD agent updates use mrsglobalsteus2prod instead.',
        advice: 'If you allow it, list the exact account names. Never use a maupdateaccount* prefix wildcard: storage account names can be registered by anyone.'
    }
];

function triageWildcardToRegex(pattern) {
    const escape = s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    let body;
    if (pattern.startsWith('*.')) {
        body = '(?:[^.]+\\.)+' + escape(pattern.slice(2)).replace(/\*/g, '[^.]*');
    } else {
        body = escape(pattern).replace(/\*/g, '[^.]*');
    }
    return new RegExp('^' + body + '$', 'i');
}

function triageMatches(entry, host) {
    const regex = entry.pattern instanceof RegExp ? entry.pattern : triageWildcardToRegex(entry.pattern);
    return regex.test(host);
}

// Accepts hostnames, URLs, "host:port", wildcard rules and proxy-log lines.
function triageNormalizeHost(raw) {
    let value = String(raw || '').trim().toLowerCase();
    if (!value) return null;
    value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    value = value.replace(/[/?#].*$/, '');
    value = value.replace(/^[^@]*@/, '');
    value = value.replace(/:\d+$/, '');
    value = value.replace(/\.$/, '');
    // Squid-style ".example.com" domain rules mean "example.com and below".
    if (/^\.[a-z0-9]/.test(value)) value = '*' + value;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return null;
    if (!/^(\*\.)?[a-z0-9*][a-z0-9*.-]*\.[a-z0-9-]+$/.test(value)) return null;
    return value;
}

function triageParseInput(text) {
    const seen = new Set();
    const hosts = [];
    for (const token of String(text || '').split(/[\s,;]+/)) {
        const host = triageNormalizeHost(token);
        if (host && !seen.has(host)) {
            seen.add(host);
            hosts.push(host);
        }
    }
    return hosts;
}

// Revocation hosts the imported C-PKI-01 result actually measured, with the
// per-host outcome: true = reachable on the session host's machine route,
// false = unreachable, 'user' = reachable only with the user's proxy context.
function triageRevocationHostsFromResults(results) {
    const hosts = new Map();
    const pki = (results || []).find(r => r && r.id === 'C-PKI-01');
    if (!pki || !pki.detailedInfo) return hosts;
    let inSection = false;
    for (const line of pki.detailedInfo.split('\n')) {
        if (/Revocation hosts used by these chains/i.test(line)) { inSection = true; continue; }
        if (inSection && /\u2550\u2550/.test(line)) break;
        const match = inSection && line.match(/^\s*([\u2714\u2718\u2139])\s+([a-z0-9.-]+)/i);
        if (match) hosts.set(match[2].toLowerCase(), match[1] === '\u2714' ? true : match[1] === '\u2718' ? false : 'user');
    }
    return hosts;
}

// Catalog entries a wildcard rule would also block, e.g. "*.windows.net"
// covers pas.windows.net and *.prod.warm.ingest.monitor.core.windows.net.
function triageCoveredEntries(wildcardHost) {
    const suffix = wildcardHost.slice(2);
    return TRIAGE_CATALOG.filter(entry => {
        const shown = (entry.display || (typeof entry.pattern === 'string' ? entry.pattern : '')).toLowerCase();
        const bare = shown.replace(/^\*\./, '');
        return bare.endsWith('.' + suffix) || (bare === suffix && shown !== wildcardHost);
    });
}

function triageClassify(host, measuredRevocationHosts) {
    const probe = host.startsWith('*.') ? 'x' + host.slice(1) : host;
    const measured = measuredRevocationHosts && measuredRevocationHosts.has(host)
        ? measuredRevocationHosts.get(host)
        : undefined;

    const matches = TRIAGE_CATALOG.filter(entry => triageMatches(entry, probe));
    matches.sort((a, b) => TRIAGE_CATEGORIES[a.category].rank - TRIAGE_CATEGORIES[b.category].rank);
    let entry = matches[0];

    if (host.startsWith('*.')) {
        const covered = triageCoveredEntries(host)
            .sort((a, b) => TRIAGE_CATEGORIES[a.category].rank - TRIAGE_CATEGORIES[b.category].rank);
        if (covered.length > 0 && (!entry || TRIAGE_CATEGORIES[covered[0].category].rank < TRIAGE_CATEGORIES[entry.category].rank)) {
            const names = covered.slice(0, 6).map(e => e.display || e.pattern);
            const more = covered.length > names.length ? ` and ${covered.length - names.length} more` : '';
            entry = {
                category: covered[0].category,
                display: host,
                purpose: `This rule also covers ${covered.length} catalogued endpoint(s): ${names.join(', ')}${more}.`,
                advice: 'Blocking a parent-domain wildcard blocks every endpoint listed. Exempt those endpoints from the rule rather than allowing the whole domain.'
            };
        }
    }

    if (measured !== undefined && !entry) {
        entry = {
            category: 'revocation',
            display: host,
            purpose: 'Revocation host referenced by the certificate chains this session host measured in C-PKI-01'
        };
    }

    if (!entry) {
        return {
            host,
            category: 'unknown',
            rule: null,
            purpose: 'Not on the AVD session-host or Azure Arc endpoint lists this tool knows.',
            advice: 'Not evidence that it is safe to block. Identify the requesting process in the proxy log before deciding.',
            measured
        };
    }

    let advice = entry.advice || '';
    if (measured === true) advice = 'Reachable from this session host in the imported C-PKI-01 scan. ' + advice;
    if (measured === false) advice = 'Unreachable from this session host in the imported C-PKI-01 scan \u2014 likely the block in this log. ' + advice;
    if (measured === 'user') advice = 'Reachable from this session host only with the signed-in user\u2019s proxy context in the imported C-PKI-01 scan \u2014 SYSTEM services may still be blocked. ' + advice;

    return {
        host,
        category: entry.category,
        rule: entry.display || (entry.pattern instanceof RegExp ? String(entry.pattern) : entry.pattern),
        purpose: entry.purpose,
        advice: advice.trim(),
        measured
    };
}

function triageEscape(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function runProxyTriage() {
    const input = document.getElementById('triage-input');
    const output = document.getElementById('triage-output');
    if (!input || !output) return;

    const hosts = triageParseInput(input.value);
    if (hosts.length === 0) {
        output.innerHTML = '<p class="triage-empty">Paste one or more hostnames or URLs from your proxy or firewall log.</p>';
        return;
    }

    const results = typeof allResults !== 'undefined' ? allResults : [];
    const measured = triageRevocationHostsFromResults(results);
    const rows = hosts
        .map(host => triageClassify(host, measured))
        .sort((a, b) => TRIAGE_CATEGORIES[a.category].rank - TRIAGE_CATEGORIES[b.category].rank || a.host.localeCompare(b.host));

    const scanNote = measured.size > 0
        ? `Using revocation hosts measured by the imported scan (C-PKI-01, ${measured.size} hosts).`
        : 'Import a session host scan to add the revocation hosts it measured (C-PKI-01).';

    output.innerHTML =
        `<p class="triage-note">${triageEscape(scanNote)}</p>` +
        '<table class="triage-table"><thead><tr><th scope="col">Host</th><th scope="col">Classification</th><th scope="col">Recommendation</th><th scope="col">Why</th></tr></thead><tbody>' +
        rows.map(row => {
            const category = TRIAGE_CATEGORIES[row.category];
            const rule = row.rule && row.rule !== row.host ? `<div class="triage-rule">matches ${triageEscape(row.rule)}</div>` : '';
            const advice = row.advice ? `<div class="triage-advice">${triageEscape(row.advice)}</div>` : '';
            return `<tr class="${category.css}"><td><code>${triageEscape(row.host)}</code>${rule}</td>` +
                `<td><span class="triage-pill">${triageEscape(category.label)}</span></td>` +
                `<td>${triageEscape(category.action)}</td>` +
                `<td>${triageEscape(row.purpose)}${advice}</td></tr>`;
        }).join('') +
        '</tbody></table>';
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        TRIAGE_CATALOG,
        triageNormalizeHost,
        triageParseInput,
        triageClassify,
        triageRevocationHostsFromResults,
        triageWildcardToRegex
    };
}
