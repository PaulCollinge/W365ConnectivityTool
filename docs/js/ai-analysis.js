/**
 * AI Analysis — builds a diagnostic prompt from test results and opens
 * Microsoft Copilot for expert remediation advice.
 */

// ── Prompt builder: extract signal from test results ──
function buildAnalysisPrompt(results) {
    if (!results || results.length === 0) return null;

    const r = id => results.find(x => x.id === id);
    const sections = [];

    // ── System prompt ──
    sections.push(
        'You are a Windows 365 / Azure Virtual Desktop connectivity expert. ' +
        'Analyze the following scan results from a user\'s physical device and provide:\n' +
        '1. A clear root-cause analysis of any failures, warnings, or concerning patterns\n' +
        '2. Specific, actionable remediation steps (commands, settings, registry keys)\n' +
        '3. Note if the issue is at the client, local network, ISP, or Azure edge\n' +
        'Be concise but thorough. Reference Microsoft Learn docs where helpful.\n'
    );

    // ── Summary ──
    const passed = results.filter(x => x.status === 'Passed').length;
    const warnings = results.filter(x => x.status === 'Warning').length;
    const failed = results.filter(x => x.status === 'Failed' || x.status === 'Error').length;
    const skipped = results.filter(x => x.status === 'Skipped').length;
    sections.push(`## Scan Summary\n${results.length} tests: ${passed} passed, ${warnings} warnings, ${failed} failed, ${skipped} skipped\n`);

    // ── Environment ──
    const envLines = [];
    const loc = r('B-LE-01');
    if (loc) envLines.push(`Location: ${loc.resultValue}`);
    const isp = r('B-LE-02');
    if (isp) envLines.push(`ISP: ${isp.resultValue}`);
    const wifi = r('L-LE-04');
    if (wifi) envLines.push(`WiFi: ${wifi.resultValue}`);
    const gwLat = r('L-LE-05');
    if (gwLat) envLines.push(`Gateway latency: ${gwLat.resultValue}`);
    const adapters = r('L-LE-06');
    if (adapters) {
        envLines.push(`Adapters: ${adapters.resultValue}`);
        // Include DNS server info if available
        if (adapters.detailedInfo && adapters.detailedInfo.includes('DNS Servers')) {
            const dnsBlock = adapters.detailedInfo.split('\n')
                .filter(l => l.includes('DNS Servers') || (l.trim().match(/^\d+\.\d+/) && adapters.detailedInfo.indexOf('DNS Servers') < adapters.detailedInfo.indexOf(l)));
            if (dnsBlock.length > 0) envLines.push(dnsBlock.join('; ').trim());
        }
    }
    const bw = r('L-LE-07');
    if (bw) envLines.push(`Bandwidth: ${bw.resultValue}`);
    const perf = r('L-LE-08');
    if (perf) envLines.push(`Machine: ${perf.resultValue}`);
    if (envLines.length > 0) sections.push(`## Environment\n${envLines.join('\n')}\n`);

    // ── Gateway & Routing ──
    const gwLines = [];
    const gw04 = r('L-TCP-04');
    if (gw04) gwLines.push(`Gateway: ${gw04.resultValue}`);
    const gw09 = r('L-TCP-09');
    if (gw09) gwLines.push(`Gateway location: ${gw09.resultValue}`);
    const egress = r('27');
    if (egress) gwLines.push(`Egress: ${egress.resultValue}`);
    if (gwLines.length > 0) sections.push(`## Gateway & Routing\n${gwLines.join('\n')}\n`);

    // ── Security checks ──
    const secLines = [];
    const tls = r('L-TCP-06');
    if (tls) secLines.push(`TLS inspection: ${tls.status} — ${tls.resultValue}`);
    const dns08 = r('L-TCP-08');
    if (dns08) secLines.push(`DNS hijacking: ${dns08.status} — ${dns08.resultValue}`);
    const vpn = r('L-TCP-07');
    if (vpn) {
        secLines.push(`Proxy/VPN/SWG: ${vpn.status} — ${vpn.resultValue}`);
        // Include VPN routing detail if VPN detected
        if (vpn.detailedInfo && vpn.detailedInfo.includes('VPN adapter')) {
            const vpnLines = vpn.detailedInfo.split('\n')
                .filter(l => l.includes('VPN adapter') || l.includes('routed direct') || l.includes('VPN tunnel'))
                .map(l => l.trim());
            if (vpnLines.length > 0) secLines.push(vpnLines.join('\n'));
        }
    }
    if (secLines.length > 0) sections.push(`## Security / Path\n${secLines.join('\n')}\n`);

    // ── UDP / NAT / TURN ──
    const udpLines = [];
    const turn03 = r('L-UDP-03');
    if (turn03) udpLines.push(`TURN reachability: ${turn03.status} — ${turn03.resultValue}`);
    const turn04 = r('L-UDP-04');
    if (turn04) udpLines.push(`TURN location: ${turn04.resultValue}`);
    const nat = r('L-UDP-05') || r('B-UDP-02');
    if (nat) udpLines.push(`NAT type: ${nat.resultValue}`);
    if (udpLines.length > 0) sections.push(`## UDP / Shortpath\n${udpLines.join('\n')}\n`);

    // ── Live Connection Diagnostics (most diagnostic value) ──
    const liveLines = [];
    const session18 = r('18');
    if (session18) {
        liveLines.push(`RTT latency: ${session18.status} — ${session18.resultValue}`);
        // Extract latency samples for spike pattern analysis
        if (session18.detailedInfo) {
            const valuesLine = session18.detailedInfo.split('\n').find(l => l.startsWith('Values:'));
            if (valuesLine) {
                liveLines.push(valuesLine.trim());
                // Detect periodic spikes
                const spikes = detectLatencySpikes(valuesLine);
                if (spikes) liveLines.push(spikes);
            }
        }
    }
    const jitter20 = r('20');
    if (jitter20) {
        liveLines.push(`Jitter: ${jitter20.status} — ${jitter20.resultValue}`);
        if (jitter20.detailedInfo) {
            const rttLine = jitter20.detailedInfo.split('\n').find(l => l.trim().startsWith('RTT Samples:'));
            if (rttLine) {
                liveLines.push(rttLine.trim());
                const spikes = detectLatencySpikes(rttLine);
                if (spikes) liveLines.push(spikes);
            }
            // Include key stats
            const statsLines = jitter20.detailedInfo.split('\n')
                .filter(l => l.includes('Mean RTT') || l.includes('Std Deviation') || l.includes('RTT Spread'))
                .map(l => l.trim());
            if (statsLines.length > 0) liveLines.push(statsLines.join('\n'));
        }
    }
    const loss21 = r('21');
    if (loss21) liveLines.push(`Packet loss: ${loss21.status} — ${loss21.resultValue}`);

    // Transport protocol
    const transport17b = r('17b');
    if (transport17b) {
        liveLines.push(`Transport: ${transport17b.resultValue}`);
        // Extract disconnect events
        if (transport17b.detailedInfo) {
            const disconnects = transport17b.detailedInfo.split('\n')
                .filter(l => l.includes('Disconnected') || l.includes('disconnected') || l.includes('Reason'))
                .map(l => l.trim());
            if (disconnects.length > 0) liveLines.push('Disconnect events:\n' + disconnects.join('\n'));
        }
    }

    const vpnPerf = r('24');
    if (vpnPerf) liveLines.push(`VPN performance: ${vpnPerf.status} — ${vpnPerf.resultValue}`);

    if (liveLines.length > 0) sections.push(`## Live Connection Diagnostics\n${liveLines.join('\n')}\n`);

    // ── All Failures and Warnings (full detail) ──
    const issues = results.filter(x => x.status === 'Failed' || x.status === 'Error' || x.status === 'Warning');
    if (issues.length > 0) {
        const issueLines = issues.map(x => {
            let line = `[${x.status.toUpperCase()}] ${x.id} ${x.name}: ${x.resultValue}`;
            // Include relevant detail (truncated to keep prompt manageable)
            if (x.detailedInfo) {
                const detail = x.detailedInfo.substring(0, 500);
                line += `\nDetail: ${detail}`;
            }
            return line;
        });
        sections.push(`## Failed / Warning Tests\n${issueLines.join('\n\n')}\n`);
    }

    // ── Endpoint reachability (only if issues) ──
    const ep01 = r('L-EP-01');
    if (ep01 && ep01.status !== 'Passed') {
        sections.push(`## Endpoint Reachability\n${ep01.resultValue}\n${(ep01.detailedInfo || '').substring(0, 300)}\n`);
    }

    // ── Traceroute summary (condensed) ──
    const trace = r('L-TCP-10');
    if (trace && trace.detailedInfo) {
        // Extract just hop lines with actual responses (not timeouts)
        const hops = trace.detailedInfo.split('\n')
            .filter(l => {
                const trimmed = l.replace(/[║│┃]/g, '').trim();
                return trimmed.match(/^\d+\s/) && !trimmed.includes('*                  *');
            })
            .map(l => l.replace(/[║│┃]/g, '').trim());
        if (hops.length > 0) {
            // Also get target headers
            const targets = trace.detailedInfo.split('\n')
                .filter(l => l.includes('Traceroute:') || l.includes('Target:'))
                .map(l => l.replace(/[║│╔╠═]/g, '').trim());
            sections.push(`## Traceroute (responding hops only)\n${targets.join('\n')}\n${hops.join('\n')}\n`);
        }
    }

    const prompt = sections.join('\n');

    // Trim to ~6000 chars max to stay URL-safe
    return prompt.length > 6000 ? prompt.substring(0, 5900) + '\n\n[truncated]' : prompt;
}

// ── Detect periodic latency spikes in a sample string ──
function detectLatencySpikes(sampleLine) {
    const nums = (sampleLine.match(/\d+/g) || []).map(Number);
    if (nums.length < 10) return null;

    const median = [...nums].sort((a, b) => a - b)[Math.floor(nums.length / 2)];
    const threshold = Math.max(median * 3, 200); // spike = 3x median or >200ms
    const spikePositions = [];
    nums.forEach((v, i) => { if (v > threshold) spikePositions.push(i); });

    if (spikePositions.length < 2) return null;

    // Check if spikes are periodic (regular gaps)
    const gaps = [];
    for (let i = 1; i < spikePositions.length; i++) {
        gaps.push(spikePositions[i] - spikePositions[i - 1]);
    }
    const avgGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const isRegular = gaps.every(g => Math.abs(g - avgGap) <= 2);

    if (isRegular && spikePositions.length >= 3) {
        const spikeVals = spikePositions.map(i => nums[i]);
        const avgSpike = Math.round(spikeVals.reduce((a, b) => a + b, 0) / spikeVals.length);
        return `⚠ PATTERN: ${spikePositions.length} periodic spikes (~${avgSpike}ms) every ~${Math.round(avgGap)} samples — suggests hardware/driver timer (WiFi power save or channel scanning)`;
    } else if (spikePositions.length >= 3) {
        return `⚠ ${spikePositions.length} latency spikes detected (>${threshold}ms threshold)`;
    }
    return null;
}

// ── Launch Copilot or fallback ──
async function launchAiAnalysis() {
    if (!allResults || allResults.length === 0) {
        alert('No test results available. Run tests or import scanner results first.');
        return;
    }

    const prompt = buildAnalysisPrompt(allResults);
    if (!prompt) return;

    // Show a brief toast
    showAiToast('Building analysis prompt...');

    // Encode for URL
    const encoded = encodeURIComponent(prompt);

    // Copilot URL: https://copilot.microsoft.com/?q=...
    // Max URL length is ~8KB for most browsers, but Copilot supports ~4KB query reliably
    const copilotUrl = `https://copilot.microsoft.com/?q=${encoded}`;

    if (copilotUrl.length <= 8000) {
        showAiToast('Opening Microsoft Copilot...');
        window.open(copilotUrl, '_blank', 'noopener');
    } else {
        // Prompt too large for URL — copy to clipboard and open Copilot empty
        try {
            await navigator.clipboard.writeText(prompt);
            showAiToast('Prompt copied to clipboard — paste it in Copilot');
            setTimeout(() => {
                window.open('https://copilot.microsoft.com/', '_blank', 'noopener');
            }, 500);
        } catch (e) {
            // Clipboard failed — show modal with prompt
            showAiPromptModal(prompt);
        }
    }
}

// ── Toast notification ──
function showAiToast(message) {
    let toast = document.getElementById('ai-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'ai-toast';
        toast.className = 'ai-toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// ── Fallback modal: show prompt for manual copy ──
function showAiPromptModal(prompt) {
    const overlay = document.createElement('div');
    overlay.className = 'ai-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    overlay.innerHTML = `
        <div class="ai-modal">
            <div class="ai-modal-header">
                <h3>Analysis Prompt</h3>
                <button class="ai-modal-close" onclick="this.closest('.ai-modal-overlay').remove()">✕</button>
            </div>
            <p class="ai-modal-instructions">
                The prompt is too large for a URL. Copy it below and paste into
                <a href="https://copilot.microsoft.com/" target="_blank" rel="noopener">Microsoft Copilot</a> or
                <a href="https://chatgpt.com/" target="_blank" rel="noopener">ChatGPT</a>.
            </p>
            <textarea class="ai-modal-textarea" readonly>${prompt.replace(/</g, '&lt;')}</textarea>
            <div class="ai-modal-actions">
                <button class="btn btn-primary" onclick="
                    navigator.clipboard.writeText(this.closest('.ai-modal').querySelector('textarea').value);
                    this.textContent='Copied!';
                    setTimeout(()=>this.textContent='Copy to Clipboard',1500);
                ">Copy to Clipboard</button>
                <button class="btn btn-secondary" onclick="window.open('https://copilot.microsoft.com/','_blank');this.closest('.ai-modal-overlay').remove()">Open Copilot</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
}
