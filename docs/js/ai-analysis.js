/**
 * Built-in Analysis Engine — rule-based expert system that analyses
 * W365 connectivity scan results and produces a prioritised diagnostic
 * report directly in the browser.  No external API required.
 */

// ═══════════════════════════════════════════════════════════════════
//  Severity helpers
// ═══════════════════════════════════════════════════════════════════
const SEV = { CRITICAL: 'critical', WARNING: 'warning', INFO: 'info' };

function finding(severity, title, detail, remediation) {
    return { severity, title, detail, remediation };
}

// ═══════════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════════
function parseMs(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*ms/i);
    return m ? parseFloat(m[1]) : NaN;
}
function parseMbps(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*Mbps/i);
    return m ? parseFloat(m[1]) : NaN;
}
function parsePct(str) {
    if (!str) return NaN;
    const m = str.match(/([\d.]+)\s*%/);
    return m ? parseFloat(m[1]) : NaN;
}
function parseSignal(str) {
    if (!str) return NaN;
    const m = str.match(/([\d]+)\s*%/);
    return m ? parseInt(m[1], 10) : NaN;
}

// ═══════════════════════════════════════════════════════════════════
//  Spike detector
// ═══════════════════════════════════════════════════════════════════
function detectLatencySpikes(sampleLine) {
    const nums = (sampleLine.match(/[\d.]+/g) || []).map(Number).filter(n => n > 0 && n < 10000);
    if (nums.length < 10) return null;

    const sorted = [...nums].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const threshold = Math.max(median * 3, 200);
    const spikePositions = [];
    nums.forEach((v, i) => { if (v > threshold) spikePositions.push(i); });
    if (spikePositions.length < 2) return null;

    const gaps = [];
    for (let i = 1; i < spikePositions.length; i++) gaps.push(spikePositions[i] - spikePositions[i - 1]);
    const avgGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const isRegular = gaps.length > 0 && gaps.every(g => Math.abs(g - avgGap) <= 2);

    const spikeVals = spikePositions.map(i => nums[i]);
    const avgSpike = Math.round(spikeVals.reduce((a, b) => a + b, 0) / spikeVals.length);
    const maxSpike = Math.max(...spikeVals);

    return {
        count: spikePositions.length,
        avgMs: avgSpike,
        maxMs: maxSpike,
        periodic: isRegular && spikePositions.length >= 3,
        gapSamples: Math.round(avgGap),
        medianMs: Math.round(median),
        threshold: Math.round(threshold)
    };
}

// ═══════════════════════════════════════════════════════════════════
//  Core analysis engine
// ═══════════════════════════════════════════════════════════════════
function runAnalysisEngine(results) {
    if (!results || results.length === 0) return [];

    const r = id => results.find(x => x.id === id);
    const findings = [];

    // ── 1. WiFi signal ──
    const wifi = r('L-LE-04');
    if (wifi) {
        const sig = parseSignal(wifi.resultValue);
        if (!isNaN(sig)) {
            if (sig < 40) {
                findings.push(finding(SEV.CRITICAL, 'Poor WiFi signal',
                    `Signal strength is ${sig}% — below the recommended 60% minimum. This will cause packet loss, retransmissions and intermittent disconnects.`,
                    'Move closer to the access point, remove physical obstructions, or switch to a 5 GHz band. If possible, use a wired Ethernet connection for Cloud PC sessions.'));
            } else if (sig < 60) {
                findings.push(finding(SEV.WARNING, 'Marginal WiFi signal',
                    `Signal strength is ${sig}%. While usable, this may cause occasional latency spikes under load.`,
                    'Consider moving closer to the access point or switching to 5 GHz. Wired Ethernet is always preferred for Cloud PC use.'));
            }
        }
        // Check for WiFi adapter power management hints
        if (wifi.detailedInfo) {
            const detail = wifi.detailedInfo.toLowerCase();
            if (detail.includes('intel') && (detail.includes('ax201') || detail.includes('ax200') || detail.includes('ax211') || detail.includes('be200'))) {
                findings.push(finding(SEV.INFO, 'Intel WiFi adapter detected',
                    'Intel WiFi adapters have independent power management that can cause periodic latency spikes even when Windows power policy is set to Maximum Performance.',
                    'Open Device Manager \u2192 Network Adapters \u2192 Intel WiFi \u2192 Properties \u2192 Advanced. Set "Power Saving Mode" to Off, "Roaming Aggressiveness" to Lowest, and "U-APSD Support" to Disabled.'));
            }
        }
    }

    // ── 2. Gateway / router latency ──
    const gwLat = r('L-LE-05');
    if (gwLat) {
        const avg = parseMs(gwLat.resultValue);
        if (!isNaN(avg)) {
            if (avg > 50) {
                findings.push(finding(SEV.CRITICAL, 'Very high gateway latency',
                    `Average latency to your local gateway is ${avg.toFixed(0)} ms — this should be < 5 ms on a healthy network. Every packet to Azure inherits this local delay.`,
                    'Check for WiFi interference, network congestion, or a malfunctioning router. Try rebooting the router, using a wired connection, or bypassing any consumer mesh/extender nodes.'));
            } else if (avg > 20) {
                findings.push(finding(SEV.WARNING, 'Elevated gateway latency',
                    `Average latency to your gateway is ${avg.toFixed(0)} ms (ideal is < 5 ms). This adds delay to every Azure round-trip.`,
                    'This commonly indicates WiFi contention or an overloaded home router. A wired connection or 5 GHz WiFi band may help.'));
            }
        }
    }

    // ── 3. Bandwidth ──
    const bwLocal = r('L-LE-07');
    const bwBrowser = r('B-LE-03');
    const bw = bwLocal || bwBrowser;
    if (bw) {
        const mbps = parseMbps(bw.resultValue);
        if (!isNaN(mbps)) {
            if (mbps < 5) {
                findings.push(finding(SEV.CRITICAL, 'Very low bandwidth',
                    `Bandwidth is only ${mbps.toFixed(1)} Mbps — well below the 20 Mbps recommended for a good Cloud PC experience. Video, screen updates and file transfers will be severely impacted.`,
                    'Check for other devices consuming bandwidth, streaming, or large downloads. Contact your ISP if bandwidth is consistently below plan speeds. Use a wired connection if on WiFi.'));
            } else if (mbps < 10) {
                findings.push(finding(SEV.WARNING, 'Low bandwidth',
                    `Bandwidth is ${mbps.toFixed(1)} Mbps — below the 20 Mbps recommended for optimal Cloud PC performance.`,
                    'Ensure other bandwidth-heavy activities are minimised during Cloud PC use. A wired Ethernet connection can improve throughput stability.'));
            }
        }
    }

    // ── 4. Machine performance ──
    const perf = r('L-LE-08');
    if (perf && (perf.status === 'Warning' || perf.status === 'Failed')) {
        findings.push(finding(perf.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'Client machine performance concern',
            perf.resultValue,
            'Close unnecessary applications, check for high CPU/memory usage in Task Manager, ensure the device is not thermally throttling, and verify that GPU drivers are up to date.'));
    }

    // ── 5. TLS inspection ──
    const tls = r('L-TCP-06');
    if (tls && tls.status !== 'Passed' && tls.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection detected',
            `A TLS-intercepting proxy (SSL inspection / MITM) is modifying the certificate chain for Windows 365 gateway connections. ${tls.resultValue}`,
            'Windows 365 RDP traffic must not be TLS-inspected. Add *.wvd.microsoft.com, *.infra.windows365.microsoft.com, and turn.azure.com to your proxy\'s SSL bypass list. See https://learn.microsoft.com/windows-365/enterprise/requirements-network'));
    }
    const tlsUdp = r('L-UDP-06');
    if (tlsUdp && tlsUdp.status !== 'Passed' && tlsUdp.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection on TURN relay',
            `TURN relay traffic (UDP 3478) is being TLS-inspected. ${tlsUdp.resultValue}`,
            'Add turn.azure.com to your proxy\'s SSL bypass / certificate pinning exception list.'));
    }
    const tlsRdp = r('25');
    if (tlsRdp && tlsRdp.status !== 'Passed' && tlsRdp.status !== 'Skipped') {
        findings.push(finding(SEV.CRITICAL, 'TLS inspection on live RDP session',
            `Active RDP session traffic is being TLS-intercepted. ${tlsRdp.resultValue}`,
            'This will cause disconnects and session instability. Exempt all Windows 365 FQDNs from SSL inspection immediately.'));
    }

    // ── 6. DNS hijacking ──
    const dnsHijack = r('L-TCP-08');
    if (dnsHijack && dnsHijack.status !== 'Passed' && dnsHijack.status !== 'Skipped') {
        findings.push(finding(SEV.WARNING, 'DNS hijacking detected',
            `DNS responses are being modified, possibly by a captive portal, security appliance, or ISP. ${dnsHijack.resultValue}`,
            'Check if a corporate DNS sinkhole or ISP-level DNS redirect is in place. Use a direct DNS resolver (e.g. 8.8.8.8 or corporate DNS) and verify NXDOMAIN is returned for non-existent domains.'));
    }

    // ── 7. VPN / Proxy / SWG ──
    const vpn = r('L-TCP-07');
    if (vpn && vpn.status !== 'Passed' && vpn.status !== 'Skipped') {
        const isVpn = vpn.resultValue.toLowerCase().includes('vpn');
        let splitTunnel = false;
        if (vpn.detailedInfo) {
            splitTunnel = vpn.detailedInfo.toLowerCase().includes('routed direct') ||
                          vpn.detailedInfo.toLowerCase().includes('split tunnel');
        }
        if (isVpn && !splitTunnel) {
            findings.push(finding(SEV.WARNING, 'VPN detected \u2014 check split tunnelling',
                `A VPN connection is active. If W365 traffic is routed through the VPN tunnel, it will add latency and reduce throughput. ${vpn.resultValue}`,
                'Configure split tunnelling to exclude Windows 365 FQDNs (*.wvd.microsoft.com, *.infra.windows365.microsoft.com, turn.azure.com) from the VPN tunnel. See https://learn.microsoft.com/windows-365/enterprise/azure-network-connections'));
        } else if (isVpn && splitTunnel) {
            findings.push(finding(SEV.INFO, 'VPN detected \u2014 correctly split-tunnelled',
                'A VPN is active but Windows 365 traffic appears to be routed directly (not through the tunnel). This is the recommended configuration.',
                null));
        }
    }
    const vpnPerf = r('24');
    if (vpnPerf && vpnPerf.status !== 'Passed' && vpnPerf.status !== 'Skipped') {
        findings.push(finding(vpnPerf.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'VPN is degrading session performance',
            vpnPerf.resultValue,
            'VPN routing is adding measurable latency to the RDP session. Enable split tunnelling for W365 traffic or disconnect the VPN during Cloud PC use.'));
    }

    // ── 8. Proxy / SWG detection from DNS routing ──
    const dnsRoute = r('B-TCP-04');
    if (dnsRoute && dnsRoute.detailedInfo) {
        const detail = dnsRoute.detailedInfo.toLowerCase();
        const swgNames = ['zscaler', 'netskope', 'globalsecureaccess', 'cloudflare-gateway', 'swg', 'menlo'];
        const detectedSwg = swgNames.find(s => detail.includes(s));
        if (detectedSwg) {
            findings.push(finding(SEV.INFO, `Secure Web Gateway detected (${detectedSwg})`,
                'Traffic is routing through a cloud security service. This is expected in managed environments but adds latency.',
                'Ensure Windows 365 endpoints are in the SWG bypass list for optimal performance.'));
        }
        // Private Link
        if (detail.includes('privatelink') && (detail.includes('10.') || detail.match(/172\.(1[6-9]|2\d|3[01])/) || detail.includes('192.168.'))) {
            findings.push(finding(SEV.INFO, 'Azure Private Link in use',
                'DNS resolution is routing through Private Link endpoints (RFC 1918 IPs). This is the expected corporate configuration.',
                null));
        }
    }

    // ── 9. NAT type ──
    const nat = r('L-UDP-05') || r('B-UDP-02');
    if (nat) {
        const val = (nat.resultValue || '').toLowerCase();
        if (val.includes('symmetric')) {
            findings.push(finding(SEV.WARNING, 'Symmetric NAT detected',
                'Your network uses Symmetric NAT, which prevents direct UDP Shortpath connections. Traffic will fall back to TURN relay, adding 10\u201330 ms latency.',
                'Symmetric NAT is common behind enterprise firewalls and CGNAT. If this is a home network, check if your router supports "Full Cone" or "Endpoint-Independent" NAT mode. If behind CGNAT, contact your ISP about getting a public IP.'));
        } else if (val.includes('blocked') || nat.status === 'Failed') {
            findings.push(finding(SEV.CRITICAL, 'UDP / STUN blocked',
                'UDP STUN connectivity is blocked. UDP Shortpath cannot be established, and TURN relay may also be impacted.',
                'Ensure outbound UDP port 3478 is open to turn.azure.com and stun.azure.com. Check firewall rules and any network security appliances.'));
        }
    }

    // ── 10. TURN reachability ──
    const turn = r('L-UDP-03');
    if (turn && (turn.status === 'Failed' || turn.status === 'Error')) {
        findings.push(finding(SEV.CRITICAL, 'TURN relay unreachable',
            `TURN relay servers on UDP 3478 are not reachable. UDP Shortpath cannot be established. ${turn.resultValue}`,
            'Ensure outbound UDP 3478 to turn.azure.com is allowed through all firewalls and network security appliances.'));
    }

    // ── 11. Session latency (Test 18) ──
    const session = r('18');
    if (session) {
        const avg = parseMs(session.resultValue);
        if (!isNaN(avg)) {
            if (avg > 200) {
                findings.push(finding(SEV.CRITICAL, 'Very high session latency',
                    `Average round-trip time is ${avg.toFixed(0)} ms — well above the 100 ms threshold for a good experience. Users will notice significant input lag and sluggish response.`,
                    'Check if traffic is being routed through a VPN or proxy. Verify that the Cloud PC provisioning region is geographically close to the user. High gateway latency (L-LE-05) compounds this issue.'));
            } else if (avg > 100) {
                findings.push(finding(SEV.WARNING, 'Elevated session latency',
                    `Average RTT is ${avg.toFixed(0)} ms. Latency above 100 ms becomes noticeable during interactive work (typing, mouse movement).`,
                    'Ensure traffic egresses locally (not hairpinned through a VPN or distant proxy). Check Cloud PC region alignment with the user\'s physical location.'));
            }
        }
        // Check for spikes in detailed samples
        if (session.detailedInfo) {
            const valLine = session.detailedInfo.split('\n').find(l => l.startsWith('Values:') || l.includes('RTT Samples:'));
            if (valLine) {
                const spikes = detectLatencySpikes(valLine);
                if (spikes && spikes.periodic) {
                    findings.push(finding(SEV.CRITICAL, 'Periodic latency spikes detected',
                        `${spikes.count} regular spikes averaging ${spikes.avgMs} ms (peak ${spikes.maxMs} ms) every ~${spikes.gapSamples} samples against a baseline median of ${spikes.medianMs} ms. This pattern is characteristic of WiFi driver background scanning or power management cycling.`,
                        'Open Device Manager \u2192 WiFi adapter \u2192 Properties \u2192 Advanced. Disable Power Saving Mode, set Roaming Aggressiveness to Lowest, disable U-APSD. If using Intel AX200/AX201/AX211, these settings are in the Intel driver properties. Alternatively, use a wired Ethernet connection.'));
                } else if (spikes && spikes.count >= 3) {
                    findings.push(finding(SEV.WARNING, 'Latency spikes detected',
                        `${spikes.count} latency spikes exceeding ${spikes.threshold} ms detected (avg ${spikes.avgMs} ms, peak ${spikes.maxMs} ms). These are irregular, suggesting intermittent network congestion or interference.`,
                        'Check for WiFi interference, competing bandwidth usage, or packet buffering. Monitor with a continuous ping to the gateway to correlate spikes with other network activity.'));
                }
            }
        }
    }

    // ── 12. Jitter (Test 20) ──
    const jitter = r('20');
    if (jitter) {
        const j = parseMs(jitter.resultValue);
        if (!isNaN(j)) {
            if (j > 60) {
                findings.push(finding(SEV.CRITICAL, 'Very high jitter',
                    `Connection jitter is ${j.toFixed(1)} ms — far above the 30 ms warning threshold. This causes inconsistent frame delivery, visual stuttering, and audio glitches.`,
                    'High jitter is usually caused by WiFi instability, network congestion, or a saturated uplink. Use a wired connection, reduce competing traffic, and check for QoS issues on the local network.'));
            } else if (j > 30) {
                findings.push(finding(SEV.WARNING, 'Elevated jitter',
                    `Connection jitter is ${j.toFixed(1)} ms — above the 30 ms threshold for smooth experience.`,
                    'Check for WiFi interference or competing bandwidth-intensive activities on the same network.'));
            }
        }
    }

    // ── 13. Packet loss / Frame drops (Test 21) ──
    const loss = r('21');
    if (loss) {
        const pct = parsePct(loss.resultValue);
        if (!isNaN(pct)) {
            if (pct > 15) {
                findings.push(finding(SEV.CRITICAL, 'Severe packet loss',
                    `Packet / frame loss is ${pct.toFixed(1)}% — this will cause visible screen corruption, freezing, and frequent disconnects.`,
                    'Check the WiFi signal strength, network adapter drivers, and for any duplex mismatches. On wired connections, try a different cable or switch port. Check for UDP throttling by firewalls.'));
            } else if (pct > 5) {
                findings.push(finding(SEV.WARNING, 'Packet loss detected',
                    `${pct.toFixed(1)}% packet / frame loss — above the 5% threshold. Users may experience occasional freezes or visual artefacts.`,
                    'Monitor for WiFi interference or network congestion peaks. Ensure the network adapter driver is up to date.'));
            }
        }
    }

    // ── 14. Transport protocol (Test 17b) ──
    const transport = r('17b');
    if (transport) {
        const val = (transport.resultValue || '').toLowerCase();
        if (val.includes('tcp')) {
            findings.push(finding(SEV.WARNING, 'Session using TCP transport',
                'The session is using TCP instead of UDP Shortpath. TCP adds latency due to head-of-line blocking and retransmissions, resulting in a less responsive experience.',
                'Ensure UDP 3478 outbound is open, NAT type allows it, and TURN relay is reachable. UDP Shortpath is enabled by default in Windows 365 \u2014 verify no GPO is disabling it.'));
        }
        // Check for disconnects
        if (transport.detailedInfo) {
            const disconnects = transport.detailedInfo.split('\n')
                .filter(l => l.toLowerCase().includes('disconnect') || l.toLowerCase().includes('reason'));
            if (disconnects.length > 1) {
                const reasons = disconnects.map(l => l.trim()).join('; ');
                findings.push(finding(SEV.WARNING, 'Session disconnect events found',
                    `RDP event logs show disconnect events: ${reasons.substring(0, 300)}`,
                    'Frequent disconnects with reason code 16644 indicate transport timeout (network drop). Code 4616 indicates network-level disconnection. Check WiFi stability, VPN keepalive settings, and idle timeout policies.'));
            }
        }
    }

    // ── 15. UDP Shortpath readiness (Test 17c) ──
    const udpReady = r('17c');
    if (udpReady && (udpReady.status === 'Failed' || udpReady.status === 'Warning')) {
        if ((udpReady.resultValue || '').toLowerCase().includes('blocked')) {
            findings.push(finding(SEV.WARNING, 'UDP Shortpath blocked',
                `UDP Shortpath is not available: ${udpReady.resultValue}. The session will use TCP, which is less responsive.`,
                'Open outbound UDP 3478 to turn.azure.com. Check for firewall rules, DPI appliances, or carrier-grade NAT blocking UDP.'));
        }
    }

    // ── 16. RDP traffic routing (Test 26) ──
    const rdpRoute = r('26');
    if (rdpRoute && rdpRoute.status !== 'Passed' && rdpRoute.status !== 'Skipped') {
        findings.push(finding(rdpRoute.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'RDP traffic not routing optimally',
            rdpRoute.resultValue,
            'Verify split tunnelling is configured for W365 endpoints. Check if a proxy is intercepting RDP WebSocket traffic.'));
    }

    // ── 17. Egress analysis (Test 27) ──
    const egress = r('27');
    if (egress && egress.status !== 'Passed' && egress.status !== 'Skipped') {
        findings.push(finding(egress.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'Non-local egress detected',
            `RDP traffic is not egressing locally: ${egress.resultValue}. Traffic may be hairpinned through a VPN or corporate proxy, adding unnecessary latency.`,
            'Configure split tunnelling so W365 traffic exits directly from the user\'s local internet connection.'));
    }

    // ── 18. Endpoint reachability ──
    const ep = r('L-EP-01') || r('B-EP-01');
    if (ep && (ep.status === 'Failed' || ep.status === 'Error')) {
        findings.push(finding(SEV.CRITICAL, 'Required endpoints unreachable',
            `One or more required Windows 365 endpoints are not reachable. ${ep.resultValue}`,
            'Check firewall rules, proxy configuration, and DNS resolution. See https://learn.microsoft.com/windows-365/enterprise/requirements-network for the full endpoint list.'));
    } else if (ep && ep.status === 'Warning') {
        findings.push(finding(SEV.WARNING, 'Some endpoints have connectivity issues',
            ep.resultValue,
            'Review the detailed endpoint list for timeouts or slow responses. Partial failures can cause intermittent login or session issues.'));
    }

    // ── 19. DNS performance ──
    const dns = r('B-TCP-03');
    if (dns) {
        const avg = parseMs(dns.resultValue);
        if (!isNaN(avg) && avg > 1000) {
            findings.push(finding(SEV.CRITICAL, 'Very slow DNS resolution',
                `DNS resolution is averaging ${avg.toFixed(0)} ms — this delays every new connection and service discovery operation.`,
                'Check DNS server responsiveness. Consider using a faster resolver or reducing DNS chain depth. Verify no DNS sinkhole or inspection is adding delay.'));
        } else if (!isNaN(avg) && avg > 500) {
            findings.push(finding(SEV.WARNING, 'Slow DNS resolution',
                `DNS resolution averaging ${avg.toFixed(0)} ms — above the 500 ms target.`,
                'Check DNS server load and network path to the resolver.'));
        }
    }

    // ── 20. Teams optimisation ──
    const teams = r('L-LE-09') || r('22');
    if (teams && teams.status !== 'Passed' && teams.status !== 'Skipped') {
        findings.push(finding(SEV.INFO, 'Teams optimisation not configured',
            teams.resultValue,
            'For the best Teams experience in a Cloud PC, enable Teams AV redirection. See https://learn.microsoft.com/windows-365/enterprise/teams-on-cloud-pc'));
    }

    // ── 21. No active session warning ──
    const activeSession = r('17');
    if (activeSession && activeSession.status === 'Warning') {
        findings.push(finding(SEV.INFO, 'No active Cloud PC session detected',
            'Live connection diagnostics (latency, jitter, packet loss) require an active RDP session. Those tests were skipped.',
            'Connect to your Cloud PC via the Windows 365 app or windows365.microsoft.com, then re-run the scan for full analysis.'));
    }

    // ── 22. Frame rate / encoding (Test 19) ──
    const frames = r('19');
    if (frames && (frames.status === 'Warning' || frames.status === 'Failed')) {
        findings.push(finding(frames.status === 'Failed' ? SEV.CRITICAL : SEV.WARNING,
            'Frame rate or encoding issues',
            frames.resultValue,
            'High encoding time (>33 ms per frame) indicates GPU or CPU overload on the Cloud PC. Check for GPU driver updates in the Cloud PC, reduce display resolution, or close GPU-intensive applications.'));
    }

    // ── 23. CNAME chain / DNS analysis ──
    const cname = r('L-TCP-05');
    if (cname && cname.status !== 'Passed' && cname.status !== 'Skipped') {
        findings.push(finding(SEV.INFO, 'DNS CNAME chain analysis',
            cname.resultValue,
            'Complex CNAME chains can add DNS resolution latency. This is usually informational unless combined with slow DNS (B-TCP-03).'));
    }

    // ── 24. Overall health summary (always add) ──
    const failed = results.filter(x => x.status === 'Failed' || x.status === 'Error').length;
    const warned = results.filter(x => x.status === 'Warning').length;
    const passed = results.filter(x => x.status === 'Passed').length;
    const total = results.length;

    if (failed === 0 && warned === 0) {
        findings.push(finding(SEV.INFO, 'All tests passed',
            `${passed} of ${total} tests passed with no warnings or failures. Your connectivity to Windows 365 looks healthy.`,
            null));
    }

    // Sort: critical first, then warning, then info
    const order = { critical: 0, warning: 1, info: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);

    return findings;
}

// ═══════════════════════════════════════════════════════════════════
//  UI: render analysis panel
// ═══════════════════════════════════════════════════════════════════
function launchAiAnalysis() {
    if (!allResults || allResults.length === 0) {
        alert('No test results available. Run tests or import scanner results first.');
        return;
    }

    const findings = runAnalysisEngine(allResults);
    showAnalysisPanel(findings);
}

function showAnalysisPanel(findings) {
    // Remove any existing panel
    const existing = document.getElementById('analysis-panel-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'analysis-panel-overlay';
    overlay.className = 'analysis-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) closeAnalysisPanel(); };

    const criticals = findings.filter(f => f.severity === 'critical');
    const warnings = findings.filter(f => f.severity === 'warning');
    const infos = findings.filter(f => f.severity === 'info');

    const sevIcon = (sev) => {
        switch (sev) {
            case 'critical': return '<span class="analysis-icon analysis-icon-critical">\u2718</span>';
            case 'warning':  return '<span class="analysis-icon analysis-icon-warning">\u26A0</span>';
            case 'info':     return '<span class="analysis-icon analysis-icon-info">\u2139</span>';
        }
    };

    const renderFinding = (f) => {
        const remHtml = f.remediation
            ? `<div class="analysis-remediation"><strong>Recommendation:</strong> ${escapeHtml(f.remediation)}</div>`
            : '';
        return `
            <div class="analysis-finding analysis-finding-${f.severity}">
                <div class="analysis-finding-header">
                    ${sevIcon(f.severity)}
                    <span class="analysis-finding-title">${escapeHtml(f.title)}</span>
                </div>
                <div class="analysis-finding-detail">${escapeHtml(f.detail)}</div>
                ${remHtml}
            </div>`;
    };

    // Summary badge counts
    const summaryHtml = `
        <div class="analysis-summary">
            ${criticals.length > 0 ? `<span class="analysis-badge badge-critical">${criticals.length} Critical</span>` : ''}
            ${warnings.length > 0 ? `<span class="analysis-badge badge-warning">${warnings.length} Warning${warnings.length > 1 ? 's' : ''}</span>` : ''}
            ${infos.length > 0 ? `<span class="analysis-badge badge-info">${infos.length} Info</span>` : ''}
            ${criticals.length === 0 && warnings.length === 0 ? '<span class="analysis-badge badge-healthy">\u2714 Healthy</span>' : ''}
        </div>`;

    const findingsHtml = findings.map(renderFinding).join('');

    overlay.innerHTML = `
        <div class="analysis-panel">
            <div class="analysis-panel-header">
                <div class="analysis-panel-title">
                    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                        <path d="M9 1L1 5l8 4 8-4-8-4z" stroke="currentColor" stroke-width="1.4" fill="none"/>
                        <path d="M1 13l8 4 8-4M1 9l8 4 8-4" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>
                    </svg>
                    Connectivity Analysis
                </div>
                <button class="analysis-close" onclick="closeAnalysisPanel()" title="Close">\u2715</button>
            </div>
            ${summaryHtml}
            <div class="analysis-findings">
                ${findingsHtml}
            </div>
            <div class="analysis-copilot">
                <div class="analysis-copilot-info">
                    <strong>Want deeper analysis?</strong> Copy the results below and paste into Microsoft Copilot for AI-powered root-cause analysis and remediation advice.
                </div>
                <button class="btn btn-ai" onclick="copilotAnalysis(this)">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="1.8" fill="none"/><path d="M12 8v4l3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    Copy &amp; Open Copilot
                </button>
            </div>
            <div class="analysis-footer">
                <button class="btn btn-secondary" onclick="copyAnalysisText()">Copy as Text</button>
                <button class="btn btn-secondary" onclick="closeAnalysisPanel()">Close</button>
            </div>
        </div>`;

    document.body.appendChild(overlay);

    // Animate in
    requestAnimationFrame(() => {
        overlay.classList.add('show');
    });
}

function closeAnalysisPanel() {
    const overlay = document.getElementById('analysis-panel-overlay');
    if (overlay) {
        overlay.classList.remove('show');
        setTimeout(() => overlay.remove(), 300);
    }
}

function copyAnalysisText() {
    const findings = runAnalysisEngine(allResults);
    const lines = findings.map(f => {
        const sev = f.severity.toUpperCase();
        let text = `[${sev}] ${f.title}\n${f.detail}`;
        if (f.remediation) text += `\nRecommendation: ${f.remediation}`;
        return text;
    });
    const fullText = `W365 Connectivity Analysis \u2014 ${new Date().toLocaleString()}\n${'='.repeat(50)}\n\n${lines.join('\n\n')}`;

    navigator.clipboard.writeText(fullText).then(() => {
        const btn = document.querySelector('.analysis-footer .btn-secondary');
        if (btn) { const orig = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = orig, 1500); }
    }).catch(() => {});
}

// ═══════════════════════════════════════════════════════════════════
//  Copilot integration: build prompt, copy, open
// ═══════════════════════════════════════════════════════════════════
function buildCopilotPrompt(results, findings) {
    const lines = [];

    lines.push('I ran a Windows 365 / Azure Virtual Desktop connectivity scan from my physical device. Please analyse the results below and provide:');
    lines.push('1. Root-cause analysis of any failures or warnings');
    lines.push('2. Specific remediation steps (commands, settings, registry keys where applicable)');
    lines.push('3. Whether the issue is at the client, local network, ISP, or Azure edge');
    lines.push('Be concise but thorough. Reference Microsoft Learn docs where helpful.');
    lines.push('');

    // ── Key test results ──
    lines.push('== SCAN RESULTS ==');
    const passed = results.filter(x => x.status === 'Passed').length;
    const warned = results.filter(x => x.status === 'Warning').length;
    const failed = results.filter(x => x.status === 'Failed' || x.status === 'Error').length;
    lines.push(`${results.length} tests: ${passed} passed, ${warned} warnings, ${failed} failed`);
    lines.push('');

    // Include every non-passed test with detail
    const issues = results.filter(x => x.status !== 'Passed' && x.status !== 'Skipped' && x.status !== 'NotRun');
    if (issues.length > 0) {
        lines.push('-- Failed / Warning Tests --');
        for (const t of issues) {
            lines.push(`[${t.status.toUpperCase()}] ${t.id} ${t.name}: ${t.resultValue}`);
            if (t.detailedInfo) {
                // Include up to 400 chars of detail
                const detail = t.detailedInfo.substring(0, 400).replace(/[\r]/g, '');
                lines.push(detail);
            }
            lines.push('');
        }
    }

    // Include key environment info (always useful for analysis)
    lines.push('-- Environment --');
    const envIds = ['B-LE-01', 'B-LE-02', 'L-LE-04', 'L-LE-05', 'L-LE-06', 'L-LE-07', 'L-LE-08'];
    for (const id of envIds) {
        const t = results.find(x => x.id === id);
        if (t) lines.push(`${t.name}: ${t.resultValue}`);
    }
    lines.push('');

    // Include live session data if available
    const sessionIds = ['17b', '18', '20', '21', '24', '27'];
    const sessionResults = sessionIds.map(id => results.find(x => x.id === id)).filter(Boolean);
    if (sessionResults.length > 0) {
        lines.push('-- Live Session Diagnostics --');
        for (const t of sessionResults) {
            lines.push(`${t.name}: ${t.status} - ${t.resultValue}`);
            // Include latency samples for spike analysis
            if ((t.id === '18' || t.id === '20') && t.detailedInfo) {
                const valLine = t.detailedInfo.split('\n').find(l => l.startsWith('Values:') || l.includes('RTT Samples:'));
                if (valLine) lines.push(valLine.trim());
            }
        }
        lines.push('');
    }

    // Include our rule-based findings as context
    if (findings && findings.length > 0) {
        lines.push('-- Automated Analysis Findings --');
        for (const f of findings) {
            lines.push(`[${f.severity.toUpperCase()}] ${f.title}: ${f.detail}`);
        }
        lines.push('');
    }

    lines.push('Please provide your analysis based on the above results.');

    return lines.join('\n');
}

async function copilotAnalysis(btn) {
    if (!allResults || allResults.length === 0) return;

    const findings = runAnalysisEngine(allResults);
    const prompt = buildCopilotPrompt(allResults, findings);

    try {
        await navigator.clipboard.writeText(prompt);
        // Update button to show success
        const origHtml = btn.innerHTML;
        btn.innerHTML = '\u2714 Copied! Paste into Copilot with Ctrl+V';
        btn.classList.add('btn-copied');
        setTimeout(() => {
            btn.innerHTML = origHtml;
            btn.classList.remove('btn-copied');
        }, 4000);
        // Open Copilot after a short delay
        setTimeout(() => {
            window.open('https://copilot.microsoft.com/', '_blank', 'noopener');
        }, 600);
    } catch (e) {
        // Clipboard failed — show the prompt in a modal for manual copy
        showPromptModal(prompt);
    }
}

function showPromptModal(prompt) {
    const overlay = document.createElement('div');
    overlay.className = 'analysis-overlay show';
    overlay.style.zIndex = '10001';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    overlay.innerHTML = `
        <div class="analysis-panel" style="transform:translateX(0)">
            <div class="analysis-panel-header">
                <div class="analysis-panel-title">Copy Prompt for Copilot</div>
                <button class="analysis-close" onclick="this.closest('.analysis-overlay').remove()" title="Close">\u2715</button>
            </div>
            <p style="padding:16px 24px;color:var(--text-secondary);font-size:13px;margin:0">
                Clipboard access was blocked. Select all text below (Ctrl+A), copy it (Ctrl+C),
                then paste it into <a href="https://copilot.microsoft.com/" target="_blank" rel="noopener" style="color:var(--accent)">Microsoft Copilot</a>.
            </p>
            <textarea readonly style="flex:1;margin:0 24px 16px;padding:12px;background:var(--bg-surface);color:var(--text-primary);border:1px solid var(--border-default);border-radius:var(--r-sm);font-family:monospace;font-size:12px;resize:none;box-sizing:border-box">${prompt.replace(/</g, '&lt;')}</textarea>
            <div class="analysis-footer">
                <button class="btn btn-ai" onclick="window.open('https://copilot.microsoft.com/','_blank','noopener');this.closest('.analysis-overlay').remove()">Open Copilot</button>
            </div>
        </div>`;

    document.body.appendChild(overlay);
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
