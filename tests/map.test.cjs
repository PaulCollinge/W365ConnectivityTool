const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

function createMap(dashboard) {
    const root = path.join(__dirname, '..', 'docs', dashboard);
    const html = readFileSync(path.join(root, 'index.html'), 'utf8');
    const elements = new Map();
    for (const match of html.matchAll(/<[^>]*\bid="((?:map|device)-(?:turn|(?:cpc-)?dns)[^"]*|sec-dns-badge[^"]*|map-security-bar)"[^>]*>/g)) {
        const element = {
            className: match[0].match(/\bclass="([^"]*)"/)?.[1] || '',
            textContent: '',
            attributes: {},
            setAttribute(name, value) { this.attributes[name] = value; },
            appendChild(child) { this.textContent += child.textContent; }
        };
        element.classList = {
            contains(name) { return element.className.split(/\s+/).includes(name); },
            add(name) { this.toggle(name, true); },
            toggle(name, force) {
                const classes = new Set(element.className.split(/\s+/));
                if (force) classes.add(name);
                else classes.delete(name);
                element.className = [...classes].join(' ');
            }
        };
        elements.set(match[1], element);
    }
    const context = vm.createContext({
        navigator: { userAgent: 'Windows' },
        document: {
            getElementById(id) { return elements.get(id); },
            createElement() { return { textContent: '', style: {} }; },
            createTextNode(text) { return { textContent: text }; }
        },
        AZURE_REGIONS: [{ code: 'polandcentral', name: 'Poland Central' }]
    });
    vm.runInContext(readFileSync(path.join(root, 'js', 'map.js'), 'utf8'), context);
    // Keep user proximity independent of GeoIP and unrelated map cards.
    context.getUserLocationContext = () => ({ countryCode: 'gb', coords: null });
    context.getServiceCoords = () => null;
    context.checkServiceProximity = () => null;
    return {
        update(results) { context.updateMapTurnCard(results); },
        updateDns(results) { context.updateMapDnsCard(results); },
        updateSecurity(results) { context.updateMapSecurityBar(results); },
        setCpcMode(value) { context.cloudPcMode = value; },
        setHostType(value) { context.hostType = value; },
        element(id) { return elements.get(id); },
        text(id) { return elements.get(`map-turn-${id}`).textContent; },
        hidden(id) { return elements.get(`map-turn-${id}`).classList.contains('hidden'); },
        classes(id) { return elements.get(`map-turn-${id}`).className; }
    };
}

function location(city, slug) {
    return {
        status: 'Passed',
        resultValue: `TURN relay (DNS): ${city} (${slug}) (51.5.1.1)`,
        detailedInfo: `Azure Region: ${city} (${slug})`
    };
}

function latency(ms) {
    return {
        status: 'Passed',
        resultValue: `TURN relay reachable at 51.5.1.1:3478 - ${ms}ms RTT`,
        detailedInfo: `Latency: ${ms}ms`
    };
}

const client = () => ({
    'L-UDP-04': location('UK South', 'uksouth'),
    'L-UDP-03': latency(40)
});
const cpc = () => ({
    'C-UDP-04': location('Poland Central', 'polandcentral'),
    'C-UDP-03': latency(11),
    'C-NET-01': { detailedInfo: 'Azure Region: polandcentral' }
});

for (const dashboard of ['', 'hybrid']) {
    const name = dashboard || 'main';
    test(`${name}: merged UK client and Polish CPC retain separate locations and RTTs`, () => {
        for (const results of [
            { ...client(), ...cpc() },
            { ...cpc(), ...client() }
        ]) {
            const map = createMap(dashboard);
            map.update(results);
            assert.equal(map.hidden('client-side'), false);
            assert.equal(map.hidden('cpc-side'), false);
            assert.match(map.text('client-loc-badge'), /UK South/);
            assert.match(map.text('client-lat-badge'), /40ms/);
            assert.match(map.text('cpc-loc-badge'), /Poland Central/);
            assert.match(map.text('cpc-lat-badge'), /11ms/);
            assert.match(map.text('prox-badge'), /Cloud PC relay: same region/);
            assert.match(map.classes('accent'), /status-passed/);
            assert.match(map.text('detail'), /not live session routing/);
        }
    });

    test(`${name}: single-side scans retain their own origin and measurements`, () => {
        for (const [results, shown, hidden, ms] of [
            [client(), 'client', 'cpc', 40],
            [cpc(), 'cpc', 'client', 11]
        ]) {
            const map = createMap(dashboard);
            map.update(results);
            assert.equal(map.hidden(`${shown}-side`), false);
            assert.equal(map.hidden(`${hidden}-side`), true);
            assert.match(map.text(`${shown}-lat-badge`), new RegExp(`${ms}ms`));
        }
    });

    test(`${name}: same-region relays still show two distinct probe origins`, () => {
        const map = createMap(dashboard);
        map.update({ ...client(), ...cpc(), 'C-UDP-04': location('UK South', 'uksouth') });
        assert.match(map.text('client-loc-badge'), /UK South/);
        assert.match(map.text('cpc-loc-badge'), /UK South/);
        assert.match(map.text('client-lat-badge'), /40ms/);
        assert.match(map.text('cpc-lat-badge'), /11ms/);
        assert.match(map.text('prox-badge'), /Cloud PC relay: neighbouring region/);
    });

    test(`${name}: cross-continent warning applies only to the Cloud PC DNS relay`, () => {
        const map = createMap(dashboard);
        map.update({ ...client(), ...cpc(), 'C-UDP-04': location('East US', 'eastus') });
        assert.match(map.text('client-loc-badge'), /UK South/);
        assert.match(map.text('cpc-loc-badge'), /East US/);
        assert.match(map.text('prox-badge'), /Cloud PC DNS relay differs from Poland Central/);
        assert.match(map.classes('accent'), /status-warning/);
    });

    test(`${name}: missing location or latency is not borrowed from the other side`, () => {
        const map = createMap(dashboard);
        const results = { ...client(), ...cpc() };
        delete results['L-UDP-04'];
        delete results['C-UDP-03'];
        map.update(results);
        assert.equal(map.text('client-loc-badge'), 'DNS location unavailable');
        assert.match(map.text('client-lat-badge'), /40ms/);
        assert.match(map.text('cpc-loc-badge'), /Poland Central/);
        assert.equal(map.hidden('cpc-lat-badge'), true);
    });

    test(`${name}: CPC failure is visible even when the client succeeds`, () => {
        const map = createMap(dashboard);
        map.update({
            ...client(), ...cpc(),
            'C-UDP-03': { status: 'Failed', resultValue: 'UDP 3478 blocked' }
        });
        assert.match(map.text('client-reach-badge'), /reachable/);
        assert.match(map.text('cpc-reach-badge'), /unreachable/);
        assert.match(map.classes('accent'), /status-failed/);
        assert.equal(map.hidden('cpc-lat-badge'), true);
    });

    test(`${name}: new results clear stale Cloud PC and proximity badges`, () => {
        const map = createMap(dashboard);
        map.update({ ...client(), ...cpc() });
        map.update(client());
        assert.equal(map.hidden('cpc-side'), true);
        assert.equal(map.hidden('prox-badge'), true);
        assert.equal(map.hidden('cpc-loc-badge'), true);
        assert.equal(map.hidden('cpc-lat-badge'), true);
        map.update({});
        assert.equal(map.hidden('client-side'), true);
        assert.equal(map.text('detail'), 'Awaiting results...');
    });

    test(`${name}: browser-only STUN does not invent a relay location or RTT`, () => {
        const map = createMap(dashboard);
        map.update({ 'B-UDP-01': { status: 'Passed', resultValue: 'STUN OK' } });
        assert.equal(map.text('detail'), '✓ STUN OK');
        assert.equal(map.hidden('client-side'), true);
        assert.equal(map.hidden('cpc-side'), true);
    });

    test(`${name}: pending probes and unknown RTTs are not rendered as success`, () => {
        const map = createMap(dashboard);
        map.update({
            'L-UDP-03': { status: 'Pending' },
            'C-UDP-03': { status: 'Passed', duration: 900 }
        });
        assert.equal(map.hidden('client-side'), true);
        assert.equal(map.hidden('cpc-lat-badge'), true);
        assert.equal(map.text('cpc-loc-badge'), 'DNS location unavailable');
        map.update({
            ...client(),
            'L-UDP-03': { status: 'Pending', resultValue: 'Previous reading: 40ms' }
        });
        assert.equal(map.hidden('client-lat-badge'), true);
    });

    test(`${name}: client and CPC DNS timing, CNAME, and integrity stay independent`, () => {
        const map = createMap(dashboard);
        map.updateDns({
            'L-TCP-03': { status: 'Passed', resultValue: 'Avg 16ms DNS (5/5 resolved)' },
            'C-TCP-03': { status: 'Passed', resultValue: 'Avg 4ms DNS (5/5 resolved)' },
            'L-TCP-05': { status: 'Passed', resultValue: 'Client chain verified' },
            'C-TCP-05': { status: 'Passed', resultValue: 'CPC chain verified' },
            'L-TCP-08': { status: 'Passed', resultValue: 'Client DNS legitimate' },
            'C-TCP-08': { status: 'Failed', resultValue: 'CPC DNS hijacked' }
        });
        assert.match(map.element('map-dns-badge').textContent, /16ms DNS$/);
        assert.match(map.element('map-cpc-dns-badge').textContent, /4ms DNS$/);
        assert.equal(map.element('map-dns-detail2').textContent, 'CNAME: Client chain verified');
        assert.equal(map.element('map-cpc-dns-detail2').textContent, 'CNAME: CPC chain verified');
        assert.equal(map.element('map-cpc-dns-detail3').textContent, 'DNS integrity: CPC DNS hijacked');
        assert.match(map.element('map-dns-accent').className, /status-passed/);
        assert.match(map.element('map-cpc-dns-accent').className, /status-failed/);
        assert.equal(map.element('device-cpc-dns-dot').attributes.fill, '#f85149');
    });

    test(`${name}: old CPC scans show DNS checks without inventing latency`, () => {
        const map = createMap(dashboard);
        map.updateDns({
            'L-TCP-03': { status: 'Passed', resultValue: 'Avg 16ms DNS (5/5 resolved)' },
            'C-TCP-05': { status: 'Passed', resultValue: 'Chain verified (120ms overall)' }
        });
        assert.match(map.element('map-cpc-dns-detail').textContent, /Run current scanner/);
        assert.equal(map.element('map-cpc-dns-badge').classList.contains('hidden'), true);
        assert.match(map.element('map-dns-badge').textContent, /16ms DNS$/);
        assert.match(map.element('map-cpc-dns-detail2').textContent, /Chain verified/);
    });

    test(`${name}: browser DNS fallback is labelled DNS+TCP+TLS and does not replace pure timing`, () => {
        const map = createMap(dashboard);
        const browserResults = {
            'L-TCP-03': { status: 'NotRun' },
            'B-TCP-03': { status: 'Passed', resultValue: 'Avg 70ms (DNS+TCP+TLS)' },
            'C-B-TCP-03': { status: 'Warning', resultValue: 'Avg 700ms (DNS+TCP+TLS)' }
        };
        map.updateDns(browserResults);
        assert.match(map.element('map-dns-badge').textContent, /70ms DNS\+TCP\+TLS/);
        assert.match(map.element('map-cpc-dns-badge').textContent, /700ms DNS\+TCP\+TLS/);
        assert.match(map.element('map-cpc-dns-accent').className, /status-warning/);
        map.updateDns({
            ...browserResults,
            'C-TCP-03': { status: 'Passed', resultValue: 'Avg 4ms DNS (5/5 resolved)' }
        });
        assert.match(map.element('map-cpc-dns-badge').textContent, /4ms DNS$/);
    });

    test(`${name}: legacy browser exports are not mistaken for a CNAME check`, () => {
        const map = createMap(dashboard);
        map.updateDns({
            'C-TCP-05': {
                status: 'Passed',
                resultValue: 'Avg 80ms (DNS+TCP+TLS)',
                detailedInfo: 'Note: Timing includes DNS + TCP + TLS. For pure DNS timing, use the Local Scanner.'
            }
        });
        assert.match(map.element('map-cpc-dns-badge').textContent, /80ms DNS\+TCP\+TLS/);
        assert.equal(map.element('map-cpc-dns-detail2').textContent, '');
        assert.equal(map.element('map-dns-badge').classList.contains('hidden'), true);
    });

    test(`${name}: failed DNS timing cannot borrow client latency or show a healthy badge`, () => {
        const map = createMap(dashboard);
        map.updateDns({
            'L-TCP-03': { status: 'Passed', resultValue: 'Avg 16ms DNS' },
            'C-TCP-03': { status: 'Failed', resultValue: 'Timed out after 3000ms' }
        });
        assert.equal(map.element('map-cpc-dns-detail').textContent, 'Timed out after 3000ms');
        assert.equal(map.element('map-cpc-dns-badge').classList.contains('hidden'), true);
        assert.match(map.element('map-cpc-dns-accent').className, /status-failed/);
    });

    test(`${name}: clearing DNS results clears old badges and status`, () => {
        const map = createMap(dashboard);
        map.updateDns({ 'C-TCP-03': { status: 'Passed', resultValue: 'Avg 4ms DNS' } });
        map.updateDns({});
        assert.equal(map.element('map-cpc-dns-badge').classList.contains('hidden'), true);
        assert.equal(map.element('map-cpc-dns-detail').textContent, 'Awaiting DNS results...');
        assert.equal(map.element('map-cpc-dns-detail2').textContent, '');
        assert.equal(map.element('device-cpc-dns-dot').attributes.fill, '#484f58');
    });

    test(`${name}: AVD DNS card uses session-host terminology`, () => {
        const map = createMap(dashboard);
        map.setHostType('avd-arc');
        map.updateDns({});
        assert.equal(map.element('map-cpc-dns-title').textContent, 'Session Host DNS');
    });

    test(`${name}: browser DNS mapping cannot collide with scanner timing or CNAME IDs`, () => {
        const root = path.join(__dirname, '..', 'docs', dashboard);
        const app = readFileSync(path.join(root, 'js', 'app.js'), 'utf8');
        const mapping = app.match(/const BROWSER_TO_CPC_ID = (\{[\s\S]*?\n\});/);
        assert.ok(mapping);
        const id = vm.runInNewContext(`(${mapping[1]})`)['B-TCP-03'];
        assert.equal(id, 'C-B-TCP-03');
        const definitions = readFileSync(path.join(root, 'js', 'browser-tests.js'), 'utf8');
        for (const testId of [id, 'C-TCP-03', 'C-TCP-05']) {
            assert.equal([...definitions.matchAll(new RegExp(`id: '${testId}'`, 'g'))].length, 1);
        }
    });

    test(`${name}: security summary cannot hide host DNS failure behind a client pass`, () => {
        const map = createMap(dashboard);
        const results = {
            'L-TCP-08': { status: 'Passed', resultValue: 'Client DNS legitimate' },
            'C-TCP-08': { status: 'Failed', resultValue: 'Host DNS hijacked' }
        };
        map.updateSecurity(results);
        assert.match(map.element('sec-dns-badge-text').textContent, /DNS Hijacking Detected \(Cloud PC \/ Host\)/);
        assert.match(map.element('sec-dns-badge').className, /fail/);
        map.setCpcMode(true);
        map.updateSecurity({ ...results, 'C-TCP-08': { status: 'Passed' }, 'L-TCP-08': { status: 'Failed' } });
        assert.equal(map.element('sec-dns-badge-text').textContent, 'No DNS Hijacking (Cloud PC / Host)');
    });
}
