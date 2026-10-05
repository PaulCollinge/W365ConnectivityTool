import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const appUrls = [
    new URL('../docs/js/app.js', import.meta.url),
    new URL('../docs/hybrid/js/app.js', import.meta.url)
];

const sample = {
    timestamp: '2025-01-02T03:04:05.000Z',
    machineName: 'جهاز-中文-😀-e\u0301',
    results: [
        {
            id: 'globalization',
            status: 'Passed',
            resultValue: 'أنا اختبار إدخال النص في لغات مختلفة 01 لأحد منتجات Microsoft',
            detailedInfo: '中文 日本語 한국어 हिन्दी עברית\nEmoji 😀 𠀋 👩🏽‍💻\nCombining e\u0301'
        }
    ]
};

function section(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    assert.notEqual(start, -1, `Missing start marker: ${startMarker}`);
    assert.notEqual(end, -1, `Missing end marker: ${endMarker}`);
    return source.slice(start, end);
}

async function loadProductionHelpers(url) {
    const source = await readFile(url, 'utf8');
    const decoderCode = section(
        source,
        '// ── Decode compressed hash',
        '// ── Shared import logic'
    );
    const truncationCode = section(
        source,
        'function truncateUnicode',
        'async function parseLocalJsonFile'
    );
    const filenameCode = section(
        source,
        'function safeFilenameComponent',
        'async function sendResultsToIT'
    );
    const context = vm.createContext({
        atob,
        btoa,
        DecompressionStream,
        Intl,
        TextDecoder,
        TextEncoder,
        Uint8Array,
        clearTimeout,
        console: { log() {} },
        ilog() {},
        setTimeout
    });

    vm.runInContext(
        `${decoderCode}\n${truncationCode}\n${filenameCode}\n`
        + 'this.helpers = { decodeCompressedHash, decodeUncompressedHash, '
        + 'truncateUnicode, safeFilenameComponent, utf8ToBase64, encodeRfc5987Value };',
        context
    );

    return {
        source,
        decoderCode,
        truncationCode,
        filenameCode,
        ...context.helpers
    };
}

async function deflateRawBase64Url(value) {
    const stream = new CompressionStream('deflate-raw');
    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode(value));
    await writer.close();

    const reader = stream.readable.getReader();
    const chunks = [];
    let length = 0;
    while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        chunks.push(chunk);
        length += chunk.length;
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    return Buffer.from(bytes).toString('base64url');
}

test('standard and hybrid globalization helpers stay synchronized', async () => {
    const [standard, hybrid] = await Promise.all(appUrls.map(loadProductionHelpers));
    assert.equal(standard.decoderCode, hybrid.decoderCode);
    assert.equal(standard.truncationCode, hybrid.truncationCode);
    assert.equal(standard.filenameCode, hybrid.filenameCode);
});

for (const url of appUrls) {
    test(`${url.pathname} preserves Unicode in legacy and compressed links`, async () => {
        const helpers = await loadProductionHelpers(url);
        const json = JSON.stringify(sample);
        const legacy = Buffer.from(json, 'utf8').toString('base64url');
        const compressed = await deflateRawBase64Url(json);

        assert.equal(
            JSON.stringify(helpers.decodeUncompressedHash(legacy)),
            json
        );
        assert.equal(
            JSON.stringify(await helpers.decodeCompressedHash(compressed)),
            json
        );

        const compact = {
            _f: 2,
            ts: sample.timestamp,
            mn: sample.machineName,
            sm: 3,
            ar: 'شرق آسيا',
            r: sample.results.map(result => ({
                i: result.id,
                s: 'P',
                v: result.resultValue,
                d: result.detailedInfo,
                t: 17
            }))
        };
        const decodedCompact = await helpers.decodeCompressedHash(
            await deflateRawBase64Url(JSON.stringify(compact))
        );
        assert.equal(decodedCompact.machineName, sample.machineName);
        assert.equal(decodedCompact.azureRegion, compact.ar);
        assert.equal(decodedCompact.results[0].resultValue, sample.results[0].resultValue);
        assert.equal(decodedCompact.results[0].detailedInfo, sample.results[0].detailedInfo);
    });

    test(`${url.pathname} truncates only at grapheme boundaries`, async () => {
        const helpers = await loadProductionHelpers(url);
        assert.equal(helpers.truncateUnicode('abc😀def', 4), 'abc');
        assert.equal(helpers.truncateUnicode('Ae\u0301B', 2), 'A');
        assert.equal(helpers.truncateUnicode('X👩🏽‍💻Y', 7), 'X');
        assert.equal(helpers.truncateUnicode('X👩🏽‍💻Y', 8), 'X👩🏽‍💻');
    });

    test(`${url.pathname} preserves Unicode filenames and MIME encodings`, async () => {
        const helpers = await loadProductionHelpers(url);
        const name = 'جهاز-中文-😀-e\u0301';
        assert.equal(helpers.safeFilenameComponent(`${name}:bad/name`, 'Unknown'), `${name}_bad_name`);
        assert.equal(Buffer.from(helpers.utf8ToBase64(name), 'base64').toString('utf8'), name);
        assert.equal(decodeURIComponent(helpers.encodeRfc5987Value(name)), name);
        assert.equal(decodeURIComponent(helpers.encodeRfc5987Value('\uD800')), '\uFFFD');
    });
}
