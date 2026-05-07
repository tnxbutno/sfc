// Node.js test for the sfc_wasm module.
// Run after building: node wasm/test_wasm.js
// Requires: web/sfc_wasm.js (built by emcmake cmake -S wasm -B wasm/build)

'use strict';

const { randomFillSync } = require('crypto');
const path = require('path');
const SfcModule = require(path.join(__dirname, '../web/sfc_wasm.js'));

// Helpers

let passed = 0;
let failed = 0;

function assert(cond, msg) {
    if (!cond) { failed++; console.error('  FAIL: ' + msg); return; }
    passed++;
    process.stdout.write('.');
}

function assertThrows(fn, msg) {
    try { fn(); failed++; console.error('  FAIL (no throw): ' + msg); }
    catch { passed++; process.stdout.write('.'); }
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function randUuid() {
    const uuid = new Uint8Array(16);
    randomFillSync(uuid);
    return uuid;
}

function readU32LE(bytes, off) {
    return bytes[off]
        | (bytes[off + 1] << 8)
        | (bytes[off + 2] << 16)
        | (bytes[off + 3] << 24);
}

function writeU16LE(bytes, off, value) {
    bytes[off] = value & 0xff;
    bytes[off + 1] = (value >> 8) & 0xff;
}

function writeU32LE(bytes, off, value) {
    bytes[off] = value & 0xff;
    bytes[off + 1] = (value >> 8) & 0xff;
    bytes[off + 2] = (value >> 16) & 0xff;
    bytes[off + 3] = (value >> 24) & 0xff;
}

function tlv(tag, text) {
    const value = new TextEncoder().encode(text);
    const out = new Uint8Array(6 + value.length);
    writeU16LE(out, 0, tag);
    writeU32LE(out, 2, value.length);
    out.set(value, 6);
    return out;
}

function withMetadata(encoded, fields) {
    const oldH = readU32LE(encoded, 8);
    const headerEnd = 12 + oldH;
    const tlvs = fields;
    const extraLen = tlvs.reduce((n, f) => n + f.length, 0);
    const out = new Uint8Array(encoded.length + extraLen);
    out.set(encoded.slice(0, headerEnd), 0);
    let pos = headerEnd;
    for (const f of tlvs) {
        out.set(f, pos);
        pos += f.length;
    }
    out.set(encoded.slice(headerEnd), pos);
    writeU32LE(out, 8, oldH + extraLen);
    return out;
}

function firstChunkOnly(encoded) {
    const h = readU32LE(encoded, 8);
    const chunkStart = 8 + h + 4;
    const payloadLen = readU32LE(encoded, chunkStart + 28);
    const chunkEnd = chunkStart + 48 + payloadLen + 36;
    return encoded.slice(0, chunkEnd);
}

// Test cases

async function run() {
    const sfc = await SfcModule();
    console.log('SFC WASM module loaded\n');

    const content = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

    // encode + decode round-trip (each algo)
    for (const algo of ['zstd', 'brotli', 'lz4', 'none']) {
        const uuid    = randUuid();
        const encoded = sfc.encode(content, 0, 'hello.bin', algo, uuid);
        assert(encoded instanceof Uint8Array,       algo + ': encode returns Uint8Array');
        assert(encoded.length > 0,                  algo + ': encoded non-empty');
        const decoded = sfc.decode(encoded);
        assert(arraysEqual(decoded.data, content),  algo + ': decode round-trip');
        assert(decoded.filename === 'hello.bin',    algo + ': filename preserved');
        assert(decoded.status   === 'verified',     algo + ': status=verified');
        assert(decoded.n === 1,                     algo + ': n=1');
        assert(decoded.m === 0,                     algo + ': m=0');
    }

    // info
    {
        const uuid    = randUuid();
        const encoded = sfc.encode(content, 0, 'info-test.txt', 'zstd', uuid);
        const info    = sfc.info(encoded);
        assert(info.filename    === 'info-test.txt', 'info: filename');
        assert(info.n           === 1,               'info: n=1');
        assert(info.m           === 0,               'info: m=0');
        assert(info.compression === 'zstd',          'info: compression');
        assert(info.innerSize   === content.length,  'info: innerSize');
        assert(info.profile     === 'regular',       'info: profile');
        assert(info.formatName  === 'PlainText',     'info: format name from extension');
        assert(info.timestamp   > 0,                 'info: timestamp set');
    }

    // extended info, metadata + verify
    {
        const uuid    = randUuid();
        const encoded = sfc.encode(content, 0, 'info-extended.bin', 'brotli', uuid);
        const info    = sfc.info(encoded);
        assert(info.filename    === 'info-extended.bin', 'info extended: filename');
        assert(info.n           === 1,                  'info extended: n=1');
        assert(info.m           === 0,                  'info extended: m=0');
        assert(info.s           === 65536,              'info extended: s=65536');
        assert(info.compression === 'brotli',           'info extended: compression');
        assert(info.erasure     === 'none',             'info extended: erasure');
        assert(info.trailer     === true,               'info extended: trailer present');

        const tagged = withMetadata(encoded, [
            tlv(0x0100, 'Ada'),
            tlv(0x0101, 'Browser inspect fixture'),
            tlv(0x0103, 'wasm-test'),
        ]);
        const meta = sfc.info(tagged);
        assert(meta.author      === 'Ada',                     'info metadata: author');
        assert(meta.description === 'Browser inspect fixture', 'info metadata: description');
        assert(meta.software    === 'wasm-test',               'info metadata: software');

        const verify = sfc.verify(encoded);
        assert(verify.ok === true,                         'verify: ok');
        assert(verify.status === 'verified',               'verify: status=verified');
        assert(verify.recoveredSize === content.length,    'verify: recoveredSize');
        assert(verify.missingChunks.length === 0,          'verify: no missing chunks');
    }

    // recovery chunks (M > 0)
    {
        const uuid    = randUuid();
        const encoded = sfc.encode(content, 2, 'resilient.bin', 'zstd', uuid);
        const decoded = sfc.decode(encoded);
        assert(arraysEqual(decoded.data, content), 'M=2: round-trip');
        assert(decoded.m === 2,                    'M=2: m field');
    }

    // empty content
    {
        const empty   = new Uint8Array(0);
        const uuid    = randUuid();
        const encoded = sfc.encode(empty, 0, 'empty.bin', 'zstd', uuid);
        const decoded = sfc.decode(encoded);
        assert(arraysEqual(decoded.data, empty), 'empty content round-trip');
    }

    // large content (200 KB)
    {
        const large = new Uint8Array(200 * 1024);
        randomFillSync(large);
        const uuid    = randUuid();
        const encoded = sfc.encode(large, 0, 'large.bin', 'zstd', uuid);
        const decoded = sfc.decode(encoded);
        assert(arraysEqual(decoded.data, large), 'large file round-trip');
    }

    // multi-chunk (content > 64 KB forces N > 1)
    {
        const big  = new Uint8Array(130 * 1024); // two chunks
        randomFillSync(big);
        const uuid    = randUuid();
        const encoded = sfc.encode(big, 0, 'big.bin', 'zstd', uuid);
        const info    = sfc.info(encoded);
        assert(info.n > 1,                      'multi-chunk: n>1');
        const decoded = sfc.decode(encoded);
        assert(arraysEqual(decoded.data, big),  'multi-chunk: round-trip');
    }

    // verify accepts partial, unpack rejects it
    {
        const big = new Uint8Array(130 * 1024); // N > 1
        randomFillSync(big);
        const uuid    = randUuid();
        const encoded = sfc.encode(big, 0, 'partial.bin', 'none', uuid);
        const partial = firstChunkOnly(encoded);

        const verify = sfc.verify(partial);
        assert(verify.ok === false,                 'partial verify: not ok');
        assert(verify.status === 'partial',         'partial verify: status=partial');
        assert(verify.recoveredSize === 65536,      'partial verify: recovered first chunk');
        assert(verify.missingChunks.length > 0,     'partial verify: missing chunks');
        assertThrows(() => sfc.decode(partial),     'partial unpack: decode throws');
    }

    // error: invalid bytes
    assertThrows(() => sfc.decode(new Uint8Array([0, 1, 2, 3])), 'decode: invalid bytes throws');
    assertThrows(() => sfc.info(new Uint8Array([0, 1, 2, 3])),   'info: invalid bytes throws');
    assertThrows(() => sfc.verify(new Uint8Array([0, 1, 2, 3])),  'verify: invalid bytes throws');
    assertThrows(() => sfc.encode(content, 0, 'bad.bin', 'bad-algo', randUuid()), 'encode: bad algo throws');

    // error: wrong magic
    {
        const uuid    = randUuid();
        const encoded = sfc.encode(content, 0, 'x.bin', 'zstd', uuid);
        const corrupt = new Uint8Array(encoded);
        corrupt[0] = 0xff; // corrupt the magic
        assertThrows(() => sfc.decode(corrupt), 'decode: corrupt magic throws');
    }

    // report
    console.log('\n');
    if (failed === 0) {
        console.log(`All ${passed} assertions passed.`);
    } else {
        console.error(`${failed} failed, ${passed} passed.`);
        process.exit(1);
    }
}

run().catch(err => {
    console.error('\nUnhandled error:', err.message || err);
    process.exit(1);
});
