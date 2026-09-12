const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
]);

const SHA256_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

const SHA256_W = new Int32Array(64);
const SHA256_STATE = new Int32Array(8);

/** Hashes `bytes[0..length]` in place, padding the buffer it was given. */
function sha256Words(bytes, length) {
    const bitLength = length * 8;
    const padded = (length + 9 + 63) & ~63;
    for (let i = length; i < padded; i++) bytes[i] = 0;
    bytes[length] = 0x80;
    bytes[padded - 4] = (bitLength >>> 24) & 0xff;
    bytes[padded - 3] = (bitLength >>> 16) & 0xff;
    bytes[padded - 2] = (bitLength >>> 8) & 0xff;
    bytes[padded - 1] = bitLength & 0xff;
    for (let i = 0; i < 8; i++) SHA256_STATE[i] = SHA256_IV[i];

    for (let offset = 0; offset < padded; offset += 64) {
        for (let i = 0; i < 16; i++) {
            SHA256_W[i] =
                (bytes[offset + i * 4] << 24) |
                (bytes[offset + i * 4 + 1] << 16) |
                (bytes[offset + i * 4 + 2] << 8) |
                bytes[offset + i * 4 + 3];
        }
        for (let i = 16; i < 64; i++) {
            const a = SHA256_W[i - 15];
            const b = SHA256_W[i - 2];
            const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
            const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
            SHA256_W[i] = (SHA256_W[i - 16] + s0 + SHA256_W[i - 7] + s1) | 0;
        }
        let [a, b, c, d, e, f, g, h] = SHA256_STATE;
        for (let i = 0; i < 64; i++) {
            const s1 =
                ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const t1 = (h + s1 + ((e & f) ^ (~e & g)) + SHA256_K[i] + SHA256_W[i]) | 0;
            const s0 =
                ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            const t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0;
            d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        SHA256_STATE[0] = (SHA256_STATE[0] + a) | 0;
        SHA256_STATE[1] = (SHA256_STATE[1] + b) | 0;
        SHA256_STATE[2] = (SHA256_STATE[2] + c) | 0;
        SHA256_STATE[3] = (SHA256_STATE[3] + d) | 0;
        SHA256_STATE[4] = (SHA256_STATE[4] + e) | 0;
        SHA256_STATE[5] = (SHA256_STATE[5] + f) | 0;
        SHA256_STATE[6] = (SHA256_STATE[6] + g) | 0;
        SHA256_STATE[7] = (SHA256_STATE[7] + h) | 0;
    }
    return SHA256_STATE;
}

function leadingZeroBits(words) {
    for (let i = 0; i < 8; i++) {
        if (words[i] !== 0) return i * 32 + Math.clz32(words[i] >>> 0);
    }
    return 256;
}

const MINE_CHUNK = 2048;

/** Mines on the page itself, in chunks, so the UI keeps responding. */
function mineInline(prefix, difficulty, onProgress, onSolved) {
    const encoded = new TextEncoder().encode(prefix);
    const buffer = new Uint8Array(encoded.length + 160);
    buffer.set(encoded);

    function hash(nonce) {
        const text = String(nonce);
        for (let i = 0; i < text.length; i++) {
            buffer[encoded.length + i] = text.charCodeAt(i);
        }
        return sha256Words(buffer, encoded.length + text.length);
    }

    function round(nonce) {
        const limit = nonce + MINE_CHUNK;
        for (; nonce < limit; nonce++) {
            if (leadingZeroBits(hash(nonce)) >= difficulty) return onSolved(nonce);
        }
        if (onProgress) onProgress(nonce);
        setTimeout(function () {
            round(nonce);
        }, 0);
    }

    round(0);
}

/** Body of each worker: same hash, its own stride of the nonce space. */
function mineStride(event) {
    const data = event.data;
    const encoded = new TextEncoder().encode(data.prefix);
    const buffer = new Uint8Array(encoded.length + 160);
    buffer.set(encoded);
    let nonce = data.workerId;
    let tried = 0;

    for (;;) {
        const text = String(nonce);
        for (let i = 0; i < text.length; i++) {
            buffer[encoded.length + i] = text.charCodeAt(i);
        }
        const words = sha256Words(buffer, encoded.length + text.length);
        if (leadingZeroBits(words) >= data.difficulty) {
            self.postMessage({ done: true, nonce: nonce, hashes: tried + 1 });
            return;
        }
        nonce += data.workerCount;
        tried++;
        if (tried % 2048 === 0) self.postMessage({ done: false, hashes: 2048 });
    }
}

function minerSource() {
    return (
        'const SHA256_K = new Uint32Array([' + Array.from(SHA256_K).join(',') + ']);\n' +
        'const SHA256_IV = [' + SHA256_IV.join(',') + '];\n' +
        'const SHA256_W = new Int32Array(64);\n' +
        'const SHA256_STATE = new Int32Array(8);\n' +
        sha256Words.toString() + '\n' +
        leadingZeroBits.toString() + '\n' +
        'self.onmessage = ' + mineStride.toString() + ';'
    );
}

/**
 * Mines `sha256(prefix + nonce)` for `difficulty` leading zero bits. Uses one
 * worker per core where it can, and the page itself where it cannot.
 */
function mineProof(prefix, difficulty, onProgress, onSolved) {
    let workers = [];
    let total = 0;
    let solved = false;

    function stop() {
        workers.forEach(function (worker) {
            worker.terminate();
        });
        workers = [];
    }

    function onMessage(event) {
        total += event.data.hashes;
        if (!event.data.done) return onProgress && onProgress(total);
        if (solved) return;
        solved = true;
        stop();
        onSolved(event.data.nonce);
    }

    try {
        const blob = new Blob([minerSource()], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const count = Math.min(navigator.hardwareConcurrency || 4, 8);
        for (let id = 0; id < count; id++) {
            const worker = new Worker(url);
            worker.onmessage = onMessage;
            worker.onerror = function () {
                if (solved) return;
                solved = true;
                stop();
                mineInline(prefix, difficulty, onProgress, onSolved);
            };
            worker.postMessage({
                prefix: prefix,
                difficulty: difficulty,
                workerId: id,
                workerCount: count,
            });
            workers.push(worker);
        }
    } catch {
        stop();
        mineInline(prefix, difficulty, onProgress, onSolved);
    }
}
