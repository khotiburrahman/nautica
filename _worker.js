import { connect } from "cloudflare:sockets";

const SYSTEM_UUID = "8fc11e59-39ce-4992-b698-5d96f47106bf";
const DOH_ENDPOINT = "https://1.1.1.1/dns-query";
const GITHUB_RAW_URL = "https://raw.githubusercontent.com/khotiburrahman/auto_proxy/refs/heads/main/active_proxies.txt";

// --- [ UTILITY & ABSTRACTION ] ---

class ByteUtils {
    static encode(text) { return new TextEncoder().encode(text); }
    static decode(buffer) { return new TextDecoder().decode(buffer); }
    static merge(...buffers) {
        const total = buffers.reduce((acc, b) => acc + b.length, 0);
        const out = new Uint8Array(total);
        let ptr = 0;
        for (const b of buffers) {
            out.set(b, ptr);
            ptr += b.length;
        }
        return out;
    }
    static hex(buf) {
        return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
    }
    static parseUUID(uuid) {
        const h = uuid.replace(/-/g, '');
        const out = new Uint8Array(16);
        for (let i = 0; i < 16; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    static b64Decode(str) {
        if (!str) return null;
        try {
            const clean = str.replace(/-/g, "+").replace(/_/g, "/");
            return Uint8Array.from(atob(clean), c => c.charCodeAt(0)).buffer;
        } catch { return null; }
    }
}

class ByteReader {
    constructor(buffer) {
        this.buf = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        this.cursor = 0;
        this.view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
    }
    has(n) { return this.cursor + n <= this.buf.length; }
    take(n) {
        const chunk = this.buf.subarray(this.cursor, this.cursor + n);
        this.cursor += n;
        return chunk;
    }
    takeRest() { return this.take(this.buf.length - this.cursor); }
    u8() { return this.buf[this.cursor++]; }
    u16() {
        const val = this.view.getUint16(this.cursor);
        this.cursor += 2;
        return val;
    }
    readEndpoint() {
        const type = this.u8();
        let target = "";
        switch (type) {
            case 1:
                target = this.take(4).join(".");
                break;
            case 2:
                target = ByteUtils.decode(this.take(this.u8()));
                break;
            case 3:
            case 4:
                if (type === 3 && this.has(this.buf[this.cursor])) {
                    target = ByteUtils.decode(this.take(this.u8()));
                } else {
                    const parts = [];
                    for (let i = 0; i < 8; i++) parts.push(this.u16().toString(16));
                    target = parts.join(":");
                }
                break;
            default:
                throw new Error(`Unknown address format: ${type}`);
        }
        const port = this.u16();
        return { target, port, type };
    }
}

// --- [ CRYPTO ENGINE ] ---

class CryptoEngine {
    static md5(data, salt) {
        let msg = typeof data === 'string' ? ByteUtils.encode(data) : data;
        if (salt) msg = ByteUtils.merge(msg, typeof salt === 'string' ? ByteUtils.encode(salt) : salt);

        const K = new Uint32Array([
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
            0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
        ]);
        const S = [
            7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
            5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
            4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
            6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
        ];
        let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        const L = msg.length, padL = ((56 - (L + 1) % 64) + 64) % 64;
        const padded = new Uint8Array(L + 1 + padL + 8);
        padded.set(msg); padded[L] = 0x80;
        const v = new DataView(padded.buffer);
        v.setUint32(padded.length - 8, (L * 8) >>> 0, true);
        v.setUint32(padded.length - 4, (L * 8 / 0x100000000) >>> 0, true);

        for (let i = 0; i < padded.length; i += 64) {
            const M = new Uint32Array(16);
            for (let j = 0; j < 16; j++) M[j] = v.getUint32(i + j * 4, true);
            let A = a, B = b, C = c, D = d;
            for (let j = 0; j < 64; j++) {
                let F, g;
                if (j < 16) { F = (B & C) | (~B & D); g = j; }
                else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
                else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
                else { F = C ^ (B | ~D); g = (7 * j) % 16; }
                F = (F + A + K[j] + M[g]) >>> 0;
                A = D; D = C; C = B; B = (B + ((F << S[j]) | (F >>> (32 - S[j])))) >>> 0;
            }
            a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
        }
        const out = new Uint8Array(16);
        const ov = new DataView(out.buffer);
        ov.setUint32(0, a, true); ov.setUint32(4, b, true); ov.setUint32(8, c, true); ov.setUint32(12, d, true);
        return out;
    }

    static sha256(data) {
        const msg = typeof data === 'string' ? ByteUtils.encode(data) : data;
        const K = new Uint32Array([
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        ]);
        let H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
        const rotr = (x, n) => (x >>> n) | (x << (32 - n));
        const L = msg.length, padL = ((56 - (L + 1) % 64) + 64) % 64;
        const padded = new Uint8Array(L + 1 + padL + 8);
        padded.set(msg); padded[L] = 0x80;
        new DataView(padded.buffer).setUint32(padded.length - 4, L * 8, false);
        const W = new Uint32Array(64);

        for (let i = 0; i < padded.length; i += 64) {
            const block = new DataView(padded.buffer, i, 64);
            for (let t = 0; t < 16; t++) W[t] = block.getUint32(t * 4, false);
            for (let t = 16; t < 64; t++) {
                const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
                const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
                W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
            }
            let [a,b,c,d,e,f,g,h] = H;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const T1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const T2 = (S0 + maj) >>> 0;
                h = g; g = f; f = e; e = (d + T1) >>> 0;
                d = c; c = b; b = a; a = (T1 + T2) >>> 0;
            }
            H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
        }
        const res = new Uint8Array(32);
        const rv = new DataView(res.buffer);
        for (let i = 0; i < 8; i++) rv.setUint32(i * 4, H[i], false);
        return res;
    }

    static hmac(key, fn) {
        const ik = new Uint8Array(64).fill(0x36), ok = new Uint8Array(64).fill(0x5c);
        const kBuf = typeof key === 'string' ? ByteUtils.encode(key) : key;
        for (let i = 0; i < kBuf.length; i++) { ik[i] ^= kBuf[i]; ok[i] ^= kBuf[i]; }
        return (data) => fn(ByteUtils.merge(ok, fn(ByteUtils.merge(ik, data))));
    }

    static vmessKDF(key, paths) {
        let runner = CryptoEngine.hmac(ByteUtils.encode("VMess AEAD KDF"), CryptoEngine.sha256);
        for (const p of paths) runner = CryptoEngine.hmac(p, runner);
        return runner(key);
    }

    static async gcmProcess(mode, key, iv, data, aad = new Uint8Array(0)) {
        const cKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [mode]);
        const params = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 };
        return new Uint8Array(await crypto.subtle[mode](params, cKey, data));
    }
}

// --- [ PROTOCOL ADAPTERS ] ---

const Constants = {
    CMD_TCP: 1, CMD_UDP: 2, CMD_P1_UDP: 3,
    VMESS_SALT: {
        LEN_KEY: ByteUtils.encode("VMess Header AEAD Key_Length"),
        LEN_IV: ByteUtils.encode("VMess Header AEAD Nonce_Length"),
        PAY_KEY: ByteUtils.encode("VMess Header AEAD Key"),
        PAY_IV: ByteUtils.encode("VMess Header AEAD Nonce"),
        RES_LEN_K: ByteUtils.encode("AEAD Resp Header Len Key"),
        RES_LEN_I: ByteUtils.encode("AEAD Resp Header Len IV"),
        RES_PAY_K: ByteUtils.encode("AEAD Resp Header Key"),
        RES_PAY_I: ByteUtils.encode("AEAD Resp Header IV")
    }
};

class BaseCodec {
    constructor(prefix) { this.header = prefix; }
    async extract(buffer) { throw new Error("Not implemented"); }
}

class ShadowsocksCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const { target, port } = reader.readEndpoint();
        return { host: target, port, isUdp: port === 53, payload: reader.takeRest(), replyHead: null };
    }
}

class VlessCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const ver = reader.u8();
        reader.take(16);
        const optLen = reader.u8();
        reader.take(optLen);
        const cmd = reader.u8();

        const isUdp = (cmd === Constants.CMD_UDP);
        if (cmd !== Constants.CMD_TCP && !isUdp) throw new Error("VLESS Cmd Invalid");

        const port = reader.u16();
        const type = reader.u8();

        let target = "";
        switch (type) {
            case 1: target = reader.take(4).join("."); break;
            case 2: target = ByteUtils.decode(reader.take(reader.u8())); break;
            case 3:
                const parts = [];
                for (let i = 0; i < 8; i++) parts.push(reader.u16().toString(16));
                target = parts.join(":");
                break;
            default: throw new Error(`VLESS Unknown address format: ${type}`);
        }

        return { host: target, port, isUdp, payload: reader.takeRest(), replyHead: new Uint8Array([ver, 0]) };
    }
}

class TrojanCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        reader.take(56);
        reader.take(2);

        const cmd = reader.u8();
        const isUdp = (cmd === Constants.CMD_P1_UDP);

        reader.cursor--;
        reader.take(1);

        const type = reader.u8();
        reader.cursor--; 
        const { target, port } = reader.readEndpoint();
        reader.take(2);

        return { host: target, port, isUdp, payload: reader.takeRest(), replyHead: null };
    }
}

class VmessCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const auth = reader.take(16);
        const lenEnc = reader.take(18);
        const nonce = reader.take(8);

        const basis = CryptoEngine.md5(ByteUtils.parseUUID(SYSTEM_UUID), "c48619fe-8f02-49e0-b9e9-edf763e17e21");

        const kLen = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_KEY, auth, nonce]).subarray(0, 16);
        const iLen = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_IV, auth, nonce]).subarray(0, 12);
        const rawLen = await CryptoEngine.gcmProcess('decrypt', kLen, iLen, lenEnc, auth);
        const headLen = (rawLen[0] << 8) | rawLen[1];

        const cmdEnc = reader.take(headLen + 16);
        const payload = reader.takeRest();

        const kPay = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.PAY_KEY, auth, nonce]).subarray(0, 16);
        const iPay = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.PAY_IV, auth, nonce]).subarray(0, 12);
        const cmdData = await CryptoEngine.gcmProcess('decrypt', kPay, iPay, cmdEnc, auth);

        const iv = cmdData.subarray(1, 17);
        const kRes = cmdData.subarray(17, 33);
        const vAuth = cmdData[33];
        const port = (cmdData[38] << 8) | cmdData[39];

        const cmdReader = new ByteReader(cmdData.subarray(40));
        const { target } = cmdReader.readEndpoint();

        const rKeyB = CryptoEngine.sha256(kRes).subarray(0, 16);
        const rIvB = CryptoEngine.sha256(iv).subarray(0, 16);

        const rlK = CryptoEngine.vmessKDF(rKeyB, [Constants.VMESS_SALT.RES_LEN_K]).subarray(0, 16);
        const rlI = CryptoEngine.vmessKDF(rIvB, [Constants.VMESS_SALT.RES_LEN_I]).subarray(0, 12);
        const h1 = await CryptoEngine.gcmProcess('encrypt', rlK, rlI, new Uint8Array([0, 4]));

        const rpK = CryptoEngine.vmessKDF(rKeyB, [Constants.VMESS_SALT.RES_PAY_K]).subarray(0, 16);
        const rpI = CryptoEngine.vmessKDF(rIvB, [Constants.VMESS_SALT.RES_PAY_I]).subarray(0, 12);
        const h2 = await CryptoEngine.gcmProcess('encrypt', rpK, rpI, new Uint8Array([vAuth, 0, 0, 0]));

        return { host: target, port, isUdp: port === 53, payload, replyHead: ByteUtils.merge(h1, h2) };
    }
}

// --- [ ROUTING & TRANSPORT ] ---

class ConnectionBroker {
    static async identify(buffer) {
        if (buffer.length >= 42) {
            try {
                const basis = CryptoEngine.md5(ByteUtils.parseUUID(SYSTEM_UUID), "c48619fe-8f02-49e0-b9e9-edf763e17e21");
                const auth = buffer.subarray(0, 16), enc = buffer.subarray(16, 34), non = buffer.subarray(34, 42);
                const lk = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_KEY, auth, non]).subarray(0, 16);
                const li = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_IV, auth, non]).subarray(0, 12);
                const dl = await CryptoEngine.gcmProcess('decrypt', lk, li, enc, auth);
                const len = (dl[0] << 8) | dl[1];
                if (len > 0 && len < 4096) return new VmessCodec();
            } catch {}
        }

        if (buffer.length >= 62) {
            const delim = buffer.slice(56, 60);
            if (delim[0] === 0x0d && delim[1] === 0x0a && [1,3,127].includes(delim[2])) {
                return new TrojanCodec();
            }
        }

        const hex = ByteUtils.hex(buffer.slice(1, 17));
        if (/^\w{8}\w{4}4\w{3}[89ab]\w{3}\w{12}$/.test(hex)) return new VlessCodec();

        return new ShadowsocksCodec();
    }
}

class SubstreamHandler {
    static attachDNS(clientWs, responsePrefix) {
        let prefixSent = false;
        const tx = new TransformStream({
            transform(chunk, ctrl) {
                let p = 0;
                while (p < chunk.byteLength) {
                    const l = (chunk[p] << 8) | chunk[p+1];
                    ctrl.enqueue(chunk.slice(p + 2, p + 2 + l));
                    p += 2 + l;
                }
            }
        });

        tx.readable.pipeTo(new WritableStream({
            async write(payload) {
                const resp = await fetch(DOH_ENDPOINT, {
                    method: "POST", headers: { "content-type": "application/dns-message" }, body: payload
                });
                const ans = new Uint8Array(await resp.arrayBuffer());
                const outLen = new Uint8Array([ans.byteLength >> 8, ans.byteLength & 0xff]);

                if (clientWs.readyState === 1) {
                    if (prefixSent || !responsePrefix) {
                        clientWs.send(ByteUtils.merge(outLen, ans));
                    } else {
                        clientWs.send(ByteUtils.merge(responsePrefix, outLen, ans));
                        prefixSent = true;
                    }
                }
            }
        })).catch(() => {});

        return tx.writable.getWriter();
    }

    static async pipeTCP(remoteNode, ws, head, retryFn) {
        let pHead = head, flowActive = false;
        await remoteNode.readable.pipeTo(new WritableStream({
            write(c) {
                flowActive = true;
                if (ws.readyState !== 1) throw new Error("WS Terminated");
                if (pHead) {
                    ws.send(ByteUtils.merge(pHead, c));
                    pHead = null;
                } else ws.send(c);
            }
        })).catch(() => ws.close());

        if (!flowActive && retryFn) retryFn();
    }
}

// --- [ HELPER: SINKRONISASI KV & RESOLVER PATH ] ---

async function syncGitHubToKV(env) {
  const kv = env.PROXY_DB || env.MY_KV;
  if (!kv) return { error: "KV Binding (PROXY_DB/MY_KV) tidak ditemukan" };

  const req = await fetch(GITHUB_RAW_URL);
  if (req.status === 200) {
    const text = await req.text();
    const lines = text.split('\n').filter(Boolean);
    const proxies = lines.map(line => {
      const [prxIP, prxPort, country, org] = line.split(',');
      return { prxIP, prxPort, country: country ? country.trim() : "UN", org: org ? org.trim() : "Unknown" };
    });

    await kv.put("PROXIES_JSON", JSON.stringify(proxies));
    return { status: "success", total: proxies.length };
  }
  return { error: "Gagal mengambil data dari GitHub" };
}

function resolveProxyFromPath(reqPath, cachedPrxList) {
    if (!cachedPrxList || cachedPrxList.length === 0) return "";

    const match = reqPath.match(/^([A-Z]{2})(\d+)?$/);
    if (match) {
        const countryCode = match[1];
        const indexNum = match[2] ? parseInt(match[2], 10) : null;

        const filtered = cachedPrxList.filter(p => p.country && p.country.toUpperCase() === countryCode);
        if (filtered.length > 0) {
            if (indexNum !== null && indexNum > 0) {
                const targetProxy = filtered[(indexNum - 1) % filtered.length];
                return `${targetProxy.prxIP}:${targetProxy.prxPort}`;
            } else {
                const randomPrx = filtered[Math.floor(Math.random() * filtered.length)];
                return `${randomPrx.prxIP}:${randomPrx.prxPort}`;
            }
        }
    }

    const randomPrx = cachedPrxList[Math.floor(Math.random() * cachedPrxList.length)];
    return `${randomPrx.prxIP}:${randomPrx.prxPort}`;
}

// ============================================================
//  FUNGSI AUTO-DETECT PROXY (HTTP CONNECT -> WEBSOCKET -> RAW)
// ============================================================

function generateWSKey() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes));
}

function createWSFrame(data) {
    const len = data.byteLength;
    const maskKey = new Uint8Array(4);
    crypto.getRandomValues(maskKey);

    let headerLen = 2 + 4; // basic + mask
    if (len >= 126) headerLen += (len < 65536 ? 2 : 8);
    const header = new Uint8Array(headerLen);
    header[0] = 0x82; // FIN + Binary

    let offset = 2;
    if (len < 126) {
        header[1] = 0x80 | len;
    } else if (len < 65536) {
        header[1] = 0x80 | 126;
        new DataView(header.buffer).setUint16(offset, len, false);
        offset += 2;
    } else {
        header[1] = 0x80 | 127;
        new DataView(header.buffer).setBigUint64(offset, BigInt(len), false);
        offset += 8;
    }
    header.set(maskKey, offset);

    const masked = new Uint8Array(len);
    for (let i = 0; i < len; i++) masked[i] = data[i] ^ maskKey[i % 4];
    return ByteUtils.merge(header, masked);
}

function parseWSFrame(buffer) {
    if (buffer.length < 2) return null;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const b2 = view.getUint8(1);
    let len = b2 & 0x7F;
    let offset = 2;
    if (len === 126) { len = view.getUint16(offset); offset += 2; }
    else if (len === 127) { len = Number(view.getBigUint64(offset)); offset += 8; }
    const masked = (b2 & 0x80) !== 0;
    if (masked) offset += 4; // skip mask
    if (buffer.length < offset + len) return null;
    const payload = buffer.slice(offset, offset + len);
    if (masked) {
        const maskKey = buffer.slice(offset - 4, offset);
        for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
    }
    return { payload, totalLength: offset + len };
}

// ----- Fungsi Utama Koneksi Otomatis -----
async function connectWithAutoDetect(proxyHost, proxyPort, targetHost, targetPort, initialPayload, fallbackNode, activeTarget, intent, remoteWs) {
    // Jika tidak pakai fallback, langsung ke tujuan
    if (!fallbackNode) {
        const sock = connect({ hostname: targetHost, port: targetPort });
        activeTarget.value = sock;
        const w = sock.writable.getWriter();
        await w.write(initialPayload);
        w.releaseLock();
        return { socket: sock, isWS: false };
    }

    const sock = connect({ hostname: proxyHost, port: proxyPort });
    activeTarget.value = sock;
    const writer = sock.writable.getWriter();

    // ---- METHOD 1: HTTP CONNECT ----
    try {
        const cmd = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`;
        await writer.write(ByteUtils.encode(cmd));
        writer.releaseLock();

        const reader = sock.readable.getReader();
        let resp = new Uint8Array();
        let isConnected = false;
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            resp = ByteUtils.merge(resp, value);
            if (ByteUtils.decode(resp).includes("\r\n\r\n")) {
                if (ByteUtils.decode(resp).includes("200")) isConnected = true;
                break;
            }
        }
        reader.releaseLock();

        if (isConnected) {
            const w2 = sock.writable.getWriter();
            await w2.write(initialPayload);
            w2.releaseLock();
            return { socket: sock, isWS: false };
        }
    } catch (e) { /* Gagal, lanjut ke WS */ }

    // ---- METHOD 2: WEBSOCKET ----
    try {
        const wsKey = generateWSKey();
        const handshake = `GET / HTTP/1.1\r\nHost: ${proxyHost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${wsKey}\r\nSec-WebSocket-Version: 13\r\n\r\n`;
        const w2 = sock.writable.getWriter();
        await w2.write(ByteUtils.encode(handshake));
        w2.releaseLock();

        const reader = sock.readable.getReader();
        let resp = new Uint8Array();
        let upgraded = false;
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            resp = ByteUtils.merge(resp, value);
            if (ByteUtils.decode(resp).includes("\r\n\r\n")) {
                if (ByteUtils.decode(resp).includes("101")) upgraded = true;
                break;
            }
        }
        reader.releaseLock();

        if (upgraded) {
            const w3 = sock.writable.getWriter();
            await w3.write(createWSFrame(initialPayload));
            w3.releaseLock();

            // Aktifkan relay WS frame
            let headSent = false;
            let leftover = new Uint8Array(0);

            (async () => {
                const upstreamReader = sock.readable.getReader();
                while (true) {
                    const { value, done } = await upstreamReader.read();
                    if (done) break;
                    let buffer = ByteUtils.merge(leftover, value);
                    while (buffer.length > 0) {
                        const result = parseWSFrame(buffer);
                        if (!result) break;
                        const { payload, totalLength } = result;
                        if (remoteWs.readyState === 1) {
                            const dataToSend = ByteUtils.merge(headSent ? new Uint8Array(0) : (intent.replyHead || new Uint8Array(0)), payload);
                            remoteWs.send(dataToSend);
                            if (!headSent && intent.replyHead) headSent = true;
                        }
                        buffer = buffer.slice(totalLength);
                    }
                    leftover = buffer;
                }
            })();

            // Relay dari Client (NekoBox) ke Proxy (bungkus WS frame)
            remoteWs.addEventListener('message', (e) => {
                if (sock.writable.locked) return;
                const raw = typeof e.data === 'string' ? ByteUtils.encode(e.data) : new Uint8Array(e.data);
                sock.writable.getWriter().then(w => {
                    w.write(createWSFrame(raw));
                    w.releaseLock();
                });
            });

            return { socket: sock, isWS: true };
        }
    } catch (e) { /* Gagal, lanjut ke RAW */ }

    // ---- METHOD 3: RAW TCP ----
    const w4 = sock.writable.getWriter();
    await w4.write(initialPayload);
    w4.releaseLock();
    return { socket: sock, isWS: false };
}

// --- [ CLOUDFLARE ENTRY POINT ] ---

export default {
    async fetch(req, env, ctx) {
        const isWs = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
        const url = new URL(req.url);
        const kv = env.PROXY_DB || env.MY_KV;

        // Endpoint Sync Database KV Manual
        if (url.pathname === "/sync-db") {
            const result = await syncGitHubToKV(env);
            return new Response(JSON.stringify(result), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }

        // Display Tampilan Daftar Proxy di Halaman Utama Domain
        if ((url.pathname === "/" || url.pathname === "") && !isWs) {
            let proxies = [];
            if (kv) {
                proxies = (await kv.get("PROXIES_JSON", "json")) || [];
            }

            let countryCounters = {};
            let responseLines = [];
            responseLines.push("=== LIST PROXY AKTIF (KV DATABASE) ===");
            responseLines.push(`Total Proxy Tersimpan: ${proxies.length}`);
            responseLines.push("Format: Path | IP:Port | Country | ORG\n");

            if (proxies.length > 0) {
                proxies.forEach((p) => {
                    const cc = (p.country || "UN").toUpperCase();
                    countryCounters[cc] = (countryCounters[cc] || 0) + 1;
                    const pathCode = `/${cc}${countryCounters[cc]}`;
                    responseLines.push(`${pathCode.padEnd(6)} : ${p.prxIP}:${p.prxPort} [${cc}] - ${p.org}`);
                });
            } else {
                responseLines.push("Data KV kosong. Jalankan endpoint /sync-db untuk mengisinya.");
            }

            return new Response(responseLines.join("\n"), { 
                status: 200, 
                headers: { "Content-Type": "text/plain; charset=utf-8" } 
            });
        }

        if (isWs) {
            let cachedPrxList = [];
            if (kv) {
                cachedPrxList = (await kv.get("PROXIES_JSON", "json")) || [];
            }

            const reqPath = url.pathname.replace(/^\/+/, '').toUpperCase();
            const ipPortMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

            let prxIP = "";
            if (ipPortMatch && !/^[A-Z]+\d*$/.test(reqPath)) {
                prxIP = ipPortMatch[1];
            } else {
                prxIP = resolveProxyFromPath(reqPath, cachedPrxList);
            }

            const fallbackNode = prxIP || null;

            const pair = new WebSocketPair();
            const [local, remote] = Object.values(pair);
            remote.accept();

            const ed = req.headers.get("sec-websocket-protocol");
            const firstPacket = ByteUtils.b64Decode(ed);

            let activeTarget = null, dnsWriter = null;

            const wsStream = new ReadableStream({
                start(ctrl) {
                    remote.addEventListener("message", e => ctrl.enqueue(e.data));
                    remote.addEventListener("close", () => ctrl.close());
                    remote.addEventListener("error", () => ctrl.error());
                    if (firstPacket) ctrl.enqueue(firstPacket);
                }
            });

            wsStream.pipeTo(new WritableStream({
                async write(chunk) {
                    if (dnsWriter) return dnsWriter.write(chunk);
                    if (activeTarget) {
                        const w = activeTarget.writable.getWriter();
                        await w.write(chunk);
                        w.releaseLock();
                        return;
                    }

                    const buf = new Uint8Array(chunk);
                    const engine = await ConnectionBroker.identify(buf);
                    const intent = await engine.extract(buf);

                    if (intent.isUdp) {
                        if (intent.port !== 53) throw new Error("Only DoH UDP allowed");
                        dnsWriter = SubstreamHandler.attachDNS(remote, intent.replyHead);
                        dnsWriter.write(intent.payload);
                        return;
                    }

                    // ----- GANTI DENGAN AUTO-DETECT -----
                    const host = fallbackNode ? fallbackNode.split(/[:=-]/)[0] : intent.host;
                    const port = fallbackNode ? parseInt(fallbackNode.split(/[:=-]/)[1], 10) : intent.port;

                    const activeTargetObj = { value: null };
                    const result = await connectWithAutoDetect(
                        host, port, 
                        intent.host, intent.port, 
                        intent.payload,
                        fallbackNode,
                        activeTargetObj,
                        intent,
                        remote
                    );

                    activeTarget = result.socket;

                    // Jika bukan WebSocket, gunakan pipeTCP biasa
                    if (!result.isWS) {
                        SubstreamHandler.pipeTCP(result.socket, remote, intent.replyHead, async () => {
                            if (fallbackNode) {
                                const retryResult = await connectWithAutoDetect(
                                    host, port,
                                    intent.host, intent.port,
                                    intent.payload,
                                    fallbackNode,
                                    activeTargetObj,
                                    intent,
                                    remote
                                );
                                retryResult.socket.closed.finally(() => remote.close());
                                SubstreamHandler.pipeTCP(retryResult.socket, remote, intent.replyHead, null);
                            }
                        });
                    }
                    // Jika WebSocket, relay sudah diatur di dalam connectWithAutoDetect
                }
            })).catch(() => remote.close());

            return new Response(null, {
                status: 101, webSocket: local, 
                headers: ed ? { "Sec-WebSocket-Protocol": ed } : {}
            });
        }

        return fetch(req);
    },

    async scheduled(event, env, ctx) {
        ctx.waitUntil(syncGitHubToKV(env));
    }
};
