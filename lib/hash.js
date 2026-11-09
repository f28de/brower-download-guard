/**
 * hash.js —— 纯 JavaScript 增量（流式）哈希实现
 *
 * 设计要点：
 *  1. 完全不依赖 WebCrypto / 第三方库 / 远程代码，符合 MV3 的内容安全策略。
 *  2. 采用增量（incremental）算法，内存占用恒定（仅 64 字节缓冲 + 256 字节状态），
 *     因此可以对任意大小的下载文件边读边算，不需要把整个文件读进内存。
 *  3. MD5 与 SHA-256 可在同一次读取中并行计算，只消耗一遍 IO。
 *
 * 正确性由 test/hash.test.mjs 对拍 Node 内置 crypto 验证（覆盖 0/55/56/63/64/65 等边界长度）。
 */

/* ------------------------------------------------------------------ *
 * 工具函数
 * ------------------------------------------------------------------ */

const ROTL32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const ROTR32 = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

/** 把字节数组转成小写十六进制字符串 */
export function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  }
  return out;
}

/** 统一把输入规整成 Uint8Array 视图（不拷贝） */
function asBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('不支持的数据类型，需要 Uint8Array / ArrayBuffer / string');
}

/* ------------------------------------------------------------------ *
 * MD5 (RFC 1321)
 * ------------------------------------------------------------------ */

// 每轮的循环左移位数
const MD5_S = new Uint8Array([
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);

// K[i] = floor(abs(sin(i + 1)) * 2^32)
const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i++) {
  MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
}

const MD5_IV = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

export class Md5 {
  constructor() {
    this.h = new Uint32Array(MD5_IV);
    this.buf = new Uint8Array(64);
    this.bufLen = 0;
    this.total = 0; // 已喂入的字节数
    this.w = new Uint32Array(16);
  }

  /** 喂入数据（可多次调用） */
  update(data) {
    this._update(asBytes(data));
    return this;
  }

  _update(bytes) {
    const n = bytes.length;
    if (n === 0) return;
    this.total += n;

    let i = 0;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, n);
      this.buf.set(bytes.subarray(0, take), this.bufLen);
      this.bufLen += take;
      i = take;
      if (this.bufLen === 64) {
        this._block(this.buf, 0);
        this.bufLen = 0;
      }
    }
    while (i + 64 <= n) {
      this._block(bytes, i);
      i += 64;
    }
    if (i < n) {
      this.buf.set(bytes.subarray(i), 0);
      this.bufLen = n - i;
    }
  }

  _block(p, off) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const o = off + i * 4;
      w[i] = (p[o] | (p[o + 1] << 8) | (p[o + 2] << 16) | (p[o + 3] << 24)) >>> 0;
    }

    let a = this.h[0];
    let b = this.h[1];
    let c = this.h[2];
    let d = this.h[3];

    for (let i = 0; i < 64; i++) {
      let f;
      let g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) & 15;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) & 15;
      }

      const tmp = d;
      d = c;
      c = b;
      const x = (a + f + MD5_K[i] + w[g]) | 0;
      b = (b + ROTL32(x, MD5_S[i])) | 0;
      a = tmp;
    }

    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
  }

  _clone() {
    const c = new Md5();
    c.h.set(this.h);
    c.buf.set(this.buf);
    c.bufLen = this.bufLen;
    c.total = this.total;
    return c;
  }

  /** 结束计算并返回 16 字节摘要（可重复调用，不破坏内部状态） */
  digest() {
    const c = this._clone();
    const bitLen = c.total * 8;
    const lo = bitLen >>> 0;
    const hi = Math.floor(bitLen / 4294967296) >>> 0;

    const rem = c.bufLen;
    const padLen = rem < 56 ? 56 - rem : 120 - rem;
    const tail = new Uint8Array(padLen + 8);
    tail[0] = 0x80;
    const dv = new DataView(tail.buffer);
    dv.setUint32(padLen, lo, true);
    dv.setUint32(padLen + 4, hi, true);
    c._update(tail);

    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 4; i++) odv.setUint32(i * 4, c.h[i], true);
    return out;
  }

  hex() {
    return toHex(this.digest());
  }
}

/* ------------------------------------------------------------------ *
 * SHA-256 (FIPS 180-4)
 * ------------------------------------------------------------------ */

const SHA256_K = new Uint32Array(64);
const SHA256_H0 = new Uint32Array(8);

// 由前 64 个质数的小数部分推导常量，避免手抄常量表出错：
//   K[i] = 取 cbrt(prime[i]) 小数部分的前 32 位
//   H[i] = 取 sqrt(prime[i])  小数部分的前 32 位
(() => {
  const primes = [];
  for (let n = 2; primes.length < 64; n++) {
    let isPrime = true;
    for (let d = 2; d * d <= n; d++) {
      if (n % d === 0) {
        isPrime = false;
        break;
      }
    }
    if (isPrime) primes.push(n);
  }
  for (let i = 0; i < 64; i++) {
    SHA256_K[i] = Math.floor((Math.cbrt(primes[i]) % 1) * 4294967296) >>> 0;
  }
  for (let i = 0; i < 8; i++) {
    SHA256_H0[i] = Math.floor((Math.sqrt(primes[i]) % 1) * 4294967296) >>> 0;
  }
})();

export class Sha256 {
  constructor() {
    this.h = new Uint32Array(SHA256_H0);
    this.buf = new Uint8Array(64);
    this.bufLen = 0;
    this.total = 0;
    this.w = new Uint32Array(64);
  }

  update(data) {
    this._update(asBytes(data));
    return this;
  }

  _update(bytes) {
    const n = bytes.length;
    if (n === 0) return;
    this.total += n;

    let i = 0;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, n);
      this.buf.set(bytes.subarray(0, take), this.bufLen);
      this.bufLen += take;
      i = take;
      if (this.bufLen === 64) {
        this._block(this.buf, 0);
        this.bufLen = 0;
      }
    }
    while (i + 64 <= n) {
      this._block(bytes, i);
      i += 64;
    }
    if (i < n) {
      this.buf.set(bytes.subarray(i), 0);
      this.bufLen = n - i;
    }
  }

  _block(p, off) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const o = off + i * 4;
      w[i] = ((p[o] << 24) | (p[o + 1] << 16) | (p[o + 2] << 8) | p[o + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = (ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >>> 3)) >>> 0;
      const s1 = (ROTR32(y, 17) ^ ROTR32(y, 19) ^ (y >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = this.h[0];
    let b = this.h[1];
    let c = this.h[2];
    let d = this.h[3];
    let e = this.h[4];
    let f = this.h[5];
    let g = this.h[6];
    let h = this.h[7];

    for (let i = 0; i < 64; i++) {
      const S1 = (ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0;
    this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0;
    this.h[7] = (this.h[7] + h) >>> 0;
  }

  _clone() {
    const c = new Sha256();
    c.h.set(this.h);
    c.buf.set(this.buf);
    c.bufLen = this.bufLen;
    c.total = this.total;
    return c;
  }

  digest() {
    const c = this._clone();
    const bitLen = c.total * 8;
    const hi = Math.floor(bitLen / 4294967296) >>> 0;
    const lo = bitLen >>> 0;

    const rem = c.bufLen;
    const padLen = rem < 56 ? 56 - rem : 120 - rem;
    const tail = new Uint8Array(padLen + 8);
    tail[0] = 0x80;
    const dv = new DataView(tail.buffer);
    dv.setUint32(padLen, hi, false);
    dv.setUint32(padLen + 4, lo, false);
    c._update(tail);

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, c.h[i], false);
    return out;
  }

  hex() {
    return toHex(this.digest());
  }
}

/* ------------------------------------------------------------------ *
 * 组合使用：一次读取同时算出 MD5 与 SHA-256
 * ------------------------------------------------------------------ */

export function createDualHasher() {
  const md5 = new Md5();
  const sha256 = new Sha256();
  return {
    update(bytes) {
      md5.update(bytes);
      sha256.update(bytes);
    },
    digest() {
      return { md5: md5.hex(), sha256: sha256.hex() };
    },
  };
}
