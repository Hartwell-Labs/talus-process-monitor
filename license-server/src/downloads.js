// ── downloads.js — R2-backed artifact distribution ────────────────────────
//
// Served on the custom domain download.hartwell-labs.pl by the same Worker as
// the license API, so both lines share one deployment and one secret store.
//
//   GET /mit/<version>/<file>          public, cacheable, no license
//   GET /enterprise/<version>/<file>   requires X-Talus-License
//
// The R2 bucket is private. It has no public bucket domain: every byte goes
// through this handler, which is what makes the Enterprise line enforceable.
//
// Free-tier budget (R2: 10 GB storage, 1M Class A, 10M Class B per month):
//   • MIT responses are cached at the edge as immutable, so a repeat download
//     does not reach R2 and costs no Class B operation.
//   • Enterprise responses are never cached (a licensed binary must not be
//     served from a shared cache), so each Enterprise download is one Class B.
//   • Uploads are the only Class A traffic; there is no listing on this path.
//   • Objects are small (25 MB for Enterprise), so storage stays far below
//     10 GB unless every historical build is kept forever. The publish script
//     keeps only the current and previous version per line.

import { is_canonical, is_pretty, decode_pretty } from './format.js';
import { resolve_key } from './store-bridge.js';

const DOWNLOAD_HOST = 'download.hartwell-labs.pl';
const ALLOWED_LINES = new Set(['mit', 'enterprise']);
const MAX_LICENSE_LEN = 8192;
const MAX_KEY_LEN = 256;
// 8 GiB, leaving 2 GiB of 10 GiB headroom for manifests and in-flight uploads.
const MAX_STORAGE_BYTES = 8 * 1024 * 1024 * 1024;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

function not_found() {
  return json({ success: false, message: 'not found' }, 404);
}

/// Object keys are version/file paths. Reject anything that could escape the
/// line prefix or confuse a downstream cache.
function safe_key(key) {
  if (!key || key.length > MAX_KEY_LEN) return false;
  if (key.includes('..') || key.includes('\\') || key.includes('//')) return false;
  return /^[A-Za-z0-9._/-]+$/.test(key);
}

function filename_of(key) {
  return key.split('/').pop() || 'download';
}

async function authorize(env, raw_key) {
  // Cheap rejection first: a missing or oversized header must not touch the
  // database, and it must not report a server error just because DB is absent.
  if (!raw_key || raw_key.length > MAX_LICENSE_LEN) {
    return { ok: false, status: 401, message: 'missing or oversized X-Talus-License' };
  }
  if (!env.LICENSE_PUBLIC_KEYS) {
    return { ok: false, status: 500, message: 'server misconfigured: missing LICENSE_PUBLIC_KEYS' };
  }

  // Same key formats as activation: short store keys resolve to the canonical
  // signed form, native Talus keys are already canonical.
  let effective = raw_key.trim();
  if (!is_canonical(effective) && !is_pretty(effective)) {
    if (!env.DB) return { ok: false, status: 500, message: 'server misconfigured: missing DB' };
    const resolved = await resolve_key(env, effective);
    if (resolved.kind === 'unknown') {
      return { ok: false, status: 404, message: 'license not found' };
    }
    effective = resolved.license_key || effective;
  }

  if (is_pretty(effective)) {
    try {
      // decode_pretty needs a synchronous digest: the pretty-key checksum is
      // verified inline, and WebCrypto's digest is async-only.
      effective = decode_pretty(effective, sha256_hex_sync);
    } catch {
      return { ok: false, status: 400, message: 'invalid license key' };
    }
  }

  const parts = effective.split('.');
  if (parts.length !== 2) return { ok: false, status: 400, message: 'invalid license key' };

  let payload_bytes;
  let sig_bytes;
  try {
    payload_bytes = base64_decode(parts[0]);
    sig_bytes = base64_decode(parts[1]);
  } catch {
    return { ok: false, status: 400, message: 'invalid license encoding' };
  }
  if (sig_bytes.length !== 64) return { ok: false, status: 401, message: 'invalid signature' };

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payload_bytes));
  } catch {
    return { ok: false, status: 400, message: 'invalid license payload' };
  }

  const kid = payload.kid || 'v1';
  if (kid === 'test') return { ok: false, status: 401, message: 'invalid signature' };

  const keys = parse_public_keys(env.LICENSE_PUBLIC_KEYS);
  const hex = keys && keys[kid];
  if (!hex) return { ok: false, status: 401, message: 'unknown signing key' };

  let pub;
  try {
    pub = hex_decode(hex);
  } catch {
    return { ok: false, status: 500, message: 'server misconfigured: bad public key' };
  }

  if (!(await verify_ed25519(pub, sig_bytes, payload_bytes))) {
    return { ok: false, status: 401, message: 'invalid signature' };
  }

  const license_id = typeof payload.license_id === 'string' ? payload.license_id : '';
  const tier = typeof payload.tier === 'string' ? payload.tier : '';
  if (!license_id || !tier) {
    return { ok: false, status: 400, message: 'license payload missing fields' };
  }

  const expires_at = typeof payload.expires_at === 'string' ? payload.expires_at : '';
  if (expires_at && new Date(expires_at).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'license expired' };
  }

  // "Exists" is a database fact, not just a valid signature: a refunded or
  // never-issued key must not download the licensed binary.
  if (!env.DB) return { ok: false, status: 500, message: 'server misconfigured: missing DB' };
  const row = await env.DB.prepare(
    'SELECT license_id, tier, revoked, expires_at FROM licenses WHERE license_id = ?1',
  )
    .bind(license_id)
    .first();

  if (!row) return { ok: false, status: 404, message: 'license not found' };
  if (row.revoked) return { ok: false, status: 403, message: 'license revoked' };
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'license expired' };
  }
  if (tier !== 'enterprise') {
    return { ok: false, status: 403, message: 'enterprise license required' };
  }

  return { ok: true, license_id, tier };
}

function range_for(request) {
  const raw = request.headers.get('range');
  if (!raw) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(raw.trim());
  if (!match) return null;
  const start = match[1] === '' ? null : Number(match[1]);
  const end = match[2] === '' ? null : Number(match[2]);
  if (start === null && end === null) return null;
  if (start !== null && end !== null && end < start) return null;
  if (start === null) return { suffix: end };
  return { offset: start, length: end === null ? undefined : end - start + 1 };
}

export async function handle_download_request(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return json({ success: false, message: 'method not allowed' }, 405);
  }
  if (!env.DOWNLOADS) {
    return json({ success: false, message: 'server misconfigured: missing DOWNLOADS' }, 500);
  }

  const url = new URL(request.url);
  // `wrangler dev` rewrites the request URL to localhost, so local smoke tests
  // opt in explicitly. Production never sets this variable.
  const host_ok = url.hostname === DOWNLOAD_HOST || env.DOWNLOAD_DEV_ALLOW_ANY === '1';
  if (!host_ok) return not_found();

  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return not_found();

  const line = parts[0];
  if (!ALLOWED_LINES.has(line)) return not_found();

  const key = parts.slice(1).join('/');
  if (!safe_key(key)) return not_found();

  if (line === 'enterprise') {
    const auth = await authorize(env, request.headers.get('x-talus-license') || '');
    if (!auth.ok) return json({ success: false, message: auth.message }, auth.status);
  }

  // MIT is immutable and public: the edge cache removes repeat R2 reads, which
  // is the difference between a cache-friendly mirror and a Class B bill.
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  if (line === 'mit' && request.method === 'GET' && cache) {
    const hit = await cache.match(request);
    if (hit) return hit;
  }

  const object_key = `${line}/${key}`;
  const range = range_for(request);
  let object;
  try {
    object =
      request.method === 'HEAD'
        ? await env.DOWNLOADS.head(object_key)
        : await env.DOWNLOADS.get(object_key, range ? { range } : undefined);
  } catch {
    return json({ success: false, message: 'storage unavailable' }, 503);
  }
  if (!object) return not_found();

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('content-type', 'application/octet-stream');
  headers.set('content-disposition', `attachment; filename="${filename_of(key)}"`);
  headers.set('x-content-type-options', 'nosniff');
  headers.set('etag', object.httpEtag || '');
  headers.set('accept-ranges', 'bytes');

  const is_range = Boolean(range && object.range);
  if (is_range) {
    if (object.range.offset !== undefined && object.range.length !== undefined) {
      headers.set(
        'content-range',
        `bytes ${object.range.offset}-${object.range.offset + object.range.length - 1}/${object.size}`,
      );
    }
    headers.set('content-length', String(object.range.length ?? ''));
  } else {
    headers.set('content-length', String(object.size));
  }

  if (line === 'mit') {
    headers.set('cache-control', 'public, max-age=31536000, immutable');
  } else {
    // A licensed binary must never land in a shared cache.
    headers.set('cache-control', 'private, no-store');
  }

  const response = new Response(request.method === 'HEAD' ? null : object.body, {
    status: is_range ? 206 : 200,
    headers,
  });

  if (line === 'mit' && request.method === 'GET' && cache && ctx?.waitUntil) {
    ctx.waitUntil(cache.put(request, response.clone()));
  }
  return response;
}

// ── Minimal verification helpers ──────────────────────────────────────────
// Kept local so the download path cannot accidentally inherit activation
// side effects (seat registration, rate-limit counters) from index.js.

function parse_public_keys(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const map = {};
  for (const pair of raw.split(',')) {
    const [kid, hex] = pair.split(':');
    if (kid && hex) map[kid.trim()] = hex.trim();
  }
  return Object.keys(map).length > 0 ? map : null;
}

function hex_decode(s) {
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base64_decode(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verify_ed25519(public_key, signature, data) {
  try {
    const key = await crypto.subtle.importKey('raw', public_key, { name: 'Ed25519' }, false, [
      'verify',
    ]);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, data);
  } catch {
    return false;
  }
}

// ── Synchronous SHA-256 ───────────────────────────────────────────────────
// The pretty-key codec verifies its checksum in a synchronous function, so
// WebCrypto (async-only) cannot be used there. Small, self-contained, and
// used only for that checksum — the license signature itself is verified
// with WebCrypto below.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256_hex_sync(bytes) {
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const len = bytes.length;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bits = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 4, bits >>> 0);
  view.setUint32(padded.length - 8, Math.floor(bits / 2 ** 32));

  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((x) => x.toString(16).padStart(8, '0')).join('');
}

// Exported for the local tests; not part of the Worker API.
export const __test = { handle_download_request, authorize, safe_key, range_for, MAX_STORAGE_BYTES };
