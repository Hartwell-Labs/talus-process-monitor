// ── Talus license key format codec ─────────────────────────────────────────
//
// Canonical (internal) form — what the Ed25519 signature actually covers:
//     base64(JSON payload) "." base64(64-byte signature)
//
// Display (pretty) form — what customers receive, type, and read aloud:
//     TALUS-XXXXX-XXXXX-XXXXX-…-XXXXX-SS
//
//   • XXXXX = Crockford base32 (0-9, A-Z minus I, L, O, U) of the canonical
//     bytes, grouped in fives — no ambiguous characters, copy-paste safe.
//   • "SS"   = last two hex chars of SHA-256 over the canonical bytes, so
//     typos are caught client-side before activation.
//
// The signature is PART of the encoded bytes, so the pretty form carries the
// full signed key. Decoding is lossless; verification always operates on the
// canonical form. Old canonical keys remain accepted everywhere.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PREFIX = 'TALUS';
const GROUP = 5;

export function is_canonical(key) {
  const k = String(key).trim();
  return k.includes('.') && /^[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+$/.test(k);
}

export function is_pretty(key) {
  const k = String(key).trim().toUpperCase().replace(/\s+/g, '');
  // Many groups = full JWT encoded. Exactly 4 groups = SHORT key: not a
  // self-contained encoding — it resolves to the JWT via admin/bind.
  return (
    k.startsWith(PREFIX + '-') &&
    /^[0-9A-Z-]+$/.test(k) &&
    (k.match(/-/g) ?? []).length >= 6
  );
}

// ── SHORT keys: TALUS-XXXXX-XXXXX-XXXXX-XXXXX ──────────────────────────
//
// A short key is a random 104-bit handle (Crockford base32). The signed
// JWT (canonical form) is bound to it server-side (admin/bind) and the
// client fetches the JWT at activation, verifies the Ed25519 signature
// locally, and proceeds as before. The short key is stored ONLY as a
// SHA-256 hash — seeing the D1 database does not reveal usable keys.

export function is_short(key) {
  const k = String(key).trim().toUpperCase().replace(/\s+/g, '');
  return (
    k.startsWith(PREFIX + '-') &&
    /^[0-9A-Z-]+$/.test(k) &&
    (k.match(/-/g) ?? []).length === 4
  );
}

// Normalize a short key: trim, collapse whitespace, uppercase. Crockford
// alphabet has no I/L/O/U, so map common mistypes to their digits.
export function normalize_short_key(key) {
  const raw = String(key).trim().toUpperCase().replace(/\s+/g, '');
  if (!raw.startsWith(PREFIX + '-')) return raw;
  return (
    PREFIX +
    '-' +
    raw
      .slice(PREFIX.length + 1)
      .replace(/O/g, '0')
      .replace(/[IL]/g, '1')
  );
}

// Canonical key string → pretty key string (sha256_hex_fn: bytes → hex).
export async function to_pretty(canonical_key, sha256_hex_fn) {
  const data = new TextEncoder().encode(String(canonical_key).trim());
  const digest = await sha256_hex_fn(data);
  const body = b32_encode(data);
  const grouped = (body.match(new RegExp(`.{1,${GROUP}}`, 'g')) ?? []).join('-');
  return `${PREFIX}-${grouped}-${digest.slice(-2).toUpperCase()}`;
}

// Pretty key string → canonical key string. Throws on checksum mismatch.
// (sha256_hex_sync: bytes → hex string, e.g. via node:crypto.)
export function decode_pretty(pretty_key, sha256_hex_sync) {
  const k = String(pretty_key).trim().toUpperCase().replace(/\s+/g, '');
  if (!k.startsWith(PREFIX + '-')) throw new Error('not a pretty key');
  const parts = k.slice(PREFIX.length + 1).split('-');
  if (parts.length < 2) throw new Error('key too short');
  const checksum = parts[parts.length - 1];
  const body = parts.slice(0, -1).join('');
  if (!/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/.test(body)) {
    throw new Error('invalid characters in key');
  }
  const data = b32_decode(body);
  const expected = sha256_hex_sync(data).slice(-2).toUpperCase();
  if (checksum !== expected) throw new Error('checksum mismatch — retype the key');
  return new TextDecoder().decode(data);
}

// ── base32 (Crockford alphabet) helpers ────────────────────────────────────

function b32_encode(bytes) {
  let out = '';
  let acc = 0;
  let nbits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    nbits += 8;
    while (nbits >= 5) {
      out += ALPHABET[(acc >>> (nbits - 5)) & 31];
      nbits -= 5;
    }
  }
  if (nbits > 0) out += ALPHABET[(acc << (5 - nbits)) & 31];
  return out;
}

function b32_decode(s) {
  const out = [];
  let acc = 0;
  let nbits = 0;
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('invalid character');
    acc = (acc << 5) | idx;
    nbits += 5;
    if (nbits >= 8) {
      out.push((acc >>> (nbits - 8)) & 0xff);
      nbits -= 8;
    }
  }
  return new Uint8Array(out);
}
