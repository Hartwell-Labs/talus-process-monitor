// ── Store bridge — Polar / Gumroad / Lemon Squeezy webhooks + redeem ──────
//
// The stores sell "Talus Enterprise" and deliver THEIR OWN license key.
// The issuer daemon (owner's machine, holds the Ed25519 signing key)
// fulfills each pending order by signing a real Talus license and recording
// the store-key → license mapping in `store_keys`. From that moment a store
// key is "translated" into a Talus license transparently:
//
//   customer pastes store key at activation
//     → server hashes it, looks up store_keys
//     → found:    respond with the Talus license key (activation continues
//                 as if the Talus key had been pasted)
//     → not yet:  record in pending_store_keys; issuer daemon fulfills and
//                 the customer simply retries
//
// Every webhook is verified with the platform's HMAC signature before any
// state is created. Order handling is idempotent per (store, order_id).
// Store keys are stored only as SHA-256 hashes (plus a short display hint
// for the admin panel) — never in plaintext.

const MAX_WEBHOOK_BODY = 64 * 1024;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

function str(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

async function sha256_hex(s) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(s),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function now_iso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ── HMAC signature verification (platform-specific headers) ───────────────

async function hmac_sha1_hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(message),
  );
  return [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmac_hex(secret, message, hash) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(message),
  );
  return [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Constant-time string comparison.
function timing_safe_equal(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Verify the webhook signature for the given store. Returns true when the
// signature is present and matches the store's configured secret.
async function verify_webhook_signature(store, request, raw_body, env) {
  const secret_field = {
    polar: 'POLAR_WEBHOOK_SECRET',
    gumroad: 'GUMROAD_WEBHOOK_SECRET',
    lemonsqueezy: 'LEMONSQUEEZY_WEBHOOK_SECRET',
  }[store];
  const secret = env[secret_field];
  if (!secret) return false; // not configured → fail closed

  if (store === 'polar') {
    // Polar: Polar-Signature: "<hex hmac-sha256 of raw body>" (v1 scheme,
    // comma-separated timestamped tags; accept the v1 tag or a bare hex).
    const header = request.headers.get('polar-signature') ?? '';
    const tag = header
      .split(',')
      .map((p) => p.trim())
      .find((p) => p.startsWith('v1='));
    const provided = tag ? tag.slice(3) : header.trim();
    if (!provided) return false;
    const expected = await hmac_hex(
      String(secret).trim(),
      raw_body,
      'SHA-256',
    );
    return timing_safe_equal(provided.toLowerCase(), expected);
  }

  if (store === 'lemonsqueezy') {
    // Lemon Squeezy: X-Signature: hex HMAC-SHA256 of the raw body.
    const provided = (request.headers.get('x-signature') ?? '').trim();
    if (!provided) return false;
    const expected = await hmac_hex(
      String(secret).trim(),
      raw_body,
      'SHA-256',
    );
    return timing_safe_equal(provided.toLowerCase(), expected);
  }

  if (store === 'gumroad') {
    // Gumroad "ping": form-encoded POST with a `hmac_sha1` field computed
    // over the RAW query-style body with that field removed (Gumroad signs
    // the serialized query string, not concatenated values). Accept both
    // candidate encodings: raw body minus the hmac field, and the classic
    // alphabetical-value concatenation.
    const provided = (() => {
      const m = raw_body.match(/[?&]hmac_sha1=([^&]+)/);
      return m ? decodeURIComponent(m[1]).trim().toLowerCase() : '';
    })();
    if (!provided) return false;

    // Candidate 1: raw body without the hmac_sha1 field (and cleaned up
    // separators), as a query string.
    const stripped = raw_body
      .replace(/^[?&]*(hmac_sha1=[^&]*&?)/, '')
      .replace(/&hmac_sha1=[^&]*/g, '')
      .replace(/^&+|&+$/g, '');
    const expected_raw = await hmac_sha1_hex(String(secret).trim(), stripped);
    if (timing_safe_equal(provided, expected_raw)) return true;

    // Candidate 2: Gumroad docs variant — values concatenated in
    // alphabetical key order.
    const params = new URLSearchParams(raw_body);
    const keys = [...params.keys()]
      .filter((k) => k !== 'hmac_sha1')
      .sort();
    const message = keys.map((k) => params.get(k) ?? '').join('');
    const expected_vals = await hmac_sha1_hex(String(secret).trim(), message);
    return timing_safe_equal(provided, expected_vals);
  }

  return false;
}

// ── Per-store payload normalization ───────────────────────────────────────
// Each parser returns { order_id, email, product, seats, event } or null.
// License terms (seats/expiry) come from the product's mapping below.

// Product name → license terms. Keeps the webhook handler generic: the
// owner creates identically-named products on every platform.
const PRODUCT_TERMS = [
  { match: /enterprise\s*-\s*5\s*seat/i, seats: 5 },
  { match: /enterprise\s*-\s*3\s*seat/i, seats: 3 },
  { match: /enterprise\s*-\s*single/i, seats: 1 },
  { match: /enterprise/i, seats: 1 },
  { match: /community/i, seats: 1 },
];

function terms_for_product(product) {
  for (const t of PRODUCT_TERMS) {
    if (t.match.test(product ?? '')) return t;
  }
  return { seats: 1 };
}

function parse_polar(payload) {
  // Polar webhook: { type: "order.created" | "order.refunded" | ..., data: {...} }
  const event = str(payload.type);
  if (!event) return null;
  const data = payload.data ?? {};
  const order_id =
    str(data.id) ??
    (typeof data.order_id === 'string' ? data.order_id : null);
  if (!order_id) return null;
  const email =
    str(data.customer?.email) ??
    str(data.email) ??
    null;
  const product =
    str(data.product?.name) ??
    str(data.product_name) ??
    (Array.isArray(data.items) ? str(data.items[0]?.product?.name) : null) ??
    null;
  return { event, order_id, email, product };
}

function parse_gumroad(raw_body) {
  // Gumroad ping: form-encoded fields (sale_id, product_name, email, refunded…)
  const params = new URLSearchParams(raw_body);
  const order_id = str(params.get('sale_id')) ?? str(params.get('order_id'));
  if (!order_id) return null;
  const refunded = (params.get('refunded') ?? '').trim() === 'true';
  const disputed = (params.get('disputed') ?? '').trim() === 'true';
  const chargebacked = (params.get('chargebacked') ?? '').trim() === 'true';
  const event =
    refunded || disputed || chargebacked ? 'order.refunded' : 'order.created';
  return {
    event,
    order_id,
    email: str(params.get('email')),
    product: str(params.get('product_name')),
  };
}

function parse_lemonsqueezy(payload) {
  // LS webhook: { meta: { event_name: "order_created" | "order_refunded" },
  //               data: { id, attributes: { ... } } }
  const event = str(payload.meta?.event_name);
  if (!event) return null;
  const data = payload.data ?? {};
  const order_id = str(data.id);
  if (!order_id) return null;
  const attrs = data.attributes ?? {};
  // First line item's product name when present.
  const first_item = Array.isArray(attrs.first_order_item)
    ? attrs.first_order_item[0]
    : null;
  return {
    event: event === 'order_refunded' ? 'order.refunded' : 'order.created',
    order_id,
    email: str(attrs.user_email) ?? str(attrs.user_name),
    product: str(attrs.product_name) ?? str(first_item?.product_name),
  };
}

// ── Webhook endpoint ──────────────────────────────────────────────────────
//
// POST /api/v1/webhook/:store  → verified, idempotent order row.
// Refund events flip the row to 'refunded' and revoke the mapped license.

export async function handle_store_webhook(request, env, store) {
  if (!env.DB) return json({ success: false, message: 'missing DB' }, 500);

  const raw_body = await request.text();
  if (raw_body.length > MAX_WEBHOOK_BODY) {
    return json({ success: false, message: 'body too large' }, 413);
  }

  const sig_ok = await verify_webhook_signature(store, request, raw_body, env);
  if (!sig_ok) {
    // 401 with a generic message; never hint at which check failed.
    return json({ success: false, message: 'invalid signature' }, 401);
  }

  let parsed = null;
  if (store === 'gumroad') {
    parsed = parse_gumroad(raw_body);
  } else {
    try {
      const payload = JSON.parse(raw_body);
      parsed =
        store === 'polar'
          ? parse_polar(payload)
          : parse_lemonsqueezy(payload);
    } catch {
      return json({ success: false, message: 'invalid JSON' }, 400);
    }
  }
  if (!parsed || !parsed.order_id) {
    return json({ success: false, message: 'unrecognized payload' }, 400);
  }

  const { event, order_id, email, product } = parsed;
  const terms = terms_for_product(product);
  const now = now_iso();

  if (event === 'order.refunded') {
    // Idempotent refund: flip status + revoke whatever license was mapped.
    const row = await env.DB.prepare(
      'SELECT license_id, status FROM orders WHERE store = ?1 AND order_id = ?2',
    )
      .bind(store, order_id)
      .first();
    if (!row) {
      // Refund for an order we never saw — record it so the issuer daemon
      // never fulfills a late-arriving purchase.
      await env.DB.prepare(
        `INSERT INTO orders (store, order_id, product, email, seats, status, created_at)
         VALUES (?1, ?2, ?3, ?4, 1, 'refunded', ?5)
         ON CONFLICT(store, order_id) DO NOTHING`,
      )
        .bind(store, order_id, product, email, now)
        .run();
      return json({ success: true, message: 'refund recorded' });
    }
    if (row.status === 'refunded') {
      return json({ success: true, message: 'already refunded' });
    }
    const license_id = row.license_id;
    // D1 batch takes bound STATEMENTS (no .run() inside the array); the
    // per-item ternaries build the statement list conditionally.
    const stmts = [
      env.DB.prepare(
        "UPDATE orders SET status = 'refunded' WHERE store = ?1 AND order_id = ?2",
      ).bind(store, order_id),
    ];
    if (license_id) {
      stmts.push(
        env.DB.prepare(
          'UPDATE licenses SET revoked = 1 WHERE license_id = ?1',
        ).bind(license_id),
        env.DB.prepare('DELETE FROM activations WHERE license_id = ?1').bind(license_id),
        env.DB.prepare(
          `INSERT INTO revocations (license_id, reason, revoked_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(license_id) DO UPDATE SET reason = excluded.reason, revoked_at = excluded.revoked_at`,
        ).bind(license_id, `store refund (${store} ${order_id})`, now),
      );
    }
    try {
      await env.DB.batch(stmts);
    } catch (err) {
      // Surfaced to the platform (which owns the secret) for fast ops.
      return json({ success: false, message: `refund db error: ${String(err)}` }, 500);
    }
    return json({ success: true, message: 'refund processed — license revoked' });
  }

  // order.created → idempotently create a pending order row.
  await env.DB.prepare(
    `INSERT INTO orders (store, order_id, product, email, seats, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)
     ON CONFLICT(store, order_id) DO NOTHING`,
  )
    .bind(store, order_id, product, email, terms.seats, now)
    .run();

  return json({ success: true, message: 'order recorded' });
}

// ── Redeem lookup (called by /api/v1/activate) ────────────────────────────
//
// Given the raw key the customer pasted, decide what it is:
//   { kind: 'short' }  — short TALUS-XXXXX-… key with a bound JWT
//   { kind: 'talus' }  — self-contained Talus key (canonical b64 or pretty)
//   { kind: 'store', store, license_key, license_id? } — a known store key
//   { kind: 'unknown' } — unknown key (recorded for diagnostics)

import { is_canonical, is_pretty, is_short, normalize_short_key } from './format.js';

export async function resolve_key(env, raw_key) {
  const k = raw_key.trim();

  // SHORT key: resolve through the short_keys binding (admin/bind).
  if (is_short(k)) {
    const sk_hash = await sha256_hex(normalize_short_key(k));
    const bound = await env.DB.prepare(
      'SELECT license_key, license_id FROM short_keys WHERE short_key_hash = ?1',
    )
      .bind(sk_hash)
      .first();
    if (bound?.license_key) {
      return {
        kind: 'short',
        license_key: bound.license_key,
        license_id: bound.license_id,
      };
    }
    // Structured like a short key but not bound (yet) — record + retry hint.
    await env.DB.prepare(
      `INSERT INTO pending_store_keys (key_hash, last_seen, attempts)
       VALUES (?1, ?2, 1)
       ON CONFLICT(key_hash) DO UPDATE SET
         last_seen = ?2,
         attempts = attempts + 1`,
    )
      .bind(sk_hash, now_iso())
      .run();
    return { kind: 'unknown', key_hash: sk_hash, hint: key_hint(k) };
  }

  // Self-contained native Talus keys: canonical "<b64>.<b64>" or the pretty
  // full-JWT display form "TALUS-XXXXX-…-SS" (checksum-verified on decode).
  if (is_canonical(k) || is_pretty(k)) return { kind: 'talus' };

  const key_hash = await sha256_hex(normalize_store_key(raw_key));
  const hint = key_hint(raw_key);

  const mapped = await env.DB.prepare(
    'SELECT talus_license_key, license_id FROM store_keys WHERE store_key_hash = ?1',
  )
    .bind(key_hash)
    .first();

  if (mapped?.talus_license_key) {
    return {
      kind: 'store',
      license_key: mapped.talus_license_key,
      license_id: mapped.license_id,
    };
  }

  // Unknown or not-yet-fulfilled store key → record for the daemon/panel.
  await env.DB.prepare(
    `INSERT INTO pending_store_keys (key_hash, last_seen, attempts)
     VALUES (?1, ?2, 1)
     ON CONFLICT(key_hash) DO UPDATE SET
       last_seen = ?2,
       attempts = attempts + 1`,
  )
    .bind(key_hash, now_iso())
    .run();

  return { kind: 'unknown', key_hash, hint };
}

// The activation path calls this after `resolve_key` returned a store key.
// It feeds the translated Talus key through the normal activation flow.
export function translated_license_id(raw_key, resolved) {
  return resolved?.license_id ?? null;
}

// ── Lookup endpoint (panel/daemon diagnostics) ────────────────────────────
//
// POST /api/v1/redeem-lookup  { key } → tells the caller what the key is.
// Used by the customer-activation guide's "troubleshooting" step. Returns
// no secret material — only the classification and (when mapped) the
// license ID. NOTE: the translated Talus key is NOT returned here by design.

export async function handle_redeem_lookup(request, env) {
  if (!env.DB) return json({ success: false, message: 'missing DB' }, 500);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, message: 'invalid JSON' }, 400);
  }
  const key = str(body?.key);
  if (!key || key.length > 8192) {
    return json({ success: false, message: 'missing key' }, 400);
  }

  const resolved = await resolve_key(env, key.trim());
  if (resolved.kind === 'talus') {
    return json({ success: true, kind: 'talus' });
  }
  if (resolved.kind === 'store') {
    return json({
      success: true,
      kind: 'store',
      license_id: resolved.license_id,
      message: 'store key is mapped to a Talus license',
    });
  }
  return json({
    success: true,
    kind: 'unknown',
    message:
      'store key not fulfilled yet — the license is generated automatically within a few minutes',
  });
}

// ── Key normalization + display hint ──────────────────────────────────────

// Store keys are hashed after trimming and collapsing internal whitespace
// (defensive: mail clients sometimes wrap long keys).
export function normalize_store_key(key) {
  return String(key).trim().replace(/\s+/g, ' ');
}

// Short non-reversible display hint for the admin panel, e.g. "ab12…wxyz".
export function key_hint(key) {
  const k = normalize_store_key(key).replace(/\s+/g, '');
  if (k.length <= 10) return k;
  return `${k.slice(0, 4)}…${k.slice(-4)}`;
}
