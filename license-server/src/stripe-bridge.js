// ── Stripe bridge — Managed Payments checkout + webhook → pending order ───
//
// Stripe is the only store that settles money itself: the customer never
// receives a store key. Instead the webhook records a `pending` row in
// `orders` (store = 'stripe') and the issuer daemon fulfills it exactly like
// a Polar/Gumroad order. That keeps one fulfillment path for every channel.
//
// Two endpoints:
//
//   POST /api/v1/checkout-session     → create a Managed Payments session
//   POST /api/v1/webhook/stripe       → checkout.session.completed etc.
//
// Stripe identifiers we must be able to re-find later are persisted, not
// discarded: customer_id (so a repeat buyer is recognised) and
// subscription_id (so a cancellation can revoke the licence that subscription
// paid for). Both live as columns on the existing `orders` row — the domain
// model the issuer daemon already reads.
//
// Security notes:
//   * The webhook is authenticated by Stripe's `Stripe-Signature` header
//     (HMAC-SHA256 over `${timestamp}.${raw_body}`), compared in constant
//     time, with a 300 s clock-skew tolerance so a captured request cannot be
//     replayed forever.
//   * `STRIPE_SECRET_KEY` is a Worker secret. It never enters this module's
//     responses, and no handler echoes an upstream error body back to the
//     caller — Stripe error payloads can quote the request.
//   * Event IDs are recorded in `stripe_events` before the order row is
//     written, so a redelivery (Stripe retries for up to 3 days) is a no-op.

const MAX_WEBHOOK_BODY = 64 * 1024;
const SIGNATURE_TOLERANCE_SECONDS = 300;
const STORE = 'stripe';

// Fleet pricing starts here: below it the 30 USD/node rate does not apply.
const FLEET_MIN_NODES = 10;

// Blueprint-defined API version. Left empty by default (account default is
// what the webhook endpoint itself uses, and Managed Payments was verified
// working on it); override with STRIPE_API_VERSION to pin a preview release.
const DEFAULT_API_VERSION = '';

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

function now_iso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ── Stripe signature verification ─────────────────────────────────────────

async function hmac_sha256_hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
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

function timing_safe_equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Stripe-Signature: `t=1750000000,v1=<hex>,v1=<hex>` — one v1 tag per active
// secret while a rotation is in flight, so every v1 must be collected rather
// than overwritten by the last one. Rejection requires that NONE matches.
function parse_signature_header(header) {
  const raw = String(header ?? '');
  let timestamp = null;
  const signatures = [];

  for (const part of raw.split(',')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key === 't') {
      const parsed = Number.parseInt(value, 10);
      if (Number.isFinite(parsed)) timestamp = parsed;
    } else if (key === 'v1') {
      // A single tag may hold several space-separated hex digests.
      for (const sig of value.split(/\s+/)) {
        if (/^[0-9a-f]{64}$/i.test(sig)) signatures.push(sig);
      }
    }
  }

  if (timestamp === null || signatures.length === 0) return null;
  return { timestamp, signatures };
}

// Fail closed: no configured secret, no header, stale timestamp, or no tag
// that matches → false. Never returns a reason, so a caller cannot use the
// response to probe the secret.
export async function verify_stripe_signature(request, raw_body, secret) {
  if (!secret) return false;
  const parsed = parse_signature_header(request.headers.get('stripe-signature'));
  if (!parsed) return false;

  const skew = Math.abs(Math.floor(Date.now() / 1000) - parsed.timestamp);
  if (skew > SIGNATURE_TOLERANCE_SECONDS) return false;

  const expected = await hmac_sha256_hex(
    String(secret).trim(),
    `${parsed.timestamp}.${raw_body}`,
  );
  return parsed.signatures.some((provided) => timing_safe_equal(provided, expected));
}

// ── Stripe REST helper (form-encoded, no SDK) ─────────────────────────────

function stripe_headers(env) {
  const headers = {
    authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
    'content-type': 'application/x-www-form-urlencoded',
  };
  const version = str(env.STRIPE_API_VERSION) ?? DEFAULT_API_VERSION;
  if (version) headers['stripe-version'] = version;
  return headers;
}

// Flattens a nested object into Stripe's bracketed form encoding:
//
//   { metadata: { tier: 'enterprise' } }
//     → metadata[tier]=enterprise
//   { line_items: [{ price: 'p', quantity: 1 }] }
//     → line_items[0][price]=p&line_items[0][quantity]=1
//
// Recursion is not cosmetic: Stripe rejects a nested object that arrives as
// the literal string `[object Object]`, which is precisely what a shallow
// encoder sends.
function flatten(prefix, value, parts) {
  if (value === undefined || value === null) return;

  if (Array.isArray(value)) {
    value.forEach((item, i) => flatten(`${prefix}[${i}]`, item, parts));
  } else if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      flatten(`${prefix}[${k}]`, v, parts);
    }
  } else {
    parts.push(`${encodeURIComponent(prefix)}=${encodeURIComponent(value)}`);
  }
}

export function encode_form(flat) {
  const parts = [];
  for (const [key, value] of Object.entries(flat)) flatten(key, value, parts);
  return parts.join('&');
}

async function stripe_call(env, method, path, form = {}) {
  const verb = method.toUpperCase();
  const init = { method: verb, headers: stripe_headers(env) };

  // A GET carrying a body is rejected by the runtime before the request ever
  // leaves the isolate, which surfaced as a lookup that silently "not found".
  // Only the verbs that need parameters get one.
  if (verb !== 'GET' && verb !== 'HEAD') {
    init.body = encode_form(form);
  }

  const res = await fetch(`https://api.stripe.com/v1/${path}`, init);
  const text = await res.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!res.ok) {
    // Keep the upstream message for the server log only; the caller gets a
    // generic failure so a Stripe error body cannot echo our own request.
    const message =
      payload?.error?.message ?? `stripe http ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  return payload;
}

// ── Checkout session creation (the page calls this before rendering) ──────

// Two tiers, each with its own server-side price:
//
//   single  1 machine                STRIPE_PRICE_ID
//   fleet   10 machines or more     STRIPE_FLEET_PRICE_ID, 30 USD/node/year
//
// The price is server-side configuration, never client input — otherwise
// anyone could point the button at a cheaper plan. The only client-supplied
// value is the node count, and it can only select a tier and a quantity within
// that tier, never the price.
//
// The 10-node floor is enforced here because Stripe has no native minimum
// quantity on a Price: `transform_quantity` accepts only `divide_by` and
// `round`, and graduated pricing (`tiering_config`) is rejected by this
// account. Rejecting is better than silently bumping — a customer who typed 3
// should be told, not billed for 10.
export async function handle_create_checkout_session(request, env) {
  if (!env.STRIPE_SECRET_KEY) {
    return json({ success: false, message: 'stripe not configured' }, 503);
  }

  let body = {};
  try {
    const text = await request.text();
    if (text) {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object') body = parsed;
    }
  } catch {
    // An empty or malformed body is not fatal: it just means "single node".
    body = {};
  }

  const tier = body.tier === 'fleet' ? 'fleet' : 'single';
  const price_id = str(
    tier === 'fleet' ? env.STRIPE_FLEET_PRICE_ID : env.STRIPE_PRICE_ID,
  );
  if (!price_id) {
    return json(
      { success: false, message: `${tier} price not configured` },
      503,
    );
  }

  const requested = Number(body.nodes);
  const min_nodes = tier === 'fleet' ? FLEET_MIN_NODES : 1;
  let nodes = min_nodes;

  if (Number.isFinite(requested)) {
    if (!Number.isInteger(requested)) {
      return json(
        { success: false, message: 'nodes must be a whole number' },
        400,
      );
    }
    if (requested < min_nodes) {
      return json(
        {
          success: false,
          message:
            tier === 'fleet'
              ? `fleet licences start at ${FLEET_MIN_NODES} nodes`
              : 'single licence is one node — use tier "fleet" for more',
          min_nodes: min_nodes,
        },
        400,
      );
    }
    if (requested > MAX_SEATS_PER_ORDER) {
      return json(
        {
          success: false,
          message: `for more than ${MAX_SEATS_PER_ORDER} nodes contact us`,
        },
        400,
      );
    }
    nodes = requested;
  }

  const origin = new URL(request.url).origin;
  const success_url =
    str(env.STRIPE_SUCCESS_URL) ?? `${origin}/talus/aktywacja`;
  const cancel_url = str(env.STRIPE_CANCEL_URL) ?? `${origin}/talus`;

  let customer_id = null;
  const provided_email = str(env.STRIPE_PRESET_EMAIL);
  if (provided_email) customer_id = await find_or_create_customer(env, provided_email);

  try {
    const session = await stripe_call(env, 'POST', 'checkout/sessions', {
      mode: 'subscription',
      line_items: [{ price: price_id, quantity: String(nodes) }],
      'managed_payments[enabled]': 'true',
      success_url: `${success_url}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url,
      // VAT needs the billing address; Managed Payments needs it for the
      // indirect-tax liability it takes on.
      billing_address_collection: 'required',
      metadata: { product: 'talus', tier, node_count: String(nodes) },
      subscription_data: {
        metadata: { product: 'talus', tier, node_count: String(nodes) },
      },
      ...(customer_id ? { customer: customer_id } : {}),
    });

    return json({
      success: true,
      session_id: session.id,
      url: session.url,
      tier,
      nodes,
      customer_id: customer_id ?? null,
      publishable_key: str(env.STRIPE_PUBLISHABLE_KEY) ?? null,
    });
  } catch (err) {
    return json(
      { success: false, message: `checkout session failed: ${String(err.message)}` },
      502,
    );
  }
}

// Repeat buyers should land on the same Customer object so their licence
// history is one row's worth of subscriptions instead of scattered identities.
// Best-effort: a failure here must not block the sale, so the caller falls
// back to letting Stripe create the customer at checkout.
async function find_or_create_customer(env, email) {
  try {
    const existing = await stripe_call(env, 'GET', `customers?email=${encodeURIComponent(email)}`);
    const hit = existing?.data?.find(
      (c) => (c.email ?? '').toLowerCase() === email.toLowerCase(),
    );
    if (hit) return hit.id;
    const created = await stripe_call(env, 'POST', 'customers', {
      email,
      description: 'Talus Process Monitor — Enterprise',
      metadata: { product: 'talus', tier: 'enterprise' },
    });
    return created?.id ?? null;
  } catch {
    return null;
  }
}

// Read-only: the activation page uses this to confirm a session was actually
// paid before it shows the customer a licence-key form. Exposes only the
// fields the page needs — never the full session payload.
export async function handle_checkout_status(request, env, session_id) {
  if (!env.STRIPE_SECRET_KEY || !session_id) {
    return json({ success: false, message: 'not found' }, 404);
  }
  if (!/^cs_[A-Za-z0-9_]{8,}$/.test(session_id)) {
    return json({ success: false, message: 'not found' }, 404);
  }
  try {
    const session = await stripe_call(env, 'GET', `checkout/sessions/${session_id}`);
    return json({
      success: true,
      status: session?.status ?? null,
      payment_status: session?.payment_status ?? null,
      customer_email: str(session?.customer_details?.email),
      customer_id: str(session?.customer),
      subscription_id: str(session?.subscription),
      amount_total: session?.amount_total ?? null,
      currency: str(session?.currency),
    });
  } catch {
    return json({ success: false, message: 'not found' }, 404);
  }
}

// ── Schema bootstrap ──────────────────────────────────────────────────────

// Storage is Turso, whose auth token lives only as a Worker secret — there is
// no local migration runner that can reach it, and the columns this module
// writes are not in the schema that predates Stripe. So the Worker applies
// them itself, once per isolate.
//
// Why this is safe rather than a hole: the statements are a literal with no
// request input anywhere in it, every one is additive or IF NOT EXISTS, and
// the result is memoised per isolate so the check runs at most once per cold
// start. A failure is recorded and retried on the next isolate rather than
// being swallowed — a webhook that cannot write its order must fail loudly.
let stripe_schema_ready = false;
let stripe_schema_error = null;

export async function ensure_stripe_schema(db) {
  if (stripe_schema_ready) return true;
  if (stripe_schema_error) return false;

  try {
    const { results } = await db.prepare('PRAGMA table_info(orders)').all();
    const existing = new Set((results ?? []).map((c) => c.name));

    // SQLite has no `ADD COLUMN IF NOT EXISTS`, hence the explicit check.
    for (const column of ['customer_id', 'subscription_id', 'payment_intent']) {
      if (existing.has(column)) continue;
      await db.prepare(`ALTER TABLE orders ADD COLUMN ${column} TEXT`).run();
    }

    await db.batch([
      db
        .prepare('CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders (customer_id)'),
      db
        .prepare('CREATE INDEX IF NOT EXISTS idx_orders_subscription ON orders (subscription_id)'),
      db
        .prepare('CREATE INDEX IF NOT EXISTS idx_orders_payment_intent ON orders (payment_intent)'),
      db
        .prepare(
          `CREATE TABLE IF NOT EXISTS stripe_events (
             event_id TEXT PRIMARY KEY,
             type TEXT NOT NULL,
             received_at TEXT NOT NULL
           )`,
        ),
      db.prepare('CREATE INDEX IF NOT EXISTS idx_stripe_events_type ON stripe_events (type)'),
    ]);

    stripe_schema_ready = true;
    return true;
  } catch (err) {
    stripe_schema_error = String(err);
    return false;
  }
}

// ── Webhook ───────────────────────────────────────────────────────────────

// POST /api/v1/webhook/stripe → verified, idempotent order row.
export async function handle_stripe_webhook(request, env, db) {
  if (!db) return json({ success: false, message: 'missing DB' }, 500);
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return json({ success: false, message: 'invalid signature' }, 401);
  }

  const raw_body = await request.text();
  if (raw_body.length > MAX_WEBHOOK_BODY) {
    return json({ success: false, message: 'body too large' }, 413);
  }

  const ok = await verify_stripe_signature(
    request,
    raw_body,
    env.STRIPE_WEBHOOK_SECRET,
  );
  if (!ok) {
    return json({ success: false, message: 'invalid signature' }, 401);
  }

  let event;
  try {
    event = JSON.parse(raw_body);
  } catch {
    return json({ success: false, message: 'invalid JSON' }, 400);
  }
  const event_id = str(event?.id);
  const type = str(event?.type);
  if (!event_id || !type) {
    return json({ success: false, message: 'unrecognized payload' }, 400);
  }

  // Stripe retries for up to 3 days; the same event_id can arrive many times.
  // Claim it first so the work below happens at most once.
  const claimed = await claim_event(db, event_id, type);
  if (!claimed) {
    return json({ success: true, message: 'already processed' });
  }

  const object = event?.data?.object ?? {};

  try {
    switch (type) {
      case 'checkout.session.completed':
      case 'checkout.session.async_payment_succeeded':
        return await record_paid_session(db, object);

      case 'checkout.session.async_payment_failed':
        return await mark_session_failed(db, object);

      case 'charge.refunded':
        return await record_refund(db, object);

      default:
        // Not an error: Stripe sends whatever is enabled on the endpoint and we
        // may not care. Claimed above, so a redelivery is still a no-op.
        return json({ success: true, message: `ignored ${type}` });
    }
  } catch (err) {
    // Roll the claim back so Stripe's retry can actually retry.
    await release_event(db, event_id);
    return json({ success: false, message: `handler error: ${String(err)}` }, 500);
  }
}

// INSERT OR IGNORE → true only for the delivery that won the race.
async function claim_event(db, event_id, type) {
  const res = await db
    .prepare(
      `INSERT INTO stripe_events (event_id, type, received_at) VALUES (?1, ?2, ?3)
       ON CONFLICT(event_id) DO NOTHING`,
    )
    .bind(event_id, type, now_iso())
    .run();
  return (res?.meta?.changes ?? 0) > 0;
}

async function release_event(db, event_id) {
  await db
    .prepare('DELETE FROM stripe_events WHERE event_id = ?1')
    .bind(event_id)
    .run();
}

// How many machines a purchase covers. Talus is sold per machine: one seat is
// one host that can activate, so a fleet order must carry its node count all
// the way to the daemon or the customer pays for 10 keys and receives one.
//
// The count travels in session metadata (`node_count`), set server-side when
// the session is created and by hand on the Payment Link. It is clamped anyway:
// the daemon signs one licence per seat, so an inflated value would mint keys
// nobody paid for, and a typo in the Dashboard would not be caught by anything
// downstream. Absent metadata means a single-key purchase.
const MAX_SEATS_PER_ORDER = 500;

export function seats_from_session(session) {
  const raw = str(session?.metadata?.node_count);
  if (!raw) return 1;
  // Digits only, no sign and no surrounding space. `parseInt` on its own is
  // not enough: it maps '3.5' to 3, which would silently shorten a fleet order
  // instead of rejecting it.
  if (!/^\d+$/.test(raw)) return 1;
  const n = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(n) || n < 1) return 1;
  return Math.min(n, MAX_SEATS_PER_ORDER);
}

// A paid Checkout Session becomes a pending order — exactly the row the other
// stores produce. `orders.order_id` is the session id, which is stable and
// unique per purchase.
async function record_paid_session(db, session) {
  const order_id = str(session?.id);
  if (!order_id) return json({ success: false, message: 'missing session id' }, 400);

  const email =
    str(session?.customer_details?.email) ?? str(session?.customer_email);
  const customer_id = str(session?.customer);
  const subscription_id = str(session?.subscription);
  const payment_intent = str(session?.payment_intent);
  const now = now_iso();

  const seats = seats_from_session(session);
  const expires_at = derive_expiry(session, now);

  await db
    .prepare(
      `INSERT INTO orders
         (store, order_id, product, email, seats, expires_at, status,
          customer_id, subscription_id, payment_intent, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?9, ?10)
       ON CONFLICT(store, order_id) DO UPDATE SET
         email           = COALESCE(excluded.email, orders.email),
         customer_id     = COALESCE(excluded.customer_id, orders.customer_id),
         subscription_id = COALESCE(excluded.subscription_id, orders.subscription_id),
         payment_intent  = COALESCE(excluded.payment_intent, orders.payment_intent)`,
    )
    .bind(
      STORE,
      order_id,
      'Talus Enterprise',
      email,
      seats,
      expires_at,
      customer_id,
      subscription_id,
      payment_intent,
      now,
    )
    .run();

  return json({
    success: true,
    message: 'order recorded',
    order_id,
    customer_id,
    subscription_id,
  });
}

async function mark_session_failed(db, session) {
  const order_id = str(session?.id);
  if (!order_id) return json({ success: false, message: 'missing session id' }, 400);
  await db
    .prepare(
      `INSERT INTO orders (store, order_id, product, status, created_at)
       VALUES (?1, ?2, ?3, 'payment_failed', ?4)
       ON CONFLICT(store, order_id) DO UPDATE SET status = 'payment_failed'`,
    )
    .bind(STORE, order_id, 'Talus Enterprise', now_iso())
    .run();
  return json({ success: true, message: 'payment failure recorded' });
}

// `charge.refunded` carries only the charge. Walk back through the invoice to
// the session that created it — a refund must revoke the licence even when the
// customer never returns to the site.
async function record_refund(db, charge) {
  const charge_id = str(charge?.id);
  if (!charge_id) return json({ success: false, message: 'missing charge id' }, 400);

  const order_id = await find_order_by_charge(db, charge);
  if (!order_id) {
    return json({ success: true, message: 'refund seen, no matching order' });
  }

  const row = await db
    .prepare('SELECT license_id, status FROM orders WHERE store = ?1 AND order_id = ?2')
    .bind(STORE, order_id)
    .first();
  if (!row) return json({ success: true, message: 'refund seen, no matching order' });
  if (row.status === 'refunded') {
    return json({ success: true, message: 'already refunded' });
  }

  const stmts = [
    db
      .prepare("UPDATE orders SET status = 'refunded' WHERE store = ?1 AND order_id = ?2")
      .bind(STORE, order_id),
  ];
  if (row.license_id) {
    stmts.push(
      db.prepare('UPDATE licenses SET revoked = 1 WHERE license_id = ?1').bind(row.license_id),
      db.prepare('DELETE FROM activations WHERE license_id = ?1').bind(row.license_id),
      db
        .prepare(
          `INSERT INTO revocations (license_id, reason, revoked_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(license_id) DO UPDATE SET reason = excluded.reason, revoked_at = excluded.revoked_at`,
        )
        .bind(row.license_id, `stripe refund (${charge_id})`, now_iso()),
    );
  }
  await db.batch(stmts);
  return json({ success: true, message: 'refund processed — license revoked' });
}

// The charge references `payment_intent`; the order it belongs to is recorded
// at purchase time under either that id or the subscription id, so a refund
// can always be traced back to the licence it paid for.
async function find_order_by_charge(db, charge) {
  const payment_intent = str(charge?.payment_intent);
  if (!payment_intent) return null;

  for (const [column, value] of [
    ['payment_intent', payment_intent],
    ['subscription_id', payment_intent],
  ]) {
    const row = await db
      .prepare(`SELECT order_id FROM orders WHERE store = ?1 AND ${column} = ?2`)
      .bind(STORE, value)
      .first();
    if (row) return row.order_id;
  }
  return null;
}

// A yearly subscription is valid for a year from the payment, not to the end
// of the calendar year. Stripe reports the billed period on the line item;
// when it is absent (async payment, test clock skew) fall back to one year.
export function derive_expiry(session, now) {
  const period_end =
    session?.subscription_details?.current_period_end ??
    session?.line_items?.data?.[0]?.current_period_end;
  if (Number.isFinite(period_end)) {
    return new Date(period_end * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  const d = new Date(now);
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}