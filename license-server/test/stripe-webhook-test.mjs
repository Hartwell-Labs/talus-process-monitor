// Tests for the Stripe webhook authentication path — the one place where a
// bug means an attacker can mint himself an Enterprise licence.
//
//   node test/stripe-webhook-test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verify_stripe_signature,
  derive_expiry,
  encode_form,
  seats_from_session,
} from '../src/stripe-bridge.js';

const SECRET = 'whsec_test_0123456789abcdef';

async function hmac_sha256_hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function req(signature) {
  return new Request('https://example.test/api/v1/webhook/stripe', {
    method: 'POST',
    headers: { 'stripe-signature': signature },
  });
}

async function sign(body, secret = SECRET, timestamp = Math.floor(Date.now() / 1000)) {
  const v1 = await hmac_sha256_hex(secret, `${timestamp}.${body}`);
  return { header: `t=${timestamp},v1=${v1}`, timestamp, v1 };
}

// ── The happy path ────────────────────────────────────────────────────────

test('accepts a correctly signed payload', async () => {
  const body = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed' });
  const { header } = await sign(body);
  assert.equal(await verify_stripe_signature(req(header), body, SECRET), true);
});

// ── Forgery: the body is what matters ─────────────────────────────────────

test('rejects a valid signature over a different body', async () => {
  // The signature covers `${timestamp}.${raw_body}`. If verification ever
  // signs the parsed object instead of the raw bytes, an attacker can reorder
  // or inject fields freely — this is the test that catches that.
  const good = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed' });
  const tampered = JSON.stringify({
    id: 'evt_1',
    type: 'checkout.session.completed',
    data: { object: { subscription_id: 'sub_attacker' } },
  });
  const { header } = await sign(good);
  assert.equal(await verify_stripe_signature(req(header), tampered, SECRET), false);
});

test('rejects a signature that does not cover the timestamp', async () => {
  const body = '{"id":"evt_1"}';
  const { v1, timestamp } = await sign(body);
  const moved = timestamp + 1;
  assert.equal(
    await verify_stripe_signature(req(`t=${moved},v1=${v1}`), body, SECRET),
    false,
  );
});

// ── Wrong secret ──────────────────────────────────────────────────────────

test('rejects a payload signed with a different secret', async () => {
  const body = '{"id":"evt_1"}';
  const { header } = await sign(body, 'whsec_someone_elses_secret');
  assert.equal(await verify_stripe_signature(req(header), body, SECRET), false);
});

test('fail-closed when the server has no secret configured', async () => {
  // A misconfigured deploy must reject every webhook, not accept them all.
  const body = '{"id":"evt_1"}';
  const { header } = await sign(body);
  assert.equal(await verify_stripe_signature(req(header), body, undefined), false);
  assert.equal(await verify_stripe_signature(req(header), body, ''), false);
});

// ── Missing / malformed headers ───────────────────────────────────────────

test('rejects when the signature header is absent or empty', async () => {
  const body = '{"id":"evt_1"}';
  assert.equal(await verify_stripe_signature(req(''), body, SECRET), false);
  assert.equal(
    await verify_stripe_signature(new Request('https://example.test/'), body, SECRET),
    false,
  );
});

test('rejects a header with no usable v1 tag', async () => {
  const body = '{"id":"evt_1"}';
  const { timestamp } = await sign(body);
  for (const header of [
    `t=${timestamp}`,
    `t=${timestamp},v1=`,
    `t=${timestamp},v1=zzzz`, // not hex
    `t=${timestamp},v1=deadbeef`, // too short
    `v1=${'a'.repeat(64)}`, // no timestamp at all
    `t=notanumber,v1=${'a'.repeat(64)}`,
  ]) {
    assert.equal(
      await verify_stripe_signature(req(header), body, SECRET),
      false,
      `should reject: ${header}`,
    );
  }
});

// ── Replay window ─────────────────────────────────────────────────────────

test('rejects a captured request outside the 300 s tolerance', async () => {
  const body = '{"id":"evt_1"}';
  const old = Math.floor(Date.now() / 1000) - 301;
  const { header } = await sign(body, SECRET, old);
  assert.equal(await verify_stripe_signature(req(header), body, SECRET), false);
});

test('accepts a slightly skewed clock inside the tolerance', async () => {
  const body = '{"id":"evt_1"}';
  const skewed = Math.floor(Date.now() / 1000) - 120;
  const { header } = await sign(body, SECRET, skewed);
  assert.equal(await verify_stripe_signature(req(header), body, SECRET), true);
});

test('rejects a timestamp from the future beyond the tolerance', async () => {
  // Without this check an attacker could set t far ahead and keep a captured
  // signature valid indefinitely.
  const body = '{"id":"evt_1"}';
  const ahead = Math.floor(Date.now() / 1000) + 3600;
  const { header } = await sign(body, SECRET, ahead);
  assert.equal(await verify_stripe_signature(req(header), body, SECRET), false);
});

// ── Secret rotation ───────────────────────────────────────────────────────

test('accepts when any of several v1 tags matches', async () => {
  // Stripe sends one v1 per active secret during a rotation. The valid one may
  // be anywhere in the list — an implementation that keeps only the first or
  // only the last tag breaks the other case.
  const body = '{"id":"evt_1"}';
  const t = Math.floor(Date.now() / 1000);
  const good = await hmac_sha256_hex(SECRET, `${t}.${body}`);
  const bogus = '0'.repeat(64);

  for (const header of [
    `t=${t},v1=${good},v1=${bogus}`, // valid first
    `t=${t},v1=${bogus},v1=${good}`, // valid last
    `t=${t},v1=${bogus},v1=${good},v1=${bogus}`, // valid in the middle
  ]) {
    assert.equal(
      await verify_stripe_signature(req(header), body, SECRET),
      true,
      `should accept: ${header}`,
    );
  }
});

test('rejects when none of the v1 tags matches', async () => {
  const body = '{"id":"evt_1"}';
  const { header } = await sign(body);
  const t = header.slice(2, header.indexOf(','));
  const header_rotated = `${t},v1=${'0'.repeat(64)},v1=${'1'.repeat(64)}`;
  assert.equal(await verify_stripe_signature(req(header_rotated), body, SECRET), false);
});

// ── Subscription period → licence expiry ──────────────────────────────────

test('uses the billed period end when Stripe reports one', () => {
  const session = {
    subscription_details: { current_period_end: 1893456000 }, // 2030-01-01Z
  };
  assert.equal(derive_expiry(session, '2026-10-17T00:00:00Z'), '2030-01-01T00:00:00Z');
});

test('falls back to one year when the period end is missing', () => {
  assert.equal(derive_expiry({}, '2026-10-17T00:00:00Z'), '2027-10-17T00:00:00Z');
});

test('falls back to one year for a garbage period end', () => {
  const session = { subscription_details: { current_period_end: 'soon' } };
  assert.equal(derive_expiry(session, '2026-10-17T00:00:00Z'), '2027-10-17T00:00:00Z');
});

test('a January purchase does not expire on 1 January', () => {
  // A calendar-year boundary here would silently hand out a short licence.
  assert.equal(derive_expiry({}, '2027-01-15T12:00:00Z'), '2028-01-15T12:00:00Z');
});

// ── Form encoding ─────────────────────────────────────────────────────────
//
// Regression: a shallow encoder stringified `metadata` as the literal
// `[object Object]`, Stripe answered "Invalid object", and session creation
// failed in production with no local test covering it.

function decode_form(encoded) {
  const out = {};
  for (const pair of encoded.split('&')) {
    const i = pair.indexOf('=');
    out[decodeURIComponent(pair.slice(0, i))] = decodeURIComponent(pair.slice(i + 1));
  }
  return out;
}

test('encodes a nested metadata object rather than stringifying it', () => {
  const out = decode_form(encode_form({ metadata: { product: 'talus', tier: 'enterprise' } }));
  assert.deepEqual(out, {
    'metadata[product]': 'talus',
    'metadata[tier]': 'enterprise',
  });
  assert.ok(!encode_form({ metadata: { a: 'b' } }).includes('object'));
});

test('encodes line_items as an indexed array of objects', () => {
  const out = decode_form(
    encode_form({ line_items: [{ price: 'price_123', quantity: '1' }] }),
  );
  assert.deepEqual(out, { 'line_items[0][price]': 'price_123', 'line_items[0][quantity]': '1' });
});

test('encodes subscription_data.metadata two levels deep', () => {
  const out = decode_form(
    encode_form({ subscription_data: { metadata: { product: 'talus' } } }),
  );
  assert.deepEqual(out, { 'subscription_data[metadata][product]': 'talus' });
});

test('keeps the {CHECKOUT_SESSION_ID} placeholder intact', () => {
  // It must reach Stripe as braces so Stripe substitutes it, not as an
  // already-expanded literal.
  const out = decode_form(
    encode_form({ success_url: 'https://x.pl/a?session_id={CHECKOUT_SESSION_ID}' }),
  );
  assert.equal(out.success_url, 'https://x.pl/a?session_id={CHECKOUT_SESSION_ID}');
});

test('drops null and undefined instead of sending them as the string "null"', () => {
  const out = encode_form({ a: '1', b: null, c: undefined, d: '' });
  assert.ok(!out.includes('null'));
  assert.ok(!out.includes('undefined'));
  assert.equal(decode_form(out).a, '1');
});

test('percent-encodes values that would otherwise break the body', () => {
  const out = decode_form(encode_form({ url: 'https://x.pl/a?b=c&d=e' }));
  assert.equal(out.url, 'https://x.pl/a?b=c&d=e');
});

// ── Node count → seats ────────────────────────────────────────────────────
//
// Talus is sold per machine: one key is one seat. If this returns 1 for a
// fleet order, the customer pays for 10 machines and receives one licence.

test('reads the node count the checkout stamped into session metadata', () => {
  assert.equal(seats_from_session({ metadata: { node_count: '10' } }), 10);
  assert.equal(seats_from_session({ metadata: { node_count: '250' } }), 250);
});

test('a fleet order yields one seat per machine', () => {
  assert.equal(seats_from_session({ metadata: { node_count: '10' } }), 10);
  assert.equal(seats_from_session({ metadata: { node_count: '42' } }), 42);
});

test('a single purchase is one seat', () => {
  assert.equal(seats_from_session({ metadata: { node_count: '1' } }), 1);
  assert.equal(seats_from_session({ metadata: {} }), 1);
  assert.equal(seats_from_session({}), 1);
  assert.equal(seats_from_session({ metadata: { node_count: null } }), 1);
});

test('a missing or malformed node count never mints extra seats', () => {
  // The daemon signs one licence per seat, so anything unparseable must fall
  // back to 1 rather than to NaN, Infinity or a default that over-issues.
  for (const bad of ['', ' ', 'ten', '3.5', '-4', '0', 'NaN', '1e3', 'null']) {
    assert.equal(
      seats_from_session({ metadata: { node_count: bad } }),
      1,
      `should be 1 for ${JSON.stringify(bad)}`,
    );
  }
});

test('clamps an absurd node count instead of trusting it', () => {
  assert.equal(seats_from_session({ metadata: { node_count: '99999' } }), 500);
  assert.equal(seats_from_session({ metadata: { node_count: '999999' } }), 500);
});

test('node_count is a string, not a number, the way Stripe sends it', () => {
  // Stripe returns metadata values as strings. A number would mean something
  // upstream changed shape, so this asserts the real payload shape.
  assert.equal(seats_from_session({ metadata: { node_count: '10' } }), 10);
});