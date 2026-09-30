#!/usr/bin/env node
// ── Talus Issuer Daemon — automatic store-key fulfillment ─────────────────
//
// Runs on the OWNER'S MACHINE (the only place the Ed25519 signing key
// lives). Polls the license server for pending store orders (from the
// Polar / Gumroad / Lemon Squeezy webhooks) and fulfills each one:
//
//   1. sign a fresh Talus Enterprise license (talus-keygen issue --json)
//   2. pre-register it on the server (admin/register)
//   3. map the store key → Talus license (admin/fulfill)
//
// After step 3 the customer's store key is "translated": activation (or the
// /api/v1/redeem endpoint) returns the real Talus license automatically.
//
// Usage:
//   node scripts/issuer-daemon.mjs --once     # one pass (cron / systemd timer)
//   node scripts/issuer-daemon.mjs            # loop every 60 s
//   node scripts/issuer-daemon.mjs --fulfill-key <STORE_KEY> --store polar \
//        --order <ORDER_ID>                   # fulfill a specific order manually
//
// Secrets (never printed): ADMIN_TOKEN, signing key in
// ~/.secrets/talus/license-keys/. The store key arrives from the webhook in
// the customer's original email? No — the daemon issues the license and
// maps the key BY ORDER ID; the store_key value comes from the store's
// license-key API or the owner's store dashboard. When the store key is not
// known to the daemon, fulfillment happens on first activation instead
// (pending_store_keys): pass --fulfill-key with the key the customer tried.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..');

const SERVER = process.env.TALUS_LICENSE_SERVER
  ?? 'https://talus-license-server.metaforicmail.workers.dev';
const KEYGEN = process.env.TALUS_KEYGEN_BIN
  ?? join(REPO, 'license-keygen/target/release/talus-keygen');
const KEYS_DIR = process.env.TALUS_KEYGEN_DIR
  ?? join(process.env.HOME ?? '', '.secrets/talus/license-keys');

function load_token() {
  if (process.env.TALUS_ADMIN_TOKEN) return process.env.TALUS_ADMIN_TOKEN.trim();
  const file = join(process.env.HOME ?? '', '.secrets/talus/admin_token');
  if (existsSync(file)) return readFileSync(file, 'utf8').split(/\r?\n/)[0].trim();
  console.error('error: no admin token (set TALUS_ADMIN_TOKEN or create ~/.secrets/talus/admin_token)');
  process.exit(1);
}
const ADMIN = load_token();

// Polar API (organization token) — fetch the REAL customer-facing license key
// (POLAR-XXXX-…) that Polar generated for an order. Mapping that key (instead
// of a placeholder) lets the customer activate it directly: the server
// translates POLAR-key → TALUS license at activation/redeem time.
const POLAR_TOKEN_FILE = join(process.env.HOME ?? '', '.secrets/talus/polar_api_token');
function load_polar_token() {
  try { return readFileSync(POLAR_TOKEN_FILE, 'utf8').split(/\r?\n/)[0].trim(); }
  catch { return process.env.POLAR_API_TOKEN ?? null; }
}
const POLAR_TOKEN = load_polar_token();

async function fetch_polar_license_key(order) {
  if (!POLAR_TOKEN) return null;
  const org = order.polar_org_id ?? process.env.POLAR_ORG_ID ?? null;
  if (!org) return null;
  const res = await fetch(`https://api.polar.sh/v1/license-keys/?organization_id=${org}&limit=100`, {
    headers: { authorization: `Bearer ${POLAR_TOKEN}`, 'user-agent': 'talus-issuer/1' },
  });
  if (!res.ok) return null;
  const data = await res.json().catch(() => ({}));
  const items = data.items ?? [];
  // Prefer explicit order linkage; fall back to customer email; single-candidate fallback.
  let hit = items.find((k) => k.order_id === order.order_id);
  if (!hit && order.email) hit = items.find((k) => k.customer?.email === order.email || k.customer_email === order.email);
  if (!hit && items.length === 1) hit = items[0];
  return hit?.key ?? hit?.license_key ?? null;
}

function api(path, body) {
  return fetch(`${SERVER}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${ADMIN}`,
    },
    body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, data: await r.json().catch(() => ({})) }));
}

// Sign a fresh Talus Enterprise license with the owner's key.
// Short format: the customer gets TALUS-XXXXX-…, the JWT is bound server-side.
function issue_license(org, seats) {
  const out = execFileSync(
    KEYGEN,
    [
      'issue',
      '--tier', 'enterprise',
      '--organization', org,
      '--seats', String(seats),
      '--format', 'short',
      '--json',
    ],
    { env: { ...process.env, TALUS_KEYGEN_DIR: KEYS_DIR }, encoding: 'utf8' },
  );
  return JSON.parse(out);
}

// Fulfillment = issue + register (+ map the store key when one exists).
// For Polar orders there is no store key: a fresh short-format license is
// issued and bound, and the ORDER row records WHICH batch key was assigned
// (in store_key_hint) so the owner can paste it into the delivery email.
async function fulfill(order) {
  const org = order.email ?? `store-${order.store}`;
  console.log(`→ fulfilling ${order.store}/${order.order_id} (seats=${order.seats}, org=${org})`);

  const lic = issue_license(org, order.seats ?? 1);

  // Bind the short customer key to its signed JWT (required for activation).
  const bind = await api('/api/v1/admin/bind', {
    short_key: lic.license_key,
    license_key: lic.license_key_canonical,
    license_id: lic.license_id,
  });
  if (bind.status !== 200) throw new Error(`bind failed: ${bind.status}`);

  const reg = await api('/api/v1/admin/register', {
    license_id: lic.license_id,
    tier: lic.tier,
    org,
    features: lic.features,
    max_nodes: lic.max_nodes,
    max_seats: lic.seats,
    expires_at: lic.expires_at,
  });
  if (reg.status !== 200) throw new Error(`register failed: ${reg.status}`);

  let store_key = order.store_key;
  if (!store_key && order.store === 'polar') {
    const polar_key = await fetch_polar_license_key(order);
    if (polar_key) {
      store_key = polar_key;
      console.log(`  ↳ mapped real Polar key for ${order.order_id}`);
    } else {
      throw new Error('polar license key not available yet — order stays pending, will retry');
    }
  }
  const fulfilled = await api('/api/v1/admin/fulfill', {
    store: order.store,
    order_id: order.order_id,
    license_id: lic.license_id,
    talus_license_key: lic.license_key,
    store_key: store_key ?? `polar-order:${order.order_id}`,
  });
  if (fulfilled.status !== 200) throw new Error(`fulfill failed: ${fulfilled.status}`);

  console.log(`✓ ${order.store}/${order.order_id} → ${lic.license_id}`);
  if (!order.store_key) {
    console.log(`  ★ KEY for ${order.email ?? 'customer'}: ${lic.license_key}`);
  }
  return lic;
}

// ── Delivery: email the license key to the customer (Resend) ──────────────
// Reads RESEND_API_KEY from ~/pisanie/mailing/.env (chmod 600). Sends from
// the verified domain. delivery-log.json prevents duplicate mails across
// restarts; catchup_delivery() re-delivers orders fulfilled but never
// emailed (e.g. daemon crashed between fulfill and send).

const DELIVERY_LOG = join(process.env.HOME ?? '', '.secrets/talus/delivery-log.json');
const MAIL_ENV = join(process.env.HOME ?? '', 'pisanie/mailing/.env');
const MAIL_FROM = process.env.TALUS_MAIL_FROM ?? 'Hartwell Labs <important@hartwell-labs.pl>';

function read_resend_key() {
  try {
    for (const line of readFileSync(MAIL_ENV, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^RESEND_API_KEY=(.+)$/);
      if (m) return m[1].trim();
    }
  } catch { /* missing file */ }
  return null;
}

function load_delivery_log() {
  try { return JSON.parse(readFileSync(DELIVERY_LOG, 'utf8')); } catch { return {}; }
}

function save_delivery_log(log) {
  try { writeFileSync(DELIVERY_LOG, JSON.stringify(log, null, 1), { mode: 0o600 }); }
  catch (e) { console.error('delivery-log write failed:', e.message); }
}

async function send_license_email(order, lic) {
  const key = read_resend_key();
  if (!key) {
    console.error('  ✉ no RESEND_API_KEY — deliver manually. KEY:', lic.license_key);
    return false;
  }
  const to = order.email;
  const subject = 'Your Talus Enterprise license key';
  const text = [
    'Thank you for purchasing Talus Process Monitor (Enterprise).',
    '',
    `Your license key: ${lic.license_key}`,
    '',
    'Activate (Linux):',
    `  talus license activate ${lic.license_key}`,
    '',
    'One key = one seat/machine. To move machines: run',
    '`talus license deactivate` first, then activate again.',
    '',
    'Docs & downloads: https://hartwell-labs.pl/talus-process-monitor/',
    'Support: reply to this email (bartosz.osiej2007@gmail.com).',
    '',
    '— Hartwell Labs · hartwell-labs.pl',
  ].join('\n');
  const html = `<p>Thank you for purchasing <b>Talus Process Monitor (Enterprise)</b>.</p>
<p>Your license key:</p>
<p style="font-family:monospace;font-size:16px;background:#f4f4f5;padding:10px;border-radius:6px"><b>${lic.license_key}</b></p>
<p>Activate:</p>
<pre style="background:#f4f4f5;padding:10px;border-radius:6px">talus license activate ${lic.license_key}</pre>
<p>One key = one seat/machine. Moving machines: run <code>talus license deactivate</code> first.</p>
<p>Docs &amp; downloads: <a href="https://hartwell-labs.pl/talus-process-monitor/">hartwell-labs.pl/talus-process-monitor</a><br>
Support: reply to this email (bartosz.osiej2007@gmail.com).</p>
<p style="color:#8b93a3;font-size:12px">Hartwell Labs · hartwell-labs.pl</p>`;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from: MAIL_FROM, to, subject, text, html, reply_to: 'bartosz.osiej2007@gmail.com' }),
  });
  const rbody = await res.json().catch(() => ({}));
  if (res.status === 200 || res.status === 201) {
    console.log(`  ✉ license emailed to ${to} (id ${rbody.id ?? '?'})`);
    return true;
  }
  console.error(`  ✉ email failed (${res.status}): ${JSON.stringify(rbody).slice(0, 160)} — KEY: ${lic.license_key}`);
  return false;
}

async function deliver_license_email(order, lic) {
  if (!order.email || order.store_key) return; // keyless Polar orders only
  const log = load_delivery_log();
  const id = `${order.store}/${order.order_id}`;
  if (log[id]?.emailed && log[id]?.license_id === lic.license_id) return;
  // Throttle: failed-email retry at most every 30 min (log.at set on every attempt).
  const last = log[id] ? Date.parse(log[id].at) : 0;
  if (Number.isFinite(last) && Date.now() - last < 30 * 60 * 1000) return;
  const ok = await send_license_email(order, lic);
  log[id] = { license_id: lic.license_id, emailed: ok, at: new Date().toISOString() };
  save_delivery_log(log);
}

async function catchup_delivery() {
  const log = load_delivery_log();
  const { status, data } = await api('/api/v1/admin/orders', { status: 'fulfilled' });
  if (status !== 200) return;
  let registry;
  try { registry = JSON.parse(readFileSync(join(KEYS_DIR, 'issued_licenses.json'), 'utf8')); }
  catch { return; }
  const items = Array.isArray(registry) ? registry : registry.licenses ?? [];
  for (const o of data.orders ?? []) {
    if (o.store !== 'polar' || !o.email || !o.license_id) continue;
    const id = `${o.store}/${o.order_id}`;
    if (log[id]?.emailed) continue;
    const rec = items.find((x) => x.license_id === o.license_id);
    if (!rec) continue;
    const ok = await send_license_email(o, {
      license_id: o.license_id,
      license_key: rec.short_key ?? rec.license_key,
    });
    log[id] = { license_id: o.license_id, emailed: ok, at: new Date().toISOString(), catchup: true };
    save_delivery_log(log);
  }
}

// ── Modes ──────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

// Manual single-key fulfillment: the customer tried to activate before the
// mapping existed; --fulfill-key is the exact key they pasted.
const keyIdx = args.indexOf('--fulfill-key');
if (keyIdx >= 0) {
  const store_key = args[keyIdx + 1];
  const store = args[args.indexOf('--store') + 1] ?? 'manual';
  const order_id = args[args.indexOf('--order') + 1] ?? `manual-${Date.now()}`;
  const order = { store, order_id, seats: 1, store_key };
  fulfill(order)
    .then((lic) => {
      console.log(`\nTalus license ${lic.license_id} is now bound to that store key.`);
      console.log('The customer can activate again with their original store key.');
    })
    .catch((e) => { console.error('error:', e.message); process.exit(1); });
} else {
  // Poll loop: fulfill every pending order. Store keys (Gumroad) are mapped
  // directly; Polar orders carry NO store key — the customer is served by
  // the short-key batch (direct delivery), so the daemon only pre-registers
  // the order context and marks it 'fulfilled' with a reserved batch key.
  const once = args.includes('--once');
  const interval_s = Number(process.env.TALUS_ISSUER_INTERVAL ?? 60);

  for (;;) {
    try {
      await catchup_delivery();
      const { status, data } = await api('/api/v1/admin/orders', { status: 'pending' });
      if (status !== 200) throw new Error(`orders fetch failed: ${status}`);
      const pending = (data.orders ?? []).filter(
        (o) => o.store_key_hash || o.store_key || o.store === 'polar',
      );
      if (pending.length === 0) {
        console.log(`[${new Date().toISOString()}] no pending orders`);
      }
      for (const order of pending) {
        try {
          const lic = await fulfill(order);
          await deliver_license_email(order, lic);
        } catch (e) {
          console.error(`✗ ${order.store}/${order.order_id}: ${e.message}`);
        }
      }
    } catch (e) {
      console.error(`[${new Date().toISOString()}] ${e.message}`);
    }
    if (once) break;
    await new Promise((r) => setTimeout(r, interval_s * 1000));
  }
}
