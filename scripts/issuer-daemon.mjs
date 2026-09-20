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
import { existsSync, readFileSync } from 'node:fs';
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

  const fulfilled = await api('/api/v1/admin/fulfill', {
    store: order.store,
    order_id: order.order_id,
    license_id: lic.license_id,
    talus_license_key: lic.license_key,
    store_key: order.store_key ?? `polar-order:${order.order_id}`, // placeholder for keyless stores
  });
  if (fulfilled.status !== 200) throw new Error(`fulfill failed: ${fulfilled.status}`);

  console.log(`✓ ${order.store}/${order.order_id} → ${lic.license_id}`);
  if (!order.store_key) {
    console.log(`  ★ DELIVER THIS KEY to ${order.email ?? 'customer'}: ${lic.license_key}`);
  }
  return lic.license_id;
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
    .then((id) => {
      console.log(`\nTalus license ${id} is now bound to that store key.`);
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
          await fulfill(order);
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
