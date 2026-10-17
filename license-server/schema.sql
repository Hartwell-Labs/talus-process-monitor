-- ── Talus license server — D1 schema ──────────────────────────────────────
-- Applied with: npx wrangler d1 execute talus-licenses --remote --file=schema.sql

-- Issued licenses. Auto-registered on first activation ("first-seen"),
-- so the server becomes the source of truth for revocation from the first
-- activation onwards. Pre-activation revocation is handled by the
-- `revocations` table below.
-- max_seats is the ONLY enforced limit: it caps how many machines may activate
-- the licence. Talus is sold per machine, so one purchased key == one seat.
--
-- max_nodes is vestigial and deliberately no longer written. It exists in the
-- signed payload (process-monitor/src/license.rs) purely so the client can
-- detect a substituted payload, and no code path ever enforced it — a row
-- claiming "10 nodes" limited nothing. The column stays so existing rows keep
-- their shape and so the payload field remains legible if it is ever used
-- again; dropping it would mean a 12-step SQLite table rebuild on a live
-- payments database to delete a column nothing reads.
CREATE TABLE IF NOT EXISTS licenses (
  license_id  TEXT PRIMARY KEY,
  tier        TEXT NOT NULL,
  org         TEXT,
  features    TEXT,
  max_nodes   INTEGER NOT NULL DEFAULT 0,  -- legacy, unenforced, not written
  max_seats   INTEGER NOT NULL DEFAULT 1,  -- the enforced limit (machines)
  expires_at  TEXT,
  revoked     INTEGER NOT NULL DEFAULT 0,
  issued_at   TEXT NOT NULL
);

-- One row per (license, machine) activation. Re-activating the same machine
-- is idempotent: the existing row and token are returned unchanged.
CREATE TABLE IF NOT EXISTS activations (
  license_id   TEXT NOT NULL,
  machine_id   TEXT NOT NULL,
  hostname     TEXT,
  token        TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  seat_index   INTEGER NOT NULL,
  last_seen    TEXT,
  PRIMARY KEY (license_id, machine_id)
);

-- Explicit pre-activation revocations (license IDs killed before they were
-- ever seen by this server — e.g. leaked keys, refunded purchases).
CREATE TABLE IF NOT EXISTS revocations (
  license_id  TEXT PRIMARY KEY,
  reason      TEXT,
  revoked_at  TEXT NOT NULL
);

-- Fixed-window rate limiting (per machine + global). Rows are pruned by the
-- worker on each check, so this stays tiny.
CREATE TABLE IF NOT EXISTS rate_events (
  bucket TEXT NOT NULL,
  ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_events_ts ON rate_events (ts);

CREATE INDEX IF NOT EXISTS idx_activations_license ON activations (license_id);

-- ── Admin panel (worker-hosted UI, TOTP login) ─────────────────────────────

-- Web sessions for /admin. Only the SHA-256 hash of the session token is
-- stored, so a D1 snapshot cannot be replayed as a session. Expired rows are
-- pruned on each login.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- TOTP replay protection: a time-step counter that was already consumed by a
-- successful login can never be accepted again (within its validity window).
CREATE TABLE IF NOT EXISTS totp_used (
  counter INTEGER PRIMARY KEY,
  used_at TEXT NOT NULL
);

-- ── Store integrations (Polar / Gumroad / Lemon Squeezy) ───────────────────

-- One row per store purchase (created by the platform webhook). The issuer
-- daemon fulfills pending orders: it signs a Talus license locally and
-- records the store-key → license mapping. Refund webhooks revoke.
CREATE TABLE IF NOT EXISTS orders (
  store           TEXT NOT NULL,
  order_id        TEXT NOT NULL,
  product         TEXT,
  email           TEXT,
  seats           INTEGER NOT NULL DEFAULT 1,
  expires_at      TEXT,
  status          TEXT NOT NULL DEFAULT 'pending',
  store_key_hash  TEXT,
  store_key_hint  TEXT,
  license_id      TEXT,
  -- Stripe resource ids, recorded at purchase time. `charge.refunded` names
  -- only a charge, so these are what let a refund be traced back to the
  -- licence it paid for. NULL for the other stores.
  customer_id     TEXT,
  subscription_id TEXT,
  payment_intent  TEXT,
  created_at      TEXT NOT NULL,
  fulfilled_at    TEXT,
  PRIMARY KEY (store, order_id)
);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders (customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_subscription ON orders (subscription_id);
CREATE INDEX IF NOT EXISTS idx_orders_payment_intent ON orders (payment_intent);

-- Webhook delivery ledger. Stripe retries an event for up to 3 days; claiming
-- the event id before doing any work makes a redelivery a no-op. A handler
-- that throws deletes its own claim so the retry can actually retry.
CREATE TABLE IF NOT EXISTS stripe_events (
  event_id     TEXT PRIMARY KEY,
  type         TEXT NOT NULL,
  received_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stripe_events_type ON stripe_events (type);

-- The "translation dictionary": store key (hashed) → Talus license. The
-- Talus license key itself is public data (signed payload + signature), so
-- it can be returned to the customer at activation time.
CREATE TABLE IF NOT EXISTS store_keys (
  store              TEXT NOT NULL,
  store_key_hash     TEXT NOT NULL,
  license_id         TEXT NOT NULL,
  talus_license_key  TEXT,
  issued_at          TEXT NOT NULL,
  PRIMARY KEY (store, store_key_hash)
);
CREATE INDEX IF NOT EXISTS idx_store_keys_hash ON store_keys (store_key_hash);

-- Store keys presented at activation that have no mapping yet (customer was
-- faster than fulfillment, or the webhook never arrived). Purely diagnostic.
CREATE TABLE IF NOT EXISTS pending_store_keys (
  key_hash  TEXT PRIMARY KEY,
  last_seen TEXT NOT NULL,
  attempts  INTEGER NOT NULL DEFAULT 1
);

-- ── SHORT customer keys → signed JWT binding ──────────────────────────────
-- Short keys (TALUS-XXXXX-XXXXX-XXXXX-XXXXX) are random handles; the signed
-- JWT lives here, keyed by the SHA-256 of the normalized short key. Created
-- by admin/bind right after keygen issues a short-format license. Only the
-- hash of the short key is stored — the JWT itself is public data (signed).
CREATE TABLE IF NOT EXISTS short_keys (
  short_key_hash TEXT PRIMARY KEY,
  license_key    TEXT NOT NULL,
  license_id     TEXT NOT NULL,
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_short_keys_license ON short_keys(license_id);
