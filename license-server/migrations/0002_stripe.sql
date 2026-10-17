-- ── Stripe: Managed Payments checkout + refund tracing ────────────────────
--
-- Run ONCE against the live database (Turso). SQLite has no
-- `ADD COLUMN IF NOT EXISTS`, so re-running the ALTERs fails harmlessly with
-- "duplicate column name" — the CREATE TABLE below is idempotent on its own.
--
--   cd license-server && npx wrangler d1 execute talus-licenses \
--     --remote --file=migrations/0002_stripe.sql
--   # or, against Turso:
--   turso db execute <turso-url> < <auth-token> ... migrations/0002_stripe.sql
--
-- Why these columns: a refund arrives as `charge.refunded`, which names only a
-- charge. Without `payment_intent` / `subscription_id` recorded at purchase
-- time there is no way to trace a charge back to the licence it paid for, and
-- a refunded customer would keep a working key.

ALTER TABLE orders ADD COLUMN customer_id TEXT;
ALTER TABLE orders ADD COLUMN subscription_id TEXT;
ALTER TABLE orders ADD COLUMN payment_intent TEXT;

-- Stripe resource IDs are globally unique, so they are indexed for the
-- refund-tracing lookups and for per-customer licence history in the admin
-- panel.
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