# Runbook: Issuing the First Paid License

> Owner-only document. Walks through the full path: payment → issue →
> deliver → verify → track. All secrets live in `~/.secrets/talus/`
> and are **never** pasted into chat, issues, or the repo.

---

## 0. One-time setup checklist

- [ ] Signing key exists: `~/.secrets/talus/license-keys/signing_key.json`
      (created by `talus-keygen init`; if you ever re-run `init`, **all
      previous keys are void** — see SECURITY.md rotation runbook).
- [ ] Activation server is up: `scripts/health-check.sh` → `✓ healthy`.
- [ ] Admin panel TOTP is set up: `scripts/setup-totp.sh` (scan the QR with
      Google Authenticator; you'll need the code + auth code to sign in at
      the hosted panel `/admin`).
- [ ] Keygen is built: `cd license-keygen && cargo build --release`.
- [ ] Payment channel is chosen (Gumroad / Lemon Squeezy / manual transfer).
- [ ] Prices decided **outside** this repo (see `docs/pricing-tiers.md`).

Secrets map:

| Secret | Location | Used for |
|---|---|---|
| Ed25519 private key | `~/.secrets/talus/license-keys/signing_key.json` | signing licenses |
| Admin token | `~/.secrets/talus/admin_token` | `scripts/revoke-license.sh`, `scripts/list-activations.sh`, panel auth code |
| TOTP seed | `~/.secrets/talus/totp_secret` | login at the hosted `/admin` panel |
| Cloudflare API token | `~/.cloudflare_token` | deploying the worker |

---

## 1. Receive payment

Two options:

### Option A — manual (fine for the first sale)

1. Customer pays via bank transfer / PayPal / Stripe payment link.
2. You confirm the money arrived.

### Option B — store platforms with automatic fulfillment (implemented)

The server now speaks to **Polar**, **Gumroad** and **Lemon Squeezy**
directly. The customer buys on the platform and receives the platform's
license key; the "translation" to a real Talus license is automatic:

```
purchase on store ──► signed webhook ──► pending order (D1)
                                              │
                    issuer daemon (your machine, holds the signing key)
                    signs a Talus license + maps store-key → Talus key
                                              ▼
customer runs: talus license activate <STORE-KEY>   ← works directly!
```

Setup per platform (one-time):

1. Create the product (e.g. "Talus Enterprise (Single Seat)" — the seat
   count is parsed from the name: "3 Seat" → 3, "5 Seat" → 5).
2. Set the webhook URL to
   `https://talus-license-server.metaforicmail.workers.dev/api/v1/webhook/<platform>`
   and copy the platform's signing secret into a Worker secret:

   ```bash
   cd license-server && npx wrangler secret put POLAR_WEBHOOK_SECRET
   npx wrangler secret put GUMROAD_WEBHOOK_SECRET
   npx wrangler secret put LEMON_SQUEEZY_WEBHOOK_SECRET
   ```

3. Run the fulfillment daemon on your machine (loop or cron):

   ```bash
   node scripts/issuer-daemon.mjs          # loop every 60 s
   node scripts/issuer-daemon.mjs --once   # single pass (systemd timer)
   ```

Refunds on the platform automatically revoke the translated Talus license
and free all seats. If a customer tries to activate before the daemon has
fulfilled the order, activation returns a clear "retry in a few minutes"
message — fulfillment is automatic; nothing to do by hand.

---

## 2. Decide license parameters

From the purchase record:

| Parameter | Flag | Example |
|---|---|---|
| Organization | `--org` | `"Acme Corp"` |
| Term | `--expires` | `2027-09-17` (omit = perpetual) |
| Seats | `--seats` | `5` |
| Managed nodes | `--max-nodes` | `0` = unlimited |
| Tier | `--tier` | `enterprise` |

## 3. Issue the license

```bash
./scripts/issue-license.sh --org "Acme Corp" --seats 5 --expires 2027-09-17
```

The script signs the key locally **and pre-registers it on the server**
(`POST /api/v1/admin/register`), so the license is visible in the admin
panel the moment you issue it — before the customer even downloads Talus.
If the server is unreachable the key is still valid; it self-registers at
first activation.

Useful variants:

```bash
# Volume pack: 5 keys for one organization (seats are per key)
./scripts/issue-license.sh --org "Acme Corp" --seats 3 --count 5

# Skip server registration (key registers on first activation)
./scripts/issue-license.sh --org "Acme Corp" --offline
```

Output (locally only):

```
═══════════════════════════════════════════════════════════
  LICENSE KEY GENERATED
═══════════════════════════════════════════════════════════
  License ID:    TALUS-1234-ABCD-EF01
  ...
  │  LICENSE KEY                                        │
  └─────────────────────────────────────────────────────┘
```

The registry is appended at
`~/.secrets/talus/license-keys/issued_licenses.json` (0600, outside any
repository). **Copy the license key** — the full one-liner between the box
borders.

## 4. Deliver to the customer

Email template:

```
Subject: Your Talus Process Monitor Enterprise license

Hi <name>,

Thank you for your purchase! Your license key:

<KEY>

Activate it with:

    talus license activate <KEY>

Full activation guide: https://github.com/Hartwell-Labs/talus-process-monitor/blob/master/docs/customer-activation-guide.md

License details:
  License ID:  TALUS-XXXX-XXXX-XXXX
  Seats:       5
  Expires:     2027-09-17

If anything doesn't work, reply to this email.

Best,
Bartosz
```

Send the key **and** keep the order record (invoice no., amount, date,
license ID) in your private ledger — amounts never go into the repo.

## 5. Sanity-check the delivered key

From the repo root (uses the offline registry, not the server):

```bash
./license-keygen/target/release/talus-keygen verify "<KEY>"
```

Expect `✓ License key is VALID` with the right License ID and tier.

## 6. Watch the activation land

After the customer runs `talus license activate <KEY>`, check seats:

```bash
./scripts/list-activations.sh TALUS-XXXX-XXXX-XXXX
```

Expected: one row — their `machine_id`, hostname, `seat_index: 1`.

Or open the hosted panel and look there:
**<https://talus-license-server.metaforicmail.workers.dev/admin>** — sign in
with the auth code + the 6-digit TOTP code from Google Authenticator, use
**Lookup license** to see the seat, **Actions** for revoke / restore /
free-seat. (Local variant: `cd admin-panel && node server.mjs`.)

## 7. Ongoing operations

| Task | Command |
|---|---|
| List issued licenses | `talus-keygen list` |
| Check server health | `./scripts/health-check.sh` |
| List who activated | `./scripts/list-activations.sh <ID>` (or the `/admin` panel) |
| Refund / piracy → revoke | `./scripts/revoke-license.sh <ID> "reason"` or the panel |
| Free a stuck seat | panel → **free seat**, or `revoke-license.sh` (frees all seats) |

Revocation notes:

- Revoking removes all activations for that license; customers must get a
  replacement key if it was a mistake.
- Keys revoked **before** their first activation are held in the
  `revocations` table, so a leaked-but-never-used key is also dead on arrival.

---

## Escalation paths

- **Customer can't activate (seat limit, no old machine):** verify purchase,
  then `revoke-license.sh` + re-issue a new key with identical parameters.
- **Suspected key leak:** revoke, re-issue, note the old ID in the private
  ledger; do not publish the leaked ID.
- **Signing key compromise:** follow the rotation runbook in SECURITY.md —
  all keys become void; re-issue for paying customers free of charge.
