# Talus License Server

License activation backend for **Talus Process Monitor** — a Cloudflare Worker
with a D1 database on the **free tier (no credit card required)**.

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/activate` | POST | — | Verify signature, enforce expiry/revocation/seats, return activation token |
| `/api/v1/deactivate` | POST | token | Release the machine's seat (token required) |
| `/api/v1/health` | GET | — | Service status |
| `/admin` | GET | session / — | **Admin panel web UI** (login page when unauthenticated) |
| `/admin/login` | POST | auth code + TOTP | Two-factor login, sets an HttpOnly session cookie (12 h) |
| `/admin/logout` | POST | session | Destroy the session |
| `/admin/session-check` | GET | session / Bearer | Probe whether the current credentials are valid |
| `/api/v1/admin/stats` | GET | Bearer / session | Overview counters + recent activations + revocations |
| `/api/v1/admin/revoke` | POST | Bearer / session | Revoke a license (frees all seats) |
| `/api/v1/admin/unrevoke` | POST | Bearer / session | Undo a revocation |
| `/api/v1/admin/activations` | POST | Bearer / session | List activations for a license |
| `/api/v1/admin/free-seat` | POST | Bearer / session | Release one machine's seat |

## Artifact downloads (`download.hartwell-labs.pl`)

The same Worker serves the private R2 bucket at the download hostname:

| Path | Access | Cache |
|---|---|---|
| `/` | public | landing page, 5 min — lists both lines from the manifests |
| `/mit/<version>/<file>` | public | `public, immutable` — repeat downloads never reach R2 |
| `/enterprise/<version>/<file>` | `X-Talus-License: <key>` | `private, no-store` |

Enterprise gating verifies the Ed25519 signature **and** requires a row in
`licenses` that is not revoked or expired and has `tier = enterprise`. A signed
key that was never issued, was refunded, or is community therefore cannot
download the licensed binary. License keys travel in a header, never a URL.

The bucket has **no public domain and no r2.dev URL**. The Worker owns the
hostname, which is what makes the Enterprise line enforceable.

### Free-tier budget

R2 free tier: **10 GB storage, 1M Class A, 10M Class B per month**.

- MIT objects are immutable and edge-cached: a repeat download is served from
  Cloudflare's cache and costs **0 Class B** operations.
- Enterprise is deliberately uncached: one Class B per download.
- Uploads are the only Class A operations; the read path never lists the
  bucket.
- Publishing keeps **two versions per line** and the Worker refuses to
  finalize a manifest above **8 GiB**, leaving 2 GiB headroom. The Enterprise
  binary is ~25 MB, so the cap is many releases away.
- The Worker's own free allowance (100k requests/day) is the real ceiling for
  very high download volume, not R2.

### One-time setup

```bash
# 1. Enable R2 once in the dashboard (free tier, no card), then:
npx wrangler r2 bucket create talus-downloads
# 2. Deploy the Worker with the download route + R2 binding
npx wrangler deploy
```

### Release publishing (automatic)

Both release workflows publish at the end of a tag build. The Worker exposes
`PUT /publish/<line>/<version>/<file>` and `POST /publish/<line>/<version>/finalize`,
but only accepts a GitHub Actions OIDC token whose audience is `talus-downloads`,
whose `repository` is one of the two Talus repositories, and whose `ref` is the
matching `refs/tags/v<version>`. No Cloudflare API token or R2 key is stored in
GitHub.

After uploading the files, the workflow finalizes the manifest. That is also
when retention runs: the version that falls out of the two-version window is
deleted from R2 and the landing page cache is purged.

`scripts/r2-publish.sh` remains as a manual fallback (for example, when
restoring an old release), using the same manifest format.

Smoke test:

```bash
curl -fI https://download.hartwell-labs.pl/mit/0.8.4/talus-monitor
curl -fI -H "X-Talus-License: $TALUS_LICENSE" \
  https://download.hartwell-labs.pl/enterprise/0.8.4/talus-monitor-enterprise
```

## Client contract (from `process-monitor/src/license.rs`)

```json
// POST /api/v1/activate
{ "license_key": "<payload>.<signature>", "machine_id": "T-...", "hostname": "...", "version": "0.7.0" }
// → 200 { "success": true, "token": "...", "expires_at": "2027-01-01T00:00:00Z", "tier": "enterprise", "message": "..." }

// POST /api/v1/deactivate
{ "license_id": "TALUS-XXXX-XXXX-XXXX", "token": "..." }
// → 200 { "success": true, "message": "license deactivated — seat released" }
```

## Security model

- **Public-key only.** The worker holds the Ed25519 *public* key (in
  `wrangler.toml [vars]` — same key as embedded in the binary). The private
  signing key never leaves the owner's machine.
- **Server-side signature verification** of every license key before any
  state is created.
- **Seats enforced in D1** (`max_seats`, default from the signed payload's
  `seat_count`); same-machine re-activation is idempotent.
- **Revocation**: `licenses.revoked` flag + `revocations` table for keys
  revoked before first activation; revocation deletes all activations.
- **First-seen auto-registration**: licenses are registered on first
  activation, so `talus-keygen issue` needs no server round-trip.
- **Rate limiting**: 5 activation attempts / 5 min per machine, plus a loose
  global abuse brake (fixed window in D1).
- **No secrets in the repo**: `ADMIN_TOKEN` and `TOTP_SECRET` are Worker
  secrets (`wrangler secret put`). Never committed, never logged.

## Admin panel (web UI, TOTP)

The worker serves the admin panel itself at **`/admin`** — no local process
needed. Login is two-factor:

1. **Auth code** — the `ADMIN_TOKEN` value (possession factor)
2. **TOTP** — 6-digit code from Google Authenticator or any RFC 6238 app
   (something you have)

A successful login sets an **HttpOnly, Secure, SameSite=Strict** session
cookie valid for 12 hours (only the SHA-256 hash of the session token is
stored in D1). TOTP time-steps are single-use — a captured code cannot be
replayed. Failed logins are rate-limited (10 / 5 min).

One-time setup (owner only; displays the QR code exactly once):

```bash
./scripts/setup-totp.sh            # generate + upload secret + show QR
./scripts/setup-totp.sh --rotate   # later: invalidate all previous codes
```

The same panel also exists as a **local variant** in `admin-panel/` (token
stays on your machine, talks to the worker through a Node proxy) — see that
directory's README. All `/api/v1/admin/*` endpoints additionally accept the
plain bearer token, so CLI scripts and the local panel keep working.

## Deploy (free tier, no credit card)

```bash
cd license-server
npm install

# 1. Create the D1 database and copy its database_id into wrangler.toml
npx wrangler d1 create talus-licenses

# 2. Apply the schema (remote)
npx wrangler d1 execute talus-licenses --remote --file=schema.sql

# 3. Set the admin secrets
npx wrangler secret put ADMIN_TOKEN

# 4. Deploy
npx wrangler deploy

# 5. Set up the TOTP login for /admin (owner-only, shows the QR once)
../scripts/setup-totp.sh
```

The worker URL is printed at the end of `wrangler deploy`
(e.g. `https://talus-license-server.<account>.workers.dev`). That URL is the
default activation server baked into the Talus binary
(`activation_server_url()` in `process-monitor/src/license.rs`); users can
override it with `TALUS_LICENSE_SERVER`.
