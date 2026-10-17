# Talus Admin Panel (local variant)

> **Prefer the hosted panel?** The worker serves the same UI at
> `https://lic.hartwell-labs.pl/admin`, protected by
> auth code + TOTP (Google Authenticator). This local variant exists for
> working strictly from your own machine, without browser sessions.

Local web UI for administering the Talus license server — run it on your
machine, point your browser at `http://localhost:8787`.

The panel talks to the **production activation worker** through a tiny local
proxy. The `ADMIN_TOKEN` stays on this machine (loaded from
`~/.secrets/talus/admin_token` or `TALUS_ADMIN_TOKEN`) — the browser never
sees it, nothing secret is committed, and the panel itself can be published
safely.

## Features

- **Overview** — licenses seen, active seats, seats added in the last 7 days,
  revoked count, live server health dot
- **Recent activations** — last 10 seats with org, tier, machine fingerprint,
  hostname and timestamp
- **Lookup license** — list every seat of a license, free a stuck seat with
  one click
- **Actions** — revoke (blocks the key everywhere and frees all seats),
  restore (undo revoke), free a single seat — all with confirmation prompts
- Auto-refresh every 30 s

## Run

```bash
cd admin-panel
node server.mjs
# → http://127.0.0.1:8787
```

Optional overrides:

```bash
TALUS_PORT=9000 node server.mjs                          # different port
TALUS_ADMIN_TOKEN_FILE=/path/to/token node server.mjs    # custom token file
TALUS_UPSTREAM=https://<your-worker>.workers.dev node server.mjs
```

No dependencies — Node 18+ (built-in `fetch`).

## Endpoints used (via the local proxy)

| Panel action | Worker endpoint |
|---|---|
| Overview + tables | `GET /api/v1/admin/stats` |
| Lookup license | `POST /api/v1/admin/activations` |
| Revoke / Restore | `POST /api/v1/admin/revoke` / `unrevoke` |
| Free seat | `POST /api/v1/admin/free-seat` |
| Health dot | `GET /api/v1/health` |

All admin endpoints require the bearer token, which only the local proxy
attaches.
