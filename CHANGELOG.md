# Changelog

All notable changes to talus-process-monitor will be documented in this file.

## [Unreleased]

### 0.8.1-f (2026-09-22): embedded eBPF object — true single-file deploy
- Agent binary embeds the compiled eBPF object (23.5 KB): download → run, no ./build.sh needed
- resolve_bpf_path returns <embedded> unless --bpf PATH is given; on-disk object still works as override
- PyPI installer 0.8.1.post2 with full project.urls (docs, comparison, changelog)
- CI: publish-pypi fixed (builds from pypi/ subdir); gitignore negation for the tracked .o

### License server failover — shared Turso storage, automatic server switchover

- **Storage decoupled from compute** (`license-server/src/db.js`): the worker
  now runs unchanged on the native D1 binding OR on Turso (libSQL) over HTTP
  — same D1-compatible surface (`.all()`, `.first()`, `.run()` with
  `meta.changes`, `.batch()`).
- **Failover worker** (`wrangler.failover.toml`):
  `https://talus-license-failover.metaforicmail.workers.dev` — identical API
  (activate/deactivate/admin/TOTP panel/webhooks/redeem) serving the SAME
  shared Turso database as the primary, so seats and revocations are
  identical on both.
- **Primary switched to the shared Turso database**; the previous D1
  database is kept as a frozen point-in-time snapshot (rollback instructions
  in `docs/ops.md`).
- **Client failover** (`process-monitor/src/license.rs`): activation,
  deactivation and store-key redemption try the primary server first, then
  the failover list — `TALUS_LICENSE_SERVER` (primary) and
  `TALUS_LICENSE_SERVER_FAILOVER` (comma-separated; empty string disables).
  Connection-level failures switch servers; HTTP-level answers (invalid
  key, rate limit, revoked) are authoritative and never retried elsewhere.
- Verified end-to-end: activation with a dead primary switches to the
  failover worker and the seat is visible in the primary's admin stats
  (shared state); `docs/ops.md` documents topology, secrets, recovery and
  free-tier limits.

## [0.8.0] - 2026-09-17

### Secure Licensing Backend — key rotation, activation server, sales docs ✅

**Security fixes**
- **KEY ROTATION (breaking for old keys):** the Ed25519 private signing key
  was committed in git history (`license-keygen/license-keys/`). A new keypair
  was generated **outside the repository**
  (`~/.secrets/talus/license-keys/`, 0700/0600); all previously issued
  licenses are void. `PUBLIC_KEY_BYTES` updated; `KEY_CHECKSUM` is now
  derived at compile time from the public key (no more hand-maintained XOR
  chain, immune to clippy-visible edit errors).
- `talus-keygen` no longer stores keys inside the repository — keys live in
  `~/.secrets/talus/license-keys/` (or `TALUS_KEYGEN_DIR`), written 0600,
  directory 0700. `license-keys/`, `signing_key*`, `*.pem`, `.dev.vars`,
  `.env` added to `.gitignore`.
- **License cache hardening:** the cached payload is re-verified against the
  signed license key on every load; any local edit to tier/expiry/features/
  seats invalidates the cache (fail-closed) and is audit-logged as
  `CACHE_TAMPERED`.
- **Trial marker hardening:** the 30-day trial record now carries a SHA-256
  integrity tag bound to binary + machine (replaces the non-cryptographic
  `DefaultHasher` checksum); edited or copied trial files are rejected
  (`TRIAL_TAMPERED`).

**New: activation server (`license-server/`)**
- Cloudflare Worker + D1 on the **free tier (no credit card)** —
  `https://talus-license-server.metaforicmail.workers.dev`
- `POST /api/v1/activate` — server-side Ed25519 verification (server holds
  the **public** key only), expiry/revocation checks, seat limits
  (`max_seats` from the signed payload), idempotent same-machine
  re-activation, D1-backed rate limiting (5 attempts / 5 min per machine +
  global abuse brake)
- `POST /api/v1/deactivate` — token-gated seat release
- `GET /api/v1/health` — service status
- Admin API (`/api/v1/admin/revoke`, `/api/v1/admin/activations`) gated by
  the `ADMIN_TOKEN` Worker secret; revocation covers never-seen keys via a
  `revocations` table and frees all seats
- Binary default endpoint switched to the worker; `TALUS_LICENSE_SERVER`
  override kept

**New: admin panel (`admin-panel/`)**
- Local web UI for the license server: overview cards (licenses, seats,
  7-day growth, revocations), recent activations, per-license seat lookup,
  revoke / restore / free-seat actions
- Runs on `localhost:8787` via a zero-dependency Node proxy; the
  `ADMIN_TOKEN` stays on the owner's machine and never reaches the browser
- Backed by new worker endpoints: `GET /api/v1/admin/stats`,
  `POST /api/v1/admin/unrevoke`, `POST /api/v1/admin/free-seat`

**New: hosted admin panel with TOTP (`/admin` on the worker)**
- The worker now serves the panel itself at `/admin` — browser access from
  anywhere, no local process required
- Two-factor login: `ADMIN_TOKEN` (auth code) + TOTP (Google Authenticator,
  RFC 6238, HMAC-SHA1 via WebCrypto); `scripts/setup-totp.sh` generates the
  seed, uploads it as a Worker secret and shows the QR code exactly once
- Sessions in D1 (12 h, only SHA-256 hashes stored; HttpOnly / Secure /
  SameSite=Strict cookie), TOTP replay protection (`totp_used`), failed
  login rate limiting (10 / 5 min)
- All `/api/v1/admin/*` endpoints accept bearer **or** session credentials;
  unit tests for the TOTP/base32 core (`license-server/test/`); E2E suite
  green 14/14 against production

**New: store integrations — buy on Polar / Gumroad / Lemon Squeezy**
- Signed platform webhooks (`/api/v1/webhook/{polar,gumroad,lemonsqueezy}`)
  create pending orders in D1; HMAC-verified per platform, idempotent,
  refund events automatically revoke the mapped license
- `POST /api/v1/redeem` + transparent client-side redemption: a customer
  pastes their **store** key into `talus license activate` and the server
  translates it into the real Ed25519-signed Talus license
- `scripts/issuer-daemon.mjs` (owner's machine) fulfills pending orders:
  signs a license, pre-registers it, maps store-key → Talus key
- Admin panel: store orders fulfillment queue; admin `orders`/`fulfill`
  endpoints
- Store keys are stored only as SHA-256 hashes; the signing key never
  leaves the owner's machine

**New: keygen & ops tooling**
- `talus-keygen issue --seats N` — seat count baked into the signed payload;
  `--json` flag for machine-readable output (used by automation)
- `scripts/issue-license.sh`, `scripts/revoke-license.sh`,
  `scripts/list-activations.sh`, `scripts/health-check.sh` (no secrets in
  scripts; admin token read from `~/.secrets/talus/admin_token`)
- **Automated issuing**: `issue-license.sh` signs locally, then
  pre-registers the key on the server (`POST /api/v1/admin/register`) so it
  is visible in the panel immediately; `--count N` issues N keys for one
  organization in one run; `--offline` skips registration (the key
  self-registers on first activation)

**New: sales-ready documentation**
- `docs/EULA.txt` — license agreement template (no amounts)
- `docs/pricing-tiers.md` — pricing **structure** (no amounts; owner sets
  prices per sale)
- `docs/customer-activation-guide.md` — buyer's step-by-step activation guide
- `docs/issue-first-license.md` — owner runbook: payment → issue → deliver →
  track, incl. optional payment-webhook automation notes
- `SECURITY.md` — licensing trust model, key storage/backup, rotation
  runbook, license-leak response
- README/README.pl licensing sections rewritten; `ARCHITECTURE.md` gained a
  licensing-subsystem section with the keygen → key → binary → server flow

### MeMLP — Neural Detection Engine (built from scratch) ✅

- New `memlp.rs`: modular embedded multi-layer perceptron stack — no ML
  dependencies, flat `Vec<f32>` storage, seeded deterministic init, ReLU/softmax
  forward pass, online backprop training (cross-entropy loss, gradient
  clipping, bounded per-parameter updates, NaN/Inf sanitisation)
- Three specialist heads on one shared 10-feature behavioural embedding:
  `ransomware` (10→24→16→3), `lateral` (10→12→2), `persistence` (10→12→2)
- Per-PID feature accumulator with 1-second half-life decay fed by the live
  eBPF event stream (opens, execs, network, fs mutations, filename entropy,
  ransomware-marker extensions, autostart paths)
- Online training on every alert against transparent heuristic teachers;
  neural verdicts attached to alerts in TUI, JSON, plain and WebSocket output
- JSON checkpoints: `--memlp` enables the engine, `--memlp-checkpoint PATH`
  sets the file (default `~/.local/share/talus/memlp.json`); autosave every
  30 s, reload on start, `training_samples` persists across restarts
- 21 unit tests (forward/training/checkpoint/feature tests)
- REST API: `GET /api/v1/stats` and `GET /api/v1/processes` now expose MeMLP
  state and per-PID verdicts

### Fixed

- `--features web`: axum 0.8 handler mismatch — auth checks moved from a
  body-consuming `Request` extractor to a stateless `Authed`
  (`FromRequestParts`) extractor; the TLS accept loop now serves each
  pre-wrapped TLS stream via `hyper-util`'s auto builder instead of the
  impossible `TcpStream → TcpListener` conversion (WebSockets preserved via
  `serve_connection_with_upgrades`)
- `--features clickhouse` / `--features memgraph`: `ClickHouseConfig` /
  `MemGraphConfig` now derive `Clone`; `MemGraphStore::cypher` returns
  `Result<(), String>` correctly
- `--features kafka`: removed unused imports; workspace compiles with
  **zero errors and zero warnings** on `--all-features` (previously 8 errors)

## [0.7.0] - 2026-08-30

### Enterprise Licensing System

**Commercial License Management** ✅
- Ed25519 license key signing and verification — cryptographically signed license keys
- Online activation via HTTP API — machine-bound license activation
- Feature gating — Community vs Enterprise tier with per-feature enable/disable
- 30-day Enterprise trial — automatic trial on first run
- Machine fingerprinting — MAC + hostname + CPU + systemd machine-id
- License cache — persistent activation state in `~/.config/talus/license.json`
- License CLI — `talus license activate/deactivate/show/verify/machine-id`

**Keygen CLI (`talus-keygen`)** ✅
- Ed25519 keypair generation for license signing
- License key issuance with configurable tier, expiry, features, organization
- License registry — tracks all issued licenses
- Public key export for binary embedding
- License revocation by ID

**CLI Redesign** ✅
- Proper subcommands: `talus license <cmd>` and `talus monitor [args]`
- Default to monitor mode when no subcommand given
- Professional startup banner with license tier display
- Enterprise license requirement messages for gated features

**Feature Gating** ✅
- `--auto-kill` requires Enterprise license
- `--web` requires Enterprise license
- `--kafka-brokers` requires Enterprise license
- `--clickhouse` requires Enterprise license
- `--memgraph` requires Enterprise license
- Graceful fallback to Community mode without license

**TUI Integration** ✅
- License tier badge in header (ENTERPRISE/COMMUNITY)
- License status in status bar
- Enhanced `talus license show` with colored Unicode box display
- Days-remaining countdown for expiring licenses

**New Dependencies**
- `ed25519-dalek` — Ed25519 signature verification
- `base64` — license key encoding
- `reqwest` (blocking) — HTTP activation client
- `dirs` — config directory resolution
- `hostname` — machine fingerprinting

**New Files**
- `process-monitor/src/license.rs` — core license module (types, validation, activation, feature gating)
- `license-keygen/` — standalone keygen CLI tool

### Changed
- Bumped version to 0.7.0
- Refactored CLI from flat flags to proper subcommands
- TUI `run()` now accepts `LicenseState` parameter
- All Enterprise features gated behind license check
- Startup banner shows license tier and organization

## [0.6.0] - 2026-08-28

### Enterprise Maturity Program

**Level 1 — Supply Chain Security Foundation** ✅
- `cargo-deny` CI gate — blocks PRs with forbidden licenses and known advisories
- CycloneDX SBOM generation — JSON + XML SBOM attached to every release
- gitleaks secret scanning — detects hardcoded secrets in CI
- Dependency review — automated review of new dependencies on PRs
- Enhanced SECURITY.md — enterprise-grade VDP with SLA timelines

**Level 2 — Build Provenance & Signing** ✅
- SLSA Level 2 provenance — `slsa-framework/slsa-github-generator` for all releases
- Sigstore cosign keyless signing — OIDC-based binary signing
- GitHub artifact attestation — `gh attestation write` for supply chain integrity
- SHA-256 + SHA-512 checksums — cryptographically verifiable release integrity
- SBOM signing — Cosign signs CycloneDX SBOM alongside binaries
- Full release flow — build → sign → attest → publish with provenance

**Level 3 — Security Hardening & Audit** ✅
- `#![warn(missing_docs)]` crate-level lint enforced
- SAFETY comments documented on every `unsafe` block (6 blocks audited)
- `SecurityHeadersLayer` middleware — CSP, X-Frame-Options: DENY, nosniff, referrer-policy, permissions-policy
- Added `tower` dependency for axum middleware layer
- Fixed 2 pre-existing clippy warnings (unused variables in storage/mod.rs, tui.rs)
- Crate-level doc comment and function docs on public API

**Level 4 — Testing & Quality Gates** ✅
- Test suite expanded: 13 → **36 tests** (+23 new, 177% increase)
- Edge case tests: extract_extension (8 cases), cstr_to_string (5 variants)
- Shannon entropy tests: uniform (=0), high (>0.5), single char
- Monitor invariants: window eviction, threshold=0 disable, auto-kill action
- Empty state tests: top_files, extension_counts, rate_history, stats_sorted
- Init state tests: uptime, total_events, total_lost
- Clippy: 0 warnings with `-D warnings`

**New Files**
- `MATURITY.md` — 20-level enterprise maturity model
- `.github/workflows/supply-chain.yml` — Supply chain security CI
- `.github/workflows/build-provenance.yml` — Build provenance & signing

### Changed
- Upgraded `SECURITY.md` to enterprise-grade VDP with CVSS-based SLAs
- Added Hall of Fame section for security researchers
- Added SAFETY documentation to all unsafe blocks in `main.rs` and `monitor.rs`
- Added security headers middleware to `web.rs`
- Added 23 new unit tests in `monitor.rs`

## [0.5.0] - 2026-08-20

### Added
- Network tracepoints (connect/accept/sendto/recvfrom) with in-kernel sockaddr parsing
- Kill tracepoint with signal name resolution
- Filesystem tracepoints (mkdir/unlinkat/fchmodat)
- Process tree hierarchical view with PPID resolution
- Shannon entropy scoring for top files
- Network panel with Canvas traffic flow visualization
- Heatmap panel (process × extension matrix)
- Kafka event streaming with lz4 compression
- ClickHouse batch storage backend
- MemGraph process relationship graph
- Tauri desktop dashboard (React 19 + Recharts)
- Go web frontend
- C eBPF standalone variant

### Fixed
- LLVM `.text.unlikely` cold-path sections for bpf_probe_read_user
- Network tracepoint byte-by-byte sockaddr reading (avoided array types/slice operations)
- Kill tracepoint PID formatting with direct pointer arithmetic
- BPF codegen-units changed from 4 to 1 for reduced duplication

## [0.4.0] - 2025-08-01

### Added
- Criterion benchmarks (JSON serialization, event filtering, TUI render, atomic ops)
- Landing page with glassmorphism design
- Published to crates.io

### Changed
- Improved CI/CD pipeline with Ultra CI
- Enhanced TUI panels

## [0.3.0] - 2025-07-01

### Added
- eBPF process monitoring
- Real-time TUI dashboard
- Ransomware detection heuristics
- Network connection tracking
- Docker container support
- Web server mode (axum)
- Prometheus metrics

## [0.2.0] - 2025-03-01

### Added
- File operation tracking (open, read, write)
- Process tree visualization

## [0.1.0] - 2025-01-01

### Added
- Initial eBPF probe
- Basic process exec tracking
