# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | ✅ Yes             |
| < 0.8   | ❌ No              |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you believe you have found a
security issue in Talus, please report it responsibly:

**Do NOT open a public GitHub issue.**

### Contact

- **Email:** security@hartwell-labs.pl
- **Keybase:** `@bartosz` (GPG: `B3A2 1F7E 9D5C 8A4B 2E3F 1A09 87C3 5F2E 1D9B 4A7C`)

### Response Timeline

| Phase | SLA |
|-------|-----|
| Acknowledgement | 24 hours |
| Initial assessment | 72 hours |
| Fix development | 7–14 days (depending on severity) |
| Patch release | 14 days |

### What to Include

1. A description of the vulnerability
2. Steps to reproduce (or POC)
3. Affected version range
4. Impact assessment (your perspective)

## Security Architecture

### License System

**Keys never leave the owner's machine.**

```
┌──────────────────┐         ┌────────────────────────┐
│  Owner machine   │         │  License server (worker)│
│  (offline)       │         │  (Cloudflare D1)       │
│                   │         │                       │
│  signing_key.json │───────│ PUBLIC KEYS ONLY       │
│  (Ed25519 priv)   │    verify                     │
│                   │    licenses                   │
└──────────────────┘    & seats                    └─────────────┘
                                                   │
                                                   │ download grant
                                                   ▼
┌──────────────────┐    verify      ┌────────────────────────┐
│  Talus binary     │◄───────────────│  Artifact signatures   │
│  (client)         │  signatures     │  (Ed25519 + SHA-256)   │
│                   │                 │                        │
│  License cache    │                 └─────────────┘          │
│  /var/lib/talus   │                                        │
│  (HMAC-protected) │                                       │
└──────────────────┘                                        │
```

### Key Rotation

- **License signing:** The `kid` (key ID) field in the license payload enables
  zero-downtime rotation. The server holds multiple public keys (`v1`, `v2`)
  and selects the right one based on `kid`. Default is `v1` for backward
  compatibility.
- **Rotation procedure:** Generate a new key pair in `~/.secrets`, add the new
  public key to `wrangler.toml` with a new `kid`, then re-issue licenses with the
  new key. Old licenses continue to validate against their original `kid`.

### Artifact Verification

Every downloaded binary is verified:

1. **SHA-256 hash** — compared against the checksum from the release assets
2. **Ed25519 signature** — verified against the embedded artifact public key
3. **ELF magic check** — confirms the downloaded file is a valid ELF64 binary
4. **Anti-downgrade** — the client refuses to install an older version than
  what is currently installed (unless `--allow-downgrade` is explicitly passed)

### Network Security

- All communication is HTTPS-only (certificate verification is always on)
- Server responses are capped at 64 KiB (license) and 50 MB (artifact)
- The license key is never sent in plaintext over the wire — only the canonical
  form is POSTed to an HTTPS endpoint
- Client-side rate limiting: 5 license activation attempts per 5 minutes

### Local Security

- License cache is stored at `/var/lib/talus/license.json` with `0600` permissions
- Config is stored at `/etc/talus/` with `0700` permissions on directories
- License cache integrity is protected with an HMAC-SHA256 tag
- The `--license-key` CLI argument is deprecated (visible in `ps`); use
  `--license-key-stdin` or `TALUS_LICENSE_KEY_FILE` (0600) instead

## Disclosure Policy

We follow **Coordinated Vulnerability Disclosure**:

1. Report the vulnerability to security@hartwell-labs.pl
2. We acknowledge within 24 hours
3. We investigate and provide a fix timeline
4. On release, we publish a security advisory with your name (if desired)

Please do not:
- Exploit the vulnerability in public or private environments
- Access other accounts or data
- Disclose details publicly before a fix is available

## Security Checklist for Contributors

- [ ] `cargo clippy --all-features -- -D warnings` passes
- [ ] `cargo audit` passes (no known CVEs in dependencies)
- [ ] `cargo deny check` passes (license + source bans)
- [ ] Private keys are never committed (they live only in `~/.secrets`)
- [ ] The `test-license` feature is gated and uses separate, non-production keys
- [ ] All network requests use HTTPS with certificate verification
- [ ] No hardcoded credentials, API tokens, or secrets in source

## Third-Party Security

- **Cloudflare Workers:** The license server runs on Cloudflare's hardened
  runtime. We use D1 (managed SQLite) for storage — no direct database access.
- **GitHub PAT:** Enterprise artifact downloads use a GitHub PAT (`repo` scope)
  stored as a Worker secret (`GITHUB_TOKEN`). It is used only server-side to
  issue single-use download grants — the token never reaches the client.
  The PAT is scoped to `Hartwell-Labs/talus-enterprise` access only.
