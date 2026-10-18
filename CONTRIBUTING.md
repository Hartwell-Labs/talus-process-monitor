# Contributing

Thank you for your interest in the project!

## Setup

1. Rust nightly is required for the eBPF build (or the toolchain used in CI).
2. Clone the repo, install dependencies, and run the checks:
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings`
   - `cargo test`

If your change touches the licensing code (`process-monitor/src/license.rs`,
`license-keygen/`, `license-server/`), also make sure:

- **Never** commit, print, or log signing keys, admin tokens, or issued
  license keys. Keys live outside the repo (`~/.secrets/talus/license-keys/`).
- `cargo test -p talus-process-monitor` passes — including
  `key_integrity_check`.
- The activation server contract (`license-server/src/index.js`) stays
  compatible with the client in `license.rs` (endpoints, field names,
  response shape).

## Reporting issues

Before opening an issue, check whether it already exists. Please describe:

- what you expected,
- what you got (logs, stack trace),
- system/toolchain version.

## Pull requests

- Keep changes small and focused (1 topic = 1 PR).
- Keep CI green (fmt + clippy + tests).
- Add tests for new behavior.
- Describe **why**, not just **what**.

Project license: MIT. Submitting a PR means you accept it for your
contribution.

## Security

Talus detects ransomware via eBPF — this is a security-focused project. If
you discover a vulnerability, report it privately to `thethreadcalls@outlook.com`
or via [GitHub Security Advisories](https://github.com/BartoszOsiej/talus-process-monitor/security/advisories/new)
(see [SECURITY.md](SECURITY.md)). Do not open a public issue for security
vulnerabilities.

## Commit style

`type(scope): summary` — `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.
