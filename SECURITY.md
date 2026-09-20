# Security Policy

## Supported versions

Only the latest `main` branch is supported with security fixes.

## Reporting a vulnerability

**Do NOT open a public issue for security reports.**

Email: thethreadcalls@outlook.com (hartwell-labs, monitored by the maintainer)

Include: affected component, reproduction steps, impact assessment. You will get
an initial response within 72 hours. If confirmed, a fix timeline is agreed with
you and credit is given in the release notes (unless you prefer otherwise).

## Scope

- Kernel-facing code (eBPF probes, LSM hooks): highest priority
- CLI/parsing layers: high
- Documentation/site: low

## Safe harbor

Good-faith research and coordinated disclosure is welcomed and will not be
pursued legally, provided you give us a reasonable window to ship a fix.

## Hardening notes

This project ships with CI-enforced builds, pinned toolchains and automated
test sweeps (see `.github/workflows/`). Fuzz targets live alongside the parser
modules where applicable.

## Known dependency notes

- **glib 0.18.5 (talus-tauri desktop shell)** — RUSTSEC medium: unsoundness in `VariantStrIter`. Not reachable from our code paths (no direct `glib` usage; transitive via tauri 2.x gtk bindings). Bumping glib to 0.20 requires a tauri major upgrade — tracked, scheduled with the next tauri release rebase. The core monitor (Rust + eBPF) is unaffected.
