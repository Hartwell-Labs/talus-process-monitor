# talus-installer

One-pass installer for Talus Enterprise: checks the host, activates a license,
installs `talus-monitor-enterprise`, writes the systemd unit, starts it, and
verifies the dashboard.

## Usage

```sh
sudo talus-installer                  # guided TUI
sudo talus-installer --no-tui --skip-license
sudo talus-installer --no-tui --license-key-stdin < key.txt
sudo talus-installer --uninstall --dry-run
```

The license key can also come from `TALUS_LICENSE_KEY_FILE` (must be `0600`).
`--license-key KEY` still works but is visible in `ps`; prefer stdin or the
file. The TUI runs the install on a background thread, so the progress screen
stays responsive and each step reports success or failure.

## Build

```sh
cargo build --release
```

The installer reuses `talus-process-monitor::license` for activation and cache
verification, so both binaries agree on key IDs and cache format.

## Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | TUI, CLI, and the single install pipeline |
| `install-talus.sh` | Bootstrap: download release asset, verify SHA-256, exec |
| `examples/mock-license.rs` | Test-only license generator (`test-license` feature) |

`install-talus.sh` fails closed: no checksum file, no matching entry, or a
mismatch aborts before the binary is executed.

## Uninstall

```sh
sudo talus-installer --uninstall
```

Removes the unit, the binary (and `.bin.prev` / `.bin.new`), the `talus`
symlink, and the cached config. `--dry-run` prints the same list without
touching anything.
