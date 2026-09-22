# 🛡️ Talus — eBPF Ransomware Detection & Response for Linux

![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Rust](https://img.shields.io/badge/Rust-2021-DEA584?style=flat-square&logo=rust)
![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8+-FCD900?style=flat-square&logo=linux)
![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go)
![Docker](https://img.shields.io/badge/Docker-GHCR-2496ED?style=flat-square&logo=docker)
![Enterprise](https://img.shields.io/badge/Enterprise-Level%204%2F20-blue?style=flat-square)
[![PyPI](https://img.shields.io/pypi/v/talus-process-monitor?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/talus-process-monitor/)
[![Crates.io](https://img.shields.io/crates/v/process-monitor?style=flat-square&logo=rust)](https://crates.io/crates/process-monitor)

**Kernel-level ransomware detection in Rust: a sliding-window heuristic over eBPF syscalls — with automated response.**

> If Talus saves you an evening of worry, a ⭐ star helps other admins find it. Practical deployment playbook: [Field Guide](https://bartoszosiej.github.io/talus-process-monitor/field-guide.html)

Talus is not a passive monitor. It is a **detect-and-respond** agent: eBPF tracepoints hook syscalls at the kernel level, a per-PID sliding window scores file-open rates in real time, and the response layer **terminates** the offending process (`SIGKILL`) the moment a verdict fires. Measured on a live desktop: **~280,000 events/s sustained with ~7.6% CPU** through per-CPU perf buffers and zero-copy handoff to the userspace detection engine.

```bash
# Install via pip (fetches the prebuilt binary from releases):
pip install talus-process-monitor && talus-monitor install
sudo talus-monitor run monitor --auto-kill

# Or build from source (~2 min):
./build.sh && sudo ./target/release/process-monitor monitor --auto-kill
```

<div align="center">

**Live demo — TUI with kernel tracing in action:**

![Talus live demo: ransomware load detected and killed](assets/talus-demo.gif)

[Architecture](ARCHITECTURE.md) · [Detection article](https://dev.to/bartoszosiej/detecting-ransomware-with-ebpf-in-rust-4779) · [🇵🇱 Wersja polska](README.pl.md) · [📄 Enterprise Report (PDF)](docs/talus-enterprise-maturity-report.pdf) · [Enterprise Maturity](MATURITY.md)

</div>

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start (30 seconds)](#quick-start-30-seconds)
- [See It Catch Ransomware](#see-it-catch-ransomware)
- [Architecture / Data Flow](#architecture--data-flow)
- [Network Visibility](#network-visibility)
- [Detection & Response](#detection--response)
- [Storage & Pipeline](#storage--pipeline)
- [Requirements](#requirements)
- [Usage](#usage)
- [Build Variants](#build-variants)
- [TUI Controls](#tui-controls)
- [Web Dashboard](#web-dashboard)
- [Operator View (TUI + Web)](#operator-view-tui--web)
- [Project Structure](#project-structure)
- [Tested Live on Linux](#tested-live-on-linux)
- [Docker / Kubernetes](#docker--kubernetes)
- [Security & Hardening](#security--hardening)
- [Enterprise Maturity](#enterprise-maturity)
- [Licensing & Pricing](#licensing--pricing)

---

## What It Does

| Capability | How |
|---|---|
| **Kernel-level tracing** | eBPF tracepoints on `execve`, `openat`, `connect`, `accept`, `sendto`, `recvfrom`, `mkdir`, `unlinkat`, `kill`, `fchmodat` |
| **Ransomware detection** | 1-second sliding window per PID; alerts when file-open rate exceeds configurable threshold |
| **Automated response** | `--auto-kill` sends `SIGKILL` to the offending process on alert verdict |
| **Network egress tracking** | Parses `sockaddr` in-kernel — captures IPv4/IPv6/Unix addresses on connect/accept/send/recv |
| **Event pipeline** | Kernel perf buffer → zero-copy ring → detection engine → TUI / JSON / WebSocket / Prometheus |
| **Process tree** | Resolves PPID from `/proc`, builds hierarchical view with per-process alert counts |
| **File ranking** | Most-opened files with Shannon entropy scoring (detects encrypted/randomised filenames) |
| **Single binary** | Full LTO, `panic = "abort"`, symbol-stripped — 1.7 MB TUI, 2.5 MB with web |
| **Kafka streaming** | Events → Kafka topics with lz4 compression, partitioned by PID |
| **ClickHouse storage** | Batch inserts into MergeTree for analytics retention |
| **MemGraph graph** | Process trees + file access as a graph (Cypher queries) |

---

## Quick Start (30 seconds)

```bash
# 1. Get it
git clone https://github.com/BartoszOsiej/talus-process-monitor
cd talus-process-monitor
./build.sh                      # or: ./install.sh --system

# 2. Run it — monitor-only mode
sudo ./target/release/process-monitor monitor

# 3. Or full EDR mode: detect + auto-kill
sudo ./target/release/process-monitor monitor --auto-kill
```

Pre-built binaries and container images: see [Releases](https://github.com/BartoszOsiej/talus-process-monitor/releases) (`process-monitor` static binary) and [Docker / Kubernetes](#docker--kubernetes).

> **Docker one-liner:**
> ```bash
> # --privileged is required: eBPF tracepoints need kernel access (CAP_BPF/CAP_SYS_ADMIN)
> docker run --privileged --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro \
>   ghcr.io/bartoszosiej/talus-process-monitor:latest
> ```

---

## See It Catch Ransomware

Reproduce the demo above in two terminals:

```bash
# Terminal 1 — Talus with a low threshold and auto-kill
sudo ./target/release/process-monitor monitor --alert-threshold 50 --auto-kill

# Terminal 2 — simulate ransomware-like mass file encryption
for i in $(seq 1 500); do touch /tmp/victim$i.enc && cat /tmp/victim$i.enc >/dev/null; done
```

Expected: within **~1 second** of the loop starting, Talus fires an alert and `SIGKILL`s the loop — the TUI shows the verdict in red in the ALERTS panel. That is the whole story: kernel tracing → heuristic verdict → response, no agent, no daemon restart, nothing to install on "the host".

---

## Architecture / Data Flow

Talus follows a **pipeline architecture** — kernel ingestion → userspace detection → operator response:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      KERNEL SPACE (eBPF programs)                       │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │ sys_enter_   │  │ sys_enter_   │  │ sys_enter_   │                  │
│  │ execve       │  │ openat       │  │ connect      │ ... 10 total     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘                   │
│         │                 │                 │                            │
│         ▼                 ▼                 ▼                            │
│  ┌─────────────────────────────────────────────────────┐               │
│  │  ProcessEvent { pid, uid, comm, filename, argv }    │               │
│  │  PerfEventArray (per-CPU, zero-copy)                │               │
│  └──────────────────────────┬──────────────────────────┘               │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────────┐
│                      USERSPACE (Rust)                                   │
│                              │                                           │
│  ┌───────────────────────────▼──────────────────────────┐              │
│  │  Reader thread — reads perf buffers per CPU          │              │
│  │  MPSC channel → Monitor event loop                   │              │
│  └───────────────────────────┬──────────────────────────┘              │
│                              │                                           │
│  ┌───────────────────────────▼──────────────────────────┐              │
│  │  DETECTION ENGINE                                    │              │
│  │  • Sliding window per PID (1s rolling)               │              │
│  │  • File-extension frequency tracking                 │              │
│  │  • Shannon entropy scoring on filenames              │              │
│  │  • Per-process stats (opens, execs, alerts, PPID)    │              │
│  └───────────┬─────────────────────────┬───────────────┘              │
│              │ VERDICT                  │                              │
│              ▼                          ▼                               │
│  ┌─────────────────────┐  ┌────────────────────────────┐              │
│  │  RESPONSE           │  │  OUTPUT                     │              │
│  │  kill(pid, SIGKILL) │  │  TUI (7 panels)            │              │
│  │  cgroup freeze      │  │  JSON / WebSocket           │              │
│  │  (extensible)       │  │  Prometheus /metrics        │              │
│  └─────────────────────┘  │  REST API                   │              │
│                           └────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

### Pipeline stages

| Stage | Component | Throughput | Mechanism |
|---|---|---|---|
| **1. Ingest** | eBPF tracepoints | ~280k events/s sustained | `bpf_perf_event_output` per-CPU |
| **2. Transport** | PerfEventArray | zero-copy | `PerfEventArrayBuffer::read_events` |
| **3. Detect** | Sliding window engine | real-time | 1s rolling window, configurable threshold |
| **4. Respond** | `kill(2)` / cgroup | < 1ms latency | `SIGKILL` on heuristic verdict |
| **5. Persist** | TUI / JSON / WebSocket | live stream | REST API + Prometheus for retention |

This maps directly to a **Kafka-style** event pipeline: kernel perf buffer = topic, reader thread = consumer, detection engine = stream processor, TUI/API = sink.

---

## Storage & Pipeline

Talus supports pluggable storage backends for event persistence and downstream analytics:

```bash
# Stream events to Kafka
sudo process-monitor monitor --kafka-brokers localhost:9092 --kafka-topic talus-events

# Store events in ClickHouse for analytics
sudo process-monitor monitor --clickhouse http://localhost:8123

# Build process relationship graph in MemGraph
sudo process-monitor monitor --memgraph http://localhost:7474

# Combine all backends
sudo process-monitor monitor \
  --kafka-brokers localhost:9092 --kafka-topic talus-events \
  --clickhouse http://localhost:8123 \
  --memgraph http://localhost:7474
```

### Kafka

Events are sent to a configurable topic with `lz4` compression and partitioned by PID for ordering per-process:

| Config | Default | Description |
|---|---|---|
| `--kafka-brokers` | — | Broker address (e.g. `localhost:9092`) |
| `--kafka-topic` | `talus-events` | Topic name |

### ClickHouse

Events are batch-inserted into a `MergeTree` table partitioned by date:

```sql
CREATE TABLE process_monitor.events (
    ts DateTime64(3),
    kind LowCardinality(String),
    pid UInt32, uid UInt32,
    comm LowCardinality(String),
    file Nullable(String),
    extension LowCardinality(Nullable(String))
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, kind, pid)
```

### MemGraph

Process trees and file access patterns are stored as a graph:

```cypher
// Find all processes that opened .enc files
MATCH (p:Process)-[r:OPENED]->(f:File)
WHERE f.path ENDS WITH '.enc'
RETURN p.pid, p.comm, f.path, r.count
ORDER BY r.count DESC

// Find exfiltration candidates (file opens + external network)
MATCH (p:Process)-[:OPENED]->(f:File), (p)-[:CONNECTED_TO]->(n:NetworkTarget)
WHERE NOT n.addr STARTS WITH '10.'
RETURN p.pid, p.comm, collect(f.path), collect(n.addr)
```

---

## Network Visibility

Talus traces network syscalls at the kernel level — not just file operations. This provides **full egress visibility** for detecting data exfiltration, C2 communication, and lateral movement.

| Syscall | Event Type | What's Captured | How |
|---|---|---|---|
| `connect` | `Connect` | Remote IPv4/IPv6/Unix address + port | `sockaddr` parsed via `bpf_probe_read_user` |
| `accept` | `Accept` | Remote address of incoming connection | Same mechanism |
| `sendto` | `SendTo` | Destination address | `sockaddr` at arg index 4 |
| `recvfrom` | `RecvFrom` | Source address | `sockaddr` at arg index 4 |

### In-kernel sockaddr parsing

The eBPF program reads raw `sockaddr` structures byte-by-byte from userspace:

```c
// Read AF_INET address from sockaddr_in
bpf_probe_read_user(&family, 2, sockaddr_ptr);      // sa_family
bpf_probe_read_user(&port_be, 2, ptr + 2);          // sin_port (big-endian)
bpf_probe_read_user(&a0, 1, ptr + 4);               // sin_addr[0]
// ... formats as "192.168.1.1:443"
```

This runs in the kernel with **zero userspace round-trips** — addresses are resolved before the event even reaches userspace.

### Example: detecting exfiltration

```jsonc
{"ts":"14:09:17.100","type":"event","kind":"Connect","pid":1234,"comm":"curl","file":"93.184.216.34:443"}
{"ts":"14:09:17.205","type":"event","kind":"SendTo","pid":1234,"comm":"curl","file":"93.184.216.34:443"}
{"ts":"14:09:17.502","type":"event","kind":"Open","pid":1234,"comm":"curl","file":"/home/user/Documents/backup.tar.gz"}
```

---

## Detection & Response

### Detection: sliding-window heuristic

Each PID maintains a **1-second rolling window** of `openat` events. When the count hits the threshold (default: 50 opens/s), a verdict fires:

```
PID 2126 ("Cache2 I/O") opened 50 files in 1.0s  →  VERDICT: SUSPICIOUS
```

The threshold is configurable at runtime via the API or CLI:

```bash
# Lower threshold for high-security environments
sudo process-monitor monitor --alert-threshold 20

# Filter by extension (e.g. detect .enc/.pdf mass opens)
sudo process-monitor monitor --filter-ext enc
```

### Response: automated termination

With `--auto-kill`, Talus sends `SIGKILL` to the offending process immediately on verdict:

```bash
# EDR mode: detect + respond
sudo process-monitor monitor --alert-threshold 50 --auto-kill
```

```rust
// The response layer — ~30 lines of Rust
fn kill_process(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    rc == 0
}

// Fired inside the detection engine on verdict:
if self.auto_kill {
    let result = kill_process(ev.pid);
    outputs.push(Output::Action(ResponseAction {
        ts: ev.ts.clone(),
        pid: ev.pid,
        action: format!("SIGKILL sent to PID {}", ev.pid),
        success: result,
    }));
}
```

This is extensible — the `ResponseAction` interface supports `kill`, cgroup freeze, network quarantine, or any custom response.

### Detection: MeMLP neural engine (`--memlp`)

Beyond the heuristic window, Talus embeds **MeMLP** — a **M**odular **e**mbedded **M**ulti-**L**ayer **P**erceptron model built from scratch (no `ndarray`, no `tch`, no ONNX — just a few KB of dependency-free Rust). The same architecture powers the neural terrain generator in the NV2 voxel engine, re-targeted here at process behaviour.

| Module | Shape | Task |
|---|---|---|
| `ransomware` | 10 → 24 → 16 → 3 | benign / suspicious / ransomware |
| `lateral` | 10 → 12 → 2 | lateral-movement suspect |
| `persistence` | 10 → 12 → 2 | autostart-persistence suspect |

Every module consumes the same **10-feature behavioural embedding** per PID (open rate, exec+network rate, filename Shannon entropy, ransomware-marker extension fraction, extension diversity, fs-mutation rate, destructive fraction, distinct-file spread, autostart-path hits, network fraction). Windows decay with a 1-second half-life, mirroring the heuristic window.

The engine **trains online**: every alert performs a backpropagation step (cross-entropy loss, gradient clipping, bounded updates) against transparent heuristic teachers, then scores the process. Checkpoints persist as JSON and reload on the next run, so the model keeps learning across restarts.

```bash
# Enable the neural engine (checkpoint auto-saves every 30s)
sudo process-monitor monitor --memlp

# Explicit checkpoint location (loaded on start, saved on shutdown + autosave)
sudo process-monitor monitor --memlp --memlp-checkpoint /var/lib/talus/memlp.json
```

Alerts carry the neural verdict in every output channel:

```
12:00:03 SUSPICIOUS [4132] encrypt.sh opened 50 files in 1s!  [MeMLP R:ransomware 91% L:normal 99% P:suspect 74%]
```

```json
{"type":"alert","pid":4132,"comm":"encrypt.sh","opens_in_1s":50,
 "memlp":{"ransomware":{"module":"ransomware","class":2,"label":"ransomware","confidence":0.91}, ...}}
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Linux kernel **5.8+** | eBPF + tracepoint support |
| **root** (`CAP_BPF` / `CAP_SYS_ADMIN`) | Required to load eBPF programs |
| Rust **nightly** + `rust-src` | Builds eBPF with `-Z build-std` |
| `bpf-linker`, `clang` | eBPF toolchain |
| BTF (`/sys/kernel/btf/vmlinux`) | Recommended for CO-RE |

---

## Usage

```bash
# EDR mode — detect and auto-kill
sudo process-monitor monitor --auto-kill

# Lower threshold for stricter detection
sudo process-monitor monitor --auto-kill --alert-threshold 20

# Monitor only (no kill)
sudo process-monitor monitor

# Filter by extension
sudo process-monitor monitor --filter-ext pdf

# JSON output for external pipelines
sudo process-monitor monitor --json | jq .

# Plain text log
sudo process-monitor monitor --plain

# Web dashboard (requires --features web build)
sudo process-monitor monitor --web 0.0.0.0:8080

# MeMLP neural detection engine (online training + JSON checkpoints)
sudo process-monitor monitor --memlp
sudo process-monitor monitor --memlp --memlp-checkpoint /var/lib/talus/memlp.json

# Self-diagnostic
sudo process-monitor monitor --diagnose
```

### CLI Reference

| Flag | Default | Description |
|---|---|---|
| `-b, --bpf <PATH>` | auto | Path to compiled eBPF object |
| `--alert-threshold <N>` | `50` | Alert when N+ files opened within 1s |
| `--auto-kill` | off | **Send SIGKILL to processes that trigger alerts** |
| `--filter-ext <EXT>` | all | Filter by file extension |
| `--top-files <N>` | `8` | Top files in TUI |
| `--json` | off | Newline-delimited JSON output |
| `--plain` | off | Plain text log |
| `--memlp` | off | Enable the MeMLP neural detection engine |
| `--memlp-checkpoint <PATH>` | `~/.local/share/talus/memlp.json` | MeMLP checkpoint (load on start, autosave every 30s) |
| `--diagnose` | off | 5-second self-diagnostic |
| `--web <ADDR>` | off | Start web server (requires `--features web`) |

---

## Build Variants

```bash
# TUI-only (default, 1.7MB)
./build.sh

# Web-featured (2.5MB) — REST API, WebSocket, Prometheus
./build.sh --web

# Both variants
./build.sh --all
```

| Variant | Size | Dependencies |
|---|---|---|
| `process-monitor-tui` | 1.7MB | aya, frankentui (ftui), chrono, crossterm |
| `process-monitor-web` | 2.5MB | +axum, tokio, tower-http, prometheus-client |

---

## TUI Controls

| Key | Action |
|---|---|
| `q` / `Esc` | Quit |
| `p` | Pause / resume |
| `c` | Clear all panels |
| `↑`/`↓` / `k`/`j` | Scroll |
| `Tab` | Next panel |
| `1`-`7` | Jump to panel |
| `/` | Search mode |
| `?` / `h` | Help overlay |

### TUI Panels (7)

| # | Panel | Description |
|---|---|---|
| 1 | **EVENTS** | Live event log with search/filter |
| 2 | **PROCESSES** | Hierarchical process tree with alert counts |
| 3 | **NETWORK** | Real-time connections (connect/accept/send/recv + IP:port) |
| 4 | **TOP FILES** | Most-opened files with Shannon entropy |
| 5 | **FILE TYPES** | Extension frequency with coloured bars |
| 6 | **ALERTS** | Alert history + response actions |
| 7 | **HEATMAP** | Syscall frequency visualisation |

---

## Web Dashboard

Optional build with `--features web`:

```bash
cargo build --release --features web
sudo process-monitor monitor --web 0.0.0.0:8080
```

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/ws` | WebSocket | Live event stream |
| `/api/v1/stats` | GET | Global statistics |
| `/api/v1/processes` | GET | Tracked processes |
| `/api/v1/files` | GET | Top opened files |
| `/api/v1/extensions` | GET | Extension frequency |
| `/api/v1/threshold` | POST | Update threshold at runtime |
| `/metrics` | GET | Prometheus metrics |

---

## Operator View (TUI + Web + Desktop)

Talus provides three operator interfaces:

- **TUI** — 7-panel terminal interface for local investigation. Cyberpunk aesthetic, process trees, heatmaps, sparklines. Runs anywhere, no browser needed.
- **Web Dashboard** — browser-based UI with WebSocket live stream, REST API for integration, and Prometheus metrics for Grafana/monitoring stacks.
- **Desktop App (Tauri + React)** — native desktop GUI built with Tauri 2 + React 19 + Recharts. Connects to the talus backend via WebSocket and REST API. See [`talus-tauri/`](talus-tauri/) for source.

All three consume the same detection engine — the agent is **headless-capable** and can run as a background daemon with JSON output piped to external SIEM/storage.

---

## Project Structure

```
talus-process-monitor/
├── process-monitor/          # Userspace: detection engine + TUI + web + FFI
│   └── src/
│       ├── main.rs           # CLI, mode selection, signal handling
│       ├── monitor.rs        # eBPF loading, perf reader, detection, response
│       ├── tui.rs            # 7-panel frankentui (ftui) cyberpunk interface
│       ├── web.rs            # axum web server (--features web)
│       ├── ffi.rs            # C FFI bindings (libtalus)
│       └── storage/          # Kafka / ClickHouse / MemGraph backends
├── process-monitor-ebpf/     # Kernel side (#![no_std], aya-ebpf)
│   └── src/
│       ├── main.rs           # execve/openat → PerfEventArray
│       ├── network.rs        # connect/accept/sendto/recvfrom + sockaddr
│       └── fs.rs             # mkdir/unlink/kill/chmod tracepoints
├── frankentui/               # FrankenTUI — self-hosted terminal UI kernel
│   └── ftui-*/               # ftui-core, ftui-render, ftui-runtime, ... (crates)
├── c-ebpf/                   # Standalone C eBPF programs (ebpf.c, process_monitor.bpf.c)
├── go-agent/                 # Go CLI agent (HTTP/WebSocket client)
├── go-web/                   # Go web frontend (main.go)
├── c-api/                    # C header for libtalus
├── talus-tauri/              # Tauri desktop dashboard (React + Rust)
├── k8s/                      # Kubernetes manifests (DaemonSet, Service)
├── proto/                    # Protobuf schema (gRPC)
├── fuzz/                     # Fuzzing harness
├── demos/                    # Recorded demo tape
├── docs/                     # Landing page, reports (TEST_REPORT, VERIFICATION-EBPF, NEW_FEATURES), licensing docs
├── screenshots/              # TUI screenshots
├── build.sh                  # Build script (--web / --all / --check)
├── install.sh                # Distro-aware installer
├── install-gui.sh            # Graphical (zenity) installer
└── Cargo.toml                # Workspace definition
```

---

## Tested Live on Linux

Talus has been **deployed and tested on real hardware** running Linux:

```bash
# Verify eBPF tracepoints exist
ls /sys/kernel/tracing/events/syscalls/sys_enter_execve/id

# Load and attach eBPF programs
sudo process-monitor monitor --diagnose

# Watch live events in another terminal
ls -la /tmp
# → Talus shows: 14:09:16 OPEN [29645] bash → /tmp

# Test auto-kill
sudo process-monitor monitor --alert-threshold 3 --auto-kill
# In another terminal: for i in $(seq 1 100); do touch /tmp/f$i; done
# → Talus kills the process after 3 opens in 1s

# Verify with bpftool
bpftool prog list      # shows attached tracepoints
bpftool map dump name events  # shows perf event array
```

---

## Docker / Kubernetes

```bash
# Docker (--privileged: eBPF needs kernel access; BTF mounted read-only for CO-RE)
docker build -t talus-process-monitor .
docker run --privileged --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro talus-process-monitor

# Kubernetes (DaemonSet on every node)
kubectl apply -f k8s/
```

---

## Enterprise Maturity

Talus follows a **20-level enterprise maturity model** — from open-source prototype to Fortune 500 ready.

| Level | Area | Status |
|---|---|---|
| L0 | Open Source Prototype | ✅ |
| L1 | Supply Chain Security (cargo-deny, SBOM, gitleaks) | ✅ |
| L2 | Build Provenance (SLSA, cosign, attestation) | ✅ |
| L3 | Security Hardening (seccomp, caps, Landlock, audit) | ✅ |
| L4 | Quality Gates (78 tests, clippy clean) | ✅ |
| L5 | Agent Sandbox (seccomp-BPF, capability drop, Landlock) | ✅ |
| L6 | Signed Audit Log (hash chain, SOC2 compliance) | ✅ |
| L7 | Web Security (TLS, API auth, restricted CORS) | ✅ |
| L8–L20 | Observability → Compliance → Enterprise | 🔜 |

📄 [Full Enterprise Report (PDF)](docs/talus-enterprise-maturity-report.pdf) · [Maturity Model](MATURITY.md)

---

## Security & Hardening

Talus is a security agent — it must be secure itself. Enterprise edition includes:

### Agent Self-Sandboxing (`sandbox.rs`)

| Layer | Mechanism | What it does |
|-------|-----------|-------------|
| **Capability dropping** | `prctl(PR_CAPBSET_DROP)` | Drops from root to 3 caps: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` |
| **seccomp-BPF** | Whitelist syscall filter | Allows only ~75 syscalls needed for event loop; blocks `ptrace`, `bpf`, `execve`, `fork`, `open_by_handle_at`, `mount`, `init_module` |
| **Landlock LSM** | Kernel ≥5.13 filesystem restrictions | Read-only access to `/sys/kernel/debug`, `/proc`, `~/.config/talus`, BPF object path only |

```bash
[sandbox] dropped 37 capabilities, kept: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN
[sandbox] seccomp-BPF filter installed (75 allowed syscalls)
[sandbox] Landlock FS restrictions applied
[sandbox] hardening applied ✓
```

### Signed Audit Log (`audit.rs`)

Every license operation is recorded in a **tamper-proof hash chain** (SOC2/ISO27001 compliance):

```
Each entry = SHA-256(HMAC(machine_key, prev_hash + timestamp + event + license_id + detail))
```

| Event | When |
|-------|------|
| `ACTIVATED` | License key activated |
| `DEACTIVATED` | License deactivated |
| `EXPIRED` | License expired |
| `MISMATCH` | Machine fingerprint mismatch |
| `TRANSFER` | License transferred to another machine |

```bash
process-monitor license audit-log          # Show last 20 entries
process-monitor license verify-audit       # Verify hash chain integrity
```

### License Security (`license.rs`)

| Feature | Implementation |
|---------|---------------|
| **Ed25519 signing** | License keys signed with Ed25519 keypair |
| **Machine fingerprint** | License bound to hardware (CPU, motherboard, MAC) |
| **Encryption at rest** | XOR encryption with machine-derived key |
| **File permissions** | `0600` on `license.dat`, `0700` on config dir |
| **Rate limiting** | Max 5 activation attempts per 5 minutes |
| **Binary integrity** | XOR checksum detects key substitution |
| **Config HMAC** | HMAC on `license.dat` + `.trial.dat` detects tampering |
| **Offline grace** | 30-day grace period without internet |
| **Downgrade protection** | Cannot downgrade from Enterprise |
| **Server-side seat enforcement** | `max_seats` checked in D1 at activation (`license-server/`) |
| **Signed-key cache binding** | Local cache re-verified against the Ed25519 signature on every load — edited tier/expiry is rejected |
| **Trial integrity tag** | SHA-256 tag ties the trial marker to binary + machine — copied/edited trial files are voided |
| **Public-key-only server** | The activation worker cannot forge licenses even if fully compromised |

### Web Dashboard Security (`web.rs`)

| Feature | Implementation |
|---------|---------------|
| **TLS (rustls)** | Self-signed cert, HTTPS only |
| **API token auth** | `Authorization: Bearer <token>` or `X-API-Token: <token>` |
| **Restricted CORS** | Only `https://localhost` allowed |
| **Auth on all endpoints** | `TALUS_WEB_AUTH=1` env var enables auth on GET/POST |

### Watchdog (`watchdog.rs`)

Fail-closed heartbeat monitoring — if the eBPF pipeline crashes:

```bash
[watchdog] ⚠ ALARM: no heartbeat for 10s — eBPF pipeline may be unresponsive
[watchdog] ✓ heartbeat restored — pipeline recovered
```

Webhook alarm via `TALUS_ALARM_WEBHOOK` env var.

---

## Licensing & Pricing

Talus is available in two editions:

| Feature | Community (Free) | Enterprise |
|---------|:---:|:---:|
| eBPF process monitoring | ✅ | ✅ |
| TUI dashboard (7 panels) | ✅ | ✅ |
| JSON / plain text output | ✅ | ✅ |
| Ransomware detection alerts | ✅ | ✅ |
| Auto-kill (EDR response) | ❌ | ✅ |
| Web dashboard & REST API | ❌ | ✅ |
| WebSocket live stream | ❌ | ✅ |
| Prometheus /metrics | ❌ | ✅ |
| Kafka event streaming | ❌ | ✅ |
| ClickHouse analytics | ❌ | ✅ |
| MemGraph process graphs | ❌ | ✅ |
| C FFI library | ❌ | ✅ |
| Agent sandboxing (seccomp/caps/Landlock) | ❌ | ✅ |
| Signed audit log (hash chain) | ❌ | ✅ |
| TLS + API auth on dashboard | ❌ | ✅ |
| Priority support | ❌ | ✅ |

### License Management

```bash
process-monitor license show              # View license status
process-monitor license activate <KEY>    # Activate online
process-monitor license deactivate        # Deactivate
process-monitor license export-json       # Export as JSON
process-monitor license backup license.json       # Backup
process-monitor license restore license.json      # Restore
process-monitor license transfer          # Transfer to another machine
process-monitor license audit-log         # View audit trail
process-monitor license verify            # Verify validity
```

### 30-Day Enterprise Trial

Talus includes a **30-day Enterprise trial** on first run. No activation required — all Enterprise features are available during the trial period.

### Getting a License

Enterprise licenses are sold directly by the author:

- 🛒 Purchase via the payment link shared by the author (Gumroad / Lemon
  Squeezy / bank transfer) — see the pricing **structure** in
  [docs/pricing-tiers.md](docs/pricing-tiers.md) (amounts are set per sale,
  not in the repo)
- 📧 Contact: [@BartoszOsiej](https://github.com/BartoszOsiej) — volume &
  team agreements (10+ seats)
- 📜 Terms: [docs/EULA.txt](docs/EULA.txt)

## Support & Services

Need help deploying Talus, or want it tuned to your environment?

- 🎉 **This week only (Sep 22–27):** code `WEEK30` = 30% off everything below at checkout.
- 🛠️ **Support Session — $150**: 60-minute 1:1 call + written config. Threshold
  tuning for your workload, false-positive triage, systemd/alert routing,
  response-playbook design. [Book instantly](https://polar.sh/checkout/polar_c_rGI15C7IzCs54qElT4NJ5aLj7o3p7Uxdj4P4T1OtUsU).
- 🏢 **Enterprise — $50 one-time**: [direct checkout](https://buy.polar.sh/f8fee751-6cde-4a3b-b3cd-6e302ce8f5a8)
  (auto-kill response, web dashboard, Kafka/ClickHouse export — full matrix above).
- 📧 Volume, on-prem or custom integrations: bartosz.osiej2007@gmail.com

### How Licensing Works

```
talus-keygen issue ──► signed key (Ed25519) ──► customer
                                                  │
                                        process-monitor license activate <KEY>
                                                  ▼
              Cloudflare Worker + D1 (primary, free tier) ── signature
              check, expiry, revocation, seat limits ──► activation token
              (automatic failover: talus-license-failover worker —
               same shared storage, transparent for the client)
```

**Buying from a store (Polar / Gumroad / Lemon Squeezy)?** You don't need a
special Talus key at all — paste the license key you received from the
store straight into `process-monitor license activate <KEY>`. The activation server
recognizes store purchases and translates the store key into your Talus
license automatically (signing happens offline; store keys are stored only
as hashes).

- Keys are **Ed25519-signed**; the binary embeds only the public key
- The **activation server** (`license-server/`) holds the public key only —
  the signing key never leaves the owner's machine
- **Automatic failover**: activation, deactivation and store-key redemption
  try the primary server first, then the failover worker — both serve the
  same shared storage, so seats and revocations are identical everywhere.
  Override with `TALUS_LICENSE_SERVER` (primary) and
  `TALUS_LICENSE_SERVER_FAILOVER` (comma-separated endpoints; set it to an
  empty string to disable failover)
- **Seats are enforced server-side**; moving a machine is
  `deactivate` → `activate`
- Revoked or expired keys are refused at activation; local cache is
  re-verified against the signed key on every load

Customer walkthrough: [docs/customer-activation-guide.md](docs/customer-activation-guide.md)

### Admin Panel (owner only)

The license server ships with a browser admin panel — the worker serves it
at [`/admin`](https://talus-license-server.metaforicmail.workers.dev/admin).
Login is two-factor: auth code (`ADMIN_TOKEN`) + a 6-digit TOTP code from
Google Authenticator. Sessions last 12 h; a used TOTP code can never be
replayed. There is also a local-only variant in [`admin-panel/`](admin-panel/)
(token never leaves your machine). Day-to-day ops:

```bash
scripts/issue-license.sh        # issue a signed license key
scripts/revoke-license.sh       # block a key everywhere
scripts/list-activations.sh     # who activated where
scripts/health-check.sh         # is the server up
../scripts/setup-totp.sh        # one-time: enable TOTP login for /admin
```

### Source Code License

MIT (see [LICENSE](LICENSE) for details)

---

## Deep Dives

Extended dossiers (architecture, verification, benchmarks, error codex) ship in this repo:
- [VERIFICATION-EBPF.md](docs/VERIFICATION-EBPF.md)
- [SECURITY.md](SECURITY.md)
