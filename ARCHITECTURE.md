# Talus Process Monitor — Architecture

This document describes the internal architecture of Talus Process Monitor:
the kernel-side eBPF programs, the userspace event pipeline, the sliding-window
alerting heuristic, and the output layer. It is intended for developers
extending or debugging the project.

---

## 1. System overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              KERNEL SPACE                                    │
│                                                                              │
│   syscall entry           eBPF tracepoint programs            map            │
│  ┌───────────┐   ┌──────────────────────────────────┐   ┌──────────────┐    │
│  │ execve    │──►│ process-monitor-ebpf             │──►│   EVENTS     │    │
│  │ openat    │   │  #[tracepoint] sys_enter_execve  │   │ PerfEventArray│   │
│  │ connect   │   │  #[tracepoint] sys_enter_openat  │   └──────┬───────┘    │
│  │ accept    │   │  #[tracepoint] sys_enter_connect │          │             │
│  │ sendto    │   │  #[tracepoint] sys_enter_accept  │          │             │
│  │ recvfrom  │   │  #[tracepoint] sys_enter_sendto  │          │             │
│  └───────────┘   │  #[tracepoint] sys_enter_recvfrom│          │             │
│                  └──────────────────────────────────┘          │             │
└─────────────────────────────────────────────────────────────────┼───────────┘
                                                                  │ per-CPU
                                                                  │ perf buffers
┌─────────────────────────────────────────────────────────────────▼───────────┐
│                             USERSPACE                                        │
│                                                                              │
│   ┌────────────────────┐   MPSC   ┌───────────────────────────────────────┐  │
│   │ talus-reader     │ channel  │ Monitor                               │  │
│   │ thread             │─────────►│  • sliding window per PID (1 s)       │  │
│   │  • open perf buf   │          │  • threshold alerting                 │  │
│   │  • decode events   │          │  • per-process stats                  │  │
│   └────────────────────┘          └──────────────┬────────────────────────┘  │
│                                                   │ Output::Event/Alert     │
│                         ┌─────────────────────────┴──────────────────┐       │
│                         │        Output layer (main thread)          │       │
│                         │  TUI (frankentui) │ JSON │ Plain │ Diagnose    │       │
│                         └────────────────────────────────────────────┘       │
└───────────────────────────────────────────────────────────────────────────────┘
```

Two crates form the workspace:

| Crate | Role | Toolchain |
|---|---|---|
| `process-monitor-ebpf` | Kernel-side tracepoint programs, `#![no_std]`, aya-ebpf | Rust **nightly** (`-Z build-std`) |
| `process-monitor` | Userspace: loader, reader thread, monitor core, TUI, web, FFI | Rust **stable** |
| `go-agent` | Go CLI agent connecting via HTTP/WebSocket | Go 1.22 |

---

## 2. Kernel side — `process-monitor-ebpf`

### 2.1 Program layout

`src/main.rs` defines two tracepoint programs and one map:

```
sys_enter_execve  ──┐
sys_enter_openat  ──┤
                    ├──► EVENTS: PerfEventArray<ProcessEvent>
sys_enter_connect ──┤
sys_enter_accept  ──┤
sys_enter_sendto  ──┤
sys_enter_recvfrom ─┘
```

Network tracepoints are defined in `src/network.rs` and share the same
`PerfEventArray` map.

Both programs run in **tracepoint context** on syscall entry, before the
kernel copies arguments, so all pointers to userspace memory are read with
`bpf_probe_read_user` — never dereferenced. This is what keeps the code
verifier-safe and immune to TOCTOU-style kernel pointer hazards.

### 2.2 Event record

The kernel and userspace agree on a fixed, `#[repr(C)]` layout so records can
be memcpy'd across the perf buffer without serialization:

```rust
pub struct ProcessEvent {
    pub event_type: u8,             // 0=EXEC, 1=OPEN, 2=CONNECT, 3=ACCEPT, 4=SENDTO, 5=RECVFROM
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],             // process comm (truncated)
    pub filename: [u8; 64],         // target path or IP:port (truncated)
    pub argv: [u8; 128],            // command line or bytes count
}
```

> **Size note:** `u8 + u32 + u32 + [u8;16] + [u8;64]` — an **85-byte payload**
> that occupies **92 bytes on the wire** (3 alignment-padding bytes before the
> first `u32`). Keeping the record small and fixed-size is what makes per-CPU
> perf buffering cheap — no allocation, no variable-length encoding in kernel
> context.

`event_type` distinguishes `execve` from `openat`; the userspace side maps it
to the `Kind::{Exec, Open}` enum.

### 2.3 Map

The `EVENTS` map is a `PerfEventArray` (one ring buffer per CPU). The kernel
program selects the current CPU's buffer implicitly; the userspace side opens
one reader per online CPU.

---

## 3. Userspace — `process-monitor`

### 3.1 Startup sequence (`Monitor::start`)

1. **Privilege check** — bails unless `geteuid() == 0`
   (`CAP_BPF` / `CAP_SYS_ADMIN` required).
2. **Object load** — `aya::Ebpf::load_file` parses the compiled eBPF object.
3. **Program load + attach** — each `TracePoint` program is loaded and attached
   to `syscalls/sys_enter_execve` and `syscalls/sys_enter_openat`.
4. **Map hand-off** — the `EVENTS` `PerfEventArray` is taken from the object
   and moved into the reader thread.
5. **Channel** — an MPSC channel connects the reader thread to the monitor.

### 3.2 Reader thread (`spawn_reader`, named `talus-reader`)

- Enumerates online CPUs and opens a `PerfEventArrayBuffer` per CPU.
- Loop: `read_events` on every buffer; batches are decoded into pre-allocated
  `BytesMut` pools (`OUT_BUFS` × `OUT_BUF_CAP`) to avoid per-event allocation.
- Counts `events.lost` (perf-buffer overruns) and forwards `Msg::Lost`.
- Decodes raw bytes into `RecordedEvent` via `to_recorded` (unsafe
  `read_unaligned` + `cstr_to_string` for the fixed-size byte arrays).
- Idles 1 ms when no buffer had events — a polling design with ~1 ms latency
  and near-zero CPU when idle.

> The workspace release profile sets `panic = "abort"`, so a panic in this
> thread aborts the process loudly instead of silently degrading to
> "events 0" forever.

### 3.3 Monitor core

Holds:

```
stats:        HashMap<u32, ProcStats>        // pid → cumulative stats
windows:      HashMap<u32, VecDeque<Instant>> // pid → open timestamps (1 s window)
file_counts:  HashMap<String, u64>            // path → total open count
ext_counts:   HashMap<String, u64>            // extension → total open count
rate_history: VecDeque<RateSample>            // per-second event counts (sparklines)
tick_execs/opens/alerts: u64                 // accumulated since last tick
```

`handle_event`:

1. Records the event into `ProcStats` (totals per kind, extension map).
2. For `Open` events, pushes the timestamp onto the PID's sliding window and
   evicts entries older than `WINDOW_SECS` (1 s).
3. Increments `file_counts` and `ext_counts` for file-extension tracking.
4. **Alert trigger:** when the window length reaches exactly `threshold`, an
   `Alert` is emitted (once per crossing; further opens keep counting). A
   threshold of `0` disables alerting entirely.

Every ~1 second, `poll()` flushes the tick counters into a `RateSample`
appended to `rate_history` (capped at 120 seconds). This powers the TUI's
sparkline rate charts.

`stats_sorted` returns processes ranked by current `opens/s` for the TUI's
"Top processes" panel. `top_files(n)` returns the N most-opened files with
normalised Shannon entropy scores. `extension_counts` feeds the "File Types"
panel. `uptime` and `total_lost` feed the status bar.

### 3.4 Output layer

`Monitor::poll` returns a `Vec<Output>` per tick, where

```rust
enum Output {
    Event(RecordedEvent),
    Alert(Alert),
}
```

The main thread routes these by mode:

| Mode | Implementation |
|---|---|
| **TUI** | `tui.rs` — ultra-advanced 7-panel cyberpunk interface: events, process tree, network, top files, extensions, alerts, heatmap. Search/filter, pane resize, help overlay, process detail view |
| **JSON** | `run_json` — one JSON object per line: events, alerts, network (see schema in `README.md`) |
| **Plain** | `run_plain` — human-readable timestamped lines with color |
| **Diagnose** | `run_diagnose` — verifies tracepoint IDs, loads + attaches, listens 5 s, prints counters |
| **Web** | `web.rs` — axum server with REST API, WebSocket, dashboard HTML, Prometheus `/metrics` (optional, `--features web`) |

Mode selection: `--tui` forces the TUI; otherwise `--json` / `--plain` select
their modes; with no flags and a TTY stdout, the TUI is the default (non-TTY
stdout defaults to plain, keeping pipes clean).

The TUI uses a resizable 3-column layout with 7 panels:
- **Left**: scrollable event log with search/filter, colour-coded EXEC/OPEN/CONNECT/ALERT tags
- **Middle**: hierarchical process tree (top) + file-type frequency bars (bottom)
- **Right**: network connections (top) + top-files with entropy (middle) + alerts (bottom)

Above the body: sparkline charts for exec/s, open/s, net/s, alert/s.
Below: status bar with live rates + keybinding footer.

Keyboard features:
- `/` search mode: filter events by text (PID, comm, file path)
- `?` help overlay: complete keybinding reference
- `Enter` on process tree: full hierarchy detail view
- `[`/`]` and `{`/`}`: resize column borders
- `1`-`7`: direct panel jump
- `Tab`/`Shift+Tab`: cycle panels

Signal handling (`install_signal_handler`) sets an atomic `QUIT` flag on
`SIGINT`/`SIGTERM` so loops exit cleanly and buffers flush.

---

## 4. Alerting heuristic

The ransomware heuristic is deliberately simple and observable:

> **For every PID, keep a 1-second sliding window of `openat` calls. If the
> window contains ≥ N opens (default 50), emit an alert.**

Design decisions:

- **Sliding window, not a rate counter** — a burst of 50 opens in 100 ms is
  just as alarming as 50 opens spread over a full second, and the window
  captures both without hysteresis or smoothing artifacts.
- **Per-process isolation** — `Cache2 I/O` hammering the Firefox cache does
  not alert because of what the browser is doing; it alerts on its *own* rate
  crossing the threshold.
- **Threshold `0` disables** the heuristic entirely for quiet deployments.
- **Fixed 1 s window** keeps memory bounded: each tracked PID holds at most a
  handful of `Instant`s, and eviction is amortized O(1).

### 4.1 MeMLP — neural detection engine (optional, `--memlp`)

Layered on top of the heuristic (never replacing it), Talus can run **MeMLP**:
a modular embedded multi-layer perceptron stack in `memlp.rs`, built from
scratch on flat `Vec<f32>` storage — no `ndarray`, no `tch`, no external
runtime. One JSON checkpoint holds three specialist heads:

| Module | Shape | Verdict |
|---|---|---|
| `ransomware` | 10 → 24 → 16 → 3 | benign / suspicious / ransomware |
| `lateral` | 10 → 12 → 2 | normal / suspect |
| `persistence` | 10 → 12 → 2 | normal / suspect |

Pipeline: every eBPF event feeds a per-PID `PidFeatures` accumulator (10
normalised behavioural features, 1-second half-life decay). When the heuristic
fires an alert, the current embedding is (a) scored by all three heads and
attached to the `Alert`, and (b) used as an online training sample against
transparent heuristic teachers — one backprop step, gradient-clipped and
update-bounded so no single sample can explode the weights (non-finite
weights are sanitised to 0.0 instead of poisoning the checkpoint with JSON
`null`).

Checkpoints autosave every 30 s from the monitor poll loop (the TUI and web
server own the `Monitor`, so a shutdown hook is not always reachable) and
reload on the next start; `training_samples` survives restarts. Weight init
is a seeded LCG — identical architectures always initialise identically, so
tests are reproducible.

---

## 5. Data flow summary

```
kernel                  userspace reader            monitor core                        output
──────────              ─────────────────          ─────────────                        ──────
openat entry   ──► EVENTS map ──► perf buffer ──► Msg::Event ──► sliding window     ──► TUI / JSON / plain
                                  (per CPU)           │          ├─ file_counts     ──► top-files panel
                                                      │          ├─ ext_counts      ──► file-types panel
                                                      │          ├─ rate_history    ──► sparkline charts
                                                      │          ├─ pid_features    ──► MeMLP heads (verdict + online train)
                                                      │          └─ Alert (on threshold) ──► alerts panel
                                                      └─ Msg::Lost ──► lost counter ──► status bar
```

---

## 6. Performance characteristics

| Aspect | Design |
|---|---|
| Kernel overhead | Two tracepoint programs; fixed-size record; no allocation |
| Userspace decode | Pre-allocated `BytesMut` pools; zero per-event allocation in the hot loop |
| Latency | Reader polls perf buffers continuously; events typically visible in <1 ms |
| Idle CPU | Reader sleeps 1 ms when no buffers have data |
| Memory | Sliding window evicts old entries every poll; maps bounded by live PIDs; rate_history capped at 120 samples |
| Binary | Full LTO + `strip = "symbols"` + `panic = "abort"` release profile |

---

## 7. Extending the project

### Add a syscall

1. Add a `#[tracepoint]` program in `process-monitor-ebpf/src/network.rs` (or `main.rs`),
   reading the new syscall's arguments with `bpf_probe_read_user` and pushing
   a `ProcessEvent` (reuse or extend `event_type`).
2. Load + attach it in `Monitor::start`.
3. Map the new `event_type` in `to_recorded` and extend `Kind` enum.
4. Add handling in `tui.rs` (panel), `main.rs` (JSON/plain), and `ffi.rs` (C API).

### Change the alert heuristic

- Threshold: CLI flag `--alert-threshold` (default 50).
- Window length: `WINDOW_SECS` in `monitor.rs`.
- Trigger semantics: the exact `== threshold` comparison in `handle_event`.

### Add an output mode

Add a variant to `Output` handling in `main.rs`, mirror `run_json` /
`run_plain`, and extend the mode-selection logic plus `Args` in the CLI.

### Add a TUI panel

1. Add a new `Panel` variant in `tui.rs`.
2. Add data collection in `monitor.rs` (if needed).
3. Implement the `draw_*` function in `tui.rs`.
4. Add to `draw_body` layout.
5. Update `Panel::all()` and `Panel::name()`.

---

## 8. Licensing subsystem

Talus has a commercial licensing layer (Community = MIT, Enterprise = paid)
spanning four components:

```
┌────────────────────┐   signs    ┌─────────────────────────────┐
│ talus-keygen       │──────────► │ license key                 │
│ (owner machine,    │  Ed25519   │ b64(payload).b64(signature) │
│  keys in           │            └──────────────┬──────────────┘
│  ~/.secrets/talus/)│                           │ delivered to customer
└────────────────────┘                           ▼
                                   ┌─────────────────────────────┐
                                   │ talus binary                │
                                   │ process-monitor/src/        │
                                   │   license.rs                │
                                   │ • embedded PUBLIC key only  │
                                   │ • local signature verify    │
                                   │ • machine fingerprint T-…   │
                                   │ • feature gating            │
                                   └──────────────┬──────────────┘
                                                  │ POST /api/v1/activate
                                                  ▼
                                   ┌─────────────────────────────┐
                                   │ license-server (CF Worker)  │
                                   │ • PUBLIC key only           │
                                   │ • signature, expiry,        │
                                   │   revocation checks         │
                                   │ • seat limits in D1         │
                                   │ • rate limit 5/5min/machine │
                                   └─────────────────────────────┘
```

### Components

| Component | Location | Trust anchor |
|---|---|---|
| Keygen CLI | `license-keygen/` | private key at `~/.secrets/talus/license-keys/` (never in repo) |
| License module | `process-monitor/src/license.rs` | `PUBLIC_KEY_BYTES` embedded at compile time, XOR `KEY_CHECKSUM` derived from it |
| Activation server | `license-server/` (Cloudflare Worker + D1, free tier) | `LICENSE_PUBLIC_KEY_HEX` var + `ADMIN_TOKEN` secret |
| Ops scripts | `scripts/` (issue / revoke / list-activations / health-check) | owner's admin token |

### Activation flow

1. Customer runs `talus license activate <KEY>`.
2. Binary verifies the Ed25519 signature locally, computes the machine
   fingerprint (`T-…`), and POSTs `{license_key, machine_id, hostname,
   version}` to the activation server (default
   `https://lic.hartwell-labs.pl`, override via
   `TALUS_LICENSE_SERVER`).
3. Server re-verifies the signature, checks expiry, revocation
   (`licenses.revoked` + `revocations`), and seats (`max_seats` from the
   signed payload's `seat_count`); same-machine re-activation returns the
   existing token (idempotent).
4. Server responds `{success, token, expires_at, tier, message}`; the binary
   caches the license (XOR-obfuscated, 0600) in `~/.config/talus/`.
5. On every start the cached payload is re-verified against the signed key —
   any divergence (tier/expiry/features/seats edited locally) invalidates the
   cache (fail-closed).

### Security properties and limits

- The signing key exists on the owner's machine only; neither the binary nor
  the server can mint licenses.
- Server-side state (D1) is the source of truth for revocation and seats.
- The local cache and trial marker are tamper-evident (cache ↔ signed-key
  binding; SHA-256 trial tag) — documented as tamper-*resistance*, not
  protection against a fully compromised binary (see SECURITY.md).
