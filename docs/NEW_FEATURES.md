# Talus Process Monitor — New Features (v0.4.0-dev)

## 🖥️ Ultra-Advanced TUI (Default)

The TUI is the **default and primary interface**. Feature-rich cyberpunk dashboard.

### Panels (7 total)

| # | Panel | Description |
|---|---|---|
| 1 | **EVENTS** | Live event log with search/filter |
| 2 | **PROCESSES** | Hierarchical process tree with mini-bars |
| 3 | **NETWORK** | Real-time network connections (connect/accept/send/recv) |
| 4 | **TOP FILES** | Most-opened files with Shannon entropy |
| 5 | **FILE TYPES** | Extension frequency with colored bars |
| 6 | **ALERTS** | Alert history with timestamps |
| 7 | **HEATMAP** | Syscall frequency visualization |

### Keyboard Shortcuts

| Key | Action |
|---|---|
| `q` / `Esc` | Quit (or clear scroll) |
| `p` | Pause / resume |
| `c` | Clear all panels |
| `↑`/`↓` / `k`/`j` | Scroll up/down |
| `PgUp`/`PgDn` | Page up/down |
| `g` / `Home` | Jump to top |
| `G` / `End` | Jump to bottom |
| `Tab` | Next panel |
| `Shift+Tab` | Previous panel |
| `1`-`7` | Jump to panel by number |
| `Enter` | Open process detail view |
| `/` | Start search mode |
| `?` / `h` | Show help overlay |
| `[` / `]` | Resize left pane |
| `{` / `}` | Resize middle pane |

### Features

- **Search/filter**: Type `/` to filter events by text (PID, comm, file path)
- **Process detail**: Press `Enter` on process tree to see full hierarchy
- **Help overlay**: Press `?` for complete keybinding reference
- **Pane resize**: Drag column borders with `[`/`]` and `{`/`}`
- **Rate display**: Real-time events/s, opens/s, network/s, alerts/s
- **Network panel**: Live view of connect/accept/sendto/recvfrom with IP:port
- **Heatmap**: Syscall frequency visualization (exec, open, network, alerts)
- **Mini-bars**: Visual bar indicators in process tree and file ranking
- **Color-coded severity**: Red for alerts, green for safe, yellow for warnings

---

## 🌐 Web Dashboard (Optional)

Full-featured web server with REST API, WebSocket live events, and cyberpunk dashboard.
**Enterprise.** Built from a private crate; `--web` refuses in this build.

### Enable

```bash
sudo process-monitor --web 0.0.0.0:8080
```

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Cyberpunk web dashboard (auto-refresh) |
| `/ws` | WebSocket | Live event stream |
| `/api/v1/stats` | GET | Global statistics |
| `/api/v1/processes` | GET | Tracked processes |
| `/api/v1/files` | GET | Top opened files |
| `/api/v1/extensions` | GET | File extension frequency |
| `/api/v1/rates` | GET | Rate history (sparklines) |
| `/api/v1/process-tree` | GET | Hierarchical process tree |
| `/api/v1/threshold` | POST | Update alert threshold at runtime |
| `/metrics` | GET | Prometheus metrics |

### Usage

```bash
# Start web server on port 8080
sudo process-monitor --web 0.0.0.0:8080

# With custom threshold
sudo process-monitor --web 0.0.0.0:8080 --alert-threshold 100

# Access dashboard
open http://localhost:8080/

# WebSocket client
wscat -c ws://localhost:8080/ws
```

### WebSocket Events

```json
{
  "type": "event",
  "ts": "14:09:16.531",
  "kind": "Open",
  "pid": 29645,
  "uid": 1000,
  "comm": "process-monitor",
  "file": "/dev/tty"
}
```

---

## 📊 Prometheus Metrics

Built-in `/metrics` endpoint with OpenMetrics format.
**Enterprise — private crate.**

### Metrics

| Metric | Type | Description |
|---|---|---|
| `talus_events_total` | Counter | Total eBPF events received |
| `talus_exec_events_total` | Counter | Total execve events |
| `talus_open_events_total` | Counter | Total openat events |
| `talus_alerts_total` | Counter | Total alerts fired |
| `talus_lost_events_total` | Counter | Lost events (perf buffer overruns) |
| `talus_ws_connections_total` | Counter | Total WebSocket connections |

### Example Prometheus config

```yaml
scrape_configs:
  - job_name: 'talus'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

---

## 🔌 Network Syscalls (eBPF)

New tracepoints for network observability:

| Syscall | Event Type | Captures |
|---|---|---|
| `connect` | `EVENT_CONNECT` | Remote IPv4/IPv6/Unix address |
| `accept` | `EVENT_ACCEPT` | Remote address |
| `sendto` | `EVENT_SENDTO` | Destination + bytes sent |
| `recvfrom` | `EVENT_RECVFROM` | Source + bytes received |

### Event format

```json
{
  "type": "event",
  "kind": "Connect",
  "pid": 1234,
  "comm": "curl",
  "file": "93.184.216.34:443"
}
```

---

## 🤖 Go Agent

Lightweight CLI that connects to the Talus daemon via HTTP/WebSocket.

### Build

```bash
cd go-agent
go build -o talus-agent .
```

### Usage

```bash
# Show stats
./talus-agent stats

# List processes
./talus-agent processes

# Top files
./talus-agent files

# File extensions
./talus-agent extensions

# Process tree
./talus-agent tree

# Watch live events
./talus-agent watch

# JSON output
./talus-agent --json stats
```

---

## 🏗️ C FFI Library (libtalus)

C-compatible library for integrating Talus with other languages (Python, C++, Rust, etc.).

### Header

```c
#include "talus.h"

talus_monitor_t* monitor;
talus_monitor_create("/path/to/bpf.o", 50, &monitor);

talus_event_t events[100];
uint32_t count;
talus_monitor_poll(monitor, events, 100, &count);

for (uint32_t i = 0; i < count; i++) {
    printf("[%d] %s\n", events[i].pid, events[i].comm);
    talus_free_string(events[i].comm);
}
talus_free_events(events, count);

talus_monitor_destroy(monitor);
```

### Functions

| Function | Description |
|---|---|
| `talus_monitor_create()` | Create monitor instance |
| `talus_monitor_destroy()` | Destroy monitor instance |
| `talus_monitor_poll()` | Poll for events |
| `talus_monitor_stats()` | Get statistics |
| `talus_monitor_processes()` | Get tracked processes |
| `talus_monitor_top_files()` | Get top opened files |
| `talus_monitor_set_threshold()` | Update threshold |
| `talus_free_string()` | Free a C string |
| `talus_free_events()` | Free events array |
| `talus_free_processes()` | Free process stats array |
| `talus_free_files()` | Free file ranks array |

---

## ☸️ Kubernetes Deployment

DaemonSet for running Talus on every node in a Kubernetes cluster.

### Deploy

```bash
kubectl create namespace observability
kubectl apply -f k8s/
```

### Components

| Resource | Description |
|---|---|
| `DaemonSet` | Runs Talus on every node with eBPF access |
| `Service` | ClusterIP service for API access |
| `ConfigMap` | Configuration (threshold, log level, etc.) |
| `ServiceMonitor` | Prometheus operator integration |

### Requirements

- Linux kernel 5.8+
- BTF enabled (`/sys/kernel/btf/vmlinux`)
- `hostPID: true` and `privileged: true` for eBPF

---

## 📝 Protobuf Schema

gRPC service definition for inter-component communication.

### Service

```protobuf
service TalusService {
    rpc GetStats(Empty) returns (MonitorStats);
    rpc GetProcesses(Empty) returns (ProcessList);
    rpc GetTopFiles(TopFilesRequest) returns (FileRankList);
    rpc WatchEvents(WatchRequest) returns (stream EventMessage);
    // ...
}
```

### Generate code

```bash
# Rust
protoc --rust_out=src/proto --grpc_out=src/proto proto/talus.proto

# Go
protoc --go_out=go-agent --go-grpc_out=go-agent proto/talus.proto

# Python
protoc --python_out=python-agent proto/talus.proto
```

---

## 🎯 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        KUBERNETES NODE                          │
│                                                                 │
│  ┌──────────────────┐     ┌──────────────────────────────────┐ │
│  │  Talus Daemon  │     │         eBPF Kernel Space        │ │
│  │  (Rust)          │     │                                  │ │
│  │                  │     │  ┌─────────┐  ┌─────────┐       │ │
│  │  ┌────────────┐  │     │  │ execve  │  │ openat  │       │ │
│  │  │ Web Server │  │     │  └────┬────┘  └────┬────┘       │ │
│  │  │ (axum)     │  │     │       └──────┬─────┘            │ │
│  │  │            │  │     │              │                   │ │
│  │  │ REST API   │  │     │  ┌───────────▼──────────┐       │ │
│  │  │ WebSocket  │  │     │  │ connect  accept      │       │ │
│  │  │ Dashboard  │  │     │  │ sendto   recvfrom    │       │ │
│  │  └────────────┘  │     │  └───────────┬──────────┘       │ │
│  │                  │     │              │                   │ │
│  │  ┌────────────┐  │     │  ┌───────────▼──────────┐       │ │
│  │  │ Prometheus │  │     │  │   PerfEventArray     │       │ │
│  │  │ /metrics   │  │     │  └───────────┬──────────┘       │ │
│  │  └────────────┘  │     └──────────────┼──────────────────┘ │
│  │                  │                    │                     │
│  │  ┌────────────┐  │     ┌──────────────▼──────────────────┐ │
│  │  │ FFI (C)    │  │     │       Userspace Reader          │ │
│  │  └────────────┘  │     │       (per-CPU perf buffers)    │ │
│  └──────────────────┘     └──────────────┬──────────────────┘ │
│                                          │                     │
│  ┌──────────────────┐     ┌──────────────▼──────────────────┐ │
│  │   Go Agent       │◄───►│       Monitor Core              │ │
│  │   (CLI/Daemon)   │     │       (sliding window, alerts)  │ │
│  └──────────────────┘     └──────────────┬──────────────────┘ │
│                                          │                     │
│                              ┌───────────▼──────────┐         │
│                              │   Output Layer       │         │
│                              │   TUI│JSON│Plain│Web │         │
│                              └──────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# Build everything
./build.sh                    # Rust (eBPF + userspace)
cd go-agent && go build       # Go agent
gcc -shared -o libtalus.so -I c-api ffi.rs  # C library (via Rust)

# Run with web dashboard
sudo process-monitor --web 0.0.0.0:8080

# Deploy to Kubernetes
kubectl apply -f k8s/

# Use Go agent
./talus-agent watch
```

---

## 🎯 Odigos Relevance

These features demonstrate expertise in areas directly relevant to Odigos:

| Feature | Odigos Relevance |
|---|---|
| **eBPF tracepoints** | Core Odigos instrumentation method |
| **Rust + Go** | Odigos uses Go for control plane, eBPF for data plane |
| **Kubernetes DaemonSet** | Standard deployment model for Odigos |
| **Prometheus metrics** | Odigos integrates with Prometheus ecosystem |
| **Protobuf/gRPC** | Inter-component communication in Odigos |
| **WebSocket live events** | Real-time observability dashboard |
| **Network syscalls** | HTTP/gRPC auto-instrumentation |
| **C FFI** | Language-agnostic agent integration |
