# 🛡️ Talus — wykrywanie ransomware na poziomie jądra (eBPF + Rust)

**[English README](README.md)** · [Architektura](ARCHITECTURE.md) · [Artykuł: jak działa detekcja](https://dev.to/bartoszosiej/detecting-ransomware-with-ebpf-in-rust-4779)

**eBPF-owy agent detect-and-respond dla Linuksa**: tracepointy eBPF hakują syscalle na poziomie jądra, ruchome okno 1 s ocenia tempo otwierania plików per PID, a warstwa odpowiedzi **ubija podejrzany proces (`SIGKILL`)** w chwili werdyktu. Zmierzono na żywym desktopie: **~280 000 zdarzeń/s przy ~7,6% CPU** (bufory per-CPU, zero-copy do silnika detekcji w Ruście).

```bash
# Wykryj + zareaguj w jednej linii (build ~2 min)
./build.sh && sudo ./target/release/process-monitor monitor --auto-kill
```

<div align="center">

**Demo na żywo — TUI ze śledzeniem jądra w akcji:**

![Demo Talus: ransomware wykryty i zabity](assets/talus-demo.gif)

</div>

---

## Szybki start (30 sekund)

```bash
git clone https://github.com/BartoszOsiej/talus-process-monitor
cd talus-process-monitor
./build.sh                      # lub: ./install.sh --system

# tryb monitorowania (bez auto-kill)
sudo ./target/release/process-monitor monitor

# pełny tryb EDR: detekcja + automatyczna odpowiedź
sudo ./target/release/process-monitor monitor --auto-kill
```

**Docker (jedna linia):**

```bash
# --privileged jest wymagany: tracepointy eBPF potrzebują dostępu do jądra (CAP_BPF/CAP_SYS_ADMIN)
docker run --privileged --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro \
  ghcr.io/bartoszosiej/talus-process-monitor:latest
```

Gotowe binarki: [Releases](https://github.com/BartoszOsiej/talus-process-monitor/releases).

---

## Zobacz, jak łapie ransomware

Powtórz demo z góry w dwóch terminalach:

```bash
# Terminal 1 — Talus z niskim progiem i auto-kill
sudo ./target/release/process-monitor monitor --alert-threshold 50 --auto-kill

# Terminal 2 — symulacja masowego "szyfrowania" plików
for i in $(seq 1 500); do touch /tmp/victim$i.enc && cat /tmp/victim$i.enc >/dev/null; done
```

Oczekiwany wynik: w ciągu **~1 sekundy** Talus odpala alert i wysyła `SIGKILL` do pętli — panel ALERTS pokazuje werdykt na czerwono.

---

## Co robi

| Możliwość | Jak |
|---|---|
| **Śledzenie na poziomie jądra** | Tracepointy eBPF: `execve`, `openat`, `connect`, `accept`, `sendto`, `recvfrom`, `mkdir`, `unlinkat`, `kill`, `fchmodat` |
| **Detekcja ransomware** | Ruchome okno 1 s per PID; alert przy przekroczeniu progu otwierań |
| **Automatyczna odpowiedź** | `--auto-kill` wysyła `SIGKILL` do procesu wywołującego alert |
| **Telemetria sieci** | Parsowanie `sockaddr` w jądrze — IPv4/IPv6/Unix na connect/accept/send/recv |
| **Potok zdarzeń** | Perf buffer jądra → zero-copy → silnik detekcji → TUI / JSON / WebSocket / Prometheus |
| **Ranking plików** | Najczęściej otwierane pliki z entropią Shannona (wykrywa losowe/szyfrowane nazwy) |
| **Pojedyncza binarka** | Pełne LTO, `panic = "abort"`, bez symboli — 1,7 MB TUI, 2,5 MB z webem |
| **SIEM** | Kafka (lz4), ClickHouse (MergeTree), MemGraph (grafy procesów, Cypher) |
| **Silnik neuronowy MeMLP** | Opcjonalny `--memlp`: MLP budowany od zera, trening online, checkpointy JSON |

## Wymagania

| Wymaganie | Uwagi |
|---|---|
| Jądro Linux **5.8+** | eBPF + tracepointy |
| **root** (`CAP_BPF` / `CAP_SYS_ADMIN`) | ładowanie programów eBPF |
| Rust **nightly** + `rust-src`, `bpf-linker`, `clang` | toolchain eBPF (`./build.sh` zainstaluje sam) |
| BTF (`/sys/kernel/btf/vmlinux`) | zalecane dla CO-RE |

## Klawisze TUI

| Klawisz | Akcja |
|---|---|
| `q` / `Esc` | Wyjście |
| `p` | Pauza / wznowienie |
| `Tab` / `1`-`7` | Panel następny / skok do panelu |
| `/` | Szukanie w zdarzeniach |
| `?` | Pomoc |

**7 paneli:** EVENTS · PROCESSES · NETWORK · TOP FILES · FILE TYPES · ALERTS · HEATMAP

## Dashboard webowy (opcjonalny)

```bash
./build.sh --web
sudo ./target/release/process-monitor monitor --web 0.0.0.0:8080
```

REST API + WebSocket (strumień na żywo) + `/metrics` dla Prometheusa.

## Rozwiązywanie problemów

```bash
sudo ./target/release/process-monitor monitor --diagnose   # 5-sekundowa autodiagnostyka
```

- **Brak zdarzeń** → sprawdź `/sys/kernel/tracing/events/syscalls/`
- **Błąd ładowania eBPF** → podaj `--bpf` jawnie albo odpal `./build.sh`
- **Brak root** → wymagane `CAP_BPF` lub `CAP_SYS_ADMIN`

## Licencjonowanie

Dwie edycje — **Community** (darmowa, MIT) i **Enterprise** (jednorazowa płatność, klucze podpisane Ed25519, aktywacja online z automatycznym failoverem).

| Funkcja | Community | Enterprise |
|---|:---:|:---:|
| Monitorowanie eBPF + TUI (7 paneli) | ✅ | ✅ |
| Alerty ransomware | ✅ | ✅ |
| Auto-kill (tryb EDR) | ❌ | ✅ |
| Dashboard webowy + REST API | ❌ | ✅ |
| Kafka / ClickHouse / MemGraph | ❌ | ✅ |
| Sandbox agenta (seccomp/caps/Landlock) + podpisany audit log | ❌ | ✅ |

Przy pierwszym uruchomieniu włącza się **30-dniowy trial Enterprise** — bez karty i rejestracji.

```bash
process-monitor license activate <KLUCZ>
sudo process-monitor monitor --auto-kill --web 0.0.0.0:8443
```

Szczegóły (EN): [README.md](README.md) · przewodnik kupującego: [docs/customer-activation-guide.md](docs/customer-activation-guide.md) · warunki: [docs/EULA.txt](docs/EULA.txt)

## Licencja

Community: MIT ([LICENSE](LICENSE)). Enterprise: [docs/EULA.txt](docs/EULA.txt).
