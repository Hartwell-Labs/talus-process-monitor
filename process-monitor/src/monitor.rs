use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use aya::maps::perf::{PerfEvent, PerfEventArrayBuffer};
use aya::maps::{MapData, PerfEventArray};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Ebpf;

pub const EVENT_EXECVE: u8 = 0;
pub const EVENT_OPENAT: u8 = 1;
pub const EVENT_CONNECT: u8 = 2;
pub const EVENT_ACCEPT: u8 = 3;
pub const EVENT_SENDTO: u8 = 4;
pub const EVENT_RECVFROM: u8 = 5;
pub const EVENT_MKDIR: u8 = 6;
pub const EVENT_UNLINK: u8 = 7;
pub const EVENT_KILL: u8 = 8;
pub const EVENT_CHMOD: u8 = 9;

const EVENT_COMM_LEN: usize = 16;
const EVENT_FILENAME_LEN: usize = 64;
const EVENT_ARGV_LEN: usize = 128;
const WINDOW_SECS: u64 = 1;
/// A PID with no events for this long is forgotten (stats, window, parent link,
/// behavioural features). It is re-created on its next event.
const IDLE_PID_TTL_SECS: u64 = 600;
/// Tighter TTL used while more than `MAX_TRACKED_PIDS` PIDs are tracked
/// (fork storms), so memory stays bounded without evicting busy processes.
const PRESSURE_PID_TTL_SECS: u64 = 30;
const MAX_TRACKED_PIDS: usize = 65_536;
/// When a PID's parent lookup fails at `/proc/<pid>/status` (process already
/// exited), we know it is dead and can forget it after this short grace period.
/// This is what keeps `build_process_tree` cheap under `hyprctl` fork storms:
/// without it, dead short-lived PIDs linger up to `IDLE_PID_TTL_SECS` (600 s)
/// and each one becomes an orphan root node, ballooning tree size and sort cost.
const DEAD_PID_GRACE_SECS: u64 = 5;

/// Learning rate for MeMLP online training (conservative — one step per alert).
const MEMLP_LEARNING_RATE: f32 = 0.03;
/// Train MeMLP only on every Nth alert to avoid CPU spikes under high event
/// rates (300K+ evts/s). Assessment (inference) still runs on every alert.
const MEMLP_TRAIN_INTERVAL: u64 = 10;
/// Maximum events included in a single TUI snapshot. Beyond this, only the
/// most recent events are shown (log tail), preventing render stalls at
/// 30K+ events per 200ms poll cycle. 1000 captures ~40ms of activity at
/// 25K evts/s — enough to reliably catch brief bursts like 30x touch/exec
/// that would otherwise fall outside the tail.
pub const TUI_SNAPSHOT_EVENT_CAP: usize = 1000;
/// Upper bound on the Monitor's internal event ring buffer. When full, oldest
/// entries are evicted (FIFO) — only the tail survives to be drained into TUI
/// snapshots. At 30K evts/s with a 200ms poll cycle, ~6K events arrive per
/// batch; 12K cap holds two full cycles so burst events (touch/exec at t=2s)
/// aren't evicted before the next poll drains them. 12K × 120 bytes = ~1.4MB.
const MONITOR_EVENT_RING_CAP: usize = 12_000;

// ── eBPF event record (must match kernel-side #[repr(C)]) ────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    /// Kernel monotonic timestamp (ns) at tracepoint entry — see eBPF side.
    pub ktime_ns: u64,
    pub comm: [u8; EVENT_COMM_LEN],
    pub filename: [u8; EVENT_FILENAME_LEN],
    pub argv: [u8; EVENT_ARGV_LEN],
}

unsafe impl aya::Pod for ProcessEvent {}

impl ProcessEvent {
    fn comm_bytes(&self) -> &[u8] {
        let end = self.comm.iter().position(|&c| c == 0).unwrap_or(self.comm.len());
        &self.comm[..end]
    }
    fn filename_bytes(&self) -> &[u8] {
        let end = self.filename.iter().position(|&c| c == 0).unwrap_or(self.filename.len());
        &self.filename[..end]
    }
    fn comm_str(&self) -> String {
        cstr_to_string(&self.comm)
    }
    fn filename_str(&self) -> String {
        cstr_to_string(&self.filename)
    }
    fn argv_str(&self) -> String {
        cstr_to_string(&self.argv)
    }
}

// ── Public types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Exec,
    Open,
    Connect,
    Accept,
    SendTo,
    RecvFrom,
    Mkdir,
    Unlink,
    Kill,
    Chmod,
    Unknown,
}

impl From<u8> for Kind {
    fn from(event_type: u8) -> Self {
        match event_type {
            0 => Kind::Exec,
            1 => Kind::Open,
            2 => Kind::Connect,
            3 => Kind::Accept,
            4 => Kind::SendTo,
            5 => Kind::RecvFrom,
            6 => Kind::Mkdir,
            7 => Kind::Unlink,
            8 => Kind::Kill,
            9 => Kind::Chmod,
            _ => Kind::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordedEvent {
    /// Kernel monotonic timestamp (ns) from the eBPF tracepoint. Formatted
    /// to a display string only when surfacing to the TUI (50×/poll) or creating
    /// an Alert — NOT per event in to_recorded(). This alone eliminates the
    /// single biggest allocation hot path at 30K evts/s.
    pub ts_ns: u64,
    pub kind: Kind,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub file: Option<String>,
    pub extension: Option<String>,
    /// Full command path from argv[0] (execve events only).
    pub argv: Option<String>,
    /// Bytes count (for network send/recv events).
    #[allow(dead_code)]
    pub bytes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub ts: String,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub opens: u64,
    /// MeMLP neural verdicts for this process (None when `--memlp` is off).
    pub memlp: Option<crate::memlp::Assessment>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcStats {
    pub pid: u32,
    #[allow(dead_code)]
    pub ppid: u32,
    pub comm: String,
    pub window_opens: u64,
    pub total_opens: u64,
    pub total_execs: u64,
    pub alerts: u64,
    pub extensions: HashMap<String, u64>,
}

/// Ranked file access entry for the TUI "Top Files" panel.
#[derive(Debug, Clone)]
pub struct FileRank {
    pub path: String,
    pub count: u64,
    pub extension: String,
    /// Shannon entropy of the filename (0.0–1.0 normalised).
    pub entropy: f64,
}

/// Event-rate sample for sparkline visualisation.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RateSample {
    pub exec_count: u64,
    pub open_count: u64,
    pub alert_count: u64,
}

/// A node in the process tree.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessNode {
    pub pid: u32,
    #[allow(dead_code)]
    pub ppid: u32,
    pub comm: String,
    pub alerts: u64,
    pub total_opens: u64,
    pub children: Vec<ProcessNode>,
}

pub enum Output {
    Event(RecordedEvent),
    Alert(Alert),
    Action(ResponseAction),
}

/// Response action taken by the agent.
#[derive(Debug, Clone)]
pub struct ResponseAction {
    pub ts: String,
    pub pid: u32,
    pub comm: String,
    pub action: String,
    pub success: bool,
}

enum Msg {
    /// Batched raw events + per-event delivery latency (ns).
    /// Batching amortizes MPSC channel lock contention at >100K evts/s.
    Events(Vec<(ProcessEvent, u64)>),
    Lost(u64),
}

/// Max events to batch before flushing to the monitor channel.
const READER_BATCH_SIZE: usize = 512;
/// Minimum events drained in one perf-buffer sweep before the reader thread
/// considers itself busy and skips its idle nap. Below this the sweep is
/// treated as low-rate: the thread sleeps [`READER_LOW_RATE_SLEEP`] so it does
/// not spin at 100% CPU just to drain a trickle of events.
const READER_MIN_SWEEP: usize = 32;
/// Idle nap for low-rate sweeps (see [`READER_MIN_SWEEP`]).
const READER_LOW_RATE_SLEEP: Duration = Duration::from_millis(1);
/// Ceiling on the reader's poll-loop at sustained high event rates. Each sweep
/// drains *all* available events out of the 256-page perf buffers via
/// `for_each`, so a 100µs nap caps the loop at ~10K sweeps/sec — still 3× the
/// headroom needed for a 7.4k evt/s burst and far below the 300K evt/s target —
/// while stopping the thread from busy-looping the core. Without it the reader
/// pegs a core (`drained >= 32` → `else` branch, no sleep), starving the poll
/// thread, backing up the sync_channel(1024), and dropping events (the
/// "390% CPU then talus dies" runaway).
const READER_HIGH_RATE_SLEEP: Duration = Duration::from_micros(100);

// ── Monitor core ──────────────────────────────────────────────────────────

/// Kernel→userspace delivery-latency histogram.
///
/// Each event carries `ktime_ns` stamped inside the kernel (tracepoint
/// entry). The perf-buffer reader thread subtracts it from its own
/// monotonic clock on receive — the difference is the one-way
/// kernel→userspace delivery latency. Bounded reservoir: keeps the last
/// `CAP` samples (microsecond resolution), computed percentiles stay
/// exact for the kept window.
#[derive(Debug, Default)]
pub struct LatencyStats {
    samples_us: Vec<u64>,
    count: u64,
    max_us: u64,
}

impl LatencyStats {
    const CAP: usize = 65_536;

    #[inline]
    fn record(&mut self, latency_ns: u64) {
        let us = (latency_ns / 1_000).min(u64::MAX / 2) as usize;
        self.count += 1;
        if us as u64 > self.max_us {
            self.max_us = us as u64;
        }
        // Reservoir: once full, replace a pseudorandom-ish slot (cheap LCG
        // keyed by count) so the window stays representative without memory
        // growth. Percentiles over the kept window are exact.
        if self.samples_us.len() < Self::CAP {
            self.samples_us.push(us as u64);
        } else {
            let slot = (self.count as usize * 2654435761) % Self::CAP;
            self.samples_us[slot] = us as u64;
        }
    }

    fn percentile(&self, p: f64) -> u64 {
        if self.samples_us.is_empty() {
            return 0;
        }
        let mut sorted = self.samples_us.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * p).min((sorted.len() - 1) as f64) as usize;
        sorted[idx]
    }

    /// (count, p50_us, p95_us, p99_us, max_us)
    pub fn summary(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.count,
            self.percentile(0.50),
            self.percentile(0.95),
            self.percentile(0.99),
            self.max_us,
        )
    }
}

/// CLOCK_MONOTONIC as nanoseconds — same clock the eBPF side stamps with
/// (`bpf_ktime_get_ns`), so subtraction is meaningful.
#[inline]
fn now_ns() -> u64 {
    // SAFETY: clock_gettime with a valid clockid and aligned timespec;
    // cannot fail for CLOCK_MONOTONIC.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

pub struct Monitor {
    rx: Receiver<Msg>,
    pub threshold: u64,
    pub auto_kill: bool,
    /// What happens when a verdict fires. `NoResponse` unless a build installs
    /// something else, so the MIT build observes without acting.
    responder: Box<dyn Responder>,
    stats: HashMap<u32, ProcStats>,
    windows: HashMap<u32, VecDeque<Instant>>,
    /// PID → PPID mapping (resolved from /proc/<pid>/status).
    pid_to_ppid: HashMap<u32, u32>,
    /// PIDs seen in handle_event but not yet resolved via /proc.
    /// Resolved in batch during the 1 s tick to keep handle_event on the hot
    /// path free of file I/O.
    pending_ppids: std::collections::HashSet<u32>,
    /// Ring buffer of recent events for TUI display. Avoids cloning every
    /// event in handle_event — events are moved here (ownership transfer,
    /// no allocation) and drained with a cap in poll().
    event_ring: std::collections::VecDeque<ProcessEvent>,
    /// Last time each PID produced an event; drives idle eviction.
    last_seen: HashMap<u32, Instant>,
    /// PIDs whose parent could not be resolved (process already dead) and the
    /// time we first detected it. Drives [`DEAD_PID_GRACE_SECS`] eviction so
    /// killed short-lived processes (e.g. `hyprctl` IPC forks) drop out
    /// quickly instead of lingering up to `IDLE_PID_TTL_SECS`.
    dead_since: HashMap<u32, Instant>,
    /// Process names (`comm`, max 15 bytes) whose burst alerts are suppressed.
    /// Their events are still counted and shown; only the alert (and any
    /// response driven by it) is skipped. Empty by default.
    ignore_comms: Vec<String>,
    /// When false (default) a comm living in `ignore_comms` is hidden from the
    /// process-tree panel in the TUI; its events are still counted and it never
    /// raises an alert. `--show-ignored` flips this to render them anyway.
    show_ignored: bool,
    /// Per-path open count for the "Top Files" panel.
    file_counts: HashMap<String, u64>,
    /// Extension → open count for extension-frequency tracking.
    ext_counts: HashMap<String, u64>,
    /// Sliding window of per-second event counts (for sparklines).
    rate_history: VecDeque<RateSample>,
    /// Counters accumulated since the last rate-history tick.
    tick_execs: u64,
    tick_opens: u64,
    tick_alerts: u64,
    tick_start: Instant,
    pub total_events: u64,
    pub total_lost: u64,
    pub started: Instant,
    /// Kernel→userspace delivery-latency histogram (nanoseconds samples).
    pub latency: LatencyStats,
    /// MeMLP neural detection engine (None unless `--memlp` is passed).
    memlp: Option<crate::memlp::MeMLP>,
    /// Per-PID behavioural feature windows feeding the MeMLP engine.
    pid_features: HashMap<u32, crate::memlp::PidFeatures>,
    /// Checkpoint path for MeMLP autosave (None = in-memory only).
    memlp_checkpoint: Option<std::path::PathBuf>,
    /// Last MeMLP checkpoint autosave time.
    memlp_last_save: Option<Instant>,
    _reader: thread::JoinHandle<()>,
    _bpf: Option<Ebpf>,
}

// ── Response: process termination ────────────────────────────────────────

/// Acts on a detection verdict.
///
/// The detector decides *whether* something is ransomware; this decides what
/// happens next. The split is deliberate and is the whole licensing model: the
/// judgement — thresholds, scoring, the MeMLP engine, the audit chain — stays
/// open and auditable, and the part that can end a process is not in this
/// repository at all.
///
/// The MIT build installs [`NoResponse`], so the flag is accepted and every
/// verdict is reported without anything happening. The Enterprise build installs
/// an implementation that terminates the process.
pub trait Responder: Send {
    /// A verdict fired for `pid`. `comm` is the process command, as read from
    /// procfs, for the operator's logs.
    fn on_verdict(&mut self, pid: u32, comm: &str) -> bool;
}

/// The responder used by the MIT build: it observes and never acts.
///
/// This is the default, so a build of this crate cannot terminate a process
/// no matter which flags it is given. That is not a runtime check that can be
/// removed — there is nothing here to remove.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoResponse;

impl Responder for NoResponse {
    fn on_verdict(&mut self, _pid: u32, _comm: &str) -> bool {
        false
    }
}

impl Monitor {
    /// Install what acts on a verdict.
    ///
    /// Without this the monitor observes and reports but does nothing, which is
    /// what the MIT build does. An Enterprise build calls this with an
    /// implementation that terminates the process.
    ///
    /// `auto_kill` stays the operator's switch: this only says what happens when
    /// the switch is on.
    /// Suppress burst alerts for these process names (e.g. `rsync`, `cc1`).
    /// Names are compared against the kernel `comm`, which is truncated to 15
    /// bytes, so longer names are truncated the same way.
    pub fn with_ignored_comms<I, S>(mut self, comms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.ignore_comms = comms
            .into_iter()
            .map(|c| c.as_ref().chars().take(EVENT_COMM_LEN - 1).collect::<String>())
            .filter(|c| !c.is_empty())
            .collect();
        self
    }

    /// Render processes whose `comm` is in `ignore_comms` in the process-tree
    /// panel. Off by default — suppressed comms vanish from the tree (their
    /// events are still counted and never alert), `--show-ignored` re-enables
    /// them so the operator can audit exactly what is being hidden.
    pub fn with_show_ignored(mut self, show: bool) -> Self {
        self.show_ignored = show;
        self
    }

    pub fn with_responder(mut self, responder: Box<dyn Responder>) -> Self {
        self.responder = responder;
        self
    }

    /// Start the eBPF monitor.
    ///
    /// Loads the compiled eBPF object, attaches tracepoints to syscall entries,
    /// and spawns the reader thread for perf buffer consumption.
    ///
    /// # Errors
    ///
    /// Returns an error if not running as root, if the eBPF object cannot be
    /// loaded, or if any tracepoint fails to attach.
    pub fn start(bpf_path: &Path, threshold: u64, auto_kill: bool) -> Result<Self> {
        // SAFETY: geteuid() is a simple syscall returning the effective user ID.
        // No pointers, no fallibility, always succeeds.
        if unsafe { libc::geteuid() } != 0 {
            bail!("must be run as root: loading eBPF programs requires CAP_BPF / CAP_SYS_ADMIN");
        }

        // Prefer the eBPF object embedded in the binary (single-file deployment,
        // no separate .o install step); fall back to an on-disk object so a
        // locally rebuilt eBPF program can be tested without recompiling the agent.
        const EMBEDDED_BPF: &[u8] = include_bytes!("bpf/process_monitor_ebpf.o");
        let mut bpf = match Ebpf::load(EMBEDDED_BPF) {
            Ok(bpf) => {
                eprintln!(
                    "[talus] eBPF object: embedded ({} bytes)",
                    EMBEDDED_BPF.len()
                );
                bpf
            }
            Err(embedded_err) => {
                eprintln!(
                    "[talus] embedded eBPF object failed to load ({}); trying file: {}",
                    embedded_err,
                    bpf_path.display()
                );
                Ebpf::load_file(bpf_path)
                    .context("failed to load eBPF program (embedded and file)")?
            }
        };
        eprintln!(
            "[talus] object parsed OK; programs: {:?}",
            bpf.programs().map(|(n, _)| n).collect::<Vec<_>>()
        );

        let program: &mut TracePoint = bpf
            .program_mut("sys_enter_execve")
            .context("failed to find 'sys_enter_execve' program")?
            .try_into()
            .context("'sys_enter_execve' is not a tracepoint program")?;
        program.load().context("failed to load execve program")?;
        program
            .attach("syscalls", "sys_enter_execve")
            .context("failed to attach execve tracepoint")?;
        eprintln!("[talus] attached tracepoint syscalls/sys_enter_execve");

        let program: &mut TracePoint = bpf
            .program_mut("sys_enter_openat")
            .context("failed to find 'sys_enter_openat' program")?
            .try_into()
            .context("'sys_enter_openat' is not a tracepoint program")?;
        program.load().context("failed to load openat program")?;
        program
            .attach("syscalls", "sys_enter_openat")
            .context("failed to attach openat tracepoint")?;
        eprintln!("[talus] attached tracepoint syscalls/sys_enter_openat");

        // Attach filesystem and signal tracepoints (best-effort: kernel may lack some).
        for (name, category, label) in [
            ("sys_enter_mkdir", "syscalls", "mkdir"),
            ("sys_enter_unlinkat", "syscalls", "unlinkat"),
            ("sys_enter_kill", "syscalls", "kill"),
            ("sys_enter_fchmodat", "syscalls", "fchmodat"),
        ] {
            if let Some(prog) = bpf.program_mut(name) {
                let tp: Result<&mut TracePoint, _> = prog.try_into();
                if let Ok(tp) = tp {
                    if tp.load().is_ok() && tp.attach(category, name).is_ok() {
                        eprintln!("[talus] attached tracepoint {category}/{name} ({label})");
                    }
                }
            }
        }

        // Attach network tracepoints (best-effort).
        for (name, label) in [
            ("sys_enter_connect", "connect"),
            ("sys_enter_accept", "accept"),
            ("sys_enter_sendto", "sendto"),
            ("sys_enter_recvfrom", "recvfrom"),
        ] {
            if let Some(prog) = bpf.program_mut(name) {
                let tp: Result<&mut TracePoint, _> = prog.try_into();
                match tp {
                    Ok(tp) => match tp.load() {
                        Ok(()) => match tp.attach("syscalls", name) {
                            Ok(_) => {
                                eprintln!("[talus] attached tracepoint syscalls/{name} ({label})")
                            }
                            Err(e) => {
                                eprintln!("[talus] WARN: loaded {name} but attach failed: {e}")
                            }
                        },
                        Err(e) => eprintln!("[talus] WARN: failed to load {name}: {e}"),
                    },
                    Err(e) => eprintln!("[talus] WARN: {name} is not a TracePoint: {e}"),
                }
            } else {
                eprintln!("[talus] WARN: program {name} not found in eBPF object");
            }
        }

        let perf_array: PerfEventArray<MapData> = bpf
            .take_map("EVENTS")
            .context("failed to find 'EVENTS' map")?
            .try_into()
            .context("'EVENTS' is not a PerfEventArray")?;

        let (tx, rx) = mpsc::sync_channel(1024);  // 1024×512 = 512K-event buffer — absorbs bursts
        let reader = spawn_reader(perf_array, tx)?;

        let now = Instant::now();
        Ok(Self {
            rx,
            threshold,
            auto_kill,
            responder: Box::new(NoResponse),
            stats: HashMap::new(),
            windows: HashMap::new(),
            pid_to_ppid: HashMap::new(),
            pending_ppids: std::collections::HashSet::new(),
            event_ring: std::collections::VecDeque::new(),
            last_seen: HashMap::new(),
            dead_since: HashMap::new(),
            ignore_comms: Vec::new(),
            show_ignored: false,
            file_counts: HashMap::new(),
            ext_counts: HashMap::new(),
            rate_history: VecDeque::new(),
            tick_execs: 0,
            tick_opens: 0,
            tick_alerts: 0,
            tick_start: now,
            total_events: 0,
            total_lost: 0,
            latency: LatencyStats::default(),
            started: now,
            memlp: None,
            pid_features: HashMap::new(),
            memlp_checkpoint: None,
            memlp_last_save: None,
            _reader: reader,
            _bpf: Some(bpf),
        })
    }

    /// Enable the MeMLP neural detection engine, loading a checkpoint from
    /// `checkpoint` when given (a fresh model is created otherwise).
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint exists but cannot be parsed or has
    /// an incompatible version.
    pub fn enable_memlp(&mut self, checkpoint: Option<&Path>) -> Result<()> {
        let model = match checkpoint {
            Some(path) => crate::memlp::MeMLP::load(path)?,
            None => crate::memlp::MeMLP::new(),
        };
        eprintln!(
            "[talus] MeMLP engine enabled: {} modules, {} parameters (checkpoint: {})",
            3,
            model.param_count(),
            checkpoint.map_or("in-memory".to_string(), |p| p.display().to_string())
        );
        self.memlp = Some(model);
        self.pid_features.clear();
        self.memlp_checkpoint = checkpoint.map(Path::to_path_buf);
        self.memlp_last_save = None;
        Ok(())
    }

    pub fn poll(&mut self) -> Vec<Output> {
        let mut outputs = Vec::new();
        // Process ALL available events — no cap, no dropping. The 200ms TUI
        // interval and sync_channel(64) provide the backpressure, not event
        // loss. At 30K evts/s, processing ~6K events takes ~30ms — well
        // within the 200ms frame budget.
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Lost(n) => self.total_lost += n,
                Msg::Events(batch) => {
                    self.total_events += batch.len() as u64;
                    for (raw, latency_ns) in batch {
                        self.record_latency(latency_ns);
                        // handle_event takes &ProcessEvent — zero String allocations
                        // in the hot path. to_recorded is called only in
                        // drain_display_events (50 events per 200ms poll).
                        self.handle_event(&raw, &mut outputs);
                    }
                }
            }
        }
        // Accumulate rate samples every ~1 second.
        if self.tick_start.elapsed() >= Duration::from_secs(1) {
            self.rate_history.push_back(RateSample {
                exec_count: self.tick_execs,
                open_count: self.tick_opens,
                alert_count: self.tick_alerts,
            });
            // Keep last 120 seconds of history.
            if self.rate_history.len() > 120 {
                self.rate_history.pop_front();
            }
            self.tick_execs = 0;
            self.tick_opens = 0;
            self.tick_alerts = 0;
            self.tick_start = Instant::now();
            self.prune_idle();
            // ── Batch-resolve PPIDs deferred from the hot path ───────────────
            // Avoid per-event /proc/{pid}/status I/O in handle_event by
            // collecting PIDs here and resolving them once per second.
            for pid in self.pending_ppids.drain() {
                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pid_to_ppid.entry(pid)
                {
                    match read_ppid_from_proc(pid) {
                        Some(ppid) => {
                            // Process still alive — parent resolved.
                            e.insert(ppid);
                            self.dead_since.remove(&pid);
                        }
                        None => {
                            // Already dead (hyprctl fork bomb / IPC). Record
                            // the time so `prune_idle` can evict it within
                            // `DEAD_PID_GRACE_SECS` instead of waiting up to
                            // `IDLE_PID_TTL_SECS`.
                            self.dead_since.entry(pid).or_insert_with(Instant::now);
                        }
                    }
                }
            }
            // ── MeMLP: decay per-PID behavioural windows (1s half-life) ──
            // Keep entries with recent activity, drop fully-stale ones so the
            // map stays bounded by live processes.
            if self.memlp.is_some() {
                self.pid_features.retain(|_, f| {
                    f.decay();
                    f.has_activity()
                });
            }
            // ── MeMLP: periodic checkpoint autosave (every 30s) ─────────
            if self.memlp.is_some() && self.memlp_checkpoint.is_some() {
                let due = self
                    .memlp_last_save
                    .map(|t| t.elapsed() >= Duration::from_secs(30))
                    .unwrap_or(true);
                if due {
                    if let (Some(model), Some(path)) =
                        (self.memlp.as_ref(), self.memlp_checkpoint.as_deref())
                    {
                        if let Err(e) = model.save(path) {
                            eprintln!("[talus] WARN: MeMLP autosave failed: {e}");
                        }
                    }
                    self.memlp_last_save = Some(Instant::now());
                }
            }
        }
        // ── Drain event ring buffer into outputs (with TUI cap) ───────────────
        // Only the most recent TUI_SNAPSHOT_EVENT_CAP events are surfaced to
        // the TUI; the rest are silently dropped to save channel bandwidth.
        self.drain_display_events(&mut outputs);
        outputs
    }

    /// Move events from the internal ring buffer into `outputs`, capped at
    /// [`TUI_SNAPSHOT_EVENT_CAP`].  The **most recent** events are kept; older
    /// ones are dropped so the TUI always shows the tail, not the head.
    /// Only the displayed events (max 50 per poll) are converted via
    /// `to_recorded()` — the remaining 30K/sec stay as raw Copy structs.
    pub fn drain_display_events(&mut self, outputs: &mut Vec<Output>) {
        let len = self.event_ring.len();
        let skip = len.saturating_sub(TUI_SNAPSHOT_EVENT_CAP);
        // Drop oldest from front.
        for _ in 0..skip {
            self.event_ring.pop_front();
        }
        // Drain the remaining (newest) events, converting to DisplayEvent.
        while let Some(raw) = self.event_ring.pop_front() {
            outputs.push(Output::Event(to_recorded(&raw)));
        }
    }

    #[inline]
    fn record_latency(&mut self, latency_ns: u64) {
        self.latency.record(latency_ns);
    }

    pub(crate) fn handle_event(&mut self, raw: &ProcessEvent, outputs: &mut Vec<Output>) {
        let pid = raw.pid;
        let uid = raw.uid;
        let ts_ns = raw.ktime_ns;
        let kind = Kind::from(raw.event_type);

        let stats = self.stats.entry(pid).or_default();
        stats.pid = pid;
        // Only allocate comm String when it actually changed — at 30K evts/s this
        // avoids 30K heap allocations/sec since most events from a PID share its comm.
        if stats.comm.as_bytes() != raw.comm_bytes() {
            stats.comm = raw.comm_str();
        }
        self.last_seen.insert(pid, Instant::now());
        // A live event revives any previously-marked-dead PID.
        self.dead_since.remove(&pid);

        // NOTE: deliberately no state reset on Exec. The execve tracepoint fires
        // on entry even when the exec fails, so resetting the burst window here
        // would let a process dodge the threshold by interleaving cheap failing
        // execve() calls. Stale state from a recycled PID is bounded by the 1 s
        // window and the idle-PID TTL instead.

        // Collect for deferred PPID resolution (avoids per-event /proc I/O).
        if !self.pid_to_ppid.contains_key(&pid) {
            self.pending_ppids.insert(pid);
        }

        // ── MeMLP: feed the live event stream to the neural engine ──────
        if self.memlp.is_some() {
            match kind {
                Kind::Exec => {
                    self.pid_features.entry(pid).or_default().observe_exec(false);
                }
                Kind::Connect | Kind::Accept | Kind::SendTo | Kind::RecvFrom => {
                    self.pid_features.entry(pid).or_default().observe_exec(true);
                }
                Kind::Open => {
                    let filename = raw.filename_str();
                    let ext = extract_extension(&filename);
                    let entropy = shannon_entropy(&filename);
                    self.pid_features.entry(pid).or_default().observe_open(
                        &filename, Some(&ext), entropy,
                    );
                }
                Kind::Mkdir => {
                    self.pid_features.entry(pid).or_default().observe_fs(false);
                }
                Kind::Unlink | Kind::Chmod => {
                    self.pid_features.entry(pid).or_default().observe_fs(true);
                }
                Kind::Kill => {}
                Kind::Unknown => {}
            }
        }

        match kind {
            Kind::Exec => {
                stats.total_execs += 1;
                self.tick_execs += 1;
            }
            Kind::Connect | Kind::Accept | Kind::SendTo | Kind::RecvFrom => {
                // Network events — count as exec for stats purposes
                stats.total_execs += 1;
                self.tick_execs += 1;
            }
            Kind::Open => {
                // Track file extensions and per-file open count.
                // Use from_utf8 + filename_bytes() to avoid a per-event String
                // allocation — from_utf8 returns a &str into the raw buffer at
                // zero cost. bump_count_capped still allocates key.to_owned()
                // only for NEW keys (hot keys: zero alloc).
                let filename = std::str::from_utf8(raw.filename_bytes()).unwrap_or("");
                let ext = extract_extension(filename);
                if !ext.is_empty() {
                    bump_count_capped(&mut stats.extensions, &ext, MAX_TRACKED_EXTS);
                    bump_count_capped(&mut self.ext_counts, &ext, MAX_TRACKED_EXTS);
                }
                if !filename.is_empty() {
                    bump_count_capped(&mut self.file_counts, filename, MAX_TRACKED_FILES);
                }

                let now = Instant::now();
                let window = self.windows.entry(pid).or_default();
                let cutoff = now - Duration::from_secs(WINDOW_SECS);
                while window.front().is_some_and(|t| *t < cutoff) {
                    window.pop_front();
                }
                window.push_back(now);

                stats.total_opens += 1;
                stats.window_opens = window.len() as u64;
                self.tick_opens += 1;

                if self.threshold > 0
                    && stats.window_opens == self.threshold
                    && !self.ignore_comms.iter().any(|ic| ic.as_bytes() == raw.comm_bytes())
                {
                    stats.alerts += 1;
                    self.tick_alerts += 1;
                    // ── MeMLP: throttled training + verdict ────────────
                    let memlp_verdict = if let Some(model) = self.memlp.as_mut() {
                        let feats = self.pid_features.entry(pid).or_default().features();
                        // Train AND assess only on every Nth alert to bound CPU at
                        // high alert rates (e.g. 300K evts/s thresh=3 → thousands
                        // of alerts/sec). Most alerts are false positives from
                        // system scans anyway.
                        if stats.alerts.is_multiple_of(MEMLP_TRAIN_INTERVAL) {
                            model.train_observation(&feats, MEMLP_LEARNING_RATE);
                            Some(model.assess(&feats))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let comm = raw.comm_str();
                    outputs.push(Output::Alert(Alert {
                        ts: format_ktime(ts_ns),
                        pid,
                        uid,
                        comm: comm.clone(),
                        opens: stats.window_opens,
                        memlp: memlp_verdict,
                    }));
                    // ── Response: act on the verdict ───────────────────────────
                    if self.auto_kill {
                        let result = self.responder.on_verdict(pid, &comm);
                        let action = if result {
                            format!("response sent to PID {} ({})", pid, comm)
                        } else {
                            format!("no response sent to PID {} ({})", pid, comm)
                        };
                        outputs.push(Output::Action(ResponseAction {
                            ts: format_ktime(ts_ns),
                            pid,
                            comm,
                            action,
                            success: result,
                        }));
                    }
                }
            }
            Kind::Mkdir | Kind::Unlink | Kind::Chmod => {
                // FS events — track in file counts for the Top Files panel.
                let path = std::str::from_utf8(raw.filename_bytes()).unwrap_or("");
                if !path.is_empty() {
                    bump_count_capped(&mut self.file_counts, path, MAX_TRACKED_FILES);
                }
                self.tick_opens += 1;
            }
            Kind::Kill | Kind::Unknown => {
                self.tick_opens += 1;
            }
        }
        // Push raw ProcessEvent (Copy, zero-alloc) to ring buffer for TUI display.
        if self.event_ring.len() >= MONITOR_EVENT_RING_CAP {
            self.event_ring.pop_front();
        }
        self.event_ring.push_back(*raw);
    }

    /// Once per second: let `window_opens` decay for quiet processes and forget
    /// PIDs that have been idle past the TTL, so per-PID maps stay bounded by
    /// recently-live processes instead of every PID ever seen.
    fn prune_idle(&mut self) {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(WINDOW_SECS);
        let stats = &mut self.stats;
        self.windows.retain(|pid, w| {
            while w.front().is_some_and(|t| *t < cutoff) {
                w.pop_front();
            }
            if let Some(s) = stats.get_mut(pid) {
                s.window_opens = w.len() as u64;
            }
            !w.is_empty()
        });

        let ttl = Duration::from_secs(if self.last_seen.len() > MAX_TRACKED_PIDS {
            PRESSURE_PID_TTL_SECS
        } else {
            IDLE_PID_TTL_SECS
        });
        let dead_ttl = Duration::from_secs(DEAD_PID_GRACE_SECS);
        let stale: Vec<u32> = self
            .last_seen
            .iter()
            .filter_map(|(pid, t)| {
                let age = now.duration_since(*t);
                if let Some(death) = self.dead_since.get(pid) {
                    // Process already dead: short grace window, then evict.
                    if now.duration_since(*death) > dead_ttl {
                        Some(*pid)
                    } else {
                        None
                    }
                } else {
                    // Still resolving or alive: classic idle TTL.
                    if age > ttl {
                        Some(*pid)
                    } else {
                        None
                    }
                }
            })
            .collect();
        for pid in stale {
            self.last_seen.remove(&pid);
            self.stats.remove(&pid);
            self.windows.remove(&pid);
            self.pid_to_ppid.remove(&pid);
            self.pid_features.remove(&pid);
            self.dead_since.remove(&pid);
        }
    }

    /// The `n` busiest processes by current window, plus the `n / 8` (min 8)
    /// heaviest by lifetime opens, de-duplicated. Cheaper than
    /// [`Monitor::stats_sorted`] on hosts with many tracked PIDs because only
    /// the selected entries are cloned (including their extension maps).
    pub fn stats_top(&self, n: usize) -> Vec<ProcStats> {
        let mut by_window: Vec<&ProcStats> = self.stats.values().collect();
        let mut by_total = by_window.clone();
        let k_total = (n / 8).max(8);
        if n < by_window.len() {
            by_window.select_nth_unstable_by(n, |a, b| b.window_opens.cmp(&a.window_opens));
            by_window.truncate(n);
        }
        if k_total < by_total.len() {
            by_total.select_nth_unstable_by(k_total, |a, b| b.total_opens.cmp(&a.total_opens));
            by_total.truncate(k_total);
        }
        let mut seen = std::collections::HashSet::with_capacity(by_window.len() + by_total.len());
        let mut out: Vec<ProcStats> = by_window
            .into_iter()
            .chain(by_total)
            .filter(|p| seen.insert(p.pid))
            .cloned()
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.window_opens));
        out
    }

    pub fn stats_sorted(&self) -> Vec<ProcStats> {
        let mut all: Vec<ProcStats> = self.stats.values().cloned().collect();
        all.sort_by_key(|s| std::cmp::Reverse(s.window_opens));
        all
    }

    /// Top-N most-opened files, sorted by count descending.
    pub fn top_files(&self, n: usize) -> Vec<FileRank> {
        // Select the top-n by count first; extension + entropy (and the path
        // clone) are computed for those n only, not for every file ever seen.
        let mut ranked: Vec<(&String, u64)> =
            self.file_counts.iter().map(|(p, &c)| (p, c)).collect();
        if n < ranked.len() {
            ranked.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            ranked.truncate(n);
        }
        ranked.sort_by_key(|r| std::cmp::Reverse(r.1));
        ranked
            .into_iter()
            .map(|(path, count)| FileRank {
                path: path.clone(),
                count,
                extension: extract_extension(path),
                entropy: shannon_entropy(path),
            })
            .collect()
    }

    /// Extension frequency map (extension → total open count across all processes).
    #[allow(dead_code)]
    pub fn extension_counts(&self) -> &HashMap<String, u64> {
        &self.ext_counts
    }

    /// Sparkline-ready rate history (last N samples).
    #[allow(dead_code)]
    pub fn rate_history(&self) -> &VecDeque<RateSample> {
        &self.rate_history
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// MeMLP engine stats: `(training_samples, parameter_count)`.
    /// Returns `None` when the neural engine is disabled.
    pub fn memlp_stats(&self) -> Option<(u64, usize)> {
        self.memlp
            .as_ref()
            .map(|m| (m.training_samples, m.param_count()))
    }

    /// Latest MeMLP verdicts for a PID, if the neural engine is enabled and
    /// the process has observable activity.
    /// Consumed by the web REST API (feature `web`); kept for embeddings.
    #[allow(dead_code)]
    pub fn memlp_verdict(&self, pid: u32) -> Option<crate::memlp::Assessment> {
        let model = self.memlp.as_ref()?;
        let feats = self.pid_features.get(&pid)?;
        Some(model.assess(&feats.features()))
    }

    /// Persist the MeMLP checkpoint to an explicit path (no-op when the
    /// engine is disabled). Complements the 30s poll autosave; retained as
    /// public API for embedders and future CLI subcommands.
    #[allow(dead_code)]
    pub fn save_memlp(&self, path: &Path) -> Result<()> {
        match &self.memlp {
            Some(model) => model.save(path),
            None => Ok(()),
        }
    }

    /// Machine-readable summary of the MeMLP engine (JSON output / REST API).
    #[allow(dead_code)]
    pub fn memlp_summary(&self) -> Option<serde_json::Value> {
        let m = self.memlp.as_ref()?;
        Some(serde_json::json!({
            "enabled": true,
            "version": m.version,
            "training_samples": m.training_samples,
            "parameters": m.param_count(),
            "modules": {
                "ransomware": m.ransomware.arch(),
                "lateral": m.lateral.arch(),
                "persistence": m.persistence.arch(),
            },
        }))
    }

    /// Build a hierarchical process tree from the flat PID→PPID stats.
    pub fn build_process_tree(&self) -> Vec<ProcessNode> {
        // A comm that lives in `ignore_comms` is hidden from the tree unless
        // `--show-ignored` was passed. Its events are still counted and it never
        // alerts (that gate lives in `handle_event`); this only changes what the
        // TUI draws. Children of a hidden process re-root to the top level so
        // they are not silently lost — only the suppressed comm line vanishes.
        let is_ignored = |comm: &str| {
            !self.show_ignored
                && self.ignore_comms
                    .iter()
                    .any(|ic| ic.as_bytes() == comm.as_bytes())
        };

        // Collect all known PIDs and their children, skipping ignored comms.
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut all_pids: Vec<u32> = Vec::new();

        for (&pid, stats) in &self.stats {
            if is_ignored(&stats.comm) {
                continue;
            }
            all_pids.push(pid);
            let ppid = self.pid_to_ppid.get(&pid).copied().unwrap_or(0);
            children_map.entry(ppid).or_default().push(pid);
        }
        let tracked: std::collections::HashSet<u32> = all_pids.iter().copied().collect();

        // Sort children by name for stable display.
        for children in children_map.values_mut() {
            children.sort_by(|a, b| {
                let ca = self.stats.get(a).map_or("", |s| s.comm.as_str());
                let cb = self.stats.get(b).map_or("", |s| s.comm.as_str());
                ca.cmp(cb)
            });
        }

        // Find roots: PIDs whose parent is not tracked (or is 0). Children of a
        // hidden process land here instead of under their suppressed parent.
        let mut roots: Vec<u32> = all_pids
            .iter()
            .filter(|&&pid| {
                let ppid = self.pid_to_ppid.get(&pid).copied().unwrap_or(0);
                ppid == 0 || !tracked.contains(&ppid)
            })
            .copied()
            .collect();
        roots.sort_by(|a, b| {
            let ca = self.stats.get(a).map_or("", |s| s.comm.as_str());
            let cb = self.stats.get(b).map_or("", |s| s.comm.as_str());
            ca.cmp(cb)
        });

        // Partition roots by whether they have tracked children. A root with
        // children (e.g. `systemd`, `bash`) is a real tree anchor built
        // recursively so descendants render. Childless roots are dead short-
        // lived forks (e.g. `hyprctl` IPC) — orphans collapsed below by comm name
        // into a single "comm ×N" node instead of being built one-by-one, which
        // is what made the PROCESSES panel "stack" under fork storms.
        let (roots_with_children, orphan_roots): (Vec<u32>, Vec<u32>) = roots
            .into_iter()
            .partition(|pid| children_map.contains_key(pid));

        let mut out: Vec<ProcessNode> = if roots_with_children.is_empty() && orphan_roots.is_empty() {
            Vec::new()
        } else {
            // Recursively build the connected tree part.
            fn build(
                pid: u32,
                stats: &HashMap<u32, ProcStats>,
                children_map: &HashMap<u32, Vec<u32>>,
            ) -> ProcessNode {
                let s = stats.get(&pid);
                let children_ids = children_map.get(&pid).cloned().unwrap_or_default();
                let children: Vec<ProcessNode> = children_ids
                    .into_iter()
                    .map(|child_pid| build(child_pid, stats, children_map))
                    .collect();
                ProcessNode {
                    pid,
                    ppid: s.map(|s| s.ppid).unwrap_or(0),
                    comm: s
                        .map(|s| s.comm.clone())
                        .unwrap_or_else(|| "<unknown>".into()),
                    alerts: s.map(|s| s.alerts).unwrap_or(0),
                    total_opens: s.map(|s| s.total_opens).unwrap_or(0),
                    children,
                }
            }
            roots_with_children
                .into_iter()
                .map(|pid| build(pid, &self.stats, &children_map))
                .collect()
        };

        let mut groups: HashMap<&str, (ProcessNode, usize)> = HashMap::new();
        for pid in orphan_roots {
            let Some(s) = self.stats.get(&pid) else { continue };
            let comm: &str = s.comm.as_str();
            let entry = groups.entry(comm).or_insert_with(|| (
                ProcessNode {
                    pid,
                    ppid: 0,
                    comm: s.comm.clone(),
                    alerts: 0,
                    total_opens: 0,
                    children: Vec::new(),
                },
                0,
            ));
            entry.0.alerts += s.alerts;
            entry.0.total_opens += s.total_opens;
            entry.1 += 1;
        }
        for (_, (mut node, n)) in groups {
            if n > 1 {
                node.comm = format!("{} \u{00d7}{}", node.comm, n);
            }
            out.push(node);
        }
        out.sort_by(|a, b| a.comm.cmp(&b.comm));
        out
    }

    /// Flatten a process tree into a Vec of (depth, node) for display.
    pub fn flatten_tree(tree: &[ProcessNode]) -> Vec<(usize, &ProcessNode)> {
        fn walk<'a>(node: &'a ProcessNode, depth: usize, out: &mut Vec<(usize, &'a ProcessNode)>) {
            out.push((depth, node));
            for child in &node.children {
                walk(child, depth + 1, out);
            }
        }
        let mut result = Vec::new();
        for root in tree {
            walk(root, 0, &mut result);
        }
        result
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Upper bound on distinct file paths tracked for the top-files ranking.
/// A long-running agent on a busy host would otherwise grow this map forever.
const MAX_TRACKED_FILES: usize = 50_000;
/// Upper bound on distinct extensions tracked globally.
const MAX_TRACKED_EXTS: usize = 4_096;

/// Like [`bump_count`], but the map never holds more than `cap` keys.
///
/// When the map is well under `cap`, behaviour is identical: increment if the
/// key exists, insert if not.
///
/// Once the map exceeds `cap + cap/10` (10 % headroom), a lazy eviction pass
/// prunes one-hit keys (the long tail). Between eviction passes, new keys at
/// the cap are silently dropped — the hot keys that drive rankings are never
/// evicted, and the O(n) retain cost is amortised over cap/10 insertions
/// instead of running on every call.
fn bump_count_capped(map: &mut HashMap<String, u64>, key: &str, cap: usize) {
    if let Some(c) = map.get_mut(key) {
        *c += 1;
        return;
    }
    // Only evict when 10 % over cap — avoids an O(cap) retain on every insert.
    if map.len() >= cap + (cap / 10) {
        map.retain(|_, c| *c > 1);
    }
    if map.len() >= cap {
        return;
    }
    map.insert(key.to_owned(), 1);
}

/// Extract file extension (without the dot). Empty string for dotfiles / no ext.
fn extract_extension(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    if let Some(pos) = name.rfind('.') {
        if pos > 0 && pos < name.len() - 1 {
            return name[pos + 1..].to_lowercase();
        }
    }
    String::new()
}

/// Read the parent PID from /proc/<pid>/status (PPid line).
/// Returns None if the file cannot be read (process exited, permission denied, etc.).
fn read_ppid_from_proc(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Boot time (wall-clock epoch) in nanoseconds, read once from /proc/stat.
/// ktime_ns (kernel monotonic) + this offset = wall-clock nanosecond timestamp.
static BOOT_TIME_NS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Convert a kernel monotonic ktime_ns to a "%H:%M:%S.%.3f" wall-clock string.
/// The boot-time offset is cached on first call (reads /proc/stat once); all
/// subsequent calls are pure arithmetic — no syscall, no allocation beyond the
/// returned String. Called only for the 50 displayed events per poll and for
/// alerts/actions, never per-event in the hot path.
pub fn format_ktime(ktime_ns: u64) -> String {
    let boot_ns = *BOOT_TIME_NS.get_or_init(|| {
        std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("btime"))
                    .and_then(|l| l.strip_prefix("btime "))
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .unwrap_or(0)
            * 1_000_000_000
    });
    let total_ns = boot_ns + ktime_ns;
    let secs = total_ns / 1_000_000_000;
    let ms = (total_ns % 1_000_000_000) / 1_000_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        ms
    )
}

/// Compute normalised Shannon entropy of a byte string (0.0 = uniform, 1.0 = max).
fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let mut entropy = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            entropy -= p * p.log2();
        }
    }
    // Normalise to [0, 1] range (max entropy for 256 symbols = 8 bits).
    entropy / 8.0
}

/// Spawn the perf buffer reader thread.
///
/// Opens one `PerfEventArrayBuffer` per online CPU and reads events in a
/// continuous loop. Events are decoded from raw bytes into `RecordedEvent`
/// and sent through the MPSC channel to the monitor core.
///
/// # Errors
///
/// Returns an error if CPU enumeration fails or if the thread cannot be spawned.
fn spawn_reader(
    mut perf_array: PerfEventArray<MapData>,
    tx: mpsc::SyncSender<Msg>,
) -> Result<thread::JoinHandle<()>> {
    let cpus = online_cpus()
        .map_err(|(err, io)| anyhow::anyhow!("failed to enumerate CPUs: {err}: {io}"))?;
    let mut buffers: Vec<PerfEventArrayBuffer<MapData>> = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buf = perf_array
            .open(cpu, Some(256))
            .context("failed to open perf buffer")?;
        buffers.push(buf);
    }

    eprintln!("[talus] opening perf buffers on {} CPUs", buffers.len());

    thread::Builder::new()
        .name("talus-reader".into())
        .spawn(move || {
            // Batch events to amortize MPSC channel lock contention at high
            // throughput (300K+ events/sec). Only cheap Copy structs (ProcessEvent
            // + latency) cross the channel; String allocation is deferred to
            // the poll thread via to_recorded() with zero-cost ktime_ns.
            let mut batch: Vec<(ProcessEvent, u64)> = Vec::with_capacity(READER_BATCH_SIZE);
            loop {
                let mut idle = true;
                let mut drained: usize = 0;
                for buf in buffers.iter_mut() {
                    buf.for_each(|event| {
                        idle = false;
                        match event {
                            PerfEvent::Sample { head, tail } => {
                                // The sample payload may span the ring boundary;
                                // concatenate head + tail into a contiguous buffer.
                                let total_len = head.len() + tail.len();
                                if total_len >= size_of::<ProcessEvent>() {
                                    // SAFETY: raw bytes from perf buffer, written by
                                    // the kernel-side eBPF program as a #[repr(C)]
                                    // ProcessEvent. read_unaligned handles alignment.
                                    let evt = if total_len == head.len() {
                                        unsafe {
                                            std::ptr::read_unaligned(
                                                head.as_ptr() as *const ProcessEvent
                                            )
                                        }
                                    } else {
                                        let mut tmp = vec![0u8; total_len];
                                        tmp[..head.len()].copy_from_slice(head);
                                        tmp[head.len()..].copy_from_slice(tail);
                                        unsafe {
                                            std::ptr::read_unaligned(
                                                tmp.as_ptr() as *const ProcessEvent
                                            )
                                        }
                                    };
                                    // Defer to_recorded() to poll(); just ship the
                                    // raw event + latency here.
                                    batch.push((evt, now_ns().saturating_sub(evt.ktime_ns)));
                                    drained += 1;
                                    if batch.len() >= READER_BATCH_SIZE {
                                        let _ = tx.send(Msg::Events(std::mem::take(&mut batch)));
                                    }
                                }
                            }
                            PerfEvent::Lost { count } => {
                                // Flush pending batch before the lost count so
                                // event ordering is preserved for latency stats.
                                if !batch.is_empty() {
                                    let _ = tx.send(Msg::Events(std::mem::take(&mut batch)));
                                }
                                let _ = tx.send(Msg::Lost(count));
                            }
                        }
                    });
                }
                // Flush any remaining events at end of buffer sweep.
                if !batch.is_empty() {
                    let _ = tx.send(Msg::Events(std::mem::take(&mut batch)));
                }
                // Flush accumulated channel-overflow drops so the monitor
                // counts them alongside kernel-side perf-buffer losses.
                if idle || drained < READER_MIN_SWEEP {
                    // Low-rate sweep: yield the CPU. Without this the reader
                    // is a 100% busy-loop at any non-zero event rate (each
                    // perf-buffer sweep is a handful of syscalls). One 1 ms
                    // nap per low-rate sweep still drains ~32K evts/s while
                    // keeping the thread near-idle.
                    thread::sleep(READER_LOW_RATE_SLEEP);
                } else {
                    // High-rate sweep: still yield briefly. The sweep already
                    // drained the full buffer, so this 100µs nap costs <0.1%
                    // of a second at 300K evt/s but prevents the reader from
                    // spinning the core and starving poll/render. See
                    // `READER_HIGH_RATE_SLEEP` for why this is mandatory.
                    crate::watchdog::heartbeat();
                    thread::sleep(READER_HIGH_RATE_SLEEP);
                }
            }
        })
        .context("failed to spawn reader thread")
}
/// Decode a raw kernel event record from bytes, exactly as the poll loop does.
///
/// Layout: `event_type`(1) `pid`(4 LE) `uid`(4 LE) `ktime_ns`(8 LE)
/// `comm`(16) `filename`(64) `argv`(128). Returns `None` for short input.
/// Exists so the decoding path can be fuzzed without eBPF; it must never panic.
#[doc(hidden)]
pub fn decode_event_bytes(data: &[u8]) -> Option<RecordedEvent> {
    const LEN: usize = 1 + 4 + 4 + 8 + EVENT_COMM_LEN + EVENT_FILENAME_LEN + EVENT_ARGV_LEN;
    if data.len() < LEN {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let mut comm = [0u8; EVENT_COMM_LEN];
    comm.copy_from_slice(&data[17..17 + EVENT_COMM_LEN]);
    let mut filename = [0u8; EVENT_FILENAME_LEN];
    filename.copy_from_slice(&data[33..33 + EVENT_FILENAME_LEN]);
    let mut argv = [0u8; EVENT_ARGV_LEN];
    argv.copy_from_slice(&data[97..97 + EVENT_ARGV_LEN]);
    let raw = ProcessEvent {
        event_type: data[0],
        pid: u32_at(1),
        uid: u32_at(5),
        ktime_ns: u64::from_le_bytes([
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        ]),
        comm,
        filename,
        argv,
    };
    Some(to_recorded(&raw))
}

fn to_recorded(raw: &ProcessEvent) -> RecordedEvent {
    let argv = raw.argv_str();
    let argv_opt = if argv.is_empty() { None } else { Some(argv) };
    match raw.event_type {
        EVENT_EXECVE => RecordedEvent {
            ts_ns: raw.ktime_ns,
            kind: Kind::Exec,
            pid: raw.pid,
            uid: raw.uid,
            comm: raw.comm_str(),
            file: None,
            extension: None,
            argv: argv_opt,
            bytes: None,
        },
        EVENT_OPENAT => {
            let filename = raw.filename_str();
            let ext = extract_extension(&filename);
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Open,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: Some(filename),
                extension: Some(ext),
                argv: None,
                bytes: None,
            }
        }
        EVENT_CONNECT => {
            let addr = raw.filename_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Connect,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: if addr.is_empty() { None } else { Some(addr) },
                extension: None,
                argv: None,
                bytes: None,
            }
        }
        EVENT_ACCEPT => {
            let addr = raw.filename_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Accept,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: if addr.is_empty() { None } else { Some(addr) },
                extension: None,
                argv: None,
                bytes: None,
            }
        }
        EVENT_SENDTO => {
            let addr = raw.filename_str();
            let bytes_str = raw.argv_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::SendTo,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: if addr.is_empty() { None } else { Some(addr) },
                extension: None,
                argv: None,
                bytes: if bytes_str.is_empty() {
                    None
                } else {
                    Some(bytes_str)
                },
            }
        }
        EVENT_RECVFROM => {
            let addr = raw.filename_str();
            let bytes_str = raw.argv_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::RecvFrom,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: if addr.is_empty() { None } else { Some(addr) },
                extension: None,
                argv: None,
                bytes: if bytes_str.is_empty() {
                    None
                } else {
                    Some(bytes_str)
                },
            }
        }
        EVENT_MKDIR => {
            let path = raw.filename_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Mkdir,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: Some(path),
                extension: None,
                argv: None,
                bytes: None,
            }
        }
        EVENT_UNLINK => {
            let path = raw.filename_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Unlink,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: Some(path),
                extension: None,
                argv: None,
                bytes: None,
            }
        }
        EVENT_KILL => {
            let details = raw.argv_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Kill,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: None,
                extension: None,
                argv: Some(details),
                bytes: None,
            }
        }
        EVENT_CHMOD => {
            let path = raw.filename_str();
            RecordedEvent {
                ts_ns: raw.ktime_ns,
                kind: Kind::Chmod,
                pid: raw.pid,
                uid: raw.uid,
                comm: raw.comm_str(),
                file: Some(path),
                extension: None,
                argv: None,
                bytes: None,
            }
        }
        _ => RecordedEvent {
            ts_ns: raw.ktime_ns,
            kind: Kind::Unknown,
            pid: raw.pid,
            uid: raw.uid,
            comm: raw.comm_str(),
            file: None,
            extension: None,
            argv: None,
            bytes: None,
        },
    }
}

fn cstr_to_string(arr: &[u8]) -> String {
    let bytes: Vec<u8> = arr.iter().take_while(|&&c| c != 0).copied().collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
impl Monitor {
    pub(crate) fn dummy() -> Self {
        let (_tx, rx) = mpsc::sync_channel(64);
        let handle = thread::spawn(|| loop {
            thread::sleep(Duration::from_secs(60));
        });
        let now = Instant::now();
        Self {
            rx,
            threshold: 3,
            auto_kill: false,
            responder: Box::new(NoResponse),
            stats: HashMap::new(),
            windows: HashMap::new(),
            pid_to_ppid: HashMap::new(),
            pending_ppids: std::collections::HashSet::new(),
            event_ring: std::collections::VecDeque::new(),
            last_seen: HashMap::new(),
            dead_since: HashMap::new(),
            ignore_comms: Vec::new(),
            show_ignored: false,
            file_counts: HashMap::new(),
            ext_counts: HashMap::new(),
            rate_history: VecDeque::new(),
            tick_execs: 0,
            tick_opens: 0,
            tick_alerts: 0,
            tick_start: now,
            total_events: 0,
            total_lost: 0,
            latency: LatencyStats::default(),
            started: now,
            memlp: None,
            pid_features: HashMap::new(),
            memlp_checkpoint: None,
            memlp_last_save: None,
            _reader: handle,
            _bpf: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: u8, pid: u32, uid: u32, comm: &str, file: &str) -> ProcessEvent {
        let mut comm_buf = [0u8; EVENT_COMM_LEN];
        let cb = comm.as_bytes();
        comm_buf[..cb.len()].copy_from_slice(cb);
        let mut file_buf = [0u8; EVENT_FILENAME_LEN];
        let fb = file.as_bytes();
        file_buf[..fb.len()].copy_from_slice(fb);
        ProcessEvent {
            event_type,
            pid,
            uid,
            ktime_ns: 0,
            comm: comm_buf,
            filename: file_buf,
            argv: [0u8; EVENT_ARGV_LEN],
        }
    }

    fn open(pid: u32, uid: u32, file: &str) -> ProcessEvent {
        make_event(EVENT_OPENAT, pid, uid, "probe", file)
    }

    #[test]
    fn cstr_to_string_stops_at_nul() {
        let mut buf = [b'a'; EVENT_FILENAME_LEN];
        buf[3] = 0;
        let s = cstr_to_string(&buf);
        assert_eq!(s, "aaa");
        assert!(!s.contains('\0'));
    }

    #[test]
    fn process_event_string_helpers_trim_nul_padding() {
        let mut ev = ProcessEvent {
            event_type: 1,
            pid: 7,
            uid: 1000,
            ktime_ns: 0,
            comm: [0u8; EVENT_COMM_LEN],
            filename: [0u8; EVENT_FILENAME_LEN],
            argv: [0u8; EVENT_ARGV_LEN],
        };
        ev.comm[..4].copy_from_slice(b"bash");
        ev.filename[..11].copy_from_slice(b"/etc/passwd");
        assert_eq!(ev.comm_str(), "bash");
        assert_eq!(ev.filename_str(), "/etc/passwd");
    }

    #[test]
    fn latency_stats_percentiles_and_reservoir_cap() {
        let mut ls = LatencyStats::default();
        // 100 samples 1..=100 µs: p50 = 50, p95 = 95, max = 100.
        for us in 1..=100u64 {
            ls.record(us * 1_000);
        }
        let (count, p50, p95, p99, max) = ls.summary();
        // nearest-rank over 0-indexed sorted samples: p=f → sorted[ceil-ish(f*n)]
        assert_eq!(count, 100);
        assert_eq!(p50, 51); // sorted[50] of values 1..=100
        assert_eq!(p95, 96); // sorted[95]
        assert_eq!(p99, 100); // sorted[99]
        assert_eq!(max, 100);

        // Reservoir cap: record far past CAP, count keeps growing, no panic,
        // and percentiles stay within the recorded range.
        for i in 0..(LatencyStats::CAP as u64 + 1_000) {
            ls.record((i % 5_000 + 1) * 1_000);
        }
        let (count2, p50b, p95b, _, maxb) = ls.summary();
        assert!(count2 > LatencyStats::CAP as u64);
        assert!(p50b <= p95b && p95b <= maxb);
        assert!(maxb >= 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // miri has no /proc filesystem
    fn exec_events_update_stats_without_alerts() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.handle_event(&make_event(EVENT_EXECVE, 9, 0, "init", ""), &mut outputs);
        let stats = monitor.stats.get(&9).expect("stats recorded");
        assert_eq!(stats.total_execs, 1);
        assert_eq!(stats.total_opens, 0);
        assert_eq!(stats.alerts, 0);
        monitor.drain_display_events(&mut outputs);
        assert!(matches!(outputs[0], Output::Event(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn opens_trigger_alert_at_threshold() {
        let mut monitor = Monitor::dummy(); // threshold = 3
        let mut outputs = Vec::new();
        for _ in 0..3 {
            monitor.handle_event(&open(42, 1000, "/tmp/x"), &mut outputs);
        }
        monitor.drain_display_events(&mut outputs);
        let alerts: Vec<_> = outputs
            .iter()
            .filter(|o| matches!(o, Output::Alert(_)))
            .collect();
        assert_eq!(alerts.len(), 1, "exactly one alert at the threshold");
        if let Output::Alert(a) = &outputs[0] {
            assert_eq!(a.pid, 42);
            assert_eq!(a.opens, 3);
        } else {
            panic!("first output must be the alert");
        }
        let stats = monitor.stats.get(&42).unwrap();
        assert_eq!(stats.alerts, 1);
        assert_eq!(stats.window_opens, 3);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn no_second_alert_above_threshold() {
        let mut monitor = Monitor::dummy(); // threshold = 3
        let mut outputs = Vec::new();
        for _ in 0..5 {
            monitor.handle_event(&open(42, 1000, "/tmp/x"), &mut outputs);
        }
        let alerts = outputs
            .iter()
            .filter(|o| matches!(o, Output::Alert(_)))
            .count();
        assert_eq!(alerts, 1, "alert fires once, not repeatedly");
        assert_eq!(monitor.stats.get(&42).unwrap().alerts, 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn stats_sorted_orders_by_window_opens_desc() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        for _ in 0..2 {
            monitor.handle_event(&open(1, 0, "/a"), &mut outputs);
        }
        for _ in 0..4 {
            monitor.handle_event(&open(2, 0, "/b"), &mut outputs);
        }
        let sorted = monitor.stats_sorted();
        assert_eq!(sorted[0].pid, 2);
        assert_eq!(sorted[0].window_opens, 4);
        assert_eq!(sorted[1].pid, 1);
        assert_eq!(sorted[1].window_opens, 2);
    }

    #[test]
    fn extract_extension_basic() {
        assert_eq!(extract_extension("/etc/passwd"), "");
        assert_eq!(extract_extension("/tmp/doc.pdf"), "pdf");
        assert_eq!(extract_extension("/home/user/file.tar.gz"), "gz");
        assert_eq!(extract_extension("/a/.hidden"), "");
    }

    #[test]
    fn shannon_entropy_range() {
        assert_eq!(shannon_entropy(""), 0.0);
        let e = shannon_entropy("abcdefghij");
        assert!(e > 0.0 && e <= 1.0);
        // Uniform single-char string has 0 entropy.
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn top_files_sorted_by_count() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        for _ in 0..3 {
            monitor.handle_event(&open(1, 0, "/a.txt"), &mut outputs);
        }
        for _ in 0..5 {
            monitor.handle_event(&open(1, 0, "/b.log"), &mut outputs);
        }
        let top = monitor.top_files(10);
        assert_eq!(top[0].path, "/b.log");
        assert_eq!(top[0].count, 5);
        assert_eq!(top[1].path, "/a.txt");
        assert_eq!(top[1].count, 3);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn extension_counts_aggregate() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.handle_event(&open(1, 0, "/a.pdf"), &mut outputs);
        monitor.handle_event(&open(1, 0, "/b.pdf"), &mut outputs);
        monitor.handle_event(&open(1, 0, "/c.rs"), &mut outputs);
        let exts = monitor.extension_counts();
        assert_eq!(exts.get("pdf"), Some(&2));
        assert_eq!(exts.get("rs"), Some(&1));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn process_tree_builds_hierarchy() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        // Manually inject PPID mappings (bypass /proc since test PIDs don't exist).
        monitor.pid_to_ppid.insert(1, 0); // systemd → root
        monitor.pid_to_ppid.insert(100, 1); // sshd → systemd
        monitor.pid_to_ppid.insert(200, 1); // bash → systemd
        monitor.pid_to_ppid.insert(300, 200); // vim → bash

        for pid in &[1, 100, 200, 300] {
            let comm = match pid {
                1 => "systemd",
                100 => "sshd",
                200 => "bash",
                300 => "vim",
                _ => unreachable!(),
            };
            monitor.handle_event(&make_event(EVENT_EXECVE, *pid, 0, comm, ""), &mut outputs);
        }

        let tree = monitor.build_process_tree();
        // Should have 1 root (systemd)
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].pid, 1);
        assert_eq!(tree[0].comm, "systemd");
        // systemd has 2 children (sshd, bash)
        assert_eq!(tree[0].children.len(), 2);
        // bash has 1 child (vim)
        let bash = tree[0].children.iter().find(|c| c.comm == "bash").unwrap();
        assert_eq!(bash.children.len(), 1);
        assert_eq!(bash.children[0].comm, "vim");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn flatten_tree_depth_ordering() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.pid_to_ppid.insert(1, 0);
        monitor.pid_to_ppid.insert(2, 1);
        monitor.pid_to_ppid.insert(3, 2);

        for pid in &[1, 2, 3] {
            monitor.handle_event(&make_event(EVENT_EXECVE, *pid, 0, &format!("proc{pid}"), ""), &mut outputs);
        }

        let tree = monitor.build_process_tree();
        let flat = Monitor::flatten_tree(&tree);
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].0, 0); // depth 0
        assert_eq!(flat[1].0, 1); // depth 1
        assert_eq!(flat[2].0, 2); // depth 2
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls read_ppid_from_proc → /proc
    fn multiple_roots() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        // Two unrelated roots.
        monitor.pid_to_ppid.insert(10, 0);
        monitor.pid_to_ppid.insert(20, 0);

        for pid in &[10, 20] {
            monitor.handle_event(&make_event(EVENT_EXECVE, *pid, 0, &format!("root{pid}"), ""), &mut outputs);
        }

        let tree = monitor.build_process_tree();
        assert_eq!(tree.len(), 2);
    }

    // ── Level 4: Edge case tests ─────────────────────────────────────────

    #[test]
    fn extract_extension_edge_cases() {
        // Double dots
        assert_eq!(extract_extension("file..txt"), "txt");
        // Only dots
        assert_eq!(extract_extension("..."), "");
        // Single char extension
        assert_eq!(extract_extension("x.c"), "c");
        // Very long extension
        assert_eq!(
            extract_extension("file.abcdefghijklmnopqrstuvwxyz"),
            "abcdefghijklmnopqrstuvwxyz"
        );
        // Dot at start (dotfile)
        assert_eq!(extract_extension(".gitignore"), "");
        // No path, just filename
        assert_eq!(extract_extension("Cargo.toml"), "toml");
        // Empty string
        assert_eq!(extract_extension(""), "");
        // Only extension
        assert_eq!(extract_extension(".rs"), "");
    }

    #[test]
    fn shannon_entropy_uniform_string() {
        // All same character → entropy = 0
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
        assert_eq!(shannon_entropy("1111111111"), 0.0);
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        // Mixed characters → entropy > 0.5
        let e = shannon_entropy("abcdefghij1234567890");
        assert!(e > 0.5, "expected high entropy, got {e}");
    }

    #[test]
    fn shannon_entropy_single_char() {
        assert_eq!(shannon_entropy("x"), 0.0);
    }

    #[test]
    fn cstr_to_string_full_buffer_no_nul() {
        let buf = [b'a'; EVENT_FILENAME_LEN];
        let s = cstr_to_string(&buf);
        assert_eq!(s.len(), EVENT_FILENAME_LEN);
        assert_eq!(s, "a".repeat(EVENT_FILENAME_LEN));
    }

    #[test]
    fn cstr_to_string_empty_buffer() {
        let buf = [0u8; EVENT_FILENAME_LEN];
        let s = cstr_to_string(&buf);
        assert!(s.is_empty());
    }

    #[test]
    fn cstr_to_string_single_char() {
        let mut buf = [0u8; EVENT_FILENAME_LEN];
        buf[0] = b'x';
        let s = cstr_to_string(&buf);
        assert_eq!(s, "x");
    }

    #[test]
    fn cstr_to_string_utf8_multibyte() {
        let mut buf = [0u8; EVENT_FILENAME_LEN];
        let text = "hello\u{4e16}\u{754c}\u{89c2}";
        let bytes = text.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        let s = cstr_to_string(&buf);
        assert_eq!(s, text);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn handle_event_connect_increments_execs() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.handle_event(&make_event(EVENT_CONNECT, 50, 1000, "curl", "93.184.216.34:443"), &mut outputs);
        let stats = monitor.stats.get(&50).unwrap();
        assert_eq!(stats.total_execs, 1, "network events count as execs");
        assert_eq!(stats.total_opens, 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn open_tracks_file_extension() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.handle_event(&open(1, 0, "/tmp/secret.enc"), &mut outputs);
        monitor.handle_event(&open(1, 0, "/tmp/data.pdf"), &mut outputs);
        monitor.handle_event(&open(1, 0, "/tmp/backup.tar.gz"), &mut outputs);

        let stats = monitor.stats.get(&1).unwrap();
        assert_eq!(stats.extensions.get("enc"), Some(&1));
        assert_eq!(stats.extensions.get("pdf"), Some(&1));
        assert_eq!(stats.extensions.get("gz"), Some(&1));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn window_eviction_removes_old_entries() {
        let mut monitor = Monitor::dummy(); // threshold = 3, WINDOW_SECS = 1
        let mut outputs = Vec::new();
        // Add 2 opens
        monitor.handle_event(&open(1, 0, "/a"), &mut outputs);
        monitor.handle_event(&open(1, 0, "/b"), &mut outputs);
        assert_eq!(monitor.stats.get(&1).unwrap().window_opens, 2);
        // Simulate time passing by manipulating the window directly
        if let Some(window) = monitor.windows.get_mut(&1) {
            // Backdate all entries by 2 seconds
            for ts in window.iter_mut() {
                *ts -= Duration::from_secs(2);
            }
        }
        // Next open should evict old entries
        monitor.handle_event(&open(1, 0, "/c"), &mut outputs);
        // Only the new entry should remain
        assert_eq!(monitor.stats.get(&1).unwrap().window_opens, 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn threshold_zero_disables_alerts() {
        let mut monitor = Monitor::dummy();
        monitor.threshold = 0; // Disable alerts
        let mut outputs = Vec::new();
        for _ in 0..100 {
            monitor.handle_event(&open(1, 0, "/x"), &mut outputs);
        }
        let alerts = outputs
            .iter()
            .filter(|o| matches!(o, Output::Alert(_)))
            .count();
        assert_eq!(alerts, 0, "threshold=0 should produce no alerts");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn auto_kill_emits_response_action() {
        let mut monitor = Monitor::dummy();
        monitor.auto_kill = true;
        let mut outputs = Vec::new();
        for _ in 0..3 {
            monitor.handle_event(&open(99, 1000, "/tmp/evil"), &mut outputs);
        }
        monitor.drain_display_events(&mut outputs);
        let actions: Vec<_> = outputs
            .iter()
            .filter(|o| matches!(o, Output::Action(_)))
            .collect();
        assert_eq!(actions.len(), 1, "auto-kill should emit one ResponseAction");
        if let Output::Action(act) = &outputs[1] {
            assert!(act.action.contains("99"));
        } else {
            panic!("expected ResponseAction at index 1");
        }
    }

    #[test]
    fn mit_build_reports_the_verdict_but_acts_on_nothing() {
        // The guarantee the licensing model rests on: a build of this crate, with
        // --auto-kill set, reaches the verdict and then does nothing. The action
        // reports failure, so an operator sees that no response happened rather
        // than silently believing it did.
        let mut monitor = Monitor::dummy();
        monitor.auto_kill = true;
        let mut outputs = Vec::new();
        for _ in 0..3 {
            monitor.handle_event(&open(4242, 1000, "/tmp/evil"), &mut outputs);
        }
        match outputs.iter().find_map(|o| match o {
            Output::Action(a) => Some(a),
            _ => None,
        }) {
            Some(action) => assert!(
                !action.success,
                "the MIT build must not report a successful response — it cannot send one"
            ),
            None => panic!("a verdict with --auto-kill should still be reported"),
        }
    }

    #[test]
    fn no_response_is_the_default_and_reports_failure() {
        // Guards a future refactor from making something actionable the default.
        let mut r = NoResponse;
        assert!(!r.on_verdict(1, "init"));
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingResponse(Arc<AtomicUsize>);
    impl Responder for CountingResponse {
        fn on_verdict(&mut self, _pid: u32, _comm: &str) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    #[test]
    fn an_installed_responder_is_the_one_that_acts() {
        // Proves the split is a real seam: the same verdict path calls out to
        // whatever responder the build installed.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut monitor = Monitor::dummy().with_responder(Box::new(CountingResponse(hits.clone())));
        monitor.auto_kill = true;
        let mut outputs = Vec::new();
        for _ in 0..3 {
            monitor.handle_event(&open(77, 1000, "/tmp/evil"), &mut outputs);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "responder called once");
        let action = outputs
            .iter()
            .find_map(|o| match o {
                Output::Action(a) => Some(a),
                _ => None,
            })
            .expect("action");
        assert!(action.success, "an installed responder reports what it did");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn top_files_empty_monitor() {
        let monitor = Monitor::dummy();
        let top = monitor.top_files(10);
        assert!(top.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn top_files_respects_limit() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        for i in 0..20 {
            monitor.handle_event(&open(1, 0, &format!("/tmp/file{i}.txt")), &mut outputs);
        }
        let top = monitor.top_files(5);
        assert_eq!(top.len(), 5);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn build_process_tree_orphan_pid() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        // PID with unknown parent (not in pid_to_ppid)
        monitor.handle_event(&make_event(EVENT_EXECVE, 500, 0, "orphan", ""), &mut outputs);
        let tree = monitor.build_process_tree();
        assert_eq!(tree.len(), 1, "orphan becomes a root");
        assert_eq!(tree[0].pid, 500);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn build_process_tree_hides_ignored_comm() {
        let mut monitor = Monitor::dummy().with_ignored_comms(["hyprctl"]);
        let mut outputs = Vec::new();
        // An ignored comm is still captured (events counted), just never alerts...
        monitor.handle_event(&make_event(EVENT_EXECVE, 4242, 0, "hyprctl", ""), &mut outputs);
        let _ = outputs;

        // ...and is hidden from the process tree by default.
        assert!(
            monitor.build_process_tree().is_empty(),
            "ignored comm must not render in the tree"
        );

        // --show-ignored brings it back as a single root node.
        let monitor = monitor.with_show_ignored(true);
        let shown = monitor.build_process_tree();
        assert_eq!(shown.len(), 1, "ignored comm returns with --show-ignored");
        assert_eq!(shown[0].pid, 4242);
        assert_eq!(shown[0].comm, "hyprctl");
    }

    #[test]
    fn flatten_empty_tree() {
        let tree: Vec<ProcessNode> = vec![];
        let flat = Monitor::flatten_tree(&tree);
        assert!(flat.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rate_history_capped_at_120() {
        let mut monitor = Monitor::dummy();
        // Simulate 130 ticks by manipulating tick_start
        for _ in 0..130 {
            monitor.tick_start = Instant::now() - Duration::from_secs(2);
            monitor.tick_execs = 10;
            monitor.poll();
        }
        assert!(monitor.rate_history.len() <= 120);
    }

    #[test]
    fn extension_counts_empty() {
        let monitor = Monitor::dummy();
        assert!(monitor.extension_counts().is_empty());
    }

    #[test]
    fn rate_history_empty_initially() {
        let monitor = Monitor::dummy();
        assert!(monitor.rate_history().is_empty());
    }

    #[test]
    fn stats_sorted_empty() {
        let monitor = Monitor::dummy();
        assert!(monitor.stats_sorted().is_empty());
    }

    #[test]
    fn uptime_starts_near_zero() {
        let monitor = Monitor::dummy();
        let uptime = monitor.uptime();
        assert!(uptime < Duration::from_secs(1));
    }

    #[test]
    fn total_events_starts_at_zero() {
        let monitor = Monitor::dummy();
        assert_eq!(monitor.total_events, 0);
        assert_eq!(monitor.total_lost, 0);
    }
    #[test]
    fn capped_counter_is_bounded_and_keeps_hot_keys() {
        let mut m: HashMap<String, u64> = HashMap::new();
        for _ in 0..5 {
            bump_count_capped(&mut m, "hot", 4);
        }
        for i in 0..100 {
            bump_count_capped(&mut m, &format!("cold{i}"), 4);
        }
        assert!(m.len() <= 4, "map exceeded cap: {}", m.len());
        assert_eq!(m.get("hot"), Some(&5), "hot key must survive pruning");
    }

    #[test]
    fn capped_counter_matches_plain_counter_below_cap() {
        let mut a: HashMap<String, u64> = HashMap::new();
        let mut b: HashMap<String, u64> = HashMap::new();
        for k in ["x", "y", "x", "z", "x", "y"] {
            bump_count_capped(&mut a, k, 100);
            bump_count_capped(&mut b, k, 100);
        }
        assert_eq!(a, b);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // handle_event → /proc
    fn window_opens_decays_when_process_goes_quiet() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        for _ in 0..5 {
            monitor.handle_event(&open(7, 0, "/a"), &mut outputs);
        }
        assert_eq!(monitor.stats.get(&7).unwrap().window_opens, 5);
        // Age every timestamp past the window, as if the process went quiet.
        for t in monitor.windows.get_mut(&7).unwrap().iter_mut() {
            *t -= Duration::from_secs(WINDOW_SECS + 1);
        }
        monitor.prune_idle();
        assert_eq!(monitor.stats.get(&7).unwrap().window_opens, 0);
        assert!(!monitor.windows.contains_key(&7), "empty window is dropped");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // handle_event → /proc
    fn idle_pids_are_evicted_and_active_ones_kept() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        monitor.handle_event(&open(10, 0, "/a"), &mut outputs);
        monitor.handle_event(&open(11, 0, "/b"), &mut outputs);
        *monitor.last_seen.get_mut(&10).unwrap() -=
            Duration::from_secs(IDLE_PID_TTL_SECS + 1);
        monitor.prune_idle();
        assert!(!monitor.stats.contains_key(&10));
        assert!(!monitor.last_seen.contains_key(&10));
        assert!(!monitor.pid_to_ppid.contains_key(&10));
        assert!(monitor.stats.contains_key(&11));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // handle_event → /proc
    fn exec_events_do_not_reset_the_burst_window() {
        // Anti-evasion: interleaving (possibly failing) execve calls between
        // opens must not keep a process under the alert threshold.
        let mut monitor = Monitor::dummy(); // threshold = 3
        let mut outputs = Vec::new();
        for _ in 0..4 {
            monitor.handle_event(&open(20, 0, "/a.txt"), &mut outputs);
            let exec = make_event(EVENT_EXECVE, 20, 0, "probe", "");
            monitor.handle_event(&exec, &mut outputs);
        }
        assert!(
            outputs.iter().any(|o| matches!(o, Output::Alert(_))),
            "burst of opens must still alert despite interleaved execs"
        );
        assert_eq!(monitor.stats.get(&20).unwrap().window_opens, 4);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // handle_event → /proc
    fn stats_top_is_bounded_deduped_and_sorted() {
        let mut monitor = Monitor::dummy();
        let mut outputs = Vec::new();
        for pid in 1..=40u32 {
            for _ in 0..pid {
                monitor.handle_event(&open(pid, 0, "/f"), &mut outputs);
            }
        }
        let top = monitor.stats_top(5);
        let mut pids: Vec<u32> = top.iter().map(|s| s.pid).collect();
        let before = pids.len();
        pids.sort_unstable();
        pids.dedup();
        assert_eq!(before, pids.len(), "no duplicates");
        assert!(top.len() < 40, "bounded, not all PIDs");
        assert_eq!(top[0].pid, 40, "busiest first");
        assert!(top.windows(2).all(|w| w[0].window_opens >= w[1].window_opens));
        let all = monitor.stats_top(1000);
        assert_eq!(all.len(), 40, "n above PID count returns everything");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // handle_event → /proc
    fn ignored_comm_never_alerts_but_is_still_counted() {
        let mut monitor = Monitor::dummy().with_ignored_comms(["probe"]); // threshold = 3
        let mut outputs = Vec::new();
        for _ in 0..10 {
            monitor.handle_event(&open(5, 0, "/tmp/x"), &mut outputs);
        }
        assert!(!outputs.iter().any(|o| matches!(o, Output::Alert(_))));
        assert_eq!(monitor.stats.get(&5).unwrap().total_opens, 10);
        assert_eq!(monitor.stats.get(&5).unwrap().alerts, 0);
        // A different process name is unaffected.
        let other = make_event(EVENT_OPENAT, 6, 0, "evil", "/tmp/y");
        for _ in 0..3 {
            monitor.handle_event(&other, &mut outputs);
        }
        assert!(outputs.iter().any(|o| matches!(o, Output::Alert(_))));
    }

    #[test]
    fn ignored_comms_are_truncated_like_kernel_comm_and_empty_dropped() {
        let monitor = Monitor::dummy().with_ignored_comms(["averyveryverylongprocessname", ""]);
        assert_eq!(monitor.ignore_comms, vec!["averyveryverylo".to_string()]);
    }

    #[test]
    fn decode_event_bytes_rejects_short_and_handles_garbage() {
        assert!(decode_event_bytes(&[]).is_none());
        assert!(decode_event_bytes(&[0u8; 10]).is_none());
        let full = 1 + 4 + 4 + 8 + EVENT_COMM_LEN + EVENT_FILENAME_LEN + EVENT_ARGV_LEN;
        for t in 0..=u8::MAX {
            let mut buf = vec![0xFFu8; full + 7];
            buf[0] = t; // includes unknown event types
            let _ = decode_event_bytes(&buf); // must not panic
        }
        let mut open = vec![0u8; full];
        open[0] = EVENT_OPENAT;
        open[17..22].copy_from_slice(b"probe");
        open[33..44].copy_from_slice(b"/tmp/a.LOCK");
        let ev = decode_event_bytes(&open).unwrap();
        assert_eq!(ev.comm, "probe");
        assert_eq!(ev.extension.as_deref(), Some("lock"));
    }
}
