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
use chrono::Local;

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

/// Learning rate for MeMLP online training (conservative — one step per alert).
const MEMLP_LEARNING_RATE: f32 = 0.03;

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
}

#[derive(Debug, Clone)]
pub struct RecordedEvent {
    pub ts: String,
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
    /// Recorded event + delivery latency in nanoseconds
    /// (kernel ktime at tracepoint entry → userspace receive time).
    Event(RecordedEvent, u64),
    Lost(u64),
}

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
    stats: HashMap<u32, ProcStats>,
    windows: HashMap<u32, VecDeque<Instant>>,
    /// PID → PPID mapping (resolved from /proc/<pid>/status).
    pid_to_ppid: HashMap<u32, u32>,
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

/// Send SIGKILL to a process. Returns true on success.
///
/// # Safety
///
/// Calls `kill(2)` with SIGKILL. The pid is cast from u32 to i32 which is
/// safe for all valid PIDs (max value 4194304 on Linux, well within i32 range).
/// SIGKILL cannot be caught, so the target process will terminate.
fn kill_process(pid: u32) -> bool {
    // SAFETY: kill(2) is a POSIX syscall. pid is within i32 range for valid PIDs.
    // SIGKILL is a valid signal number. No pointer dereference involved.
    let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    rc == 0
}

impl Monitor {
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

        let (tx, rx) = mpsc::channel();
        let reader = spawn_reader(perf_array, tx)?;

        let now = Instant::now();
        Ok(Self {
            rx,
            threshold,
            auto_kill,
            stats: HashMap::new(),
            windows: HashMap::new(),
            pid_to_ppid: HashMap::new(),
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
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Lost(n) => self.total_lost += n,
                Msg::Event(ev, latency_ns) => {
                    self.total_events += 1;
                    self.record_latency(latency_ns);
                    self.handle_event(&ev, &mut outputs);
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
        outputs
    }

    #[inline]
    fn record_latency(&mut self, latency_ns: u64) {
        self.latency.record(latency_ns);
    }

    pub(crate) fn handle_event(&mut self, ev: &RecordedEvent, outputs: &mut Vec<Output>) {
        let stats = self.stats.entry(ev.pid).or_default();
        stats.pid = ev.pid;
        stats.comm = ev.comm.clone();

        // Resolve PPID from /proc on first encounter.
        if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_ppid.entry(ev.pid) {
            if let Some(ppid) = read_ppid_from_proc(ev.pid) {
                e.insert(ppid);
                stats.ppid = ppid;
            }
        }

        // ── MeMLP: feed the live event stream to the neural engine ──────
        if self.memlp.is_some() {
            match ev.kind {
                Kind::Exec => {
                    self.pid_features
                        .entry(ev.pid)
                        .or_default()
                        .observe_exec(false);
                }
                Kind::Connect | Kind::Accept | Kind::SendTo | Kind::RecvFrom => {
                    self.pid_features
                        .entry(ev.pid)
                        .or_default()
                        .observe_exec(true);
                }
                Kind::Open => {
                    let entropy = ev.file.as_deref().map(shannon_entropy).unwrap_or(0.0);
                    self.pid_features.entry(ev.pid).or_default().observe_open(
                        ev.file.as_deref().unwrap_or(""),
                        ev.extension.as_deref(),
                        entropy,
                    );
                }
                Kind::Mkdir => {
                    self.pid_features
                        .entry(ev.pid)
                        .or_default()
                        .observe_fs(false);
                }
                Kind::Unlink | Kind::Chmod => {
                    self.pid_features
                        .entry(ev.pid)
                        .or_default()
                        .observe_fs(true);
                }
                Kind::Kill => {}
            }
        }

        match ev.kind {
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
                // Track file extensions.
                if let Some(ref ext) = ev.extension {
                    if !ext.is_empty() {
                        *stats.extensions.entry(ext.clone()).or_insert(0) += 1;
                        *self.ext_counts.entry(ext.clone()).or_insert(0) += 1;
                    }
                }

                // Track per-file open count.
                if let Some(ref file) = ev.file {
                    *self.file_counts.entry(file.clone()).or_insert(0) += 1;
                }

                let now = Instant::now();
                let window = self.windows.entry(ev.pid).or_default();
                let cutoff = now - Duration::from_secs(WINDOW_SECS);
                while window.front().is_some_and(|t| *t < cutoff) {
                    window.pop_front();
                }
                window.push_back(now);

                stats.total_opens += 1;
                stats.window_opens = window.len() as u64;
                self.tick_opens += 1;

                if self.threshold > 0 && stats.window_opens == self.threshold {
                    stats.alerts += 1;
                    self.tick_alerts += 1;
                    // ── MeMLP: online training step + neural verdict ────
                    let memlp_verdict = if let Some(model) = self.memlp.as_mut() {
                        let feats = self.pid_features.entry(ev.pid).or_default().features();
                        model.train_observation(&feats, MEMLP_LEARNING_RATE);
                        Some(model.assess(&feats))
                    } else {
                        None
                    };
                    outputs.push(Output::Alert(Alert {
                        ts: ev.ts.clone(),
                        pid: ev.pid,
                        uid: ev.uid,
                        comm: ev.comm.clone(),
                        opens: stats.window_opens,
                        memlp: memlp_verdict,
                    }));
                    // ── Response: terminate the offending process ──────────
                    if self.auto_kill {
                        let result = kill_process(ev.pid);
                        outputs.push(Output::Action(ResponseAction {
                            ts: ev.ts.clone(),
                            pid: ev.pid,
                            comm: ev.comm.clone(),
                            action: format!("SIGKILL sent to PID {} ({})", ev.pid, ev.comm),
                            success: result,
                        }));
                    }
                }
            }
            Kind::Mkdir | Kind::Unlink | Kind::Kill | Kind::Chmod => {
                // FS/signal events — track in file counts for the Top Files panel.
                if let Some(ref file) = ev.file {
                    *self.file_counts.entry(file.clone()).or_insert(0) += 1;
                }
                self.tick_opens += 1;
            }
        }
        outputs.push(Output::Event(ev.clone()));
    }

    pub fn stats_sorted(&self) -> Vec<ProcStats> {
        let mut all: Vec<ProcStats> = self.stats.values().cloned().collect();
        all.sort_by_key(|s| std::cmp::Reverse(s.window_opens));
        all
    }

    /// Top-N most-opened files, sorted by count descending.
    pub fn top_files(&self, n: usize) -> Vec<FileRank> {
        let mut files: Vec<FileRank> = self
            .file_counts
            .iter()
            .map(|(path, &count)| {
                let ext = extract_extension(path);
                let entropy = shannon_entropy(path);
                FileRank {
                    path: path.clone(),
                    count,
                    extension: ext,
                    entropy,
                }
            })
            .collect();
        files.sort_by_key(|b| std::cmp::Reverse(b.count));
        files.truncate(n);
        files
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
        // Collect all known PIDs and their children.
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut all_pids: Vec<u32> = Vec::new();

        for &pid in self.stats.keys() {
            all_pids.push(pid);
            let ppid = self.pid_to_ppid.get(&pid).copied().unwrap_or(0);
            children_map.entry(ppid).or_default().push(pid);
        }

        // Sort children by name for stable display.
        for children in children_map.values_mut() {
            children.sort_by_key(|pid| {
                self.stats
                    .get(pid)
                    .map(|s| s.comm.clone())
                    .unwrap_or_default()
            });
        }

        // Find roots: PIDs whose parent is not in our stats (or is 0).
        let mut roots: Vec<u32> = all_pids
            .iter()
            .filter(|&&pid| {
                let ppid = self.pid_to_ppid.get(&pid).copied().unwrap_or(0);
                ppid == 0 || !self.stats.contains_key(&ppid)
            })
            .copied()
            .collect();
        roots.sort_by_key(|pid| {
            self.stats
                .get(pid)
                .map(|s| s.comm.clone())
                .unwrap_or_default()
        });

        // Build recursively.
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

        roots
            .into_iter()
            .map(|pid| build(pid, &self.stats, &children_map))
            .collect()
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
    tx: mpsc::Sender<Msg>,
) -> Result<thread::JoinHandle<()>> {
    let cpus = online_cpus()
        .map_err(|(err, io)| anyhow::anyhow!("failed to enumerate CPUs: {err}: {io}"))?;
    let mut buffers: Vec<PerfEventArrayBuffer<MapData>> = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let buf = perf_array
            .open(cpu, Some(128))
            .context("failed to open perf buffer")?;
        buffers.push(buf);
    }

    eprintln!("[talus] opening perf buffers on {} CPUs", buffers.len());

    thread::Builder::new()
        .name("talus-reader".into())
        .spawn(move || {
            loop {
                let mut idle = true;
                for buf in buffers.iter_mut() {
                    buf.for_each(|event| {
                        idle = false;
                        match event {
                            PerfEvent::Sample { head, tail } => {
                                // The sample payload may span the ring boundary;
                                // concatenate head + tail into a contiguous buffer.
                                let total_len = head.len() + tail.len();
                                if total_len >= size_of::<ProcessEvent>() {
                                    // SAFETY: The raw bytes come from the perf buffer and were
                                    // written by the kernel-side eBPF program as a ProcessEvent
                                    // (#[repr(C)] fixed-size struct). read_unaligned is used
                                    // because perf buffer alignment is not guaranteed. The struct
                                    // layout matches the kernel-side definition exactly.
                                    if total_len == head.len() {
                                        // Contiguous: no wrapping
                                        let evt = unsafe {
                                            std::ptr::read_unaligned(
                                                head.as_ptr() as *const ProcessEvent
                                            )
                                        };
                                        let _ = tx.send(Msg::Event(
                                            to_recorded(&evt),
                                            now_ns().saturating_sub(evt.ktime_ns),
                                        ));
                                    } else {
                                        // Wrapped: copy into a temporary buffer
                                        let mut buf = vec![0u8; total_len];
                                        buf[..head.len()].copy_from_slice(head);
                                        buf[head.len()..].copy_from_slice(tail);
                                        let evt = unsafe {
                                            std::ptr::read_unaligned(
                                                buf.as_ptr() as *const ProcessEvent
                                            )
                                        };
                                        let _ = tx.send(Msg::Event(
                                            to_recorded(&evt),
                                            now_ns().saturating_sub(evt.ktime_ns),
                                        ));
                                    }
                                }
                            }
                            PerfEvent::Lost { count } => {
                                let _ = tx.send(Msg::Lost(count));
                            }
                        }
                    });
                }
                if idle {
                    thread::sleep(Duration::from_millis(1));
                } else {
                    // Signal watchdog that eBPF pipeline is alive
                    crate::watchdog::heartbeat();
                }
            }
        })
        .context("failed to spawn reader thread")
}
fn to_recorded(raw: &ProcessEvent) -> RecordedEvent {
    let ts = Local::now().format("%H:%M:%S%.3f").to_string();
    let argv = raw.argv_str();
    let argv_opt = if argv.is_empty() { None } else { Some(argv) };
    match raw.event_type {
        EVENT_EXECVE => RecordedEvent {
            ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
                ts,
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
            ts,
            kind: Kind::Exec,
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
        let (_tx, rx) = mpsc::channel();
        let handle = thread::spawn(|| loop {
            thread::sleep(Duration::from_secs(60));
        });
        let now = Instant::now();
        Self {
            rx,
            threshold: 3,
            auto_kill: false,
            stats: HashMap::new(),
            windows: HashMap::new(),
            pid_to_ppid: HashMap::new(),
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

    fn open(pid: u32, uid: u32, file: &str) -> RecordedEvent {
        RecordedEvent {
            ts: "00:00:00.000".into(),
            kind: Kind::Open,
            pid,
            uid,
            comm: "probe".into(),
            file: Some(file.into()),
            extension: Some(extract_extension(file)),
            argv: None,
            bytes: None,
        }
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
        monitor.handle_event(
            &RecordedEvent {
                ts: "00:00:00.000".into(),
                kind: Kind::Exec,
                pid: 9,
                uid: 0,
                comm: "init".into(),
                file: None,
                extension: None,
                argv: None,
                bytes: None,
            },
            &mut outputs,
        );
        let stats = monitor.stats.get(&9).expect("stats recorded");
        assert_eq!(stats.total_execs, 1);
        assert_eq!(stats.total_opens, 0);
        assert_eq!(stats.alerts, 0);
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
        let alerts: Vec<_> = outputs
            .iter()
            .filter(|o| matches!(o, Output::Alert(_)))
            .collect();
        assert_eq!(alerts.len(), 1, "exactly one alert at the threshold");
        if let Output::Alert(a) = &outputs[2] {
            assert_eq!(a.pid, 42);
            assert_eq!(a.opens, 3);
        } else {
            panic!("third output must be the alert");
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
            monitor.handle_event(
                &RecordedEvent {
                    ts: "00:00:00.000".into(),
                    kind: Kind::Exec,
                    pid: *pid,
                    uid: 0,
                    comm: match pid {
                        1 => "systemd".into(),
                        100 => "sshd".into(),
                        200 => "bash".into(),
                        300 => "vim".into(),
                        _ => unreachable!(),
                    },
                    file: None,
                    extension: None,
                    argv: None,
                    bytes: None,
                },
                &mut outputs,
            );
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
            monitor.handle_event(
                &RecordedEvent {
                    ts: "00:00:00.000".into(),
                    kind: Kind::Exec,
                    pid: *pid,
                    uid: 0,
                    comm: format!("proc{pid}"),
                    file: None,
                    extension: None,
                    argv: None,
                    bytes: None,
                },
                &mut outputs,
            );
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
            monitor.handle_event(
                &RecordedEvent {
                    ts: "00:00:00.000".into(),
                    kind: Kind::Exec,
                    pid: *pid,
                    uid: 0,
                    comm: format!("root{pid}"),
                    file: None,
                    extension: None,
                    argv: None,
                    bytes: None,
                },
                &mut outputs,
            );
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
        monitor.handle_event(
            &RecordedEvent {
                ts: "00:00:00.000".into(),
                kind: Kind::Connect,
                pid: 50,
                uid: 1000,
                comm: "curl".into(),
                file: Some("93.184.216.34:443".into()),
                extension: None,
                argv: None,
                bytes: None,
            },
            &mut outputs,
        );
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
        let actions: Vec<_> = outputs
            .iter()
            .filter(|o| matches!(o, Output::Action(_)))
            .collect();
        assert_eq!(actions.len(), 1, "auto-kill should emit one ResponseAction");
        if let Output::Action(act) = &outputs[3] {
            assert!(act.action.contains("SIGKILL"));
            assert!(act.action.contains("99"));
        } else {
            panic!("expected ResponseAction at index 3");
        }
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
        monitor.handle_event(
            &RecordedEvent {
                ts: "00:00:00.000".into(),
                kind: Kind::Exec,
                pid: 500,
                uid: 0,
                comm: "orphan".into(),
                file: None,
                extension: None,
                argv: None,
                bytes: None,
            },
            &mut outputs,
        );
        let tree = monitor.build_process_tree();
        assert_eq!(tree.len(), 1, "orphan becomes a root");
        assert_eq!(tree[0].pid, 500);
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
}
