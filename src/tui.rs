//! Talus Process Monitor — FrankenTUI dashboard
//!
//! Uses MiniBar, BarChart, LineChart, Canvas, Badge, Sparkline, heatmap_gradient,
//! and StyledText with color wave effects from ftui-extras.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::process::Command as StdCommand;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use ftui_core::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, Modifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ftui_core::geometry::Rect;
use ftui_extras::charts::{heatmap_gradient, LineChart, Series, Sparkline};
use ftui_extras::text_effects::{StyledText, TextEffect};
use ftui_layout::{Constraint, Flex};
use ftui_render::budget::FrameBudgetConfig;
use ftui_render::cell::PackedRgba;
use ftui_render::frame::Frame;
use ftui_runtime::program::{App, Cmd, Model};
use ftui_runtime::terminal_writer::ScreenMode;
use ftui_runtime::{Every, Subscription};
use ftui_style::{Style, StyleFlags};
use ftui_text::Line;
use ftui_text::Span;
use ftui_widgets::badge::Badge;
use ftui_widgets::block::Block;
use ftui_widgets::borders::{BorderType, Borders};
use ftui_widgets::log_viewer::{LogViewer, LogViewerState};
use ftui_widgets::paragraph::Paragraph;
use ftui_widgets::progress::{MiniBar, MiniBarColors};
use ftui_widgets::status_line::{StatusItem, StatusLine};
use ftui_widgets::{StatefulWidget, Widget};

use crate::license::LicenseState;
use crate::monitor::{
    is_system_comm, FileRank, Monitor, Output, ProcStats, RateSample, TUI_SNAPSHOT_EVENT_CAP,
};

/// Processes that produce too many events to display (polling, IPC, etc.)
const NOISY_COMMS: &[&str] = &[
    // Desktop / compositor IPC — spawn forks (hyprctl etc.) flood the log.
    "hyprctl",
    "hyprland",
    "freebuff",
    "waybar",
    "upowerd",
    "mutter",
    "Xwayland",
    "sway",
    "fuzzel",
    "wlsunset",
    // Audio IPC
    "pipewire",
    "wireplumber",
    // D-Bus / system daemons
    "dbus-daemon",
    "systemd-resolve",
    "systemd-network",
    // Notification daemons
    "dunst",
    "mako",
];

// ── Palette — cohesive cyberpunk ─────────────────────────────────────────

/// Base background: deep matte navy (#1a1b26).
const BG: PackedRgba = PackedRgba::rgb(26, 27, 38);
const BLUE: PackedRgba = PackedRgba::rgb(122, 162, 247);

const GREEN: PackedRgba = PackedRgba::rgb(80, 200, 120);
/// Blood red — reserved for emergency alerts (high-entropy ransomware markers).
const RED: PackedRgba = PackedRgba::rgb(220, 20, 45);
const AMBER: PackedRgba = PackedRgba::rgb(250, 180, 50);
const PURPLE: PackedRgba = PackedRgba::rgb(160, 120, 240);

const CYAN: PackedRgba = PackedRgba::rgb(100, 210, 245);
const DIM: PackedRgba = PackedRgba::rgb(86, 95, 137);
const FG: PackedRgba = PackedRgba::rgb(169, 177, 214);
const BRIGHT: PackedRgba = PackedRgba::rgb(192, 202, 245);
const BORDER: PackedRgba = PackedRgba::rgb(41, 46, 66);
const BORDER_HI: PackedRgba = PackedRgba::rgb(122, 162, 247);
/// Selected process row background (muted navy, above the panel background).
const SELECT_BG: PackedRgba = PackedRgba::rgb(48, 56, 92);

// ── Layout / gateway constants ────────────────────────────────────────────

/// Link shown on the first-run gateway frame.
const GATEWAY_URL: &str = "https://hartwell-labs.pl";
/// Height (rows) of the telemetry card in the right-hand detail column.
/// The card renders 8 rows of content plus a two-row border.
const TELEMETRY_H: u16 = 10;
/// Demo-mode figures (only used when `TALUS_TUI_DEMO=1`).
const DEMO_EPS: f64 = 280_000.0;
const DEMO_CPU: f64 = 7.6;

// ── Panels ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Events,
    Processes,
    Network,
    TopFiles,
    Extensions,
    Alerts,
    Heatmap,
}

impl Panel {
    /// Panel order is part of the UI contract: `1`-`7` jump straight to the
    /// index in this array, and the status line prints the focused name.
    const ALL: [Panel; 7] = [
        Panel::Events,
        Panel::Processes,
        Panel::Network,
        Panel::TopFiles,
        Panel::Extensions,
        Panel::Alerts,
        Panel::Heatmap,
    ];
    /// Number of panels. The `collapsed` array carries one extra slot for the
    /// rate-chart strip, so it is `PANEL_COUNT + 1` long.
    const COUNT: usize = Self::ALL.len();
    fn name(&self) -> &'static str {
        match self {
            Self::Events => "EVENTS",
            Self::Processes => "PROCESSES",
            Self::Network => "NETWORK",
            Self::TopFiles => "TOP FILES",
            Self::Extensions => "FILE TYPES",
            Self::Alerts => "ALERTS",
            Self::Heatmap => "HEATMAP",
        }
    }
}

// ── Messages ──────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Msg {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
    Noop,
}

impl From<Event> for Msg {
    fn from(e: Event) -> Self {
        match e {
            Event::Key(k) => Msg::Key(k),
            Event::Mouse(m) => Msg::Mouse(m),
            _ => Msg::Noop,
        }
    }
}

// ── Snapshot from monitor thread ──────────────────────────────────────────

struct Snapshot {
    events: Vec<Evt>,
    stats: Vec<ProcStats>,
    tree: Vec<(usize, u32, String, u64, u64)>, // (depth, pid, comm, opens, alerts)
    top_files: Vec<FileRank>,
    exts: std::collections::HashMap<String, u64>,
    rates: VecDeque<RateSample>,
    total: u64,
    lost: u64,
    uptime: u64,
    /// `false` for a light snapshot (events + counters only): the process
    /// tree, per-process stats, top files and extension maps are then empty
    /// and `apply_snapshot` leaves the existing panels untouched.
    refresh: bool,
}

/// Minimum interval between full (heavy) snapshots built by the poll thread.
const HEAVY_REFRESH: Duration = Duration::from_millis(2000);
/// Max processes carried per heavy snapshot (busiest by window + heaviest by lifetime).
const TUI_PROC_LIMIT: usize = 128;

/// Base tick unit for the UI clock (50 ms).
///
/// Every tick repaints the whole frame — header with `ColorWave`, the process
/// table and the event log — so the tick rate is the TUI's dominant CPU cost.
/// `ftui_runtime::tick_strategy::Uniform` is used for multi-screen apps; this
/// dashboard is single-screen, so the same "tick every Nth frame" semantics are
/// applied directly to the subscription period (TICK_BASE × divisor).
const TICK_BASE: Duration = Duration::from_millis(50);

/// Uniform tick divisor — render every `N`th base tick.
///
/// | divisor | FPS | idle CPU (measured) |
/// |---------|-----|---------------------|
/// | 1       | 20  | ~36-55%             |
/// | 10      | 2   | target ~5%          |
/// | 20      | 1   | target ~3%          |
///
/// A monitoring dashboard does not need 20 FPS; 2 FPS keeps events feeling
/// live while bounding repaint cost. Raise to 20 for the quietest possible run.
const UNIFORM_TICK_DIVISOR: u32 = 20;

/// Row in the heatmap: process name + per-extension counts.
struct HeatmapRow {
    label: String,
    ext_counts: Vec<(String, u64)>,
}

#[derive(Clone)]
struct Evt {
    ts: String,
    kind: String,
    pid: u32,
    comm: String,
    file: Option<String>,
    is_alert: bool,
    opens: u64,
    memlp: Option<crate::memlp::Assessment>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct NetEntry {
    ts: String,
    pid: u32,
    comm: String,
    kind: String,
    addr: String,
}

// ── State ─────────────────────────────────────────────────────────────────

struct App_ {
    log: LogViewer,
    log_st: LogViewerState,
    alerts: LogViewer,
    alert_st: LogViewerState,
    net: VecDeque<NetEntry>,
    procs: Vec<ProcRow>,
    tree: Vec<(usize, u32, String, u64, u64)>,
    files: Vec<FileRow>,
    exts: Vec<(String, u64)>,
    heatmap: Vec<HeatmapRow>,
    heatmap_exts: Vec<String>,
    rates: VecDeque<RateSample>,
    rate_chart: Vec<(f64, f64)>,
    open_chart: Vec<(f64, f64)>,
    alert_chart: Vec<(f64, f64)>,
    focused: usize,
    paused: bool,
    help: bool,
    total: u64,
    lost: u64,
    uptime: u64,
    alert_count: u64,
    time: f64,
    rx: mpsc::Receiver<Snapshot>,
    // ── license state ──
    #[allow(dead_code)]
    tier: String,
    #[allow(dead_code)]
    organization: Option<String>,
    is_activated: bool,
    // ── anti-spam: rate limit per comm ──
    rate_counters: HashMap<String, (u64, Instant)>,
    rate_limit: u64,
    rate_window: Duration,
    rate_suppressed: u64,
    // ── collapsible panels (one slot per panel + the rate-chart strip) ──
    collapsed: [bool; Panel::COUNT + 1],
    // ── copy buffer ──
    last_event_lines: VecDeque<String>,
    last_alert_lines: VecDeque<String>,
    /// Identity of the previously pushed log line, split into its parts so
    /// repeated events compare without allocating.
    last_log_kind: &'static str,
    last_log_comm: String,
    last_log_file: String,
    /// How many consecutive events matched the last identity.
    last_log_repeat: u64,
    // ── search mode ──
    search_mode: bool,
    search_buf: String,
    search_hits: usize,
    // ── mouse hit-testing: stored body area from last render ──
    body_area: Cell<Rect>,
    // ── 70/30 layout hit-testing ──
    left_area: Cell<Rect>,
    side_area: Cell<Rect>,
    // ── process table mouse state ──
    /// Inner rect of the process table from the last render (for hit-testing).
    proc_area: Cell<Rect>,
    /// First visible row; bumped by the mouse wheel.
    proc_scroll: usize,
    /// PID of the clicked process row, kept across snapshots.
    proc_sel: Option<u32>,
    // ── first-run gateway frame ──
    gateway: bool,
    gateway_sel: usize,
    gateway_note: String,
    gateway_link_area: Cell<Rect>,
    gateway_cont_area: Cell<Rect>,
    // ── live telemetry (view-only; derived from snapshot counters) ──
    demo: bool,
    eps: f64,
    eps_mark: (Instant, u64),
    cpu_pct: f64,
    cpu_mark: u64,
}

#[allow(dead_code)]
struct ProcRow {
    pid: u32,
    comm: String,
    opens: u64,
    alerts: u64,
}
struct FileRow {
    name: String,
    count: u64,
    ext: String,
    entropy: f64,
}

impl App_ {
    fn new(rx: mpsc::Receiver<Snapshot>, license: &LicenseState) -> Self {
        let mut log = LogViewer::new(1000);
        let tier_name = license.tier_name().to_string();
        let org = license.organization.clone();
        let activated = license.is_activated;
        let tier_display = if activated {
            tier_name.to_string()
        } else {
            format!("{tier_name} (free)")
        };
        log.push(
            format!("[talus] eBPF monitor started — license: {tier_display} — press ? for help")
                .as_str(),
        );
        Self {
            log,
            log_st: LogViewerState::default(),
            alerts: LogViewer::new(200),
            alert_st: LogViewerState::default(),
            net: VecDeque::new(),
            procs: Vec::new(),
            tree: Vec::new(),
            files: Vec::new(),
            exts: Vec::new(),
            heatmap: Vec::new(),
            heatmap_exts: Vec::new(),
            rate_chart: Vec::new(),
            open_chart: Vec::new(),
            alert_chart: Vec::new(),
            rates: VecDeque::new(),
            focused: 0,
            paused: false,
            help: false,
            total: 0,
            lost: 0,
            uptime: 0,
            alert_count: 0,
            time: 0.0,
            rx,
            tier: tier_name,
            organization: org,
            is_activated: activated,
            rate_counters: HashMap::new(),
            rate_limit: 15, // max 15 events per comm per 1s
            rate_window: Duration::from_secs(1),
            rate_suppressed: 0,
            collapsed: [false; Panel::COUNT + 1],
            last_event_lines: VecDeque::new(),
            last_alert_lines: VecDeque::new(),
            last_log_kind: "",
            last_log_comm: String::new(),
            last_log_file: String::new(),
            last_log_repeat: 0,
            search_mode: false,
            search_buf: String::new(),
            search_hits: 0,
            body_area: Cell::new(Rect::default()),
            left_area: Cell::new(Rect::default()),
            side_area: Cell::new(Rect::default()),
            proc_area: Cell::new(Rect::default()),
            proc_scroll: 0,
            proc_sel: None,
            gateway: gateway_should_show(),
            gateway_sel: 0,
            gateway_note: String::new(),
            gateway_link_area: Cell::new(Rect::default()),
            gateway_cont_area: Cell::new(Rect::default()),
            demo: std::env::var("TALUS_TUI_DEMO")
                .map(|v| v == "1")
                .unwrap_or(false),
            eps: 0.0,
            eps_mark: (Instant::now(), 0),
            cpu_pct: 0.0,
            cpu_mark: proc_cpu_ticks().unwrap_or(0),
        }
    }

    /// Rows that fit inside the process table's last drawn inner rect.
    fn proc_rows(&self) -> usize {
        self.proc_area.get().height as usize
    }

    /// Scroll the process table by `delta` rows, clamped to its content.
    fn scroll_procs(&mut self, delta: isize) {
        let max = self.tree.len().saturating_sub(self.proc_rows());
        let next = self.proc_scroll as isize + delta;
        self.proc_scroll = next.clamp(0, max as isize) as usize;
    }

    /// Select the process row under screen row `y`; clicking it again clears.
    fn click_proc_row(&mut self, y: u16) {
        let area = self.proc_area.get();
        if area.height == 0 || y < area.y || y >= area.y + area.height {
            return;
        }
        let scroll = self
            .proc_scroll
            .min(self.tree.len().saturating_sub(self.proc_rows()));
        let idx = scroll + (y - area.y) as usize;
        if let Some(row) = self.tree.get(idx) {
            let pid = row.1;
            self.proc_sel = if self.proc_sel == Some(pid) {
                None
            } else {
                Some(pid)
            };
        }
    }

    /// Recompute events/s and this process's CPU% once per second.
    fn sample_telemetry(&mut self, total: u64) {
        let now = Instant::now();
        let dt = now.duration_since(self.eps_mark.0).as_secs_f64();
        if dt < 1.0 {
            return;
        }
        self.eps = total.saturating_sub(self.eps_mark.1) as f64 / dt;
        self.eps_mark = (now, total);
        if let Some(ticks) = proc_cpu_ticks() {
            // SAFETY: sysconf has no preconditions.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
            self.cpu_pct = ticks.saturating_sub(self.cpu_mark) as f64 / hz / dt * 100.0;
            self.cpu_mark = ticks;
        }
    }

    /// Try to open the gateway link in the user's browser.
    fn open_gateway_link(&mut self) {
        let ok = StdCommand::new("xdg-open")
            .arg(GATEWAY_URL)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok();
        self.gateway_note = if ok {
            "opening in your browser...".to_string()
        } else {
            format!("could not launch a browser - visit {GATEWAY_URL}")
        };
    }

    /// Leave the gateway frame and remember that it has been seen.
    fn leave_gateway(&mut self) {
        self.gateway = false;
        if let Some(path) = gateway_marker_path() {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(path, b"seen\n");
        }
    }

    fn apply_snapshot(&mut self, s: Snapshot) {
        self.sample_telemetry(s.total);
        for e in &s.events {
            let kind_tag = match e.kind.as_str() {
                "Exec" => "EXEC  ",
                "Open" => "OPEN  ",
                "Connect" | "Accept" | "SendTo" | "RecvFrom" => "NET   ",
                "Mkdir" => "MKDIR ",
                "Unlink" => "UNLINK",
                "Kill" => "KILL  ",
                "Chmod" => "CHMOD ",
                _ => "EVENT ",
            };
            let file_part = e.file.as_deref().unwrap_or("");
            let is_noisy = NOISY_COMMS.contains(&e.comm.as_str());

            // ── anti-spam: rate limit per comm ──
            if !e.is_alert {
                let entry = self
                    .rate_counters
                    .entry(e.comm.clone())
                    .or_insert((0, Instant::now()));
                if entry.0 == 0 || entry.1.elapsed() >= self.rate_window {
                    *entry = (1, Instant::now()); // new window
                } else {
                    entry.0 += 1;
                    if entry.0 > self.rate_limit {
                        self.total += 1;
                        self.rate_suppressed += 1;
                        continue;
                    }
                }
            }
            self.total += 1;

            let line = if e.is_alert {
                let memlp_part = e.memlp.as_ref().map(|m| {
                    let summary = m.summary();
                    if m.is_threat() {
                        format!("  [MeMLP {summary} :: THREAT]")
                    } else {
                        format!("  [MeMLP {summary}]")
                    }
                });
                format!(
                    "{} *** ALERT  [{}] {} opened {} files/s{}",
                    e.ts,
                    e.pid,
                    e.comm,
                    e.opens,
                    memlp_part.as_deref().unwrap_or("")
                )
            } else {
                format!(
                    "{} {} [{:>6}] {:<16} {}",
                    e.ts, kind_tag, e.pid, e.comm, file_part
                )
            };
            if !is_noisy {
                // Collapse repeats: 300 `hyprctl` IPC events become one line
                // with a `(x300)` suffix instead of 300 identical rows. Only
                // log-scale checkpoints are pushed so the log keeps a trace
                // of ongoing activity without re-rendering every event.
                if kind_tag == self.last_log_kind
                    && e.comm == self.last_log_comm
                    && file_part == self.last_log_file
                {
                    let before = self.last_log_repeat;
                    self.last_log_repeat += 1;
                    let now = self.last_log_repeat;
                    if before != 0 && (now == 10 || now == 100 || now.is_multiple_of(1000)) {
                        let collapsed = format!(
                            "{} {} [{:>6}] {:<16} {}  (x{})",
                            e.ts, kind_tag, e.pid, e.comm, file_part, now
                        );
                        self.log.push(collapsed.as_str());
                        self.last_event_lines.push_back(collapsed);
                        if self.last_event_lines.len() > 50 {
                            self.last_event_lines.pop_front();
                        }
                    }
                } else {
                    self.last_log_kind = kind_tag;
                    self.last_log_comm.clear();
                    self.last_log_comm.push_str(&e.comm);
                    self.last_log_file.clear();
                    self.last_log_file.push_str(file_part);
                    self.last_log_repeat = 1;
                    self.log.push(line.as_str());
                    self.last_event_lines.push_back(line.clone());
                    if self.last_event_lines.len() > 50 {
                        self.last_event_lines.pop_front();
                    }
                }
            }
            if !is_noisy
                && matches!(
                    e.kind.as_str(),
                    "Connect" | "Accept" | "SendTo" | "RecvFrom"
                )
            {
                self.net.push_front(NetEntry {
                    ts: e.ts.clone(),
                    pid: e.pid,
                    comm: e.comm.clone(),
                    kind: e.kind.clone(),
                    addr: file_part.to_string(),
                });
                while self.net.len() > 200 {
                    self.net.pop_back();
                }
            }
            if e.is_alert {
                self.alert_count += 1;
                self.alerts.push(line.as_str());
                self.last_alert_lines.push_back(line);
                if self.last_alert_lines.len() > 50 {
                    self.last_alert_lines.pop_front();
                }
            }
        }
        if !s.refresh {
            self.total = s.total;
            self.lost = s.lost;
            self.uptime = s.uptime;
            return;
        }
        self.procs = s
            .stats
            .iter()
            .filter(|p| !is_system_comm(&p.comm))
            .map(|p| ProcRow {
                pid: p.pid,
                comm: p.comm.clone(),
                opens: p.window_opens,
                alerts: p.alerts,
            })
            .collect();
        self.procs.sort_by_key(|b| std::cmp::Reverse(b.opens));
        let mut tree: Vec<(usize, u32, String, u64, u64)> = s
            .tree
            .into_iter()
            .filter(|(_, _, comm, _, _)| !is_system_comm(comm))
            .collect();
        // Filtering the kernel roots leaves their children at depth 1+, which
        // would render every row indented by an invisible parent. Re-root the
        // visible forest so the first level starts at column 0.
        if let Some(min_depth) = tree.iter().map(|row| row.0).min() {
            for row in &mut tree {
                row.0 -= min_depth;
            }
        }
        self.tree = tree;
        // A refresh can shrink the table or drop the selected process. Clamp
        // the scroll offset and forget a selection that is no longer present.
        let visible = self.proc_area.get().height as usize;
        self.proc_scroll = self
            .proc_scroll
            .min(self.tree.len().saturating_sub(visible));
        if let Some(pid) = self.proc_sel {
            if !self.tree.iter().any(|row| row.1 == pid) {
                self.proc_sel = None;
            }
        }
        self.files = s
            .top_files
            .iter()
            .map(|f| FileRow {
                name: f.path.rsplit('/').next().unwrap_or(&f.path).to_string(),
                count: f.count,
                ext: f.extension.clone(),
                entropy: f.entropy,
            })
            .collect();
        let mut ext_vec: Vec<(String, u64)> = s.exts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        ext_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        self.exts = ext_vec;
        self.rates = s.rates;

        // Rebuild the charts from the monitor's full 120-second history.
        // Appending only the newest sample (the old behaviour) left the
        // charts empty for the first few seconds and one point behind, which
        // made the RATES strip look broken on startup and during demos.
        self.rate_chart = self
            .rates
            .iter()
            .enumerate()
            .map(|(i, r)| (i as f64, r.exec_count as f64))
            .collect();
        self.open_chart = self
            .rates
            .iter()
            .enumerate()
            .map(|(i, r)| (i as f64, r.open_count as f64))
            .collect();
        self.alert_chart = self
            .rates
            .iter()
            .enumerate()
            .map(|(i, r)| (i as f64, r.alert_count as f64))
            .collect();
        self.total = s.total;
        self.lost = s.lost;
        self.uptime = s.uptime;

        // Build heatmap: top procs × top exts (using global ext counts)
        let mut procs_for_heat: Vec<&ProcStats> = s
            .stats
            .iter()
            .filter(|p| !is_system_comm(&p.comm))
            .collect();
        procs_for_heat.sort_by_key(|b| std::cmp::Reverse(b.total_opens));
        procs_for_heat.truncate(8);

        let mut all_exts: Vec<(String, u64)> =
            s.exts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        all_exts.sort_by_key(|b| std::cmp::Reverse(b.1));
        let top_exts: Vec<String> = all_exts.iter().take(6).map(|(e, _)| e.clone()).collect();

        if !procs_for_heat.is_empty() && !top_exts.is_empty() {
            self.heatmap = procs_for_heat
                .iter()
                .map(|p| {
                    let ext_counts: Vec<(String, u64)> = top_exts
                        .iter()
                        .map(|ext| (ext.clone(), p.extensions.get(ext).copied().unwrap_or(0)))
                        .collect();
                    HeatmapRow {
                        label: p.comm.clone(),
                        ext_counts,
                    }
                })
                .collect();
            self.heatmap_exts = top_exts;
        } else {
            self.heatmap = vec![];
            self.heatmap_exts = vec![];
        }
    }
}

impl Model for App_ {
    type Message = Msg;
    fn init(&mut self) -> Cmd<Msg> {
        Cmd::None
    }

    fn update(&mut self, msg: Msg) -> Cmd<Msg> {
        match msg {
            // ── first-run gateway: arrow-navigable + mouse-clickable ──
            Msg::Key(k) if self.gateway && k.kind == KeyEventKind::Press => {
                if k.modifiers.contains(Modifiers::CTRL) && k.code == KeyCode::Char('c') {
                    return Cmd::Quit;
                }
                match k.code {
                    KeyCode::Char('q') => return Cmd::Quit,
                    KeyCode::Escape => self.leave_gateway(),
                    KeyCode::Up | KeyCode::Left | KeyCode::BackTab | KeyCode::Char('k') => {
                        self.gateway_sel = self.gateway_sel.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Right | KeyCode::Tab | KeyCode::Char('j') => {
                        self.gateway_sel = (self.gateway_sel + 1).min(1);
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if self.gateway_sel == 0 {
                            self.open_gateway_link();
                        } else {
                            self.leave_gateway();
                        }
                    }
                    _ => {}
                }
            }
            Msg::Mouse(m) if self.gateway => {
                if let MouseEventKind::Down(MouseButton::Left) = m.kind {
                    if self.gateway_link_area.get().contains(m.x, m.y) {
                        self.gateway_sel = 0;
                        self.open_gateway_link();
                    } else if self.gateway_cont_area.get().contains(m.x, m.y) {
                        self.gateway_sel = 1;
                        self.leave_gateway();
                    }
                }
            }
            // Search mode must be matched before the global key handler:
            // otherwise every typed character is consumed as a panel shortcut
            // and the search buffer never fills.
            Msg::Key(k) if k.kind == KeyEventKind::Press && self.search_mode => {
                if k.modifiers.contains(Modifiers::CTRL) && k.code == KeyCode::Char('c') {
                    return Cmd::Quit;
                }
                match k.code {
                    KeyCode::Escape => {
                        self.search_mode = false;
                        self.search_buf.clear();
                        self.search_hits = 0;
                        self.log.clear_search();
                        self.log.set_filter(None);
                    }
                    KeyCode::Enter => {
                        // Keep the filter active, leave the input line.
                        self.search_mode = false;
                    }
                    KeyCode::Backspace => {
                        self.search_buf.pop();
                        if self.search_buf.is_empty() {
                            self.search_hits = 0;
                            self.log.clear_search();
                            self.log.set_filter(None);
                        } else {
                            self.log.set_filter(Some(&self.search_buf));
                            self.search_hits = self.log.search(&self.search_buf);
                        }
                    }
                    KeyCode::Char(c) => {
                        self.search_buf.push(c);
                        self.log.set_filter(Some(&self.search_buf));
                        self.search_hits = self.log.search(&self.search_buf);
                    }
                    _ => {}
                }
            }
            Msg::Key(k) if k.kind == KeyEventKind::Press => {
                if self.help {
                    self.help = false;
                    return Cmd::None;
                }
                if k.modifiers.contains(Modifiers::CTRL) && k.code == KeyCode::Char('c') {
                    return Cmd::Quit;
                }
                // Scroll keys follow the focused panel: the event log on
                // EVENTS, the alert history on ALERTS. Other panels keep no
                // scrollback, so the keys are ignored there.
                let scroll_alerts = self.focused == 5;
                match k.code {
                    KeyCode::Char('q') => return Cmd::Quit,
                    KeyCode::Escape => {
                        // Esc clears an active filter first; only a second Esc
                        // (or `q`) quits. Avoids closing the dashboard when
                        // the user meant to dismiss a search.
                        if self.search_buf.is_empty() {
                            return Cmd::Quit;
                        }
                        self.search_buf.clear();
                        self.search_hits = 0;
                        self.log.clear_search();
                        self.log.set_filter(None);
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => self.help = true,
                    KeyCode::Char('/') => {
                        // Search targets the event log; move focus there so
                        // the filtered panel and the input are visibly linked.
                        self.focused = 0;
                        self.search_mode = true;
                        self.search_buf.clear();
                        self.search_hits = 0;
                        self.log.clear_search();
                        self.log.set_filter(None);
                    }
                    KeyCode::Char('p') => self.paused = !self.paused,
                    KeyCode::Char('c') => self.clear_panels(),
                    KeyCode::Char('r') => {
                        self.rate_limit = if self.rate_limit == 15 {
                            5
                        } else if self.rate_limit == 5 {
                            50
                        } else {
                            15
                        };
                    }
                    KeyCode::Char('y') => self.copy_focused_panel(),
                    KeyCode::Char(' ') => {
                        // toggle collapse of focused panel
                        let idx = self.focused.min(Panel::COUNT - 1);
                        self.collapsed[idx] = !self.collapsed[idx];
                    }
                    KeyCode::Tab => self.focused = (self.focused + 1) % Panel::COUNT,
                    KeyCode::BackTab => {
                        self.focused = if self.focused == 0 {
                            Panel::COUNT - 1
                        } else {
                            self.focused - 1
                        }
                    }
                    KeyCode::Char(c @ '1'..='7') => self.focused = (c as usize) - ('1' as usize),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if scroll_alerts {
                            self.alerts.scroll_up(1);
                        } else if self.focused == 0 {
                            self.log.scroll_up(1);
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if scroll_alerts {
                            self.alerts.scroll_down(1);
                        } else if self.focused == 0 {
                            self.log.scroll_down(1);
                        }
                    }
                    KeyCode::PageUp => {
                        if scroll_alerts {
                            self.alerts.page_up(&self.alert_st);
                        } else if self.focused == 0 {
                            self.log.page_up(&self.log_st);
                        }
                    }
                    KeyCode::PageDown => {
                        if scroll_alerts {
                            self.alerts.page_down(&self.alert_st);
                        } else if self.focused == 0 {
                            self.log.page_down(&self.log_st);
                        }
                    }
                    KeyCode::Home => {
                        if scroll_alerts {
                            self.alerts.scroll_to_top();
                        } else if self.focused == 0 {
                            self.log.scroll_to_top();
                        }
                    }
                    KeyCode::End => {
                        if scroll_alerts {
                            self.alerts.scroll_to_bottom();
                        } else if self.focused == 0 {
                            self.log.scroll_to_bottom();
                        }
                    }
                    _ => {}
                }
            }
            Msg::Mouse(m) => {
                // The process table is interactive even when the event stream
                // owns focus (PROCESSES is the default detail panel).
                let proc = self.proc_area.get();
                let over_procs = proc.width > 0 && proc.contains(m.x, m.y);
                match m.kind {
                    MouseEventKind::ScrollUp if over_procs => {
                        self.focused = 1;
                        self.scroll_procs(-3);
                    }
                    MouseEventKind::ScrollDown if over_procs => {
                        self.focused = 1;
                        self.scroll_procs(3);
                    }
                    MouseEventKind::Down(MouseButton::Left) if over_procs => {
                        self.focused = 1;
                        self.click_proc_row(m.y);
                    }
                    MouseEventKind::ScrollUp => {
                        if self.focused == 5 {
                            self.alerts.scroll_up(3);
                        } else if self.focused == 0 {
                            self.log.scroll_up(3);
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if self.focused == 5 {
                            self.alerts.scroll_down(3);
                        } else if self.focused == 0 {
                            self.log.scroll_down(3);
                        }
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        // Hit-test the 70/30 split from draw_body
                        let (la, sa) = (self.left_area.get(), self.side_area.get());
                        if la.contains(m.x, m.y) {
                            self.focused = 0;
                        } else if sa.contains(m.x, m.y) && self.focused == 0 {
                            self.focused = 1;
                        }
                    }
                    _ => {}
                }
            }
            Msg::Tick if self.paused => {
                // While paused the poll thread keeps sending (the channel is
                // unbounded). Drain and discard so resuming does not replay a
                // multi-minute backlog in a single frame. Counters are
                // authoritative in the next live snapshot.
                while self.rx.try_recv().is_ok() {}
            }
            Msg::Tick => {
                // Advance the animation clock by one full tick period so the
                // ColorWave speed is independent of the divisor.
                self.time += (TICK_BASE * UNIFORM_TICK_DIVISOR).as_secs_f64();
                while let Ok(s) = self.rx.try_recv() {
                    self.apply_snapshot(s);
                }
            }
            _ => {}
        }
        Cmd::None
    }

    fn view(&self, frame: &mut Frame) {
        let area = Rect::from_size(frame.buffer.width(), frame.buffer.height());

        // Fill entire screen with dark background. `Buffer::fill` uses a bulk
        // `slice.fill` per row (memset-class), replacing the previous per-cell
        // `get_mut` double loop that wrote ~W*H cells on every frame. Under
        // `with_mouse()` the runtime can redraw on every mouse-motion event, so
        // this O(W*H) loop was a direct contributor to the 200-300% CPU spin.
        let mut bg_cell = ftui_render::cell::Cell::from_char(' ');
        bg_cell.bg = BG;
        frame.buffer.fill(area, bg_cell);

        if self.gateway {
            return self.draw_gateway(frame, area);
        }

        if self.help {
            return self.draw_help(frame, area);
        }

        // Rate-chart strip: 6 rows on normal terminals, 5 on short ones so
        // the detail panel keeps usable height. Collapsed = title row only.
        let lc_h: u16 = if self.collapsed[Panel::COUNT] {
            1
        } else if area.height < 28 {
            5
        } else {
            6
        };
        let outer = Flex::vertical()
            .constraints([
                Constraint::Fixed(2), // header
                Constraint::Min(0),   // body
                Constraint::Fixed(lc_h),
                Constraint::Fixed(1), // status
            ])
            .split(area);

        self.draw_header(frame, outer[0]);
        self.draw_body(frame, outer[1]);
        self.draw_linechart(frame, outer[2]);
        self.draw_status(frame, outer[3]);
        if self.search_mode {
            self.draw_search_bar(frame, area);
        }

        self.body_area.set(outer[1]);
    }

    fn subscriptions(&self) -> Vec<Box<dyn Subscription<Msg>>> {
        // Uniform divisor applied to the base tick: divisor 10 → 2 FPS.
        // Each tick repaints the entire frame, so this is the single biggest
        // CPU lever in the TUI (20 FPS was ~36-55% CPU).
        vec![Box::new(Every::new(
            TICK_BASE * UNIFORM_TICK_DIVISOR,
            || Msg::Tick,
        ))]
    }
}

// ── Drawing ───────────────────────────────────────────────────────────────

impl App_ {
    fn border(&self, idx: usize) -> PackedRgba {
        if self.focused == idx {
            BORDER_HI
        } else {
            BORDER
        }
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let row0 = Rect::new(area.x, area.y, area.width, 1);

        // Row 0: Animated color wave title + badges
        let title = format!(
            "talus  eBPF process monitor  {} events  {} lost  up {}",
            self.total,
            self.lost,
            fmt_dur(self.uptime)
        );
        let styled_title = StyledText::new(title)
            .bold()
            .effect(TextEffect::ColorWave {
                color1: BLUE,
                color2: CYAN,
                speed: 1.2,
                wavelength: 8.0,
            })
            .base_color(BLUE)
            .time(self.time);
        styled_title.render(row0, f);

        // Row 1: Status badges (license tier + eBPF + alerts + lost)
        let tier_color = if self.is_activated { GREEN } else { AMBER };
        let tier_badge = if self.is_activated {
            "ENTERPRISE"
        } else {
            "COMMUNITY"
        };

        let lost_label = format!("{} LOST", self.lost);
        let badges_data: [(&str, PackedRgba); 4] = [
            (tier_badge, tier_color),
            ("eBPF", GREEN),
            ("LIVE", if self.alert_count > 0 { RED } else { GREEN }),
            (&lost_label, if self.lost > 0 { AMBER } else { DIM }),
        ];
        let mut x = area.x;
        for &(label, color) in &badges_data {
            let style = Style::new()
                .fg(PackedRgba::rgb(10, 12, 20))
                .bg(color)
                .attrs(StyleFlags::BOLD);
            let badge = Badge::new(label).with_style(style).with_padding(1, 1);
            let w = badge.width().min(area.width.saturating_sub(x - area.x));
            if w == 0 {
                break;
            }
            badge.render(Rect::new(x, area.y + 1, w, 1), f);
            x += w + 1;
        }

        // Sparkline of event rate next to badges
        if self.rates.len() > 2 && x < area.right() {
            let spark_w = (area.right() - x).saturating_sub(2) as usize;
            let data: Vec<f64> = self
                .rates
                .iter()
                .rev()
                .take(spark_w)
                .rev()
                .map(|r| r.exec_count as f64)
                .collect();
            if !data.is_empty() {
                let spark_area = Rect::new(x, area.y + 1, spark_w as u16, 1);
                Sparkline::new(&data)
                    .style(Style::new().fg(BLUE))
                    .render(spark_area, f);
            }
        }
    }

    fn draw_body(&self, f: &mut Frame, area: Rect) {
        // Asymmetric split: event stream | telemetry + detail. The detail
        // panels (process tree, top files, network, heatmap) need real width
        // for their labels and bars, so they get 35% rather than 30%.
        let cols = Flex::horizontal()
            .constraints([Constraint::Percentage(65.0), Constraint::Percentage(35.0)])
            .split(area);
        let side = Flex::vertical()
            .constraints([Constraint::Fixed(TELEMETRY_H), Constraint::Min(0)])
            .split(cols[1]);

        self.draw_events(f, cols[0]);
        self.draw_telemetry(f, side[0]);
        // Clear the process hit-box before drawing; only `draw_procs` fills it,
        // so a hidden table cannot still receive clicks.
        self.proc_area.set(Rect::default());
        // The detail panel under the telemetry card follows focus (Tab / 1-7);
        // with the event stream focused it shows PROCESSES.
        match self.focused {
            2 => self.draw_net(f, side[1]),
            3 => self.draw_files(f, side[1]),
            4 => self.draw_exts_chart(f, side[1]),
            5 => self.draw_alerts(f, side[1]),
            6 => self.draw_heatmap(f, side[1]),
            _ => self.draw_procs(f, side[1]),
        }

        self.left_area.set(cols[0]);
        self.side_area.set(side[1]);
    }

    /// Right-hand telemetry card: throughput, CPU, counters, license tier.
    fn draw_telemetry(&self, f: &mut Frame, area: Rect) {
        let b = Block::new()
            .title(" TELEMETRY ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(BORDER));
        let inner = b.inner(area);
        b.render(area, f);

        let (eps, cpu, src, src_color) = if self.demo {
            (DEMO_EPS, DEMO_CPU, "DEMO", AMBER)
        } else {
            (self.eps, self.cpu_pct, "LIVE", GREEN)
        };
        let (tier, tier_color) = if self.is_activated {
            ("ENTERPRISE", GREEN)
        } else {
            ("COMMUNITY", AMBER)
        };
        let row = |label: &str, value: String, color: PackedRgba| {
            Line::from_spans(vec![
                Span::styled(format!(" {label:<9}"), Style::new().fg(DIM)),
                Span::styled(value, Style::new().fg(color).attrs(StyleFlags::BOLD)),
            ])
        };
        let lines = vec![
            row("source", src.to_string(), src_color),
            row("events/s", fmt_rate(eps), BRIGHT),
            row("cpu", format!("{cpu:.1}%"), BRIGHT),
            row("total", self.total.to_string(), FG),
            row(
                "lost",
                self.lost.to_string(),
                if self.lost > 0 { AMBER } else { FG },
            ),
            row(
                "alerts",
                self.alert_count.to_string(),
                if self.alert_count > 0 { RED } else { FG },
            ),
            row("uptime", fmt_dur(self.uptime), FG),
            row("status", tier.to_string(), tier_color),
        ];
        Paragraph::new(ftui_text::Text::from_lines(lines)).render(inner, f);
    }

    /// First-run gateway: a rounded frame with a clickable, arrow-navigable link.
    fn draw_gateway(&self, f: &mut Frame, area: Rect) {
        let w = area.width.min(60);
        let h = area.height.min(13);
        let x = area.x + (area.width - w) / 2;
        let y = area.y + (area.height - h) / 2;
        let frame_area = Rect::new(x, y, w, h);

        let b = Block::new()
            .title(" talus ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(BORDER_HI));
        let inner = b.inner(frame_area);
        b.render(frame_area, f);

        let row_rect = |r: u16| Rect::new(inner.x, inner.y + r, inner.width, 1);
        let sel = self.gateway_sel;

        if inner.height > 1 {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  talus  eBPF process monitor",
                Style::new().fg(BRIGHT).attrs(StyleFlags::BOLD),
            )]))
            .render(row_rect(1), f);
        }
        if inner.height > 2 {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  Hartwell Labs",
                Style::new().fg(DIM),
            )]))
            .render(row_rect(2), f);
        }
        if inner.height > 4 {
            let link_style = if sel == 0 {
                Style::new()
                    .fg(CYAN)
                    .attrs(StyleFlags::BOLD | StyleFlags::UNDERLINE)
            } else {
                Style::new().fg(BLUE).attrs(StyleFlags::UNDERLINE)
            };
            let marker = if sel == 0 { "> " } else { "  " };
            Paragraph::new(Line::from_spans(vec![
                Span::styled(format!("  {marker}"), Style::new().fg(CYAN)),
                Span::styled(GATEWAY_URL, link_style),
            ]))
            .render(row_rect(4), f);
            self.gateway_link_area.set(row_rect(4));
        }
        if inner.height > 5 {
            let (marker, style) = if sel == 1 {
                ("> ", Style::new().fg(CYAN).attrs(StyleFlags::BOLD))
            } else {
                ("  ", Style::new().fg(FG))
            };
            Paragraph::new(Line::from_spans(vec![
                Span::styled(format!("  {marker}"), Style::new().fg(CYAN)),
                Span::styled("Continue to monitor", style),
            ]))
            .render(row_rect(5), f);
            self.gateway_cont_area.set(row_rect(5));
        }
        if inner.height > 7 && !self.gateway_note.is_empty() {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                format!("  {}", self.gateway_note),
                Style::new().fg(AMBER),
            )]))
            .render(row_rect(7), f);
        }
        if inner.height > 8 {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  up/down select  enter open  click  esc skip  q quit",
                Style::new().fg(DIM),
            )]))
            .render(row_rect(inner.height - 1), f);
        }
    }

    fn block<'a>(&self, idx: usize, title: &'a str) -> Block<'a> {
        Block::new()
            .title(title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(self.border(idx)))
    }

    fn draw_events(&self, f: &mut Frame, area: Rect) {
        let title = if self.search_buf.is_empty() {
            " EVENTS ".to_string()
        } else {
            format!(
                " EVENTS — \"{}\" ({} hits) ",
                trunc(&self.search_buf, 18),
                self.search_hits
            )
        };
        let b = self.block(0, &title);
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[0] {
            if inner.height > 0 {
                Paragraph::new(Line::from_spans(vec![Span::styled(
                    "  [space] to expand",
                    Style::new().fg(DIM),
                )]))
                .render(Rect::new(inner.x, inner.y, inner.width, 1), f);
            }
            return;
        }
        let mut st = self.log_st.clone();
        self.log.render(inner, f, &mut st);
    }

    fn draw_alerts(&self, f: &mut Frame, area: Rect) {
        let title = format!(" ALERTS ({}) ", self.alert_count);
        let b = self.block(5, &title);
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[5] {
            return;
        }
        if self.alert_count == 0 {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  no alerts — system quiet",
                Style::new().fg(DIM),
            )]))
            .render(inner, f);
            return;
        }
        let mut st = self.alert_st.clone();
        self.alerts.render(inner, f, &mut st);
    }

    fn draw_procs(&self, f: &mut Frame, area: Rect) {
        // Rows available inside the border, known before the title so the
        // title can show the visible slice when the table is scrolled.
        let rows = area.height.saturating_sub(2) as usize;
        let max_scroll = self.tree.len().saturating_sub(rows);
        let scroll = self.proc_scroll.min(max_scroll);
        let title = if max_scroll > 0 {
            format!(
                " PROCESSES ({}) [{}-{}] ",
                self.tree.len(),
                scroll + 1,
                (scroll + rows).min(self.tree.len())
            )
        } else {
            format!(" PROCESSES ({}) ", self.tree.len())
        };
        let b = self.block(1, &title);
        let inner = b.inner(area);
        b.render(area, f);
        // Even an empty/collapsed table keeps its hit-box so wheel/click do
        // nothing instead of falling through to the event log.
        self.proc_area.set(inner);
        if self.collapsed[1] || self.tree.is_empty() {
            return;
        }

        let max = self.tree.iter().map(|row| row.3).max().unwrap_or(1).max(1);

        // A bar only earns its space on a wide detail column; below that the
        // open count itself is more useful than a one-cell stub.
        let bar_w = if inner.width >= 36 {
            (inner.width as usize / 3).clamp(8, 20)
        } else {
            0
        };
        // Keep one blank column between the bar and the panel border.
        let text_w = inner.width as usize - bar_w;
        let colors = MiniBarColors::new(BLUE, GREEN, AMBER, RED);
        let rows = inner.height as usize;
        let scroll = self.proc_scroll.min(self.tree.len().saturating_sub(rows));

        for (offset, &(depth, pid, ref comm, opens, alerts)) in
            self.tree.iter().skip(scroll).take(rows).enumerate()
        {
            let i = scroll + offset; // absolute index for `tree_prefix`
            let y = inner.y + offset as u16;
            let value = (opens as f64 / max as f64).clamp(0.0, 1.0);
            let prefix = tree_prefix(&self.tree, i, depth);
            let prefix_w = prefix.chars().count();
            // Columns: tree prefix, pid, name, opens. `comm_w` soaks up the
            // remaining width so the opens count is always visible instead of
            // being clipped off at the right edge on an 80-column terminal.
            let comm_w = text_w.saturating_sub(prefix_w + 13).clamp(4, 20);
            let label = format!(
                "{prefix}{pid:>5} {:<width$}{opens:>6}",
                trunc(comm, comm_w),
                width = comm_w
            );
            let label_c = if alerts > 0 {
                RED
            } else if opens > 10 {
                AMBER
            } else {
                BRIGHT
            };
            let mut style = Style::new().fg(label_c);
            if self.proc_sel == Some(pid) {
                style = style.bg(SELECT_BG).attrs(StyleFlags::BOLD);
            }
            Paragraph::new(Line::from_spans(vec![Span::styled(label, style)]))
                .render(Rect::new(inner.x, y, text_w as u16, 1), f);

            if bar_w > 1 {
                let fill_w = (bar_w - 1) as u16;
                let bar_area = Rect::new(inner.x + text_w as u16, y, fill_w, 1);
                MiniBar::new(value, fill_w)
                    .colors(colors)
                    .show_percent(fill_w >= 16)
                    .render(bar_area, f);
            }
        }
    }

    fn draw_exts_chart(&self, f: &mut Frame, area: Rect) {
        let b = self.block(4, " FILE TYPES ");
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[4] {
            return;
        }
        if self.exts.is_empty() {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  no file activity yet",
                Style::new().fg(DIM),
            )]))
            .render(inner, f);
            return;
        }

        let max = self.exts.iter().map(|(_, c)| *c).max().unwrap_or(1).max(1);
        let colors = MiniBarColors::new(BLUE, GREEN, AMBER, RED);
        let rows = inner.height as usize;
        let label_w = 10u16.min(inner.width);
        let count_w = 6u16.min(inner.width.saturating_sub(label_w));
        let bar_w = inner.width.saturating_sub(label_w + count_w + 2);

        // One compact row per extension (label, count, bar). The generic
        // BarChart left a blank row between bars and printed no counts.
        for (i, (ext, count)) in self.exts.iter().take(rows).enumerate() {
            let y = inner.y + i as u16;
            let label = format!(
                "{:<width$}",
                trunc(&format!(".{ext}"), label_w as usize),
                width = label_w as usize
            );
            let value = (*count as f64 / max as f64).clamp(0.0, 1.0);
            Paragraph::new(Line::from_spans(vec![
                Span::styled(label, Style::new().fg(ext_color(ext))),
                Span::styled(
                    format!("{count:>width$}", width = count_w as usize),
                    Style::new().fg(BRIGHT),
                ),
            ]))
            .render(Rect::new(inner.x, y, label_w + count_w, 1), f);

            if bar_w > 1 {
                let bar_area = Rect::new(inner.x + label_w + count_w + 1, y, bar_w, 1);
                MiniBar::new(value, bar_w)
                    .colors(colors)
                    .show_percent(false)
                    .render(bar_area, f);
            }
        }
    }

    fn draw_net(&self, f: &mut Frame, area: Rect) {
        let title = format!(" NETWORK ({}) ", self.net.len());
        let b = self.block(2, &title);
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[2] {
            return;
        }
        if self.net.is_empty() {
            Paragraph::new(ftui_text::Text::from_lines(vec![
                Line::from_spans(vec![Span::styled(
                    "  no network events captured",
                    Style::new().fg(DIM),
                )]),
                Line::from_spans(vec![Span::styled(
                    "  (kernel may lack sockaddr capture)",
                    Style::new().fg(DIM),
                )]),
            ]))
            .render(inner, f);
            return;
        }

        // Recent-connections list replaces the sparse canvas. `net` is a
        // newest-first deque, so take from the front and draw oldest-first:
        // the previous `rev().take()` showed the *oldest* N connections and
        // hid every new one.
        let rows = inner.height as usize;
        let recent: Vec<&NetEntry> = self.net.iter().take(rows).collect();
        let width = inner.width as usize;

        // Column widths shrink with the panel so the address (the reason the
        // panel exists) is never clipped to its first character.
        let (ts_w, kind_w, comm_w) = if width >= 50 {
            (8, 5, 14)
        } else if width >= 34 {
            (8, 5, 8)
        } else {
            (0, 5, 7)
        };
        let used = if ts_w == 0 {
            kind_w + comm_w + 2
        } else {
            ts_w + kind_w + comm_w + 3
        };
        let addr_w = width.saturating_sub(used).max(4);

        for (i, e) in recent.iter().rev().enumerate() {
            let y = inner.y + i as u16;
            let mut spans = Vec::with_capacity(4);
            if ts_w > 0 {
                spans.push(Span::styled(
                    format!("{:<ts_w$} ", trunc(&e.ts, ts_w)),
                    Style::new().fg(DIM),
                ));
            }
            let (kind, kind_c) = match e.kind.as_str() {
                "Connect" => ("CONN", CYAN),
                "Accept" => ("ACPT", PURPLE),
                "SendTo" => ("SEND", BLUE),
                "RecvFrom" => ("RECV", BLUE),
                other => (other, FG),
            };
            spans.push(Span::styled(
                format!("{:<kind_w$} ", trunc(kind, kind_w)),
                Style::new().fg(kind_c),
            ));
            spans.push(Span::styled(
                format!("{:<comm_w$} ", trunc(&e.comm, comm_w)),
                Style::new().fg(BRIGHT),
            ));
            spans.push(Span::styled(trunc(&e.addr, addr_w), Style::new().fg(FG)));
            Paragraph::new(Line::from_spans(spans))
                .render(Rect::new(inner.x, y, inner.width, 1), f);
        }
    }

    fn draw_files(&self, f: &mut Frame, area: Rect) {
        let b = self.block(3, " TOP FILES ");
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[3] || self.files.is_empty() {
            return;
        }

        let max = self.files.iter().map(|r| r.count).max().unwrap_or(1).max(1);
        let rows = inner.height as usize;

        // Bar width: only show when there's room beyond the label + rank column.
        // The label + rank takes ~20 cols; bar appears only when width > 36.
        let bar_w = if inner.width > 36 {
            inner.width.saturating_sub(36) as usize
        } else {
            0
        };
        let colors = MiniBarColors::new(BLUE, GREEN, AMBER, RED);

        for (i, r) in self.files.iter().take(rows).enumerate() {
            let y = inner.y + i as u16;
            let value = (r.count as f64 / max as f64).clamp(0.0, 1.0);

            let rank_c = if i < 3 { AMBER } else { DIM };
            // Show rank + filename; when width is tight drop the bar and shrink the label.
            if bar_w == 0 {
                let label = format!(
                    "{:>2}. {}",
                    i + 1,
                    trunc(&r.name, (inner.width.saturating_sub(3).max(1)).into())
                );
                Paragraph::new(Line::from_spans(vec![Span::styled(
                    label,
                    Style::new().fg(rank_c),
                )]))
                .render(Rect::new(inner.x, y, inner.width.max(1), 1), f);
            } else {
                let _label = format!(
                    "{:>2}. {:<}",
                    i + 1,
                    trunc(&r.name, (inner.width.saturating_sub(5).max(1)).into())
                );
                let ext_c = ext_color(&r.ext);
                let entropy_c = if r.entropy > 0.7 {
                    RED
                } else if r.entropy > 0.4 {
                    AMBER
                } else {
                    GREEN
                };

                let label_w = (inner.width - bar_w as u16 - 1).max(1);
                // Reserve the trailing ` H:x.x` column so long names cannot
                // push the entropy value out of the row.
                let name_w = label_w.saturating_sub(10) as usize;
                Paragraph::new(Line::from_spans(vec![
                    Span::styled(format!("{:>2}.", i + 1), Style::new().fg(rank_c)),
                    Span::styled(
                        format!(" {}", trunc(&r.name, name_w)),
                        Style::new().fg(ext_c),
                    ),
                    Span::styled(format!(" H:{:.1}", r.entropy), Style::new().fg(entropy_c)),
                ]))
                .render(Rect::new(inner.x, y, label_w, 1), f);

                // MiniBar only when width permits
                let bar_x = inner.x + label_w;
                let bar_area = Rect::new(bar_x, y, bar_w as u16, 1);
                MiniBar::new(value, bar_w as u16)
                    .colors(colors)
                    .show_percent(false)
                    .render(bar_area, f);
            }
        }
    }

    fn draw_heatmap(&self, f: &mut Frame, area: Rect) {
        let b = self.block(6, " HEATMAP ");
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[6] || self.heatmap.is_empty() {
            return;
        }

        let rows = inner.height as usize;
        let ext_count = self.heatmap_exts.len();
        if ext_count == 0 {
            return;
        }

        // The label column is carved out first; the remaining width is split
        // between the extension cells. Previously `cell_w` was derived from
        // the full width and then shifted by 14 columns, so the last cells
        // rendered past the panel border (and into the event log).
        let label_w: u16 = 12.min(inner.width);
        let grid_w = inner.width.saturating_sub(label_w);
        let shown = ext_count.min((grid_w / 4).max(1) as usize);
        let cell_w = (grid_w as usize / shown.max(1)).max(4);

        // Header row: extension labels
        for (j, ext) in self.heatmap_exts.iter().enumerate() {
            if j >= shown {
                break;
            }
            let x = inner.x + label_w + (j * cell_w) as u16;
            if x >= inner.right() {
                break;
            }
            // One label per heatmap cell, clipped to that cell so adjacent
            // columns never run together (`.pdf.rs.png.jso.txt`). Narrow
            // cells drop the dot so three-letter extensions keep a gap.
            let label = if cell_w >= 5 {
                clip(&format!(".{ext}"), cell_w)
            } else {
                // Leave one separator column in a 4-wide cell.
                format!("{:<width$}", clip(ext, cell_w - 1), width = cell_w)
            };
            Paragraph::new(Line::from_spans(vec![Span::styled(
                label,
                Style::new().fg(ext_color(ext)),
            )]))
            .render(Rect::new(x, inner.y, cell_w as u16, 1), f);
        }

        // Data rows
        let max_val = self
            .heatmap
            .iter()
            .flat_map(|r| r.ext_counts.iter().map(|(_, c)| *c))
            .max()
            .unwrap_or(1)
            .max(1);

        for (i, row) in self.heatmap.iter().take(rows.saturating_sub(1)).enumerate() {
            let y = inner.y + 1 + i as u16;

            // Process label
            let label = format!("{:<12}", trunc(&row.label, 12));
            Paragraph::new(Line::from_spans(vec![Span::styled(
                label,
                Style::new().fg(BRIGHT),
            )]))
            .render(Rect::new(inner.x, y, label_w, 1), f);

            // Heatmap cells - only render `shown` columns
            for (j, (_ext, count)) in row.ext_counts.iter().enumerate() {
                if j >= shown {
                    break;
                }
                let x = inner.x + label_w + (j * cell_w) as u16;
                if x >= inner.right() {
                    break;
                }
                let frac = *count as f64 / max_val as f64;
                let color = heatmap_gradient(frac);
                let bar_len = ((cell_w - 1) as f64 * frac).round() as usize;
                let bar = "█".repeat(bar_len);
                if !bar.is_empty() {
                    Paragraph::new(Line::from_spans(vec![Span::styled(
                        bar,
                        Style::new().fg(color),
                    )]))
                    .render(Rect::new(x, y, (cell_w - 1) as u16, 1), f);
                }
            }
        }
    }

    fn draw_linechart(&self, f: &mut Frame, area: Rect) {
        if self.collapsed[Panel::COUNT] || area.height < 2 {
            return;
        }

        // Wrap the three charts in a titled block so the strip reads as intentional
        // even when empty. The block uses the rate-chart slot (index Panel::COUNT).
        let title = format!(" RATES (last {}s) ", self.rate_chart.len());
        let b = self.block(Panel::COUNT, &title);
        let inner = b.inner(area);
        b.render(area, f);

        // The monitor publishes its first rate sample after one second. Show
        // a deliberate placeholder instead of an empty box until then.
        if self.rate_chart.len() <= 2 {
            Paragraph::new(Line::from_spans(vec![Span::styled(
                "  collecting rate samples...",
                Style::new().fg(DIM),
            )]))
            .render(inner, f);
            return;
        }

        let charts_layout = Flex::horizontal()
            .constraints([
                Constraint::Percentage(34.0),
                Constraint::Percentage(33.0),
                Constraint::Percentage(33.0),
            ])
            .split(inner);

        // Exec/s chart
        if self.rate_chart.len() > 2 {
            let series = vec![Series::new("exec/s", &self.rate_chart, GREEN)];
            let max_y = self
                .rate_chart
                .iter()
                .map(|&(_, y)| y)
                .fold(0.0f64, f64::max)
                .max(1.0);
            LineChart::new(series)
                .style(Style::new().fg(GREEN))
                .y_bounds(0.0, max_y)
                .render(charts_layout[0], f);
            chart_label(f, charts_layout[0], "exec/s", GREEN);
        }

        // Open/s chart
        if self.open_chart.len() > 2 {
            let series = vec![Series::new("open/s", &self.open_chart, BLUE)];
            let max_y = self
                .open_chart
                .iter()
                .map(|&(_, y)| y)
                .fold(0.0f64, f64::max)
                .max(1.0);
            LineChart::new(series)
                .style(Style::new().fg(BLUE))
                .y_bounds(0.0, max_y)
                .render(charts_layout[1], f);
            chart_label(f, charts_layout[1], "open/s", BLUE);
        }

        // Alert/s chart
        if self.alert_chart.len() > 2 {
            let series = vec![Series::new("alert/s", &self.alert_chart, RED)];
            let max_y = self
                .alert_chart
                .iter()
                .map(|&(_, y)| y)
                .fold(0.0f64, f64::max)
                .max(1.0);
            LineChart::new(series)
                .style(Style::new().fg(RED))
                .y_bounds(0.0, max_y)
                .render(charts_layout[2], f);
            chart_label(f, charts_layout[2], "alert/s", RED);
        }
    }

    fn draw_search_bar(&self, f: &mut Frame, area: Rect) {
        // Draw over the status line (last row) so the input is always visible
        // and never lands in the middle of the rate charts.
        let bar_area = Rect::new(
            area.x,
            area.y + area.height.saturating_sub(1),
            area.width,
            1,
        );
        let hits_text = if self.search_hits > 0 {
            format!(" {} matches", self.search_hits)
        } else {
            String::new()
        };
        let line = format!(" /{}{}", self.search_buf, hits_text);
        Paragraph::new(Line::from_spans(vec![Span::styled(
            line,
            Style::new().fg(CYAN).attrs(StyleFlags::BOLD),
        )]))
        .render(bar_area, f);
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let p = Panel::ALL[self.focused];
        let tier_display = if self.is_activated { "ENT" } else { "COMM" };
        let left = format!(" {} | {} ", p.name(), tier_display);
        let selected = if self.focused == 1 {
            self.proc_sel
                .and_then(|pid| self.tree.iter().find(|row| row.1 == pid))
        } else {
            None
        };
        let center = if let Some((_, pid, comm, opens, alerts)) = selected {
            format!("sel:{comm} pid:{pid}  opens:{opens}  alerts:{alerts}")
        } else {
            format!(
                "evt:{}  lost:{}  up:{}   /:search  p:pause  space:collapse",
                self.total,
                self.lost,
                fmt_dur(self.uptime)
            )
        };
        let status = StatusLine::new()
            .left(StatusItem::text(&left))
            .center(StatusItem::text(&center))
            .right(StatusItem::key_hint("?", "help"));
        status.render(area, f);
    }

    /// Copy last 20 lines of the focused panel to clipboard.
    fn copy_focused_panel(&self) {
        let mut lines: Vec<String> = Vec::new();
        match self.focused {
            0 => {
                // EVENTS
                let start = self.last_event_lines.len().saturating_sub(20);
                lines = self.last_event_lines.range(start..).cloned().collect();
            }
            1 => {
                // PROCESSES
                for (i, row) in self.procs.iter().take(20).enumerate() {
                    lines.push(format!(
                        "{:>2}. {:>5} {:<16} opens:{} alerts:{}",
                        i + 1,
                        row.pid,
                        row.comm,
                        row.opens,
                        row.alerts
                    ));
                }
            }
            2 => {
                // NETWORK
                for (i, e) in self.net.iter().take(20).enumerate() {
                    lines.push(format!(
                        "{:>2}. {} {:>6} {:<14} {}",
                        i + 1,
                        e.ts,
                        e.pid,
                        e.comm,
                        e.addr
                    ));
                }
            }
            3 => {
                // TOP FILES
                for (i, r) in self.files.iter().take(20).enumerate() {
                    lines.push(format!(
                        "{:>2}. {:<24} .{:<6} H:{:.1}",
                        i + 1,
                        r.name,
                        r.ext,
                        r.entropy
                    ));
                }
            }
            4 => {
                // FILE TYPES
                for (ext, cnt) in self.exts.iter().take(20) {
                    lines.push(format!(".{:<10} {}", ext, cnt));
                }
            }
            5 => {
                // ALERTS
                let start = self.last_alert_lines.len().saturating_sub(20);
                lines = self.last_alert_lines.range(start..).cloned().collect();
            }
            6 => {
                // HEATMAP
                for row in self.heatmap.iter().take(20) {
                    let parts: Vec<String> = row
                        .ext_counts
                        .iter()
                        .map(|(e, c)| format!(".{}:{}", e, c))
                        .collect();
                    lines.push(format!("{:<14} {}", row.label, parts.join(" ")));
                }
            }
            _ => {}
        }
        if lines.is_empty() {
            return;
        }
        let text = lines.join("\n");
        // Try clipboard backends: xclip > xsel > wl-copy > pbcopy
        let copied = [
            ("xclip", vec!["-selection", "clipboard"]),
            ("xsel", vec!["--clipboard", "--input"]),
            ("wl-copy", vec![]),
            ("pbcopy", vec![]),
        ]
        .iter()
        .any(|(cmd, extra_args)| {
            StdCommand::new(cmd)
                .args(extra_args)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    child.stdin.take().unwrap().write_all(text.as_bytes())?;
                    child.wait()
                })
                .map(|s| s.success())
                .unwrap_or(false)
        });
        if !copied {
            // Fallback: write to /tmp/talus-copy.txt
            let _ = std::fs::write("/tmp/talus-copy.txt", &text);
        }
    }

    /// Clear every panel's contents without touching the monitor counters.
    fn clear_panels(&mut self) {
        self.log.clear();
        self.alerts.clear();
        self.net.clear();
        self.procs.clear();
        self.tree.clear();
        self.files.clear();
        self.exts.clear();
        self.heatmap.clear();
        self.heatmap_exts.clear();
        self.rate_chart.clear();
        self.open_chart.clear();
        self.alert_chart.clear();
        self.last_event_lines.clear();
        self.last_alert_lines.clear();
        self.alert_count = 0;
        self.search_mode = false;
        self.search_buf.clear();
        self.search_hits = 0;
        self.proc_scroll = 0;
        self.proc_sel = None;
        self.log.clear_search();
        self.log.set_filter(None);
    }

    fn draw_help(&self, f: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from_spans(vec![Span::styled(
                " talus — keyboard shortcuts",
                Style::new().fg(BLUE).attrs(StyleFlags::BOLD),
            )]),
            Line::raw(""),
            Line::from_spans(vec![Span::styled(
                " NAV",
                Style::new().fg(AMBER).attrs(StyleFlags::BOLD),
            )]),
            Line::raw("   Tab/Shift+Tab   cycle panels"),
            Line::raw("   1-7             jump to panel"),
            Line::raw("   j/k or arrows   scroll events / alerts"),
            Line::raw("   PgUp/PgDn/Home/End  scroll to page / edge"),
            Line::raw("   mouse           click process row to select, wheel scrolls"),
            Line::raw(""),
            Line::from_spans(vec![Span::styled(
                " ACT",
                Style::new().fg(AMBER).attrs(StyleFlags::BOLD),
            )]),
            Line::raw("   p               pause/resume"),
            Line::raw("   r               cycle rate limit (5/15/50)"),
            Line::raw("   /               search/filter events (Enter keep, Esc clear)"),
            Line::raw("   c               clear all panels"),
            Line::raw("   space           collapse/expand panel"),
            Line::raw("   y               copy last 20 lines"),
            Line::raw("   Esc             clear filter, then quit"),
            Line::raw("   q               quit"),
            Line::raw("   Ctrl+C          force quit"),
        ];
        let b = Block::new()
            .title(" help ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(BLUE));
        let inner = b.inner(area);
        b.render(area, f);
        Paragraph::new(ftui_text::Text::from_lines(lines)).render(inner, f);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn trunc(s: &str, max: usize) -> String {
    // Count/slice by chars, not bytes: slicing a UTF-8 string at a byte offset
    // panics on multi-byte process names and file paths.
    if s.chars().count() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('~');
        out
    }
}

/// Hard character clip with no ellipsis — for column headers where a `~`
/// would be noise (e.g. `.jso` rather than `.js~`).
fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Overlay a filled label on the top-right corner of a rate chart.
///
/// `LineChart`'s built-in legend leaves the cell between the marker and the
/// name untouched, so a plotted glyph can sit flush against the label. A
/// background-filled label masks the plot and keeps the strip legible.
fn chart_label(f: &mut Frame, area: Rect, name: &str, color: PackedRgba) {
    let text = format!("■ {name}");
    let w = text.chars().count() as u16;
    if area.width <= w + 1 {
        return;
    }
    let rect = Rect::new(area.right() - w, area.y, w, 1);
    Paragraph::new(Line::from_spans(vec![Span::styled(
        text,
        Style::new().fg(color).bg(BG),
    )]))
    .render(rect, f);
}

/// Tree-drawing prefix for row `i` of the visible process forest.
///
/// `└──` is used only when no later sibling exists at the same depth before
/// the walk returns to a shallower level; `├──` otherwise. Ancestor rails
/// (`│`) stay open while that ancestor still has siblings below.
fn tree_prefix(rows: &[(usize, u32, String, u64, u64)], i: usize, depth: usize) -> String {
    if depth == 0 {
        return String::new();
    }
    let mut out = String::new();
    for level in 1..depth {
        let rail = rows[i + 1..]
            .iter()
            .take_while(|row| row.0 >= level)
            .any(|row| row.0 == level);
        out.push_str(if rail { "│   " } else { "    " });
    }
    let last = !rows[i + 1..]
        .iter()
        .take_while(|row| row.0 >= depth)
        .any(|row| row.0 == depth);
    out.push_str(if last { "└── " } else { "├── " });
    out
}

fn fmt_rate(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.2}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.1}k", v / 1_000.0)
    } else {
        format!("{v:.0}")
    }
}

/// utime + stime of this process, in clock ticks (from /proc/self/stat).
fn proc_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the ")" that closes comm; index 0 is field 3 (state).
    let rest = stat.rsplit_once(')')?.1;
    let mut it = rest.split_whitespace();
    let utime: u64 = it.nth(11)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    Some(utime + stime)
}

fn gateway_marker_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("talus").join("tui-gateway-seen"))
}

/// The gateway shows on first run only. `TALUS_TUI_GATEWAY=1` forces it,
/// `TALUS_TUI_GATEWAY=0` suppresses it.
fn gateway_should_show() -> bool {
    match std::env::var("TALUS_TUI_GATEWAY").as_deref() {
        Ok("1") => return true,
        Ok("0") => return false,
        _ => {}
    }
    gateway_marker_path().is_some_and(|p| !p.exists())
}

fn fmt_dur(s: u64) -> String {
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

fn ext_color(ext: &str) -> PackedRgba {
    match ext {
        "enc" | "locked" | "crypto" => RED,
        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "go" | "java" => GREEN,
        "pdf" | "doc" | "docx" | "txt" | "md" => AMBER,
        "jpg" | "png" | "mp4" | "mp3" => PURPLE,
        "json" | "toml" | "yaml" | "yml" => CYAN,
        _ => BLUE,
    }
}

// ── Public API ────────────────────────────────────────────────────────────

pub fn run(mut monitor: Monitor, license: LicenseState) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel::<Snapshot>();
    let mut last_heavy: Option<Instant> = None;
    let h = thread::Builder::new()
        .name("poll".into())
        .spawn(move || loop {
            let mut evts: Vec<Evt> = monitor
                .poll()
                .into_iter()
                .filter_map(|o| match o {
                    Output::Event(ev) => Some(Evt {
                        ts: crate::monitor::format_ktime(ev.ts_ns),
                        kind: format!("{:?}", ev.kind),
                        pid: ev.pid,
                        comm: ev.comm,
                        file: ev.file,
                        is_alert: false,
                        opens: 0,
                        memlp: None,
                    }),
                    Output::Alert(a) => Some(Evt {
                        ts: a.ts,
                        kind: "Alert".into(),
                        pid: a.pid,
                        comm: a.comm,
                        file: None,
                        is_alert: true,
                        opens: a.opens,
                        memlp: a.memlp,
                    }),
                    Output::Action(_) => None,
                })
                .collect();
            // Cap the number of events in each snapshot to prevent render
            // stalls when the monitor has accumulated a backlog (e.g.
            // 10K+ events per 33ms cycle during find/pacman scans).
            // Only the most recent TUI_SNAPSHOT_EVENT_CAP events are kept.
            if evts.len() > TUI_SNAPSHOT_EVENT_CAP {
                let skip = evts.len() - TUI_SNAPSHOT_EVENT_CAP;
                evts.drain(..skip);
            }
            let refresh = last_heavy.is_none_or(|t| t.elapsed() >= HEAVY_REFRESH);
            if refresh || !evts.is_empty() {
                let snap = if refresh {
                    last_heavy = Some(Instant::now());
                    let tree_raw = {
                        let tree = monitor.build_process_tree();
                        Monitor::flatten_tree(&tree)
                            .into_iter()
                            .map(|(depth, node)| {
                                (
                                    depth,
                                    node.pid,
                                    node.comm.clone(),
                                    node.total_opens,
                                    node.alerts,
                                )
                            })
                            .collect::<Vec<_>>()
                    };
                    Snapshot {
                        events: evts,
                        stats: monitor.stats_top(TUI_PROC_LIMIT),
                        tree: tree_raw,
                        top_files: monitor.top_files(20),
                        exts: monitor.extension_counts().clone(),
                        rates: monitor.rate_history().clone(),
                        total: monitor.total_events,
                        lost: monitor.total_lost,
                        uptime: monitor.uptime().as_secs(),
                        refresh: true,
                    }
                } else {
                    // Light snapshot: events and counters only. The expensive
                    // aggregates are rebuilt at most every HEAVY_REFRESH.
                    Snapshot {
                        events: evts,
                        stats: Vec::new(),
                        tree: Vec::new(),
                        top_files: Vec::new(),
                        exts: std::collections::HashMap::new(),
                        rates: VecDeque::new(),
                        total: monitor.total_events,
                        lost: monitor.total_lost,
                        uptime: monitor.uptime().as_secs(),
                        refresh: false,
                    }
                };
                if tx.send(snap).is_err() {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200)); // 5 FPS — TUI only needs situational awareness
        })?;
    let app = App_::new(rx, &license);
    // The default frame budget (16 ms, frame skipping allowed) makes the
    // runtime skip `present` whenever the dashboard takes longer than that to
    // render (easy in debug builds or with a large log). `dirty` then stays
    // set and the terminal keeps showing the first frame ("0 events"). A
    // monitoring dashboard must always present, so use a generous budget and
    // never skip frames.
    // The default strict(250ms) budget has `allow_frame_skip = false`: under
    // load the render exceeds 250ms, `dirty` never clears, and the main thread
    // busy-presents every iteration → 200-300% CPU runaway. `relaxed()` keeps a
    // 33ms budget and *allows frame skipping*, so a storm of dirty frames
    // (mouse motion / snapshot churn) degrades gracefully instead of pinning a
    // core. The 2.5s tick still drives steady updates, so situational awareness
    // is unchanged.
    let res = App::new(app)
        .screen_mode(ScreenMode::AltScreen)
        .with_mouse()
        .with_budget(FrameBudgetConfig::relaxed())
        .run();
    let _ = h.join();
    res.map_err(|e| anyhow::anyhow!("tui: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ftui_render::grapheme_pool::GraphemePool;

    fn app() -> App_ {
        let (_tx, rx) = mpsc::channel();
        let mut app = App_::new(rx, &LicenseState::community());
        app.gateway = false;
        app
    }

    fn render(app: &App_, w: u16, h: u16) -> String {
        let mut pool = GraphemePool::new();
        let mut frame = Frame::new(w, h, &mut pool);
        app.view(&mut frame);
        let mut out = String::with_capacity((w as usize + 1) * h as usize);
        for y in 0..h {
            for x in 0..w {
                let c = frame
                    .buffer
                    .get(x, y)
                    .and_then(|c| c.content.as_char())
                    .unwrap_or(' ');
                out.push(c);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn every_panel_is_reachable_and_titled() {
        let panels = [
            (2, "NETWORK"),
            (3, "TOP FILES"),
            (4, "FILE TYPES"),
            (5, "ALERTS"),
            (6, "HEATMAP"),
        ];
        for (idx, title) in panels {
            let mut app = app();
            app.focused = idx;
            let screen = render(&app, 120, 40);
            assert!(
                screen.contains(title),
                "panel {idx} should render {title}\n{screen}"
            );
        }
    }

    #[test]
    fn alerts_panel_shows_quiet_placeholder() {
        let mut app = app();
        app.focused = 5;
        let screen = render(&app, 120, 40);
        assert!(screen.contains("ALERTS (0)"), "{screen}");
        assert!(screen.contains("no alerts"), "{screen}");
    }

    #[test]
    fn process_table_click_selects_and_wheel_scrolls() {
        let mut app = app();
        app.focused = 1;
        app.tree = (0..60)
            .map(|i| (0, 1000 + i, format!("p{i}"), 0u64, 0u64))
            .collect();
        let _ = render(&app, 120, 40);
        let area = app.proc_area.get();
        assert!(area.height > 3, "process table should be visible");

        // Click the second visible row → that PID is selected.
        app.update(Msg::Mouse(MouseEvent::new(
            MouseEventKind::Down(MouseButton::Left),
            area.x + 1,
            area.y + 1,
        )));
        assert_eq!(app.focused, 1);
        assert_eq!(app.proc_sel, Some(1001));

        // Clicking the same row again clears the selection.
        app.update(Msg::Mouse(MouseEvent::new(
            MouseEventKind::Down(MouseButton::Left),
            area.x + 1,
            area.y + 1,
        )));
        assert_eq!(app.proc_sel, None);

        // Wheel down three rows, then back up past the top (clamped to 0).
        app.update(Msg::Mouse(MouseEvent::new(
            MouseEventKind::ScrollDown,
            area.x + 1,
            area.y + 1,
        )));
        assert_eq!(app.proc_scroll, 3);
        app.update(Msg::Mouse(MouseEvent::new(
            MouseEventKind::ScrollUp,
            area.x + 1,
            area.y + 1,
        )));
        assert_eq!(app.proc_scroll, 0);
    }

    #[test]
    fn digit_keys_cover_all_seven_panels() {
        for (key, expected) in [
            ('1', 0),
            ('2', 1),
            ('3', 2),
            ('4', 3),
            ('5', 4),
            ('6', 5),
            ('7', 6),
        ] {
            let mut app = app();
            app.update(Msg::Key(KeyEvent::new(KeyCode::Char(key))));
            assert_eq!(app.focused, expected, "key {key}");
        }
    }

    #[test]
    fn tab_cycles_through_seven_panels() {
        let mut app = app();
        for _ in 0..Panel::COUNT {
            app.update(Msg::Key(KeyEvent::new(KeyCode::Tab)));
        }
        assert_eq!(app.focused, 0);
        app.update(Msg::Key(KeyEvent::new(KeyCode::BackTab)));
        assert_eq!(app.focused, Panel::COUNT - 1);
    }

    #[test]
    fn search_mode_receives_typed_characters() {
        let mut app = app();
        app.update(Msg::Key(KeyEvent::new(KeyCode::Char('/'))));
        assert!(app.search_mode);
        for c in "hello".chars() {
            app.update(Msg::Key(KeyEvent::new(KeyCode::Char(c))));
        }
        assert_eq!(app.search_buf, "hello");
        // Esc leaves search mode and clears the filter.
        app.update(Msg::Key(KeyEvent::new(KeyCode::Escape)));
        assert!(!app.search_mode);
        assert!(app.search_buf.is_empty());
    }

    #[test]
    fn quit_works_from_any_panel() {
        for focused in 0..Panel::COUNT {
            let mut app = app();
            app.focused = focused;
            let cmd = app.update(Msg::Key(KeyEvent::new(KeyCode::Char('q'))));
            assert!(matches!(cmd, Cmd::Quit), "q must quit from panel {focused}");
        }
    }

    #[test]
    fn heatmap_stays_inside_its_panel() {
        let mut app = app();
        app.focused = 6;
        app.heatmap_exts = (0..12).map(|i| format!("e{i}")).collect();
        app.heatmap = (0..4)
            .map(|i| HeatmapRow {
                label: format!("proc{i}"),
                ext_counts: (0..12).map(|j| (format!("e{j}"), (i * j) as u64)).collect(),
            })
            .collect();
        let screen = render(&app, 120, 40);
        // The right-hand detail column starts at 70% of 120 columns (x=84).
        // No heatmap cell may spill left into the event panel.
        for (y, row) in screen.lines().enumerate() {
            if row.contains("HEATMAP") {
                continue;
            }
            let left: String = row.chars().take(84).collect();
            assert!(
                !left.contains('█'),
                "heatmap bar leaked into the left column on row {y}: {row}"
            );
        }
    }

    #[test]
    fn dump_layout_for_inspection() {
        if std::env::var("TALUS_DUMP_TUI").is_err() {
            return;
        }
        let mut app = app();
        populate(&mut app);
        for (f, w, h) in [
            (0u16, 120u16, 40u16),
            (2, 120, 40),
            (3, 120, 40),
            (4, 120, 40),
            (5, 120, 40),
            (6, 120, 40),
            (1, 80, 24),
        ] {
            app.focused = f as usize;
            println!("=== focus {f} {w}x{h} ===\n{}", render(&app, w, h));
        }
    }

    fn populate(app: &mut App_) {
        use crate::monitor::{FileRank, ProcStats, RateSample};
        let mut events = Vec::new();
        let comms = [
            "firefox", "code", "cargo", "find", "python3", "rg", "node", "ssh",
        ];
        for i in 0..24u32 {
            let comm = comms[(i as usize) % comms.len()].to_string();
            events.push(Evt {
                ts: format!("20:31:{:02}", i % 60),
                kind: if i % 7 == 0 {
                    "Connect".into()
                } else if i % 3 == 0 {
                    "Exec".into()
                } else {
                    "Open".into()
                },
                pid: 1000 + i,
                comm: comm.clone(),
                file: Some(if i % 7 == 0 {
                    format!("10.0.0.{}:443", i % 250)
                } else {
                    format!(
                        "/home/htw/projects/file_{i}.{}",
                        if i % 2 == 0 { "rs" } else { "pdf" }
                    )
                }),
                is_alert: false,
                opens: 0,
                memlp: None,
            });
        }
        events.push(Evt {
            ts: "20:31:59".into(),
            kind: "Alert".into(),
            pid: 4242,
            comm: "encrypt0r".into(),
            file: None,
            is_alert: true,
            opens: 812,
            memlp: None,
        });
        let mut exts = std::collections::HashMap::new();
        for (e, c) in [
            ("pdf", 120u64),
            ("rs", 94),
            ("png", 71),
            ("json", 55),
            ("txt", 33),
            ("enc", 12),
        ] {
            exts.insert(e.to_string(), c);
        }
        let mut pext = std::collections::HashMap::new();
        pext.insert("pdf".to_string(), 40u64);
        pext.insert("rs".to_string(), 12);
        let stats = vec![
            ProcStats {
                pid: 4242,
                ppid: 1,
                comm: "encrypt0r".into(),
                window_opens: 812,
                total_opens: 9812,
                total_execs: 1,
                alerts: 3,
                extensions: pext.clone(),
            },
            ProcStats {
                pid: 3311,
                ppid: 1,
                comm: "firefox".into(),
                window_opens: 240,
                total_opens: 4200,
                total_execs: 2,
                alerts: 0,
                extensions: pext.clone(),
            },
            ProcStats {
                pid: 2100,
                ppid: 1,
                comm: "cargo".into(),
                window_opens: 120,
                total_opens: 900,
                total_execs: 5,
                alerts: 0,
                extensions: pext.clone(),
            },
            ProcStats {
                pid: 9001,
                ppid: 1,
                comm: "find".into(),
                window_opens: 64,
                total_opens: 320,
                total_execs: 1,
                alerts: 0,
                extensions: pext,
            },
        ];
        let tree = vec![
            (0usize, 1u32, "systemd".to_string(), 0u64, 0u64),
            (1, 3311, "firefox".to_string(), 240, 0),
            (1, 2100, "cargo".to_string(), 120, 0),
            (2, 2101, "rustc".to_string(), 88, 0),
            (2, 4242, "encrypt0r".to_string(), 812, 3),
            (1, 9001, "find".to_string(), 64, 0),
        ];
        let top_files = (0..12)
            .map(|i| FileRank {
                path: format!(
                    "/home/htw/Documents/quarterly_report_{i}.{}",
                    if i % 2 == 0 { "pdf" } else { "rs" }
                ),
                count: 400 - i * 27,
                extension: if i % 2 == 0 {
                    "pdf".into()
                } else {
                    "rs".into()
                },
                entropy: 0.1 + (i as f64) * 0.07,
            })
            .collect();
        let mut rates = VecDeque::new();
        for i in 0..40u64 {
            rates.push_back(RateSample {
                exec_count: 40 + (i * 17) % 120,
                open_count: 300 + (i * 61) % 900,
                alert_count: i % 5,
            });
        }
        app.apply_snapshot(Snapshot {
            events,
            stats,
            tree,
            top_files,
            exts,
            rates,
            total: 18_420,
            lost: 3,
            uptime: 3_725,
            refresh: true,
        });
    }

    #[test]
    fn gateway_and_help_render_on_small_terminals() {
        let mut app = app();
        app.gateway = true;
        for (w, h) in [(80, 24), (40, 12), (24, 8)] {
            let screen = render(&app, w, h);
            assert!(screen.contains("talus"), "gateway {w}x{h}\n{screen}");
        }
        app.gateway = false;
        app.help = true;
        let screen = render(&app, 80, 24);
        assert!(screen.contains("keyboard shortcuts"), "{screen}");
    }

    #[test]
    fn escape_clears_filter_before_quitting() {
        let mut app = app();
        app.update(Msg::Key(KeyEvent::new(KeyCode::Char('/'))));
        for c in "cargo".chars() {
            app.update(Msg::Key(KeyEvent::new(KeyCode::Char(c))));
        }
        app.update(Msg::Key(KeyEvent::new(KeyCode::Enter)));
        let cmd = app.update(Msg::Key(KeyEvent::new(KeyCode::Escape)));
        assert!(
            !matches!(cmd, Cmd::Quit),
            "first Esc must only clear filter"
        );
        assert!(app.search_buf.is_empty());
        let cmd = app.update(Msg::Key(KeyEvent::new(KeyCode::Escape)));
        assert!(matches!(cmd, Cmd::Quit), "second Esc must quit");
    }

    #[test]
    fn slash_moves_focus_to_the_event_log() {
        let mut app = app();
        app.focused = 4;
        app.update(Msg::Key(KeyEvent::new(KeyCode::Char('/'))));
        assert_eq!(app.focused, 0);
        assert!(app.search_mode);
    }

    #[test]
    fn pause_discards_the_snapshot_backlog() {
        let (tx, rx) = mpsc::channel();
        let mut app = App_::new(rx, &LicenseState::community());
        app.gateway = false;
        app.paused = true;
        tx.send(Snapshot {
            events: Vec::new(),
            stats: Vec::new(),
            tree: Vec::new(),
            top_files: Vec::new(),
            exts: std::collections::HashMap::new(),
            rates: VecDeque::new(),
            total: 999,
            lost: 0,
            uptime: 1,
            refresh: false,
        })
        .unwrap();
        app.update(Msg::Tick);
        assert_eq!(app.total, 0, "paused ticks must not apply snapshots");
        app.paused = false;
        app.update(Msg::Tick);
        assert_eq!(app.total, 0, "drained backlog must not replay on resume");
    }

    #[test]
    fn rate_charts_are_seeded_from_the_full_history() {
        let mut app = app();
        populate(&mut app);
        assert_eq!(app.rate_chart.len(), 40);
        assert_eq!(app.open_chart.len(), 40);
        assert_eq!(app.alert_chart.len(), 40);
        let screen = render(&app, 120, 40);
        assert!(screen.contains("RATES (last 40s)"), "{screen}");
        assert!(!screen.contains("collecting rate samples"), "{screen}");
    }

    #[test]
    fn network_panel_keeps_full_addresses() {
        let mut app = app();
        populate(&mut app);
        app.focused = 2;
        let screen = render(&app, 120, 40);
        // Oldest→newest order, last connection is the newest one.
        assert!(screen.contains("10.0.0.0:443"), "{screen}");
        assert!(screen.contains("10.0.0.21:443"), "{screen}");
    }

    #[test]
    fn process_tree_connectors_respect_siblings() {
        let mut app = app();
        populate(&mut app);
        app.focused = 1;
        let screen = render(&app, 120, 40);
        assert!(screen.contains("├──  2101 rustc"), "{screen}");
        assert!(screen.contains("└──  4242 encrypt0r"), "{screen}");
    }

    #[test]
    fn narrow_process_panel_keeps_open_counts() {
        let mut app = app();
        populate(&mut app);
        app.focused = 1;
        let screen = render(&app, 80, 24);
        assert!(screen.contains("encrypt0r"), "{screen}");
        assert!(!screen.contains("encrypt~"), "{screen}");
        assert!(screen.contains("812"), "{screen}");
    }

    #[test]
    fn trunc_is_utf8_safe() {
        assert_eq!(trunc("zażółć", 4), "zaż~");
        assert_eq!(trunc("abc", 10), "abc");
    }
}
