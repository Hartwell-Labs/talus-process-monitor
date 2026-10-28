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
use ftui_extras::canvas::{Canvas, Mode, Painter};
use ftui_extras::charts::{
    heatmap_gradient, BarChart, BarDirection, BarGroup, BarMode, LineChart, Series, Sparkline,
};
use ftui_extras::text_effects::{StyledText, TextEffect};
use ftui_layout::{Constraint, Flex};
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
use crate::monitor::{FileRank, Monitor, Output, ProcStats, RateSample};

/// Processes that produce too many events to display (polling, IPC, etc.)
const NOISY_COMMS: &[&str] = &[
    // Desktop / compositor IPC
    "freebuff",
    "waybar",
    "upowerd",
    "mutter",
    "Xwayland",
    "hyprland",
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

// ── Layout / gateway constants ────────────────────────────────────────────

/// Link shown on the first-run gateway frame.
const GATEWAY_URL: &str = "https://hartwell-labs.pl";
/// Height (rows) of the telemetry card in the right-hand 30% column.
const TELEMETRY_H: u16 = 11;
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
}

impl Panel {
    const ALL: [Panel; 6] = [
        Panel::Events,
        Panel::Processes,
        Panel::Network,
        Panel::TopFiles,
        Panel::Extensions,
        Panel::Alerts,
    ];
    fn name(&self) -> &'static str {
        match self {
            Self::Events => "EVENTS",
            Self::Processes => "PROCESSES",
            Self::Network => "NETWORK",
            Self::TopFiles => "TOP FILES",
            Self::Extensions => "FILE TYPES",
            Self::Alerts => "ALERTS",
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
const HEAVY_REFRESH: Duration = Duration::from_millis(200);
/// Max processes carried per heavy snapshot (busiest by window + heaviest by lifetime).
const TUI_PROC_LIMIT: usize = 128;

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
    _alerts: LogViewer,
    _alert_st: LogViewerState,
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
    chart_x: f64,
    smooth_exec: f64,
    smooth_open: f64,
    smooth_alert: f64,
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
    // ── collapsible panels ──
    collapsed: [bool; 7],
    // ── copy buffer ──
    last_event_lines: VecDeque<String>,
    // ── search mode ──
    search_mode: bool,
    search_buf: String,
    search_hits: usize,
    // ── mouse hit-testing: stored body area from last render ──
    body_area: Cell<Rect>,
    // ── 70/30 layout hit-testing ──
    left_area: Cell<Rect>,
    side_area: Cell<Rect>,
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
        let mut log = LogViewer::new(5000);
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
            _alerts: LogViewer::new(200),
            _alert_st: LogViewerState::default(),
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
            chart_x: 0.0,
            smooth_exec: 0.0,
            smooth_open: 0.0,
            smooth_alert: 0.0,
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
            collapsed: [false; 7],
            last_event_lines: VecDeque::new(),
            search_mode: false,
            search_buf: String::new(),
            search_hits: 0,
            body_area: Cell::new(Rect::default()),
            left_area: Cell::new(Rect::default()),
            side_area: Cell::new(Rect::default()),
            gateway: gateway_should_show(),
            gateway_sel: 0,
            gateway_note: String::new(),
            gateway_link_area: Cell::new(Rect::default()),
            gateway_cont_area: Cell::new(Rect::default()),
            demo: std::env::var("TALUS_TUI_DEMO").map(|v| v == "1").unwrap_or(false),
            eps: 0.0,
            eps_mark: (Instant::now(), 0),
            cpu_pct: 0.0,
            cpu_mark: proc_cpu_ticks().unwrap_or(0),
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
                self.log.push(line.as_str());
                self.last_event_lines.push_back(line.clone());
                if self.last_event_lines.len() > 50 {
                    self.last_event_lines.pop_front();
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
                self._alerts.push(line.as_str());
            }
        }
        if !s.refresh {
            self.total = s.total;
            self.lost = s.lost;
            self.uptime = s.uptime;
            return;
        }
        let system_comms = [
            "systemd",
            "kthreadd",
            "rcu_sched",
            "ksoftirqd",
            "migration",
            "watchdog",
            "khungtaskd",
            "kswapd0",
            "kcompactd0",
            "jbd2",
            "init",
        ];
        self.procs = s
            .stats
            .iter()
            .filter(|p| !system_comms.contains(&p.comm.as_str()))
            .map(|p| ProcRow {
                pid: p.pid,
                comm: p.comm.clone(),
                opens: p.window_opens,
                alerts: p.alerts,
            })
            .collect();
        self.procs.sort_by_key(|b| std::cmp::Reverse(b.opens));
        self.tree = s
            .tree
            .into_iter()
            .filter(|(_, _, comm, _, _)| !system_comms.contains(&comm.as_str()))
            .collect();
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

        // EMA smoothing — process only the LATEST rate sample per tick
        let alpha = 0.25;
        if let Some(latest) = self.rates.back() {
            self.chart_x += 1.0;
            self.smooth_exec = self.smooth_exec * (1.0 - alpha) + latest.exec_count as f64 * alpha;
            self.smooth_open = self.smooth_open * (1.0 - alpha) + latest.open_count as f64 * alpha;
            self.smooth_alert =
                self.smooth_alert * (1.0 - alpha) + latest.alert_count as f64 * alpha;
            self.rate_chart.push((self.chart_x, self.smooth_exec));
            self.open_chart.push((self.chart_x, self.smooth_open));
            self.alert_chart.push((self.chart_x, self.smooth_alert));
        }
        let max_pts = 120;
        if self.rate_chart.len() > max_pts {
            self.rate_chart.drain(..self.rate_chart.len() - max_pts);
            self.open_chart.drain(..self.open_chart.len() - max_pts);
            self.alert_chart.drain(..self.alert_chart.len() - max_pts);
        }
        self.total = s.total;
        self.lost = s.lost;
        self.uptime = s.uptime;

        // Build heatmap: top procs × top exts (using global ext counts)
        let system_comms = [
            "systemd",
            "kthreadd",
            "rcu_sched",
            "ksoftirqd",
            "migration",
            "watchdog",
            "khungtaskd",
            "kswapd0",
            "kcompactd0",
            "jbd2",
        ];
        let mut procs_for_heat: Vec<&ProcStats> = s
            .stats
            .iter()
            .filter(|p| !system_comms.contains(&p.comm.as_str()))
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
            Msg::Key(k) if k.kind == KeyEventKind::Press => {
                if self.help {
                    self.help = false;
                    return Cmd::None;
                }
                if k.modifiers.contains(Modifiers::CTRL) && k.code == KeyCode::Char('c') {
                    return Cmd::Quit;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Escape => {
                        if self.focused == 0 {
                            return Cmd::Quit;
                        }
                    }
                    KeyCode::Char('?') => self.help = true,
                    KeyCode::Char('/') => {
                        self.search_mode = true;
                        self.search_buf.clear();
                    }
                    KeyCode::Char('p') => self.paused = !self.paused,
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
                        let idx = self.focused.min(6);
                        self.collapsed[idx] = !self.collapsed[idx];
                    }
                    KeyCode::Tab => self.focused = (self.focused + 1) % 6,
                    KeyCode::BackTab => {
                        self.focused = if self.focused == 0 {
                            5
                        } else {
                            self.focused - 1
                        }
                    }
                    KeyCode::Char(c @ '1'..='6') => self.focused = (c as usize) - ('1' as usize),
                    KeyCode::Up | KeyCode::Char('k') => self.log.scroll_up(1),
                    KeyCode::Down | KeyCode::Char('j') => self.log.scroll_down(1),
                    KeyCode::PageUp => self.log.page_up(&self.log_st),
                    KeyCode::PageDown => self.log.page_down(&self.log_st),
                    KeyCode::Home => self.log.scroll_to_top(),
                    KeyCode::End => self.log.scroll_to_bottom(),
                    _ => {}
                }
            }
            // Search mode input
            Msg::Key(k) if k.kind == KeyEventKind::Press && self.search_mode => {
                match k.code {
                    KeyCode::Escape => {
                        self.search_mode = false;
                        self.log.clear_search();
                        self.log.set_filter(None);
                    }
                    KeyCode::Enter => {
                        self.search_mode = false;
                        // keep filter active
                    }
                    KeyCode::Backspace => {
                        self.search_buf.pop();
                        if self.search_buf.is_empty() {
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
            Msg::Mouse(m) => {
                match m.kind {
                    MouseEventKind::ScrollUp => {
                        self.collapsed[self.focused.min(6)] = true;
                    }
                    MouseEventKind::ScrollDown => {
                        self.collapsed[self.focused.min(6)] = false;
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
            Msg::Tick if !self.paused => {
                self.time += 0.05;
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

        // Fill entire screen with dark background
        let bg = BG;
        for y in 0..area.height {
            for x in 0..area.width {
                if let Some(cell) = frame.buffer.get_mut(x, y) {
                    cell.bg = bg;
                }
            }
        }

        if self.gateway {
            return self.draw_gateway(frame, area);
        }

        if self.help {
            return self.draw_help(frame, area);
        }

        let lc_h: u16 = if self.collapsed[6] { 1 } else { 6 };
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
        vec![Box::new(Every::new(Duration::from_millis(50), || {
            Msg::Tick
        }))]
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
        // Strict asymmetric split: 70% event stream | 30% telemetry + detail.
        let cols = Flex::horizontal()
            .constraints([Constraint::Percentage(70.0), Constraint::Percentage(30.0)])
            .split(area);
        let side = Flex::vertical()
            .constraints([Constraint::Fixed(TELEMETRY_H), Constraint::Min(0)])
            .split(cols[1]);

        self.draw_events(f, cols[0]);
        self.draw_telemetry(f, side[0]);
        // The detail panel under the telemetry card follows focus (Tab / 1-6);
        // with the event stream focused it shows PROCESSES.
        match self.focused {
            2 => self.draw_net(f, side[1]),
            3 => self.draw_files(f, side[1]),
            4 => self.draw_exts_chart(f, side[1]),
            5 => self.draw_heatmap(f, side[1]),
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
            row("lost", self.lost.to_string(), if self.lost > 0 { AMBER } else { FG }),
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
                Style::new().fg(CYAN).attrs(StyleFlags::BOLD | StyleFlags::UNDERLINE)
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
        if self.collapsed[0] {
            let b = self.block(0, " EVENTS ");
            let inner = b.inner(area);
            b.render(area, f);
            if inner.height > 0 {
                Paragraph::new(Line::from_spans(vec![Span::styled(
                    "  [space] to expand",
                    Style::new().fg(DIM),
                )]))
                .render(Rect::new(inner.x, inner.y, inner.width, 1), f);
            }
            return;
        }
        let b = self.block(0, " EVENTS ");
        let inner = b.inner(area);
        b.render(area, f);
        let mut st = self.log_st.clone();
        self.log.render(inner, f, &mut st);
    }

    fn draw_procs(&self, f: &mut Frame, area: Rect) {
        let title = format!(" PROCESSES ({}) ", self.tree.len());
        let b = self.block(1, &title);
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[1] || self.tree.is_empty() {
            return;
        }

        let max = self
            .tree
            .iter()
            .map(|&(_, _, _, opens, _)| opens)
            .max()
            .unwrap_or(1)
            .max(1);
        let bar_w = inner.width.saturating_sub(38) as usize;
        let colors = MiniBarColors::new(BLUE, GREEN, AMBER, RED);
        let rows = inner.height as usize;

        for (i, &(depth, pid, ref comm, opens, alerts)) in self.tree.iter().take(rows).enumerate() {
            let y = inner.y + i as u16;
            let value = (opens as f64 / max as f64).clamp(0.0, 1.0);

            // Tree connector prefix
            let indent = "│   ".repeat(depth);
            let connector = if i + 1 < self.tree.len()
                && self
                    .tree
                    .get(i + 1)
                    .is_some_and(|&(d, _, _, _, _)| d > depth)
            {
                "├── "
            } else if depth > 0 {
                "└── "
            } else {
                "    "
            };

            let prefix = format!("{}{}", indent, connector);
            let label = format!("{} {:>5} {:<16}", prefix, pid, trunc(comm, 16));
            let label_c = if alerts > 0 {
                RED
            } else if opens > 10 {
                AMBER
            } else {
                BRIGHT
            };

            let text_w = inner.width.saturating_sub(bar_w as u16 + 1);
            Paragraph::new(Line::from_spans(vec![Span::styled(
                label,
                Style::new().fg(label_c),
            )]))
            .render(Rect::new(inner.x, y, text_w, 1), f);

            // MiniBar
            let bar_x = inner.x + text_w;
            let bar_area = Rect::new(bar_x, y, bar_w as u16, 1);
            MiniBar::new(value, bar_w as u16)
                .colors(colors)
                .show_percent(true)
                .render(bar_area, f);
        }
    }

    fn draw_exts_chart(&self, f: &mut Frame, area: Rect) {
        let b = self.block(4, " FILE TYPES ");
        let inner = b.inner(area);
        b.render(area, f);
        if self.exts.is_empty() {
            return;
        }

        // BarChart from ftui-extras
        let max_count = self
            .exts
            .iter()
            .map(|(_, c)| *c as f64)
            .fold(0.0f64, f64::max)
            .max(1.0);
        let groups: Vec<BarGroup> = self
            .exts
            .iter()
            .take(10)
            .map(|(ext, cnt)| BarGroup::new(ext.as_str(), vec![*cnt as f64]))
            .collect();

        let palette: Vec<PackedRgba> = self
            .exts
            .iter()
            .take(10)
            .map(|(ext, _)| ext_color(ext))
            .collect();

        BarChart::new(groups)
            .direction(BarDirection::Horizontal)
            .mode(BarMode::Grouped)
            .bar_width(1)
            .colors(palette)
            .style(Style::new().fg(FG))
            .max(max_count)
            .render(inner, f);
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
            Paragraph::new(Line::from_spans(vec![
                Span::styled("  no network events captured", Style::new().fg(DIM)),
                Span::styled(
                    "\n  (kernel may lack sockaddr capture)",
                    Style::new().fg(DIM),
                ),
            ]))
            .render(inner, f);
            return;
        }

        // Split: top = aggregated per-process, bottom = Canvas traffic flow
        let split = Flex::vertical()
            .constraints([Constraint::Percentage(60.0), Constraint::Percentage(40.0)])
            .split(inner);

        // --- Top: per-process aggregated connections ---
        let mut proc_conns: std::collections::HashMap<String, (u64, u64, u64, u64)> =
            std::collections::HashMap::new(); // (connect, accept, send, recv)
        for e in self.net.iter() {
            let entry = proc_conns.entry(e.comm.clone()).or_insert((0, 0, 0, 0));
            match e.kind.as_str() {
                "Connect" => entry.0 += 1,
                "Accept" => entry.1 += 1,
                "SendTo" => entry.2 += 1,
                "RecvFrom" => entry.3 += 1,
                _ => {}
            }
        }
        let mut procs: Vec<_> = proc_conns.into_iter().collect();
        procs.sort_by(|a, b| {
            let a_total = a.1 .0 + a.1 .1 + a.1 .2 + a.1 .3;
            let b_total = b.1 .0 + b.1 .1 + b.1 .2 + b.1 .3;
            b_total.cmp(&a_total)
        });
        let max_conns = procs
            .iter()
            .map(|(_, c)| c.0 + c.1 + c.2 + c.3)
            .max()
            .unwrap_or(1)
            .max(1);

        let rows = split[0].height as usize;
        let bar_w = split[0].width.saturating_sub(38) as usize;
        for (i, (comm, (conn, acc, send, recv))) in procs.iter().take(rows).enumerate() {
            let y = split[0].y + i as u16;
            let total = conn + acc + send + recv;
            let value = (total as f64 / max_conns as f64).clamp(0.0, 1.0);

            // Label: comm + counts
            let label = format!(" {:<14}", trunc(comm, 14));
            Paragraph::new(Line::from_spans(vec![
                Span::styled(label, Style::new().fg(BRIGHT)),
                Span::styled(format!(" >{:<4} <{:<4} ", conn, acc), Style::new().fg(CYAN)),
                Span::styled(
                    format!(" {:>4}  {:>4} ", send, recv),
                    Style::new().fg(PURPLE),
                ),
            ]))
            .render(Rect::new(split[0].x, y, 38.min(split[0].width), 1), f);

            // Bar: stacked direction
            let bar_area = Rect::new(split[0].x + 38, y, bar_w as u16, 1);
            let colors = MiniBarColors::new(BLUE, GREEN, AMBER, PURPLE);
            MiniBar::new(value, bar_w as u16)
                .colors(colors)
                .show_percent(false)
                .render(bar_area, f);
        }

        // --- Bottom: Canvas traffic flow visualization ---
        if split[1].height >= 3 {
            let canvas_area = Rect::new(
                split[1].x + 1,
                split[1].y + 1,
                split[1].width.saturating_sub(2),
                split[1].height.saturating_sub(2),
            );
            if canvas_area.width >= 4 && canvas_area.height >= 2 {
                let mut painter = Painter::for_area(canvas_area, Mode::Block);
                let (pw, ph) = painter.size();
                let _t = self.time;

                // Draw traffic flow: each recent event becomes a colored dot
                // moving right (out) or left (in)
                for (i, e) in self.net.iter().rev().take((pw * ph) as usize).enumerate() {
                    let frac = i as f64 / (pw * ph).max(1) as f64;
                    let px = if matches!(e.kind.as_str(), "Connect" | "SendTo") {
                        // Outgoing: left to right
                        (frac * pw as f64) as i32
                    } else {
                        // Incoming: right to left
                        ((1.0 - frac) * pw as f64) as i32
                    };
                    let py = ((i as f64 / pw as f64).fract() * ph as f64) as i32;
                    let c = match e.kind.as_str() {
                        "Connect" => BLUE,
                        "Accept" => GREEN,
                        "SendTo" => AMBER,
                        "RecvFrom" => PURPLE,
                        _ => CYAN,
                    };
                    painter.point_colored(px, py, c);
                }

                Canvas::from_painter(&painter)
                    .style(Style::new().fg(FG))
                    .render(canvas_area, f);
            }
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
        let bar_w = inner.width.saturating_sub(36) as usize;
        let colors = MiniBarColors::new(BLUE, GREEN, AMBER, RED);

        for (i, r) in self.files.iter().take(rows).enumerate() {
            let y = inner.y + i as u16;
            let value = (r.count as f64 / max as f64).clamp(0.0, 1.0);

            let rank_c = if i < 3 { AMBER } else { DIM };
            let label = format!("{:>2}. {:<16}", i + 1, trunc(&r.name, 16));
            let ext_c = ext_color(&r.ext);
            let entropy_c = if r.entropy > 0.7 {
                RED
            } else if r.entropy > 0.4 {
                AMBER
            } else {
                GREEN
            };

            let label_w = 28.min(inner.width);
            Paragraph::new(Line::from_spans(vec![
                Span::styled(label, Style::new().fg(rank_c)),
                Span::styled(format!(" .{:<5}", r.ext), Style::new().fg(ext_c)),
                Span::styled(format!("H:{:.1}", r.entropy), Style::new().fg(entropy_c)),
            ]))
            .render(Rect::new(inner.x, y, label_w, 1), f);

            // MiniBar
            let bar_area = Rect::new(inner.x + label_w, y, bar_w as u16, 1);
            MiniBar::new(value, bar_w as u16)
                .colors(colors)
                .show_percent(false)
                .render(bar_area, f);
        }
    }

    fn draw_heatmap(&self, f: &mut Frame, area: Rect) {
        let b = self.block(5, " HEATMAP ");
        let inner = b.inner(area);
        b.render(area, f);
        if self.collapsed[5] || self.heatmap.is_empty() {
            return;
        }

        let rows = inner.height as usize;
        let ext_count = self.heatmap_exts.len();
        if ext_count == 0 {
            return;
        }

        // Header row: extension labels
        let cell_w = (inner.width as usize / ext_count).max(4);
        for (j, ext) in self.heatmap_exts.iter().enumerate() {
            let x = inner.x + (j * cell_w) as u16;
            let label = format!(".{:<4}", trunc(ext, 4));
            Paragraph::new(Line::from_spans(vec![Span::styled(
                label,
                Style::new().fg(DIM),
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
            let label = format!("{:<14}", trunc(&row.label, 14));
            Paragraph::new(Line::from_spans(vec![Span::styled(
                label,
                Style::new().fg(BRIGHT),
            )]))
            .render(Rect::new(inner.x, y, 14.min(inner.width), 1), f);

            // Heatmap cells
            for (j, (_ext, count)) in row.ext_counts.iter().enumerate() {
                let x = inner.x + 14 + (j * cell_w) as u16;
                let frac = *count as f64 / max_val as f64;
                let color = heatmap_gradient(frac);
                let bar_len = ((cell_w - 1) as f64 * frac) as usize;
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
        if self.collapsed[6] || area.height < 2 {
            return;
        }

        let charts_layout = Flex::horizontal()
            .constraints([
                Constraint::Percentage(34.0),
                Constraint::Percentage(33.0),
                Constraint::Percentage(33.0),
            ])
            .split(area);

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
        }
    }

    fn draw_search_bar(&self, f: &mut Frame, area: Rect) {
        let bar_area = Rect::new(
            area.x,
            area.y + area.height.saturating_sub(3),
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
        let center = format!(
            "evt:{}  lost:{}  sup:{}  up:{}  r:limit  y:copy  space:collapse",
            self.total,
            self.lost,
            self.rate_suppressed,
            fmt_dur(self.uptime)
        );
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
                // ALERTS / HEATMAP
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
            Line::raw("   1-6             jump to panel"),
            Line::raw("   j/k or arrows   scroll"),
            Line::raw(""),
            Line::from_spans(vec![Span::styled(
                " ACT",
                Style::new().fg(AMBER).attrs(StyleFlags::BOLD),
            )]),
            Line::raw("   p               pause/resume"),
            Line::raw("   r               cycle rate limit (5/15/50)"),
            Line::raw("   /               search/filter events"),
            Line::raw("   space           collapse/expand panel"),
            Line::raw("   y               copy last 20 lines"),
            Line::raw("   q/Esc           quit"),
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
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max.saturating_sub(1)])
    }
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
            let evts: Vec<Evt> = monitor
                .poll()
                .into_iter()
                .filter_map(|o| match o {
                    Output::Event(ev) => Some(Evt {
                        ts: ev.ts,
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
            thread::sleep(Duration::from_millis(16));
        })?;
    let app = App_::new(rx, &license);
    let res = App::new(app)
        .screen_mode(ScreenMode::AltScreen)
        .with_mouse()
        .run();
    let _ = h.join();
    res.map_err(|e| anyhow::anyhow!("tui: {}", e))
}
