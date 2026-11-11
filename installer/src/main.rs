//! talus-installer — TUI installer for Talus Enterprise.
//!
//! Uses the same ftui runtime as talus-monitor (FrankenTUI 0.6).
//!
//! Flow:  Welcome → SystemCheck → LicenseInput → InstallProgress → Complete
//!
//! License logic is delegated to `talus_process_monitor::license` so the
//! installer and the agent share identical activation / cache behaviour.

use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ftui::core::geometry::Rect;
use ftui::layout::{Alignment as LayoutAlignment, Constraint, Flex};
use ftui::render::budget::FrameBudgetConfig;
use ftui::render::cell::PackedRgba;
use ftui::runtime::program::{App, Cmd, Model};
use ftui::runtime::terminal_writer::ScreenMode;
use ftui::runtime::{Every, Subscription};
use ftui::style::{Style, StyleFlags};
use ftui::text::{Line, Span, Text};
use ftui::widgets::block::{Alignment, Block};
use ftui::widgets::borders::{BorderType, Borders};
use ftui::widgets::paragraph::Paragraph;
use ftui::widgets::Widget;
use ftui::{Cell, Event, Frame, KeyCode, KeyEvent, KeyEventKind, Modifiers};

use talus_process_monitor::license;

// ── Color palette (matches Talus dark-tech theme) ─────────────────────────────

const BG: PackedRgba = PackedRgba::rgb(26, 27, 38);
const CYAN: PackedRgba = PackedRgba::rgb(100, 210, 245);
const GREEN: PackedRgba = PackedRgba::rgb(80, 200, 120);
const RED: PackedRgba = PackedRgba::rgb(220, 20, 45);
const YELLOW: PackedRgba = PackedRgba::rgb(250, 180, 50);
const DIM: PackedRgba = PackedRgba::rgb(86, 95, 137);
const FG: PackedRgba = PackedRgba::rgb(169, 177, 214);

// ── Screen enum ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    SystemCheck,
    LicenseInput,
    InstallProgress,
    Complete,
}

// ── Check result ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CheckResult {
    label: String,
    passed: bool,
    detail: String,
}

// ── Install step ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct InstallStep {
    label: String,
    done: bool,
    current: bool,
    error: Option<String>,
}

// ── License status ───────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum LicenseStatus {
    Idle,
    Verifying,
    Activated {
        license_id: String,
        org: Option<String>,
    },
    Error(String),
}

// ── App message ──────────────────────────────────────────────────────────────

enum Msg {
    Key(KeyEvent),
    Paste(String),
    Tick,
    Noop,
}

/// Messages from the background install thread.
enum InstallEvent {
    Steps(Vec<InstallStep>),
    Finished(Result<(), String>),
}

impl From<Event> for Msg {
    fn from(e: Event) -> Self {
        match e {
            Event::Key(k) => Msg::Key(k),
            Event::Paste(p) => Msg::Paste(p.text),
            _ => Msg::Noop,
        }
    }
}

// ── Installer model ──────────────────────────────────────────────────────────

struct Installer {
    screen: Screen,
    license_input: String,
    license_cursor: usize,
    license_status: LicenseStatus,
    checks: Vec<CheckResult>,
    install_steps: Vec<InstallStep>,
    install_done: bool,
    install_error: Option<String>,
    binary_override: Option<PathBuf>,
    license_key_override: Option<String>,
    skip_license: bool,
    notice: Option<String>,
    ticks: u64,
    install_rx: Option<mpsc::Receiver<InstallEvent>>,
}

impl Installer {
    fn new(license_key: Option<String>, skip_license: bool) -> Self {
        Self {
            screen: Screen::Welcome,
            license_input: license_key.clone().unwrap_or_default(),
            license_cursor: 0,
            license_status: LicenseStatus::Idle,
            checks: Vec::new(),
            install_steps: default_steps(),
            install_done: false,
            install_error: None,
            binary_override: None,
            license_key_override: license_key,
            skip_license,
            notice: None,
            ticks: 0,
            install_rx: None,
        }
    }
}

impl Installer {
    fn poll_install(&mut self) {
        let Some(rx) = self.install_rx.take() else {
            return;
        };
        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(InstallEvent::Steps(steps)) => self.install_steps = steps,
                Ok(InstallEvent::Finished(result)) => {
                    self.install_done = true;
                    if let Err(e) = result {
                        self.install_error = Some(e);
                    }
                    finished = true;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if !self.install_done {
                        self.install_done = true;
                        self.install_error = Some("installer stopped unexpectedly".into());
                    }
                    finished = true;
                    break;
                }
            }
        }
        if !finished {
            self.install_rx = Some(rx);
        }
    }
}

fn start_install(app: &mut Installer, skip_license: bool) {
    app.screen = Screen::InstallProgress;
    app.install_done = false;
    app.install_error = None;
    app.install_steps = default_steps();
    app.notice = None;

    let (tx, rx) = mpsc::channel();
    app.install_rx = Some(rx);
    let binary_override = app.binary_override.clone();

    std::thread::spawn(move || {
        let mut steps = default_steps();
        let tx_steps = tx.clone();
        let mut changed = move |s: &[InstallStep]| {
            let _ = tx_steps.send(InstallEvent::Steps(s.to_vec()));
        };
        let result = perform_install(&binary_override, skip_license, &mut steps, &mut changed)
            .map_err(|e| format!("{e:#}"));
        let _ = tx.send(InstallEvent::Finished(result));
    });
}

impl Model for Installer {
    type Message = Msg;

    fn init(&mut self) -> Cmd<Msg> {
        self.checks = run_system_checks();
        Cmd::none()
    }

    fn update(&mut self, msg: Msg) -> Cmd<Msg> {
        match msg {
            Msg::Key(k) if k.kind == KeyEventKind::Press => {
                handle_key(self, k);
            }
            Msg::Paste(text) => {
                // Insert pasted text at cursor position (for license input)
                if matches!(self.screen, Screen::LicenseInput)
                    && matches!(
                        self.license_status,
                        LicenseStatus::Idle | LicenseStatus::Error(_)
                    )
                {
                    let idx = char_idx_to_byte_idx(&self.license_input, self.license_cursor);
                    self.license_input.insert_str(idx, &text);
                    self.license_cursor += text.chars().count();
                }
            }
            Msg::Tick => {
                self.ticks = self.ticks.wrapping_add(1);
                self.poll_install();
            }
            _ => {}
        }
        Cmd::none()
    }

    fn view(&self, frame: &mut Frame) {
        let area = Rect::from_size(frame.buffer.width(), frame.buffer.height());

        // Background fill
        let mut bg_cell = Cell::from_char(' ');
        bg_cell.bg = BG;
        frame.buffer.fill(area, bg_cell);

        match self.screen {
            Screen::Welcome => render_welcome(frame, area),
            Screen::SystemCheck => render_system_check(frame, area, self),
            Screen::LicenseInput => render_license_input(frame, area, self),
            Screen::InstallProgress => render_install_progress(frame, area, self),
            Screen::Complete => render_complete(frame, area, self),
        }
    }

    fn subscriptions(&self) -> Vec<Box<dyn Subscription<Msg>>> {
        vec![Box::new(Every::new(Duration::from_millis(500), || {
            Msg::Tick
        }))]
    }
}

// ── Key handling ─────────────────────────────────────────────────────────────

fn handle_key(app: &mut Installer, k: KeyEvent) {
    match app.screen {
        Screen::Welcome => match k.code {
            KeyCode::Char('q') | KeyCode::Escape => std::process::exit(0),
            KeyCode::Enter => {
                app.notice = None;
                app.screen = Screen::SystemCheck;
            }
            _ => {}
        },
        Screen::SystemCheck => match k.code {
            KeyCode::Char('q') | KeyCode::Escape => std::process::exit(0),
            KeyCode::Backspace => app.screen = Screen::Welcome,
            KeyCode::Enter | KeyCode::Char('n') => {
                if !checks_pass(app, 0) {
                    app.notice = Some(
                        "Root is required for the system install. Re-run with: sudo talus-installer"
                            .into(),
                    );
                } else {
                    app.notice = None;
                    continue_after_checks(app);
                }
            }
            _ => {}
        },
        Screen::LicenseInput => match k.code {
            KeyCode::Char('q') if k.modifiers.contains(Modifiers::CTRL) => std::process::exit(0),
            KeyCode::Escape => app.screen = Screen::SystemCheck,
            KeyCode::Char(c) => {
                if matches!(
                    app.license_status,
                    LicenseStatus::Idle | LicenseStatus::Error(_)
                ) {
                    let idx = char_idx_to_byte_idx(&app.license_input, app.license_cursor);
                    app.license_input.insert(idx, c);
                    app.license_cursor += 1;
                }
            }
            KeyCode::Backspace => {
                if app.license_cursor > 0 {
                    let idx = char_idx_to_byte_idx(&app.license_input, app.license_cursor - 1);
                    app.license_input.remove(idx);
                    app.license_cursor -= 1;
                }
            }
            KeyCode::Delete => {
                let idx = char_idx_to_byte_idx(&app.license_input, app.license_cursor);
                if idx < app.license_input.len() {
                    app.license_input.remove(idx);
                }
            }
            KeyCode::Left => app.license_cursor = app.license_cursor.saturating_sub(1),
            KeyCode::Right => {
                if app.license_cursor < app.license_input.chars().count() {
                    app.license_cursor += 1;
                }
            }
            KeyCode::Enter => {
                let key = app.license_input.trim().to_string();
                if key.is_empty()
                    || !matches!(
                        app.license_status,
                        LicenseStatus::Idle | LicenseStatus::Error(_)
                    )
                {
                    return;
                }
                app.license_status = LicenseStatus::Verifying;
                match activate_license_bg(&key) {
                    Ok((id, org)) => {
                        app.license_status = LicenseStatus::Activated {
                            license_id: id,
                            org,
                        };
                        start_install(app, false);
                    }
                    Err(e) => app.license_status = LicenseStatus::Error(e),
                }
            }
            _ => {}
        },
        Screen::InstallProgress => match k.code {
            KeyCode::Char('q') | KeyCode::Escape => std::process::exit(0),
            KeyCode::Enter if app.install_done && app.install_error.is_none() => {
                app.screen = Screen::Complete
            }
            _ => {}
        },
        Screen::Complete => match k.code {
            KeyCode::Char('q') | KeyCode::Escape | KeyCode::Enter => std::process::exit(0),
            _ => {}
        },
    }
}

fn checks_pass(app: &Installer, idx: usize) -> bool {
    app.checks.get(idx).map(|c| c.passed).unwrap_or(false)
}

/// Decide the next screen once the checks are acknowledged.
fn continue_after_checks(app: &mut Installer) {
    if app.skip_license {
        start_install(app, true);
    } else if has_valid_license() {
        if let Ok(Some(cache)) = license::LicenseCache::load() {
            app.license_status = LicenseStatus::Activated {
                license_id: cache.payload.license_id.clone(),
                org: cache.payload.organization.clone(),
            };
        }
        start_install(app, false);
    } else if let Some(key) = app.license_key_override.clone() {
        app.license_input = key.clone();
        app.license_status = LicenseStatus::Verifying;
        match activate_license_bg(&key) {
            Ok((id, org)) => {
                app.license_status = LicenseStatus::Activated {
                    license_id: id,
                    org,
                };
                start_install(app, false);
            }
            Err(e) => {
                app.license_status = LicenseStatus::Error(e);
                app.screen = Screen::LicenseInput;
            }
        }
    } else {
        app.screen = Screen::LicenseInput;
    }
}

// ── System checks ────────────────────────────────────────────────────────────

fn run_system_checks() -> Vec<CheckResult> {
    let mut results = Vec::new();

    let is_root = unsafe { libc::getuid() } == 0;
    results.push(CheckResult {
        label: "Root privileges".into(),
        passed: is_root,
        detail: if is_root {
            "eBPF and systemd setup need root".into()
        } else {
            "Re-run with: sudo talus-installer".into()
        },
    });

    let (kernel_ok, kernel) = check_kernel_version();
    results.push(CheckResult {
        label: "Kernel >= 5.8 (eBPF CO-RE)".into(),
        passed: kernel_ok,
        detail: format!("Linux {kernel}"),
    });

    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .find(|p| std::path::Path::new(p).exists());
    results.push(CheckResult {
        label: "tracefs mounted".into(),
        passed: tracefs.is_some(),
        detail: match tracefs {
            Some(p) => format!("{p} available"),
            None => "Mount debugfs: sudo mount -t debugfs none /sys/kernel/debug".into(),
        },
    });

    let free_mb = disk_free_mb("/usr/local");
    results.push(CheckResult {
        label: "Disk space".into(),
        passed: free_mb.map(|mb| mb >= 100).unwrap_or(false),
        detail: match free_mb {
            Some(mb) => format!("{mb} MB free in /usr/local (100 MB required)"),
            None => "Could not read free space for /usr/local".into(),
        },
    });

    let systemd = std::path::Path::new("/run/systemd/system").exists();
    results.push(CheckResult {
        label: "systemd".into(),
        passed: systemd,
        detail: if systemd {
            "Service manager available".into()
        } else {
            "systemd not running — install the binary manually".into()
        },
    });

    results
}

fn disk_free_mb(path: &str) -> Option<u64> {
    use std::ffi::CString;
    let path = CString::new(path).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some((stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024))
}

fn check_kernel_version() -> (bool, String) {
    let out = Command::new("uname").arg("-r").output();
    match out {
        Ok(o) => {
            let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let clean = version.split('-').next().unwrap_or(&version);
            let parts: Vec<&str> = clean.split('.').collect();
            let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let passed = major > 5 || (major == 5 && minor >= 8);
            (passed, version)
        }
        Err(e) => (false, format!("uname failed: {e}")),
    }
}

// ── License activation ───────────────────────────────────────────────────────

/// Check if a valid (non-expired, machine-bound) license cache already exists.
/// If so, the installer can skip activation entirely — the user has already
/// activated on this machine.
fn has_valid_license() -> bool {
    license::verify_cached_license().is_ok()
}

/// Activate a license key — accepts short keys (TALUS-XXXXX…), canonical/JWT
/// keys, and store-purchase keys. Short keys are resolved via the license
/// server before local Ed25519 verification and online activation.
fn activate_license_bg(key: &str) -> Result<(String, Option<String>), String> {
    match license::activate_license(key) {
        Ok(cache) => Ok((
            cache.payload.license_id.clone(),
            cache.payload.organization.clone(),
        )),
        Err(e) => Err(format!("Activation failed: {e}")),
    }
}

// ── Installation pipeline ────────────────────────────────────────────────────

/// Build talus-monitor-enterprise from source with an explicit --source-dir.
/// The source directory must be provided explicitly — no hardcoded paths.
fn build_talus_from_source(source_dir: &std::path::Path) -> Result<PathBuf> {
    if !source_dir.exists() {
        return Err(anyhow!(
            "source directory not found: {}",
            source_dir.display()
        ));
    }

    let cargo_toml = source_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(anyhow!(
            "no Cargo.toml found in source dir: {}",
            source_dir.display()
        ));
    }

    // Build the target directory structure
    let target_dir = source_dir.join("target/release/talus-monitor-enterprise");

    // Construct PATH that includes the user's cargo bin via SUDO_USER
    let build_user = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(whoami::username);

    let user_home = format!("/home/{build_user}");
    let cargo_bin = format!("{user_home}/.cargo/bin");
    let current_path = std::env::var("PATH").unwrap_or_default();
    let build_path = if current_path.contains(&cargo_bin) {
        current_path
    } else {
        format!("{cargo_bin}:{current_path}")
    };

    eprintln!("[talus-installer] Building talus-monitor-enterprise (cargo build --release)...");
    eprintln!(
        "[talus-installer] Building as user: {build_user}, source: {}",
        source_dir.display()
    );

    // Run as the original user (preserves their cargo/rustup configuration)
    let status = if build_user != whoami::username() {
        Command::new("sudo")
            .args(["-u", &build_user, "--"])
            .env("HOME", &user_home)
            .env("PATH", &build_path)
            .args([
                "env",
                &format!("HOME={user_home}"),
                &format!("PATH={build_path}"),
                "cargo",
                "build",
                "--release",
            ])
            .current_dir(source_dir)
            .status()
            .context("cargo build failed (is Rust/cargo installed?)")?
    } else {
        Command::new("cargo")
            .args(["build", "--release"])
            .env("PATH", &build_path)
            .current_dir(source_dir)
            .status()
            .context("cargo build failed (is Rust/cargo installed?)")?
    };

    if !status.success() {
        return Err(anyhow!("cargo build failed with status: {status}"));
    }

    if target_dir.exists() {
        Ok(target_dir)
    } else {
        Err(anyhow!(
            "build succeeded but binary not found at {}",
            target_dir.display()
        ))
    }
}

fn binary_source(
    cli_override: &Option<PathBuf>,
    build_from_source: bool,
    source_dir: &Option<PathBuf>,
) -> Result<PathBuf> {
    // 1. CLI override (--binary)
    if let Some(p) = cli_override {
        if p.exists() {
            return Ok(p.clone());
        }
        return Err(anyhow!("binary not found at: {}", p.display()));
    }

    // 2. Installed locations, then PATH, then the source tree.
    let mut candidates = vec![
        PathBuf::from("/usr/local/bin/talus-monitor-enterprise"),
        PathBuf::from("target/release/talus-monitor-enterprise"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("talus-monitor-enterprise"));
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        candidates.extend(
            path.split(':')
                .map(|d| PathBuf::from(d).join("talus-monitor-enterprise")),
        );
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        candidates.push(PathBuf::from(format!(
            "/home/{user}/Projects/talus/talus-enterprise/target/release/talus-monitor-enterprise"
        )));
    }

    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }

    // 3. Explicit build from source (--build-from-source --source-dir <PATH>)
    if build_from_source {
        let dir = source_dir
            .as_ref()
            .ok_or_else(|| anyhow!("--build-from-source requires --source-dir <PATH>"))?;
        return build_talus_from_source(dir);
    }

    // 4. No binary found — instruct the user
    Err(anyhow!(
        "talus-monitor-enterprise binary not found in common paths.\n\
         Use one of:\n\
         • --binary /path/to/talus-monitor-enterprise\n\
         • --build-from-source --source-dir /path/to/talus-enterprise\n\
         (automatic fallback to `cargo build` has been removed for security)"
    ))
}

fn create_systemd_unit() -> Result<()> {
    // ExecStart matches install-systemd.sh: --web for the dashboard +
    // --ignore-comm for common processes so legitimate bursts (cargo,
    // firefox, systemd, pipewire, …) don't trigger false-positive alerts.
    // --auto-kill is intentionally omitted — the service starts in
    // monitor-only mode (detection + dashboard).  EDR response is opt-in
    // via a systemd drop-in (see install-systemd.sh for details).
    let unit = r#"[Unit]
Description=Talus eBPF Endpoint Security Agent (Enterprise)
Documentation=https://hartwell-labs.pl
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=HOME=/root
ExecStart=/usr/local/bin/talus-monitor-enterprise monitor --web 127.0.0.1:8080 --alert-threshold 200 --json --ignore-comm sh --ignore-comm bash --ignore-comm cargo --ignore-comm rustc --ignore-comm firefox --ignore-comm code --ignore-comm systemd --ignore-comm dbus --ignore-comm pipewire --ignore-comm wireplumber --ignore-comm node
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"#;

    let dest = std::path::Path::new("/etc/systemd/system/talus-monitor.service");
    std::fs::write(dest, unit).context("failed to write systemd unit (needs root)")?;
    Ok(())
}

fn default_steps() -> Vec<InstallStep> {
    [
        "Locate talus binary",
        "Install binary to /usr/local/bin",
        "Verify license cache",
        "Write systemd service",
        "Enable + start service",
        "Verify service + dashboard",
    ]
    .into_iter()
    .map(|label| InstallStep {
        label: label.into(),
        done: false,
        current: false,
        error: None,
    })
    .collect()
}

/// One install path for both the TUI and `--no-tui`. Each step is reported as
/// it starts and finishes, so the caller can render progress or print lines.
fn perform_install(
    binary_override: &Option<PathBuf>,
    skip_license: bool,
    steps: &mut [InstallStep],
    changed: &mut dyn FnMut(&[InstallStep]),
) -> Result<()> {
    macro_rules! step {
        ($idx:expr, $body:expr) => {{
            for (i, s) in steps.iter_mut().enumerate() {
                s.current = i == $idx;
            }
            changed(steps);
            match $body {
                Ok(v) => {
                    steps[$idx].current = false;
                    steps[$idx].done = true;
                    changed(steps);
                    v
                }
                Err(e) => {
                    steps[$idx].current = false;
                    steps[$idx].error = Some(format!("{e:#}"));
                    changed(steps);
                    return Err(e);
                }
            }
        }};
    }

    let src = step!(
        0,
        match binary_source(binary_override, false, &None) {
            Ok(path) => Ok(path),
            Err(not_found) => {
                let cache = license::LicenseCache::load()?.filter(|_| !skip_license);
                match cache {
                    Some(cache) => {
                        let tier = match cache.payload.tier {
                            license::LicenseTier::Community => "community",
                            license::LicenseTier::Enterprise => "enterprise",
                        };
                        license::download_artifact(tier, None, false)
                            .map(|(path, _)| path)
                            .with_context(|| {
                                format!("{not_found:#}; license-server download failed")
                            })
                    }
                    None => Err(not_found),
                }
            }
        }
    );

    let dest = std::path::Path::new("/usr/local/bin/talus-monitor-enterprise").to_path_buf();
    let mut installed = false;
    let result = (|| -> Result<()> {
        step!(1, install_binary(&src, &dest));
        installed = true;

        let licensed = skip_license || license::LicenseCache::load()?.is_some();
        step!(
            2,
            if licensed {
                Ok(())
            } else {
                Err(anyhow!(
                    "license cache not found — activate a license first or use --skip-license"
                ))
            }
        );

        step!(3, create_systemd_unit());
        step!(4, start_service());
        step!(5, verify_installation());
        Ok(())
    })();

    if result.is_err() && installed {
        let _ = rollback_install(&dest);
    }
    result
}

/// Copy the binary next to its destination, fsync, validate, then rename.
/// The previous binary is kept as `.bin.prev` for rollback.
fn install_binary(src: &std::path::Path, dest: &std::path::Path) -> Result<()> {
    use std::io::Read;

    std::fs::create_dir_all(
        dest.parent()
            .ok_or_else(|| anyhow!("destination has no parent: {}", dest.display()))?,
    )?;

    let prev = dest.with_extension("bin.prev");
    if dest.exists() {
        std::fs::copy(dest, &prev)
            .with_context(|| format!("backup {} -> {}", dest.display(), prev.display()))?;
    }

    let dest_new = dest.with_extension("bin.new");
    std::fs::copy(src, &dest_new)
        .with_context(|| format!("copy {} -> {}", src.display(), dest_new.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest_new, std::fs::Permissions::from_mode(0o755))?;
    }

    // ELF64 little-endian only: 7f 45 4c 46 02 01.
    let mut magic = [0u8; 6];
    let valid = std::fs::File::open(&dest_new)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|_| magic == [0x7f, b'E', b'L', b'F', 2, 1])
        .unwrap_or(false);
    if !valid {
        let _ = std::fs::remove_file(&dest_new);
        bail!("{} is not a valid ELF64 binary", src.display());
    }

    std::fs::File::open(&dest_new)?.sync_all()?;
    std::fs::rename(&dest_new, dest)
        .with_context(|| format!("rename {} -> {}", dest_new.display(), dest.display()))?;

    let _ = std::fs::remove_file("/usr/local/bin/talus");
    std::os::unix::fs::symlink(dest, "/usr/local/bin/talus")?;
    Ok(())
}

fn start_service() -> Result<()> {
    run_systemctl(&["daemon-reload"]);
    run_systemctl(&["enable", "talus-monitor.service"]);
    let status = Command::new("systemctl")
        .args(["start", "talus-monitor.service"])
        .status()
        .context("failed to run systemctl start")?;
    if !status.success() {
        show_journal_errors();
        bail!(
            "could not start talus-monitor.service (exit code {})",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

fn run_systemctl(args: &[&str]) {
    let _ = Command::new("systemctl").args(args).status();
}

fn verify_installation() -> Result<()> {
    let mut state = String::new();
    for _ in 0..5 {
        std::thread::sleep(Duration::from_secs(1));
        state = Command::new("systemctl")
            .args(["is-active", "talus-monitor.service"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if state == "active" {
            break;
        }
    }
    if state != "active" {
        show_journal_errors();
        bail!("talus-monitor.service is not active (state: {state})");
    }
    if verify_dashboard() {
        eprintln!("[talus] dashboard reachable at https://127.0.0.1:8080/ (self-signed certificate)");
    } else {
        eprintln!("[talus] warning: service is active but the dashboard did not answer yet");
    }
    Ok(())
}

/// Rollback: restore previous binary if present, stop service, remove unit.
fn rollback_install(dest: &std::path::Path) -> Result<()> {
    eprintln!("[talus-installer] Rolling back changes...");

    let prev = dest.with_extension("bin.prev");
    if prev.exists() {
        std::fs::copy(&prev, dest)
            .with_context(|| format!("rollback copy {:?} -> {:?}", prev, dest))?;
        eprintln!("[talus-installer] Restored previous binary from {:?}", prev);
    } else {
        let _ = std::fs::remove_file(dest);
        eprintln!("[talus-installer] Removed new binary (no previous version to restore)");
    }

    // Stop and disable service with timeout (containers may not have systemd)
    let _ = Command::new("timeout")
        .arg("5")
        .arg("systemctl")
        .arg("stop")
        .arg("talus-monitor.service")
        .status();
    let _ = Command::new("timeout")
        .arg("5")
        .arg("systemctl")
        .arg("disable")
        .arg("talus-monitor.service")
        .status();
    let _ = std::fs::remove_file("/etc/systemd/system/talus-monitor.service");
    let _ = Command::new("timeout")
        .arg("5")
        .arg("systemctl")
        .arg("daemon-reload")
        .status();

    eprintln!("[talus-installer] Rollback complete.");
    Ok(())
}

/// Show the last 20 lines of journal output for the service on failure.
fn show_journal_errors() {
    eprintln!();
    eprintln!("─── journalctl -u talus-monitor -n 20 ───");
    if let Ok(output) = Command::new("journalctl")
        .args(["-u", "talus-monitor", "-n", "20", "--no-pager"])
        .output()
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprint!("{stdout}{stderr}");
    } else {
        eprintln!("  (journalctl not available)");
    }
    eprintln!("───");
    eprintln!();
}

/// Check if the dashboard endpoint is responding on 127.0.0.1:8080.
/// Tries an HTTP request; returns false if the endpoint is not reachable
/// (e.g. service still starting, or curl not installed).
fn verify_dashboard() -> bool {
    let port: u16 = 8080;
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), port);
    std::net::TcpStream::connect_timeout(&addr.into(), std::time::Duration::from_secs(3)).is_ok()
}

// ── Rendering helpers ────────────────────────────────────────────────────────

fn char_idx_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

fn styled_block(title: &'static str, color: PackedRgba) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color).attrs(StyleFlags::BOLD))
        .title(title)
        .title_alignment(Alignment::Center)
}

fn set_cursor(f: &mut Frame, x: u16, y: u16) {
    f.set_cursor(Some((x, y)));
    f.set_cursor_visible(true);
}

// ──── Rendering ───────────────────────────────────────────────────────────────

fn render_welcome(f: &mut Frame, area: Rect) {
    let block = styled_block(" Talus Installer ", CYAN);
    block.render(area, f);

    let inner = block.inner(area);
    let chunks = Flex::vertical()
        .alignment(LayoutAlignment::Center)
        .constraints([
            Constraint::Fixed(1),
            Constraint::Fixed(11),
            Constraint::Fixed(2),
        ])
        .split(inner);

    let body = Paragraph::new(Text::from_lines(vec![
        Line::raw(""),
        Line::from_spans(vec![Span::styled(
            "T A L U S",
            Style::new().fg(CYAN).attrs(StyleFlags::BOLD),
        )]),
        Line::from_spans(vec![Span::styled(
            "endpoint security, installed in one pass",
            Style::new().fg(DIM),
        )]),
        Line::raw(""),
        Line::raw("This will install the monitor, register a systemd service,"),
        Line::raw("activate your license, and verify the dashboard."),
        Line::raw(""),
        Line::from_spans(vec![
            Span::raw("Needs: "),
            Span::styled("root", Style::new().fg(FG)),
            Span::raw(" · "),
            Span::styled("Linux >= 5.8", Style::new().fg(FG)),
            Span::raw(" · a license key or trial mode"),
        ]),
        Line::raw(""),
        Line::from_spans(vec![
            Span::raw("[ "),
            Span::styled("Enter", Style::new().fg(YELLOW)),
            Span::raw(" ]  Begin      [ "),
            Span::styled("q", Style::new().fg(YELLOW)),
            Span::raw(" ]  Quit"),
        ]),
    ]))
    .alignment(Alignment::Center)
    .style(Style::new().fg(FG));
    body.render(chunks[1], f);
}

fn render_system_check(f: &mut Frame, area: Rect, app: &Installer) {
    let block = styled_block(" System Check ", CYAN);
    block.render(area, f);

    let inner = block.inner(area);
    let passed = app.checks.iter().filter(|c| c.passed).count();
    let all_ok = passed == app.checks.len();
    let summary_style = if all_ok {
        Style::new().fg(GREEN)
    } else {
        Style::new().fg(YELLOW)
    };

    let mut items: Vec<Line<'static>> = vec![
        Line::from_spans(vec![Span::styled(
            format!("{passed}/{} checks passed", app.checks.len()),
            summary_style.attrs(StyleFlags::BOLD),
        )]),
        Line::raw(""),
    ];
    for c in &app.checks {
        let style = if c.passed {
            Style::new().fg(GREEN)
        } else {
            Style::new().fg(RED)
        };
        items.push(Line::from_spans(vec![
            Span::raw("  "),
            Span::styled(if c.passed { "✓" } else { "✗" }, style),
            Span::raw(format!(" {}", c.label)),
        ]));
        items.push(Line::from_spans(vec![Span::raw(format!(
            "    {}",
            c.detail
        ))
        .with_style(Style::new().fg(DIM))]));
    }

    let content = Paragraph::new(Text::from_lines(items))
        .alignment(Alignment::Left)
        .style(Style::new().fg(FG));
    content.render(inner, f);

    if let Some(notice) = &app.notice {
        Paragraph::new(Line::from_spans(vec![Span::styled(
            notice.as_str(),
            Style::new().fg(RED),
        )]))
        .alignment(Alignment::Center)
        .render(Rect::new(area.left(), area.bottom() - 3, area.width, 1), f);
    }

    let footer = Paragraph::new(Line::from_spans(vec![
        Span::raw("[ "),
        Span::styled("Enter", Style::new().fg(YELLOW)),
        Span::raw(" ] Continue  [ "),
        Span::styled("Backspace", Style::new().fg(YELLOW)),
        Span::raw(" ] Back  [ "),
        Span::styled("q", Style::new().fg(YELLOW)),
        Span::raw(" ] Quit"),
    ]))
    .style(Style::new().fg(DIM))
    .alignment(Alignment::Center);
    footer.render(Rect::new(area.left(), area.bottom() - 2, area.width, 1), f);
}

fn render_license_input(f: &mut Frame, area: Rect, app: &Installer) {
    let block = styled_block(" License Activation ", CYAN);
    block.render(area, f);

    let inner = block.inner(area);

    let chunks = Flex::vertical()
        .constraints([
            Constraint::Fixed(4),
            Constraint::Fixed(5),
            Constraint::Min(0),
        ])
        .split(inner);

    // Status line
    let status_style = match &app.license_status {
        LicenseStatus::Idle => Style::new().fg(FG),
        LicenseStatus::Verifying => Style::new().fg(YELLOW),
        LicenseStatus::Activated { .. } => Style::new().fg(GREEN),
        LicenseStatus::Error(_) => Style::new().fg(RED),
    };

    let status_text = match &app.license_status {
        LicenseStatus::Idle => "Paste your Talus Enterprise license key below.".to_string(),
        LicenseStatus::Verifying => "Validating and activating license...".to_string(),
        LicenseStatus::Activated { license_id, org } => {
            let base = format!("Activated: {license_id}");
            if let Some(o) = org {
                format!("{base} (org: {o})")
            } else {
                base
            }
        }
        LicenseStatus::Error(e) => e.to_string(),
    };

    let status = Paragraph::new(Line::from_spans(vec![Span::styled(
        status_text.as_str(),
        status_style,
    )]))
    .alignment(Alignment::Center);
    status.render(chunks[0], f);

    // Input box
    let input_block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(YELLOW));

    let input_area = input_block.inner(chunks[1]);
    input_block.render(chunks[1], f);

    // Render input text with cursor
    let input_str = &app.license_input;
    let cursor_pos = char_idx_to_byte_idx(input_str, app.license_cursor);
    let (before, after) = input_str.split_at(cursor_pos);

    let input_par = Paragraph::new(Line::from_spans(vec![
        Span::raw(before),
        Span::styled("|", Style::new().fg(CYAN).attrs(StyleFlags::BLINK)),
        Span::raw(after).with_style(Style::new().fg(DIM)),
    ]));
    input_par.render(input_area, f);

    // Set cursor
    set_cursor(
        f,
        input_area.left() + before.chars().count() as u16,
        input_area.top(),
    );

    // Footer
    let footer = Paragraph::new(Line::from_spans(vec![
        Span::raw("[ "),
        Span::styled("Enter", Style::new().fg(YELLOW)),
        Span::raw(" ] Activate  [ Backspace ]  [ "),
        Span::styled("Esc", Style::new().fg(YELLOW)),
        Span::raw(" ] Back  [ Ctrl-Q ] Quit"),
    ]))
    .style(Style::new().fg(DIM))
    .alignment(Alignment::Center);
    footer.render(Rect::new(area.left(), area.bottom() - 2, area.width, 1), f);
}

fn render_install_progress(f: &mut Frame, area: Rect, app: &Installer) {
    let block = styled_block(" Installing Talus ", CYAN);
    block.render(area, f);

    let inner = block.inner(area);
    let total = app.install_steps.len().max(1);
    let done = app.install_steps.iter().filter(|s| s.done).count();
    let width = (inner.width.saturating_sub(12) as usize).clamp(12, 40);
    let filled = done * width / total;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));

    let (icon, icon_style) = if app.install_done && app.install_error.is_some() {
        ("✗", Style::new().fg(RED))
    } else if app.install_done {
        ("✓", Style::new().fg(GREEN))
    } else {
        const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        (
            SPIN[(app.ticks as usize / 2) % SPIN.len()],
            Style::new().fg(CYAN),
        )
    };

    Paragraph::new(Line::from_spans(vec![
        Span::styled(bar, Style::new().fg(CYAN)),
        Span::raw(format!("  {done}/{total} ")),
        Span::styled(icon, icon_style),
    ]))
    .alignment(Alignment::Center)
    .render(Rect::new(inner.left(), inner.top(), inner.width, 1), f);

    let items: Vec<Line<'static>> = app
        .install_steps
        .iter()
        .map(|s| {
            let (icon, style) = if s.error.is_some() {
                ("✗", Style::new().fg(RED))
            } else if s.done {
                ("✓", Style::new().fg(GREEN))
            } else if s.current {
                ("›", Style::new().fg(YELLOW))
            } else {
                ("·", Style::new().fg(DIM))
            };
            Line::from_spans(vec![
                Span::raw("  "),
                Span::styled(icon, style),
                Span::raw(format!(" {}", s.label)).with_style(style),
            ])
        })
        .collect();

    let steps_area = Rect::new(
        inner.left(),
        inner.top() + 2,
        inner.width,
        inner.height.saturating_sub(4),
    );
    Paragraph::new(Text::from_lines(items))
        .alignment(Alignment::Left)
        .style(Style::new().fg(FG))
        .render(steps_area, f);

    if let Some(err) = &app.install_error {
        Paragraph::new(Line::from_spans(vec![Span::styled(
            err.lines().next().unwrap_or_default(),
            Style::new().fg(RED),
        )]))
        .alignment(Alignment::Center)
        .render(
            Rect::new(inner.left(), inner.bottom() - 2, inner.width, 1),
            f,
        );
    }

    let footer = if app.install_done && app.install_error.is_none() {
        Line::from_spans(vec![
            Span::raw("[ "),
            Span::styled("Enter", Style::new().fg(YELLOW)),
            Span::raw(" ] Continue   [ "),
            Span::styled("q", Style::new().fg(YELLOW)),
            Span::raw(" ] Quit"),
        ])
    } else {
        Line::raw(if app.install_done {
            "Installation failed — press q to exit"
        } else {
            "This usually takes a few seconds."
        })
    };
    Paragraph::new(footer)
        .style(Style::new().fg(DIM))
        .alignment(Alignment::Center)
        .render(Rect::new(area.left(), area.bottom() - 1, area.width, 1), f);
}

fn render_complete(f: &mut Frame, area: Rect, app: &Installer) {
    let block = styled_block(" Installation Complete ", GREEN);
    block.render(area, f);

    let inner = block.inner(area);
    let chunks = Flex::vertical()
        .alignment(LayoutAlignment::Center)
        .constraints([
            Constraint::Fixed(1),
            Constraint::Min(0),
            Constraint::Fixed(2),
        ])
        .split(inner);

    let mut lines = vec![
        Line::raw(""),
        Line::from_spans(vec![Span::styled(
            "Talus Enterprise is installed and running.",
            Style::new().fg(GREEN).attrs(StyleFlags::BOLD),
        )]),
        Line::raw(""),
        Line::from_spans(vec![
            Span::raw("Dashboard   "),
            Span::styled("https://127.0.0.1:8080/", Style::new().fg(CYAN)),
        ]),
        Line::from_spans(vec![
            Span::raw("Metrics     "),
            Span::styled(
                "curl -sk https://127.0.0.1:8080/metrics",
                Style::new().fg(CYAN),
            ),
        ]),
        Line::from_spans(vec![
            Span::raw("Logs        "),
            Span::styled("journalctl -fu talus-monitor", Style::new().fg(CYAN)),
        ]),
        Line::raw(""),
    ];

    match &app.license_status {
        LicenseStatus::Activated { license_id, org } => lines.push(Line::from_spans(vec![
            Span::raw("License     "),
            Span::styled(license_id.as_str(), Style::new().fg(FG)),
            Span::raw(match org {
                Some(o) => format!(" ({o})"),
                None => String::new(),
            }),
        ])),
        _ => lines.push(Line::from_spans(vec![
            Span::raw("License     "),
            Span::styled("trial mode", Style::new().fg(YELLOW)),
        ])),
    }
    lines.push(Line::raw(""));
    lines.push(Line::from_spans(vec![
        Span::raw("Commands    "),
        Span::styled("talus license show", Style::new().fg(FG)),
        Span::raw("  ·  "),
        Span::styled("sudo talus-installer --uninstall", Style::new().fg(FG)),
    ]));
    lines.push(Line::raw(""));
    lines.push(Line::from_spans(vec![
        Span::raw("[ "),
        Span::styled("Enter", Style::new().fg(YELLOW)),
        Span::raw(" / "),
        Span::styled("q", Style::new().fg(YELLOW)),
        Span::raw(" ] Exit"),
    ]));

    Paragraph::new(Text::from_lines(lines))
        .style(Style::new().fg(FG))
        .alignment(Alignment::Center)
        .render(chunks[1], f);
}

// ── Non-interactive install ──────────────────────────────────────────────────

/// Non-interactive installer: --no-tui mode.
/// Builds (if needed), installs, and optionally activates license.
fn run_install_non_interactive(
    binary_override: Option<PathBuf>,
    license_key: Option<String>,
    skip_license: bool,
    is_root: bool,
    build_from_source: bool,
    source_dir: Option<PathBuf>,
) -> Result<()> {
    let src = if build_from_source {
        let dir = source_dir
            .ok_or_else(|| anyhow!("--build-from-source requires --source-dir <PATH>"))?;
        println!("Building from {}...", dir.display());
        build_talus_from_source(&dir)?
    } else {
        binary_source(&binary_override, false, &source_dir)?
    };
    println!("Binary: {}", src.display());
    println!();

    if !is_root {
        println!("Root is required to write /usr/local/bin and the systemd unit.");
        println!("Re-run with:");
        if skip_license {
            println!("  sudo talus-installer --no-tui --skip-license");
        } else {
            println!("  sudo talus-installer --no-tui --license-key-stdin < key.txt");
        }
        return Ok(());
    }

    if skip_license {
        println!("License: skipped (trial mode)");
    } else if has_valid_license() {
        if let Ok(Some(cache)) = license::LicenseCache::load() {
            println!(
                "License: {} (fingerprint {})",
                cache.payload.license_id,
                license::key_fingerprint(&cache.key)
            );
        }
    } else if let Some(key) = license_key.as_deref() {
        println!(
            "Activating license (fingerprint {})...",
            license::key_fingerprint(key)
        );
        let cache = license::activate_license(key).map_err(|e| {
            anyhow!("license activation failed: {e}\nUse --skip-license to install in trial mode.")
        })?;
        println!("License: {}", cache.payload.license_id);
    } else {
        return Err(anyhow!(
            "no license key — use --license-key-stdin, TALUS_LICENSE_KEY_FILE, or --skip-license"
        ));
    }
    println!();

    let mut steps = default_steps();
    let mut last = usize::MAX;
    let mut changed = |s: &[InstallStep]| {
        if let Some((i, step)) = s.iter().enumerate().find(|(_, st)| st.current) {
            if i != last {
                last = i;
                println!("[{}/{}] {}", i + 1, s.len(), step.label);
            }
        }
    };

    perform_install(&Some(src), skip_license, &mut steps, &mut changed)?;

    println!();
    println!("Talus Enterprise installed and running.");
    println!("  Dashboard: https://127.0.0.1:8080/ (self-signed certificate)");
    println!("  Logs:      journalctl -fu talus-monitor");
    println!("  Remove:    sudo talus-installer --uninstall");
    Ok(())
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--uninstall") {
        let dry_run = args.iter().any(|a| a == "--dry-run");
        if unsafe { libc::getuid() } != 0 && !dry_run {
            bail!("uninstall needs root: sudo talus-installer --uninstall");
        }
        return uninstall(dry_run);
    }

    if args.iter().any(|a| a == "--dry-run") {
        bail!("--dry-run is only valid with --uninstall");
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("talus-installer {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("talus-installer — TUI installer for Talus Enterprise");
        println!();
        println!("Usage: sudo talus-installer [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --no-tui                        Non-interactive mode (no terminal UI)");
        println!("  --skip-license                  Skip license activation (trial mode)");
        println!("  --license-key <KEY>             Activate license non-interactively (deprecated, use --license-key-stdin)");
        println!("  --license-key-stdin             Read license key from stdin (secure, not visible in `ps`)");
        println!("  --binary <PATH>                 Override binary location");
        println!("  --build-from-source --source-dir <PATH>  Build from source");
        println!("  --uninstall                     Remove Talus from the system");
        println!("  --uninstall --dry-run           Show what uninstall would remove");
        println!("  --version, -V                   Show version");
        println!("  --help, -h                      Show this help");
        println!();
        println!("Environment:");
        println!("  TALUS_LICENSE_KEY_FILE          Path to license key file (0600)");
        println!("  TALUS_LICENSE_SERVER            Override license server URL (HTTPS only)");
        println!("  TALUS_LICENSE_SERVER_FAILOVER   Comma-separated failover servers");
        return Ok(());
    }

    let mut binary_override: Option<PathBuf> = None;
    let mut license_key: Option<String> = None;
    let mut license_key_stdin: bool = false;
    let mut skip_license: bool = false;
    let mut no_tui: bool = false;
    let mut build_from_source: bool = false;
    let mut source_dir: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" => {
                if let Some(path) = args.get(i + 1) {
                    binary_override = Some(PathBuf::from(path));
                    i += 1;
                }
            }
            "--license-key" => {
                // Deprecated: visible in `ps`. Warn the user.
                eprintln!("talus-installer: WARNING: --license-key is visible in `ps`; use --license-key-stdin instead");
                // Still accept but don't log the key value
                if let Some(key) = args.get(i + 1) {
                    license_key = Some(key.clone());
                    i += 1;
                }
            }
            "--license-key-stdin" => {
                license_key_stdin = true;
            }
            "--skip-license" => {
                skip_license = true;
            }
            "--no-tui" => {
                no_tui = true;
            }
            "--build-from-source" => {
                build_from_source = true;
            }
            "--source-dir" => {
                if let Some(path) = args.get(i + 1) {
                    source_dir = Some(PathBuf::from(path));
                    i += 1;
                }
            }
            other if other.starts_with('-') => {
                bail!("unknown option: {other} (see --help)");
            }
            _ => {}
        }
        i += 1;
    }

    // Read license key from stdin if requested
    if license_key_stdin {
        use std::io::Read;
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read license key from stdin")?;
        let key = input.trim().to_string();
        if key.is_empty() {
            eprintln!("talus-installer: no license key received on stdin");
        } else {
            license_key = Some(key);
        }
    }

    // Read license key from file if TALUS_LICENSE_KEY_FILE is set
    if license_key.is_none() {
        if let Ok(file_path) = std::env::var("TALUS_LICENSE_KEY_FILE") {
            let path = PathBuf::from(&file_path);
            // Verify file permissions are 0600 (owner-only)
            if let Ok(metadata) = std::fs::metadata(&path) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(anyhow!(
                        "license key file must be 0600 (owner-only read), \
                         currently {:o} — run: chmod 600 {}",
                        mode & 0o777,
                        file_path
                    ));
                }
            }
            let key = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read license key file: {file_path}"))?;
            let key = key.trim().to_string();
            if !key.is_empty() {
                license_key = Some(key);
            }
        }
    }

    // Root check — warn if not root, but still proceed (build + license can work without root)
    let is_root = unsafe { libc::getuid() } == 0;
    if !is_root {
        eprintln!("talus-installer: not running as root — system install needs sudo");
    }

    // Non-interactive mode: --license-key or --skip-license
    if no_tui {
        return run_install_non_interactive(
            binary_override,
            license_key,
            skip_license,
            is_root,
            build_from_source,
            source_dir,
        );
    }

    let model = Installer::new(license_key, skip_license);
    App::new(model)
        .screen_mode(ScreenMode::AltScreen)
        .with_mouse()
        .with_budget(FrameBudgetConfig::relaxed())
        .run()
        .map_err(|e| anyhow!("TUI error: {e}"))
}

fn uninstall(dry_run: bool) -> Result<()> {
    if dry_run {
        println!("=== DRY RUN — no changes will be made ===");
        println!("Would stop and disable: talus-monitor.service");
        println!("Would remove: /etc/systemd/system/talus-monitor.service");
        println!("Would run: systemctl daemon-reload");
        println!("Would remove: /usr/local/bin/talus-monitor-enterprise");
        println!("Would remove: /usr/local/bin/talus-monitor-enterprise.bin.prev");
        println!("Would remove: /usr/local/bin/talus-monitor-enterprise.bin.new");
        println!("Would remove: /usr/local/bin/talus");
        if let Some(config) = dirs::config_dir() {
            println!("Would remove: {}/talus/", config.display());
        }
        println!("=== End dry run ===");
        return Ok(());
    }

    println!("Uninstalling Talus Enterprise...");

    // Use a short timeout per systemctl call so a broken/hung systemd
    // (common in containers) doesn't stall the entire uninstall.
    let run_systemctl = |args: &[&str]| {
        let _ = Command::new("timeout")
            .arg("5")
            .arg("systemctl")
            .args(args)
            .status();
    };

    run_systemctl(&["stop", "talus-monitor.service"]);
    run_systemctl(&["disable", "talus-monitor.service"]);
    let _ = std::fs::remove_file("/etc/systemd/system/talus-monitor.service");
    run_systemctl(&["daemon-reload"]);
    let _ = std::fs::remove_file("/usr/local/bin/talus-monitor-enterprise");
    let _ = std::fs::remove_file("/usr/local/bin/talus-monitor-enterprise.bin.prev");
    let _ = std::fs::remove_file("/usr/local/bin/talus-monitor-enterprise.bin.new");
    let _ = std::fs::remove_file("/usr/local/bin/talus");
    let _ = std::fs::remove_dir_all(
        dirs::config_dir()
            .map(|d| d.join("talus"))
            .unwrap_or_default(),
    );

    println!("Talus Enterprise uninstalled.");
    Ok(())
}
