#![warn(missing_docs)]
//! Talus Process Monitor — eBPF-based endpoint security agent.
//!
//! Traces execve, openat, connect, and other syscalls via eBPF tracepoints,
//! scores per-process file-open rates in real-time, and terminates offending
//! processes when a heuristic verdict fires.

// The detection engine is a library as well as a binary, so the paid modules can
// be built from a private crate that depends on this one. `lib.rs` owns the
// module declarations; `main.rs` only adds what the binary needs.
use crate::{license, sandbox, storage, watchdog};

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::monitor::{Kind, Monitor, Output, Responder};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

/// What a build contributes beyond the detector.
///
/// The CLI is one implementation, not two. Duplicating a thousand lines into the
/// private crate would guarantee the two drift apart within one release, and the
/// paid half is supposed to be a small addition rather than a fork. So the
/// shared code asks here instead: the MIT build passes nothing, and
/// `NoResponse` plus an empty sink list is what every unlisted capability
/// resolves to.
/// Derived so that the observing build is the default, and adding a third
/// capability later cannot silently make it act by default. A hand-written
/// `Default` would have been the same code today and a trap the day somebody
/// added a field.
#[derive(Default)]
pub struct Hooks {
    /// Installed on the monitor. Without it, verdicts are reported and nothing
    /// happens.
    pub responder: Option<Box<dyn Responder>>,
    /// Registers the SIEM destinations on the pipeline. Without it, only the
    /// JSON and plain output have somewhere to go.
    pub sinks: Option<fn(&mut storage::StoragePipeline)>,
}

use serde_json::json;

static QUIT: AtomicBool = AtomicBool::new(false);

/// Where the compiled eBPF object is looked for when an explicit `--bpf` was
/// not given and the embedded object is not being used.
///
/// Note what this is not: a release binary embeds the object with
/// `include_bytes!`, and `resolve_bpf_path` returns `<embedded>` before
/// reaching this list. These paths only matter for a build from source that
/// wants to load the object from disk instead.
///
/// They are checked with `Path::exists`, which does not expand globs. A
/// `bpfel-unknown-none/*/build/...` pattern here would silently never match,
/// which is why none is written: the real object path carries a hash suffix
/// that changes with the toolchain, and a list of literals cannot track it.
/// Resolving that properly means walking the directory, not listing more
/// strings.
const BPF_CANDIDATES: &[&str] = &[
    "target/bpfel-unknown-none/release/process-monitor-ebpf",
    "target/release/process-monitor-ebpf",
    "process-monitor-ebpf/target/bpfel-unknown-none/release/process-monitor-ebpf",
    "/usr/local/lib/talus/process-monitor-ebpf",
];

#[derive(Parser)]
#[command(
    name = "talus",
    version,
    about = "eBPF-based endpoint security agent for Linux",
    long_about = "Talus is an endpoint security agent for Linux. It hooks syscalls at the\n\
                  kernel level via eBPF tracepoints and scores per-process file-open\n\
                  rates in real time, raising a verdict when a process does something\n\
                  no ordinary program does.\n\n\
                  This build reports. It has no code that can terminate a process, so\n\
                  a verdict here is always reported as unacted - that is what the\n\
                  output says, and it is not a placeholder.\n\n\
                  The response path, the web dashboard and the SIEM exporters are a\n\
                  separate build. See NOTICE in the repository for why the split is\n\
                  a boundary of distribution rather than a licence flag."
)]
/// Command-line surface. The fields are private and filled by clap; both
/// builds share this one definition, so they cannot disagree about a flag.
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// License management
    License {
        #[command(subcommand)]
        action: LicenseAction,
    },
    /// Run the eBPF monitor (default command)
    Monitor(MonitorArgs),
}

#[derive(Subcommand)]
enum LicenseAction {
    /// Activate a license key online
    Activate {
        /// The license key string (format: <payload>.<signature>)
        key: String,
    },
    /// Deactivate the current license (release machine binding)
    Deactivate,
    /// Show license information and status
    Show,
    /// Verify the cached license is valid
    Verify,
    /// Display the machine fingerprint (for license binding)
    MachineId,
    /// Export license as JSON (for integration)
    ExportJson,
    /// Transfer license to another machine
    Transfer,
    /// Backup license to a file
    Backup {
        /// Destination file path
        dest: String,
    },
    /// Restore license from a backup file
    Restore {
        /// Source backup file path
        src: String,
    },
    /// Show license audit log
    AuditLog {
        /// Number of entries to show (default: 20)
        #[arg(long, default_value_t = 20)]
        lines: usize,
    },
    /// Verify audit log integrity (hash chain)
    VerifyAudit,
}

#[derive(Parser)]
/// Everything `run_monitor` needs, collected by clap.
pub struct MonitorArgs {
    /// Path to the compiled eBPF program
    #[arg(short, long, value_name = "PATH")]
    bpf: Option<PathBuf>,

    /// Alert when a process opens N+ files within 1 second (0 disables alerts)
    #[arg(long, default_value_t = 50, value_name = "N")]
    alert_threshold: u64,

    /// Newline-delimited JSON output (no TUI)
    #[arg(long)]
    json: bool,

    /// Plain text log output (no TUI)
    #[arg(long, conflicts_with = "json")]
    plain: bool,

    /// Force the TUI even when stdout is not a terminal
    #[arg(long)]
    tui: bool,

    /// Run a 5-second end-to-end self-diagnostic and exit
    #[arg(long, conflicts_with_all = ["json", "plain", "tui"])]
    diagnose: bool,

    /// Run a throughput benchmark: measure events/s for N seconds with synthetic I/O load
    #[arg(long, value_name = "SECS", conflicts_with_all = ["json", "plain", "tui", "diagnose"])]
    benchmark: Option<Option<u64>>,

    /// Only show events matching this extension filter (e.g. "pdf", "enc")
    #[arg(long, value_name = "EXT")]
    filter_ext: Option<String>,

    /// Show top-N files in TUI (default: 8)
    #[arg(long, default_value_t = 8, value_name = "N")]
    top_files: usize,

    /// Start web server with REST API, WebSocket, and dashboard (requires Enterprise license)
    #[arg(long, value_name = "ADDR", default_value = None)]
    web: Option<String>,

    /// Automatically kill processes that trigger alerts — EDR response mode (requires Enterprise license)
    #[arg(long)]
    auto_kill: bool,

    /// Kafka broker address (e.g. localhost:9092) — enables Kafka producer (requires Enterprise license)
    #[arg(long, value_name = "BROKERS", requires = "kafka_topic")]
    kafka_brokers: Option<String>,

    /// Kafka topic name (requires --kafka-brokers)
    #[arg(long, value_name = "TOPIC")]
    kafka_topic: Option<String>,

    /// ClickHouse URL (e.g. http://localhost:8123) — enables ClickHouse storage (requires Enterprise license)
    #[arg(long, value_name = "URL")]
    clickhouse: Option<String>,

    /// MemGraph URL (e.g. http://localhost:7474) — enables process graph (requires Enterprise license)
    #[arg(long, value_name = "URL")]
    memgraph: Option<String>,

    /// Enable the MeMLP neural detection engine (built-in, trains online from live events)
    #[arg(long)]
    memlp: bool,

    /// MeMLP checkpoint path — loads an existing model and saves on shutdown
    /// (default: ~/.local/share/talus/memlp.json when --memlp is set)
    #[arg(long, value_name = "PATH", requires = "memlp")]
    memlp_checkpoint: Option<PathBuf>,
}

/// The one entry point, called by both builds.
///
/// The MIT binary calls this with `Hooks::default()` and gets a detector that
/// observes. The Enterprise binary calls it with a responder and a sink list
/// and gets the same detector with the ability to act. Neither build owns a
/// parser, so the two cannot disagree about what a flag means - which is the
/// failure that a runtime licence gate over a shared codebase invites.
pub fn main_with(hooks: Hooks) -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ── License subcommand — no root required ─────────────────────
        Some(Commands::License { action }) => match action {
            LicenseAction::Activate { key } => {
                license::activate_license(&key)?;
                eprintln!();
                eprintln!("[talus] ✓ License activated. Restart talus to apply.");
                Ok(())
            }
            LicenseAction::Deactivate => license::deactivate_license(),
            LicenseAction::Show => license::show_license_info(),
            LicenseAction::Verify => {
                let cache = license::verify_cached_license()?;
                eprintln!(
                    "[talus] ✓ License {} is valid ({})",
                    cache.payload.license_id, cache.payload.tier
                );
                if let Some(ref org) = cache.payload.organization {
                    eprintln!("[talus]   Organization: {org}");
                }
                let features: Vec<String> =
                    cache.payload.effective_features().into_iter().collect();
                eprintln!("[talus]   Features: {}", features.join(", "));
                Ok(())
            }
            LicenseAction::MachineId => {
                let id = license::generate_machine_id()?;
                println!("Machine ID: {id}");
                Ok(())
            }
            LicenseAction::ExportJson => {
                let json = license::export_license_json()?;
                println!("{json}");
                Ok(())
            }
            LicenseAction::Transfer => license::transfer_license(),
            LicenseAction::Backup { dest } => {
                let cache = license::LicenseCache::load()?
                    .context("no license found — nothing to backup")?;
                let path = std::path::PathBuf::from(&dest);
                cache.backup(&path)?;
                eprintln!("[talus] ✓ License backed up to: {dest}");
                Ok(())
            }
            LicenseAction::Restore { src } => {
                let path = std::path::PathBuf::from(&src);
                let cache = license::LicenseCache::restore(&path)?;
                eprintln!("[talus] ✓ License restored from: {src}");
                eprintln!("[talus]   License ID: {}", cache.payload.license_id);
                eprintln!("[talus]   Tier: {}", cache.payload.tier);
                Ok(())
            }
            LicenseAction::AuditLog { lines } => {
                let entries = license::read_audit_log(lines);
                if entries.is_empty() {
                    println!("No audit log entries found.");
                } else {
                    println!("═══════════════════════════════════════════════════");
                    println!("  LICENSE AUDIT LOG (last {} entries)", entries.len());
                    println!("═══════════════════════════════════════════════════");
                    for entry in &entries {
                        println!("  {entry}");
                    }
                    println!("═══════════════════════════════════════════════════");
                }
                Ok(())
            }
            LicenseAction::VerifyAudit => match license::verify_audit_log() {
                Ok(n) => {
                    println!("═══════════════════════════════════════════════════");
                    println!("  AUDIT LOG INTEGRITY CHECK");
                    println!("═══════════════════════════════════════════════════");
                    println!("  Status:   ✓ VALID");
                    println!("  Entries:  {n} verified, 0 corrupted");
                    println!("  Chain:    intact (hash chain verified)");
                    println!("═══════════════════════════════════════════════════");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("═══════════════════════════════════════════════════");
                    eprintln!("  AUDIT LOG INTEGRITY CHECK");
                    eprintln!("═══════════════════════════════════════════════════");
                    eprintln!("  Status:   ✗ FAILED");
                    eprintln!("  Error:    {e}");
                    eprintln!("═══════════════════════════════════════════════════");
                    bail!("audit log integrity check failed");
                }
            },
        },

        // ── Monitor — default command (requires root) ─────────────────
        Some(Commands::Monitor(args)) => run_monitor(args, hooks),
        None => run_monitor(MonitorArgs::default(), hooks),
    }
}

/// Default MonitorArgs when no subcommand is given (empty struct defaults)
impl Default for MonitorArgs {
    fn default() -> Self {
        Self {
            bpf: None,
            alert_threshold: 50,
            json: false,
            plain: false,
            tui: false,
            diagnose: false,
            benchmark: None,
            filter_ext: None,
            top_files: 8,
            web: None,
            auto_kill: false,
            kafka_brokers: None,
            kafka_topic: None,
            clickhouse: None,
            memgraph: None,
            memlp: false,
            memlp_checkpoint: None,
        }
    }
}

/// Attach, run and shut down the detector.
///
/// `hooks` is what makes this the same function in both builds: a MIT build
/// arrives with no responder and no sinks, and so reports verdicts without
/// acting on them.
pub fn run_monitor(args: MonitorArgs, hooks: Hooks) -> Result<()> {
    // Give the diagnose mode a clear, helpful non-root message before
    // Monitor::start would bail with a generic error.
    // SAFETY: geteuid() is a simple syscall that always succeeds and returns
    // the effective user ID. No pointer dereference, no fallibility.
    if args.diagnose && unsafe { libc::geteuid() } != 0 {
        eprintln!("run with: sudo talus monitor --diagnose");
        return Ok(());
    }

    // ── Initialize license state ─────────────────────────────────────
    let license_state = license::init_license();

    // --auto-kill is accepted and does nothing here. The detector reaches the
    // verdict and reports "no response sent"; the responder that would act is
    // in the private crate. Refusing the flag instead would suggest a licence
    // would help, and it would not.
    // Four flags remain that this build cannot honour. Saying so once is
    // clearer than four license boxes, and it is the truth: a licence would not
    // help, because the code they would enable is in a different repository.
    let enterprise_only: &[(&str, bool)] = &[
        ("--web", args.web.is_some()),
        ("--kafka-brokers", args.kafka_brokers.is_some()),
        ("--clickhouse", args.clickhouse.is_some()),
        ("--memgraph", args.memgraph.is_some()),
    ];
    // Only refuse in a build that has nothing to offer. The same CLI serves the
    // Enterprise binary, which supplies a responder and a sink list; refusing
    // unconditionally would have the commercial build rejecting its own flags,
    // which is what an earlier version of this file did.
    let has_enterprise = hooks.sinks.is_some();
    if let Some((flag, _)) = enterprise_only
        .iter()
        .filter(|_| !has_enterprise)
        .find(|(_, used)| *used)
    {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  ENTERPRISE — NOT IN THIS BUILD                          ║");
        eprintln!("║                                                          ║");
        eprintln!("║  {flag} needs the Enterprise build of Talus.                ║");
        eprintln!("║                                                          ║");
        eprintln!("║  This binary is MIT and contains no dashboard code,      ║");
        eprintln!("║  no Kafka producer, no ClickHouse or MemGraph client.    ║");
        eprintln!("║  A licence key would not change that — the source is not  ║");
        eprintln!("║  in this repository.                                     ║");
        eprintln!("║                                                          ║");
        eprintln!("║  Enterprise:  contact@hartwell-labs.pl                     ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();
        bail!("{flag} is an Enterprise feature");
    }

    let bpf_path = resolve_bpf_path(args.bpf.as_ref())?;
    let monitor =
        Monitor::start(&bpf_path, args.alert_threshold, args.auto_kill).with_context(|| {
            format!(
                "failed to initialize the eBPF monitor using '{}'",
                bpf_path.display()
            )
        })?;
    // Install the responder this build supplied. No hooks means NoResponse,
    // which is the whole point: the MIT build cannot act because nothing was
    // given to act with, rather than because a check refused to let it.
    let mut monitor = monitor;
    if let Some(r) = hooks.responder {
        monitor = monitor.with_responder(r);
    }

    // ── MeMLP neural engine (load checkpoint when given) ──────────────
    if args.memlp {
        let checkpoint = match &args.memlp_checkpoint {
            Some(p) => Some(p.clone()),
            None => Some(
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join(".local/share/talus/memlp.json"),
            ),
        };
        monitor
            .enable_memlp(checkpoint.as_deref())
            .with_context(|| "failed to initialize the MeMLP neural detection engine")?;
    }

    // ── Agent hardening (drop caps, seccomp, Landlock) ──────────────
    // Applied AFTER Monitor::start so aya can use syscalls during init.
    sandbox::apply(&bpf_path)?;

    install_signal_handler();

    // Spawn fail-closed watchdog
    let _watchdog = watchdog::spawn_watchdog();

    let use_tui = args.tui || (!args.json && !args.plain && io::stdout().is_terminal());

    // ── Startup banner ───────────────────────────────────────────────
    let banner_color = if license_state.is_activated {
        "\x1b[32m"
    } else {
        "\x1b[33m"
    };
    // Honest banner (security hardening): a running trial is shown as a
    // trial with its remaining window, not as "Community" with a phantom
    // "Enterprise Trial" organization line.
    let trial_days = crate::license::trial_days_remaining();
    // A key in this build unlocks nothing: the code it would enable is in a
    // private crate. Saying "Enterprise" here would be claiming a capability
    // this binary does not have, which is the one thing the split exists to
    // stop. The key is still shown and still validated — it is the same key
    // the Enterprise build takes — it just does not change this banner.
    let tier_label = if license_state.is_activated {
        format!(
            "{}MIT (key accepted — Enterprise features are in a different build)",
            banner_color
        )
    } else {
        "\x1b[33mMIT\x1b[0m".to_string()
    };

    eprintln!();
    eprintln!("  \x1b[36m╔══════════════════════════════════════════════════╗\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  \x1b[1m⚡ TALUS eBPF ENDPOINT SECURITY AGENT\x1b[0m          \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m╠══════════════════════════════════════════════════╣\x1b[0m");
    eprintln!(
        "  \x1b[36m║\x1b[0m  License:  {:<38} \x1b[36m║\x1b[0m",
        tier_label
    );
    if let Some(ref org) = license_state.organization {
        if trial_days.is_none() {
            eprintln!("  \x1b[36m║\x1b[0m  Org:      {:<38} \x1b[36m║\x1b[0m", org);
        }
    }
    eprintln!(
        "  \x1b[36m║\x1b[0m  eBPF:     {:<38} \x1b[36m║\x1b[0m",
        bpf_path.display()
    );
    eprintln!(
        "  \x1b[36m║\x1b[0m  Threshold: {:<37} \x1b[36m║\x1b[0m",
        format!("{} opens/s", args.alert_threshold)
    );
    if args.memlp {
        eprintln!(
            "  \x1b[36m║\x1b[0m  MeMLP:    {:<38} \x1b[36m║\x1b[0m",
            format!(
                "neural engine ON ({})",
                monitor.memlp_stats().map(|(_, p)| p).unwrap_or(0)
            )
        );
    }
    if args.auto_kill {
        eprintln!("  \x1b[36m║\x1b[0m  \x1b[31mMode:     EDR (auto-kill enabled)\x1b[0m              \x1b[36m║\x1b[0m");
    }
    eprintln!("  \x1b[36m╚══════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();

    // ── Storage pipeline ──────────────────────────────────────────────
    #[allow(unused_mut)]
    let mut pipeline = storage::StoragePipeline::new();
    if let Some(register) = hooks.sinks {
        register(&mut pipeline);
    }

    if let Some(duration) = args.benchmark {
        let secs = duration.unwrap_or(10);
        run_benchmark(&mut monitor, secs)?;
    } else if args.diagnose {
        run_diagnose(&mut monitor)?;
    } else if args.web.is_some() {
        bail!(
            "--web is an Enterprise feature and is not in this build.\n\
             This binary is MIT licensed and contains no dashboard code.\n\
             See LICENSE, or contact contact@hartwell-labs.pl for Enterprise."
        );
    } else if use_tui {
        eprintln!("[talus] TUI mode — q quit, p pause, ? help, Tab switch panel");
        crate::tui::run(monitor, license_state)?;
    } else if args.json {
        run_json(&mut monitor, &pipeline)?;
    } else {
        run_plain(&mut monitor, &pipeline)?;
    }

    eprintln!("[talus] shutdown complete");
    Ok(())
}

/// Decide which eBPF object to load.
///
/// Returns the marker path `<embedded>` when the binary carries its own object,
/// which is the normal case for a release build.
pub fn resolve_bpf_path(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    let mut tried: Vec<String> = Vec::new();

    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.clone());
        }
        bail!(
            "eBPF program not found at '{}' (build it with ./build.sh or install.sh)",
            path.display()
        );
    }

    // 0. The binary embeds its own eBPF object (include_bytes! in monitor.rs) —
    //    this is the normal path for prebuilt release binaries. resolve_bpf_path
    //    only needs to find an on-disk override.
    if explicit.is_none() {
        return Ok(PathBuf::from("<embedded>"));
    }

    // 1. Build tree (CARGO_TARGET_DIR is set by build.sh / install.sh).
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        for sub in [
            "bpfel-unknown-none/bpf/process-monitor-ebpf",
            "bpfel-unknown-none/release/process-monitor-ebpf",
        ] {
            let candidate = PathBuf::from(&*dir).join(sub);
            if candidate.exists() {
                return Ok(candidate);
            }
            tried.push(candidate.display().to_string());
        }
    }

    // 2. Relative to the running binary (checked before user-local installs so a
    //    freshly built tree is preferred over a stale ~/.local copy):
    //    - <root>/target/bpfel-unknown-none/... for <root>/target/release/process-monitor
    //    - <bin>/../lib/talus/...             for ~/.local/bin/process-monitor
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [
                dir.join("../bpfel-unknown-none/bpf/process-monitor-ebpf"),
                dir.join("../bpfel-unknown-none/release/process-monitor-ebpf"),
                dir.join("../lib/talus/process-monitor-ebpf"),
            ] {
                if candidate.exists() {
                    return Ok(candidate);
                }
                tried.push(candidate.display().to_string());
            }
        }
    }

    // 3. User-local install, found through the invoking user's real home.
    //    `sudo` resets $HOME to /root, so derive the home from SUDO_UID (set
    //    by sudo) or the real uid via the passwd database, and also try $HOME.
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        homes.push(PathBuf::from(home));
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        // SAFETY: getuid() is a simple syscall returning the real user ID.
        // No pointers, no fallibility, always succeeds.
        .unwrap_or_else(|| unsafe { libc::getuid() });
    if let Some(dir) = passwd_dir(uid) {
        homes.push(dir);
    }
    for home in homes {
        let candidate = home.join(".local/lib/talus/process-monitor-ebpf");
        if candidate.exists() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }

    // 4. Working-directory-relative candidates and the system install.
    for candidate in BPF_CANDIDATES {
        if Path::new(candidate).exists() {
            return Ok(PathBuf::from(candidate));
        }
        tried.push(candidate.to_string());
    }

    bail!(
        "could not locate the eBPF program; tried: {}. Build it with ./build.sh, \
         install it with install.sh, or pass --bpf PATH",
        tried.join(", ")
    )
}

/// Resolves the home directory for `uid` from the passwd database.
///
/// Used to find user-local installs when running under `sudo` (where `$HOME`
/// points at the target user's home, not the invoking user's).
///
/// # Safety
///
/// Calls `getpwuid_r` which requires:
/// - `pwd` is a valid mutable pointer to a `libc::passwd` (zeroed)
/// - `buf` is a valid mutable buffer of adequate size (4096 bytes)
/// - `result` is a valid mutable pointer to a pointer
///
/// All invariants are satisfied by the local variables above.
/// On success, `pwd.pw_dir` is dereferenced only after checking it is non-null.
fn passwd_dir(uid: u32) -> Option<PathBuf> {
    // SAFETY: getpwuid_r is a POSIX reentrant function. We pass valid pointers
    // to zeroed structs and a 4096-byte buffer, which is sufficient for passwd
    // entries. The result pointer is checked for null before dereferencing pw_dir.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() && !pwd.pw_dir.is_null() {
            let dir = std::ffi::CStr::from_ptr(pwd.pw_dir)
                .to_string_lossy()
                .into_owned();
            Some(PathBuf::from(dir))
        } else {
            None
        }
    }
}

/// End-to-end self-diagnostic: verifies the environment, loads + attaches the
/// eBPF programs, then listens for events for 5 seconds and reports counts.
pub fn run_diagnose(monitor: &mut Monitor) -> Result<()> {
    println!("=== Talus Process Monitor diagnostic ===");
    println!();
    println!("OK: running as root");

    for (cat, name) in [
        ("syscalls", "sys_enter_execve"),
        ("syscalls", "sys_enter_openat"),
    ] {
        let id_path = Path::new("/sys/kernel/tracing/events")
            .join(cat)
            .join(name)
            .join("id");
        match std::fs::read_to_string(&id_path) {
            Ok(id) => println!("OK: tracepoint {cat}/{name} id={}", id.trim()),
            Err(e) => println!("FAIL: cannot read {}: {e}", id_path.display()),
        }
    }

    println!();
    println!("Loading and attaching eBPF programs...");
    println!("Listening for 5 seconds; generate events by running, in another terminal:");
    println!("    ls -la /");
    println!();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last_report = std::time::Instant::now();
    let mut execs = 0u64;
    let mut opens = 0u64;
    let mut alerts = 0u64;
    while std::time::Instant::now() < deadline {
        for output in monitor.poll() {
            match output {
                Output::Event(ev) => match ev.kind {
                    Kind::Exec => execs += 1,
                    Kind::Open => opens += 1,
                    Kind::Connect
                    | Kind::Accept
                    | Kind::SendTo
                    | Kind::RecvFrom
                    | Kind::Mkdir
                    | Kind::Unlink
                    | Kind::Kill
                    | Kind::Chmod => {}
                },
                Output::Alert(_) => alerts += 1,
                Output::Action(_) => {}
            }
        }
        if last_report.elapsed() >= Duration::from_secs(1) {
            last_report = std::time::Instant::now();
            println!(
                "  t-{:.0}s  exec={execs}  open={opens}  alerts={alerts}  lost={}",
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_secs_f32(),
                monitor.total_lost
            );
        }
        thread::sleep(Duration::from_millis(50));
    }

    println!();
    println!("=== RESULT ===");
    println!("exec events: {execs}");
    println!("open events: {opens}");
    println!("alerts:      {alerts}");
    println!("lost:        {}", monitor.total_lost);
    if execs + opens > 0 {
        println!("SUCCESS: events are flowing through the eBPF pipeline.");
    } else {
        println!("NO EVENTS RECEIVED within the diagnostic window.");
        println!("Check the [talus] stderr lines above for attach/load errors.");
    }
    Ok(())
}

/// Run a throughput benchmark for the specified duration.
///
/// Spawns a synthetic I/O generator (touch + read files) in a background
/// thread to create measurable syscall traffic, then counts eBPF events
/// for `secs` seconds and reports events/s, peak events/s, and events by type.
pub fn run_benchmark(monitor: &mut Monitor, secs: u64) -> Result<()> {
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // ── Synthetic I/O generator (multi-threaded) ─────────────────────
    // Spawns one thread per CPU core, each hammering openat via
    // File::open + read to maximize syscall density.
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let io_threads: Vec<_> = (0..num_cpus)
        .map(|tid| {
            let r = r.clone();
            thread::Builder::new()
                .name(format!("bench-io-{tid}"))
                .spawn(move || {
                    let dir = PathBuf::from(format!("/tmp/talus_bench_io_{tid}"));
                    let _ = fs::create_dir_all(&dir);
                    // Pre-create files
                    for j in 0..1024 {
                        let path = dir.join(format!("f{j}"));
                        let _ = fs::write(&path, b"bench");
                    }
                    let mut i = 0u64;
                    while r.load(Ordering::Relaxed) {
                        let path = dir.join(format!("f{}", i & 1023));
                        // File::open triggers openat, read triggers read syscall
                        if let Ok(mut f) = fs::File::open(&path) {
                            let mut buf = [0u8; 64];
                            let _ = std::io::Read::read(&mut f, &mut buf);
                        }
                        i = i.wrapping_add(1);
                    }
                    let _ = fs::remove_dir_all(&dir);
                })
                .expect("failed to spawn I/O thread")
        })
        .collect();

    println!("╔══════════════════════════════════════════════════╗");
    println!("║  TALUS eBPF THROUGHPUT BENCHMARK                ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  Duration:    {secs:>3}s                              ║");
    println!("║  Mode:        synthetic I/O (touch+read)         ║");
    println!("║  Tracepoints: execve, openat + best-effort       ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("Generating synthetic I/O in background...");

    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut total_execs = 0u64;
    let mut total_opens = 0u64;
    let mut total_net = 0u64;
    let mut total_other = 0u64;
    let mut total_events = 0u64;
    let mut peak_eps = 0f64;
    let mut tick_events = 0u64;
    let mut tick_start = std::time::Instant::now();
    let mut samples: Vec<f64> = Vec::new();

    while std::time::Instant::now() < deadline {
        for output in monitor.poll() {
            match output {
                Output::Event(ev) => {
                    total_events += 1;
                    tick_events += 1;
                    match ev.kind {
                        Kind::Exec => total_execs += 1,
                        Kind::Open => total_opens += 1,
                        Kind::Connect | Kind::Accept | Kind::SendTo | Kind::RecvFrom => {
                            total_net += 1
                        }
                        Kind::Mkdir | Kind::Unlink | Kind::Kill | Kind::Chmod => total_other += 1,
                    }
                }
                Output::Alert(_) => {}
                Output::Action(_) => {}
            }
        }

        if tick_start.elapsed() >= Duration::from_secs(1) {
            let elapsed = tick_start.elapsed().as_secs_f64();
            let eps = tick_events as f64 / elapsed;
            samples.push(eps);
            if eps > peak_eps {
                peak_eps = eps;
            }
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_secs_f32();
            println!(
                "  [{:>3}s remaining]  events/s: {eps:>10.0}  peak: {peak_eps:>10.0}  total: {total_events}",
                remaining as u64,
            );
            tick_events = 0;
            tick_start = std::time::Instant::now();
        }

        thread::sleep(Duration::from_millis(10));
    }

    // Stop I/O generators
    running.store(false, Ordering::Relaxed);
    for t in io_threads {
        let _ = t.join();
    }

    println!("  Events lost:       {}", monitor.total_lost);

    // ── Results ──────────────────────────────────────────────────────
    let avg_eps = if !samples.is_empty() {
        samples.iter().sum::<f64>() / samples.len() as f64
    } else {
        0.0
    };
    let p95_idx = (samples.len() as f64 * 0.95) as usize;
    let mut sorted = samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p95_eps = sorted
        .get(p95_idx.min(sorted.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0);

    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  BENCHMARK RESULTS ({secs}s)");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("  Total events:      {total_events}");
    println!("  Events lost:       {}", monitor.total_lost);
    println!();
    println!("  ── Throughput ──────────────────────────────────────");
    println!("  Average events/s:  {avg_eps:>10.0}  (delivered to userspace)");
    println!("  Peak events/s:     {peak_eps:>10.0}");
    println!("  P95 events/s:      {p95_eps:>10.0}");
    let kernel_eps = avg_eps + (monitor.total_lost as f64 / secs as f64);
    println!("  Kernel-level est:  {kernel_eps:>10.0}  (delivered + lost)");
    println!();
    println!("  ── Breakdown ───────────────────────────────────────");
    println!("  Exec events:       {total_execs}");
    println!("  Open events:       {total_opens}");
    println!("  Network events:    {total_net}");
    println!("  Other events:      {total_other}");
    println!();
    let (lcount, p50, p95, p99, lmax) = monitor.latency.summary();
    println!("  ── Delivery latency (kernel → userspace) ──────────");
    if lcount > 0 {
        println!("  Samples:           {lcount}");
        println!("  p50:               {p50:>8} µs");
        println!("  p95:               {p95:>8} µs");
        println!("  p99:               {p99:>8} µs");
        println!("  Max:               {lmax:>8} µs");
    } else {
        println!("  (no latency samples collected)");
    }
    println!(
        "  Alerts:            {}",
        monitor.total_events - total_events + total_events
    );
    println!();
    if avg_eps >= 500_000.0 {
        println!("  ✓ Delivered throughput ≥ 500,000 events/s — PASS");
    } else if kernel_eps >= 500_000.0 {
        println!(
            "  ~ Kernel-level throughput ≥ 500,000 events/s — perf buffer limited to {:.0} delivered",
            avg_eps
        );
    } else {
        println!(
            "  ✗ Throughput {:.0} events/s — below 500,000 target",
            avg_eps
        );
    }
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}

/// Install signal handlers for graceful shutdown.
///
/// # Safety
///
/// `handle_signal` is an `extern "C"` function with the correct signature
/// for `sighandler_t`. The cast from function pointer to `*const ()` to
/// `sighandler_t` is the standard pattern for POSIX signal handlers.
/// No heap memory or references are involved.
fn install_signal_handler() {
    // SAFETY: handle_signal is a valid extern "C" function matching the
    // sighandler_t signature. The function pointer cast is the canonical
    // POSIX pattern. signal() itself is safe to call at program startup.
    unsafe {
        let handler = handle_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

extern "C" fn handle_signal(_: libc::c_int) {
    QUIT.store(true, Ordering::SeqCst);
}

/// Stream events as newline-delimited JSON until interrupted.
pub fn run_json(monitor: &mut Monitor, pipeline: &storage::StoragePipeline) -> Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    loop {
        let outputs: Vec<Output> = monitor.poll().into_iter().collect();
        for output in &outputs {
            match output {
                Output::Event(ev) => {
                    let kind = match ev.kind {
                        Kind::Exec => "exec",
                        Kind::Open => "open",
                        Kind::Connect => "connect",
                        Kind::Accept => "accept",
                        Kind::SendTo => "sendto",
                        Kind::RecvFrom => "recvfrom",
                        Kind::Mkdir => "mkdir",
                        Kind::Unlink => "unlink",
                        Kind::Kill => "kill",
                        Kind::Chmod => "chmod",
                    };
                    let value = json!({
                        "ts": ev.ts,
                        "type": kind,
                        "pid": ev.pid,
                        "uid": ev.uid,
                        "comm": ev.comm,
                        "file": ev.file,
                    });
                    writeln!(out, "{value}")?;
                }
                Output::Alert(al) => {
                    let value = json!({
                        "ts": al.ts,
                        "type": "alert",
                        "pid": al.pid,
                        "uid": al.uid,
                        "comm": al.comm,
                        "opens_in_1s": al.opens,
                        "memlp": al.memlp,
                    });
                    writeln!(out, "{value}")?;
                }
                Output::Action(act) => {
                    let value = json!({
                        "ts": act.ts,
                        "type": "response",
                        "pid": act.pid,
                        "comm": act.comm,
                        "action": act.action,
                        "success": act.success,
                    });
                    writeln!(out, "{value}")?;
                }
            }
        }
        pipeline.forward_outputs(&outputs);
        out.flush()?;
        if QUIT.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Stream events as human-readable lines, filtering known-noisy processes.
pub fn run_plain(monitor: &mut Monitor, pipeline: &storage::StoragePipeline) -> Result<()> {
    use colored::Colorize;
    const NOISY: &[&str] = &[
        "freebuff",
        "waybar",
        "upowerd",
        "mutter",
        "Xwayland",
        "hyprland",
        "sway",
        "fuzzel",
        "wlsunset",
        "pipewire",
        "wireplumber",
        "dbus-daemon",
        "systemd-resolve",
        "systemd-network",
        "dunst",
        "mako",
    ];
    loop {
        let outputs: Vec<Output> = monitor.poll().into_iter().collect();
        pipeline.forward_outputs(&outputs);
        for output in outputs {
            match output {
                Output::Event(ev) => {
                    if NOISY.contains(&ev.comm.as_str()) {
                        continue;
                    }
                    match ev.kind {
                        Kind::Exec => {
                            println!(
                                "{} {} [{}] {} by uid {}",
                                ev.ts,
                                "EXEC".green().bold(),
                                ev.pid,
                                ev.comm.bold(),
                                ev.uid
                            );
                        }
                        Kind::Open => {
                            if let Some(file) = ev.file {
                                println!(
                                    "{} {} [{}] {} -> {}",
                                    ev.ts,
                                    "OPEN".blue().bold(),
                                    ev.pid,
                                    ev.comm.dimmed(),
                                    file.dimmed()
                                );
                            }
                        }
                        Kind::Connect | Kind::Accept | Kind::SendTo | Kind::RecvFrom => {
                            let kind_str = format!("{:?}", ev.kind).to_uppercase();
                            let addr = ev.file.as_deref().unwrap_or("?");
                            println!(
                                "{} {} [{}] {} -> {}",
                                ev.ts,
                                kind_str.magenta().bold(),
                                ev.pid,
                                ev.comm.dimmed(),
                                addr.dimmed()
                            );
                        }
                        Kind::Mkdir | Kind::Unlink | Kind::Chmod => {
                            let kind_str = format!("{:?}", ev.kind).to_uppercase();
                            let path = ev.file.as_deref().unwrap_or("?");
                            println!(
                                "{} {} [{}] {} -> {}",
                                ev.ts,
                                kind_str.yellow().bold(),
                                ev.pid,
                                ev.comm.dimmed(),
                                path.dimmed()
                            );
                        }
                        Kind::Kill => {
                            let details = ev.argv.as_deref().unwrap_or("?");
                            println!(
                                "{} {} [{}] {} -> {}",
                                ev.ts,
                                "KILL".red().bold(),
                                ev.pid,
                                ev.comm.bold(),
                                details.dimmed()
                            );
                        }
                    }
                }
                Output::Alert(al) => {
                    println!(
                        "{} {} [{}] {} opened {} files in 1s!{}",
                        al.ts,
                        "SUSPICIOUS".yellow().bold(),
                        al.pid,
                        al.comm.bold(),
                        al.opens,
                        al.memlp
                            .map(|m| format!("  [MeMLP {}]", m.summary()))
                            .unwrap_or_default()
                    );
                }
                Output::Action(act) => {
                    let status = if act.success {
                        "OK".green()
                    } else {
                        "FAILED".red()
                    };
                    println!(
                        "{} {} [{}] {} — {}",
                        act.ts,
                        "RESPONSE".red().bold(),
                        act.pid,
                        act.comm.bold(),
                        status
                    );
                }
            }
        }
        if QUIT.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
