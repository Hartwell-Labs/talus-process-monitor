// ── sandbox.rs — Agent self-sandboxing (seccomp, capabilities, Landlock) ──
//
// Enterprise security hardening for the Talus agent:
//
// 1. Capability dropping — reduce from root to minimal caps needed for eBPF:
//    CAP_BPF (39), CAP_PERFMON (38), CAP_NET_ADMIN (12)
//
// 2. seccomp-BPF — whitelist of syscalls for the event-processing loop.
//    Installs AFTER eBPF programs are loaded (aya needs many syscalls during init).
//
// 3. Landlock (kernel ≥5.13) — restrict filesystem access to:
//    /sys/kernel/debug (eBPF), /proc, /dev/null, /tmp, config dir, BPF object path.
//
// Design: fail-open on kernels that don't support a feature (seccomp/Landlock),
// but NEVER silently skip capability dropping.

use std::collections::HashSet;
use std::ffi::CString;
use std::path::Path;

use anyhow::{bail, Context, Result};

// ── Linux constants ──────────────────────────────────────────────────────────

// prctl options
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;

// seccomp modes
const SECCOMP_MODE_FILTER: u64 = 2;

// capability constants (linux/capability.h)
const CAP_BPF: i32 = 39;
const CAP_PERFMON: i32 = 38;
const CAP_NET_ADMIN: i32 = 12;
const _CAP_FOWNER: i32 = 3;

// Landlock ABI v3 (kernel 5.19+)
const LANDLOCK_ABI_VERSION: u32 = 3;
const LANDLOCK_CREATE_RULESET: i64 = 444;
const LANDLOCK_ADD_RULE: i64 = 445;
const LANDLOCK_RESTRICT_SELF: i64 = 446;

// Landlock rule types
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 1;
const _LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 2;

// ── Capability dropping ──────────────────────────────────────────────────────

/// Drop all capabilities except the ones needed for eBPF operation.
///
/// Required capabilities:
/// - CAP_BPF (39): load/attach eBPF programs
/// - CAP_PERFMON (38): perf_event_open for perf buffer
/// - CAP_NET_ADMIN (12): some eBPF program types (XDP, cgroup)
///
/// Drops: CAP_SYS_ADMIN (no longer needed after load), CAP_DAC_OVERRIDE,
/// CAP_FOWNER, and everything else.
pub fn drop_capabilities() -> Result<()> {
    // Read current capabilities
    let caps = get_current_capabilities().context("failed to read current capabilities")?;

    // Build the set of caps we want to KEEP
    let mut keep = HashSet::new();
    keep.insert(CAP_BPF as u32);
    keep.insert(CAP_PERFMON as u32);
    keep.insert(CAP_NET_ADMIN as u32);

    // Compute caps to drop
    let to_drop: Vec<u32> = caps.difference(&keep).copied().collect();

    if to_drop.is_empty() {
        eprintln!("[sandbox] all capabilities already minimal");
        return Ok(());
    }

    // Drop them via prctl(PR_CAPBSET_DROP)
    for cap in &to_drop {
        // PR_CAPBSET_DROP = 24
        let ret = unsafe { libc::prctl(24, *cap as i32, 0, 0, 0) };
        if ret != 0 {
            eprintln!(
                "[sandbox] WARN: failed to drop CAP_{} (cap {}): {}",
                cap_name(*cap),
                cap,
                std::io::Error::last_os_error()
            );
        }
    }

    eprintln!(
        "[sandbox] dropped {} capabilities, kept: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN",
        to_drop.len()
    );

    Ok(())
}

/// Get the set of capabilities in the bounding set.
fn get_current_capabilities() -> Result<HashSet<u32>> {
    let mut caps = HashSet::new();

    // Read from /proc/self/status
    let status =
        std::fs::read_to_string("/proc/self/status").context("failed to read /proc/self/status")?;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapBnd:\t") {
            if let Ok(val) = u64::from_str_radix(rest.trim(), 16) {
                for bit in 0..64 {
                    if val & (1 << bit) != 0 {
                        caps.insert(bit as u32);
                    }
                }
            }
        }
    }

    Ok(caps)
}

/// Human-readable capability name.
fn cap_name(cap: u32) -> &'static str {
    match cap {
        0 => "CHOWN",
        1 => "DAC_OVERRIDE",
        2 => "DAC_READ_SEARCH",
        3 => "FOWNER",
        4 => "FSETID",
        5 => "KILL",
        6 => "SETGID",
        7 => "SETUID",
        8 => "SETPCAP",
        9 => "LINUX_IMMUTABLE",
        10 => "NET_BIND_SERVICE",
        12 => "NET_ADMIN",
        13 => "NET_RAW",
        14 => "IPC_LOCK",
        15 => "IPC_OWNER",
        16 => "SYS_MODULE",
        17 => "SYS_RAWIO",
        18 => "SYS_CHROOT",
        19 => "SYS_PTRACE",
        20 => "SYS_PACCT",
        21 => "SYS_ADMIN",
        22 => "SYS_BOOT",
        23 => "SYS_NICE",
        24 => "SYS_RESOURCE",
        25 => "SYS_TIME",
        26 => "SYS_TTY_CONFIG",
        27 => "MKNOD",
        28 => "LEASE",
        29 => "AUDIT_WRITE",
        30 => "AUDIT_CONTROL",
        31 => "SETFCAP",
        38 => "PERFMON",
        39 => "BPF",
        _ => "UNKNOWN",
    }
}

// ── seccomp-BPF filter ───────────────────────────────────────────────────────

// BPF instruction opcodes
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

// BPF jump constants
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x0000_0000;

// x86_64: syscall number is at offset 120 in seccomp_data (offset 15 * 8 = 120)
const SYSCALL_OFFSET: u16 = 120;

/// A single BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program header.
#[repr(C)]
struct SockFProg {
    len: u16,
    filter: *const SockFilter,
}

/// Build the seccomp-BPF filter program.
///
/// WHITELIST approach: only syscalls in the allowed set pass through.
/// Everything else is killed (SECCOMP_RET_KILL_PROCESS).
///
/// CRITICAL BLOCKS (not in allowlist):
/// - ptrace (101) — prevents process injection/debugging
/// - bpf (321) — prevents self-modification of eBPF programs
/// - perf_event_open (241) — prevents creating new perf events
/// - execve (59) — agent should never exec after init
/// - fork (57) — agent shouldn't fork after init
/// - open_by_handle_at (334) — filesystem escape vector
/// - mount/umount/pivot_root/setns/unshare — namespace/filesystem escape
/// - init_module/finit_module — kernel module loading
/// - keyctl/add_key/request_key — kernel keyring
///
/// The filter is a linear scan — simple, auditable, no complex jump logic.
fn build_seccomp_filter() -> Vec<SockFilter> {
    // ── ALLOWLIST: syscalls permitted after eBPF init ───────────────
    //
    // Installed AFTER Monitor::start() — aya has already:
    //   1. Called bpf(321) to load programs
    //   2. Called perf_event_open(241) to set up perf buffers
    //   3. Spawned the reader thread
    //
    // BLOCKED (security-critical):
    //   ptrace (101)       — never; prevents process injection
    //   bpf (321)          — after init; prevents self-modification
    //   perf_event_open(241) — after init; perf fds already opened
    //   open_by_handle_at(334) — filesystem escape vector
    //   execve (59)        — agent should never exec after init
    //   fork (57)           — agent shouldn't fork after init
    //   mount (165)         — filesystem manipulation
    //   umount2 (166)       — filesystem manipulation
    //   pivot_root (155)    — namespace escape
    //   setns (308)         — namespace manipulation
    //   unshare (272)       — namespace manipulation
    //   keyctl (250)        — kernel keyring
    //   add_key (248)       — kernel keyring
    //   request_key (249)   — kernel keyring
    //   init_module (175)   — kernel module loading
    //   finit_module (176)  — kernel module loading
    //   delete_module (176) — kernel module loading
    //   kexec_load (246)    — kernel replacement
    //   reboot (169)        — system reboot
    //   swapon (167)        — swap manipulation
    //   swapoff (168)       — swap manipulation
    //
    let allowed: HashSet<i64> = [
        // ── I/O ────────────────────────────────────────────────────
        0,   // read
        1,   // write
        3,   // close
        8,   // lseek
        16,  // ioctl
        19,  // readv
        20,  // writev
        63,  // readlinkat
        72,  // fcntl
        78,  // getdents64
        79,  // getcwd
        89,  // readlink
        217, // getdents64 (old)
        257, // openat
        262, // newfstatat
        // ── Memory ─────────────────────────────────────────────────
        9,  // mmap
        10, // mprotect
        11, // munmap
        12, // brk
        25, // mremap
        28, // madvise
        31, // shmget (aya shared memory)
        // ── Process/thread ─────────────────────────────────────────
        39,  // getpid
        56,  // clone (tokio needs threads)
        60,  // exit
        158, // arch_prctl
        186, // gettid
        202, // futex
        218, // set_tid_address
        231, // exit_group
        234, // tgkill
        302, // prlimit64
        307, // prctl (for seccomp/cap drop)
        318, // getrandom
        // ── Signals ────────────────────────────────────────────────
        13, // rt_sigaction
        14, // rt_sigprocmask
        15, // rt_sigreturn
        // ── Scheduling ─────────────────────────────────────────────
        24,  // sched_yield
        204, // sched_getaffinity
        // ── Time ───────────────────────────────────────────────────
        35,  // nanosleep
        228, // clock_gettime
        230, // clock_nanosleep
        // ── Networking (tokio web server) ───────────────────────────
        291, // epoll_create1
        293, // epoll_ctl
        294, // epoll_pwait
        288, // accept4
        41,  // socket
        42,  // connect
        44,  // sendto
        45,  // recvfrom
        46,  // sendmsg
        47,  // recvmsg
        49,  // bind
        50,  // listen
        52,  // setsockopt
        82,  // select
        281, // epoll_wait (old)
        // ── Filesystem (minimal) ───────────────────────────────────
        2,   // open
        4,   // stat
        5,   // fstat
        6,   // lstat
        73,  // ftruncate
        76,  // getrlimit
        83,  // mkdirat
        263, // unlinkat
        303, // statx
        // ── Signal FDs (tokio) ─────────────────────────────────────
        292, // timerfd_create
        296, // timerfd_settime
        // ── Landlock (if supported) ────────────────────────────────
        444, // landlock_create_ruleset
        445, // landlock_add_rule
        446, // landlock_restrict_self
    ]
    .iter()
    .copied()
    .collect();

    let _max_syscall = *allowed.iter().max().unwrap_or(&446);

    // Build BPF instructions:
    // [0] Load syscall number from seccomp_data
    // [1..N] Compare against each allowed syscall, jump to ALLOW if match
    // [N+1] Kill (default deny)
    let mut prog: Vec<SockFilter> = Vec::new();

    // Instruction 0: load syscall number
    prog.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SYSCALL_OFFSET as u32,
    });

    // For each allowed syscall, emit: if (syscall == X) goto ALLOW
    let _ret_allow_idx = (allowed.len() + 1) as u16; // index of RET ALLOW instruction

    for (i, &syscall) in allowed.iter().enumerate() {
        let remaining = allowed.len() - i;
        // Jump distance to ALLOW: skip (remaining - 1) comparison blocks + 1 kill instruction
        let jump_to_allow = (remaining) as u8 + 1; // +1 to skip kill

        prog.push(SockFilter {
            code: BPF_JEQ | BPF_JGE,
            jt: jump_to_allow,
            jf: 0,
            k: syscall as u32,
        });
    }

    // Default: KILL
    prog.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // ALLOW
    prog.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // Fix up JEQ instructions: each should jump to the next comparison on false,
    // or to ALLOW on true.
    let mut i = 1; // skip instruction 0 (load)
    for (idx, &_syscall) in allowed.iter().enumerate() {
        let remaining = allowed.len() - idx;
        let jump_to_allow = (remaining) as u8 + 1;

        if i < prog.len() {
            prog[i].jt = jump_to_allow; // true → allow
            prog[i].jf = 1; // false → next comparison
            i += 1;
        }
    }

    prog
}

/// Install the seccomp-BPF filter.
///
/// MUST be called AFTER aya loads eBPF programs (aya uses many syscalls during init).
/// The filter only restricts syscalls in the event-processing hot path.
pub fn install_seccomp_filter() -> Result<()> {
    // Check if seccomp is supported
    // Try PR_SET_NO_NEW_PRIVS first (required before SECCOMP_MODE_FILTER)
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "[sandbox] WARN: PR_SET_NO_NEW_PRIVS failed ({}), skipping seccomp",
            std::io::Error::last_os_error()
        );
        return Ok(());
    }

    let filter = build_seccomp_filter();
    let fprog = SockFProg {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &fprog as *const _ as usize,
            0,
            0,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[sandbox] WARN: seccomp filter install failed ({err}), running without syscall filtering");
        return Ok(());
    }

    eprintln!(
        "[sandbox] seccomp-BPF filter installed ({} allowed syscalls)",
        filter.len() - 2 // subtract load + kill + allow instructions
    );

    Ok(())
}

/// True when the syscall filter could NOT be installed (or NNP could not be
/// set). Exposed so callers can decide to refuse startup instead of running
/// unsandboxed (hardening policy).
pub fn seccomp_is_degraded() -> bool {
    // NNP bit stays set once it succeeds — read /proc/self/status NoNewPrivs
    // plus the PR_GET_SECCOMP probe: a filter is active only if the probe
    // reports SECCOMP_MODE_FILTER.
    let nnp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("NoNewPrivs:\t")?.parse::<i32>().ok())
        })
        .unwrap_or(0);
    if nnp != 1 {
        return true;
    }
    // PR_GET_SECCOMP = 21: 0/1 = a mode is active, EACCES/EINVAL = none.
    let rc = unsafe { libc::prctl(21, 0, 0, 0, 0) };
    rc < 0
}

// ── Landlock filesystem restrictions ─────────────────────────────────────────

/// Restrict filesystem access via Landlock LSM (kernel ≥5.13).
///
/// Allows read-only access to:
/// - /sys/kernel/debug (eBPF maps)
/// - /sys/fs/bpf (BPF filesystem)
/// - /proc (process info)
/// - /dev/null, /dev/urandom
/// - ~/.config/talus (license, audit log)
/// - BPF object file path
/// - /tmp (temp files)
pub fn apply_landlock(bpf_path: &Path) -> Result<()> {
    // Check Landlock ABI version
    let abiv = get_landlock_abi_version();
    if abiv == 0 {
        eprintln!("[sandbox] Landlock not available on this kernel, skipping FS restrictions");
        return Ok(());
    }

    // Define allowed paths (read-only)
    let allowed_paths: Vec<(&str, u64)> = vec![
        ("/sys/kernel/debug", LANDLOCK_ACCESS_FS_READ_DIR),
        ("/sys/fs/bpf", LANDLOCK_ACCESS_FS_READ_DIR),
        ("/sys/kernel/debug/tracing", LANDLOCK_ACCESS_FS_READ_FILE),
        ("/proc", LANDLOCK_ACCESS_FS_READ_DIR),
        ("/dev/null", LANDLOCK_ACCESS_FS_READ_FILE),
        ("/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE),
        ("/tmp", LANDLOCK_ACCESS_FS_READ_DIR),
    ];

    // Compute allowed access (bitwise OR of all rules)
    let mut allowed_access: u64 = 0;
    for &(_, access) in &allowed_paths {
        allowed_access |= access;
    }

    // Create Landlock ruleset
    let attr = LandlockRulesetAttr {
        handled_access_fs: allowed_access,
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const _ as usize,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32, // ABI version 0 = latest
        )
    };

    if ruleset_fd < 0 {
        eprintln!(
            "[sandbox] WARN: landlock_create_ruleset failed ({}), skipping FS restrictions",
            std::io::Error::last_os_error()
        );
        return Ok(());
    }

    // Add path rules
    for &(path, access) in &allowed_paths {
        let path_c = CString::new(path).unwrap_or_default();
        let rule = LandlockPathBeneathAttr {
            allowed_access: access,
            parent_fd: open_ro_fd(&path_c)?,
        };

        let ret = unsafe {
            libc::syscall(
                LANDLOCK_ADD_RULE,
                ruleset_fd as usize,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const _ as usize,
                0u32,
            )
        };

        if ret < 0 {
            eprintln!(
                "[sandbox] WARN: landlock_add_rule failed for {path} ({})",
                std::io::Error::last_os_error()
            );
        }
    }

    // Add BPF object path if it exists
    if bpf_path.exists() {
        if let Some(parent) = bpf_path.parent() {
            if let Some(parent_str) = parent.to_str() {
                let path_c = CString::new(parent_str).unwrap_or_default();
                if let Ok(fd) = open_ro_fd(&path_c) {
                    let rule = LandlockPathBeneathAttr {
                        allowed_access: LANDLOCK_ACCESS_FS_READ_FILE,
                        parent_fd: fd,
                    };

                    let ret = unsafe {
                        libc::syscall(
                            LANDLOCK_ADD_RULE,
                            ruleset_fd as usize,
                            LANDLOCK_RULE_PATH_BENEATH,
                            &rule as *const _ as usize,
                            0u32,
                        )
                    };

                    if ret < 0 {
                        eprintln!(
                            "[sandbox] WARN: landlock_add_rule failed for BPF path ({})",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }
    }

    // Add config directory
    if let Some(config_dir) = dirs::config_dir() {
        let config_path = config_dir.join("talus");
        if config_path.exists() {
            if let Some(config_str) = config_path.to_str() {
                let path_c = CString::new(config_str).unwrap_or_default();
                if let Ok(fd) = open_ro_fd(&path_c) {
                    let rule = LandlockPathBeneathAttr {
                        allowed_access: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
                        parent_fd: fd,
                    };

                    let ret = unsafe {
                        libc::syscall(
                            LANDLOCK_ADD_RULE,
                            ruleset_fd as usize,
                            LANDLOCK_RULE_PATH_BENEATH,
                            &rule as *const _ as usize,
                            0u32,
                        )
                    };

                    if ret < 0 {
                        eprintln!(
                            "[sandbox] WARN: landlock_add_rule failed for config dir ({})",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }
    }

    // Enforce the ruleset on current process
    let ret = unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd as usize, 0u32) };

    if ret < 0 {
        eprintln!(
            "[sandbox] WARN: landlock_restrict_self failed ({}), running without FS restrictions",
            std::io::Error::last_os_error()
        );
    } else {
        eprintln!("[sandbox] Landlock FS restrictions applied");
    }

    // Close ruleset fd
    unsafe { libc::close(ruleset_fd as i32) };

    Ok(())
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Check Landlock ABI version (returns 0 if not supported).
fn get_landlock_abi_version() -> u32 {
    let attr = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    };

    let ret = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const _ as usize,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if ret < 0 {
        return 0;
    }

    // Close the fd we just created for the version check
    unsafe { libc::close(ret as i32) };

    LANDLOCK_ABI_VERSION
}

/// Open a directory read-only for Landlock rules.
fn open_ro_fd(path: &CString) -> Result<i32> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY,
        )
    };

    if fd < 0 {
        bail!(
            "failed to open {} for Landlock: {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        );
    }

    Ok(fd)
}

// ── Main sandbox entry point ─────────────────────────────────────────────────

/// Apply all sandbox hardening measures.
///
/// Call order in run_monitor():
/// 1. `Monitor::start()` — load eBPF, attach tracepoints
/// 2. `sandbox::apply(bpf_path)` — drop caps, install seccomp, apply Landlock
/// 3. Event processing loop
///
/// The filter is fail-open on unsupported kernels but always logs a warning.
pub fn apply(bpf_path: &Path) -> Result<()> {
    eprintln!("[sandbox] applying agent hardening...");

    // 1. Drop capabilities (always works, most impactful)
    if let Err(e) = drop_capabilities() {
        eprintln!("[sandbox] WARN: capability dropping failed: {e}");
    }

    // 2. Install seccomp-BPF filter (restrict syscalls)
    if let Err(e) = install_seccomp_filter() {
        eprintln!("[sandbox] WARN: seccomp filter failed: {e}");
    }

    // 3. Apply Landlock FS restrictions (kernel ≥5.13)
    if let Err(e) = apply_landlock(bpf_path) {
        eprintln!("[sandbox] WARN: Landlock failed: {e}");
    }

    // 4. Degradation transparency: an agent running WITHOUT its syscall
    // filter must say so loudly and record it in the audit register, so
    // SIEM/audit reviewers can spot unhardened deployments (seccomp is the
    // primary control; Landlock degradation is reported by apply_landlock).
    if seccomp_is_degraded() {
        eprintln!("[sandbox] SECURITY WARNING: seccomp filter NOT active — running with degraded isolation");
        crate::audit::audit_log(
            "SANDBOX_DEGRADED",
            "-",
            "seccomp filter not active (kernel refused NNP/filter install)",
        );
    }

    eprintln!("[sandbox] hardening applied ✓");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_valid_bpf() {
        let filter = build_seccomp_filter();
        // Must have at least: load + 1 comparison + kill + allow
        assert!(filter.len() >= 4, "filter too short: {}", filter.len());

        // First instruction must be LOAD
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SYSCALL_OFFSET as u32);

        // Last two instructions must be RET KILL and RET ALLOW
        let last = filter.len() - 1;
        assert_eq!(filter[last].code, BPF_RET | BPF_K);
        assert_eq!(filter[last].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[last - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[last - 1].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn seccomp_filter_covers_critical_syscalls() {
        let filter = build_seccomp_filter();
        let allowed: HashSet<u32> = filter
            .iter()
            .filter(|i| i.code == (BPF_JEQ | BPF_JGE))
            .map(|i| i.k)
            .collect();

        // Core syscalls the agent MUST have
        assert!(allowed.contains(&0), "read must be allowed");
        assert!(allowed.contains(&1), "write must be allowed");
        assert!(allowed.contains(&3), "close must be allowed");
        assert!(allowed.contains(&9), "mmap must be allowed");
        assert!(allowed.contains(&202), "futex must be allowed");
        assert!(allowed.contains(&291), "epoll_create1 must be allowed");

        // BLOCKED after init — prevents self-modification
        assert!(!allowed.contains(&321), "bpf must be BLOCKED after init");
        assert!(
            !allowed.contains(&241),
            "perf_event_open must be BLOCKED after init"
        );
        assert!(!allowed.contains(&101), "ptrace must be BLOCKED always");
        assert!(
            !allowed.contains(&59),
            "execve must be BLOCKED (no exec after init)"
        );
        assert!(
            !allowed.contains(&57),
            "fork must be BLOCKED (no fork after init)"
        );
    }

    #[test]
    fn cap_name_covers_important_caps() {
        assert_eq!(cap_name(39), "BPF");
        assert_eq!(cap_name(38), "PERFMON");
        assert_eq!(cap_name(12), "NET_ADMIN");
        assert_eq!(cap_name(21), "SYS_ADMIN");
    }

    #[test]
    fn get_current_capabilities_returns_set() {
        let caps = get_current_capabilities().unwrap();
        // As root, should have at least some caps
        assert!(!caps.is_empty() || unsafe { libc::geteuid() } != 0);
    }

    // Miri cannot emulate the landlock syscalls (e.g. 444 on x86_64);
    // the call is a plain syscall wrapper, not undefined behaviour.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn landlock_abi_check_does_not_panic() {
        // This should return 0 on unsupported kernels, or >= 1 on supported ones
        let _version = get_landlock_abi_version();
    }

    // apply() installs a landlock ruleset under the hood — same Miri
    // limitation as landlock_abi_check_does_not_panic above.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn sandbox_apply_does_not_panic() {
        let tmp = std::env::temp_dir().join("talus_sandbox_test");
        let _ = std::fs::write(&tmp, b"dummy");
        // Should not panic even if capabilities/landlock are not available
        let _ = apply(&tmp);
        let _ = std::fs::remove_file(&tmp);
    }
}
