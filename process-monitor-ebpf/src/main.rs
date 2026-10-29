#![no_std]
#![no_main]
#![allow(linker_messages)]
#![allow(invalid_value)] // MaybeUninit UB warnings — safe in eBPF (stack zeroed by kernel)

mod fs;
mod network;

use core::slice;

use aya_ebpf::{
    cty::c_char,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

pub const EVENT_EXECVE: u8 = 0;
pub const EVENT_OPENAT: u8 = 1;
pub const EVENT_FILENAME_LEN: usize = 64;
pub const EVENT_COMM_LEN: usize = 16;
pub const EVENT_ARGV_LEN: usize = 128;

/// Event record shared between kernel and userspace (`#[repr(C)]`).
#[repr(C)]
pub struct ProcessEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    /// Kernel monotonic timestamp (ns) taken at tracepoint entry.
    /// Userspace subtracts it from its own ktime to measure
    /// kernel→userspace delivery latency.
    pub ktime_ns: u64,
    pub comm: [u8; EVENT_COMM_LEN],
    pub filename: [u8; EVENT_FILENAME_LEN],
    pub argv: [u8; EVENT_ARGV_LEN],
}

#[map]
pub static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    emit_event(&ctx, EVENT_EXECVE, 0)
}

#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    emit_event(&ctx, EVENT_OPENAT, 1)
}

/// eBPF-safe byte copy — avoids LLVM memcpy builtin.
#[inline(always)]
unsafe fn raw_copy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0;
    while i < len {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

fn emit_event(ctx: &TracePointContext, event_type: u8, filename_arg: u32) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // Use MaybeUninit to avoid LLVM memset builtin on struct init.
    // BPF stack is zeroed by the kernel, so this is safe in practice.
    let mut event: ProcessEvent = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    event.event_type = event_type;
    event.pid = pid;
    event.uid = uid;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };

    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(EVENT_COMM_LEN - 1);
        unsafe { raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n) };
    }

    let ptr_size = core::mem::size_of::<*const c_char>();
    let filename_offset = 16 + filename_arg as usize * ptr_size;

    // Read the filename from the tracepoint args.
    if let Ok(filename) = unsafe { ctx.read_at::<*const c_char>(filename_offset) } {
        if !filename.is_null() {
            let dst = unsafe {
                slice::from_raw_parts_mut(event.filename.as_mut_ptr(), EVENT_FILENAME_LEN)
            };
            if let Ok(bytes) = unsafe { bpf_probe_read_user_str_bytes(filename.cast::<u8>(), dst) }
            {
                let n = bytes.len().min(EVENT_FILENAME_LEN);
                unsafe { raw_copy(event.filename.as_mut_ptr(), bytes.as_ptr(), n) };
            }
        }
    }

    // For execve: read argv[0] (full command path as typed by user).
    // Tracepoint layout: arg0=filename, arg1=argv (userspace char** pointer).
    if event_type == EVENT_EXECVE {
        let argv_offset = 16 + 1 * ptr_size;
        // Read the argv pointer value from the tracepoint context buffer.
        if let Ok(argv_ptr) = unsafe { ctx.read_at::<*const *const c_char>(argv_offset) } {
            if !argv_ptr.is_null() {
                // Dereference argv to get argv[0] (a userspace pointer).
                // Use bpf_probe_read_user since argv_ptr points to userspace memory.
                if let Ok(arg0) = unsafe { bpf_probe_read_user::<*const c_char>(argv_ptr) } {
                    if !arg0.is_null() {
                        let dst = unsafe {
                            slice::from_raw_parts_mut(event.argv.as_mut_ptr(), EVENT_ARGV_LEN)
                        };
                        if let Ok(bytes) =
                            unsafe { bpf_probe_read_user_str_bytes(arg0.cast::<u8>(), dst) }
                        {
                            let n = bytes.len().min(EVENT_ARGV_LEN);
                            unsafe { raw_copy(event.argv.as_mut_ptr(), bytes.as_ptr(), n) };
                        }
                    }
                }
            }
        }
    }

    // ── Kernel-side noise filtering ──────────────────────────────────────
    // Drop high-volume, low-signal openat events at the source. find/pacman/xargs
    // scans generate hundreds of thousands of openat syscalls on virtual fs
    // and system-library paths; none are relevant to ransomware detection
    // (which targets user data, config and persistence paths).
    //
    // Filtered:  /proc  /sys  /dev  /run  /usr  /var  /etc/ld.so
    // Kept:      /home  /root  /opt  /tmp  /mnt  /srv  /etc/* (config)  /etc/ld.so.preload
    if event_type == EVENT_OPENAT {
        let f = &event.filename;
        // Determine if this is kernel-introspection noise. Absolute prefixes
        // (/proc /sys /dev /run /usr /var /etc/ld.so.cache) and bare relative
        // basenames from a /proc/<pid> fd (stat, cmdline, cgroup, …) all carry
        // zero ransomware signal — drop at source to keep the user-space
        // pipeline below ~5 K evts/s of real activity.
        let is_noise = if f[0] == b'/' {
            // Absolute path noise prefixes.
            f[1] == b'p' && f[2] == b'r' && f[3] == b'o'            // /proc*
                || f[1] == b's' && f[2] == b'y' && f[3] == b's'    // /sys*
                || f[1] == b'd' && f[2] == b'e' && f[3] == b'v'    // /dev*
                || f[1] == b'r' && f[2] == b'n' && f[3] == b'u'    // /run*
                || f[1] == b'u' && f[2] == b's' && f[3] == b'r'    // /usr/*
                || f[1] == b'v' && f[2] == b'a' && f[3] == b'r'    // /var/*
                || (f[1] == b'e' && f[2] == b't' && f[3] == b'c'   // /etc/ld.so.cache
                    && f[4] == b'/' && f[5] == b'l' && f[6] == b'd'
                    && f[7] == b'.' && f[8] == b's' && f[9] == b'o'
                    && f[10] == b'/' && f[11] != b'p')             // keep /etc/ld.so.preload
        } else {
            // Relative basenames opened via a /proc/<pid> dir fd.
            // Compare byte-by-zero so we don't read past the NUL terminator.
            rel_is_noise(f)
        };
        if is_noise {
            return 0;
        }
    }

    EVENTS.output(ctx, &event, 0);
    0
}

/// BPF-safe check for relative /proc basenames. `event.filename` is a fixed
/// `[u8; 64]` NUL-padded; compare byte-by-NUL so we never read past the
/// terminator (the verifier rejects unbounded indexing).
#[inline(always)]
fn rel_is_noise(f: &[u8; EVENT_FILENAME_LEN]) -> bool {
    // `stat`            — 4 bytes
    f[0] == b's' && f[1] == b't' && f[2] == b'a' && f[3] == b't' && f[4] == 0
    // `status`          — 6 bytes
        || f[0] == b's' && f[1] == b't' && f[2] == b'a' && f[3] == b't'
        && f[4] == b'u' && f[5] == b's' && f[6] == 0
    // `cmdline`         — 7 bytes
        || f[0] == b'c' && f[1] == b'm' && f[2] == b'd' && f[3] == b'l'
        && f[4] == b'i' && f[5] == b'n' && f[6] == b'e' && f[7] == 0
    // `environ`         — 7 bytes
        || f[0] == b'e' && f[1] == b'n' && f[2] == b'v' && f[3] == b'i'
        && f[4] == b'r' && f[5] == b'o' && f[6] == b'n' && f[7] == 0
    // `cgroup`          — 6 bytes
        || f[0] == b'c' && f[1] == b'g' && f[2] == b'r' && f[3] == b'o'
        && f[4] == b'u' && f[5] == b'p' && f[6] == 0
    // `fd`              — 2 bytes
        || f[0] == b'f' && f[1] == b'd' && f[2] == 0
    // `maps`            — 4 bytes
        || f[0] == b'm' && f[1] == b'a' && f[2] == b'p' && f[3] == b's' && f[4] == 0
    // `smaps`           — 5 bytes
        || f[0] == b's' && f[1] == b'm' && f[2] == b'a' && f[3] == b'p' && f[4] == b's' && f[5] == 0
    // `comm`            — 4 bytes
        || f[0] == b'c' && f[1] == b'o' && f[2] == b'm' && f[3] == b'm' && f[4] == 0
    // `exe`             — 3 bytes
        || f[0] == b'e' && f[1] == b'x' && f[2] == b'e' && f[3] == 0
    // `smaps_rollup`    — 12 bytes
        || f[0] == b's' && f[1] == b'm' && f[2] == b'a' && f[3] == b'p'
        && f[4] == b's' && f[5] == b'_' && f[6] == b'r' && f[7] == b'o'
        && f[8] == b'l' && f[9] == b'l' && f[10] == b'a' && f[11] == b'p' && f[12] == 0
    // `oom_score`       — 9 bytes
        || f[0] == b'o' && f[1] == b'o' && f[2] == b'm' && f[3] == b'_'
        && f[4] == b's' && f[5] == b'c' && f[6] == b'o' && f[7] == b'r'
        && f[8] == b'e' && f[9] == 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
