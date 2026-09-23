//! Filesystem and signal eBPF tracepoint programs for Talus Process Monitor.
//!
//! Traces mkdir, unlink, rmdir, kill, and chmod syscalls — high-signal
//! events for security monitoring (file tampering, process killing).
//!
//! IMPORTANT: Avoids all array indexing, iterator operations, and match
//! patterns that generate `.text.unlikely` LLVM cold-path sections.
//! Uses pointer arithmetic for all buffer writes.

use core::slice;

use aya_ebpf::{
    cty::c_char,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

pub const EVENT_MKDIR: u8 = 6;
pub const EVENT_UNLINK: u8 = 7;
pub const EVENT_KILL: u8 = 8;
pub const EVENT_CHMOD: u8 = 9;

#[repr(C)]
pub struct FsEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    /// Kernel monotonic timestamp (ns) — layout-compatible with
    /// `super::ProcessEvent::ktime_ns` (same clock, same position).
    pub ktime_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 64],
    pub argv: [u8; 128],
}

#[map]
pub static FS_EVENTS: PerfEventArray<FsEvent> = PerfEventArray::new(0);

use super::EVENTS;

#[inline(always)]
unsafe fn zero_fs_event() -> FsEvent {
    core::mem::MaybeUninit::uninit().assume_init()
}

#[inline(always)]
unsafe fn raw_copy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0;
    while i < len {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

/// Write signal name bytes into dst at pos using pointer arithmetic. Returns new pos.
#[inline(always)]
unsafe fn write_sig_ptr(dst: *mut u8, mut pos: usize, sig: i32) -> usize {
    let name: *const u8 = if sig == 1 {
        b"SIGHUP".as_ptr()
    } else if sig == 2 {
        b"SIGINT".as_ptr()
    } else if sig == 3 {
        b"SIGQUIT".as_ptr()
    } else if sig == 6 {
        b"SIGABRT".as_ptr()
    } else if sig == 9 {
        b"SIGKILL".as_ptr()
    } else if sig == 15 {
        b"SIGTERM".as_ptr()
    } else {
        b"?".as_ptr()
    };
    let name_len: usize = if sig == 1 {
        6
    } else if sig == 2 {
        5
    } else if sig == 3 {
        6
    } else if sig == 6 {
        6
    } else if sig == 9 {
        6
    } else if sig == 15 {
        6
    } else {
        1
    };
    let mut i = 0;
    while i < name_len && pos < 127 {
        *dst.add(pos) = *name.add(i);
        pos += 1;
        i += 1;
    }
    pos
}

/// Trace `mkdir` — directory creation.
#[tracepoint(name = "sys_enter_mkdir", category = "syscalls")]
pub fn sys_enter_mkdir(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = unsafe { zero_fs_event() };
    event.event_type = EVENT_MKDIR;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;

    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(15);
        unsafe { raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n) };
    }

    let pathname_offset = 16;
    if let Ok(pathname_ptr) = unsafe { ctx.read_at::<*const c_char>(pathname_offset) } {
        if !pathname_ptr.is_null() {
            let dst = unsafe { slice::from_raw_parts_mut(event.filename.as_mut_ptr(), 64) };
            if let Ok(bytes) =
                unsafe { bpf_probe_read_user_str_bytes(pathname_ptr.cast::<u8>(), dst) }
            {
                let n = bytes.len().min(63);
                unsafe { raw_copy(event.filename.as_mut_ptr(), bytes.as_ptr(), n) };
            }
        }
    }

    unsafe {
        EVENTS.output(
            &ctx,
            &*(&event as *const _ as *const super::ProcessEvent),
            0,
        );
    }
    0
}

/// Trace `unlink` — file deletion.
#[tracepoint(name = "sys_enter_unlinkat", category = "syscalls")]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = unsafe { zero_fs_event() };
    event.event_type = EVENT_UNLINK;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;

    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(15);
        unsafe { raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n) };
    }

    let ptr_size = core::mem::size_of::<*const c_char>();
    let pathname_offset = 16 + 1 * ptr_size;
    if let Ok(pathname_ptr) = unsafe { ctx.read_at::<*const c_char>(pathname_offset) } {
        if !pathname_ptr.is_null() {
            let dst = unsafe { slice::from_raw_parts_mut(event.filename.as_mut_ptr(), 64) };
            if let Ok(bytes) =
                unsafe { bpf_probe_read_user_str_bytes(pathname_ptr.cast::<u8>(), dst) }
            {
                let n = bytes.len().min(63);
                unsafe { raw_copy(event.filename.as_mut_ptr(), bytes.as_ptr(), n) };
            }
        }
    }

    unsafe {
        EVENTS.output(
            &ctx,
            &*(&event as *const _ as *const super::ProcessEvent),
            0,
        );
    }
    0
}

/// Trace `kill` — signal delivery to process.
#[tracepoint(name = "sys_enter_kill", category = "syscalls")]
pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = unsafe { zero_fs_event() };
    event.event_type = EVENT_KILL;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;

    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(15);
        unsafe { raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n) };
    }

    let ptr_size = core::mem::size_of::<*const c_char>();
    let pid_offset = 16;
    if let Ok(target_pid) = unsafe { ctx.read_at::<i32>(pid_offset) } {
        let sig_offset = 16 + ptr_size;
        if let Ok(sig) = unsafe { ctx.read_at::<i32>(sig_offset) } {
            // Format "target_pid:sig_name" into event.argv using pointer arithmetic
            let argv_ptr = event.argv.as_mut_ptr();
            let mut pos: usize = 0;

            // Write target PID digits
            let mut v = target_pid as u32;
            if v == 0 {
                unsafe {
                    *argv_ptr.add(0) = b'0';
                }
                pos = 1;
            } else {
                let mut tmp = [0u8; 10];
                let mut n = 0;
                while v > 0 && n < 10 {
                    tmp[n] = b'0' + (v % 10) as u8;
                    v /= 10;
                    n += 1;
                }
                let mut i = 0;
                while i < n {
                    unsafe {
                        *argv_ptr.add(pos) = tmp[n - 1 - i];
                    }
                    pos += 1;
                    i += 1;
                }
            }

            // Write ':'
            if pos < 127 {
                unsafe {
                    *argv_ptr.add(pos) = b':';
                }
                pos += 1;
            }

            // Write signal name using pointer arithmetic
            _ = unsafe { write_sig_ptr(argv_ptr, pos, sig) };
        }
    }

    unsafe {
        EVENTS.output(
            &ctx,
            &*(&event as *const _ as *const super::ProcessEvent),
            0,
        );
    }
    0
}

/// Trace `chmod` — file permission change.
#[tracepoint(name = "sys_enter_fchmodat", category = "syscalls")]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = unsafe { zero_fs_event() };
    event.event_type = EVENT_CHMOD;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;

    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(15);
        unsafe { raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n) };
    }

    let ptr_size = core::mem::size_of::<*const c_char>();
    let pathname_offset = 16 + 1 * ptr_size;
    if let Ok(pathname_ptr) = unsafe { ctx.read_at::<*const c_char>(pathname_offset) } {
        if !pathname_ptr.is_null() {
            let dst = unsafe { slice::from_raw_parts_mut(event.filename.as_mut_ptr(), 64) };
            if let Ok(bytes) =
                unsafe { bpf_probe_read_user_str_bytes(pathname_ptr.cast::<u8>(), dst) }
            {
                let n = bytes.len().min(63);
                unsafe { raw_copy(event.filename.as_mut_ptr(), bytes.as_ptr(), n) };
            }
        }
    }

    unsafe {
        EVENTS.output(
            &ctx,
            &*(&event as *const _ as *const super::ProcessEvent),
            0,
        );
    }
    0
}
