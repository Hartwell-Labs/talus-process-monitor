//! Network eBPF tracepoint programs for Talus Process Monitor.
//!
//! IMPORTANT: Avoids ALL code patterns that generate `.text.unlikely` LLVM
//! cold-path sections. No array indexing, no Result matching on non-trivial types.
//! Reads sockaddr byte-by-byte via bpf_probe_read_user.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user,
    },
    macros::tracepoint,
    programs::TracePointContext,
};

pub const EVENT_CONNECT: u8 = 2;
pub const EVENT_ACCEPT: u8 = 3;
pub const EVENT_SENDTO: u8 = 4;
pub const EVENT_RECVFROM: u8 = 5;

use super::ProcessEvent;
use super::EVENTS;

#[inline(always)]
unsafe fn zero_event() -> ProcessEvent {
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

#[inline(always)]
unsafe fn read_comm(event: &mut ProcessEvent) {
    if let Ok(comm) = bpf_get_current_comm() {
        let n = comm.len().min(15);
        raw_copy(event.comm.as_mut_ptr(), comm.as_ptr(), n);
    }
}

/// Format a single u8 decimal digit(s) into buf at pos. Returns new pos.
#[inline(always)]
fn write_octet(buf: &mut [u8; 21], mut pos: usize, val: u8) -> usize {
    if val >= 100 {
        buf[pos] = b'0' + val / 100;
        pos += 1;
    }
    if val >= 10 {
        buf[pos] = b'0' + (val / 10) % 10;
        pos += 1;
    }
    buf[pos] = b'0' + val % 10;
    pos + 1
}

/// Format u16 decimal into buf at pos. Returns new pos.
#[inline(always)]
fn write_u16(buf: &mut [u8; 21], mut pos: usize, mut val: u16) -> usize {
    if val >= 10000 {
        buf[pos] = b'0' + (val / 10000) as u8;
        pos += 1;
        val %= 10000;
    }
    if val >= 1000 {
        buf[pos] = b'0' + (val / 1000) as u8;
        pos += 1;
        val %= 1000;
    }
    if val >= 100 {
        buf[pos] = b'0' + (val / 100) as u8;
        pos += 1;
        val %= 100;
    }
    if val >= 10 {
        buf[pos] = b'0' + (val / 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (val % 10) as u8;
    pos + 1
}

/// Try to read IPv4 sockaddr into event.filename.
#[inline(always)]
unsafe fn try_read_sockaddr(ctx: &TracePointContext, arg_idx: usize, event: &mut ProcessEvent) {
    let offset = 16 + arg_idx * core::mem::size_of::<usize>();

    if let Ok(ptr) = ctx.read_at::<*const u8>(offset) {
        if !ptr.is_null() {
            let family_lo: u8 = bpf_probe_read_user(ptr).unwrap_or(0);
            let family_hi: u8 = bpf_probe_read_user(ptr.add(1)).unwrap_or(0);
            let family = (family_lo as u16) | ((family_hi as u16) << 8);

            if family == 2 {
                // AF_INET
                let port_lo: u8 = bpf_probe_read_user(ptr.add(2)).unwrap_or(0);
                let port_hi: u8 = bpf_probe_read_user(ptr.add(3)).unwrap_or(0);
                let port = (port_lo as u16) | ((port_hi as u16) << 8);

                let a0: u8 = bpf_probe_read_user(ptr.add(4)).unwrap_or(0);
                let a1: u8 = bpf_probe_read_user(ptr.add(5)).unwrap_or(0);
                let a2: u8 = bpf_probe_read_user(ptr.add(6)).unwrap_or(0);
                let a3: u8 = bpf_probe_read_user(ptr.add(7)).unwrap_or(0);

                // Format "A.B.C.D:PORT" — no array indexing
                let mut buf = [0u8; 21];
                let mut pos = write_octet(&mut buf, 0, a0);
                buf[pos] = b'.';
                pos += 1;
                pos = write_octet(&mut buf, pos, a1);
                buf[pos] = b'.';
                pos += 1;
                pos = write_octet(&mut buf, pos, a2);
                buf[pos] = b'.';
                pos += 1;
                pos = write_octet(&mut buf, pos, a3);
                buf[pos] = b':';
                pos += 1;
                pos = write_u16(&mut buf, pos, port);

                raw_copy(event.filename.as_mut_ptr(), buf.as_ptr(), pos);
            } else if family == 10 {
                raw_copy(event.filename.as_mut_ptr(), b"[IPv6]".as_ptr(), 6);
            } else if family == 1 {
                raw_copy(event.filename.as_mut_ptr(), b"[ Unix ]".as_ptr(), 7);
            }
        }
    }
}

// ── Tracepoint programs ──────────────────────────────────────────────────

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let mut event = unsafe { zero_event() };
    event.event_type = EVENT_CONNECT;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;
    unsafe {
        read_comm(&mut event);
    }
    unsafe {
        try_read_sockaddr(&ctx, 1, &mut event);
    }
    EVENTS.output(&ctx, &event, 0);
    0
}

#[tracepoint(name = "sys_enter_accept", category = "syscalls")]
pub fn sys_enter_accept(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let mut event = unsafe { zero_event() };
    event.event_type = EVENT_ACCEPT;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;
    unsafe {
        read_comm(&mut event);
    }
    unsafe {
        try_read_sockaddr(&ctx, 1, &mut event);
    }
    EVENTS.output(&ctx, &event, 0);
    0
}

#[tracepoint(name = "sys_enter_sendto", category = "syscalls")]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let mut event = unsafe { zero_event() };
    event.event_type = EVENT_SENDTO;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;
    unsafe {
        read_comm(&mut event);
    }
    unsafe {
        try_read_sockaddr(&ctx, 4, &mut event);
    }
    EVENTS.output(&ctx, &event, 0);
    0
}

#[tracepoint(name = "sys_enter_recvfrom", category = "syscalls")]
pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let mut event = unsafe { zero_event() };
    event.event_type = EVENT_RECVFROM;
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.uid = uid;
    unsafe {
        read_comm(&mut event);
    }
    unsafe {
        try_read_sockaddr(&ctx, 4, &mut event);
    }
    EVENTS.output(&ctx, &event, 0);
    0
}
