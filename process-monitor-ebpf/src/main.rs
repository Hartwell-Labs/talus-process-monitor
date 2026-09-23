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

    EVENTS.output(ctx, &event, 0);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
