//! The only `unsafe` code in user space: the program entry stub and the
//! `syscall` instruction (AGENTS.md section 5, drivers.md).

#![allow(unsafe_code)]

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    // The kernel enters with `rdi` = the argument and a 16-byte aligned
    // stack; `call` leaves it as the System V ABI expects at function entry.
    "_start:",
    "and rsp, -16",
    "call pharos_main",
    "ud2",
    ".previous",
);

/// Makes system call `number` with up to six arguments; returns `rax`
/// (status) and `rdx` (value).
#[cfg(target_arch = "x86_64")]
pub fn raw(number: u64, args: [u64; 6]) -> (u64, u64) {
    let status: u64;
    let value: u64;
    // SAFETY: the kernel's system-call ABI (syscalls-ipc.md): arguments in
    // rdi, rsi, rdx, r10, r8, r9; it returns status in rax and a value in
    // rdx, clobbers rcx and r11, and preserves every other register and the
    // stack. It touches only memory this process passes and owns, so Rust's
    // view of memory stays valid.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => status,
            in("rdi") args[0],
            in("rsi") args[1],
            inlateout("rdx") args[2] => value,
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}
