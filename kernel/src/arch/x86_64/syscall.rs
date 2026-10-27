//! System-call entry and exit (D-014, syscalls-ipc.md, issue #40).
//!
//! `syscall` jumps to the entry stub (`pharos_syscall_entry`) with interrupts disabled
//! (`SFMASK`), the user RIP in `rcx`, and RFLAGS in `r11`. The stub saves
//! the user RSP in a scratch slot (one CPU), switches to the running
//! thread's kernel stack (the same top as TSS `rsp0`), saves the user
//! registers as a [`SyscallFrame`], and calls the handler installed with
//! [`init`]. The handler writes the status to `rax` and the value to `rdx`
//! in the frame. On the way back the stub restores everything else and
//! returns with `sysret`, or with `iretq` if the return address is not a
//! user address (CVE-2012-0217: `sysret` to a non-canonical RIP faults in
//! ring 0 with the user's stack pointer on Intel CPUs). Process address
//! spaces never map the last user page, so that address cannot occur.

use core::arch::global_asm;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use super::gdt::{KERNEL_CODE, USER_CODE, USER_DATA};
use super::paging::USER_END;

/// User registers saved by the entry stub, lowest address first. The
/// handler reads the call number and arguments and writes `rax` (status)
/// and `rdx` (value); other fields are restored unchanged.
#[repr(C)]
#[derive(Debug)]
pub struct SyscallFrame {
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// Call number on entry, status on return.
    pub rax: u64,
    /// User RIP (saved by `syscall` in `rcx`).
    pub rip: u64,
    /// User RFLAGS (saved by `syscall` in `r11`).
    pub rflags: u64,
    /// User RSP.
    pub rsp: u64,
}

impl SyscallFrame {
    /// The six arguments in ABI order (`rdi`, `rsi`, `rdx`, `r10`, `r8`,
    /// `r9`).
    pub fn args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }
}

/// Top of the running thread's kernel stack; kept equal to TSS `rsp0` by
/// `gdt::set_kernel_stack`.
pub(super) static KERNEL_STACK_TOP: AtomicU64 = AtomicU64::new(0);
/// The user RSP between `syscall` and the switch to the kernel stack.
static USER_RSP_SCRATCH: AtomicU64 = AtomicU64::new(0);
/// The handler; null until [`init`].
static HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Status returned when no handler is installed (`UNKNOWN_CALL`).
const NO_HANDLER: u64 = 1;

global_asm!(
    ".global pharos_syscall_entry",
    "pharos_syscall_entry:",
    "mov [rip + {scratch}], rsp",
    "mov rsp, [rip + {top}]",
    "push qword ptr [rip + {scratch}]",
    "push r11",
    "push rcx",
    "push rax",
    "push rdi",
    "push rsi",
    "push rdx",
    "push r10",
    "push r8",
    "push r9",
    // Ten words below a 16-byte-aligned top: aligned for the call.
    "mov rdi, rsp",
    "call {dispatch}",
    // Only a user-half RIP may go through `sysret`; rcx is free until the
    // pops restore it.
    "mov rcx, {user_end}",
    "cmp qword ptr [rsp + 7 * 8], rcx",
    "jae 3f",
    "pop r9",
    "pop r8",
    "pop r10",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rax",
    "pop rcx",
    "pop r11",
    "pop rsp",
    "sysretq",
    // Fallback, unreachable while the last user page stays unmapped (the
    // address after a `syscall` is then always a user address): `iretq`
    // checks RIP while still on the kernel stack, so a bad RIP faults in
    // ring 0 with a sane stack (a reported kernel fault) instead of with
    // the user's stack pointer.
    "3:",
    "pop r9",
    "pop r8",
    "pop r10",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rax",
    "pop rcx",
    "pop r11",
    "push {user_data}",
    "push qword ptr [rsp + 8]",
    "push r11",
    "push {user_code}",
    "push rcx",
    "iretq",
    scratch = sym USER_RSP_SCRATCH,
    top = sym KERNEL_STACK_TOP,
    dispatch = sym dispatch,
    user_end = const USER_END,
    user_data = const USER_DATA,
    user_code = const USER_CODE,
);

unsafe extern "C" {
    fn pharos_syscall_entry();
}

extern "C" fn dispatch(frame: &mut SyscallFrame) {
    // SFMASK clears both on entry.
    debug_assert_eq!(super::rflags() & (1 << 10 | 1 << 18), 0, "DF or AC set");
    let handler = HANDLER.load(Ordering::Acquire);
    if handler.is_null() {
        frame.rax = NO_HANDLER;
        frame.rdx = 0;
        return;
    }
    // SAFETY: the only non-null values stored in `HANDLER` come from
    // `init`, which stores a `fn(&mut SyscallFrame)`. Function and data
    // pointers have the same size on x86-64.
    let handler = unsafe { core::mem::transmute::<*mut (), fn(&mut SyscallFrame)>(handler) };
    handler(frame);
}

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
const EFER_SCE: u64 = 1;
/// RFLAGS bits cleared on entry: TF, IF, DF, NT, AC.
const SFMASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18);

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: callers write the architectural system-call MSRs with values
    // that point at this module's entry stub and the kernel's GDT
    // selectors; `wrmsr` touches no memory.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nostack, preserves_flags))
    };
}

/// Enables `syscall`/`sysret` and installs `handler` for every system call.
/// Needs the kernel GDT (user segments) and runs with interrupts disabled.
pub fn init(handler: fn(&mut SyscallFrame)) {
    HANDLER.store(handler as *mut (), Ordering::Release);
    // STAR: kernel CS/SS from 0x08, user base 0x20 (sysret: SS 0x28|3,
    // CS 0x30|3).
    let user_base = u64::from(USER_DATA & !3) - 8;
    wrmsr(IA32_STAR, user_base << 48 | u64::from(KERNEL_CODE) << 32);
    wrmsr(IA32_LSTAR, pharos_syscall_entry as *const () as u64);
    wrmsr(IA32_FMASK, SFMASK);
    wrmsr(IA32_EFER, super::rdmsr(IA32_EFER) | EFER_SCE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_matches_stub_layout() {
        // The stub pushes user RSP first (highest address) and r9 last.
        assert_eq!(size_of::<SyscallFrame>(), 10 * 8);
        assert_eq!(core::mem::offset_of!(SyscallFrame, r9), 0);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rax), 6 * 8);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rsp), 9 * 8);
    }

    #[test]
    fn star_base_matches_gdt() {
        assert_eq!(u64::from(USER_DATA & !3) - 8, 0x20);
        assert_eq!(u64::from(USER_CODE & !3), 0x20 + 16);
    }

    #[test]
    fn sfmask_clears_interrupts_and_alignment_check() {
        assert_ne!(SFMASK & (1 << 9), 0, "IF");
        assert_ne!(SFMASK & (1 << 18), 0, "AC (SMAP)");
    }
}
