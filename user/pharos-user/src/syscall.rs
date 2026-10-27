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

/// Memory the kernel mapped for this process: device registers
/// ([`crate::mmio_map`]) or a DMA buffer ([`crate::dma_alloc`]). Accesses
/// are volatile, bounds-checked, and naturally aligned; a bad offset is a
/// program bug and panics (ending the process). Values are created only
/// after the kernel confirmed the mapping, which lasts as long as the
/// process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    base: usize,
    len: usize,
}

impl Mapped {
    /// Called only by the wrappers in `lib.rs`, after the kernel mapped
    /// `len` bytes at `base` into this process.
    pub(crate) fn new(base: u64, len: u64) -> Self {
        Self {
            base: base as usize,
            len: len as usize,
        }
    }

    /// Size in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false: mappings are at least one page.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn at(&self, offset: usize, size: usize) -> usize {
        assert!(
            offset % size == 0 && offset.checked_add(size).is_some_and(|end| end <= self.len),
            "mapped memory access out of bounds or misaligned"
        );
        self.base + offset
    }

    pub fn read8(&self, offset: usize) -> u8 {
        let at = self.at(offset, 1);
        // SAFETY: `at` lies inside memory the kernel mapped for this process
        // (checked by `at`), which stays mapped while the process lives.
        unsafe { (at as *const u8).read_volatile() }
    }

    pub fn read16(&self, offset: usize) -> u16 {
        let at = self.at(offset, 2);
        // SAFETY: as in `read8`; `at` is 2-byte aligned (checked).
        unsafe { (at as *const u16).read_volatile() }
    }

    pub fn read32(&self, offset: usize) -> u32 {
        let at = self.at(offset, 4);
        // SAFETY: as in `read8`; `at` is 4-byte aligned (checked).
        unsafe { (at as *const u32).read_volatile() }
    }

    pub fn read64(&self, offset: usize) -> u64 {
        let at = self.at(offset, 8);
        // SAFETY: as in `read8`; `at` is 8-byte aligned (checked).
        unsafe { (at as *const u64).read_volatile() }
    }

    pub fn write8(&self, offset: usize, value: u8) {
        let at = self.at(offset, 1);
        // SAFETY: as in `read8`; the kernel maps these pages writable, and no
        // Rust reference points into them.
        unsafe { (at as *mut u8).write_volatile(value) }
    }

    pub fn write16(&self, offset: usize, value: u16) {
        let at = self.at(offset, 2);
        // SAFETY: as in `write8`; `at` is 2-byte aligned (checked).
        unsafe { (at as *mut u16).write_volatile(value) }
    }

    pub fn write32(&self, offset: usize, value: u32) {
        let at = self.at(offset, 4);
        // SAFETY: as in `write8`; `at` is 4-byte aligned (checked).
        unsafe { (at as *mut u32).write_volatile(value) }
    }

    pub fn write64(&self, offset: usize, value: u64) {
        let at = self.at(offset, 8);
        // SAFETY: as in `write8`; `at` is 8-byte aligned (checked).
        unsafe { (at as *mut u64).write_volatile(value) }
    }
}
