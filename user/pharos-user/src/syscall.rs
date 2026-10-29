//! The only `unsafe` code in user space: the program entry stub, the
//! `syscall` instruction, volatile access to mapped device memory, the heap
//! allocator, and the memory functions the compiler calls (AGENTS.md
//! section 5, drivers.md, user-environment.md).

#![allow(unsafe_code)]

#[cfg(pharos_user)]
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

/// Memory functions the compiler calls for copies, fills, and comparisons.
/// User programs link no C library (D-016), so this crate supplies them.
/// Copies and fills use `rep movsb` and `rep stosb`, and comparisons
/// volatile reads, so the compiler cannot turn them into calls to
/// themselves.
#[cfg(pharos_user)]
mod mem {
    use core::ffi::{c_int, c_void};

    /// # Safety
    /// `dest` and `src` are valid for `n` bytes and do not overlap.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        // SAFETY: the caller guarantees both ranges are valid and disjoint;
        // `rep movsb` copies exactly `n` bytes forwards (DF is clear, as the
        // ABI requires at every call).
        unsafe {
            core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") dest => _, inout("rsi") src => _, options(nostack, preserves_flags));
        }
        dest
    }

    /// # Safety
    /// `dest` and `src` are valid for `n` bytes; they may overlap.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memmove(
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        let (dest, src) = (dest.cast::<u8>(), src.cast::<u8>());
        if n == 0 || (dest as usize) <= (src as usize) || (dest as usize) >= (src as usize) + n {
            // SAFETY: a forward copy is correct when `dest` starts at or
            // before `src`, or past the end of it; validity as for memcpy.
            unsafe { memcpy(dest.cast(), src.cast(), n) };
        } else {
            // SAFETY: `dest` lies inside `src`'s range after its start, so
            // copy backwards from the last byte (DF set for the copy and
            // cleared again, as the ABI requires); both ranges are valid
            // for `n` bytes (caller).
            unsafe {
                core::arch::asm!(
                    "std",
                    "rep movsb",
                    "cld",
                    inout("rcx") n => _,
                    inout("rdi") dest.add(n - 1) => _,
                    inout("rsi") src.add(n - 1) => _,
                    options(nostack),
                );
            }
        }
        dest.cast()
    }

    /// # Safety
    /// `dest` is valid for `n` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(dest: *mut c_void, c: c_int, n: usize) -> *mut c_void {
        // SAFETY: the caller guarantees `dest` is valid for `n` bytes;
        // `rep stosb` writes exactly those bytes (DF clear).
        unsafe {
            core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") dest => _, in("al") c as u8, options(nostack, preserves_flags));
        }
        dest
    }

    /// # Safety
    /// `a` and `b` are valid for `n` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
        let (a, b) = (a.cast::<u8>(), b.cast::<u8>());
        for i in 0..n {
            // SAFETY: `i < n` and the caller guarantees both are valid for
            // `n` bytes. Volatile reads keep the loop a loop.
            let (x, y) = unsafe { (a.add(i).read_volatile(), b.add(i).read_volatile()) };
            if x != y {
                return i32::from(x) - i32::from(y);
            }
        }
        0
    }

    /// # Safety
    /// As [`memcmp`].
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
        // SAFETY: the same contract as memcmp.
        unsafe { memcmp(a, b, n) }
    }

    /// Referenced by the prebuilt `core` for this target; never called,
    /// because programs abort on panic instead of unwinding.
    #[unsafe(no_mangle)]
    pub extern "C" fn rust_eh_personality() {}
}

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
/// ([`crate::mmio_map`]), a DMA buffer ([`crate::dma_alloc`]), or a buffer
/// that may be shared ([`crate::mem_map_buffer`], [`crate::mem_map_cap`]).
/// Accesses are volatile, bounds-checked, and naturally aligned; a bad
/// offset is a program bug and panics (ending the process). Values are
/// created only after the kernel confirmed the mapping. Device memory stays
/// mapped as long as the process; a buffer until [`crate::mem_unmap`], after
/// which using its `Mapped` is a program bug (it faults, or reaches whatever
/// this process maps there next, never another process's memory). Writing
/// a read-only shared mapping is a page fault that ends the process.
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

    /// The start address (for [`crate::mem_share`] and
    /// [`crate::mem_unmap`]).
    pub fn addr(&self) -> u64 {
        self.base as u64
    }

    /// Copies `buf.len()` bytes from `offset` into `buf` (8 bytes at a time
    /// where aligned).
    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let at = offset + i;
            if at % 8 == 0 && buf.len() - i >= 8 {
                buf[i..i + 8].copy_from_slice(&self.read64(at).to_le_bytes());
                i += 8;
            } else {
                buf[i] = self.read8(at);
                i += 1;
            }
        }
    }

    /// Copies `bytes` to `offset` (8 bytes at a time where aligned).
    pub fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            let at = offset + i;
            if at % 8 == 0 && bytes.len() - i >= 8 {
                let mut word = [0u8; 8];
                word.copy_from_slice(&bytes[i..i + 8]);
                self.write64(at, u64::from_le_bytes(word));
                i += 8;
            } else {
                self.write8(at, bytes[i]);
                i += 1;
            }
        }
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

/// Register probes for the `vector_state` test kernel (D-016): they put
/// known values in every vector register, let time pass, and read the
/// registers back, which only assembly can do.
pub mod vector {
    /// 16 registers of 32 bytes (AVX) or 16 (SSE), as u64 lanes.
    const LANES: usize = 64;

    /// Whether AVX is usable: CPUID reports AVX and OSXSAVE, and `XCR0`
    /// enables SSE and AVX state.
    #[allow(unused_unsafe)] // `__cpuid` is safe in recent Rust, `unsafe` in 1.85
    pub fn avx_enabled() -> bool {
        // SAFETY: CPUID is available in user mode and has no side effects.
        let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
        if leaf1.ecx & (1 << 27) == 0 || leaf1.ecx & (1 << 28) == 0 {
            return false;
        }
        let xcr0: u32;
        // SAFETY: OSXSAVE is set (checked), so XGETBV is allowed in user
        // mode; it only reads XCR0.
        unsafe {
            core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") xcr0, out("edx") _, options(nomem, nostack, preserves_flags))
        };
        xcr0 & 0b110 == 0b110
    }

    fn pattern(seed: u64) -> [u64; LANES] {
        core::array::from_fn(|i| {
            seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(i as u64 + 1)
        })
    }

    fn load(src: &[u64; LANES], avx: bool) {
        let s = src.as_ptr();
        if avx {
            // SAFETY: AVX is enabled (the caller checked `avx_enabled`); `s`
            // points to 512 readable bytes; only vector registers change, and
            // the caller expects that (they are clobbered by design).
            unsafe {
                core::arch::asm!(
                "vmovdqu ymm0, [{s} + 0]",
                "vmovdqu ymm1, [{s} + 32]",
                "vmovdqu ymm2, [{s} + 64]",
                "vmovdqu ymm3, [{s} + 96]",
                "vmovdqu ymm4, [{s} + 128]",
                "vmovdqu ymm5, [{s} + 160]",
                "vmovdqu ymm6, [{s} + 192]",
                "vmovdqu ymm7, [{s} + 224]",
                "vmovdqu ymm8, [{s} + 256]",
                "vmovdqu ymm9, [{s} + 288]",
                "vmovdqu ymm10, [{s} + 320]",
                "vmovdqu ymm11, [{s} + 352]",
                "vmovdqu ymm12, [{s} + 384]",
                "vmovdqu ymm13, [{s} + 416]",
                "vmovdqu ymm14, [{s} + 448]",
                "vmovdqu ymm15, [{s} + 480]",
                    s = in(reg) s,
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                    options(nostack, preserves_flags, readonly),
                );
            }
        } else {
            // SAFETY: SSE is always available to user programs (D-016); `s`
            // points to at least 256 readable bytes.
            unsafe {
                core::arch::asm!(
                "movdqu xmm0, [{s} + 0]",
                "movdqu xmm1, [{s} + 16]",
                "movdqu xmm2, [{s} + 32]",
                "movdqu xmm3, [{s} + 48]",
                "movdqu xmm4, [{s} + 64]",
                "movdqu xmm5, [{s} + 80]",
                "movdqu xmm6, [{s} + 96]",
                "movdqu xmm7, [{s} + 112]",
                "movdqu xmm8, [{s} + 128]",
                "movdqu xmm9, [{s} + 144]",
                "movdqu xmm10, [{s} + 160]",
                "movdqu xmm11, [{s} + 176]",
                "movdqu xmm12, [{s} + 192]",
                "movdqu xmm13, [{s} + 208]",
                "movdqu xmm14, [{s} + 224]",
                "movdqu xmm15, [{s} + 240]",
                    s = in(reg) s,
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                    options(nostack, preserves_flags, readonly),
                );
            }
        }
    }

    /// Fills the registers from `seed`, spins `spins` times without touching
    /// them (the process may be preempted meanwhile), stores them, and
    /// returns whether every lane is unchanged.
    pub fn registers_survive(seed: u64, spins: u64, avx: bool) -> bool {
        let want = pattern(seed);
        let mut got = [0u64; LANES];
        let s = want.as_ptr();
        let d = got.as_mut_ptr();
        let n = spins.max(1);
        if avx {
            // SAFETY: as in `load`; `d` points to 512 writable bytes; the loop
            // only counts `n` down.
            unsafe {
                core::arch::asm!(
                "vmovdqu ymm0, [{s} + 0]",
                "vmovdqu ymm1, [{s} + 32]",
                "vmovdqu ymm2, [{s} + 64]",
                "vmovdqu ymm3, [{s} + 96]",
                "vmovdqu ymm4, [{s} + 128]",
                "vmovdqu ymm5, [{s} + 160]",
                "vmovdqu ymm6, [{s} + 192]",
                "vmovdqu ymm7, [{s} + 224]",
                "vmovdqu ymm8, [{s} + 256]",
                "vmovdqu ymm9, [{s} + 288]",
                "vmovdqu ymm10, [{s} + 320]",
                "vmovdqu ymm11, [{s} + 352]",
                "vmovdqu ymm12, [{s} + 384]",
                "vmovdqu ymm13, [{s} + 416]",
                "vmovdqu ymm14, [{s} + 448]",
                "vmovdqu ymm15, [{s} + 480]",
                    "2:",
                    "dec {n}",
                    "jnz 2b",
                "vmovdqu [{d} + 0], ymm0",
                "vmovdqu [{d} + 32], ymm1",
                "vmovdqu [{d} + 64], ymm2",
                "vmovdqu [{d} + 96], ymm3",
                "vmovdqu [{d} + 128], ymm4",
                "vmovdqu [{d} + 160], ymm5",
                "vmovdqu [{d} + 192], ymm6",
                "vmovdqu [{d} + 224], ymm7",
                "vmovdqu [{d} + 256], ymm8",
                "vmovdqu [{d} + 288], ymm9",
                "vmovdqu [{d} + 320], ymm10",
                "vmovdqu [{d} + 352], ymm11",
                "vmovdqu [{d} + 384], ymm12",
                "vmovdqu [{d} + 416], ymm13",
                "vmovdqu [{d} + 448], ymm14",
                "vmovdqu [{d} + 480], ymm15",
                    s = in(reg) s,
                    d = in(reg) d,
                    n = inout(reg) n => _,
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                    options(nostack),
                );
            }
            got == want
        } else {
            // SAFETY: as above, with 256 bytes each.
            unsafe {
                core::arch::asm!(
                "movdqu xmm0, [{s} + 0]",
                "movdqu xmm1, [{s} + 16]",
                "movdqu xmm2, [{s} + 32]",
                "movdqu xmm3, [{s} + 48]",
                "movdqu xmm4, [{s} + 64]",
                "movdqu xmm5, [{s} + 80]",
                "movdqu xmm6, [{s} + 96]",
                "movdqu xmm7, [{s} + 112]",
                "movdqu xmm8, [{s} + 128]",
                "movdqu xmm9, [{s} + 144]",
                "movdqu xmm10, [{s} + 160]",
                "movdqu xmm11, [{s} + 176]",
                "movdqu xmm12, [{s} + 192]",
                "movdqu xmm13, [{s} + 208]",
                "movdqu xmm14, [{s} + 224]",
                "movdqu xmm15, [{s} + 240]",
                    "2:",
                    "dec {n}",
                    "jnz 2b",
                "movdqu [{d} + 0], xmm0",
                "movdqu [{d} + 16], xmm1",
                "movdqu [{d} + 32], xmm2",
                "movdqu [{d} + 48], xmm3",
                "movdqu [{d} + 64], xmm4",
                "movdqu [{d} + 80], xmm5",
                "movdqu [{d} + 96], xmm6",
                "movdqu [{d} + 112], xmm7",
                "movdqu [{d} + 128], xmm8",
                "movdqu [{d} + 144], xmm9",
                "movdqu [{d} + 160], xmm10",
                "movdqu [{d} + 176], xmm11",
                "movdqu [{d} + 192], xmm12",
                "movdqu [{d} + 208], xmm13",
                "movdqu [{d} + 224], xmm14",
                "movdqu [{d} + 240], xmm15",
                    s = in(reg) s,
                    d = in(reg) d,
                    n = inout(reg) n => _,
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                    options(nostack),
                );
            }
            got[..32] == want[..32]
        }
    }

    /// Fills every register with `value`, spins `spins` times (so other
    /// threads run while the registers hold it), and executes `ud2`: the
    /// process is killed (`#UD`) with `value` still in its registers.
    pub fn crash_holding(value: u64, spins: u64, avx: bool) -> ! {
        load(&[value; LANES], avx);
        // SAFETY: the loop only counts `spins` down, touching no vector
        // register; `ud2` then raises #UD and the kernel kills the process.
        unsafe {
            core::arch::asm!(
                "2:",
                "dec {n}",
                "jnz 2b",
                "ud2",
                n = in(reg) spins.max(1),
                options(noreturn, nomem, nostack),
            )
        }
    }

    /// Whether any 64-bit lane of the registers equals `value`, read
    /// without first writing them.
    pub fn registers_contain(value: u64, avx: bool) -> bool {
        let mut got = [0u64; LANES];
        let d = got.as_mut_ptr();
        if avx {
            // SAFETY: AVX is enabled (checked by the caller); `d` points to
            // 512 writable bytes; storing reads registers without changing
            // them.
            unsafe {
                core::arch::asm!(
                "vmovdqu [{d} + 0], ymm0",
                "vmovdqu [{d} + 32], ymm1",
                "vmovdqu [{d} + 64], ymm2",
                "vmovdqu [{d} + 96], ymm3",
                "vmovdqu [{d} + 128], ymm4",
                "vmovdqu [{d} + 160], ymm5",
                "vmovdqu [{d} + 192], ymm6",
                "vmovdqu [{d} + 224], ymm7",
                "vmovdqu [{d} + 256], ymm8",
                "vmovdqu [{d} + 288], ymm9",
                "vmovdqu [{d} + 320], ymm10",
                "vmovdqu [{d} + 352], ymm11",
                "vmovdqu [{d} + 384], ymm12",
                "vmovdqu [{d} + 416], ymm13",
                "vmovdqu [{d} + 448], ymm14",
                "vmovdqu [{d} + 480], ymm15",
                    d = in(reg) d,
                    options(nostack, preserves_flags),
                );
            }
        } else {
            // SAFETY: as above, 256 bytes.
            unsafe {
                core::arch::asm!(
                "movdqu [{d} + 0], xmm0",
                "movdqu [{d} + 16], xmm1",
                "movdqu [{d} + 32], xmm2",
                "movdqu [{d} + 48], xmm3",
                "movdqu [{d} + 64], xmm4",
                "movdqu [{d} + 80], xmm5",
                "movdqu [{d} + 96], xmm6",
                "movdqu [{d} + 112], xmm7",
                "movdqu [{d} + 128], xmm8",
                "movdqu [{d} + 144], xmm9",
                "movdqu [{d} + 160], xmm10",
                "movdqu [{d} + 176], xmm11",
                "movdqu [{d} + 192], xmm12",
                "movdqu [{d} + 208], xmm13",
                "movdqu [{d} + 224], xmm14",
                "movdqu [{d} + 240], xmm15",
                    d = in(reg) d,
                    options(nostack, preserves_flags),
                );
            }
        }
        got.contains(&value)
    }

    /// The SIMD control register.
    pub fn mxcsr() -> u32 {
        let mut v = 0u32;
        // SAFETY: STMXCSR stores the 32-bit MXCSR into `v`, a valid local.
        unsafe {
            core::arch::asm!("stmxcsr [{}]", in(reg) &mut v, options(nostack, preserves_flags))
        };
        v
    }
}

/// The heap (user-environment.md): size-class free lists for allocations
/// up to 32 KiB, carved from the static arena and then from 64 KiB
/// `mem_map` chunks; larger ones are their own mapping, unmapped when freed.
// Host builds only run its unit tests.
#[cfg_attr(not(pharos_user), allow(dead_code))]
mod heap {
    use core::alloc::Layout;
    use core::ptr::null_mut;

    /// Bytes of heap each program has before it needs `mem_map` (in its
    /// `.bss`).
    pub const HEAP_SIZE: usize = 256 * 1024;
    /// Largest size-class allocation; larger ones get their own mapping.
    pub const LARGE: usize = 32 * 1024;
    /// Bytes `mem_map`ped at a time for small allocations.
    pub const CHUNK: usize = 64 * 1024;
    const PAGE: usize = 4096;
    /// Size classes 16, 32, ..., [`LARGE`] bytes.
    const CLASSES: usize = 12;

    /// Maps `len` bytes (a multiple of 4096) and returns the address, or 0.
    pub type Map = fn(usize) -> usize;
    /// Unmaps a mapping [`Map`] returned.
    pub type Unmap = fn(usize, usize);

    /// The allocator's state. Free blocks hold the address of the next free
    /// block of their class in their first word (0 ends the list).
    // ponytail: chunks are never returned and blocks never split or merge,
    // so memory freed in one class serves only that class; return empty
    // chunks if a long-running service's footprint matters.
    pub struct Heap {
        free: [usize; CLASSES],
        /// The unused part of the current chunk.
        next: usize,
        end: usize,
        /// The static arena's bounds.
        arena: (usize, usize),
        map: Map,
        unmap: Unmap,
    }

    /// Size class of `layout`, or `None` for a large allocation. A block of
    /// class size `s` is aligned to `min(s, 4096)`, so rounding the size up
    /// to the alignment honours it.
    fn class(layout: Layout) -> Option<usize> {
        let size = layout
            .size()
            .max(layout.align())
            .max(16)
            .next_power_of_two();
        (size <= LARGE).then(|| size.trailing_zeros() as usize - 4)
    }

    impl Heap {
        /// A heap that first carves `arena` (`len` bytes at page-aligned
        /// `base`, unused by anything else).
        pub const fn new(base: usize, len: usize, map: Map, unmap: Unmap) -> Self {
            Self {
                free: [0; CLASSES],
                next: base,
                end: base + len,
                arena: (base, base + len),
                map,
                unmap,
            }
        }

        /// A block for `layout`, or null when out of memory or the
        /// alignment is above 4096.
        ///
        /// # Safety
        /// Every block on the free lists must be one this heap handed out
        /// and was given back with [`dealloc`](Self::dealloc), unused since.
        pub unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
            if layout.align() > PAGE {
                return null_mut();
            }
            let Some(class) = class(layout) else {
                let Some(len) = layout.size().checked_next_multiple_of(PAGE) else {
                    return null_mut();
                };
                let mapped = (self.map)(len);
                if mapped != 0 {
                    return mapped as *mut u8;
                }
                // No `mem_map` (a program started without a limit): carve
                // it from the arena while the arena lasts, as the old bump
                // heap did, so such programs keep working.
                let start = self.next.next_multiple_of(PAGE);
                if !self.in_arena(self.next) || start + len > self.end {
                    return null_mut();
                }
                self.next = start + len;
                return start as *mut u8;
            };
            let head = self.free[class];
            if head != 0 {
                // SAFETY: `head` is a free block of this class (the caller's
                // contract), at least 16 bytes and aligned, holding the next
                // free block's address.
                self.free[class] = unsafe { *(head as *const usize) };
                return head as *mut u8;
            }
            let size = 16 << class;
            let mut start = self.next.next_multiple_of(size.min(PAGE));
            // User addresses are below 2^47, so this cannot overflow.
            if start + size > self.end {
                let chunk = (self.map)(CHUNK);
                if chunk == 0 {
                    return null_mut();
                }
                (start, self.end) = (chunk, chunk + CHUNK);
            }
            self.next = start + size;
            start as *mut u8
        }

        fn in_arena(&self, addr: usize) -> bool {
            (self.arena.0..self.arena.1).contains(&addr)
        }

        /// Gives back a block [`alloc`](Self::alloc) returned for `layout`.
        ///
        /// # Safety
        /// `ptr` came from `alloc` on this heap with the same `layout`, and
        /// is not used after this call.
        pub unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
            match class(layout) {
                // ponytail: large blocks carved from the arena are never
                // reused; give programs that need more a limit.
                None if self.in_arena(ptr as usize) => {}
                None => (self.unmap)(ptr as usize, layout.size().next_multiple_of(PAGE)),
                Some(class) => {
                    // SAFETY: the block is ours again (the caller's contract)
                    // and holds at least one aligned word.
                    unsafe { *(ptr as *mut usize) = self.free[class] };
                    self.free[class] = ptr as usize;
                }
            }
        }
    }

    #[cfg(pharos_user)]
    mod global {
        use super::*;
        use core::cell::UnsafeCell;
        use core::sync::atomic::{AtomicBool, Ordering};

        #[repr(C, align(4096))]
        struct Arena(UnsafeCell<[u8; HEAP_SIZE]>);

        // SAFETY: only `Heap` touches the arena, under `LOCK`.
        unsafe impl Sync for Arena {}

        static ARENA: Arena = Arena(UnsafeCell::new([0; HEAP_SIZE]));

        fn map(len: usize) -> usize {
            crate::mem_map(len as u64).map_or(0, |addr| addr as usize)
        }

        fn unmap(addr: usize, len: usize) {
            let _ = crate::mem_unmap(addr as u64, len as u64);
        }

        struct Locked {
            lock: AtomicBool,
            heap: UnsafeCell<Option<Heap>>,
        }

        // SAFETY: `heap` is reached only while `lock` is held.
        unsafe impl Sync for Locked {}

        impl Locked {
            fn with<R>(&self, f: impl FnOnce(&mut Heap) -> R) -> R {
                while self
                    .lock
                    .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    core::hint::spin_loop();
                }
                // SAFETY: the lock gives this call the only reference.
                let slot = unsafe { &mut *self.heap.get() };
                let heap = slot.get_or_insert_with(|| {
                    Heap::new(ARENA.0.get() as usize, HEAP_SIZE, map, unmap)
                });
                let result = f(heap);
                self.lock.store(false, Ordering::Release);
                result
            }
        }

        // SAFETY: `Heap` hands out disjoint, aligned blocks of at least the
        // requested size (or null), and only blocks given back through
        // `dealloc` return to its free lists.
        unsafe impl core::alloc::GlobalAlloc for Locked {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // SAFETY: only this allocator fills the free lists.
                self.with(|heap| unsafe { heap.alloc(layout) })
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                // SAFETY: `GlobalAlloc`'s contract is `Heap::dealloc`'s.
                self.with(|heap| unsafe { heap.dealloc(ptr, layout) })
            }
        }

        #[global_allocator]
        static ALLOCATOR: Locked = Locked {
            lock: AtomicBool::new(false),
            heap: UnsafeCell::new(None),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::heap::*;

    #[test]
    fn vector_probes_work_on_the_host() {
        // Linux saves vector state too, so the probes must hold here.
        assert!(super::vector::registers_survive(1, 1_000_000, false));
        if super::vector::avx_enabled() {
            assert!(super::vector::registers_survive(2, 1_000_000, true));
        }
        assert_eq!(
            super::vector::mxcsr() & 0x1f80,
            0x1f80,
            "SIMD exceptions masked"
        );
    }

    // A fake `mem_map`: page-aligned host memory, with live mappings
    // counted.
    static MAPPED: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());
    static FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn fake_map(len: usize) -> usize {
        if FAIL.load(std::sync::atomic::Ordering::Relaxed) {
            return 0;
        }
        let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
        // SAFETY: a valid, non-zero-size layout.
        let addr = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
        if addr != 0 {
            MAPPED.lock().unwrap().push((addr, len));
        }
        addr
    }

    fn fake_unmap(addr: usize, len: usize) {
        let mut mapped = MAPPED.lock().unwrap();
        let i = mapped
            .iter()
            .position(|&m| m == (addr, len))
            .expect("whole mapping");
        mapped.remove(i);
        let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
        // SAFETY: allocated by `fake_map` with this layout.
        unsafe { std::alloc::dealloc(addr as *mut u8, layout) };
    }

    /// The heap under test, with safe calls: every test block is given
    /// back at most once, with its own layout, and never used after.
    struct Test(Heap);

    impl Test {
        fn alloc(&mut self, size: usize, align: usize) -> usize {
            let layout = core::alloc::Layout::from_size_align(size, align).unwrap();
            // SAFETY: only `free` below fills the free lists.
            unsafe { self.0.alloc(layout) as usize }
        }

        fn free(&mut self, p: usize, size: usize, align: usize) {
            let layout = core::alloc::Layout::from_size_align(size, align).unwrap();
            // SAFETY: the tests pass blocks `alloc` returned for this layout,
            // once, and do not touch them again.
            unsafe { self.0.dealloc(p as *mut u8, layout) }
        }
    }

    #[test]
    fn heap_aligns_reuses_maps_large_and_runs_out() {
        let arena = Box::leak(Box::new(Page([0; 8192])));
        let base = arena.0.as_mut_ptr() as usize;
        let mut heap = Test(Heap::new(base, 8192, fake_map, fake_unmap));
        let mut blocks = Vec::new();
        for (size, align) in [
            (1, 1),
            (24, 8),
            (3, 1),
            (100, 64),
            (4096, 4096),
            (8, 16),
            (5000, 8),
        ] {
            let p = heap.alloc(size, align);
            assert!(p != 0 && p % align == 0, "size {size} align {align}");
            blocks.push((p, size));
        }
        for (i, a) in blocks.iter().enumerate() {
            for b in &blocks[i + 1..] {
                assert!(a.0 + a.1 <= b.0 || b.0 + b.1 <= a.0, "overlap");
            }
        }
        let mapped = || MAPPED.lock().unwrap().clone();
        assert_eq!(mapped().len(), 1, "the arena ran out: one chunk");
        // Freed blocks come back for the same class.
        let (p, _) = blocks[1];
        heap.free(p, 24, 8);
        assert_eq!(heap.alloc(20, 4), p, "reused");
        // Large allocations are their own mapping, unmapped when freed.
        let big = heap.alloc(LARGE + 1, 8);
        assert!(big != 0 && big % 4096 == 0);
        assert!(mapped().contains(&(big, LARGE + 4096)));
        heap.free(big, LARGE + 1, 8);
        assert_eq!(mapped().len(), 1, "unmapped");
        assert_eq!(heap.alloc(8, 8192), 0, "alignment above 4096");
        assert_eq!(heap.alloc(isize::MAX as usize - 4096, 1), 0, "too large");
        FAIL.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            heap.alloc(LARGE + 1, 8),
            0,
            "mem_map refused, arena used up"
        );
        let fill = (0..3).all(|_| heap.alloc(LARGE, 8) != 0);
        assert!(!fill, "no chunk: the class runs out");
        FAIL.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn without_mem_map_large_blocks_come_from_the_arena() {
        fn refuse(_: usize) -> usize {
            0
        }
        fn never(_: usize, _: usize) {
            panic!("an arena block was unmapped");
        }
        let arena = Box::leak(Box::new(Big([0; 2 * LARGE])));
        let base = arena.0.as_mut_ptr() as usize;
        let mut heap = Test(Heap::new(base, 2 * LARGE, refuse, never));
        let small = heap.alloc(16, 8);
        let big = heap.alloc(LARGE + 1, 8);
        assert!(big >= base + 4096 && big % 4096 == 0 && big > small);
        heap.free(big, LARGE + 1, 8);
        assert_eq!(
            heap.alloc(LARGE + 1, 8),
            0,
            "not reused; the arena is used up"
        );
        assert_ne!(heap.alloc(16, 8), 0, "small blocks still fit");
    }

    #[repr(C, align(4096))]
    struct Big([u8; 2 * LARGE]);

    #[repr(C, align(4096))]
    struct Page([u8; 8192]);
}
