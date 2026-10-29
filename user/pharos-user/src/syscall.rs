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

/// The heap: a bump allocator, installed as the global allocator on the
/// bare-metal target.
// Host builds only run its unit test.
#[cfg_attr(not(pharos_user), allow(dead_code))]
mod heap {
    /// Bytes of heap each program has (in its `.bss`).
    pub const HEAP_SIZE: usize = 256 * 1024;

    #[repr(C, align(4096))]
    struct Arena(core::cell::UnsafeCell<[u8; HEAP_SIZE]>);

    // SAFETY: `Bump::alloc` hands out disjoint ranges of the arena (each byte
    // at most once, claimed through the atomic `NEXT`), so threads never share
    // a byte through it.
    unsafe impl Sync for Arena {}

    static ARENA: Arena = Arena(core::cell::UnsafeCell::new([0; HEAP_SIZE]));
    /// Offset of the first unclaimed arena byte.
    static NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// A bump allocator over a fixed arena: allocation claims the next aligned
    /// range; nothing is ever freed.
    // ponytail: never frees, fine for short-lived programs that allocate once
    // (mounting an image); add a free list when a long-running service needs one.
    pub struct Bump;

    // SAFETY: `alloc` returns either null or a range of `layout.size()` bytes
    // aligned to `layout.align()` inside the static arena that no other call
    // returned (the compare-exchange claims it exactly once). `dealloc` does
    // nothing, which is always allowed.
    unsafe impl core::alloc::GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
            use core::sync::atomic::Ordering::Relaxed;
            let base = ARENA.0.get().cast::<u8>();
            let mut next = NEXT.load(Relaxed);
            loop {
                // Align the address, not the offset (the arena is page-aligned,
                // so the two agree for every alignment up to 4096).
                let Some(start) = (base as usize + next)
                    .checked_next_multiple_of(layout.align())
                    .map(|a| a - base as usize)
                else {
                    return core::ptr::null_mut();
                };
                let end = match start.checked_add(layout.size()) {
                    Some(end) if end <= HEAP_SIZE => end,
                    _ => return core::ptr::null_mut(),
                };
                match NEXT.compare_exchange_weak(next, end, Relaxed, Relaxed) {
                    // SAFETY: `start <= end <= HEAP_SIZE`, so the pointer stays
                    // inside the arena.
                    Ok(_) => return unsafe { base.add(start) },
                    Err(current) => next = current,
                }
            }
        }

        unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
    }

    #[cfg(pharos_user)]
    #[global_allocator]
    static ALLOCATOR: Bump = Bump;
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

    #[test]
    fn bump_allocator_aligns_never_overlaps_and_runs_out() {
        use core::alloc::{GlobalAlloc, Layout};
        let heap = Bump;
        let mut ranges = Vec::new();
        for (size, align) in [(1, 1), (24, 8), (3, 1), (100, 64), (4096, 4096), (8, 16)] {
            let layout = Layout::from_size_align(size, align).unwrap();
            // SAFETY: a valid, non-zero-size layout.
            let p = unsafe { heap.alloc(layout) } as usize;
            assert!(p != 0 && p % align == 0, "size {size} align {align}");
            ranges.push(p..p + size);
        }
        for (i, a) in ranges.iter().enumerate() {
            for b in &ranges[i + 1..] {
                assert!(a.end <= b.start || b.end <= a.start, "overlap");
            }
        }
        let too_big = Layout::from_size_align(HEAP_SIZE, 1).unwrap();
        // SAFETY: as above.
        assert!(unsafe { heap.alloc(too_big) }.is_null(), "exhausted");
    }
}
