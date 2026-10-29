//! x87, SSE, and AVX state for threads (D-016, user-environment.md).
//!
//! The kernel is soft-float and never touches these registers, so only a
//! switch between threads must save and restore them: eagerly, on every
//! switch (lazy switching leaked state between processes on affected CPUs,
//! LazyFP). [`init`] enables SSE, and `XSAVE` with AVX when the CPU has both;
//! otherwise `FXSAVE` covers x87 and SSE. Each thread owns an [`Area`] that
//! starts in a clean state, so a new process never sees another's values.

use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};

/// Bytes per save area: `FXSAVE` needs 512, `XSAVE` with AVX 832.
pub const AREA_SIZE: usize = 1024;

/// One thread's saved registers, aligned as `FXSAVE` and `XSAVE` require.
#[repr(C, align(64))]
pub struct Area([u8; AREA_SIZE]);

impl Area {
    /// The state after `FNINIT`, with every SIMD exception masked: x87
    /// control word 0x037F, `MXCSR` 0x1F80, every register zero. For `XSAVE`
    /// the header is zero (`XSTATE_BV` = 0), so `XRSTOR` puts every enabled
    /// component in its initial state and loads `MXCSR` from here.
    pub const fn clean() -> Self {
        let mut a = [0u8; AREA_SIZE];
        a[0] = 0x7f; // FCW 0x037F
        a[1] = 0x03;
        a[24] = 0x80; // MXCSR 0x1F80
        a[25] = 0x1f;
        Self(a)
    }

    /// The saved `MXCSR` (for tests).
    pub fn mxcsr(&self) -> u32 {
        u32::from_le_bytes([self.0[24], self.0[25], self.0[26], self.0[27]])
    }
}

/// How state is saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Not set up yet: there is nothing to save (only the soft-float kernel
    /// has run).
    Off,
    /// `FXSAVE`/`FXRSTOR`: x87 and SSE.
    Fxsave,
    /// `XSAVE`/`XRSTOR` with `XCR0` = x87 | SSE | AVX.
    XsaveAvx,
}

static MODE: AtomicU8 = AtomicU8::new(0);

/// The current mode.
pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        1 => Mode::Fxsave,
        2 => Mode::XsaveAvx,
        _ => Mode::Off,
    }
}

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;
/// `XCR0` bits: x87, SSE, AVX.
const XCR0_AVX: u64 = 0b111;

/// Enables x87, SSE, and (if available) AVX for user code and picks the
/// save mode. Idempotent; called by the kernel's CPU setup before any
/// thread switch.
#[allow(unused_unsafe)] // `__cpuid_count` is safe in recent Rust, `unsafe` in 1.85
pub fn init() {
    if mode() != Mode::Off {
        return;
    }
    // SAFETY: CPUID exists on every x86-64 CPU and has no side effects.
    let leaf1 = unsafe { core::arch::x86_64::__cpuid_count(1, 0) };
    let xsave = leaf1.ecx & (1 << 26) != 0;
    let avx = leaf1.ecx & (1 << 28) != 0;
    let cr0: u64;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    let cr0 = (cr0 & !(CR0_EM | CR0_TS)) | CR0_MP | CR0_NE;
    // SAFETY: clearing EM and TS lets x87 and SSE instructions run; the
    // kernel (soft-float target) executes none, and every thread switch from
    // now on saves and restores them. MP and NE select the standard
    // exception reporting (`#NM` with TS, `#MF` for x87 errors).
    unsafe { asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags)) };
    let cr4: u64;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    let mut cr4 = cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT;
    let mut mode = Mode::Fxsave;
    if xsave && avx {
        cr4 |= CR4_OSXSAVE;
    }
    // SAFETY: OSFXSR and OSXMMEXCPT enable SSE and route SIMD exceptions to
    // vector 19; OSXSAVE (set only when CPUID reports XSAVE) enables XSAVE
    // and XSETBV. None of them changes how kernel code runs.
    unsafe { asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags)) };
    if xsave && avx {
        // SAFETY: OSXSAVE is set and the CPU supports XSAVE and AVX, so XCR0
        // may hold x87 | SSE | AVX (bit 0 must stay set).
        unsafe {
            asm!("xsetbv", in("ecx") 0u32, in("eax") XCR0_AVX as u32, in("edx") 0u32, options(nomem, nostack))
        };
        // SAFETY: as above, CPUID has no side effects. Leaf 0xD, sub-leaf 0:
        // EBX is the save size for the components now enabled in XCR0.
        let size = unsafe { core::arch::x86_64::__cpuid_count(0xd, 0) }.ebx as usize;
        mode = if size <= AREA_SIZE {
            Mode::XsaveAvx
        } else {
            // Larger than our areas (not expected for x87 | SSE | AVX):
            // turn AVX back off and use FXSAVE.
            // SAFETY: XCR0 = x87 | SSE is always valid with OSXSAVE.
            unsafe {
                asm!("xsetbv", in("ecx") 0u32, in("eax") 0b11u32, in("edx") 0u32, options(nomem, nostack))
            };
            Mode::Fxsave
        };
    }
    MODE.store(
        match mode {
            Mode::Off => 0,
            Mode::Fxsave => 1,
            Mode::XsaveAvx => 2,
        },
        Ordering::Relaxed,
    );
}

/// Saves the CPU's x87/SSE/AVX registers into `area`.
pub fn save(area: &mut Area) {
    let p = area.0.as_mut_ptr();
    match mode() {
        Mode::Off => {}
        // SAFETY: `p` is a 64-byte aligned, writable buffer of AREA_SIZE
        // bytes (at least 512, FXSAVE's size); FXSAVE only stores to it.
        Mode::Fxsave => unsafe {
            asm!("fxsave64 [{}]", in(reg) p, options(nostack, preserves_flags))
        },
        // SAFETY: as above; `init` checked that the XSAVE size for the
        // enabled components fits in AREA_SIZE. EDX:EAX selects x87 | SSE |
        // AVX, all enabled in XCR0.
        Mode::XsaveAvx => unsafe {
            asm!("xsave64 [{}]", in(reg) p, in("eax") XCR0_AVX as u32, in("edx") 0u32, options(nostack, preserves_flags))
        },
    }
}

/// Loads the x87/SSE/AVX registers from `area`, which holds either
/// [`Area::clean`] or what [`save`] stored (in the same mode).
pub fn restore(area: &Area) {
    let p = area.0.as_ptr();
    match mode() {
        Mode::Off => {}
        // SAFETY: `p` is 64-byte aligned and holds a valid FXSAVE image: the
        // clean image (reserved MXCSR bits clear) or one FXSAVE wrote. Only
        // the kernel writes areas.
        Mode::Fxsave => unsafe {
            asm!("fxrstor64 [{}]", in(reg) p, options(nostack, preserves_flags, readonly))
        },
        // SAFETY: as above for XSAVE: the clean image has a zero header
        // (XSTATE_BV = 0, standard form), or XSAVE wrote it in this mode, so
        // XRSTOR cannot fault on a reserved bit.
        Mode::XsaveAvx => unsafe {
            asm!("xrstor64 [{}]", in(reg) p, in("eax") XCR0_AVX as u32, in("edx") 0u32, options(nostack, preserves_flags, readonly))
        },
    }
}
