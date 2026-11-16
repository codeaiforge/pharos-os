//! Support for test kernels in `kernel/tests/` (decision D-009).
//!
//! A test kernel is a small `no_main` binary that Limine boots in QEMU. It
//! runs checks, prints one `PHAROS-TEST:` line per check, and ends with the
//! marker `PHAROS: tests ok` plus QEMU exit status 33, or `PHAROS: tests
//! FAILED` plus status 35. `cargo xtask runner` boots each test kernel and
//! applies the D-009 pass rule. Write a test kernel with [`test_kernel!`].
//!
//! [`test_kernel!`]: crate::test_kernel

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::x86_64::{_print_panic, QemuExit, halt, qemu_exit};
use crate::kprintln;
use crate::mm::raw::IrqMutex;

/// Final serial line of a passing test kernel. Must match `xtask`.
pub const TESTS_OK_MARKER: &str = "PHAROS: tests ok";

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Records the checks of the test kernel. A test kernel has one run, so all
/// handles share one count: an exception hook can create a handle, add
/// checks, and finish the run that `kmain` started.
pub struct TestRun(());

impl TestRun {
    pub const fn new() -> Self {
        Self(())
    }

    /// Records and prints the result of one check.
    pub fn check(&mut self, name: &str, ok: bool) {
        if ok {
            PASSED.fetch_add(1, Ordering::Relaxed);
            kprintln!("PHAROS-TEST: {name} ... ok");
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            kprintln!("PHAROS-TEST: {name} ... FAILED");
        }
    }

    /// Prints the summary and the final marker, signals QEMU, and halts.
    pub fn finish(self) -> ! {
        let (p, f) = (
            PASSED.load(Ordering::Relaxed),
            FAILED.load(Ordering::Relaxed),
        );
        kprintln!("PHAROS-TEST: {p} passed, {f} failed");
        if passed(p, f) {
            kprintln!("{TESTS_OK_MARKER}");
            qemu_exit(QemuExit::Success);
        } else {
            kprintln!("PHAROS: tests FAILED");
            qemu_exit(QemuExit::Failure);
        }
        halt()
    }
}

impl Default for TestRun {
    fn default() -> Self {
        Self::new()
    }
}

/// Sets up the frame allocator and the kernel's own page tables from the
/// Limine responses, as `kmain` does. Prints the reason and returns false on
/// failure. For test kernels that need memory management.
#[cfg(target_os = "none")]
pub fn init_memory(
    hhdm: Option<&crate::limine::HhdmResponse>,
    memmap: Option<&crate::limine::MemmapResponse>,
    image: Option<&crate::limine::ExecutableAddressResponse>,
) -> bool {
    use crate::arch::x86_64::paging::KernelImage;
    use crate::mm;

    let (Some(hhdm), Some(memmap), Some(image)) = (hhdm, memmap, image) else {
        kprintln!("init_memory: a Limine response is missing");
        return false;
    };
    let entries = || memmap.entries().map(|e| (e.base, e.length, e.kind));
    let image = KernelImage {
        physical_base: image.physical_base,
        virtual_base: image.virtual_base,
    };
    let result = mm::init_frames(hhdm.offset, entries())
        .and_then(|_| mm::init_paging(hhdm.offset, entries(), image));
    if let Err(error) = &result {
        kprintln!("init_memory: {error}");
    }
    result.is_ok()
}

/// Turns the IOMMU on from the bootloader's RSDP, as `kmain` does, so
/// devices can be granted: `DeviceHandle::grant` attaches each to its own
/// domain and refuses them without one (#243). Call after
/// [`init_memory`] and the heap, before granting a device. Panics (the
/// test fails) with the reason if the IOMMU cannot start.
#[cfg(target_os = "none")]
pub fn init_iommu(rsdp: Option<&crate::limine::RsdpResponse>) {
    use crate::acpi::{self, DirectMap};
    let dmar = rsdp
        .and_then(|r| r.address.checked_sub(crate::arch::x86_64::paging::hhdm()))
        .and_then(|rsdp| acpi::find(&DirectMap, rsdp, b"DMAR").ok().flatten())
        .and_then(|table| acpi::parse_dmar(&table).ok())
        .expect("init_iommu: no DMAR table");
    if let Err(error) = crate::iommu::init(&dmar) {
        panic!("init_iommu: {error}");
    }
}

/// Frames a test holds to leave the allocator nearly empty, from
/// [`hold_frames`]; give them back with [`release_frames`].
#[cfg(target_os = "none")]
pub struct HeldFrames(alloc::vec::Vec<(crate::mm::frame::Frame, usize)>);

/// Takes every free frame but `keep`, in contiguous runs (halved when none
/// that long is left): one entry per run, so a 2 or 4 GiB machine (half a
/// million frames or more) fits the 4 MiB kernel heap.
#[cfg(target_os = "none")]
pub fn hold_frames(keep: usize) -> HeldFrames {
    let mut held = alloc::vec::Vec::new();
    if let Some(frames) = crate::mm::frames().as_mut() {
        let mut spare = frames.stats().free.saturating_sub(keep);
        let mut run = 1 << 16;
        while spare > 0 && run > 0 {
            let n = run.min(spare);
            match frames.alloc_contiguous(n, 1) {
                Ok(frame) => {
                    held.push((frame, n));
                    spare -= n;
                }
                Err(_) => run /= 2,
            }
        }
    }
    HeldFrames(held)
}

/// Gives back what [`hold_frames`] took.
#[cfg(target_os = "none")]
pub fn release_frames(held: HeldFrames) {
    if let Some(frames) = crate::mm::frames().as_mut() {
        for (frame, n) in held.0 {
            let _ = frames.free_contiguous(frame, n);
        }
    }
}

/// A test kernel passes only if it ran at least one check and none failed,
/// so an empty test kernel cannot pass by accident.
pub fn passed(passed: usize, failed: usize) -> bool {
    passed > 0 && failed == 0
}

/// Hook for test kernels that expect a panic (for example out of memory).
static PANIC_HOOK: IrqMutex<Option<fn(&PanicInfo<'_>) -> !>> = IrqMutex::new(None);

/// Routes the next panic to `hook` instead of failing the run.
pub fn set_panic_hook(hook: fn(&PanicInfo<'_>) -> !) {
    *PANIC_HOOK.lock() = Some(hook);
}

/// Panic handler body for test kernels: a hook if one is set, otherwise
/// report and signal failure.
pub fn test_panic(info: &PanicInfo<'_>) -> ! {
    let hook = *PANIC_HOOK.lock();
    if let Some(hook) = hook {
        hook(info);
    }
    _print_panic(format_args!("PHAROS: panic: {info}\n"));
    qemu_exit(QemuExit::Failure);
    halt()
}

#[cfg(test)]
mod tests {
    use super::passed;

    #[test]
    fn verdict() {
        assert!(passed(3, 0));
        assert!(!passed(3, 1));
        assert!(!passed(0, 0), "a test kernel without checks must not pass");
    }
}
