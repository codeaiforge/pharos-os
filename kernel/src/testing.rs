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

/// A test kernel passes only if it ran at least one check and none failed,
/// so an empty test kernel cannot pass by accident.
pub fn passed(passed: usize, failed: usize) -> bool {
    passed > 0 && failed == 0
}

/// Panic handler body for test kernels: report and signal failure.
pub fn test_panic(info: &PanicInfo<'_>) -> ! {
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
