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

use crate::arch::x86_64::{_print_panic, QemuExit, halt, qemu_exit};
use crate::kprintln;

/// Final serial line of a passing test kernel. Must match `xtask`.
pub const TESTS_OK_MARKER: &str = "PHAROS: tests ok";

/// Counts the checks of one test kernel.
pub struct TestRun {
    passed: usize,
    failed: usize,
}

impl TestRun {
    pub const fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    /// Records and prints the result of one check.
    pub fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
            kprintln!("PHAROS-TEST: {name} ... ok");
        } else {
            self.failed += 1;
            kprintln!("PHAROS-TEST: {name} ... FAILED");
        }
    }

    /// Prints the summary and the final marker, signals QEMU, and halts.
    pub fn finish(self) -> ! {
        kprintln!(
            "PHAROS-TEST: {} passed, {} failed",
            self.passed,
            self.failed
        );
        if passed(self.passed, self.failed) {
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
