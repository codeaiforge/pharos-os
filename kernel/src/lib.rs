//! # pharos-kernel
//!
//! The Pharos OS kernel, at milestone M2.2: a minimal `no_std` x86-64 kernel
//! that Limine boots on UEFI and BIOS. Design: `docs/architecture/boot.md`.
//!
//! What it does today: start in the higher half, check the Limine protocol
//! revision, read the memory map and other boot information, report them over
//! the COM1 serial port, and halt. It loads its own GDT, TSS, and IDT and
//! reports CPU exceptions. It has **no** hardware interrupts, memory
//! management, scheduling, processes, or drivers beyond serial.
//!
//! This library holds the parts that do not depend on the entry point. Logic
//! that is independent of hardware is unit-tested on the host
//! (`cargo test -p pharos-kernel --lib`). The hardware layer compiles on any
//! x86-64 build but only runs in the kernel. The entry point is in `main.rs`.

#![cfg_attr(not(test), no_std)]

// Compiled on any x86-64 build (not only bare metal) so editors and host
// builds can analyse it; it is only executed by the kernel.
#[cfg(target_arch = "x86_64")]
pub mod arch;
pub mod boot_info;
pub mod limine;
pub mod sync;
#[cfg(target_arch = "x86_64")]
pub mod testing;

/// Prints to the kernel console (COM1), like `print!`.
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::_print(format_args!($($arg)*))
    };
}

/// Prints a line to the kernel console (COM1), like `println!`.
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::arch::x86_64::_print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Declares the kernel's Limine requests as a module named `requests` in the
/// calling crate: the base-revision tag plus bootloader info, firmware type,
/// HHDM, and memory map requests, between the start and end markers in the
/// `.limine_requests*` sections (kept by `linker.ld`).
///
/// Used by the kernel binary and by every test kernel. The statics must be
/// defined in the binary itself; statics in this library could be dropped by
/// the linker. The module uses only `unsafe` *attributes* (`link_section`),
/// which choose where data is placed; it contains no unsafe code.
#[macro_export]
macro_rules! limine_requests {
    () => {
        #[allow(unsafe_code)]
        mod requests {
            use $crate::limine::{
                BaseRevisionTag, BootloaderInfoResponse, FirmwareTypeResponse, HhdmResponse,
                MemmapResponse, REQUESTS_END_MARKER, REQUESTS_START_MARKER, Request,
                bootloader_info_request, firmware_type_request, hhdm_request, memmap_request,
            };

            #[used]
            #[unsafe(link_section = ".limine_requests_start")]
            static START: [u64; 4] = REQUESTS_START_MARKER;

            #[used]
            #[unsafe(link_section = ".limine_requests")]
            pub static BASE_REVISION_TAG: BaseRevisionTag = BaseRevisionTag::new();

            #[used]
            #[unsafe(link_section = ".limine_requests")]
            pub static BOOTLOADER_INFO: Request<BootloaderInfoResponse> = bootloader_info_request();

            #[used]
            #[unsafe(link_section = ".limine_requests")]
            pub static FIRMWARE_TYPE: Request<FirmwareTypeResponse> = firmware_type_request();

            #[used]
            #[unsafe(link_section = ".limine_requests")]
            pub static HHDM: Request<HhdmResponse> = hhdm_request();

            #[used]
            #[unsafe(link_section = ".limine_requests")]
            pub static MEMMAP: Request<MemmapResponse> = memmap_request();

            #[used]
            #[unsafe(link_section = ".limine_requests_end")]
            static END: [u64; 2] = REQUESTS_END_MARKER;
        }
    };
}

/// Defines a test kernel: Limine requests (as `requests`), the `kmain` entry
/// point, and the panic handler. `$run` is a `fn(&mut TestRun)` that performs
/// the checks. See [`testing`].
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! test_kernel {
    ($run:path) => {
        $crate::limine_requests!();

        /// Entry point named in `linker.ld`.
        #[allow(unsafe_code)] // `no_mangle` exports the symbol; the function is safe Rust.
        #[unsafe(no_mangle)]
        extern "C" fn kmain() -> ! {
            let mut run = $crate::testing::TestRun::new();
            $run(&mut run);
            run.finish()
        }

        #[panic_handler]
        fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
            $crate::testing::test_panic(info)
        }
    };
}

/// Human-readable implementation status of this crate.
pub const STATUS: &str = "minimal kernel: boots via Limine and reports boot information over \
                          serial; handles CPU exceptions; no hardware interrupts, memory management, \
                          scheduling, or processes";

#[cfg(test)]
mod tests {
    use super::STATUS;

    #[test]
    fn status_states_the_limits() {
        assert!(STATUS.contains("minimal"));
        assert!(STATUS.contains("no hardware interrupts"));
    }
}
