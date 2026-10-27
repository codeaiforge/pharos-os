//! # pharos-kernel
//!
//! The Pharos OS kernel, at milestone M2.2: a minimal `no_std` x86-64 kernel
//! that Limine boots on UEFI and BIOS. Design: `docs/architecture/boot.md`.
//!
//! What it does today: start in the higher half, check the Limine protocol
//! revision, read the memory map and other boot information, report them over
//! the COM1 serial port, and halt. It has **no** interrupt handling, memory
//! management, scheduling, processes, or drivers beyond serial.
//!
//! This library holds the parts that do not depend on the entry point. Logic
//! that is independent of hardware is unit-tested on the host
//! (`cargo test -p pharos-kernel --lib`); the hardware layer is compiled only
//! for the bare-metal target. The entry point is in `main.rs`.

#![cfg_attr(not(test), no_std)]

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod arch;
pub mod boot_info;
pub mod limine;

/// Human-readable implementation status of this crate.
pub const STATUS: &str = "minimal kernel: boots via Limine and reports boot information over \
                          serial; no interrupts, memory management, scheduling, or processes";

#[cfg(test)]
mod tests {
    use super::STATUS;

    #[test]
    fn status_states_the_limits() {
        assert!(STATUS.contains("minimal"));
        assert!(STATUS.contains("no interrupts"));
    }
}
