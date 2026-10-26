//! # pharos-kernel (placeholder)
//!
//! This crate is a **temporary host-side architectural placeholder**. It
//! reserves the `kernel/` location and package name in the workspace so that
//! documentation, CI, and tooling can refer to it before kernel work begins.
//!
//! It is an ordinary `std` library built for the host. It does **not**:
//!
//! - boot on any machine or emulator,
//! - access or manage hardware,
//! - provide memory protection, scheduling, processes, or system calls,
//! - implement any operating-system functionality.
//!
//! The bootable kernel (entry point, Limine boot protocol, linker script) is
//! planned for M2.2. See `docs/architecture/boot.md`.
//!
//! The crate is `no_std` so it builds for `x86_64-unknown-none`; unit tests
//! still run on the host (`cargo test -p pharos-kernel --lib`).

#![cfg_attr(not(test), no_std)]

/// Human-readable implementation status of this crate.
pub const STATUS: &str = "host-side placeholder: not bootable, no hardware access, \
                          no operating-system functionality";

#[cfg(test)]
mod tests {
    use super::STATUS;

    #[test]
    fn status_declares_placeholder() {
        assert!(STATUS.contains("placeholder"));
        assert!(STATUS.contains("not bootable"));
    }
}
