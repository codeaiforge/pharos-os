# kernel (`pharos-kernel`)

**Status: placeholder.** This crate is a temporary host-side architectural placeholder.

It is an ordinary Rust library compiled for the host. It does **not** boot, manage hardware, provide memory protection, or implement any operating-system functionality. It exists so the workspace, CI, and docs have a stable home for kernel work.

## What it contains

- `src/lib.rs`: crate documentation describing its placeholder status, a `STATUS` constant, and one test.

## What will change

The bootable kernel is planned for Phase 2 ([roadmap](../docs/project/implementation-roadmap.md), milestones M2.1–M2.2). The M2.1 decisions are accepted (D-001 to D-003); the design is in [docs/architecture/boot.md](../docs/architecture/boot.md). M2.2 will introduce:

- `#![no_std]` and `#![no_main]`;
- the built-in `x86_64-unknown-none` target on stable Rust;
- the Limine boot protocol, with protocol structures written in this crate;
- a linker script placing the kernel at `0xffffffff80000000`;
- an `xtask` build tool and QEMU boot tests with serial output (UEFI and BIOS).

None of these exist yet. Until then this crate must stay a normal host-buildable library so `cargo build --workspace` and `cargo test --workspace` work on a standard Linux machine.

## Rules for this crate

- No `unsafe` code while it remains a placeholder (enforced by the workspace lint).
- No hardware-specific code, inline assembly, or target-specific configuration until M2.2 work begins, following [boot.md](../docs/architecture/boot.md).
- Do not describe anything here as implemented unless it is tested.
