# Boot evaluation (D-001, D-002, D-003)

- **Status:** Draft. Recommendations are **Proposed**, not accepted. They become decisions only after the QEMU prototype ([#3](https://github.com/codeaiforge/pharos-os/issues/3)) provides evidence and the maintainer accepts them ([#4](https://github.com/codeaiforge/pharos-os/issues/4)).
- **Implementation status:** Planned. Nothing here is implemented.
- **Research date:** 2026-10-26. Versions and maintenance facts are as of that date; see [Sources](#sources).
- **Roadmap:** [M2.1](../project/implementation-roadmap.md#m21--architecture-and-boot-protocol-decisions). **Issues:** [#1](https://github.com/codeaiforge/pharos-os/issues/1) (D-001), [#2](https://github.com/codeaiforge/pharos-os/issues/2) (D-002, D-003).

## Summary

| Decision | Recommendation (Proposed) | Fallback |
| --- | --- | --- |
| D-001 Bootloader and boot protocol | **Limine** bootloader with the **Limine boot protocol** | Multiboot2 (bootable by both GRUB and Limine) |
| D-002 Firmware | **UEFI primary**, BIOS secondary while it costs nothing kernel-side | UEFI only |
| D-003 Target, linker, build | Built-in **`x86_64-unknown-none`** on stable; small **linker script**; an **`xtask`** crate for image building and QEMU | Cargo aliases plus scripts |

## D-001 — Bootloader and boot protocol

### Options

**A. Limine (bootloader + Limine protocol).** Mature, actively released (v12.9.4, 2026-10-19). The bootloader is BSD-2-Clause, and the protocol specification is 0BSD. It supports x86-64 on BIOS and UEFI, plus Linux, Multiboot 1/2, and Limine protocols. The kernel is entered in 64-bit long mode, loaded at or above `0xffffffff80000000`, and receives a memory map, a higher-half direct map (HHDM), framebuffer, SMP, and other information through requests embedded in the kernel image. It supports UEFI Secure Boot with an enrolled config hash. Rust bindings: the `limine` crate (MIT OR Apache-2.0).

**B. Multiboot2 (for example via GRUB).** A long-established specification. On x86 the kernel is entered in **32-bit protected mode with paging disabled**, so the kernel must provide its own assembly trampoline (page tables, GDT, switch to long mode) before any Rust code runs in 64-bit mode. GRUB is GPL-3.0. That is compatible with distributing it alongside an Apache-2.0 kernel as a separate program, but adds source-offer and notice obligations for images that include GRUB. Building images uses host GRUB packages (`grub-mkrescue`, BIOS and EFI variants), whose versions follow the distribution. Rust bindings: the `multiboot2` crate (MIT/Apache-2.0, declares Rust 1.85.1, slightly above our 1.85 minimum). Limine can also boot Multiboot2 kernels.

**C. Rust `bootloader` crate (rust-osdev).** Pure Rust, MIT OR Apache-2.0, supports BIOS and UEFI, enters the kernel in long mode with its own boot-information API. Maintained (v0.11.17, 2026-07-27) but describes itself as experimental. **Building disk images requires a nightly Rust compiler** (and, in the recommended setup, the unstable `bindeps` Cargo feature). The kernel itself builds on stable `x86_64-unknown-none`.

**D. Custom UEFI loader (using the `uefi` crate).** Full control and all-Rust. The `uefi` crate is MIT OR Apache-2.0 but declares Rust **1.91**, above our 1.85 minimum. UEFI only. We would write and maintain ELF loading, page-table setup, memory-map handoff, and `ExitBootServices` ourselves. All of that becomes project code in the trusted computing base, and building it delays M2.2.

### Evaluation

Ratings: **Strong**, **Adequate**, **Weak**, relative to the other options.

| Criterion (from the decision log) | A. Limine | B. Multiboot2/GRUB | C. `bootloader` crate | D. Custom UEFI |
| --- | --- | --- | --- | --- |
| Maturity and maintenance | Strong: frequent releases, reference implementation of its protocol | Strong: long history | Adequate: maintained, self-described experimental | Weak: we are the maintainers |
| License compatibility (Apache-2.0) | Strong: BSD-2-Clause / 0BSD / MIT-Apache crate | Adequate: GPL-3.0 bootloader adds distribution obligations | Strong: MIT OR Apache-2.0 | Strong: MIT OR Apache-2.0 |
| BIOS and UEFI coverage | Strong: both | Strong: both | Strong: both | Weak: UEFI only |
| QEMU support | Strong | Strong | Strong | Strong (OVMF) |
| Kernel-side boot code (TCB, `unsafe`) | Strong: enters in long mode, higher half, with HHDM and memory map | Weak: 32-bit to 64-bit trampoline in assembly | Strong: enters in long mode | Weak: whole loader is ours |
| Rust integration | Adequate: crate exists; see supply-chain note | Adequate: `multiboot2` crate | Strong: designed for Rust kernels | Strong: `uefi` crate |
| Reproducible images without root, on stable Rust | Strong: pinned Limine release plus `xorriso`/FAT tools; stable Rust | Adequate: no root, but GRUB version follows host distribution | Weak: requires nightly Rust | Adequate: stable, but `uefi` needs Rust 1.91 |

### Supply-chain note on the `limine` crate

The official `limine-bootloader/limine-rs` repository stops at version 0.5.0. Versions 0.6.2–0.6.5 (latest 2026-06-07) were published by a crate co-owner from a personal repository (`robotman2412/limine-boot-rust`). The original Limine maintainers remain crate owners, so this looks like a maintenance handover, not a takeover. Mitigations if Limine is accepted:

- pin an exact crate version and review its source before adopting it; or
- implement the small subset of protocol structures we need ourselves. The specification is 0BSD and the structures are plain `#[repr(C)]` data.

Decide between these in #4, after the prototype.

### Recommendation (Proposed)

**Limine with the Limine protocol.** It minimizes boot-path `unsafe` code in the kernel (no mode-switch trampoline), covers BIOS and UEFI, has permissive licenses, and supports reproducible image builds on stable Rust. **Fallback: Multiboot2**, which keeps GRUB and Limine both available as loaders if the Limine protocol proves unsuitable. Options C and D are not recommended now: C needs nightly Rust, and D adds the most code and maintenance. D can be revisited later if owning the boot chain becomes a security requirement (for example for measured or verified boot in M4.3).

**Evidence still needed (from #3):** a Limine image boots our kernel in QEMU on UEFI (OVMF) and BIOS (SeaBIOS), built without root using a pinned Limine release.

## D-002 — BIOS and/or UEFI

### Options

- **UEFI only.** Matches modern hardware and is required for Secure Boot. In QEMU it needs OVMF firmware (Ubuntu/Mint package `ovmf`).
- **BIOS only.** QEMU's default firmware (SeaBIOS) boots it with no extra packages, but new x86 PCs increasingly ship without legacy BIOS compatibility. Not viable as the only path.
- **Both.** Wider coverage; doubles the boot test matrix.

### Evaluation

With Limine, one kernel binary and one hybrid image boot on both firmware types. Supporting BIOS therefore costs a second QEMU run in CI and no kernel code. With Multiboot2 or a custom loader the cost would differ.

### Recommendation (Proposed)

**UEFI is the primary, required path**, tested in CI with OVMF. **BIOS is supported as a secondary path while it requires no kernel-side code**, tested with SeaBIOS. If BIOS ever requires kernel-specific work, drop it via a new decision record. Revisit at M5.2 (hardware compatibility). Secure Boot is out of scope until M4.3, but this choice keeps it possible.

## D-003 — Rust target, linker, and build strategy

### Target

- **Built-in `x86_64-unknown-none`.** Tier 2 target with precompiled `core` and `alloc` via `rustup target add x86_64-unknown-none` (since Rust 1.62), so it works on **stable** Rust. Properties that suit a kernel: no `std`; no SIMD/floating-point registers by default; System V calling convention **without red zone**; ELF output; **`kernel` code model by default**, which places code in the top 2 GiB of the address space and matches Limine's `>= 0xffffffff80000000` load requirement.
- **Custom target JSON.** Full control, but requires nightly Rust (`-Z build-std`).

**Recommendation (Proposed): `x86_64-unknown-none` on stable.** Add `targets = ["x86_64-unknown-none"]` to `rust-toolchain.toml` so rustup installs it automatically.

### Linker

The built-in target produces ELF but does not define the kernel's memory layout. **Recommendation (Proposed):** a small linker script that sets the higher-half base, aligns segments to pages, and keeps the bootloader request sections (for Limine, the request markers must not be discarded). Confirm the exact script in the prototype.

### Build orchestration

| Option | Stable Rust | Notes |
| --- | --- | --- |
| Cargo aliases plus shell scripts | Yes | Simplest; shell logic is harder to test and less portable |
| **`xtask` crate** (host Rust binary invoked as `cargo xtask <cmd>`) | Yes | Builds the kernel with `--target`, assembles the image with the pinned Limine release, runs QEMU (D-009). Testable Rust, no extra tools beyond those it invokes |
| `build.rs` with artifact dependencies (`bindeps`) | **No** (nightly) | Pattern used by the `bootloader` crate |

**Recommendation (Proposed): an `xtask` crate.** It is a separate host tool. The `pharos` CLI stays read-only and never runs commands, as its documentation states.

### Effect on the host workspace

A `no_std`, `no_main` kernel binary cannot build or test for the host target, so `cargo test --workspace` and `cargo clippy --workspace --all-targets` would fail if the kernel stayed a normal member. Options:

1. Keep the kernel in the workspace, exclude it from `default-members`, run host commands with `--exclude pharos-kernel`, and lint the kernel separately with `--target x86_64-unknown-none`. One `Cargo.lock`, but the documented commands change.
2. Move the kernel to its own workspace (`exclude` it from the root). Host commands stay unchanged; two lock files.
3. Per-package target selection (`forced-target`). Unstable, nightly only. Not acceptable.

Separately, put target-independent kernel logic (for example frame allocators) in a `no_std` library crate that also builds for the host, so it can be unit-tested with `cargo test` (as planned for M2.5).

**Recommendation (Proposed): option 1**, with CI updated to run host checks with `--exclude pharos-kernel` and kernel checks with `--target x86_64-unknown-none`. Confirm in the prototype; option 2 is the fallback if option 1's flags prove error-prone.

### New tools (when accepted; not installed now)

| Tool | Purpose | Mint/Ubuntu |
| --- | --- | --- |
| `x86_64-unknown-none` target | Kernel compilation | via `rust-toolchain.toml` |
| QEMU | Boot and test | `sudo apt install qemu-system-x86` |
| OVMF | UEFI firmware for QEMU | `sudo apt install ovmf` |
| `xorriso` | Build ISO images | `sudo apt install xorriso` |
| Limine release | Bootloader binaries | downloaded at a pinned version with a verified checksum by `xtask` (exact mechanism decided in #4) |

## Open questions for the prototype (#3)

1. Does the linker script plus `x86_64-unknown-none` produce an image that Limine loads on both OVMF and SeaBIOS?
2. ISO (via `xorriso`) or FAT disk image: which is simpler to build reproducibly without root?
3. How should the pinned Limine release be fetched and verified (release tarball checksum, or vendored binaries)?
4. Does `--exclude pharos-kernel` in host commands work cleanly in CI and in rust-analyzer?

## Sources

All accessed 2026-10-26.

- Limine README and USAGE (v12.9.4): <https://github.com/limine-bootloader/limine>
- Limine boot protocol specification: <https://github.com/limine-bootloader/limine-protocol/blob/trunk/PROTOCOL.md>
- `limine` crate: <https://crates.io/crates/limine>; former repository: <https://github.com/limine-bootloader/limine-rs>; current repository: <https://github.com/robotman2412/limine-boot-rust>
- Rust `bootloader` README (v0.11.17): <https://github.com/rust-osdev/bootloader>
- `uefi` crate: <https://crates.io/crates/uefi>
- `multiboot2` crate: <https://crates.io/crates/multiboot2>
- Multiboot2 specification, section 3.3 "I386 machine state": <https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html>
- GRUB license (COPYING, GPL-3.0): <https://git.savannah.gnu.org/cgit/grub.git/tree/COPYING>
- Rust target `x86_64-unknown-none`: <https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html>
- Rust platform support tiers: <https://doc.rust-lang.org/rustc/platform-support.html>
