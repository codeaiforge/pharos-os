# Boot evaluation (D-001, D-002, D-003; Secure Boot, #166)

The [Secure Boot evaluation](#secure-boot-evaluation-166-d-028) (M4.3) is at the end.

- **Status:** Complete. The recommendations were **accepted** on 2026-10-26 ([#4](https://github.com/codeaiforge/pharos-os/issues/4)), with own Limine protocol structures and the kernel as a workspace member. The resulting design is in [boot.md](boot.md). This document is kept as the record of options and evidence.
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

**Evidence (from #3):** a Limine 12.9.4 image booted a prototype kernel in QEMU on both UEFI (OVMF) and BIOS (SeaBIOS), built without root from a signature-verified release. See [Prototype evidence](#prototype-evidence-3).

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

## Prototype evidence (#3)

Source, exact commands, environment, and full output: [`prototypes/limine-boot` on the `proto/limine-boot` branch](https://github.com/codeaiforge/pharos-os/tree/proto/limine-boot/prototypes/limine-boot). The prototype is throwaway and is not merged into `main`.

**Environment:** Rust 1.99.1 stable, QEMU 8.2.2 (`q35`, TCG), OVMF 2024.02, xorriso 1.5.6, Limine 12.9.4 binary release.

| Check | UEFI (OVMF) | BIOS (SeaBIOS) |
| --- | --- | --- |
| Boots and reports pass (QEMU exit status 33 plus serial marker) | yes | yes |
| Kernel runs in the higher half (`0xffffffff80001140`) | yes | yes |
| Base revision 6 accepted | yes | yes |
| Bootloader info, firmware type, HHDM, memory map responses | all received | all received |
| Reported firmware type | UEFI (64-bit) | x86 BIOS |

The harness also reported **FAIL** (exit status 35) on both firmware types for a deliberately broken kernel, so it detects failures.

### Answers to the open questions

1. **Linker script plus `x86_64-unknown-none` with Limine on OVMF and SeaBIOS?** Yes. Two settings were needed: `-C relocation-model=static` and a linker script that keeps the `.limine_requests*` sections between the start and end markers. With them, one ELF and one hybrid ISO boot on both firmware types.
2. **ISO or FAT image?** **ISO** built with `xorriso` plus `limine bios-install` works without root and is byte-identical across clean builds, provided file timestamps are pinned before running `xorriso`. `SOURCE_DATE_EPOCH` alone left 9 differing bytes. A FAT disk image was not tried, because it needs extra tools (`mtools`, `sgdisk`) and offers no advantage for QEMU testing. Proposed: ISO.
3. **Fetching and verifying Limine?** The official GitHub release provides per-asset SHA-256 digests and GPG signatures. The prototype verified both; the signing key (`05D2 9860 D0A0 668A AEFB 9D69 1F3C 021B ECA2 3821`) is registered on the primary maintainer's GitHub account. Proposed for `xtask`: download a pinned release version, check a SHA-256 committed in the repository, and document the GPG check for maintainers who update the pin.
4. **`--exclude pharos-kernel` in practice?** Works. With the kernel as a workspace member, `default-members` plus `--exclude` keep every host command passing, including plain `cargo test`. The kernel checks and builds with `--target x86_64-unknown-none`, and target-specific `rustflags` in `.cargo/config.toml` do not affect host builds. Without the exclusion, `--workspace` commands fail as predicted. **Not tested:** rust-analyzer behaviour; check in the editor during M2.2 and fall back to option 2 (separate workspace) if it is poor.

### Additional findings

- Hand-written Limine protocol structures for six requests took about 100 lines, which supports the option of not depending on the `limine` crate (see [supply-chain note](#supply-chain-note-on-the-limine-crate)).
- OVMF writes console escape codes and boot messages to the serial port before the kernel starts, so tests must search for a marker rather than compare the whole log.
- QEMU boots under TCG (no KVM) took about one second each, fast enough for every CI run.

## Secure Boot evaluation (#166, D-028)

- **Status:** Complete; evaluation only. D-028 moved enforcement to M5.5, so nothing here changes the images `xtask` builds. **Implementation status:** not implemented.
- **Date:** 2026-11-07. **Roadmap:** [M4.3](../project/implementation-roadmap.md#m43--reliable-boot-and-recovery), enforcement in [M5.5](../project/implementation-roadmap.md#m55--reproducible-builds-release-artifacts-documentation-and-release-criteria).
- **Question:** how does a Pharos image behave under OVMF with Secure Boot on, and what must M5.5 do to make the chain from the firmware to the factory image hold?

**Environment:** QEMU 8.2.2 (`q35`, TCG), OVMF 2024.02 (Ubuntu `ovmf` 2024.02-2ubuntu0.10), sbsigntool 0.9.4, Limine 12.9.4 (the pinned release), the main image built by `cargo xtask image` on `main` at `0921577`. Secure Boot firmware: `OVMF_CODE_4M.secboot.fd`, which needs `-M q35,smm=on -global driver=cfi.pflash01,property=secure,value=on`. Variable stores: `OVMF_VARS_4M.ms.fd` (Microsoft's keys enrolled, Secure Boot on) and `OVMF_VARS_4M.snakeoil.fd` (Debian's public test key, `PkKek-1-snakeoil`, enrolled as PK, KEK, and in `db`, Secure Boot on). The snakeoil key stands in for our own key; it is public and must never sign a release.

**Procedure:** each case copies the image's `iso-root`, changes it, and rebuilds the ISO with `xtask`'s `xorriso` arguments. `BOOTX64.EFI` is replaced in both places that carry it: `EFI/BOOT/` and the El Torito FAT image `boot/limine/limine-uefi-cd.bin` (`mcopy -o`), which is the one OVMF boots from a CD. The steps, in this order:

1. Path hashes: append `#<BLAKE2b-512>` (`b2sum`) to every `path:` and `module_path:` in `limine.conf` (the kernel, `root`, and `recovery`, in all three entries).
2. Config hash: `limine enroll-config BOOTX64.EFI $(b2sum limine.conf | cut -d' ' -f1)`.
3. Signature: `sbsign --key <key> --cert <cert> BOOTX64.EFI`, checked with `sbverify`.

Then the image is booted for up to 60 s with serial and the screen captured. A pass is QEMU status 33 with `PHAROS: boot ok` (D-009).

| Case | Firmware and keys | Result |
| --- | --- | --- |
| Unchanged image | Secure Boot off (`OVMF_CODE_4M.fd`) | Boots |
| Unsigned Limine | Microsoft's keys | Refused by the firmware: `failed to load Boot0001 "UEFI QEMU DVD-ROM …": Access Denied`, then PXE |
| Unsigned Limine | Our test key | Refused by the firmware, `Access Denied` |
| Signed with our key | Microsoft's keys (our key not in `db`) | Refused by the firmware, `Access Denied` |
| Signed, no config hash | Our test key | **Boots.** Limine checks nothing: the config, kernel, and modules can be changed freely |
| Config hash enrolled and signed, paths without hashes | Our test key | Refused by Limine: `PANIC: Secure Boot is active and URI 'boot():/boot/kernel' has no associated hash!`, back to the menu |
| Paths hashed, config hash enrolled, signed | Our test key | **Boots** |
| The same image | Secure Boot off | Boots |
| Signed first, config hash enrolled after | Our test key | Refused by the firmware, `Access Denied`: `enroll-config` changes the binary and breaks the signature |
| One byte of the kernel changed | Our test key | Refused by Limine: `Blake2b hash for URI 'boot():/boot/kernel' does not match!` |
| One byte of the `root` module changed | Our test key | Refused by Limine: `Blake2b hash for URI 'boot():/boot/modules/root' does not match!` |
| A line added to `limine.conf` | Our test key | Refused by Limine: `CHECKSUM MISMATCH FOR CONFIG FILE`, system halted |

### Findings

1. **The chain holds with all three steps, and only with all three.** Firmware (`db`) → signed Limine → enrolled config hash → path hashes on the kernel and both factory image copies → `init`'s Ed25519 check of a slot with the key in the factory image (D-028). The slots are outside Limine's reach and need none of this; the factory image is covered by its path hash.
2. **A signed Limine without an enrolled config hash protects nothing past Limine.** M5.5 must enroll the hash for every signed build and check it before release. Limine asks for path hashes only once a config hash is enrolled.
3. **Order matters:** path hashes, then config hash, then signature. Any change to the kernel or a module changes the config hash and so the signed binary: every release re-signs Limine.
4. **The kernel and the services need no change.** The same image boots with Secure Boot on or off; nothing in Pharos reads the Secure Boot state.
5. **Signing is deterministic.** Signing Limine twice with the same key gave the same bytes, so a signed ISO can still be byte-identical across builds (D-009's check) for whoever holds the key. Others can compare after removing the signature (`sbattach --remove`).
6. **Failures are visible but only on screen.** Limine's refusals are drawn on the framebuffer, not written to serial, and wait for a key; the firmware's `Access Denied` reaches serial. A CI check for M5.5 needs a screen capture (QEMU `screendump`) or a timeout counted as a refusal.
7. **QEMU arguments differ:** the Secure Boot firmware needs SMM and a secure flash, so `qemu_args` would need a variant.

### Open for M5.5 (not tested here)

- Whose key: Limine is not signed by Microsoft, so a PC with only Microsoft's keys refuses it (as above). Either the user enrolls our key in the firmware, or a Microsoft-signed shim loads Limine with a key the user enrolls once (MOK). To be decided with installation.
- Measured boot: Limine's documentation, as recorded in [D-028](../project/decision-log.md)'s context, says a config hash also forces `measured_boot` where a TPM 2.0 exists. No software TPM (`swtpm`) is installed here, so this was not tried.
- The same source says the config editor is disabled under Secure Boot; not tried headless.
- Real hardware (M5.2), and a key that is ours, kept off the repository and CI (AGENTS.md §4).

## Sources

Boot evaluation: all accessed 2026-10-26. Secure Boot evaluation: the experiments above (2026-11-07), the `limine` tool's own `enroll-config --help`, and Limine's documentation as recorded in D-028's context.

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
