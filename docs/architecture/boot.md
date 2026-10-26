# Boot design

## 1. Status

- **Design:** Accepted (2026-10-26), based on decisions [D-001, D-002, D-003](../project/decision-log.md#accepted-decisions-m21).
- **Implementation:** Planned for [M2.2](../project/implementation-roadmap.md#m22--minimal-bootable-x86-64-kernel) and [M2.3](../project/implementation-roadmap.md#m23--early-serial-output-and-qemu-boot-validation). Nothing on `main` boots yet. A throwaway prototype validated this design ([evidence](boot-evaluation.md#prototype-evidence-3)).

## 2. Context

The kernel needs a reproducible way to be built, packaged, and started on x86-64 machines, first in QEMU. Constraints from the [vision](../project/vision.md) and [AGENTS.md](../../AGENTS.md): stable Rust, minimal `unsafe`, a small trusted computing base, reproducible builds, and no root privileges to build or test. The options were compared in the [boot evaluation](boot-evaluation.md).

## 3. Design

### Boot flow

```text
firmware (UEFI: OVMF / BIOS: SeaBIOS)
  └─ Limine (pinned release; BOOTX64.EFI or limine-bios.sys)
       ├─ reads boot/limine/limine.conf
       ├─ loads boot/kernel (ELF) at 0xffffffff80000000
       ├─ answers the kernel's Limine requests (memory map, HHDM, ...)
       └─ jumps to the kernel entry point in 64-bit long mode
            └─ kernel: set up serial, read boot info, continue initialization
```

### Kernel entry contract (Limine protocol, base revision 6)

- **CPU state:** 64-bit long mode with paging, PAE, write protection, and NX (if available) enabled; interrupts disabled (`RFLAGS = 0x2`); no IDT, TSS, or LDT; legacy PIC IRQs masked; kernel segments mapped in the higher half. Limine's GDT lives in bootloader-reclaimable memory, so the kernel must load its own GDT, and set up an IDT, before reclaiming that memory or enabling interrupts (M2.4).
- **Requests:** the kernel declares requests as statics in `.limine_requests` sections, between the start and end markers. Required in M2.2: base revision, memory map, HHDM. Bootloader info and firmware type are optional but useful for diagnostics.
- **Revision check:** the kernel must verify that the base-revision tag's third value was set to 0. If not, it reports an error and halts, instead of running with a protocol it did not ask for.
- **Responses:** read with volatile loads, because the bootloader writes them outside the compiler's view. A missing response is an error the kernel reports, not undefined behaviour.

### Protocol structures

Written in the project from the 0BSD Limine specification (decision D-001), not taken from the `limine` crate. They live in one module, each structure documented with its specification section. Adopting a newer base revision is a deliberate change: update the structures, read the spec's revision changes, and run the boot tests.

### Target and linking

- Target `x86_64-unknown-none` on stable Rust: `kernel` code model, no red zone, soft-float by default.
- `-C relocation-model=static`, set under `[target.x86_64-unknown-none]` in `.cargo/config.toml` so host builds are unaffected.
- A project linker script: base `0xffffffff80000000`; separate page-aligned load segments for requests (RW), text (RX), rodata (R), and data/bss (RW); `KEEP` for the request sections; discard `.eh_frame` and notes.

### Image

A hybrid BIOS/UEFI ISO:

```text
boot/kernel                     kernel ELF
boot/limine/limine.conf         one entry: protocol limine, path boot():/boot/kernel
boot/limine/limine-bios.sys     Limine BIOS stage
boot/limine/limine-bios-cd.bin  BIOS El Torito image
boot/limine/limine-uefi-cd.bin  UEFI El Torito image
EFI/BOOT/BOOTX64.EFI            Limine UEFI application
```

Built with `xorriso -as mkisofs` (BIOS and EFI El Torito entries, protective MBR), then `limine bios-install`. File timestamps are set to a fixed `SOURCE_DATE_EPOCH` before `xorriso` runs, so images are byte-identical across builds.

### Build tool (`xtask`)

A host Rust crate run as `cargo xtask <command>`. Planned commands (names may change in M2.2):

| Command | Does |
| --- | --- |
| `build` | Build the kernel for `x86_64-unknown-none` (release) |
| `image` | Fetch and verify the pinned Limine release if needed, then assemble the ISO |
| `run [--bios]` | Boot the ISO in QEMU (UEFI by default) with serial on stdout |
| `test` | Boot under UEFI and BIOS headless and report pass/fail (D-009, M2.3) |

`xtask` runs external tools (`cargo`, `xorriso`, `qemu-system-x86_64`) and writes only under `target/`. The `pharos` CLI keeps its read-only scope.

### Workspace layout

The kernel stays the `pharos-kernel` workspace member. In place since issue #9:

- the root `Cargo.toml` sets `default-members` without the kernel;
- host checks in CI, `scripts/check.sh`, and the docs use `--workspace --exclude pharos-kernel`;
- the kernel is linted with `cargo clippy -p pharos-kernel --target x86_64-unknown-none -- -D warnings`, and its library logic is unit-tested on the host with `cargo test -p pharos-kernel --lib`;
- `rust-toolchain.toml` lists `targets = ["x86_64-unknown-none"]`, and `.cargo/config.toml` sets `relocation-model=static` for that target only.

Still to come in M2.2: `xtask` builds the kernel binary; the kernel crate overrides the workspace `unsafe_code = "forbid"` lint (P-001), with every `unsafe` block documented.

## 4. Security

- **Trust:** the firmware and Limine are part of the boot trusted computing base, but neither is project code. Limine is pinned to an exact release. `xtask` checks it against a SHA-256 committed in the repository. Whoever updates the pin also verifies the GPG signature by Limine's maintainer (key `05D2 9860 D0A0 668A AEFB 9D69 1F3C 021B ECA2 3821`).
- **Untrusted input:** boot information comes from the bootloader. The kernel checks the base revision and the presence of each required response, and treats counts and pointers as bounded by the protocol's guarantees. Further validation (for example, overlapping memory-map entries) is part of M2.5.
- **`unsafe`:** needed for port I/O, reading bootloader-written memory, and dereferencing response pointers. Kept in small, documented functions.
- **Not yet covered:** Secure Boot and measured boot (M4.3). Without an enrolled config hash, Limine provides no integrity guarantee for the kernel file.
- **Licensing:** boot images contain Limine binaries (BSD-2-Clause). Images that are distributed must include Limine's license notice.

## 5. Testing

- **M2.2:** the kernel boots under OVMF and SeaBIOS in QEMU and signals success through `isa-debug-exit` (exit status 33). This was demonstrated in the prototype.
- **M2.3:** `cargo xtask test` runs both boots headless in CI with a timeout and requires both the exit status and a serial marker. OVMF writes its own output to serial first, so tests search for the marker. A deliberately failing kernel must make the test fail.
- **Reproducibility:** CI builds the ISO twice and compares SHA-256 hashes (planned; added with the image step).
- **Host checks:** remain `cargo fmt`, Clippy, and tests with `--exclude pharos-kernel`.

## 6. Alternatives

See the [boot evaluation](boot-evaluation.md#d-001--bootloader-and-boot-protocol). In short: GRUB/Multiboot2 (needs a 32-bit trampoline; GPL-3.0; it remains the fallback protocol), the `bootloader` crate (needs nightly Rust for images), a custom UEFI loader (largest code and maintenance cost, UEFI only), FAT disk images (needs extra tools; no benefit for QEMU), and a separate kernel workspace (fallback if rust-analyzer handles the member poorly).

## 7. Open questions

- rust-analyzer behaviour with a `no_std` workspace member (check in M2.2).
- Exact QEMU automation and exit signalling for CI: decision D-009, needed by M2.3. The prototype's `isa-debug-exit` plus serial marker approach is the leading candidate.
- Framebuffer use for early output: not needed until a later milestone; serial is the primary channel.
