# Boot design

## 1. Status

- **Design:** Accepted (2026-10-26), based on decisions [D-001, D-002, D-003](../project/decision-log.md#accepted-decisions-m21).
- **Implementation:** Implemented in [M2.2](../project/implementation-roadmap.md#m22--minimal-bootable-x86-64-kernel) and [M2.3](../project/implementation-roadmap.md#m23--early-serial-output-and-qemu-boot-validation); the kernel boots on UEFI and BIOS and CI checks it. A throwaway prototype validated this design first ([evidence](boot-evaluation.md#prototype-evidence-3)). Exceptions and interrupts: [interrupts.md](interrupts.md).

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

- **CPU state:** 64-bit long mode with paging, PAE, write protection, and NX (if available) enabled; interrupts disabled (`RFLAGS = 0x2`); no IDT, TSS, or LDT; legacy PIC IRQs masked; kernel segments mapped in the higher half. Limine's GDT and boot stack live in bootloader-reclaimable memory, so `kmain` first switches to the kernel's own stack, which has an unmapped guard page below it (implemented, issue #22), then loads its own GDT and TSS (issue #20; `arch::x86_64::gdt`) and its IDT for CPU exceptions (issue #21; `arch::x86_64::idt`). After building its frame allocator it switches to its own page tables (issue #27; [memory.md](memory.md)), so Limine's page tables are no longer used either.
- **Requests:** the kernel declares requests as statics in `.limine_requests` sections, between the start and end markers. Required in M2.2: base revision, memory map, HHDM. Bootloader info and firmware type are optional but useful for diagnostics.
- **Revision check:** the kernel must verify that the base-revision tag's third value was set to 0. If not, it reports an error and halts, instead of running with a protocol it did not ask for.
- **Responses:** valid only until the kernel reclaims bootloader memory (issue #28; after that `response()` returns `None` and the kernel uses its own copy of the memory map). Read with volatile loads, because the bootloader writes them outside the compiler's view. A missing response is an error the kernel reports, not undefined behaviour.

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

A host Rust crate (`xtask/`, standard library only) run as `cargo xtask <command>` through an alias in `.cargo/config.toml`.

| Command | Status | Does |
| --- | --- | --- |
| `build` | Implemented (#10) | Build `pharos-kernel` for `x86_64-unknown-none` (release) |
| `image [--kernel <ELF>]` | Implemented (#10) | Fetch and verify the pinned Limine release if needed, then assemble `target/xtask/image/pharos.iso`. Uses the built kernel unless `--kernel` is given |
| `run [--bios] [--gdb] [--kernel <ELF>]` | Implemented (#12; `--kernel` in #24) | Build, make the image, and boot it in QEMU (OVMF by default, SeaBIOS with `--bios`) with serial on the terminal and `isa-debug-exit` attached. Exits 0 only on the kernel's success signal. `--gdb` waits for GDB on `localhost:1234`; `--kernel` boots the given ELF (for example a test kernel) instead of building the kernel |
| `test [--timeout <SECS>]` | Implemented (#14, #16) | Boot check under UEFI and BIOS headless (marker `PHAROS: boot ok`), then every test kernel through `cargo test -p pharos-kernel --target x86_64-unknown-none --test '*'` (marker `PHAROS: tests ok`). Pass = QEMU status 33 and the marker, within 60 s per boot by default. Serial logs in `target/xtask/logs/`; the end of the log is printed on failure |
| `runner <ELF>` | Implemented (#16) | Cargo `runner` for `x86_64-unknown-none` (`.cargo/config.toml`): wrap one test kernel in its own image under `target/xtask/runner/<name>/` and boot it headless under UEFI. The time limit comes from `cargo xtask test --timeout` via `PHAROS_TEST_TIMEOUT` |

`image` downloads `limine-binary.tar.xz` with `curl` into `target/xtask/limine-<version>/`, checks it with `sha256sum` against the SHA-256 pinned in `xtask/src/main.rs`, unpacks it with `tar`, and compiles the `limine` host tool with `cc`. A cached archive with the wrong hash, or a fresh download with the wrong hash, stops the build with an error; a bad download is deleted. The ISO also contains Limine's `LICENSE` (`boot/limine/LICENSE`) to meet its BSD-2-Clause notice requirement.

`xtask` runs external tools (`cargo`, `curl`, `sha256sum`, `tar`, `cc`, `xorriso`, and later `qemu-system-x86_64`) and writes only under `target/`. It adds no third-party crates. The `pharos` CLI keeps its read-only scope.

#### Updating the Limine pin

Maintainers only, as a deliberate change:

1. Download `limine-binary.tar.xz` and `limine-binary.tar.xz.sig` for the new version from the official release page (<https://github.com/limine-bootloader/limine/releases>).
2. Verify the signature in a temporary keyring with the maintainer key registered on GitHub (`curl -s https://github.com/mintsuki.gpg | gpg --import`), and check that its fingerprint is `05D2 9860 D0A0 668A AEFB 9D69 1F3C 021B ECA2 3821`. If the key changed, find out why before continuing.
3. Check that the archive's SHA-256 matches the digest GitHub shows for the asset.
4. Update `LIMINE_VERSION` and `LIMINE_SHA256` in `xtask/src/main.rs`, read Limine's changelog for protocol changes, and run the boot tests on UEFI and BIOS.
5. Record the update in `CHANGELOG.md`.

### Workspace layout

The kernel stays the `pharos-kernel` workspace member. In place since issue #9:

- the root `Cargo.toml` sets `default-members` without the kernel;
- host checks in CI, `scripts/check.sh`, and the docs use `--workspace --exclude pharos-kernel`;
- the kernel (library, binary, and test kernels) is linted with `cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' -- -D warnings`, and its library logic is unit-tested on the host with `cargo test -p pharos-kernel --lib`;
- `rust-toolchain.toml` lists `targets = ["x86_64-unknown-none"]`, and `.cargo/config.toml` sets `relocation-model=static` for that target only.

Editors: rust-analyzer's on-save check runs `scripts/ra-check.sh` (set in `.vscode/settings.json`), which mirrors the CI split. Its default `cargo clippy --workspace` would build the kernel for the host and report false errors. The hardware layer (`arch`) compiles on any x86-64 build so rust-analyzer can resolve it on an x86-64 host (#9).

Since issue #11: `cargo xtask build` builds the kernel binary. The kernel crate has its own lint table instead of inheriting `unsafe_code = "forbid"` (P-001): `unsafe_code = "deny"`, allowed only in `arch::x86_64` (and its submodules) and `limine`, plus Clippy's `undocumented_unsafe_blocks = "deny"`. The crate has a library (host-testable logic and the hardware layer) and a binary (entry point and Limine requests); `build.rs` passes `linker.ld` to the binary only when building for `x86_64-unknown-none`.

## 4. Security

- **Trust:** the firmware and Limine are part of the boot trusted computing base, but neither is project code. Limine is pinned to an exact release. `xtask` checks it against a SHA-256 committed in the repository. Whoever updates the pin also verifies the GPG signature by Limine's maintainer (key `05D2 9860 D0A0 668A AEFB 9D69 1F3C 021B ECA2 3821`).
- **Untrusted input:** boot information comes from the bootloader. The kernel checks the base revision and the presence of each required response, and treats counts and pointers as bounded by the protocol's guarantees. Further validation (for example, overlapping memory-map entries) is part of M2.5.
- **`unsafe`:** needed for port I/O, reading bootloader-written memory, and dereferencing response pointers. Kept in small, documented functions.
- **Not yet covered:** Secure Boot and measured boot (M4.3). Without an enrolled config hash, Limine provides no integrity guarantee for the kernel file.
- **Licensing:** boot images contain Limine binaries (BSD-2-Clause). Images that are distributed must include Limine's license notice.

## 5. Testing

- **M2.2 (done):** `cargo xtask run` and `cargo xtask run --bios` boot the kernel, which signals success through `isa-debug-exit` (QEMU exit status 33) or failure (35). The kernel writes to that port only when CPUID reports a hypervisor, so real hardware never sees it.
- **M2.3 (D-009 accepted):** `cargo xtask test` runs the boot check headless under UEFI and BIOS, then every test kernel in `kernel/tests/` under UEFI. A boot passes only with QEMU status 33 and its serial marker (`PHAROS: boot ok` or `PHAROS: tests ok`), within 60 seconds. OVMF writes its own output to serial first, so the marker is searched for, not matched against the whole log. Logs go to `target/xtask/logs/`, and their end is printed on failure.
- **CI:** the `qemu` job (Ubuntu 24.04 runner) installs QEMU, OVMF, and xorriso, runs `cargo xtask test`, then builds the ISO twice and compares SHA-256 hashes (D-009). It uploads no artifacts; failing serial logs are printed in the job output.
- **Host checks:** remain `cargo fmt`, Clippy, and tests with `--exclude pharos-kernel`.

## 6. Alternatives

See the [boot evaluation](boot-evaluation.md#d-001--bootloader-and-boot-protocol). In short: GRUB/Multiboot2 (needs a 32-bit trampoline; GPL-3.0; it remains the fallback protocol), the `bootloader` crate (needs nightly Rust for images), a custom UEFI loader (largest code and maintenance cost, UEFI only), FAT disk images (needs extra tools; no benefit for QEMU), and a separate kernel workspace (fallback if rust-analyzer handles the member poorly).

## 7. Open questions

- Exact QEMU automation and exit signalling for CI: decision D-009, needed by M2.3. The prototype's `isa-debug-exit` plus serial marker approach is the leading candidate.
- Framebuffer use for early output: not needed until a later milestone; serial is the primary channel.
