# Boot design

## 1. Status

- **Design:** Accepted (2026-10-26), based on decisions [D-001, D-002, D-003](../project/decision-log.md#accepted-decisions-m21).
- **Recovery and updates (M4.3, D-028, #161):** design **approved** (2026-11-06); [part 8](#8-recovery-and-updates-m43-d-028) is **planned, not implemented**.
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
       ├─ loads each module in boot/modules/ (M2.8: the filesystem image `root`)
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
boot/limine/limine.conf         one entry: protocol limine, path boot():/boot/kernel,
                                plus module_path/module_string per module
boot/modules/root               filesystem image packed from kernel/root/ (storage.md)
boot/limine/limine-bios.sys     Limine BIOS stage
boot/limine/limine-bios-cd.bin  BIOS El Torito image
boot/limine/limine-uefi-cd.bin  UEFI El Torito image
EFI/BOOT/BOOTX64.EFI            Limine UEFI application
```

Test-kernel images (`cargo xtask runner`, and `image`/`run --kernel`) carry the test modules instead of `root`: `pattern` and `odd`, with contents the test kernels know. The kernel records the modules before bootloader memory is reclaimed, since Limine's module list lives there ([storage.md](storage.md)).

Built with `xorriso -as mkisofs` (BIOS and EFI El Torito entries, protective MBR), then `limine bios-install`. File timestamps are set to a fixed `SOURCE_DATE_EPOCH` before `xorriso` runs, so images are byte-identical across builds.

### Build tool (`xtask`)

A host Rust crate (`xtask/`, standard library only) run as `cargo xtask <command>` through an alias in `.cargo/config.toml`.

| Command | Status | Does |
| --- | --- | --- |
| `build` | Implemented (#10) | Build `pharos-kernel` for `x86_64-unknown-none` (release) |
| `image [--kernel <ELF>]` | Implemented (#10) | Fetch and verify the pinned Limine release if needed, then assemble `target/xtask/image/pharos.iso`. Uses the built kernel unless `--kernel` is given |
| `run [--bios] [--gdb] [--kernel <ELF>]` | Implemented (#12; `--kernel` in #24) | Build, make the image, and boot it in QEMU (OVMF by default, SeaBIOS with `--bios`) with serial on the terminal and `isa-debug-exit` attached. Since M2.9 every run also attaches a read-only virtio-blk disk (`disk.img` next to the ISO: the `fs-good` test image) and, since #62, one network card: modern virtio-net on user-mode networking (`-nic none -netdev user,id=net0 -device virtio-net-pci,netdev=net0,disable-legacy=on`), with no other card. Exits 0 only on the kernel's success signal. `--gdb` waits for GDB on `localhost:1234`; `--kernel` boots the given ELF (for example a test kernel) instead of building the kernel |
| `test [--timeout <SECS>]` | Implemented (#14, #16) | Boot check under UEFI and BIOS headless (marker `PHAROS: boot ok`, printed only after `init` reports that every boot service succeeded, since #61), then every test kernel through `cargo test -p pharos-kernel --target x86_64-unknown-none --test '*'` (marker `PHAROS: tests ok`). Pass = QEMU status 33 and the marker, within 60 s per boot by default. Serial logs in `target/xtask/logs/`; the end of the log is printed on failure |
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
- host checks in CI, `scripts/check.sh`, and the docs use `--workspace --exclude pharos-kernel` (and, since M2.9, `--exclude pharos-programs`, the bare-metal user programs);
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

## 8. Recovery and updates (M4.3, D-028)

**Planned, not implemented.** Design approved (#161, 2026-11-06). It follows [D-028](../project/decision-log.md#d-028-boot-recovery-known-good-images-and-signed-updates): an update replaces only the root image; a factory image on the boot medium is always the fallback; `init` verifies and selects; signature and the user's yes before an update is applied.

### Images

| Image | Where | Written by | Holds |
| --- | --- | --- | --- |
| Factory | the boot medium: module `root`, and a second, identical copy as module `recovery` | the build only | every program and table (today's root image) |
| Slot A, slot B | store namespace `system`, files `a` and `b` | `init`, after the user approved | a signed root image |
| Incoming | store namespace `incoming`, files by name | the host tool, or the runtime for an agent's proposal | signed root images not yet approved |

- **The kernel** mounts `root`; if it fails its checks, it mounts `recovery` and tells `init` (mode `recovery`). Only if both fail does the boot stop (`no root filesystem`). The second copy guards against one damaged file, not a damaged medium. A mode from the command line (below) is passed to `init` as its `spawn` argument.
- **Always from the factory image:** `init`, the storage service, and `trust`. A slot cannot break the code that falls back or the trusted path. Every other service, and the policy tables and manifests they read (`Object::Root`), come from the selected image.

### Signed image format

A slot or incoming file is a 128-byte header followed by a `pharos-fs` image (at most 16 MiB):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `PHAROSIM` |
| 8 | 4 | header version, 1 |
| 12 | 4 | reserved, zero |
| 16 | 8 | image version (u64, from the build; strictly increasing per release) |
| 24 | 8 | image length in bytes |
| 32 | 32 | SHA-256 of the image |
| 64 | 64 | Ed25519 signature of bytes 0–63 |

- **Verification** (new crate `crates/pharos-image`, `no_std`, `unsafe` forbidden): every field checked, the length against the file, the SHA-256 recomputed (the `pharos-store` implementation), the signature checked with `ed25519-compact` (verify only, `default-features = false`) against one public key compiled into the factory `init`. Any failure is a typed error; it never panics; fuzzed on the host. The kernel then runs the existing `pharos-fs` checks on the mount.
- **Signing on the host:** `cargo xtask image sign <image> --version <n> --key <file>`. No private key is in the repository. Release keys stay with the maintainer, offline. Test images are signed with a key `xtask` generates under `target/xtask/keys/` on first use; test kernels' `init` is built with that public key (an environment variable read at build time, `PHAROS_IMAGE_KEY`; the default build without it trusts no key, so every slot is refused and the factory image runs).
- **Versions:** an incoming image is accepted only if its version is higher than every slot's that is `good`. Booting an existing slot needs no version check: it was checked when it was staged. So a rollback to the previous slot is allowed and an older image cannot be installed again.

### The slot record

One file, `system/state` (each write is one store commit, so it is always old or new, D-017): magic, format version, `active` (A, B, or none), a one-shot `next` mode (normal, safe, recovery), and per slot its state (`empty`, `staged`, `trying`, `good`, `bad`), its version, its SHA-256, and its attempts (u8). CRC-32 over the record. A missing or corrupt record is treated as no slots (factory), reported and audited, and rewritten empty.

### Boot flow in `init`

1. Start the storage service and `trust` from the factory image.
2. Read the mode: the kernel's (command line, or `recovery` after a bad `root`), else the record's `next`, which is cleared. `recovery` skips the slots.
3. Pick a candidate: the active slot if it is `good`, or `trying` with fewer than 3 attempts; else the other slot if `good`; else the factory image. A slot at 3 attempts becomes `bad`.
4. Write the attempt (`trying`, attempts + 1) **before** using the slot, so a crash, a hang, or a kernel fault during it counts on the next boot.
5. Read the slot into a buffer attached to the store, verify it (`pharos-image`), and mount it with `fs_mount` (below). A slot that fails becomes `bad` at once; go to 3.
6. Start the remaining services from the mounted image, as today (D-026 policies).
7. **Ready** (D-026) within 20 s of the first slot service starting: the slot becomes `good` with attempts 0 and `active`. Otherwise, or if a boot service failed after its restarts: stop every slot service (`process_stop`), count the attempt, and go to 3 **in place**, without a reboot. The factory image is the last candidate; if it is not ready either, `init` reports the failure as today.
8. Report to the kernel `[ready, failed, image]` (image: 0 factory, 1 A, 2 B, 3 recovery copy). The kernel waits up to 75 s (30 s before), enough for two slots and the factory image.

Every step is an audit record (`system` action: candidate, verified or refused with the reason, ready, fallback, mode) once the audit service runs, and a `trust` line from structured fields: `system: slot A version 7 failed (not ready in 20 s), trying factory`. Records before the audit service starts are kept and sent when it is ready, as today.

### The kernel call `fs_mount`

| No. | Call | Arguments | Result | Capability needed |
| --- | --- | --- | --- | --- |
| 27 | `fs_mount` | filesystem handle, `Memory` handle, offset, length (≤ 16 MiB) | new filesystem handle (`READ`, `GRANT`) | filesystem `MOUNT` (new right, `1 << 10`); memory `READ` |

- The kernel **copies** the range into frames it owns (charged to the caller's page limit), then mounts the copy with `pharos_fs::Image::mount`, so the caller cannot change the bytes after the checks. The copy is mapped nowhere in user space and freed when the last capability on it goes.
- **Only `init` holds `MOUNT`:** the kernel gives it on `init`'s root capability; every `Give(Root, …)` in `pharos-services` is `READ` only (an existing rule), so the capability audit (D-027) fails if any service gets `MOUNT`.
- At most two mounted images at once besides the boot modules (`NO_MEMORY` past that); `TOO_LARGE` over 16 MiB; a failed check is the new error `BAD_IMAGE` (13) with nothing kept. The fuzz test of `syscall::decode` covers it. No new `unsafe`: the copy uses the existing `mm::raw` frame slices.

### Recovery and safe mode

| Mode | Runs | Entered |
| --- | --- | --- |
| Normal | the selected image, everything | default |
| Safe | the selected image, every boot service except the agent runtime | Limine entry `Pharos OS (safe mode)` (`cmdline: safe`); `trust` command `safe` for the next boot |
| Recovery | the factory image, safe mode, slots ignored | Limine entry `Pharos OS (recovery)` (`cmdline: recovery`); `trust` command `recovery` for the next boot; automatically when `root` fails and `recovery` mounts, or when no candidate reaches ready |

- **Release images** get `timeout: 3` with the three entries; test images keep `timeout: 0` and boot one entry with the mode they test. The kernel reads the command line through the Limine executable command line request (a new structure in `limine.rs`); anything other than empty, `safe`, or `recovery` is reported and treated as normal.
- **Ready in safe mode and recovery** means every service started; the agent platform is reported as not started.
- **`stop all`** and every `trust` command work in every mode; `trust` and `init` never come from a slot.

### Updates

1. **Staging.** An image reaches `incoming` from the host (`cargo xtask store build` with an `incoming/` directory, as for models) or from an agent: a new runtime permission, `update propose`, lets an agent call a new runtime operation `PROPOSE` naming one of its data files; the runtime copies it to `incoming/<agent>-<n>` (the runtime gains `WRITE` on `incoming` only) and audits it. A proposal does nothing else.
2. **Review.** `trust` command `update`: `trust` asks `init` (on its report capability, as for `services`); `init` verifies each incoming image and answers from fields; `trust` shows `approve #<n>: update to version <v> (sha256 <first 16 hex>, from <agent or host>, now <v> on slot A)? (yes <n> / no <n>)`. An image that fails verification is shown as refused with the reason, never offered.
3. **Apply.** On `yes`, `init` copies the image into the slot that is not `active` (`staged`), deletes the incoming file, and tries it at once in place (steps 4–7 above, on the staged slot). Ready: it becomes `active` and `good`; the other slot keeps the previous image as the rollback target. Not ready: the slot becomes `bad`, the previous slot's services start again, and `trust` shows `update to version <v> failed, rolled back to <v'>`. `no`, no answer in 60 s, or `trust` unreachable mean no; the incoming file is deleted.
4. **Rollback by the user:** `trust` command `rollback` marks the active slot `bad` and makes the other `good` slot active, in place.
5. **Repair loops are bounded:** a slot `bad` is never tried again; an incoming image with a SHA-256 of a `bad` slot is refused; at most 4 incoming files, a fifth `PROPOSE` gets `NO_SPACE`.

### `trust` commands (new)

`system` (mode, image running, each slot's state, version, and SHA-256 prefix, incoming count), `update`, `rollback`, `safe`, `recovery`. Every answer comes from `init`'s fields; `trust` keeps no state.

### Security

- **Trust:** the factory image and the public key in it are the root of trust for updates; the boot medium is read-only. Limine and the firmware are unchanged (Secure Boot: #166, M5.5).
- **An agent** can only add a file to `incoming` (with `update propose`); it holds nothing on `init`, `trust`, `system`, or the kernel's `MOUNT`. Approval is the user's, on the trusted path, from fields. A signed image an agent proposes is still the maintainer's image.
- **Limits (accepted):** whoever holds the disk can erase the slots (the factory image runs) or replay a slot file with a lower version over a slot (refused only if a higher version was `good` in the record they can also rewrite): the record is not authenticated without a device secret (M5.5, with the audit anchor). The kernel and Limine are not updated.

### Tests

| Test | Checks |
| --- | --- |
| Host, `pharos-image` | Round trip with a test key; a changed byte in the header, the image, or the signature, a wrong key, a truncated file, a bad length, and an older version refused, each with its error; 100,000 mutated files never panic |
| Host, `init`'s selection (in `pharos-services` or `pharos_programs::system`) | Every record state and mode to its candidate; attempts counted before use; a corrupt record means factory; staging rules (version, `bad` hashes, 4 incoming) |
| Host, `syscall` | The fuzz test covers `fs_mount` |
| QEMU, `fsmount` | `fs_mount` with and without `MOUNT`, a corrupt image (`BAD_IMAGE`), 17 MiB (`TOO_LARGE`), a third mount (`NO_MEMORY`); the caller changes its buffer after mounting and reads the old bytes |
| QEMU, `recovery` (boot image, several boots on one store disk, as `store_crash`) | A corrupted slot, an unsigned slot, and a slot whose agent runtime never sends ready each end on the other slot or the factory image with `boot ok`; a slot killed mid-boot (QEMU killed) counts an attempt and is `bad` after 3; a corrupted `root` module boots `recovery`; `safe` and `recovery` entries start no agent runtime |
| QEMU, `update` | A host-staged update approved with `yes` becomes active; one that is not ready is rolled back in place; `no` and no answer leave it unapplied; an agent's `PROPOSE` is not applied without `yes`; a malfunctioning agent (spinning, flooding `PROPOSE`, trying `MOUNT` and the `system` namespace) cannot stop `stop all`, `recovery`, or the fallback |
| Mutations (gate, #167) | Skipping the attempt write, or accepting an unsigned slot, fails CI |
