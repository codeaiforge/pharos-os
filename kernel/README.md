# kernel (`pharos-kernel`)

**Status: minimal kernel (M2.2).** Limine boots it on UEFI and BIOS. It checks the boot protocol revision, reads the memory map and other boot information, reports them over the COM1 serial port, and halts.

It has **no** interrupt handling, memory management, scheduling, processes, system calls, or drivers beyond serial. `cargo xtask run` boots it in QEMU and checks the result: the kernel signals success or failure through QEMU's `isa-debug-exit` device, only when CPUID reports a hypervisor. Automated boot tests in CI come with M2.3. Design: [docs/architecture/boot.md](../docs/architecture/boot.md).

## Layout

| Path | Contents |
| --- | --- |
| `src/main.rs` | Binary (`no_main`): the `kmain` entry point and the Limine request declarations |
| `src/lib.rs` | Library (`no_std`): crate overview and status |
| `src/limine.rs` | Limine protocol structures (base revision 6), written from the 0BSD specification |
| `src/boot_info.rs` | Hardware-independent interpretation of boot information (unit-tested on the host) |
| `src/arch/x86_64.rs` | Hardware layer: port I/O, COM1 serial, halt. All hardware `unsafe` code is here |
| `linker.ld` | Places the kernel at `0xffffffff80000000` and keeps the Limine request sections |
| `build.rs` | Passes `linker.ld` to the binary when building for `x86_64-unknown-none` |

## Build, test, and boot

```sh
cargo test -p pharos-kernel --lib                                        # host unit tests
cargo clippy -p pharos-kernel --target x86_64-unknown-none -- -D warnings # lint for the real target
cargo xtask build                                                         # kernel ELF
cargo xtask image                                                         # target/xtask/image/pharos.iso
```

Boot it in QEMU (builds the kernel and image first):

```sh
cargo xtask run          # UEFI (OVMF)
cargo xtask run --bios   # BIOS (SeaBIOS)
cargo xtask run --gdb    # wait for GDB; see docs/development/debugging.md
```

The serial output ends with `PHAROS: boot ok`, and the command exits 0 only on the kernel's success signal (QEMU exit status 33). Boot failures and panics print `PHAROS: boot failed: ...` or `PHAROS: panic: ...`; QEMU then exits with status 35 and `cargo xtask run` fails.

## Rules for this crate

- `unsafe` is denied by default (`Cargo.toml`). It is allowed only in `arch::x86_64` and `limine`, and every `unsafe` block needs a `// SAFETY:` comment; Clippy fails the build otherwise. `main.rs` uses only placement attributes (`link_section`, `no_mangle`).
- Follow the [D-004 constraints](../docs/project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries) for early kernel code: hardware access only through the hardware layer; no drivers beyond serial, interrupt controller, and timer; no filesystem, network, or agent code.
- Keep hardware-independent logic in host-testable modules with unit tests.
- Do not describe anything here as implemented unless it is tested.
