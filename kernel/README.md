# kernel (`pharos-kernel`)

**Status: minimal kernel (M2.4 in progress).** Limine boots it on UEFI and BIOS. It loads its own GDT, TSS, and IDT, checks the boot protocol revision, reads the memory map and other boot information, reports them over the COM1 serial port, and halts. CPU exceptions are reported over serial.

It has **no** hardware interrupts, memory management, scheduling, processes, system calls, or drivers beyond serial. `cargo xtask run` boots it in QEMU and checks the result: the kernel signals success or failure through QEMU's `isa-debug-exit` device, only when CPUID reports a hypervisor. CI runs the boot check and the test kernels on every push. Design: [docs/architecture/boot.md](../docs/architecture/boot.md).

## Layout

| Path | Contents |
| --- | --- |
| `src/main.rs` | Binary (`no_main`): the `kmain` entry point; Limine requests declared with `limine_requests!` |
| `src/lib.rs` | Library (`no_std`): crate overview and status |
| `src/limine.rs` | Limine protocol structures (base revision 6), written from the 0BSD specification |
| `src/boot_info.rs` | Hardware-independent interpretation of boot information (unit-tested on the host) |
| `src/testing.rs` | Support for test kernels: `TestRun`, the `test_kernel!` macro, the test panic handler |
| `tests/` | Test kernels (one `no_main` kernel per file), booted in QEMU by `cargo xtask test` |
| `src/sync.rs` | `SpinLock`: a lock without `unsafe` for resources such as the serial port (unit-tested on the host, including with threads) |
| `src/arch/x86_64.rs` | Hardware layer: port I/O, COM1 serial and the kernel console behind `kprint!`/`kprintln!`, interrupt enable/disable and `without_interrupts`, QEMU exit signal, halt. All hardware `unsafe` code is here and in its submodules |
| `src/arch/x86_64/gdt.rs` | The kernel's own GDT (null, kernel code, kernel data, TSS) and TSS with a 16 KiB double-fault stack (IST1); loaded by `gdt::init()` at the start of `kmain`. Descriptor encoding is unit-tested on the host |
| `src/arch/x86_64/idt.rs` | IDT with `global_asm!` entry stubs for CPU exceptions 0–31, the exception dispatcher and serial report, and test helpers (breakpoint, page-fault probe, fatal hook). Frame layout, gate encoding, and report text are unit-tested on the host |
| `linker.ld` | Places the kernel at `0xffffffff80000000` and keeps the Limine request sections |
| `build.rs` | Passes `linker.ld` to the binary when building for `x86_64-unknown-none` |

## Build, test, and boot

```sh
cargo test -p pharos-kernel --lib                                        # host unit tests
cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' -- -D warnings  # lint for the real target, incl. test kernels
cargo xtask build                                                         # kernel ELF
cargo xtask image                                                         # target/xtask/image/pharos.iso
```

Boot it in QEMU (builds the kernel and image first):

```sh
cargo xtask run          # UEFI (OVMF)
cargo xtask run --bios   # BIOS (SeaBIOS)
cargo xtask run --gdb    # wait for GDB; see docs/development/debugging.md
cargo xtask test         # headless boot check (UEFI and BIOS) and the test kernels
```

To add a kernel test, see [Kernel tests (QEMU)](../docs/development/testing.md#kernel-tests-qemu).

The serial output ends with `PHAROS: boot ok`, and the command exits 0 only on the kernel's success signal (QEMU exit status 33). Boot failures and panics print `PHAROS: boot failed: ...` or `PHAROS: panic: ...`; QEMU then exits with status 35 and `cargo xtask run` fails.

## Printing

Use `kprint!` and `kprintln!` (exported by the library) for all output. They write to COM1 through one console behind a `SpinLock`, so lines from different code paths do not interleave; COM1 is configured on first use. The panic handler releases the lock before printing, so a panic inside a `kprintln!` still reports itself (the interrupted line may be cut short).

The console is **interrupt-safe**: it disables interrupts while holding the lock and then restores the previous state (`arch::x86_64::without_interrupts`), so an interrupt handler never waits for a holder it interrupted. A CPU exception can still hit while the lock is held (for example a page fault inside `kprintln!`), so fatal exception handlers, like the panic handler, print through `_print_panic`, which releases the lock first. The `interrupt_state` test kernel checks that printing keeps interrupts enabled or disabled as they were.

## Exceptions

`kmain` loads the IDT right after the GDT (`arch::x86_64::idt::init`). Entry stubs are written with `global_asm!` because the `x86-interrupt` calling convention is nightly-only; they save the general-purpose registers and call one Rust dispatcher.

- **Breakpoint (`int3`):** prints `PHAROS: breakpoint at <address>, continuing` and returns.
- **Any other exception:** fatal. It prints `PHAROS: exception: ` followed by the mnemonic, name, vector, error code (decoded for page faults), CR2 for page faults, and the saved registers, through the panic print path; then it signals failure to QEMU and halts.
- **Test kernels** can install a fatal hook (`idt::set_fatal_hook`) to turn an expected exception into test results; all `TestRun` handles share one count, so the hook can finish the run.

Vectors 32–255 are not present yet: an interrupt there raises a general-protection fault. The double fault runs on the current stack until it gets its IST stack (#22).

## Segments and stacks

`kmain` first loads the kernel's own GDT and TSS (`arch::x86_64::gdt::init`), so nothing depends on Limine's GDT in bootloader-reclaimable memory. The TSS gives the double-fault handler (M2.4) its own 16 KiB stack. Limitation: that stack is a static array without a guard page, so a double-fault handler that overflows it would overwrite neighbouring data; guard pages come with paging (M2.5). The kernel still runs on Limine's boot stack (at least 64 KiB, in bootloader-reclaimable memory) until it has its own.

## Rules for this crate

- `unsafe` is denied by default (`Cargo.toml`). It is allowed only in `arch::x86_64` (and its submodules) and `limine`, and every `unsafe` block needs a `// SAFETY:` comment; Clippy fails the build otherwise. `main.rs` uses only placement attributes (`link_section`, `no_mangle`).
- Follow the [D-004 constraints](../docs/project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries) for early kernel code: hardware access only through the hardware layer; no drivers beyond serial, interrupt controller, and timer; no filesystem, network, or agent code.
- Keep hardware-independent logic in host-testable modules with unit tests.
- Do not describe anything here as implemented unless it is tested.
