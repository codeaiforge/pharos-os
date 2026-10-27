# Debugging

## Today: the host workspace

### CLI

```sh
cargo run -p pharos-cli -- doctor
echo $?          # 0 success, 1 problem reported, 2 invalid usage
```

- Usage errors are printed to stderr; normal output goes to stdout. Separate them with `cargo run -q -p pharos-cli -- bad 2>/dev/null`.
- Debug a failing test with output: `cargo test -p pharos-cli <test_name> -- --nocapture`.
- Get a backtrace from a panic: `RUST_BACKTRACE=1 cargo run -p pharos-cli -- <command>`.
- Step through with a debugger: `rust-gdb target/debug/pharos` (requires `gdb`; optional).

### Build problems

- Run `cargo clean` and rebuild if incremental artifacts look stale. This only removes `target/`.
- Check the active toolchain with `rustup show`; `rust-toolchain.toml` should select `stable`.
- See the common failures table in [setup.md](setup.md#common-failures).

## Kernel in QEMU

### Boot and read the serial log

```sh
cargo xtask run          # UEFI (OVMF)
cargo xtask run --bios   # BIOS (SeaBIOS)
```

Serial output (COM1) appears on the terminal. The last kernel line is `PHAROS: boot ok`, `PHAROS: boot failed: <reason>`, or `PHAROS: panic: <message>`. The command exits 0 only if the kernel signalled success (QEMU exit status 33). On a kernel failure QEMU exits with status 35 and the command fails. Any other exit means the kernel never signalled, for example after a triple fault (QEMU runs with `-no-reboot`). Under UEFI, OVMF prints its own boot messages before the kernel starts.

### Headless boots and logs

`cargo xtask test` boots without a terminal and writes serial output to `target/xtask/logs/boot-<firmware>.log`. On failure it prints the end of the log with firmware escape codes removed; the log file keeps the raw output. Use `--timeout <SECS>` to shorten the limit when checking for hangs.

### Read an exception report

A fatal CPU exception ends the serial log with a report like this one (a page fault from the `exceptions` test kernel without its hook):

```text
PHAROS: exception: #PF page fault (vector 14), error code 0x0 (not-present page, read, kernel mode)
  CR2 (address) 0xffffffff7ffff000
  RIP 0xffffffff80001f4a  CS 0x0008  RFLAGS 0x00000082
  RSP 0xffff80000a054fc8  SS 0x0010
  RAX ...
```

- The first line names the exception, its vector, and the CPU's error code; for page faults the error code is decoded.
- `CR2` (page faults only) is the address that faulted.
- `RIP` is the faulting instruction. Find the function with `gdb -batch -ex 'info symbol 0x<RIP>' <ELF>` or `addr2line -f -e <ELF> 0x<RIP>` on the same build.
- A stack overflow appears as `#DF double fault` with `RSP` just above the kernel stack's guard page.
- After the report QEMU exits with status 35. Breakpoints (`int3`) print `PHAROS: breakpoint at <address>, continuing` instead and do not stop the kernel.

### Break into the kernel with GDB

Verified on 2026-10-27 with GDB 15.1 and QEMU 8.2.2.

1. Start QEMU paused, with a GDB server on `localhost:1234`:

   ```sh
   cargo xtask run --bios --gdb
   ```

   It prints the GDB command to use, then waits.
2. In a second terminal:

   ```sh
   gdb target/x86_64-unknown-none/release/pharos-kernel \
       -ex 'target remote localhost:1234' -ex 'break kmain' -ex continue
   ```

   GDB connects while the CPU is still at the reset vector (`0xfff0`), then stops at `Breakpoint 1, 0xffffffff80001170 in kmain ()` once Limine jumps to the kernel. (The address changes as the kernel changes.)
3. Inspect (`info registers`, `x/8i $rip`, `bt`), then `continue`. The kernel finishes booting and QEMU exits with the kernel's status.

The release build has symbols but no debug information, so GDB shows function names and addresses, not source lines.

### Debug a test kernel (source level)

Test kernels are debug builds with full debug information. `--kernel` boots one under `cargo xtask run`:

```sh
cargo test -p pharos-kernel --target x86_64-unknown-none --test exceptions --no-run
# Cargo prints the binary, for example target/x86_64-unknown-none/debug/deps/exceptions-<hash>
cargo xtask run --kernel target/x86_64-unknown-none/debug/deps/exceptions-<hash> --gdb
```

Then, in a second terminal, stop in the exception dispatcher when the page fault arrives:

```text
$ gdb target/x86_64-unknown-none/debug/deps/exceptions-<hash>
(gdb) target remote localhost:1234
(gdb) break pharos_kernel::arch::x86_64::idt::dispatch if frame.vector == 14
(gdb) continue
Breakpoint 1, pharos_kernel::arch::x86_64::idt::dispatch (frame=...) at kernel/src/arch/x86_64/idt.rs:271
(gdb) print frame.vector
$1 = 14
(gdb) info symbol frame.rip
pharos_kernel::arch::x86_64::idt::touch_unmapped_probe + 10 in section .text
(gdb) print/x $cr2
$2 = 0xffffffff7ffff000
(gdb) print/x *frame
(gdb) continue
```

Verified on 2026-10-27 (GDB 15.1, QEMU 8.2.2, UEFI): the breakpoint stopped on the page fault with the values above, `print/x *frame` showed the saved registers, and after `continue` the test kernel passed (QEMU status 33). Without the condition, the breakpoint also stops on each `int3` the test kernel executes (vector 3). GDB's Rust mode uses `frame.vector`, not `frame->vector`. Breakpoints set through QEMU's GDB stub do not use the guest's `int3`, so they do not disturb the kernel's breakpoint handler.

### Diagnose a triple fault

If QEMU exits with status 0 and no kernel report, the CPU most likely triple-faulted (the kernel's handlers could not run). Re-run the same image with QEMU's interrupt log:

```sh
qemu-system-x86_64 -M q35 -m 256M -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -cdrom target/xtask/image/pharos.iso -serial stdio \
    -d int,cpu_reset -D qemu.log
grep -E 'check_exception|Triple fault' qemu.log | tail
```

(This boots under SeaBIOS; add the two OVMF `-drive` options from `cargo xtask run` for UEFI.) The `check_exception old: X new: Y` lines show the escalation. For example, a stack overflow with the double fault deliberately moved off its IST stack (2026-10-27) logged:

```text
check_exception old: 0xffffffff new 0xe
check_exception old: 0xe new 0xe
check_exception old: 0x8 new 0xe
Triple fault
```

A page fault (`0xe`), a second page fault while delivering it (which becomes a double fault, `0x8`), and a page fault while delivering the double fault. The lines before them give `RIP`, `CR2`, and the registers at each step. Do not commit `qemu.log`.

### Useful QEMU options

`cargo xtask run` already uses `-serial stdio`, `-display none`, `-no-reboot`, `isa-debug-exit`, and (with `--gdb`) `-s -S`; `--kernel <ELF>` boots another kernel, such as a test kernel. Other options for manual runs:

| Technique | Purpose | Typical QEMU options |
| --- | --- | --- |
| Serial console | Primary early log channel and test output | `-serial stdio` |
| Headless runs | CI and scripted tests | `-display none` |
| Stop on triple fault | Keep state instead of rebooting | `-no-reboot -no-shutdown` |
| Interrupt/exception log | Diagnose faults | `-d int,cpu_reset -D qemu.log` |
| GDB stub | Breakpoints and stepping in the kernel | `-s -S`, then `gdb` with `target remote :1234` |
| Debug exit device | Report test results via QEMU exit code | `-device isa-debug-exit,iobase=0xf4,iosize=0x04` |
| QEMU monitor | Inspect registers and memory | `-monitor stdio` (`info registers`, `info mem`) |

Rules for kernel debugging:

- Use QEMU, not real hardware, unless real-hardware testing is explicitly authorized.
- Do not commit QEMU logs, disk images, or core dumps.
- Record any reproducible crash as an issue with the exact command and serial output.
