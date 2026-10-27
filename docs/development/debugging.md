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

The release build has symbols but no debug information, so GDB shows function names and addresses, not source lines. Source-level debugging needs debug information in the kernel build; add it when a milestone needs it.

### Useful QEMU options

`cargo xtask run` already uses `-serial stdio`, `-display none`, `-no-reboot`, `isa-debug-exit`, and (with `--gdb`) `-s -S`. Other options for manual runs:

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
