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

## Planned: kernel debugging (not available yet)

Nothing below works today, because no bootable kernel exists. It records the intended approach so M2.2–M2.4 can adopt it; the boot path is decided ([boot.md](../architecture/boot.md)); QEMU automation details depend on decision D-009.

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
