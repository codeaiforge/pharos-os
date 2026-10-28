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

### Inspect page tables

Stop a test kernel after the switch to the kernel's own page tables, for example at the start of `init_heap` in the `heap` test kernel:

```sh
cargo test -p pharos-kernel --target x86_64-unknown-none --test heap --no-run
cargo xtask run --kernel target/x86_64-unknown-none/debug/deps/heap-<hash> --gdb
```

```text
$ gdb target/x86_64-unknown-none/debug/deps/heap-<hash>
(gdb) target remote localhost:1234
(gdb) break pharos_kernel::mm::global::init_heap
(gdb) continue
(gdb) monitor info mem
...
ffffffff80000000-ffffffff80001000 0000000000001000 -rw
ffffffff80001000-ffffffff80026000 0000000000025000 -r-
ffffffff80026000-ffffffff80031000 000000000000b000 -rw
ffffffff80032000-ffffffff80042000 0000000000010000 -rw
ffffffff80043000-ffffffff80047000 0000000000004000 -rw
```

`monitor info mem` (QEMU's monitor, through GDB) lists mapped ranges with read/write rights; above are the kernel image (requests, text plus rodata, data) and the two stacks, with the unmapped guard pages as gaps at `…31000` and `…42000`. It does not show NX. `monitor info tlb` lists every page individually. To read raw entries, walk the tables through the direct map in GDB's C mode:

```text
(gdb) set language c
(gdb) set $root = 0xffff800000000000 + ($cr3 & ~0xfff)
(gdb) printf "%#018lx\n", *(unsigned long *)($root + 511*8)
```

and so on down the levels (mask entries with `0x000ffffffffff000`). Bit 0 is present, bit 1 writable, bit 7 a 2 MiB page, bit 63 no-execute.

Verified on 2026-10-27 (GDB 15.1, QEMU 8.2.2, UEFI): `monitor info mem` showed the layout above; the raw entries were `0x…9d58001` for a text page (present, not writable, executable), `0x8000…9d7d023` for a data page (no-execute, writable), `0` for the kernel stack's guard page, and `0x8000…200083` for the direct map at 2–4 MiB (a 2 MiB no-execute page). After `continue` the test kernel passed (QEMU status 33). GDB's default Rust mode rejects C expressions such as `~0xfff`; use `set language c`.

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

### Debug a user program (across the privilege boundary)

GDB follows a process into ring 3 and back. User programs are flat binaries without symbols, so stop in the kernel first, read the user address from the system-call frame, and set a hardware breakpoint there. A hardware breakpoint writes nothing into the process's read-only code page. QEMU's GDB stub uses the current CR3, so user addresses resolve in the running process's address space.

```text
$ cargo test -p pharos-kernel --target x86_64-unknown-none --test syscalls --no-run
$ cargo xtask run --kernel target/x86_64-unknown-none/debug/deps/syscalls-<hash> --gdb
$ gdb target/x86_64-unknown-none/debug/deps/syscalls-<hash>   # second terminal
(gdb) target remote localhost:1234
(gdb) break pharos_kernel::syscall::kernel::handle
(gdb) continue
Breakpoint 1, pharos_kernel::syscall::kernel::handle (frame=0xffffc8000000ffb0) at kernel/src/syscall.rs:169
(gdb) print frame.rax          # the call number: 1 = yield
$1 = 1
(gdb) print/x frame.rip        # where sysret will return to
$2 = 0x400030
(gdb) print/x $cs              # still the kernel
$3 = 0x8
(gdb) hbreak *0x400030
(gdb) delete 1
(gdb) continue
Breakpoint 2, 0x0000000000400030 in ?? ()
(gdb) print/x $cs              # ring 3: user code selector
$4 = 0x33
(gdb) print/x $rax             # the call's status: 0 = success
$5 = 0x0
(gdb) x/3i $pc
=> 0x400030:	mov    %rax,0x38(%r13)
   0x400034:	mov    %rdx,0x40(%r13)
   0x400038:	mov    $0x1,%r14
(gdb) delete
(gdb) continue
```

Verified on 2026-10-27 (GDB 15.1, QEMU 8.2.2, UEFI). The breakpoint in the handler stopped on the process's first call, with its own CR3 loaded (`print/x $cr3` showed `0x621000`, not the kernel root). The hardware breakpoint stopped in ring 3 right after `sysret`, at the table program's instruction that stores the result (`TestProgram::SyscallTable`). After `continue` the test kernel passed (QEMU status 33), and GDB reported the closed connection when QEMU exited. To stop on a fault in user mode instead, break on `pharos_kernel::process::on_user_fault`.

### Debug a Rust user program or driver

Rust user programs (`user/programs`, M2.9) are ELF files with a symbol table. xtask builds them in release mode into `target/x86_64-unknown-none/release/<name>` and copies them into the boot image as `bin/<name>`. Load that file's symbols next to the kernel's, and set *hardware* breakpoints on its functions: the code is mapped read-only in the process, and a hardware breakpoint writes nothing. The process's address space is loaded whenever it runs, so its addresses resolve while it is on the CPU.

```text
$ cargo test -p pharos-kernel --target x86_64-unknown-none --test virtio_blk --no-run
$ cargo xtask run --kernel target/x86_64-unknown-none/debug/deps/virtio_blk-<hash> --gdb
$ gdb target/x86_64-unknown-none/debug/deps/virtio_blk-<hash>   # second terminal
(gdb) target remote localhost:1234
(gdb) add-symbol-file target/x86_64-unknown-none/release/virtio-blk
(gdb) hbreak virtio_blk::main
Hardware assisted breakpoint 1 at 0x401280
(gdb) continue
Breakpoint 1, 0x0000000000401280 in virtio_blk::main ()
(gdb) print/x $cs              # ring 3
$1 = 0x33
(gdb) bt 3
#0  0x0000000000401280 in virtio_blk::main ()
#1  0x0000000000402866 in pharos_main ()
#2  0x0000000000000000 in ?? ()
(gdb) delete
(gdb) continue
```

Verified on 2026-10-28 (GDB 15.1, QEMU 8.2.2, UEFI): the breakpoint stopped in the driver's first run, and after `continue` the test kernel passed (QEMU status 33). Addresses differ between builds; `nm -C target/x86_64-unknown-none/release/<name>` lists the functions. Release builds inline small functions, so a breakpoint on one may never be hit; break on its caller.

Other ways to see what a driver does:

- **Its output:** every `debug_write` line appears in the serial log as `process <id>: <text>`; test kernels also echo their program's lines. The driver's exit code says where it stopped (the table in `user/programs/src/bin/virtio-blk.rs`).
- **A fault:** the kernel prints `PHAROS: process <id> killed:` with the full exception report, including `RIP` in the program; `nm` turns it into a function name. A panic exits with code `0xdead` (`pharos_user::PANIC_EXIT`).
- **Kernel side:** break on `pharos_kernel::syscall::kernel::handle` to watch its system calls, or on `pharos_kernel::irq::on_vector` to see device interrupts arrive.
- **The device:** `info pci` and `info mtree` in the QEMU monitor show its BARs and where they are mapped (see [Useful QEMU options](#useful-qemu-options) for reaching the monitor).

### Trace task switches

`sched::set_trace(true)` prints every task switch over serial, with the scheduler's tick count. Task 0 is the boot thread; with preemption enabled, the idle task is the first task created by `sched::enable_preemption`. The `preemption` test kernel turns tracing on while three tasks sleep 50, 10, and 30 ms and task 0 sleeps 100 ms. Boot that test kernel to see the trace:

```sh
cargo test -p pharos-kernel --target x86_64-unknown-none --test preemption --no-run
cargo xtask run --kernel target/x86_64-unknown-none/debug/deps/preemption-<hash>
```

Verified on 2026-10-27 (UEFI and BIOS, identical output):

```text
sched: tick 0: task 0 -> task 2
sched: tick 0: task 2 -> task 3
sched: tick 0: task 3 -> task 4
sched: tick 0: task 4 -> task 1
sched: tick 2: task 1 -> task 3
sched: tick 2: task 3 exited -> task 1
sched: tick 4: task 1 -> task 4
sched: tick 4: task 4 exited -> task 1
sched: tick 6: task 1 -> task 2
sched: tick 6: task 2 exited -> task 1
sched: tick 11: task 1 -> task 0
```

Each task goes to sleep in turn and the idle task (1) runs. The 10 ms sleeper (3) wakes at tick 2, the 30 ms one (4) at tick 4, the 50 ms one (2) at tick 6, and task 0 at tick 11. A sleep waits one extra tick, so it never ends early. Tracing prints from the timer interrupt, so a trace left on while tasks are busy slows them down noticeably.

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
| QEMU monitor | Inspect registers and memory | `-monitor stdio` (`info registers`, `info mem`, `info tlb`), or `monitor <command>` from GDB |

Rules for kernel debugging:

- Use QEMU, not real hardware, unless real-hardware testing is explicitly authorized.
- Do not commit QEMU logs, disk images, or core dumps.
- Record any reproducible crash as an issue with the exact command and serial output.
