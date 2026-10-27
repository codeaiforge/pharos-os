# Testing

## Current tests (Phase 1)

All tests run on the host:

```sh
cargo test                          # host crates (default members)
cargo test -p pharos-kernel --lib   # kernel library logic
```

| Package | Location | Covers |
| --- | --- | --- |
| `pharos-cli` | `tools/pharos-cli/src/main.rs` | Command parsing and aliases, case sensitivity, missing/unknown/extra arguments, help content, version from Cargo metadata, `info` status labels, usage errors on stderr with exit 2, `doctor` results and exit codes for supported and unsupported hosts, `doctor` never claiming unbuilt capabilities |
| `pharos-cli` | `tools/pharos-cli/tests/cli.rs` | End-to-end: runs the real binary and checks exit codes as the shell sees them, stdout/stderr separation, and that a non-UTF-8 argument is a usage error rather than a panic |
| `xtask` | `xtask/src/main.rs` | Argument parsing, `sha256sum` output parsing, checksum comparison, pinned values, and that all outputs stay under `target/` |
| `pharos-kernel` | `kernel/src/limine.rs`, `kernel/src/boot_info.rs`, `kernel/src/sync.rs`, `kernel/src/testing.rs`, `kernel/src/arch/x86_64/gdt.rs`, `kernel/src/arch/x86_64/idt.rs`, `kernel/src/arch/x86_64/apic.rs`, `kernel/src/arch/x86_64/paging.rs`, `kernel/src/mm/bitmap.rs`, `kernel/src/mm/frame.rs`, `kernel/src/mm/heap.rs`, `kernel/src/time.rs`, `kernel/src/sched.rs`, `kernel/src/lib.rs` | Limine structure sizes match the specification, request IDs, base-revision check, firmware names, memory-map summary (including empty and overflowing maps), `SpinLock` locking, release, forced release, and mutual exclusion across 4 threads; GDT and TSS descriptor encoding against reference values and the SDM layout (including the ring 3 user segments and their `sysret` order); bitmap range allocation (aligned runs, next fit with wrap-around, double and partial double frees, reservations), frame allocation from memory-map spans (alignment, low-memory and overflow edges, storage placement and reservation, distinct frames, physically aligned contiguous runs, skipped regions, pending reclaimable regions and their release), the memory-map copy, heap allocation (unit rounding, alignment, coalescing, bad and double frees, exhaustion), round-robin run-queue order (yield, block, a lone task, the idle thread), sleepers in deadline order, the capability table (handles, rights, deletion, full table, derivation and revocation at any depth), IPC endpoint queues (first in first out both ways), system-call decoding (with a 200,000-call randomized test), user address ranges (randomized), the system-call frame layout and MSR values, timer calibration (the smallest run counts, implausible rates rejected, tick count, cycle-to-nanosecond conversion without overflow), IDT gate encoding, page-table indexes, leaf and table entry encoding (with and without NX, user pages, W^X), page splitting into 2 MiB and 4 KiB pages, direct-map access per memory-map kind, exception frame layout, error-code vectors, page-fault error decoding, and exception report text; the test-kernel verdict (no checks means failure). Run with `cargo test -p pharos-kernel --lib` |

The CLI is tested through a `run` function that writes to in-memory buffers, and `doctor` takes the OS and architecture as parameters, so tests are deterministic and do not depend on the machine running them.

## Boot check (QEMU)

```sh
cargo xtask test               # boot check under UEFI and BIOS, headless
cargo xtask test --timeout 120 # longer limit per boot (default 60 s)
```

Each boot passes only if QEMU exits with status 33 **and** the serial log contains the line `PHAROS: boot ok`, within the time limit (decision D-009). A kernel that reports failure (status 35), exits without signalling, prints a different marker, or hangs fails the check; a hung QEMU is stopped at the limit. The command prints one line per firmware and, on failure, the last lines of the serial log. Full logs: `target/xtask/logs/boot-uefi.log` and `boot-bios.log`.

Needs QEMU, OVMF, and xorriso, so it is not part of `scripts/check.sh`. CI runs it in the `qemu` job on every push to `main` and on manual runs (Ubuntu 24.04 runner), followed by a check that two image builds are byte-identical. First runs on 2026-10-27: the job took 44 s (20 s installing packages, boot checks 3.2 s UEFI and 0.4 s BIOS), and the CI image hash matched the local build (`51bc0a7f…`). A branch whose kernel reports a boot failure made the job fail at "Boot check", with the kernel's reason in the job output ([run 40473362173](https://github.com/codeaiforge/pharos-os/actions/runs/40473362173)). After the boot check, `cargo xtask test` runs the kernel tests (next section); CI runs both. For an interactive boot with serial on the terminal, use `cargo xtask run` (see [debugging.md](debugging.md)).

## Kernel tests (QEMU)

Code that needs real hardware state (boot information, CPU, later memory and interrupts) is tested inside QEMU by **test kernels**: small `no_main` kernels in `kernel/tests/`, each booted on its own (decision D-009). `cargo xtask test` runs them after the boot check, through `cargo test -p pharos-kernel --target x86_64-unknown-none --test '*'`; Cargo hands each test binary to `cargo xtask runner`, which boots it headless under UEFI.

Output, for each test kernel:

```text
  PHAROS-TEST: memory map present ... ok
  ...
  PHAROS-TEST: 9 passed, 0 failed
test kernel boot_info (uefi): PASS in 2.2 s
```

A test kernel passes only if it ran at least one check, none failed, and it ended with `PHAROS: tests ok` and QEMU status 33 within the time limit. A failed check, a panic, a hang, or a test kernel with no checks fails the run.

| Test kernel | Checks |
| --- | --- |
| `kernel/tests/address_spaces.rs` | Two process address spaces share the kernel half (code, heap) and map the same user address to different frames. User pages are user-accessible; the probe page and kernel half are not. The kernel does not see process pages. A process cannot map into the kernel half, and the kernel space refuses user pages. A task in each space sees its own page and CR3 root on every turn, while task 0 stays on the kernel root. Ended tasks return every frame. `destroy` frees 10 pages and 4 tables. A kernel mapping added later appears in existing process spaces. A kernel page remapped while a process space is active shows the new frame: the stale-TLB bug fixed in #41 |
| `kernel/tests/apic_timer.rs` | Memory management set up first; The local APIC is mapped and enabled; its version register is plausible; no ticks before the timer starts; with the periodic timer running and interrupts enabled, at least 20 timer interrupts arrive, and every wake-up was a timer or spurious interrupt |
| `kernel/tests/boot_info.rs` | Base revision accepted; memory map present, non-empty, with usable memory and the kernel image; HHDM offset in the higher half; bootloader is Limine; firmware is 64-bit UEFI; the test kernel runs at its linked higher-half address |
| `kernel/tests/double_fault.rs` | Under the kernel's own page tables: The test kernel runs on the kernel stack; unbounded recursion hits the guard page and is reported as a double fault: vector 8, error code 0, the handler runs on the IST1 stack, and the faulting RSP is at the bottom of the kernel stack (checked from a fatal hook; the run ends with QEMU status 33) |
| `kernel/tests/exceptions.rs` | The IDT is loaded; two breakpoints are handled and execution continues; registers survive a breakpoint; a read of the unmapped probe page raises a page fault with vector 14, CR2 equal to the probe address, error code 0 (not present, read, kernel), RIP in the kernel, and the kernel CS (checked from a fatal hook) |
| `kernel/tests/frames.rs` | The frame allocator starts from the memory map, rejects a second init, and reserves its bitmap storage; 512 frames are aligned, at or above 1 MiB, inside usable entries, and distinct; double frees and unknown frames are rejected; freeing restores the count; a 16-frame run is 64 KiB aligned; exhausting memory hands out every free frame exactly once, then reports out of memory |
| `kernel/tests/gdt.rs` | Limine's GDT is active at entry; after `gdt::init()` (called twice, the second call harmless) the GDTR points at the kernel GDT, CS/SS/DS/TR hold the kernel selectors, and TSS IST1 is the 16-byte-aligned top of the double-fault stack |
| `kernel/tests/hardening.rs` | Regressions from the M2.7 security review:<br>• a process with DF and AC set keeps running through ticks, the kernel asserts both are clear in every handler, and the flags come back (F1);<br>• x87 is killed with `#NM` (F3);<br>• `out` to QEMU's exit port, `int3`, and `int 0x80` are killed with `#GP` (DPL 0 gates);<br>• 300 `debug_write` calls leave a 64-entry log and under 48 KiB of heap growth (F2) |
| `kernel/tests/heap.rs` | The heap window is mapped writable and no-execute; the heap is 4 MiB and empty; `Box`, a 10,000-element `Vec`, `String`/`format!`, a 1,000-entry `BTreeMap`, and a 4 KiB-aligned box work; usage returns to zero after drops; 20,000 random allocations and frees of 1–2,048 bytes keep their contents intact and leave the heap empty; allocating keeps interrupts enabled |
| `kernel/tests/heap_oom.rs` | Asking for 8 MiB from the 4 MiB heap reaches the panic handler with `memory allocation of 8388608 bytes failed` (caught by a panic hook), and the heap stays consistent |
| `kernel/tests/interrupt_state.rs` | Interrupts are disabled at entry; printing and `without_interrupts` (also nested) restore the previous interrupt state, enabled or disabled; `enable_interrupts`/`disable_interrupts` set and clear IF |
| `kernel/tests/ipc.rs` | Ping and pong processes exchange 1,000 call-and-reply messages over two endpoints, each reply the request plus one (checked by the programs); afterwards pong waits and nobody else does. Two table processes then:<br>• pass a console capability with `WRITE` only, use it, and fail to pass it on (no `GRANT`);<br>• revoke it, after which its use fails with `REVOKED` while the granter's own capability still works;<br>• cut a 10-byte message to a 4-byte buffer (value 10);<br>• are refused `send` on a receive-only endpoint, `receive` on a send-only one, passing a capability without `GRANT`, kernel or read-only receive buffers, and unknown handles.<br>Messages arrive intact and in order, registers survive, and all frames are returned. It prints the round-trip time (TCG timing only) |
| `kernel/tests/no_execute.rs` | Calling a `ret` placed in writable kernel data faults: vector 14, CR2 and RIP at the probe, error code present + instruction fetch |
| `kernel/tests/paging.rs` | CR3 holds the kernel root; text is read+execute, rodata read-only, data writable and no-execute; text maps to Limine's physical load address; both stacks mapped with unmapped guard pages below; the direct map covers usable memory with 2 MiB pages; Limine responses readable after the switch; a fresh frame mapped at the test page is written there and read back through the direct map, then unmapped; touching the unmapped page faults (not present, read) |
| `kernel/tests/preemption.rs` | With the timer tick preempting tasks: three sleepers (50, 10, 30 ms) wake in deadline order (`bca`) and no sleep ends early; with a task that spins forever and two workers that never yield, task 0 wakes from a 300 ms sleep within 2 s, every busy task keeps making progress, workers see at most 10 ticks between turns, and the scheduler counts ticks. Bounds are wide on purpose (TCG) |
| `kernel/tests/reclaim.rs` | The memory map is copied completely; reclaimable frames wait reserved; reclaim frees exactly the reclaimable frames from the memory map, retires Limine's responses, and gains nothing a second time; every free frame (reclaimed ones included) is then allocated, filled, and read back, and the copied memory map still matches |
| `kernel/tests/syscalls.rs` | A ring 3 process runs a table of 19 system calls and records each result, and the kernel checks them:<br>• `yield`; `debug_write` across a page boundary, from the code page, and of 0 bytes;<br>• bad buffers: kernel, unmapped, running into an unmapped page, reaching the last user page, overflowing (`BAD_ADDRESS`), and 257 bytes (`TOO_LARGE`);<br>• handle 0, an unknown handle, and a missing right;<br>• unknown numbers, and `send` before IPC (`UNKNOWN_CALL`);<br>• `delete`, then using and deleting the handle again.<br>`rdi`, `rsi`, `r10`, `r8`, `r9`, and `rsp` survive every call. `exit` delivers its code, the debug output arrives, and every frame is returned. The last user page cannot be mapped, and a `syscall` at the end of the page below faults in user mode |
| `kernel/tests/task_overflow.rs` | A spawned task's unbounded recursion hits the guard area below its stack and is reported as a double fault, with the faulting RSP at the bottom of the task stack |
| `kernel/tests/tasks.rs` | Scheduler init (second init rejected), task 0 is the boot thread; three spawned tasks interleave round-robin (`abcabcabc`), each on its own stack in the stack window, with interrupts enabled and its own ID; callee-saved registers survive switches; exited tasks return their 12 stack frames; a later task runs its closure; yielding while holding an `IrqMutex` panics |
| `kernel/tests/timer.rs` | Calibration against the PIT is accepted and the tick period is 10 ms of APIC timer counts; uptime is zero before calibration and never goes backwards; 50 ms by the PIT reads 45–500 ms on the TSC clock; `delay(100 ms)` lasts at least 100 ms and under 1 s; 20 periodic ticks take 190 ms to 2 s. Bounds are wide on purpose (QEMU under TCG on a loaded runner) |
| `kernel/tests/user_mode.rs` | A process counting in ring 3 is preempted (it counts while task 0 sleeps and wakes), and TSS `rsp0` is a task stack top. Seven processes are each killed with the expected fault, while the spinner and task 0 continue: reading and writing kernel data, jumping into kernel code, and reading another process's page (page faults with error codes 0x5, 0x7, 0x15, and 0x4); `cli`, `hlt`, and `mov cr3` (general-protection faults). Killed processes return every frame |
| `kernel/tests/write_protect.rs` | Writing read-only kernel data faults: vector 14, CR2 at the probe, error code present + write |

To add a test kernel:

1. Create `kernel/tests/<name>.rs` with `#![no_std]`, `#![no_main]`, `pharos_kernel::test_kernel!(run);`, and `fn run(t: &mut TestRun)` calling `t.check("description", condition)` for each check. The Limine responses are available as `requests::MEMMAP` and so on.
2. Add a `[[test]]` entry with `name = "<name>"` and `harness = false` to `kernel/Cargo.toml`.
3. Run `cargo xtask test`. Each test kernel costs about two seconds under UEFI, so group related checks.

In CI the first run with kernel tests (2026-10-27, [run 40476613340](https://github.com/codeaiforge/pharos-os/actions/runs/40476613340)) took 9 s for the boot check and the `boot_info` test kernel. The job itself took 555 s that time because Ubuntu's package mirror delivered the QEMU packages at 44 kB/s (8.5 minutes); the earlier run took 44 s in total. If slow mirrors keep recurring, consider caching the packages; the job's 20-minute limit covers occasional slowness. At the end of M2.4 (2026-10-27, [run 40507039495](https://github.com/codeaiforge/pharos-os/actions/runs/40507039495)) the job took 97 s: 16 s for packages, 71 s for the boot check and six test kernels (about 3 s each in CI), and the reproducibility check. At the end of M2.5 ([run 40516480215](https://github.com/codeaiforge/pharos-os/actions/runs/40516480215)) it took 113 s with 13 test kernels (3–4 s each in CI). At the end of M2.6 ([run 40530704211](https://github.com/codeaiforge/pharos-os/actions/runs/40530704211)) it took 117 s with 16 test kernels; the timing-based `timer` and `preemption` kernels took 4.0 and 4.3 s and passed on every M2.6 run without retries.


## Quality gates

Run `scripts/check.sh` before every pull request. It runs these commands, the same ones as CI's `check` job, and stops at the first failure:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --exclude pharos-kernel --all-targets --locked -- -D warnings
cargo build --workspace --exclude pharos-kernel --locked
cargo test --workspace --exclude pharos-kernel --locked
cargo test -p pharos-kernel --lib --locked
cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude pharos-kernel --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc -p pharos-kernel --target x86_64-unknown-none --no-deps --locked
python3 scripts/check-links.py
```

Why the split: the kernel targets bare metal (`x86_64-unknown-none`, decision D-003), so it is excluded from host checks and linted for its own target. Its target-independent logic is unit-tested on the host through the library. CI's `msrv` job also builds and tests the host crates and the kernel library on Rust 1.85. `scripts/check.sh` repeats those three commands (`cargo +1.85 build`/`test`) when Rust 1.85 is installed (`rustup toolchain install 1.85 --profile minimal`), and says it skipped them otherwise. Newer language features, such as let chains (Rust 1.88), fail only there: four M2.7 commits passed every local check yet failed CI's `msrv` job for that reason, fixed in #42.

## Writing tests

- Every behavior change comes with a test; every bug fix with a test that fails without the fix.
- Keep tests deterministic: no network, no wall-clock dependence, no reliance on host state. Pass environment facts in as parameters.
- Test error paths and exit codes, not only the happy path.
- Never report a test as passing unless it ran and passed.

## Planned test strategy (not implemented)

| Layer | Starts | Approach |
| --- | --- | --- |
| Host unit tests for target-independent kernel logic | M2.5 | Keep allocators and parsers in host-testable modules; consider Miri |
| QEMU boot test and kernel tests | M2.3 | `cargo xtask test`: boot check under UEFI and BIOS, then `harness = false` test kernels through Cargo's runner; pass = QEMU status 33 **and** the serial marker, 60 s timeout, logs printed on failure (D-009, accepted) |
| QEMU kernel tests | M2.3 onward | One test kernel per subsystem in `kernel/tests/`; M2.4 added interrupt state, GDT, exceptions, double fault, and APIC timer tests; M2.5 memory tests; M2.6 timer, task, task stack overflow, and preemption tests |
| Isolation and fuzz tests | M2.7 | Attempt forbidden memory access and invalid syscalls; fuzz syscall argument handling |
| Agent adversarial tests | M3.4 | Capability bypass attempts, prompt-injection suites, resource exhaustion |
| Release matrix | M5.1 | Firmware, memory sizes, CPU models; long-running stability |

QEMU is not used by any test today, and none should be described as passing until it exists.
