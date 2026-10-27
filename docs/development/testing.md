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
| `pharos-kernel` | `kernel/src/limine.rs`, `kernel/src/boot_info.rs`, `kernel/src/sync.rs`, `kernel/src/testing.rs`, `kernel/src/arch/x86_64/gdt.rs`, `kernel/src/arch/x86_64/idt.rs`, `kernel/src/lib.rs` | Limine structure sizes match the specification, request IDs, base-revision check, firmware names, memory-map summary (including empty and overflowing maps), `SpinLock` locking, release, forced release, and mutual exclusion across 4 threads; GDT and TSS descriptor encoding against reference values and the SDM layout; IDT gate encoding, exception frame layout, error-code vectors, page-fault error decoding, and exception report text; the test-kernel verdict (no checks means failure). Run with `cargo test -p pharos-kernel --lib` |

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
| `kernel/tests/boot_info.rs` | Base revision accepted; memory map present, non-empty, with usable memory and the kernel image; HHDM offset in the higher half; bootloader is Limine; firmware is 64-bit UEFI; the test kernel runs at its linked higher-half address |
| `kernel/tests/double_fault.rs` | The test kernel runs on the kernel stack; unbounded recursion hits the guard page and is reported as a double fault: vector 8, error code 0, the handler runs on the IST1 stack, and the faulting RSP is at the bottom of the kernel stack (checked from a fatal hook; the run ends with QEMU status 33) |
| `kernel/tests/exceptions.rs` | The IDT is loaded; two breakpoints are handled and execution continues; registers survive a breakpoint; a read of the unmapped probe page raises a page fault with vector 14, CR2 equal to the probe address, error code 0 (not present, read, kernel), RIP in the kernel, and the kernel CS (checked from a fatal hook) |
| `kernel/tests/gdt.rs` | Limine's GDT is active at entry; after `gdt::init()` (called twice, the second call harmless) the GDTR points at the kernel GDT, CS/SS/DS/TR hold the kernel selectors, and TSS IST1 is the 16-byte-aligned top of the double-fault stack |
| `kernel/tests/interrupt_state.rs` | Interrupts are disabled at entry; printing and `without_interrupts` (also nested) restore the previous interrupt state, enabled or disabled; `enable_interrupts`/`disable_interrupts` set and clear IF |

To add a test kernel:

1. Create `kernel/tests/<name>.rs` with `#![no_std]`, `#![no_main]`, `pharos_kernel::test_kernel!(run);`, and `fn run(t: &mut TestRun)` calling `t.check("description", condition)` for each check. The Limine responses are available as `requests::MEMMAP` and so on.
2. Add a `[[test]]` entry with `name = "<name>"` and `harness = false` to `kernel/Cargo.toml`.
3. Run `cargo xtask test`. Each test kernel costs about two seconds under UEFI, so group related checks.

In CI the first run with kernel tests (2026-10-27, [run 40476613340](https://github.com/codeaiforge/pharos-os/actions/runs/40476613340)) took 9 s for the boot check and the `boot_info` test kernel. The job itself took 555 s that time because Ubuntu's package mirror delivered the QEMU packages at 44 kB/s (8.5 minutes); the earlier run took 44 s in total. If slow mirrors keep recurring, consider caching the packages; the job's 20-minute limit covers occasional slowness.


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

Why the split: the kernel targets bare metal (`x86_64-unknown-none`, decision D-003), so it is excluded from host checks and linted for its own target. Its target-independent logic is unit-tested on the host through the library. CI's `msrv` job also builds and tests the host crates and the kernel library on Rust 1.85.

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
| QEMU kernel tests | M2.4 onward | In-kernel test runner reporting over serial |
| Isolation and fuzz tests | M2.7 | Attempt forbidden memory access and invalid syscalls; fuzz syscall argument handling |
| Agent adversarial tests | M3.4 | Capability bypass attempts, prompt-injection suites, resource exhaustion |
| Release matrix | M5.1 | Firmware, memory sizes, CPU models; long-running stability |

QEMU is not used by any test today, and none should be described as passing until it exists.
