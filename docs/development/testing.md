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
| `pharos-kernel` | `kernel/src/limine.rs`, `kernel/src/boot_info.rs`, `kernel/src/lib.rs` | Limine structure sizes match the specification, request IDs, base-revision check, firmware names, memory-map summary (including empty and overflowing maps). Run with `cargo test -p pharos-kernel --lib` |

The CLI is tested through a `run` function that writes to in-memory buffers, and `doctor` takes the OS and architecture as parameters, so tests are deterministic and do not depend on the machine running them.

## Boot check (QEMU)

```sh
cargo xtask test               # boot check under UEFI and BIOS, headless
cargo xtask test --timeout 120 # longer limit per boot (default 60 s)
```

Each boot passes only if QEMU exits with status 33 **and** the serial log contains the line `PHAROS: boot ok`, within the time limit (decision D-009). A kernel that reports failure (status 35), exits without signalling, prints a different marker, or hangs fails the check; a hung QEMU is stopped at the limit. The command prints one line per firmware and, on failure, the last lines of the serial log. Full logs: `target/xtask/logs/boot-uefi.log` and `boot-bios.log`.

Needs QEMU, OVMF, and xorriso, so it is not part of `scripts/check.sh`. CI runs it in the `qemu` job on every push to `main` and on manual runs (Ubuntu 24.04 runner), followed by a check that two image builds are byte-identical. Kernel test targets (#16) are still to come in M2.3. For an interactive boot with serial on the terminal, use `cargo xtask run` (see [debugging.md](debugging.md)).

## Quality gates

Run `scripts/check.sh` before every pull request. It runs these commands, the same ones as CI's `check` job, and stops at the first failure:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --exclude pharos-kernel --all-targets --locked -- -D warnings
cargo build --workspace --exclude pharos-kernel --locked
cargo test --workspace --exclude pharos-kernel --locked
cargo test -p pharos-kernel --lib --locked
cargo clippy -p pharos-kernel --target x86_64-unknown-none --locked -- -D warnings
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
