# Testing

## Current tests (Phase 1)

All tests run on the host:

```sh
cargo test --workspace
```

| Package | Location | Covers |
| --- | --- | --- |
| `pharos-cli` | `tools/pharos-cli/src/main.rs` | Command parsing and aliases, case sensitivity, missing/unknown/extra arguments, help content, version from Cargo metadata, `info` status labels, usage errors on stderr with exit 2, `doctor` results and exit codes for supported and unsupported hosts, `doctor` never claiming unbuilt capabilities |
| `pharos-cli` | `tools/pharos-cli/tests/cli.rs` | End-to-end: runs the real binary and checks exit codes as the shell sees them, stdout/stderr separation, and that a non-UTF-8 argument is a usage error rather than a panic |
| `pharos-kernel` | `kernel/src/lib.rs` | The crate declares itself a placeholder (a smoke test; the crate has no logic yet) |

The CLI is tested through a `run` function that writes to in-memory buffers, and `doctor` takes the OS and architecture as parameters, so tests are deterministic and do not depend on the machine running them.

## Quality gates

Run before every pull request; CI runs the same commands with `--locked`, plus rustdoc with warnings as errors and a build and test on Rust 1.85:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-links.py
```

## Writing tests

- Every behavior change comes with a test; every bug fix with a test that fails without the fix.
- Keep tests deterministic: no network, no wall-clock dependence, no reliance on host state. Pass environment facts in as parameters.
- Test error paths and exit codes, not only the happy path.
- Never report a test as passing unless it ran and passed.

## Planned test strategy (not implemented)

| Layer | Starts | Approach |
| --- | --- | --- |
| Host unit tests for target-independent kernel logic | M2.5 | Keep allocators and parsers in host-testable modules; consider Miri |
| QEMU boot test | M2.3 | Boot headless with a timeout; pass when a serial marker appears or QEMU exits with a known code (D-009) |
| QEMU kernel tests | M2.4 onward | In-kernel test runner reporting over serial |
| Isolation and fuzz tests | M2.7 | Attempt forbidden memory access and invalid syscalls; fuzz syscall argument handling |
| Agent adversarial tests | M3.4 | Capability bypass attempts, prompt-injection suites, resource exhaustion |
| Release matrix | M5.1 | Firmware, memory sizes, CPU models; long-running stability |

QEMU is not used by any test today, and none should be described as passing until it exists.
