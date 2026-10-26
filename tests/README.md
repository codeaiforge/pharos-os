# tests/

This directory is reserved for tests that span more than one crate, and later for QEMU-based system tests.

## Current state

There are no tests here yet. Current tests live in each crate:

- `kernel/src/lib.rs` — placeholder status test.
- `tools/pharos-cli/src/main.rs` — unit tests: command parsing, output, unknown commands, and exit codes.
- `tools/pharos-cli/tests/cli.rs` — end-to-end tests of the real `pharos` binary.

Run them with:

```sh
cargo test                          # host crates (default members)
cargo test -p pharos-kernel --lib   # kernel library logic, on the host
```

Or run the full gate with `scripts/check.sh`.

Note: Cargo only builds `tests/*.rs` automatically for a package whose root contains them. This root is a virtual workspace (no package), so files placed directly here will **not** run until a test package or harness is added. Crate-specific integration tests belong in that crate's own `tests/` directory (for example `tools/pharos-cli/tests/`).

## Planned

- **M2.3**: a QEMU boot test harness that boots the kernel, captures serial output, and checks for an expected marker, with a timeout. See [docs/development/testing.md](../docs/development/testing.md).
- Later: regression tests for interrupts, memory management, system calls, and agent isolation.
