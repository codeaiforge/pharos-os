# Development setup

This page covers what is needed **today** (Phase 1). Tools for later phases are listed separately and are not required yet.

## Required tools

| Tool | Why | Check |
| --- | --- | --- |
| rustup | Installs and selects the Rust toolchain from `rust-toolchain.toml` | `rustup --version` |
| Rust stable (cargo, rustc) | Builds the workspace | `cargo --version` |
| rustfmt, clippy | Formatting and lints (installed automatically via `rust-toolchain.toml`) | `cargo fmt --version`, `cargo clippy --version` |
| C linker (`cc`) | Rust links host binaries with the system linker | `cc --version` |
| Git | Clone the repository | `git --version` |

### Install on Linux Mint / Ubuntu

```sh
sudo apt install build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Read the rustup script before running it if you prefer; see <https://rustup.rs/>. Restart your shell afterwards (or run `. "$HOME/.cargo/env"`).

## Toolchain choice

- `rust-toolchain.toml` selects the **stable** channel with `rustfmt` and `clippy`. It does not pin a patch release, so it will not silently become obsolete; run `rustup update stable` to get new releases.
- The workspace uses **edition 2024**, so the minimum supported Rust is **1.85** (`rust-version` in `Cargo.toml`). The `msrv` CI job builds and tests on 1.85; locally the scaffold was tested with Rust 1.99.1.
- Reproducibility of dependencies comes from the committed `Cargo.lock` and `--locked` in CI.

## First build

From the repository root:

```sh
cargo build --workspace
```

Expected: `Finished` with no warnings. The first run may download the toolchain components named in `rust-toolchain.toml`.

## Validate the workspace

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-links.py
cargo run -q -p pharos-cli -- doctor
```

Expected:

- `fmt` prints nothing and exits 0.
- `clippy` finishes with no warnings.
- `test` reports all tests passed for `pharos-cli` (unit and end-to-end) and `pharos-kernel`.
- The link check reports `0 broken`.
- `doctor` shows `PASS` for host OS and architecture on Linux x86-64, `SKIP` for QEMU and inference (they do not exist yet), and `Result: no problems found.` It exits 0.

## Common failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `error: linker 'cc' not found` | No C toolchain | `sudo apt install build-essential` |
| `rustup: command not found` / `cargo: command not found` | rustup not installed or not on `PATH` | Install rustup; run `. "$HOME/.cargo/env"` |
| `feature 'edition2024' is required` or similar edition error | Rust older than 1.85 | `rustup update stable` |
| `error: 'cargo-fmt' is not installed` | Component missing | `rustup component add rustfmt clippy` |
| `doctor` shows `WARN` and exits 1 | Host is not Linux x86-64 | Expected on other hosts; the supported environment is Linux x86-64 |
| `--locked` fails in CI | `Cargo.lock` out of date | Run `cargo build --workspace` locally and include the updated `Cargo.lock` |

## Optional tools for later phases (not required now)

| Tool | Needed from | Purpose | Install (Mint/Ubuntu) |
| --- | --- | --- | --- |
| QEMU (`qemu-system-x86_64`) | M2.2 | Boot and test the kernel | `sudo apt install qemu-system-x86` |
| OVMF | M2.2 | UEFI firmware for QEMU (UEFI is the primary path, D-002) | `sudo apt install ovmf` |
| xorriso | M2.2 | Build the hybrid BIOS/UEFI ISO (D-003) | `sudo apt install xorriso` |
| `x86_64-unknown-none` Rust target | M2.2 | Compile the kernel (D-003) | `rustup target add x86_64-unknown-none` (added to `rust-toolchain.toml` in M2.2) |
| Limine 12.9.4 | M2.2 | Bootloader in the boot image (D-001) | fetched and verified by `cargo xtask` (M2.2); not installed system-wide |
| GDB | M2.4 | Kernel debugging via QEMU's GDB stub | `sudo apt install gdb` |
| markdownlint-cli2 | any time | Lint Markdown (config in `.markdownlint-cli2.jsonc`) | `npx markdownlint-cli2 "**/*.md"` (requires Node.js) |

The M2.2 tools follow from the accepted boot decisions; see [boot design](../architecture/boot.md). None is needed for the current workspace.
