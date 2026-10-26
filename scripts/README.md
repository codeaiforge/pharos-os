# scripts/

This directory is reserved for small helper scripts for development tasks, such as launching QEMU with the project's standard options once a bootable kernel exists.

## Current scripts

| Script | Purpose | Requirements |
| --- | --- | --- |
| `check.sh` | Runs the same checks as the CI `check` job, in order, and stops at the first failure. Run: `scripts/check.sh` | Rust toolchain from `rust-toolchain.toml`, Python 3 |
| `check-links.py` | Checks relative links and `#anchors` in all Markdown files; exits 1 if any are broken. Read-only; external URLs are not checked. Run: `python3 scripts/check-links.py` | Python 3.9+ (standard library only) |

Everything else is a plain Cargo command (see [docs/development/workflow.md](../docs/development/workflow.md)).

## Rules for scripts added here

- Prefer Cargo commands or the `pharos` CLI when they can do the job; add a script only when they cannot.
- Scripts must be safe by default: no `sudo`, no package installation, no writes outside the repository and `target/`, and no writes to block devices.
- Use `set -euo pipefail` in shell scripts and print clear error messages.
- Document each script's purpose, inputs, and requirements at the top of the file and in this README.
- Scripts must never commit, push, tag, or otherwise change Git state.
