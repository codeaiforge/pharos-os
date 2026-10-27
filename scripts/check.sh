#!/usr/bin/env bash
# Runs the same checks as the CI `check` job (.github/workflows/ci.yml), in the
# same order, and stops at the first failure.
# Read-only apart from Cargo's target/ directory. No root, no network beyond
# what Cargo itself needs. Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

run() { printf '\n==> %s\n' "$*"; "$@"; }

run cargo fmt --all -- --check
# Host crates; the kernel targets bare metal (D-003).
run cargo clippy --workspace --exclude pharos-kernel --all-targets --locked -- -D warnings
run cargo build --workspace --exclude pharos-kernel --locked
run cargo test --workspace --exclude pharos-kernel --locked
# Kernel: host-testable library logic, then the bare-metal target.
run cargo test -p pharos-kernel --lib --locked
run cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' --locked -- -D warnings
run env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude pharos-kernel --no-deps --locked
run env RUSTDOCFLAGS="-D warnings" cargo doc -p pharos-kernel --target x86_64-unknown-none --no-deps --locked
run python3 scripts/check-links.py

printf '\nAll checks passed.\n'
