#!/usr/bin/env bash
# Runs the same checks as the CI `check` job (.github/workflows/ci.yml), in the
# same order, then the `msrv` job's checks if Rust 1.85 is installed, and stops
# at the first failure.
# Read-only apart from Cargo's target/ directory. No root, no network beyond
# what Cargo itself needs. Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

run() { printf '\n==> %s\n' "$*"; "$@"; }

run cargo fmt --all -- --check
# Host crates; the kernel and user programs target bare metal (D-003, D-008).
run cargo clippy --workspace --exclude pharos-kernel --exclude pharos-programs --all-targets --locked -- -D warnings
run cargo build --workspace --exclude pharos-kernel --exclude pharos-programs --locked
run cargo test --workspace --exclude pharos-kernel --exclude pharos-programs --locked
run cargo test -p pharos-programs --lib --locked
# Kernel: host-testable library logic, then the bare-metal target.
run cargo test -p pharos-kernel --lib --locked
run cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' --locked -- -D warnings
# User programs: no_std static programs for x86_64-unknown-linux-gnu, as
# cargo xtask builds them (user-environment.md).
run env CARGO_TARGET_DIR=target/user RUSTFLAGS="--cfg pharos_user -C panic=abort" cargo clippy -p pharos-programs --target x86_64-unknown-linux-gnu --locked -- -D warnings
run env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude pharos-kernel --exclude pharos-programs --no-deps --locked
run env RUSTDOCFLAGS="-D warnings" cargo doc -p pharos-kernel --target x86_64-unknown-none --no-deps --locked
run python3 scripts/check-links.py
run python3 -m unittest -q scripts/test_bench_inference.py

# The CI `msrv` job: the same host builds and tests on the minimum supported
# Rust. Runs only if that toolchain is installed (rustup toolchain install
# 1.85 --profile minimal); otherwise says so, because CI will still run it.
if rustup run 1.85 rustc --version >/dev/null 2>&1; then
    run cargo +1.85 build --workspace --exclude pharos-kernel --exclude pharos-programs --locked
    run cargo +1.85 test --workspace --exclude pharos-kernel --exclude pharos-programs --locked
    run cargo +1.85 test -p pharos-programs --lib --locked
    run cargo +1.85 test -p pharos-kernel --lib --locked
else
    printf '\n==> SKIPPED: Rust 1.85 not installed, so the CI msrv job was not repeated locally.\n'
    printf '    Install it with: rustup toolchain install 1.85 --profile minimal\n'
fi

printf '\nAll checks passed.\n'
