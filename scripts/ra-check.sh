#!/usr/bin/env bash
# rust-analyzer's on-save check (wired up in .vscode/settings.json).
# Mirrors the CI split: host crates without the kernel, then the kernel for
# its bare-metal target. A plain `cargo clippy --workspace` would build the
# kernel for the host and report false errors (duplicate `panic_impl`).
# Prints Cargo's JSON diagnostics for the editor. Read-only apart from target/.
cd "$(dirname "$0")/.."
status=0
cargo clippy --workspace --exclude pharos-kernel --exclude pharos-programs --all-targets \
    --message-format=json-diagnostic-rendered-ansi "$@" || status=$?
cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' \
    --message-format=json-diagnostic-rendered-ansi "$@" || status=$?
cargo clippy -p pharos-programs --target x86_64-unknown-none \
    --message-format=json-diagnostic-rendered-ansi "$@" || status=$?
exit "$status"
