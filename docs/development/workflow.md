# Development workflow

This workflow works on any branch and does not depend on hosting. Rules in [AGENTS.md](../../AGENTS.md) apply throughout.

## The loop

1. **Inspect.** Read the code and docs you will touch, and find the related roadmap milestone.
2. **Plan.** For anything beyond a small fix, write down the intended change (issue or PR description) before implementing.
3. **Implement** a focused change. Keep `unsafe` out unless the milestone requires it and the policy is followed.
4. **Test.** Add or update tests that fail without your change.
5. **Document.** Update README, `docs/`, and `CHANGELOG.md` (`Unreleased`) as needed.
6. **Check** locally:

   ```sh
   cargo fmt --all
   scripts/check.sh
   ```

7. **Review.** Open a pull request with the template; list the commands you ran and their results.

## Useful commands

| Task | Command |
| --- | --- |
| Build host crates | `cargo build` |
| Fast type check | `cargo check` |
| Check the kernel | `cargo clippy -p pharos-kernel --target x86_64-unknown-none --lib --bins --test '*' -- -D warnings` |
| Run boot check and kernel tests | `cargo xtask test` (needs QEMU, OVMF, xorriso) |
| Test kernel library logic | `cargo test -p pharos-kernel --lib` |
| Run the CLI | `cargo run -p pharos-cli -- <command>` |
| Build the kernel | `cargo xtask build` |
| Build the boot image | `cargo xtask image` (needs xorriso; downloads the pinned Limine release once) |
| Test one package | `cargo test -p pharos-cli` |
| Test by name | `cargo test -p pharos-cli doctor` |
| Format | `cargo fmt --all` |
| Lint host crates | `cargo clippy --workspace --exclude pharos-kernel --exclude pharos-programs --all-targets -- -D warnings` |
| Build docs | `cargo doc --workspace --exclude pharos-kernel --exclude pharos-programs --no-deps --open` |
| Same as CI | `scripts/check.sh` |

## Adding a package

1. Create it under the right directory (`tools/` for host tools; kernel-related crates per D-003 when decided).
2. Use workspace metadata: `version.workspace = true`, `edition.workspace = true`, `rust-version.workspace = true`, `license.workspace = true`, `publish.workspace = true`, and `[lints] workspace = true`.
3. Add it to `members` in the root `Cargo.toml`.
4. Explain why a new package is needed instead of a module.

## Adding a dependency

Follow the dependency policy in [AGENTS.md](../../AGENTS.md#6-dependencies): justify it, check its license and maintenance, and include the updated `Cargo.lock`.

## Version and changelog

- The version lives once, in `[workspace.package]` in the root `Cargo.toml`. The CLI reads it at compile time; do not copy it elsewhere in code.
- Record user-visible changes under `Unreleased` in `CHANGELOG.md`.
- Releases, tags, and publishing are maintainer actions, not part of the development loop.
