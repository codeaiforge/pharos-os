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
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   python3 scripts/check-links.py
   ```

7. **Review.** Open a pull request with the template; list the commands you ran and their results.

## Useful commands

| Task | Command |
| --- | --- |
| Build everything | `cargo build --workspace` |
| Fast type check | `cargo check --workspace` |
| Run the CLI | `cargo run -p pharos-cli -- <command>` |
| Test one package | `cargo test -p pharos-cli` |
| Test by name | `cargo test -p pharos-cli doctor` |
| Format | `cargo fmt --all` |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Build docs | `cargo doc --workspace --no-deps --open` |
| Same as CI | `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo build --workspace --locked && cargo test --workspace --locked && python3 scripts/check-links.py` |

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
