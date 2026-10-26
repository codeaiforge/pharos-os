# AGENTS.md — Development rules for Pharos OS

These rules apply to every contributor: people, AI coding assistants, and automation. They hold for the life of the project unless changed through review.

## 1. Before you change anything

- Inspect the repository first: read the relevant code, docs, and the [roadmap](docs/project/implementation-roadmap.md). Do not assume a file, feature, or tool exists.
- Explain the intended change before substantial implementation (in the issue, PR description, or to the person you are assisting).
- Make focused, incremental changes. One concern per change. Do not mix refactors with behavior changes.
- Stay within the current milestone. Work on a later milestone only when its prerequisites and gate are satisfied, or when the change is cross-cutting (tests, security, docs, decisions).

## 2. Git restrictions (strict)

AI assistants and automation must **never**:

- commit, amend, tag, push, publish, or create releases;
- rewrite Git history, rebase shared branches, or force-push;
- initialize, delete, or alter Git metadata (`.git/`, config, hooks, remotes);
- bypass these restrictions through scripts, aliases, CI jobs, or other indirect tools.

The only exception is an explicit authorization from the maintainer for a specific action. Read-only inspection (`git status`, `git diff`, `git log`, `git show`) is always allowed.

## 3. Safety of the development host

- Never run destructive commands (`rm -rf` outside build output, disk writes, partitioning, `dd` to devices) or privileged system modifications (`sudo`, package installs, kernel modules, firmware changes) without explicit authorization.
- Do not install packages or change system configuration to make a check pass. Report the missing tool and the exact command the maintainer can run.
- Boot experimental kernels only in QEMU unless real-hardware testing is explicitly authorized.

## 4. Secrets

- Never print, log, commit, or transmit credentials, tokens, private keys, or personal data.
- Never add secrets to source, tests, docs, CI files, or examples. Use placeholders such as `<TOKEN>`.
- If you find a secret in the repository, stop and report it privately (see [SECURITY.md](SECURITY.md)).

## 5. Rust standards

- Use safe Rust by default. The workspace currently forbids `unsafe` (`unsafe_code = "forbid"` in `Cargo.toml`).
- When `unsafe` becomes necessary (expected in the kernel from Phase 2):
  - allow it only in the specific crate or module that needs it, never workspace-wide;
  - keep each `unsafe` block minimal and wrap it in a safe abstraction;
  - document every block with a `// SAFETY:` comment stating the invariants relied on;
  - explain it in the PR and require review of that code specifically.
- Code must pass `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Prefer clear error messages that say what failed and what to do next. Do not `unwrap()` on fallible input outside tests.
- Keep builds reproducible: commit `Cargo.lock`, use `--locked` in CI, track the stable toolchain via `rust-toolchain.toml`, and avoid nightly features unless a decision record justifies them.

## 6. Dependencies

- Prefer the standard library. Add a dependency only when it provides clear value that is hard to replicate safely.
- For each new dependency, state in the PR: why it is needed, its license (must be compatible with Apache-2.0), its maintenance status, and its transitive dependency count.
- Kernel and other privileged code have a higher bar: every dependency joins the trusted computing base.

## 7. Architecture boundaries

- Keep privileged kernel responsibilities (memory, scheduling, interrupts, isolation, IPC) separate from user-space services and AI agents.
- AI inference and agents run outside the kernel, unprivileged, and are treated as untrusted.
- Agent capabilities are explicit, least-privilege, revocable, and auditable. No ambient authority: an agent gets access to a file, process, device, or network only through a granted capability.
- Model output is untrusted input. Never execute it, or pass it to privileged interfaces, without validation and policy checks.
- Record significant architecture choices in the [decision log](docs/project/decision-log.md) before or with the implementation.

## 8. Tests and documentation

- Add or update tests with every behavior change. Bug fixes include a test that fails without the fix.
- Update documentation in the same change: README, relevant `docs/` pages, and `CHANGELOG.md`.
- Never describe planned functionality as implemented. Use the labels **implemented**, **placeholder**, and **planned** consistently.

## 9. Reporting

- Report commands you ran and their real outcomes, including warnings and failures.
- Never claim a test, build, lint, or QEMU run passed unless it actually ran and succeeded in this change.
- Say clearly when a tool was unavailable or a check was skipped, and why.

## 10. License and contributions

- All contributions are under the Apache License 2.0 ([LICENSE](LICENSE)), following [CONTRIBUTING.md](CONTRIBUTING.md).
- Do not copy code or text from sources with incompatible or unknown licenses. Record any third-party material in [NOTICE](NOTICE).
