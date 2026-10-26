# Contributing to Pharos OS

Thank you for your interest. Pharos OS is early-stage systems software, so the bar for correctness, security, and clarity is high. Read [AGENTS.md](AGENTS.md) first; its rules apply to all contributors.

## Setup

Follow [docs/development/setup.md](docs/development/setup.md). In short: install rustup and a C linker, then run:

```sh
cargo build
cargo test
```

## Local workflow

The workflow does not depend on any branch name. See [docs/development/workflow.md](docs/development/workflow.md) for detail.

1. Pick or open an issue and link it to a roadmap milestone.
2. Describe your intended change before large implementation work.
3. Make a focused change with tests and docs.
4. Run the quality checks below until they pass.
5. Open a pull request using the template and report what you ran.

## Quality checks

Run the full gate before review; it runs the same checks as CI and stops at the first failure:

```sh
scripts/check.sh
```

It covers formatting, Clippy with warnings as errors, build, tests, rustdoc, and Markdown links. Host crates and the bare-metal kernel are checked separately; the individual commands are listed in [testing.md](docs/development/testing.md#quality-gates).

Use `cargo fmt --all` to fix formatting. If `markdownlint-cli2` is available, lint docs with `npx markdownlint-cli2 "**/*.md"` (configured in `.markdownlint-cli2.jsonc`); this is optional.

## Documentation expectations

- Update docs in the same change as the behavior they describe.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- Label features honestly: **implemented**, **placeholder**, or **planned**.
- Record architecture decisions in [docs/project/decision-log.md](docs/project/decision-log.md).

## Review

- Every change is reviewed before merge. Small changes are reviewed faster.
- Reviewers check correctness, tests, docs, scope, dependencies, and security impact.
- Address feedback with follow-up changes; explain disagreements technically.

## Security-sensitive changes

Changes in these areas need explicit security review and a clear description in the PR:

- any `unsafe` code (each block needs a `// SAFETY:` comment);
- new dependencies, especially in kernel or privileged code;
- privilege boundaries, system calls, IPC, memory management;
- agent capabilities, sandboxing, tool access, network access;
- CI workflow permissions or anything that handles credentials.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

By contributing, you agree that your contributions are licensed under the [Apache License, Version 2.0](LICENSE), as described in section 5 of that license.
