# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, any release may contain breaking changes.

## [Unreleased]

### Added

- Boot design (`docs/architecture/boot.md`): accepted boot flow, Limine entry contract, image layout, and `xtask` build plan. Nothing boots on `main` yet.
- Accepted decisions D-001 (Limine, own protocol structures), D-002 (UEFI primary, BIOS secondary), and D-003 (`x86_64-unknown-none` on stable, linker script, `xtask`, ISO images, kernel as workspace member).
- Boot evaluation for D-001 to D-003 (`docs/architecture/boot-evaluation.md`), with proposed recommendations: Limine, UEFI primary with BIOS secondary, `x86_64-unknown-none` with an `xtask` build tool. Not accepted yet.
- Prototype evidence for D-001 to D-003 in the boot evaluation: Limine booted a prototype kernel under UEFI and BIOS in QEMU, with reproducible kernel and ISO builds.

### Security

- Pin `actions/checkout` in CI to the signed v5.1.0 release commit SHA instead of the movable `v5` tag.

## [0.1.0] - 2026-10-26

Initial scaffold, completing Phase 1 (Foundation). Pharos OS is not bootable; this release contains host-side tooling and documentation only.

### Added

- Cargo workspace (edition 2024, resolver 3, stable toolchain via `rust-toolchain.toml`) with `Cargo.lock`.
- `pharos-kernel`: host-side placeholder library. It does not boot and implements no operating-system functionality.
- `pharos-cli`: the `pharos` host-side CLI with `help`, `version`, `info`, and `doctor` commands, defined exit codes, unit tests, and end-to-end tests of the binary.
- Workspace lint `unsafe_code = "forbid"`; Clippy warnings are errors in CI. Minimum supported Rust 1.85 (`rust-version`), verified in CI.
- GitHub Actions CI (format, Clippy, build, test, rustdoc, Markdown link check, Rust 1.85 build and test) with read-only permissions and job timeouts.
- `scripts/check-links.py`: read-only checker for relative Markdown links and anchors.
- Project documentation: vision, architecture (proposed), implementation roadmap, decision log, glossary, threat model, and development guides.
- Repository policy files: `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Apache-2.0 `LICENSE`, and `NOTICE`.
- Private vulnerability reporting through GitHub, documented in `SECURITY.md`.
- Issue and pull-request templates, editor configuration, and optional VS Code recommendations.

[Unreleased]: https://github.com/codeaiforge/pharos-os/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/codeaiforge/pharos-os/releases/tag/v0.1.0
