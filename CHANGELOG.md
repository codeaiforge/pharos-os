# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, any release may contain breaking changes.

## [Unreleased]

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
