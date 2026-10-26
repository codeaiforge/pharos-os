# Pharos OS

Pharos OS by CodeAIForge is an experimental project to build a local-first AI agent platform, and eventually a standalone operating system, in Rust.

> [!WARNING]
> Pharos OS is **not** a bootable or production-ready operating system. It is in early development at the repository-scaffold stage. Do not use it for anything security-critical.

## Status

**v0.1.0 — Phase 1 (Foundation) complete.** The next milestone is M2.1, architecture and boot-protocol decisions. See the [implementation roadmap](docs/project/implementation-roadmap.md).

| Area | Status |
| --- | --- |
| Rust workspace, formatting, linting, tests, CI config | Implemented |
| `pharos` host-side CLI (`help`, `version`, `info`, `doctor`) | Implemented |
| `kernel` crate | Placeholder: a normal host library; does not boot |
| Bootable x86-64 kernel, QEMU boot | Planned |
| Memory management, interrupts, scheduling, processes, IPC | Planned |
| Storage, drivers, networking | Planned |
| Local AI inference and agent platform | Planned |

## Vision

Pharos OS aims to run AI agents locally under an operating-system design where agents are untrusted by default: they get explicit, least-privilege capabilities, inference runs isolated from privileged code, and model output is never trusted as instructions to the kernel. The project favors correctness, security, reproducibility, and small verifiable milestones over feature count. Read more in [vision](docs/project/vision.md) and [architecture](docs/project/architecture.md).

## Development environment

| | Initial target |
| --- | --- |
| Host | Linux Mint (other x86-64 Linux distributions should work) |
| Language | Rust, stable channel, edition 2024 (minimum Rust 1.85) |
| Architecture | x86-64 |
| Emulator | QEMU (needed from Phase 2; not used yet) |

## Prerequisites

- [rustup](https://rustup.rs/) with a stable Rust toolchain. `rust-toolchain.toml` selects `stable` with `rustfmt` and `clippy`, and rustup installs them on first use.
- A C linker (`cc`). On Linux Mint/Ubuntu: `sudo apt install build-essential`.

QEMU and cross-compilation tools are **not** required yet. See [setup](docs/development/setup.md).

## Build and run

```sh
cargo build --workspace
cargo run -p pharos-cli -- help
```

## CLI usage

```console
$ cargo run -q -p pharos-cli -- version
pharos 0.1.0

$ cargo run -q -p pharos-cli -- info
Pharos OS 0.1.0
Project of: CodeAIForge
Stage:      Phase 1 - Foundation (repository scaffold)
...

$ cargo run -q -p pharos-cli -- doctor
pharos doctor (read-only checks)
  [PASS] host OS             linux (supported: linux)
  [PASS] host architecture   x86_64 (supported: x86_64)
  ...
```

Exit status: `0` success, `1` the command reported a problem (for example, `doctor` warnings), `2` invalid usage.

## Test, format, lint

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-links.py   # Markdown link check
```

These are the checks CI runs (CI also builds rustdoc and tests on Rust 1.85) ([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Repository layout

| Path | Purpose |
| --- | --- |
| `kernel/` | Placeholder for the future kernel ([kernel/README.md](kernel/README.md)) |
| `tools/pharos-cli/` | The `pharos` host-side development CLI |
| `docs/` | Project, development, architecture, and security docs ([index](docs/README.md)) |
| `tests/` | Future cross-crate and QEMU integration tests ([tests/README.md](tests/README.md)) |
| `scripts/` | Future helper scripts ([scripts/README.md](scripts/README.md)) |

## Documentation

- [Implementation roadmap](docs/project/implementation-roadmap.md)
- [Architecture](docs/project/architecture.md)
- [Development setup](docs/development/setup.md) and [workflow](docs/development/workflow.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md) and [threat model](docs/security/threat-model.md)
- [Changelog](CHANGELOG.md)
- [Agent and contributor rules](AGENTS.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See also [NOTICE](NOTICE).
