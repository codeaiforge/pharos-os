# Pharos OS documentation

## Project

- [Vision](project/vision.md) — purpose, principles, goals, and non-goals.
- [Architecture](project/architecture.md) — what is implemented, and the layers, boundaries, and capability model.
- [Implementation roadmap](project/implementation-roadmap.md) — the authoritative phased plan with milestone gates.
- [Decision log](project/decision-log.md) — decision-record template and open decisions.
- [Glossary](project/glossary.md) — project terminology.

## Development

- [Setup](development/setup.md) — prerequisites and first build.
- [Workflow](development/workflow.md) — day-to-day development loop.
- [Testing](development/testing.md) — current tests and the planned test strategy.
- [Reference platform](development/reference-platform.md) — QEMU with KVM: host and VMM requirements, how to check a host, and host reports.
- [Debugging](development/debugging.md) — debugging the CLI now, the kernel later.

## Architecture

- [How Pharos works](architecture/overview.md) — diagrams of how the components interact; start here.
- [Architecture documents guide](architecture/README.md) — the index of detailed design documents and how they are organized.

## Security

- [Threat model](security/threat-model.md) — assets, trust boundaries, threats, and mitigations.
- [M2.7 security review](security/review-m2.7-kernel-user-boundary.md) — the kernel/user boundary: system calls, user memory, entry paths, and `unsafe` code.
- [Security policy](../SECURITY.md) — how to report vulnerabilities.

## Repository policies

- [AGENTS.md](../AGENTS.md) — enduring rules for all contributors and AI assistants.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribution process.
- [CHANGELOG.md](../CHANGELOG.md) — change history.
