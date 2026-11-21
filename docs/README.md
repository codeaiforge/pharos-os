# Pharos OS documentation

## Using Pharos

- [Running Pharos as a microVM](user/microvm.md) — verifying a release, setting up and booting a VM, the trusted console, and exporting and checking the audit trail.

## Project

- [Vision](project/vision.md) — Pharos as an agent cell and authority broker: purpose, the three tiers, principles, goals, and non-goals.
- [Comparison](project/comparison.md) — Pharos against sandboxes on Linux, a runtime on seL4, and Windows' agent workspace, every claim sourced.
- [Architecture](project/architecture.md) — what is implemented, the layers, boundaries, and capability model, and the planned cell, broker, and tiers.
- [Implementation roadmap](project/implementation-roadmap.md) — the authoritative phased plan with milestone gates.
- [Release criteria](project/release-criteria.md) — what a release must pass, and the evidence its gate records.
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
