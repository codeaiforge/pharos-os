# Vision

## Purpose

Pharos OS by CodeAIForge explores how to run AI agents locally and safely by designing the operating system around them, rather than adding agents on top of a system that grants them broad, ambient access.

The project starts as a host-side Rust workspace and CLI, grows into an experimental x86-64 kernel validated in QEMU, then adds a local AI agent platform, and aims eventually to become a standalone operating system.

## Principles

1. **Correctness before features.** Each milestone is small, testable, and gated.
2. **Security by construction.** Least privilege, a minimal trusted computing base, and explicit capabilities are design inputs, not later hardening.
3. **Agents are untrusted.** AI agents and model output are treated as untrusted input. They never gain unrestricted kernel access.
4. **Isolation of inference.** Inference runs outside privileged code, with bounded resources.
5. **Local-first.** Core functions, including inference, work without a network connection. Network access is a granted capability.
6. **Reproducibility.** Builds, tests, and boots are reproducible from the repository.
7. **Honest status.** Documentation distinguishes implemented, placeholder, and planned work.
8. **Safe Rust by default.** `unsafe` is minimal, justified, documented, and reviewed.

## Goals

- A buildable, tested Rust workspace with clear package boundaries (Phase 1).
- A minimal bootable x86-64 kernel with observable serial output in QEMU, then core OS services (Phase 2).
- A local agent platform with explicit permissions, sandboxing, resource limits, and audit logs (Phase 3).
- An integrated system where AI services run as unprivileged user-space components (Phase 4).
- Reproducible release artifacts with documented hardware support and release criteria (Phase 5).

## Non-goals (for now)

- POSIX or Linux binary compatibility.
- Supporting architectures other than x86-64 before the x86-64 design is stable.
- Broad real-hardware driver coverage; QEMU comes first.
- Cloud-hosted inference as a core dependency.
- Production use or security certification.
- Delivery dates; the roadmap is ordered by dependency, not by calendar.

## Long-term direction

If the core design proves sound, Pharos OS should provide a small, auditable kernel; user-space services for storage, networking, and devices; and an agent runtime where every capability an agent holds is visible, limited, and revocable by the user.
