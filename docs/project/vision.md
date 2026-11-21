# Vision

Rewritten in M6.0 (#264) for [D-033](decision-log.md#d-033-repositioning-pharos-as-an-agent-cell-and-authority-broker-and-the-three-tiers) (accepted 2026-11-13). The earlier vision, a local-first single-user OS that runs its own model and agents, is what Phases 1–5 built; it is the base of this one, not replaced by it. Each statement below is labelled **implemented** (in v0.5.0) or **planned** (with its milestone in the [roadmap](implementation-roadmap.md)). How Pharos compares with the alternatives is in [comparison.md](comparison.md).

## Purpose

Pharos OS by CodeAIForge is an **agent cell**: a small system, run as a microVM on an ordinary KVM host, that holds all the authority an AI agent can use (capabilities, credentials, approvals, and the audit trail) and gives the agent none of it directly. An agent's limits are then a property of the machine it runs on, enforced by a capability kernel, not a promise made by the agent's own software or its model.

It is for **organizations that want to put agents into operations where a mistake is costly**, such as regulated work, without handing the agents the keys: every action an agent takes goes through a granted capability, a human approval where the policy asks for one, and an audit record that a verifier outside Pharos can check.

## The three tiers

Agents run in one of three tiers ([roadmap](implementation-roadmap.md#agent-tiers-d-033)). The tier decides who enforces the agent's limits.

| Tier | Where the agent runs | Who enforces its limits | State |
| --- | --- | --- | --- |
| 1. Native | inside Pharos, as `no_std` Rust under the agent runtime | the Pharos kernel and runtime, end to end | **implemented** |
| 2. WASM | inside Pharos, in a WASM runtime that is itself an unprivileged service | the Pharos kernel and runtime, through the WASM sandbox | **planned** (M7.5) |
| 3. Foreign | in a Linux microVM beside Pharos, with no credentials and no network device | Pharos brokers every external action; the guest's containment is the host's VM configuration, so the host kernel and hypervisor are in the trusted base | **planned** (M6.3; the host leaves the trusted base with M8.2) |

The claim that an agent's limits are a property of the machine holds end to end for Tiers 1 and 2. In Tier 3, Pharos's contribution is the broker, not the containment, until M8.2.

## Principles

1. **Correctness before features.** Each milestone is small, testable, and gated.
2. **Security by construction.** Least privilege, a minimal trusted computing base, and explicit capabilities are design inputs, not later hardening.
3. **Agents and models are untrusted.** Agents and model output, local or remote, are untrusted input. They never gain kernel access, and model output never acts without validation and policy checks.
4. **No ambient authority.** An agent holds nothing it was not granted: no file system, socket, or credential store to fall back on.
5. **Fail closed.** An action that cannot be checked, approved, or recorded does not happen.
6. **A trusted path for people.** Approvals and the emergency stop reach the user over a path no agent can reach or imitate.
7. **Evidence a third party can check.** The audit trail is signed and verifiable outside Pharos; releases are reproducible and signed.
8. **Honest status.** Documentation distinguishes implemented, placeholder, and planned work, and says where an alternative is better.
9. **Safe Rust by default.** `unsafe` is minimal, justified, documented, and reviewed.

## Goals

**Implemented (Phases 1–5, v0.5.0):**

- A capability microkernel in Rust, running as a microVM on QEMU with KVM, every device behind its own IOMMU domain.
- Tier 1 agents as untrusted processes under a supervised runtime: revocable, least-privilege permissions; default-deny networking per destination; budgets; validated tool calls; a trusted console no agent can reach, with an emergency stop; every consequential action recorded before it happens, or refused.
- Local inference as an unprivileged service, its output untrusted.
- Evidence: a per-VM device key, an audit trail signed after every record and checked outside Pharos, measured boot, Secure Boot with Pharos's keys, and reproducible, signed releases.

**Planned:**

- **The authority broker (Phase 6):** agents never hold credentials; a vault and an egress gateway put them on requests an allow-list permits (M6.2), over TCP and TLS run as user-space services (M6.1).
- **Foreign agents (Tier 3, M6.3):** existing Python and TypeScript agent frameworks in a Linux microVM, reaching the outside only through Pharos.
- **Organizational governance:** approval of the full payload, routed by risk (M6.4); identities, roles, and tenants (M6.5); a runtime policy (M6.6); evidence an auditor can read (M6.7, M6.8).
- **Brokered models (M6.9):** local or remote models reached only through Pharos, never by an agent directly.
- **Multi-tenant (M6.5, M6.10):** one runtime per tenant, in place of the single user of v0.5.0.
- **WASM agents (Tier 2, M7.5),** an MCP adapter (M7.6), and information-flow labels (M7.8).
- **Real hardware (Phase 8):** bare metal (M8.1), and Pharos as the hypervisor for Tier 3 guests (M8.2).

## Non-goals

- **POSIX or Linux binaries on Pharos.** Tier 3 runs them in a Linux guest beside it.
- **A general-purpose desktop** or graphical interface.
- **Agents holding credentials or sockets,** in any tier.
- **Any part of the broker in the kernel.** Each component is a user-space service or sits outside the system.
- **Cloud inference as a dependency.** A remote model is reached only through the model broker (M6.9), and air-gapped use with local inference stays possible.
- **Architectures other than x86-64** before the x86-64 design is stable (ARM64 is evaluated in M8.3).
- **Production use or security certification** before Phase 8 (a gap analysis is M8.6).
- **Delivery dates;** the roadmap is ordered by dependency, not by calendar.

## Long-term direction

A small, auditable kernel and trusted base that any agent, whatever its framework or model, must go through to act: every capability it holds visible, limited, and revocable by the people responsible for it, and every action provable afterwards. The agent runtime stays portable enough to run on another capability kernel, such as seL4, if a verified kernel is required (D-033).
