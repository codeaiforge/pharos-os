# Comparison with the alternatives

Written in M6.0 (#266) for the alternatives [D-033](decision-log.md#d-033-repositioning-pharos-as-an-agent-cell-and-authority-broker-and-the-three-tiers) weighs: sandboxes on Linux, a runtime on seL4, and Windows' agent workspace. Every claim about an alternative cites a source, read on **2026-11-21** (the [sources](#sources) list them); every claim about Pharos is labelled **implemented** with the test that shows it, or **planned** with its milestone. Where an alternative is better, or good enough, this document says so. The first set of sources came from the strategic assessment of 2026-11-13 named in D-033; each was read again for this document, and those that had changed are cited as they read now.

## What Pharos claims

Five properties, the ones the [vision](vision.md) rests on. They hold today for Tier 1 agents (native `no_std` programs) on the KVM reference platform, with the host trusted.

| # | Property | State, and what shows it |
| --- | --- | --- |
| P1 | **No ambient authority.** An agent holds one capability for its whole life, `SEND` on the runtime's endpoint, badged with its slot; it has no file system, socket, or credential store of its own ([agents.md](../architecture/agents.md)) | **implemented:** the `hostile` test kernel (an agent trying everything outside its grants, beside one that must be unaffected), `agents_net` (default-deny networking per destination), `tools` (calls outside the grants refused) |
| P2 | **Fail closed.** A grant or approval whose audit record fails is not given; a send that cannot be recorded does not go out (`NO_AUDIT`); a boot without the device key stops ([capabilities.md](../architecture/capabilities.md), [release-integrity.md](../architecture/release-integrity.md)) | **implemented:** the `permissions` test kernel (with the audit service killed, the agent's writes and inference get `NO_AUDIT` and a task started afterwards gets no grant), and `device_key` (a boot without the key refused; a throwaway branch on which the kernel ignores the key failed CI) |
| P3 | **A trusted path for people.** Approvals and the emergency stop are on a console device only `trust` holds; prompts are built from structured fields, not agent text ([tools.md](../architecture/tools.md)); `trust` stops the runtime and every agent without the runtime's help | **implemented:** the `trust` and `compromised` test kernels (a hostile program under the runtime's exact manifest cannot put a forged registration on the console) |
| P4 | **Evidence a third party can check.** The audit head is Ed25519-signed after every record with a key derived from the per-VM device secret, carries the boot measurement, and is checked outside Pharos ([release-integrity.md](../architecture/release-integrity.md)) | **implemented:** the `audit` and `rotate` test kernels; a verifier skipping the signature check failed CI on a throwaway branch ([run 44713676203](https://github.com/codeaiforge/pharos-os/actions/runs/44713676203)) |
| P5 | **Enforcement outside the model.** Model output is untrusted input: a tool call runs only if it parses, validates, and is within the grants | **implemented:** the `injection` test kernel (injected instructions in a granted file and model output proposing ungranted calls, none of which act), `s1` (a real model's `read_file` call validated and run) |

Why P5 matters: published in-model defenses against prompt injection fail under adaptive attack. Nasr, Carlini, Tramèr and others bypassed 12 recent defenses, "with attack success rate above 90% for most" [S10]. Enforcement has to sit outside the model, whichever model it is.

What Pharos does **not** claim: a verified kernel (seL4 has one, Pharos does not); containment of a Tier 3 guest (the host does it, D-036); payload approval (the user confirms a `send`'s destination and size, not its payload, until M6.4); bare metal or more than one CPU (M8.1, M6.10).

## Sandboxes on Linux

### MicroVM and application-kernel sandboxes

**Firecracker** runs microVMs on KVM with "a minimal required device model" and "only 5 emulated devices" [S3]. **gVisor** is "an application kernel" that "runs in userspace" and intercepts application system calls [S4]. Agent sandbox services build on them: **E2B** runs "one Firecracker microVM per sandbox" [S5]; **GKE Agent Sandbox** uses gVisor, with Kata pluggable, and Google reports "300 sandboxes per second, per cluster" from a warm pool [S6] (the post gives no test conditions).

- **What they give:** strong, fast, cheap isolation of agent *code*, on infrastructure organizations already run. For running untrusted code, this is enough, and far cheaper to adopt than a new system.
- **What they do not address:** what the agent does with the authority it is given. A sandbox holding an API key, a network route, or a mounted directory lets the agent use all of it; the sandbox has no notion of a grant per destination, an approval, or a record before the action.
- **Where Pharos differs:** P1 to P4 sit above containment, in the broker. Pharos does not replace these sandboxes: its planned Tier 3 (M6.3) runs foreign agents in exactly such a Linux microVM, with no credentials and no network device, and brokers what leaves it. In Tier 3 the containment is the host's, as in these products.

### Agent CLIs' OS sandboxes

**Claude Code** sandboxes commands with bubblewrap on Linux and Seatbelt on macOS; network connections go through a proxy that checks each host against allowed domains, "which start empty", and prompts for a new domain; writes are limited to the working directory, a per-user temp directory, and added directories, while reads cover "the entire computer, except certain denied directories" [S1]. The sandbox "is off by default", and "when the platform doesn't support the sandbox or the dependency check at startup fails, Claude Code runs commands without sandboxing", unless `sandbox.failIfUnavailable` is set to `true` [S1]. **OpenAI Codex** uses "bwrap plus seccomp" on Linux and Seatbelt on macOS, runs "with network access turned off" by default, and has the sandbox modes `read-only`, `workspace-write`, and `danger-full-access` [S2]; its documentation notes the sandbox "may not work if the host or container configuration blocks the namespace, setuid bwrap, or seccomp operations" it needs [S2].

- **What they give:** default-deny egress, confined writes, and approval prompts for the developer at the keyboard, at no cost beyond the tool itself.
- **What they do not address:** they are retrofits on the host's mechanisms, so their guarantees are configuration: off by default, fail-open by default in Claude Code's case, and reads of the whole machine. Their approval prompts are part of the agent tool's own interface [S1, S2], which runs as the user, beside the agent's commands.
- **Where Pharos differs:** P1 (no ambient reads: an agent reads only a file it was granted, `tools`), P2 (no fail-open path: the authority is the capability, there is no unsandboxed mode to fall back to), and P3 (the prompt is on a device the agent cannot reach, `trust`).

### MCP gateways

**Docker MCP Gateway** runs MCP servers in containers and logs their calls through a centralized proxy [S7]; Docker's announcement adds interceptors, signature verification, and blocking of secrets [S8].

- **What they give:** one place to see, filter, and contain the tools agents use; a real improvement on tools run with the user's full rights.
- **What they do not address:** the gateway sees calls, not intent. A call to an allowed tool with an injected argument passes, unless an interceptor recognises it.
- **Where Pharos differs:** P3 and P4 apply to every tool call, and the user confirms each `send` on the trusted path; but Pharos does not yet speak MCP (an adapter is M7.6), and its confirmation covers destination and size, not payload, until M6.4. Today, a gateway reaches far more tools than Pharos's two.

## A runtime on seL4

**seL4** is a microkernel with machine-checked proofs: functional correctness, integrity, and confidentiality on Arm and RISC-V configurations; on x86-64, functional correctness of the C code only [S9]. The AArch64 confidentiality proof was completed in August 2026 [S10a]. seL4 is a minimal kernel; drivers, file systems, and networking are built on top [S11]. The Microkit framework lists x86-64 support in its changelog [S12] (its platforms page still says "x64 support is on the roadmap" [S13]), and Rust bindings are released (`rust-sel4` 6.0.0, 30 October 2026 [S14]).

- **What it gives:** a stronger kernel argument than Pharos can make. Pharos's kernel is tested (81 test kernels on every push, host tests and fuzzing of its protocols, a security review at each milestone and an independent one of the trusted base at M5.4, the [threat model](../security/threat-model.md)), not proven.
- **What it does not give:** seL4 isolates; it does not run agents. It has no agent runtime, inference service, approval path, or audit trail. A paper positioning its own agent system puts it as: seL4 "proves that an OS kernel can formally verify capability isolation—but does not record what happens within those isolation boundaries" [S15].
- **Where Pharos differs:** what is new in Pharos is above the kernel: the runtime, the trusted console, audit-or-refuse, and signed evidence (P1 to P5). The same runtime on seL4 would keep them and gain the proofs. D-033 therefore keeps the runtime portable so that option stays open, and Pharos never claims seL4-level assurance.

## Windows' agent workspace

Windows runs agents under **their own accounts**, "distinct from your personal user account", in a **separate Windows session** with its own desktop; the feature "is off by default" and "currently in preview" [S16]. Agents that integrate with Windows "must be signed by a trusted source" [S17]. With the setting on, Windows grants agents read and write access to six known folders (Documents, Downloads, Desktop, Videos, Pictures, Music), set per agent to allow always, ask every time, or never; and agent accounts "have access to any folders that all authenticated users have access to" [S16]. Microsoft names cross-prompt injection (XPIA) as a risk: "malicious content embedded in UI elements or documents can override agent instructions, leading to unintended actions like data exfiltration or malware installation" [S16]. Microsoft's security documentation now also describes Microsoft Execution Containers, "policy-driven runtime boundaries that help control file and network access while agents run" [S18]; this document has not evaluated them.

- **What it gives:** agent identities and a separate workspace on the platform most organizations' desktops already run, with signing, per-folder consent, and enterprise management around it.
- **What it does not give:** authority is accounts and access lists, not capabilities, so an agent account reaches whatever all authenticated users can, beyond the folders it was granted [S16]; and the risk Microsoft names, XPIA, is the case Pharos's P5 and P1 are built for.
- **Where Pharos differs:** P1 (an agent reaches nothing but the runtime, `hostile`), P5 (injected content cannot act beyond the grants, `injection`), and P3 (approval off the agent's desktop, `trust`). Windows has the ecosystem; Pharos has no desktop and does not plan one.

## Summary

| | MicroVM and gVisor sandboxes | Agent CLIs' OS sandboxes | MCP gateways | A runtime on seL4 | Windows' agent workspace | Pharos (v0.5.0, Tier 1) |
| --- | --- | --- | --- | --- | --- | --- |
| Contains agent code | yes [S3–S6] | yes, by host configuration [S1, S2] | MCP servers in containers [S7] | yes, verified kernel [S9] | separate account and session [S16] | yes, one process per attempt (`hostile`) |
| No ambient authority | what the sandbox holds | reads of the machine [S1] | per tool | depends on the runtime built | accounts and access lists [S16] | **implemented** (P1) |
| No fail-open path | not applicable | fail-open by default in Claude Code [S1] | not described [S7, S8] | depends on the runtime built | not described [S16, S17] | **implemented** (P2) |
| Approval on a path the agent cannot reach | not described [S3–S6] | in the agent tool's own interface [S1, S2] | not described [S7, S8] | not provided by the kernel [S11] | per-folder consent [S16] | **implemented** (P3); full payload **planned** (M6.4) |
| Audit checkable outside the system | not described [S3–S6] | not described [S1, S2] | logs [S7] | not provided by the kernel [S15] | not evaluated | **implemented** (P4) |
| Verified kernel | no | no | no | **yes** [S9] | no | no |
| Runs existing agent frameworks | **yes** | **yes** | **yes** | no | **yes** | **planned** (Tier 3, M6.3) |
| Adoption cost | low | lowest | low | high | low on Windows | high |

"Not described" means the sources read do not describe it, not that the product cannot do it. The honest reading: each alternative owns one or two of these rows, and several are better than Pharos on cost, ecosystem, or assurance. None of the alternatives read combines the middle four rows under one enforcement point. That combination is Pharos's claim, it is implemented only for Tier 1 today, and the work of Phase 6 is to extend it to the agents organizations already run.

## Sources

All read on 2026-11-21.

- [S1] Claude Code, "Sandboxing": https://code.claude.com/docs/en/sandboxing
- [S2] OpenAI Codex, "Agent approvals and security": https://learn.chatgpt.com/docs/agent-approvals-security (formerly developers.openai.com/codex/agent-approvals-security)
- [S3] Firecracker: https://firecracker-microvm.github.io/
- [S4] gVisor documentation: https://gvisor.dev/docs/
- [S5] E2B infrastructure, README: https://github.com/e2b-dev/infra
- [S6] Google Cloud, "Bringing you Agent Sandbox on GKE and Agent Substrate", 21 May 2026: https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate
- [S7] Docker, "MCP Gateway": https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- [S8] Docker blog, "Docker MCP Gateway: secure infrastructure for agentic AI", 9 July 2025: https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/
- [S9] seL4, "Verified configurations": https://docs.sel4.systems/projects/sel4/verified-configurations.html, and "Proofs": https://sel4.systems/Verification/proofs.html
- [S10] M. Nasr, N. Carlini, …, F. Tramèr, "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections", arXiv 2510.09023, 10 October 2025: https://arxiv.org/abs/2510.09023
- [S10a] seL4 news, 2026: https://sel4.systems/news/2026.html
- [S11] seL4 FAQ: https://sel4.systems/About/FAQ.html
- [S12] seL4 Microkit, `CHANGES.md`: https://github.com/seL4/microkit
- [S13] seL4 Microkit, "Supported platforms": https://docs.sel4.systems/projects/microkit/platforms.html
- [S14] `rust-sel4` releases: https://github.com/seL4/rust-sel4/releases
- [S15] J. Zhang, "Right to History: A Sovereignty Kernel for Verifiable AI Agent Execution", arXiv 2602.20214, section 1: https://arxiv.org/html/2602.20214
- [S16] Microsoft Support, "Experimental agentic features": https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features
- [S17] Windows Experience Blog, "Securing AI agents on Windows", 16 October 2025: https://blogs.windows.com/windowsexperience/2025/10/16/securing-ai-agents-on-windows/
- [S18] Microsoft Learn, "Agent governance": https://learn.microsoft.com/en-us/windows/security/application-security/agent-governance
