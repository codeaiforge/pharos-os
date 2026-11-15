# How Pharos works

This page explains how the parts of Pharos fit together: what each process holds, how the system boots, how an agent's request is checked, and where the trust boundaries are. It is the place to start. The other documents in this directory hold the detailed designs, and this page links to them; where they and this page differ, they are right and this page needs fixing.

**Status:** every diagram shows what is **implemented** on `main`, on one CPU in QEMU, unless a part is labelled **planned**. Each one is drawn from the code it names (`pharos_services::tables::BOOT` for the capability map, `init`'s `boot_image` for the boot), so a change to that code updates the diagram in the same change (AGENTS.md section 8).

Reading order for a new contributor: this page, then [system calls and IPC](syscalls-ipc.md) (the kernel interface everything uses), [services](services.md) (`init` and the service table), [agents](agents.md) and [capabilities](capabilities.md) (the runtime and its permissions), and the [threat model](../security/threat-model.md).

## Contents

1. [Layers](#1-layers)
2. [Processes and the capabilities they hold](#2-processes-and-the-capabilities-they-hold)
3. [Boot](#3-boot)
4. [An agent task, end to end](#4-an-agent-task-end-to-end)
5. [A sensitive tool call](#5-a-sensitive-tool-call)
6. [Where authority comes from, and how it is taken away](#6-where-authority-comes-from-and-how-it-is-taken-away)
7. [Trust zones](#7-trust-zones)

Colours are the same in every diagram:

| Colour | Means |
| --- | --- |
| Dark blue | The kernel: the only privileged code |
| Green | The trusted base reviewed in M5.4 ([review](../security/review-m5.4-trusted-base.md)) |
| Grey | Services outside the trusted base: they hold only their manifest |
| Orange | Untrusted: agents and everything a model writes |
| Dashed arrow | A process capability (spawn, `STOP`, `WAIT`), or a capability that only some service tables give, as its label says |

## 1. Layers

Each layer reaches the one below only through IPC endpoints it holds as capabilities, and all of user space reaches the kernel only through system calls.

```mermaid
flowchart TB
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef trusted fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef service fill:#eceff1,stroke:#607d8b,color:#1c262b
    classDef untrusted fill:#ffe5cc,stroke:#e65100,color:#4a1d00
    classDef outside fill:#ffffff,stroke:#9e9e9e,color:#424242,stroke-dasharray:4 3

    subgraph ring3["User space: ring 3, one address space per process"]
        direction TB
        agents["<b>Agents</b><br/>untrusted; one process<br/>per task attempt,<br/>one capability each"]:::untrusted
        runtime["<b>Agent runtime and policy</b><br/>lifecycle, permission grants,<br/>budgets, audit before acting"]:::trusted
        infer["<b>Inference service</b><br/>unprivileged; own no_std<br/>engine, CPU only,<br/>bounded memory"]:::service
        services["<b>System services</b><br/>init, store, audit, trust,<br/>knowledge, network,<br/>virtio drivers"]:::trusted
        agents -->|"requests only"| runtime
        runtime -->|"prompts in,<br/>tokens out as data"| infer
        runtime --> services
        infer -->|"model files, read-only"| services
    end

    subgraph ring0["Kernel: ring 0"]
        kernel["<b>Kernel</b><br/>privileged, minimal: memory,<br/>scheduling, interrupts,<br/>isolation, IPC, capabilities"]:::kernel
    end

    boot["<b>Boot</b><br/>UEFI or BIOS firmware, Limine"]:::outside
    host["<b>Host tooling</b><br/>outside the OS: pharos CLI,<br/>cargo xtask, QEMU harness"]:::outside

    ring3 ==>|"system calls:<br/>the privilege boundary"| ring0
    kernel ---|"loaded by"| boot
    boot ---|"built, booted, and<br/>inspected in QEMU by"| host

    style ring3 fill:transparent,stroke:#78909c,stroke-dasharray:6 4
    style ring0 fill:transparent,stroke:#1e3a5f,stroke-width:2px
```

Every arrow inside user space is IPC through an endpoint capability.

Details: [architecture overview](../project/architecture.md), decision [D-004](../project/decision-log.md#d-004-kernel-architecture-and-privilege-boundaries).

## 2. Processes and the capabilities they hold

This is the boot table (`pharos_services::tables::BOOT`). Every arrow is a kernel capability: `SEND` on another process's endpoint (labelled with its badge or store namespace), a device, or a process capability. A process can reach nothing it holds no arrow to. The capability audit (D-027) checks every running service against this table.

Not drawn, to keep the picture readable: every service except `virtio-blk` also holds the debug console and `SEND` on `init`'s report endpoint (ready, health, and events); `init` holds every boot capability and starts every process.

```mermaid
flowchart TB
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef trusted fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef service fill:#eceff1,stroke:#607d8b,color:#1c262b
    classDef untrusted fill:#ffe5cc,stroke:#e65100,color:#4a1d00
    classDef device fill:#fff8e1,stroke:#8d6e63,color:#3e2723
    classDef person fill:#ffffff,stroke:#2e7d32,color:#10301a

    user(["User"]):::person
    console[["virtio-console"]]:::device
    agent["<b>agent</b><br/>one per task attempt,<br/>at most 4 running"]:::untrusted
    trust["<b>trust</b><br/>trusted console:<br/>stop, revoke, approve"]:::trusted
    runtime["<b>agents</b><br/>agent runtime, 64 MiB"]:::trusted
    init["<b>init</b><br/>service manager,<br/>boot slots, updates"]:::trusted
    infer["<b>infer</b><br/>local inference, 1 GiB"]:::service
    knowledge["<b>knowledge</b><br/>entries with provenance"]:::service
    audit["<b>audit</b><br/>only writer of the trail"]:::trusted
    net["<b>net</b><br/>Ethernet, ARP, IPv4,<br/>ICMP, UDP"]:::service
    store["<b>store</b><br/>copy-on-write,<br/>SHA-256 chains"]:::trusted
    vblk["<b>virtio-blk</b><br/>one-shot driver"]:::service
    disk1[("disk 1: the store")]:::device
    disk0[("disk 0")]:::device
    nic[["virtio-net"]]:::device

    user <-->|"types and reads"| console
    console --- trust
    agent ==>|"SEND badged with its slot:<br/>its only capability"| runtime
    trust -.->|"STOP, WAIT on the runtime<br/>and on every agent"| runtime
    runtime -->|"badged as<br/>the runtime"| trust
    runtime -.->|"spawn, STOP,<br/>WAIT, GRANT"| agent
    trust -->|"report: services, system,<br/>update, apply, rollback"| init

    runtime -->|"client 1"| infer
    trust -->|"client 2"| knowledge
    trust -->|"client 2"| audit
    runtime -->|"client 3"| audit
    init -->|"client 1"| audit
    runtime -.->|"only if a policy entry<br/>needs it; none at boot"| net

    infer -->|"ns models,<br/>read-only"| store
    knowledge -->|"ns knowledge"| store
    audit -->|"ns audit"| store
    runtime -->|"ns agents"| store
    init -->|"ns system:<br/>slot record"| store

    store --- disk1
    vblk --- disk0
    net --- nic
```

`ns` is a store namespace: each client's badge names the one namespace it reaches, and whether it may write it. Green is the trusted base, grey a service outside it, orange untrusted.

What the picture shows:

- **An agent holds one capability for its whole life**, `SEND` on the runtime, badged with its slot. Everything it does is a runtime request, which the runtime checks against that slot's grants ([agents](agents.md#processes-and-what-each-holds)).
- **`trust` can stop the runtime and every agent without the runtime's help.** `init` gives it `STOP` on the runtime, and the runtime registers each agent with `trust` before answering any of its requests (D-018).
- **Only `audit` writes the audit trail** and only `knowledge` writes namespace `knowledge`; every other writer goes through them.
- **`infer` reads models and nothing else.** It reaches no agent, no network, and no file but `models`, read-only.
- **At boot the runtime's policy table is empty,** so no agent runs and the runtime gets no network, files, knowledge, or update capability. Test tables give it those to test them (dashed line).

Details: [services](services.md), [agents](agents.md), [storage](storage.md), [networking](networking.md), [inference](inference.md), [knowledge](knowledge.md).

## 3. Boot

The kernel mounts the factory image and starts `init`. `init` then picks the root image the other services run from: a signed A/B slot, or the factory image. The storage service and `trust` always come from the factory image, so a bad slot can break neither the code that falls back nor the trusted path. Every fallback happens in place, without a reboot.

```mermaid
flowchart TD
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef trusted fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef outside fill:#ffffff,stroke:#9e9e9e,color:#424242
    classDef fail fill:#ffebee,stroke:#c62828,color:#4a0d0d
    classDef ok fill:#e3f2fd,stroke:#1565c0,color:#0d2a4a

    fw["Firmware: UEFI (OVMF) or BIOS (SeaBIOS)"]:::outside
    limine["Limine: loads the kernel and the modules<br/>root and recovery, passes the command line"]:::outside
    kinit["Kernel: serial, memory map, page tables,<br/>interrupts, timer, scheduler"]:::kernel
    root{"root image<br/>passes its checks?"}
    copy{"recovery copy<br/>passes?"}
    halt["Boot stops:<br/>no root filesystem"]:::fail
    spawn["Kernel starts init with the table<br/>and the mode: normal, safe, or recovery"]:::kernel
    storesvc["init starts the store from the factory image,<br/>reads the slot record, takes its one-shot mode"]:::trusted
    isrec{"recovery mode?"}
    pick{"a candidate slot?<br/>active good or trying,<br/>then the other one"}
    attempt["Write the attempt to the record<br/>before using the slot"]:::trusted
    verify{"Ed25519 signature,<br/>SHA-256, and version<br/>check out?"}
    bad["Slot marked bad"]:::fail
    mount["fs_mount: the kernel copies<br/>and checks the image"]:::kernel
    start["Start the other services from the slot,<br/>trust from the factory image"]:::trusted
    ready{"every service ready<br/>within 20 s?"}
    stopsvc["Stop the slot's services,<br/>count the attempt"]:::fail
    good["Slot becomes good and active"]:::ok
    factory["Start the services from<br/>the factory image"]:::trusted
    fready{"ready?"}
    report["Report to the kernel:<br/>ready, failed, image, mode"]:::ok

    fw --> limine --> kinit --> root
    root -->|"yes"| spawn
    root -->|"no"| copy
    copy -->|"yes: recovery mode"| spawn
    copy -->|"no"| halt
    spawn --> storesvc --> isrec
    isrec -->|"no"| pick
    isrec -->|"yes: slots ignored"| factory
    pick -->|"yes"| attempt --> verify
    pick -->|"none left"| factory
    verify -->|"no"| bad --> pick
    verify -->|"yes"| mount --> start --> ready
    ready -->|"yes"| good --> report
    ready -->|"no"| stopsvc --> pick
    factory --> fready
    fready -->|"yes"| report
    fready -->|"no, in normal mode:<br/>again in recovery mode"| factory
```

- **Safe mode** (Limine entry, or `trust`'s `safe` for the next boot) starts every service but the agent runtime; **recovery** is safe mode on the factory image with the slots ignored.
- **An update** goes through the same path: `trust`'s `apply` makes `init` write the image to the slot that is not active and try it in place; if it is not ready, that slot becomes bad and the previous one runs again.
- The kernel waits up to 75 s for `init`'s report, enough for two slots and the factory image.

Details: [boot](boot.md), and [recovery and updates](boot.md#8-recovery-and-updates-m43-d-028).

## 4. An agent task, end to end

A task comes from a control client (the test kernels' tables list one; the boot table lists none). The runtime starts one agent process per attempt. Every consequential step is recorded in the audit trail **before** it is done, and refused with `NO_AUDIT` if it cannot be recorded.

```mermaid
sequenceDiagram
    autonumber
    participant C as Control client
    participant R as Agent runtime
    participant T as trust
    participant K as Kernel
    participant A as Agent
    participant I as infer
    participant AU as audit
    participant S as store

    C->>R: SUBMIT agent name, input
    R->>AU: INTENT submit
    AU->>S: append, SHA-256 chained
    R->>S: task record
    R->>AU: OUTCOME submit
    R-->>C: task ID

    Note over R,A: one process per attempt
    R->>K: spawn the agent's program,<br/>one capability, its page limit
    R->>AU: the attempt's grants
    R->>T: REGISTER slot, name, STOP and WAIT
    Note over R: answers the agent only after<br/>trust holds its STOP

    A->>R: TASK
    R-->>A: input and last checkpoint,<br/>copied into its buffer

    A->>R: INFER model n, prompt in its buffer
    Note over R: model n granted? budget left?
    R->>AU: INTENT inference
    R->>I: prompt, copied into<br/>the runtime's own buffer
    loop until done
        A->>R: NEXT
        R->>I: NEXT
        I-->>R: tokens
        R-->>A: tokens, as data only
    end
    R->>AU: OUTCOME inference

    A->>R: CHECKPOINT
    R->>S: commit
    R-->>A: OK once committed

    A->>R: COMPLETE result
    R->>S: task done, with its result
    R->>K: process_stop the agent
```

- **A crash or a hang** (no request for `progress_ms`) ends the attempt; the runtime starts a new one with the last checkpoint, up to the entry's attempts, then fails the task.
- **The runtime never interprets model output.** Tokens reach the agent as data; anything a model makes the agent ask for is one more request through the same checks.
- **Budgets** (CPU, pages, tokens, datagrams, requests, file bytes) are checked on each request, per attempt and per group ([resources](resources.md)).

Details: [agents](agents.md#lifecycle-98), [the runtime's interface](agents.md#the-runtimes-interface-agents-version-1), [durable tasks](agents.md#durable-tasks-99).

## 5. A sensitive tool call

`send` is the one sensitive tool: each call needs the user's yes on the trusted console. The runtime never waits; the agent polls with the same call. `trust` writes the prompt from structured fields, so no agent or model text reaches the user's screen.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant T as trust
    participant R as Agent runtime
    participant A as Agent
    participant AU as audit
    participant N as net

    A->>R: TOOL send, the call's text in its buffer
    Note over R: copy the call out, parse the strict JSON subset,<br/>validate it against the schema, then check:<br/>tool listed? net grant for the destination? budgets?
    alt malformed, not listed, no grant, or over budget
        R-->>A: BAD_REQUEST, NO_ACCESS, or OVER_LIMIT
    else checks pass
        R->>T: CONFIRM request n, agent, task,<br/>destination, byte count
        R-->>A: PENDING
        T->>U: confirm #n: worker task 12 wants to send<br/>37 bytes to 10.0.2.2:47000? (yes n / no n)
        U->>T: yes n
        T->>AU: the user's answer
        T->>R: ANSWER, non-blocking send
        A->>R: TOOL send, the same call again
        R->>AU: INTENT tool send, never the payload
        alt the trail cannot record it
            R-->>A: NO_AUDIT, nothing sent
        else recorded
            R->>N: one UDP datagram
            R->>AU: OUTCOME
            R-->>A: OK
        end
    end
    Note over U,R: no, no answer in 60 s, a full queue, or trust<br/>unreachable mean REFUSED. Revoking the destination<br/>while it waits means NO_ACCESS. A yes runs that<br/>one call once.
```

The network leg exists only in test tables today: the boot table gives the runtime no network capability (section 2).

Details: [tools](tools.md), [approval on the trusted path](capabilities.md#approval-on-the-trusted-path-106).

## 6. Where authority comes from, and how it is taken away

Pharos has two kinds of authority. **Kernel capabilities** are held by processes and checked by the kernel on every system call. **Permissions** are grants the runtime keeps for each task attempt and checks on every request; an agent never holds them as capabilities.

```mermaid
flowchart LR
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef trusted fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef service fill:#eceff1,stroke:#607d8b,color:#1c262b
    classDef untrusted fill:#ffe5cc,stroke:#e65100,color:#4a1d00
    classDef person fill:#ffffff,stroke:#2e7d32,color:#10301a

    subgraph caps["Kernel capabilities: held by processes, checked by the kernel"]
        direction TB
        k["Kernel"]:::kernel
        i["<b>init</b><br/>every boot capability,<br/>MOUNT on the root"]:::trusted
        s["<b>Each service</b><br/>exactly its manifest,<br/>checked by the capability audit"]:::service
        rt["<b>Agent runtime</b><br/>its manifest, and GRANT<br/>on its own endpoint"]:::trusted
        ag["<b>Agent</b><br/>one badged SEND<br/>on the runtime"]:::untrusted
        k -->|"at boot"| i
        i -->|"spawn: rights only narrow,<br/>a badge is set once"| s
        i -->|"spawn"| rt
        rt -->|"spawn"| ag
    end

    subgraph perms["Permissions: kept by the runtime, per task attempt"]
        direction TB
        entry["<b>Policy entry</b><br/>what the agent gets,<br/>and what it may ask for"]:::trusted
        man["<b>Agent manifest</b><br/>may ask for less,<br/>never more"]:::untrusted
        approve(["<b>User's yes on trust</b><br/>to an ASK for an<br/>askable permission"]):::person
        deleg["<b>Delegation</b><br/>up to 4 of a<br/>supervisor's permissions"]:::trusted
        grants["<b>The attempt's grants</b><br/>model, data, net, file,<br/>channel, knowledge,<br/>update propose"]:::trusted
        entry --> grants
        man -->|"narrows"| grants
        approve --> grants
        deleg --> grants
    end

    ag ==>|"every request is<br/>checked against"| grants

    style caps fill:transparent,stroke:#1e3a5f,stroke-dasharray:6 4
    style perms fill:transparent,stroke:#2e7d32,stroke-dasharray:6 4
```

Authority is taken away in five ways, none of which needs the agent's help:

| How | Who | What it reaches |
| --- | --- | --- |
| `revoke <agent> <permission>` | the user, on `trust` | that permission, from every task of the agent that has not ended: a running attempt at once, a waiting one at its next start; inference sessions and network flows opened with it end, and a waiting confirmation ends with `NO_ACCESS` |
| Expiry | the runtime | a grant past its deadline, checked on every use, as if revoked |
| `stop <agent>`, `stop group <group>` | the user, on `trust` | `process_stop` on the agent's processes, done by `trust` itself, without the runtime |
| `stop all` | the user, on `trust` | the runtime, and with it every agent; `init` restarts nothing that was stopped until the next boot |
| Kernel `revoke` of memory or a device | the holder of the original capability (for example `init`, taking a device from a driver) | every mapping made through it or a capability derived from it, in every process, before `revoke` returns; the pages become private zeroed memory |

- **Rights only narrow** as a capability is passed on, and a badge, once set, cannot be changed, so a service can tell its clients apart and no client can pose as another.
- **Nothing is remembered across tasks:** an attempt's grants are rebuilt from the policy entry, the manifest, and the task's own approvals.
- **Stopping a process stops every process it started,** depth first, so no work outlives its supervisor.

Details: [capabilities](capabilities.md), [coordination](coordination.md#delegation-135), [system calls and IPC](syscalls-ipc.md), decision [D-012](../project/decision-log.md#d-012-agent-sandboxing-tool-permissions-and-network-isolation).

## 7. Trust zones

Who must be correct for the system's guarantees to hold, and what is checked where untrusted data crosses into trusted code.

```mermaid
flowchart LR
    classDef kernel fill:#1e3a5f,stroke:#0f1f33,color:#ffffff
    classDef trusted fill:#d8f0dc,stroke:#2e7d32,color:#10301a
    classDef service fill:#eceff1,stroke:#607d8b,color:#1c262b
    classDef untrusted fill:#ffe5cc,stroke:#e65100,color:#4a1d00

    subgraph U["Untrusted"]
        direction TB
        u1["Agents"]:::untrusted
        u2["Model output"]:::untrusted
        u4["Granted file contents"]:::untrusted
        u3["Model files"]:::untrusted
        u5["Network peers"]:::untrusted
        u6["Slot and incoming images,<br/>until verified"]:::untrusted
    end

    subgraph C["Contained: hold only their manifest"]
        direction TB
        c1["infer"]:::service
        c2["net"]:::service
        c3["knowledge, virtio-blk"]:::service
    end

    subgraph T["Trusted base, reviewed in M5.4"]
        direction TB
        t1["Agent runtime:<br/>enforces agent policy"]:::trusted
        t2["trust:<br/>the user's console"]:::trusted
        t3["init, store, audit"]:::trusted
        t4["Kernel, Limine, firmware"]:::kernel
    end

    u1 -->|"copied out, parsed, checked<br/>against its grants, audited<br/>before acting"| t1
    u2 -->|"data only, never commands"| t1
    u4 -->|"passed to the agent as data;<br/>the runtime never reads it"| t1
    u3 -->|"SHA-256, size, and shape<br/>against a compiled table"| c1
    u5 -->|"default deny,<br/>per destination"| c2
    u6 -->|"Ed25519, SHA-256,<br/>version floor"| t3
    C -->|"only through the<br/>capabilities they hold"| T
    t1 -->|"structured fields only;<br/>trust writes the text"| t2
    t3 -->|"system calls: decoded,<br/>rights checked"| t4

    style U fill:transparent,stroke:#e65100,stroke-dasharray:6 4
    style C fill:transparent,stroke:#607d8b,stroke-dasharray:6 4
    style T fill:transparent,stroke:#2e7d32,stroke-width:2px
```

- **The agent runtime is in the trusted base for agent policy,** since it holds and checks every agent's permissions, and it is also tested as compromised: the `compromised` test kernel runs a hostile program under the runtime's exact manifest and checks that it can do nothing beyond it (86 probes, all refused), and the same for `infer` (83).
- **A model's output is untrusted input everywhere.** A prompt injection can make an agent ask for anything, but only through requests the runtime checks against permissions the user or a policy granted.

Details: [threat model](../security/threat-model.md), [M5.4 review](../security/review-m5.4-trusted-base.md), [the hostile services](services.md#ai-services-m46-d-031).
