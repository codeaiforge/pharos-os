# Glossary

| Term | Meaning in Pharos OS |
| --- | --- |
| **Agent** | A program, usually driven by an AI model, that performs tasks for the user. Always untrusted; runs with only the capabilities granted to it. |
| **Agent runtime** | Planned user-space component that starts, stops, supervises, and limits agents and enforces their permissions. |
| **Audit log** | A tamper-evident record of capability grants, revocations, and sensitive agent actions. Planned. |
| **BIOS / UEFI** | Firmware interfaces that start the machine and hand control to a bootloader. Which ones Pharos supports is an open decision. |
| **Boot protocol** | The contract between bootloader and kernel: entry state, memory map, and boot information. Open decision. |
| **Capability** | An unforgeable, explicit right to use a specific resource (file, device, IPC endpoint, network destination, tool). |
| **Decision record** | An entry in the decision log describing a choice, its options, and its rationale. |
| **Host** | The developer machine (initially Linux Mint, x86-64) where code is built and QEMU runs. |
| **Implemented / placeholder / planned** | Status labels. *Implemented*: exists and is tested. *Placeholder*: reserves a location but has no real function. *Planned*: described in the roadmap; not built. |
| **Inference** | Running a trained model to produce output. Planned to run locally in an unprivileged service. |
| **Inference runtime** | The software that loads and executes models. Not yet chosen. |
| **IPC** | Inter-process communication: how isolated components exchange messages. |
| **Kernel** | The privileged core of the OS. In this repository, currently only a host-side placeholder crate. |
| **Least privilege** | Each component receives only the access it needs for its task. |
| **Milestone gate** | The checks that must pass before work on the next milestone begins. |
| **Model output** | Text or data produced by a model. Treated as untrusted input. |
| **QEMU** | An open-source machine emulator used to boot and test the kernel without real hardware. |
| **Sandbox** | An isolation boundary that limits what an agent or service can access. |
| **Serial console** | An emulated serial port (COM1) used for early kernel output and test results. |
| **System call (syscall)** | The interface user-space code uses to request kernel services. |
| **Target** | The platform code is compiled for. The host target today; a bare-metal x86-64 target for the kernel later. |
| **Tool (agent tool)** | A defined operation an agent may invoke, such as reading a file, only if it holds the matching capability. |
| **Trusted computing base (TCB)** | All code that must be correct for the system's security to hold. Kept as small as possible. |
