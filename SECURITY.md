# Security Policy

## Status of this software

Pharos OS is **experimental software in early development**. The kernel boots only in QEMU, and the project provides no security guarantees. Do not use it in production or for any security-critical purpose, and do not boot it on real hardware.

## Supported versions

Only the latest release and the latest state of the `main` branch receive fixes. Older releases are not patched.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues, pull requests, or discussions.**

Report vulnerabilities privately through GitHub's private vulnerability reporting:

- Open <https://github.com/codeaiforge/pharos-os/security/advisories/new>, or
- go to the repository's **Security** tab and choose **Report a vulnerability**.

This requires a GitHub account. The report is visible only to you and the repository maintainers.

Please include:

- the affected component (file, crate, command, or document) and version or commit;
- steps to reproduce, and the impact you expect;
- any suggested fix or mitigation.

Never include real credentials, tokens, or private keys in a report.

## What to expect

Because the project is early stage, there is no committed response time. Reports will be handled in good faith, discussed privately in the advisory, fixed where valid, and credited if you wish once a fix is public.

## Scope

In scope: everything in this repository and its releases:
- the kernel (`kernel/`);
- the user-space library and programs (`user/`), including `init`, the trusted console (`trust`), the agent runtime, and the inference, storage, audit, and network services;
- the host crates and tools (`crates/`, the `pharos` CLI, `cargo xtask`), including image signing and verification;
- the CI workflows, and the documentation (for example, unsafe instructions).

The [threat model](docs/security/threat-model.md) says what each part is meant to withstand. Examples of what to report:
- an agent or service reaching a file, process, device, network, or model without a capability granted to it;
- a user program, driver, or device corrupting kernel memory or another process's memory;
- an update image that boots without a valid signature, or an older image that boots in place of a newer one;
- a way to stop, hide from, or forge the trusted console or the audit trail;
- safe Rust in `pharos-user` that reaches undefined behaviour.

Also report a leaked release signing key the same way.

Not vulnerabilities, unless a report shows impact beyond what is documented:
- limits the threat model records as known (for example, no IOMMU and no KPTI yet);
- anything that needs real hardware, which is not supported;
- a model producing unwanted text without crossing a capability boundary;
- the test signing key that `cargo xtask` generates under `target/xtask/keys/`, which is not a secret.
