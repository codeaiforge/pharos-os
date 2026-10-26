# Security Policy

## Status of this software

Pharos OS is **experimental software in early development**. It is not a bootable operating system and provides no security guarantees. Do not use it in production or for any security-critical purpose.

## Supported versions

There are no released versions. Only the latest state of the main development line receives fixes.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues, pull requests, or discussions.**

No dedicated security contact address or reporting channel has been established yet. Until one is published in this file:

1. If the repository is hosted on a platform with private vulnerability reporting (for example, GitHub security advisories) and the maintainers have enabled it, use that feature.
2. Otherwise, contact the CodeAIForge maintainers privately through a channel you already have with them, and ask for a private way to share details. Do not include exploit details in a first contact made through any public channel.

Please include:

- the affected component (file, crate, command, or document);
- steps to reproduce, and the impact you expect;
- any suggested fix or mitigation.

Never include real credentials, tokens, or private keys in a report.

## What to expect

Because the project is early stage, there is no committed response time. Reports will be handled in good faith, fixed where valid, and credited if you wish once a fix is public.

## Scope

In scope today: the Rust workspace, the `pharos` CLI, the CI workflow, and the documentation (for example, unsafe instructions). The threat model for the planned system is in [docs/security/threat-model.md](docs/security/threat-model.md).
