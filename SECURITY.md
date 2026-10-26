# Security Policy

## Status of this software

Pharos OS is **experimental software in early development**. It is not a bootable operating system and provides no security guarantees. Do not use it in production or for any security-critical purpose.

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

In scope today: the Rust workspace, the `pharos` CLI, the CI workflow, and the documentation (for example, unsafe instructions). The threat model for the planned system is in [docs/security/threat-model.md](docs/security/threat-model.md).
