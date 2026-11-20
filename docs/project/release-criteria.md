# Release criteria

## Status

**Written** for v0.5, the microVM release (M5.5, #260). They apply from v0.5 on, and the maintainer changes them only through review. The gate issue (#261 for v0.5) records the evidence for each one; a release is made only when all are met and the maintainer approves.

## Criteria

All on **the release commit**: the commit the tag will name, with the workspace version already bumped. A run on an earlier commit does not count.

| # | Criterion | How it is checked | Evidence recorded at the gate |
| --- | --- | --- | --- |
| 1 | The push checks pass | CI's `CI` workflow on the commit: `check`, the minimum-version job, and the four `qemu` shares (the boot checks and every test kernel) | the run's link |
| 2 | The release matrix passes | `matrix.yml` dispatched on the commit with every cell and `stability: yes`: the 8 cells, the repeat pass, the 60-minute soak, and S1 ([testing.md](../development/testing.md#release-test-matrix-m51-d-032)) | the run's link; any failure not shown to be infrastructure gets a `bug` issue and fails the criterion |
| 3 | The 8-hour soak passes | `cargo xtask soak --minutes 480` on the reference platform (D-032, amended) | its summary line: cycles, tasks, audit records, free frames first and last |
| 4 | S1 passes with the real model | `cargo xtask s1` and `cargo xtask bench-infer --runs 3` under KVM, with `PHAROS_MODEL` | the result, and first token and tokens/s against S1's targets |
| 5 | Two independent builds are bit-identical | CI's reproducible-release step (two builds in one job), and the maintainer's local `cargo xtask release` from the same commit: the three `SHA256SUMS` are equal ([release-integrity.md](../architecture/release-integrity.md#6-signed-release-artifacts-259)) | both `SHA256SUMS`, with the boot measurement |
| 6 | A rewritten trail is rejected | the host test `signed_heads_reject_a_trail_rewritten_from_the_disk` and the `audit` and `rotate` test kernels pass; a throwaway branch on which the verifier skips the signature check fails CI | the throwaway branch's failing run |
| 7 | Secure Boot is enforced | the Secure Boot boot checks: the signed image boots, and a changed kernel, module, or `limine.conf` does not; a throwaway branch that leaves out the path hashes fails CI (#258) | the runs' links |
| 8 | No open critical or high security finding | every security review's findings are fixed or rated below high by the maintainer, and no open issue is rated critical or high | the list of open findings with their ratings |
| 9 | The documents match the code | the status labels (**implemented**, **planned**) in the docs the release touches; the threat model updated at the phase gate; `CHANGELOG.md` has the release's section; the [user guide](../user/microvm.md) runs as written on the release's files | the gate's check of each |
| 10 | The release is signed | `cargo xtask release sign` with the maintainer's offline release key; its public key in `RELEASE-KEY` at the repository root; `cargo xtask release verify <DIR> --key RELEASE-KEY` passes | the public key and `SHA256SUMS.sig` |
| 11 | The maintainer approves | the maintainer's comment on the gate issue | the comment |

## Not release criteria

- Real hardware, and VMMs other than QEMU with KVM: untested (M8.1).
- Performance beyond S1's targets.
- A test on a host other than the reference platform's.

## How a criterion changes

A criterion is removed or weakened only in a reviewed change to this file, with its reason in the decision log. A release that misses one is not made: the gate stays open until the criterion is met or changed that way. (D-032's amendment, which let the M5.1 gate record a 2-hour soak, is the precedent: the 8-hour soak stayed a release criterion.)
