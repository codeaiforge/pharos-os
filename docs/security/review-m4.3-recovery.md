# Security review: M4.3 reliable boot and recovery

- **Scope:** everything M4.3 added since commit `62b81ba` (the M4.2 gate):
  - D-028 and the design, [boot.md section 8](../architecture/boot.md#8-recovery-and-updates-m43-d-028) (#160, #161);
  - `crates/pharos-image`: the signed image format, `verify`, and the slot record (`slots`) (#162, #163);
  - the kernel call `fs_mount` and the `MOUNT` right, `fs::Copy`, the boot mode from the command line, and the `recovery` module (#163, #164);
  - `init`'s slot selection, fallback in place, safe mode and recovery, and its update requests (`UPDATE`, `ANSWER`, `ROLLBACK`, `NEXT`) (#163–#165);
  - `trust`'s `system`, `safe`, `recovery`, `update`, `apply`, `discard`, and `rollback` (#164, #165);
  - the runtime's `PROPOSE` and store namespace 9, `system/incoming` (#165);
  - the Secure Boot evaluation (#166) and every new `unsafe` block.
- **Design under review:** [boot.md](../architecture/boot.md), D-028, D-018, D-022, D-027, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-07, issue #167. Reviewer: AI-assisted (Claude Code), from reading the code. No finding is fixed; five are recorded.
- **Status:** **awaiting the maintainer's approval** (M4.3 gate, #167).

## Method

1. Listed every changed file since `62b81ba` and searched the diff for new `unsafe` blocks: none in Pharos code. The one new dependency, `ed25519-compact` 2.6.0, has one (a volatile wipe of key memory), reviewed in #162.
2. Followed each way an image can come to run: the boot medium (`root`, then `recovery`), a slot (`init`'s check, then `fs_mount`), and an update (incoming file, offer, `apply`, stage, try).
3. Followed each way a request can reach `init`'s update handlers, and each capability that can reach `system`, `system/incoming`, or `MOUNT`.
4. Checked each acceptance criterion of M4.3 against a test that runs in CI.
5. Checked what each in-place switch (fallback, apply, rollback) costs and gives back.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | **`fs_mount`'s charge is kept until `init` ends.** The copy's pages are charged to the caller (`syscall.rs`, `fs_mount`) and given back only when the mount fails. Deleting the mounted filesystem frees the frames but not the charge. Every in-place switch (fallback, `apply`, `rollback`) mounts one more image, so `init`'s 3 GiB limit, about 950 MiB of it not given to services, shrinks by one image each time until the next boot. Once it runs out, `fs_mount` answers `NO_MEMORY`, `init` reports `not mounted`, and marks a slot that verified correctly `bad`. With a 4 MiB image this takes about 200 switches in one boot, and each `apply` needs a new signed image. The design says the charge lasts "until it ends" (as for `mem_share`'s frame list), but that was written for a few mounts per boot. | **Recorded.** Fix later: give the charge back when the copy is freed, or do not mark a slot `bad` for `NO_MEMORY` (only for `BAD_IMAGE`). |
| F2 | Low | **The version floor counts only `good` slots.** `Record::min_version` is 0 when no slot is `good`: on a new system, after a corrupt record is rewritten empty, or with both slots `bad`. An older signed release can then be offered and installed. It still needs the signature and `apply <n>` on the trusted console. The factory image has no version in the record. | **Recorded:** D-028's rule as accepted ("higher than every slot's that is `good`"). Counting `bad` slots, or building a floor into the factory `init`, is a design change for the maintainer. |
| F3 | Low | **The bytes checked are not the bytes mounted.** `Slots::check` copies the slot file to `init`'s heap and verifies the copy; `fs_mount` then copies from the shared buffer, which the storage service also maps. Between the check and the mount, only the storage service could change it. | **Recorded:** documented in boot.md (#163). The storage service always comes from the factory image and writes to the buffer only when `init` asks. |
| F4 | Low | **Agent proposals can fill `incoming`.** An agent with `update propose` may fill all 4 places (the runtime counts every file, the host's too). `update` shows only the first 4 names, so a file the host stages after that is not shown until the user discards one. | **Recorded:** no boot-table entry may propose (M4.2 narrowing, handle 12 not given); the user sees and can discard each proposal, and nothing is applied without `apply <n>`. |
| F5 | Low (test) | **Two rows of boot.md's test table are not QEMU tests.** No test kernel runs an agent's `PROPOSE` through to `init` and shows that it stays unapplied. No test runs a malfunctioning agent during a fallback or recovery. | **Recorded,** covered in parts instead (next section): only `trust`'s badge reaches `ANSWER`; the `tools` kernel shows a proposal writes nothing outside `system/incoming`; `hostile` and `exhaustion` show `stop all` with a hostile agent; the `never-ready` and `failing` rounds show fallback when the agent runtime never becomes ready; the capability audit (D-027) shows the runtime holds nothing on `init`, `system`, or `MOUNT`. |

Accepted limit, unchanged (boot.md "Security"): the slot record is not authenticated. Whoever holds the disk can erase the slots or rewrite the record. Fixing that needs a device secret (M5.5).

## Who can change what runs

- **Only `init` holds `MOUNT`.** The kernel puts it on `init`'s root capability only (`process::init_capabilities`). `fs_mount` gives a new filesystem `READ | GRANT`, never `MOUNT`. Every `Give(Root, …)` in `pharos-services` must be `READ`, both by a host rule and in the live audit (D-027).
- **Only `trust` reaches the update handlers.** `init` answers `SYSTEM`, `NEXT`, `UPDATE`, `ANSWER`, and `ROLLBACK` only on the kernel-set badge of its `bin/trust` table entry. The table is compiled into the factory `init`, and `trust`'s program comes from the factory image. `trust` sends `ANSWER` only for `apply <n>` or `discard <n>` typed on the trusted console. Those numbers are `init`'s and never reach the runtime (`yes`/`no` answer the runtime).
- **`apply` applies only the image offered.** `init` checks the file again and compares its SHA-256 with the offer's (`changed since it was offered`). Before mounting a slot it checks the slot file again against the record's SHA-256 (`not the image the record names`). Offers expire after 60 s, and a new `update` forgets earlier ones.
- **One switch at a time:** while `init` boots, applies, or rolls back, its slot client is taken. The requests `UPDATE`, `ANSWER`, and `ROLLBACK` then get `BUSY`. `NEXT` cannot be written and answers `INTERNAL`.
- **An agent can only add a file.** Namespace 9 is the prefix `system/incoming`; `pharos_fs::valid_path` refuses `.` and `..`, so a path cannot leave it. The runtime writes only `<agent>-<n>`, at the first free `n`, after checking `update propose` and auditing. Data files are at most 64 KiB, so a proposal cannot be a real system image yet.
- **Recovery needs no slot and no agent.** `init`, the storage service, and `trust` always come from the factory image. The kernel mounts `recovery` if `root` fails its checks. Safe mode and recovery do not start the agent runtime.

## Acceptance criteria

| Criterion | Shown by (in CI) |
| --- | --- |
| A corrupted system image leads to recovery, not an unbootable system | `recovery` rounds: a corrupted and an unsigned slot refused, the other slot or the factory image runs; a corrupt `root` module boots the `recovery` copy; a factory image not ready restarts in recovery |
| A rejected or failing update is rolled back | `update` rounds `failing` (slot B not ready, `bad`, slot A runs in place) and `rollback`; the last boot refuses an old, a forged, and a bad slot's image |
| An agent's proposed update cannot be applied without approval | Only `trust`'s badge reaches `ANSWER`; `tools` kernel (`PROPOSE` refused without the permission, at most 4, nothing outside `system/incoming`); F5 |
| A malfunctioning agent cannot disable recovery or the emergency stop | `hostile` and `exhaustion` (`stop all`); `never-ready` and `failing` (a runtime that never becomes ready falls back); the capability audit; F5 |

## Kernel

New: `fs_mount` (call 27), the right `MOUNT`, the error `BAD_IMAGE`, `fs::Copy` (at most 2 at once), the command-line mode (`boot_info::boot_mode`), and the Limine executable command line request (in `limine.rs`, already allowed `unsafe`). No new `unsafe` block. The copy reads its source through the existing safe `read_user`, in an address space no process runs in. `fs_mount` checks `offset + len` against the memory's frames after the decoder refused wrapping ranges. The `fsmount` kernel shows the frames and the copy count return to zero once the caller ends.

## Measured

The IPC round trip: 1,978 ns median (1,897–2,004 ns over 5 runs of 100,000, KVM), then 1,922 ns (1,818–1,998 ns) on a second try, within D-004's 2 µs budget (M4.2: 1,850 ns). M4.3 changed no IPC, scheduler, or `arch` code, so the rise is taken as noise on the host. One run of the first try was over 2 µs, so the margin is small.
