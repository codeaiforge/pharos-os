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
- **Date:** 2026-11-07, issue #167. Reviewer: AI-assisted (Claude Code), from reading the code. All five findings are fixed (2026-11-08), each with a test except F3 (below).
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
| F1 | Low | **`fs_mount`'s charge was kept until `init` ended.** The copy's pages were charged to the caller and given back only when the mount failed; deleting the mounted filesystem freed the frames but not the charge. Each in-place switch (fallback, `apply`, `rollback`) used up one image's worth of `init`'s 3 GiB limit (about 950 MiB not given to services) until the next boot. Once that ran out, `fs_mount` answered `NO_MEMORY` and `init` marked a slot that verified correctly `bad`: about 200 switches in one boot with a 4 MiB image. | **Fixed:** the copy holds a `process::Charge`, which gives its pages back when the copy is freed, whoever drops it, through an atomic counter (no lock). `mountprobe` mounts and deletes 20 more times within its 64-page limit; with the charge kept, that step fails. Host test `a_mount_charge_is_given_back_when_dropped`. |
| F2 | Low | **The version floor counted only `good` slots.** `Record::min_version` was 0 when no slot was `good`: on a new system, or with both slots `bad`. An older signed release could then be offered and installed, with the signature and `apply <n>`. | **Fixed:** the floor is above every version a slot records (`bad`, `trying`, `staged` too) and above the factory image's version, built into `init` (`PHAROS_IMAGE_VERSION`, 0 without it). `pharos_programs::system::admit` checks a bad slot's image first, then the floor, so each refusal keeps its own reason. D-028 is amended (stricter). Host tests in `pharos_image::slots` and `pharos_programs::system`. A corrupt record rewritten empty still loses the slots' versions: the accepted limit below. |
| F3 | Low | **The bytes checked were not the bytes mounted.** `init` verified a heap copy of the slot file, then `fs_mount` copied from the shared buffer, which the storage service still mapped. | **Fixed:** after reading a file to check it, `init` revokes the store's capability on the buffer. The kernel ends the store's mapping before `revoke` returns. `init` attaches the buffer again only at the next request that needs it, so between the check and the mount or the slot write only `init` can change the bytes. The kernel side (a revoked mapping reads zeros) is tested by `shared_memory`; the `recovery` and `update` rounds show the flow still works. No test plays a hostile storage service, so no test fails without this fix. |
| F4 | Low | **Agent proposals could fill `incoming`.** An agent with `update propose` could fill all 4 places `update` looks at, hiding a file the host staged after that. | **Fixed:** agents may fill 3 (`MAX_PROPOSED`); a fourth `PROPOSE` is `OVER_LIMIT`, so one place stays for the host. The `tools` kernel checks 3 proposals stored and the fourth refused. |
| F5 | Low (test) | **Two rows of boot.md's test table were not QEMU tests:** an agent's proposal through `init`, and a malfunctioning agent during a fallback. | **Fixed:** the `update` kernel's last boot offers an image named as an agent's proposal (`proposer-1`); the runtime's `yes 1` gets `no request #1`, and `system` still shows slot A. The `recovery` kernel's new `spinning` round runs slot A with an agent runtime (`spinner`) that spins forever: `init` stops it on its 20 s deadline and slot B runs in place. `stop all` with a hostile agent stays covered by `hostile` and `exhaustion`. |

Accepted limit, unchanged (boot.md "Security"): the slot record is not authenticated. Whoever holds the disk can erase the slots or rewrite the record. Fixing that needs a device secret (M5.5).

## Who can change what runs

- **Only `init` holds `MOUNT`.** The kernel puts it on `init`'s root capability only (`process::init_capabilities`). `fs_mount` gives a new filesystem `READ | GRANT`, never `MOUNT`. Every `Give(Root, …)` in `pharos-services` must be `READ`, both by a host rule and in the live audit (D-027).
- **Only `trust` reaches the update handlers.** `init` answers `SYSTEM`, `NEXT`, `UPDATE`, `ANSWER`, and `ROLLBACK` only on the kernel-set badge of its `bin/trust` table entry. The table is compiled into the factory `init`, and `trust`'s program comes from the factory image. `trust` sends `ANSWER` only for `apply <n>` or `discard <n>` typed on the trusted console. Those numbers are `init`'s and never reach the runtime (`yes`/`no` answer the runtime).
- **`apply` applies only the image offered.** `init` checks the file again and compares its SHA-256 with the offer's (`changed since it was offered`). Before mounting a slot it checks the slot file again against the record's SHA-256 (`not the image the record names`). Offers expire after 60 s, and a new `update` forgets earlier ones.
- **One switch at a time:** while `init` boots, applies, or rolls back, its slot client is taken. The requests `UPDATE`, `ANSWER`, and `ROLLBACK` then get `BUSY`. `NEXT` cannot be written and answers `INTERNAL`.
- **An agent can only add a file.** Namespace 9 is the prefix `system/incoming`; `pharos_fs::valid_path` refuses `.` and `..`, so a path cannot leave it. The runtime writes only `<agent>-<n>`, at the first free `n`, after checking `update propose` and auditing, at most 3 waiting (F4). Data files are at most 64 KiB, so a proposal cannot be a real system image yet.
- **Recovery needs no slot and no agent.** `init`, the storage service, and `trust` always come from the factory image. The kernel mounts `recovery` if `root` fails its checks. Safe mode and recovery do not start the agent runtime.

## Acceptance criteria

| Criterion | Shown by (in CI) |
| --- | --- |
| A corrupted system image leads to recovery, not an unbootable system | `recovery` rounds: a corrupted and an unsigned slot refused, the other slot or the factory image runs; a corrupt `root` module boots the `recovery` copy; a factory image not ready restarts in recovery |
| A rejected or failing update is rolled back | `update` rounds `failing` (slot B not ready, `bad`, slot A runs in place) and `rollback`; the last boot refuses an old, a forged, and a bad slot's image |
| An agent's proposed update cannot be applied without approval | Only `trust`'s badge reaches `ANSWER`; `tools` kernel (`PROPOSE` refused without the permission, at most 3, nothing outside `system/incoming`); `update`'s last boot (a proposal not applied by the runtime's `yes 1`, F5) |
| A malfunctioning agent cannot disable recovery or the emergency stop | `hostile` and `exhaustion` (`stop all`); `never-ready`, `spinning`, and `failing` (a runtime that exits, spins forever, or never becomes ready falls back, F5); the capability audit |

## Kernel

New: `fs_mount` (call 27), the right `MOUNT`, the error `BAD_IMAGE`, `fs::Copy` (at most 2 at once), the command-line mode (`boot_info::boot_mode`), and the Limine executable command line request (in `limine.rs`, already allowed `unsafe`). No new `unsafe` block. The copy reads its source through the existing safe `read_user`, in an address space no process runs in. `fs_mount` checks `offset + len` against the memory's frames after the decoder refused wrapping ranges. The `fsmount` kernel shows the frames and the copy count return to zero once the caller ends. The fix for F1 adds `process::Charge` (safe code, an `Arc<AtomicU64>` per process): a copy's pages count against its caller's limit until the copy is freed.

## Measured

The IPC round trip: 1,978 ns median (1,897–2,004 ns over 5 runs of 100,000, KVM), then 1,922 ns (1,818–1,998 ns) on a second try, within D-004's 2 µs budget (M4.2: 1,850 ns). M4.3 changed no IPC, scheduler, or `arch` code, so the rise is taken as noise on the host. One run of the first try was over 2 µs, so the margin is small.
