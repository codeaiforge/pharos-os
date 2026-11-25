# Security review: M6.3 foreign-agent bridge (Tier 3)

- **Scope:** the new trust boundary between a Linux guest VM and Pharos ([bridge.md](../architecture/bridge.md), D-036):
  - the bridge service (`user/programs/src/bin/bridge.rs`) and its frames (`pharos_proto::bridge`);
  - the virtio-console driver with its buffer sizes as parameters (`user/programs/src/virtio_console.rs`);
  - the runtime's guest slots: `BIND`, `STOP_GUEST`, each attempt's minted capability, and the `bind` and `unbind` records (`agents.rs`, and `agents.rs`, `manifest.rs`, and `audit.rs` in `pharos-proto`);
  - `trust`'s guest agents;
  - the `derive` system call (35);
  - `init`'s bridge entry and table 12;
  - the launch tool (`xtask/src/bridge.rs`): both command lines, the allow-list, and the QMP checks;
  - the guest image builder, its lock, and the guest's client library and agent.

  Alpine, Python, LangGraph, and QEMU themselves are out of scope; how Pharos uses them is in scope.
- **Design under review:** bridge.md, the threat model's "Foreign-agent bridge (M6.3)" rows, D-036, and AGENTS.md sections 5 and 7. D-036 trusts the host kernel and QEMU in M6.3.
- **Threat model:** three attackers, each alone:
  - a malicious guest: root in the guest VM, writing any bytes to its port at any time and rate;
  - a compromised bridge process;
  - a confused or malicious agent or control client calling `BIND`, `STOP_GUEST`, or `derive`.

  An attacker wins in any of these cases:
  - the guest reaches the network, a disk, a host file, another guest, or any Pharos service but the runtime;
  - the guest acts beyond its grants and budgets, or without a record;
  - a guest's action is attributed to another agent, task, or attempt;
  - a capability from one attempt works in another, or after its attempt ends;
  - `derive` widens a capability;
  - the bridge or the runtime crashes, hangs, or is held by the guest;
  - the guest reaches the firmware or a console through the channel;
  - the launch tool starts a guest with a network device, disk, shared filesystem, or second channel;
  - a bad download enters the guest image.
- **Dates:** 2026-11-25, milestone M6.3. Code under review: `main` at `5859b4b`.
- **Status:** **signed off by the maintainer on 2026-11-25** (the M6.3 gate, #301), with the severities as proposed and #302–#307 filed rather than fixed before the gate. Findings F1–F3 are fixed.

## Reviewers and their independence

Neither reviewer was given the CHANGELOG, the roadmap, the earlier reviews, or the main session's view. Both followed one written method:
1. the attack surface;
2. every untrusted input traced to its use;
3. every `unsafe` invariant;
4. each attempt's capability from `derive` to `revoke`, across a bridge restart, a runtime restart, `stop`, cancellation, and timeouts;
5. the launch tool's allow-list and QMP checks;
6. limits, timeouts, and waits, with the guest flooding, silent, or pipelining;
7. the audit records.

Each finding had to quote code with `file:line` and give a trigger, or be marked unconfirmed.

| Reviewer | Family | Independence |
| --- | --- | --- |
| gemini-3.8-flash (GitHub Copilot CLI, read-only: shell, write, and URL tools denied) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks |
| Claude (a separate agent, Claude Code; it could run host tests and compile scratch programs, not edit the repository or boot QEMU) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method |

The main session (Claude Code, which wrote the code) checked each finding against the code before fixing or filing it. Gemini found 2 findings (Medium and Low). Claude found 8: 1 High, 1 Medium, 1 Low, 1 Low/Info, and 4 Info. The High finding (F1) was reproduced in QEMU before its fix, and is fixed.

## Findings fixed

| ID | Proposed severity | Found by | Finding | Test (fails without the fix) |
| --- | --- | --- | --- | --- |
| F1 | High (Claude R-2) | Claude | **After a runtime restart, the bridge's capability worked on the new runtime.** Revoking a capability marks its children only. `init` gives a restarted runtime the same endpoint, and nothing revokes what the old runtime minted, so the bridge's copy still reached the new runtime with the old slot's badge. The new runtime served it as whatever held that slot: the guest's next attempt with no `bind` record and nothing to revoke at its end, or another agent, under that agent's grants. It needs a runtime crash during a bound attempt, which the guest was not shown to cause. Fixed (with F2): a guest attempt's capability has its own badge (`agents::guest_badge`: `0x80_0000`, the task's low 15 bits, and the attempt), never an agent process's slot badge. The runtime serves a guest badge only for the slot holding that attempt bound (`Runtime::slot_of`), and answers any other `NO_SESSION`, which the bridge takes as the attempt's end (`bridge: refused by the runtime`). Attempt numbers are stored and grow at every start, so a restarted runtime never mints an earlier badge until task IDs pass 32,768 more | `bridge`, case `restart`: the kernel kills the runtime during a bound attempt; the guest's next request goes through the capability the killed runtime minted. With the badge check removed, the new runtime served it (`agents: guest: stale`), and the kernel and the runner fail |
| F2 | Medium (Claude R-1) | Claude | **A request queued under a slot's capability was served for the slot's next holder.** The kernel copies the badge into the message at `send`, and revocation is checked only when a handle is looked up, so a request the bridge sent while the runtime was busy, before its attempt ended, is still delivered. The badge named the slot, and the slot is filled again before the runtime receives, so the request could act as the guest's next attempt or as another agent (for example `FAIL` or `COMPLETE` of its task). Timing-dependent; not reproduced. Fixed by F1's change: the queued request's badge names an attempt that is no longer bound, so it is answered `NO_SESSION`, and a guest badge never names an agent process's slot | As F1: the stale request is the same path. `pharos-proto`: `guest_badges_name_attempts` |
| F3 | Low (Gemini R-1, proposed Medium) | Gemini | **A reply's gaps carried an earlier attempt's bytes.** The bridge maps its agent buffer once and attaches it for each attempt. A `TASK` reply with a checkpoint sends the buffer from 0 to the checkpoint's end, and the runtime writes only the input and the checkpoint, so whatever an earlier attempt left between them reached the guest (an HTTPS answer, a `DATA_GET` file). The bridge serves one guest agent, so the bytes are that agent's own, from its earlier tasks. Fixed: the bridge zeroes its buffer at each attach | `bridge`, case `restart`: its second attempt checks that the bytes between its input and its checkpoint are zero, after its first left an HTTPS answer there. Without the zeroing they are not |

Claude's R-4 (Low/Info: the bridge's after-attempt probe `try_send(slot, b"x")` was recorded as the guest's malformed request when the capability still worked) is closed by F1: a guest badge whose attempt is over names no slot, so nothing is recorded.

## Findings filed

| Issue | Proposed severity | Found by | Finding |
| --- | --- | --- | --- |
| #302 | Low | Claude R-3 | A `BIND` reply after the bridge's 2 s timeout, or a guest request the runtime takes over 40 s to answer (two gateway tries of 35 s), leaves a bound attempt the bridge does not hold. The next `BIND` ends it as `bridge restarted` and spends one of the task's attempts; a completed request is recorded while the guest is told the attempt ended |
| #303 | Info | Claude R-5 | The operations the bridge passes are enforced only in the bridge. A compromised bridge can send any agent operation; the runtime still checks each against the guest entry's grants, which hold none of inference, tools, messages, knowledge, or subtasks |
| #304 | Info | Claude R-6 | `trust` keeps a guest's registration after its attempt ends (`list` shows it; `stop` prints `stopped`). `STOP_GUEST` names a slot, and `BIND` takes any guest-marked entry's attempt; with one guest entry, neither can reach another agent |
| #305 | Info | Claude R-7 | The launch tool does not count `-serial` or `-qmp`, and does not check the image's paths against the built hashes. None of this adds a network device, disk, shared filesystem, or second channel, which the allow-list and QMP checks refuse |
| #306 | Info | Claude R-8 | `derive` cuts a badge to 24 bits where `send` refuses one over them. No authority is gained |
| #307 | Info | Gemini R-2 | A frame's message length is one byte, so a 256-byte agents v1 message cannot cross the bridge. No passed operation sends or gets one |

## Checked and found correct

Both reviewers checked these and found them correct; where only one did, its name follows.

- **Frames (`pharos_proto::bridge`):**
  - The header checks the magic, the version, the kind, and a length of at most 70,000. `feed` cannot write past the frame buffer.
  - Before the guest's `HELLO`, only `HELLO` frames are found, and at most 64 KiB is skipped.
  - `parse_request` needs a message of 2 to 256 bytes that parses as agents v1, an operation the bridge passes, and exactly the buffer data the operation reads, where it reads it. Its offsets match the runtime's (Claude).
  - The largest `REPLY` fits in a frame (Claude).
- **The bridge:**
  - No `unsafe`. Buffer bounds are checked before every write.
  - Every wait is bounded: `HELLO` and each frame write 10 s, each request 40 s, `BIND` 2 s, silence 60 s.
  - One request at a time; a request before the reply ends the attempt.
  - It holds only the console, the device, the report endpoint, and the runtime under badge `0x81`. Memory stays within its 512 KiB (Claude).
- **`BIND` and `STOP_GUEST`:**
  - `BIND` is served only under the bridge's badge, `STOP_GUEST` only under `trust`'s.
  - The capability is minted with `SEND | GRANT` in the runtime's own table and passed with `SEND` alone, so the bridge cannot pass it on or derive from it.
  - The `bind` record is written before the capability is given; if it fails, the capability is deleted.
- **Revocation within one runtime:** the capability is revoked, and `unbind` recorded with its reason, at every end: `COMPLETE`, `FAIL`, hung, the task's deadline, over CPU, cancellation, `STOP_GUEST`, a second `BIND`, and a failed registration with `trust`. A late reply finds its one-shot reply capability revoked (Claude).
- **`derive`:** it needs `GRANT`, its rights are the parent's masked, a badged parent keeps its badge, a child of a revoked parent is revoked, and it counts against the handle limit.
- **`trust`:** a guest's stop goes to the runtime, and `trust` stops the runtime if that is not taken in 2 s. `stop all` stops the runtime first.
- **The launch tool:**
  - `-device` and `-chardev` values must match exactly. These are refused: `-netdev`, `-net`, `-nic` other than `none`, `-virtfs`, `-fsdev`, the disk options, `--` options, and the JSON device form. `-nodefaults` and exactly one channel are required.
  - The QMP check requires exactly the q35 IDs plus `1af4:1043` on the guest, no block device, and two consoles on Pharos, and stops both VMs otherwise. Its parser does not take `subsystem-vendor` for `vendor` (Claude).
  - The guest starts only after `bridge: ready`, and Pharos runs with `-no-reboot`.
- **The guest image:**
  - Every download, cached or not, is checked against its pinned SHA-256 before use, and the lock needs `https` URLs.
  - Archives are read into the initramfs in memory and never extracted on the host (Claude).
  - `/init` starts only the agent, with `python3 -I`.
  - Accepted limit: `cargo xtask guest lock` trusts what it fetches (no Alpine signature check), as the threat model's "trusted by their pinned hashes" says.
- **The audit trail:** every guest request reaches the runtime as the attempt's request, recorded as for any agent; a protocol error is the task's failure and in `unbind`.

## Gate evidence (#301)

| Criterion | Evidence |
| --- | --- |
| `bridge` in CI | `bridge` passed under KVM in CI's QEMU share 1 on `main` at `5859b4b` ([run 45567555256](https://github.com/codeaiforge/pharos-os/actions/runs/45567555256)); with this review's fixes and the `restart` case it passed locally (32 checks, 32.4 s) |
| The hostile-guest suite passes | The same runs: the guest's own checks of what it can reach, nine hostile frames, the refusals, a restarted bridge, and (with the fixes) a restarted runtime |
| The throwaway branch that gives the guest a network device failed CI | `throwaway/m6.3-guest-network` at `f175206` ([run 45568903308](https://github.com/codeaiforge/pharos-os/actions/runs/45568903308)): with the launch tool's `-nic` and QMP checks disabled, `bridge` failed in QEMU share 1 (`the guest's log lacks 'guest: virtio devices 1'`), and the launch tool's refusal tests failed in the host and Rust 1.91 jobs; the branch is deleted ([#301 comment](https://github.com/codeaiforge/pharos-os/issues/301#issuecomment-7156129471)) |
| A security review independent of the authoring agents, no open critical or high finding | This report. Claude's one High finding (F1) is fixed, with its Medium (F2) and Gemini's (F3) |
| The maintainer approves | Approved 2026-11-25 |
