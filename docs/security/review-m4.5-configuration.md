# Security review: M4.5 system configuration and diagnostics

- **Scope:** everything M4.5 added since commit `5a0864c` (the M4.4 gate):
  - D-030 and the design: [services.md, configuration and health](../architecture/services.md#configuration-and-health-m45-d-030) (#174, #175);
  - `pharos_services::config`, `pharos_programs::system::image_config`, `init`'s `read_config`, `factory_config`, and the checks at offer, apply, and boot, `cargo xtask`'s `check_config`, and `kernel/root/etc/system.conf` (#176);
  - `init`'s `check_health`, `supervise::{quiet_us, unresponsive}`, event `Unresponsive` (15), `init` op `CONFIG` (11), the uptime and last check in `SERVICES`, `trust`'s `INFO`, `health`, and `config` (#177);
  - the tests: `health`, the `manage`, `update`, `recovery`, and `budgets` additions (#176–#178).
- **Design under review:** services.md, D-030, D-028, D-026, D-022, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-09, issue #179. Reviewer: AI-assisted (Claude Code), from reading the code, with one QEMU experiment (F2). F1 and F3 were not reproduced. F1–F3 are fixed (2026-11-09), each with a test that fails without its fix.
- **Status:** **proposed**, with F1–F3 fixed; awaiting the maintainer's review.

## Method

1. Listed every changed file since `5a0864c` and searched the diff for new `unsafe` blocks and dependencies: none (`xtask` now depends on the workspace crate `pharos-services`).
2. Read the parser for every way untrusted text could panic, index out of bounds, or be narrowed instead of refused.
3. Followed a configuration file from the host to a running service: built, signed, staged, offered, applied, mounted, read at boot, and ignored in safe mode and recovery.
4. Followed each health check: who is asked, on which capability, how a late answer is handled, what an unresponsive service costs, and what each service's longest blocking call is against its window.
5. Checked who can ask `init` for `CONFIG` and the extended `SERVICES`.
6. Checked each acceptance criterion of M4.5 against a test that runs in CI.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low (latent) | **The agent runtime's window (30 s) is shorter than its own blocking calls, so a long inference request makes `init` stop the runtime and every agent.** The runtime is single-threaded and calls `infer` with `GENERATE_US` (60 s), twice if the first call answers `NO_BUFFER` (`agents.rs`); `infer` processes the whole prompt before it answers `GENERATE` (`prompt_us`). On the reference host the S1 model loads in 6.7 s and processes prompts at about 36 tokens/s ([inference-evaluation.md](../project/inference-evaluation.md)), so a first request of about 850 tokens, or about 1,100 later, keeps the runtime silent past 30 s; `init` then stops it as unresponsive (with every agent's process), and the fourth time gives it up until reboot. An agent with a model grant and a policy entry allowing such prompts can do this on purpose. Latent: the boot policy table is empty, so no agent runs on the shipped system; reachable with the test tables. | **Fixed:** `agents` has a compiled window of 180 s; `GENERATE_US` moved to `pharos_proto::infer`, and the host test `the_runtime_outlasts_its_longest_inference_call` requires the window above twice it plus one check interval (it fails with the old 30 s). Other services' longest calls were not audited against their windows. |
| F2 | Low (test) | **CI never shows a real boot service answering a real check.** A service's `answered` time starts at its ready time, checks run every 10 s, and the `manage` run is about 8 s, so its `health` lines (`up 7 s, answered 7 s ago`) show the ready time, except `trust`'s (restarted 21 times). The runner requires `, answered ` on one line only, and no other full-table run checks for `unresponsive`. A boot service that never answered `init`'s `INFO` (for example a version byte `trust` does not accept) would pass CI and be restarted every 30–40 s in use. Shown not to be the case today: with the check every 1 s and every window 3 s, `manage` passed and every daemon showed `answered 0 s ago`. | **Fixed:** `init` runs a round of checks whenever a daemon becomes ready, and keeps a bit per entry that has answered since; until then `health` shows `no answer yet` (`quiet_s` `NO_ANSWER`, new) instead of the ready time. The `manage` runner types `health` before the `trust` restarts and requires all 7 ready daemons to show an answered check; without the round at ready it fails (`net ready, … no answer yet`). The first run of the fix showed a restarted `trust` misses the round at its ready, since it is waiting on `init` for `RUNTIME`; it answers the next round 10 s later, and `init` waits 100 ms for it once per restart. |
| F3 | Low | **A configuration can delay or end the restarts of `trust` and `audit`.** `start = no` is refused for `PROTECTED` services, but `restarts` and `delay_ms` are not: `restarts = 0` makes `trust` `Never`, so after one crash or one unresponsive check the trusted console and `stop all` are gone until reboot while agents keep running; `delay_ms = 60000` makes the restart delays 60, 240, and 960 s (compiled: 0.1, 0.4, 1.6 s). While `audit` is down the runtime refuses audited actions (it fails closed after `AUDIT_US`), so that is availability only. Needs a signed image and the user's yes; safe mode ignores the file. | **Fixed:** the parser refuses `restarts` and `delay_ms` in a section for `trust`, `audit`, or `store` (`line N: <name> restarts as compiled`, new `Why::Compiled`); `start = yes` is still allowed. Parser tests for each protected service with `restarts = 0`, `restarts = 3`, `delay_ms = 60000`, and `delay_ms = 100`; with the check removed they fail. |
| F4 | Info | **A round of health checks blocks `init` for up to 100 ms per silent daemon** (7 daemons with endpoints: 0.7 s every 10 s). Events (ready, ends, slot events) wait in the queue; `trust`'s calls to `init` wait 1 s (`INIT_US`), so commands are still answered. | Accepted: bounded, and only while services are silent. |

## Who can reach what

- **Configuration holds settings, never authority.** The parser knows three keys, `start`, `restarts`, and `delay_ms`, in `[service <name>]` sections naming compiled entries; nothing names a program, a capability, a manifest, or a policy. Unknown keys, sections, and values are refused.
- **Refused, never narrowed.** `restarts` over the compiled limit, `delay_ms` outside 10–60,000, `start = no` for `trust`, `audit`, `store`, a driver, or a service a started one needs: the whole file is refused with its line. The parser checks size (4 KiB), line length (128), and bytes (printable ASCII) first, uses no allocation, and indexes entries only below `MAX_SERVICES` (32, the width of its bitmasks).
- **Only a signed image carries a file, with the user's yes.** `init` reads `etc/system.conf` from the image it starts services from: the factory image (built by `cargo xtask`, which refuses a bad file) or a slot, verified and mounted by `fs_mount` as a copy the storage service cannot change (D-028). An update's file is checked when offered and again at boot; a slot with a bad file is bad and the next is tried. An agent's proposal is at most 64 KiB and unsigned, so it is not an image.
- **Safe mode and recovery use compiled values,** so a valid but harmful file (F3) is undone by `safe` on the trusted console or the safe-mode Limine entry.
- **Only `trust` sees configuration and health.** `init` answers `CONFIG` and `SERVICES` (with uptime and last check) only on the badge of its `bin/trust` entry. `trust`'s agent rows come from process capabilities the runtime registered, read with `process_usage`.
- **A late answer cannot pass for another.** Each check is a `call` with a one-shot reply capability the kernel revokes when the call returns (`syscall.rs`), so an answer after the 100 ms timeout is dropped, not taken as the next service's.
- **The health check stops only what a crash would.** An unresponsive service is stopped, recorded (event 15, audited), and handed to its restart policy, never past its limit; the window is compiled, so a file cannot shorten it.

## Accepted limits

- **Any answer counts,** including an error status: a service whose loop answers `INFO` but nothing else looks healthy (services.md, rejected alternatives).
- **No agent limits in the file:** the boot policy table is empty, so there is nothing to configure yet (design, #175).
- **Changing the file needs a new signed image;** there is no reload (D-030).

## Acceptance criteria

| Criterion | Shown by (in CI) |
| --- | --- |
| Invalid configuration is rejected with a clear error before it is applied | Host: `pharos_services::config` (each refusal with its line), `image_config`, the `xtask` builder refusing a bad root. QEMU: `update` round `config` (refused at offer, `bad configuration, line 3` and `line 4`, never offered), `recovery` round `bad-config` (refused at boot, slot bad, B runs) |
| Diagnostics report service and agent health | `health` (a daemon that never answers: unresponsive after 30–41 s, restarted once, given up); `manage` (`health` and `config` on the trusted console, every ready daemon answering a check; F2); `budgets` (`health` shows a running agent's process, CPU time, and pages; mutation-checked) |
| Misconfiguration cannot widen privileges | The keys hold no authority; `restarts` over the limit refused (host tests; `update` round `config`, 9 restarts of `knowledge`); protected services keep their compiled restarts (F3). The gate's mutation (#179) is still to run |

## Measured

The IPC round trip: 1,894 ns median (1,836–1,946 ns over 5 runs of 100,000, KVM), within D-004's 2 µs budget (M4.4: 1,874 ns at its gate). M4.5 adds a round of `INFO` calls from `init` every 10 s, not work on the system-call path.
