# Security review: M6.4 payload approval

- **Scope:** payload approval ([approval.md](../architecture/approval.md), D-037):
  - trust v1 `ASK` and `BUFFER`, and agents v1 `ANSWER`'s digest (`pharos_proto::trust`, `pharos_proto::agents`);
  - the display, the digest, and the answer rules (`pharos_programs::approval`), and `trust`'s asks, pages, and two approvers (`user/programs/src/bin/trust.rs`);
  - the runtime's held calls, `MARK`, and the manifest's `approve` key (`user/programs/src/bin/agents.rs`, `pharos_proto::manifest`);
  - the gateway's `APPROVED`, `MARK`, `NOT_APPROVED`, and its table of approvals (`pharos_proto::gateway`, `pharos_programs::gateway`, `user/programs/src/bin/gateway.rs`);
  - `Route::approve` and the tables (`pharos_services`), and the `approval` kernel and the runner's checks.
- **Design under review:** approval.md, D-037, the threat model's "Payload approval (M6.4)" rows, and AGENTS.md sections 5 and 7.
- **Threat model:** four attackers, each alone:
  - a malicious agent sending any agents v1 message, with any payload bytes;
  - a compromised runtime sending any trust v1 or gateway v1 message;
  - one person at the trusted console who wants a two-approver action to go with only their own approval, or who owns the agent;
  - anyone who reads the trail afterwards.

  An attacker wins in any of these cases:
  - bytes are sent other than those shown and approved;
  - a marked action is sent without approval, or with fewer distinct approvers than its mark;
  - the requester counts as an approver of a two-approver action;
  - an approval is used twice;
  - an agent shapes what the console shows so a person is misled;
  - a person approves without the hash line having been shown to them;
  - an ask waits forever, or `trust` blocks so the emergency stop stops working;
  - a payload or a secret reaches the trail.
- **Dates:** 2026-11-27, milestone M6.4. Code under review: `main` at `61c48d4` (#322–#328).
- **Status:** **signed off by the maintainer on 2026-11-28** (the M6.4 gate, #329), with the severities as proposed and #330–#332 filed rather than fixed before the gate. CI: `approval` passed on `main` at `bc5a7f5` (run 46056881506); the throwaway branch where the gateway flips a byte of an approved body failed `approval` (run 46147617447: the server received `{"a":1}` 0 times, not 1). The same runs found `exhaustion`'s `stop all` over its 200 ms bound in 2 of 6 CI runs since `bc5a7f5`, not shown to be caused by it, filed as #333. Fixed: F1–F7, F9, and G1. Filed: #330 (F8), #331 (F10), #332 (F11). Documented: F12, F13, and G3.

## Reviewers and their independence

Neither reviewer was given the CHANGELOG, the roadmap, or the main session's view. Both worked from one written method:
1. the attack surface, each message and how its badge is checked;
2. every untrusted input traced to its use;
3. the binding of the bytes sent to the bytes hashed;
4. the answer state machine in `trust` and the runtime's;
5. the display;
6. timeouts, limits, and whether every failure denies;
7. the audit records.

Each finding had to quote code with `file:line` and give a trigger.

| Reviewer | Family | Independence |
| --- | --- | --- |
| gemini-3.8-flash (GitHub Copilot CLI, read-only: shell, write, and URL tools denied; approved by the maintainer for M6.4) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks. It read the working tree while the fixes below were being made, so some of its quotes are of code before a fix and some after (it quotes `Approvals::add` with F2's fix and `room` without F4's) |
| Claude (a separate agent, Claude Code; it could read the code and run host tests, not edit the repository or boot QEMU) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method. It reviewed `61c48d4` |

The main session (Claude Code, which wrote the code) checked each finding against the code before fixing or filing it. Claude found 13 (F1–F13): F1 High; F2, F3, F4 Medium; F5–F11 Low; F12 and F13 Info. Gemini found 3 (G1–G3): G2 repeats F4. Gemini rated G1 and G2 Low, and G3 Info. Both found the binding of the bytes sent to the bytes shown sound.

## Findings fixed

| ID | Proposed severity | Finding | Fix and test |
| --- | --- | --- | --- |
| F1 | High | **One person could be both approvers of a `two` action.** Anyone logged in may add a person (`person add`) or set another's passphrase (`person passphrase`) without knowing it, then log in as that person, so the agent's owner could approve twice under two names. The trail showed it afterwards; nothing prevented it. This is the M6.5 review's F3 (a limit by D-038's choice), and it defeated D-037's four eyes; the threat model's identity row had left it to D-037, which decided nothing about it | The maintainer chose a fix in `trust` (2026-11-27). `trust` keeps the people whose passphrase someone else set since it started (`person add`, or `person passphrase` of another), and a two-approver ask refuses their yes (`<name>'s passphrase was set by someone else; set your own first`, recorded `not theirs`) until they set their own (`approval::may_approve`, host-tested). The `approval` kernel adds `dave` as `admin`, logs in as him, and his yes is refused; mutation-checked. **Limit:** `trust` keeps the list in memory, so a passphrase set before `trust` restarted counts once `trust` can approve again (after the runtime restarts, F9); the trail still shows who set it |
| F2 | Medium | **One decision could leave two gateway approvals.** `trust` tells the gateway before the runtime. If the runtime did not answer, the yes was taken back in `trust` only, and a second yes added a second approval of the same bytes, which a compromised runtime could use twice | The gateway's `Approvals::add` replaces an approval of the same route and bytes (host test: approved twice, used once). `trust` marks an ask answered once the runtime has its yes, and refuses any further yes (`approved; waiting for the runtime`) |
| F3 | Medium | **`trust`'s asks had no deadline of their own.** `RESOLVED` is a 1 s non-blocking send, lost while `trust` is busy (a passphrase hash takes seconds under TCG). A stale ask then held one of the 4 slots for good, and still took a yes, which recorded `APPROVE` and gave the gateway an approval the runtime had already treated as refused | `ASK` carries the runtime's deadline (`wait_ms`, from `approval::timeout_us`). `trust` ends each ask then itself (`ask #<n>: no answer; refused`), whether or not `RESOLVED` comes, and wakes for the next one. No test tells the two apart: in the `approval` kernel the runtime's `RESOLVED` reaches the restarted `trust` too |
| F4 / G2 | Medium (Gemini: Low) | **A manifest's `approve` on a route the table does not mark could never be approved.** The gateway answered `APPROVED` for an unmarked route `NOT_FOUND`, so `trust` approved nothing, and the request was refused for good | The gateway takes an approval for any route its table has. A route the table does not mark needs none, so the approval goes unused. Host test. The `approve` key is not run end to end in a kernel |
| F5 | Low | **The ask's first line could be dropped, and was never repeated.** It went through the rate limit on lines the runtime's messages make, while the pages and the hash line did not. `show` never repeated it, so a second approver did not see which agent, owner, or route it was | The first line is kept with the ask and written with every first page, never rate-limited or dropped (a page the console cannot take whole shows no hash line). The review also noted the design's "the route and its method": the method is not shown, as `ASK` does not carry it and the compiled route fixes it; approval.md now says so |
| F6 | Low | **"Seen" needed only the last page since login.** The page pointer survived a login, so `more` could show a new person only the last page and its hash line | A login or a logout sets each ask back to its first page, as well as not seen |
| F7 | Low | **A payload line could wrap on an 80-column terminal.** Lines were up to 135 characters, so the wrapped part began at column 0 without `| ` and showed up to 13 characters the agent chose | 16 bytes a line, not the design's 32: the longest is 71 characters (host test). A 4 KiB payload is 16 pages of 256 bytes. The `tools`, `injection`, and `vault` scripts read two lines |
| F9 | Low | **A restarted `trust` showed asks it could not answer.** It had no `CHANNEL`, yet it took a yes and sent `APPROVED` to the gateway, leaving an approval no one would use | With no channel, a yes is refused at once (`trust restarted and cannot tell the runtime; nothing approved`) and nothing goes to the gateway. The `approval` kernel checks it |
| G1 | Low (Gemini) | **approval.md said `pharos_services::check` refuses a marked route too long to approve, or in a table whose `trust` cannot approve.** `check` does neither. `check_routes` and `trust_approves` hold the rules, and host tests apply them to every table | approval.md now says where each rule is checked |

## Findings filed

| Issue | ID | Proposed severity | Finding |
| --- | --- | --- |
| #330 | F8 | Low | The trail cannot always tie a person's approval to what was sent. The runtime records no ask, and an expiry is `refuse` with `no answer`, not `expire`. `trust`'s records carry no task or agent. A digest that does not match is recorded as a person's no. The first of two yeses reads like a final one. The intent's hash covers other bytes than the approval's digest. `trust`'s record follows the action, best effort |
| #331 | F10 | Low | An approval is bound to the route and the bytes, not to the client or the call. One left by a call the agent abandoned stays usable for 60 s by any client the route lists. The `approval` kernel relies on this to send `e` as client 2 |
| #332 | F11 | Low | A `send` approved but not yet repeated never expires in the runtime. And the runtime asks before the gateway's path and size checks, so a person can approve a request the gateway then refuses |

## Found by the gate's own run

The full suite on the fixes failed the `vault` kernel once: after the gateway's kill, `fetcher`'s request was `BUSY`. Since #326 the runtime asks the gateway `MARK` before each request, with a 1 s wait, and a gateway slow to come back under the suite's load did not answer in time; a `REQUEST` alone had waited 35 s. `MARK` now waits as long as a request (`MARK_US`). `vault` passed alone before and after.

## Documented, not changed

- **F12 (Info):** `trust`'s waits are bounded: a page's lines up to 100 ms each, the gateway's `APPROVED` 1 s. So the stops keep working. Pages skip the rate limit, so a compromised runtime can fill the console with them.
- **F13 (Info):** a compromised runtime that reuses an ask number gets one ask's first line shown with another's pages. Since F5 each ask keeps its own first line, and the bytes approved are still the bytes shown.
- **G3 (Info):** with the agent's owner unknown to `trust`, every yes on a two-approver ask is refused. This fails closed, as designed.

## Approval fatigue

The gate counts the asks a task puts to a person. The runner counts them from every passing kernel's trail: one per runtime `approve` or `refuse` record with `user`, `no answer`, or `task ended` as its detail (`resolve::asks`, host-tested). It fails a kernel with more than 8 for one task. The most are in the `approval` kernel's first task, 6, and the `tools` kernel's, 5. The demo scenarios do not exist until M6.10; their budget comes with them.

## Checked and found sound

- **The bytes sent are the bytes hashed.** The gateway copies a request once, then hashes and sends those same copies. It uses the approval once, before it releases a secret or connects. `trust` copies the bytes and clears its buffer before it shows or hashes them. The runtime compares the whole 32-byte digest, and takes `ANSWER` only from `trust`'s badge.
- **Badges.** The gateway enforces the route's own mark, at most 4 approvals, and 60 s. Only badge 3, `trust`'s alone, can send `APPROVED`. `MARK` answers only a client the route lists.
- **The display.** Every non-printable byte and every `\` is escaped (host test over all 256 values). Every payload line starts with `| `, and no line of `trust`'s own does.
- **Answers.** An answer needs a login. "Seen" is reset on login, logout, and idle logout. The digits, the distinct names, and the requester rule hold, apart from F1.
- **Denials.** The runtime's deadlines apply, and every failure path traced denies.
- **Limits.** The limits agree: 4,096 approvable bytes, a 256-byte path, a 256-byte query. A path cannot hold a zero byte.
- **`unsafe`.** None is added.
