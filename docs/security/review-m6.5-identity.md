# Security review: M6.5 identity and organization model

- **Scope:** people, sessions, owners, and actor resolution ([identity.md](../architecture/identity.md), D-038):
  - PBKDF2 (`pharos_crypto::pbkdf2`) and the person file (`pharos_proto::identity`);
  - the trusted-path commands and sessions (`pharos_proto::trust`, `pharos_programs::identity`, `user/programs/src/bin/trust.rs`), with the console driver's buffer wiping;
  - owners: `manifest::Entry::owner`, trust v1 `OWNER`, `REGISTER`'s owner, and the runtime's start check and record (`agents.rs`);
  - `trust`'s capabilities and store namespace 10 (`pharos_services`);
  - the host tools: `cargo xtask identity first`, the person records the runner seeds, and `store audit --resolve` (`xtask/src/resolve.rs`).
- **Design under review:** identity.md, D-038, the threat model's "Identity and owners (M6.5)" rows, and AGENTS.md sections 4, 5, and 7. D-018 item 2: identity is attribution, never authority.
- **Threat model:** four attackers, each alone:
  - someone at the trusted console who knows no passphrase, or only their own;
  - a malicious agent, or a compromised runtime, sending any trust v1 message;
  - anyone who reads the store disk or the trail afterwards;
  - whoever controls the host build (out of scope except where the docs claim otherwise).

  An attacker wins in any of these cases:
  - acting as another person, or logging in without the passphrase;
  - bypassing or shortening the refusal delay;
  - leaking a passphrase or its hash;
  - changing identity records other than from the trusted path;
  - a role or an identity granting anything;
  - an agent starting with an owner who is no current person, or an owner being removed;
  - a record resolving to the wrong principal;
  - `trust` hanging, or the emergency stop locked behind a login.
- **Dates:** 2026-11-26, milestone M6.5. Code under review: `main` at `2c5a54a` (#310–#313).
- **Status:** **awaiting the maintainer's sign-off** (the M6.5 gate, #314). Findings F1, F2, and F4 are fixed. F3 is documented as a limit by design. The rest are to be filed.

## Reviewers and their independence

The reviewer was not given the CHANGELOG, the roadmap, or the main session's view. It worked from one written method:
1. the attack surface;
2. every untrusted input traced to its use;
3. secrets handling;
4. the session, refusal, and idle state machine;
5. the owner check failing closed, and `person remove`'s refusal across restarts;
6. resolution against spoofing;
7. limits and timeouts.

Each finding had to quote code with `file:line` and give a trigger.

| Reviewer | Family | Independence |
| --- | --- | --- |
| Claude (a separate agent, Claude Code; it could read the code and run host tests, not edit the repository or boot QEMU) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method |

M5.4's minimum is one reviewer from a different model family. That review has not been run: it sends the code to an outside service, which is the maintainer's to approve.

The main session (Claude Code, which wrote the code) checked each finding against the code before fixing or filing it. The reviewer found 12:
- F1, F2, F3: Medium;
- F4: Medium/Low;
- F5: Low/Medium;
- F6, F7, F8: Low;
- F9, F10: Low/Info;
- F11, F12: Info.

## Findings fixed

| ID | Proposed severity | Finding | Fix and test (fails without the fix) |
| --- | --- | --- | --- |
| F1 | Medium | **Any successful login cleared the console's refusal delay.** So a person could alternate guesses at another's passphrase with logins as themselves, about one guess every 2–3 s instead of every 60 s | Only a login as the name last refused resets the delay (`Session::refused(name, now)`). `another_persons_login_keeps_the_delay`: the next refusal doubles to 4 s, where it was 1 s |
| F2 | Medium | **A person named `console` or `user` could be added.** Their records then read, and resolved, as the logged-out console's (`console`) or as the pre-M6.5 console's (`user`), the wrong principal | `pharos_proto::identity::RESERVED` and `valid_person`: `Person::new`, `parse`, `person add`, and `identity first` refuse both names. `console_and_user_are_no_persons_names` |
| F4 | Medium/Low | **A person command's record was cut at 64 bytes (`audit::MAX_DETAIL`) without a mark.** So the trail could hide a role. Console lines are at most 64 bytes, so `person roles` always fits; `person add`'s record adds ` roles ` and could be cut | `pharos_programs::identity::recordable`: `person add` is refused when its record would not fit whole. A host test, and the `trust` kernel types a 59-byte `person add` whose record would be 65 bytes |

## Documented, not changed

| ID | Proposed severity | Finding | Where |
| --- | --- | --- | --- |
| F3 | Medium | **Anyone logged in may reset another person's passphrase (`person passphrase`), or add a person, without that person's passphrase.** So one person can log in as another, and one person can make a second. This is D-038's and identity.md's choice: every logged-in person may type the person commands, and restricting them by role would make the role an authority (D-018). D-037 decides what two approvers need | Threat model, identity and owners: a limit |
| F11 | Info | **A compromised runtime skips the owner check, which is the runtime's.** It can also send `OWNER` for 64 names, filling `trust`'s owners so real owners are not kept, or refuse `person remove` of any name, or `REGISTER` any owner for `list` | Threat model: a limit |

## Findings to file

| ID | Proposed severity | Finding |
| --- | --- | --- |
| F5 | Low/Medium | Under TCG a passphrase hash holds `trust` for about 5 s. An attempt starting then waits the runtime's 5 s `OWNER` call and may fail `owner not checked`, closed. While the runtime waits on it, `trust`'s 2 s sends to the runtime (`yes`, `revoke`, `usage`, a guest's stop) fail as "not answering", and a guest's stop then stops the runtime. The comment and identity.md said "at most 2 s"; both are corrected |
| F6 | Low | `login <name>` answered `login: wait n s` (or a name that does not parse) sets no prompt, so a passphrase typed next is read as a command and not wiped: `stop hunter22x` would echo `no agent hunter22x` |
| F7 | Low | A pending `login` prompt never expires: the next operator's `stop all` is taken as a passphrase, refused, and adds to the delay |
| F8 | Low | `store audit --resolve` and the runner's check keep people and owners across every stream, read in byte order (`log/1`, `log/10`, `log/2`), and key owners by agent name, not attempt. A trail where a person's records precede their login in another boot resolves; an owner in a start record is not checked to be a person the trail shows; any runtime record with task 0 resolves as a control client's request |
| F9 | Low/Info | Copies of secrets left in `trust`'s memory: PBKDF2's HMAC midstates; a pending `Prompt::New`'s first passphrase dropped on an idle logout or replaced unwiped; a passphrase line over 64 bytes, or split across two receive chunks, left in a buffer |
| F10 | Low/Info | A login of a name with no record is refused without hashing, so its quicker answer shows which names are people. `OWNER` shows the runtime the same |
| F12 | Info | `person remove`'s "last person" counts files in `people/`, including any that do not parse. `identity first` reads the passphrase with echo if `stty -echo` fails, without saying so |

## Checked and found sound

- The logged-out gate is checked before every command; unknown commands become `help`, which shows only the login help; `restart` and `start` need a login, and `trust`, `audit`, and `store` cannot be stopped, so no one logged out can restart `trust` to reset the delay.
- The hash compare is constant-time; the person file's parser refuses unknown, repeated, or missing keys and bad hex; a record must name its own file; names cannot leave `people/`.
- No passphrase, salt, or hash reaches a record or the console on the prompted paths; the line, the line buffer, the received bytes, and the console's DMA page are wiped (but see F6 and F9).
- Only `trust` holds namespace 10, at handle 6.
- `OWNER` fails closed: its parse is strict, only the runtime's badge with a reply capability is answered, replies are one-shot, and `NOT_FOUND`, `BUSY`, and a time-out all refuse the attempt before anything is spawned, with its start record written.
- No code reads a role except to show it.
- The idle logout counts only typed lines (and, since #313, `trust`'s answers to them), not runtime messages.
- `person remove` refuses the last person and each owner the runtime asked about, and ends the removed person's session.
- In resolution, a refused login teaches nothing, and an agent named like a person needs its own start record.
