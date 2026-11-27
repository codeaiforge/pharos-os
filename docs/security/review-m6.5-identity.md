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
- **Status:** **signed off by the maintainer on 2026-11-27** (the M6.5 gate, #314), with the severities as proposed and #315–#321 filed rather than fixed before the gate. CI: `identity` passed on `main` at `41d531b` (run 45956899434); the throwaway branch granting `asker` model 2 failed `identity` and `permissions` (run 45976522180). Fixed: F1, F2, F4, F13, and F14. Documented as limits: F3 (by design) and F11. Filed: #315–#321.

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
| gemini-3.8-flash (GitHub Copilot CLI, read-only: shell, write, and URL tools denied; approved by the maintainer) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks. It reviewed `719b89b`, after F1, F2, and F4 were fixed |
| Claude (a separate agent, Claude Code; it could read the code and run host tests, not edit the repository or boot QEMU) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method. It reviewed `2c5a54a` |

The main session (Claude Code, which wrote the code) checked each finding against the code before fixing or filing it. Claude found 12 (F1–F12):
- F1, F2, F3: Medium;
- F4: Medium/Low;
- F5: Low/Medium;
- F6, F7, F8: Low;
- F9, F10: Low/Info;
- F11, F12: Info.

Gemini found 9. Seven repeat Claude's: F5, F6, F7 (extended), F8, F9, F10, and F12. Gemini rated F10 Low/Medium. Gemini's two new findings are F13 and F14. Gemini also found the refusal delay sound after F1's fix.

## Findings fixed

| ID | Proposed severity | Finding | Fix and test (fails without the fix) |
| --- | --- | --- | --- |
| F1 | Medium | **Any successful login cleared the console's refusal delay.** So a person could alternate guesses at another's passphrase with logins as themselves, about one guess every 2–3 s instead of every 60 s | Only a login as the name last refused resets the delay (`Session::refused(name, now)`). `another_persons_login_keeps_the_delay`: the next refusal doubles to 4 s, where it was 1 s |
| F2 | Medium | **A person named `console` or `user` could be added.** Their records then read, and resolved, as the logged-out console's (`console`) or as the pre-M6.5 console's (`user`), the wrong principal | `pharos_proto::identity::RESERVED` and `valid_person`: `Person::new`, `parse`, `person add`, and `identity first` refuse both names. `console_and_user_are_no_persons_names` |
| F13 | Medium (Gemini) | **A pending passphrase prompt took a stop as the passphrase.** This extends F7. During `person add` or `person passphrase` (`Prompt::New`), or `login` (`Prompt::Login`), another operator's `stop all` was read as the passphrase, and the emergency stop never ran. Typed twice, it could even become a person's passphrase | A stop typed at any prompt ends the prompt (its first passphrase wiped) and runs (`trust::is_stop`). `valid_passphrase` refuses a line that parses as a stop, so no passphrase is one. The `identity` kernel types `stop nosuch` at `person passphrase`'s prompt and must see `no agent nosuch`; without the fix it does not. Host test: `a_stop_is_never_a_passphrase` |
| F14 | Info (Gemini) | `manifest::owned` checked owners with `valid_name`, so a compiled table could name `console` or `user` as an owner. Such an entry would still fail at its start, since neither can be a person | `owned` uses `valid_person`, now `const`. `every_compiled_entry_names_an_owner` refuses both |
| F4 | Medium/Low | **A person command's record was cut at 64 bytes (`audit::MAX_DETAIL`) without a mark.** So the trail could hide a role. Console lines are at most 64 bytes, so `person roles` always fits; `person add`'s record adds ` roles ` and could be cut | `pharos_programs::identity::recordable`: `person add` is refused when its record would not fit whole. A host test, and the `trust` kernel types a 59-byte `person add` whose record would be 65 bytes |

## Documented, not changed

| ID | Proposed severity | Finding | Where |
| --- | --- | --- | --- |
| F3 | Medium | **Anyone logged in may reset another person's passphrase (`person passphrase`), or add a person, without that person's passphrase.** So one person can log in as another, and one person can make a second. This is D-038's and identity.md's choice: every logged-in person may type the person commands, and restricting them by role would make the role an authority (D-018). D-037 decides what two approvers need | Threat model, identity and owners: a limit |
| F11 | Info | **A compromised runtime skips the owner check, which is the runtime's.** It can also send `OWNER` for 64 names, filling `trust`'s owners so real owners are not kept, or refuse `person remove` of any name, or `REGISTER` any owner for `list` | Threat model: a limit |

## Findings filed

| Issue | ID | Proposed severity | Finding |
| --- | --- | --- | --- |
| #315 | F5 | Low/Medium | Under TCG a passphrase hash holds `trust` for about 5 s. An attempt starting then waits the runtime's 5 s `OWNER` call and may fail `owner not checked`, closed. While the runtime waits on it, `trust`'s 2 s sends to the runtime (`yes`, `revoke`, `usage`, a guest's stop) fail as "not answering", and a guest's stop then stops the runtime. The comment and identity.md said "at most 2 s"; both are corrected |
| #316 | F6 | Low | `login <name>` answered `login: wait n s` (or a name that does not parse) sets no prompt, so a passphrase typed next is read as a command and not wiped: `stop hunter22x` would echo `no agent hunter22x` |
| #317 | F7 | Low | A pending `login` prompt never expires. The stops are fixed by F13; the expiry is what remains |
| #318 | F8 | Low | `store audit --resolve` and the runner's check keep people and owners across every stream, read in byte order (`log/1`, `log/10`, `log/2`), and key owners by agent name, not attempt. A trail where a person's records precede their login in another boot resolves; an owner in a start record is not checked to be a person the trail shows; any runtime record with task 0 resolves as a control client's request |
| #319 | F9 | Low/Info | Copies of secrets left in `trust`'s memory: PBKDF2's HMAC midstates; a pending `Prompt::New`'s first passphrase dropped on an idle logout or replaced unwiped; a passphrase line over 64 bytes, or split across two receive chunks, left in a buffer |
| #320 | F10 | Low/Info (Gemini: Low/Medium; identity.md's "answered the same way" is true of the words, not the time) | A login of a name with no record is refused without hashing, so its quicker answer shows which names are people. `OWNER` shows the runtime the same |
| #321 | F12 | Info | `person remove`'s "last person" counts files in `people/`, including any that do not parse. `identity first` reads the passphrase with echo if `stty -echo` fails, without saying so |

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
