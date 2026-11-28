# Runtime policy: signed bundles, ceilings, and the diff

## 1. Status

- **Design:** **Accepted**: approved by the maintainer on 2026-11-28 (#335), with each open question decided as recommended (section 7). It follows [D-039](../project/decision-log.md#d-039-runtime-policy-and-its-language) (accepted 2026-11-28) and builds on agent manifests ([agents.md](agents.md)), signed images ([boot.md](boot.md), D-028), and the approval pager ([approval.md](approval.md)).
- **Implementation:** **planned**: the bundle and its checks (#336), `trust`'s dry run and load (#337), the runtime under loaded policy (#338), and the `policy` test kernel (#339). The gate is #340.

## 2. Context

What exists at M6.4 (checked at `62f52cd`):

- **Compiled policy.** The runtime's policy tables are `const` slices of `manifest::Entry` in `user/programs/src/bin/agents.rs` (`BOOT`, `TEST`, `BUDGETS`, `HTTPS_TABLE`, `GUEST_TABLE`); its argument picks one (0–5). Every entry is `'static`, and every one names an owner (a compile-time assert).
- **Manifests are read once.** At its own start the runtime reads `agents/<name>.manifest` from the read-only image for each entry, checks it with `manifest::parse` and `Manifest::within`, and keeps the result as `Limits`. An attempt's start looks its `Limits` up; nothing is read again.
- **What a manifest can say.** Manifest v1 has 18 keys. An `Entry` has more that no manifest can express: `ask_models`, `ask_data`, `ask_net`, `ask_files`, `ask_knowledge`, the whole `budget` (its group too), `guest`, and `owner`. `within` checks every v1 key against the entry, except `approve`, which `parse` only checks against the manifest's own `https`.
- **Signed images.** `pharos-image`: a 128-byte header (magic `PHAROSIM`, version, length, SHA-256 of the body, Ed25519 over the first 64 bytes), `verify(file, key, min_version)`, `sign` for the host. `init`'s key comes from `PHAROS_IMAGE_KEY` at build time; `xtask` makes a test key under `target/xtask/keys/`.
- **The store.** The runtime holds `agents` (5, its own) and `system/incoming` (9, read-write); only `init` reaches `system`. Nothing puts a file into an existing store image from the host except internal test helpers (`store_image::put`); `store build` builds an image from a directory.
- **`trust`.** The approval pager (16 bytes a line, 16 lines a page, `show`/`more`, a hash line with 8 hex digits) and `ASK` over a buffer the runtime writes (D-037). Input lines are at most 64 bytes, output 256.
- **Audit.** Actions 1–31; details at most 64 bytes. The attempt's `start` record's detail is `owner <name>`.

## 3. Design

### Overview

1. The host writes a policy as text, signs it (`cargo xtask policy sign`), and puts it in the store at `system/incoming/policy` (`cargo xtask store put`).
2. On `trust`'s `policy` command, the runtime reads it, checks its signature and version, parses every entry, and checks each against its compiled entry: the ceiling. Anything that fails refuses the whole bundle, and `trust` says why.
3. If it passes, the runtime writes the diff against the policy in force as text, and asks `trust` with `ASK` (kind `Policy`). `trust` pages it as it pages a payload; the person types `yes <n> <8 hex>`.
4. On the yes, the runtime stores the bundle at `agents/policy`, records it, and uses it from each agent's next attempt.
5. At its start the runtime reads `agents/policy`, checks it the same way, and falls back to the compiled table, recorded, if it fails.

The runtime does the checks because it holds the compiled tables, the ceilings; `init` does not know them. It is already the component that checks every manifest against them.

### The bundle

- **Header:** the `pharos-image` header with magic `PHAROSPL` and its own key. `pharos-image` gains `verify_kind(file, magic, key, min_version)`; `verify` is it with `PHAROSIM`. The version is the policy's; the SHA-256 covers the body.
- **Body:** text, at most 64 KiB (16 slots of 4 KiB), the first line `policy = 1`. Then one section per agent, each starting `agent = <name>`, in the manifest's syntax (`key = value`, `#` comments, blank lines ignored).
- **Keys:** every manifest v1 key except `name` (the section's) and `program`, which must equal the compiled entry's, so it is not written; and the keys a manifest cannot have:
  - `ask_models`, `ask_data`, `ask_net`, `ask_files`, `ask_knowledge`, typed as the corresponding v1 keys;
  - `budget.cpu_ms`, `budget.tokens`, `budget.net_sends`, `budget.net_bytes`, `budget.data_kb`, `budget.file_kb`, `budget.messages`, `budget.knowledge`, `budget.rate`;
  - `approve`, as in v1, a mark per route.
  Every key is required in each section, so a section is a whole entry and the diff compares like with like. `owner`, `guest`, and `budget.group` are not keys: they stay the compiled entry's (an owner is D-038's record, and a group is code).
- **Agents:** the bundle lists exactly the agents that may run. Each must have a compiled entry; one with none is refused. An agent with a compiled entry but no section does not run under this policy (a narrowing, shown in the diff as `- <name>`).
- **Parsing:** `pharos_proto::policy::parse`, beside `manifest::parse`, with its rules: unknown, repeated, and missing keys refused, values range-checked, never panics. It returns owned entries (`policy::Entry`, owned names).

### The ceiling check

- `policy::Entry::within(&manifest::Entry)`: every field no larger than the compiled one, by the rules `Manifest::within` uses for the v1 fields, and the same subset and `<=` rules for the `ask_*` fields and every budget field. A route's `approve` mark may be raised, never lowered below the compiled route's mark or the manifest's.
- Over a ceiling, the whole bundle is refused, never narrowed: `policy: refused version <v>: <agent> <key> over its ceiling`.
- An agent's manifest is then checked with `within` against its policy entry, not its compiled one, when the bundle is checked and again at the runtime's start. A manifest over its policy entry refuses that agent's start, as today, recorded.

### Versions

- The version must be above the one in force (`agents/policy`'s, or 0 with none). Equal or lower is refused: `policy: refused version <v>: not newer than <w>`.
- The newest version applied is the one in `agents/policy`; there is no separate counter. The host, which can write the store offline, can roll it back; the host is trusted until M8.2.

### The key

- `PHAROS_POLICY_KEY` at build time, 64 hex digits, as `PHAROS_IMAGE_KEY`; with none, every bundle is refused (`no policy key`). The runtime compiles it in.
- `cargo xtask policy sign <TEXT> <OUT> --version <N> [--key <FILE>]`, with a test key at `target/xtask/keys/policy.key` made on first use, and the `policy` kernel's runtime built with its public half.
- A key apart from the release key and the image key, so whoever signs policy cannot sign code.

### Staging

- `cargo xtask store put <IMAGE> <STORE-PATH> <FILE>` puts one file into an existing store image (`store_image::put`, which the tests already use). D-039 called this `store import`; `put` says what it does.
- The bundle goes at `system/incoming/policy`, which the runtime reads through namespace 9. A compromised runtime could write there too; it gains nothing, as the signature is checked.

### The dry run and the diff

`policy` on the trusted console, logged in, asks the runtime (agents v1, new op `POLICY`). The runtime answers with a refusal line, or `ASK` kind `Policy` with the diff in the ask buffer. `trust` shows:

```text
ask #4: policy version 3 (sha256 1f0c9a2e…), now version 2; 2 widen, 1 narrows
| 0000 ! fetcher budget
| 0010 .tokens 4000 ->
| 0020 8000\x0a- fetcher
...
#4: 112 bytes, sha256 7a1b33c0; yes 4 7a1b33c0 / no 4
```

- The diff is the bytes the pager shows; it is text, one change a line: `! <agent> <key> <old> -> <new>` for a widening, `- ` for a narrowing, `+ <agent>` for an agent the policy adds, `- <agent>` for one it drops. Lines sorted by agent and key, so two runs give the same bytes.
- A change widens if the new value is not `within` the old one. The header line counts widenings and narrowings.
- No change at all is refused (`policy: version <v> changes nothing`), so a yes always changes something.
- A diff over the ask buffer (`trust::MAX_PAYLOAD`, 4 KiB) is refused (`policy: version <v>: the diff is too long to show; change less at once`), as a payload too long to show is (D-037).
- The approval digest is the diff's; the header line carries the bundle's version and SHA-256 prefix. The runtime keeps the bundle it diffed and applies only that bundle on a yes with that diff's digest.
- One approver, any logged-in person (open question 2). No answer in 60 s, or `no`, leaves the policy in force; recorded as for asks.

### Applying

- On the yes, the runtime writes the bundle to `agents/policy` (one store commit), records `policy applied version <v> <8 hex>`, and replaces its `Limits` from the new entries.
- **Running attempts keep their grants until they end** (open question 3). The new policy applies from each agent's next attempt. `stop <agent>` makes a narrowing immediate.
- If the store write fails, nothing changes and `trust` says so.

### At the runtime's start

- With `agents/policy` present: verify, version (any), parse, `within` every compiled entry, then every manifest within its policy entry. If the bundle fails, the compiled table is used and `policy refused <reason>; compiled` is recorded. It is not deleted: the next `policy` load replaces it.
- With none: the compiled table, as today.

### Audit

- A new action `POLICY` (32). Actor the runtime's service name; details: `offered <v> <8 hex>`, `refused <v> <reason>`, `applied <v> <8 hex>`, `compiled <reason>`.
- `trust`'s `approve`/`refuse`/`expire` records for the ask, as for every ask, with the person.
- The attempt's `start` detail becomes `owner <name> policy <v>`, or `policy compiled`.

## 4. Security

- **Never wider than the ceilings.** Every entry is checked against its compiled entry, and the whole bundle refused if any is over. A ceiling only changes with a reviewed build.
- **A stolen policy key** widens nothing without a person's yes, and nothing past the ceilings with it.
- **The person sees what changes**, from the runtime's diff, paged by `trust` as a payload is, and the yes names its digest.
- **Rollback:** an older signed bundle is refused online. Offline, the host can write the store; trusted until M8.2.
- **Limits:**
  - The runtime computes the diff and applies the bundle, so a compromised runtime can show one diff and apply another: the same limit as `send` (approval.md). It can also ignore policy altogether; it is in the trusted base.
  - A narrowing reaches a running attempt only at its next start, or by `stop`.
  - The owner, the group, and `guest` cannot change without a build.

## 5. Testing

| Where | What |
| --- | --- |
| Host | `policy::parse` (every key, refusals, never panics; fuzzed like `manifest::parse`); `within` for every field, `approve` marks raised and not lowered; the diff (widen and narrow per field, sorted, identical across runs); `verify_kind` with each magic; `cargo xtask policy sign` and `store put` round trips |
| QEMU, `policy` (#339) | An unsigned bundle refused; one signed with another key refused; an older version refused; one over a ceiling refused, not narrowed; the dry run lists exactly the changed grants; a widening applied only after `yes`; a `no` and no answer leave it unchanged; the next attempt runs under it (its `start` record names the version) and a narrowed agent's manifest is refused; a restart keeps it; a corrupted stored bundle falls back to compiled, recorded |
| CI | A throwaway branch that accepts an unsigned bundle must fail `policy` (run linked in the gate) |

## 6. Alternatives

- **`init` checks the bundle**, as it does images: it holds `system` and a key already, but not the ceilings, which are the runtime's tables. Moving the tables to a shared crate would let it; the runtime would still have to trust `init`'s check.
- **Only the keys that change in the bundle**: shorter files, but a missing key would mean "the compiled value", and the diff would compare a partial entry.
- **Running attempts narrowed at once**: revoking a granted model or file mid-attempt; possible (revocation exists, M3.4), but a policy load would then stop work unseen in the diff.

## 7. Open questions

**Decided (2026-11-28, #335):** 1. agents absent from the bundle do not run; 2. one approver; 3. running attempts keep their grants until they end; 4. `cargo xtask store put`.

1. **Agents absent from the bundle** do not run (recommended), or run under their compiled entry.
2. **Who approves:** one person (recommended for M6.6), or two people when it widens, as a route marked `two`.
3. **Running attempts:** keep their grants until they end (recommended), or are stopped when a narrowing touches them.
4. **`store put`** as a new host command (recommended), or staging only by `store build`.
