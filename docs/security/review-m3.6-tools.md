# Security review: M3.6 controlled tool integration

- **Scope:** everything M3.6 added to `pharos-proto`, the agent runtime, `trust`, and `init` since commit `de411ea` (the M3.5 gate):
  - D-023 and the design, [tools.md](../architecture/tools.md) (#123, #124);
  - the tool-call parser and validator, `pharos_proto::tool`, and its injection corpus (#125);
  - the `TOOL` request, `pharos_programs::tools::plan`, and the tool lists in the policy table and manifests (#126);
  - `read_file`, the `file <name>` permission, the `files` namespace, and the `file_kb` budget (#127);
  - confirmation of `send` on the trusted console, `CONFIRM`, `PENDING`, and `REFUSED` (#128);
  - the `tools` and `injection` test kernels (#126–#129);
  - each tool's permission requirements, and every new `unsafe` block.
- **Design under review:** [tools.md](../architecture/tools.md), D-023, D-012, D-018, [capabilities.md](../architecture/capabilities.md).
- **Date:** 2026-11-05, issue #130. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. The one finding is fixed.
- **Status:** **approved** by the maintainer on 2026-11-05 (M3.6 gate, #130).

## Method

1. Listed every changed file since `de411ea` and searched the diff for new `unsafe` blocks: none.
2. Followed a `TOOL` request from the agent's buffer to the store or the network service, checking where each byte is copied, checked, and used, and what each refusal returns and records.
3. For each tool, listed the permission it needs and what it can reach with it.
4. Followed a confirmation from the first call to every way it can end: a yes, a no, no answer, `trust` unreachable, the task ending, a revocation, and a different call meanwhile.
5. Checked every message that now carries a `file` permission (up to 34 bytes) against its buffer.
6. Turned each finding into a check that fails without the fix.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | Revoking a destination while a `send` to it waited for the user did not end the confirmation: it stayed on the trusted console until the agent repeated the call or the 60 s passed. A yes then sent nothing (the grant is checked first on every repeat), but the console showed a request that could no longer happen, and D-012 item 8 has a revocation end what was opened with the permission at once. | **Fixed:** `revoke` ends a waiting confirmation for what it takes away, as it ends an inference session (`confirm #<n>: refused`). In the `tools` kernel the agent waits 2 s before repeating the call, and the runner checks the confirmation was refused within 1 s of the revocation; without the fix the console never shows `confirm #5: refused` in order and the check fails. |

## The parser and validator

- **Bounded and allocation-free:** at most 1 KiB in, 8 arguments, 512 bytes a string, keys of at most 32 bytes; unescaped output is never longer than its input, so the 1 KiB scratch buffer always suffices. The text is checked as UTF-8 first (overlong forms and surrogates refused).
- **No two readings of one text:** duplicate keys at either level, keys written with escapes, and anything after the object are refused, so a call cannot carry a second tool name or argument that another parser would read (corpus: `name` twice, `name`, two calls in a row).
- **No control characters in any string,** written or escaped (tab, CR, and LF only, escaped), so nothing a call carries can drive a terminal.
- **Validation runs on the parsed form,** never on the text, and every schema argument is required.
- **Evidence:** host tests for every rule and every truncation, 10,000 round trips, 1,000,000 fuzzed texts, a corpus of 48 calls, ten mutations caught (#125); on Pharos, the `injection` kernel runs 15 of them through the runtime.

## The `TOOL` path

- **Copied before use:** the call is copied out of the agent's shared buffer into the runtime's memory before it is parsed, and a waiting confirmation is compared against the runtime's copy, so the agent cannot change a call between check and use.
- **Order of checks:** the tool list, then the one permission the call needs, then the budget, then (for `send`) the user, then the audit intent; nothing runs if a check fails, and a refused call costs nothing but its place in `rate`.
- **Existence is not revealed:** an ungranted file is refused before the store is asked, so `NO_ACCESS` says nothing of whether it exists.
- **Refusals cannot flood the trail:** each kind is recorded once per attempt (the `injection` kernel's 122 refused calls make 6 records and a total).
- **A tool adds no authority:** `read_file` reaches only files named by `file` grants, `send` only destinations named by `net` grants, which `SEND_TO` already allowed; the network service still checks the runtime's destinations.

## Each tool's permission requirements

| Tool | Needs | Reaches | Sensitive | Reviewed |
| --- | --- | --- | --- | --- |
| `read_file` | `file <name>`: one name, no `/`, in the read-only `files` namespace | that file's bytes, at most 64 KiB, into the agent's buffer; charged to `file_kb` | no: the grant is the user's consent | yes |
| `send` | `net <a.b.c.d>:<port>` | one datagram of at most 248 bytes to that destination, on the runtime's port; charged as `SEND_TO` | yes: the user confirms each call | yes |

## Confirmation

- **The prompt is the runtime's and `trust`'s:** `CONFIRM` carries numbers and the policy entry's name only; `trust` writes the text. The `injection` kernel's agent logs a copy of the prompt and sends a payload that reads like an answer; neither reaches the trusted console, and its own `ANSWER` is `NO_ACCESS`.
- **A yes runs that call once,** compared byte for byte with the call the user was asked about; a different call while one waits is `BUSY`; a repeat after it ran is asked again.
- **Every other ending is a no:** `no`, no answer within the approval timeout, `trust` unreachable, the task ending, or (since F1) a revocation.
- **Numbering is shared with approvals,** and both count against the 4 waiting places and the one per agent (#117).

## Messages carrying a longer permission

A `file` permission takes up to 34 bytes on the wire instead of 7. The longest audit record is now 199 bytes, within the store's 200-byte inline limit (a test checks the bound is exact). `APPROVE` (79 bytes), `REVOKED` (70), and the runtime's other messages to `trust` fit its 96-byte buffer. **Note:** `trust` encodes its requests to the runtime in 64 bytes, and a `REVOKE` with a 32-byte agent name and a 32-byte file name would need 69; the trusted console's 64-byte typed line limits the two names to 52 bytes together (57 on the wire), so it cannot happen today. Both grow together if the line limit is raised.

## IPC round trip

M3.6 changed no kernel code. `cargo xtask bench-ipc` under KVM, 100,000 round trips per run, pinned to one host CPU: 5 runs at the gate, run medians 1,889 to 1,932 ns, **median 1,907 ns**, within D-004's 2,000 ns budget (1,935 ns at the M3.5 gate).

## `unsafe` added in M3.6

None. The parser, the planner, and the runtime's tool code are in crates and programs that forbid `unsafe`.

## Accepted limits (tracked)

- **The boot runtime has neither its network nor its files handle:** `init` passes a service at most 8 capabilities (`spawn`'s limit), found in #127; harmless while the boot policy table runs no agent, and to be fixed before it does ([threat model](threat-model.md)).
- **A granted file reaches the model in full,** so a model can be steered by what it reads; the defense is that the agent can do nothing beyond its grants, and `send` asks first.
- **The user sees a `send`'s destination and size, not its payload** (the maintainer's choice at this review, closing the design's open question): no byte an agent or model controls reaches the trusted console, at the cost of the user not seeing what leaves.
- **The budget is charged when a confirmed call is sent,** not before asking; a call the user confirmed can still be refused `OVER_LIMIT`, and a yes is used up by a send the network service refuses.
- **`file_kb` is charged before the store read** and not given back if the read fails.
- **The test model writes no tool calls,** so on Pharos the calls a model would write are given by the test agent; the scenario model's own tool calls are not exercised in CI.
