# Security review: M6.2 credential vault and egress gateway

- **Scope:** the new trust boundary for credentials ([gateway.md](../architecture/gateway.md), D-035):
  - the vault (`user/programs/src/bin/vault.rs`) and `pharos_proto::vault` (the `vault` v1 codec and the secrets file's parser);
  - the gateway (`user/programs/src/bin/gateway.rs`, its decisions in `user/programs/src/gateway.rs`), `pharos_proto::http`, and the `gateway` v1 codec;
  - the runtime's `REQUEST` and the `https` grant (`agents.rs`, `permission.rs`, `manifest.rs`);
  - the kernel's secrets file: `fw_cfg`, the `Secrets` capability, and `secrets_read`;
  - `init`'s vault and gateway entries and the route rules in `pharos-services`;
  - RSA and P-384 verification in `pharos-tls`'s provider.

  rustls, rustls-webpki, and the RustCrypto crates themselves are out of scope; how Pharos code uses them is in scope.
- **Design under review:** gateway.md, the threat model's "Credential vault and egress gateway (M6.2)" rows, D-035, and AGENTS.md sections 5 and 7.
- **Threat model:** four attackers, each alone:
  - a malicious agent, sending any bytes to the runtime, with any granted routes;
  - the remote server and the network, which control every byte of every answer;
  - a compromised client of the gateway or the vault other than the one a route names;
  - a compromised TLS or network service.

  An attacker wins in any of these cases:
  - an agent or a model gets any byte of a secret, through its memory, an answer, a content type, an error, a status, a length, or an audit record;
  - a request reaches a destination, method, or path outside a route the agent was granted;
  - a header is injected or a request smuggled;
  - a secret reaches the store, the trail, the console, or any process other than the vault, the gateway, and the TLS service;
  - a request is sent with no stored intent, or with a false outcome;
  - a secret stays in memory longer than the design says;
  - the vault or the gateway crashes or hangs, or one client holds it.
- **Dates:** 2026-11-24, milestone M6.2. Code under review: `main` at `6b07686`.
- **Status:** **signed off by the maintainer on 2026-11-24** (the M6.2 gate, #285), with the severities as proposed and #286–#293 filed rather than fixed before the gate. Findings F1–F4 are fixed.

## Reviewers and their independence

Neither reviewer was given the CHANGELOG, the roadmap, the earlier reviews, or the main session's view. Both followed one written method:
1. the attack surface;
2. every untrusted input traced to its use;
3. every `unsafe` invariant;
4. the secret's lifetime: every copy, and where it is erased;
5. the HTTP code against RFC 9112;
6. limits, timeouts, and waits;
7. the audit records.

Each finding had to quote code with `file:line` and give a trigger, or be marked unconfirmed.

| Reviewer | Family | Independence |
| --- | --- | --- |
| gemini-3.8-flash (GitHub Copilot CLI 1.0.114, read-only: shell, write, and URL tools denied) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks. Its R-1 quote does not match the source (it cites a `decimal(...)` call and an array `concat` in `vault.rs` that are not there), but the finding is real in the code as written |
| Claude (a separate agent, Claude Code; it could run host tests and compile scratch programs, not edit the repository) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method |

The main session (Claude Code, which wrote the code) checked each finding against the code before fixing or filing it. Gemini found 2 findings (Medium and Low); Claude found 11 (6 Low, 5 Info). Neither found anything Critical or High.

## Findings fixed

| ID | Proposed severity | Found by | Finding | Test (fails without the fix) |
| --- | --- | --- | --- | --- |
| F1 | Low (Gemini R-2, Claude R-1) | both | Buffers were attached only at startup. After the vault or the TLS service restarted (both `Restart::Up(3)`), every release or TLS read and write answered `NO_BUFFER`. After the gateway restarted, the runtime's buffer was never attached again. Either way, HTTPS stayed down until reboot. It failed closed, with nothing leaked. Fixed: the gateway attaches its vault or TLS buffer again when either answers `NO_BUFFER` and asks once more; the runtime does the same with the gateway | `vault`: the kernel kills the vault and the TLS service, then the gateway, when the client names them, and checks that `init` restarted each before an `again` task gets its secret injected and stripped. Each of the three re-attaches removed alone fails the kernel |
| F2 | Medium (Gemini R-1) | Gemini | The vault's release record (`release <route> secret <name> status <n>`) was not cut to the audit limit of 64 bytes. With route and secret names of up to 32 bytes each, it can reach 91 bytes, so `audit::encode` refuses it, and every release of such a route answers `NO_AUDIT`. Only a compiled table can set the names, not an agent. Fixed: the detail is made in `pharos_programs::gateway::release_detail` and cut to 64 bytes, as the gateway's details are | `pharos-programs`: `a_release_record_always_fits` (two 32-byte names and a status) |
| F3 | Info (Claude R-7) | Claude | `http::strip` scans once, left to right, so a value sharing bytes with `[secret]` could survive whole: `]a` in `]aa` became `[secret]a`. A value made only of letters from `secret` (`cre`) could also survive. A value with `"` or `\` would be escaped in a JSON echo, and so not found. Fixed: a secret's value may not contain `[`, `]`, `"`, or `\`, and may not be part of `[secret]`. Without brackets, a value cannot overlap the text that replaces it, so one pass leaves no copy | `pharos-proto`: `no_valid_value_survives_stripping`: the cases above, and 100,000 random short values and answers over the letters of `[secret]`. The random part alone fails with the old rule |
| F4 | Low/Info (Claude R-4) | Claude | `secrets_read` zeroed its temporary copy of the file just before freeing it, which the optimizer may remove as a dead store. The reviewer compiled the same pattern at `opt-level=3`, and no `memset` was left. Fixed: `core::hint::black_box` after the fill, as the gateway's `erase` does | None: an elided store cannot be seen from a test. Filed with #286 |

## Findings filed

| Issue | Proposed severity | Found by | Finding |
| --- | --- | --- | --- |
| #286 | Low | Claude R-2 | When a server echoes the secret, the gateway's raw answer and its parsed copies are freed without zeroing. The last plaintext chunk stays in the TLS buffer, and `write_bytes` leaves a stack word. Nothing reaches an agent, but "parsed with no secret in memory" is false for an echo |
| #287 | Low | Claude R-3 (race not reproduced) | A vault reply that arrives after the gateway's 1 s timeout leaves the secret in the vault buffer, and the trail records a release that was never used |
| #288 | Low | Claude R-5 | The vault and the gateway find a route by index, each in the table its own `arg` names, and nothing checks the two agree. A table mistake could put a route's secret toward another route's destination |
| #289 | Low | Claude R-6 (unconfirmed), R-1 | The runtime's 35 s wait leaves about 1 s over the gateway's worst case. A restarted gateway attaches with a blocking `send` |
| #290 | Info | Claude R-8 | A long intent detail is cut, and the path with it |
| #291 | Info | Claude R-9 | A malformed gateway or vault request is answered but not recorded |
| #292 | Info | Claude R-10 | An `HTTP/1.0` answer with `Transfer-Encoding: chunked` is accepted |
| #293 | Info | Claude R-11 | A request that was sent but whose answer was refused is recorded the same as one never sent |

## Checked and found correct

Both reviewers checked these and found them correct; where only one did, its name follows.

- **The secrets file:**
  - Only `init` gets `Secrets`, and only as `READ | GRANT`. The table rules give it only to the vault, only `READ`, and never twice. `init` only asks for the size.
  - The parser enforces its limits (16 secrets, 4 KiB, the name and value sets, a newline on every line, no name twice), and reports a fault by line number only.
- **Access:**
  - The vault answers only the gateway's badge.
  - The gateway checks the client against each route.
  - The runtime checks the agent's `https` grant before the budget and the intent. The grant cannot be asked for, and a manifest can only narrow it.
- **The request:**
  - The method, `Host`, the fixed headers, the secret's header, and `Content-Length` all come from the route or the gateway.
  - A path matches its pattern segment by segment, with only unreserved bytes allowed. `.`, `..`, empty segments, `%`, `#`, a space, CR, and LF are all refused.
  - A secret's value is visible ASCII only, so it cannot inject a line.
  - The agent's bytes are copied once at each hop, so there is no gap between checking and use (Claude).
- **The answer (RFC 9112):**
  - The head is at most 8 KiB and 64 lines, with strict CRLF and no obsolete folding.
  - A body with two lengths, or with `Content-Length` and `Transfer-Encoding` together, is refused. Only the coding `chunked` is accepted, and no `Content-Encoding` but `identity`.
  - Bodies are checked exactly. Chunks and their trailers are validated, and trailers are then dropped.
  - A body that runs to the close needs `close_notify`.
  - Stripping runs on the decoded body, so a secret split across chunks is still found. A content type that holds the value is dropped.
- **The secret's lifetime (apart from F4, #286, and #287):**
  - The secret and the request bytes are erased with `black_box`.
  - The vault buffer is zeroed after each read, and the TLS buffer after the write.
  - Both releases are erased on every error path.
  - Nothing unstripped is ever returned.
- **Limits and waits:**
  - Every IPC call has a timeout, and every TLS call is bounded by the 30 s deadline.
  - The read loop is capped, and route limits are at most 60 KiB.
  - No index on untrusted input can panic, and every loop is linear (Claude).
  - Reply capabilities are one-shot, so a stale reply cannot be taken for a later call's (Claude).
- **The audit trail:**
  - The intent is recorded before the release, the connection, and the write, and the outcome before the answer is written back.
  - The vault records each release or refusal before writing its buffer.
  - No record holds a value. Details carry names, lengths, statuses, a body hash, and the path.
- **`unsafe`:** the only block in scope is `fw_cfg_file` in `arch/x86_64.rs`. Its port reads are bounded by the buffer, and its `SAFETY` comments hold (Claude). No user-space code in scope has any (Gemini).
- **The TLS provider:**
  - RSA keys must be 2,048 to 4,096 bits. PKCS#1 v1.5 and PSS use SHA-256, -384, or -512, never SHA-1, and PSS takes the hash's length as its salt.
  - P-384 is ECDSA with SHA-384 over DER signatures.
  - The algorithm identifiers are mapped correctly.

## Gate evidence (#285)

| Criterion | Evidence |
| --- | --- |
| `vault` in CI | `vault` passed in the CI `qemu` job on `main` at `6b07686` ([run 45245101366](https://github.com/codeaiforge/pharos-os/actions/runs/45245101366)); with this review's fixes it passed locally (15.3 s) |
| The fuzzers run in CI for their budget without findings | Same run, both host jobs: the #283 fuzz tests for answers, paths, request heads, the `gateway` codec, secrets files, and `https` permissions and manifests |
| The throwaway branch where the gateway echoes the injected header failed CI | `throwaway/gateway-echo-header` at `e2abeb6` ([run 45347753416](https://github.com/codeaiforge/pharos-os/actions/runs/45347753416)): the `vault` kernel failed at the fetcher's echo check (QEMU shard 4), and `the_answer_is_stripped_and_its_type_dropped_if_tainted` failed in the host and Rust 1.91 jobs; the branch is deleted (#285 comment) |
| A security review independent of the authoring agents, no open critical or high finding | This report. Nothing Critical or High was found. Gemini's one Medium finding (F2) is fixed |
| The maintainer approves | Approved 2026-11-24 |
