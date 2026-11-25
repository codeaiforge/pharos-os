# Security review: M6.1 TCP and TLS

- **Scope:** the new trust boundary for TCP, TLS, and certificate validation ([tls.md](../architecture/tls.md), D-034):
  - `crates/pharos-tls`: the root file, the configuration, the crypto provider, the HMAC-DRBG, and the session;
  - the TLS service (`user/programs/src/bin/tls.rs`) and its virtio-rng driver;
  - the network service's TCP part (`user/programs/src/bin/net.rs`);
  - the `tls` v1 codec and the TCP part of `net` v2;
  - `entropy` and `_Unwind_Resume` in `pharos-user`'s `syscall.rs` (new `unsafe`);
  - `clock_real` and the date floor in the kernel;
  - `init`'s TLS endpoint and `allow_tls`, and the TLS entries of the service tables.

  rustls, rustls-webpki, smoltcp, and the RustCrypto crates themselves are out of scope; how Pharos code uses them is in scope.
- **Design under review:** tls.md, the threat model's "TCP and TLS (M6.1)" rows, D-034, and AGENTS.md sections 5 and 7.
- **Threat model:** three attackers, each alone:
  - the network, which controls every byte from `10.0.2.2` and beyond, certificates included;
  - a compromised client of the TLS service;
  - a compromised network service.

  An attacker wins if a certificate that should be refused passes, if a client reaches another client's connection or a destination it was not given, if the network service sees plaintext, if a connection has no stored intent or a false outcome, if the generator is predictable, or if either service crashes, hangs, or is held by one client.
- **Dates:** 2026-11-23, milestone M6.1. Code under review: `main` at `c71ee65`.
- **Status:** **signed off by the maintainer on 2026-11-23** (the M6.1 gate, #274), with the severities as proposed and #275–#278 filed rather than fixed before the gate. Findings F1–F5 are fixed.

## Reviewers and their independence

Neither reviewer was given the CHANGELOG, the roadmap, the earlier reviews, or the main session's view. Both followed one written method:
1. attack surface;
2. every untrusted input traced to its use;
3. every `unsafe` invariant;
4. the certificate path;
5. the cryptography glue against the algorithms;
6. limits, timeouts, and waits;
7. the audit records.

Each finding had to quote code with `file:line` and give a trigger, or be marked unconfirmed.

| Reviewer | Family | Independence |
| --- | --- | --- |
| gemini-3.8-flash (GitHub Copilot CLI 1.0.114, read-only: shell, write, and network tools denied) | Different family (Google) | **Independent of the authoring model**, as M5.4's minimum asks. Several of its quotes do not match the source (it cites `net::decode_count`, `finish(i, c, why)`, and `refusal::CLOSED`, which do not exist), but each of its four findings matches real code that the other reviewer quoted correctly |
| Claude (a separate agent, Claude Code; it could run host tests, not edit) | Same family as the authoring model | **Not independent**: it saw only the code, the design, and the method |

The main session (Claude Code, which wrote the code) checked every finding against the code before fixing or filing it. Severities below are as proposed; where the reviewers differed, both are given.

## Findings fixed

| ID | Proposed severity | Found by | Finding | Test (fails without the fix) |
| --- | --- | --- | --- | --- |
| F1 | High (Gemini R-3), Medium (Claude R-1) | both | The TLS service used the count in a `TCP_POLL` reply without checking it against the 8 KiB it asked for (`pull` in `tls.rs`). A compromised network service could crash the service: an out-of-bounds read of its 64 KiB buffer panics, a count of `u32::MAX` fails the allocation, and the same reply after each restart leaves it down. A count within the buffer but over the window fed another connection's bytes into the session. Fixed: a count over the window is a TCP error, and a `TCP_WRITE` count over what was sent ends the push | `tls` (#277): `proxy` answers destination 6's `TCP_POLL` with a count of `u32::MAX`; the `OPEN` must be refused `HANDSHAKE`/TCP and the service still answer (without the fix the service stops, and the `OPEN`'s 5 s wait fails the check) |
| F2 | High (Gemini R-1), Medium (Claude R-2) | both | A refused TCP connection was kept until its client polled it. `TCP_CLOSE` could not remove it, because the lookup skipped refused connections, yet it still counted toward the client's limit of 4. A TLS client that closed an `OPEN` in the window between the refusal and the next poll, or a TLS service that restarted while connecting, leaked a slot at the network service for good. After four, every TLS `OPEN` failed until the network service restarted. Gemini's trigger, through the service's own close after a poll, does not happen, because the poll removes the connection; Claude's race does. Fixed: `TCP_CLOSE` removes a refused connection, and one that is neither polled nor closed expires after 10 s | `network`: `tcper: a refused TCP_CONNECT closed unpolled frees its slot, five times` (fails without the fix) |
| F3 | High (Gemini R-2), Low (Claude R-4) | both | No idle timeout held for a TLS connection. Every `TCP_POLL` refreshed the network service's 60 s idle clock, and the TLS service polls every 10 ms, so it never fired. The TLS service had none of its own, so a silent server held a client's `READ` forever, and a client that died left its connections, live or ended, in the service's 4 slots. Two dead clients blocked every other client. Fixed: the TLS service closes a connection with no client request and no data from the server for 60 s, and `TCP_POLL` counts as activity only when data moves | `tls` (#277): the table sets the idle limit to 3 s; a connection left alone for 4.5 s must answer `READ` with `CLOSED` (fails without the idle close) |
| F4 | Medium (Gemini R-4), Low (Claude R-3) | both | `CLOSE` during a handshake answered the waiting `OPEN` with `HANDSHAKE`/`PROTOCOL`, which was false, and wrote no outcome for the intent, so the trail never said how the attempt ended. Fixed: the outcome `closed` is recorded, and the `OPEN` is answered `CLOSED` | `tls`: destination 4 (a host listener that never answers) is opened with a 1 ms timeout and closed during its handshake; the runner requires the outcome `closed` (fails without the fix) |
| F5 | Info (Claude R-7) | Claude | The success outcome was written with `let _`, so a handshake whose outcome could not be stored still opened. Fixed: no stored outcome, no connection (`NO_AUDIT`), as with the intent | `tls` (#277): `proxy` refuses destination 5's success outcome; the `OPEN` must be `NO_AUDIT`, and the runner finds its intent with no outcome (fails without the fix) |

The `MAX_PLAIN` comment, which said "Encrypted bytes" although the limit is on plaintext (Claude R-7), is corrected.

## Findings filed

| Issue | Proposed severity | Found by | Finding |
| --- | --- | --- | --- |
| #275 | Low | Claude R-5 | One client looping `OPEN` and `CLOSE` writes 2 to 3 records each time, with no rate limit. Once the trail is full, every audited action in the system fails |
| #276 | Info | Claude R-6 | The kernel's date floor is the fixed default (2025-10-26) unless `SOURCE_DATE_EPOCH` is exported at build time. `cargo xtask` passes it only to `xorriso`. The floor still stops a reset clock |
| #277 | — | main session | Regression tests for F1, F3, and F5 |
| #278 | Info | Claude R-7 | The virtio-rng DMA page keeps the last seed's bytes after it is copied out |

## Checked and found correct

Both reviewers checked these and found them correct; the line names where only one did.

- **Certificates:**
  - The root file parser keeps its limits: 16 roots and 16 KiB, every length checked, no overflow.
  - The configuration is TLS 1.3 only, with one suite, no resumption, and no early data.
  - Only the destination's name from `init` is checked, and SNI is sent.
  - The mapping of rustls errors to reasons is right.
- **Cryptography:**
  - AES-128-GCM's nonce is the IV XOR the sequence number, as RFC 8446 says, and the record header is its AAD.
  - An all-zero X25519 result is refused, and a P-256 share must be an uncompressed point.
  - ECDSA signatures are DER-decoded, and malformed keys are refused.
- **The generator:**
  - HMAC-DRBG matches SP 800-90A: instantiate, reseed, generate, and its budgets.
  - It is reseeded before every handshake from virtio-rng and RDSEED.
  - `SharedDrbg` fails closed when busy, so two callers never get the same bytes.
- **Access:**
  - `ALLOW` is taken only on badge 0.
  - A client opens only by index into `init`'s list, and never names a host or a server name.
  - Clients are kept out of each other's connections and buffers.
- **The audit trail:** the intent is stored before any TCP, and no plaintext is recorded.
- **The session:** an error is final, and nothing can be read or written after it.
- **`unsafe`:** the invariants of `has_rdseed`, `rdseed64` (retry on a clear carry), and `_Unwind_Resume` (exit 101) hold.
- **The clock:**
  - A date before the floor is refused, and `clock_real` answers `NOT_FOUND` without one.
  - The TLS service then answers `NO_CLOCK`.
- **Replies:** one-shot reply capabilities mean a late reply cannot be taken for a later call's (Claude).
- **virtio-rng:** used elements are checked, and a fill has a deadline (Gemini).
- **The network service:** its TCP limits and buffer checks (Claude).

## Gate evidence (#274)

| Criterion | Evidence |
| --- | --- |
| `tls` in CI | `tls` and `tls_norandom` passed in the CI `qemu` job on `main` at `c71ee65` ([run 45131592671](https://github.com/codeaiforge/pharos-os/actions/runs/45131592671)) |
| The fuzzers run in CI for their budget without findings | Same run, both host jobs: TCP (200,000 frames), TLS flights (100,000), certificates (100,000), root files, and the `tls` and `net` codecs |
| The throwaway branch that skips the name check failed CI | `throwaway/tls-no-name-check` at `1a76bf1` ([run 45131765126](https://github.com/codeaiforge/pharos-os/actions/runs/45131765126)): the `pharos-tls` host test and the `tls` kernel failed at the name check; the `network` kernel's failure is a side effect of the mutation (#274 comment) |
| A security review independent of the authoring agents, no open critical or high finding | This report. Gemini's three High findings (F1, F2, F3) are fixed; nothing Critical was found |
| The maintainer approves | Approved 2026-11-23 |
