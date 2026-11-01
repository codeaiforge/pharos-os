# Security review: M3.2 local inference

- **Scope:** everything M3.2 added at the boundaries between clients, the inference service, the storage service, model files, and the kernel (since commit `4002e80`, the M3.0 gate):
  - the inference service `bin/infer`, its manifest (`pharos_programs::models`), and its place in `init` (#88, #89);
  - interface `inference` version 1 and the shared codecs in `pharos-proto` (D-019, #92, #88);
  - model loading: the read through the store window, size, SHA-256, the GGUF reader, the engine loader, and the configuration check;
  - the tokenizer (#84) and batched prompts (#85, #90), which handle client text and model data;
  - system call 24 `uptime` (D-021) and the held-locks counter change (#81);
  - every new `unsafe` block.
- **Design under review:** [inference.md](../architecture/inference.md), D-019, D-021, D-010, D-011.
- **Date:** 2026-11-01, issue #91. Reviewer: AI-assisted (Claude Code), with code reading and a test for each claim. The finding was fixed in the same issue.
- **Status:** **approved** by the maintainer on 2026-11-01 (M3.2 gate, #91).

## Method

1. Listed every changed file under `kernel/`, `user/`, `crates/`, and `xtask/` since `4002e80`, and searched the diff for new `unsafe` blocks.
2. Followed every value a client sends (each request field, the badge, the attached buffer and its length, the capability on each message) from `receive` to its last use in `bin/infer`.
3. Followed a model file from the store to the engine: what is checked before any byte is parsed, and what the store or a client can still change afterwards.
4. Listed what the service allocates or keeps per request, per client, and per model, and the limit on each.
5. Checked every capability the service receives is either kept on purpose or deleted, and compared the handles it holds after both test clients with `init`'s table.
6. Turned the finding into a check that fails without the fix, and mutation-checked it.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | One client could erase another's record. The service kept only the last ended session's `RESULT` record, and the next `GENERATE` from any client cleared it, as the design said. A second client starting a session between the first's last `NEXT` and its `RESULT` left the first with `NO_SESSION`. The record is what M3.4's audit trail will store, so one agent could hide another's inference from it. | **Fixed:** each client's record is kept with its buffer slot until that client's next session ends; an attach that replaces the client's buffer keeps it. `inference` test (failure client): a record survives a second client's session. Mutation-checked (another client's session clears the record: 2 checks fail). |

## The service's inputs

- **Requests** are parsed by `pharos_proto::infer::parse`: version first, exact lengths, no trailing bytes (`BAD_REQUEST`), other versions refused with the supported range. The codec is host-tested and fuzzed. Badge 0 gets `NO_ACCESS`.
- **Capabilities on messages:** an `ATTACH` capability is mapped read-only (at most 64 KiB) and then deleted; the capability on a `call` is the one-shot reply capability, answered with a non-blocking send and deleted. Every other capability is deleted unused. The `inference` test checks that the service holds exactly its four granted handles and its own reply endpoint after both clients.
- **The prompt** is copied out of the shared buffer before it is checked as UTF-8 and tokenized, so the client cannot change it while the service works. `prompt_len` is checked against the client's own buffer (`NO_BUFFER`) and 64 KiB (`TOO_LARGE`); `max_new` against 2,048.
- **Context:** the prompt's tokens plus `max_new` are checked against the manifest's context (2,048 for S1) before the session allocates its cache, which is sized from them (at most 48 MiB). `Session::new` checks the same bounds and every token ID again.
- **Sessions** belong to a badge and a number; another client's `NEXT`, `CANCEL`, and `RESULT` get `NO_SESSION` (tested). A session with no `NEXT` for 10 s is cancelled.
- **Replies** are at most 256 bytes; `NEXT` returns at most 240 bytes of text and keeps the rest for the next call.

## Model loading

- **Only manifest models load.** The manifest is compiled in; a client names a model by number only. Each entry pins the file's size, SHA-256, and every configuration value.
- **The file is checked before parsing.** The store's size comes first (`MODEL_INVALID`, step size). The whole file is then copied out of the 16 MiB window into private memory, and only that copy is hashed and parsed, so the store cannot change bytes after the hash. Memory for the file is reserved with `try_reserve_exact`, so a failure answers `MODEL_INVALID`, step read, instead of ending the service.
- **The parsers are checked and fuzzed.** The GGUF reader checks every count, length, offset, and tensor shape (20,000 fuzzed files); the tokenizer checks its vocabulary and merges (25,000 fuzzed texts and merge lists). Host tests feed `models::verify` and `open` a changed byte, short and long files, six malformed files whose hash matches their entry, and a wrong configuration, and each is refused at its step (#89).
- **The window** is mapped once and shared with the storage service; the service deletes the `Memory` capability after sending it (#89) and reads the window only through `Mapped`'s volatile copies.

## The kernel

- **`uptime` (24)** takes no arguments and returns microseconds since boot. It needs no capability: `rdtsc` and timeouts already let a program measure time (D-021, and the `rdtsc` limit below).
- **The held-locks counter (#81)** is updated with a plain load and store instead of an atomic add. It changes only inside `IrqMutex::lock` and the guard's drop, both with interrupts disabled, on one CPU, so no update can be interrupted. Host tests, which lock from several threads, keep the atomic add. The single-CPU assumption is already a carried limit.

## `unsafe` added in M3.2

None. `pharos-infer` and `pharos-proto` forbid it; the inference service and its client use only `pharos-user`'s safe interface. No hand-written SIMD was added (#86).

## Accepted limits (tracked)

- **A long prompt holds the service.** The prompt is processed in one step before `GENERATE` answers: the 233-token S1 prompt takes 6.3 s on Pharos under KVM, so a prompt near the 2,048-token context takes about a minute or more. Other clients' calls meanwhile wait and time out instead of getting `BUSY`. One session at a time on one CPU is the design; carried to M3.5 with per-agent token and time budgets.
- **A failed load is kept until the service restarts.** A store error or timeout while reading a model (step read) marks the model failed, like a hash failure. Restarting the service is M3.3.
- **Clients are never forgotten:** at most 8 badges hold a buffer slot, and a slot stays after its client ends, as in the storage service. Only `init` hands out the capability, and it gives no client one in M3.2. Carried to M3.3.
- **A loaded model stays in memory** until the service ends, so a manifest entry that passes the hash and then fails the configuration check leaks its file. Only a wrong manifest entry can cause it.
- **The record is not yet stored anywhere.** The client gets it with `RESULT`; M3.4's audit trail stores it.
