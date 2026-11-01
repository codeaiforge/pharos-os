# Local inference

## 1. Status

- **Design:** **Accepted**: reviewed and approved by the maintainer on 2026-10-31 (issue #83). It follows [D-010](../project/decision-log.md#d-010-ai-inference-runtime-model-formats-and-licensing), [D-011](../project/decision-log.md#d-011-cpugpu-support-and-memoryvram-constraints), and [D-019](../project/decision-log.md#d-019-service-interfaces-and-versioning), and builds on M3.0 ([user-environment.md](user-environment.md), [storage.md part 8](storage.md#8-the-writable-store-m30)).
- **Implementation (#88):** **implemented**: the service (`user/programs/src/bin/infer.rs`), the manifest (`pharos_programs::models`), the interface (`pharos_proto::infer`), generation sessions (`pharos_infer::session`), the test model (`pharos_infer::synth::test_model`), `init` starting the service at boot, and the `inference` test kernel. Where it differs from the text below, it says so. The failure tests are **implemented** (#89, section 5).
- **Implementation:** the tokenizer is **implemented** (#84: `crates/pharos-infer/src/bpe.rs` and the generated `unicode.rs`; identical to `llama-tokenize` on 40 of 40 cases, [inference-evaluation.md](../project/inference-evaluation.md)). The interface crate `pharos-proto` exists (#92). **Planned:** the rest of M3.2 (#85–#91).

## 2. Context

M3.1 chose our own engine, `pharos-infer` (`no_std`, safe Rust, no dependencies), GGUF with Q8_0 weights, and Qwen2.5-0.5B-Instruct q8_0 for scenario S1 (D-010). On the host it generates 13.7–14.6 tokens/s on one thread against S1's target of 5. But it reads a prompt one token at a time, so the 233-token S1 prompt takes about 16 s against the 10 s first-token target. It also takes prompts only as token IDs from llama.cpp (#69).

M3.0 gave Pharos what the engine needs: SSE2 in user programs, 1 GiB in one process, the 676 MB model file read from the store into a process, and timeouts (#74–#80). D-019 fixed how services talk: a shared codec crate, `pharos-proto`, a version and operation on every message, common status codes, `INFO` and `ATTACH`, and long results pulled with `NEXT` and `CANCEL`.

M3.2 must deliver an inference service on Pharos that:

- produces output from a supported model;
- refuses unsupported models and configurations, and model files that fail their integrity check, with clear errors;
- stays within its memory limit;
- holds no privileges beyond its capabilities;
- leaves callers with an error, not a hang, when it is down.

Scenario S1 later gives an agent "an inference capability with a budget" (phase3-requirements.md).

## 3. Design

### The engine (`pharos-infer`)

Three additions, all host work first (D-020), each compared with llama.cpp or with the engine's own earlier output:

- **Tokenizer (#84).** Qwen2's byte-level BPE, from the GGUF file's `tokenizer.ggml.tokens`, `merges`, and token types:
  - a pre-tokenizer that splits text as Qwen2's pattern does: contractions, letter runs, single digits, punctuation runs, and whitespace;
  - byte-level encoding, BPE merges by rank, and special tokens matched as whole strings (`<|im_start|>`, `<|im_end|>`, `<|endoftext|>`).

  Unicode letter and number classes come from `core`'s `char::is_alphabetic` and `is_numeric`, which differ slightly from the pattern's `\p{L}` and `\p{N}`. The test corpus includes text where they differ, and every mismatch with llama.cpp's `llama-tokenize` is a failure until explained. Vocabulary and merges are untrusted input: checked before use and fuzzed.
- **Batched prompts (#85).** The prompt is processed in blocks of up to 32 tokens: each weight row is read once per block instead of once per token. The S1 prompt then needs 8 passes over the weights instead of 233. Each output value is still computed with the same operations in the same order as on the single-token path, so the generated tokens stay bit-identical; the tests compare both paths. *Implemented:* only the last token's logits are computed, and each weight block is widened to 16 bits once per block; the S1 prompt takes 8.4–9.0 s on the host instead of about 16 s (inference-evaluation.md).
- **No hand-written SIMD in M3.2 (#86).**
  - **The constraint:** explicit SIMD needs `unsafe` even on the newest Rust. Checked with Rust 1.99 on 2026-10-31: calling a function marked `#[target_feature(enable = "sse2")]` from ordinary code is `unsafe`, even though SSE2 is always present on x86-64, and SIMD loads through pointers are always `unsafe`. `pharos-infer` forbids `unsafe`.
  - **Why it is not needed:** the host measurement (13.7–14.6 tokens/s) was compiled for the same SSE2 baseline as Pharos user programs, with the compiler vectorizing the Q8_0 dot products. Generation already meets S1 almost three times over, and batching addresses the first-token time.
  - **What #86 becomes:** it measures the engine on Pharos (#90) and adds SIMD only if a target is missed. The options then are a second build of the service for `x86-64-v3` (AVX2 and FMA), chosen when it starts, in safe Rust; or a small reviewed `unsafe` module. Either is a design change for the maintainer.
  - **Determinism:** one build runs on every CPU, so the same request gives the same tokens everywhere. This is D-010 item 5.
- **Math functions.** On Pharos, `pharos-programs` implements the engine's `Math` trait with `libm` (D-016). Host comparisons use the same `libm` implementation, not the standard library's, so Pharos and the host compute identical values.

### The service

`user/programs/src/bin/infer.rs`, an unprivileged user process.

- **Capabilities (from `init`):**
  - the console (`WRITE`);
  - its endpoint (`RECEIVE`);
  - `init`'s report endpoint (`SEND`, badged);
  - a storage capability for namespace 3, `models`, with the read-only bit (`SEND`).

  Nothing else: no device, no network, no other namespace.
- **Memory:** a 1 GiB page limit (D-011): the model in private memory (676 MB for the S1 model, read through a 16 MiB window as #78 does), a key/value cache of 24 KiB per token, and activations.
- **Start:** `init` starts it after the storage service, from its reviewed table. It reports `ready` at once, without loading a model, so booting does not wait for a 676 MB read.
- **Clients:** each gets an endpoint capability badged with a client number. `init` hands out none in M3.2; the test kernels and the S1 measurement do. The agent runtime does from M3.3.
- **One request at a time.** Pharos has one CPU and the engine is single-threaded. While a session is running, other clients get `BUSY`.

### The model manifest

Supported models are a table compiled into the service, reviewed code like `init`'s service table. Each entry gives:

- a model number;
- the store path (in `models`);
- the expected SHA-256 and size;
- the expected configuration: architecture `qwen2`, layer count, dimensions, vocabulary size, context length, and tensor type Q8_0;
- the context the service allows (S1 model: 2,048 tokens, a 48 MiB cache).

The table has two entries:

- **Model 1:** Qwen2.5-0.5B-Instruct q8_0, SHA-256 `ca59ca7f…844e` (D-010).
- **Model 2, the test model:** a tiny Qwen2-shaped GGUF that `cargo xtask` generates from a fixed seed. Its SHA-256 is pinned in the table, and a host test checks that the generator still produces exactly that file.

**Loading** happens on a model's first `GENERATE`, and the model then stays in memory:

1. Read the file into private memory; its size must match.
2. Check the SHA-256.
3. Parse it with the GGUF reader.
4. Check every configuration value against the manifest.
5. Build the tokenizer.

A failure at any step marks the model as failed until the service restarts, and every request for it gets `MODEL_INVALID` with the step that failed. A model not in the table, or a store file that is not one, cannot be loaded at all.

**Why compiled in:** a manifest read from the store would be data that anyone able to write the `models` namespace could change. The maintainer, through `cargo xtask store build`, is the only writer today, but nothing signs the store (D-017). Changing the table is a code change, and adding a model is an explicit, reviewed act. Signed manifests are M4.3 (updates).

### The interface (`pharos-proto`, interface `inference`, version 1)

Every request starts with version 1 and an operation (D-019). Every reply starts with a status. Common status codes are 0–9; the interface's own:

| Code | Name | Meaning |
| --- | --- | --- |
| 32 | `NO_MODEL` | The model number is not in the manifest |
| 33 | `MODEL_INVALID` | The model failed loading; the reply names the step (size, hash, format, configuration) |
| 34 | `CONTEXT` | Prompt plus requested tokens exceed the allowed context |
| 35 | `NO_SESSION` | The session number is unknown or has ended |

| Operation | Request | Reply | Timeout to use |
| --- | --- | --- | --- |
| `INFO` (common) | — | Interface name and versions; for each manifest model: number, name, SHA-256, context allowed, whether loaded or failed | 1 s |
| `ATTACH` (common, a `send`) | buffer size, with a `Memory` capability (`READ` and `WRITE`) | — | — |
| `GENERATE` | model, maximum new tokens (at most 2,048), the prompt's length in the attached buffer (UTF-8, at most 64 KiB) | Session number, prompt token count | 120 s (includes loading the model on first use) |
| `NEXT` | session | Up to 16 new tokens' text (at most 240 bytes), and whether generation ended and why: end-of-text token, token limit, or context limit | 30 s |
| `CANCEL` | session | — (the session ends) | 1 s |
| `RESULT` | session (after it ended) | The record: model number and SHA-256, engine version, settings, prompt and generated token counts, stop reason, prompt and generation times | 1 s |

*Implemented with these details:*
- **Times** come from system call 24 `uptime` (D-021, added for this), in microseconds.
- **Stop reasons** are end-of-text, token limit, and cancelled. The "context limit" reason never occurs, because a request whose prompt plus tokens exceeds the context is refused with `CONTEXT`.
- **`RESULT` on a running session** answers `BUSY`; on another client's session, `NO_SESSION`.
- **Limits:** `GENERATE` over 2,048 tokens or a 64 KiB prompt gets `TOO_LARGE`, and zero tokens or an empty prompt `BAD_REQUEST`. The attached buffer is at most 64 KiB and mapped read-only.
- **Model loading** reads a 16 MiB window, as #78 does. `MODEL_INVALID` steps are read, size, hash, format, and configuration. A file is checked against the manifest's size before anything is allocated.
- **The test model** (model 2) has a 64-token context, the 256 byte tokens, three merges, and `<|endoftext|>`, so it takes text prompts. A host test pins its SHA-256.

- **Prompts** arrive through the attached buffer and are copied into private memory before tokenizing, as #78 does for file data. Outputs fit in messages.
- **Settings:** greedy decoding only, so a result can be replayed exactly (D-010 item 5). Sampling settings would get a new operation, not a new meaning for these bytes.
- **Sessions:** a session that sees no `NEXT` for 10 s is cancelled, and its `RESULT` stays available until the next `GENERATE`. A client that dies therefore holds the service for at most 10 s plus one step.
- **The record** in `RESULT` is what M3.4's audit trail will store. The service keeps no log of its own.

### Failures

- **A dead or hung service:** callers use `call` with the timeouts above (#76) and get `TIMED_OUT`. The service replies with non-blocking sends, so a client that does not wait cannot stall it. Restarting the service is M3.3 (supervision).
- **A request over the limits** (prompt, tokens, context) is refused before anything is allocated. The service never asks for more memory than its manifest entry implies, so it cannot fail half-way for lack of memory.
- **A malformed model** fails its hash check first. A model with the right hash cannot be malformed unless the manifest entry is wrong, and the GGUF parser rejects bad input anyway (fuzzed since #69).

*Implemented with these details (#89):*
- **Test models 3 and 4** in the manifest copy model 2's entry; `cargo xtask` stores them with one byte changed (`corrupt.gguf`, a hash failure) and 32 bytes short (`short.gguf`, a size failure). They are listed by `INFO` like any model.
- **The format and configuration steps** cannot be reached in QEMU without a wrong manifest entry, so the checks after reading are shared functions, `pharos_programs::models::verify` (size, hash) and `open` (format, configuration), and host tests give them malformed files with a matching entry.
- **A stopped service** is tested as an endpoint nobody receives on: the kernel has no call to stop a process from outside yet (M3.3).
- **The service's own handles:** it deletes the capability for the window it shares with the store once sent, so it holds only its four handles and its reply endpoint.

## 4. Security

- **The model file is untrusted until its SHA-256 matches the manifest,** and parsed by checked, fuzzed code even after that.
- **Prompts and outputs are untrusted data** (AGENTS.md section 7): the service only tokenizes prompts and returns text; nothing it produces is executed or passed to a privileged interface.
- **Least privilege:** the service reaches only `models`, read-only, and its own endpoints. A compromised service could return wrong text, but it cannot write storage, reach the network, or touch devices.
- **Resource use:** bounded by its page limit, one session at a time, the context limit, and the idle timeout. Per-agent budgets (tokens, compute time) are M3.5. Until then any holder of an inference capability can keep the CPU busy for one `GENERATE` of up to 2,048 tokens.
- **Shared buffers:** prompts are copied out of the attached buffer before use, so a client changing it during a request cannot change what is tokenized.
- **New trusted code:** none in the kernel. The service, the tokenizer, and `pharos-proto` are user-space, safe Rust.

## 5. Testing

| Test | What it checks |
| --- | --- |
| Host, `pharos-infer` | Tokenizer: IDs identical to `llama-tokenize` on the benchmark prompts and a corpus of hard cases; fuzzed vocabularies and merges. Batched prompts: tokens identical to the single-token path. `libm` math: tokens identical between the host and the Pharos build's arithmetic |
| Host, `pharos-proto` | The inference interface round-trips; truncated, oversized, and trailing-byte messages refused; wrong version refused; fuzzed |
| Host, `xtask` | The generated test model has the pinned SHA-256 |
| QEMU, `inference_tiny` (#87) | `pharos-infer` in a user program generates from the test model; the tokens equal those `cargo xtask` computed on the host. *Implemented:* the tokens and a hash of every logit's bits, with `libm` on both sides |
| QEMU, `inference` (#88, #89) | Through the service: `INFO`; `GENERATE`, `NEXT` until the end, `RESULT` with the expected record; `CANCEL`; `BUSY` for a second client; an idle session dropped; `NO_MODEL`; `MODEL_INVALID` for a file with a wrong hash, a truncated file, and a wrong configuration (each placed in the store by `cargo xtask`); `CONTEXT`; a client's timeout when the service is stopped; the service holds only its listed capabilities. *Implemented:* all of these, except the wrong configuration and malformed files, which are host tests of `pharos_programs::models` (section 3, Failures) |
| KVM, `cargo xtask bench-infer` (#90) | S1 on Pharos: the Qwen2.5-0.5B model from `PHAROS_MODEL`, the S1 prompt; load time, first-token time, tokens per second, peak memory; tokens identical to the host's |

Each check is mutation-tested as in earlier milestones.

## 6. Alternatives

- **Hand-written SIMD now:** faster generation, but `unsafe` in a crate that forbids it, for a target already met. Revisited with #90's numbers.
- **Runtime CPU dispatch inside one binary:** needs `unsafe` calls into `target_feature` functions, and gives different floating-point results on different CPUs, against D-010's determinism.
- **A manifest file in the store:** easier to add models, but data an unsigned store cannot vouch for. Reconsidered with signed updates (M4.3).
- **Loading the model at start:** the first request is faster, but every boot would read 676 MB and the 1 GiB would be taken before anyone asks.
- **Pushing tokens to the client:** needs the service to send while the client waits, and a client that stops receiving would block or lose tokens. Pulling with `NEXT` (D-019) gives back-pressure and cancellation for free.
- **Several sessions at once:** no gain on one CPU with a single-threaded engine, and each would need its own key/value cache within the 1 GiB.

## 7. Open questions

- The first-token time on Pharos under KVM with batching (#90). On the host, batching brings the S1 prompt from about 16 s to 8.4–9.0 s (#85), 1.0–1.6 s inside the target.
- Chat formatting (the `<|im_start|>` template) belongs to the caller in M3.2. The agent runtime (M3.3) decides whether the service should apply it.
