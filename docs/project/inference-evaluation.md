# Inference-runtime evaluation (M3.1)

- **Status:** in progress (issue #69). The native engine spike and the benchmark harness exist; the engines and models below are **not yet installed or measured**. Results are filled in only from real runs.
- **Feeds:** D-010 (runtime, formats, licensing), D-011 (CPU/GPU, memory), and the M3.0 targets (#70).
- **All measurements here are host results** (D-020): they show what an engine does on Linux, not on Pharos.
- **Inputs:** [phase3-requirements.md](phase3-requirements.md) (scenario S1, model tiers T/S/H, 5 tokens/s target), the harness in [testing.md](../development/testing.md#inference-benchmarks-host).

## Engines

| Engine | Version (pinned) | License | Role | Why |
| --- | --- | --- | --- | --- |
| llama.cpp | release `b11609` (2026-10-14), commit `fcac190`, CPU build `llama-b11609-bin-ubuntu-x64.tar.gz` | MIT | Speed baseline and output reference for GGUF models | The established CPU engine; on Pharos it would need a C library, threads, `mmap`, and a C++ runtime, which M3.0 excludes |
| candle | tag `0.11.0`, commit `3d5f4d9` (examples `llama2-c`, `quantized-qwen2-instruct`) | Apache-2.0 or MIT | An existing Rust engine | What a Rust engine with a standard library needs from the OS |
| llama2.c `run.c` | commit `350e04f` | MIT | Output reference for tier T only | A small C reference for the llama2.c format the spike reads first |
| **pharos-infer** (native spike) | this repository, `crates/pharos-infer` | Apache-2.0 | The candidate engine for Pharos | `no_std`, safe Rust, no dependencies; the subject of the port-cost question |

Licenses are from each project's repository metadata; the full license texts are read before anything is adopted, and adopted third-party material is recorded in NOTICE.

## Models

| Tier | Model | File | Size | SHA-256 | License (model card metadata) |
| --- | --- | --- | --- | --- | --- |
| T | karpathy/tinyllamas `stories15M` (revision `0bd21da`) | `stories15M.bin` (llama2.c format, f32) | 60.8 MB | `cd590644d963867a2b6e5a1107f51fad663c41d79c149fbecbbb1f95fa81f49a` | MIT |
| S | Qwen/Qwen2.5-0.5B-Instruct-GGUF (revision `9217f5d`) | `qwen2.5-0.5b-instruct-q8_0.gguf` | 675.7 MB | `ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e` | Apache-2.0 |
| S | same repository | `qwen2.5-0.5b-instruct-q4_k_m.gguf` | 491.4 MB | `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db` | Apache-2.0 |
| S | HuggingFaceTB/SmolLM2-360M-Instruct-GGUF (revision `593b5a2`) | `smollm2-360m-instruct-q8_0.gguf` | 386.4 MB | `48ab3034d0dd401fbc721eb1df3217902fee7dab9078992d66431f09b7750201` | Apache-2.0 |
| H | Qwen/Qwen2.5-1.5B-Instruct-GGUF (revision `91cad51`) | `qwen2.5-1.5b-instruct-q4_k_m.gguf` | 1117.3 MB | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` | Apache-2.0 |

Sizes and checksums are from the Hugging Face API (Git LFS object IDs) on 2026-10-29. Llama 3.2 1B was left out: its community license carries use restrictions, and the Apache-2.0 candidates cover the same sizes. There is no official GGUF of SmolLM2-135M.

## Maintainer steps

The AI assistant installs and downloads nothing (AGENTS.md section 3). Run these outside the repository; everything goes under `~/pharos-eval`. No `sudo` is needed: llama.cpp comes as a prebuilt archive, and `run.c` and candle build with the `cc` and `cargo` already on the reference host.

```sh
mkdir -p ~/pharos-eval/models && cd ~/pharos-eval

# llama.cpp b11609, CPU build (MIT)
curl -LO https://github.com/ggml-org/llama.cpp/releases/download/b11609/llama-b11609-bin-ubuntu-x64.tar.gz
echo "f95cbb27dd6e377f2ce30f5cfd7ec987af3259c025fc7c98fff62927a16ff528  llama-b11609-bin-ubuntu-x64.tar.gz" | sha256sum -c
mkdir -p llama.cpp && tar xzf llama-b11609-bin-ubuntu-x64.tar.gz -C llama.cpp

# llama2.c reference (MIT), pinned by commit
git clone https://github.com/karpathy/llama2.c
git -C llama2.c checkout 350e04fe35433e6d2941dce5a1f53308f87058eb
cc -O3 -o llama2.c/run llama2.c/run.c -lm

# candle 0.11.0 (Apache-2.0/MIT); cargo downloads its dependencies
git clone --branch 0.11.0 --depth 1 https://github.com/huggingface/candle
(cd candle && cargo build --release --example llama2-c --example quantized-qwen2-instruct)

# Models, pinned by repository revision, each checked
cd models
get() { curl -L --fail -o "$3" "https://huggingface.co/$1/resolve/$2/$3" && echo "$4  $3" | sha256sum -c; }
get karpathy/tinyllamas 0bd21da7698eaf29a0d7de3992de8a46ef624add stories15M.bin cd590644d963867a2b6e5a1107f51fad663c41d79c149fbecbbb1f95fa81f49a
get Qwen/Qwen2.5-0.5B-Instruct-GGUF 9217f5db79a29953eb74d5343926648285ec7e67 qwen2.5-0.5b-instruct-q8_0.gguf ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e
get Qwen/Qwen2.5-0.5B-Instruct-GGUF 9217f5db79a29953eb74d5343926648285ec7e67 qwen2.5-0.5b-instruct-q4_k_m.gguf 74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
get HuggingFaceTB/SmolLM2-360M-Instruct-GGUF 593b5a2e04c8f3e4ee880263f93e0bd2901ad47f smollm2-360m-instruct-q8_0.gguf 48ab3034d0dd401fbc721eb1df3217902fee7dab9078992d66431f09b7750201
get Qwen/Qwen2.5-1.5B-Instruct-GGUF 91cad51170dc346986eccefdc2dd33a9da36ead9 qwen2.5-1.5b-instruct-q4_k_m.gguf 6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
# Tokenizers: llama2.c's (in the clone) for tier T; Qwen's tokenizer.json for candle, pinned by revision
curl -L --fail -o qwen2.5-0.5b-tokenizer.json https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct/resolve/7ae557604adf67be50417f59c2c2f167def9a775/tokenizer.json
sha256sum qwen2.5-0.5b-tokenizer.json   # recorded in this report after download
```

About 3.4 GB in total. The GPU (GTX 1060) is measured only if the Vulkan build is added later; it is a host reference, not a Pharos target (D-011).

## The native engine spike (`crates/pharos-infer`)

**Implemented** (host-tested; not yet run on a real model):

- Reads llama2.c checkpoints (f32 Llama architecture, grouped-query attention) and tokenizers, following `run.c`; greedy decoding.
- `no_std` with `alloc`, no dependencies, `unsafe` forbidden; the library builds for `x86_64-unknown-none`.
- Floating-point functions (`sqrt`, `exp`, `sin`, `cos`, `powf`) come from the caller through a `Math` trait, because `core` lacks them; the host passes the standard library's.
- Untrusted-input checks: every dimension is bounded and every size computed with overflow checks before anything is allocated; 20,000 fuzzed model and tokenizer files never panic.
- Tests: grouped-query attention equals the same model with key/value heads copied out per head (exact), every position up to the context length, deterministic output, the tokenizer's merges (the highest-scoring pair wins), byte fallback, and decoding. Five mutations were each caught.
- `pharos-infer <model> <tokenizer> <prompt> <n>` prints the text as `run.c` does and the harness's JSON timing line; a prompt longer than the model's context is refused with a message.

**Not yet:** GGUF, quantized weights (Q8_0, Q4_K), Qwen2 (attention biases, its RoPE layout), the GPT-2-style byte-level tokenizer, SIMD kernels. Those are needed for tier S and are the next step after tier T matches `run.c`.

## Findings so far (no measurements yet)

1. **The bare-metal target has no SSE.** `rustc --print cfg --target x86_64-unknown-none` lists only `fxsr`: SSE is off, so f32 arithmetic is compiled to software routines. Pharos user programs are built for that target today, so the engine would run on software floating point. **M3.0 needs a user-program target with SSE2 enabled** (a custom target specification or target features, decided in D-016), alongside the kernel saving vector state. The kernel itself stays on the soft-float target.
2. **Math functions are a port decision.** `core` has no `sqrt`, `exp`, `sin`, `cos`, or `powf`. On Pharos they come either from a reviewed dependency (for example `libm`, MIT/Apache-2.0) or from our own implementations; output comparison with `run.c` will show how much accuracy matters. `sqrt` can be exact with SSE2 (`sqrtss`).
3. **Long prompts need a long context.** `stories15M` has a 256-token context. The S1 summary prompt (about 230 words) probably exceeds it once tokenized (to be confirmed with the real tokenizer), so tier T runs only the short prompt; S1 needs tier S.

## Measurements

To be filled in from `scripts/bench-inference.py` runs after the maintainer steps, per engine and model: load time, prompt and generation tokens per second (1 thread and 10 threads), peak memory, output identical across runs (determinism), and output comparison against the reference engine (identical tokens for greedy decoding, or the first difference explained).

| Engine | Model | Threads | Gen tok/s | Prompt tok/s | Load | Peak memory | Deterministic | Matches reference |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | — | — | — |

## Portability to Pharos

To be completed per engine: what it needs from the OS (threads, `mmap`, SIMD level, allocator, file I/O, C library), mapped to M3.0 deliverables, with an estimate of the port effort. The native spike's needs so far: an allocator (the M3.0 freeing allocator), SSE2 in user mode (finding 1), whole-file reads of the model (M3.0 storage), and the math functions (finding 2); no threads and no `mmap`.
