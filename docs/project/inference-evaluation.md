# Inference-runtime evaluation (M3.1)

- **Status:** in progress (issue #69). Engines and models are installed on the reference host; llama.cpp and the native spike are measured, and the spike matches `run.c` exactly on `stories15M`. candle is not yet measured. Results come only from real runs.
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
mkdir -p llama.cpp && tar xzf llama-b11609-bin-ubuntu-x64.tar.gz -C llama.cpp   # tools land in llama.cpp/llama-b11609/

# llama2.c reference (MIT), pinned by commit
git clone https://github.com/karpathy/llama2.c
git -C llama2.c checkout 350e04fe35433e6d2941dce5a1f53308f87058eb
cc -O3 -o llama2.c/run llama2.c/run.c -lm

# candle 0.11.0 (Apache-2.0/MIT); cargo downloads its dependencies
git clone --branch 0.11.0 --depth 1 https://github.com/huggingface/candle
(cd candle && cargo build --release --features candle-datasets --example llama2-c --example quantized-qwen2-instruct)

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
echo "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539  qwen2.5-0.5b-tokenizer.json" | sha256sum -c   # recorded 2026-10-29
```

About 3.4 GB in total. The GPU (GTX 1060) is measured only if the Vulkan build is added later; it is a host reference, not a Pharos target (D-011).

## The native engine spike (`crates/pharos-infer`)

**Implemented** (host-tested, and checked against `run.c` on `stories15M`):

- Reads llama2.c checkpoints (f32 Llama architecture, grouped-query attention) and tokenizers, following `run.c`; greedy decoding.
- `no_std` with `alloc`, no dependencies, `unsafe` forbidden; the library builds for `x86_64-unknown-none`.
- Floating-point functions (`sqrt`, `exp`, `sin`, `cos`, `powf`) come from the caller through a `Math` trait, because `core` lacks them; the host passes the standard library's.
- Untrusted-input checks: every dimension is bounded and every size computed with overflow checks before anything is allocated; 20,000 fuzzed model and tokenizer files never panic.
- Tests: grouped-query attention equals the same model with key/value heads copied out per head (exact), every position up to the context length, deterministic output, the tokenizer's merges (the highest-scoring pair wins), byte fallback, and decoding. Five mutations were each caught.
- `pharos-infer <model> <tokenizer> <prompt> <n>` prints the text as `run.c` does and the harness's JSON timing line; a prompt longer than the model's context is refused with a message.

**Not yet:** GGUF, quantized weights (Q8_0, Q4_K), Qwen2 (attention biases, its RoPE layout), the GPT-2-style byte-level tokenizer, SIMD kernels. Those are needed for tier S and are the next step after tier T matches `run.c`.

## Output comparison

**`pharos-infer` against llama2.c `run.c` on `stories15M`, greedy decoding** (`run -t 0.0 -n 256 -i <prompt> -z tokenizer.bin` against `pharos-infer <model> <tokenizer> <prompt> <256 − prompt tokens + 1>`), run on 2026-10-29:

| Prompt | Prompt tokens (with BOS) | Result |
| --- | --- | --- |
| "Once upon a time" | 5 | Identical output, 813 bytes |
| "Lily and Ben went to the park" | 9 | Identical output, 850 bytes |
| "The little robot" | 4 | Identical output, 790 bytes |

Byte-for-byte identical text, both engines stopping at the same end-of-story token. In those runs `run.c` (`cc -O3`, no `-march`) reported 84 tokens per second and `pharos-infer` (release build, no target CPU flags) about 78, both single-threaded; the harness measurements below are the comparable numbers.

## Findings so far

1. **The bare-metal target has no SSE.** `rustc --print cfg --target x86_64-unknown-none` lists only `fxsr`: SSE is off, so f32 arithmetic is compiled to software routines. Pharos user programs are built for that target today, so the engine would run on software floating point. **M3.0 needs a user-program target with SSE2 enabled** (a custom target specification or target features, decided in D-016), alongside the kernel saving vector state. The kernel itself stays on the soft-float target.
2. **Math functions are a port decision.** `core` has no `sqrt`, `exp`, `sin`, `cos`, or `powf`. On Pharos they come either from a reviewed dependency (for example `libm`, MIT/Apache-2.0) or from our own implementations; output comparison with `run.c` will show how much accuracy matters. `sqrt` can be exact with SSE2 (`sqrtss`).
3. **Long prompts need a long context.** `stories15M` has a 256-token context. The S1 summary prompt (about 230 words) probably exceeds it once tokenized (to be confirmed with the real tokenizer), so tier T runs only the short prompt; S1 needs tier S.

## Measurements

Run on 2026-10-29 on the reference host (i9-10900K, AVX2/FMA, 125 GB) with `scripts/bench-inference.py`: two prompts (`short`, and the S1 `summary` prompt), 128 generated tokens, seed 42, greedy decoding, 3 runs each, medians shown. The runner script is recorded below. llama.cpp used `llama-completion -m {model} -p {prompt} -n {n} -t {threads} -s {seed} --temp 0 -no-cnv --simple-io --no-display-prompt` (raw prompts, no chat template: these numbers measure speed, not answer quality).

| Engine | Model | Threads | Prompt | Gen tok/s | Prompt tok/s | Load | Peak RSS | Same output, 3 runs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pharos-infer | stories15M f32 | 1 | short | 77.6 | 78.6 | 50 ms | 118 MiB | yes |
| llama.cpp | Qwen2.5-0.5B q8_0 | 1 | short | 23.0 | 71.3 | 342 ms | 1,091 MiB | yes |
| llama.cpp | Qwen2.5-0.5B q8_0 | 1 | summary | 21.9 | 95.0 | 356 ms | 1,105 MiB | yes |
| llama.cpp | Qwen2.5-0.5B q8_0 | 10 | summary | 45.4 | 744 | 304 ms | 1,105 MiB | yes |
| llama.cpp | Qwen2.5-0.5B q4_k_m | 1 | summary | 23.1 | 83.1 | 339 ms | 959 MiB | yes |
| llama.cpp | Qwen2.5-0.5B q4_k_m | 10 | summary | 58.3 | 609 | 307 ms | 961 MiB | yes |
| llama.cpp | SmolLM2-360M q8_0 | 1 | summary | 28.5 | 105 | 207 ms | 733 MiB | yes |
| llama.cpp | SmolLM2-360M q8_0 | 10 | summary | 57.2 | 865 | 178 ms | 733 MiB | yes |
| llama.cpp | Qwen2.5-1.5B q4_k_m | 1 | summary | 12.1 | 41.9 | 1,021 ms | 2,650 MiB | yes |
| llama.cpp | Qwen2.5-1.5B q4_k_m | 10 | summary | 24.3 | 329 | 932 ms | 2,653 MiB | yes |

Short-prompt rows for llama.cpp at 10 threads are in the JSON results; they are within 4% of the summary rows for generation. SmolLM2 answered the raw short prompt with an immediate end-of-text token, so it has no short-prompt generation rate.

**Reading the numbers:**

- **The S1 target is reachable on one CPU.** Pharos runs on one CPU; single-threaded llama.cpp generates 22–23 tokens/s with Qwen2.5-0.5B and 12 with Qwen2.5-1.5B, against the 5 tokens/s target, and reads the 233-token S1 prompt in 2.5 s (0.5B q8_0) to 5.6 s (1.5B q4_k_m), so the first token arrives within the 10 s target. This is on the host, with AVX2; Pharos under KVM should come close if the engine uses SIMD (finding 1).
- **Output is deterministic** for both engines at fixed seed and thread count: every configuration produced identical text in its three runs, at 1 and at 10 threads.
- **Memory:** peak RSS is 1.7 to 2.5 times the model file for llama.cpp (it maps the file and allocates its context and buffers at its default context length), and 2 times for `pharos-infer`, which copies the f32 weights into memory. The M3.0 targets of 2 GB guest memory and 1.5 GB for the service fit Qwen2.5-0.5B; Qwen2.5-1.5B would need about 3 GB.
- **The native engine's speed per parameter.** `pharos-infer` is scalar f32 code: 78 tokens/s for a 15 M-parameter model, while llama.cpp runs a 494 M-parameter model at 22 tokens/s with 8-bit weights and AVX2. Scaling `pharos-infer` linearly by parameter count gives about 2–3 tokens/s for Qwen2.5-0.5B (an estimate, not a measurement), below the 5 tokens/s target. **To meet S1, the native engine needs quantized weights (Q8_0 at least) and SIMD kernels** (SSE2 baseline, AVX2 when present).

Runner (results in `target/bench/`, never committed):

```sh
L=~/pharos-eval/llama.cpp/llama-b11609; M=~/pharos-eval/models
python3 scripts/bench-inference.py --engine native --model $M/stories15M.bin --label "stories15M f32 t1" \
    --threads 1 --runs 3 -n 128 --prompt short \
    -- target/release/pharos-infer {model} ~/pharos-eval/llama2.c/tokenizer.bin {prompt} {n}
python3 scripts/bench-inference.py --engine llama --model $M/<model>.gguf --label "<model> t<T>" \
    --threads <T> --runs 3 -n 128 --version-cmd "$L/llama-completion --version" \
    -- $L/llama-completion -m {model} -p {prompt} -n {n} -t {threads} -s {seed} --temp 0 -no-cnv --simple-io --no-display-prompt
```

candle: not yet measured (its first build failed for a missing feature flag; the corrected build step is above).

## Portability to Pharos

To be completed per engine: what it needs from the OS (threads, `mmap`, SIMD level, allocator, file I/O, C library), mapped to M3.0 deliverables, with an estimate of the port effort. The native spike's needs so far: an allocator (the M3.0 freeing allocator), SSE2 in user mode (finding 1), whole-file reads of the model (M3.0 storage), and the math functions (finding 2); no threads and no `mmap`.
