//! Small GGUF files built in code: a GGUF writer and a tiny random Qwen2
//! model with Q8_0 weights. Used by the host tests, and by `cargo xtask`
//! for the `inference_tiny` test kernel, which runs the same model on Pharos and
//! compares its output with the host's (#87).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::gguf::Gguf;
use crate::gguf::{TYPE_F32, TYPE_Q8_0};
use crate::quant::quantize_row_q8_0;
use crate::qwen2::{Qwen2, Qwen2Config, Qwen2State};
use crate::{Error, Math, argmax};

/// A metadata value.
pub enum Meta<'a> {
    U32(u32),
    F32(f32),
    Str(&'a str),
    Strings(Vec<&'a str>),
    I32s(Vec<i32>),
}

/// A tensor: its name, ggml dimensions, type, and stored bytes.
pub struct TensorSpec {
    pub name: String,
    pub dims: Vec<u64>,
    pub ty: u32,
    pub data: Vec<u8>,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend((s.len() as u64).to_le_bytes());
    out.extend(s.as_bytes());
}

/// A GGUF version 3 file with `meta` and `tensors`, aligned to 32 bytes.
pub fn gguf_file(meta: &[(&str, Meta<'_>)], tensors: &[TensorSpec]) -> Vec<u8> {
    let mut out = b"GGUF".to_vec();
    out.extend(3u32.to_le_bytes());
    out.extend((tensors.len() as u64).to_le_bytes());
    out.extend((meta.len() as u64).to_le_bytes());
    for (k, v) in meta {
        put_str(&mut out, k);
        match v {
            Meta::U32(x) => {
                out.extend(4u32.to_le_bytes());
                out.extend(x.to_le_bytes());
            }
            Meta::F32(x) => {
                out.extend(6u32.to_le_bytes());
                out.extend(x.to_le_bytes());
            }
            Meta::Str(s) => {
                out.extend(8u32.to_le_bytes());
                put_str(&mut out, s);
            }
            Meta::Strings(list) => {
                out.extend(9u32.to_le_bytes());
                out.extend(8u32.to_le_bytes());
                out.extend((list.len() as u64).to_le_bytes());
                for s in list {
                    put_str(&mut out, s);
                }
            }
            Meta::I32s(list) => {
                out.extend(9u32.to_le_bytes());
                out.extend(5u32.to_le_bytes());
                out.extend((list.len() as u64).to_le_bytes());
                for v in list {
                    out.extend(v.to_le_bytes());
                }
            }
        }
    }
    let mut offset = 0u64;
    let mut offsets = Vec::new();
    for t in tensors {
        put_str(&mut out, &t.name);
        out.extend((t.dims.len() as u32).to_le_bytes());
        for d in &t.dims {
            out.extend(d.to_le_bytes());
        }
        out.extend(t.ty.to_le_bytes());
        out.extend(offset.to_le_bytes());
        offsets.push(offset);
        offset += (t.data.len() as u64).div_ceil(32) * 32;
    }
    while out.len() % 32 != 0 {
        out.push(0);
    }
    for t in tensors {
        out.extend(&t.data);
        while out.len() % 32 != 0 {
            out.push(0);
        }
    }
    out
}

/// A one-dimensional F32 tensor.
pub fn f32_tensor(name: &str, values: &[f32]) -> TensorSpec {
    TensorSpec {
        name: name.into(),
        dims: vec![values.len() as u64],
        ty: TYPE_F32,
        data: values.iter().flat_map(|v| v.to_le_bytes()).collect(),
    }
}

/// A Q8_0 matrix of `rows` rows of `cols` values (ggml dims [cols, rows]).
pub fn q8_tensor(name: &str, cols: usize, values: &[f32]) -> TensorSpec {
    TensorSpec {
        name: name.into(),
        dims: vec![cols as u64, (values.len() / cols) as u64],
        ty: TYPE_Q8_0,
        data: quantize_row_q8_0(values),
    }
}

/// A pseudo-random generator (xorshift) for weights.
pub struct Rng(pub u64);

impl Rng {
    pub fn vec(&mut self, n: usize) -> Vec<f32> {
        (0..n)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                ((self.0 % 2001) as f32 / 1000.0 - 1.0) * 0.4
            })
            .collect()
    }
}

/// The tiny model's dimensions.
pub const TINY: Qwen2Config = Qwen2Config {
    dim: 64,
    hidden_dim: 96,
    n_layers: 2,
    n_heads: 4,
    n_kv_heads: 2,
    vocab_size: 40,
    context: 32,
    rope_base: 10000.0,
    rms_eps: 1e-6,
};

/// A tiny Qwen2 GGUF. `expand_kv` writes each K/V head once per query head
/// (n_kv_heads = n_heads) with the same values; `tied` omits output.weight.
pub fn tiny_model(seed: u64, expand_kv: bool, tied: bool) -> Vec<u8> {
    let toks: Vec<String> = (0..TINY.vocab_size).map(|i| format!("t{i}")).collect();
    let toks: Vec<&str> = toks.iter().map(String::as_str).collect();
    qwen2_file(
        &TINY,
        seed,
        expand_kv,
        tied,
        vec![("tokenizer.ggml.tokens", Meta::Strings(toks))],
    )
}

/// A Qwen2 GGUF with dimensions `c`, random weights from `seed`, and the
/// extra metadata `tokenizer` (at least `tokenizer.ggml.tokens`).
fn qwen2_file(
    c: &Qwen2Config,
    seed: u64,
    expand_kv: bool,
    tied: bool,
    tokenizer: Vec<(&str, Meta<'_>)>,
) -> Vec<u8> {
    let c = *c;
    let mut r = Rng(seed);
    let (d, h, hs) = (c.dim, c.hidden_dim, c.dim / c.n_heads);
    let kv_heads = if expand_kv { c.n_heads } else { c.n_kv_heads };
    let mut tensors = vec![q8_tensor("token_embd.weight", d, &r.vec(c.vocab_size * d))];
    if !tied {
        tensors.push(q8_tensor("output.weight", d, &r.vec(c.vocab_size * d)));
    }
    tensors.push(f32_tensor("output_norm.weight", &r.vec(d)));
    let expand = |w: &[f32], per_head: usize| -> Vec<f32> {
        if !expand_kv {
            return w.to_vec();
        }
        (0..c.n_heads)
            .flat_map(|head| {
                let kv = head / (c.n_heads / c.n_kv_heads);
                w[kv * per_head..(kv + 1) * per_head].to_vec()
            })
            .collect()
    };
    for l in 0..c.n_layers {
        let p = |s: &str| format!("blk.{l}.{s}");
        let (k, kb, v, vb) = (
            r.vec(c.n_kv_heads * hs * d),
            r.vec(c.n_kv_heads * hs),
            r.vec(c.n_kv_heads * hs * d),
            r.vec(c.n_kv_heads * hs),
        );
        tensors.extend([
            f32_tensor(&p("attn_norm.weight"), &r.vec(d)),
            q8_tensor(&p("attn_q.weight"), d, &r.vec(d * d)),
            f32_tensor(&p("attn_q.bias"), &r.vec(d)),
            q8_tensor(&p("attn_k.weight"), d, &expand(&k, hs * d)),
            f32_tensor(&p("attn_k.bias"), &expand(&kb, hs)),
            q8_tensor(&p("attn_v.weight"), d, &expand(&v, hs * d)),
            f32_tensor(&p("attn_v.bias"), &expand(&vb, hs)),
            q8_tensor(&p("attn_output.weight"), d, &r.vec(d * d)),
            f32_tensor(&p("ffn_norm.weight"), &r.vec(d)),
            q8_tensor(&p("ffn_gate.weight"), d, &r.vec(h * d)),
            q8_tensor(&p("ffn_up.weight"), d, &r.vec(h * d)),
            q8_tensor(&p("ffn_down.weight"), h, &r.vec(d * h)),
        ]);
    }
    let mut meta = vec![
        ("general.architecture", Meta::Str("qwen2")),
        ("qwen2.embedding_length", Meta::U32(d as u32)),
        ("qwen2.feed_forward_length", Meta::U32(h as u32)),
        ("qwen2.block_count", Meta::U32(c.n_layers as u32)),
        ("qwen2.attention.head_count", Meta::U32(c.n_heads as u32)),
        ("qwen2.attention.head_count_kv", Meta::U32(kv_heads as u32)),
        ("qwen2.context_length", Meta::U32(c.context as u32)),
        ("qwen2.rope.freq_base", Meta::F32(c.rope_base)),
        (
            "qwen2.attention.layer_norm_rms_epsilon",
            Meta::F32(c.rms_eps),
        ),
    ];
    meta.extend(tokenizer);
    gguf_file(&meta, &tensors)
}

/// The test model's dimensions: [`TINY`]'s, with a byte-level vocabulary
/// and a 64-token context.
pub const TEST: Qwen2Config = Qwen2Config {
    vocab_size: 256 + TEST_TOKENS.len(),
    context: 64,
    ..TINY
};

/// The test model's tokens after the 256 byte tokens; the last is its
/// end-of-text token.
const TEST_TOKENS: [&str; 4] = ["he", "ll", "hell", "<|endoftext|>"];

/// The inference service's test model (manifest model 2, #88): [`TEST`]'s
/// dimensions and a working GPT-2 byte-level tokenizer (the 256 byte
/// tokens, three merges, and `<|endoftext|>` as a control token and the
/// end-of-text token), so it takes text prompts.
pub fn test_model() -> Vec<u8> {
    let mut tokens: Vec<String> = (0..=255u8)
        .map(|b| {
            let mut buf = [0u8; 4];
            String::from_utf8_lossy(crate::bpe::byte_char(b, &mut buf)).into_owned()
        })
        .collect();
    tokens.extend(TEST_TOKENS.iter().map(|t| String::from(*t)));
    let mut types = vec![1i32; tokens.len()];
    let eos = tokens.len() - 1;
    types[eos] = 3;
    let meta = vec![
        (
            "tokenizer.ggml.tokens",
            Meta::Strings(tokens.iter().map(String::as_str).collect()),
        ),
        ("tokenizer.ggml.token_type", Meta::I32s(types)),
        (
            "tokenizer.ggml.merges",
            Meta::Strings(vec!["h e", "l l", "he ll"]),
        ),
        ("tokenizer.ggml.eos_token_id", Meta::U32(eos as u32)),
    ];
    qwen2_file(&TEST, TEST_SEED, false, false, meta)
}

/// The test model's seed.
pub const TEST_SEED: u64 = 7;

/// The seed of the tiny model `cargo xtask` stores: its greedy output
/// varies (6 distinct tokens), so a wrong token shows.
pub const TINY_SEED: u64 = 39;

/// The prompt [`run_tiny`] reads.
pub const TINY_PROMPT: [usize; 8] = [3, 9, 1, 27, 27, 5, 12, 30];

/// Runs [`TINY_PROMPT`] through the model in `file` as one block, then
/// generates greedily up to the model's context. Returns the generated
/// tokens and an FNV-1a hash of every logit's bits, so any difference in
/// arithmetic shows, not only one that changes a token.
pub fn run_tiny(file: &[u8], m: &impl Math) -> Result<(Vec<usize>, u64), Error> {
    let g = Gguf::parse(file)?;
    let vocab = g.strings(b"tokenizer.ggml.tokens")?.len();
    let model = Qwen2::load(&g, vocab)?;
    let positions = model.config.context;
    if TINY_PROMPT.len() >= positions || TINY_PROMPT.iter().any(|&t| t >= vocab) {
        return Err(Error::BadConfig);
    }
    let mut s = Qwen2State::new(&model.config, positions);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |logits: &[f32]| {
        for v in logits {
            hash ^= u64::from(v.to_bits());
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    let mut logits = model.forward_batch(&mut s, &TINY_PROMPT, 0, m).to_vec();
    mix(&logits);
    let mut tokens = Vec::new();
    for pos in TINY_PROMPT.len()..positions {
        let next = argmax(&logits);
        tokens.push(next);
        logits = model.forward(&mut s, next, pos, m).to_vec();
        mix(&logits);
    }
    Ok((tokens, hash))
}
