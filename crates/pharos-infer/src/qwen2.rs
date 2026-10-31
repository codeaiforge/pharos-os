//! Qwen2-architecture models from GGUF files with Q8_0 weights (M3.1
//! tier S: Qwen2.5-0.5B-Instruct q8_0), following llama.cpp's Qwen2 graph:
//! RMS norm, attention with biases on Q, K, and V, grouped-query attention,
//! "NeoX" rotary embeddings (each head's halves rotated together), and a
//! SwiGLU feed-forward layer.

use alloc::vec;
use alloc::vec::Vec;

use crate::gguf::{Gguf, TYPE_Q8_0, Tensor};
use crate::quant::{Q8Vec, QK8_0, dequantize_q8_0, dot_q8_0, dot_q8_0_many};
use crate::{Error, MAX_DIM, MAX_HIDDEN, MAX_LAYERS, MAX_VOCAB, Math};

/// Model dimensions, from the GGUF metadata.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Qwen2Config {
    pub dim: usize,
    pub hidden_dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub n_kv_heads: usize,
    pub vocab_size: usize,
    pub context: usize,
    pub rope_base: f32,
    pub rms_eps: f32,
}

impl Qwen2Config {
    pub fn head_size(&self) -> usize {
        self.dim / self.n_heads
    }

    pub fn kv_dim(&self) -> usize {
        self.head_size() * self.n_kv_heads
    }
}

struct Layer<'a> {
    attn_norm: Vec<f32>,
    q: Tensor<'a>,
    q_bias: Vec<f32>,
    k: Tensor<'a>,
    k_bias: Vec<f32>,
    v: Tensor<'a>,
    v_bias: Vec<f32>,
    o: Tensor<'a>,
    ffn_norm: Vec<f32>,
    gate: Tensor<'a>,
    up: Tensor<'a>,
    down: Tensor<'a>,
}

/// A loaded model; weights borrow the file's bytes.
pub struct Qwen2<'a> {
    pub config: Qwen2Config,
    embedding: Tensor<'a>,
    output: Tensor<'a>,
    output_norm: Vec<f32>,
    layers: Vec<Layer<'a>>,
}

fn dim(g: &Gguf<'_>, key: &[u8], max: usize) -> Result<usize, Error> {
    usize::try_from(g.uint(key)?)
        .ok()
        .filter(|&v| v > 0 && v <= max)
        .ok_or(Error::BadConfig)
}

fn q8(t: Tensor<'_>) -> Result<Tensor<'_>, Error> {
    if t.ty == TYPE_Q8_0 {
        Ok(t)
    } else {
        Err(Error::UnsupportedType)
    }
}

impl<'a> Qwen2<'a> {
    /// Loads a Qwen2 model, checking the architecture, every dimension, and
    /// every tensor's shape and type.
    pub fn load(g: &Gguf<'a>, vocab_size: usize) -> Result<Self, Error> {
        if g.get(b"general.architecture") != Some(crate::gguf::Value::Str(b"qwen2")) {
            return Err(Error::BadConfig);
        }
        let c = Qwen2Config {
            dim: dim(g, b"qwen2.embedding_length", MAX_DIM)?,
            hidden_dim: dim(g, b"qwen2.feed_forward_length", MAX_HIDDEN)?,
            n_layers: dim(g, b"qwen2.block_count", MAX_LAYERS)?,
            n_heads: dim(g, b"qwen2.attention.head_count", MAX_DIM)?,
            n_kv_heads: dim(g, b"qwen2.attention.head_count_kv", MAX_DIM)?,
            vocab_size,
            context: dim(g, b"qwen2.context_length", 1 << 20)?,
            rope_base: g.float(b"qwen2.rope.freq_base")? as f32,
            rms_eps: g.float(b"qwen2.attention.layer_norm_rms_epsilon")? as f32,
        };
        let ok = c.vocab_size > 0
            && c.vocab_size <= MAX_VOCAB
            && c.dim % c.n_heads == 0
            && c.n_heads % c.n_kv_heads == 0
            && c.head_size() % 2 == 0
            && c.dim % QK8_0 == 0
            && c.hidden_dim % QK8_0 == 0
            && c.rope_base > 0.0
            && c.rms_eps > 0.0;
        if !ok {
            return Err(Error::BadConfig);
        }
        let (d, h, kv, v) = (
            c.dim as u64,
            c.hidden_dim as u64,
            c.kv_dim() as u64,
            c.vocab_size as u64,
        );
        let embedding = q8(g.tensor(b"token_embd.weight", &[d, v])?)?;
        let output = if g.has(b"output.weight") {
            q8(g.tensor(b"output.weight", &[d, v])?)?
        } else {
            embedding // tied embeddings
        };
        let mut name = Vec::new();
        let mut layers = Vec::new();
        for l in 0..c.n_layers {
            let mut t = |suffix: &str, dims: &[u64]| {
                name.clear();
                name.extend_from_slice(b"blk.");
                push_decimal(&mut name, l);
                name.push(b'.');
                name.extend_from_slice(suffix.as_bytes());
                g.tensor(&name, dims)
            };
            layers.push(Layer {
                attn_norm: t("attn_norm.weight", &[d])?.f32s()?,
                q: q8(t("attn_q.weight", &[d, d])?)?,
                q_bias: t("attn_q.bias", &[d])?.f32s()?,
                k: q8(t("attn_k.weight", &[d, kv])?)?,
                k_bias: t("attn_k.bias", &[kv])?.f32s()?,
                v: q8(t("attn_v.weight", &[d, kv])?)?,
                v_bias: t("attn_v.bias", &[kv])?.f32s()?,
                o: q8(t("attn_output.weight", &[d, d])?)?,
                ffn_norm: t("ffn_norm.weight", &[d])?.f32s()?,
                gate: q8(t("ffn_gate.weight", &[d, h])?)?,
                up: q8(t("ffn_up.weight", &[d, h])?)?,
                down: q8(t("ffn_down.weight", &[h, d])?)?,
            });
        }
        Ok(Self {
            config: c,
            embedding,
            output,
            output_norm: g.tensor(b"output_norm.weight", &[d])?.f32s()?,
            layers,
        })
    }
}

fn push_decimal(out: &mut Vec<u8>, mut n: usize) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// Most prompt tokens [`Qwen2::forward_batch`] runs in one pass.
pub const MAX_BATCH: usize = 32;

/// Activations for up to [`MAX_BATCH`] tokens and the key/value cache for up
/// to `max_pos` positions.
pub struct Qwen2State {
    max_pos: usize,
    x: Vec<f32>,
    xb: Vec<f32>,
    q: Vec<f32>,
    att_out: Vec<f32>,
    hb: Vec<f32>,
    hb2: Vec<f32>,
    att: Vec<f32>,
    logits: Vec<f32>,
    key_cache: Vec<f32>,
    value_cache: Vec<f32>,
    quant: Vec<Q8Vec>,
}

impl Qwen2State {
    /// State for `max_pos` positions (at most the model's context).
    pub fn new(c: &Qwen2Config, max_pos: usize) -> Self {
        let max_pos = max_pos.min(c.context);
        let cache = c.n_layers * max_pos * c.kv_dim();
        let (d, h) = (MAX_BATCH * c.dim, MAX_BATCH * c.hidden_dim);
        Self {
            max_pos,
            x: vec![0.0; d],
            xb: vec![0.0; d],
            q: vec![0.0; d],
            att_out: vec![0.0; d],
            hb: vec![0.0; h],
            hb2: vec![0.0; h],
            att: vec![0.0; max_pos],
            logits: vec![0.0; c.vocab_size],
            key_cache: vec![0.0; cache],
            value_cache: vec![0.0; cache],
            quant: (0..MAX_BATCH).map(|_| Q8Vec::new()).collect(),
        }
    }

    pub fn max_pos(&self) -> usize {
        self.max_pos
    }
}

fn rmsnorm(out: &mut [f32], x: &[f32], weight: &[f32], eps: f32, m: &impl Math) {
    let ss = x.iter().map(|v| v * v).sum::<f32>() / x.len() as f32;
    let scale = 1.0 / m.sqrt(ss + eps);
    for ((o, v), w) in out.iter_mut().zip(x).zip(weight) {
        *o = v * scale * w;
    }
}

/// `out[b] = W x[b]` for the `n` vectors in `x` (one row of `W` per output),
/// each vector quantized first. Each weight row is read once for all `n`
/// vectors; each output is the same dot product as for one vector alone.
fn matmul(out: &mut [f32], w: &Tensor<'_>, x: &[f32], n: usize, quant: &mut [Q8Vec]) {
    let (rows, cols) = (out.len() / n, x.len() / n);
    for (q, x) in quant.iter_mut().zip(x.chunks_exact(cols)) {
        q.quantize(x);
    }
    if n == 1 {
        for (i, o) in out.iter_mut().enumerate() {
            *o = dot_q8_0(w.row(i), &quant[0]);
        }
        return;
    }
    let mut sums = [0.0f32; MAX_BATCH];
    for i in 0..rows {
        dot_q8_0_many(w.row(i), &quant[..n], &mut sums[..n]);
        for (b, sum) in sums[..n].iter().enumerate() {
            out[b * rows + i] = *sum;
        }
    }
}

fn add_bias(v: &mut [f32], bias: &[f32]) {
    for chunk in v.chunks_exact_mut(bias.len()) {
        for (v, b) in chunk.iter_mut().zip(bias) {
            *v += b;
        }
    }
}

/// Rotates each head of `v` (NeoX layout: element `i` with `i + half`).
pub(crate) fn rope(v: &mut [f32], head_size: usize, pos: usize, base: f32, m: &impl Math) {
    let half = head_size / 2;
    // As llama.cpp: theta starts at pos and is multiplied by
    // base^(-2/head_size) for each pair.
    let theta_scale = m.powf(base, -2.0 / head_size as f32);
    for head in v.chunks_exact_mut(head_size) {
        let mut theta = pos as f32;
        for i in 0..half {
            let (c, s) = (m.cos(theta), m.sin(theta));
            let (a, b) = (head[i], head[i + half]);
            head[i] = a * c - b * s;
            head[i + half] = a * s + b * c;
            theta *= theta_scale;
        }
    }
}

impl Qwen2<'_> {
    /// Runs `token` at `pos` (below the state's `max_pos`, `token` below
    /// `vocab_size`) and returns the logits.
    pub fn forward<'s>(
        &self,
        s: &'s mut Qwen2State,
        token: usize,
        pos: usize,
        m: &impl Math,
    ) -> &'s [f32] {
        self.forward_batch(s, &[token], pos, m)
    }

    /// Runs `tokens` (1 to [`MAX_BATCH`], each below `vocab_size`) at
    /// positions `pos..pos + tokens.len()` (at most the state's `max_pos`),
    /// filling the key/value cache for all of them, and returns the last
    /// token's logits. Every value is computed with the same operations in
    /// the same order as running the tokens one by one with
    /// [`Qwen2::forward`], so the logits are bit-identical.
    pub fn forward_batch<'s>(
        &self,
        s: &'s mut Qwen2State,
        tokens: &[usize],
        pos: usize,
        m: &impl Math,
    ) -> &'s [f32] {
        let n = tokens.len();
        assert!(
            (1..=MAX_BATCH).contains(&n) && pos + n <= s.max_pos,
            "forward_batch: 1 to {MAX_BATCH} tokens within the state's positions"
        );
        let c = &self.config;
        let (d, h, kv_dim, hs) = (c.dim, c.hidden_dim, c.kv_dim(), c.head_size());
        let (nd, nh) = (n * d, n * h);
        let kv_mul = c.n_heads / c.n_kv_heads;
        for (x, &t) in s.x.chunks_exact_mut(d).zip(tokens) {
            dequantize_q8_0(self.embedding.row(t), x);
        }
        let scale = 1.0 / m.sqrt(hs as f32);

        for (l, layer) in self.layers.iter().enumerate() {
            for (o, x) in s.xb[..nd].chunks_exact_mut(d).zip(s.x.chunks_exact(d)) {
                rmsnorm(o, x, &layer.attn_norm, c.rms_eps, m);
            }
            // The block's positions are contiguous in the cache.
            let at = (l * s.max_pos + pos) * kv_dim;
            let kv = at..at + n * kv_dim;
            matmul(&mut s.q[..nd], &layer.q, &s.xb[..nd], n, &mut s.quant);
            let keys = &mut s.key_cache[kv.clone()];
            matmul(keys, &layer.k, &s.xb[..nd], n, &mut s.quant);
            let values = &mut s.value_cache[kv.clone()];
            matmul(values, &layer.v, &s.xb[..nd], n, &mut s.quant);
            add_bias(&mut s.q[..nd], &layer.q_bias);
            add_bias(&mut s.key_cache[kv.clone()], &layer.k_bias);
            add_bias(&mut s.value_cache[kv.clone()], &layer.v_bias);
            for (b, (q, k)) in s.q[..nd]
                .chunks_exact_mut(d)
                .zip(s.key_cache[kv].chunks_exact_mut(kv_dim))
                .enumerate()
            {
                rope(q, hs, pos + b, c.rope_base, m);
                rope(k, hs, pos + b, c.rope_base, m);
            }

            let base = l * s.max_pos * kv_dim;
            for b in 0..n {
                let p = pos + b;
                for head in 0..c.n_heads {
                    let q = &s.q[b * d + head * hs..][..hs];
                    let kv_off = (head / kv_mul) * hs;
                    let att = &mut s.att[..=p];
                    for (t, a) in att.iter_mut().enumerate() {
                        let k = &s.key_cache[base + t * kv_dim + kv_off..][..hs];
                        *a = q.iter().zip(k).map(|(x, y)| x * y).sum::<f32>() * scale;
                    }
                    let max = att.iter().copied().fold(f32::NEG_INFINITY, f32::max);
                    let mut sum = 0.0;
                    for a in att.iter_mut() {
                        *a = m.exp(*a - max);
                        sum += *a;
                    }
                    let out = &mut s.att_out[b * d + head * hs..][..hs];
                    out.fill(0.0);
                    for (t, a) in att.iter().enumerate() {
                        let v = &s.value_cache[base + t * kv_dim + kv_off..][..hs];
                        for (o, x) in out.iter_mut().zip(v) {
                            *o += a / sum * x;
                        }
                    }
                }
            }
            matmul(&mut s.xb[..nd], &layer.o, &s.att_out[..nd], n, &mut s.quant);
            for (x, d) in s.x[..nd].iter_mut().zip(&s.xb[..nd]) {
                *x += d;
            }

            for (o, x) in s.xb[..nd].chunks_exact_mut(d).zip(s.x.chunks_exact(d)) {
                rmsnorm(o, x, &layer.ffn_norm, c.rms_eps, m);
            }
            matmul(&mut s.hb[..nh], &layer.gate, &s.xb[..nd], n, &mut s.quant);
            matmul(&mut s.hb2[..nh], &layer.up, &s.xb[..nd], n, &mut s.quant);
            for (g, u) in s.hb[..nh].iter_mut().zip(&s.hb2[..nh]) {
                *g = *g / (1.0 + m.exp(-*g)) * u;
            }
            matmul(&mut s.xb[..nd], &layer.down, &s.hb[..nh], n, &mut s.quant);
            for (x, d) in s.x[..nd].iter_mut().zip(&s.xb[..nd]) {
                *x += d;
            }
        }

        // Only the last token's logits are needed.
        let last = &s.x[nd - d..nd];
        rmsnorm(&mut s.xb[..d], last, &self.output_norm, c.rms_eps, m);
        matmul(&mut s.logits, &self.output, &s.xb[..d], 1, &mut s.quant);
        &s.logits
    }
}

/// GPT-2 byte-level decoding: each token string encodes bytes as Unicode
/// characters (printable Latin-1 bytes as themselves, the rest from U+0100
/// up). Returns the bytes `piece` stands for, or `None` if it holds a
/// character outside that table.
pub fn decode_byte_level(piece: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(piece).ok()?;
    let mut out = Vec::with_capacity(piece.len());
    for ch in text.chars() {
        let c = ch as u32;
        let byte = match c {
            0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff => c as u8,
            0x100..=0x143 => {
                // The 68 remaining bytes, in increasing order, mapped to
                // U+0100 onwards.
                let n = (c - 0x100) as usize;
                *SHIFTED.get(n)?
            }
            _ => return None,
        };
        out.push(byte);
    }
    Some(out)
}

/// Bytes not printable in GPT-2's table, in increasing order: 0x00-0x20,
/// 0x7f-0xa0, 0xad.
const SHIFTED: [u8; 68] = {
    let mut t = [0u8; 68];
    let mut n = 0;
    let mut b = 0usize;
    while b < 256 {
        let printable = (b >= 0x21 && b <= 0x7e) || (b >= 0xa1 && b <= 0xac) || (b >= 0xae);
        if !printable {
            t[n] = b as u8;
            n += 1;
        }
        b += 1;
    }
    t
};
