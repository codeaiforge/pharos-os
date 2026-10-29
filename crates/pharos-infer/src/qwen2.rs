//! Qwen2-architecture models from GGUF files with Q8_0 weights (M3.1
//! tier S: Qwen2.5-0.5B-Instruct q8_0), following llama.cpp's Qwen2 graph:
//! RMS norm, attention with biases on Q, K, and V, grouped-query attention,
//! "NeoX" rotary embeddings (each head's halves rotated together), and a
//! SwiGLU feed-forward layer.

use alloc::vec;
use alloc::vec::Vec;

use crate::gguf::{Gguf, TYPE_Q8_0, Tensor};
use crate::quant::{Q8Vec, QK8_0, dequantize_q8_0, dot_q8_0};
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

/// Activations and the key/value cache for up to `max_pos` positions.
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
    quant: Q8Vec,
}

impl Qwen2State {
    /// State for `max_pos` positions (at most the model's context).
    pub fn new(c: &Qwen2Config, max_pos: usize) -> Self {
        let max_pos = max_pos.min(c.context);
        let cache = c.n_layers * max_pos * c.kv_dim();
        Self {
            max_pos,
            x: vec![0.0; c.dim],
            xb: vec![0.0; c.dim],
            q: vec![0.0; c.dim],
            att_out: vec![0.0; c.dim],
            hb: vec![0.0; c.hidden_dim],
            hb2: vec![0.0; c.hidden_dim],
            att: vec![0.0; max_pos],
            logits: vec![0.0; c.vocab_size],
            key_cache: vec![0.0; cache],
            value_cache: vec![0.0; cache],
            quant: Q8Vec::new(),
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

/// `out = W x` for Q8_0 `W` (one row per output), with `x` quantized first.
fn matvec(out: &mut [f32], w: &Tensor<'_>, x: &[f32], quant: &mut Q8Vec) {
    quant.quantize(x);
    for (i, o) in out.iter_mut().enumerate() {
        *o = dot_q8_0(w.row(i), quant);
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
        let c = &self.config;
        let (kv_dim, hs) = (c.kv_dim(), c.head_size());
        let kv_mul = c.n_heads / c.n_kv_heads;
        dequantize_q8_0(self.embedding.row(token), &mut s.x);
        let scale = 1.0 / m.sqrt(hs as f32);

        for (l, layer) in self.layers.iter().enumerate() {
            rmsnorm(&mut s.xb, &s.x, &layer.attn_norm, c.rms_eps, m);
            let at = (l * s.max_pos + pos) * kv_dim;
            matvec(&mut s.q, &layer.q, &s.xb, &mut s.quant);
            matvec(
                &mut s.key_cache[at..at + kv_dim],
                &layer.k,
                &s.xb,
                &mut s.quant,
            );
            matvec(
                &mut s.value_cache[at..at + kv_dim],
                &layer.v,
                &s.xb,
                &mut s.quant,
            );
            for (v, b) in s.q.iter_mut().zip(&layer.q_bias) {
                *v += b;
            }
            for (v, b) in s.key_cache[at..at + kv_dim].iter_mut().zip(&layer.k_bias) {
                *v += b;
            }
            for (v, b) in s.value_cache[at..at + kv_dim].iter_mut().zip(&layer.v_bias) {
                *v += b;
            }
            rope(&mut s.q, hs, pos, c.rope_base, m);
            rope(&mut s.key_cache[at..at + kv_dim], hs, pos, c.rope_base, m);

            let base = l * s.max_pos * kv_dim;
            for h in 0..c.n_heads {
                let q = &s.q[h * hs..(h + 1) * hs];
                let kv_off = (h / kv_mul) * hs;
                let att = &mut s.att[..=pos];
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
                let out = &mut s.att_out[h * hs..(h + 1) * hs];
                out.fill(0.0);
                for (t, a) in att.iter().enumerate() {
                    let v = &s.value_cache[base + t * kv_dim + kv_off..][..hs];
                    for (o, x) in out.iter_mut().zip(v) {
                        *o += a / sum * x;
                    }
                }
            }
            matvec(&mut s.xb, &layer.o, &s.att_out, &mut s.quant);
            for (x, d) in s.x.iter_mut().zip(&s.xb) {
                *x += d;
            }

            rmsnorm(&mut s.xb, &s.x, &layer.ffn_norm, c.rms_eps, m);
            matvec(&mut s.hb, &layer.gate, &s.xb, &mut s.quant);
            matvec(&mut s.hb2, &layer.up, &s.xb, &mut s.quant);
            for (g, u) in s.hb.iter_mut().zip(&s.hb2) {
                *g = *g / (1.0 + m.exp(-*g)) * u;
            }
            matvec(&mut s.xb, &layer.down, &s.hb, &mut s.quant);
            for (x, d) in s.x.iter_mut().zip(&s.xb) {
                *x += d;
            }
        }

        let x = s.x.clone();
        rmsnorm(&mut s.x, &x, &self.output_norm, c.rms_eps, m);
        matvec(&mut s.logits, &self.output, &s.x, &mut s.quant);
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
