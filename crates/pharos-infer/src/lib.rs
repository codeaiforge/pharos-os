//! Pharos OS native inference engine: a **spike** for the M3.1 runtime
//! evaluation (#69, D-010), not a product.
//!
//! It runs Llama-architecture models in the llama2.c checkpoint format
//! (f32 weights) with greedy decoding, following the reference `run.c` from
//! github.com/karpathy/llama2.c (MIT) so its output can be compared token by
//! token; and Qwen2 models from GGUF files with Q8_0 weights ([`gguf`],
//! [`quant`], [`qwen2`]), following llama.cpp's Qwen2 graph for comparison
//! with llama.cpp. The question it answers is what the smallest inference core costs
//! to port to Pharos (D-020: built and tested on the host, later run
//! unchanged on Pharos).
//!
//! - `no_std` with `alloc`, no dependencies, `unsafe` forbidden (workspace
//!   lint). Floating-point functions (`sqrt`, `exp`, `sin`, `cos`, `powf`)
//!   are not in `core`, so the caller supplies them through [`Math`]; the
//!   host passes the standard library's.
//! - Model and tokenizer files are untrusted input: every size is checked
//!   with overflow checks before anything is allocated, and no input makes
//!   the parsers panic (fuzzed in the tests).
//! - Single-threaded and deterministic: the same model, prompt, and step
//!   count always give the same tokens.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod bpe;
pub mod gguf;
pub mod quant;
pub mod qwen2;
pub mod unicode;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// Floating-point functions the engine needs and `core` lacks.
pub trait Math {
    fn sqrt(&self, x: f32) -> f32;
    fn exp(&self, x: f32) -> f32;
    fn sin(&self, x: f32) -> f32;
    fn cos(&self, x: f32) -> f32;
    fn powf(&self, x: f32, y: f32) -> f32;
}

/// Largest accepted dimensions: far above the M3.1 candidates, small enough
/// that size arithmetic cannot approach `usize` limits.
pub const MAX_DIM: usize = 1 << 14;
pub const MAX_HIDDEN: usize = 1 << 16;
pub const MAX_LAYERS: usize = 256;
pub const MAX_VOCAB: usize = 1 << 18;
pub const MAX_SEQ: usize = 1 << 16;
/// Longest token piece in a tokenizer file.
pub const MAX_PIECE: usize = 256;

/// Token IDs fixed by the llama2.c tokenizer.
pub const BOS: usize = 1;
pub const EOS: usize = 2;

/// Why a file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than its header or its declared contents.
    Truncated,
    /// A dimension is zero, negative, above its limit, or inconsistent.
    BadConfig,
    /// The tokenizer's vocabulary does not match the model.
    BadTokenizer,
    /// More bytes than the declared contents (only for exact formats).
    TrailingBytes,
    /// Not a supported file format or version, or a malformed field.
    BadFormat,
    /// A tensor the model needs is missing.
    MissingTensor,
    /// A tensor type this engine does not compute with.
    UnsupportedType,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "file is shorter than its declared contents",
            Self::BadConfig => "model dimensions are invalid or above the engine's limits",
            Self::BadTokenizer => "tokenizer file is invalid or does not match the model",
            Self::TrailingBytes => "file has bytes after its declared contents",
            Self::BadFormat => "not a supported file format, or a malformed field",
            Self::MissingTensor => "a tensor the model needs is missing",
            Self::UnsupportedType => {
                "a tensor has a type this engine does not support (only F32 and Q8_0)"
            }
        })
    }
}

/// Model dimensions, from the checkpoint header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub dim: usize,
    pub hidden_dim: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub n_kv_heads: usize,
    pub vocab_size: usize,
    pub seq_len: usize,
    /// The classifier reuses the token embedding (llama2.c: positive vocab).
    pub shared_classifier: bool,
}

impl Config {
    pub fn head_size(&self) -> usize {
        self.dim / self.n_heads
    }

    pub fn kv_dim(&self) -> usize {
        self.dim / self.n_heads * self.n_kv_heads
    }

    fn check(&self) -> Result<(), Error> {
        let in_range = |v: usize, max: usize| v > 0 && v <= max;
        let ok = in_range(self.dim, MAX_DIM)
            && in_range(self.hidden_dim, MAX_HIDDEN)
            && in_range(self.n_layers, MAX_LAYERS)
            && in_range(self.n_heads, self.dim)
            && in_range(self.n_kv_heads, self.n_heads)
            && in_range(self.vocab_size, MAX_VOCAB)
            && in_range(self.seq_len, MAX_SEQ)
            && self.dim % self.n_heads == 0
            && self.n_heads % self.n_kv_heads == 0
            && self.head_size() % 2 == 0;
        if ok { Ok(()) } else { Err(Error::BadConfig) }
    }

    /// Number of f32 values the checkpoint holds after the header, in
    /// llama2.c order (including the two unused RoPE tables).
    fn weight_count(&self) -> Option<usize> {
        let (d, h, l, v, kv) = (
            self.dim,
            self.hidden_dim,
            self.n_layers,
            self.vocab_size,
            self.kv_dim(),
        );
        let per_layer = d
            .checked_mul(d)?
            .checked_mul(2)? // wq, wo
            .checked_add(d.checked_mul(kv)?.checked_mul(2)?)? // wk, wv
            .checked_add(d.checked_mul(h)?.checked_mul(3)?)? // w1, w2, w3
            .checked_add(d.checked_mul(2)?)?; // two rmsnorm weights
        let rope = self.seq_len.checked_mul(self.head_size())?; // two tables of half size
        let classifier = if self.shared_classifier {
            0
        } else {
            v.checked_mul(d)?
        };
        v.checked_mul(d)?
            .checked_add(per_layer.checked_mul(l)?)?
            .checked_add(d)?
            .checked_add(rope)?
            .checked_add(classifier)
    }
}

/// A parsed model: dimensions and weights.
pub struct Model {
    pub config: Config,
    token_embedding: Vec<f32>,
    rms_att: Vec<f32>,
    wq: Vec<f32>,
    wk: Vec<f32>,
    wv: Vec<f32>,
    wo: Vec<f32>,
    rms_ffn: Vec<f32>,
    w1: Vec<f32>,
    w2: Vec<f32>,
    w3: Vec<f32>,
    rms_final: Vec<f32>,
    /// Empty when the classifier is shared with the token embedding.
    classifier: Vec<f32>,
}

/// Reads little-endian values from a byte slice, refusing to run past it.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if n > self.bytes.len() {
            return Err(Error::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn i32(&mut self) -> Result<i32, Error> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn f32s(&mut self, n: usize) -> Result<Vec<f32>, Error> {
        let bytes = self.take(n.checked_mul(4).ok_or(Error::Truncated)?)?;
        Ok(bytes
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect())
    }
}

fn positive(v: i32) -> Result<usize, Error> {
    usize::try_from(v)
        .ok()
        .filter(|&v| v > 0)
        .ok_or(Error::BadConfig)
}

impl Model {
    /// Parses a llama2.c checkpoint. Checks the header and the total size
    /// before allocating any weights.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes };
        let mut header = [0i32; 7];
        for v in header.iter_mut() {
            *v = r.i32()?;
        }
        let [dim, hidden, layers, heads, kv_heads, vocab, seq] = header;
        let config = Config {
            dim: positive(dim)?,
            hidden_dim: positive(hidden)?,
            n_layers: positive(layers)?,
            n_heads: positive(heads)?,
            n_kv_heads: positive(kv_heads)?,
            vocab_size: positive(vocab.checked_abs().ok_or(Error::BadConfig)?)?,
            seq_len: positive(seq)?,
            shared_classifier: vocab > 0,
        };
        config.check()?;
        let count = config.weight_count().ok_or(Error::BadConfig)?;
        let needed = count.checked_mul(4).ok_or(Error::BadConfig)?;
        if r.bytes.len() < needed {
            return Err(Error::Truncated);
        }
        if r.bytes.len() > needed {
            return Err(Error::TrailingBytes);
        }
        let c = config;
        let (d, h, l, kv) = (c.dim, c.hidden_dim, c.n_layers, c.kv_dim());
        let token_embedding = r.f32s(c.vocab_size * d)?;
        let rms_att = r.f32s(l * d)?;
        let wq = r.f32s(l * d * d)?;
        let wk = r.f32s(l * d * kv)?;
        let wv = r.f32s(l * d * kv)?;
        let wo = r.f32s(l * d * d)?;
        let rms_ffn = r.f32s(l * d)?;
        let w1 = r.f32s(l * h * d)?;
        let w2 = r.f32s(l * d * h)?;
        let w3 = r.f32s(l * h * d)?;
        let rms_final = r.f32s(d)?;
        r.take(c.seq_len * c.head_size() * 4)?; // unused RoPE tables
        let classifier = if c.shared_classifier {
            Vec::new()
        } else {
            r.f32s(c.vocab_size * d)?
        };
        Ok(Self {
            config,
            token_embedding,
            rms_att,
            wq,
            wk,
            wv,
            wo,
            rms_ffn,
            w1,
            w2,
            w3,
            rms_final,
            classifier,
        })
    }
}

/// Activations and the key/value cache for one sequence.
pub struct State {
    x: Vec<f32>,
    xb: Vec<f32>,
    xb2: Vec<f32>,
    hb: Vec<f32>,
    hb2: Vec<f32>,
    q: Vec<f32>,
    att: Vec<f32>,
    logits: Vec<f32>,
    key_cache: Vec<f32>,
    value_cache: Vec<f32>,
}

impl State {
    pub fn new(c: &Config) -> Self {
        let cache = c.n_layers * c.seq_len * c.kv_dim();
        Self {
            x: vec![0.0; c.dim],
            xb: vec![0.0; c.dim],
            xb2: vec![0.0; c.dim],
            hb: vec![0.0; c.hidden_dim],
            hb2: vec![0.0; c.hidden_dim],
            q: vec![0.0; c.dim],
            att: vec![0.0; c.n_heads * c.seq_len],
            logits: vec![0.0; c.vocab_size],
            key_cache: vec![0.0; cache],
            value_cache: vec![0.0; cache],
        }
    }
}

fn rmsnorm(out: &mut [f32], x: &[f32], weight: &[f32], m: &impl Math) {
    let ss = x.iter().map(|v| v * v).sum::<f32>() / x.len() as f32 + 1e-5;
    let scale = 1.0 / m.sqrt(ss);
    for ((o, v), w) in out.iter_mut().zip(x).zip(weight) {
        *o = w * (scale * v);
    }
}

/// `out = W x`, with `W` row-major, `out.len()` rows of `x.len()` columns.
fn matmul(out: &mut [f32], x: &[f32], w: &[f32]) {
    let n = x.len();
    for (o, row) in out.iter_mut().zip(w.chunks_exact(n)) {
        *o = row.iter().zip(x).map(|(a, b)| a * b).sum();
    }
}

fn softmax(x: &mut [f32], m: &impl Math) {
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0;
    for v in x.iter_mut() {
        *v = m.exp(*v - max);
        sum += *v;
    }
    for v in x.iter_mut() {
        *v /= sum;
    }
}

impl Model {
    /// Runs one token at position `pos` and returns the logits. `pos` must
    /// be below `seq_len` and `token` below `vocab_size`.
    pub fn forward<'s>(
        &self,
        s: &'s mut State,
        token: usize,
        pos: usize,
        m: &impl Math,
    ) -> &'s [f32] {
        let c = &self.config;
        let (dim, hidden, kv_dim, hs) = (c.dim, c.hidden_dim, c.kv_dim(), c.head_size());
        let kv_mul = c.n_heads / c.n_kv_heads;
        s.x.copy_from_slice(&self.token_embedding[token * dim..(token + 1) * dim]);

        for l in 0..c.n_layers {
            rmsnorm(&mut s.xb, &s.x, &self.rms_att[l * dim..(l + 1) * dim], m);
            let at = (l * c.seq_len + pos) * kv_dim;
            matmul(
                &mut s.q,
                &s.xb,
                &self.wq[l * dim * dim..(l + 1) * dim * dim],
            );
            matmul(
                &mut s.key_cache[at..at + kv_dim],
                &s.xb,
                &self.wk[l * dim * kv_dim..(l + 1) * dim * kv_dim],
            );
            matmul(
                &mut s.value_cache[at..at + kv_dim],
                &s.xb,
                &self.wv[l * dim * kv_dim..(l + 1) * dim * kv_dim],
            );

            // RoPE, as in run.c: rotate q always, k only within kv_dim.
            for i in (0..dim).step_by(2) {
                let head_dim = (i % hs) as f32;
                let freq = 1.0 / m.powf(10000.0, head_dim / hs as f32);
                let val = pos as f32 * freq;
                let (fcr, fci) = (m.cos(val), m.sin(val));
                let (q0, q1) = (s.q[i], s.q[i + 1]);
                s.q[i] = q0 * fcr - q1 * fci;
                s.q[i + 1] = q0 * fci + q1 * fcr;
                if i < kv_dim {
                    let k = &mut s.key_cache[at + i..at + i + 2];
                    let (k0, k1) = (k[0], k[1]);
                    k[0] = k0 * fcr - k1 * fci;
                    k[1] = k0 * fci + k1 * fcr;
                }
            }

            let layer = l * c.seq_len * kv_dim;
            for h in 0..c.n_heads {
                let q = &s.q[h * hs..(h + 1) * hs];
                let att = &mut s.att[h * c.seq_len..h * c.seq_len + pos + 1];
                let kv_off = (h / kv_mul) * hs;
                for (t, a) in att.iter_mut().enumerate() {
                    let k = &s.key_cache[layer + t * kv_dim + kv_off..][..hs];
                    *a = q.iter().zip(k).map(|(x, y)| x * y).sum::<f32>() / m.sqrt(hs as f32);
                }
                softmax(att, m);
                let xb = &mut s.xb[h * hs..(h + 1) * hs];
                xb.fill(0.0);
                for (t, a) in att.iter().enumerate() {
                    let v = &s.value_cache[layer + t * kv_dim + kv_off..][..hs];
                    for (o, x) in xb.iter_mut().zip(v) {
                        *o += a * x;
                    }
                }
            }
            matmul(
                &mut s.xb2,
                &s.xb,
                &self.wo[l * dim * dim..(l + 1) * dim * dim],
            );
            for (x, d) in s.x.iter_mut().zip(&s.xb2) {
                *x += d;
            }

            rmsnorm(&mut s.xb, &s.x, &self.rms_ffn[l * dim..(l + 1) * dim], m);
            let wh = l * hidden * dim..(l + 1) * hidden * dim;
            matmul(&mut s.hb, &s.xb, &self.w1[wh.clone()]);
            matmul(&mut s.hb2, &s.xb, &self.w3[wh]);
            for (a, b) in s.hb.iter_mut().zip(&s.hb2) {
                *a = *a * (1.0 / (1.0 + m.exp(-*a))) * b;
            }
            matmul(
                &mut s.xb,
                &s.hb,
                &self.w2[l * dim * hidden..(l + 1) * dim * hidden],
            );
            for (x, d) in s.x.iter_mut().zip(&s.xb) {
                *x += d;
            }
        }

        let x = s.x.clone();
        rmsnorm(&mut s.x, &x, &self.rms_final, m);
        let classifier = if c.shared_classifier {
            &self.token_embedding
        } else {
            &self.classifier
        };
        matmul(&mut s.logits, &s.x, classifier);
        &s.logits
    }
}

/// The index of the largest value (the first on ties), as `run.c` picks.
pub fn argmax(v: &[f32]) -> usize {
    let mut best = 0;
    for (i, x) in v.iter().enumerate() {
        if *x > v[best] {
            best = i;
        }
    }
    best
}

/// A llama2.c tokenizer: one piece and score per token ID.
pub struct Tokenizer {
    pieces: Vec<Vec<u8>>,
    scores: Vec<f32>,
    /// Token IDs sorted by piece, for lookups.
    sorted: Vec<usize>,
}

impl Tokenizer {
    /// Parses a llama2.c `tokenizer.bin` for a model with `vocab_size`
    /// tokens. The file must hold exactly that many pieces.
    pub fn parse(bytes: &[u8], vocab_size: usize) -> Result<Self, Error> {
        if vocab_size == 0 || vocab_size > MAX_VOCAB {
            return Err(Error::BadTokenizer);
        }
        let mut r = Reader { bytes };
        let max_len = positive(r.i32()?).map_err(|_| Error::BadTokenizer)?;
        if max_len > MAX_PIECE {
            return Err(Error::BadTokenizer);
        }
        let mut pieces = Vec::new();
        let mut scores = Vec::new();
        for _ in 0..vocab_size {
            let score = f32::from_le_bytes(r.take(4)?.try_into().map_err(|_| Error::Truncated)?);
            let len = usize::try_from(r.i32()?).map_err(|_| Error::BadTokenizer)?;
            if len > max_len {
                return Err(Error::BadTokenizer);
            }
            pieces.push(r.take(len)?.to_vec());
            scores.push(score);
        }
        if !r.bytes.is_empty() {
            return Err(Error::TrailingBytes);
        }
        let mut sorted: Vec<usize> = (0..vocab_size).collect();
        sorted.sort_by(|&a, &b| pieces[a].cmp(&pieces[b]).then(a.cmp(&b)));
        Ok(Self {
            pieces,
            scores,
            sorted,
        })
    }

    fn lookup(&self, piece: &[u8]) -> Option<usize> {
        self.sorted
            .binary_search_by(|&id| self.pieces[id].as_slice().cmp(piece))
            .ok()
            .map(|i| self.sorted[i])
    }

    /// Encodes `text` as `run.c` does: BOS, a leading-space piece, one token
    /// per UTF-8 character (raw bytes as `<0xXX>` tokens, IDs `byte + 3`,
    /// when a character has no piece), then repeated merges of the adjacent
    /// pair with the highest score.
    pub fn encode(&self, text: &str) -> Vec<usize> {
        let mut tokens = vec![BOS];
        if !text.is_empty() {
            if let Some(space) = self.lookup(b" ") {
                tokens.push(space);
            }
        }
        let mut buf = [0u8; 4];
        for ch in text.chars() {
            let bytes = ch.encode_utf8(&mut buf).as_bytes();
            match self.lookup(bytes) {
                Some(id) => tokens.push(id),
                None => tokens.extend(bytes.iter().map(|b| usize::from(*b) + 3)),
            }
        }
        let mut merged = Vec::new();
        loop {
            let mut best: Option<(f32, usize, usize)> = None;
            for i in 0..tokens.len().saturating_sub(1) {
                merged.clear();
                merged.extend_from_slice(self.piece(tokens[i]));
                merged.extend_from_slice(self.piece(tokens[i + 1]));
                if let Some(id) = self.lookup(&merged) {
                    if best.is_none_or(|(score, _, _)| self.scores[id] > score) {
                        best = Some((self.scores[id], id, i));
                    }
                }
            }
            match best {
                Some((_, id, i)) => {
                    tokens[i] = id;
                    tokens.remove(i + 1);
                }
                None => return tokens,
            }
        }
    }

    fn piece(&self, id: usize) -> &[u8] {
        self.pieces.get(id).map_or(&[], Vec::as_slice)
    }

    /// The bytes token `id` stands for after `prev`, as `run.c` prints them:
    /// a leading space is dropped after BOS, and `<0xXX>` is that raw byte.
    pub fn decode(&self, prev: usize, id: usize) -> Vec<u8> {
        let mut piece = self.piece(id);
        if prev == BOS && piece.first() == Some(&b' ') {
            piece = &piece[1..];
        }
        if let [b'<', b'0', b'x', h, l, b'>'] = piece {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(*h), hex(*l)) {
                return vec![(h * 16 + l) as u8];
            }
        }
        piece.to_vec()
    }
}

/// Greedy generation as `run.c` does it: feed the prompt, then the most
/// likely token, for at most `steps` positions (and at most `seq_len`),
/// stopping at BOS. Calls `emit(prev, next)` at every step, prompt tokens
/// included, as `run.c` prints them. Returns the number of prompt tokens
/// (BOS included) and of generated tokens.
pub fn generate(
    model: &Model,
    tokenizer: &Tokenizer,
    prompt: &str,
    steps: usize,
    m: &impl Math,
    mut emit: impl FnMut(usize, usize),
) -> (usize, usize) {
    let c = &model.config;
    let prompt_tokens = tokenizer.encode(prompt);
    let steps = steps.min(c.seq_len);
    let mut state = State::new(c);
    let mut token = prompt_tokens[0];
    let mut generated = 0;
    for pos in 0..steps {
        if token >= c.vocab_size {
            break;
        }
        let logits = model.forward(&mut state, token, pos, m);
        let next = if pos + 1 < prompt_tokens.len() {
            prompt_tokens[pos + 1]
        } else {
            generated += 1;
            argmax(logits)
        };
        if next == BOS {
            break;
        }
        emit(token, next);
        token = next;
    }
    (prompt_tokens.len(), generated)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bpe;
#[cfg(test)]
mod tests_gguf;
