use super::*;
use std::string::String;
use std::vec::Vec;

struct Std;

impl Math for Std {
    fn sqrt(&self, x: f32) -> f32 {
        x.sqrt()
    }
    fn exp(&self, x: f32) -> f32 {
        x.exp()
    }
    fn sin(&self, x: f32) -> f32 {
        x.sin()
    }
    fn cos(&self, x: f32) -> f32 {
        x.cos()
    }
    fn powf(&self, x: f32, y: f32) -> f32 {
        x.powf(y)
    }
}

/// A deterministic pseudo-random source (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn weight(&mut self) -> f32 {
        (self.next() % 2001) as f32 / 1000.0 - 1.0
    }
}

const SMALL: Config = Config {
    dim: 16,
    hidden_dim: 24,
    n_layers: 2,
    n_heads: 4,
    n_kv_heads: 2,
    vocab_size: 32,
    seq_len: 12,
    shared_classifier: true,
};

/// Weight tensors in llama2.c order, as (name, values).
fn tensors(c: &Config, seed: u64) -> Vec<Vec<f32>> {
    let mut rng = Rng(seed);
    let (d, h, l, v, kv) = (c.dim, c.hidden_dim, c.n_layers, c.vocab_size, c.kv_dim());
    let mut make = |n: usize| (0..n).map(|_| rng.weight() * 0.5).collect::<Vec<f32>>();
    let mut t = vec![
        make(v * d),
        make(l * d),
        make(l * d * d),
        make(l * d * kv),
        make(l * d * kv),
        make(l * d * d),
        make(l * d),
        make(l * h * d),
        make(l * d * h),
        make(l * h * d),
        make(d),
        make(c.seq_len * c.head_size()),
    ];
    if !c.shared_classifier {
        t.push(make(v * d));
    }
    t
}

fn checkpoint(c: &Config, t: &[Vec<f32>]) -> Vec<u8> {
    let vocab = if c.shared_classifier {
        c.vocab_size as i32
    } else {
        -(c.vocab_size as i32)
    };
    let header = [
        c.dim as i32,
        c.hidden_dim as i32,
        c.n_layers as i32,
        c.n_heads as i32,
        c.n_kv_heads as i32,
        vocab,
        c.seq_len as i32,
    ];
    let mut out: Vec<u8> = header.iter().flat_map(|v| v.to_le_bytes()).collect();
    for tensor in t {
        out.extend(tensor.iter().flat_map(|v| v.to_le_bytes()));
    }
    out
}

fn header_with(c: &Config, patch: impl Fn(&mut [i32; 7])) -> Vec<u8> {
    let mut bytes = checkpoint(c, &tensors(c, 1));
    let mut h = [0i32; 7];
    for (i, v) in h.iter_mut().enumerate() {
        *v = i32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    patch(&mut h);
    for (i, v) in h.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

#[test]
fn parses_shared_and_separate_classifiers() {
    let m = Model::parse(&checkpoint(&SMALL, &tensors(&SMALL, 1))).unwrap();
    assert_eq!(m.config, SMALL);
    let separate = Config {
        shared_classifier: false,
        ..SMALL
    };
    let m = Model::parse(&checkpoint(&separate, &tensors(&separate, 1))).unwrap();
    assert_eq!(m.config, separate);
    assert_eq!(m.classifier.len(), SMALL.vocab_size * SMALL.dim);
}

#[test]
fn refuses_bad_headers_and_sizes() {
    let good = checkpoint(&SMALL, &tensors(&SMALL, 1));
    assert_eq!(Model::parse(&good[..20]).err(), Some(Error::Truncated));
    assert_eq!(
        Model::parse(&good[..good.len() - 4]).err(),
        Some(Error::Truncated)
    );
    let mut long = good.clone();
    long.push(0);
    assert_eq!(Model::parse(&long).err(), Some(Error::TrailingBytes));
    type Patch = fn(&mut [i32; 7]);
    let bad: [(&str, Patch); 9] = [
        ("zero dim", |h| h[0] = 0),
        ("negative layers", |h| h[2] = -2),
        ("heads not dividing dim", |h| h[3] = 3),
        ("kv heads not dividing heads", |h| h[4] = 3),
        ("more kv heads than heads", |h| h[4] = 8),
        ("odd head size", |h| {
            h[0] = 12;
            h[3] = 4;
            h[4] = 4
        }),
        ("dim above limit", |h| h[0] = (MAX_DIM * 2) as i32),
        ("vocab i32::MIN", |h| h[5] = i32::MIN),
        ("huge everything", |h| {
            *h = [1 << 14, 1 << 16, 256, 1 << 14, 1 << 14, 1 << 18, 1 << 16]
        }),
    ];
    for (what, patch) in bad {
        let r = Model::parse(&header_with(&SMALL, patch));
        assert!(
            matches!(r, Err(Error::BadConfig | Error::Truncated)),
            "{what}: {:?}",
            r.err()
        );
    }
    // Huge but valid dimensions (head size 256) are refused by size, before
    // allocating anything.
    let r = Model::parse(&header_with(&SMALL, |h| {
        *h = [1 << 14, 1 << 16, 256, 1 << 6, 1 << 6, 1 << 18, 1 << 16]
    }));
    assert_eq!(r.err(), Some(Error::Truncated));
}

#[test]
fn forward_is_finite_and_deterministic() {
    let model = Model::parse(&checkpoint(&SMALL, &tensors(&SMALL, 7))).unwrap();
    let run = || {
        let mut s = State::new(&model.config);
        let mut all = Vec::new();
        for (pos, tok) in [1usize, 5, 9, 3].iter().enumerate() {
            all.extend_from_slice(model.forward(&mut s, *tok, pos, &Std));
        }
        all
    };
    let a = run();
    assert!(a.iter().all(|v| v.is_finite()));
    assert_eq!(a, run(), "same input, same logits");
}

#[test]
fn runs_every_position_up_to_seq_len() {
    // The last position of the last layer is where a cache index past
    // kv_dim would run off the end.
    let model = Model::parse(&checkpoint(&SMALL, &tensors(&SMALL, 9))).unwrap();
    let mut s = State::new(&SMALL);
    for pos in 0..SMALL.seq_len {
        let logits = model.forward(&mut s, pos % SMALL.vocab_size, pos, &Std);
        assert!(logits.iter().all(|v| v.is_finite()), "position {pos}");
    }
}

#[test]
fn shared_kv_heads_equal_copied_kv_heads() {
    // A model with 2 KV heads for 4 query heads must equal the same model
    // with each KV head's weights copied out to one per query head.
    let grouped = SMALL;
    let full = Config {
        n_kv_heads: 4,
        ..SMALL
    };
    let t = tensors(&grouped, 3);
    let (d, l, hs) = (SMALL.dim, SMALL.n_layers, SMALL.head_size());
    let expand = |w: &Vec<f32>| {
        let mut out = Vec::new();
        for layer in 0..l {
            let rows = &w[layer * d * grouped.kv_dim()..(layer + 1) * d * grouped.kv_dim()];
            for head in 0..4 {
                let kv = head / 2;
                out.extend_from_slice(&rows[kv * hs * d..(kv + 1) * hs * d]);
            }
        }
        out
    };
    let mut t_full = t.clone();
    t_full[3] = expand(&t[3]);
    t_full[4] = expand(&t[4]);
    let a = Model::parse(&checkpoint(&grouped, &t)).unwrap();
    let b = Model::parse(&checkpoint(&full, &t_full)).unwrap();
    let (mut sa, mut sb) = (State::new(&grouped), State::new(&full));
    for (pos, tok) in [2usize, 7, 11, 4, 4].iter().enumerate() {
        let la = a.forward(&mut sa, *tok, pos, &Std).to_vec();
        let lb = b.forward(&mut sb, *tok, pos, &Std);
        assert_eq!(la, lb, "position {pos}");
    }
}

/// A llama2.c tokenizer: <unk>, <s>, </s>, 256 byte tokens, then `extra`.
fn tokenizer_bytes(extra: &[(&str, f32)]) -> (Vec<u8>, usize) {
    let mut pieces: Vec<(Vec<u8>, f32)> = vec![
        (b"<unk>".to_vec(), 0.0),
        (b"<s>".to_vec(), 0.0),
        (b"</s>".to_vec(), 0.0),
    ];
    for b in 0..=255u8 {
        pieces.push((std::format!("<0x{b:02X}>").into_bytes(), 0.0));
    }
    for (p, s) in extra {
        pieces.push((p.as_bytes().to_vec(), *s));
    }
    let mut out = 16i32.to_le_bytes().to_vec();
    for (p, s) in &pieces {
        out.extend(s.to_le_bytes());
        out.extend((p.len() as i32).to_le_bytes());
        out.extend(p);
    }
    (out, pieces.len())
}

const EXTRA: [(&str, f32); 6] = [
    (" ", -1.0),
    ("a", -2.0),
    ("b", -2.0),
    ("ab", -0.5),
    (" ab", -0.1),
    ("é", -3.0),
];

fn id(t: &Tokenizer, piece: &str) -> usize {
    t.lookup(piece.as_bytes()).unwrap()
}

#[test]
fn encodes_with_merges_and_byte_fallback() {
    let (bytes, n) = tokenizer_bytes(&EXTRA);
    let t = Tokenizer::parse(&bytes, n).unwrap();
    assert_eq!(t.encode("ab"), [BOS, id(&t, " ab")], "merged twice");
    assert_eq!(t.encode("é"), [BOS, id(&t, " "), id(&t, "é")]);
    assert_eq!(
        t.encode("ñ"),
        [BOS, id(&t, " "), 0xC3 + 3, 0xB1 + 3],
        "no piece: raw bytes"
    );
    assert_eq!(t.encode(""), [BOS]);
}

#[test]
fn the_highest_scoring_merge_wins() {
    // "ab" and "bc" compete for the "b"; "bc" scores higher, so "abc" is
    // a + bc, not ab + c.
    let extra = [
        (" ", -1.0),
        ("a", -2.0),
        ("b", -2.0),
        ("c", -2.0),
        ("ab", -1.5),
        ("bc", -0.2),
    ];
    let (bytes, n) = tokenizer_bytes(&extra);
    let t = Tokenizer::parse(&bytes, n).unwrap();
    assert_eq!(
        t.encode("abc"),
        [BOS, id(&t, " "), id(&t, "a"), id(&t, "bc")]
    );
}

#[test]
fn decodes_bytes_and_leading_space() {
    let (bytes, n) = tokenizer_bytes(&EXTRA);
    let t = Tokenizer::parse(&bytes, n).unwrap();
    assert_eq!(
        t.decode(BOS, id(&t, " ab")),
        b"ab",
        "space dropped after BOS"
    );
    assert_eq!(t.decode(5, id(&t, " ab")), b" ab");
    assert_eq!(t.decode(5, 0x41 + 3), b"A", "<0x41> is the byte 'A'");
    assert_eq!(t.decode(5, 100_000), b"", "unknown ID decodes to nothing");
}

#[test]
fn refuses_bad_tokenizers() {
    let (bytes, n) = tokenizer_bytes(&EXTRA);
    assert_eq!(
        Tokenizer::parse(&bytes, n + 1).err(),
        Some(Error::Truncated)
    );
    assert_eq!(
        Tokenizer::parse(&bytes, n - 1).err(),
        Some(Error::TrailingBytes)
    );
    assert_eq!(Tokenizer::parse(&bytes, 0).err(), Some(Error::BadTokenizer));
    let mut long_piece = bytes.clone();
    long_piece[0..4].copy_from_slice(&2i32.to_le_bytes()); // max length 2, "<unk>" is 5
    assert_eq!(
        Tokenizer::parse(&long_piece, n).err(),
        Some(Error::BadTokenizer)
    );
}

#[test]
fn generate_replays_the_prompt_then_stops_at_steps() {
    let c = Config {
        vocab_size: 259 + EXTRA.len(),
        seq_len: 16,
        ..SMALL
    };
    let model = Model::parse(&checkpoint(&c, &tensors(&c, 5))).unwrap();
    let (bytes, n) = tokenizer_bytes(&EXTRA);
    let t = Tokenizer::parse(&bytes, n).unwrap();
    let run = || {
        let mut emitted = Vec::new();
        let counts = generate(&model, &t, "ab", 6, &Std, |prev, next| {
            emitted.push((prev, next))
        });
        (counts, emitted)
    };
    let ((prompt, generated), emitted) = run();
    assert_eq!(prompt, 2, "BOS and ' ab'");
    assert!(
        generated <= 5,
        "6 steps: 1 prompt step and at most 5 generated"
    );
    assert!(
        emitted.len() == generated + 1 || emitted.len() < 6,
        "the prompt step is printed too"
    );
    if let Some(first) = emitted.first() {
        assert_eq!(
            *first,
            (BOS, id(&t, " ab")),
            "the prompt token is printed first"
        );
    }
    assert_eq!(run().1, emitted, "greedy decoding is deterministic");
    let text: String = emitted
        .iter()
        .map(|(p, n)| String::from_utf8_lossy(&t.decode(*p, *n)).into_owned())
        .collect();
    assert!(text.starts_with("ab"));
}

#[test]
fn fuzzed_files_never_panic() {
    let good = checkpoint(&SMALL, &tensors(&SMALL, 1));
    let (tok, n) = tokenizer_bytes(&EXTRA);
    let mut rng = Rng(0x5eed);
    for i in 0..20_000 {
        let (src, is_model) = if i % 2 == 0 {
            (&good, true)
        } else {
            (&tok, false)
        };
        let mut f = src.clone();
        for _ in 0..(rng.next() % 4 + 1) {
            // Mostly the header and lengths, where the checks are.
            let at = (rng.next() as usize) % f.len().min(if i % 4 < 2 { 64 } else { f.len() });
            f[at] = rng.next() as u8;
        }
        let len = (rng.next() as usize) % (f.len() + 8);
        f.resize(len, 0);
        if is_model {
            let _ = Model::parse(&f);
        } else {
            let _ = Tokenizer::parse(&f, n);
        }
    }
}
