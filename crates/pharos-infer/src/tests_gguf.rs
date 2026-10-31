//! Tests for the GGUF reader, Q8_0 arithmetic, and the Qwen2 model, on
//! small files built here.

use crate::gguf::{Gguf, TYPE_F32, Value};
use crate::quant::{Q8Vec, dequantize_q8_0, dot_q8_0, f16_to_f32, f32_to_f16, quantize_row_q8_0};
use crate::qwen2::{MAX_BATCH, Qwen2, Qwen2State, decode_byte_level};
use crate::synth::{
    Meta, TINY, TINY_PROMPT, TINY_SEED, TensorSpec, f32_tensor, gguf_file, q8_tensor, run_tiny,
    tiny_model,
};
use crate::{Error, Math};
use std::vec;
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

// ---- half precision and Q8_0 ----

#[test]
fn f16_known_values() {
    assert_eq!(f16_to_f32(0x3c00), 1.0);
    assert_eq!(f16_to_f32(0x3800), 0.5);
    assert_eq!(f16_to_f32(0xc000), -2.0);
    assert_eq!(f16_to_f32(0x7bff), 65504.0);
    assert_eq!(f16_to_f32(0x0001), 2f32.powi(-24), "smallest subnormal");
    assert_eq!(f16_to_f32(0x0200), 2f32.powi(-15));
    assert_eq!(f16_to_f32(0x7c00), f32::INFINITY);
    assert!(f16_to_f32(0x7e00).is_nan());
    assert_eq!(f32_to_f16(65520.0), 0x7c00, "rounds up to infinity");
    assert_eq!(
        f32_to_f16(1.0 + 2f32.powi(-11)),
        0x3c00,
        "tie to even (down)"
    );
    assert_eq!(
        f32_to_f16(1.0 + 3.0 * 2f32.powi(-11)),
        0x3c02,
        "tie to even (up)"
    );
    assert_eq!(
        f32_to_f16(2f32.powi(-25)),
        0x0000,
        "half the smallest subnormal ties to 0"
    );
    assert_eq!(f32_to_f16(2f32.powi(-25) * 1.5), 0x0001);
    assert_eq!(f32_to_f16(f32::NAN) & 0x7e00, 0x7e00);
}

#[test]
fn every_f16_round_trips_through_f32() {
    for h in 0..=u16::MAX {
        let f = f16_to_f32(h);
        if f.is_nan() {
            continue;
        }
        assert_eq!(f32_to_f16(f), h, "{h:#06x}");
    }
}

#[test]
fn activation_quantization_rounds_half_to_even() {
    // max |x| = 127 gives scale 1, so x * id = x exactly.
    let mut x = vec![0.0f32; 32];
    x[0] = 127.0;
    x[1] = 2.5;
    x[2] = 3.5;
    x[3] = -2.5;
    let mut q = Q8Vec::new();
    q.quantize(&x);
    assert_eq!(q.scales, [1.0]);
    assert_eq!(&q.values[..4], &[127, 2, 4, -2]);
}

#[test]
fn q8_0_dot_matches_f32_within_quantization_error() {
    let x: Vec<f32> = (0..96)
        .map(|i| ((i * 37 % 101) as f32 - 50.0) / 25.0)
        .collect();
    let w: Vec<f32> = (0..96)
        .map(|i| ((i * 53 % 89) as f32 - 44.0) / 30.0)
        .collect();
    let row = quantize_row_q8_0(&w);
    let mut deq = vec![0.0; 96];
    dequantize_q8_0(&row, &mut deq);
    assert!(
        w.iter()
            .zip(&deq)
            .all(|(a, b)| (a - b).abs() <= 1.5 / 127.0 * 1.01)
    );
    let mut q = Q8Vec::new();
    q.quantize(&x);
    let exact: f32 = w.iter().zip(&x).map(|(a, b)| a * b).sum();
    let approx = dot_q8_0(&row, &q);
    assert!(
        (exact - approx).abs() < 0.05 * exact.abs().max(1.0),
        "{exact} vs {approx}"
    );
}

#[test]
fn reads_metadata_and_tensors() {
    let file = gguf_file(
        &[
            ("general.architecture", Meta::Str("qwen2")),
            ("n", Meta::U32(7)),
            ("eps", Meta::F32(0.5)),
            ("toks", Meta::Strings(vec!["a", "Ġb"])),
            ("types", Meta::I32s(vec![1, 3])),
        ],
        &[
            f32_tensor("norm", &[1.0, 2.0, 3.0]),
            q8_tensor("w", 32, &[0.25; 64]),
        ],
    );
    let g = Gguf::parse(&file).unwrap();
    assert_eq!(g.get(b"general.architecture"), Some(Value::Str(b"qwen2")));
    assert_eq!(g.uint(b"n"), Ok(7));
    assert_eq!(g.float(b"eps"), Ok(0.5));
    assert_eq!(g.strings(b"toks").unwrap(), [&b"a"[..], "Ġb".as_bytes()]);
    assert_eq!(g.ints(b"types").unwrap(), [1, 3]);
    assert_eq!(
        g.tensor(b"norm", &[3]).unwrap().f32s().unwrap(),
        [1.0, 2.0, 3.0]
    );
    let w = g.tensor(b"w", &[32, 2]).unwrap();
    assert_eq!((w.rows, w.cols, w.row(1).len()), (2, 32, 34));
    assert_eq!(
        g.tensor(b"w", &[32, 3]).err(),
        Some(Error::BadConfig),
        "wrong shape"
    );
    assert_eq!(g.tensor(b"x", &[1]).err(), Some(Error::MissingTensor));
    assert_eq!(g.uint(b"eps").err(), Some(Error::BadConfig), "wrong type");
}

#[test]
fn refuses_malformed_files() {
    let good = gguf_file(&[("n", Meta::U32(1))], &[f32_tensor("t", &[1.0; 8])]);
    // Every truncation is an error, never a panic.
    for n in 0..good.len() {
        assert!(Gguf::parse(&good[..n]).is_err(), "prefix of {n} bytes");
    }
    let patch = |at: usize, bytes: &[u8]| {
        let mut f = good.clone();
        f[at..at + bytes.len()].copy_from_slice(bytes);
        Gguf::parse(&f).err()
    };
    assert_eq!(patch(0, b"GGUG"), Some(Error::BadFormat));
    assert_eq!(
        patch(4, &2u32.to_le_bytes()),
        Some(Error::BadFormat),
        "version 2"
    );
    assert_eq!(
        patch(8, &u64::MAX.to_le_bytes()),
        Some(Error::BadFormat),
        "tensor count"
    );
    assert_eq!(
        patch(16, &u64::MAX.to_le_bytes()),
        Some(Error::BadFormat),
        "key count"
    );
    assert_eq!(
        patch(24, &u64::MAX.to_le_bytes()),
        Some(Error::BadFormat),
        "key length"
    );
    // An unknown value type, a nested array, a bad bool.
    let header = 24 + 8 + 1; // up to the value type of key "n"
    assert_eq!(patch(header, &99u32.to_le_bytes()), Some(Error::BadFormat));
    let nested = gguf_file(&[("a", Meta::I32s(vec![1]))], &[]);
    let mut f = nested.clone();
    f[24 + 8 + 1 + 4..24 + 8 + 1 + 8].copy_from_slice(&9u32.to_le_bytes());
    assert_eq!(
        Gguf::parse(&f).err(),
        Some(Error::BadFormat),
        "nested array"
    );

    let spec = |dims: Vec<u64>, ty: u32, len: usize| TensorSpec {
        name: "t".into(),
        dims,
        ty,
        data: vec![0; len],
    };
    let tensor_end = |t: TensorSpec| gguf_file(&[], &[t]);
    let mut f = tensor_end(spec(vec![8], TYPE_F32, 32));
    f.truncate(f.len() - 4);
    assert_eq!(
        Gguf::parse(&f).err(),
        Some(Error::Truncated),
        "data past the end"
    );
    assert_eq!(
        Gguf::parse(&tensor_end(spec(vec![0], TYPE_F32, 0))).err(),
        Some(Error::BadFormat),
        "zero dim"
    );
    let mut f = tensor_end(spec(vec![8], TYPE_F32, 32));
    let dims_at = 24 + 8 + 1;
    f[dims_at..dims_at + 4].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(
        Gguf::parse(&f).err(),
        Some(Error::BadFormat),
        "five dimensions"
    );
    let f = tensor_end(spec(vec![u64::MAX, 2], TYPE_F32, 0));
    assert_eq!(
        Gguf::parse(&f).err(),
        Some(Error::BadFormat),
        "element count overflow"
    );
    let f = tensor_end(spec(vec![32], 12, 64)); // Q4_K: not read by this engine
    let g = Gguf::parse(&f).unwrap();
    assert_eq!(g.tensor(b"t", &[32]).err(), Some(Error::UnsupportedType));
    let mut f = tensor_end(spec(vec![8], TYPE_F32, 32));
    let off_at = dims_at + 4 + 8 + 4;
    f[off_at..off_at + 8].copy_from_slice(&4u64.to_le_bytes());
    assert_eq!(
        Gguf::parse(&f).err(),
        Some(Error::BadFormat),
        "misaligned offset"
    );
}

#[test]
fn fuzzed_gguf_never_panics() {
    let file = gguf_file(
        &[
            ("toks", Meta::Strings(vec!["a", "b", "c"])),
            ("n", Meta::U32(3)),
        ],
        &[
            f32_tensor("norm", &[1.0; 8]),
            q8_tensor("w", 32, &[0.5; 64]),
        ],
    );
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..20_000 {
        let mut f = file.clone();
        for _ in 0..(next() % 4 + 1) {
            let at = (next() as usize) % f.len().min(256);
            f[at] = next() as u8;
        }
        let len = (next() as usize) % (f.len() + 8);
        f.resize(len, 0);
        if let Ok(g) = Gguf::parse(&f) {
            let _ = g.strings(b"toks");
            let _ = g.tensor(b"w", &[32, 2]).map(|t| t.row(1).len());
            let _ = g.tensor(b"norm", &[8]).and_then(|t| t.f32s());
        }
    }
}

// ---- Qwen2 ----

fn logits(file: &[u8], tokens: &[usize]) -> Vec<Vec<f32>> {
    let g = Gguf::parse(file).unwrap();
    let m = Qwen2::load(&g, TINY.vocab_size).unwrap();
    let mut s = Qwen2State::new(&m.config, tokens.len());
    tokens
        .iter()
        .enumerate()
        .map(|(pos, t)| m.forward(&mut s, *t, pos, &Std).to_vec())
        .collect()
}

#[test]
fn loads_and_runs_deterministically() {
    let file = tiny_model(1, false, false);
    let g = Gguf::parse(&file).unwrap();
    let m = Qwen2::load(&g, TINY.vocab_size).unwrap();
    assert_eq!(m.config, TINY);
    let tokens: Vec<usize> = (0..TINY.context).map(|i| i * 7 % TINY.vocab_size).collect();
    let a = logits(&file, &tokens);
    assert!(
        a.iter().flatten().all(|v| v.is_finite()),
        "every position up to the context"
    );
    assert_eq!(a, logits(&file, &tokens));
}

#[test]
fn batched_prompts_match_token_by_token() {
    let file = tiny_model(4, false, false);
    let g = Gguf::parse(&file).unwrap();
    let m = Qwen2::load(&g, TINY.vocab_size).unwrap();
    let tokens: Vec<usize> = (0..TINY.context)
        .map(|i| i * 11 % TINY.vocab_size)
        .collect();
    let single = logits(&file, &tokens);
    assert_eq!(TINY.context, MAX_BATCH, "one block can fill the context");
    for size in [1, 3, 7, MAX_BATCH] {
        let mut s = Qwen2State::new(&m.config, tokens.len());
        for (i, block) in tokens.chunks(size).enumerate() {
            let pos = i * size;
            let got = m.forward_batch(&mut s, block, pos, &Std);
            // Bit-identical, not just close.
            assert_eq!(got, &single[pos + block.len() - 1][..], "blocks of {size}");
        }
    }
}

/// [`Std`] with `sin` and `cos` swapped: a wrong math function.
struct Swapped;

impl Math for Swapped {
    fn sqrt(&self, x: f32) -> f32 {
        x.sqrt()
    }
    fn exp(&self, x: f32) -> f32 {
        x.exp()
    }
    fn sin(&self, x: f32) -> f32 {
        x.cos()
    }
    fn cos(&self, x: f32) -> f32 {
        x.sin()
    }
    fn powf(&self, x: f32, y: f32) -> f32 {
        x.powf(y)
    }
}

#[test]
fn tiny_run_is_deterministic_and_sees_the_math() {
    let file = tiny_model(TINY_SEED, false, false);
    let (tokens, hash) = run_tiny(&file, &Std).unwrap();
    assert_eq!(tokens.len(), TINY.context - TINY_PROMPT.len());
    let mut distinct = tokens.clone();
    distinct.sort();
    distinct.dedup();
    assert!(distinct.len() >= 5, "varied output: {tokens:?}");
    assert_eq!(run_tiny(&file, &Std).unwrap(), (tokens.clone(), hash));
    assert_ne!(run_tiny(&file, &Swapped).unwrap().1, hash);
    assert!(run_tiny(&file[..100], &Std).is_err());
}

#[test]
fn grouped_kv_heads_equal_expanded_kv_heads() {
    let tokens = [3, 9, 1, 27, 27, 5];
    assert_eq!(
        logits(&tiny_model(2, false, false), &tokens),
        logits(&tiny_model(2, true, false), &tokens)
    );
}

#[test]
fn missing_output_weight_ties_to_the_embedding() {
    // Seed and generation order are the same except output.weight, so a tied
    // model must differ from the untied one (it uses token_embd instead).
    let tied = logits(&tiny_model(3, false, true), &[1, 2, 3]);
    assert!(tied.iter().flatten().all(|v| v.is_finite()));
    assert_ne!(tied, logits(&tiny_model(3, false, false), &[1, 2, 3]));
}

#[test]
fn load_refuses_bad_models() {
    let good = tiny_model(4, false, false);
    let g = Gguf::parse(&good).unwrap();
    assert!(
        Qwen2::load(&g, TINY.vocab_size + 1).is_err(),
        "vocabulary does not match the embedding"
    );
    let llama = gguf_file(&[("general.architecture", Meta::Str("llama"))], &[]);
    assert_eq!(
        Qwen2::load(&Gguf::parse(&llama).unwrap(), 40).err(),
        Some(Error::BadConfig)
    );
}

#[test]
fn rope_rotates_each_heads_halves_together() {
    // Head size 4, position 1, base 10000: pair (0, 2) turns by 1 radian,
    // pair (1, 3) by 10000^(-1/2) = 0.01 radians (NeoX layout).
    let mut a = [1.0, 0.0, 0.0, 0.0];
    crate::qwen2::rope(&mut a, 4, 1, 10000.0, &Std);
    let want = [1f32.cos(), 0.0, 1f32.sin(), 0.0];
    assert!(
        a.iter().zip(want).all(|(x, y)| (x - y).abs() < 1e-6),
        "{a:?}"
    );
    let mut b = [0.0, 1.0, 0.0, 0.0];
    crate::qwen2::rope(&mut b, 4, 1, 10000.0, &Std);
    let want = [0.0, 0.01f32.cos(), 0.0, 0.01f32.sin()];
    assert!(
        b.iter().zip(want).all(|(x, y)| (x - y).abs() < 1e-6),
        "{b:?}"
    );
    let mut c = [0.3, -0.7, 0.2, 0.9];
    crate::qwen2::rope(&mut c, 4, 0, 10000.0, &Std);
    assert_eq!(c, [0.3, -0.7, 0.2, 0.9], "position 0 is the identity");
}

#[test]
fn byte_level_decoding() {
    assert_eq!(decode_byte_level("Ġthe".as_bytes()), Some(b" the".to_vec()));
    assert_eq!(decode_byte_level("Ċ".as_bytes()), Some(b"\n".to_vec()));
    assert_eq!(decode_byte_level(b"abc"), Some(b"abc".to_vec()));
    assert_eq!(decode_byte_level("ĀĠ".as_bytes()), Some(vec![0x00, 0x20]));
    assert_eq!(
        decode_byte_level("中".as_bytes()),
        None,
        "not in the byte table"
    );
    // The table covers all 256 bytes exactly once.
    let mut seen = [false; 256];
    for c in (0x21u32..=0x7e)
        .chain(0xa1..=0xac)
        .chain(0xae..=0xff)
        .chain(0x100..=0x143)
    {
        let ch = char::from_u32(c).unwrap();
        let mut buf = [0u8; 4];
        let b = decode_byte_level(ch.encode_utf8(&mut buf).as_bytes()).unwrap();
        assert!(!seen[b[0] as usize], "{c:#x}");
        seen[b[0] as usize] = true;
    }
    assert!(seen.iter().all(|s| *s));
}
