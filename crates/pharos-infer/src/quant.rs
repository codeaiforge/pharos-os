//! Half-precision floats and 8-bit blocks (ggml's Q8_0), in safe scalar
//! code.
//!
//! A Q8_0 block holds 32 values as one f16 scale `d` and 32 `i8` values
//! `q`, meaning `d * q`. Matrix-vector products quantize the input vector to
//! Q8_0 too and multiply blocks with integer dot products, as llama.cpp's CPU
//! backend does, so results stay close to llama.cpp's. The input
//! quantization follows llama.cpp's AVX2 path (scale `127 / max|x|`, round
//! half to even), which is what runs on the reference host.

use alloc::vec::Vec;

/// Values per Q8_0 block.
pub const QK8_0: usize = 32;
/// Bytes per Q8_0 block: an f16 scale and 32 signed bytes.
pub const Q8_0_BYTES: usize = 2 + QK8_0;

/// Converts IEEE 754 half-precision bits to f32 (exact, all cases).
pub fn f16_to_f32(h: u16) -> f32 {
    let sign = u32::from(h >> 15) << 31;
    let exp = u32::from((h >> 10) & 0x1f);
    let mant = u32::from(h & 0x3ff);
    let bits = match (exp, mant) {
        (0, 0) => sign,
        (0, m) => {
            // Subnormal: normalize the mantissa.
            let shift = m.leading_zeros() - 21; // m has 10 significant bits
            let m = (m << shift) & 0x3ff;
            sign | ((113 - shift) << 23) | (m << 13)
        }
        (31, 0) => sign | 0x7f80_0000,
        (31, m) => sign | 0x7fc0_0000 | (m << 13),
        (e, m) => sign | ((e + 112) << 23) | (m << 13),
    };
    f32::from_bits(bits)
}

/// Converts f32 to half precision, rounding to nearest even (as F16C does).
pub fn f32_to_f16(x: f32) -> u16 {
    let bits = x.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let mant = bits & 0x7f_ffff;
    if exp == 0xff {
        return sign | 0x7c00 | if mant != 0 { 0x200 } else { 0 };
    }
    let e = exp - 127 + 15;
    if e >= 0x1f {
        return sign | 0x7c00;
    }
    if e <= 0 {
        if e < -10 {
            return sign;
        }
        // Subnormal half: shift the full mantissa, rounding to nearest even.
        let m = mant | 0x80_0000;
        let shift = (14 - e) as u32;
        let half = m >> shift;
        let rem = m & ((1 << shift) - 1);
        let mid = 1 << (shift - 1);
        let round = rem > mid || (rem == mid && half & 1 == 1);
        return sign | (half + u32::from(round)) as u16;
    }
    let half = ((e as u32) << 10) | (mant >> 13);
    let rem = mant & 0x1fff;
    let round = rem > 0x1000 || (rem == 0x1000 && half & 1 == 1);
    // A carry out of the mantissa correctly bumps the exponent (to infinity
    // at the top).
    sign | (half + u32::from(round)) as u16
}

fn abs(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & 0x7fff_ffff)
}

/// Rounds to the nearest integer, ties to even, for `|x| < 2^22`.
fn round_even(x: f32) -> f32 {
    const MAGIC: f32 = 12_582_912.0; // 1.5 * 2^23
    if x >= 0.0 {
        (x + MAGIC) - MAGIC
    } else {
        (x - MAGIC) + MAGIC
    }
}

/// A vector quantized to Q8_0 blocks: one scale (already rounded through
/// f16, as stored) and 32 values per block, each in -127..=127 and kept
/// widened to 16 bits for [`dot_q8_0_many`].
pub struct Q8Vec {
    pub scales: Vec<f32>,
    pub values: Vec<i16>,
}

impl Q8Vec {
    pub fn new() -> Self {
        Self {
            scales: Vec::new(),
            values: Vec::new(),
        }
    }

    /// Quantizes `x` (length a multiple of 32) as llama.cpp's AVX2 path does.
    pub fn quantize(&mut self, x: &[f32]) {
        self.scales.clear();
        self.values.clear();
        for block in x.chunks_exact(QK8_0) {
            let amax = block
                .iter()
                .fold(0.0f32, |m, v| if abs(*v) > m { abs(*v) } else { m });
            let d = amax / 127.0;
            let id = if amax != 0.0 { 127.0 / amax } else { 0.0 };
            self.scales.push(f16_to_f32(f32_to_f16(d)));
            self.values
                .extend(block.iter().map(|v| round_even(v * id) as i16));
        }
    }
}

impl Default for Q8Vec {
    fn default() -> Self {
        Self::new()
    }
}

/// The f32 values of one row of Q8_0 blocks.
pub fn dequantize_q8_0(row: &[u8], out: &mut [f32]) {
    for (block, out) in row
        .chunks_exact(Q8_0_BYTES)
        .zip(out.chunks_exact_mut(QK8_0))
    {
        let d = f16_to_f32(u16::from_le_bytes([block[0], block[1]]));
        for (o, q) in out.iter_mut().zip(&block[2..]) {
            *o = d * f32::from(*q as i8);
        }
    }
}

/// The integer dot product of one block's 32 weights and 32 quantized
/// values, both widened to 16 bits (so it compiles to SSE2's 16-bit
/// multiply-add, `pmaddwd`; products and sums are exact).
fn block_dot(w: &[i16; QK8_0], x: &[i16]) -> i32 {
    w.iter()
        .zip(&x[..QK8_0])
        .map(|(w, v)| i32::from(*w) * i32::from(*v))
        .sum()
}

/// The dot product of one row of Q8_0 blocks with a quantized vector.
pub fn dot_q8_0(row: &[u8], x: &Q8Vec) -> f32 {
    let mut sum = 0.0f32;
    for ((block, d_x), q_x) in row
        .chunks_exact(Q8_0_BYTES)
        .zip(&x.scales)
        .zip(x.values.chunks_exact(QK8_0))
    {
        let d_w = f16_to_f32(u16::from_le_bytes([block[0], block[1]]));
        let isum: i32 = block[2..]
            .iter()
            .zip(q_x)
            .map(|(w, v)| i32::from(*w as i8) * i32::from(*v))
            .sum();
        sum += d_w * d_x * isum as f32;
    }
    sum
}

/// [`dot_q8_0`] of one row with each of the `out.len()` vectors that `xs`
/// holds back to back (each the row's length), into `out`. Each weight block
/// is decoded and widened once for all vectors (the saving that batching
/// gives); each sum is accumulated block by block in the same order, and
/// integer sums are exact, so the results are bit-identical to
/// `dot_q8_0`'s.
///
/// One buffer, not one per vector: separate vectors start on 4 KiB
/// boundaries in Pharos's allocator, so the same block of each fell in the
/// same L1 cache set, and the S1 prompt took 13.3 s instead of about 9 (#90).
pub fn dot_q8_0_many(row: &[u8], xs: &Q8Vec, out: &mut [f32]) {
    out.fill(0.0);
    let blocks = row.len() / Q8_0_BYTES;
    let mut w = [0i16; QK8_0];
    for (k, block) in row.chunks_exact(Q8_0_BYTES).enumerate() {
        let d_w = f16_to_f32(u16::from_le_bytes([block[0], block[1]]));
        for (w, b) in w.iter_mut().zip(&block[2..]) {
            *w = i16::from(*b as i8);
        }
        for (b, sum) in out.iter_mut().enumerate() {
            let at = b * blocks + k;
            let isum = block_dot(&w, &xs.values[at * QK8_0..]);
            *sum += d_w * xs.scales[at] * isum as f32;
        }
    }
}

/// Quantizes `x` to Q8_0 blocks in the stored layout (for building test
/// models), with llama.cpp's reference rounding (`roundf`).
pub fn quantize_row_q8_0(x: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(x.len() / QK8_0 * Q8_0_BYTES);
    for block in x.chunks_exact(QK8_0) {
        let amax = block
            .iter()
            .fold(0.0f32, |m, v| if abs(*v) > m { abs(*v) } else { m });
        let d = amax / 127.0;
        let id = if d != 0.0 { 1.0 / d } else { 0.0 };
        out.extend_from_slice(&f32_to_f16(d).to_le_bytes());
        for v in block {
            let t = v * id;
            // roundf: half away from zero.
            let r = if t >= 0.0 {
                (t + 0.5) as i32
            } else {
                (t - 0.5) as i32
            };
            out.push(r.clamp(-127, 127) as i8 as u8);
        }
    }
    out
}
