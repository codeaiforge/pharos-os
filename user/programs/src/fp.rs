//! A floating-point checksum (D-016): fixed inputs through arithmetic and
//! the `libm` functions the inference engine needs, folded into one value.
//! The host and Pharos must compute the same bits, which checks that user
//! programs use hardware floating point correctly and that their state
//! survives preemption (`vector_state` test kernel). Also the engine's
//! [`Libm`] math functions.

/// `pharos-infer`'s math functions, from `libm` (D-016).
pub struct Libm;

impl pharos_infer::Math for Libm {
    fn sqrt(&self, x: f32) -> f32 {
        libm::sqrtf(x)
    }
    fn exp(&self, x: f32) -> f32 {
        libm::expf(x)
    }
    fn sin(&self, x: f32) -> f32 {
        libm::sinf(x)
    }
    fn cos(&self, x: f32) -> f32 {
        libm::cosf(x)
    }
    fn powf(&self, x: f32, y: f32) -> f32 {
        libm::powf(x, y)
    }
}

/// The checksum the host computes (host test below).
pub const EXPECTED: u64 = 0xf3b5_e485_8afa_5715;

/// Folds every result's bits into one value (FNV-1a over the bit patterns).
pub fn checksum() -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bits: u64| {
        h ^= bits;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    let mut x = 0.125f32;
    for i in 0..256 {
        let v = i as f32 * 0.37 - 41.0;
        x = x * 1.0001 + v / 7.0;
        mix(u64::from(x.to_bits()));
        mix(u64::from(libm::sqrtf(v.abs() + 1.0).to_bits()));
        mix(u64::from(libm::expf(v / 16.0).to_bits()));
        mix(u64::from(libm::sinf(v).to_bits()));
        mix(u64::from(libm::cosf(v).to_bits()));
        mix(u64::from(libm::powf(10000.0, -(i as f32) / 64.0).to_bits()));
        let d = f64::from(v) * core::f64::consts::PI;
        mix((d / 3.0 + d * d).to_bits());
    }
    h
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_checksum_is_the_expected_one() {
        assert_eq!(
            super::checksum(),
            super::EXPECTED,
            "{:#018x}",
            super::checksum()
        );
    }
}
