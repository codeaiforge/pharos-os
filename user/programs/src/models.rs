//! The inference service's model manifest (inference.md): the models it
//! will load, each with its store path in the `models` namespace, size,
//! SHA-256, and configuration. Reviewed code like `init`'s service table:
//! adding a model is a code change, and a file whose size, hash, or
//! configuration differs is refused.

use pharos_infer::qwen2::Qwen2Config;

/// A supported model.
pub struct Model {
    pub number: u8,
    pub name: &'static [u8],
    /// The file, in the `models` namespace.
    pub path: &'static [u8],
    pub size: u64,
    pub sha256: [u8; 32],
    /// Every value must match the loaded file's.
    pub config: Qwen2Config,
    /// Prompt plus new tokens the service allows (bounds the cache).
    pub context: u32,
}

/// The SHA-256 written as 64 hexadecimal digits.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(b[2 * i]) << 4 | digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

pub const MANIFEST: &[Model] = &[
    // Scenario S1's model (D-010): Qwen/Qwen2.5-0.5B-Instruct-GGUF, revision
    // 9217f5d (inference-evaluation.md). 2,048 tokens: a 48 MiB cache.
    Model {
        number: 1,
        name: b"qwen2.5-0.5b-instruct-q8_0",
        path: b"qwen2.5-0.5b-instruct-q8_0.gguf",
        size: 675_710_816,
        sha256: hex32("ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e"),
        config: Qwen2Config {
            dim: 896,
            hidden_dim: 4864,
            n_layers: 24,
            n_heads: 14,
            n_kv_heads: 2,
            vocab_size: 151_936,
            context: 32_768,
            rope_base: 1_000_000.0,
            rms_eps: 1e-6,
        },
        context: 2048,
    },
    // The test model `cargo xtask` generates (`pharos_infer::synth::
    // test_model`); the host test below pins it.
    Model {
        number: 2,
        name: b"test",
        path: b"test.gguf",
        size: TEST_SIZE,
        sha256: hex32(TEST_SHA256),
        config: pharos_infer::synth::TEST,
        context: pharos_infer::synth::TEST.context as u32,
    },
];

const TEST_SIZE: u64 = 108_672;
const TEST_SHA256: &str = "ce89f17a20908224140a761fca9c3159c26746bb85b10de035406ab93ff3e7e0";

/// The manifest entry for `number`.
pub fn find(number: u8) -> Option<&'static Model> {
    MANIFEST.iter().find(|m| m.number == number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_model_is_the_generated_one() {
        let file = pharos_infer::synth::test_model();
        let m = find(2).unwrap();
        let hex: std::string::String = pharos_store::sha256(&[&file])
            .iter()
            .map(|b| std::format!("{b:02x}"))
            .collect();
        assert_eq!((file.len() as u64, hex.as_str()), (m.size, TEST_SHA256));
        assert_eq!(m.sha256, pharos_store::sha256(&[&file]));
        let g = pharos_infer::gguf::Gguf::parse(&file).unwrap();
        let e = pharos_infer::session::Engine::load(&g).unwrap();
        assert_eq!(e.model.config, m.config);
    }

    #[test]
    fn numbers_are_unique_and_contexts_fit() {
        for (i, m) in MANIFEST.iter().enumerate() {
            assert!(MANIFEST[..i].iter().all(|o| o.number != m.number));
            assert!(m.context as usize <= m.config.context && m.context > 0);
            assert!(m.path.len() <= pharos_proto::store::MAX_CLIENT_PATH);
        }
        assert_eq!(find(1).unwrap().sha256[..2], [0xca, 0x59]);
        assert!(find(9).is_none());
    }
}
