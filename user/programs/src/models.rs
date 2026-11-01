//! The inference service's model manifest (inference.md): the models it
//! will load, each with its store path in the `models` namespace, size,
//! SHA-256, and configuration. Reviewed code like `init`'s service table:
//! adding a model is a code change, and a file whose size, hash, or
//! configuration differs is refused.

use pharos_infer::gguf::Gguf;
use pharos_infer::qwen2::Qwen2Config;
use pharos_infer::session::Engine;
use pharos_proto::infer::Step;

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
    TEST_ENTRY,
    // Two copies of model 2's entry for the failure tests (#89): `cargo
    // xtask` writes `corrupt.gguf` with one byte changed (a hash failure)
    // and `short.gguf` 32 bytes short (a size failure).
    Model {
        number: 3,
        name: b"corrupt",
        path: b"corrupt.gguf",
        ..TEST_ENTRY
    },
    Model {
        number: 4,
        name: b"short",
        path: b"short.gguf",
        ..TEST_ENTRY
    },
];

const TEST_ENTRY: Model = Model {
    number: 2,
    name: b"test",
    path: b"test.gguf",
    size: TEST_SIZE,
    sha256: hex32(TEST_SHA256),
    config: pharos_infer::synth::TEST,
    context: pharos_infer::synth::TEST.context as u32,
};

const TEST_SIZE: u64 = 108_672;
const TEST_SHA256: &str = "ce89f17a20908224140a761fca9c3159c26746bb85b10de035406ab93ff3e7e0";

/// The manifest entry for `number`.
pub fn find(number: u8) -> Option<&'static Model> {
    MANIFEST.iter().find(|m| m.number == number)
}

/// Checks `file` against `m` before anything parses it: size, then SHA-256.
pub fn verify(m: &Model, file: &[u8]) -> Result<(), Step> {
    if file.len() as u64 != m.size {
        return Err(Step::Size);
    }
    if pharos_store::sha256(&[file]) != m.sha256 {
        return Err(Step::Hash);
    }
    Ok(())
}

/// Parses a verified `file` and checks every configuration value against
/// `m`. Only fails if the manifest entry itself is wrong.
pub fn open<'a>(m: &Model, file: &'a [u8]) -> Result<Engine<'a>, Step> {
    let g = Gguf::parse(file).map_err(|_| Step::Format)?;
    let engine = Engine::load(&g).map_err(|_| Step::Format)?;
    if engine.model.config != m.config {
        return Err(Step::Config);
    }
    Ok(engine)
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
        for n in [3, 4] {
            let m = find(n).unwrap();
            assert_eq!(
                (m.size, m.sha256, m.config),
                (TEST_SIZE, find(2).unwrap().sha256, find(2).unwrap().config)
            );
        }
        assert!(find(9).is_none());
    }

    /// An entry for `file` as it is, so the checks after the hash run.
    fn entry_for(file: &[u8]) -> Model {
        Model {
            size: file.len() as u64,
            sha256: pharos_store::sha256(&[file]),
            ..TEST_ENTRY
        }
    }

    fn step(m: &Model, file: &[u8]) -> Result<(), Step> {
        verify(m, file)?;
        open(m, file).map(drop)
    }

    #[test]
    fn each_load_check_refuses_its_file() {
        let good = pharos_infer::synth::test_model();
        assert_eq!(step(&TEST_ENTRY, &good), Ok(()));
        let mut flipped = good.clone();
        flipped[good.len() / 2] ^= 1;
        assert_eq!(step(&TEST_ENTRY, &flipped), Err(Step::Hash));
        assert_eq!(step(&TEST_ENTRY, &good[..good.len() - 32]), Err(Step::Size));
        let mut long = good.clone();
        long.push(0);
        assert_eq!(step(&TEST_ENTRY, &long), Err(Step::Size));

        // Malformed files whose size and hash match their entry: only the
        // parser stands between them and the engine.
        let mut tensors = good.clone();
        tensors[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut keys = good.clone();
        keys[16..24].copy_from_slice(&(1u64 << 40).to_le_bytes());
        // The first tensor's offset: after its name, 2 dimensions, type.
        let name = b"token_embd.weight";
        let at = good.windows(name.len()).position(|w| w == name).unwrap() + name.len();
        let mut offset = good.clone();
        offset[at + 4 + 16 + 4..at + 4 + 16 + 12].copy_from_slice(&(1u64 << 40).to_le_bytes());
        let mut misaligned = good.clone();
        misaligned[at + 4 + 16 + 4] |= 1;
        for (what, file) in [
            ("truncated", &good[..good.len() / 2]),
            ("header only", &good[..24]),
            ("huge tensor count", &tensors[..]),
            ("huge key count", &keys[..]),
            ("offset past the end", &offset[..]),
            ("misaligned offset", &misaligned[..]),
        ] {
            assert_eq!(step(&entry_for(file), file), Err(Step::Format), "{what}");
        }

        let wrong = Model {
            config: Qwen2Config {
                rope_base: pharos_infer::synth::TEST.rope_base * 2.0,
                ..pharos_infer::synth::TEST
            },
            ..TEST_ENTRY
        };
        assert_eq!(step(&wrong, &good), Err(Step::Config));
    }
}
