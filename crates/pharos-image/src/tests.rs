use super::*;
use std::vec::Vec;

const SEED: [u8; 32] = [7; 32];

fn signed(image: &[u8], version: u64) -> Vec<u8> {
    let mut f = sign(image, version, &SEED).to_vec();
    f.extend_from_slice(image);
    f
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 8032 section 7.1, test 1: pins the library's Ed25519.
#[test]
fn ed25519_matches_rfc_8032() {
    let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    assert_eq!(
        public_key(&seed).to_vec(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let sig = KeyPair::from_seed(Seed::new(seed)).sk.sign(b"", None);
    assert_eq!(
        sig.as_ref().to_vec(),
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
}

#[test]
fn round_trip() {
    let image = b"pharos-fs bytes";
    let f = signed(image, 7);
    let v = verify(&f, &public_key(&SEED), 7).unwrap();
    assert_eq!(v.version, 7);
    assert_eq!(v.image, image);
    assert_eq!(v.sha256, pharos_store::sha256(&[image]));
    // An empty image is a valid file; the kernel's mount refuses it.
    assert!(verify(&signed(b"", 1), &public_key(&SEED), 0).is_ok());
}

#[test]
fn each_refusal() {
    let key = public_key(&SEED);
    let f = signed(b"some image", 5);
    let changed = |at: usize, x: u8| {
        let mut g = f.clone();
        g[at] ^= x;
        verify(&g, &key, 0).map(|_| ())
    };
    assert_eq!(changed(0, 1), Err(Error::Magic));
    assert_eq!(changed(8, 1), Err(Error::HeaderVersion));
    assert_eq!(changed(12, 1), Err(Error::Reserved));
    assert_eq!(changed(16, 1), Err(Error::Signature)); // version
    assert_eq!(changed(31, 0x80), Err(Error::TooLarge));
    assert_eq!(changed(24, 1), Err(Error::Length));
    assert_eq!(changed(40, 1), Err(Error::Signature)); // hash
    assert_eq!(changed(100, 1), Err(Error::Signature));
    assert_eq!(changed(HEADER_LEN, 1), Err(Error::Hash)); // image byte
    assert_eq!(
        verify(&f, &public_key(&[8; 32]), 0).map(|_| ()),
        Err(Error::Signature)
    );
    assert_eq!(verify(&f, &[0; 32], 0).map(|_| ()), Err(Error::Signature));
    assert_eq!(
        verify(&f[..HEADER_LEN - 1], &key, 0).map(|_| ()),
        Err(Error::Truncated)
    );
    assert_eq!(
        verify(&f[..f.len() - 1], &key, 0).map(|_| ()),
        Err(Error::Length)
    );
    assert_eq!(verify(&f, &key, 6).map(|_| ()), Err(Error::Old));
    assert!(verify(&f, &key, 5).is_ok());
}

/// xorshift64*: deterministic, no dependencies.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// 100,000 mutated files: none panics, none but the original verifies.
#[test]
fn mutations_never_panic() {
    let key = public_key(&SEED);
    let f = signed(&[0x5a; 300], 3);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..100_000 {
        let mut g = f.clone();
        match rng.next() % 4 {
            0 => g.truncate((rng.next() as usize) % f.len()),
            1 => g.push(rng.next() as u8),
            _ => {
                for _ in 0..1 + rng.next() % 4 {
                    let at = (rng.next() as usize) % g.len();
                    g[at] = rng.next() as u8;
                }
            }
        }
        if g != f {
            assert!(verify(&g, &key, 0).is_err());
        }
    }
}

#[test]
fn a_message_signature_holds_only_for_its_message_and_key() {
    let seed = [7; 32];
    let public = public_key(&seed);
    let sig = sign_message(b"sums", &seed);
    assert!(verify_message(b"sums", &sig, &public));
    assert!(!verify_message(b"sumz", &sig, &public));
    assert!(!verify_message(b"sums", &sig, &public_key(&[8; 32])));
    let mut bad = sig;
    bad[0] ^= 1;
    assert!(!verify_message(b"sums", &bad, &public));
}

mod head {
    use crate::head::{Error, Head, LEN, anchor_seed};

    fn sample() -> Head {
        Head {
            boot: 3,
            records: 42,
            chain: [7; 32],
            measurement: [9; 32],
            uptime_us: 123_456,
        }
    }

    #[test]
    fn a_signed_head_verifies_and_round_trips() {
        let seed = anchor_seed(&[1; 32]);
        let public = crate::public_key(&seed);
        let bytes = sample().sign(&seed);
        assert_eq!(&bytes[..8], b"PHAROSAH");
        assert_eq!(Head::verify(&bytes, &public), Ok(sample()));
    }

    #[test]
    fn any_change_or_another_key_is_refused() {
        let seed = anchor_seed(&[1; 32]);
        let public = crate::public_key(&seed);
        let bytes = sample().sign(&seed);
        for i in 0..LEN {
            let mut changed = bytes;
            changed[i] ^= 1;
            assert!(Head::verify(&changed, &public).is_err(), "byte {i}");
        }
        let other = crate::public_key(&anchor_seed(&[2; 32]));
        assert_eq!(Head::verify(&bytes, &other), Err(Error::Signature));
        assert_eq!(Head::verify(&bytes[..LEN - 1], &public), Err(Error::Length));
    }

    #[test]
    fn the_anchor_seed_is_the_kernels_derivation() {
        assert_eq!(
            anchor_seed(&[5; 32]),
            pharos_store::derive(&[5; 32], b"pharos audit anchor v1")
        );
        assert_ne!(anchor_seed(&[5; 32]), [5; 32]);
    }
}

#[test]
fn the_export_code_names_every_stream_its_count_and_head() {
    use crate::head::export_code;
    let streams = [(1, 6, [1u8; 32]), (2, 40, [2u8; 32])];
    let code = export_code(streams);
    assert_eq!(code, export_code(streams), "deterministic");
    assert_ne!(code, export_code([streams[0]]), "a stream left out");
    assert_ne!(
        code,
        export_code([(1, 6, [1u8; 32]), (2, 41, [2u8; 32])]),
        "a record more"
    );
    assert_ne!(
        code,
        export_code([(1, 6, [1u8; 32]), (2, 40, [3u8; 32])]),
        "another head"
    );
    assert_ne!(code, export_code([streams[1], streams[0]]), "the order");
}
