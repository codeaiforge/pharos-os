use std::string::String;
use std::vec;

use super::*;

fn hex(h: [u8; 32]) -> String {
    h.iter().map(|b| std::format!("{b:02x}")).collect()
}

#[test]
fn sha256_matches_fips_180_4_vectors() {
    assert_eq!(
        hex(sha256(&[b"abc"])),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(sha256(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256(&[
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        ])),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let million = vec![b'a'; 1_000_000];
    assert_eq!(
        hex(sha256(&[&million[..400_001], &million[400_001..]])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn hmac_matches_rfc_4231() {
    // Test cases 1, 2, and 6 (a key longer than the block).
    assert_eq!(
        hex(hmac(&[0x0b; 20], &[b"Hi There"])),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(hmac(b"Jefe", &[b"what do ya ", b"want for nothing?"])),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hex(hmac(
            &[0xaa; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn derive_matches_rfc_5869() {
    // Test case 3 (no salt, no info): the first 32 bytes of its OKM.
    assert_eq!(
        hex(derive(&[0x0b; 22], b"")),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    );
    assert_ne!(derive(&[1; 32], b"a"), derive(&[1; 32], b"b"));
}

#[test]
fn equal_compares_every_byte() {
    let a = [7u8; 32];
    let mut b = a;
    assert!(equal(&a, &b));
    b[31] ^= 1;
    assert!(!equal(&a, &b));
}

#[test]
fn measurement_covers_names_order_and_contents() {
    let k = sha256(&[b"kernel bytes"]);
    let r = sha256(&[b"root bytes"]);
    let m = measurement([(&b"kernel"[..], k), (&b"root"[..], r)]);
    // Length-prefixed: one byte, the name, the hash.
    let mut flat = std::vec::Vec::new();
    for (n, h) in [(&b"kernel"[..], k), (&b"root"[..], r)] {
        flat.push(n.len() as u8);
        flat.extend_from_slice(n);
        flat.extend_from_slice(&h);
    }
    assert_eq!(m, sha256(&[&flat]));
    assert_ne!(m, measurement([(&b"root"[..], r), (&b"kernel"[..], k)]));
    assert_ne!(m, measurement([(&b"kernel"[..], r), (&b"root"[..], k)]));
    assert_ne!(m, measurement([(&b"kerne"[..], k), (&b"lroot"[..], r)]));
}

/// RFC 7914 section 11's PBKDF2-HMAC-SHA256 vectors (their first 32 bytes),
/// and a password longer than a block; each checked against Python's
/// `hashlib.pbkdf2_hmac` (#310).
#[test]
fn pbkdf2_matches_rfc_7914() {
    let hex = |h: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };
    assert_eq!(
        pbkdf2(b"passwd", b"salt", 1),
        hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
    );
    assert_eq!(
        pbkdf2(b"Password", b"NaCl", 80000),
        hex("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56")
    );
    assert_eq!(
        pbkdf2(&[b'x'; 100], b"salt", 3),
        hex("59bfa49750dd5462ce38370a1e7abe0736ff334cf1c2f0d84f23a03435d660d1")
    );
    // One iteration is one HMAC of the salt and block number 1.
    assert_eq!(pbkdf2(b"k", b"s", 1), hmac(b"k", &[b"s", &[0, 0, 0, 1]]));
}
