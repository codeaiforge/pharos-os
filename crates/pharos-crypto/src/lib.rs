//! Hashing and key derivation for Pharos OS (D-047,
//! [release-integrity.md](../../../docs/architecture/release-integrity.md)):
//! SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), HKDF-SHA256 (RFC 5869)
//! for 32-byte keys, and PBKDF2-HMAC-SHA256 (RFC 8018) for passphrases. One crate for the kernel, the services, and the host
//! tools, so each derives the same keys.
//!
//! `no_std`, no dependencies, `unsafe` forbidden (workspace lint). Not
//! constant-time against a local timing attacker beyond what the code's
//! shape gives; comparisons of MACs use [`equal`].

#![no_std]

#[cfg(test)]
extern crate std;

mod sha256;

pub use sha256::{Sha256, sha256};

const BLOCK: usize = 64;

/// HMAC-SHA256 of `parts` concatenated, keyed with `key` (RFC 2104).
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| k.map(|b| b ^ byte);
    let mut inner = Sha256::new();
    inner.update(&pad(0x36));
    for p in parts {
        inner.update(p);
    }
    sha256(&[&pad(0x5c), &inner.finish()])
}

/// The first 32-byte block of PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2)
/// of `password` with `salt` and `iterations` (at least 1): the identity
/// records' passphrase hash (identity.md, #310). The key's padded states
/// are hashed once, so each iteration costs two compressions.
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if password.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(&[password]));
    } else {
        k[..password.len()].copy_from_slice(password);
    }
    let keyed = |byte: u8| {
        let mut h = Sha256::new();
        h.update(&k.map(|b| b ^ byte));
        h
    };
    let (inner, outer) = (keyed(0x36), keyed(0x5c));
    let mac = |parts: &[&[u8]]| {
        let mut i = inner.clone();
        for p in parts {
            i.update(p);
        }
        let mut o = outer.clone();
        o.update(&i.finish());
        o.finish()
    };
    let mut u = mac(&[salt, &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..iterations {
        u = mac(&[&u]);
        for (a, b) in t.iter_mut().zip(u) {
            *a ^= b;
        }
    }
    k.fill(0);
    core::hint::black_box(&k);
    t
}

/// A 32-byte key for purpose `info`, derived from the secret `ikm` with
/// HKDF-SHA256 and no salt (RFC 5869: extract, then the first block of
/// expand).
pub fn derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac(&[0; 32], &[ikm]);
    hmac(&prk, &[info, &[1]])
}

/// The boot measurement (D-047, release-integrity.md section 3): SHA-256
/// over each measured file's name (its length as one byte, then the name)
/// and SHA-256, in boot order. The kernel computes it at boot; the release
/// publishes the one its files give.
pub fn measurement<'a>(files: impl IntoIterator<Item = (&'a [u8], [u8; 32])>) -> [u8; 32] {
    let mut h = Sha256::new();
    for (name, hash) in files {
        let name = &name[..name.len().min(255)];
        h.update(&[name.len() as u8]);
        h.update(name);
        h.update(&hash);
    }
    h.finish()
}

/// Whether `a` and `b` are equal, without stopping at the first difference.
pub fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests;
