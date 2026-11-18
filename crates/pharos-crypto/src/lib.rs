//! Hashing and key derivation for Pharos OS (D-047,
//! [release-integrity.md](../../../docs/architecture/release-integrity.md)):
//! SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), and HKDF-SHA256 (RFC 5869)
//! for 32-byte keys. One crate for the kernel, the services, and the host
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

/// A 32-byte key for purpose `info`, derived from the secret `ikm` with
/// HKDF-SHA256 and no salt (RFC 5869: extract, then the first block of
/// expand).
pub fn derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac(&[0; 32], &[ikm]);
    hmac(&prk, &[info, &[1]])
}

/// Whether `a` and `b` are equal, without stopping at the first difference.
pub fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests;
