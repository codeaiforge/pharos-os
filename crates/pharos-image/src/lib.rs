//! Signed root images (D-028, boot.md part 8): a 128-byte header followed
//! by a `pharos-fs` image of at most 16 MiB.
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `PHAROSIM` |
//! | 8 | 4 | header version, 1 |
//! | 12 | 4 | reserved, zero |
//! | 16 | 8 | image version |
//! | 24 | 8 | image length in bytes |
//! | 32 | 32 | SHA-256 of the image |
//! | 64 | 64 | Ed25519 signature of bytes 0–63 |
//!
//! [`verify`] checks every field and never panics; [`sign`] is for the host
//! (`cargo xtask image sign`). The kernel checks the `pharos-fs` image
//! itself when it is mounted.
//!
//! `no_std`, `unsafe` forbidden (workspace lint).

#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

pub const MAGIC: [u8; 8] = *b"PHAROSIM";
pub const HEADER_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 128;
/// Largest image after the header.
pub const MAX_IMAGE: u64 = 16 << 20;

/// Why a file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the header.
    Truncated,
    Magic,
    HeaderVersion,
    /// Reserved bytes not zero.
    Reserved,
    /// The length field is over [`MAX_IMAGE`].
    TooLarge,
    /// The length field does not match the file.
    Length,
    /// The signature does not verify with the key (or the key is invalid).
    Signature,
    /// The SHA-256 does not match the image.
    Hash,
    /// The version is below the lowest accepted.
    Old,
}

impl Error {
    /// A short reason for audit records and `trust` lines.
    pub fn reason(self) -> &'static str {
        match self {
            Error::Truncated => "truncated",
            Error::Magic => "not a Pharos image",
            Error::HeaderVersion => "unknown header version",
            Error::Reserved => "reserved bytes set",
            Error::TooLarge => "image over 16 MiB",
            Error::Length => "length does not match",
            Error::Signature => "bad signature",
            Error::Hash => "SHA-256 does not match",
            Error::Old => "version too old",
        }
    }
}

/// A file that passed [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified<'a> {
    pub version: u64,
    pub sha256: [u8; 32],
    /// The `pharos-fs` image after the header.
    pub image: &'a [u8],
}

/// Checks `file` against the public `key`: every header field, the
/// signature, the SHA-256, and `version >= min_version` (pass 0 to boot a
/// slot already staged; staging passes the highest good version + 1).
pub fn verify<'a>(file: &'a [u8], key: &[u8; 32], min_version: u64) -> Result<Verified<'a>, Error> {
    let (header, image) = file.split_at_checked(HEADER_LEN).ok_or(Error::Truncated)?;
    let u32_at = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or([0; 4]));
    let u64_at = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or([0; 8]));
    if header[..8] != MAGIC {
        return Err(Error::Magic);
    }
    if u32_at(8) != HEADER_VERSION {
        return Err(Error::HeaderVersion);
    }
    if u32_at(12) != 0 {
        return Err(Error::Reserved);
    }
    let length = u64_at(24);
    if length > MAX_IMAGE {
        return Err(Error::TooLarge);
    }
    if length != image.len() as u64 {
        return Err(Error::Length);
    }
    let signature = Signature::from_slice(&header[64..]).map_err(|_| Error::Signature)?;
    PublicKey::new(*key)
        .verify(&header[..64], &signature)
        .map_err(|_| Error::Signature)?;
    let sha256 = pharos_store::sha256(&[image]);
    if header[32..64] != sha256 {
        return Err(Error::Hash);
    }
    let version = u64_at(16);
    if version < min_version {
        return Err(Error::Old);
    }
    Ok(Verified {
        version,
        sha256,
        image,
    })
}

/// The header that signs `image` as `version` with the key from `seed`
/// (host side). Write it, then the image.
pub fn sign(image: &[u8], version: u64, seed: &[u8; 32]) -> [u8; HEADER_LEN] {
    let mut h = [0; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..12].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    h[16..24].copy_from_slice(&version.to_le_bytes());
    h[24..32].copy_from_slice(&(image.len() as u64).to_le_bytes());
    h[32..64].copy_from_slice(&pharos_store::sha256(&[image]));
    let signature = KeyPair::from_seed(Seed::new(*seed)).sk.sign(&h[..64], None);
    h[64..].copy_from_slice(signature.as_ref());
    h
}

/// The public key for `seed`.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    *KeyPair::from_seed(Seed::new(*seed)).pk
}
