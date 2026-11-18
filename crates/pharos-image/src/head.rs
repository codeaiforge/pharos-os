//! The signed audit head (D-047 item 4, release-integrity.md section 4):
//! what `audit` writes to `audit/head/<boot>` after each record it
//! commits, and what `cargo xtask store audit --key` checks a trail
//! against.
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `PHAROSAH` |
//! | 8 | 4 | version, 1 |
//! | 12 | 4 | boot (the stream `log/<boot>`) |
//! | 16 | 8 | records in the stream |
//! | 24 | 32 | the stream's chain head |
//! | 56 | 32 | the boot measurement |
//! | 88 | 8 | uptime in microseconds |
//! | 96 | 64 | Ed25519 signature of bytes 0–95 |
//!
//! The signing seed is the `AuditAnchor` key, derived from the device
//! secret; the host derives the same seed from its key file, so it can
//! print the public key without booting ([`anchor_seed`]).

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

pub const MAGIC: [u8; 8] = *b"PHAROSAH";
pub const VERSION: u32 = 1;
pub const LEN: usize = 160;
const SIGNED: usize = 96;

/// The HKDF label of the `AuditAnchor` key (must match the kernel's
/// `key::Purpose::AuditAnchor`).
pub const ANCHOR_LABEL: &[u8] = b"pharos audit anchor v1";

/// What a head says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub boot: u32,
    pub records: u64,
    pub chain: [u8; 32],
    pub measurement: [u8; 32],
    pub uptime_us: u64,
}

/// Why a head was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not [`LEN`] bytes.
    Length,
    /// Wrong magic or version.
    Format,
    /// The signature does not verify with the given public key.
    Signature,
    /// The public key is malformed.
    Key,
}

impl Head {
    /// The signed bytes for `seed`.
    pub fn sign(&self, seed: &[u8; 32]) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[..8].copy_from_slice(&MAGIC);
        out[8..12].copy_from_slice(&VERSION.to_le_bytes());
        out[12..16].copy_from_slice(&self.boot.to_le_bytes());
        out[16..24].copy_from_slice(&self.records.to_le_bytes());
        out[24..56].copy_from_slice(&self.chain);
        out[56..88].copy_from_slice(&self.measurement);
        out[88..96].copy_from_slice(&self.uptime_us.to_le_bytes());
        let signature = KeyPair::from_seed(Seed::new(*seed))
            .sk
            .sign(&out[..SIGNED], None);
        out[SIGNED..].copy_from_slice(signature.as_ref());
        out
    }

    /// Checks `bytes` with `public` and returns what they say. Never
    /// panics.
    pub fn verify(bytes: &[u8], public: &[u8; 32]) -> Result<Self, Error> {
        let bytes: &[u8; LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        let u32_at =
            |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let u64_at = |i: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i..i + 8]);
            u64::from_le_bytes(b)
        };
        if bytes[..8] != MAGIC || u32_at(8) != VERSION {
            return Err(Error::Format);
        }
        let key = PublicKey::from_slice(public).map_err(|_| Error::Key)?;
        let signature = Signature::from_slice(&bytes[SIGNED..]).map_err(|_| Error::Signature)?;
        key.verify(&bytes[..SIGNED], &signature)
            .map_err(|_| Error::Signature)?;
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&bytes[24..56]);
        let mut measurement = [0u8; 32];
        measurement.copy_from_slice(&bytes[56..88]);
        Ok(Self {
            boot: u32_at(12),
            records: u64_at(16),
            chain,
            measurement,
            uptime_us: u64_at(88),
        })
    }
}

/// The `AuditAnchor` seed for the device secret `secret` (host side: the
/// kernel derives it the same way).
pub fn anchor_seed(secret: &[u8; 32]) -> [u8; 32] {
    pharos_store::derive(secret, ANCHOR_LABEL)
}
