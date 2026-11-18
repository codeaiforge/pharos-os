//! The device secret and the keys derived from it (D-047,
//! [release-integrity.md](../../docs/architecture/release-integrity.md)).
//!
//! The host passes 32 random bytes per VM as the `fw_cfg` file
//! [`FW_CFG_NAME`]; the kernel reads them once at boot ([`init`]) and keeps
//! them here. They never leave the kernel: a process holding a `Key`
//! capability for a [`Purpose`] reads only that purpose's derived key
//! (`key_read`).

/// The `fw_cfg` file that holds the device secret.
pub const FW_CFG_NAME: &[u8] = b"opt/org.pharos/device-key";

/// Size of the secret and of each derived key.
pub const KEY_LEN: usize = 32;

/// What a derived key is for. Each has its own label, so one key reveals
/// nothing about another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// `audit`'s Ed25519 seed, which signs the chain head.
    AuditAnchor,
    /// `init`'s HMAC key for the slot record.
    SlotRecord,
}

impl Purpose {
    /// The HKDF `info` label; `xtask` derives with the same one.
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::AuditAnchor => b"pharos audit anchor v1",
            Self::SlotRecord => b"pharos slot record v1",
        }
    }
}

/// Why there is no device secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No `fw_cfg` file of that name (or no `fw_cfg` at all).
    Missing,
    /// The file is not [`KEY_LEN`] bytes.
    Size(usize),
    /// [`init`] already ran.
    AlreadySet,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => write!(f, "no device key (opt/org.pharos/device-key, D-047)"),
            Self::Size(n) => write!(
                f,
                "the device key (opt/org.pharos/device-key) is {n} bytes, not {KEY_LEN} (D-047)"
            ),
            Self::AlreadySet => f.write_str("the device key was already read"),
        }
    }
}

/// The key for `purpose` derived from `secret` (HKDF-SHA256, no salt).
pub fn derive(secret: &[u8; KEY_LEN], purpose: Purpose) -> [u8; KEY_LEN] {
    pharos_crypto::derive(secret, purpose.label())
}

#[cfg(target_os = "none")]
mod global {
    use super::*;
    use crate::mm::raw::IrqMutex;

    static SECRET: IrqMutex<Option<[u8; KEY_LEN]>> = IrqMutex::new(None);

    /// Reads the device secret from `fw_cfg`. Call once, during boot,
    /// before `init` starts.
    pub fn init() -> Result<(), Error> {
        let mut secret = SECRET.lock();
        if secret.is_some() {
            return Err(Error::AlreadySet);
        }
        let mut buf = [0u8; KEY_LEN];
        match crate::arch::x86_64::fw_cfg_file(FW_CFG_NAME, &mut buf) {
            None => Err(Error::Missing),
            Some(KEY_LEN) => {
                *secret = Some(buf);
                Ok(())
            }
            Some(n) => Err(Error::Size(n)),
        }
    }

    /// Whether the device secret was read.
    pub fn present() -> bool {
        SECRET.lock().is_some()
    }

    /// The key for `purpose`, if the device secret was read.
    pub fn derived(purpose: Purpose) -> Option<[u8; KEY_LEN]> {
        SECRET.lock().as_ref().map(|s| derive(s, purpose))
    }

    static MEASUREMENT: IrqMutex<Option<[u8; 32]>> = IrqMutex::new(None);

    /// Measures the boot (D-047 item 2): SHA-256 of each `(name, contents)`
    /// in boot order, then [`pharos_crypto::measurement`] over them. Call
    /// once, before bootloader memory is reclaimed. Returns the digest.
    pub fn measure<'a>(files: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> [u8; 32] {
        let digest = pharos_crypto::measurement(
            files.map(|(name, bytes)| (name, pharos_crypto::sha256(&[bytes]))),
        );
        *MEASUREMENT.lock() = Some(digest);
        digest
    }

    /// The boot measurement, once [`measure`] ran.
    pub fn measurement() -> Option<[u8; 32]> {
        *MEASUREMENT.lock()
    }
}

#[cfg(target_os = "none")]
pub use global::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_derive_different_keys() {
        let secret = [7u8; KEY_LEN];
        assert_ne!(
            derive(&secret, Purpose::AuditAnchor),
            derive(&secret, Purpose::SlotRecord)
        );
        assert_eq!(
            derive(&secret, Purpose::AuditAnchor),
            pharos_crypto::derive(&secret, b"pharos audit anchor v1")
        );
    }
}
