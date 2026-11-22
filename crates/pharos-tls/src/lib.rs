//! The TLS 1.3 client parts of Pharos OS's TLS service (D-034,
//! [tls.md](../../../docs/architecture/tls.md)):
//!
//! - [`provider`]: rustls's crypto provider in safe Rust: the suite
//!   `TLS13_AES_128_GCM_SHA256`, key exchange X25519 then secp256r1, and
//!   signatures ECDSA P-256 with SHA-256 and Ed25519.
//! - [`drbg`]: an HMAC-DRBG (SHA-256, NIST SP 800-90A) that fails closed.
//! - [`roots`]: the pinned root file, `system/tls/roots`.
//! - [`config`]: the one client configuration: TLS 1.3 only, the pinned
//!   roots, no client certificate, no resumption.
//! - [`Session`]: a sans-I/O client over rustls's unbuffered API.
//! - [`refusal`]: why a handshake failed, as `tls` v1 reports it.
//!
//! `no_std` with `alloc`; `unsafe` is forbidden (workspace lint).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod drbg;
mod provider;
mod session;
#[cfg(test)]
mod tests;

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::crypto::SecureRandom;
use rustls::pki_types::CertificateDer;
use rustls::time_provider::TimeProvider;
use rustls::{CertificateError, ClientConfig, Error, RootCertStore};

pub use provider::{TLS13_AES_128_GCM_SHA256, provider};
/// The rustls this crate is built on, for its callers' types.
pub use rustls;
pub use session::Session;

/// Most roots in the root file (tls.md).
pub const MAX_ROOTS: usize = 16;
/// Largest root file, in bytes.
pub const MAX_ROOTS_FILE: usize = 16 * 1024;

/// Parses the root file: DER certificates, each preceded by its length as
/// a little-endian u16. A file that is too large, holds too many roots, is
/// truncated, or holds a certificate webpki cannot use as a trust anchor
/// gives `None`, so the service runs with no roots and every handshake
/// fails as an unknown issuer.
pub fn roots(file: &[u8]) -> Option<RootCertStore> {
    if file.len() > MAX_ROOTS_FILE {
        return None;
    }
    let mut store = RootCertStore::empty();
    let mut rest = file;
    while !rest.is_empty() {
        let [a, b, tail @ ..] = rest else {
            return None;
        };
        let len = usize::from(u16::from_le_bytes([*a, *b]));
        if len == 0 || len > tail.len() || store.roots.len() == MAX_ROOTS {
            return None;
        }
        let (der, tail) = tail.split_at(len);
        store.add(CertificateDer::from(der.to_vec())).ok()?;
        rest = tail;
    }
    Some(store)
}

/// Encodes certificates as a root file (for `cargo xtask` and tests).
pub fn encode_roots(certs: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in certs {
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// The client configuration: TLS 1.3 only, `roots`, the server's name
/// checked by webpki, no client certificate, no resumption (nothing kept
/// between connections), no early data, SNI sent.
pub fn config(
    roots: RootCertStore,
    random: &'static dyn SecureRandom,
    time: Arc<dyn TimeProvider>,
) -> Result<Arc<ClientConfig>, Error> {
    let mut c = ClientConfig::builder_with_details(Arc::new(provider(random)), time)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.resumption = rustls::client::Resumption::disabled();
    c.enable_early_data = false;
    c.enable_sni = true;
    Ok(Arc::new(c))
}

/// Why a handshake failed, as `tls` v1's `HANDSHAKE` reasons number them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// The chain does not end at a pinned root.
    UnknownIssuer = 1,
    /// A certificate is expired or not yet valid.
    Expired = 2,
    /// The certificate is not for the destination's name.
    Name = 3,
    /// Any other certificate error.
    Certificate = 4,
    /// A protocol error or an alert, including no suite or group in common.
    Protocol = 5,
}

/// Classifies a handshake error.
pub fn refusal(e: &Error) -> Refusal {
    match e {
        Error::InvalidCertificate(c) => match c {
            CertificateError::UnknownIssuer => Refusal::UnknownIssuer,
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => Refusal::Expired,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Refusal::Name
            }
            _ => Refusal::Certificate,
        },
        _ => Refusal::Protocol,
    }
}
