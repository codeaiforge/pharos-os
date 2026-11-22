//! HMAC-DRBG with SHA-256 (NIST SP 800-90A Rev. 1, section 10.1.2), and a
//! shared generator for rustls that fails closed.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use pharos_crypto::hmac;
use rustls::crypto::{GetRandomFailed, SecureRandom};

/// Requests between reseeds (tls.md: 10,000).
pub const RESEED_REQUESTS: u32 = 10_000;
/// Bytes between reseeds (tls.md: 1 MiB).
pub const RESEED_BYTES: u32 = 1 << 20;
/// The most one request may ask for (SP 800-90A table 2: 2^19 bits).
pub const MAX_REQUEST: usize = 1 << 16;

/// The generator's state: `K` and `V`, and the use since the last seed.
#[derive(Clone)]
pub struct HmacDrbg {
    k: [u8; 32],
    v: [u8; 32],
    requests: u32,
    bytes: u32,
}

/// Why [`HmacDrbg::generate`] gave nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum NeedsReseed {
    /// The request or byte budget since the last seed is spent.
    Reseed,
    /// More than [`MAX_REQUEST`] bytes were asked for.
    TooLong,
}

impl HmacDrbg {
    /// Instantiates from `entropy`, `nonce`, and `personal` (10.1.2.3).
    pub fn new(entropy: &[u8], nonce: &[u8], personal: &[u8]) -> Self {
        let mut d = Self {
            k: [0; 32],
            v: [1; 32],
            requests: 0,
            bytes: 0,
        };
        d.update(&[entropy, nonce, personal]);
        d
    }

    /// Reseeds with fresh `entropy` and `additional` input (10.1.2.4).
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) {
        self.update(&[entropy, additional]);
        self.requests = 0;
        self.bytes = 0;
    }

    /// Whether the next request needs a reseed first.
    pub fn due(&self) -> bool {
        self.requests >= RESEED_REQUESTS || self.bytes >= RESEED_BYTES
    }

    /// Fills `out` (10.1.2.5), or refuses when a reseed is due.
    pub fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), NeedsReseed> {
        if out.len() > MAX_REQUEST {
            return Err(NeedsReseed::TooLong);
        }
        if self.due() {
            return Err(NeedsReseed::Reseed);
        }
        if !additional.is_empty() {
            self.update(&[additional]);
        }
        for chunk in out.chunks_mut(32) {
            self.v = hmac(&self.k, &[&self.v]);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(&[additional]);
        self.requests += 1;
        self.bytes += out.len() as u32;
        Ok(())
    }

    /// The update function (10.1.2.2), over `data` concatenated.
    fn update(&mut self, data: &[&[u8]]) {
        let empty = data.iter().all(|d| d.is_empty());
        for round in [0u8, 1] {
            let mut parts: [&[u8]; 5] = [&self.v, &[round], &[], &[], &[]];
            for (p, d) in parts[2..].iter_mut().zip(data) {
                *p = d;
            }
            self.k = hmac(&self.k, &parts[..2 + data.len()]);
            self.v = hmac(&self.k, &[&self.v]);
            if empty {
                break;
            }
        }
    }
}

/// An [`HmacDrbg`] that rustls can share (`fill` takes `&self`), without a
/// lock: a call that finds the generator in use fails rather than wait or
/// reuse state, so it can never hand two callers the same bytes. The TLS
/// service is single-threaded, so in practice it never does.
pub struct SharedDrbg {
    busy: AtomicBool,
    seeded: AtomicBool,
    k: [AtomicU64; 4],
    v: [AtomicU64; 4],
    requests: AtomicU32,
    bytes: AtomicU32,
}

impl core::fmt::Debug for SharedDrbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedDrbg")
    }
}

impl SharedDrbg {
    /// An unseeded generator: every `fill` fails until [`seed`](Self::seed).
    pub const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            seeded: AtomicBool::new(false),
            k: [const { AtomicU64::new(0) }; 4],
            v: [const { AtomicU64::new(0) }; 4],
            requests: AtomicU32::new(0),
            bytes: AtomicU32::new(0),
        }
    }

    /// Instantiates (first call) or reseeds (later calls) from `entropy`.
    /// Returns false if the generator was in use.
    pub fn seed(&self, entropy: &[u8]) -> bool {
        self.with(|d| match d {
            Some(d) => d.reseed(entropy, &[]),
            None => *d = Some(HmacDrbg::new(entropy, &[], b"pharos-tls")),
        })
        .is_some()
    }

    /// Whether the generator has been seeded and needs no reseed.
    pub fn ready(&self) -> bool {
        self.with(|d| d.as_ref().is_some_and(|d| !d.due()))
            .unwrap_or(false)
    }

    fn with<R>(&self, f: impl FnOnce(&mut Option<HmacDrbg>) -> R) -> Option<R> {
        if self.busy.swap(true, Ordering::Acquire) {
            return None;
        }
        let load = |w: &[AtomicU64; 4]| {
            let mut b = [0u8; 32];
            for (c, w) in b.chunks_mut(8).zip(w) {
                c.copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
            }
            b
        };
        let mut d = self.seeded.load(Ordering::Relaxed).then(|| HmacDrbg {
            k: load(&self.k),
            v: load(&self.v),
            requests: self.requests.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        });
        let r = f(&mut d);
        if let Some(d) = &d {
            let store = |w: &[AtomicU64; 4], b: &[u8; 32]| {
                for (c, w) in b.chunks(8).zip(w) {
                    w.store(
                        u64::from_le_bytes(c.try_into().unwrap_or([0; 8])),
                        Ordering::Relaxed,
                    );
                }
            };
            store(&self.k, &d.k);
            store(&self.v, &d.v);
            self.requests.store(d.requests, Ordering::Relaxed);
            self.bytes.store(d.bytes, Ordering::Relaxed);
            self.seeded.store(true, Ordering::Relaxed);
        }
        self.busy.store(false, Ordering::Release);
        Some(r)
    }
}

impl Default for SharedDrbg {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureRandom for SharedDrbg {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        match self.with(|d| d.as_mut().map(|d| d.generate(buf, &[]))) {
            Some(Some(Ok(()))) => Ok(()),
            _ => Err(GetRandomFailed),
        }
    }
}
