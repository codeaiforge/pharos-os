//! rustls's provider traits on RustCrypto and `pharos-crypto` (D-034 item
//! 4): SHA-256 and HMAC from `pharos-crypto` (HKDF through rustls's
//! `HkdfUsingHmac`), AES-128-GCM from aes-gcm, X25519 from x25519-dalek,
//! secp256r1 and ECDSA P-256 from p256, Ed25519 from ed25519-compact.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Tag};

type GcmNonce = aes_gcm::aead::Nonce<Aes128Gcm>;
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, KeyProvider, SecureRandom, SharedSecret, SupportedKxGroup,
    WebPkiSupportedAlgorithms, hash, hmac,
};
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, alg_id,
};
use rustls::sign::SigningKey;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved,
    ProtocolVersion, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};

/// The provider: one suite, two groups, two signature algorithms, and
/// `random` for key shares and the client random.
pub fn provider(random: &'static dyn SecureRandom) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: alloc::vec![TLS13_AES_128_GCM_SHA256],
        // ponytail: two small groups leaked per provider; the TLS service
        // makes one provider for its life.
        kx_groups: [NamedGroup::X25519, NamedGroup::secp256r1]
            .map(|name| Box::leak(Box::new(Group { name, random })) as &dyn SupportedKxGroup)
            .to_vec(),
        signature_verification_algorithms: ALGORITHMS,
        secure_random: random,
        key_provider: &NoKeys,
    }
}

/// `TLS13_AES_128_GCM_SHA256`, the suite RFC 8446 section 9.1 requires.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &Sha256,
            // AES-GCM: 2^24 full records per key (rustls's value for its own
            // providers; draft-irtf-cfrg-aead-limits).
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha256),
        aead_alg: &Aes128GcmAead,
        quic: None,
    });

// --- SHA-256 and HMAC-SHA256 (pharos-crypto) ---

struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(pharos_crypto::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&pharos_crypto::sha256(&[data]))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

struct Sha256Context(pharos_crypto::Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finish())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finish())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct HmacSha256;

impl hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacKey(key.to_vec()))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacKey(Vec<u8>);

impl Drop for HmacKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl hmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut parts = Vec::with_capacity(middle.len() + 2);
        parts.push(first);
        parts.extend_from_slice(middle);
        parts.push(last);
        hmac::Tag::new(&pharos_crypto::hmac(&self.0, &parts))
    }

    fn tag_len(&self) -> usize {
        32
    }
}

// --- AES-128-GCM (aes-gcm) ---

struct Aes128GcmAead;

const TAG_LEN: usize = 16;

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Gcm::new(&key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Gcm::new(&key, iv))
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

/// One direction's key, or none if the key had the wrong length (then every
/// record fails, which rustls turns into an alert).
struct Gcm {
    cipher: Option<Aes128Gcm>,
    iv: Iv,
}

impl Gcm {
    fn new(key: &AeadKey, iv: Iv) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key.as_ref()).ok(),
            iv,
        }
    }

    fn nonce(&self, seq: u64) -> GcmNonce {
        GcmNonce::from(Nonce::new(&self.iv, seq).0)
    }
}

impl MessageEncrypter for Gcm {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let cipher = self.cipher.as_ref().ok_or(Error::EncryptError)?;
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = cipher
            .encrypt_inout_detached(
                &self.nonce(seq),
                &make_tls13_aad(total),
                payload.as_mut().into(),
            )
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Gcm {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let cipher = self.cipher.as_ref().ok_or(Error::DecryptError)?;
        let payload = &mut msg.payload;
        let len = payload.len();
        let Some(body) = len.checked_sub(TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let aad = make_tls13_aad(len);
        let nonce = self.nonce(seq);
        let (text, tag) = payload.split_at_mut(body);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::DecryptError)?;
        cipher
            .decrypt_inout_detached(&nonce, &aad, text.into(), &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(body);
        msg.into_tls13_unpadded_message()
    }
}

// --- Key exchange: X25519 (x25519-dalek) and secp256r1 (p256) ---

/// A key-exchange group with the generator its key shares draw from
/// (rustls's `start` gets no handle to the provider's).
struct Group {
    name: NamedGroup,
    random: &'static dyn SecureRandom,
}

impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

impl SupportedKxGroup for Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if self.name == NamedGroup::X25519 {
            x25519_share(self.random)
        } else {
            p256_share(self.random)
        }
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

/// Random bytes for one key share.
fn secret(random: &dyn SecureRandom) -> Result<[u8; 32], Error> {
    let mut k = [0u8; 32];
    random
        .fill(&mut k)
        .map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok(k)
}

struct X25519Share {
    secret: [u8; 32],
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Share {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = x25519_dalek::x25519(self.secret, peer);
        // RFC 8446 section 7.4.2: an all-zero result means a small-order
        // point; abort.
        if shared == [0; 32] {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl Drop for X25519Share {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

struct P256Share {
    secret: p256::SecretKey,
    public: Vec<u8>,
}

impl ActiveKeyExchange for P256Share {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // RFC 8446 section 4.2.8.2: uncompressed points only.
        if peer.len() != 65 || peer[0] != 4 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

fn x25519_share(random: &dyn SecureRandom) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let secret = secret(random)?;
    let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    Ok(Box::new(X25519Share { secret, public }))
}

fn p256_share(random: &dyn SecureRandom) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    // A scalar of zero or at least the group order is refused; the chance
    // is about 2^-32, so a few tries always suffice.
    for _ in 0..8 {
        let mut k = secret(random)?;
        let key = p256::SecretKey::from_slice(&k);
        k.fill(0);
        if let Ok(secret) = key {
            let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
            return Ok(Box::new(P256Share { secret, public }));
        }
    }
    Err(Error::FailedToGetRandomBytes)
}

// --- Signatures: ECDSA P-256 with SHA-256 (p256), Ed25519 (ed25519-compact) ---

static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&EcdsaP256Sha256, &Ed25519],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&EcdsaP256Sha256]),
        (SignatureScheme::ED25519, &[&Ed25519]),
    ],
};

#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use p256::ecdsa::signature::Verifier;
        let key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key =
            ed25519_compact::PublicKey::from_slice(public_key).map_err(|_| InvalidSignature)?;
        let sig =
            ed25519_compact::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

// --- No client certificates ---

#[derive(Debug)]
struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(&self, _: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("pharos-tls loads no private keys".into()))
    }
}
