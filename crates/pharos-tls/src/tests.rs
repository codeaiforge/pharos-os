//! Host tests: the DRBG against NIST CAVP, HKDF against RFC 8448, X25519
//! against RFC 7748, the root file, and handshakes with a rustls server
//! (rustls's ring provider, host only) for each refusal (tls.md, testing).

use std::boxed::Box;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SignatureAlgorithm,
};
use rustls::crypto::SecureRandom;
use rustls::crypto::ring as server_crypto;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::ServerConnection;
use rustls::time_provider::TimeProvider;
use rustls::{AlertDescription, Error, ServerConfig};

use crate::drbg::{HmacDrbg, NeedsReseed, RESEED_REQUESTS, SharedDrbg};
use crate::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- HMAC-DRBG: NIST CAVP (drbgtestvectors.zip, HMAC_DRBG.rsp, SHA-256) ---

#[test]
fn drbg_matches_cavp_without_reseed() {
    // drbgvectors_no_reseed, [SHA-256], no inputs, COUNT = 0: two
    // generates, the second returned.
    let mut d = HmacDrbg::new(
        &hex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488"),
        &hex("659ba96c601dc69fc902940805ec0ca8"),
        &[],
    );
    let mut out = [0u8; 128];
    d.generate(&mut out, &[]).unwrap();
    d.generate(&mut out, &[]).unwrap();
    assert_eq!(
        out[..],
        hex(
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8"
        )[..]
    );
}

#[test]
fn drbg_matches_cavp_with_reseed_and_inputs() {
    // drbgvectors_pr_false, [SHA-256], personalization and additional
    // input of 256 bits, COUNT = 0.
    let mut d = HmacDrbg::new(
        &hex("cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416"),
        &hex("d0c0d01d156016d0eb6b7e9c7c3c8da8"),
        &hex("6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa"),
    );
    d.reseed(
        &hex("8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82"),
        &hex("1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3"),
    );
    let mut out = [0u8; 128];
    d.generate(
        &mut out,
        &hex("16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff"),
    )
    .unwrap();
    d.generate(
        &mut out,
        &hex("53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2"),
    )
    .unwrap();
    assert_eq!(
        out[..],
        hex(
            "dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f"
        )[..]
    );
}

#[test]
fn drbg_refuses_without_a_reseed_once_its_budget_is_spent() {
    let mut d = HmacDrbg::new(&[1; 48], &[], &[]);
    let mut b = [0u8; 1];
    for _ in 0..RESEED_REQUESTS {
        d.generate(&mut b, &[]).unwrap();
    }
    assert_eq!(d.generate(&mut b, &[]), Err(NeedsReseed::Reseed));
    d.reseed(&[2; 48], &[]);
    assert!(d.generate(&mut b, &[]).is_ok());
    // The byte budget too: 16 requests of 64 KiB.
    let mut d = HmacDrbg::new(&[1; 48], &[], &[]);
    let mut big = vec![0u8; drbg::MAX_REQUEST];
    for _ in 0..16 {
        d.generate(&mut big, &[]).unwrap();
    }
    assert!(d.due());
    big.push(0);
    assert_eq!(d.generate(&mut big, &[]), Err(NeedsReseed::TooLong));
}

#[test]
fn shared_drbg_fails_closed_until_seeded_and_never_repeats() {
    let d = SharedDrbg::new();
    let mut a = [0u8; 32];
    assert!(d.fill(&mut a).is_err());
    assert!(!d.ready());
    assert!(d.seed(&[7; 48]));
    assert!(d.ready());
    let mut b = [0u8; 32];
    d.fill(&mut a).unwrap();
    d.fill(&mut b).unwrap();
    assert_ne!(a, b);
    // The same seed, through the plain generator, gives the same bytes.
    let mut plain = HmacDrbg::new(&[7; 48], &[], b"pharos-tls");
    let mut c = [0u8; 32];
    plain.generate(&mut c, &[]).unwrap();
    assert_eq!(a, c);
}

// --- HKDF on pharos-crypto: RFC 8448 section 3 (simple 1-RTT) ---

#[test]
fn key_schedule_matches_rfc_8448() {
    let suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap();
    let hkdf = suite.hkdf_provider;
    let zero = [0u8; 32];
    // Early secret = HKDF-Extract(0, 0) = HMAC(0^32, 0^32).
    let early = hkdf.hmac_sign(&rustls::crypto::tls13::OkmBlock::new(&zero), &zero);
    assert_eq!(
        early.as_ref(),
        hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    );
    // Derive-Secret(early, "derived", "").
    let empty = suite.common.hash_provider.hash(&[]);
    let label = b"tls13 derived";
    let info: [&[u8]; 5] = [
        &32u16.to_be_bytes(),
        &[label.len() as u8],
        label,
        &[32],
        empty.as_ref(),
    ];
    let derived = hkdf
        .expander_for_okm(&rustls::crypto::tls13::OkmBlock::new(early.as_ref()))
        .expand_block(&info);
    assert_eq!(
        derived.as_ref(),
        hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
    );
    // Handshake secret = HKDF-Extract(derived, the ECDHE secret).
    let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let handshake = hkdf.hmac_sign(&derived, &shared);
    assert_eq!(
        handshake.as_ref(),
        hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
}

#[test]
fn x25519_matches_rfc_7748() {
    // RFC 7748 section 5.2, the first vector.
    let k: [u8; 32] = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        .try_into()
        .unwrap();
    let u: [u8; 32] = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        .try_into()
        .unwrap();
    assert_eq!(
        x25519_dalek::x25519(k, u)[..],
        hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")[..]
    );
}

// --- The root file ---

#[test]
fn root_file_parses_and_refuses_what_it_should() {
    let a = Ca::new("Pharos Test A", &rcgen::PKCS_ECDSA_P256_SHA256);
    let b = Ca::new("Pharos Test B", &rcgen::PKCS_ED25519);
    let file = encode_roots(&[a.der.as_ref(), b.der.as_ref()]);
    assert_eq!(roots(&file).map(|r| r.roots.len()), Some(2));
    assert_eq!(roots(&[]).map(|r| r.roots.len()), Some(0));
    // Truncated: in the length, and in a certificate.
    assert!(roots(&file[..1]).is_none());
    assert!(roots(&file[..file.len() - 1]).is_none());
    // A zero length, and bytes that are no certificate.
    assert!(roots(&[0, 0]).is_none());
    assert!(roots(&encode_roots(&[b"not a certificate"])).is_none());
    // Too many roots, and too large a file.
    let many: Vec<&[u8]> = (0..=MAX_ROOTS).map(|_| a.der.as_ref()).collect();
    assert!(roots(&encode_roots(&many)).is_none());
    assert!(roots(&vec![0u8; MAX_ROOTS_FILE + 1]).is_none());
}

// --- Handshakes against a rustls server ---

/// 2030-01-01T00:00:00Z: inside the test certificates' validity.
const NOW: u64 = 1_893_456_000;

#[derive(Debug)]
struct Fixed(u64);

impl TimeProvider for Fixed {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

struct Ca {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    fn new(name: &str, alg: &'static SignatureAlgorithm) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let der = p.self_signed(&key).unwrap().der().clone();
        Self {
            der,
            issuer: Issuer::new(p, key),
        }
    }

    /// A server certificate for `name`, valid `from` to `until` (years).
    fn leaf(
        &self,
        name: &str,
        from: i32,
        until: i32,
        alg: &'static SignatureAlgorithm,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut p = CertificateParams::new(vec![String::from(name)]).unwrap();
        p.not_before = rcgen::date_time_ymd(from, 1, 1);
        p.not_after = rcgen::date_time_ymd(until, 1, 1);
        let cert = p.signed_by(&key, &self.issuer).unwrap().der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (vec![cert, self.der.clone()], key)
    }
}

fn client(ca: &Ca) -> Arc<rustls::ClientConfig> {
    let random: &'static SharedDrbg = Box::leak(Box::new(SharedDrbg::new()));
    assert!(random.seed(&[0x5a; 48]));
    let roots = roots(&encode_roots(&[ca.der.as_ref()])).unwrap();
    config(roots, random, Arc::new(Fixed(NOW))).unwrap()
}

/// A server with ring's defaults, narrowed by `f`.
fn server(
    (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    f: impl FnOnce(&mut rustls::crypto::CryptoProvider),
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let mut p = server_crypto::default_provider();
    f(&mut p);
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Moves bytes both ways until the client's handshake ends or fails.
fn handshake(c: &mut Session, s: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..16 {
        pump(c, s)?;
        if c.is_open() && !s.is_handshaking() {
            return Ok(());
        }
    }
    panic!("the handshake did not finish");
}

fn pump(c: &mut Session, s: &mut ServerConnection) -> Result<(), Error> {
    let out = c.take_outgoing();
    let mut rd = &out[..];
    while !rd.is_empty() {
        s.read_tls(&mut rd).unwrap();
    }
    // A server error queues an alert, sent below.
    let _ = s.process_new_packets();
    let mut back = Vec::new();
    while s.wants_write() {
        s.write_tls(&mut back).unwrap();
    }
    c.receive(&back)
}

fn connect(
    ca: &Ca,
    name: &str,
    cfg: Arc<ServerConfig>,
) -> Result<(Session, ServerConnection), Error> {
    let mut c = Session::new(client(ca), name)?;
    let mut s = ServerConnection::new(cfg).unwrap();
    handshake(&mut c, &mut s)?;
    Ok((c, s))
}

fn refused(ca: &Ca, name: &str, cfg: Arc<ServerConfig>) -> Refusal {
    match connect(ca, name, cfg) {
        Ok(_) => panic!("the handshake succeeded"),
        Err(e) => refusal(&e),
    }
}

const P256: &SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

#[test]
fn handshake_carries_data_both_ways_and_closes() {
    use std::io::{Read, Write};
    let ca = Ca::new("Pharos Test CA", P256);
    let cfg = server(ca.leaf("good.test", 2025, 2035, P256), |_| {}, TLS13);
    let (mut c, mut s) = connect(&ca, "good.test", cfg).unwrap();
    assert_eq!(
        s.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
    );
    assert_eq!(s.server_name(), Some("good.test"));
    c.write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    pump(&mut c, &mut s).unwrap();
    let mut got = [0u8; 64];
    let n = s.reader().read(&mut got).unwrap();
    assert_eq!(&got[..n], b"GET / HTTP/1.0\r\n\r\n");
    s.writer()
        .write_all(b"HTTP/1.0 200 OK\r\n\r\nhello")
        .unwrap();
    s.send_close_notify();
    pump(&mut c, &mut s).unwrap();
    let mut buf = [0u8; 64];
    let n = c.read(&mut buf);
    assert_eq!(&buf[..n], b"HTTP/1.0 200 OK\r\n\r\nhello");
    assert!(c.peer_closed());
    assert_eq!((c.bytes_out, c.bytes_in), (18, 24));
    c.close().unwrap();
    pump(&mut c, &mut s).unwrap();
    assert!(s.process_new_packets().unwrap().peer_has_closed());
}

#[test]
fn handshake_uses_secp256r1_when_the_server_wants_it() {
    let ca = Ca::new("Pharos Test CA", P256);
    let cfg = server(
        ca.leaf("good.test", 2025, 2035, P256),
        |p| p.kx_groups = vec![server_crypto::kx_group::SECP256R1],
        TLS13,
    );
    let (_, s) = connect(&ca, "good.test", cfg).unwrap();
    assert_eq!(
        s.negotiated_key_exchange_group().unwrap().name(),
        rustls::NamedGroup::secp256r1
    );
}

#[test]
fn handshake_accepts_an_ed25519_chain() {
    let ca = Ca::new("Pharos Test CA", &rcgen::PKCS_ED25519);
    let cfg = server(
        ca.leaf("good.test", 2025, 2035, &rcgen::PKCS_ED25519),
        |_| {},
        TLS13,
    );
    assert!(connect(&ca, "good.test", cfg).is_ok());
}

#[test]
fn an_unknown_issuer_is_refused() {
    let ca = Ca::new("Pharos Test CA", P256);
    let other = Ca::new("Someone Else", P256);
    let cfg = server(other.leaf("good.test", 2025, 2035, P256), |_| {}, TLS13);
    assert_eq!(refused(&ca, "good.test", cfg), Refusal::UnknownIssuer);
}

#[test]
fn an_expired_or_not_yet_valid_certificate_is_refused() {
    let ca = Ca::new("Pharos Test CA", P256);
    let expired = server(ca.leaf("good.test", 2025, 2029, P256), |_| {}, TLS13);
    assert_eq!(refused(&ca, "good.test", expired), Refusal::Expired);
    let early = server(ca.leaf("good.test", 2031, 2035, P256), |_| {}, TLS13);
    assert_eq!(refused(&ca, "good.test", early), Refusal::Expired);
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let ca = Ca::new("Pharos Test CA", P256);
    let cfg = server(ca.leaf("other.test", 2025, 2035, P256), |_| {}, TLS13);
    assert_eq!(refused(&ca, "good.test", cfg), Refusal::Name);
}

#[test]
fn a_server_without_our_suite_group_or_version_is_refused() {
    let ca = Ca::new("Pharos Test CA", P256);
    let leaf = || ca.leaf("good.test", 2025, 2035, P256);
    let suite = server(
        leaf(),
        |p| p.cipher_suites = vec![server_crypto::cipher_suite::TLS13_AES_256_GCM_SHA384],
        TLS13,
    );
    assert_eq!(refused(&ca, "good.test", suite), Refusal::Protocol);
    let group = server(
        leaf(),
        |p| p.kx_groups = vec![server_crypto::kx_group::SECP384R1],
        TLS13,
    );
    assert_eq!(refused(&ca, "good.test", group), Refusal::Protocol);
    let tls12 = server(leaf(), |_| {}, &[&rustls::version::TLS12]);
    assert_eq!(refused(&ca, "good.test", tls12), Refusal::Protocol);
    // A P-384 key: the client offers only P-256 and Ed25519 signatures
    // (no P-384 until M6.2), so the server has nothing to sign with.
    let p384 = server(
        ca.leaf("good.test", 2025, 2035, &rcgen::PKCS_ECDSA_P384_SHA384),
        |_| {},
        TLS13,
    );
    assert_eq!(refused(&ca, "good.test", p384), Refusal::Protocol);
}

#[test]
fn a_tampered_record_ends_the_session_and_a_truncated_one_waits() {
    use std::io::Write;
    let ca = Ca::new("Pharos Test CA", P256);
    let cfg = server(ca.leaf("good.test", 2025, 2035, P256), |_| {}, TLS13);
    let (mut c, mut s) = connect(&ca, "good.test", cfg).unwrap();
    s.writer().write_all(b"secret").unwrap();
    let mut rec = Vec::new();
    s.write_tls(&mut rec).unwrap();
    // Half a record: nothing yet, and no error.
    let half = rec.len() / 2;
    c.receive(&rec[..half]).unwrap();
    assert_eq!(c.readable(), 0);
    // The rest, with one byte flipped: bad_record_mac, and the session is
    // dead.
    let mut rest = rec[half..].to_vec();
    rest[0] ^= 1;
    assert_eq!(c.receive(&rest), Err(Error::DecryptError));
    assert_eq!(c.readable(), 0);
    assert!(c.write(b"x").is_err());
    assert!(c.error().is_some());
}

#[test]
fn only_dns_names_are_accepted() {
    let ca = Ca::new("Pharos Test CA", P256);
    assert!(Session::new(client(&ca), "10.0.2.2").is_err());
    assert!(Session::new(client(&ca), "not a name").is_err());
}

#[test]
fn no_random_means_no_handshake() {
    let ca = Ca::new("Pharos Test CA", P256);
    let random: &'static SharedDrbg = Box::leak(Box::new(SharedDrbg::new()));
    let roots = roots(&encode_roots(&[ca.der.as_ref()])).unwrap();
    let cfg = config(roots, random, Arc::new(Fixed(NOW))).unwrap();
    assert!(Session::new(cfg, "good.test").is_err());
}

#[test]
fn a_server_alert_is_a_protocol_refusal() {
    assert_eq!(
        refusal(&Error::AlertReceived(AlertDescription::HandshakeFailure)),
        Refusal::Protocol
    );
}
