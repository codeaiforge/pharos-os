//! A sans-I/O TLS client session over rustls's unbuffered API: the caller
//! moves TLS bytes between it and TCP, and plaintext between it and the
//! client.

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{ClientConfig, Error};

/// One connection's TLS state.
pub struct Session {
    conn: UnbufferedClientConnection,
    /// TLS bytes received and not yet processed.
    incoming: Vec<u8>,
    /// TLS bytes to send.
    outgoing: Vec<u8>,
    /// Plaintext received and not yet read.
    plain: Vec<u8>,
    /// Plaintext written and not yet encrypted (before the handshake ends).
    pending: Vec<u8>,
    open: bool,
    close: Close,
    peer_closed: bool,
    failed: Option<Error>,
    /// Plaintext bytes each way, for the audit record.
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(PartialEq)]
enum Close {
    No,
    Asked,
    Sent,
}

impl Session {
    /// Starts a handshake with `name`, the name the certificate is checked
    /// against and sent as SNI. Fails if `name` is not a DNS name.
    pub fn new(config: Arc<ClientConfig>, name: &str) -> Result<Self, Error> {
        let name = ServerName::try_from(name)
            .map_err(|_| Error::General("not a DNS name".into()))?
            .to_owned();
        if !matches!(name, ServerName::DnsName(_)) {
            return Err(Error::General("not a DNS name".into()));
        }
        let mut s = Self {
            conn: UnbufferedClientConnection::new(config, name)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plain: Vec::new(),
            pending: Vec::new(),
            open: false,
            close: Close::No,
            peer_closed: false,
            failed: None,
            bytes_in: 0,
            bytes_out: 0,
        };
        s.process()?;
        Ok(s)
    }

    /// Whether the handshake has completed.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Whether the server sent `close_notify`: no more plaintext will come.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// The error that ended the session, if one did.
    pub fn error(&self) -> Option<&Error> {
        self.failed.as_ref()
    }

    /// TLS bytes received but not yet processed.
    pub fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    /// Plaintext waiting for [`read`](Self::read).
    pub fn readable(&self) -> usize {
        self.plain.len()
    }

    /// Takes the TLS bytes to send.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    /// TLS bytes waiting to be sent.
    pub fn outgoing(&self) -> &[u8] {
        &self.outgoing
    }

    /// Marks the first `n` outgoing bytes sent.
    pub fn sent(&mut self, n: usize) {
        self.outgoing.drain(..n.min(self.outgoing.len()));
    }

    /// Feeds TLS bytes received from the server and processes them.
    pub fn receive(&mut self, tls: &[u8]) -> Result<(), Error> {
        self.incoming.extend_from_slice(tls);
        self.process()
    }

    /// Queues plaintext; it is encrypted once the handshake has completed.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.close != Close::No {
            return Err(Error::General("closed".into()));
        }
        self.pending.extend_from_slice(data);
        self.process()
    }

    /// Moves up to `out.len()` bytes of plaintext into `out`.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.plain.len());
        out[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        n
    }

    /// Queues `close_notify` after any pending plaintext.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.close == Close::No {
            self.close = Close::Asked;
        }
        self.process()
    }

    /// Drives rustls until it needs more input from the server. An error
    /// is final: the session refuses everything after it.
    fn process(&mut self) -> Result<(), Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let r = self.step();
        if let Err(e) = &r {
            self.failed = Some(e.clone());
            self.open = false;
            self.plain.clear();
            self.pending.clear();
        }
        r
    }

    fn step(&mut self) -> Result<(), Error> {
        loop {
            let UnbufferedStatus { discard, state } =
                self.conn.process_tls_records(&mut self.incoming);
            let mut done = false;
            match state? {
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(record) = r.next_record() {
                        let record = record?;
                        self.bytes_in += record.payload.len() as u64;
                        self.plain.extend_from_slice(record.payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut e) => {
                    let start = self.outgoing.len();
                    let mut room = 1024;
                    loop {
                        self.outgoing.resize(start + room, 0);
                        match e.encode(&mut self.outgoing[start..]) {
                            Ok(n) => {
                                self.outgoing.truncate(start + n);
                                break;
                            }
                            Err(EncodeError::InsufficientSize(s)) => room = s.required_size,
                            Err(_) => {
                                self.outgoing.truncate(start);
                                break;
                            }
                        }
                    }
                }
                // The bytes are in `outgoing`, sent in order by the caller.
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::WriteTraffic(mut w) => {
                    self.open = true;
                    if !self.pending.is_empty() {
                        encrypt(&mut self.outgoing, |out| w.encrypt(&self.pending, out))?;
                        self.bytes_out += self.pending.len() as u64;
                        self.pending.clear();
                    }
                    if self.close == Close::Asked {
                        encrypt(&mut self.outgoing, |out| w.queue_close_notify(out))?;
                        self.close = Close::Sent;
                    }
                    done = true;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.peer_closed = true;
                    done = true;
                }
                // BlockedHandshake: needs more from the server; early data is
                // server-only; later states are not used.
                _ => done = true,
            }
            self.incoming.drain(..discard);
            if done {
                return Ok(());
            }
        }
    }
}

/// Appends what `f` encrypts to `out`, growing it as rustls asks.
fn encrypt(
    out: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> Result<usize, Error> {
    let start = out.len();
    let mut room = 1024;
    loop {
        out.resize(start + room, 0);
        match f(&mut out[start..]) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(n);
            }
            Err(EncryptError::InsufficientSize(s)) => room = s.required_size,
            Err(_) => {
                out.truncate(start);
                return Err(Error::EncryptError);
            }
        }
    }
}
