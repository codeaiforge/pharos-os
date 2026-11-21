//! The host endpoint for the QEMU network tests (issue #64, networking.md):
//! a UDP echo server on localhost, and a TCP one on the same port (#270,
//! tls.md). slirp forwards the guest's datagrams and connections for
//! `10.0.2.2` to the host's loopback, so the guest reaches both at
//! `10.0.2.2:47000`.

use std::io::{ErrorKind, Read, Write};
#[cfg(test)]
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Where `runner` starts the server.
pub const ADDR: &str = "127.0.0.1:47000";

/// How often the server thread checks whether it should stop.
const POLL: Duration = Duration::from_millis(50);

/// A running echo server. It stops when dropped.
pub struct EchoServer {
    #[cfg(test)]
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

/// Echoes `stream` until the peer closes it or the server stops.
fn echo_stream(mut stream: TcpStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(POLL));
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
}

impl EchoServer {
    /// Binds `addr` for UDP and TCP and echoes every datagram back to its
    /// sender, and every connection's bytes back on it, until dropped.
    /// Fails with a clear message if the port is taken.
    pub fn start(addr: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind(addr).map_err(|e| {
            format!(
                "cannot start the UDP echo server for the network tests on {addr}: {e}; \
                 stop whatever holds that port (for example another test run) and retry"
            )
        })?;
        socket
            .set_read_timeout(Some(POLL))
            .map_err(|e| format!("cannot set a timeout on the echo server socket: {e}"))?;
        #[cfg(test)]
        let addr = socket
            .local_addr()
            .map_err(|e| format!("cannot read the echo server address: {e}"))?;
        // The UDP socket's own address, so port 0 (tests) gives both the
        // same port.
        let bound = socket
            .local_addr()
            .map_err(|e| format!("cannot read the echo server address: {e}"))?;
        let listener = TcpListener::bind(bound)
            .and_then(|l| l.set_nonblocking(true).map(|()| l))
            .map_err(|e| {
                format!(
                    "cannot start the TCP echo server for the network tests on {addr}: {e}; \
                     stop whatever holds that port (for example another test run) and retry"
                )
            })?;
        let stop = Arc::new(AtomicBool::new(false));
        let tcp_flag = Arc::clone(&stop);
        let tcp = std::thread::spawn(move || {
            let mut streams = Vec::new();
            while !tcp_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let flag = Arc::clone(&tcp_flag);
                        let _ = stream.set_nonblocking(false);
                        streams.push(std::thread::spawn(move || echo_stream(stream, &flag)));
                    }
                    Err(_) => std::thread::sleep(POLL),
                }
            }
            for s in streams {
                let _ = s.join();
            }
        });
        let flag = Arc::clone(&stop);
        let udp = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !flag.load(Ordering::Relaxed) {
                // Timeouts and transient errors just loop back to the check.
                if let Ok((n, from)) = socket.recv_from(&mut buf) {
                    let _ = socket.send_to(&buf[..n], from);
                }
            }
        });
        Ok(Self {
            #[cfg(test)]
            addr,
            stop,
            threads: vec![udp, tcp],
        })
    }

    #[cfg(test)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
    }

    #[test]
    fn echoes_each_datagram_to_its_sender() {
        let server = EchoServer::start("127.0.0.1:0").unwrap();
        let (a, b) = (client(), client());
        let mut buf = [0u8; 64];
        a.send_to(b"from a", server.addr()).unwrap();
        b.send_to(b"from b", server.addr()).unwrap();
        let (n, from) = a.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"from a"[..], server.addr()));
        let (n, _) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"from b");
    }

    #[test]
    fn echoes_each_tcp_connection() {
        let server = EchoServer::start("127.0.0.1:0").unwrap();
        let mut a = TcpStream::connect(server.addr()).unwrap();
        a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        a.write_all(b"over tcp").unwrap();
        let mut buf = [0u8; 8];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"over tcp");
        drop(a);
        // A second connection after the first ended is served too.
        let mut b = TcpStream::connect(server.addr()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        b.write_all(b"again").unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"again");
    }

    #[test]
    fn stops_and_frees_the_port_when_dropped() {
        let server = EchoServer::start("127.0.0.1:0").unwrap();
        let addr = server.addr();
        drop(server);
        // Nothing answers any more, and the port can be bound again.
        let c = client();
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        c.send_to(b"anyone?", addr).unwrap();
        assert!(c.recv_from(&mut [0u8; 8]).is_err());
        EchoServer::start(&addr.to_string()).unwrap();
    }

    #[test]
    fn reports_a_taken_port() {
        let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = holder.local_addr().unwrap().to_string();
        let Err(e) = EchoServer::start(&addr) else {
            panic!("bound a taken port");
        };
        assert!(
            e.contains(&addr) && e.contains("stop whatever holds that port"),
            "{e}"
        );
    }
}
