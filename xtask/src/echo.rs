//! The host endpoint for the QEMU network tests (issue #64, networking.md):
//! a UDP echo server on localhost. slirp forwards the guest's datagrams for
//! `10.0.2.2` to the host's loopback, so the guest reaches it at
//! `10.0.2.2:47000`.

#[cfg(test)]
use std::net::SocketAddr;
use std::net::UdpSocket;
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
    thread: Option<JoinHandle<()>>,
}

impl EchoServer {
    /// Binds `addr` and echoes every datagram back to its sender until
    /// dropped. Fails with a clear message if the port is taken.
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
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
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
            thread: Some(thread),
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
        if let Some(thread) = self.thread.take() {
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
