//! The host side of the `vault` test kernel (#284, gateway.md): runs
//! `scripts/vault-test-server.py` (Python's standard library only) with the
//! `tls` kernel's good certificate, on `pharos_services::VAULT_SERVER`'s
//! port. slirp forwards the guest's `10.0.2.2` to the host's loopback.

use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::Result;

/// The running server; stopped when dropped.
pub struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts the server with `dir`'s `good.pem` and `good.key` (made by
/// `tls_server::make`) and the secrets file `secrets`, logging to
/// `dir/vault-server.log`.
pub fn start(dir: &Path, secrets: &Path) -> Result<Server> {
    let port = pharos_services::VAULT_SERVER.1;
    if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
        return Err(format!(
            "cannot start the vault test server on 127.0.0.1:{port}: the port is taken; \
             stop whatever holds it (for example another test run) and retry"
        ));
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/vault-test-server.py");
    let log = dir.join("vault-server.log");
    let _ = std::fs::remove_file(&log);
    let mut child = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(port.to_string())
        .arg(dir.join("good.pem"))
        .arg(dir.join("good.key"))
        .arg(secrets)
        .arg(&log)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run python3 for the vault test server: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("the vault test server exited ({status})"));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(Server(child));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    Err(format!(
        "the vault test server on 127.0.0.1:{port} did not start in 10 s"
    ))
}
