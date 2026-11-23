//! The host side of the `tls` test kernel (#273, tls.md): a throwaway test
//! authority and server certificates made with `openssl`, and an `openssl
//! s_server` for each, on the ports `pharos_services::TLS_SERVERS` lists.
//! slirp forwards the guest's connections for `10.0.2.2` to the host's
//! loopback.
//!
//! The certificates are dated with `openssl ca -startdate -enddate`, which
//! every OpenSSL 3 has (`x509 -not_after` needs 3.4).

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::Result;

/// The name the good certificate is for (`pharos_services::TLS_TEST_NAME`).
pub const NAME: &str = "pharos-test.local";
/// The `tls` kernel's first server port; the others follow it.
pub const PORT: u16 = 47_443;

/// The servers, in `TLS_SERVERS` order: certificate, name, validity.
const SERVERS: [(&str, &str, &str, &str); 4] = [
    ("good", NAME, "20250101000000Z", "20350101000000Z"),
    ("expired", NAME, "20200101000000Z", "20210101000000Z"),
    (
        "other",
        "other-name.local",
        "20250101000000Z",
        "20350101000000Z",
    ),
    ("stranger", NAME, "20250101000000Z", "20350101000000Z"),
];

const CONFIG: &str = "\
[ca]
default_ca = test
[test]
database = index.txt
new_certs_dir = .
serial = serial
default_md = sha256
policy = any
unique_subject = no
[any]
commonName = supplied
[root]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:${ENV::PHAROS_SAN}
";

fn openssl(dir: &Path, args: &[&str], san: &str) -> Result<()> {
    let out = Command::new("openssl")
        .current_dir(dir)
        .env("PHAROS_SAN", san)
        .args(args)
        .output()
        .map_err(|e| {
            format!(
                "cannot run openssl for the tls test kernel: {e}; install OpenSSL 3 \
                 (for example `sudo apt-get install openssl`)"
            )
        })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "openssl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// A P-256 key and a certificate request for `cn` in `dir`.
fn request(dir: &Path, name: &str, cn: &str) -> Result<()> {
    let key = format!("{name}.key");
    openssl(
        dir,
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            &key,
        ],
        "",
    )?;
    let subject = format!("/CN={cn}");
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-key",
            &key,
            "-subj",
            &subject,
            "-out",
            &format!("{name}.csr"),
        ],
        "",
    )
}

/// Signs `name`'s request with authority `ca` (itself when `name == ca`).
fn sign(dir: &Path, name: &str, ca: &str, san: &str, dates: (&str, &str)) -> Result<()> {
    let (csr, pem, key) = (
        format!("{name}.csr"),
        format!("{name}.pem"),
        format!("{ca}.key"),
    );
    let cert = format!("{ca}.pem");
    let mut args = vec![
        "ca",
        "-batch",
        "-notext",
        "-config",
        "ca.cnf",
        "-keyfile",
        &key,
        "-in",
        &csr,
        "-out",
        &pem,
        "-startdate",
        dates.0,
        "-enddate",
        dates.1,
        "-extensions",
    ];
    if name == ca {
        args.extend(["root", "-selfsign"]);
    } else {
        args.extend(["leaf", "-cert", &cert]);
    }
    openssl(dir, &args, san)
}

/// Makes the test authority, another one that is not pinned, and the four
/// server certificates in `dir` (emptied first); returns the root file
/// for `system/tls/roots`: the pinned authority's DER, after its length.
pub fn make(dir: &Path) -> Result<Vec<u8>> {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let write = |file: &str, text: &str| {
        fs::write(dir.join(file), text).map_err(|e| format!("cannot write {file}: {e}"))
    };
    write("ca.cnf", CONFIG)?;
    write("index.txt", "")?;
    write("serial", "1000\n")?;
    let dates = ("20200101000000Z", "20400101000000Z");
    for (ca, cn) in [
        ("ca", "Pharos Test CA"),
        ("stranger-ca", "Pharos Stranger CA"),
    ] {
        request(dir, ca, cn)?;
        sign(dir, ca, ca, "unused", dates)?;
    }
    for (name, san, from, until) in SERVERS {
        let ca = if name == "stranger" {
            "stranger-ca"
        } else {
            "ca"
        };
        request(dir, name, san)?;
        sign(dir, name, ca, san, (from, until))?;
    }
    openssl(
        dir,
        &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
        "",
    )?;
    let der = fs::read(dir.join("ca.der")).map_err(|e| format!("cannot read ca.der: {e}"))?;
    let len = u16::try_from(der.len()).map_err(|_| "the test authority is too large")?;
    let mut roots = len.to_le_bytes().to_vec();
    roots.extend(der);
    Ok(roots)
}

/// The running servers; stopped when dropped.
pub struct Servers {
    children: Vec<Child>,
}

impl Drop for Servers {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Starts an `s_server` for each certificate [`make`] put in `dir`, on
/// `port` and the three after it, serving `-www` over TLS 1.3 only. Fails
/// with the port's name if one is taken or a server does not come up.
pub fn start(dir: &Path, port: u16) -> Result<Servers> {
    let mut servers = Servers {
        children: Vec::new(),
    };
    for (i, (name, ..)) in SERVERS.iter().enumerate() {
        let port = port + i as u16;
        // s_server binds with SO_REUSEADDR, which on Linux does not stop
        // it binding a port another socket already listens on; check here.
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return Err(format!(
                "cannot start the tls test server on 127.0.0.1:{port}: the port is taken; \
                 stop whatever holds it (for example another test run) and retry"
            ));
        }
        let log = log_file(dir, name)?;
        let child = Command::new("openssl")
            .current_dir(dir)
            .args(["s_server", "-accept"])
            .arg(format!("127.0.0.1:{port}"))
            .args([
                "-cert",
                &format!("{name}.pem"),
                "-key",
                &format!("{name}.key"),
            ])
            .args(["-www", "-tls1_3"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log)
            .spawn()
            .map_err(|e| format!("cannot run openssl s_server: {e}"))?;
        servers.children.push(child);
        wait_up(
            servers.children.last_mut().expect("just pushed"),
            port,
            dir,
            name,
        )?;
    }
    Ok(servers)
}

fn log_file(dir: &Path, name: &str) -> Result<fs::File> {
    let path: PathBuf = dir.join(format!("{name}.log"));
    fs::File::create(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))
}

fn wait_up(child: &mut Child, port: u16, dir: &Path, name: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let log = fs::read_to_string(dir.join(format!("{name}.log"))).unwrap_or_default();
            return Err(format!(
                "openssl s_server for {name} on 127.0.0.1:{port} exited ({status}): {}",
                log.trim()
            ));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "openssl s_server for {name} on 127.0.0.1:{port} did not start in 10 s"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// `openssl s_client` against `port`: its output, with the request
    /// `GET /` sent.
    fn client(dir: &Path, port: u16, name: &str) -> String {
        let mut c = Command::new("openssl")
            .current_dir(dir)
            .args(["s_client", "-connect"])
            .arg(format!("127.0.0.1:{port}"))
            .args([
                "-CAfile",
                "ca.pem",
                "-servername",
                name,
                "-verify_hostname",
                name,
            ])
            .args(["-verify_return_error", "-tls1_3", "-ign_eof"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .unwrap();
        let out = c.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }

    #[test]
    fn the_test_servers_serve_their_certificates_and_a_taken_port_is_reported() {
        let dir = std::env::temp_dir().join(format!("pharos-tls-{}", std::process::id()));
        let roots = make(&dir).unwrap();
        let len = usize::from(u16::from_le_bytes([roots[0], roots[1]]));
        assert_eq!(roots.len(), 2 + len, "one root, after its length");
        let port = 48_443;
        let servers = start(&dir, port).unwrap();
        let good = client(&dir, port, NAME);
        assert!(good.contains("HTTP/1.0 200 ok"), "{good}");
        assert!(good.contains("Verify return code: 0 (ok)"), "{good}");
        let expired = client(&dir, port + 1, NAME);
        assert!(expired.contains("certificate has expired"), "{expired}");
        let other = client(&dir, port + 2, NAME);
        assert!(other.contains("hostname mismatch"), "{other}");
        let stranger = client(&dir, port + 3, NAME);
        assert!(
            stranger.contains("unable to get local issuer"),
            "{stranger}"
        );
        // While they run, their ports are taken.
        let taken = start(&dir, port).err().unwrap();
        assert!(
            taken.contains("127.0.0.1:48443") && taken.contains("taken"),
            "{taken}"
        );
        drop(servers);
        // Stopped: the port is free again.
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
