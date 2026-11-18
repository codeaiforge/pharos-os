//! `image sign`: a filesystem image with a signed header (D-028,
//! boot.md part 8). No private key is in the repository: release keys stay
//! with the maintainer; the test key is made under `target/xtask/keys/`.

use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use crate::{Paths, Result};

pub fn sign(
    paths: &Paths,
    image: &Path,
    out: &Path,
    version: u64,
    key: Option<&Path>,
) -> Result<()> {
    let seed = match key {
        Some(path) => read_seed(path)?,
        None => test_seed(paths)?,
    };
    let bytes = fs::read(image).map_err(|e| format!("cannot read {}: {e}", image.display()))?;
    if bytes.len() as u64 > pharos_image::MAX_IMAGE {
        return Err(format!(
            "{} is {} bytes; a signed image holds at most {} (16 MiB)",
            image.display(),
            bytes.len(),
            pharos_image::MAX_IMAGE
        ));
    }
    // Its configuration, as `init` will check it at offer and boot (M4.5).
    crate::fs_image::check_config(&bytes).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut file = pharos_image::sign(&bytes, version, &seed).to_vec();
    file.extend_from_slice(&bytes);
    let public = pharos_image::public_key(&seed);
    // ponytail: checks our own output with the code init will use.
    pharos_image::verify(&file, &public, version)
        .map_err(|e| format!("the signed file does not verify: {}", e.reason()))?;
    fs::write(out, &file).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "signed {} as version {version}: {}",
        image.display(),
        out.display()
    );
    println!("public key: {}", hex(&public));
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn parse_seed(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut seed = [0; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(seed)
}

pub fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read key {}: {e}", path.display()))?;
    parse_seed(&text).ok_or(format!(
        "{} must hold an Ed25519 seed as 64 hex digits",
        path.display()
    ))
}

/// The test key: made from the system's random source on first use.
pub fn test_seed(paths: &Paths) -> Result<[u8; 32]> {
    let dir = paths.target.join("xtask").join("keys");
    let path = dir.join("test.key");
    if path.exists() {
        return read_seed(&path);
    }
    let mut seed = [0; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("cannot read /dev/urandom for a test key: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    fs::write(&path, hex(&seed) + "\n")
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::write(
        dir.join("test.pub"),
        hex(&pharos_image::public_key(&seed)) + "\n",
    )
    .map_err(|e| format!("cannot write the test public key: {e}"))?;
    println!("made a test key: {}", path.display());
    Ok(seed)
}

/// This host's device secret (D-047, release-integrity.md): 32 random
/// bytes made on first use in `target/xtask/keys/device.key`, readable by
/// the user only. Every machine `xtask` starts gets it through `fw_cfg`,
/// but test kernels, which get [`crate::TEST_DEVICE_KEY`].
pub fn device_key(paths: &Paths) -> Result<[u8; 32]> {
    let dir = paths.target.join("xtask").join("keys");
    let path = dir.join("device.key");
    if let Ok(bytes) = fs::read(&path) {
        return bytes.try_into().map_err(|b: Vec<u8>| {
            format!(
                "{} is {} bytes, not 32; delete it to make a new device key",
                path.display(),
                b.len()
            )
        });
    }
    let mut key = [0; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .map_err(|e| format!("cannot read /dev/urandom for a device key: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    write_private(&path, &key)?;
    Ok(key)
}

/// A device key file: exactly 32 bytes.
pub fn read_device_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        format!(
            "{} is {} bytes, not a 32-byte device key",
            path.display(),
            b.len()
        )
    })
}

/// The audit public key of a device key: Ed25519's public key for the
/// `AuditAnchor` seed the kernel derives (D-047).
pub fn anchor_public(device_key: &[u8; 32]) -> [u8; 32] {
    pharos_image::public_key(&pharos_image::head::anchor_seed(device_key))
}

/// Writes `bytes` to `path`, readable and writable by the user only.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = fs::remove_file(path);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds() {
        let seed = parse_seed(&("0f".repeat(32) + "\n")).unwrap();
        assert_eq!(seed, [0x0f; 32]);
        assert_eq!(hex(&seed), "0f".repeat(32));
        assert!(parse_seed(&"0f".repeat(31)).is_none());
        assert!(parse_seed(&"zz".repeat(32)).is_none());
        assert!(parse_seed(&"é".repeat(32)).is_none());
    }
}
