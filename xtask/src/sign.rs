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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn parse_seed(text: &str) -> Option<[u8; 32]> {
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

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read key {}: {e}", path.display()))?;
    parse_seed(&text).ok_or(format!(
        "{} must hold an Ed25519 seed as 64 hex digits",
        path.display()
    ))
}

/// The test key: made from the system's random source on first use.
fn test_seed(paths: &Paths) -> Result<[u8; 32]> {
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
