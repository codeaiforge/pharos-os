//! `release` (D-047 item 5, release-integrity.md section 6): the release
//! files, their `SHA256SUMS` with the boot measurement, and its Ed25519
//! signature by the maintainer's offline release key.
//!
//! `SHA256SUMS` is in `sha256sum` format (`<hex>  <name>`, sorted by
//! name), so `sha256sum -c` checks the files, plus one line
//! `boot-measurement <hex>`: the digest the kernel computes over what it
//! booted (`key::measure`) and signs into every audit head. It lists
//! `BUILDINFO` too: the source commit and the tools that built the files,
//! for a second, independent build to use the same ones.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{DISK_IMAGE, Paths, Result, STORE_IMAGE, io_err, secure_boot, sign};

pub const SUMS: &str = "SHA256SUMS";
pub const SIG: &str = "SHA256SUMS.sig";
const MEASUREMENT: &str = "boot-measurement";
const BUILDINFO: &str = "BUILDINFO";
/// In `BUILDINFO`'s source line when tracked files differ from the commit.
const MODIFIED: &str = " (modified)";
/// `BUILDINFO`'s line naming the `db` certificate that signed Limine
/// (#258): this, then its SHA-256 in hex.
const SECURE_BOOT: &str = "secure-boot db ";

/// `cargo xtask release [--secure-boot <KEYDIR>]`: builds the main image
/// and puts the release files and `SHA256SUMS` in
/// `target/xtask/release/<version>/`. The device key next to the image is
/// never copied: it is this host's secret. With `KEYDIR` (`PK.crt`,
/// `KEK.crt`, `db.crt`, `db.key`; #258), Limine in the ISO is signed with
/// the `db` key, and the release gets the variable store with the three
/// certificates enrolled.
pub fn build(paths: &Paths, keys: Option<&Path>) -> Result<PathBuf> {
    crate::build(paths)?;
    let (mut iso, measurement) = crate::main_image(paths, None)?;
    if let Some(keys) = keys {
        let out = paths
            .target
            .join("xtask")
            .join("secure-boot")
            .join("release");
        iso = secure_boot::signed(paths, &iso.with_file_name("iso-root"), keys, &out, |_| {
            Ok(())
        })?;
    }
    let version = env!("CARGO_PKG_VERSION");
    let dir = paths.target.join("xtask").join("release").join(version);
    crate::recreate_dir(&dir)?;
    let files = [
        (format!("pharos-{version}.iso"), iso.clone()),
        (DISK_IMAGE.to_owned(), iso.with_file_name(DISK_IMAGE)),
        (STORE_IMAGE.to_owned(), iso.with_file_name(STORE_IMAGE)),
    ];
    let mut entries = Vec::new();
    // The toolchain too: its standard-library sources (#261).
    let toolchain = crate::std_source(paths)?.0;
    let host = [crate::cargo_home(), paths.root.clone(), toolchain];
    for (name, from) in &files {
        crate::copy(from, &dir.join(name))?;
        host_free(&dir.join(name), &host)?;
        entries.push((name.clone(), hash(&dir.join(name))?));
    }
    if let Some(keys) = keys {
        let vars = dir.join(secure_boot::VARS);
        secure_boot::vars(keys, &vars)?;
        entries.push((secure_boot::VARS.to_owned(), hash(&vars)?));
    }
    let mut info_text = buildinfo(paths)?;
    if let Some(keys) = keys {
        let db = hash(&keys.join("db.crt"))?;
        info_text.push_str(&format!("{SECURE_BOOT}{}\n", sign::hex(&db)));
    }
    let info = dir.join(BUILDINFO);
    fs::write(&info, info_text).map_err(io_err("cannot write", &info))?;
    entries.push((BUILDINFO.to_owned(), hash(&info)?));
    let text = sums(&entries, &measurement);
    let path = dir.join(SUMS);
    fs::write(&path, &text).map_err(io_err("cannot write", &path))?;
    println!("Release: {}", dir.display());
    print!("{text}");
    Ok(dir)
}

/// `cargo xtask release sign <DIR> --release-key <FILE>`: checks the files
/// against `SHA256SUMS`, then signs it into `SHA256SUMS.sig` (128 hex
/// digits). Refuses the test key.
pub fn sign(paths: &Paths, dir: &Path, key: &Path) -> Result<()> {
    let seed = sign::read_seed(key)?;
    let test = paths.target.join("xtask").join("keys").join("test.key");
    if test.exists() && sign::read_seed(&test)? == seed {
        return Err(format!(
            "{} is the test key ({}); sign a release with the maintainer's release key",
            key.display(),
            test.display()
        ));
    }
    let text = read(&dir.join(SUMS))?;
    let (entries, _) = check_files(dir, &text)?;
    let info = if entries.iter().any(|(n, _)| n == BUILDINFO) {
        read(&dir.join(BUILDINFO))?
    } else {
        String::new()
    };
    if info.contains(MODIFIED) {
        return Err(format!(
            "{} was built from a modified tree; build the release from a clean checkout",
            dir.display()
        ));
    }
    secure_boot_signed(paths, dir, &entries, &info)?;
    let signature = pharos_image::sign_message(text.as_bytes(), &seed);
    let public = pharos_image::public_key(&seed);
    // ponytail: checks our own output with the code `verify` uses.
    if !pharos_image::verify_message(text.as_bytes(), &signature, &public) {
        return Err("the new signature does not verify".into());
    }
    let path = dir.join(SIG);
    fs::write(&path, sign::hex(&signature) + "\n").map_err(io_err("cannot write", &path))?;
    println!("signed {}: {}", dir.join(SUMS).display(), path.display());
    println!("release key {}", sign::hex(&public));
    Ok(())
}

/// Refuses a release whose Limine is not signed for Secure Boot, or is
/// signed with the test `db` key (#258).
fn secure_boot_signed(
    paths: &Paths,
    dir: &Path,
    entries: &[(String, [u8; 32])],
    info: &str,
) -> Result<()> {
    let db = info.lines().find_map(|l| l.strip_prefix(SECURE_BOOT));
    let (Some(db), true) = (db, entries.iter().any(|(n, _)| n == secure_boot::VARS)) else {
        return Err(format!(
            "{} has no Secure Boot signature; build it with `cargo xtask release --secure-boot <KEYDIR>`",
            dir.display()
        ));
    };
    let test = paths
        .target
        .join("xtask")
        .join("keys")
        .join("secureboot")
        .join("db.crt");
    if test.is_file() && sign::hex(&hash(&test)?) == db {
        return Err(format!(
            "{}'s Limine is signed with the test db key ({}); sign it with the maintainer's",
            dir.display(),
            test.display()
        ));
    }
    Ok(())
}

/// `cargo xtask release verify <DIR> --key <FILE>`: the signature on
/// `SHA256SUMS` under the public key in FILE (64 hex digits, such as
/// `RELEASE-KEY`), then every file it lists. Returns the measurement.
pub fn verify(dir: &Path, key: &Path) -> Result<[u8; 32]> {
    let public = hex32(read(key)?.trim()).ok_or(format!(
        "{} must hold a public key as 64 hex digits",
        key.display()
    ))?;
    let text = read(&dir.join(SUMS))?;
    let sig_text = read(&dir.join(SIG))?;
    let signature = hex64(sig_text.trim()).ok_or(format!(
        "{} must hold 128 hex digits",
        dir.join(SIG).display()
    ))?;
    if !pharos_image::verify_message(text.as_bytes(), &signature, &public) {
        return Err(format!(
            "{} is not signed by the key in {}",
            dir.join(SUMS).display(),
            key.display()
        ));
    }
    let (entries, measurement) = check_files(dir, &text)?;
    println!("signature good: release key {}", sign::hex(&public));
    for (name, _) in &entries {
        println!("{name}: OK");
    }
    println!("{MEASUREMENT} {}", sign::hex(&measurement));
    Ok(measurement)
}

/// The source commit and the build tools, one per line.
fn buildinfo(paths: &Paths) -> Result<String> {
    let out = |program: &str, args: &[&str]| -> Result<String> {
        let bytes = crate::run(
            Command::new(program).current_dir(&paths.root).args(args),
            false,
        )?;
        Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .next()
            .unwrap_or("")
            .to_owned())
    };
    let commit = out("git", &["rev-parse", "HEAD"])?;
    let modified = !out("git", &["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    Ok(format!(
        "source {commit}{}\n{}\n{}\n{}\nlimine {}\nsource-date-epoch {}\n",
        if modified { MODIFIED } else { "" },
        out("rustc", &["-V"])?,
        out("cargo", &["-V"])?,
        out("xorriso", &["-version"])?,
        crate::LIMINE_VERSION,
        crate::source_date_epoch()?,
    ))
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(io_err("cannot read", path))
}

fn hash(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).map_err(io_err("cannot read", path))?;
    Ok(pharos_store::sha256(&[&bytes]))
}

/// Refuses a file that names a host path from `host` (Cargo's home, the
/// source tree): another host would build different bytes (#259).
fn host_free(path: &Path, host: &[PathBuf]) -> Result<()> {
    let bytes = fs::read(path).map_err(io_err("cannot read", path))?;
    for dir in host {
        let needle = dir.to_string_lossy();
        if !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            return Err(format!(
                "{} contains the host path {needle}, so another host would build it differently; \
                 remap it (--remap-path-prefix, see user_rustflags)",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `SHA256SUMS` for `entries`, sorted by name, and the measurement.
fn sums(entries: &[(String, [u8; 32])], measurement: &[u8; 32]) -> String {
    let mut entries = entries.to_vec();
    entries.sort();
    let mut text: String = entries
        .iter()
        .map(|(name, h)| format!("{}  {name}\n", sign::hex(h)))
        .collect();
    text.push_str(&format!("{MEASUREMENT} {}\n", sign::hex(measurement)));
    text
}

type Sums = (Vec<(String, [u8; 32])>, [u8; 32]);

/// The entries and the measurement in `text`; every line must be one or
/// the other, a name must be a plain file name, and the measurement must
/// appear exactly once.
fn parse(text: &str) -> Result<Sums> {
    let mut entries = Vec::new();
    let mut measurement = None;
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix(&format!("{MEASUREMENT} ")) {
            let m = hex32(hex).ok_or(format!("bad {MEASUREMENT} line: {line:?}"))?;
            if measurement.replace(m).is_some() {
                return Err(format!("{SUMS} has two {MEASUREMENT} lines"));
            }
            continue;
        }
        let (hex, name) = line
            .split_once("  ")
            .ok_or(format!("bad line in {SUMS}: {line:?}"))?;
        let h = hex32(hex).ok_or(format!("bad hash in {SUMS}: {line:?}"))?;
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(format!("bad file name in {SUMS}: {name:?}"));
        }
        entries.push((name.to_owned(), h));
    }
    if entries.is_empty() {
        return Err(format!("{SUMS} lists no files"));
    }
    Ok((
        entries,
        measurement.ok_or(format!("{SUMS} has no {MEASUREMENT} line"))?,
    ))
}

/// [`parse`], and each listed file in `dir` has its hash.
fn check_files(dir: &Path, text: &str) -> Result<Sums> {
    let (entries, measurement) = parse(text)?;
    for (name, want) in &entries {
        if hash(&dir.join(name))? != *want {
            return Err(format!("{name} does not match {SUMS}"));
        }
    }
    Ok((entries, measurement))
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    sign::parse_seed(text)
}

fn hex64(text: &str) -> Option<[u8; 64]> {
    if text.len() != 128 {
        return None;
    }
    let mut out = [0; 64];
    out[..32].copy_from_slice(&hex32(&text[..64])?);
    out[32..].copy_from_slice(&hex32(&text[64..])?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signed release in a fresh temporary directory.
    fn release(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("pharos-release-{tag}-{}", std::process::id()));
        crate::recreate_dir(&dir).unwrap();
        fs::write(dir.join("a.iso"), b"iso").unwrap();
        fs::write(dir.join("store.img"), b"store").unwrap();
        fs::write(dir.join(secure_boot::VARS), b"vars").unwrap();
        fs::write(
            dir.join(BUILDINFO),
            format!("source x\n{SECURE_BOOT}{}\n", sign::hex(&[7; 32])),
        )
        .unwrap();
        let entries: Vec<_> = [BUILDINFO, secure_boot::VARS, "store.img", "a.iso"]
            .iter()
            .map(|n| (n.to_string(), hash(&dir.join(n)).unwrap()))
            .collect();
        fs::write(dir.join(SUMS), sums(&entries, &[9; 32])).unwrap();
        let seed = [5; 32];
        let key = dir.join("release.key");
        fs::write(&key, sign::hex(&seed)).unwrap();
        let public = dir.join("RELEASE-KEY");
        fs::write(&public, sign::hex(&pharos_image::public_key(&seed)) + "\n").unwrap();
        let paths = Paths {
            root: dir.clone(),
            target: dir.join("target"),
        };
        sign(&paths, &dir, &key).unwrap();
        (dir, public)
    }

    #[test]
    fn a_signed_release_verifies_and_gives_its_measurement() {
        let (dir, key) = release("ok");
        assert_eq!(verify(&dir, &key), Ok([9; 32]));
        let text = read(&dir.join(SUMS)).unwrap();
        assert!(text.contains(&format!(
            "{}  a.iso\n",
            sign::hex(&hash(&dir.join("a.iso")).unwrap())
        )));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_changed_file_sums_or_key_is_refused() {
        let (dir, key) = release("bad");
        fs::write(dir.join("a.iso"), b"isO").unwrap();
        assert_eq!(
            verify(&dir, &key),
            Err("a.iso does not match SHA256SUMS".into())
        );
        fs::write(dir.join("a.iso"), b"iso").unwrap();

        let good = read(&dir.join(SUMS)).unwrap();
        fs::write(
            dir.join(SUMS),
            good.replace(&sign::hex(&[9; 32]), &sign::hex(&[8; 32])),
        )
        .unwrap();
        assert!(verify(&dir, &key).unwrap_err().contains("is not signed by"));
        fs::write(dir.join(SUMS), &good).unwrap();

        let other = dir.join("OTHER-KEY");
        fs::write(&other, sign::hex(&pharos_image::public_key(&[6; 32]))).unwrap();
        assert!(
            verify(&dir, &other)
                .unwrap_err()
                .contains("is not signed by")
        );
        assert_eq!(verify(&dir, &key), Ok([9; 32]));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_build_from_a_modified_tree_is_not_signed() {
        let (dir, _) = release("modified");
        fs::write(dir.join(BUILDINFO), format!("source abc{MODIFIED}\n")).unwrap();
        let entries: Vec<_> = ["store.img", "a.iso", BUILDINFO]
            .iter()
            .map(|n| (n.to_string(), hash(&dir.join(n)).unwrap()))
            .collect();
        fs::write(dir.join(SUMS), sums(&entries, &[9; 32])).unwrap();
        let paths = Paths {
            root: dir.clone(),
            target: dir.join("target"),
        };
        let err = sign(&paths, &dir, &dir.join("release.key")).unwrap_err();
        assert!(err.contains("modified tree"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_test_key_signs_no_release() {
        let (dir, _) = release("test-key");
        let keys = dir.join("target").join("xtask").join("keys");
        fs::create_dir_all(&keys).unwrap();
        fs::copy(dir.join("release.key"), keys.join("test.key")).unwrap();
        let paths = Paths {
            root: dir.clone(),
            target: dir.join("target"),
        };
        let err = sign(&paths, &dir, &dir.join("release.key")).unwrap_err();
        assert!(err.contains("is the test key"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    /// `dir`'s `SHA256SUMS` rewritten for its files `names`, then signed.
    fn resign(dir: &Path, names: &[&str]) -> Result<()> {
        let entries: Vec<_> = names
            .iter()
            .map(|n| (n.to_string(), hash(&dir.join(n)).unwrap()))
            .collect();
        fs::write(dir.join(SUMS), sums(&entries, &[9; 32])).unwrap();
        let paths = Paths {
            root: dir.to_path_buf(),
            target: dir.join("target"),
        };
        sign(&paths, dir, &dir.join("release.key"))
    }

    #[test]
    fn a_release_without_secure_boot_is_not_signed() {
        let (dir, _) = release("no-sb");
        let err = resign(&dir, &[BUILDINFO, "store.img", "a.iso"]).unwrap_err();
        assert!(err.contains("no Secure Boot signature"), "{err}");
        fs::write(dir.join(BUILDINFO), "source x\n").unwrap();
        let err = resign(&dir, &[BUILDINFO, secure_boot::VARS, "a.iso"]).unwrap_err();
        assert!(err.contains("no Secure Boot signature"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_release_signed_with_the_test_db_key_is_not_signed() {
        let (dir, _) = release("test-db");
        let keys = dir.join("target/xtask/keys/secureboot");
        fs::create_dir_all(&keys).unwrap();
        fs::write(keys.join("db.crt"), b"test db cert").unwrap();
        let db = sign::hex(&hash(&keys.join("db.crt")).unwrap());
        fs::write(
            dir.join(BUILDINFO),
            format!("source x\n{SECURE_BOOT}{db}\n"),
        )
        .unwrap();
        let err = resign(&dir, &[BUILDINFO, secure_boot::VARS, "a.iso"]).unwrap_err();
        assert!(err.contains("test db key"), "{err}");
        fs::write(keys.join("db.crt"), b"another cert").unwrap();
        resign(&dir, &[BUILDINFO, secure_boot::VARS, "a.iso"]).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_file_naming_a_host_path_is_refused() {
        let dir = std::env::temp_dir().join(format!("pharos-release-host-{}", std::process::id()));
        crate::recreate_dir(&dir).unwrap();
        let file = dir.join("init");
        fs::write(&file, b"panic at /home/me/.cargo/registry/src/x.rs").unwrap();
        let host = [PathBuf::from("/home/me/.cargo")];
        assert!(
            host_free(&file, &host)
                .unwrap_err()
                .contains("/home/me/.cargo")
        );
        fs::write(&file, b"panic at /cargo/registry/src/x.rs").unwrap();
        host_free(&file, &host).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sums_lines_are_checked() {
        let h = sign::hex(&[1; 32]);
        let m = format!("{MEASUREMENT} {h}\n");
        assert!(parse(&format!("{h}  a\n{m}")).is_ok());
        assert!(
            parse(&format!("{h}  a\n"))
                .unwrap_err()
                .contains("no boot-measurement")
        );
        assert!(
            parse(&format!("{h}  a\n{m}{m}"))
                .unwrap_err()
                .contains("two")
        );
        assert!(parse(&m).unwrap_err().contains("no files"));
        assert!(
            parse(&format!("{h}  ../a\n{m}"))
                .unwrap_err()
                .contains("bad file name")
        );
        assert!(
            parse(&format!("{h} a\n{m}"))
                .unwrap_err()
                .contains("bad line")
        );
        assert!(
            parse(&format!("{}  a\n{m}", &h[1..]))
                .unwrap_err()
                .contains("bad hash")
        );
    }
}
