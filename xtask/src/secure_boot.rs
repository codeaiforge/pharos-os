//! Secure Boot (#258, D-028, D-047 item 3, release-integrity.md part 5).
//!
//! The chain the M4.3 evaluation showed holds (boot-evaluation.md), in
//! this order, since each step changes what the next covers:
//! 1. a BLAKE2b hash on every `path:` and `module_path:` in `limine.conf`;
//! 2. the config's BLAKE2b hash enrolled into Limine (`limine
//!    enroll-config`);
//! 3. Limine signed with the `db` key (`sbsign`), in `EFI/BOOT/` and in the
//!    El Torito FAT image OVMF boots a CD from.
//!
//! Every image gets steps 1 and 2 ([`hash_paths`], [`enroll`]): they need
//! no key and are deterministic. [`signed`] adds step 3 for a copy of a
//! built image tree. [`vars`] writes an OVMF variable store with the PK,
//! KEK, and `db` certificates enrolled and Secure Boot on, with
//! `virt-fw-vars` (virt-firmware 26.10, a host tool, never shipped).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Paths, Result, io_err, run};

/// OVMF built with Secure Boot (needs SMM and a secure flash).
pub const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd";
/// The variable store a release ships (release-integrity.md part 5).
pub const VARS: &str = "OVMF_VARS_4M.pharos.fd";
/// The owner GUID of Pharos's certificates in the variable store:
/// UUIDv5 of `pharos-os` in the DNS namespace.
const OWNER: &str = "52581af0-2e31-5398-8de1-17f7fc538d75";
/// The three keys, each `<name>.key` (RSA-2048, PEM) and `<name>.crt`.
pub const KEYS: [&str; 3] = ["PK", "KEK", "db"];
/// The tools, and how the maintainer gets them (AGENTS.md §3).
const TOOLS: [(&str, &str); 4] = [
    ("b2sum", "coreutils"),
    ("sbsign", "sudo apt install sbsigntool"),
    ("mcopy", "sudo apt install mtools"),
    ("virt-fw-vars", "pip install virt-firmware==26.10"),
];

/// `conf` with `#<BLAKE2b-512>` after every `boot():/` path, each file
/// read under `root` (the ISO's tree). A path that already has a hash is
/// left as it is.
pub fn hash_paths(conf: &str, root: &Path) -> Result<String> {
    let mut out = String::with_capacity(conf.len() * 2);
    for line in conf.lines() {
        let key = line.trim_start();
        let path = ["path: boot():/", "module_path: boot():/"]
            .iter()
            .find_map(|p| key.strip_prefix(p))
            .filter(|p| !p.contains('#'));
        out.push_str(line);
        if let Some(path) = path {
            out.push('#');
            out.push_str(&b2sum(&root.join(path))?);
        }
        out.push('\n');
    }
    Ok(out)
}

/// The BLAKE2b-512 of `path` in hex, from `b2sum`.
fn b2sum(path: &Path) -> Result<String> {
    tool("b2sum")?;
    let out = run(Command::new("b2sum").arg(path), false)?;
    let text = String::from_utf8_lossy(&out);
    text.split_whitespace()
        .next()
        .filter(|h| h.len() == 128)
        .map(str::to_owned)
        .ok_or(format!("b2sum gave no hash for {}", path.display()))
}

/// Enrolls `conf`'s hash into the Limine binary `efi` with Limine's tool.
pub fn enroll(limine_tool: &Path, efi: &Path, conf: &Path) -> Result<()> {
    let hash = b2sum(conf)?;
    run(
        Command::new(limine_tool)
            .arg("enroll-config")
            .arg(efi)
            .arg(hash),
        false,
    )
    .map(|_| ())
}

/// `Err` with the install command if `name` is not on `PATH`.
fn tool(name: &str) -> Result<()> {
    let found = std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()));
    if found {
        return Ok(());
    }
    let how = TOOLS
        .iter()
        .find(|(t, _)| *t == name)
        .map_or("", |(_, how)| how);
    Err(format!("{name} not found; Secure Boot needs it ({how})"))
}

/// The test keys in `target/xtask/keys/secureboot/`, made with `openssl`
/// on first use. Never for a release: `release sign` refuses them.
pub fn test_keys(paths: &Paths) -> Result<PathBuf> {
    let dir = paths.target.join("xtask").join("keys").join("secureboot");
    fs::create_dir_all(&dir).map_err(io_err("cannot create", &dir))?;
    for name in KEYS {
        if dir.join(format!("{name}.crt")).is_file() && dir.join(format!("{name}.key")).is_file() {
            continue;
        }
        run(
            Command::new("openssl")
                .args(["req", "-quiet", "-newkey", "rsa:2048", "-nodes", "-keyout"])
                .arg(dir.join(format!("{name}.key")))
                .args(["-new", "-x509", "-sha256", "-days", "3650", "-subj"])
                .arg(format!("/CN=Pharos OS test {name}/"))
                .arg("-out")
                .arg(dir.join(format!("{name}.crt"))),
            false,
        )?;
    }
    Ok(dir)
}

/// Builds `out`'s ISO from a copy of the image tree `root` with Limine
/// signed by `keys`'s `db` key, in both places that carry it. The tree
/// already has the path hashes and the enrolled config hash. `edit`
/// changes the copy before it is packed (the refusal checks).
pub fn signed(
    paths: &Paths,
    root: &Path,
    keys: &Path,
    out: &Path,
    edit: impl FnOnce(&Path) -> Result<()>,
) -> Result<PathBuf> {
    for name in ["sbsign", "mcopy"] {
        tool(name)?;
    }
    let copy = out.join("iso-root");
    crate::recreate_dir(&copy)?;
    run(
        Command::new("cp").arg("-a").arg(root.join(".")).arg(&copy),
        false,
    )?;
    let efi = copy.join("EFI").join("BOOT").join("BOOTX64.EFI");
    run(
        Command::new("sbsign")
            .arg("--key")
            .arg(keys.join("db.key"))
            .arg("--cert")
            .arg(keys.join("db.crt"))
            .arg("--output")
            .arg(&efi)
            .arg(&efi),
        false,
    )?;
    edit(&copy)?;
    finish(&copy)?;
    let iso = out.join("pharos.iso");
    crate::pack_iso(paths, &copy, &iso)?;
    // The files `qemu_args` takes from beside the ISO.
    let from = root.parent().unwrap_or(Path::new("."));
    for name in [crate::DEVICE_KEY, crate::DISK_IMAGE, crate::STORE_IMAGE] {
        crate::copy(&from.join(name), &out.join(name))?;
    }
    Ok(iso)
}

/// Pins every time in the image tree `root` to `SOURCE_DATE_EPOCH` and
/// puts `EFI/BOOT/BOOTX64.EFI` into the El Torito FAT image, the copy
/// OVMF boots from a CD. `mcopy -m` keeps the file's pinned time, so the
/// FAT image is the same in every build; then its own time is pinned.
pub fn finish(root: &Path) -> Result<()> {
    tool("mcopy")?;
    let epoch = crate::source_date_epoch()?;
    let time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(epoch);
    crate::pin_timestamps(root, time)?;
    run(
        Command::new("mcopy")
            .args(["-m", "-o", "-i"])
            .arg(root.join("boot").join("limine").join("limine-uefi-cd.bin"))
            .arg(root.join("EFI").join("BOOT").join("BOOTX64.EFI"))
            .arg("::/EFI/BOOT/BOOTX64.EFI"),
        false,
    )?;
    crate::pin_timestamps(root, time)
}

/// Writes `out`: OVMF's empty variable store with `keys`'s PK, KEK, and
/// `db` certificates enrolled and Secure Boot on. Deterministic.
pub fn vars(keys: &Path, out: &Path) -> Result<()> {
    tool("virt-fw-vars")?;
    let cert = |name: &str| keys.join(format!("{name}.crt"));
    run(
        Command::new("virt-fw-vars")
            .args(["-i", "/usr/share/OVMF/OVMF_VARS_4M.fd", "-o"])
            .arg(out)
            .args(["--set-pk", OWNER])
            .arg(cert("PK"))
            .args(["--add-kek", OWNER])
            .arg(cert("KEK"))
            .args(["--add-db", OWNER])
            .arg(cert("db"))
            .arg("--sb"),
        false,
    )
    .map(|_| ())
}

/// `args` (from `qemu_args`, UEFI) for the Secure Boot firmware with the
/// variable store `vars`: SMM on, the flash secure, `OVMF_CODE` swapped.
pub fn qemu_args(args: Vec<std::ffi::OsString>, vars: &Path) -> Vec<std::ffi::OsString> {
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        let next = args.peek().map(|a| a.to_string_lossy().into_owned());
        match (arg.to_str(), next.as_deref()) {
            (Some("-M"), Some("q35")) => {
                args.next();
                out.extend([
                    "-M".into(),
                    "q35,smm=on".into(),
                    "-global".into(),
                    "driver=cfi.pflash01,property=secure,value=on".into(),
                ]);
            }
            (Some("-drive"), Some(d)) if d.starts_with("if=pflash") => {
                args.next();
                let d = if d.contains("readonly=on") {
                    format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}")
                } else {
                    format!("if=pflash,format=raw,file={}", vars.display())
                };
                out.extend(["-drive".into(), d.into()]);
            }
            _ => out.push(arg),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_boot_path_gets_its_hash_and_nothing_else_changes() {
        let root = std::env::temp_dir().join(format!("pharos-sb-{}", std::process::id()));
        fs::create_dir_all(root.join("boot/modules")).unwrap();
        fs::write(root.join("boot/kernel"), b"kernel").unwrap();
        fs::write(root.join("boot/modules/root"), b"root").unwrap();
        let conf = "timeout: 3\n\n/Pharos OS\n    path: boot():/boot/kernel\n    cmdline: safe\n    module_path: boot():/boot/modules/root\n    module_string: root\n";
        let hashed = hash_paths(conf, &root).unwrap();
        let lines: Vec<&str> = hashed.lines().collect();
        let kernel = b2sum(&root.join("boot/kernel")).unwrap();
        assert_eq!(lines[3], format!("    path: boot():/boot/kernel#{kernel}"));
        assert!(lines[5].starts_with("    module_path: boot():/boot/modules/root#"));
        assert_ne!(lines[5].rsplit('#').next(), Some(kernel.as_str()));
        for i in [0, 1, 2, 4, 6] {
            assert_eq!(lines[i], conf.lines().nth(i).unwrap());
        }
        // Hashed once: a second pass changes nothing.
        assert_eq!(hash_paths(&hashed, &root).unwrap(), hashed);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_secure_boot_firmware_replaces_the_machine_and_the_flash() {
        let args: Vec<std::ffi::OsString> = [
            "-M",
            "q35",
            "-m",
            "256M",
            "-drive",
            "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive",
            "if=pflash,format=raw,file=v.fd",
        ]
        .iter()
        .map(Into::into)
        .collect();
        let out: Vec<String> = qemu_args(args, Path::new("sb.fd"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            out,
            [
                "-M",
                "q35,smm=on",
                "-global",
                "driver=cfi.pflash01,property=secure,value=on",
                "-m",
                "256M",
                "-drive",
                &format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}"),
                "-drive",
                "if=pflash,format=raw,file=sb.fd",
            ]
        );
    }
}
