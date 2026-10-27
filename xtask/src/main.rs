//! `cargo xtask`: host-side build tool for Pharos OS (decision D-003).
//!
//! Builds the kernel and assembles a reproducible hybrid BIOS/UEFI ISO with a
//! pinned, checksum-verified Limine release. Unlike the read-only `pharos`
//! CLI, this tool runs external programs (`cargo`, `curl`, `sha256sum`, `tar`,
//! `cc`, `xorriso`, `qemu-system-x86_64`). It writes only under the
//! workspace's `target/` directory and never needs root. Design: `docs/architecture/boot.md`.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

/// Pinned Limine release (D-001). To update the pin, follow
/// "Updating the Limine pin" in docs/architecture/boot.md.
const LIMINE_VERSION: &str = "12.9.4";
const LIMINE_SHA256: &str = "9880cc04681262214db9b824ed8a5c55296955027d8caa9f55ab52a6dd85d6a0";
const LIMINE_ARCHIVE: &str = "limine-binary.tar.xz";

/// Default timestamp for every file in the ISO, so builds are byte-identical.
/// Overridable through the standard `SOURCE_DATE_EPOCH` variable.
const DEFAULT_SOURCE_DATE_EPOCH: u64 = 1_761_436_800;

const KERNEL_TARGET: &str = "x86_64-unknown-none";
const KERNEL_PACKAGE: &str = "pharos-kernel";
const LIMINE_CONF: &str = include_str!("../limine.conf");

/// UEFI firmware for QEMU (Ubuntu/Mint package `ovmf`).
const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";
/// QEMU exit statuses the kernel produces through `isa-debug-exit`
/// (`(value << 1) | 1` for 0x10 and 0x11; see `arch::x86_64::QemuExit`).
const QEMU_EXIT_SUCCESS: i32 = 33;
const QEMU_EXIT_FAILURE: i32 = 35;

const HELP: &str = "\
cargo xtask - build tool for Pharos OS

USAGE:
    cargo xtask <COMMAND> [OPTIONS]

COMMANDS:
    build                   Build the kernel for x86_64-unknown-none (release)
    image [--kernel <ELF>]  Build a hybrid BIOS/UEFI ISO with the pinned Limine
                            release. Uses the built kernel unless --kernel is given.
    run [--bios] [--gdb]    Build, make the image, and boot it in QEMU with serial
                            output on this terminal. UEFI (OVMF) by default; --bios
                            uses SeaBIOS; --gdb waits for GDB on localhost:1234.
                            Succeeds only if the kernel reports success.
    help                    Show this help message

Outputs go to target/xtask/. Requires curl, sha256sum, tar (xz), cc, and xorriso;
`run` also needs qemu-system-x86_64 and, for UEFI, OVMF.
";

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, PartialEq, Eq)]
enum Task {
    Help,
    Build,
    Image { kernel: Option<PathBuf> },
    Run { bios: bool, gdb: bool },
}

fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Task> {
    let mut args = args.into_iter();
    let task = match args.next().as_deref() {
        None | Some("help" | "-h" | "--help") => return Ok(Task::Help),
        Some("build") => Task::Build,
        Some("image") => {
            let mut kernel = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--kernel" => {
                        let path = args.next().ok_or("--kernel needs a path")?;
                        kernel = Some(PathBuf::from(path));
                    }
                    other => return Err(format!("unexpected argument '{other}'")),
                }
            }
            return Ok(Task::Image { kernel });
        }
        Some("run") => {
            let (mut bios, mut gdb) = (false, false);
            for arg in args {
                match arg.as_str() {
                    "--bios" => bios = true,
                    "--gdb" => gdb = true,
                    other => return Err(format!("unexpected argument '{other}'")),
                }
            }
            return Ok(Task::Run { bios, gdb });
        }
        Some(other) => return Err(format!("unknown command '{other}'")),
    };
    match args.next() {
        Some(extra) => Err(format!("unexpected argument '{extra}'")),
        None => Ok(task),
    }
}

/// Workspace paths. Everything xtask writes lives under `target/`.
struct Paths {
    root: PathBuf,
    target: PathBuf,
}

impl Paths {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives one level below the workspace root")
            .to_path_buf();
        let target = root.join("target");
        Self { root, target }
    }

    fn kernel_elf(&self) -> PathBuf {
        self.target
            .join(KERNEL_TARGET)
            .join("release")
            .join(KERNEL_PACKAGE)
    }

    fn limine_dir(&self) -> PathBuf {
        self.target
            .join("xtask")
            .join(format!("limine-{LIMINE_VERSION}"))
    }

    fn image_dir(&self) -> PathBuf {
        self.target.join("xtask").join("image")
    }
}

/// A failed external command, with a hint when the program is missing.
struct CommandError {
    program: String,
    detail: String,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.program, self.detail)
    }
}

fn install_hint(program: &str) -> &'static str {
    match program {
        "xorriso" => " (install with: sudo apt install xorriso)",
        "curl" => " (install with: sudo apt install curl)",
        "cc" => " (install with: sudo apt install build-essential)",
        _ => "",
    }
}

/// Runs a command. Output is shown only if it fails, unless `verbose`.
fn run(cmd: &mut Command, verbose: bool) -> Result<Vec<u8>> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let output = if verbose {
        cmd.status().map(|status| std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    } else {
        cmd.output()
    };
    let output = output.map_err(|e| {
        let detail = if e.kind() == io::ErrorKind::NotFound {
            format!("not found{}", install_hint(&program))
        } else {
            e.to_string()
        };
        CommandError {
            program: program.clone(),
            detail,
        }
        .to_string()
    })?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let mut message = format!("{program} failed ({})", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        message.push_str(":\n");
        message.push_str(stderr.trim_end());
    }
    Err(message)
}

/// Extracts the hash from `sha256sum` output (`<hex>  <path>`).
fn parse_sha256sum(output: &str) -> Result<String> {
    let hash = output.split_whitespace().next().unwrap_or_default();
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hash.to_ascii_lowercase())
    } else {
        Err(format!("unexpected sha256sum output: {output:?}"))
    }
}

fn sha256(path: &Path) -> Result<String> {
    let stdout = run(Command::new("sha256sum").arg(path), false)?;
    parse_sha256sum(&String::from_utf8_lossy(&stdout))
}

fn verify_checksum(path: &Path, expected: &str, actual: &str) -> Result<()> {
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "checksum mismatch for {}\n  expected {expected}\n  actual   {actual}",
            path.display()
        ))
    }
}

fn source_date_epoch() -> Result<u64> {
    match env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value
            .parse()
            .map_err(|_| format!("SOURCE_DATE_EPOCH must be a number of seconds, got {value:?}")),
        Err(_) => Ok(DEFAULT_SOURCE_DATE_EPOCH),
    }
}

fn io_err(action: &str, path: &Path) -> impl FnOnce(io::Error) -> String {
    let path = path.display().to_string();
    let action = action.to_owned();
    move |e| format!("{action} {path}: {e}")
}

fn recreate_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(io_err("cannot remove", path))?;
    }
    fs::create_dir_all(path).map_err(io_err("cannot create", path))
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(io_err(&format!("cannot copy to {}", to.display()), from))
}

/// Sets the modification time of `dir` and everything below it.
fn pin_timestamps(dir: &Path, time: SystemTime) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(io_err("cannot read", dir))? {
        let path = entry.map_err(io_err("cannot read", dir))?.path();
        if path.is_dir() {
            pin_timestamps(&path, time)?;
        } else {
            set_mtime(&path, time)?;
        }
    }
    set_mtime(dir, time)
}

fn set_mtime(path: &Path, time: SystemTime) -> Result<()> {
    fs::File::open(path)
        .and_then(|file| file.set_modified(time))
        .map_err(io_err("cannot set timestamp on", path))
}

/// Downloads (if needed), verifies, and unpacks the pinned Limine release.
/// Returns the unpacked directory and the compiled `limine` host tool.
fn ensure_limine(paths: &Paths) -> Result<(PathBuf, PathBuf)> {
    let dir = paths.limine_dir();
    fs::create_dir_all(&dir).map_err(io_err("cannot create", &dir))?;
    let archive = dir.join(LIMINE_ARCHIVE);

    if archive.exists() {
        verify_checksum(&archive, LIMINE_SHA256, &sha256(&archive)?).map_err(|e| {
            format!(
                "{e}\nThe cached download is not the pinned release. Delete {} and retry.",
                dir.display()
            )
        })?;
    } else {
        let url = format!(
            "https://github.com/limine-bootloader/limine/releases/download/v{LIMINE_VERSION}/{LIMINE_ARCHIVE}"
        );
        let partial = dir.join(format!("{LIMINE_ARCHIVE}.part"));
        println!("Downloading Limine {LIMINE_VERSION} from {url}");
        run(
            Command::new("curl")
                .args(["--fail", "--silent", "--show-error", "--location"])
                .args(["--proto", "=https", "--tlsv1.2", "--output"])
                .arg(&partial)
                .arg(&url),
            false,
        )?;
        if let Err(e) = verify_checksum(&partial, LIMINE_SHA256, &sha256(&partial)?) {
            let _ = fs::remove_file(&partial);
            return Err(format!("{e}\nThe download was deleted. Do not use it."));
        }
        fs::rename(&partial, &archive).map_err(io_err("cannot rename", &partial))?;
    }
    println!("Limine {LIMINE_VERSION}: SHA-256 verified ({LIMINE_SHA256})");

    // Unpack fresh each time from the verified archive into its own directory.
    let unpacked = dir.join("unpacked");
    recreate_dir(&unpacked)?;
    run(
        Command::new("tar")
            .arg("-xJf")
            .arg(&archive)
            .arg("-C")
            .arg(&unpacked),
        false,
    )?;
    let files = unpacked.join("limine-binary");
    if !files.join("limine.c").is_file() {
        return Err(format!(
            "unexpected Limine archive layout: {} has no limine-binary/limine.c",
            archive.display()
        ));
    }

    // The release ships the host tool as source; compile it with the system C compiler.
    let tool = dir.join("limine");
    run(
        Command::new("cc")
            .args(["-O2", "-std=c99", "-D_FILE_OFFSET_BITS=64"])
            .arg(files.join("limine.c"))
            .arg("-o")
            .arg(&tool),
        false,
    )?;
    Ok((files, tool))
}

fn build(paths: &Paths) -> Result<()> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    run(
        Command::new(cargo)
            .current_dir(&paths.root)
            .args([
                "build",
                "--release",
                "--locked",
                "--package",
                KERNEL_PACKAGE,
            ])
            .args(["--target", KERNEL_TARGET]),
        true,
    )?;
    Ok(())
}

fn image(paths: &Paths, kernel: Option<PathBuf>) -> Result<()> {
    let kernel = kernel.unwrap_or_else(|| paths.kernel_elf());
    if !kernel.is_file() {
        return Err(format!(
            "kernel not found at {}\nRun `cargo xtask build` first, or pass --kernel <ELF>.",
            kernel.display()
        ));
    }
    let epoch = source_date_epoch()?;
    let (limine, tool) = ensure_limine(paths)?;

    let out = paths.image_dir();
    let root = out.join("iso-root");
    recreate_dir(&root)?;
    let boot = root.join("boot");
    let boot_limine = boot.join("limine");
    let efi = root.join("EFI").join("BOOT");
    for dir in [&boot_limine, &efi] {
        fs::create_dir_all(dir).map_err(io_err("cannot create", dir))?;
    }
    copy(&kernel, &boot.join("kernel"))?;
    fs::write(boot_limine.join("limine.conf"), LIMINE_CONF)
        .map_err(io_err("cannot write", &boot_limine))?;
    for name in [
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
    ] {
        copy(&limine.join(name), &boot_limine.join(name))?;
    }
    // Limine is BSD-2-Clause: images carry its license notice.
    copy(&limine.join("LICENSE"), &boot_limine.join("LICENSE"))?;
    copy(&limine.join("BOOTX64.EFI"), &efi.join("BOOTX64.EFI"))?;

    // SOURCE_DATE_EPOCH alone does not make the ISO byte-identical; file
    // timestamps must be pinned too (prototype finding, boot-evaluation.md).
    pin_timestamps(&root, SystemTime::UNIX_EPOCH + Duration::from_secs(epoch))?;

    let iso = out.join("pharos.iso");
    run(
        Command::new("xorriso")
            .env("SOURCE_DATE_EPOCH", epoch.to_string())
            .args(["-as", "mkisofs", "-R", "-r", "-J"])
            .args(["-b", "boot/limine/limine-bios-cd.bin"])
            .args(["-no-emul-boot", "-boot-load-size", "4", "-boot-info-table"])
            .args(["-hfsplus", "-apm-block-size", "2048"])
            .args(["--efi-boot", "boot/limine/limine-uefi-cd.bin"])
            .args([
                "-efi-boot-part",
                "--efi-boot-image",
                "--protective-msdos-label",
            ])
            .arg(&root)
            .arg("-o")
            .arg(&iso),
        false,
    )?;
    run(
        Command::new(&tool)
            .arg(OsStr::new("bios-install"))
            .arg(&iso),
        false,
    )?;

    println!("Image: {}", iso.display());
    println!("SHA-256: {}", sha256(&iso)?);
    Ok(())
}

/// QEMU arguments for booting `iso`. UEFI uses OVMF with a writable copy of
/// its variable store at `vars`.
fn qemu_args(iso: &Path, vars: &Path, bios: bool, gdb: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "-M",
        "q35",
        "-m",
        "256M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-cdrom",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.push(iso.into());
    if !bios {
        args.push("-drive".into());
        args.push(format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}").into());
        let mut vars_drive = OsString::from("if=pflash,format=raw,file=");
        vars_drive.push(vars);
        args.push("-drive".into());
        args.push(vars_drive);
    }
    if gdb {
        // -s: GDB server on localhost:1234; -S: wait for GDB before starting.
        args.push("-s".into());
        args.push("-S".into());
    }
    args
}

/// Turns QEMU's exit status into a result. Only the kernel's success signal
/// counts as success.
fn interpret_qemu_status(code: Option<i32>) -> Result<()> {
    match code {
        Some(QEMU_EXIT_SUCCESS) => Ok(()),
        Some(QEMU_EXIT_FAILURE) => Err(format!(
            "the kernel reported a failure (QEMU exit status {QEMU_EXIT_FAILURE}); see the serial output above"
        )),
        Some(other) => Err(format!(
            "QEMU exited with status {other} without a kernel signal; the kernel may have crashed or QEMU failed to start"
        )),
        None => Err("QEMU was stopped by a signal before the kernel reported a result".into()),
    }
}

fn run_qemu(paths: &Paths, bios: bool, gdb: bool) -> Result<()> {
    build(paths)?;
    image(paths, None)?;
    let out = paths.image_dir();
    let iso = out.join("pharos.iso");
    let vars = out.join("ovmf-vars.fd");
    if !bios {
        if !Path::new(OVMF_CODE).is_file() {
            return Err(format!(
                "UEFI firmware not found at {OVMF_CODE} (install with: sudo apt install ovmf), or use --bios"
            ));
        }
        copy(Path::new(OVMF_VARS), &vars)?;
    }
    if gdb {
        let kernel = paths.kernel_elf();
        println!("QEMU is waiting for GDB. In another terminal run:");
        println!(
            "  gdb {} -ex 'target remote localhost:1234' -ex 'break kmain' -ex continue",
            kernel.display()
        );
    }
    println!(
        "Booting {} with {} (serial output follows; stop with Ctrl+C)",
        iso.display(),
        if bios { "SeaBIOS" } else { "OVMF (UEFI)" }
    );
    let status = Command::new("qemu-system-x86_64")
        .args(qemu_args(&iso, &vars, bios, gdb))
        .status()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "qemu-system-x86_64: not found (install with: sudo apt install qemu-system-x86)"
                    .to_owned()
            } else {
                format!("qemu-system-x86_64: {e}")
            }
        })?;
    interpret_qemu_status(status.code())?;
    println!("Kernel reported success (QEMU exit status {QEMU_EXIT_SUCCESS}).");
    Ok(())
}

fn main() -> ExitCode {
    let result = parse(env::args().skip(1)).and_then(|task| {
        let paths = Paths::new();
        match task {
            Task::Help => {
                print!("{HELP}");
                Ok(())
            }
            Task::Build => build(&paths),
            Task::Image { kernel } => image(&paths, kernel),
            Task::Run { bios, gdb } => run_qemu(&paths, bios, gdb),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_commands() {
        assert_eq!(parse(args(&[])), Ok(Task::Help));
        assert_eq!(parse(args(&["help"])), Ok(Task::Help));
        assert_eq!(parse(args(&["build"])), Ok(Task::Build));
        assert_eq!(parse(args(&["image"])), Ok(Task::Image { kernel: None }));
        assert_eq!(
            parse(args(&["image", "--kernel", "k.elf"])),
            Ok(Task::Image {
                kernel: Some(PathBuf::from("k.elf"))
            })
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse(args(&["boot"])).is_err());
        assert!(parse(args(&["build", "--fast"])).is_err());
        assert!(parse(args(&["image", "--kernel"])).is_err());
        assert!(parse(args(&["image", "--iso"])).is_err());
        assert!(parse(args(&["run", "--uefi"])).is_err());
    }

    #[test]
    fn parses_run_flags() {
        assert_eq!(
            parse(args(&["run"])),
            Ok(Task::Run {
                bios: false,
                gdb: false
            })
        );
        assert_eq!(
            parse(args(&["run", "--gdb", "--bios"])),
            Ok(Task::Run {
                bios: true,
                gdb: true
            })
        );
    }

    #[test]
    fn qemu_args_match_the_firmware_and_debug_options() {
        let (iso, vars) = (Path::new("pharos.iso"), Path::new("vars.fd"));
        let joined = |a: Vec<OsString>| {
            a.iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let uefi = joined(qemu_args(iso, vars, false, false));
        assert!(uefi.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
        assert!(uefi.contains("-cdrom pharos.iso"));
        assert!(uefi.contains(OVMF_CODE) && uefi.contains("file=vars.fd"));
        assert!(!uefi.contains(" -S"));
        let bios = joined(qemu_args(iso, vars, true, true));
        assert!(!bios.contains("pflash"));
        assert!(bios.ends_with("-s -S"));
    }

    #[test]
    fn only_the_kernel_success_signal_counts() {
        assert!(interpret_qemu_status(Some(33)).is_ok());
        assert!(
            interpret_qemu_status(Some(35))
                .unwrap_err()
                .contains("reported a failure")
        );
        assert!(
            interpret_qemu_status(Some(0))
                .unwrap_err()
                .contains("without a kernel signal")
        );
        assert!(interpret_qemu_status(Some(1)).is_err());
        assert!(interpret_qemu_status(None).is_err());
    }

    #[test]
    fn parses_sha256sum_output() {
        let line = format!(
            "{}  /tmp/limine-binary.tar.xz\n",
            LIMINE_SHA256.to_uppercase()
        );
        assert_eq!(parse_sha256sum(&line), Ok(LIMINE_SHA256.to_owned()));
        assert!(parse_sha256sum("").is_err());
        assert!(parse_sha256sum("abc  file").is_err());
        assert!(parse_sha256sum(&format!("{}  file", "g".repeat(64))).is_err());
    }

    #[test]
    fn checksum_comparison() {
        let path = Path::new("limine-binary.tar.xz");
        assert!(verify_checksum(path, LIMINE_SHA256, LIMINE_SHA256).is_ok());
        assert!(verify_checksum(path, LIMINE_SHA256, &LIMINE_SHA256.to_uppercase()).is_ok());
        let wrong = "0".repeat(64);
        let err = verify_checksum(path, LIMINE_SHA256, &wrong).unwrap_err();
        assert!(err.contains("checksum mismatch") && err.contains(&wrong));
    }

    #[test]
    fn pinned_values_are_well_formed() {
        assert_eq!(parse_sha256sum(LIMINE_SHA256), Ok(LIMINE_SHA256.to_owned()));
        assert!(LIMINE_CONF.contains("protocol: limine"));
        assert!(LIMINE_CONF.contains("path: boot():/boot/kernel"));
    }

    #[test]
    fn outputs_stay_under_target() {
        let paths = Paths::new();
        for path in [paths.kernel_elf(), paths.limine_dir(), paths.image_dir()] {
            assert!(path.starts_with(&paths.target), "{}", path.display());
        }
    }
}
