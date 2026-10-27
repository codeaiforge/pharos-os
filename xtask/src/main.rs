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
use std::process::{Child, Command, ExitCode};
use std::time::{Duration, Instant, SystemTime};

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

/// Serial marker the kernel prints after a successful boot (D-009).
const BOOT_MARKER: &str = "PHAROS: boot ok";
/// Serial marker a passing test kernel prints last (D-009; must match
/// `pharos_kernel::testing::TESTS_OK_MARKER`).
const TESTS_MARKER: &str = "PHAROS: tests ok";
/// Environment variable `test` uses to pass its time limit to `runner`.
const TEST_TIMEOUT_ENV: &str = "PHAROS_TEST_TIMEOUT";
/// Default time limit per headless boot under TCG (D-009).
const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 60;
/// Log lines shown when a headless boot fails.
const LOG_TAIL_LINES: usize = 40;

const HELP: &str = "\
cargo xtask - build tool for Pharos OS

USAGE:
    cargo xtask <COMMAND> [OPTIONS]

COMMANDS:
    build                   Build the kernel for x86_64-unknown-none (release)
    image [--kernel <ELF>]  Build a hybrid BIOS/UEFI ISO with the pinned Limine
                            release. Uses the built kernel unless --kernel is given.
    run [--bios] [--gdb] [--kernel <ELF>]
                            Build, make the image, and boot it in QEMU with serial
                            output on this terminal. UEFI (OVMF) by default; --bios
                            uses SeaBIOS; --gdb waits for GDB on localhost:1234;
                            --kernel boots the given ELF (for example a test
                            kernel) instead of building the kernel.
                            Succeeds only if the kernel reports success.
    test [--timeout <SECS>] Boot check: build, make the image, and boot it headless
                            under UEFI and BIOS. Then kernel tests: boot every test
                            kernel in kernel/tests/ under UEFI. A boot passes only
                            if QEMU exits with status 33 and the serial log shows
                            the expected marker within the time limit (default
                            60 s). Logs: target/xtask/logs/.
    runner <ELF>            Boot one test kernel headless (used by Cargo as the
                            runner for x86_64-unknown-none; see .cargo/config.toml).
    help                    Show this help message

Outputs go to target/xtask/. Requires curl, sha256sum, tar (xz), cc, and xorriso;
`run` and `test` also need qemu-system-x86_64 and, for UEFI, OVMF.
";

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, PartialEq, Eq)]
enum Task {
    Help,
    Build,
    Image {
        kernel: Option<PathBuf>,
    },
    Run {
        bios: bool,
        gdb: bool,
        kernel: Option<PathBuf>,
    },
    Test {
        timeout: Duration,
    },
    Runner {
        elf: PathBuf,
    },
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
            let (mut bios, mut gdb, mut kernel) = (false, false, None);
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--bios" => bios = true,
                    "--gdb" => gdb = true,
                    "--kernel" => {
                        let path = args.next().ok_or("--kernel needs a path")?;
                        kernel = Some(PathBuf::from(path));
                    }
                    other => return Err(format!("unexpected argument '{other}'")),
                }
            }
            return Ok(Task::Run { bios, gdb, kernel });
        }
        Some("runner") => {
            let elf = args
                .next()
                .ok_or("runner needs the path of a test kernel")?;
            if let Some(extra) = args.next() {
                return Err(format!(
                    "unexpected argument '{extra}' (test kernels take no arguments)"
                ));
            }
            return Ok(Task::Runner {
                elf: PathBuf::from(elf),
            });
        }
        Some("test") => {
            let mut secs = DEFAULT_BOOT_TIMEOUT_SECS;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--timeout" => {
                        let value = args.next().ok_or("--timeout needs a number of seconds")?;
                        secs = value.parse().ok().filter(|&s| s > 0).ok_or(format!(
                            "--timeout must be a positive number of seconds, got '{value}'"
                        ))?;
                    }
                    other => return Err(format!("unexpected argument '{other}'")),
                }
            }
            return Ok(Task::Test {
                timeout: Duration::from_secs(secs),
            });
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

    fn logs_dir(&self) -> PathBuf {
        self.target.join("xtask").join("logs")
    }

    fn runner_dir(&self, name: &str) -> PathBuf {
        self.target.join("xtask").join("runner").join(name)
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

/// Builds the ISO for `kernel` (default: the built kernel) in `out` and
/// returns its path.
fn image(paths: &Paths, kernel: Option<PathBuf>, out: &Path) -> Result<PathBuf> {
    let kernel = kernel.unwrap_or_else(|| paths.kernel_elf());
    if !kernel.is_file() {
        return Err(format!(
            "kernel not found at {}\nRun `cargo xtask build` first, or pass --kernel <ELF>.",
            kernel.display()
        ));
    }
    let epoch = source_date_epoch()?;
    let (limine, tool) = ensure_limine(paths)?;

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

    Ok(iso)
}

/// Builds the main image and prints its path and hash.
fn main_image(paths: &Paths, kernel: Option<PathBuf>) -> Result<PathBuf> {
    let iso = image(paths, kernel, &paths.image_dir())?;
    println!("Image: {}", iso.display());
    println!("SHA-256: {}", sha256(&iso)?);
    Ok(iso)
}

/// QEMU arguments for booting `iso`. `serial` is a QEMU character device
/// such as `stdio` or `file:<path>`. UEFI uses OVMF with a writable copy of
/// its variable store at `vars`.
fn qemu_args(iso: &Path, vars: &Path, serial: &OsStr, bios: bool, gdb: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "-M",
        "q35",
        "-m",
        "256M",
        "-display",
        "none",
        "-no-reboot",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-cdrom",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.push(iso.into());
    args.push("-serial".into());
    args.push(serial.into());
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

/// Name of a firmware choice, for messages and log file names.
fn firmware_name(bios: bool) -> &'static str {
    if bios { "bios" } else { "uefi" }
}

/// For UEFI, checks that OVMF is installed and writes a fresh copy of its
/// variable store to `vars`. Nothing to do for BIOS.
fn prepare_firmware(vars: &Path, bios: bool) -> Result<()> {
    if bios {
        return Ok(());
    }
    if !Path::new(OVMF_CODE).is_file() {
        return Err(format!(
            "UEFI firmware not found at {OVMF_CODE} (install with: sudo apt install ovmf), or use --bios"
        ));
    }
    copy(Path::new(OVMF_VARS), vars)
}

fn qemu_command(args: Vec<OsString>) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(args);
    cmd
}

fn qemu_error(e: io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        "qemu-system-x86_64: not found (install with: sudo apt install qemu-system-x86)".to_owned()
    } else {
        format!("qemu-system-x86_64: {e}")
    }
}

fn run_qemu(paths: &Paths, bios: bool, gdb: bool, kernel: Option<PathBuf>) -> Result<()> {
    let elf = match kernel {
        Some(elf) => elf,
        None => {
            build(paths)?;
            paths.kernel_elf()
        }
    };
    let iso = main_image(paths, Some(elf.clone()))?;
    let out = paths.image_dir();
    let vars = out.join("ovmf-vars.fd");
    prepare_firmware(&vars, bios)?;
    if gdb {
        println!("QEMU is waiting for GDB. In another terminal run:");
        println!(
            "  gdb {} -ex 'target remote localhost:1234' -ex 'break kmain' -ex continue",
            elf.display()
        );
    }
    println!(
        "Booting {} with {} (serial output follows; stop with Ctrl+C)",
        iso.display(),
        if bios { "SeaBIOS" } else { "OVMF (UEFI)" }
    );
    let status = qemu_command(qemu_args(&iso, &vars, OsStr::new("stdio"), bios, gdb))
        .status()
        .map_err(qemu_error)?;
    interpret_qemu_status(status.code())?;
    println!("Kernel reported success (QEMU exit status {QEMU_EXIT_SUCCESS}).");
    Ok(())
}

/// What a headless boot produced.
struct BootRun {
    /// QEMU's exit status; `None` if it timed out or was killed by a signal.
    status: Option<i32>,
    timed_out: bool,
    log: String,
    elapsed: Duration,
}

/// Waits for `child`, killing it after `timeout`.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<(Option<i32>, bool)> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(qemu_error)? {
            return Ok((status.code(), false));
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Boots `iso` without a terminal, with serial output written to `log`.
fn boot_headless(
    iso: &Path,
    vars: &Path,
    log: &Path,
    bios: bool,
    timeout: Duration,
) -> Result<BootRun> {
    prepare_firmware(vars, bios)?;
    let _ = fs::remove_file(log);
    let mut serial = OsString::from("file:");
    serial.push(log);
    let start = Instant::now();
    let mut child = qemu_command(qemu_args(iso, vars, &serial, bios, false))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(qemu_error)?;
    let (status, timed_out) = wait_with_timeout(&mut child, timeout)?;
    let bytes = fs::read(log).unwrap_or_default();
    Ok(BootRun {
        status,
        timed_out,
        log: String::from_utf8_lossy(&bytes).into_owned(),
        elapsed: start.elapsed(),
    })
}

/// Decides whether a headless boot passed (D-009): QEMU exit status 33 and
/// the serial marker, within the time limit.
fn evaluate_boot(run: &BootRun, marker: &str, timeout: Duration) -> Result<()> {
    let has_marker = run
        .log
        .lines()
        .any(|line| line.trim_end_matches('\r').trim() == marker);
    if run.timed_out {
        return Err(format!(
            "no result within {} s; the kernel may hang (QEMU was stopped)",
            timeout.as_secs()
        ));
    }
    match run.status {
        Some(QEMU_EXIT_SUCCESS) if has_marker => Ok(()),
        Some(QEMU_EXIT_SUCCESS) => Err(format!(
            "QEMU exited with the success status, but the serial log lacks \"{marker}\""
        )),
        Some(QEMU_EXIT_FAILURE) => Err(format!(
            "the kernel reported a failure (QEMU exit status {QEMU_EXIT_FAILURE})"
        )),
        Some(other) => Err(format!(
            "QEMU exited with status {other} without a kernel signal"
        )),
        None => Err("QEMU was stopped by a signal".into()),
    }
}

/// Removes terminal escape sequences and carriage returns, which firmware
/// writes to the serial port, so logs are readable as plain text.
fn clean_log(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // Parameters, then one final byte in the range '@'..='~'.
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
            }
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// The last `n` non-empty lines of a cleaned log.
fn log_tail(text: &str, n: usize) -> Vec<String> {
    let cleaned = clean_log(text);
    let lines: Vec<&str> = cleaned.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| (*l).to_owned())
        .collect()
}

/// Prints why a headless boot failed and the end of its serial log.
fn report_failure(label: &str, run: &BootRun, log: &Path, reason: &str) {
    let secs = run.elapsed.as_secs_f32();
    println!("{label}: FAIL after {secs:.1} s: {reason}");
    println!("  serial log ({}), last lines:", log.display());
    for line in log_tail(&run.log, LOG_TAIL_LINES) {
        println!("  | {line}");
    }
}

/// `cargo xtask test`: boot check under UEFI and BIOS, then the kernel tests
/// (D-009). Both parts always run; the command fails if either fails.
fn test(paths: &Paths, timeout: Duration) -> Result<()> {
    let boot = boot_check(paths, timeout);
    if let Err(e) = &boot {
        println!("{e}");
    }
    println!("Kernel tests (cargo test -p {KERNEL_PACKAGE} --target {KERNEL_TARGET} --test '*'):");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let tests = run(
        Command::new(cargo)
            .current_dir(&paths.root)
            .env(TEST_TIMEOUT_ENV, timeout.as_secs().to_string())
            .args(["test", "--locked", "--package", KERNEL_PACKAGE])
            .args(["--target", KERNEL_TARGET, "--test", "*"]),
        true,
    );
    match (boot, tests) {
        (Ok(()), Ok(_)) => {
            println!("All boot checks and kernel tests passed.");
            Ok(())
        }
        (Ok(()), Err(_)) => Err("kernel tests failed (see above)".into()),
        (Err(_), Ok(_)) => Err("boot checks failed (see above)".into()),
        (Err(_), Err(_)) => Err("boot checks and kernel tests failed (see above)".into()),
    }
}

fn boot_check(paths: &Paths, timeout: Duration) -> Result<()> {
    build(paths)?;
    let iso = main_image(paths, None)?;
    let logs = paths.logs_dir();
    fs::create_dir_all(&logs).map_err(io_err("cannot create", &logs))?;

    let mut failures = 0;
    for bios in [false, true] {
        let name = firmware_name(bios);
        let log = logs.join(format!("boot-{name}.log"));
        let vars = logs.join(format!("boot-{name}-ovmf-vars.fd"));
        let run = boot_headless(&iso, &vars, &log, bios, timeout)?;
        let label = format!("boot check ({name})");
        match evaluate_boot(&run, BOOT_MARKER, timeout) {
            Ok(()) => println!("{label}: PASS in {:.1} s", run.elapsed.as_secs_f32()),
            Err(reason) => {
                failures += 1;
                report_failure(&label, &run, &log, &reason);
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} of 2 boot checks failed"));
    }
    println!("All boot checks passed.");
    Ok(())
}

/// Test name from a Cargo test binary path such as
/// `target/x86_64-unknown-none/debug/deps/boot_info-45a734add0c0d3ef`.
fn test_name(elf: &Path) -> String {
    let stem = elf
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "test".to_owned());
    match stem.rsplit_once('-') {
        Some((name, hash)) if !name.is_empty() && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            name.to_owned()
        }
        _ => stem,
    }
}

/// Time limit for `runner`, passed by `test` through `PHAROS_TEST_TIMEOUT`.
fn runner_timeout(value: Option<&str>) -> Result<Duration> {
    match value {
        None => Ok(Duration::from_secs(DEFAULT_BOOT_TIMEOUT_SECS)),
        Some(v) => v
            .parse()
            .ok()
            .filter(|&s: &u64| s > 0)
            .map(Duration::from_secs)
            .ok_or(format!(
                "{TEST_TIMEOUT_ENV} must be a positive number of seconds, got '{v}'"
            )),
    }
}

/// `cargo xtask runner <ELF>`: Cargo's runner for test kernels. Wraps one
/// test kernel in its own image and boots it headless under UEFI (D-009).
fn runner(paths: &Paths, elf: &Path) -> Result<()> {
    let timeout = runner_timeout(env::var(TEST_TIMEOUT_ENV).ok().as_deref())?;
    let name = test_name(elf);
    let out = paths.runner_dir(&name);
    fs::create_dir_all(&out).map_err(io_err("cannot create", &out))?;
    let iso = image(paths, Some(elf.to_path_buf()), &out)?;
    let logs = paths.logs_dir();
    fs::create_dir_all(&logs).map_err(io_err("cannot create", &logs))?;
    let log = logs.join(format!("test-{name}.log"));
    let run = boot_headless(&iso, &out.join("ovmf-vars.fd"), &log, false, timeout)?;
    let label = format!("test kernel {name} (uefi)");
    match evaluate_boot(&run, TESTS_MARKER, timeout) {
        Ok(()) => {
            for line in clean_log(&run.log)
                .lines()
                .filter(|l| l.starts_with("PHAROS-TEST:"))
            {
                println!("  {line}");
            }
            println!("{label}: PASS in {:.1} s", run.elapsed.as_secs_f32());
            Ok(())
        }
        Err(reason) => {
            report_failure(&label, &run, &log, &reason);
            Err(format!("{label} failed"))
        }
    }
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
            Task::Image { kernel } => main_image(&paths, kernel).map(|_| ()),
            Task::Run { bios, gdb, kernel } => run_qemu(&paths, bios, gdb, kernel),
            Task::Test { timeout } => test(&paths, timeout),
            Task::Runner { elf } => runner(&paths, &elf),
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
                gdb: false,
                kernel: None
            })
        );
        assert_eq!(
            parse(args(&["run", "--gdb", "--bios"])),
            Ok(Task::Run {
                bios: true,
                gdb: true,
                kernel: None
            })
        );
        assert_eq!(
            parse(args(&["run", "--kernel", "t.elf", "--gdb"])),
            Ok(Task::Run {
                bios: false,
                gdb: true,
                kernel: Some(PathBuf::from("t.elf"))
            })
        );
        assert!(parse(args(&["run", "--kernel"])).is_err());
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
        let stdio = OsStr::new("stdio");
        let uefi = joined(qemu_args(iso, vars, stdio, false, false));
        assert!(uefi.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
        assert!(uefi.contains("-cdrom pharos.iso"));
        assert!(uefi.contains(OVMF_CODE) && uefi.contains("file=vars.fd"));
        assert!(!uefi.contains(" -S"));
        assert!(uefi.contains("-serial stdio"));
        let bios = joined(qemu_args(
            iso,
            vars,
            OsStr::new("file:boot.log"),
            true,
            true,
        ));
        assert!(bios.contains("-serial file:boot.log"));
        assert!(!bios.contains("pflash"));
        assert!(bios.ends_with("-s -S"));
    }

    #[test]
    fn parses_test_timeout() {
        assert_eq!(
            parse(args(&["test"])),
            Ok(Task::Test {
                timeout: Duration::from_secs(DEFAULT_BOOT_TIMEOUT_SECS)
            })
        );
        assert_eq!(
            parse(args(&["test", "--timeout", "5"])),
            Ok(Task::Test {
                timeout: Duration::from_secs(5)
            })
        );
        assert!(parse(args(&["test", "--timeout"])).is_err());
        assert!(parse(args(&["test", "--timeout", "0"])).is_err());
        assert!(parse(args(&["test", "--timeout", "soon"])).is_err());
        assert!(parse(args(&["test", "--bios"])).is_err());
    }

    #[test]
    fn parses_runner() {
        assert_eq!(
            parse(args(&["runner", "target/deps/boot_info-0123abcd"])),
            Ok(Task::Runner {
                elf: PathBuf::from("target/deps/boot_info-0123abcd")
            })
        );
        assert!(parse(args(&["runner"])).is_err());
        assert!(parse(args(&["runner", "k", "--nocapture"])).is_err());
    }

    #[test]
    fn names_test_kernels() {
        let name = |p: &str| test_name(Path::new(p));
        assert_eq!(
            name("target/x86_64-unknown-none/debug/deps/boot_info-45a734add0c0d3ef"),
            "boot_info"
        );
        assert_eq!(name("deps/memory-map-0f"), "memory-map");
        assert_eq!(name("deps/plain"), "plain");
        assert_eq!(name("deps/ends-with-word"), "ends-with-word");
    }

    #[test]
    fn runner_timeout_from_environment() {
        assert_eq!(
            runner_timeout(None),
            Ok(Duration::from_secs(DEFAULT_BOOT_TIMEOUT_SECS))
        );
        assert_eq!(runner_timeout(Some("15")), Ok(Duration::from_secs(15)));
        assert!(runner_timeout(Some("0")).is_err());
        assert!(runner_timeout(Some("later")).is_err());
    }

    fn boot_run(status: Option<i32>, timed_out: bool, log: &str) -> BootRun {
        BootRun {
            status,
            timed_out,
            log: log.to_owned(),
            elapsed: Duration::from_secs(1),
        }
    }

    #[test]
    fn boot_passes_only_with_status_and_marker() {
        let t = Duration::from_secs(60);
        let good = "\u{1b}[2JBdsDxe: starting\r\nPharos OS 0.1.0 kernel\r\nPHAROS: boot ok\r\n";
        assert!(evaluate_boot(&boot_run(Some(33), false, good), BOOT_MARKER, t).is_ok());

        let no_marker = evaluate_boot(&boot_run(Some(33), false, "Pharos OS\n"), BOOT_MARKER, t);
        assert!(no_marker.unwrap_err().contains("lacks"));
        let partial = evaluate_boot(
            &boot_run(Some(33), false, "PHAROS: boot ok?\n"),
            BOOT_MARKER,
            t,
        );
        assert!(partial.is_err(), "marker must match a whole line");

        let failed = evaluate_boot(&boot_run(Some(35), false, good), BOOT_MARKER, t);
        assert!(failed.unwrap_err().contains("reported a failure"));
        let other = evaluate_boot(&boot_run(Some(0), false, good), BOOT_MARKER, t);
        assert!(other.unwrap_err().contains("without a kernel signal"));
        let timeout = evaluate_boot(&boot_run(None, true, good), BOOT_MARKER, t);
        assert!(timeout.unwrap_err().contains("no result within 60 s"));
        assert!(evaluate_boot(&boot_run(None, false, good), BOOT_MARKER, t).is_err());
    }

    #[test]
    fn cleans_firmware_noise_from_logs() {
        let raw = "\u{1b}[2J\u{1b}[01;01H\u{1b}[=3hBdsDxe: loading\r\n\r\nPHAROS: boot ok\r\n";
        assert_eq!(clean_log(raw), "BdsDxe: loading\n\nPHAROS: boot ok\n");
        assert_eq!(log_tail(raw, 1), vec!["PHAROS: boot ok".to_owned()]);
        assert_eq!(log_tail(raw, 10).len(), 2);
        assert!(log_tail("", 5).is_empty());
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
