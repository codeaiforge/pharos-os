//! `pharos`: host-side development CLI for Pharos OS.
//!
//! Scope: print project metadata and run read-only environment checks. This
//! program never runs external commands, never requests privileges, never
//! reads secrets, and never modifies the system.

use std::env;
use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

const PROJECT: &str = "Pharos OS";
const ORGANIZATION: &str = "CodeAIForge";
/// Comes from Cargo package metadata (workspace version), never hand-copied.
const VERSION: &str = env!("CARGO_PKG_VERSION");
const STAGE: &str = "Phase 3 - AI Agent Platform (M3.3 complete, M3.4 next)";

/// Command succeeded.
const EXIT_OK: u8 = 0;
/// Command ran but reported a problem (e.g. `doctor` warnings, I/O failure).
const EXIT_FAILURE: u8 = 1;
/// Invalid invocation (unknown command, missing or extra arguments).
const EXIT_USAGE: u8 = 2;

const HELP: &str = "\
pharos - host-side development tool for Pharos OS

USAGE:
    pharos <COMMAND>

COMMANDS:
    help       Show this help message
    version    Show the pharos version
    info       Show project status and what is implemented
    doctor     Run read-only checks of the development environment

OPTIONS:
    -h, --help       Same as `help`
    -V, --version    Same as `version`

EXIT STATUS:
    0  success
    1  command reported a problem (for example, doctor warnings)
    2  invalid usage
";

/// Each entry: (status label, description). Keep labels honest: only mark
/// something `implemented` once it exists and is tested.
const COMPONENTS: &[(&str, &str)] = &[
    ("implemented", "host-side Rust workspace and `pharos` CLI"),
    (
        "implemented",
        "`cargo xtask`: kernel build, reproducible boot image, QEMU run",
    ),
    (
        "implemented",
        "minimal x86-64 kernel: boots in QEMU via Limine (UEFI and BIOS), \
         reports boot information over serial, starts init and its services",
    ),
    (
        "implemented",
        "CPU exception handling (incl. stack overflow) and local APIC timer interrupts",
    ),
    (
        "implemented",
        "kernel memory management: frame allocator, own page tables, heap",
    ),
    (
        "implemented",
        "calibrated timer and preemptive scheduling of kernel tasks",
    ),
    ("implemented", "QEMU boot check in CI (UEFI and BIOS)"),
    (
        "implemented",
        "kernel tests inside QEMU (test kernels in kernel/tests/)",
    ),
    (
        "implemented",
        "user processes in ring 3, system calls, IPC with capabilities",
    ),
    (
        "implemented",
        "read-only storage: RAM disk, checked filesystem image, file capabilities",
    ),
    (
        "implemented",
        "user-space drivers: PCI, device capabilities, MSI-X interrupts, virtio-blk",
    ),
    (
        "implemented",
        "services and networking: init, a user-space UDP/ICMP network service, \
         badged network capabilities",
    ),
    ("planned", "writable storage, TCP, more drivers"),
    ("planned", "local AI inference and sandboxed agent platform"),
];

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Info,
    Doctor,
}

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    Missing,
    Unknown(String),
    Unexpected(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "no command given"),
            Self::Unknown(cmd) => write!(f, "unknown command '{cmd}'"),
            Self::Unexpected(arg) => write!(f, "unexpected argument '{arg}'"),
        }
    }
}

/// Parses arguments (program name already removed).
fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command, ParseError> {
    let mut args = args.into_iter();
    let command = match args.next().as_deref() {
        None => return Err(ParseError::Missing),
        Some("help" | "-h" | "--help") => Command::Help,
        Some("version" | "-V" | "--version") => Command::Version,
        Some("info") => Command::Info,
        Some("doctor") => Command::Doctor,
        Some(other) => return Err(ParseError::Unknown(other.to_owned())),
    };
    match args.next() {
        Some(extra) => Err(ParseError::Unexpected(extra)),
        None => Ok(command),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Warn,
    /// Not checked because the capability does not exist yet.
    Skip,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

/// Builds the doctor report. `os` and `arch` are parameters so tests can
/// simulate other hosts deterministically.
fn doctor_checks(os: &str, arch: &str) -> Vec<Check> {
    let expect = |actual: &str, wanted: &str| {
        if actual == wanted {
            Status::Pass
        } else {
            Status::Warn
        }
    };
    vec![
        Check {
            name: "host OS",
            status: expect(os, "linux"),
            detail: format!("{os} (supported: linux)"),
        },
        Check {
            name: "host architecture",
            status: expect(arch, "x86_64"),
            detail: format!("{arch} (supported: x86_64)"),
        },
        Check {
            name: "development stage",
            status: Status::Pass,
            detail: STAGE.to_owned(),
        },
        Check {
            name: "QEMU boot",
            status: Status::Skip,
            detail: "not checked by doctor (read-only); run `cargo xtask run`".to_owned(),
        },
        Check {
            name: "AI inference",
            status: Status::Skip,
            detail: "not checked: no inference runtime exists yet".to_owned(),
        },
    ]
}

fn doctor_exit_code(checks: &[Check]) -> u8 {
    if checks.iter().any(|c| c.status == Status::Warn) {
        EXIT_FAILURE
    } else {
        EXIT_OK
    }
}

fn write_info(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{PROJECT} {VERSION}")?;
    writeln!(out, "Project of: {ORGANIZATION}")?;
    writeln!(out, "Stage:      {STAGE}")?;
    writeln!(out)?;
    writeln!(out, "Implementation status:")?;
    for (status, what) in COMPONENTS {
        let label = format!("[{status}]");
        writeln!(out, "  {label:<13} {what}")?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Pharos OS is not a usable or production-ready operating system yet."
    )
}

fn write_doctor(out: &mut dyn Write, checks: &[Check]) -> io::Result<()> {
    writeln!(out, "pharos doctor (read-only checks)")?;
    for check in checks {
        writeln!(
            out,
            "  [{}] {:<18} {}",
            check.status.label(),
            check.name,
            check.detail
        )?;
    }
    let warnings = checks.iter().filter(|c| c.status == Status::Warn).count();
    if warnings == 0 {
        writeln!(out, "Result: no problems found.")
    } else {
        writeln!(
            out,
            "Result: {warnings} warning(s); this host differs from the supported environment."
        )
    }
}

/// Runs the CLI and returns the process exit code.
fn run<I: IntoIterator<Item = String>>(
    args: I,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<u8> {
    match parse(args) {
        Ok(Command::Help) => {
            out.write_all(HELP.as_bytes())?;
            Ok(EXIT_OK)
        }
        Ok(Command::Version) => {
            writeln!(out, "pharos {VERSION}")?;
            Ok(EXIT_OK)
        }
        Ok(Command::Info) => {
            write_info(out)?;
            Ok(EXIT_OK)
        }
        Ok(Command::Doctor) => {
            // These are the compile-time target values, which equal the host
            // for native builds.
            let checks = doctor_checks(env::consts::OS, env::consts::ARCH);
            write_doctor(out, &checks)?;
            Ok(doctor_exit_code(&checks))
        }
        Err(error) => {
            writeln!(err, "error: {error}")?;
            writeln!(err, "Run 'pharos help' for usage.")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn main() -> ExitCode {
    // Lossy conversion: a non-UTF-8 argument becomes an unknown command
    // instead of a panic.
    let args = env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned());
    match run(args, &mut io::stdout().lock(), &mut io::stderr().lock()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: failed to write output: {error}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Runs the CLI in memory: (exit code, stdout, stderr).
    fn run_capture(list: &[&str]) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args(list), &mut out, &mut err).expect("writing to Vec cannot fail");
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn parses_commands_and_aliases() {
        for (input, expected) in [
            ("help", Command::Help),
            ("-h", Command::Help),
            ("--help", Command::Help),
            ("version", Command::Version),
            ("-V", Command::Version),
            ("--version", Command::Version),
            ("info", Command::Info),
            ("doctor", Command::Doctor),
        ] {
            assert_eq!(parse(args(&[input])), Ok(expected), "input: {input}");
        }
    }

    #[test]
    fn rejects_missing_unknown_and_extra_arguments() {
        assert_eq!(parse(args(&[])), Err(ParseError::Missing));
        assert_eq!(
            parse(args(&["boot"])),
            Err(ParseError::Unknown("boot".into()))
        );
        assert_eq!(
            parse(args(&["Info"])),
            Err(ParseError::Unknown("Info".into())),
            "commands are case-sensitive"
        );
        assert_eq!(
            parse(args(&["info", "--verbose"])),
            Err(ParseError::Unexpected("--verbose".into()))
        );
    }

    #[test]
    fn help_lists_every_command() {
        let (code, out, err) = run_capture(&["help"]);
        assert_eq!(code, EXIT_OK);
        assert!(err.is_empty());
        for cmd in ["help", "version", "info", "doctor"] {
            assert!(out.contains(cmd), "help is missing '{cmd}'");
        }
    }

    #[test]
    fn version_comes_from_cargo_metadata() {
        let (code, out, _) = run_capture(&["version"]);
        assert_eq!(code, EXIT_OK);
        assert_eq!(out, format!("pharos {}\n", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn info_reports_stage_and_honest_status() {
        let (code, out, _) = run_capture(&["info"]);
        assert_eq!(code, EXIT_OK);
        assert!(out.contains(PROJECT));
        assert!(out.contains(VERSION));
        assert!(out.contains(STAGE));
        assert!(out.contains("[implemented] minimal x86-64 kernel"));
        assert!(out.contains("[implemented] kernel tests inside QEMU"));
        assert!(out.contains("not a usable or production-ready"));
    }

    #[test]
    fn only_workspace_and_cli_are_labeled_implemented() {
        // Update this list only when a component exists and is tested. The
        // kernel is verified with `cargo xtask run` on UEFI and BIOS (M2.2);
        // exceptions and timer interrupts by test kernels in CI (M2.4); memory
        // management by test kernels in CI (M2.5); timer and scheduling by test
        // kernels in CI (M2.6); processes, system calls, and IPC by test
        // kernels in CI (M2.7); read-only storage by test kernels in CI (M2.8);
        // user-space drivers by test kernels in CI (M2.9); services and
        // networking by test kernels in CI (M2.10).
        let implemented: Vec<&str> = COMPONENTS
            .iter()
            .filter(|(status, _)| *status == "implemented")
            .map(|(_, what)| *what)
            .collect();
        assert_eq!(implemented.len(), 12);
        assert!(implemented.iter().all(|what| {
            what.contains("workspace")
                || what.contains("xtask")
                || what.contains("minimal")
                || what.contains("CI")
                || what.contains("kernel tests")
                || what.contains("exception")
                || what.contains("memory management")
                || what.contains("scheduling")
                || what.contains("system calls")
                || what.contains("storage")
                || what.contains("drivers")
                || what.contains("networking")
        }));
        for (status, _) in COMPONENTS {
            assert!(["implemented", "placeholder", "planned"].contains(status));
        }
    }

    #[test]
    fn usage_errors_go_to_stderr_with_exit_2() {
        for input in [&[][..], &["frobnicate"][..], &["help", "extra"][..]] {
            let (code, out, err) = run_capture(input);
            assert_eq!(code, EXIT_USAGE, "input: {input:?}");
            assert!(out.is_empty());
            assert!(err.starts_with("error: "));
            assert!(err.contains("pharos help"));
        }
    }

    #[test]
    fn doctor_passes_on_supported_host() {
        let checks = doctor_checks("linux", "x86_64");
        assert_eq!(doctor_exit_code(&checks), EXIT_OK);
    }

    #[test]
    fn doctor_warns_on_unsupported_host() {
        for (os, arch) in [("macos", "x86_64"), ("linux", "aarch64")] {
            let checks = doctor_checks(os, arch);
            assert_eq!(doctor_exit_code(&checks), EXIT_FAILURE, "{os}/{arch}");
        }
    }

    #[test]
    fn doctor_never_claims_unbuilt_capabilities() {
        let checks = doctor_checks("linux", "x86_64");
        for name in ["QEMU boot", "AI inference"] {
            let check = checks.iter().find(|c| c.name == name).unwrap();
            assert_eq!(check.status, Status::Skip, "{name}");
        }
        let mut out = Vec::new();
        write_doctor(&mut out, &checks).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("[SKIP] QEMU boot"));
        assert!(out.contains("no problems found"));
    }
}
