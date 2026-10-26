//! End-to-end tests: run the real `pharos` binary and check what a shell
//! sees (exit codes, stdout vs. stderr). Unit tests in `src/main.rs` cover
//! the logic; these cover `main()` and process behavior.

use std::process::{Command, Output};

fn pharos<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pharos"))
        .args(args)
        .output()
        .expect("failed to start the pharos binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn version_prints_cargo_version_and_exits_0() {
    let out = pharos(&["version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stdout(&out),
        format!("pharos {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(out.stderr.is_empty());
}

#[test]
fn help_and_info_exit_0_with_output_on_stdout() {
    for cmd in ["help", "info"] {
        let out = pharos(&[cmd]);
        assert_eq!(out.status.code(), Some(0), "{cmd}");
        assert!(!out.stdout.is_empty(), "{cmd}");
        assert!(out.stderr.is_empty(), "{cmd}");
    }
}

#[test]
fn doctor_exit_code_matches_host_support() {
    let out = pharos(&["doctor"]);
    let supported = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    assert_eq!(out.status.code(), Some(if supported { 0 } else { 1 }));
    assert!(stdout(&out).contains("[SKIP] QEMU boot"));
}

#[test]
fn usage_errors_exit_2_with_message_on_stderr() {
    for args in [&[][..], &["bogus"][..], &["help", "extra"][..]] {
        let out = pharos(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = stderr(&out);
        assert!(err.starts_with("error: "), "{args:?}: {err}");
        assert!(err.contains("pharos help"), "{args:?}: {err}");
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_a_usage_error_not_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let out = pharos(&[OsStr::from_bytes(b"\xff")]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown command"));
}
