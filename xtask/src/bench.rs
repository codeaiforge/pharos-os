//! `cargo xtask bench-ipc`: the IPC round trip under KVM against D-004's
//! 2 µs budget (#81). CI runs under emulation (TCG), where timing means
//! nothing, so this is a local measurement.

use std::env;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::{
    KERNEL_PACKAGE, KERNEL_TARGET, Paths, Result, TESTS_MARKER, boot_headless, build_user_programs,
    evaluate_boot, image, run, test_modules,
};

/// Round trips per boot, set at build time in the `ipc` test kernel.
const ROUND_TRIPS: u64 = 100_000;
const KVM: &str = "/dev/kvm";

/// The test kernel's executable from Cargo's JSON messages.
fn executable(json: &str) -> Option<PathBuf> {
    json.lines()
        .filter(|l| l.contains("\"reason\":\"compiler-artifact\""))
        .find_map(|l| {
            let at = l.find("\"executable\":\"")? + "\"executable\":\"".len();
            let path = &l[at..at + l[at..].find('"')?];
            path.contains("/deps/ipc-").then(|| PathBuf::from(path))
        })
}

/// The nanoseconds in the kernel's `IPC round trip: <n> ns` line.
fn round_trip_ns(log: &str) -> Option<u64> {
    let rest = log.split("IPC round trip: ").nth(1)?;
    rest.split(' ').next()?.parse().ok()
}

pub fn ipc(paths: &Paths, runs: u32) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(KVM)
        .map_err(|e| {
            format!(
                "KVM is not available ({KVM}: {e}); the budget is defined under KVM. \
                 Enable virtualization in the firmware, load the kvm module, and add \
                 your user to the kvm group"
            )
        })?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let json = run(
        Command::new(cargo)
            .current_dir(&paths.root)
            .env("PHAROS_IPC_ROUND_TRIPS", ROUND_TRIPS.to_string())
            .args(["test", "--locked", "--release", "--no-run"])
            .args(["--message-format=json", "--package", KERNEL_PACKAGE])
            .args(["--target", KERNEL_TARGET, "--test", "ipc"]),
        false,
    )?;
    let elf = executable(&String::from_utf8_lossy(&json))
        .ok_or("cargo built no ipc test kernel (no executable in its output)")?;
    let out = paths.runner_dir("bench-ipc");
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let modules = test_modules(&build_user_programs(paths)?);
    let iso = image(paths, Some(elf), &modules, &out)?;
    let kvm = ["-enable-kvm".into(), "-cpu".into(), "host".into()];
    let timeout = Duration::from_secs(60);
    let mut times = Vec::new();
    for i in 1..=runs {
        let log = out.join(format!("run-{i}.log"));
        let boot = boot_headless(&iso, &out.join("ovmf-vars.fd"), &log, false, timeout, &kvm)?;
        evaluate_boot(&boot, TESTS_MARKER, timeout)
            .map_err(|e| format!("run {i}: {e} (log: {})", log.display()))?;
        let ns = round_trip_ns(&boot.log).ok_or(format!(
            "run {i}: no round-trip line (log: {})",
            log.display()
        ))?;
        println!("  run {i}: {ns} ns per round trip ({ROUND_TRIPS} round trips, KVM)");
        times.push(ns);
    }
    times.sort_unstable();
    let median = times[times.len() / 2];
    let verdict = if median <= 2000 { "within" } else { "over" };
    println!(
        "IPC round trip: median {median} ns, min {} ns, max {} ns; {verdict} D-004's 2000 ns budget",
        times[0],
        times[times.len() - 1]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_executable_and_the_time() {
        let json = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"pharos_kernel"},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","executable":"/w/target/x86_64-unknown-none/release/deps/ipc-0f3a"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        assert_eq!(
            executable(json),
            Some(PathBuf::from(
                "/w/target/x86_64-unknown-none/release/deps/ipc-0f3a"
            ))
        );
        assert_eq!(executable(r#"{"reason":"build-finished"}"#), None);
        let log = "x\nIPC round trip: 1987 ns (100000 round trips in 198700 us; ...)\n";
        assert_eq!(round_trip_ns(log), Some(1987));
        assert_eq!(round_trip_ns("nothing"), None);
    }
}
