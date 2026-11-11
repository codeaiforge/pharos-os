//! `cargo xtask bench-ipc`: the IPC round trip under KVM against D-004's
//! 2 µs budget (#81). `cargo xtask bench-infer`: scenario S1 through the
//! inference service under KVM (#90). CI runs under emulation (TCG), where
//! timing means nothing, so these are local measurements.

use std::env;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::{
    KERNEL_PACKAGE, KERNEL_TARGET, MODEL_ENV, Paths, Result, STORE_IMAGE, TESTS_MARKER,
    boot_headless, build_user_programs, evaluate_boot, image, run, store_image, test_modules,
};

/// Round trips per boot, set at build time in the `ipc` test kernel.
const ROUND_TRIPS: u64 = 100_000;
const KVM: &str = "/dev/kvm";

/// The executable of test kernel `name` from Cargo's JSON messages.
fn executable(json: &str, name: &str) -> Option<PathBuf> {
    let deps = format!("/deps/{name}-");
    json.lines()
        .filter(|l| l.contains("\"reason\":\"compiler-artifact\""))
        .find_map(|l| {
            let at = l.find("\"executable\":\"")? + "\"executable\":\"".len();
            let path = &l[at..at + l[at..].find('"')?];
            path.contains(&deps).then(|| PathBuf::from(path))
        })
}

/// The nanoseconds in the kernel's `IPC round trip: <n> ns` line.
fn round_trip_ns(log: &str) -> Option<u64> {
    let rest = log.split("IPC round trip: ").nth(1)?;
    rest.split(' ').next()?.parse().ok()
}

pub fn kvm() -> Result<()> {
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
    Ok(())
}

/// Builds release test kernel `name` with environment variable `env` set.
fn release_kernel(paths: &Paths, name: &str, env: (&str, &str)) -> Result<PathBuf> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let json = run(
        Command::new(cargo)
            .current_dir(&paths.root)
            .env(env.0, env.1)
            .args(["test", "--locked", "--release", "--no-run"])
            .args(["--message-format=json", "--package", KERNEL_PACKAGE])
            .args(["--target", KERNEL_TARGET, "--test", name]),
        false,
    )?;
    executable(&String::from_utf8_lossy(&json), name).ok_or(format!(
        "cargo built no {name} test kernel (no executable in its output)"
    ))
}

pub fn ipc(paths: &Paths, runs: u32) -> Result<()> {
    kvm()?;
    let elf = release_kernel(
        paths,
        "ipc",
        ("PHAROS_IPC_ROUND_TRIPS", &ROUND_TRIPS.to_string()),
    )?;
    let out = paths.runner_dir("bench-ipc");
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let modules = test_modules(&build_user_programs(paths)?);
    let iso = image(paths, Some(elf), &modules, &out, Some(""))?;
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

/// S1's numbers from the client's line (microseconds and tokens).
#[derive(Debug, PartialEq)]
struct S1Run {
    load_us: u64,
    prompt_tokens: u64,
    prompt_us: u64,
    first_token_us: u64,
    generated: u64,
    generate_us: u64,
    peak_pages: u64,
}

impl S1Run {
    fn tokens_per_s(&self) -> f64 {
        self.generated as f64 * 1e6 / self.generate_us.max(1) as f64
    }
}

/// Parses `S1: load <a> us, prompt <n> tokens in <b> us, first token <c>
/// us, <m> tokens in <d> us` and `S1 peak: <p> pages`.
fn s1_run(log: &str) -> Option<S1Run> {
    let line = log.lines().find_map(|l| l.split("S1: load ").nth(1))?;
    let n: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|w| !w.is_empty())
        .map(|w| w.parse().ok())
        .collect::<Option<_>>()?;
    let peak = log
        .split("S1 peak: ")
        .nth(1)?
        .split(' ')
        .next()?
        .parse()
        .ok()?;
    match n[..] {
        [
            load_us,
            prompt_tokens,
            prompt_us,
            first_token_us,
            generated,
            generate_us,
        ] => Some(S1Run {
            load_us,
            prompt_tokens,
            prompt_us,
            first_token_us,
            generated,
            generate_us,
            peak_pages: peak,
        }),
        _ => None,
    }
}

/// S1's targets (phase3-requirements.md).
const S1_TOKENS_PER_S: f64 = 5.0;
const S1_FIRST_TOKEN_US: u64 = 10_000_000;

pub fn infer(paths: &Paths, runs: u32) -> Result<()> {
    kvm()?;
    let model = env::var_os(MODEL_ENV).map(PathBuf::from).ok_or(format!(
        "{MODEL_ENV} must name qwen2.5-0.5b-instruct-q8_0.gguf (inference-evaluation.md says where to get it)"
    ))?;
    let elf = release_kernel(paths, "inference", ("PHAROS_INFER_S1", "1"))?;
    let out = paths.runner_dir("bench-infer");
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let modules = test_modules(&build_user_programs(paths)?);
    let iso = image(paths, Some(elf), &modules, &out, Some(""))?;
    store_image::s1(&out.join(STORE_IMAGE), &model)?;
    let qemu = [
        "-enable-kvm".into(),
        "-cpu".into(),
        "host".into(),
        "-m".into(),
        "2G".into(),
    ];
    let timeout = Duration::from_secs(300);
    let mut results = Vec::new();
    for i in 1..=runs {
        let log = out.join(format!("run-{i}.log"));
        let boot = boot_headless(&iso, &out.join("ovmf-vars.fd"), &log, false, timeout, &qemu)?;
        evaluate_boot(&boot, TESTS_MARKER, timeout)
            .map_err(|e| format!("run {i}: {e} (log: {})", log.display()))?;
        let r =
            s1_run(&boot.log).ok_or(format!("run {i}: no S1 lines (log: {})", log.display()))?;
        println!(
            "  run {i}: load {:.2} s, prompt {} tokens in {:.2} s, first token {:.2} s, {} tokens at {:.1} tokens/s, service peak {} MiB mapped; text identical to the host's",
            r.load_us as f64 / 1e6,
            r.prompt_tokens,
            r.prompt_us as f64 / 1e6,
            r.first_token_us as f64 / 1e6,
            r.generated,
            r.tokens_per_s(),
            (r.peak_pages * 4096) >> 20,
        );
        results.push(r);
    }
    let median = |f: &dyn Fn(&S1Run) -> f64| {
        let mut v: Vec<f64> = results.iter().map(f).collect();
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    let first = median(&|r| r.first_token_us as f64);
    let cold = median(&|r| (r.load_us + r.first_token_us) as f64);
    let rate = median(&|r| r.tokens_per_s());
    let verdict = |ok: bool| if ok { "met" } else { "MISSED" };
    println!(
        "S1 on Pharos (KVM, median of {runs}): first token {:.2} s (target 10 s: {}), {rate:.1} tokens/s (target 5: {}); \
         the first request after boot also loads the model: {:.2} s + {:.2} s = {:.2} s",
        first / 1e6,
        verdict(first <= S1_FIRST_TOKEN_US as f64),
        verdict(rate >= S1_TOKENS_PER_S),
        median(&|r| r.load_us as f64) / 1e6,
        first / 1e6,
        cold / 1e6,
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
            executable(json, "ipc"),
            Some(PathBuf::from(
                "/w/target/x86_64-unknown-none/release/deps/ipc-0f3a"
            ))
        );
        assert_eq!(executable(r#"{"reason":"build-finished"}"#, "ipc"), None);
        assert_eq!(executable(json, "inference"), None);
        let log = "x\nIPC round trip: 1987 ns (100000 round trips in 198700 us; ...)\n";
        assert_eq!(round_trip_ns(log), Some(1987));
        assert_eq!(round_trip_ns("nothing"), None);
    }

    #[test]
    fn parses_the_s1_lines() {
        let log = "  9: S1: load 2500000 us, prompt 233 tokens in 8100000 us, first token 8300000 us, 128 tokens in 9000000 us\nS1 peak: 200000 pages mapped by the service\n";
        let r = s1_run(log).unwrap();
        assert_eq!(
            r,
            S1Run {
                load_us: 2_500_000,
                prompt_tokens: 233,
                prompt_us: 8_100_000,
                first_token_us: 8_300_000,
                generated: 128,
                generate_us: 9_000_000,
                peak_pages: 200_000,
            }
        );
        assert!((r.tokens_per_s() - 14.222).abs() < 0.01);
        assert_eq!(
            s1_run("  S1: load 1 us, prompt 2 tokens\nS1 peak: 3 pages"),
            None
        );
        assert_eq!(s1_run(&log.replace("S1 peak", "x")), None);
    }
}
