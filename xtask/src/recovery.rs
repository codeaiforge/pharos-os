//! The `recovery` test kernel's boots (#163, boot.md section 8). The kernel
//! starts `init` with the boot table, as the main kernel does, and prints
//! the image the report names. Before its last boot, the runner boots it
//! on stores it prepares, each with signed slots and a slot record, and
//! checks `init`'s lines and the record it left:
//!
//! 1. slot A corrupt, slot B good: A refused, B runs;
//! 2. slot A signed with another key, slot B empty: A refused, the factory
//!    image runs;
//! 3. slot A never ready (its agent runtime exits at once): three boots on
//!    one store, the second killed right after the attempt was written;
//!    each counts an attempt and ends on the factory image, and after the
//!    third A is bad. The last boot (the runner's own) does not try A.
//!
//! Safe mode and recovery (#164), before round 3:
//!
//! 4. `next-safe`: the record asks for safe mode: slot A runs without the
//!    agent runtime, and `next` is cleared;
//! 5. `cmdline-recovery`, an image whose Limine entry says `recovery`:
//!    the factory image runs without the agent runtime; slot A, good, is
//!    not tried;
//! 6. `corrupt-root`, an image whose `root` module is corrupt: the kernel
//!    mounts the `recovery` copy, and `init` runs it in recovery mode;
//! 7. `broken-factory`, an image whose factory agent runtime exits at
//!    once: not ready, so `init` stops its services and starts again in
//!    recovery mode.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use pharos_image::slots::{Mode, Record, Slot, SlotInfo, State};

use crate::{
    ImageFile, Module, Paths, Result, STORE_IMAGE, clean_log, console, fs_image, image,
    prepare_firmware, qemu_args, qemu_command, qemu_error, sign, store_image,
};

pub const TEST: &str = "recovery";

/// A boot that takes longer has hung.
const BOOT_LIMIT: Duration = Duration::from_secs(180);

/// `image` with a signed header: version `version`, key from `seed`.
fn signed(image: &[u8], version: u64, seed: &[u8; 32]) -> Vec<u8> {
    let mut file = pharos_image::sign(image, version, seed).to_vec();
    file.extend_from_slice(image);
    file
}

/// What the record says of a slot file, before it was ever booted.
fn good(file: &[u8]) -> SlotInfo {
    SlotInfo {
        state: State::Good,
        attempts: 0,
        version: u64::from_le_bytes(file[16..24].try_into().unwrap_or_default()),
        sha256: file[32..64].try_into().unwrap_or_default(),
    }
}

/// A store whose record makes slot A active.
fn store(path: &Path, a: &[u8], b: Option<&[u8]>) -> Result<()> {
    store_next(path, a, b, Mode::Normal)
}

/// The same, with `next` for the next boot's mode.
fn store_next(path: &Path, a: &[u8], b: Option<&[u8]>, next: Mode) -> Result<()> {
    let record = Record {
        active: Some(Slot::A),
        next,
        slots: [good(a), b.map_or(SlotInfo::EMPTY, good)],
    }
    .encode();
    let mut files: Vec<(&[u8], &[u8])> = vec![(b"system/a", a), (b"system/state", &record)];
    if let Some(b) = b {
        files.push((b"system/b", b));
    }
    store_image::with_room(path, &files)
}

fn record(iso: &Path) -> Result<Record> {
    let bytes = store_image::read(&iso.with_file_name(STORE_IMAGE), b"system/state")?
        .ok_or("the store has no system/state")?;
    Record::decode(&bytes).ok_or_else(|| "system/state does not decode".into())
}

/// Boots once and returns the serial log; with `kill_at`, QEMU is killed
/// 200 ms after that text appears.
fn boot(
    iso: &Path,
    vars: &Path,
    logs: &Path,
    extra: &[OsString],
    round: &str,
    kill_at: Option<&str>,
) -> Result<String> {
    prepare_firmware(vars, false)?;
    console::fifos(iso.parent().unwrap_or(Path::new(".")))?;
    let log = logs.join(format!("test-{TEST}-{round}.log"));
    let _ = fs::remove_file(&log);
    let mut serial = OsString::from("file:");
    serial.push(&log);
    let mut args = qemu_args(iso, vars, &serial, false, false);
    args.extend_from_slice(extra);
    let mut child = qemu_command(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(qemu_error)?;
    let read = || String::from_utf8_lossy(&fs::read(&log).unwrap_or_default()).into_owned();
    let start = Instant::now();
    loop {
        if kill_at.is_some_and(|k| read().contains(k)) {
            std::thread::sleep(Duration::from_millis(200));
            break;
        }
        if child.try_wait().map_err(qemu_error)?.is_some() {
            break;
        }
        if start.elapsed() > BOOT_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{TEST} {round}: no end in {} s",
                BOOT_LIMIT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(clean_log(&read()))
}

/// Every one of `lines` is in `log`, else what is missing.
fn expect(round: &str, log: &str, lines: &[&str]) -> Result<()> {
    for line in lines {
        if !log.contains(line) {
            return Err(format!("{TEST} {round}: no line \"{line}\""));
        }
    }
    println!("  {round}: {}", lines.join("; "));
    Ok(())
}

fn expect_slot(round: &str, r: &Record, slot: Slot, state: State, attempts: u8) -> Result<()> {
    let s = r.slot(slot);
    if (s.state, s.attempts) != (state, attempts) {
        return Err(format!(
            "{TEST} {round}: slot {} is {:?} with {} attempts, expected {state:?} with {attempts}",
            slot.name(),
            s.state,
            s.attempts
        ));
    }
    Ok(())
}

/// An image of the test kernel `elf` with `modules` and a Limine entry
/// with `cmdline`, in its own directory next to `iso`'s.
fn other_image(
    paths: &Paths,
    elf: &Path,
    iso: &Path,
    round: &str,
    modules: &[Module],
    cmdline: &str,
) -> Result<std::path::PathBuf> {
    let out = iso.parent().unwrap_or(Path::new(".")).join(round);
    fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    image(paths, Some(elf.to_path_buf()), modules, &out, Some(cmdline))
}

/// Not one of `lines` is in `log`.
fn absent(round: &str, log: &str, lines: &[&str]) -> Result<()> {
    match lines.iter().find(|l| log.contains(*l)) {
        Some(line) => Err(format!("{TEST} {round}: unexpected line \"{line}\"")),
        None => Ok(()),
    }
}

/// The lines every boot outside normal mode has: the agent runtime is
/// not started, and the kernel reports that mode.
fn off(mode: &str) -> [String; 3] {
    [
        "init: agents not started: safe mode".into(),
        format!("recovery: {mode} mode"),
        "PHAROS: tests ok".into(),
    ]
}

/// The boots before the runner's last one.
#[allow(clippy::too_many_arguments)]
pub fn rounds(
    paths: &Paths,
    elf: &Path,
    programs: &[ImageFile],
    iso: &Path,
    vars: &Path,
    logs: &Path,
    extra: &[OsString],
) -> Result<()> {
    let seed = sign::test_seed(paths)?;
    let dir = paths.root.join("kernel").join("root");
    let root = fs_image::pack_with(&dir, programs)?;
    // The agent runtime replaced by `svc`, which exits at once in mode 0.
    let svc = programs
        .iter()
        .find(|(p, _)| p == "bin/svc")
        .ok_or("no bin/svc")?;
    let never_ready: Vec<ImageFile> = (programs.iter())
        .map(|(p, b)| match p.as_str() {
            "bin/agents" => (p.clone(), svc.1.clone()),
            _ => (p.clone(), b.clone()),
        })
        .collect();
    let never_ready = fs_image::pack_with(&dir, &never_ready)?;
    let store_path = iso.with_file_name(STORE_IMAGE);
    let tests_ok = "PHAROS: tests ok";

    // 1. A corrupt slot A: the other slot runs.
    let mut corrupt = signed(&root, 3, &seed);
    corrupt[pharos_image::HEADER_LEN + 600] ^= 1;
    store(&store_path, &corrupt, Some(&signed(&root, 2, &seed)))?;
    let log = boot(iso, vars, logs, extra, "corrupt", None)?;
    expect(
        "corrupt",
        &log,
        &[
            "init: system: slot A: attempt 1",
            "init: system: slot A refused: SHA-256 does not match",
            "init: system: slot B: attempt 1",
            "init: system: running slot B version 2",
            "recovery: running slot B",
            tests_ok,
        ],
    )?;
    let r = record(iso)?;
    expect_slot("corrupt", &r, Slot::A, State::Bad, 1)?;
    expect_slot("corrupt", &r, Slot::B, State::Good, 0)?;
    if r.active != Some(Slot::B) {
        return Err(format!("{TEST} corrupt: slot B is not active"));
    }

    // 2. Slot A signed with another key, and no slot B: the factory image.
    store(&store_path, &signed(&root, 5, &[7; 32]), None)?;
    let log = boot(iso, vars, logs, extra, "unsigned", None)?;
    expect(
        "unsigned",
        &log,
        &[
            "init: system: slot A refused: bad signature",
            "init: system: running factory image",
            "recovery: running the factory image",
            tests_ok,
        ],
    )?;
    expect_slot("unsigned", &record(iso)?, Slot::A, State::Bad, 1)?;

    // 4. Safe mode from the record's `next`: slot A without the runtime.
    let slot_a = signed(&root, 6, &seed);
    store_next(&store_path, &slot_a, None, Mode::Safe)?;
    let log = boot(iso, vars, logs, extra, "next-safe", None)?;
    let [a, b, c] = off("safe");
    expect(
        "next-safe",
        &log,
        &[
            "init: system: safe mode (from the slot record, now cleared)",
            "init: system: running slot A version 6",
            "recovery: running slot A",
            &a,
            &b,
            &c,
        ],
    )?;
    absent("next-safe", &log, &["init: agents started"])?;
    let r = record(iso)?;
    expect_slot("next-safe", &r, Slot::A, State::Good, 0)?;
    if r.next != Mode::Normal {
        return Err(format!(
            "{TEST} next-safe: next is {:?}, not cleared",
            r.next
        ));
    }

    // 5. Recovery from the Limine entry: the slots are not used.
    let modules = crate::kernel_modules(paths, programs)?;
    let other = other_image(paths, elf, iso, "cmdline-recovery", &modules, "recovery")?;
    store(&other.with_file_name(STORE_IMAGE), &slot_a, None)?;
    let other_vars = other.with_file_name("ovmf-vars.fd");
    let log = boot(&other, &other_vars, logs, extra, "cmdline-recovery", None)?;
    let [a, b, c] = off("recovery");
    expect(
        "cmdline-recovery",
        &log,
        &[
            "init: system: recovery mode (from the kernel)",
            "init: system: running factory image",
            "recovery: running the factory image",
            &a,
            &b,
            &c,
        ],
    )?;
    absent(
        "cmdline-recovery",
        &log,
        &["init: system: slot A: attempt", "init: agents started"],
    )?;
    expect_slot(
        "cmdline-recovery",
        &record(&other)?,
        Slot::A,
        State::Good,
        0,
    )?;

    // 6. A corrupt `root` module: the kernel mounts its copy.
    let mut bad_root = modules.clone();
    let first = bad_root.first_mut().ok_or("no root module")?;
    first.1[0] ^= 0xff;
    let other = other_image(paths, elf, iso, "corrupt-root", &bad_root, "")?;
    let other_vars = other.with_file_name("ovmf-vars.fd");
    let log = boot(&other, &other_vars, logs, extra, "corrupt-root", None)?;
    expect(
        "corrupt-root",
        &log,
        &[
            "; recovery copy mounted",
            "init: system: recovery mode (root failed its checks; the recovery copy runs)",
            "init: system: running recovery copy",
            "recovery: running the recovery copy",
            &a,
            &b,
            &c,
        ],
    )?;

    // 7. A factory image that is not ready: recovery mode, in place.
    let broken = [
        ("root", never_ready.clone()),
        ("recovery", never_ready.clone()),
    ];
    let other = other_image(paths, elf, iso, "broken-factory", &broken, "")?;
    let other_vars = other.with_file_name("ovmf-vars.fd");
    let log = boot(&other, &other_vars, logs, extra, "broken-factory", None)?;
    expect(
        "broken-factory",
        &log,
        &[
            "init: agents started",
            "init: system: factory image not ready; its services stopped; recovery mode",
            "init: system: running factory image",
            "recovery: running the factory image",
            &a,
            &b,
            &c,
        ],
    )?;

    // 3. Slot A never ready: one attempt per boot, the second boot killed
    //    once its attempt is written.
    store(&store_path, &signed(&never_ready, 4, &seed), None)?;
    for (n, kill) in [(1, false), (2, true), (3, false)] {
        let round = format!("never-ready-{n}");
        let attempt = format!("init: system: slot A: attempt {n}");
        let log = boot(
            iso,
            vars,
            logs,
            extra,
            &round,
            kill.then_some(attempt.as_str()),
        )?;
        if kill {
            expect(&round, &log, &[&attempt])?;
            println!("  {round}: killed after the attempt was written");
        } else {
            expect(
                &round,
                &log,
                &[
                    &attempt,
                    "init: system: slot A version 4 not ready within 20 s; its services stopped",
                    "init: system: running factory image",
                    "recovery: running the factory image",
                    tests_ok,
                ],
            )?;
        }
        // The third attempt used up A's: it is bad at once.
        let used_up = "init: system: slot A: attempts used up; bad";
        let (state, said) = match n {
            3 => (State::Bad, true),
            _ => (State::Trying, false),
        };
        if log.contains(used_up) != said {
            return Err(format!("{TEST} {round}: \"{used_up}\" expected: {said}"));
        }
        expect_slot(&round, &record(iso)?, Slot::A, state, n)?;
    }
    Ok(())
}

/// After the runner's own boot, the fourth on the never-ready slot: it is
/// bad, so it is not tried, and the record stays as it was.
pub fn last(iso: &Path, log: &str) -> Result<()> {
    expect(
        "never-ready-4",
        log,
        &[
            "init: system: running factory image",
            "recovery: running the factory image",
        ],
    )?;
    if log.contains("init: system: slot A: attempt") {
        return Err(format!("{TEST} never-ready-4: the bad slot A was tried"));
    }
    expect_slot("never-ready-4", &record(iso)?, Slot::A, State::Bad, 3)
}
