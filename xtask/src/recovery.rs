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

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use pharos_image::slots::{Record, Slot, SlotInfo, State};

use crate::{
    ImageFile, Paths, Result, STORE_IMAGE, clean_log, console, fs_image, prepare_firmware,
    qemu_args, qemu_command, qemu_error, sign, store_image,
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
    let record = Record {
        active: Some(Slot::A),
        slots: [good(a), b.map_or(SlotInfo::EMPTY, good)],
        ..Record::EMPTY
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

/// The boots before the runner's last one.
pub fn rounds(
    paths: &Paths,
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
