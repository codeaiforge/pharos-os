//! The trusted path's host side (D-018, agents.md): QEMU attaches the
//! guest's virtio-console to two FIFOs next to the boot image, `trust.in`
//! (what the user types) and `trust.out` (what the trusted service says).
//! `cargo xtask run` leaves them for the user; the `trust` test kernel's
//! runner plays the user from a [`Script`].

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The FIFOs' common name: QEMU's `pipe` character device opens
/// `<path>.in` and `<path>.out`.
pub const PIPE: &str = "trust";

/// Makes `trust.in` and `trust.out` FIFOs in `dir` (replacing anything
/// else by those names); returns `dir/trust`.
pub fn fifos(dir: &Path) -> Result<PathBuf, String> {
    let base = dir.join(PIPE);
    for end in ["in", "out"] {
        let path = base.with_extension(end);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_fifo() => continue,
            Ok(_) => fs::remove_file(&path)
                .map_err(|e| format!("cannot replace {}: {e}", path.display()))?,
            Err(_) => {}
        }
        let made = Command::new("mkfifo").arg(&path).status().map_err(|e| {
            format!("cannot run mkfifo for the trusted console ({e}); it comes with coreutils")
        })?;
        if !made.success() {
            return Err(format!("mkfifo {} failed", path.display()));
        }
    }
    Ok(base)
}

/// What to wait for and what to type then: once the console output
/// contains `expect`, the runner writes `send` (if not empty). Steps run in
/// order; each looks at all output so far.
pub type Step = (&'static str, &'static str);

/// How far `steps` get on `output`, from step `done`: the index of the
/// first step still waiting, and what to type for the steps it passed.
pub fn advance(steps: &[Step], mut done: usize, output: &str) -> (usize, Vec<&'static str>) {
    let mut typed = Vec::new();
    while let Some(&(expect, send)) = steps.get(done) {
        if !output.contains(expect) {
            break;
        }
        if !send.is_empty() {
            typed.push(send);
        }
        done += 1;
    }
    (done, typed)
}

/// A script playing the user on the trusted console, in a thread. The
/// FIFOs are opened read-write, which on Linux never waits for QEMU; the
/// thread ends with the runner's process.
pub struct Script {
    /// Steps reached, the output so far, and when each step was reached.
    state: Arc<Mutex<(usize, String, Vec<Instant>)>>,
    steps: &'static [Step],
}

impl Script {
    pub fn start(base: &Path, steps: &'static [Step]) -> Result<Self, String> {
        let open = |end: &str| {
            let path = base.with_extension(end);
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| format!("cannot open {}: {e}", path.display()))
        };
        let (mut input, mut output) = (open("in")?, open("out")?);
        let state = Arc::new(Mutex::new((0, String::new(), Vec::new())));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok(n) = output.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let Ok(mut s) = shared.lock() else { break };
                s.1.push_str(&String::from_utf8_lossy(&buf[..n]));
                let (done, typed) = advance(steps, s.0, &s.1);
                let now = Instant::now();
                s.2.resize(done, now);
                s.0 = done;
                drop(s);
                for line in typed {
                    if input.write_all(line.as_bytes()).is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Self { state, steps })
    }

    /// How long step `step + 1` took to be reached after step `step`, so
    /// after what `step` typed (#120); `None` if either was not reached.
    pub fn took(&self, step: usize) -> Option<Duration> {
        let s = self.state.lock().ok()?;
        Some(s.2.get(step + 1)?.duration_since(*s.2.get(step)?))
    }

    /// `Ok(output)` if every step was reached and nothing in `refused`
    /// appeared; else what went wrong, with the output.
    pub fn finish(&self, refused: &[&str]) -> Result<String, String> {
        let (done, output) = self
            .state
            .lock()
            .map(|s| (s.0, s.1.clone()))
            .unwrap_or_default();
        if let Some((expect, _)) = self.steps.get(done) {
            return Err(format!(
                "the trusted console never said {expect:?}; it said:\n{output}"
            ));
        }
        if let Some(word) = refused.iter().find(|w| output.contains(*w)) {
            return Err(format!(
                "the trusted console said {word:?}, which it must not; it said:\n{output}"
            ));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEPS: &[Step] = &[("ready", ""), ("worker", "list\n"), ("running", "stop\n")];

    #[test]
    fn steps_advance_in_order() {
        assert_eq!(advance(STEPS, 0, ""), (0, vec![]));
        assert_eq!(advance(STEPS, 0, "ready"), (1, vec![]));
        assert_eq!(
            advance(STEPS, 0, "ready, worker"),
            (2, vec!["list\n"]),
            "two steps at once"
        );
        assert_eq!(
            advance(STEPS, 0, "running worker"),
            (0, vec![]),
            "a later step's text does not pass an earlier one"
        );
        assert_eq!(advance(STEPS, 2, "x running"), (3, vec!["stop\n"]));
        assert_eq!(advance(STEPS, 3, "anything"), (3, vec![]));
    }

    #[test]
    fn fifos_are_made_and_kept() {
        let dir = std::env::temp_dir().join(format!("pharos-fifo-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("trust.in"), b"stale").unwrap();
        let base = fifos(&dir).unwrap();
        for end in ["in", "out"] {
            let m = fs::symlink_metadata(base.with_extension(end)).unwrap();
            assert!(m.file_type().is_fifo(), "{end}");
        }
        assert_eq!(fifos(&dir).unwrap(), base, "a second call keeps them");
        fs::remove_dir_all(&dir).unwrap();
    }
}
