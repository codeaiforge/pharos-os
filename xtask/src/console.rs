//! The trusted path's host side (D-018, agents.md): QEMU attaches the
//! guest's virtio-console to two FIFOs next to the boot image, `trust.in`
//! (what the user types) and `trust.out` (what the trusted service says).
//! `cargo xtask run` leaves them for the user; the `trust` test kernel's
//! runner plays the user from a [`Script`]. A script may also drive QEMU's
//! monitor (QMP) through a second pair, `qmp.in` and `qmp.out` (#171).

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
/// The QMP pair's name.
pub const QMP: &str = "qmp";
/// A step's `send` with this prefix goes to QMP, not the console.
pub const QMP_PREFIX: &str = "qmp:";
/// A step's `expect` with this prefix matches only after the previous
/// step's match, so a line seen before can be waited for again.
pub const AFTER: &str = ">";

/// Makes `trust.in` and `trust.out` FIFOs in `dir` (replacing anything
/// else by those names); returns `dir/trust`.
pub fn fifos(dir: &Path) -> Result<PathBuf, String> {
    fifos_named(dir, PIPE)
}

/// [`fifos`] named `name`.
pub fn fifos_named(dir: &Path, name: &str) -> Result<PathBuf, String> {
    let base = dir.join(name);
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
/// order; each looks at all output so far, or, with [`AFTER`], at the
/// output after the previous step's match.
pub type Step = (&'static str, &'static str);

/// How far `steps` get on `output`, from step `done` whose match ended at
/// byte `from`: the index of the first step still waiting, where the last
/// match ended, and what to type for the steps it passed.
pub fn advance(
    steps: &[Step],
    mut done: usize,
    mut from: usize,
    output: &str,
) -> (usize, usize, Vec<&'static str>) {
    let mut typed = Vec::new();
    while let Some(&(expect, send)) = steps.get(done) {
        let found = match expect.strip_prefix(AFTER) {
            Some(text) => output
                .get(from..)
                .and_then(|o| o.find(text))
                .map(|at| from + at + text.len()),
            None => output.find(expect).map(|at| at + expect.len()),
        };
        let Some(end) = found else { break };
        from = from.max(end);
        if !send.is_empty() {
            typed.push(send);
        }
        done += 1;
    }
    (done, from, typed)
}

/// A script playing the user on the trusted console, in a thread. The
/// FIFOs are opened read-write, which on Linux never waits for QEMU; the
/// thread ends with the runner's process.
/// Steps reached, where the last match ended, the output so far, and when
/// each step was reached.
type State = (usize, usize, String, Vec<Instant>);

pub struct Script {
    state: Arc<Mutex<State>>,
    steps: &'static [Step],
}

fn open_pair(base: &Path) -> Result<(std::fs::File, std::fs::File), String> {
    let open = |end: &str| {
        let path = base.with_extension(end);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))
    };
    Ok((open("in")?, open("out")?))
}

/// Reads a file as it grows, waiting for it to appear (the serial log,
/// which QEMU writes). Never ends.
struct Tail {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl Read for Tail {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.file.is_none() {
                self.file = std::fs::File::open(&self.path).ok();
            }
            if let Some(n) = self.file.as_mut().map(|f| f.read(buf)).transpose()? {
                if n > 0 {
                    return Ok(n);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Script {
    /// Plays `steps` on the console FIFOs at `base`, and QMP's at `qmp`
    /// if given: QMP's output joins the transcript as `qmp: ` text, and a
    /// [`QMP_PREFIX`] line is written to QMP. With `serial` (a log that
    /// must not exist yet), the kernel's serial output joins it as
    /// `serial: ` text, so a step can wait for the kernel.
    pub fn start(
        base: &Path,
        qmp: Option<&Path>,
        serial: Option<&Path>,
        steps: &'static [Step],
    ) -> Result<Self, String> {
        let (input, output) = open_pair(base)?;
        let qmp = qmp.map(open_pair).transpose()?;
        let state = Arc::new(Mutex::new((0, 0, String::new(), Vec::new())));
        let inputs = Arc::new(Mutex::new((input, qmp.as_ref().map(|q| q.0.try_clone()))));
        let reader = |mut from: Box<dyn Read + Send>, tag: &'static str| {
            let (shared, inputs) = (Arc::clone(&state), Arc::clone(&inputs));
            std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                // Whole lines only, so the two readers never split one.
                let mut pending = String::new();
                while let Ok(n) = from.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                    let Some(last) = pending.rfind('\n') else {
                        continue;
                    };
                    let lines: String = pending.drain(..=last).collect();
                    let Ok(mut s) = shared.lock() else { break };
                    for line in lines.split_inclusive('\n') {
                        s.2.push_str(tag);
                        s.2.push_str(line);
                    }
                    let (done, at, typed) = advance(steps, s.0, s.1, &s.2);
                    let now = Instant::now();
                    s.3.resize(done, now);
                    (s.0, s.1) = (done, at);
                    drop(s);
                    let Ok(mut io) = inputs.lock() else { break };
                    for line in typed {
                        let written = match line.strip_prefix(QMP_PREFIX) {
                            Some(cmd) => match &mut io.1 {
                                Some(Ok(q)) => q.write_all(cmd.as_bytes()),
                                _ => return,
                            },
                            None => io.0.write_all(line.as_bytes()),
                        };
                        if written.is_err() {
                            return;
                        }
                    }
                }
            });
        };
        reader(Box::new(output), "");
        if let Some((_, out)) = qmp {
            reader(Box::new(out), "qmp: ");
        }
        if let Some(path) = serial {
            let tail = Tail {
                path: path.to_path_buf(),
                file: None,
            };
            reader(Box::new(tail), "serial: ");
        }
        Ok(Self { state, steps })
    }

    /// How long step `step + 1` took to be reached after step `step`, so
    /// after what `step` typed (#120); `None` if either was not reached.
    pub fn took(&self, step: usize) -> Option<Duration> {
        let s = self.state.lock().ok()?;
        Some(s.3.get(step + 1)?.duration_since(*s.3.get(step)?))
    }

    /// `Ok(output)` if every step was reached and nothing in `refused`
    /// appeared; else what went wrong, with the output.
    pub fn finish(&self, refused: &[&str]) -> Result<String, String> {
        let (done, output) = self
            .state
            .lock()
            .map(|s| (s.0, s.2.clone()))
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
        let typed = |r: (usize, usize, Vec<&'static str>)| (r.0, r.2);
        assert_eq!(typed(advance(STEPS, 0, 0, "")), (0, vec![]));
        assert_eq!(typed(advance(STEPS, 0, 0, "ready")), (1, vec![]));
        assert_eq!(
            typed(advance(STEPS, 0, 0, "ready, worker")),
            (2, vec!["list\n"]),
            "two steps at once"
        );
        assert_eq!(
            typed(advance(STEPS, 0, 0, "running worker")),
            (0, vec![]),
            "a later step's text does not pass an earlier one"
        );
        assert_eq!(
            typed(advance(STEPS, 2, 0, "x running")),
            (3, vec!["stop\n"])
        );
        assert_eq!(typed(advance(STEPS, 3, 0, "anything")), (3, vec![]));
    }

    #[test]
    fn after_steps_wait_for_new_text() {
        const AGAIN: &[Step] = &[("added", "del\n"), ("removed", "add\n"), (">added", "ok\n")];
        let (done, at, typed) = advance(AGAIN, 0, 0, "added removed");
        assert_eq!((done, at, typed), (2, 13, vec!["del\n", "add\n"]));
        assert_eq!(
            advance(AGAIN, 2, at, "added removed").0,
            2,
            "the first added does not count"
        );
        assert_eq!(advance(AGAIN, 2, at, "added removed added").2, vec!["ok\n"]);
        assert_eq!(advance(AGAIN, 2, 99, "short").0, 2, "past the end");
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
