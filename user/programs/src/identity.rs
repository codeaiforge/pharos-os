//! People and console sessions for `trust` (identity.md, D-038, #310):
//! person records on the store's `identity` namespace through [`Files`],
//! passphrase checks, and the session state (who is logged in, the
//! refusal delay, the idle timeout). Host-tested; `trust` wires it to the
//! console and the store.

use alloc::vec::Vec;

use pharos_proto::identity::{self, MAX_FILE, MAX_PEOPLE, PEOPLE, Person};
use pharos_proto::trust::{Command, MAX_NAME};

use crate::tasks::{Files, StoreFailed};

/// A session ends after this long without a typed line (identity.md).
pub const IDLE_US: u64 = 15 * 60 * 1_000_000;
/// A refused login delays the next by 1 s, doubling to at most 60 s.
pub const FIRST_WAIT_US: u64 = 1_000_000;
pub const MAX_WAIT_US: u64 = 60_000_000;

fn path(name: &[u8]) -> Vec<u8> {
    [PEOPLE, name].concat()
}

/// Person `name`'s record; `None` if there is none or it does not parse
/// (a record that does not parse is no one: it cannot be logged in as).
pub fn read(f: &mut impl Files, name: &[u8]) -> Result<Option<Person>, StoreFailed> {
    Ok(f.read(&path(name))?
        .and_then(|b| identity::parse(&b).ok())
        .filter(|p| p.name() == name))
}

/// Every person's name, sorted.
pub fn names(f: &mut impl Files) -> Result<Vec<Vec<u8>>, StoreFailed> {
    let mut names: Vec<Vec<u8>> = f
        .list(PEOPLE)?
        .into_iter()
        .filter_map(|p| p.strip_prefix(PEOPLE).map(<[u8]>::to_vec))
        .collect();
    names.sort();
    Ok(names)
}

/// Writes `p`'s record, replacing any.
pub fn write(f: &mut impl Files, p: &Person) -> Result<(), StoreFailed> {
    let mut out = [0u8; MAX_FILE];
    let n = p.encode(&mut out).ok_or(StoreFailed)?;
    f.write(&path(p.name()), &out[..n])
}

/// What `add` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Done,
    Exists,
    Full,
}

/// Adds `p` if no one has its name and there is room.
pub fn add(f: &mut impl Files, p: &Person) -> Result<Added, StoreFailed> {
    let names = names(f)?;
    if names.iter().any(|n| n == p.name()) {
        return Ok(Added::Exists);
    }
    if names.len() >= MAX_PEOPLE {
        return Ok(Added::Full);
    }
    write(f, p)?;
    Ok(Added::Done)
}

/// What `remove` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removed {
    Done,
    NotFound,
    /// The last person: the console would have no one to log in as.
    Last,
}

pub fn remove(f: &mut impl Files, name: &[u8]) -> Result<Removed, StoreFailed> {
    let names = names(f)?;
    if !names.iter().any(|n| n == name) {
        return Ok(Removed::NotFound);
    }
    if names.len() == 1 {
        return Ok(Removed::Last);
    }
    f.delete(&path(name))?;
    Ok(Removed::Done)
}

/// The record's hash for `passphrase`.
pub fn hash(passphrase: &[u8], salt: &[u8; 32], iterations: u32) -> [u8; 32] {
    pharos_crypto::pbkdf2(passphrase, salt, iterations)
}

/// Whether `passphrase` is `p`'s, compared in constant time.
pub fn matches(p: &Person, passphrase: &[u8]) -> bool {
    pharos_crypto::equal(&hash(passphrase, &p.salt, p.iterations), &p.hash)
}

/// A salt: unique, not secret (identity.md): SHA-256 over the name, the
/// wall clock, the uptime, and RDSEED where the CPU has it.
pub fn salt(name: &[u8], clock: u64, uptime: u64, rdseed: Option<u64>) -> [u8; 32] {
    pharos_crypto::sha256(&[
        b"pharos person salt",
        name,
        &clock.to_le_bytes(),
        &uptime.to_le_bytes(),
        &rdseed.unwrap_or(0).to_le_bytes(),
        &[u8::from(rdseed.is_some())],
    ])
}

/// What the console may do with no one logged in: log in, help, and every
/// stop (the emergency stop, an agent, a group, a service), which only
/// take away, never grant: with memory used up a restarted `trust` cannot
/// read the identity store, and a runaway must still be stoppable (#310,
/// the maintainer's choice of 2026-11-26).
pub fn allowed_logged_out(c: &Command<'_>) -> bool {
    use pharos_proto::service::Action;
    matches!(
        c,
        Command::Login(_)
            | Command::StopAll
            | Command::Stop(_)
            | Command::StopGroup(_)
            | Command::Manage(Action::Stop, _)
            | Command::Help
    )
}

/// Who is logged in at the trusted console, and the refusal delay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    name: [u8; MAX_NAME],
    len: usize,
    last: u64,
    failures: u32,
    wait_until: u64,
}

impl Session {
    pub fn person(&self) -> Option<&[u8]> {
        (self.len > 0).then(|| &self.name[..self.len])
    }

    /// How long until a login may be tried, in microseconds; 0 for now.
    pub fn wait(&self, now: u64) -> u64 {
        self.wait_until.saturating_sub(now)
    }

    /// A refused login: the next waits 1 s, doubling to 60 s.
    pub fn refused(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        let wait = FIRST_WAIT_US
            .checked_shl(self.failures - 1)
            .unwrap_or(MAX_WAIT_US)
            .min(MAX_WAIT_US);
        self.wait_until = now.saturating_add(wait);
    }

    /// `name` logged in: the delay is reset.
    pub fn start(&mut self, name: &[u8], now: u64) {
        let n = name.len().min(MAX_NAME);
        self.name = [0; MAX_NAME];
        self.name[..n].copy_from_slice(&name[..n]);
        self.len = n;
        self.last = now;
        self.failures = 0;
        self.wait_until = 0;
    }

    pub fn end(&mut self) {
        self.len = 0;
    }

    /// A typed line: the session is active.
    pub fn touch(&mut self, now: u64) {
        self.last = now;
    }

    /// Whether the session has run out (no line for [`IDLE_US`]).
    pub fn idle(&self, now: u64) -> bool {
        self.len > 0 && now.saturating_sub(self.last) >= IDLE_US
    }

    /// When the session runs out, if someone is logged in.
    pub fn idle_at(&self) -> Option<u64> {
        (self.len > 0).then(|| self.last.saturating_add(IDLE_US))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Mem(BTreeMap<Vec<u8>, Vec<u8>>);

    impl Files for Mem {
        fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
            self.0.insert(path.to_vec(), bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
            Ok(self.0.get(path).cloned())
        }
        fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed> {
            self.0.remove(path);
            Ok(())
        }
        fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
            Ok(self
                .0
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    fn person(name: &[u8], pass: &[u8]) -> Person {
        let salt = salt(name, 1, 2, None);
        Person::new(name, b"ops", salt, 10, hash(pass, &salt, 10)).unwrap()
    }

    #[test]
    fn people_are_added_read_and_removed_but_never_the_last() {
        let mut f = Mem::default();
        let alice = person(b"alice", b"alice's passphrase");
        assert_eq!(add(&mut f, &alice), Ok(Added::Done));
        assert_eq!(add(&mut f, &alice), Ok(Added::Exists));
        assert_eq!(read(&mut f, b"alice"), Ok(Some(alice)));
        assert_eq!(read(&mut f, b"bob"), Ok(None));
        assert_eq!(remove(&mut f, b"alice"), Ok(Removed::Last));
        assert_eq!(remove(&mut f, b"bob"), Ok(Removed::NotFound));
        assert_eq!(
            add(&mut f, &person(b"bob", b"bob's passphrase")),
            Ok(Added::Done)
        );
        assert_eq!(
            names(&mut f),
            Ok(std::vec![b"alice".to_vec(), b"bob".to_vec()])
        );
        assert_eq!(remove(&mut f, b"alice"), Ok(Removed::Done));
        assert_eq!(read(&mut f, b"alice"), Ok(None));
        // A record under another name, or one that does not parse, is no one.
        f.0.insert(b"people/carol".to_vec(), std::vec![b'x'; 8]);
        assert_eq!(read(&mut f, b"carol"), Ok(None));
        let mut out = [0u8; MAX_FILE];
        let n = person(b"dave", b"dave's passphrase")
            .encode(&mut out)
            .unwrap();
        f.0.insert(b"people/eve".to_vec(), out[..n].to_vec());
        assert_eq!(read(&mut f, b"eve"), Ok(None));
    }

    #[test]
    fn the_people_list_has_a_limit() {
        let mut f = Mem::default();
        for i in 0..MAX_PEOPLE {
            let name = std::format!("p{i}");
            assert_eq!(
                add(&mut f, &person(name.as_bytes(), b"a passphrase")),
                Ok(Added::Done)
            );
        }
        assert_eq!(
            add(&mut f, &person(b"one-more", b"a passphrase")),
            Ok(Added::Full)
        );
    }

    #[test]
    fn only_the_passphrase_matches() {
        let alice = person(b"alice", b"alice's passphrase");
        assert!(matches(&alice, b"alice's passphrase"));
        assert!(!matches(&alice, b"alice's passphrasf"));
        assert!(!matches(&alice, b""));
        // Another salt or count gives another hash.
        assert_ne!(hash(b"p", &[0; 32], 10), hash(b"p", &[1; 32], 10));
        assert_ne!(hash(b"p", &[0; 32], 10), hash(b"p", &[0; 32], 11));
        assert_ne!(salt(b"a", 1, 2, None), salt(b"a", 1, 2, Some(0)));
        assert_ne!(salt(b"a", 1, 2, None), salt(b"b", 1, 2, None));
    }

    #[test]
    fn logged_out_the_console_logs_in_stops_and_helps() {
        use pharos_proto::trust::command;
        for line in [
            &b"login alice"[..],
            b"stop all",
            b"stop worker",
            b"stop group crew",
            b"stop service infer",
            b"help",
            b"nonsense",
        ] {
            assert!(allowed_logged_out(&command(line)), "{line:?}");
        }
        for line in [
            &b"list"[..],
            b"start infer",
            b"restart infer",
            b"yes 1",
            b"no 1",
            b"revoke worker model 1",
            b"people",
            b"person add bob",
            b"logout",
            b"apply 1",
            b"audit rotate 0123456789abcdef",
        ] {
            assert!(!allowed_logged_out(&command(line)), "{line:?}");
        }
    }

    #[test]
    fn refusals_wait_longer_and_a_login_resets_them() {
        let mut s = Session::default();
        assert_eq!((s.person(), s.wait(0)), (None, 0));
        let t = 1_000_000_000;
        s.refused(t);
        assert_eq!(s.wait(t), 1_000_000);
        s.refused(t);
        assert_eq!(s.wait(t), 2_000_000);
        for _ in 0..10 {
            s.refused(t);
        }
        assert_eq!(s.wait(t), MAX_WAIT_US, "at most 60 s");
        for _ in 0..100 {
            s.refused(t);
        }
        assert_eq!(s.wait(t), MAX_WAIT_US, "no overflow");
        assert_eq!(s.wait(t + MAX_WAIT_US), 0);
        s.start(b"alice", t + MAX_WAIT_US);
        assert_eq!(s.person(), Some(&b"alice"[..]));
        s.refused(t + MAX_WAIT_US);
        assert_eq!(s.wait(t + MAX_WAIT_US), 1_000_000, "reset by the login");
    }

    #[test]
    fn a_session_ends_after_15_idle_minutes() {
        let mut s = Session::default();
        assert!(!s.idle(u64::MAX), "no one logged in");
        assert_eq!(s.idle_at(), None);
        s.start(b"alice", 10);
        assert!(!s.idle(10 + IDLE_US - 1));
        assert!(s.idle(10 + IDLE_US));
        s.touch(100);
        assert_eq!(s.idle_at(), Some(100 + IDLE_US));
        assert!(!s.idle(10 + IDLE_US));
        s.end();
        assert_eq!(s.person(), None);
        assert!(!s.idle(u64::MAX));
    }
}
