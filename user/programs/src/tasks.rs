//! The agent runtime's durable tasks (#99, agents.md): the task record,
//! its file format, every state change, and recovery. Separate from IPC
//! and storage: changes are written through [`Files`], which the runtime
//! implements over the storage service and host tests over memory that
//! can fail at any write.
//!
//! One file per task, `tasks/<id>`, rewritten whole on every change, so a
//! change is one crash-consistent commit (D-017). `next-id` is written
//! before a new task's file, so an ID is never reused. Every change is
//! made on a copy, written, and only then kept: a failed write leaves the
//! task as it was, and the runtime answers an error.

use alloc::vec::Vec;

use pharos_proto::agents::{
    KEY, MAX_CHECKPOINT, MAX_DEPS, MAX_INPUT, MAX_KEY_RESULT, MAX_KEYS, MAX_RESULT, MAX_TASKS,
    State,
};
use pharos_proto::permission::Permission;
use pharos_proto::{Reader, Writer, trust};

/// The store did not do what was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreFailed;

/// Whole-file storage. A write replaces the file or, on error, leaves it
/// as it was.
pub trait Files {
    fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed>;
    /// `Ok(None)` if there is no such file.
    fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed>;
    fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed>;
    /// Every name under `prefix`.
    fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed>;
}

pub const NEXT_ID: &[u8] = b"next-id";
pub const DIR: &[u8] = b"tasks/";
const MAGIC: &[u8; 4] = b"PTSK";
/// Format 2 (#134) adds the parent task and delegated permissions, format
/// 3 (#207) what was revoked from or refused to the task; older records
/// are still read, without them.
const FORMAT: u8 = 3;
/// Most permissions delegated to one subtask (#135).
pub const MAX_DELEGATED: usize = 4;
/// Most permissions revoked from, and refused to, one task (#207).
pub const MAX_CLOSED: usize = 16;

/// Why a change was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotFound,
    TooLarge,
    /// Not allowed in the task's state.
    Busy,
    /// The store did not take the write; nothing changed.
    Store,
}

/// An idempotency key and, once ended, its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub key: [u8; KEY],
    pub done: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub id: u32,
    pub agent: Vec<u8>,
    pub state: State,
    /// Attempts started.
    pub attempts: u8,
    pub deps: Vec<u32>,
    pub input: Vec<u8>,
    pub checkpoint: Vec<u8>,
    /// The result, or why it failed.
    pub result: Vec<u8>,
    pub keys: Vec<Key>,
    /// The goal this is a subtask of (#134); 0 for none.
    pub parent: u32,
    /// What its supervisor delegated to it (#135).
    pub delegated: Vec<Permission>,
    /// Revoked from it, kept across restarts of its agent and of the
    /// runtime (#207).
    pub revoked: Vec<Permission>,
    /// Refused to it when asked, so not asked again (#207).
    pub refused: Vec<Permission>,
}

/// What `BEGIN` answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Begin {
    Go,
    Done(Vec<u8>),
    Unknown,
}

fn decimal(mut v: u32, out: &mut Vec<u8>) {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// `tasks/<id>`.
pub fn path(id: u32) -> Vec<u8> {
    let mut p = Vec::from(DIR);
    decimal(id, &mut p);
    p
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn bytes32(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

impl Task {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.push(FORMAT);
        put_u32(&mut out, self.id);
        out.extend_from_slice(&[self.state as u8, self.attempts, self.agent.len() as u8]);
        out.extend_from_slice(&self.agent);
        out.push(self.deps.len() as u8);
        for d in &self.deps {
            put_u32(&mut out, *d);
        }
        bytes32(&mut out, &self.input);
        bytes32(&mut out, &self.checkpoint);
        bytes32(&mut out, &self.result);
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(&k.key);
            match &k.done {
                None => out.push(0),
                Some(r) => {
                    out.extend_from_slice(&[1, r.len() as u8]);
                    out.extend_from_slice(r);
                }
            }
        }
        put_u32(&mut out, self.parent);
        for list in [&self.delegated, &self.revoked, &self.refused] {
            out.push(list.len() as u8);
            for p in list {
                let mut b = [0u8; pharos_proto::permission::WIRE];
                let mut w = Writer::new(&mut b);
                if p.write(&mut w).is_some() {
                    let n = w.len();
                    out.extend_from_slice(&b[..n]);
                }
            }
        }
        out
    }

    /// Parses a task file, checking every length and limit.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAGIC {
            return None;
        }
        let format = r.u8()?;
        if !(1..=FORMAT).contains(&format) {
            return None;
        }
        let id = r.u32()?;
        let state = State::from_code(r.u8()?)?;
        let attempts = r.u8()?;
        let n = usize::from(r.u8()?);
        let agent = r.take(n).filter(|a| trust::valid_name(a))?.to_vec();
        let n = usize::from(r.u8()?);
        if n > MAX_DEPS {
            return None;
        }
        let mut deps = Vec::new();
        for _ in 0..n {
            deps.push(r.u32()?);
        }
        let mut take32 = |max: u32| {
            let n = r.u32()?;
            (n <= max).then_some(())?;
            Some(r.take(n as usize)?.to_vec())
        };
        let input = take32(MAX_INPUT)?;
        let checkpoint = take32(MAX_CHECKPOINT)?;
        let result = take32(MAX_RESULT)?;
        let n = usize::from(r.u8()?);
        if n > MAX_KEYS {
            return None;
        }
        let mut keys = Vec::new();
        for _ in 0..n {
            let key = r.take(KEY)?.try_into().ok()?;
            let done = match r.u8()? {
                0 => None,
                1 => {
                    let len = usize::from(r.u8()?);
                    Some(r.take(len).filter(|_| len <= MAX_KEY_RESULT)?.to_vec())
                }
                _ => return None,
            };
            if keys.iter().any(|k: &Key| k.key == key) {
                return None;
            }
            keys.push(Key { key, done });
        }
        let list = |r: &mut Reader<'_>, max: usize| {
            let n = usize::from(r.u8()?);
            (n <= max).then_some(())?;
            (0..n)
                .map(|_| Permission::read(r))
                .collect::<Option<Vec<_>>>()
        };
        let (mut parent, mut delegated) = (0, Vec::new());
        let (mut revoked, mut refused) = (Vec::new(), Vec::new());
        if format >= 2 {
            parent = r.u32()?;
            delegated = list(&mut r, MAX_DELEGATED)?;
        }
        if format >= 3 {
            revoked = list(&mut r, MAX_CLOSED)?;
            refused = list(&mut r, MAX_CLOSED)?;
        }
        r.is_empty().then_some(Self {
            parent,
            delegated,
            revoked,
            refused,
            id,
            agent,
            state,
            attempts,
            deps,
            input,
            checkpoint,
            result,
            keys,
        })
    }

    pub fn ended(&self) -> bool {
        matches!(self.state, State::Done | State::Failed | State::Cancelled)
    }
}

/// What [`Tasks::load`] found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    pub tasks: usize,
    /// Running when the runtime last ended: now pending or failed.
    pub recovered: usize,
    /// Files that are not task records; left in place.
    pub unreadable: usize,
}

/// Every task, in ID order.
pub struct Tasks {
    pub list: Vec<Task>,
    next_id: u32,
}

impl Tasks {
    /// Reads every task file. A task that was running is pending again,
    /// with the attempt it was on counted, or failed with `retries
    /// exhausted` if that was its last (`max_attempts` by agent name;
    /// `None`: the agent can no longer run).
    pub fn load(
        f: &mut impl Files,
        max_attempts: impl Fn(&[u8]) -> Option<u8>,
    ) -> Result<(Self, Loaded), Error> {
        let next = match f.read(NEXT_ID).map_err(|_| Error::Store)? {
            Some(b) => u32::from_le_bytes(b.as_slice().try_into().map_err(|_| Error::Store)?),
            None => 1,
        };
        let mut t = Self {
            list: Vec::new(),
            next_id: next.max(1),
        };
        let mut found = Loaded::default();
        for name in f.list(DIR).map_err(|_| Error::Store)? {
            let task = f
                .read(&name)
                .map_err(|_| Error::Store)?
                .and_then(|b| Task::decode(&b))
                .filter(|task| path(task.id) == name);
            match task {
                Some(task) if t.list.len() < MAX_TASKS => t.list.push(task),
                _ => found.unreadable += 1,
            }
        }
        t.list.sort_by_key(|task| task.id);
        if let Some(last) = t.list.last() {
            t.next_id = t.next_id.max(last.id + 1);
        }
        found.tasks = t.list.len();
        for i in 0..t.list.len() {
            if t.list[i].state == State::Running {
                let max = max_attempts(&t.list[i].agent).unwrap_or(0);
                t.retry(f, i, max)?;
                found.recovered += 1;
            }
        }
        Ok((t, found))
    }

    pub fn find(&self, id: u32) -> Option<usize> {
        self.list.iter().position(|t| t.id == id)
    }

    /// Writes `task` as entry `i` (or a new one), then keeps it.
    fn save(&mut self, f: &mut impl Files, i: Option<usize>, task: Task) -> Result<(), Error> {
        f.write(&path(task.id), &task.encode())
            .map_err(|_| Error::Store)?;
        match i {
            Some(i) => self.list[i] = task,
            None => self.list.push(task),
        }
        Ok(())
    }

    /// A new pending task. Every dependency must exist.
    pub fn submit(
        &mut self,
        f: &mut impl Files,
        agent: &[u8],
        deps: &[u32],
        input: &[u8],
    ) -> Result<u32, Error> {
        if self.list.len() >= MAX_TASKS || input.len() > MAX_INPUT as usize || deps.len() > MAX_DEPS
        {
            return Err(Error::TooLarge);
        }
        if deps.iter().any(|d| self.find(*d).is_none()) {
            return Err(Error::NotFound);
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(Error::TooLarge)?;
        // The ID is used up before the task exists.
        f.write(NEXT_ID, &next.to_le_bytes())
            .map_err(|_| Error::Store)?;
        self.next_id = next;
        let task = Task {
            id,
            agent: agent.to_vec(),
            state: State::Pending,
            attempts: 0,
            deps: deps.to_vec(),
            input: input.to_vec(),
            checkpoint: Vec::new(),
            result: Vec::new(),
            keys: Vec::new(),
            parent: 0,
            delegated: Vec::new(),
            revoked: Vec::new(),
            refused: Vec::new(),
        };
        self.save(f, None, task)?;
        Ok(id)
    }

    /// A new pending subtask of task `parent` (#134), with `delegated`
    /// permissions (#135).
    pub fn submit_child(
        &mut self,
        f: &mut impl Files,
        agent: &[u8],
        parent: u32,
        input: &[u8],
        delegated: &[Permission],
    ) -> Result<u32, Error> {
        if self.find(parent).is_none() || delegated.len() > MAX_DELEGATED {
            return Err(Error::NotFound);
        }
        let id = self.submit(f, agent, &[], input)?;
        let i = self.find(id).ok_or(Error::NotFound)?;
        let mut t = self.list[i].clone();
        t.parent = parent;
        t.delegated = delegated.to_vec();
        self.save(f, Some(i), t)?;
        Ok(id)
    }

    /// Subtasks not ended whose goal has ended or is gone (#136): no work
    /// outlives its goal.
    pub fn orphans(&self) -> Vec<u32> {
        let open = |id: u32| self.find(id).is_some_and(|i| !self.list[i].ended());
        self.list
            .iter()
            .filter(|t| t.parent != 0 && !t.ended() && !open(t.parent))
            .map(|t| t.id)
            .collect()
    }

    /// Subtasks of `parent` not yet ended.
    pub fn open_children(&self, parent: u32) -> usize {
        self.list
            .iter()
            .filter(|t| t.parent == parent && !t.ended())
            .count()
    }

    /// Every subtask of `parent`, ended or not (M3.7 review F1).
    pub fn children(&self, parent: u32) -> usize {
        self.list.iter().filter(|t| t.parent == parent).count()
    }

    /// The oldest pending task whose dependencies are done and whose agent
    /// `can_run`. A task with a failed or cancelled dependency fails
    /// first (`dependency failed`).
    pub fn next(&mut self, f: &mut impl Files, can_run: impl Fn(&Task) -> bool) -> Option<usize> {
        for i in 0..self.list.len() {
            if self.list[i].state != State::Pending {
                continue;
            }
            let deps: Vec<Option<State>> = self.list[i]
                .deps
                .iter()
                .map(|d| self.find(*d).map(|j| self.list[j].state))
                .collect();
            let broken = deps
                .iter()
                .any(|s| matches!(s, None | Some(State::Failed | State::Cancelled)));
            if broken {
                // On a store error it stays pending and is tried again.
                let _ = self.finish(f, i, State::Failed, b"dependency failed");
                continue;
            }
            if deps.iter().all(|s| *s == Some(State::Done)) && can_run(&self.list[i]) {
                return Some(i);
            }
        }
        None
    }

    /// Records `p` as revoked from task `i` (or, if `refused`, refused to
    /// it), so it holds after a restart of the runtime (#207). Already
    /// recorded: nothing to write.
    pub fn close(
        &mut self,
        f: &mut impl Files,
        i: usize,
        p: Permission,
        refused: bool,
    ) -> Result<(), Error> {
        let mut t = self.list[i].clone();
        let list = if refused {
            &mut t.refused
        } else {
            &mut t.revoked
        };
        if list.contains(&p) {
            return Ok(());
        }
        if list.len() >= MAX_CLOSED {
            return Err(Error::TooLarge);
        }
        list.push(p);
        self.save(f, Some(i), t)
    }

    /// Starts an attempt: counted and stored before the agent runs.
    pub fn start(&mut self, f: &mut impl Files, i: usize) -> Result<(), Error> {
        let mut t = self.list[i].clone();
        if t.state != State::Pending {
            return Err(Error::Busy);
        }
        t.state = State::Running;
        t.attempts = t.attempts.saturating_add(1);
        self.save(f, Some(i), t)
    }

    pub fn checkpoint(&mut self, f: &mut impl Files, i: usize, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_CHECKPOINT as usize {
            return Err(Error::TooLarge);
        }
        let mut t = self.list[i].clone();
        t.checkpoint = bytes.to_vec();
        self.save(f, Some(i), t)
    }

    /// `GO` only after the key is stored as begun.
    pub fn begin(&mut self, f: &mut impl Files, i: usize, key: [u8; KEY]) -> Result<Begin, Error> {
        if let Some(k) = self.list[i].keys.iter().find(|k| k.key == key) {
            return Ok(match &k.done {
                Some(r) => Begin::Done(r.clone()),
                None => Begin::Unknown,
            });
        }
        let mut t = self.list[i].clone();
        if t.keys.len() >= MAX_KEYS {
            return Err(Error::TooLarge);
        }
        t.keys.push(Key { key, done: None });
        self.save(f, Some(i), t)?;
        Ok(Begin::Go)
    }

    /// Records a begun key's result. Ending it again with the same result
    /// is allowed; with another, refused.
    pub fn end(
        &mut self,
        f: &mut impl Files,
        i: usize,
        key: [u8; KEY],
        result: &[u8],
    ) -> Result<(), Error> {
        if result.len() > MAX_KEY_RESULT {
            return Err(Error::TooLarge);
        }
        let mut t = self.list[i].clone();
        let k = t
            .keys
            .iter_mut()
            .find(|k| k.key == key)
            .ok_or(Error::NotFound)?;
        match &k.done {
            Some(r) if r == result => return Ok(()),
            Some(_) => return Err(Error::Busy),
            None => k.done = Some(result.to_vec()),
        }
        self.save(f, Some(i), t)
    }

    /// Ends the task with `state` (done, failed, or cancelled).
    pub fn finish(
        &mut self,
        f: &mut impl Files,
        i: usize,
        state: State,
        result: &[u8],
    ) -> Result<(), Error> {
        if result.len() > MAX_RESULT as usize {
            return Err(Error::TooLarge);
        }
        let mut t = self.list[i].clone();
        if t.ended() {
            return Err(Error::Busy);
        }
        t.state = state;
        t.result = result.to_vec();
        self.save(f, Some(i), t)
    }

    /// A failed attempt: pending again, or failed with `retries
    /// exhausted` once `max` attempts were started. Returns whether it
    /// will run again.
    pub fn retry(&mut self, f: &mut impl Files, i: usize, max: u8) -> Result<bool, Error> {
        if self.list[i].attempts >= max {
            self.finish(f, i, State::Failed, b"retries exhausted")?;
            return Ok(false);
        }
        let mut t = self.list[i].clone();
        t.state = State::Pending;
        self.save(f, Some(i), t)?;
        Ok(true)
    }

    /// Retries every task that is running here but has no process
    /// (`has_process` by ID): one whose failed attempt the store did not
    /// take. Each gets [`Self::retry`] with its agent's `max_attempts`
    /// (`None`: the agent can no longer run). Returns each task's ID and
    /// outcome; a refused write leaves it for the next call.
    pub fn retry_stranded(
        &mut self,
        f: &mut impl Files,
        has_process: impl Fn(u32) -> bool,
        max_attempts: impl Fn(&[u8]) -> Option<u8>,
    ) -> Vec<(u32, Result<bool, Error>)> {
        let stranded: Vec<usize> = (0..self.list.len())
            .filter(|&i| self.list[i].state == State::Running && !has_process(self.list[i].id))
            .collect();
        stranded
            .into_iter()
            .map(|i| {
                let max = max_attempts(&self.list[i].agent).unwrap_or(0);
                (self.list[i].id, self.retry(f, i, max))
            })
            .collect()
    }

    /// Deletes an ended task's record, unless a task that has not ended
    /// depends on it.
    pub fn forget(&mut self, f: &mut impl Files, id: u32) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::NotFound)?;
        let needed = self.list.iter().any(|t| !t.ended() && t.deps.contains(&id));
        if !self.list[i].ended() || needed {
            return Err(Error::Busy);
        }
        f.delete(&path(id)).map_err(|_| Error::Store)?;
        self.list.remove(i);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Files in memory. After `left` more writes or deletes, every one
    /// fails: the store "crashed" there.
    #[derive(Default)]
    struct Mem {
        files: BTreeMap<Vec<u8>, Vec<u8>>,
        left: Option<usize>,
        writes: usize,
    }

    impl Mem {
        fn spend(&mut self) -> Result<(), StoreFailed> {
            match &mut self.left {
                Some(0) => Err(StoreFailed),
                Some(n) => {
                    *n -= 1;
                    self.writes += 1;
                    Ok(())
                }
                None => {
                    self.writes += 1;
                    Ok(())
                }
            }
        }
        fn after_crash(&self) -> Self {
            Self {
                files: self.files.clone(),
                ..Self::default()
            }
        }
    }

    impl Files for Mem {
        fn write(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), StoreFailed> {
            self.spend()?;
            self.files.insert(path.to_vec(), bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, StoreFailed> {
            Ok(self.files.get(path).cloned())
        }
        fn delete(&mut self, path: &[u8]) -> Result<(), StoreFailed> {
            self.spend()?;
            self.files.remove(path);
            Ok(())
        }
        fn list(&mut self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StoreFailed> {
            Ok(self
                .files
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    const MAX: u8 = 3;

    fn load(f: &mut Mem) -> (Tasks, Loaded) {
        Tasks::load(f, |a| (a == b"worker").then_some(MAX)).unwrap()
    }

    fn task() -> Task {
        Task {
            id: 7,
            agent: b"worker".to_vec(),
            state: State::Running,
            attempts: 2,
            deps: std::vec![1, 2],
            input: b"in".to_vec(),
            checkpoint: std::vec![9; 100],
            result: Vec::new(),
            keys: std::vec![
                Key {
                    key: [1; KEY],
                    done: None
                },
                Key {
                    key: [2; KEY],
                    done: Some(b"r".to_vec())
                },
            ],
            parent: 3,
            delegated: std::vec![
                Permission::file(b"report.txt").unwrap(),
                Permission::Model(2)
            ],
            revoked: std::vec![Permission::DataRead],
            refused: std::vec![Permission::Model(3), Permission::DataWrite],
        }
    }

    #[test]
    fn format_1_records_are_still_read() {
        let mut t = task();
        t.parent = 0;
        t.delegated.clear();
        t.revoked.clear();
        t.refused.clear();
        let mut b = t.encode();
        // Format 2: nothing revoked or refused (#207).
        b[4] = 2;
        b.truncate(b.len() - 2);
        assert_eq!(Task::decode(&b), Some(t.clone()));
        // Format 1: no parent, no delegated permissions.
        b[4] = 1;
        b.truncate(b.len() - 5);
        assert_eq!(Task::decode(&b), Some(t));
        b[4] = 4;
        assert_eq!(Task::decode(&b), None, "an unknown format");
    }

    #[test]
    fn revoked_and_refused_outlive_a_restart() {
        let mut f = Mem::default();
        let (mut tasks, _) = load(&mut f);
        let id = tasks.submit(&mut f, b"worker", &[], b"in").unwrap();
        let i = tasks.find(id).unwrap();
        let net = Permission::Net {
            addr: [10, 0, 2, 2],
            port: 7,
        };
        tasks.close(&mut f, i, Permission::Model(2), false).unwrap();
        tasks.close(&mut f, i, Permission::Model(2), false).unwrap();
        tasks.close(&mut f, i, net, true).unwrap();
        let (again, _) = load(&mut f);
        let i = again.find(id).unwrap();
        assert_eq!(again.list[i].revoked, [Permission::Model(2)], "once");
        assert_eq!(again.list[i].refused, [net]);
        let mut full = again;
        for n in 1..MAX_CLOSED as u8 {
            full.close(&mut f, i, Permission::Model(n + 2), false)
                .unwrap();
        }
        assert_eq!(
            full.close(&mut f, i, Permission::DataRead, false),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn subtasks_name_their_parent() {
        let mut f = Mem::default();
        let (mut tasks, _) = load(&mut f);
        let goal = tasks.submit(&mut f, b"worker", &[], b"goal").unwrap();
        let file = Permission::file(b"report.txt").unwrap();
        let a = tasks
            .submit_child(&mut f, b"worker", goal, b"a", &[file])
            .unwrap();
        let b = tasks
            .submit_child(&mut f, b"worker", goal, b"b", &[])
            .unwrap();
        assert_eq!(
            tasks.submit_child(&mut f, b"worker", 999, b"c", &[]),
            Err(Error::NotFound)
        );
        assert_eq!(
            tasks.submit_child(&mut f, b"worker", goal, b"c", &[file; 5]),
            Err(Error::NotFound)
        );
        assert_eq!(tasks.open_children(goal), 2);
        let i = tasks.find(a).unwrap();
        assert_eq!(
            (tasks.list[i].parent, tasks.list[i].delegated.as_slice()),
            (goal, &[file][..])
        );
        tasks
            .finish(&mut f, tasks.find(b).unwrap(), State::Done, b"ok")
            .unwrap();
        assert_eq!(tasks.open_children(goal), 1);
        assert_eq!(tasks.children(goal), 2, "ended ones too");
        // Both kept across a restart.
        let (again, _) = load(&mut f);
        let i = again.find(a).unwrap();
        assert_eq!(
            (again.list[i].parent, again.list[i].delegated.as_slice()),
            (goal, &[file][..])
        );
        assert_eq!(again.open_children(goal), 1);
        assert_eq!(again.orphans(), [], "its goal is open");
    }

    #[test]
    fn subtasks_of_an_ended_goal_are_orphans() {
        let mut f = Mem::default();
        let (mut tasks, _) = load(&mut f);
        let other = tasks.submit(&mut f, b"worker", &[], b"other").unwrap();
        let c = tasks
            .submit_child(&mut f, b"worker", other, b"c", &[])
            .unwrap();
        for state in [State::Done, State::Failed, State::Cancelled] {
            let goal = tasks.submit(&mut f, b"worker", &[], b"goal").unwrap();
            let a = tasks
                .submit_child(&mut f, b"worker", goal, b"a", &[])
                .unwrap();
            let b = tasks
                .submit_child(&mut f, b"worker", goal, b"b", &[])
                .unwrap();
            tasks
                .finish(&mut f, tasks.find(b).unwrap(), State::Done, b"ok")
                .unwrap();
            assert_eq!(tasks.orphans(), []);
            tasks
                .finish(&mut f, tasks.find(goal).unwrap(), state, b"")
                .unwrap();
            assert_eq!(tasks.orphans(), [a], "{state:?}: the open one only");
            tasks
                .finish(&mut f, tasks.find(a).unwrap(), State::Cancelled, b"")
                .unwrap();
        }
        // A goal forgotten (or never stored) leaves its subtasks orphans.
        tasks.list.retain(|t| t.id != other);
        assert_eq!(tasks.orphans(), [c]);
    }

    #[test]
    fn records_round_trip_and_bad_ones_are_refused() {
        let t = task();
        let b = t.encode();
        assert_eq!(Task::decode(&b), Some(t.clone()));
        for n in 0..b.len() {
            assert_eq!(Task::decode(&b[..n]), None, "cut at {n}");
        }
        let mut long = b.clone();
        long.push(0);
        assert_eq!(Task::decode(&long), None, "trailing byte");
        let mut big = t.clone();
        big.checkpoint = std::vec![0; MAX_CHECKPOINT as usize];
        big.input = std::vec![0; MAX_INPUT as usize];
        big.result = std::vec![0; MAX_RESULT as usize];
        big.keys = (0..MAX_KEYS as u8)
            .map(|i| Key {
                key: [i; KEY],
                done: Some(std::vec![0; MAX_KEY_RESULT]),
            })
            .collect();
        assert_eq!(
            Task::decode(&big.encode()),
            Some(big.clone()),
            "every maximum"
        );
        let changes: [fn(&mut Task); 7] = [
            |t: &mut Task| t.checkpoint.push(0),
            |t: &mut Task| t.input.push(0),
            |t: &mut Task| t.result.push(0),
            |t: &mut Task| t.keys[0].done.as_mut().unwrap().push(0),
            |t: &mut Task| t.agent = b"a b".to_vec(),
            |t: &mut Task| t.deps = std::vec![1; 5],
            |t: &mut Task| t.keys[1].key = t.keys[0].key,
        ];
        for change in changes {
            let mut over = big.clone();
            change(&mut over);
            assert_eq!(Task::decode(&over.encode()), None);
        }
        let mut bad = b.clone();
        bad[9] = 9;
        assert_eq!(Task::decode(&bad), None, "unknown state");
        bad = b.clone();
        bad[0] = b'X';
        assert_eq!(Task::decode(&bad), None, "magic");
        // Fuzzed: cut and changed records never panic.
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..100_000 {
            let mut m = b.clone();
            for _ in 0..1 + x % 3 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize >> 8) % m.len();
                m[i] = x as u8;
            }
            let cut = (x as usize >> 20) % (m.len() + 1);
            if let Some(t) = Task::decode(&m[..cut]) {
                assert!(t.keys.len() <= MAX_KEYS && t.deps.len() <= MAX_DEPS);
            }
        }
    }

    #[test]
    fn every_state_change() {
        let mut f = Mem::default();
        let (mut t, found) = load(&mut f);
        assert_eq!(found, Loaded::default());
        let a = t.submit(&mut f, b"worker", &[], b"a").unwrap();
        assert_eq!(a, 1);
        assert_eq!(
            t.submit(&mut f, b"worker", &[99], b""),
            Err(Error::NotFound)
        );
        let b = t.submit(&mut f, b"worker", &[a], b"b").unwrap();
        assert_eq!(t.next(&mut f, |_| true), Some(0), "b waits for a");
        assert_eq!(t.next(&mut f, |task| task.id != a), None);
        t.start(&mut f, 0).unwrap();
        assert_eq!(t.start(&mut f, 0), Err(Error::Busy));
        assert_eq!((t.list[0].state, t.list[0].attempts), (State::Running, 1));
        assert_eq!(t.next(&mut f, |_| true), None, "a runs, b waits");
        t.checkpoint(&mut f, 0, b"half").unwrap();
        assert_eq!(
            t.checkpoint(&mut f, 0, &std::vec![0; MAX_CHECKPOINT as usize + 1]),
            Err(Error::TooLarge)
        );
        assert_eq!(t.retry(&mut f, 0, MAX), Ok(true));
        assert_eq!(t.list[0].state, State::Pending);
        assert_eq!(t.list[0].checkpoint, b"half", "kept for the next attempt");
        t.start(&mut f, 0).unwrap();
        t.finish(&mut f, 0, State::Done, b"ok").unwrap();
        assert_eq!(t.finish(&mut f, 0, State::Failed, b""), Err(Error::Busy));
        assert_eq!(t.next(&mut f, |_| true), Some(1), "b can run now");
        assert_eq!(t.forget(&mut f, b), Err(Error::Busy), "b has not ended");
        assert_eq!(t.forget(&mut f, a), Err(Error::Busy), "b depends on a");
        assert_eq!(t.forget(&mut f, 99), Err(Error::NotFound));
        // A cancelled dependency fails its dependents.
        let c = t.submit(&mut f, b"worker", &[], b"c").unwrap();
        let d = t.submit(&mut f, b"worker", &[c, a], b"d").unwrap();
        let ci = t.find(c).unwrap();
        t.finish(&mut f, ci, State::Cancelled, b"").unwrap();
        let _ = t.next(&mut f, |task| task.id == d);
        let di = t.find(d).unwrap();
        assert_eq!(t.list[di].state, State::Failed);
        assert_eq!(t.list[di].result, b"dependency failed");
        // Attempts are bounded.
        t.start(&mut f, 1).unwrap();
        assert_eq!(t.retry(&mut f, 1, MAX), Ok(true));
        t.start(&mut f, 1).unwrap();
        assert_eq!(t.retry(&mut f, 1, MAX), Ok(true));
        t.start(&mut f, 1).unwrap();
        assert_eq!(t.retry(&mut f, 1, MAX), Ok(false), "the third was the last");
        assert_eq!(t.list[1].state, State::Failed);
        assert_eq!(t.list[1].result, b"retries exhausted");
        t.forget(&mut f, b).unwrap();
        assert_eq!(t.find(b), None);
        assert!(!f.files.contains_key(&path(b)), "its file is deleted");
        // The store holds exactly what memory holds.
        let (again, found) = load(&mut f.after_crash());
        assert_eq!(found.unreadable, 0);
        assert_eq!(again.list, t.list);
    }

    #[test]
    fn keys_answer_go_done_unknown() {
        let mut f = Mem::default();
        let (mut t, _) = load(&mut f);
        t.submit(&mut f, b"worker", &[], b"").unwrap();
        t.start(&mut f, 0).unwrap();
        let k = [5; KEY];
        assert_eq!(t.begin(&mut f, 0, k), Ok(Begin::Go));
        assert_eq!(
            t.begin(&mut f, 0, k),
            Ok(Begin::Unknown),
            "begun, not ended"
        );
        assert_eq!(t.end(&mut f, 0, [6; KEY], b"x"), Err(Error::NotFound));
        t.end(&mut f, 0, k, b"sent").unwrap();
        assert_eq!(
            t.end(&mut f, 0, k, b"sent"),
            Ok(()),
            "the same result again"
        );
        assert_eq!(t.end(&mut f, 0, k, b"other"), Err(Error::Busy));
        assert_eq!(t.begin(&mut f, 0, k), Ok(Begin::Done(b"sent".to_vec())));
        assert_eq!(
            t.end(&mut f, 0, k, &[0; MAX_KEY_RESULT + 1]),
            Err(Error::TooLarge)
        );
        for i in 1..MAX_KEYS as u8 {
            assert_eq!(t.begin(&mut f, 0, [100 + i; KEY]), Ok(Begin::Go));
        }
        assert_eq!(
            t.begin(&mut f, 0, [0; KEY]),
            Err(Error::TooLarge),
            "33 keys"
        );
        // After a restart: done stays done, begun stays unknown.
        assert_eq!(t.retry(&mut f, 0, MAX), Ok(true));
        let (mut t, _) = load(&mut f.after_crash());
        assert_eq!(t.begin(&mut f, 0, k), Ok(Begin::Done(b"sent".to_vec())));
        assert_eq!(t.begin(&mut f, 0, [101; KEY]), Ok(Begin::Unknown));
    }

    #[test]
    fn recovery_from_every_state() {
        let mut f = Mem::default();
        let (mut t, _) = load(&mut f);
        for state in [
            State::Pending,
            State::Running,
            State::Done,
            State::Failed,
            State::Cancelled,
        ] {
            let id = t.submit(&mut f, b"worker", &[], b"").unwrap();
            let i = t.find(id).unwrap();
            if state != State::Pending {
                t.start(&mut f, i).unwrap();
            }
            if t.list[i].state != state {
                t.finish(&mut f, i, state, b"r").unwrap();
            }
        }
        // A running task on its last attempt, and one of an agent that is
        // gone.
        let last = t.submit(&mut f, b"worker", &[], b"").unwrap();
        for _ in 0..MAX {
            let i = t.find(last).unwrap();
            t.start(&mut f, i).unwrap();
            if t.list[i].attempts < MAX {
                t.retry(&mut f, i, MAX).unwrap();
            }
        }
        let gone = t.submit(&mut f, b"retired", &[], b"").unwrap();
        let i = t.find(gone).unwrap();
        t.start(&mut f, i).unwrap();
        f.files
            .insert(b"tasks/junk".to_vec(), b"not a task".to_vec());
        let renamed = t.list[0].encode();
        f.files.insert(b"tasks/999".to_vec(), renamed);

        let mut after = f.after_crash();
        let (r, found) = load(&mut after);
        assert_eq!(found.tasks, 7);
        assert_eq!(found.recovered, 3);
        assert_eq!(found.unreadable, 2, "junk, and a record under another ID");
        let states: Vec<(State, u8)> = r.list.iter().map(|t| (t.state, t.attempts)).collect();
        assert_eq!(
            states,
            [
                (State::Pending, 0),
                (State::Pending, 1),
                (State::Done, 1),
                (State::Failed, 1),
                (State::Cancelled, 1),
                (State::Failed, MAX),
                (State::Failed, 1),
            ]
        );
        assert_eq!(r.list[5].result, b"retries exhausted");
        assert_eq!(r.list[6].result, b"retries exhausted", "its agent is gone");
        // Recovery is stored, and IDs are not reused.
        let (mut again, found) = load(&mut after.after_crash());
        assert_eq!(found.recovered, 0);
        let id = again.submit(&mut after, b"worker", &[], b"").unwrap();
        assert_eq!(id, gone + 1);
    }

    #[test]
    fn ids_are_never_reused() {
        let mut f = Mem::default();
        let (mut t, _) = load(&mut f);
        let id = t.submit(&mut f, b"worker", &[], b"").unwrap();
        t.finish(&mut f, 0, State::Done, b"").unwrap();
        t.forget(&mut f, id).unwrap();
        let (mut t, _) = load(&mut f.after_crash());
        assert_eq!(t.submit(&mut f, b"worker", &[], b""), Ok(id + 1));
        // `next-id` is written first: a crash before the task file still
        // uses the ID up.
        let mut cut = Mem {
            files: f.files.clone(),
            left: Some(1),
            ..Mem::default()
        };
        let (mut t, _) = load(&mut cut);
        assert_eq!(t.submit(&mut cut, b"worker", &[], b""), Err(Error::Store));
        let (mut t, _) = load(&mut cut.after_crash());
        assert_eq!(t.submit(&mut f, b"worker", &[], b""), Ok(id + 3));
    }

    #[test]
    fn a_refused_retry_is_tried_again() {
        let mut f = Mem::default();
        let (mut t, _) = load(&mut f);
        let a = t.submit(&mut f, b"worker", &[], b"").unwrap();
        let b = t.submit(&mut f, b"worker", &[], b"").unwrap();
        t.start(&mut f, 0).unwrap();
        t.start(&mut f, 1).unwrap();
        let max = |agent: &[u8]| (agent == b"worker").then_some(MAX);
        // `a`'s agent crashed, and the store refuses the retry.
        f.left = Some(0);
        assert_eq!(t.retry(&mut f, 0, MAX), Err(Error::Store));
        assert_eq!(t.list[0].state, State::Running, "nothing changed");
        let has = |id: u32| id == b;
        assert_eq!(
            t.retry_stranded(&mut f, has, max),
            [(a, Err(Error::Store))],
            "still refused: kept for later"
        );
        f.left = None;
        assert_eq!(t.retry_stranded(&mut f, has, max), [(a, Ok(true))]);
        assert_eq!(t.list[0].state, State::Pending, "runs again");
        assert_eq!(t.list[1].state, State::Running, "b has its process");
        assert_eq!(t.retry_stranded(&mut f, has, max), [], "nothing left");
        let (again, _) = load(&mut f.after_crash());
        assert_eq!(again.list[0].state, State::Pending, "and it is stored");
        // On its last attempt it fails instead.
        t.start(&mut f, 0).unwrap();
        t.list[0].attempts = MAX;
        assert_eq!(t.retry_stranded(&mut f, has, max), [(a, Ok(false))]);
        assert_eq!(t.list[0].result, b"retries exhausted");
    }

    /// What a run had confirmed before its store stopped taking writes.
    #[derive(Default)]
    struct Confirmed {
        ids: Vec<u32>,
        go: Vec<(u32, [u8; KEY])>,
        done: Vec<(u32, [u8; KEY], Vec<u8>)>,
        checkpoint: Vec<(u32, Vec<u8>)>,
        finished: Vec<(u32, State)>,
    }

    /// A fixed run of the runtime's changes; stops at the first refused
    /// write, as a crashed runtime would.
    fn scenario(f: &mut Mem) -> Confirmed {
        let mut c = Confirmed::default();
        let Ok((mut t, _)) = Tasks::load(f, |_| Some(MAX)) else {
            return c;
        };
        let mut go = || -> Result<(), Error> {
            let a = t.submit(f, b"worker", &[], b"a")?;
            c.ids.push(a);
            let b = t.submit(f, b"worker", &[a], b"b")?;
            c.ids.push(b);
            t.start(f, 0)?;
            for n in 0..3u8 {
                let key = [n; KEY];
                if t.begin(f, 0, key)? == Begin::Go {
                    c.go.push((a, key));
                }
                t.end(f, 0, key, &[n])?;
                c.done.push((a, key, std::vec![n]));
                t.checkpoint(f, 0, &[n; 10])?;
                c.checkpoint.push((a, std::vec![n; 10]));
            }
            t.retry(f, 0, MAX)?;
            t.start(f, 0)?;
            t.finish(f, 0, State::Done, b"done")?;
            c.finished.push((a, State::Done));
            let i = t.next(f, |_| true).ok_or(Error::NotFound)?;
            t.start(f, i)?;
            t.finish(f, i, State::Cancelled, b"")?;
            c.finished.push((b, State::Cancelled));
            t.forget(f, a)?;
            Ok(())
        };
        let _ = go();
        c
    }

    #[test]
    fn every_store_write_cut() {
        let mut full = Mem::default();
        scenario(&mut full);
        let total = full.writes;
        assert!(total > 15, "{total} writes");
        for cut in 0..=total {
            let mut f = Mem {
                left: Some(cut),
                ..Mem::default()
            };
            let c = scenario(&mut f);
            let mut after = f.after_crash();
            let (mut t, found) = Tasks::load(&mut after, |_| Some(MAX)).unwrap();
            assert_eq!(found.unreadable, 0, "cut {cut}");
            for id in &c.ids {
                let forgotten = cut == total && *id == 1;
                assert!(
                    forgotten || t.find(*id).is_some(),
                    "cut {cut}: task {id} lost"
                );
            }
            for (id, key) in &c.go {
                if let Some(i) = t.find(*id) {
                    assert_ne!(
                        t.begin(&mut after, i, *key),
                        Ok(Begin::Go),
                        "cut {cut}: GO twice"
                    );
                }
            }
            for (id, key, result) in &c.done {
                if let Some(i) = t.find(*id) {
                    let b = t.begin(&mut after, i, *key);
                    assert_eq!(b, Ok(Begin::Done(result.clone())), "cut {cut}");
                }
            }
            if let Some((id, cp)) = c.checkpoint.last() {
                if let Some(i) = t.find(*id) {
                    assert_eq!(&t.list[i].checkpoint, cp, "cut {cut}: checkpoint lost");
                }
            }
            for (id, state) in &c.finished {
                if let Some(i) = t.find(*id) {
                    assert_eq!(t.list[i].state, *state, "cut {cut}");
                }
            }
            assert!(
                t.list.iter().all(|t| t.state != State::Running),
                "cut {cut}: recovered"
            );
            let id = t.submit(&mut after, b"worker", &[], b"").unwrap();
            assert!(
                c.ids.iter().all(|old| id > *old),
                "cut {cut}: ID {id} reused"
            );
        }
    }
}
