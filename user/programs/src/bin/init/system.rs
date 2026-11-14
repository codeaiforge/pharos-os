//! `init`'s image slots (#163, boot.md section 8): namespace `system` on
//! its own unbadged storage capability, through one buffer big enough for
//! a slot file. The same buffer is the `Memory` object `fs_mount` copies
//! the image from. Updates wait in `system/incoming` (#165). Once a file
//! is read for a check, the store's access to the buffer is revoked until
//! the next request that needs it (#167), so the bytes checked are the
//! bytes mounted or written.

use alloc::vec::Vec;
use core::cell::Cell;

use pharos_image::HEADER_LEN;
use pharos_image::slots::{RECORD_LEN, Record, Slot};
use pharos_programs::system::{MAX_INCOMING, Refusal, image_config};
use pharos_proto::store::{self, Request, Status};
use pharos_services::Service;
use pharos_services::config::{self, Config};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Handle, Mapped, Received, call_timeout, fs_mount, mem_map, mem_share, revoke, send,
};

/// A 16 MiB image takes about a second to read under QEMU.
const STORE_US: u64 = 10_000_000;
/// A slot file: the header and an image of at most 16 MiB.
const BUFFER: u64 = pharos_image::MAX_IMAGE + 4096;
const RECORD: &[u8] = b"state";
/// Where updates wait, in namespace `system`.
pub const INCOMING: &[u8] = b"incoming/";

/// What [`Slots::check`] found: the version, SHA-256, length, and the
/// image's configuration or why it was refused.
pub type Checked = (u64, [u8; 32], u64, Result<Config, config::Error>);

pub struct Slots {
    store: Handle,
    reply: Handle,
    buffer: Mapped,
    /// `READ | WRITE | GRANT` on the buffer, kept for `fs_mount`.
    memory: Handle,
    /// The store's access is revoked: attach again before using it.
    private: Cell<bool>,
}

/// What `system/state` held.
pub enum Loaded {
    Record(Record),
    Missing,
    Corrupt,
    Unreadable,
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

impl Slots {
    /// Maps and shares the buffer and attaches it at the store.
    pub fn open(store: Handle, reply: Handle) -> Option<Self> {
        let buffer = mem_map(BUFFER).ok()?;
        let memory = mem_share(&buffer).ok()?;
        let slots = Self {
            store,
            reply,
            buffer,
            memory,
            private: Cell::new(false),
        };
        slots.attach().then_some(slots)
    }

    fn attach(&self) -> bool {
        self.private.set(false);
        let len = self.buffer.len() as u64;
        let mut msg = [0u8; 16];
        let sent = store::encode(&Request::Attach { len }, &mut msg)
            .is_some_and(|n| send(self.store, &msg[..n], self.memory, READ | WRITE, 0).is_ok());
        sent && matches!(self.call(&Request::Buffer), Some((Status::Ok, out)) if u64_at(&out, 1) == len)
    }

    fn call(&self, req: &Request<'_>) -> Option<(Status, [u8; 256])> {
        let mut msg = [0u8; 256];
        let n = store::encode(req, &mut msg)?;
        let mut out = [0u8; 256];
        match call_timeout(self.store, &msg[..n], self.reply, &mut out, STORE_US) {
            Ok(Received::Message { len, .. }) if len >= 1 => Some((Status::from_code(out[0]), out)),
            _ => None,
        }
    }

    /// A request that uses the buffer, attaching it again first if it was
    /// made private, and once more if the store lost it (it restarted).
    fn call_buffered(&self, req: &Request<'_>) -> Option<(Status, [u8; 256])> {
        if self.private.get() && !self.attach() {
            return None;
        }
        match self.call(req)? {
            (Status::NoBuffer, _) if self.attach() => self.call(req),
            answer => Some(answer),
        }
    }

    /// Reads `path` into the buffer: its length, `None` if there is no
    /// such file, `Err` if the store failed.
    fn read(&self, path: &[u8]) -> Result<Option<u64>, ()> {
        let (status, out) = self.call(&Request::Stat { path }).ok_or(())?;
        match status {
            Status::NotFound => return Ok(None),
            Status::Ok => {}
            _ => return Err(()),
        }
        let len = u64_at(&out, 2);
        if len > self.buffer.len() as u64 {
            return Err(());
        }
        let req = Request::Read {
            path,
            offset: 0,
            len,
            at: 0,
        };
        match self.call_buffered(&req) {
            Some((Status::Ok, out)) if u64_at(&out, 1) == len => Ok(Some(len)),
            _ => Err(()),
        }
    }

    pub fn load(&self) -> Loaded {
        match self.read(RECORD) {
            Err(()) => Loaded::Unreadable,
            Ok(None) => Loaded::Missing,
            Ok(Some(len)) if len == RECORD_LEN as u64 => {
                let mut bytes = [0u8; RECORD_LEN];
                self.buffer.read_bytes(0, &mut bytes);
                Record::decode(&bytes).map_or(Loaded::Corrupt, Loaded::Record)
            }
            Ok(Some(_)) => Loaded::Corrupt,
        }
    }

    /// Writes `record` (one store commit: the old record or the new).
    pub fn save(&self, record: &Record) -> bool {
        self.buffer.write_bytes(0, &record.encode());
        let req = Request::Write {
            path: RECORD,
            len: RECORD_LEN as u64,
            at: 0,
        };
        matches!(self.call_buffered(&req), Some((Status::Ok, _)))
    }

    /// Reads `path` (in namespace `system`) and verifies its signature
    /// with `key`: its version, SHA-256, length, and its image's
    /// configuration checked against `table` (M4.5). Versions and the
    /// configuration are the caller's to judge. The store's access to the buffer is revoked
    /// first (the kernel ends its mapping), so until the next buffered
    /// request only `init` can change the checked bytes.
    pub fn check(
        &self,
        path: &[u8],
        key: Option<&[u8; 32]>,
        table: &[Service],
    ) -> Result<Checked, Refusal> {
        let key = key.ok_or(Refusal::NoKey)?;
        let Ok(Some(len)) = self.read(path) else {
            return Err(Refusal::Unreadable);
        };
        if revoke(self.memory).is_err() {
            return Err(Refusal::Unreadable);
        }
        self.private.set(true);
        let mut file = Vec::new();
        file.try_reserve_exact(len as usize)
            .map_err(|_| Refusal::Unreadable)?;
        file.resize(len as usize, 0);
        self.buffer.read_bytes(0, &mut file);
        let v = pharos_image::verify(&file, key, 0).map_err(Refusal::Image)?;
        let config = image_config(&file[HEADER_LEN..], table);
        Ok((v.version, v.sha256, len, config))
    }

    /// Reads `slot`, verifies it with `key` and against the SHA-256 the
    /// record names, and mounts its image with `MOUNT` on `root`: the new
    /// filesystem, the image's version, and its configuration (M4.5). The kernel mounts a copy of
    /// the buffer.
    pub fn mount(
        &self,
        root: Handle,
        slot: Slot,
        record: &Record,
        key: Option<&[u8; 32]>,
        table: &[Service],
    ) -> Result<(Handle, u64, Result<Config, config::Error>), Refusal> {
        let (version, sha256, len, config) = self.check(slot.path(), key, table)?;
        if sha256 != record.slot(slot).sha256 {
            return Err(Refusal::Replaced);
        }
        let image_len = len - HEADER_LEN as u64;
        let fs = fs_mount(root, self.memory, HEADER_LEN as u64, image_len)
            .map_err(|_| Refusal::NotMounted)?;
        Ok((fs, version, config))
    }

    /// The first [`MAX_INCOMING`] files in `system/incoming`, names only
    /// (without the directory); `None` if the store did not answer.
    pub fn incoming(&self) -> Option<Vec<Vec<u8>>> {
        let (status, out) = self.call(&Request::List {
            prefix: INCOMING,
            start: 0,
        })?;
        if status != Status::Ok {
            return None;
        }
        let mut names = Vec::new();
        let mut at = 3;
        for _ in 0..out[1] {
            let len = usize::from(*out.get(at)?);
            let name = out.get(at + 1..at + 1 + len)?;
            names.push(name.strip_prefix(INCOMING)?.to_vec());
            at += 1 + len;
        }
        names.truncate(MAX_INCOMING);
        Some(names)
    }

    /// Writes the buffer's first `len` bytes, as [`Self::check`] left
    /// them, as `slot`'s file (one store commit).
    pub fn write_slot(&self, slot: Slot, len: u64) -> bool {
        let req = Request::Write {
            path: slot.path(),
            len,
            at: 0,
        };
        matches!(self.call_buffered(&req), Some((Status::Ok, _)))
    }

    /// Deletes `path` in namespace `system`.
    pub fn delete(&self, path: &[u8]) -> bool {
        matches!(
            self.call(&Request::Delete { path }),
            Some((Status::Ok | Status::NotFound, _))
        )
    }
}
