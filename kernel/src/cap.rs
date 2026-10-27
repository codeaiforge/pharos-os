//! Capabilities (D-012 direction, syscalls-ipc.md): a reference to a kernel
//! object plus rights, held in a per-process table and named by handle.
//!
//! Issue #40 adds the table, the debug-console object, and `delete`; IPC
//! endpoints, granting, and revocation through the derivation tree follow
//! in #41.

use alloc::sync::Arc;
use alloc::vec::Vec;

/// Index into a process's capability table; 0 is never valid.
pub type Handle = u64;

/// A set of rights.
pub type Rights = u32;
/// Send on an endpoint.
pub const SEND: Rights = 1;
/// Receive on an endpoint.
pub const RECEIVE: Rights = 1 << 1;
/// Pass the capability to another process.
pub const GRANT: Rights = 1 << 2;
/// Write to the debug console.
pub const WRITE: Rights = 1 << 3;

/// Largest number of handles a process can hold.
// ponytail: fixed cap per process; make it a quota when processes need more.
pub const MAX_HANDLES: usize = 64;

/// A kernel object that capabilities refer to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    /// The kernel's serial debug console.
    DebugConsole,
}

/// A capability: an object and the rights its holder has on it.
#[derive(Debug)]
pub struct Capability {
    object: Object,
    rights: Rights,
}

impl Capability {
    /// A new (original) capability.
    pub fn new(object: Object, rights: Rights) -> Arc<Self> {
        Arc::new(Self { object, rights })
    }

    /// The object referred to.
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// The rights held.
    pub fn rights(&self) -> Rights {
        self.rights
    }
}

/// Why a capability lookup failed.
#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// No capability under this handle.
    InvalidHandle,
    /// The capability lacks a needed right.
    MissingRight,
    /// The table holds [`MAX_HANDLES`] capabilities already.
    TableFull,
}

/// A process's capability table.
#[derive(Debug, Default)]
pub struct CapTable {
    slots: Vec<Option<Arc<Capability>>>,
}

impl CapTable {
    /// An empty table.
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Stores `cap` under the lowest free handle and returns the handle.
    pub fn insert(&mut self, cap: Arc<Capability>) -> Result<Handle, CapError> {
        let index = match self.slots.iter().position(Option::is_none) {
            Some(index) => index,
            None if self.slots.len() < MAX_HANDLES => {
                self.slots.push(None);
                self.slots.len() - 1
            }
            None => return Err(CapError::TableFull),
        };
        self.slots[index] = Some(cap);
        Ok(index as Handle + 1)
    }

    fn slot(&mut self, handle: Handle) -> Result<&mut Option<Arc<Capability>>, CapError> {
        let index = usize::try_from(handle.wrapping_sub(1)).map_err(|_| CapError::InvalidHandle)?;
        self.slots.get_mut(index).ok_or(CapError::InvalidHandle)
    }

    /// The capability under `handle`, if it has every right in `needed`.
    pub fn get(&mut self, handle: Handle, needed: Rights) -> Result<Arc<Capability>, CapError> {
        let cap = self.slot(handle)?.as_ref().ok_or(CapError::InvalidHandle)?;
        if cap.rights & needed != needed {
            return Err(CapError::MissingRight);
        }
        Ok(cap.clone())
    }

    /// Removes `handle` from the table.
    pub fn delete(&mut self, handle: Handle) -> Result<(), CapError> {
        self.slot(handle)?
            .take()
            .map(drop)
            .ok_or(CapError::InvalidHandle)
    }

    /// Handles in use.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// True if no handle is in use.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(rights: Rights) -> Arc<Capability> {
        Capability::new(Object::DebugConsole, rights)
    }

    #[test]
    fn handles_start_at_one_and_are_reused() {
        let mut t = CapTable::new();
        assert_eq!(t.insert(console(WRITE)), Ok(1));
        assert_eq!(t.insert(console(0)), Ok(2));
        assert_eq!(t.delete(1), Ok(()));
        assert_eq!(t.insert(console(WRITE)), Ok(1), "lowest free handle");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn invalid_handles_and_rights() {
        let mut t = CapTable::new();
        t.insert(console(WRITE)).unwrap();
        t.insert(console(GRANT)).unwrap();
        assert_eq!(
            t.get(0, 0).unwrap_err(),
            CapError::InvalidHandle,
            "0 is never valid"
        );
        assert_eq!(t.get(3, 0).unwrap_err(), CapError::InvalidHandle);
        assert_eq!(t.get(u64::MAX, 0).unwrap_err(), CapError::InvalidHandle);
        assert_eq!(t.get(2, WRITE).unwrap_err(), CapError::MissingRight);
        assert_eq!(t.get(1, WRITE).unwrap().object(), &Object::DebugConsole);
        assert_eq!(t.get(1, WRITE | GRANT).unwrap_err(), CapError::MissingRight);
    }

    #[test]
    fn delete_twice_and_full_table() {
        let mut t = CapTable::new();
        t.insert(console(WRITE)).unwrap();
        assert_eq!(t.delete(1), Ok(()));
        assert_eq!(t.delete(1), Err(CapError::InvalidHandle));
        assert_eq!(t.get(1, 0).unwrap_err(), CapError::InvalidHandle);
        assert_eq!(t.delete(0), Err(CapError::InvalidHandle));
        for _ in 0..MAX_HANDLES {
            t.insert(console(0)).unwrap();
        }
        assert_eq!(t.insert(console(0)), Err(CapError::TableFull));
    }
}
