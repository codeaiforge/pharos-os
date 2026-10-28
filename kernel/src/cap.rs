//! Capabilities (D-012 direction, syscalls-ipc.md): a reference to a kernel
//! object plus rights, held in a per-process table and named by handle.
//!
//! Granting a capability over IPC derives a child with the same or fewer
//! rights. The derivation tree makes revocation possible without the
//! holders' cooperation: [`Capability::revoke`] marks every descendant
//! revoked, and every lookup checks the mark (lazy invalidation).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::Fs;
use crate::ipc::Endpoint;
use crate::mm::raw::IrqMutex;

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
/// Open files (on a filesystem) or read them (on a file).
pub const READ: Rights = 1 << 4;
/// Map a device's BARs and allocate DMA buffers for it.
pub const MAP: Rights = 1 << 5;
/// Create interrupts for a device.
pub const IRQ: Rights = 1 << 6;
/// Read a device's PCI configuration space.
pub const CONFIG: Rights = 1 << 7;
/// Wait for an interrupt.
pub const WAIT: Rights = 1 << 8;

/// Badges are 24 bits (services.md).
pub const BADGE_MASK: u32 = 0xff_ffff;

/// Largest number of handles a process can hold.
// ponytail: fixed cap per process; make it a quota when processes need more.
pub const MAX_HANDLES: usize = 64;

/// A kernel object that capabilities refer to.
#[derive(Clone)]
pub enum Object {
    /// The kernel's serial debug console.
    DebugConsole,
    /// An IPC endpoint.
    Endpoint(Arc<Endpoint>),
    /// A mounted filesystem: with `READ`, opens files.
    Filesystem(Arc<Fs>),
    /// One file of a mounted filesystem: with `READ`, reads it.
    File {
        fs: Arc<Fs>,
        file: pharos_fs::FileId,
    },
    /// One PCI function handed to a driver (drivers.md).
    Device(Arc<crate::device::DeviceHandle>),
    /// A process started with `spawn`: observe how it ended (services.md).
    #[cfg(target_os = "none")]
    Process(Arc<crate::process::ProcessRecord>),
    /// One MSI-X entry of a device (drivers.md).
    #[cfg(target_os = "none")]
    Interrupt(Arc<crate::irq::Irq>),
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugConsole => f.write_str("DebugConsole"),
            Self::Endpoint(e) => write!(f, "Endpoint({:p})", Arc::as_ptr(e)),
            Self::Filesystem(fs) => write!(f, "Filesystem({:p})", Arc::as_ptr(fs)),
            Self::File { fs, file } => write!(f, "File({:p}, {file:?})", Arc::as_ptr(fs)),
            Self::Device(d) => write!(f, "{d:?}"),
            #[cfg(target_os = "none")]
            Self::Process(p) => write!(f, "Process({})", p.id),
            #[cfg(target_os = "none")]
            Self::Interrupt(i) => write!(f, "{i:?}"),
        }
    }
}

/// A capability: an object, the rights its holder has on it, and the
/// capabilities derived from it.
pub struct Capability {
    object: Object,
    rights: Rights,
    /// Set once when passed on from a capability with badge 0; delivered
    /// with every message sent through it.
    badge: u32,
    revoked: AtomicBool,
    children: IrqMutex<Vec<Weak<Capability>>>,
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capability")
            .field("object", &self.object)
            .field("rights", &self.rights)
            .field("badge", &self.badge)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl Capability {
    /// A new (original) capability.
    pub fn new(object: Object, rights: Rights) -> Arc<Self> {
        Self::with_badge(object, rights, 0)
    }

    /// A child capability for the same object with this one's rights
    /// limited to `mask`, recorded in the derivation tree.
    pub fn derive(self: &Arc<Self>, mask: Rights) -> Arc<Self> {
        self.derive_badged(mask, 0)
    }

    /// As [`Self::derive`], and if this capability has badge 0, the child
    /// gets `badge` (24 bits). A badged capability keeps its badge: it can
    /// be narrowed and passed on, never re-badged.
    pub fn derive_badged(self: &Arc<Self>, mask: Rights, badge: u32) -> Arc<Self> {
        let badge = if self.badge == 0 {
            badge & BADGE_MASK
        } else {
            self.badge
        };
        self.adopt(Self::with_badge(
            self.object.clone(),
            self.rights & mask,
            badge,
        ))
    }

    fn with_badge(object: Object, rights: Rights, badge: u32) -> Arc<Self> {
        Arc::new(Self {
            object,
            rights,
            badge,
            revoked: AtomicBool::new(false),
            children: IrqMutex::new(Vec::new()),
        })
    }

    /// A child capability for a different `object` reached through this
    /// one (a file opened through a filesystem, an interrupt created for a
    /// device) with `rights`, which the caller chooses for the new object.
    /// Revoking this capability revokes the child too.
    pub fn derive_object(self: &Arc<Self>, object: Object, rights: Rights) -> Arc<Self> {
        self.adopt(Self::new(object, rights))
    }

    /// Records `child` in the derivation tree (revoked at once if this
    /// capability is).
    fn adopt(&self, child: Arc<Self>) -> Arc<Self> {
        if self.is_revoked() {
            child.revoked.store(true, Ordering::Relaxed);
        }
        let mut children = self.children.lock();
        children.retain(|c| c.strong_count() > 0);
        children.push(Arc::downgrade(&child));
        drop(children);
        child
    }

    /// Revokes every capability derived from this one, at any depth, and
    /// returns how many were newly revoked. This one stays valid.
    pub fn revoke(&self) -> usize {
        let mut pending: Vec<Weak<Capability>> = core::mem::take(&mut *self.children.lock());
        let mut count = 0;
        while let Some(child) = pending.pop() {
            let Some(child) = child.upgrade() else {
                continue;
            };
            if !child.revoked.swap(true, Ordering::Relaxed) {
                count += 1;
            }
            pending.append(&mut child.children.lock());
        }
        count
    }

    /// True once an ancestor revoked it.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Relaxed)
    }

    /// The object referred to.
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// The rights held.
    pub fn rights(&self) -> Rights {
        self.rights
    }

    /// The badge (0 if none).
    pub fn badge(&self) -> u32 {
        self.badge
    }
}

/// Why a capability lookup failed.
#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// No capability under this handle.
    InvalidHandle,
    /// The capability was revoked.
    Revoked,
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
        if cap.is_revoked() {
            return Err(CapError::Revoked);
        }
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
        assert!(matches!(
            t.get(1, WRITE).unwrap().object(),
            Object::DebugConsole
        ));
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

    #[test]
    fn derive_limits_rights() {
        let parent = console(WRITE | GRANT);
        let child = parent.derive(WRITE | SEND);
        assert_eq!(child.rights(), WRITE, "never more than the parent");
        assert!(!child.is_revoked());
    }

    #[test]
    fn revoke_reaches_every_descendant_and_spares_the_holder() {
        let root = console(WRITE | GRANT);
        let a = root.derive(WRITE | GRANT);
        let b = a.derive(WRITE);
        let c = root.derive(WRITE);
        let mut t = CapTable::new();
        let hb = t.insert(b.clone()).unwrap();
        assert_eq!(root.revoke(), 3);
        assert!(a.is_revoked() && b.is_revoked() && c.is_revoked());
        assert!(!root.is_revoked(), "the revoker keeps its capability");
        assert_eq!(t.get(hb, WRITE).unwrap_err(), CapError::Revoked);
        assert_eq!(
            t.delete(hb),
            Ok(()),
            "a revoked handle can still be deleted"
        );
        assert_eq!(root.revoke(), 0, "nothing left to revoke");
        let d = root.derive(WRITE);
        assert!(!d.is_revoked(), "new grants after a revocation work");
    }

    #[test]
    fn revoking_a_middle_node_spares_siblings_and_ancestors() {
        let root = console(WRITE | GRANT);
        let a = root.derive(WRITE | GRANT);
        let sibling = root.derive(WRITE);
        let b = a.derive(WRITE);
        assert_eq!(a.revoke(), 1);
        assert!(b.is_revoked() && !a.is_revoked() && !sibling.is_revoked());
        let from_revoked = b.derive(WRITE);
        assert!(
            from_revoked.is_revoked(),
            "children of revoked capabilities are revoked"
        );
    }

    #[test]
    fn derived_objects_follow_revocation() {
        let parent = console(READ | GRANT | WRITE);
        let other = parent.derive_object(Object::DebugConsole, READ | GRANT);
        assert_eq!(other.rights(), READ | GRANT);
        let grandchild = other.derive(READ);
        assert_eq!(parent.revoke(), 2);
        assert!(other.is_revoked() && grandchild.is_revoked());
    }

    #[test]
    fn badges_are_set_once_kept_when_narrowed_and_never_changed() {
        let root = console(WRITE | GRANT);
        assert_eq!(root.badge(), 0);
        let a = root.derive_badged(WRITE | GRANT, 7);
        assert_eq!((a.badge(), a.rights()), (7, WRITE | GRANT));
        let narrowed = a.derive(WRITE);
        assert_eq!(narrowed.badge(), 7, "kept when narrowed");
        let rebadged = a.derive_badged(WRITE, 9);
        assert_eq!(rebadged.badge(), 7, "never re-badged");
        assert_eq!(
            root.derive_badged(WRITE, 0x1ff_ffff).badge(),
            BADGE_MASK,
            "24 bits"
        );
        assert_eq!(root.derive(WRITE).badge(), 0, "plain derive sets none");
        assert_eq!(root.revoke(), 3, "badged children are in the tree");
        assert!(a.is_revoked() && narrowed.is_revoked() && rebadged.is_revoked());
    }

    #[test]
    fn dropped_children_are_skipped() {
        let root = console(WRITE | GRANT);
        drop(root.derive(WRITE));
        let kept = root.derive(WRITE);
        assert_eq!(root.revoke(), 1);
        assert!(kept.is_revoked());
    }
}
