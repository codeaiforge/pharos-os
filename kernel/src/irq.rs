//! Device interrupts for user-space drivers (M2.9, issue #54,
//! [drivers.md](../../docs/architecture/drivers.md)).
//!
//! An [`Irq`] is the object behind an `Interrupt` capability: one MSI-X
//! table entry of one device, routed to one of the 16 vectors 48–63. The
//! kernel programs the table entry (drivers never map the table), so a
//! driver cannot aim interrupts anywhere else. The handler only counts,
//! wakes the one waiting thread, and sends EOI; the driver acknowledges at
//! the device. Dropping the object masks the entry and frees the vector.
//!
//! [`Vectors`] is the bookkeeping, host-tested; the rest touches hardware.
//! Safe Rust.

use crate::arch::x86_64::idt::DEVICE_VECTORS;
use crate::mm::raw::IrqMutex;

/// Most vectors one device may hold, so one driver cannot take all 16.
pub const MAX_PER_DEVICE: usize = 4;

/// A thread ID (`sched::TaskId`).
pub type TaskId = u64;

/// Why an interrupt cannot be created or waited on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqError {
    /// The device has no MSI-X, or no table entry with that index.
    NoEntry,
    /// The entry already has an interrupt, or a thread already waits.
    InUse,
    /// All 16 vectors are taken, or the device holds [`MAX_PER_DEVICE`].
    NoVector,
    /// The table entry could not be reached.
    Hardware,
    /// No interrupt arrived before the deadline.
    TimedOut,
}

#[derive(Clone, Copy, Default)]
struct Slot {
    /// `(device identity, MSI-X entry)` while allocated.
    owner: Option<(usize, u16)>,
    /// Interrupts since the last wait returned.
    pending: u64,
    waiter: Option<TaskId>,
    /// Notification bits, once bound to an endpoint with `irq_notify`.
    bound: Option<u32>,
}

/// The device-interrupt vectors: which are allocated, their counts, and
/// their waiters.
pub struct Vectors {
    slots: [Slot; DEVICE_VECTORS],
    delivered: u64,
    spurious: u64,
    woken: u64,
}

impl Vectors {
    /// No vector allocated.
    pub const fn new() -> Self {
        const FREE: Slot = Slot {
            owner: None,
            pending: 0,
            waiter: None,
            bound: None,
        };
        Self {
            slots: [FREE; DEVICE_VECTORS],
            delivered: 0,
            spurious: 0,
            woken: 0,
        }
    }

    /// Allocates a vector index for MSI-X entry `entry` of `device`.
    pub fn alloc(&mut self, device: usize, entry: u16) -> Result<usize, IrqError> {
        if self.slots.iter().any(|s| s.owner == Some((device, entry))) {
            return Err(IrqError::InUse);
        }
        let held = self
            .slots
            .iter()
            .filter(|s| s.owner.is_some_and(|(d, _)| d == device));
        if held.count() >= MAX_PER_DEVICE {
            return Err(IrqError::NoVector);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.owner.is_none())
            .ok_or(IrqError::NoVector)?;
        self.slots[index] = Slot {
            owner: Some((device, entry)),
            ..Slot::default()
        };
        Ok(index)
    }

    /// Frees vector `index`.
    pub fn free(&mut self, index: usize) {
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Slot::default();
        }
    }

    /// Records an interrupt on vector `index`; says what to do about it.
    pub fn fire(&mut self, index: usize) -> Fired {
        match self.slots.get_mut(index) {
            Some(slot) if slot.owner.is_some() => {
                self.delivered += 1;
                if let Some(bits) = slot.bound {
                    return Fired::Notify(bits);
                }
                slot.pending += 1;
                match slot.waiter.take() {
                    Some(task) => {
                        self.woken += 1;
                        Fired::Wake(task)
                    }
                    None => Fired::Nothing,
                }
            }
            _ => {
                self.spurious += 1;
                Fired::Nothing
            }
        }
    }

    /// Binds vector `index` to notification `bits`: from now on each
    /// interrupt sets them instead of counting for a waiter. Refused while a
    /// thread waits or once bound.
    pub fn bind(&mut self, index: usize, bits: u32) -> Result<(), IrqError> {
        let slot = self.slots.get_mut(index).ok_or(IrqError::NoEntry)?;
        if slot.waiter.is_some() || slot.bound.is_some() {
            return Err(IrqError::InUse);
        }
        slot.bound = Some(bits);
        Ok(())
    }

    /// Starts a wait by `me` on vector `index`: returns the interrupts that
    /// arrived since the last wait, or `None` after recording `me` as the
    /// waiter (the caller then blocks and calls [`Self::take`] when woken).
    pub fn wait(&mut self, index: usize, me: TaskId) -> Result<Option<u64>, IrqError> {
        let slot = self.slots.get_mut(index).ok_or(IrqError::NoEntry)?;
        if slot.waiter.is_some() || slot.bound.is_some() {
            return Err(IrqError::InUse);
        }
        if slot.pending > 0 {
            return Ok(Some(core::mem::take(&mut slot.pending)));
        }
        slot.waiter = Some(me);
        Ok(None)
    }

    /// Clears `me` as the waiter on vector `index` (its wait timed out).
    pub fn cancel(&mut self, index: usize, me: TaskId) {
        if let Some(slot) = self.slots.get_mut(index).filter(|s| s.waiter == Some(me)) {
            slot.waiter = None;
        }
    }

    /// Takes the interrupts counted on vector `index`.
    pub fn take(&mut self, index: usize) -> u64 {
        self.slots
            .get_mut(index)
            .map_or(0, |s| core::mem::take(&mut s.pending))
    }

    /// Vectors allocated.
    pub fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.owner.is_some()).count()
    }
}

/// What an interrupt calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fired {
    /// Wake this thread, waiting in `irq_wait`.
    Wake(TaskId),
    /// Set these bits on the bound endpoint.
    Notify(u32),
    /// Nothing (counted, or spurious).
    Nothing,
}

impl Default for Vectors {
    fn default() -> Self {
        Self::new()
    }
}

static VECTORS: IrqMutex<Vectors> = IrqMutex::new(Vectors::new());

/// Device-interrupt counts since boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Interrupts on allocated vectors.
    pub delivered: u64,
    /// Interrupts on unallocated device vectors.
    pub spurious: u64,
    /// Interrupts that woke a blocked waiter.
    pub woken: u64,
    /// Vectors allocated now.
    pub in_use: usize,
}

/// Device-interrupt counts since boot.
pub fn stats() -> Stats {
    let v = VECTORS.lock();
    Stats {
        delivered: v.delivered,
        spurious: v.spurious,
        woken: v.woken,
        in_use: v.in_use(),
    }
}

/// Called by the IDT dispatcher for vector `48 + index`, with interrupts
/// disabled.
pub fn on_vector(index: usize) {
    let fired = VECTORS.lock().fire(index);
    crate::arch::x86_64::apic::eoi();
    match fired {
        Fired::Wake(task) => {
            crate::sched::wake(task);
        }
        #[cfg(target_os = "none")]
        Fired::Notify(bits) => kernel::notify(index, bits),
        _ => {}
    }
}

#[cfg(target_os = "none")]
pub use kernel::{Irq, wait};

#[cfg(target_os = "none")]
mod kernel {
    use alloc::sync::Arc;

    use super::*;
    use crate::arch::x86_64::idt::FIRST_DEVICE_VECTOR;
    use crate::arch::x86_64::{apic, pci as hw};
    use crate::device::DeviceHandle;
    use crate::ipc::Endpoint;
    use crate::mm::raw::IrqMutex;
    use crate::pci::Bar;
    use crate::sched;

    /// The endpoint each bound vector notifies (`irq_notify`). Kept beside
    /// [`VECTORS`] because the host-tested table holds no kernel objects.
    static BINDINGS: IrqMutex<[Option<Arc<Endpoint>>; DEVICE_VECTORS]> =
        IrqMutex::new([const { None }; DEVICE_VECTORS]);

    /// Sets `bits` on the endpoint bound to vector `index` (interrupt
    /// context: no allocation; the binding outlives this call because only
    /// the interrupt's drop removes it, with interrupts disabled).
    pub(super) fn notify(index: usize, bits: u32) {
        let endpoint = BINDINGS.lock().get(index).cloned().flatten();
        if let Some(endpoint) = endpoint {
            crate::ipc::notify(&endpoint, bits);
        }
    }

    /// One MSI-X entry of a device, routed to a vector.
    pub struct Irq {
        /// Kept alive (and enabled) while the interrupt exists.
        pub device: Arc<DeviceHandle>,
        pub entry: u16,
        index: usize,
        /// Physical address of the table entry.
        table_entry: u64,
    }

    impl core::fmt::Debug for Irq {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "Irq({:?}, entry {}, vector {})",
                self.device,
                self.entry,
                self.vector()
            )
        }
    }

    impl Irq {
        /// Routes MSI-X entry `entry` of `device` to a free vector,
        /// unmasks it, and enables MSI-X on the device.
        pub fn create(device: Arc<DeviceHandle>, entry: u16) -> Result<Arc<Self>, IrqError> {
            let msix = device.pci.msix.ok_or(IrqError::NoEntry)?;
            if entry >= msix.table_size {
                return Err(IrqError::NoEntry);
            }
            let Some(Some(Bar::Memory { base, .. })) =
                device.pci.bars.get(usize::from(msix.table_bar))
            else {
                return Err(IrqError::NoEntry);
            };
            let table_entry = base + u64::from(msix.table_offset) + 16 * u64::from(entry);
            let owner = Arc::as_ptr(&device) as usize;
            let index = VECTORS.lock().alloc(owner, entry)?;
            // From here on, dropping `irq` masks the entry and frees the vector.
            let irq = Arc::new(Self {
                device,
                entry,
                index,
                table_entry,
            });
            hw::set_msix_entry(table_entry, Some((irq.vector(), apic::id())))
                .map_err(|_| IrqError::Hardware)?;
            hw::set_msix_control(irq.device.pci.address, msix.offset, true, false);
            Ok(irq)
        }

        /// The CPU vector (48–63).
        pub fn vector(&self) -> u8 {
            FIRST_DEVICE_VECTOR + self.index as u8
        }

        /// True if the table entry is masked (tests).
        pub fn masked(&self) -> bool {
            hw::msix_entry_masked(self.table_entry)
        }

        /// Physical address of the table entry (tests).
        pub fn table_entry(&self) -> u64 {
            self.table_entry
        }
    }

    impl Irq {
        /// Binds this interrupt to `bits` on `endpoint` (`irq_notify`).
        pub fn bind(&self, endpoint: Arc<Endpoint>, bits: u32) -> Result<(), IrqError> {
            VECTORS.lock().bind(self.index, bits)?;
            BINDINGS.lock()[self.index] = Some(endpoint);
            Ok(())
        }
    }

    impl Drop for Irq {
        fn drop(&mut self) {
            // Mask first, so the vector is never raised once it is free.
            let _ = hw::set_msix_entry(self.table_entry, None);
            let binding = BINDINGS.lock()[self.index].take();
            VECTORS.lock().free(self.index);
            drop(binding);
        }
    }

    /// Waits for `irq` on the running thread until tick `deadline`
    /// (`None`: forever); returns the interrupts since the last wait (at
    /// least 1). Runs inside a system call, with interrupts disabled until
    /// the thread blocks, so no wake is missed. An interrupt that arrives
    /// after the deadline but before this thread runs again still counts;
    /// a timeout leaves the count for the next wait.
    pub fn wait(irq: &Irq, deadline: Option<u64>) -> Result<u64, IrqError> {
        let me = sched::current_id().unwrap_or(0);
        let started = VECTORS.lock().wait(irq.index, me)?;
        if let Some(count) = started {
            return Ok(count);
        }
        let woken = sched::block_until(deadline);
        let mut vectors = VECTORS.lock();
        match vectors.take(irq.index) {
            0 if !woken => {
                vectors.cancel(irq.index, me);
                Err(IrqError::TimedOut)
            }
            count => Ok(count.max(1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_wait_frees_the_slot_for_the_next() {
        let mut v = Vectors::new();
        let i = v.alloc(1, 0).unwrap();
        assert_eq!(v.wait(i, 7), Ok(None));
        v.cancel(i, 8);
        assert_eq!(v.wait(i, 8), Err(IrqError::InUse), "only 7's own wait");
        v.cancel(i, 7);
        assert_eq!(v.fire(i), Fired::Nothing, "counted, nobody to wake");
        assert_eq!(v.wait(i, 7), Ok(Some(1)), "the next wait gets it");
    }

    #[test]
    fn vectors_are_allocated_once_per_entry_and_freed() {
        let mut v = Vectors::new();
        assert_eq!(v.alloc(1, 0), Ok(0));
        assert_eq!(v.alloc(1, 0), Err(IrqError::InUse), "same entry");
        assert_eq!(v.alloc(1, 1), Ok(1));
        assert_eq!(v.alloc(2, 0), Ok(2), "another device");
        v.free(0);
        assert_eq!(v.in_use(), 2);
        assert_eq!(v.alloc(1, 0), Ok(0), "lowest free vector");
        assert_eq!(v.alloc(1, 2), Ok(3));
        assert_eq!(v.alloc(1, 3), Ok(4), "4 for device 1");
        assert_eq!(v.alloc(1, 4), Err(IrqError::NoVector), "per-device limit");
        // 5 in use; 10 more from three devices.
        for (device, entries) in [(10, 4), (11, 4), (12, 2)] {
            for entry in 0..entries {
                v.alloc(device, entry).unwrap();
            }
        }
        assert_eq!(v.in_use(), DEVICE_VECTORS - 1);
        assert_eq!(v.alloc(3, 0), Ok(15));
        assert_eq!(v.alloc(4, 0), Err(IrqError::NoVector), "all 16 taken");
        v.free(99); // out of range: ignored
    }

    #[test]
    fn interrupts_are_counted_and_wake_the_waiter() {
        let mut v = Vectors::new();
        let i = v.alloc(1, 0).unwrap();
        assert_eq!(v.wait(i, 7), Ok(None), "nothing yet: 7 waits");
        assert_eq!(v.wait(i, 8), Err(IrqError::InUse), "one waiter");
        assert_eq!(v.bind(i, 1), Err(IrqError::InUse), "not while waiting");
        assert_eq!(v.fire(i), Fired::Wake(7));
        assert_eq!(v.fire(i), Fired::Nothing, "already woken");
        assert_eq!((v.delivered, v.woken), (2, 1));
        assert_eq!(v.take(i), 2);
        assert_eq!(v.take(i), 0);
        v.fire(i);
        assert_eq!(v.wait(i, 7), Ok(Some(1)), "returns at once");
        assert_eq!(v.wait(i, 7), Ok(None));
    }

    #[test]
    fn bound_vectors_notify_instead_of_counting() {
        let mut v = Vectors::new();
        let i = v.alloc(1, 0).unwrap();
        assert_eq!(v.bind(i, 1 << 5), Ok(()));
        assert_eq!(v.bind(i, 1), Err(IrqError::InUse), "bound once");
        assert_eq!(v.wait(i, 7), Err(IrqError::InUse), "no irq_wait once bound");
        assert_eq!(v.fire(i), Fired::Notify(1 << 5));
        assert_eq!(v.take(i), 0, "nothing counted for a waiter");
        v.free(i);
        let j = v.alloc(2, 0).unwrap();
        assert_eq!(v.fire(j), Fired::Nothing, "a new owner starts unbound");
    }

    #[test]
    fn unallocated_vectors_count_as_spurious() {
        let mut v = Vectors::new();
        assert_eq!(v.fire(3), Fired::Nothing);
        assert_eq!(v.fire(99), Fired::Nothing);
        let i = v.alloc(1, 0).unwrap();
        v.wait(i, 5).unwrap();
        v.free(i);
        assert_eq!(v.fire(i), Fired::Nothing, "freed: the old waiter is gone");
        assert_eq!((v.delivered, v.spurious), (0, 3));
    }
}
