//! Raw memory for the memory manager (decision D-005): direct-map slices and
//! a lock that owns its data. One of the few modules where `unsafe` is
//! allowed (AGENTS.md); everything else in `mm` is safe Rust.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::{disable_interrupts, enable_interrupts, interrupts_enabled};
use crate::sync::{SpinGuard, SpinLock};

/// A spin lock that owns `T` and disables interrupts while held (restoring
/// the previous state on release), so an interrupt handler never waits for a
/// holder it interrupted.
pub struct IrqMutex<T> {
    lock: SpinLock,
    value: UnsafeCell<T>,
}

// SAFETY: access to `value` is serialized by `lock`; `T: Send` lets the value
// be used from whichever context holds the lock.
unsafe impl<T: Send> Sync for IrqMutex<T> {}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: SpinLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        let interrupts_were_enabled = interrupts_enabled();
        disable_interrupts();
        let guard = self.lock.lock();
        IrqMutexGuard {
            mutex: self,
            guard: Some(guard),
            interrupts_were_enabled,
        }
    }
}

pub struct IrqMutexGuard<'a, T> {
    mutex: &'a IrqMutex<T>,
    /// Always `Some` until `drop`, which releases it before re-enabling
    /// interrupts.
    guard: Option<SpinGuard<'a>>,
    interrupts_were_enabled: bool,
}

impl<T> Deref for IrqMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock, so no other reference exists.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for IrqMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and `&mut self` makes this the only access.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for IrqMutexGuard<'_, T> {
    fn drop(&mut self) {
        // Release the spin lock first, then restore interrupts, so no
        // interrupt can arrive while this CPU still holds the lock.
        drop(self.guard.take());
        if self.interrupts_were_enabled {
            enable_interrupts();
        }
    }
}

static BITMAP_STORAGE_TAKEN: AtomicBool = AtomicBool::new(false);

/// The frame allocator's bitmap storage: `words` `u64`s at physical `phys`,
/// reached through the direct map at `hhdm`. Zeroed by the allocator.
///
/// May be called once; later calls return `None`. The caller must pass a
/// range inside one usable memory-map region that nothing else uses (the
/// frame allocator reserves it right after).
pub(crate) fn bitmap_storage(hhdm: u64, phys: u64, words: usize) -> Option<&'static mut [u64]> {
    if BITMAP_STORAGE_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: the range is usable RAM (caller contract) mapped writable by
    // the direct map, 8-byte aligned (frame-aligned `phys`), and taken only
    // once (flag above), so this is the only reference to it. `u64` has no
    // invalid bit patterns, so whatever the memory holds is a valid value.
    Some(unsafe { core::slice::from_raw_parts_mut((hhdm + phys) as *mut u64, words) })
}
