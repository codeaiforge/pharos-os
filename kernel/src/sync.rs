//! Synchronization primitives for the kernel. No `unsafe`; unit-tested on the
//! host.

use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};

/// A spin lock that guards a resource outside Rust's memory, such as the
/// serial port. It holds no data, so it needs no `unsafe`.
///
/// Not interrupt-safe yet: if an interrupt handler on the same CPU waits for
/// a lock the interrupted code holds, it spins forever. Before interrupts are
/// enabled (M2.4), code holding a lock that handlers also use must disable
/// interrupts first.
pub struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Waits until the lock is free, then takes it.
    pub fn lock(&self) -> SpinGuard<'_> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            // Read-only wait, so waiting CPUs do not fight over the cache line.
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    /// Takes the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinGuard<'_>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinGuard { lock: self })
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Releases the lock whoever holds it. Only for paths where the holder
    /// will never run again, such as the panic handler on a single CPU.
    pub fn force_unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for SpinLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds a [`SpinLock`]; releases it when dropped.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::SpinLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn lock_and_release() {
        let lock = SpinLock::new();
        let guard = lock.lock();
        assert!(lock.is_locked());
        assert!(lock.try_lock().is_none(), "held lock cannot be taken twice");
        drop(guard);
        assert!(!lock.is_locked());
        assert!(lock.try_lock().is_some());
    }

    #[test]
    fn force_unlock_frees_a_held_lock() {
        let lock = SpinLock::new();
        let guard = lock.lock();
        lock.force_unlock();
        assert!(lock.try_lock().is_some());
        drop(guard);
    }

    #[test]
    fn excludes_concurrent_holders() {
        // Each thread does a non-atomic read-modify-write under the lock.
        // Without mutual exclusion, increments would be lost.
        static LOCK: SpinLock = SpinLock::new();
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let threads: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..10_000 {
                        let _guard = LOCK.lock();
                        let value = COUNTER.load(Ordering::Relaxed);
                        COUNTER.store(value + 1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(COUNTER.load(Ordering::Relaxed), 40_000);
    }
}
