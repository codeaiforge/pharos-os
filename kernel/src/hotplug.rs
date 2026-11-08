//! Native PCIe hotplug (M4.4, D-029, drivers.md): each hot-plug capable
//! slot of a bridge on bus 0, polled on the timer; a device that arrives
//! gets BARs inside its port's windows and is handed to `init`, and one
//! the user removes is revoked before its slot is powered off.
//!
//! The decoding, BAR assignment, and the slot state machine are safe Rust
//! and host-tested. Register access is in `arch::x86_64::pci`; the slots,
//! the tick, and the system calls are in its `kernel` module.

use crate::pci::Bar;

/// Most slots handled; more are logged and ignored.
pub const MAX_SLOTS: usize = 8;
/// Ticks between polls (100 ms at 100 Hz).
pub const POLL_TICKS: u64 = 10;
/// How long a powered slot may take to show its function, and the least
/// time between two arrivals in one slot, in ticks (1 s).
pub const POWER_TICKS: u64 = 100;

/// Slot Status bits.
pub mod status {
    pub const BUTTON: u16 = 1;
    pub const PRESENCE_CHANGED: u16 = 1 << 3;
    pub const COMMAND_DONE: u16 = 1 << 4;
    pub const PRESENT: u16 = 1 << 6;
    pub const LINK_CHANGED: u16 = 1 << 8;
    /// The bits cleared by writing them back.
    pub const EVENTS: u16 = BUTTON | PRESENCE_CHANGED | COMMAND_DONE | LINK_CHANGED | 0b110;
}

/// Slot Control values the kernel writes: events the slot reports
/// (button, presence; never an interrupt), indicators, and power.
pub mod control {
    const ENABLES: u16 = 1 | 1 << 3;
    const ATTENTION_OFF: u16 = 0b11 << 6;
    const ATTENTION_BLINK: u16 = 0b10 << 6;
    const POWER_LED_ON: u16 = 0b01 << 8;
    const POWER_LED_OFF: u16 = 0b11 << 8;
    const POWER_OFF: u16 = 1 << 10;
    pub const ON: u16 = ENABLES | ATTENTION_OFF | POWER_LED_ON;
    pub const OFF: u16 = ENABLES | ATTENTION_OFF | POWER_LED_OFF | POWER_OFF;
    /// Powered, with the attention indicator blinking: removal refused.
    pub const KEPT: u16 = ENABLES | ATTENTION_BLINK | POWER_LED_ON;
}

/// A slot is handled if its port's PCI Express capability says a slot is
/// implemented (`caps`: the capability's first dword, so the PCI Express
/// Capabilities register is bits 16–31) and Slot Capabilities says
/// hot-plug capable.
pub fn handled(caps: u32, slot_caps: u32) -> bool {
    caps & 1 << 24 != 0 && slot_caps & 1 << 6 != 0
}

/// True if the slot signals command completion (Slot Capabilities bit 18
/// clear), so writes wait for it.
pub fn signals_completion(slot_caps: u32) -> bool {
    slot_caps & 1 << 18 == 0
}

/// An address window of a bridge: `base` to `limit`, inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub base: u64,
    pub limit: u64,
}

impl Window {
    fn open(base: u64, limit: u64) -> Option<Self> {
        (base <= limit).then_some(Self { base, limit })
    }

    /// True if it overlaps `[b, b + len)`.
    pub fn overlaps(&self, b: u64, len: u64) -> bool {
        b <= self.limit && self.base < b.saturating_add(len)
    }
}

/// The memory window from the bridge's register at `0x20`; `None` if
/// closed.
pub fn memory_window(reg: u32) -> Option<Window> {
    let base = u64::from(reg & 0xfff0) << 16;
    let limit = u64::from(reg & 0xfff0_0000) | 0xf_ffff;
    Window::open(base, limit)
}

/// The prefetchable window from the registers at `0x24`, `0x28` (upper
/// base), and `0x2c` (upper limit); the upper halves count only for a
/// 64-bit window.
pub fn prefetchable_window(reg: u32, upper_base: u32, upper_limit: u32) -> Option<Window> {
    let wide = reg & 0xf == 1;
    let (ub, ul) = if wide {
        (u64::from(upper_base) << 32, u64::from(upper_limit) << 32)
    } else {
        (0, 0)
    };
    let base = ub | u64::from(reg & 0xfff0) << 16;
    let limit = ul | u64::from(reg & 0xfff0_0000) | 0xf_ffff;
    Window::open(base, limit)
}

/// Why a device gets no BARs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoFit {
    /// A BAR has no window it may go in, or does not fit in it.
    Window,
}

/// Bases for each memory BAR of `bars` (decoded from probes, so their
/// bases are meaningless): largest first, each aligned to its size, in a
/// bump allocation from each window's base. A 64-bit prefetchable BAR goes
/// in the prefetchable window, a 32-bit prefetchable one there only if the
/// window is below 4 GiB, everything else in the memory window (always
/// below 4 GiB). I/O BARs get nothing: no window has ports.
pub fn assign(
    bars: &[Option<Bar>; 6],
    memory: Option<Window>,
    prefetchable: Option<Window>,
) -> Result<[Option<u64>; 6], NoFit> {
    let mut order: [(usize, u64, bool, bool); 6] = [(0, 0, false, false); 6];
    let mut n = 0;
    for (i, bar) in bars.iter().enumerate() {
        if let Some(Bar::Memory {
            size,
            prefetchable,
            wide,
            ..
        }) = *bar
        {
            order[n] = (i, size, prefetchable, wide);
            n += 1;
        }
    }
    let order = &mut order[..n];
    order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut next = [memory.map(|w| w.base), prefetchable.map(|w| w.base)];
    let mut out = [None; 6];
    for &(i, size, pref, wide) in order.iter() {
        let low_pref = prefetchable.is_some_and(|w| w.limit < 1 << 32);
        let which = usize::from(pref && (wide || low_pref) && prefetchable.is_some());
        let window = [memory, prefetchable][which].ok_or(NoFit::Window)?;
        let at = next[which].ok_or(NoFit::Window)?;
        if size == 0 || !size.is_power_of_two() {
            return Err(NoFit::Window);
        }
        let base = at.checked_add(size - 1).ok_or(NoFit::Window)? & !(size - 1);
        let end = base.checked_add(size - 1).ok_or(NoFit::Window)?;
        if end > window.limit {
            return Err(NoFit::Window);
        }
        out[i] = Some(base);
        next[which] = end.checked_add(1);
    }
    Ok(out)
}

/// A slot's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Powered off; `last` is the tick of its last arrival.
    Empty { last: Option<u64> },
    /// Powered on at tick `since`; waiting for the function to appear.
    Powering { since: u64 },
    /// A device runs and `init` has it.
    Occupied,
    /// The user pressed the button; `init` is asked.
    Removing,
    /// Occupied since boot: its device was found by enumeration and given
    /// out as a boot device, so the slot is left alone.
    Fixed,
}

/// What the kernel does for a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    PowerOn,
    PowerOff,
    /// Assign BARs, scan, and hand the device to `init` (if that fails,
    /// [`failed`] gives the next state).
    Probe,
    /// Revoke the device, then power off.
    Revoke,
    /// Blink the attention indicator: removal refused.
    Keep,
}

/// What `init` hears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    Added = 1,
    Remove = 2,
    Removed = 3,
}

/// The next state, what to do, and what to tell `init`.
pub type Step = (State, Option<Act>, Option<Event>);

/// One step of the slot in `state` with Slot Status `sta` (its event
/// bits as read before clearing them), `present` whether its function
/// answers configuration reads, at tick `now`.
pub fn step(state: State, sta: u16, present: bool, now: u64) -> Step {
    use status::*;
    let card = sta & PRESENT != 0;
    let event = sta & (BUTTON | PRESENCE_CHANGED) != 0;
    match state {
        State::Empty { last } => {
            let rested = last.is_none_or(|l| now.saturating_sub(l) >= POWER_TICKS);
            if card && event && rested {
                (State::Powering { since: now }, Some(Act::PowerOn), None)
            } else {
                (state, None, None)
            }
        }
        State::Powering { since } => {
            if !card || now.saturating_sub(since) > POWER_TICKS {
                (
                    State::Empty { last: Some(since) },
                    Some(Act::PowerOff),
                    None,
                )
            } else if present {
                (State::Occupied, Some(Act::Probe), Some(Event::Added))
            } else {
                (state, None, None)
            }
        }
        State::Occupied if !card => (
            State::Empty { last: None },
            Some(Act::Revoke),
            Some(Event::Removed),
        ),
        State::Occupied if sta & BUTTON != 0 => (State::Removing, None, Some(Event::Remove)),
        State::Removing if !card => (
            State::Empty { last: None },
            Some(Act::Revoke),
            Some(Event::Removed),
        ),
        State::Occupied | State::Removing | State::Fixed => (state, None, None),
    }
}

/// The state after a [`Act::Probe`] that failed (no fit, or the function
/// still in use): powered off, counted as an arrival.
pub fn failed(now: u64) -> Step {
    (State::Empty { last: Some(now) }, Some(Act::PowerOff), None)
}

/// `init`'s answer to [`Event::Remove`]; `None` if the slot is not
/// [`State::Removing`].
pub fn answer(state: State, release: bool) -> Option<Step> {
    match (state, release) {
        (State::Removing, true) => Some((
            State::Empty { last: None },
            Some(Act::Revoke),
            Some(Event::Removed),
        )),
        (State::Removing, false) => Some((State::Occupied, Some(Act::Keep), None)),
        _ => None,
    }
}

/// `slot_next`'s value: slot index (bits 0–7, for `slot_answer`), event
/// (8–15), handle (16–23; `init`'s table holds 64), the slot's physical
/// number (24–31, what the user sees), PCI ID (32–63, vendor in the low
/// half).
pub fn encode(slot: usize, event: Event, handle: u64, number: u16, id: u32) -> u64 {
    (slot as u64 & 0xff)
        | (event as u64) << 8
        | (handle & 0xff) << 16
        | u64::from(number as u8) << 24
        | u64::from(id) << 32
}

#[cfg(target_os = "none")]
pub use kernel::{answer_slot, find, next, notify_on, slots, tick};

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::pci::{self as hw, Address};
    use crate::cap::{CONFIG, Capability, GRANT, IRQ, MAP, Object};
    use crate::device::DeviceHandle;
    use crate::ipc::Endpoint;
    use crate::mm::raw::IrqMutex;
    use crate::{kprintln, pci, process, sched};
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    struct Slot {
        port: Address,
        /// The PCI Express capability's offset.
        cap: u8,
        number: u16,
        secondary: u8,
        memory: Option<Window>,
        prefetchable: Option<Window>,
        completion: bool,
        state: State,
        /// The device and the capability `init`'s is derived from.
        device: Option<(Arc<pci::Device>, Arc<Capability>)>,
    }

    impl Slot {
        fn function(&self) -> Address {
            Address {
                bus: self.secondary,
                device: 0,
                function: 0,
            }
        }

        fn status(&self) -> (u16, u16) {
            let v = hw::read32(self.port, self.cap + 0x18);
            (v as u16, (v >> 16) as u16)
        }

        /// Writes Slot Control, clearing `clear` in Slot Status, and waits
        /// (a bounded spin) for the command to complete.
        fn write(&self, control: u16, clear: u16) {
            hw::write_slot(self.port, self.cap, control, clear);
            if !self.completion {
                return;
            }
            // ponytail: a spin of up to 100,000 reads (QEMU completes at
            // once); a timer wait if real hardware needs longer.
            for _ in 0..100_000 {
                if self.status().1 & status::COMMAND_DONE != 0 {
                    hw::write_slot(self.port, self.cap, control, status::COMMAND_DONE);
                    return;
                }
            }
            kprintln!("hotplug: slot {}: command not completed", self.number);
        }
    }

    /// The slots. `slot_next` and `slot_answer` take one out while they
    /// work on it (probing, granting, revoking), so this lock is never held
    /// for that work (review F4); only `init` calls them, one at a time.
    static SLOTS: IrqMutex<Vec<Option<Slot>>> = IrqMutex::new(Vec::new());
    /// What the tick reads, fixed at boot: each handled slot's port and
    /// capability offset, so the tick never waits for a slot being worked
    /// on.
    static POLLED: IrqMutex<Vec<(Address, u8)>> = IrqMutex::new(Vec::new());
    /// Slots powering on (a bit each): the tick wakes `init` for them.
    static POWERING: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// `init`'s endpoint and bit (`slot_notify`).
    static NOTIFY: IrqMutex<Option<(Arc<Endpoint>, u32)>> = IrqMutex::new(None);

    /// Finds the hot-plug slots of bridges on bus 0 (after
    /// [`pci::enumerate`]): windows checked against the boot memory map.
    pub fn find() -> usize {
        let mut slots = Vec::new();
        for device in 0..32u8 {
            let port = Address {
                bus: 0,
                device,
                function: 0,
            };
            if hw::read32(port, 0) as u16 == 0xffff {
                continue;
            }
            if (hw::read32(port, 0x0c) >> 16) & 0x7f != 1 {
                continue;
            }
            let first = hw::read32(port, 0x34) as u8 & !0b11;
            let (caps, _) = pci::capabilities(first, |o| hw::read32(port, o));
            let Some(cap) = caps.iter().find(|c| c.id == pci::CAP_EXPRESS) else {
                continue;
            };
            let slot_caps = hw::read32(port, cap.offset + 0x14);
            if !handled(hw::read32(port, cap.offset), slot_caps) {
                continue;
            }
            if slots.len() == MAX_SLOTS {
                kprintln!("hotplug: more than {MAX_SLOTS} slots; 00:{device:02x}.0 ignored");
                continue;
            }
            let over = |w: Option<Window>| {
                w.filter(|w| {
                    let free = crate::mm::memory_map().as_ref().is_some_and(|m| {
                        m.truncated() == 0
                            && !m.entries().iter().any(|e| w.overlaps(e.base, e.length))
                    });
                    if !free {
                        kprintln!("hotplug: 00:{device:02x}.0: a window overlaps memory; closed");
                    }
                    free
                })
            };
            let mut slot = Slot {
                port,
                cap: cap.offset,
                number: (slot_caps >> 19) as u16,
                secondary: (hw::read32(port, 0x18) >> 8) as u8,
                memory: over(memory_window(hw::read32(port, 0x20))),
                prefetchable: over(prefetchable_window(
                    hw::read32(port, 0x24),
                    hw::read32(port, 0x28),
                    hw::read32(port, 0x2c),
                )),
                completion: signals_completion(slot_caps),
                state: State::Empty { last: None },
                device: None,
            };
            let (control, sta) = slot.status();
            if control & 1 << 10 == 0 && sta & status::PRESENT != 0 {
                // ponytail: a device present at boot stays a boot device;
                // hotplug handles only slots empty at boot.
                slot.state = State::Fixed;
            } else {
                slot.write(control::OFF, status::EVENTS);
            }
            kprintln!(
                "hotplug: slot {} at 00:{device:02x}.0, bus {}, {}",
                slot.number,
                slot.secondary,
                if slot.state == State::Fixed {
                    "occupied at boot (not handled)"
                } else {
                    "empty"
                }
            );
            slots.push(slot);
        }
        let n = slots.len();
        *POLLED.lock() = (slots.iter())
            .filter(|s| s.state != State::Fixed)
            .map(|s| (s.port, s.cap))
            .collect();
        *SLOTS.lock() = slots.into_iter().map(Some).collect();
        n
    }

    /// The physical numbers of the slots handled and empty at boot (for
    /// tests).
    pub fn slots() -> Vec<u16> {
        (SLOTS.lock().iter().flatten())
            .filter(|s| s.state != State::Fixed)
            .map(|s| s.number)
            .collect()
    }

    /// `slot_notify`: from now on slot work sets `bits` on `endpoint`.
    pub fn notify_on(endpoint: Arc<Endpoint>, bits: u32) {
        *NOTIFY.lock() = Some((endpoint, bits));
    }

    /// The timer tick (interrupt context): every [`POLL_TICKS`], one read
    /// per slot; signals `init` if a slot has an event or is powering on.
    /// No allocation, no writes.
    pub fn tick(ticks: u64) {
        if ticks % POLL_TICKS != 0 {
            return;
        }
        let powering = POWERING.load(core::sync::atomic::Ordering::Relaxed) != 0;
        let work = powering
            || POLLED.lock().iter().any(|&(port, cap)| {
                let sta = (hw::read32(port, cap.wrapping_add(0x18)) >> 16) as u16;
                sta & (status::BUTTON | status::PRESENCE_CHANGED) != 0
            });
        if work {
            let target = NOTIFY.lock().clone();
            if let Some((endpoint, bits)) = target {
                crate::ipc::notify(&endpoint, bits);
            }
        }
    }

    /// Carries out `act` on slot `i`; for a probe, the device's handle in
    /// `init`'s table and its ID, or `None` if it failed (then the slot is
    /// powered off).
    fn act(slot: &mut Slot, act: Act, init: &process::Process, now: u64) -> Option<(u64, u32)> {
        match act {
            Act::PowerOn => slot.write(control::ON, status::EVENTS),
            Act::PowerOff => slot.write(control::OFF, status::EVENTS),
            Act::Keep => slot.write(control::KEPT, status::EVENTS),
            Act::Revoke => {
                if let Some((device, root)) = slot.device.take() {
                    // Stops the device and ends every mapping of it.
                    process::revoke(&root);
                    if let Object::Device(handle) = root.object() {
                        handle.stop();
                    }
                    pci::remove(device.address);
                }
                slot.write(control::OFF, status::EVENTS);
            }
            Act::Probe => {
                let found = probe(slot, init);
                if found.is_none() {
                    slot.state = failed(now).0;
                    slot.write(control::OFF, status::EVENTS);
                }
                return found;
            }
        }
        None
    }

    /// Gives the function behind `slot` BARs, scans it, and hands it to
    /// `init`.
    fn probe(slot: &mut Slot, init: &process::Process) -> Option<(u64, u32)> {
        let f = slot.function();
        let (mut original, mut probe) = ([0; 6], [0; 6]);
        if (hw::read32(f, 0x0c) >> 16) & 0x7f != 0 {
            kprintln!("hotplug: slot {}: not an ordinary device", slot.number);
            return None;
        }
        for i in 0..6u8 {
            (original[i as usize], probe[i as usize]) = hw::probe_bar(f, i);
        }
        let bars = pci::decode_bars(original, probe);
        let bases = match assign(&bars, slot.memory, slot.prefetchable) {
            Ok(b) => b,
            Err(_) => {
                let id = hw::read32(f, 0);
                kprintln!(
                    "hotplug: slot {}: {:04x}:{:04x} does not fit its window",
                    slot.number,
                    id as u16,
                    id >> 16
                );
                return None;
            }
        };
        for (i, base) in bases.iter().enumerate() {
            if let (Some(base), Some(Bar::Memory { wide, .. })) = (base, bars[i]) {
                hw::write_bar(f, i as u8, *base as u32 | (original[i] & 0xf));
                if wide {
                    hw::write_bar(f, i as u8 + 1, (*base >> 32) as u32);
                }
            }
        }
        let device = Arc::new(pci::scan_function(f)?);
        let Some(handle) = DeviceHandle::grant(device.clone()) else {
            kprintln!(
                "hotplug: slot {}: previous device still in use",
                slot.number
            );
            return None;
        };
        // Not bus master until its driver allocates buffers, so a device
        // no driver takes cannot DMA (review F3).
        handle.unmaster();
        let root = Capability::new(Object::Device(handle), MAP | CONFIG | IRQ | GRANT);
        let given = init
            .caps
            .lock()
            .insert(root.derive(MAP | CONFIG | IRQ | GRANT))
            .ok()?;
        let id = u32::from(device.vendor) | u32::from(device.device) << 16;
        kprintln!(
            "hotplug: slot {}: {:04x}:{:04x} added",
            slot.number,
            device.vendor,
            device.device
        );
        pci::add(device.clone());
        slot.device = Some((device, root));
        Some((given, id))
    }

    /// `slot_next`: runs the state machine for each slot with work, for
    /// `init`, until one has an event for it; 0 if none.
    pub fn next(init: &process::Process) -> u64 {
        let now = sched::ticks();
        let count = SLOTS.lock().len();
        for i in 0..count {
            let found = with_slot(i, |slot| next_in(i, slot, init, now)).unwrap_or(0);
            if found != 0 {
                return found;
            }
        }
        0
    }

    /// Runs `f` on slot `i` taken out of [`SLOTS`], so no lock is held
    /// while it works (review F4), then puts it back and notes whether it
    /// is powering on for the tick.
    fn with_slot<T>(i: usize, f: impl FnOnce(&mut Slot) -> T) -> Option<T> {
        use core::sync::atomic::Ordering::Relaxed;
        let mut slot = SLOTS.lock().get_mut(i).and_then(Option::take)?;
        let out = f(&mut slot);
        let bit = 1u8 << (i % MAX_SLOTS);
        if matches!(slot.state, State::Powering { .. }) {
            POWERING.fetch_or(bit, Relaxed);
        } else {
            POWERING.fetch_and(!bit, Relaxed);
        }
        if let Some(s) = SLOTS.lock().get_mut(i) {
            *s = Some(slot);
        }
        Some(out)
    }

    /// One slot's steps for [`next`]: its event, or 0.
    fn next_in(i: usize, slot: &mut Slot, init: &process::Process, now: u64) -> u64 {
        // A slot may take several steps (power on, then probe) in one
        // call if its function appears at once, as in QEMU.
        for _ in 0..3 {
            // Each event is seen once: cleared as soon as it is read.
            let (control, sta) = slot.status();
            let seen = sta & (status::BUTTON | status::PRESENCE_CHANGED | status::LINK_CHANGED);
            if seen != 0 {
                hw::write_slot(slot.port, slot.cap, control, seen);
            }
            let present = hw::read32(slot.function(), 0) as u16 != 0xffff;
            let (state, act_, event) = step(slot.state, sta, present, now);
            slot.state = state;
            let probed = act_.and_then(|a| act(slot, a, init, now));
            if let Some(event) = event {
                let (handle, id) = match (event, probed) {
                    (Event::Added, Some(p)) => p,
                    (Event::Added, None) => return 0,
                    _ => (
                        0,
                        slot.device
                            .as_ref()
                            .map_or(0, |(d, _)| u32::from(d.vendor) | u32::from(d.device) << 16),
                    ),
                };
                return encode(i, event, handle, slot.number, id);
            }
            if act_.is_none() {
                return 0;
            }
        }
        0
    }

    /// `slot_answer`: `init`'s answer to a removal; false if the slot is
    /// not being removed. A release is complete when it returns (revoked,
    /// powered off): no `REMOVED` event follows, which is only for a device
    /// taken without asking.
    pub fn answer_slot(init: &process::Process, slot: usize, release: bool) -> bool {
        with_slot(slot, |s| {
            let Some((state, act_, _)) = answer(s.state, release) else {
                return false;
            };
            s.state = state;
            if let Some(a) = act_ {
                act(s, a, init, sched::ticks());
            }
            if release {
                kprintln!("hotplug: slot {}: released and powered off", s.number);
            }
            true
        })
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use status::*;

    #[test]
    fn decodes_slots_and_windows() {
        // QEMU's root port: slot implemented, hot-plug capable.
        assert!(handled(0x0142_4810, 0x000a_007b));
        assert!(!handled(0x0042_4810, 0x000a_007b), "no slot");
        assert!(!handled(0x0142_4810, 0x000a_003b), "not hot-plug capable");
        assert!(signals_completion(0x000a_007b));
        assert!(!signals_completion(0x000e_007b));
        // OVMF and SeaBIOS windows from the experiment.
        assert_eq!(
            memory_window(0x8030_8020),
            Some(Window {
                base: 0x8020_0000,
                limit: 0x803f_ffff
            })
        );
        assert_eq!(memory_window(0x0000_fff0), None, "closed");
        assert_eq!(
            prefetchable_window(0xc011_c001, 0xc0, 0xc0),
            Some(Window {
                base: 0xc0_c000_0000,
                limit: 0xc0_c01f_ffff
            })
        );
        assert_eq!(
            prefetchable_window(0xfeb0_fea0, 0x12, 0x12),
            Some(Window {
                base: 0xfea0_0000,
                limit: 0xfebf_ffff
            }),
            "32-bit: the upper halves ignored"
        );
        assert_eq!(prefetchable_window(0x0001_fff1, 0, 0), None);
        let w = memory_window(0x8030_8020).unwrap();
        assert!(w.overlaps(0x803f_f000, 0x2000) && !w.overlaps(0x8040_0000, 1));
    }

    fn mem(size: u64, prefetchable: bool, wide: bool) -> Option<Bar> {
        Some(Bar::Memory {
            base: 0,
            size,
            prefetchable,
            wide,
        })
    }

    #[test]
    fn assigns_bars_largest_first_and_aligned() {
        let memory = memory_window(0x8030_8020);
        let pref64 = prefetchable_window(0xc011_c001, 0xc0, 0xc0);
        // virtio modern: BAR1 4 KiB, BAR4 16 KiB 64-bit prefetchable.
        let mut bars = [None; 6];
        bars[1] = mem(0x1000, false, false);
        bars[4] = mem(0x4000, true, true);
        bars[0] = Some(Bar::Io { base: 0, size: 32 });
        let got = assign(&bars, memory, pref64).unwrap();
        assert_eq!(got[1], Some(0x8020_0000));
        assert_eq!(got[4], Some(0xc0_c000_0000));
        assert_eq!(got[0], None, "no I/O window");
        // Two in one window: the larger first, then aligned.
        let mut two = [None; 6];
        two[0] = mem(0x1000, false, false);
        two[2] = mem(0x10_0000, false, false);
        let got = assign(&two, memory, None).unwrap();
        assert_eq!((got[2], got[0]), (Some(0x8020_0000), Some(0x8030_0000)));
        // 32-bit prefetchable: in a window below 4 GiB, not one above.
        let mut p32 = [None; 6];
        p32[0] = mem(0x1000, true, false);
        let low = prefetchable_window(0xfeb0_fea0, 0, 0);
        assert_eq!(assign(&p32, memory, low).unwrap()[0], Some(0xfea0_0000));
        assert_eq!(assign(&p32, memory, pref64).unwrap()[0], Some(0x8020_0000));
        // Too big, or no window.
        let mut big = [None; 6];
        big[0] = mem(0x40_0000, false, false);
        assert_eq!(assign(&big, memory, None), Err(NoFit::Window));
        assert_eq!(assign(&bars, None, pref64), Err(NoFit::Window));
        // 64-bit prefetchable with no prefetchable window: memory window.
        assert_eq!(assign(&bars, memory, None).unwrap()[4], Some(0x8020_0000));
        let mut odd = [None; 6];
        odd[0] = mem(0x1800, false, false);
        assert_eq!(assign(&odd, memory, None), Err(NoFit::Window));
    }

    #[test]
    fn a_device_arrives_and_is_removed() {
        let empty = State::Empty { last: None };
        // QEMU's device_add: presence changed, button, present.
        let add = PRESENT | PRESENCE_CHANGED | BUTTON;
        assert_eq!(
            step(empty, add, false, 10),
            (State::Powering { since: 10 }, Some(Act::PowerOn), None)
        );
        let powering = State::Powering { since: 10 };
        assert_eq!(step(powering, PRESENT, false, 20), (powering, None, None));
        assert_eq!(
            step(powering, PRESENT, true, 20),
            (State::Occupied, Some(Act::Probe), Some(Event::Added))
        );
        assert_eq!(
            failed(20),
            (State::Empty { last: Some(20) }, Some(Act::PowerOff), None)
        );
        // device_del: the button.
        assert_eq!(
            step(State::Occupied, PRESENT | BUTTON, true, 30),
            (State::Removing, None, Some(Event::Remove))
        );
        assert_eq!(
            step(State::Removing, PRESENT | BUTTON, true, 31),
            (State::Removing, None, None),
            "a second press while asking"
        );
        assert_eq!(
            answer(State::Removing, true),
            Some((
                State::Empty { last: None },
                Some(Act::Revoke),
                Some(Event::Removed)
            ))
        );
        assert_eq!(
            answer(State::Removing, false),
            Some((State::Occupied, Some(Act::Keep), None))
        );
        assert_eq!(answer(State::Occupied, true), None);
        assert_eq!(answer(empty, false), None);
    }

    #[test]
    fn surprise_removal_timeouts_flapping_and_boot_devices() {
        let empty = State::Empty { last: None };
        // Gone while running or being asked: revoked at once.
        for s in [State::Occupied, State::Removing] {
            assert_eq!(
                step(s, PRESENCE_CHANGED, true, 5),
                (
                    State::Empty { last: None },
                    Some(Act::Revoke),
                    Some(Event::Removed)
                )
            );
        }
        // Powered, but the function never appears, or the card goes.
        let powering = State::Powering { since: 0 };
        assert_eq!(
            step(powering, PRESENT, false, POWER_TICKS + 1),
            (State::Empty { last: Some(0) }, Some(Act::PowerOff), None)
        );
        assert_eq!(
            step(powering, PRESENCE_CHANGED, false, 1),
            (State::Empty { last: Some(0) }, Some(Act::PowerOff), None)
        );
        // Flapping: no second arrival within a second of the last.
        let recent = State::Empty { last: Some(50) };
        let add = PRESENT | PRESENCE_CHANGED;
        assert_eq!(step(recent, add, false, 60), (recent, None, None));
        assert_eq!(step(recent, add, false, 150).1, Some(Act::PowerOn));
        // A card that stays after power off, with no new event: left off.
        assert_eq!(step(empty, PRESENT, false, 10), (empty, None, None));
        // Presence lost while empty, or a slot occupied at boot: nothing.
        assert_eq!(
            step(empty, PRESENCE_CHANGED, false, 10),
            (empty, None, None)
        );
        assert_eq!(
            step(State::Fixed, add | BUTTON, true, 10),
            (State::Fixed, None, None)
        );
        // Encoding.
        assert_eq!(
            encode(1, Event::Added, 9, 2, 0x1042_1af4),
            0x1042_1af4_0209_0101
        );
    }
}
