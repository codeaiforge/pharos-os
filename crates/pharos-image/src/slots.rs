//! The slot record, `system/state` (boot.md section 8, #163): which slot is
//! active, a one-shot mode, and per slot its state, version, SHA-256, and
//! attempts; and how `init` picks the image to boot from it.
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `PHAROSSR` |
//! | 8 | 4 | format version, 1 |
//! | 12 | 1 | active: 0 none, 1 A, 2 B |
//! | 13 | 1 | next mode: 0 normal, 1 safe, 2 recovery |
//! | 14 | 2 | reserved, zero |
//! | 16 | 48 | slot A: state, attempts, 6 reserved, version (u64), SHA-256 |
//! | 64 | 48 | slot B, the same |
//! | 112 | 4 | CRC-32 of bytes 0–111 |
//!
//! Each write is one store commit, so the record is always the old one or
//! the new one (D-017). A missing or corrupt record means no slots.

pub const RECORD_MAGIC: [u8; 8] = *b"PHAROSSR";
pub const RECORD_VERSION: u32 = 1;
pub const RECORD_LEN: usize = 116;
/// Attempts without ready before a slot is `Bad`.
pub const MAX_ATTEMPTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    /// The slot's file in namespace `system`.
    pub fn path(self) -> &'static [u8] {
        match self {
            Self::A => b"a",
            Self::B => b"b",
        }
    }

    /// `A` or `B`.
    pub fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Empty,
    /// Approved and copied in, not yet booted (#165).
    Staged,
    /// Being booted: `attempts` counts the boots that did not reach ready.
    Trying,
    Good,
    /// Never tried again.
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Safe,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotInfo {
    pub state: State,
    pub attempts: u8,
    pub version: u64,
    pub sha256: [u8; 32],
}

impl SlotInfo {
    pub const EMPTY: Self = Self {
        state: State::Empty,
        attempts: 0,
        version: 0,
        sha256: [0; 32],
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub active: Option<Slot>,
    pub next: Mode,
    pub slots: [SlotInfo; 2],
}

impl Default for Record {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Record {
    /// No slots: the factory image runs.
    pub const EMPTY: Self = Self {
        active: None,
        next: Mode::Normal,
        slots: [SlotInfo::EMPTY; 2],
    };

    pub fn slot(&self, slot: Slot) -> &SlotInfo {
        &self.slots[slot.index()]
    }

    fn slot_mut(&mut self, slot: Slot) -> &mut SlotInfo {
        &mut self.slots[slot.index()]
    }

    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut r = [0; RECORD_LEN];
        r[..8].copy_from_slice(&RECORD_MAGIC);
        r[8..12].copy_from_slice(&RECORD_VERSION.to_le_bytes());
        r[12] = match self.active {
            None => 0,
            Some(Slot::A) => 1,
            Some(Slot::B) => 2,
        };
        r[13] = self.next as u8;
        for (i, s) in self.slots.iter().enumerate() {
            let at = 16 + 48 * i;
            r[at] = s.state as u8;
            r[at + 1] = s.attempts;
            r[at + 8..at + 16].copy_from_slice(&s.version.to_le_bytes());
            r[at + 16..at + 48].copy_from_slice(&s.sha256);
        }
        let crc = pharos_fs::crc32(&r[..112]);
        r[112..].copy_from_slice(&crc.to_le_bytes());
        r
    }

    /// The record in `bytes`, or `None` if any field is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; RECORD_LEN] = bytes.try_into().ok()?;
        let u32_at = |at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        if r[..8] != RECORD_MAGIC
            || u32_at(8) != RECORD_VERSION
            || u32_at(112) != pharos_fs::crc32(&r[..112])
            || r[14..16] != [0, 0]
        {
            return None;
        }
        let active = match r[12] {
            0 => None,
            1 => Some(Slot::A),
            2 => Some(Slot::B),
            _ => return None,
        };
        let next = [Mode::Normal, Mode::Safe, Mode::Recovery]
            .get(usize::from(r[13]))
            .copied()?;
        let mut slots = [SlotInfo::EMPTY; 2];
        for (i, s) in slots.iter_mut().enumerate() {
            let at = 16 + 48 * i;
            use State::*;
            s.state = [Empty, Staged, Trying, Good, Bad]
                .get(usize::from(r[at]))
                .copied()?;
            s.attempts = r[at + 1];
            if r[at + 2..at + 8] != [0; 6] {
                return None;
            }
            s.version = u64::from_le_bytes(r[at + 8..at + 16].try_into().ok()?);
            s.sha256 = r[at + 16..at + 48].try_into().ok()?;
        }
        Some(Self {
            active,
            next,
            slots,
        })
    }

    /// The slot to boot, or `None` for the factory image: the active slot
    /// if it is `Good`, `Staged`, or `Trying` with attempts left, else the
    /// other slot if `Good` or `Trying` with attempts left. `tried` are the
    /// slots that already failed in this boot. A `Trying` slot whose
    /// attempts are used up becomes `Bad` here.
    pub fn candidate(&mut self, tried: [bool; 2]) -> Option<Slot> {
        for s in &mut self.slots {
            if s.state == State::Trying && s.attempts >= MAX_ATTEMPTS {
                s.state = State::Bad;
            }
        }
        let first = self.active?;
        [first, first.other()].into_iter().find(|&slot| {
            let s = self.slot(slot);
            let usable = match s.state {
                State::Good | State::Trying => true,
                State::Staged => slot == first,
                State::Empty | State::Bad => false,
            };
            usable && !tried[slot.index()]
        })
    }

    /// Counts an attempt on `slot` (write it before using the slot, so a
    /// crash or a hang during the boot counts too).
    pub fn attempt(&mut self, slot: Slot) {
        let s = self.slot_mut(slot);
        s.state = State::Trying;
        s.attempts = s.attempts.saturating_add(1);
    }

    /// `slot` failed its checks: never tried again.
    pub fn refuse(&mut self, slot: Slot) {
        self.slot_mut(slot).state = State::Bad;
    }

    /// This boot's mode (#164): the kernel's if it asked for one, else
    /// the record's one-shot `next`, which is cleared either way only if
    /// it was used. Returns the mode and whether the record changed.
    pub fn take_mode(&mut self, kernel: Mode) -> (Mode, bool) {
        if kernel != Mode::Normal || self.next == Mode::Normal {
            return (kernel, false);
        }
        let next = self.next;
        self.next = Mode::Normal;
        (next, true)
    }

    /// `slot` reached ready: `Good`, attempts 0, and active.
    pub fn ready(&mut self, slot: Slot) {
        let s = self.slot_mut(slot);
        s.state = State::Good;
        s.attempts = 0;
        self.active = Some(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(state: State, attempts: u8, version: u64) -> SlotInfo {
        SlotInfo {
            state,
            attempts,
            version,
            sha256: [version as u8; 32],
        }
    }

    fn record(active: Option<Slot>, a: SlotInfo, b: SlotInfo) -> Record {
        Record {
            active,
            next: Mode::Normal,
            slots: [a, b],
        }
    }

    #[test]
    fn a_record_round_trips_and_any_changed_byte_is_refused() {
        let r = Record {
            active: Some(Slot::B),
            next: Mode::Recovery,
            slots: [info(State::Bad, 3, 7), info(State::Good, 0, 8)],
        };
        let bytes = r.encode();
        assert_eq!(Record::decode(&bytes), Some(r));
        assert_eq!(Record::decode(&Record::EMPTY.encode()), Some(Record::EMPTY));
        for at in 0..RECORD_LEN {
            for bit in 0..8 {
                let mut changed = bytes;
                changed[at] ^= 1 << bit;
                assert_eq!(Record::decode(&changed), None, "byte {at} bit {bit}");
            }
        }
        assert_eq!(Record::decode(&bytes[..RECORD_LEN - 1]), None);
        assert_eq!(Record::decode(&[]), None);
    }

    #[test]
    fn fields_out_of_range_are_refused_even_with_a_good_crc() {
        let fix = |mut b: [u8; RECORD_LEN]| {
            let crc = pharos_fs::crc32(&b[..112]);
            b[112..].copy_from_slice(&crc.to_le_bytes());
            b
        };
        let good = Record::EMPTY.encode();
        for (at, value) in [(8, 2), (12, 3), (13, 3), (14, 1), (16, 5), (18, 1), (64, 9)] {
            let mut b = good;
            b[at] = value;
            assert_eq!(Record::decode(&fix(b)), None, "byte {at} = {value}");
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100_000 {
            let mut b = Record::EMPTY.encode();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b[(x % RECORD_LEN as u64) as usize] = (x >> 32) as u8;
            if x & 1 == 0 {
                let crc = pharos_fs::crc32(&b[..112]);
                b[112..].copy_from_slice(&crc.to_le_bytes());
            }
            let _ = Record::decode(&b);
        }
    }

    #[test]
    fn every_state_leads_to_its_candidate() {
        use State::*;
        let none = [false; 2];
        // (active, A, B, the candidate)
        let cases = [
            (None, Empty, Empty, None),
            (None, Good, Good, None),
            (Some(Slot::A), Good, Empty, Some(Slot::A)),
            (Some(Slot::A), Trying, Good, Some(Slot::A)),
            (Some(Slot::A), Staged, Good, Some(Slot::A)),
            (Some(Slot::A), Bad, Good, Some(Slot::B)),
            (Some(Slot::A), Empty, Good, Some(Slot::B)),
            (Some(Slot::A), Bad, Trying, Some(Slot::B)),
            // Only the active slot may be staged.
            (Some(Slot::A), Bad, Staged, None),
            (Some(Slot::A), Bad, Bad, None),
            (Some(Slot::A), Bad, Empty, None),
            (Some(Slot::B), Good, Good, Some(Slot::B)),
            (Some(Slot::B), Good, Bad, Some(Slot::A)),
        ];
        for (active, a, b, want) in cases {
            let mut r = record(active, info(a, 0, 1), info(b, 0, 2));
            assert_eq!(r.candidate(none), want, "{active:?} {a:?} {b:?}");
        }
    }

    #[test]
    fn a_slot_that_failed_this_boot_is_skipped() {
        let mut r = record(
            Some(Slot::A),
            info(State::Good, 0, 1),
            info(State::Good, 0, 2),
        );
        assert_eq!(r.candidate([true, false]), Some(Slot::B));
        assert_eq!(r.candidate([true, true]), None);
        assert_eq!(r.candidate([false, true]), Some(Slot::A));
    }

    #[test]
    fn attempts_are_counted_and_used_up() {
        let mut r = record(Some(Slot::A), info(State::Good, 0, 1), SlotInfo::EMPTY);
        for n in 1..=MAX_ATTEMPTS {
            assert_eq!(r.candidate([false; 2]), Some(Slot::A), "attempt {n}");
            r.attempt(Slot::A);
            assert_eq!(*r.slot(Slot::A), info(State::Trying, n, 1));
            // As read back on the next boot.
            r = Record::decode(&r.encode()).unwrap();
        }
        assert_eq!(r.candidate([false; 2]), None);
        assert_eq!(r.slot(Slot::A).state, State::Bad);
        // Bad stays bad, whatever its attempts.
        r.slots[0].attempts = 0;
        assert_eq!(r.candidate([false; 2]), None);
    }

    #[test]
    fn the_kernels_mode_wins_and_next_is_used_once() {
        let mut r = Record {
            next: Mode::Safe,
            ..Record::EMPTY
        };
        assert_eq!(r.take_mode(Mode::Recovery), (Mode::Recovery, false));
        assert_eq!(r.next, Mode::Safe, "kept for a boot that uses it");
        assert_eq!(r.take_mode(Mode::Normal), (Mode::Safe, true));
        assert_eq!(r.next, Mode::Normal);
        assert_eq!(r.take_mode(Mode::Normal), (Mode::Normal, false));
        r.next = Mode::Recovery;
        assert_eq!(r.take_mode(Mode::Normal), (Mode::Recovery, true));
    }

    #[test]
    fn ready_makes_a_slot_good_and_active_and_refuse_bad() {
        let mut r = record(
            Some(Slot::A),
            info(State::Good, 0, 1),
            info(State::Good, 0, 2),
        );
        r.attempt(Slot::A);
        r.refuse(Slot::A);
        assert_eq!(r.slot(Slot::A).state, State::Bad);
        assert_eq!(r.candidate([false; 2]), Some(Slot::B));
        r.attempt(Slot::B);
        r.ready(Slot::B);
        assert_eq!(r.active, Some(Slot::B));
        assert_eq!(*r.slot(Slot::B), info(State::Good, 0, 2));
        assert_eq!(r.candidate([false; 2]), Some(Slot::B));
    }
}
