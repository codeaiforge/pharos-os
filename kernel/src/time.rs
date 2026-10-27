//! Kernel clock and scheduler tick (D-006 timer part, issue #32).
//!
//! [`init`] calibrates the local APIC timer and the TSC against PIT channel
//! 2: five 10 ms runs, keeping the smallest result, because a delay (for
//! example the emulated CPU being descheduled) can only inflate a run.
//! Uptime comes from the TSC, not from counting ticks, since ticks can be
//! lost under load. The tick runs at [`TICK_HZ`].
//!
//! The calibration is a documented singleton (one CPU; D-004 constraint 6),
//! kept in atomics.

use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::arch::x86_64::{self as arch, apic};

/// Scheduler tick rate (D-006).
pub const TICK_HZ: u32 = 100;
/// Calibration runs; the smallest result counts.
pub const CALIBRATION_RUNS: usize = 5;
/// Length of one calibration run.
pub const CALIBRATION_MS: u64 = 10;

/// Slowest APIC timer accepted, in ticks (divided by 16) per ms: below this
/// a tick period would have fewer than 1,000 timer counts.
const MIN_APIC_PER_MS: u32 = 1_000 * TICK_HZ / 1_000;
/// Slowest TSC accepted: 1 MHz.
const MIN_TSC_PER_MS: u64 = 1_000;

/// Measured clock rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calibration {
    /// Local APIC timer ticks (divided by 16) per millisecond.
    pub apic_per_ms: u32,
    /// TSC cycles per millisecond.
    pub tsc_per_ms: u64,
}

/// Why calibration was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum CalibrationError {
    /// No runs were made.
    NoRuns,
    /// The rates are outside what the kernel can use.
    Implausible(Calibration),
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuns => f.write_str("no calibration runs"),
            Self::Implausible(c) => write!(
                f,
                "implausible timer rates: APIC {} ticks/ms (need {MIN_APIC_PER_MS} to {}), \
                 TSC {} cycles/ms (need at least {MIN_TSC_PER_MS})",
                c.apic_per_ms,
                u32::MAX / (1_000 / TICK_HZ),
                c.tsc_per_ms
            ),
        }
    }
}

impl Calibration {
    /// Combines `(apic ticks, tsc cycles)` runs of `ms` milliseconds each:
    /// the smallest value of each counter counts.
    pub fn from_runs(runs: &[(u32, u64)], ms: u64) -> Result<Self, CalibrationError> {
        let apic = runs
            .iter()
            .map(|r| r.0)
            .min()
            .ok_or(CalibrationError::NoRuns)?;
        let tsc = runs
            .iter()
            .map(|r| r.1)
            .min()
            .ok_or(CalibrationError::NoRuns)?;
        let ms = ms.max(1);
        let calibration = Self {
            apic_per_ms: (u64::from(apic) / ms) as u32,
            tsc_per_ms: tsc / ms,
        };
        let tick_fits = calibration.apic_per_ms <= u32::MAX / (1_000 / TICK_HZ);
        if calibration.apic_per_ms < MIN_APIC_PER_MS
            || !tick_fits
            || calibration.tsc_per_ms < MIN_TSC_PER_MS
        {
            return Err(CalibrationError::Implausible(calibration));
        }
        Ok(calibration)
    }

    /// APIC timer initial count for one tick period.
    pub fn tick_count(&self) -> u32 {
        self.apic_per_ms * (1_000 / TICK_HZ)
    }
}

/// Converts TSC cycles to nanoseconds at `tsc_per_ms` (non-zero).
fn cycles_to_ns(cycles: u64, tsc_per_ms: u64) -> u64 {
    (u128::from(cycles) * 1_000_000 / u128::from(tsc_per_ms)) as u64
}

/// TSC cycles per ms; 0 until [`init`].
static TSC_PER_MS: AtomicU64 = AtomicU64::new(0);
/// TSC value at [`init`].
static TSC_START: AtomicU64 = AtomicU64::new(0);
/// APIC timer count per tick; 0 until [`init`].
static TICK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Calibrates the APIC timer and the TSC against the PIT and starts the
/// clock. Call once after `apic::init`; the timer is left stopped (see
/// [`start_tick`]). Takes about 50 ms.
pub fn init() -> Result<Calibration, CalibrationError> {
    let pit_ticks = (arch::PIT_HZ * CALIBRATION_MS / 1_000) as u16;
    let mut runs = [(0, 0); CALIBRATION_RUNS];
    arch::without_interrupts(|| {
        for run in runs.iter_mut() {
            *run = apic::measure_against_pit(pit_ticks);
        }
    });
    // The PIT counts `pit_ticks / PIT_HZ` seconds, slightly under 10 ms.
    let calibration = Calibration::from_runs(&runs, CALIBRATION_MS)?;
    TSC_START.store(arch::rdtsc(), Ordering::Relaxed);
    TICK_COUNT.store(calibration.tick_count(), Ordering::Relaxed);
    TSC_PER_MS.store(calibration.tsc_per_ms, Ordering::Relaxed);
    Ok(calibration)
}

/// Starts the periodic tick at [`TICK_HZ`]. Returns false (and does
/// nothing) before [`init`].
pub fn start_tick() -> bool {
    match TICK_COUNT.load(Ordering::Relaxed) {
        0 => false,
        count => {
            apic::start_timer(count);
            true
        }
    }
}

/// Time since [`init`] (zero before), from the TSC.
pub fn uptime() -> Duration {
    match TSC_PER_MS.load(Ordering::Relaxed) {
        0 => Duration::ZERO,
        tsc_per_ms => {
            let cycles = arch::rdtsc().wrapping_sub(TSC_START.load(Ordering::Relaxed));
            Duration::from_nanos(cycles_to_ns(cycles, tsc_per_ms))
        }
    }
}

/// Busy-waits for at least `duration`. Returns at once before [`init`].
pub fn delay(duration: Duration) {
    if TSC_PER_MS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let end = uptime() + duration;
    while uptime() < end {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smallest_run_counts() {
        // Values from the D-006 prototype under host load: a single run read
        // 29% high; the smallest was right.
        let runs = [
            (737_370, 43_545_050),
            (625_110, 36_958_530),
            (804_950, 47_583_120),
            (625_170, 36_958_840),
            (799_130, 47_248_460),
        ];
        let c = Calibration::from_runs(&runs, 10).unwrap();
        assert_eq!(c.apic_per_ms, 62_511);
        assert_eq!(c.tsc_per_ms, 3_695_853);
        assert_eq!(c.tick_count(), 625_110, "10 ms at 100 Hz");
    }

    #[test]
    fn implausible_rates_are_rejected() {
        assert_eq!(
            Calibration::from_runs(&[], 10),
            Err(CalibrationError::NoRuns)
        );
        let slow_apic = Calibration::from_runs(&[(500, 40_000_000)], 10);
        assert!(matches!(slow_apic, Err(CalibrationError::Implausible(_))));
        let slow_tsc = Calibration::from_runs(&[(625_000, 5_000)], 10);
        assert!(matches!(slow_tsc, Err(CalibrationError::Implausible(_))));
        // Fast enough that one tick period would overflow the 32-bit count.
        let fast_apic = Calibration::from_runs(&[(u32::MAX, 40_000_000)], 1);
        assert!(matches!(fast_apic, Err(CalibrationError::Implausible(_))));
        let message = format!("{}", slow_apic.unwrap_err());
        assert!(message.contains("APIC 50 ticks/ms"), "{message}");
    }

    #[test]
    fn cycles_convert_to_nanoseconds() {
        assert_eq!(cycles_to_ns(3_000_000, 3_000_000), 1_000_000);
        assert_eq!(cycles_to_ns(3, 3_000_000), 1);
        // A year of cycles at 3 GHz does not overflow.
        let year = 3_000_000 * 1_000 * 3600 * 24 * 365;
        assert_eq!(
            cycles_to_ns(year, 3_000_000),
            1_000_000_000 * 3600 * 24 * 365
        );
    }
}
