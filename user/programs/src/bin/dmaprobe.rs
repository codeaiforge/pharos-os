//! A driver that attacks with its device's DMA (#244, iommu.md): it sets
//! up the virtio-blk disk, then asks the device to read sector 0 into the
//! physical address it was given as its argument (a kernel frame the test
//! filled), which its IOMMU domain does not map. Then it resets the device
//! and reads sector 0 into its own buffer, which must still work.
//!
//! Handles: 1 debug console, 2 the device (`MAP | CONFIG | IRQ`). Reports
//! one line per step, and each set-up's DMA address (`dma <hex>`); exits 0 if the own read worked, whatever the attack
//! did (the test kernel judges the attack by the canary and the fault).

#![no_std]
#![no_main]

use pharos_programs::virtio::{Blk, MAX_READ};
use pharos_user::{Handle, debug_write, irq_create, sleep};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const BASE: u64 = 0x1000_0000;
/// After the attack, a second set-up at other addresses.
const AGAIN: u64 = 0x2000_0000;

fn say(text: &str) {
    let _ = debug_write(CONSOLE, text.as_bytes());
}

/// `dma ` and `value` as 16 hex digits: a buffer the test checks is
/// unmapped once this process has ended.
fn hex(value: u64) -> [u8; 20] {
    let mut out = *b"dma 0000000000000000";
    for i in 0..16 {
        out[4 + i] = b"0123456789abcdef"[(value >> (60 - 4 * i)) as usize & 0xf];
    }
    out
}

fn main(target: u64) -> u64 {
    let Ok(irq) = irq_create(DEVICE, 0) else {
        say("irq_create failed");
        return 2;
    };
    let mut blk = match Blk::init(DEVICE, 0, BASE) {
        Ok(blk) => blk,
        Err(why) => {
            say(why);
            return 2;
        }
    };
    let _ = debug_write(CONSOLE, &hex(blk.dma_phys()));
    if blk.submit_into(0, MAX_READ, target).is_err() {
        say("attack not submitted");
        return 3;
    }
    say("attack submitted");
    // A blocked DMA may never complete (QEMU marks the device broken), so
    // poll for up to a second instead of waiting on the interrupt.
    let mut outcome = "attack: no completion";
    for _ in 0..50 {
        match blk.complete() {
            Ok(true) => {
                outcome = "attack: completed";
                break;
            }
            Ok(false) => sleep(20_000),
            Err(_) => {
                outcome = "attack: completed with an error";
                break;
            }
        }
    }
    say(outcome);
    blk.reset();

    let mut blk = match Blk::init(DEVICE, 0, AGAIN) {
        Ok(blk) => blk,
        Err(why) => {
            say(why);
            return 4;
        }
    };
    let _ = debug_write(CONSOLE, &hex(blk.dma_phys()));
    let mut sector = [0u8; 512];
    if blk.read(irq, 0, &mut sector).is_err() || !sector.starts_with(b"PHAROSFS") {
        say("own read failed");
        return 5;
    }
    say("ok own read");
    blk.reset();
    0
}
