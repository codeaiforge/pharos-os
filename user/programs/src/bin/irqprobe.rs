//! Device-interrupt probe for the `device_irq` test kernel (issue #54).
//!
//! Handles: 1 debug console, 2 the virtio-blk device (`MAP | CONFIG | IRQ`),
//! 3 an endpoint to wait on, 4 the same device without `IRQ`. The program
//! routes MSI-X entry 0 to an interrupt, reads sector 0 of the disk, and
//! sleeps in `irq_wait` until the device's completion interrupt wakes it.
//! Then it revokes the interrupt, deletes it, and waits for a message so
//! the kernel can check the entry is masked. Each step prints `ok <step>`
//! or `FAIL <step>`; the exit code is the number of failures.

#![no_std]
#![no_main]

use pharos_programs::virtio;
use pharos_user::{Error, debug_write, delete, irq_create, irq_wait, receive, revoke};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const DEVICE: u64 = 2;
const WAIT: u64 = 3;
const NO_IRQ: u64 = 4;
const BASE: u64 = 0x1000_0000;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 80];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

fn main(_: u64) -> u64 {
    let mut f = 0;
    report(
        &mut f,
        "no IRQ right: MISSING_RIGHT",
        irq_create(NO_IRQ, 0) == Err(Error::MissingRight),
    );
    report(
        &mut f,
        "entry past the table: NOT_FOUND",
        irq_create(DEVICE, 2) == Err(Error::NotFound),
    );
    let irq = irq_create(DEVICE, 0);
    report(&mut f, "irq_create entry 0", irq.is_ok());
    let Ok(irq) = irq else {
        return f;
    };
    report(
        &mut f,
        "entry taken: IN_USE",
        irq_create(DEVICE, 0) == Err(Error::InUse),
    );
    report(
        &mut f,
        "waiting on a device handle: MISSING_RIGHT",
        irq_wait(DEVICE) == Err(Error::MissingRight),
    );

    match virtio::Blk::init(DEVICE, 0, BASE) {
        Ok(mut blk) => {
            report(&mut f, "virtio-blk set up", true);
            let submitted = blk.submit(0, virtio::SECTOR).is_ok();
            report(
                &mut f,
                "irq_wait wakes on the completion interrupt",
                submitted && irq_wait(irq).is_ok_and(|n| n >= 1),
            );
            report(&mut f, "read completed", blk.complete() == Ok(true));
            // The data, read again through the driver's blocking path.
            let mut sector = [0u8; virtio::SECTOR];
            report(
                &mut f,
                "sector 0 starts with the filesystem magic",
                blk.read(irq, 0, &mut sector).is_ok() && sector.starts_with(b"PHAROSFS"),
            );
            blk.reset();
        }
        Err(why) => report(&mut f, why, false),
    }

    report(
        &mut f,
        "revoking the device revokes the interrupt",
        revoke(DEVICE) == Ok(1),
    );
    report(
        &mut f,
        "revoked interrupt: REVOKED",
        irq_wait(irq) == Err(Error::Revoked),
    );
    report(&mut f, "delete the interrupt", delete(irq).is_ok());

    // Wait until the kernel has checked the entry is masked.
    let mut msg = [0u8; 8];
    report(
        &mut f,
        "released by the kernel",
        receive(WAIT, &mut msg).is_ok(),
    );
    f
}
