//! Device-capability probe for the `device_caps` test kernel (issue #55).
//!
//! Handles: 1 debug console, 2 the virtio-blk device (`MAP | CONFIG`),
//! 3 an endpoint to wait on, 4 the same device without rights. The argument
//! locates the virtio common configuration: BAR in bits 0–7, offset in the
//! BAR above. Each step prints `ok <step>` or `FAIL <step>`; the exit code
//! is the number of failures. The program prints `dma <hex>` (the buffer's
//! physical address) and waits for a message before exiting, so the kernel
//! can inspect the buffer and the device while it lives.
//!
//! With bit 63 of the argument set, it only maps the common configuration,
//! deletes both device handles, and waits: the mapping alone must keep the
//! device granted and enabled.

#![no_std]
#![no_main]

use pharos_user::{Error, Mapped, config_read, debug_write, delete, dma_alloc, mmio_map, receive};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const DEVICE: u64 = 2;
const WAIT: u64 = 3;
const POWERLESS: u64 = 4;
const REGS: u64 = 0x1000_0000;
const DMA: u64 = 0x2000_0000;

/// virtio common configuration offsets (virtio 1.x, 4.1.4.3).
const NUM_QUEUES: usize = 0x12;
const DEVICE_STATUS: usize = 0x14;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 64];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

/// `dma ` and `value` as 16 hex digits.
fn hex(value: u64) -> [u8; 20] {
    let mut out = *b"dma 0000000000000000";
    for i in 0..16 {
        out[4 + i] = b"0123456789abcdef"[(value >> (60 - 4 * i)) as usize & 0xf];
    }
    out
}

/// Argument bit: map registers only.
const MMIO_ONLY: u64 = 1 << 63;

fn main(arg: u64) -> u64 {
    let mut f = 0;
    let mmio_only = arg & MMIO_ONLY != 0;
    let arg = arg & !MMIO_ONLY;
    let (bar, offset) = ((arg & 0xff) as u8, arg >> 8);
    if mmio_only {
        let page = offset / 4096 * 4096;
        report(
            &mut f,
            "mmio_map only",
            mmio_map(DEVICE, bar, page, 4096, REGS).is_ok(),
        );
        report(
            &mut f,
            "delete both device handles",
            delete(DEVICE).is_ok() && delete(POWERLESS).is_ok(),
        );
        let mut msg = [0u8; 8];
        report(
            &mut f,
            "released by the kernel",
            receive(WAIT, &mut msg).is_ok(),
        );
        return f;
    }
    let page = offset / 4096 * 4096;
    let in_page = (offset - page) as usize;

    let id = config_read(DEVICE, 0, 4);
    report(
        &mut f,
        "config_read vendor and device",
        id == Ok(0x1042_1af4),
    );
    report(
        &mut f,
        "config_read a byte",
        config_read(DEVICE, 0x0b, 1) == Ok(0x01),
    );

    let regs: Result<Mapped, Error> = mmio_map(DEVICE, bar, page, 4096, REGS);
    report(&mut f, "mmio_map the common configuration", regs.is_ok());
    if let Ok(regs) = regs {
        report(&mut f, "one queue", regs.read16(in_page + NUM_QUEUES) == 1);
        regs.write8(in_page + DEVICE_STATUS, 0);
        report(
            &mut f,
            "status reset",
            regs.read8(in_page + DEVICE_STATUS) == 0,
        );
        regs.write8(in_page + DEVICE_STATUS, 1); // ACKNOWLEDGE
        report(
            &mut f,
            "status write reaches the device",
            regs.read8(in_page + DEVICE_STATUS) == 1,
        );
        regs.write8(in_page + DEVICE_STATUS, 0);
    }
    report(
        &mut f,
        "mapping the same address again: IN_USE",
        mmio_map(DEVICE, bar, page, 4096, REGS).err() == Some(Error::InUse),
    );
    report(
        &mut f,
        "BAR 6: NOT_FOUND",
        mmio_map(DEVICE, 6, 0, 4096, REGS + 0x10_0000).err() == Some(Error::NotFound),
    );
    report(
        &mut f,
        "past the BAR: BAD_ADDRESS",
        mmio_map(DEVICE, bar, 0, 0x10_0000, REGS + 0x10_0000).err() == Some(Error::BadAddress),
    );
    report(
        &mut f,
        "MSI-X table page: BAD_ADDRESS",
        mmio_map(DEVICE, 1, 0, 4096, REGS + 0x10_0000).err() == Some(Error::BadAddress),
    );
    report(
        &mut f,
        "no MAP right: MISSING_RIGHT",
        mmio_map(POWERLESS, bar, page, 4096, REGS + 0x20_0000).err() == Some(Error::MissingRight),
    );
    report(
        &mut f,
        "no CONFIG right: MISSING_RIGHT",
        config_read(POWERLESS, 0, 4).err() == Some(Error::MissingRight),
    );

    // Register mappings are limited to 256 pages per process: 1 so far,
    // then the whole 4-page BAR 63 more times.
    let mut mapped = 0;
    let last = loop {
        let at = REGS + 0x100_0000 + mapped * 0x4000;
        match mmio_map(DEVICE, bar, 0, 0x4000, at) {
            Ok(_) if mapped < 100 => mapped += 1,
            other => break other.err(),
        }
    };
    report(
        &mut f,
        "256 register pages in all, then NO_MEMORY",
        mapped == 63 && last == Some(Error::NoMemory),
    );

    let dma = dma_alloc(DEVICE, 2, DMA);
    report(&mut f, "dma_alloc 2 pages", dma.is_ok());
    if let Ok((buf, phys)) = dma {
        report(
            &mut f,
            "DMA buffer starts zeroed",
            buf.read64(0) == 0 && buf.read64(8184) == 0,
        );
        buf.write64(0, 0x1122_3344_5566_7788);
        buf.write64(4096, 0x99aa_bbcc_ddee_ff00);
        let _ = debug_write(CONSOLE, &hex(phys));
    }
    report(
        &mut f,
        "17 pages: TOO_LARGE",
        dma_alloc(DEVICE, 17, DMA + 0x10_0000).err() == Some(Error::TooLarge),
    );
    report(
        &mut f,
        "DMA over an existing mapping: IN_USE",
        dma_alloc(DEVICE, 1, DMA).err() == Some(Error::InUse),
    );
    let mut ok = true;
    for i in 0..3 {
        ok &= dma_alloc(DEVICE, 16, DMA + 0x10_0000 * (i + 1)).is_ok();
    }
    report(&mut f, "50 DMA pages in all", ok);
    report(
        &mut f,
        "past 64 pages: NO_MEMORY",
        dma_alloc(DEVICE, 16, DMA + 0x10_0000 * 5).err() == Some(Error::NoMemory),
    );
    report(
        &mut f,
        "delete both device handles",
        delete(DEVICE).is_ok() && delete(POWERLESS).is_ok(),
    );

    // Wait until the kernel has looked at the buffer and the device.
    let mut msg = [0u8; 8];
    report(
        &mut f,
        "released by the kernel",
        receive(WAIT, &mut msg).is_ok(),
    );
    f
}
