//! virtio 1.x block device over the modern PCI transport
//! ([drivers.md](../../../docs/architecture/drivers.md)): find the
//! configuration structures, set up one split virtqueue, and read sectors,
//! one request at a time. Every value the device returns is checked: the
//! used index advances by at most the one request outstanding, the
//! descriptor ID is that request's, the length is what the request asked
//! for, and the status is OK. Any failure during setup sets `FAILED`.

use pharos_user::{Error, Handle, Mapped, config_read, dma_alloc, irq_wait, mmio_map};

const COMMON_CFG: u32 = 1;
const NOTIFY_CFG: u32 = 2;
const DEVICE_CFG: u32 = 4;
const CAP_VENDOR: u32 = 0x09;
/// PCI vendor and device ID of a modern virtio-blk device.
const VIRTIO_BLK_ID: u32 = 0x1042_1af4;

// Common configuration offsets (virtio 1.x, 4.1.4.3).
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0c;
const CONFIG_MSIX_VECTOR: usize = 0x10;
const DEVICE_STATUS: usize = 0x14;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_MSIX_VECTOR: usize = 0x1a;
const QUEUE_ENABLE: usize = 0x1c;
const QUEUE_NOTIFY_OFF: usize = 0x1e;
const QUEUE_DESC: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;
const COMMON_LEN: usize = 0x38;

const ACKNOWLEDGE: u8 = 1;
const DRIVER: u8 = 2;
const DRIVER_OK: u8 = 4;
const FEATURES_OK: u8 = 8;
const FAILED: u8 = 128;
const NO_VECTOR: u16 = 0xffff;

/// Largest queue size used.
const MAX_QUEUE: u16 = 16;
// Layout of the two DMA pages: rings and request header in the first,
// data in the second.
const DESC: usize = 0x000;
const AVAIL: usize = 0x100;
const USED: usize = 0x200;
const HEADER: usize = 0x400;
const STATUS: usize = 0x410;
const DATA: usize = 0x1000;
/// Bytes per sector.
pub const SECTOR: usize = 512;
/// Largest read per request.
pub const MAX_READ: usize = 4096;

const NEXT: u16 = 1;
const WRITE: u16 = 2;
const REQUEST_IN: u32 = 0;

/// True if `device` is a modern virtio-blk device.
pub fn is_blk(device: Handle) -> bool {
    config_read(device, 0, 4) == Ok(VIRTIO_BLK_ID)
}

/// A vendor capability's `(BAR, offset, notify multiplier)`.
fn find(device: Handle, cfg_type: u32) -> Option<(u8, u32, u32)> {
    let read = |offset: u8, width| config_read(device, offset, width).ok();
    let mut ptr = read(0x34, 1)? as u8 & 0xfc;
    for _ in 0..48 {
        if ptr < 0x40 {
            return None;
        }
        if read(ptr, 1)? == CAP_VENDOR && read(ptr.checked_add(3)?, 1)? == cfg_type {
            let multiplier = match cfg_type {
                NOTIFY_CFG => read(ptr.checked_add(16)?, 4)?,
                _ => 0,
            };
            return Some((
                read(ptr + 4, 1)? as u8,
                read(ptr.checked_add(8)?, 4)?,
                multiplier,
            ));
        }
        ptr = read(ptr.checked_add(1)?, 1)? as u8 & 0xfc;
    }
    None
}

/// Maps the page holding `offset` of `bar` at `at`; returns it and the
/// offset inside, if `len` bytes fit in the page.
fn map(device: Handle, bar: u8, offset: u32, len: usize, at: u64) -> Option<(Mapped, usize)> {
    let page = u64::from(offset) & !0xfff;
    let inside = (offset & 0xfff) as usize;
    if inside + len > 4096 {
        return None;
    }
    Some((mmio_map(device, bar, page, 4096, at).ok()?, inside))
}

/// Judges the used ring for the one request in flight (data length
/// `len`): `advance` is how far the used index moved, `id` and `used_len`
/// are the new used element, `status` the request's status byte. All of
/// them come from the device and are untrusted.
pub fn check_used(
    advance: u16,
    id: u32,
    used_len: u32,
    len: usize,
    status: u8,
) -> Result<bool, &'static str> {
    match advance {
        0 => return Ok(false),
        1 => {}
        _ => return Err("used index jumped past the requests in flight"),
    }
    if id != 0 {
        return Err("unknown descriptor ID");
    }
    if used_len as usize != len + 1 {
        return Err("wrong used length");
    }
    match status {
        0 => Ok(true),
        _ => Err("device reported an error"),
    }
}

/// One virtio-blk device with one queue.
pub struct Blk {
    common: Mapped,
    c: usize,
    notify: Mapped,
    n: usize,
    queue: Mapped,
    phys: u64,
    size: u16,
    avail: u16,
    used: u16,
    /// Data bytes of the request in flight, if any.
    outstanding: Option<usize>,
    /// Disk size in sectors.
    pub capacity: u64,
}

impl Blk {
    /// Resets and sets up `device`, with queue 0's interrupts on MSI-X
    /// entry `entry`. Uses user addresses `at` to `at + 0x10_2000`. On
    /// failure the device is left with `FAILED` set.
    pub fn init(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        if !is_blk(device) {
            return Err("not a virtio-blk device");
        }
        let (bar, offset, _) = find(device, COMMON_CFG).ok_or("no common configuration")?;
        let (common, c) = map(device, bar, offset, COMMON_LEN, at).ok_or("cannot map common")?;
        let result = Self::setup(device, entry, at, &common, c);
        if result.is_err() {
            common.write8(c + DEVICE_STATUS, FAILED);
        }
        result
    }

    fn setup(
        device: Handle,
        entry: u16,
        at: u64,
        common: &Mapped,
        c: usize,
    ) -> Result<Self, &'static str> {
        let (bar, offset, multiplier) =
            find(device, NOTIFY_CFG).ok_or("no notify configuration")?;
        let (notify, notify_base) =
            map(device, bar, offset, 0, at + 0x1000).ok_or("cannot map notify")?;
        let (bar, offset, _) = find(device, DEVICE_CFG).ok_or("no device configuration")?;
        let (config, d) = map(device, bar, offset, 8, at + 0x2000).ok_or("cannot map config")?;
        let (queue, phys) = dma_alloc(device, 2, at + 0x10_0000).map_err(|_| "no DMA pages")?;

        let status = |v: u8| common.write8(c + DEVICE_STATUS, v);
        status(0);
        if common.read8(c + DEVICE_STATUS) != 0 {
            return Err("reset failed");
        }
        status(ACKNOWLEDGE);
        status(ACKNOWLEDGE | DRIVER);
        // Only VERSION_1 (feature bit 32), and it is required.
        common.write32(c + DEVICE_FEATURE_SELECT, 1);
        if common.read32(c + DEVICE_FEATURE) & 1 == 0 {
            return Err("no VERSION_1");
        }
        common.write32(c + DRIVER_FEATURE_SELECT, 0);
        common.write32(c + DRIVER_FEATURE, 0);
        common.write32(c + DRIVER_FEATURE_SELECT, 1);
        common.write32(c + DRIVER_FEATURE, 1);
        status(ACKNOWLEDGE | DRIVER | FEATURES_OK);
        if common.read8(c + DEVICE_STATUS) & FEATURES_OK == 0 {
            return Err("features refused");
        }
        common.write16(c + CONFIG_MSIX_VECTOR, NO_VECTOR);
        common.write16(c + QUEUE_SELECT, 0);
        let size = common.read16(c + QUEUE_SIZE).min(MAX_QUEUE);
        if !size.is_power_of_two() {
            return Err("bad queue size");
        }
        common.write16(c + QUEUE_SIZE, size);
        common.write16(c + QUEUE_MSIX_VECTOR, entry);
        if common.read16(c + QUEUE_MSIX_VECTOR) != entry {
            return Err("queue vector refused");
        }
        for (reg, part) in [
            (QUEUE_DESC, DESC),
            (QUEUE_DRIVER, AVAIL),
            (QUEUE_DEVICE, USED),
        ] {
            let addr = phys + part as u64;
            common.write32(c + reg, addr as u32);
            common.write32(c + reg + 4, (addr >> 32) as u32);
        }
        let n = usize::from(common.read16(c + QUEUE_NOTIFY_OFF)) * multiplier as usize;
        let n = notify_base
            .checked_add(n)
            .filter(|&n| n + 2 <= 4096)
            .ok_or("notify address outside the page")?;
        let capacity = u64::from(config.read32(d)) | u64::from(config.read32(d + 4)) << 32;
        common.write16(c + QUEUE_ENABLE, 1);
        status(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
        Ok(Self {
            common: *common,
            c,
            notify,
            n,
            queue,
            phys,
            size,
            avail: 0,
            used: 0,
            outstanding: None,
            capacity,
        })
    }

    /// Starts reading `len` bytes (whole sectors, at most [`MAX_READ`])
    /// from `sector`.
    pub fn submit(&mut self, sector: u64, len: usize) -> Result<(), &'static str> {
        if self.outstanding.is_some() {
            return Err("a request is already in flight");
        }
        if len == 0 || len > MAX_READ || len % SECTOR != 0 {
            return Err("bad read length");
        }
        let end = sector.checked_add((len / SECTOR) as u64);
        if end.is_none_or(|end| end > self.capacity) {
            return Err("read past the end of the disk");
        }
        let q = &self.queue;
        q.write32(HEADER, REQUEST_IN);
        q.write32(HEADER + 4, 0);
        q.write64(HEADER + 8, sector);
        q.write8(STATUS, 0xff);
        let descs = [
            (HEADER, 16, NEXT, 1),
            (DATA, len as u32, NEXT | WRITE, 2),
            (STATUS, 1, WRITE, 0),
        ];
        for (i, (part, len, flags, next)) in descs.into_iter().enumerate() {
            let d = DESC + 16 * i;
            q.write64(d, self.phys + part as u64);
            q.write32(d + 8, len);
            q.write16(d + 12, flags);
            q.write16(d + 14, next);
        }
        q.write16(AVAIL + 4 + 2 * usize::from(self.avail % self.size), 0);
        self.avail = self.avail.wrapping_add(1);
        q.write16(AVAIL + 2, self.avail);
        self.outstanding = Some(len);
        self.notify.write16(self.n, 0);
        Ok(())
    }

    /// Checks whether the request in flight finished: `Ok(false)` if not
    /// yet, `Ok(true)` once the device returned it correctly.
    pub fn complete(&mut self) -> Result<bool, &'static str> {
        let len = self.outstanding.ok_or("no request in flight")?;
        let q = &self.queue;
        let used = q.read16(USED + 2);
        let element = USED + 4 + 8 * usize::from(self.used % self.size);
        let verdict = check_used(
            used.wrapping_sub(self.used),
            q.read32(element),
            q.read32(element + 4),
            len,
            q.read8(STATUS),
        );
        if verdict != Ok(false) {
            self.used = used;
            self.outstanding = None;
        }
        verdict
    }

    /// Reads `buf.len()` bytes (whole sectors, at most [`MAX_READ`]) from
    /// `sector`, sleeping on interrupt `irq` until the device is done.
    pub fn read(&mut self, irq: Handle, sector: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        self.submit(sector, buf.len())?;
        while !self.complete()? {
            irq_wait(irq).map_err(|_: Error| "irq_wait failed")?;
        }
        for (i, chunk) in buf.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&self.queue.read64(DATA + 8 * i).to_le_bytes());
        }
        Ok(())
    }

    /// Resets the device (stops all queue activity).
    pub fn reset(&self) {
        self.common.write8(self.c + DEVICE_STATUS, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_ring_values_are_checked() {
        assert_eq!(check_used(0, 9, 9, 512, 9), Ok(false), "not done yet");
        assert_eq!(check_used(1, 0, 513, 512, 0), Ok(true));
        assert_eq!(check_used(1, 0, 4097, 4096, 0), Ok(true));
        assert!(check_used(2, 0, 513, 512, 0).is_err(), "only one in flight");
        assert!(
            check_used(u16::MAX, 0, 513, 512, 0).is_err(),
            "index went back"
        );
        assert!(check_used(1, 1, 513, 512, 0).is_err(), "not our descriptor");
        assert!(check_used(1, 0, 512, 512, 0).is_err(), "short");
        assert!(check_used(1, 0, 4097, 512, 0).is_err(), "long");
        assert!(check_used(1, 0, 513, 512, 1).is_err(), "I/O error");
        assert!(
            check_used(1, 0, 513, 512, 0xff).is_err(),
            "status not written"
        );
    }
}
