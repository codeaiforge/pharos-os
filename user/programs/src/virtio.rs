//! Minimal virtio 1.x block access over the modern PCI transport
//! ([drivers.md](../../../docs/architecture/drivers.md)): find the
//! configuration structures, set up one split virtqueue in one DMA page,
//! and read one 512-byte sector at a time. Included by programs with
//! `#[path]`. Device values are checked before use.

use pharos_user::{Handle, Mapped, config_read, dma_alloc, mmio_map};

const COMMON_CFG: u32 = 1;
const NOTIFY_CFG: u32 = 2;
const CAP_VENDOR: u32 = 0x09;

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
const NO_VECTOR: u16 = 0xffff;

/// Queue size used (a power of two).
const QSIZE: u16 = 8;
// Layout of the one DMA page.
const DESC: usize = 0x000;
const AVAIL: usize = 0x100;
const USED: usize = 0x200;
const HEADER: usize = 0x400;
const STATUS: usize = 0x410;
const DATA: usize = 0x800;
/// Bytes per sector.
pub const SECTOR: usize = 512;

const NEXT: u16 = 1;
const WRITE: u16 = 2;
const REQUEST_IN: u32 = 0;

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

/// One virtio-blk device with one queue.
pub struct Blk {
    common: Mapped,
    c: usize,
    notify: Mapped,
    n: usize,
    queue: Mapped,
    phys: u64,
    avail: u16,
    used: u16,
}

impl Blk {
    /// Resets and sets up `device`, with queue 0's interrupts on MSI-X
    /// entry `entry`. Uses user addresses `at` to `at + 0x10_1000`.
    pub fn init(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        let (bar, offset, _) = find(device, COMMON_CFG).ok_or("no common configuration")?;
        let (common, c) = map(device, bar, offset, COMMON_LEN, at).ok_or("cannot map common")?;
        let (bar, offset, multiplier) =
            find(device, NOTIFY_CFG).ok_or("no notify configuration")?;
        let (notify, notify_base) =
            map(device, bar, offset, 0, at + 0x1000).ok_or("cannot map notify")?;
        let (queue, phys) = dma_alloc(device, 1, at + 0x10_0000).map_err(|_| "no DMA page")?;

        let status = |v: u8| common.write8(c + DEVICE_STATUS, v);
        status(0);
        if common.read8(c + DEVICE_STATUS) != 0 {
            return Err("reset failed");
        }
        status(ACKNOWLEDGE);
        status(ACKNOWLEDGE | DRIVER);
        // Only VERSION_1 (feature bit 32).
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
        if common.read16(c + QUEUE_SIZE) < QSIZE {
            return Err("queue too small");
        }
        common.write16(c + QUEUE_SIZE, QSIZE);
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
        common.write16(c + QUEUE_ENABLE, 1);
        status(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
        Ok(Self {
            common,
            c,
            notify,
            n,
            queue,
            phys,
            avail: 0,
            used: 0,
        })
    }

    /// Starts reading `sector` (one request at a time).
    pub fn submit_read(&mut self, sector: u64) {
        let q = &self.queue;
        q.write32(HEADER, REQUEST_IN);
        q.write32(HEADER + 4, 0);
        q.write64(HEADER + 8, sector);
        q.write8(STATUS, 0xff);
        let descs = [
            (HEADER, 16, NEXT, 1),
            (DATA, SECTOR as u32, NEXT | WRITE, 2),
            (STATUS, 1, WRITE, 0),
        ];
        for (i, (part, len, flags, next)) in descs.into_iter().enumerate() {
            let d = DESC + 16 * i;
            q.write64(d, self.phys + part as u64);
            q.write32(d + 8, len);
            q.write16(d + 12, flags);
            q.write16(d + 14, next);
        }
        q.write16(AVAIL + 4 + 2 * usize::from(self.avail % QSIZE), 0);
        self.avail = self.avail.wrapping_add(1);
        q.write16(AVAIL + 2, self.avail);
        self.notify.write16(self.n, 0);
    }

    /// Checks the request finished: exactly one new used entry, for
    /// descriptor 0, with status OK.
    pub fn complete(&mut self) -> Result<(), &'static str> {
        let q = &self.queue;
        let used = q.read16(USED + 2);
        match used.wrapping_sub(self.used) {
            0 => return Err("nothing used yet"),
            1 => {}
            _ => return Err("used index jumped"),
        }
        if q.read32(USED + 4 + 8 * usize::from(self.used % QSIZE)) != 0 {
            return Err("unknown descriptor ID");
        }
        self.used = used;
        match q.read8(STATUS) {
            0 => Ok(()),
            _ => Err("device reported an error"),
        }
    }

    /// The 8 bytes at `offset` of the last sector read.
    pub fn data64(&self, offset: usize) -> u64 {
        self.queue.read64(DATA + offset % SECTOR / 8 * 8)
    }

    /// Resets the device (stops all queue activity).
    pub fn reset(&self) {
        self.common.write8(self.c + DEVICE_STATUS, 0);
    }
}
