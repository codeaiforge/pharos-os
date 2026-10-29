//! virtio 1.x over the modern PCI transport
//! ([drivers.md](../../../docs/architecture/drivers.md)): finding the
//! configuration structures, feature negotiation, and split virtqueues
//! ([`Transport`], [`Queue`]), and the block device on top ([`Blk`]: one
//! queue, one read at a time). Every value a device returns is checked
//! before use; any failure during setup sets `FAILED`.

use pharos_user::{Error, Handle, Mapped, config_read, dma_alloc, irq_wait, mmio_map};

const COMMON_CFG: u32 = 1;
const NOTIFY_CFG: u32 = 2;
const DEVICE_CFG: u32 = 4;
const CAP_VENDOR: u32 = 0x09;
/// PCI vendor and device ID of a modern virtio-blk device.
pub const VIRTIO_BLK_ID: u32 = 0x1042_1af4;

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
pub const MAX_QUEUE: u16 = 16;
// Layout of one queue in its page: descriptors, available ring, used ring.
const DESC: usize = 0x000;
const AVAIL: usize = 0x100;
const USED: usize = 0x200;

/// Descriptor flag: the chain continues at `next`.
pub const NEXT: u16 = 1;
/// Descriptor flag: the device writes this buffer.
pub const WRITE: u16 = 2;

/// True if `device` has the PCI vendor and device ID `id`.
pub fn has_id(device: Handle, id: u32) -> bool {
    config_read(device, 0, 4) == Ok(id)
}

/// True if `device` is a modern virtio-blk device.
pub fn is_blk(device: Handle) -> bool {
    has_id(device, VIRTIO_BLK_ID)
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

/// A device's configuration structures, mapped.
pub struct Transport {
    common: Mapped,
    c: usize,
    notify: Mapped,
    notify_base: usize,
    multiplier: u32,
    /// The device-specific configuration, at offset [`Self::d`].
    pub config: Mapped,
    pub d: usize,
}

impl Transport {
    /// Checks `device` has PCI ID `id` and maps its common, notify, and
    /// device configuration (at least `config_len` bytes) at `at` to
    /// `at + 0x3000`. On failure after the common configuration is mapped,
    /// the device is left `FAILED`.
    pub fn open(device: Handle, id: u32, config_len: usize, at: u64) -> Result<Self, &'static str> {
        if !has_id(device, id) {
            return Err("wrong device type");
        }
        let (bar, offset, _) = find(device, COMMON_CFG).ok_or("no common configuration")?;
        let (common, c) = map(device, bar, offset, COMMON_LEN, at).ok_or("cannot map common")?;
        let t = find(device, NOTIFY_CFG)
            .ok_or("no notify configuration")
            .and_then(|(bar, offset, multiplier)| {
                let (notify, notify_base) =
                    map(device, bar, offset, 0, at + 0x1000).ok_or("cannot map notify")?;
                let (bar, offset, _) = find(device, DEVICE_CFG).ok_or("no device configuration")?;
                let (config, d) =
                    map(device, bar, offset, config_len, at + 0x2000).ok_or("cannot map config")?;
                Ok(Self {
                    common,
                    c,
                    notify,
                    notify_base,
                    multiplier,
                    config,
                    d,
                })
            });
        if t.is_err() {
            common.write8(c + DEVICE_STATUS, FAILED);
        }
        t
    }

    fn status(&self, v: u8) {
        self.common.write8(self.c + DEVICE_STATUS, v);
    }

    /// Resets the device and negotiates `VERSION_1` plus the low feature
    /// bits `wanted`, all of which the device must offer.
    pub fn negotiate(&self, wanted: u32) -> Result<(), &'static str> {
        let (common, c) = (&self.common, self.c);
        self.status(0);
        if common.read8(c + DEVICE_STATUS) != 0 {
            return Err("reset failed");
        }
        self.status(ACKNOWLEDGE);
        self.status(ACKNOWLEDGE | DRIVER);
        common.write32(c + DEVICE_FEATURE_SELECT, 1);
        if common.read32(c + DEVICE_FEATURE) & 1 == 0 {
            return Err("no VERSION_1");
        }
        common.write32(c + DEVICE_FEATURE_SELECT, 0);
        if common.read32(c + DEVICE_FEATURE) & wanted != wanted {
            return Err("a needed feature is missing");
        }
        common.write32(c + DRIVER_FEATURE_SELECT, 0);
        common.write32(c + DRIVER_FEATURE, wanted);
        common.write32(c + DRIVER_FEATURE_SELECT, 1);
        common.write32(c + DRIVER_FEATURE, 1);
        self.status(ACKNOWLEDGE | DRIVER | FEATURES_OK);
        if common.read8(c + DEVICE_STATUS) & FEATURES_OK == 0 {
            return Err("features refused");
        }
        common.write16(c + CONFIG_MSIX_VECTOR, NO_VECTOR);
        Ok(())
    }

    /// Sets up queue `index` (size min(device maximum, 16)) in the page at
    /// offset `base` of `mem` (physical `phys`), interrupts on MSI-X entry
    /// `entry`, and enables it.
    pub fn queue(
        &self,
        index: u16,
        entry: u16,
        mem: Mapped,
        base: usize,
        phys: u64,
    ) -> Result<Queue, &'static str> {
        let (common, c) = (&self.common, self.c);
        common.write16(c + QUEUE_SELECT, index);
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
        let n = usize::from(common.read16(c + QUEUE_NOTIFY_OFF)) * self.multiplier as usize;
        let n = self
            .notify_base
            .checked_add(n)
            .filter(|&n| n + 2 <= 4096)
            .ok_or("notify address outside the page")?;
        common.write16(c + QUEUE_ENABLE, 1);
        Ok(Queue {
            mem,
            base,
            size,
            index,
            avail: 0,
            used: 0,
            notify: self.notify,
            n,
        })
    }

    /// Tells the device the driver is ready (`DRIVER_OK`).
    pub fn ready(&self) {
        self.status(ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);
    }

    /// Marks the device `FAILED`.
    pub fn fail(&self) {
        self.status(FAILED);
    }

    /// Resets the device (stops all queue activity).
    pub fn reset(&self) {
        self.status(0);
    }
}

/// One split virtqueue.
pub struct Queue {
    mem: Mapped,
    base: usize,
    /// Number of descriptors.
    pub size: u16,
    index: u16,
    avail: u16,
    used: u16,
    notify: Mapped,
    n: usize,
}

impl Queue {
    /// Writes descriptor `i`.
    pub fn set(&self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let d = self.base + DESC + 16 * usize::from(i % self.size);
        self.mem.write64(d, addr);
        self.mem.write32(d + 8, len);
        self.mem.write16(d + 12, flags);
        self.mem.write16(d + 14, next);
    }

    /// Makes the chain starting at descriptor `head` available.
    pub fn offer(&mut self, head: u16) {
        let slot = self.base + AVAIL + 4 + 2 * usize::from(self.avail % self.size);
        self.mem.write16(slot, head);
        self.avail = self.avail.wrapping_add(1);
        self.mem.write16(self.base + AVAIL + 2, self.avail);
    }

    /// Tells the device there is new work.
    pub fn kick(&self) {
        self.notify.write16(self.n, self.index);
    }

    /// How far the device moved the used index since the last
    /// [`Self::take_used`] (untrusted: check against what is outstanding).
    pub fn used_advance(&self) -> u16 {
        self.mem
            .read16(self.base + USED + 2)
            .wrapping_sub(self.used)
    }

    /// The next used element `(id, len)` (untrusted), and moves past it.
    pub fn take_used(&mut self) -> (u32, u32) {
        let e = self.base + USED + 4 + 8 * usize::from(self.used % self.size);
        self.used = self.used.wrapping_add(1);
        (self.mem.read32(e), self.mem.read32(e + 4))
    }
}

// ---- Block device ----------------------------------------------------------

/// Bytes per sector.
pub const SECTOR: usize = 512;
/// Largest read or write per request.
pub const MAX_READ: usize = 4096;
/// Feature bit: the device accepts flush requests.
pub const BLK_F_FLUSH: u32 = 1 << 9;
// In the first DMA page after the queue: request header and status. Data in
// the second page.
const HEADER: usize = 0x400;
const STATUS: usize = 0x410;
const DATA: usize = 0x1000;
const REQUEST_IN: u32 = 0;
const REQUEST_OUT: u32 = 1;
const REQUEST_FLUSH: u32 = 4;

/// What a request does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
    Flush,
}

impl Op {
    /// Bytes the device writes for a request with `len` data bytes: the
    /// data (reads only) and the status byte.
    pub fn used_len(self, len: usize) -> usize {
        match self {
            Self::Read => len + 1,
            Self::Write | Self::Flush => 1,
        }
    }
}

/// Judges the used ring for the one request in flight, for which the
/// device should have written `expected` bytes ([`Op::used_len`]):
/// `advance` is how far the used index moved, `id` and `used_len` are the
/// new used element, `status` the request's status byte. All of them come
/// from the device and are untrusted.
pub fn check_used(
    advance: u16,
    id: u32,
    used_len: u32,
    expected: usize,
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
    if used_len as usize != expected {
        return Err("wrong used length");
    }
    match status {
        0 => Ok(true),
        _ => Err("device reported an error"),
    }
}

/// One virtio-blk device with one queue.
pub struct Blk {
    t: Transport,
    q: Queue,
    mem: Mapped,
    phys: u64,
    /// Bytes the device should write for the request in flight, if any.
    outstanding: Option<usize>,
    /// Disk size in sectors.
    pub capacity: u64,
}

impl Blk {
    /// Resets and sets up `device`, with queue 0's interrupts on MSI-X
    /// entry `entry`. Uses user addresses `at` to `at + 0x10_2000`. On
    /// failure the device is left with `FAILED` set.
    pub fn init(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        Self::init_with(device, entry, at, 0)
    }

    /// [`Self::init`] that also negotiates [`BLK_F_FLUSH`], for drivers
    /// that write.
    pub fn init_flushing(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        Self::init_with(device, entry, at, BLK_F_FLUSH)
    }

    fn init_with(device: Handle, entry: u16, at: u64, features: u32) -> Result<Self, &'static str> {
        if !is_blk(device) {
            return Err("not a virtio-blk device");
        }
        let t = Transport::open(device, VIRTIO_BLK_ID, 8, at)?;
        let (mem, phys) = match dma_alloc(device, 2, at + 0x10_0000) {
            Ok(dma) => dma,
            Err(_) => {
                t.fail();
                return Err("no DMA pages");
            }
        };
        let q = match t
            .negotiate(features)
            .and_then(|()| t.queue(0, entry, mem, 0, phys))
        {
            Ok(q) => q,
            Err(why) => {
                t.fail();
                return Err(why);
            }
        };
        let capacity = u64::from(t.config.read32(t.d)) | u64::from(t.config.read32(t.d + 4)) << 32;
        t.ready();
        Ok(Self {
            t,
            q,
            mem,
            phys,
            outstanding: None,
            capacity,
        })
    }

    /// Starts reading `len` bytes (whole sectors, at most [`MAX_READ`])
    /// from `sector`.
    pub fn submit(&mut self, sector: u64, len: usize) -> Result<(), &'static str> {
        self.start(Op::Read, sector, len)
    }

    /// Starts request `op`: for reads and writes, `len` bytes (whole
    /// sectors, at most [`MAX_READ`]) at `sector`, in the data page (a
    /// write's data must be there already); a flush has no data.
    fn start(&mut self, op: Op, sector: u64, len: usize) -> Result<(), &'static str> {
        if self.outstanding.is_some() {
            return Err("a request is already in flight");
        }
        if op != Op::Flush {
            if len == 0 || len > MAX_READ || len % SECTOR != 0 {
                return Err("bad request length");
            }
            let end = sector.checked_add((len / SECTOR) as u64);
            if end.is_none_or(|end| end > self.capacity) {
                return Err("request past the end of the disk");
            }
        }
        let kind = match op {
            Op::Read => REQUEST_IN,
            Op::Write => REQUEST_OUT,
            Op::Flush => REQUEST_FLUSH,
        };
        let m = &self.mem;
        m.write32(HEADER, kind);
        m.write32(HEADER + 4, 0);
        m.write64(HEADER + 8, if op == Op::Flush { 0 } else { sector });
        m.write8(STATUS, 0xff);
        self.q.set(0, self.phys + HEADER as u64, 16, NEXT, 1);
        let status = self.phys + STATUS as u64;
        match op {
            Op::Flush => self.q.set(1, status, 1, WRITE, 0),
            _ => {
                // Reads: the device writes the data; writes: it reads it.
                let flags = if op == Op::Read { NEXT | WRITE } else { NEXT };
                self.q.set(1, self.phys + DATA as u64, len as u32, flags, 2);
                self.q.set(2, status, 1, WRITE, 0);
            }
        }
        self.q.offer(0);
        self.outstanding = Some(op.used_len(len));
        self.q.kick();
        Ok(())
    }

    /// Waits on `irq` until the request in flight is done.
    fn wait(&mut self, irq: Handle) -> Result<(), &'static str> {
        while !self.complete()? {
            irq_wait(irq).map_err(|_: Error| "irq_wait failed")?;
        }
        Ok(())
    }

    /// Writes `data` (whole sectors, at most [`MAX_READ`]) at `sector`,
    /// sleeping on `irq` until the device has it (not necessarily durable:
    /// see [`Self::flush`]).
    pub fn write(&mut self, irq: Handle, sector: u64, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_READ {
            return Err("bad request length");
        }
        self.mem.write_bytes(DATA, data);
        self.start(Op::Write, sector, data.len())?;
        self.wait(irq)
    }

    /// Makes every completed write durable (needs [`Self::init_flushing`]).
    pub fn flush(&mut self, irq: Handle) -> Result<(), &'static str> {
        self.start(Op::Flush, 0, 0)?;
        self.wait(irq)
    }

    /// Checks whether the request in flight finished: `Ok(false)` if not
    /// yet, `Ok(true)` once the device returned it correctly.
    pub fn complete(&mut self) -> Result<bool, &'static str> {
        let len = self.outstanding.ok_or("no request in flight")?;
        let advance = self.q.used_advance();
        if advance == 0 {
            return Ok(false);
        }
        let (id, used_len) = self.q.take_used();
        self.outstanding = None;
        check_used(advance, id, used_len, len, self.mem.read8(STATUS))
    }

    /// Reads `buf.len()` bytes (whole sectors, at most [`MAX_READ`]) from
    /// `sector`, sleeping on interrupt `irq` until the device is done.
    pub fn read(&mut self, irq: Handle, sector: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        self.submit(sector, buf.len())?;
        self.wait(irq)?;
        self.mem.read_bytes(DATA, buf);
        Ok(())
    }

    /// Resets the device (stops all queue activity).
    pub fn reset(&self) {
        self.t.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_ring_values_are_checked() {
        let read = Op::Read.used_len(512);
        assert_eq!(check_used(0, 9, 9, read, 9), Ok(false), "not done yet");
        assert_eq!(check_used(1, 0, 513, read, 0), Ok(true));
        assert_eq!(check_used(1, 0, 4097, Op::Read.used_len(4096), 0), Ok(true));
        assert!(
            check_used(2, 0, 513, read, 0).is_err(),
            "only one in flight"
        );
        assert!(
            check_used(u16::MAX, 0, 513, read, 0).is_err(),
            "index went back"
        );
        assert!(
            check_used(1, 1, 513, read, 0).is_err(),
            "not our descriptor"
        );
        assert!(check_used(1, 0, 512, read, 0).is_err(), "short");
        assert!(check_used(1, 0, 4097, read, 0).is_err(), "long");
        assert!(check_used(1, 0, 513, read, 1).is_err(), "I/O error");
        assert!(
            check_used(1, 0, 513, read, 0xff).is_err(),
            "status not written"
        );
        // Writes and flushes: the device writes only the status byte.
        assert_eq!(Op::Write.used_len(4096), 1);
        assert_eq!(Op::Flush.used_len(0), 1);
        assert_eq!(check_used(1, 0, 1, Op::Write.used_len(4096), 0), Ok(true));
        assert!(
            check_used(1, 0, 4097, Op::Write.used_len(4096), 0).is_err(),
            "a write writes no data"
        );
    }
}
