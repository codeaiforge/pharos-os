//! virtio-net over the shared virtio transport (networking.md): `VERSION_1`
//! and `MAC` only, one receive and one transmit queue of up to 16 buffers
//! of 2 KiB, each frame preceded by the 12-byte virtio-net header. Both
//! queues interrupt on one MSI-X entry. Every used element is checked
//! ([`check_rx`], [`check_tx`]) before use.

use pharos_user::{Handle, Mapped, dma_alloc};

use crate::virtio::{Queue, Transport, WRITE};

/// PCI vendor and device ID of a modern virtio-net device.
pub const VIRTIO_NET_ID: u32 = 0x1041_1af4;
/// Feature bit: the device configuration holds the MAC address.
const FEATURE_MAC: u32 = 1 << 5;
/// The virtio-net header before every frame (`VERSION_1`).
pub const HEADER: usize = 12;
/// Bytes per buffer.
pub const BUFFER: usize = 2048;
/// Shortest frame: an Ethernet header.
pub const MIN_FRAME: usize = 14;
/// Longest frame sent: Ethernet header plus a 1500-byte payload.
pub const MAX_FRAME: usize = 1514;
const BUFFERS: usize = 16;

/// Checks a used receive element: `advance` (how far the used index
/// moved) at most `posted` buffers, `id` a posted buffer of a queue of
/// `size`, `len` at least a header plus an Ethernet header and at most a
/// buffer. Returns the frame length.
pub fn check_rx(
    advance: u16,
    posted: usize,
    id: u32,
    size: u16,
    is_posted: impl Fn(usize) -> bool,
    len: u32,
) -> Result<usize, &'static str> {
    if usize::from(advance) > posted {
        return Err("receive used index jumped");
    }
    let id = id as usize;
    if id >= usize::from(size) || !is_posted(id) {
        return Err("receive descriptor not posted");
    }
    let len = len as usize;
    if !(HEADER + MIN_FRAME..=BUFFER).contains(&len) {
        return Err("bad receive length");
    }
    Ok(len - HEADER)
}

/// Checks a used transmit element: `advance` at most `busy` buffers in
/// flight, `id` one of them.
pub fn check_tx(
    advance: u16,
    busy: usize,
    id: u32,
    size: u16,
    is_busy: impl Fn(usize) -> bool,
) -> Result<usize, &'static str> {
    if usize::from(advance) > busy {
        return Err("transmit used index jumped");
    }
    let id = id as usize;
    if id >= usize::from(size) || !is_busy(id) {
        return Err("transmit completion for a buffer not in flight");
    }
    Ok(id)
}

/// One virtio-net device.
pub struct Net {
    t: Transport,
    rx: Queue,
    tx: Queue,
    rx_mem: Mapped,
    rx_phys: u64,
    tx_mem: Mapped,
    tx_phys: u64,
    posted: [bool; BUFFERS],
    busy: [bool; BUFFERS],
    /// The device's MAC address.
    pub mac: [u8; 6],
}

impl Net {
    /// Resets and sets up `device`, both queues interrupting on MSI-X
    /// entry `entry`, and posts every receive buffer. Uses user addresses
    /// `at` to `at + 0x30_8000`. On failure the device is left `FAILED`.
    pub fn init(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        let t = Transport::open(device, VIRTIO_NET_ID, 6, at)?;
        let net = Self::setup(&t, device, entry, at);
        match net {
            Ok((rx, tx, rx_dma, tx_dma)) => {
                let mut mac = [0u8; 6];
                for (i, b) in mac.iter_mut().enumerate() {
                    *b = t.config.read8(t.d + i);
                }
                let mut net = Self {
                    t,
                    rx,
                    tx,
                    rx_mem: rx_dma.0,
                    rx_phys: rx_dma.1,
                    tx_mem: tx_dma.0,
                    tx_phys: tx_dma.1,
                    posted: [false; BUFFERS],
                    busy: [false; BUFFERS],
                    mac,
                };
                for i in 0..net.rx.size {
                    net.post(i);
                }
                net.t.ready();
                net.rx.kick();
                Ok(net)
            }
            Err(why) => {
                t.fail();
                Err(why)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn setup(
        t: &Transport,
        device: Handle,
        entry: u16,
        at: u64,
    ) -> Result<(Queue, Queue, (Mapped, u64), (Mapped, u64)), &'static str> {
        let (rings, phys) = dma_alloc(device, 2, at + 0x10_0000).map_err(|_| "no DMA pages")?;
        let pages = (BUFFERS * BUFFER / 4096) as u64;
        let rx = dma_alloc(device, pages, at + 0x20_0000).map_err(|_| "no DMA pages")?;
        let tx = dma_alloc(device, pages, at + 0x30_0000).map_err(|_| "no DMA pages")?;
        t.negotiate(FEATURE_MAC)?;
        let rxq = t.queue(
            0,
            entry,
            rings.try_clone().ok_or("not DMA memory")?,
            0,
            phys,
        )?;
        let txq = t.queue(1, entry, rings, 4096, phys + 4096)?;
        Ok((rxq, txq, rx, tx))
    }

    fn post(&mut self, i: u16) {
        let at = self.rx_phys + u64::from(i) * BUFFER as u64;
        self.rx.set(i, at, BUFFER as u32, WRITE, 0);
        self.rx.offer(i);
        self.posted[usize::from(i)] = true;
    }

    /// Frees transmit buffers the device is done with.
    pub fn reclaim(&mut self) -> Result<(), &'static str> {
        let mut advance = self.tx.used_advance();
        while advance > 0 {
            let busy = self.busy.iter().filter(|b| **b).count();
            let (id, _) = self.tx.take_used();
            let busy_now = self.busy;
            let id = check_tx(advance, busy, id, self.tx.size, |i| busy_now[i])?;
            self.busy[id] = false;
            advance -= 1;
        }
        Ok(())
    }

    /// Sends one frame (14 to 1514 bytes). Fails if every transmit buffer
    /// is in flight.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if !(MIN_FRAME..=MAX_FRAME).contains(&frame.len()) {
            return Err("bad frame length");
        }
        self.reclaim()?;
        let size = usize::from(self.tx.size);
        let i = self.busy[..size]
            .iter()
            .position(|b| !b)
            .ok_or("transmit queue full")?;
        let base = i * BUFFER;
        for o in (0..HEADER).step_by(4) {
            self.tx_mem.write32(base + o, 0);
        }
        for (o, &b) in frame.iter().enumerate() {
            self.tx_mem.write8(base + HEADER + o, b);
        }
        let len = (HEADER + frame.len()) as u32;
        self.tx.set(i as u16, self.tx_phys + base as u64, len, 0, 0);
        self.busy[i] = true;
        self.tx.offer(i as u16);
        self.tx.kick();
        Ok(())
    }

    /// Takes one received frame into `out` (at least 2034 bytes), reposting
    /// its buffer. `Ok(None)` if none is waiting.
    pub fn recv(&mut self, out: &mut [u8]) -> Result<Option<usize>, &'static str> {
        let advance = self.rx.used_advance();
        if advance == 0 {
            return Ok(None);
        }
        let posted = self.posted.iter().filter(|p| **p).count();
        let (id, len) = self.rx.take_used();
        let posted_now = self.posted;
        let n = check_rx(advance, posted, id, self.rx.size, |i| posted_now[i], len)?;
        let id = id as usize;
        self.posted[id] = false;
        let base = id * BUFFER + HEADER;
        let out = out.get_mut(..n).ok_or("receive buffer too small")?;
        for (o, b) in out.iter_mut().enumerate() {
            *b = self.rx_mem.read8(base + o);
        }
        self.post(id as u16);
        self.rx.kick();
        Ok(Some(n))
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
    fn receive_values_are_checked() {
        let all = |_| true;
        assert_eq!(check_rx(1, 16, 3, 16, all, 12 + 60), Ok(60));
        assert_eq!(check_rx(16, 16, 0, 16, all, 2048), Ok(2036), "full buffer");
        assert!(
            check_rx(17, 16, 0, 16, all, 100).is_err(),
            "more than posted"
        );
        assert!(
            check_rx(1, 16, 16, 16, all, 100).is_err(),
            "ID out of range"
        );
        assert!(
            check_rx(1, 16, 2, 16, |i| i != 2, 100).is_err(),
            "not posted"
        );
        assert!(check_rx(1, 16, 0, 16, all, 12 + 13).is_err(), "runt frame");
        assert!(
            check_rx(1, 16, 0, 16, all, 2049).is_err(),
            "past the buffer"
        );
        assert!(check_rx(1, 16, 0, 16, all, u32::MAX).is_err());
    }

    #[test]
    fn transmit_values_are_checked() {
        let busy = |i| i == 4;
        assert_eq!(check_tx(1, 1, 4, 16, busy), Ok(4));
        assert!(check_tx(2, 1, 4, 16, busy).is_err(), "more than in flight");
        assert!(check_tx(1, 1, 5, 16, busy).is_err(), "not in flight");
        assert!(check_tx(1, 1, 99, 16, busy).is_err(), "ID out of range");
    }
}
