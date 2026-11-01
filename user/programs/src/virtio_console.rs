//! virtio-console over the shared virtio transport (agents.md, D-018): the
//! trusted path's device. `VERSION_1` only (no multiport), so port 0's
//! receive queue is queue 0 and its transmit queue queue 1. Up to 16
//! receive buffers of 64 bytes and 16 transmit buffers of 256 bytes, each
//! queue in one page; both interrupt on one MSI-X entry. Every used element
//! is checked ([`check_used`]) before use. Output never blocks: when every
//! transmit buffer is in flight, a line is refused.

use pharos_user::{Handle, Mapped, dma_alloc};

use crate::virtio::{Queue, Transport, WRITE};

/// PCI vendor and device ID of a modern virtio-console device.
pub const VIRTIO_CONSOLE_ID: u32 = 0x1043_1af4;
/// Bytes per receive buffer.
pub const RX_BUFFER: usize = 64;
/// Bytes per transmit buffer: the longest write.
pub const TX_BUFFER: usize = 256;
const BUFFERS: usize = 16;

/// Checks a used element: `advance` (how far the used index moved) at most
/// `outstanding` buffers, `id` one of them in a queue of `size`, `len` at
/// most `max`. Returns `(id, len)`.
pub fn check_used(
    advance: u16,
    outstanding: usize,
    id: u32,
    size: u16,
    is_out: impl Fn(usize) -> bool,
    len: u32,
    max: usize,
) -> Result<(usize, usize), &'static str> {
    if usize::from(advance) > outstanding {
        return Err("used index jumped");
    }
    let id = id as usize;
    if id >= usize::from(size) || !is_out(id) {
        return Err("used element for a buffer the device does not have");
    }
    let len = len as usize;
    if len > max {
        return Err("used length past the buffer");
    }
    Ok((id, len))
}

/// One virtio-console device.
pub struct Console {
    t: Transport,
    rx: Queue,
    tx: Queue,
    rx_mem: Mapped,
    rx_phys: u64,
    tx_mem: Mapped,
    tx_phys: u64,
    posted: [bool; BUFFERS],
    busy: [bool; BUFFERS],
}

impl Console {
    /// Resets and sets up `device`, both queues interrupting on MSI-X
    /// entry `entry`, and posts every receive buffer. Uses user addresses
    /// `at` to `at + 0x30_1000`. On failure the device is left `FAILED`.
    pub fn init(device: Handle, entry: u16, at: u64) -> Result<Self, &'static str> {
        let t = Transport::open(device, VIRTIO_CONSOLE_ID, 0, at)?;
        let setup = (|| {
            let (rings, phys) = dma_alloc(device, 2, at + 0x10_0000).map_err(|_| "no DMA pages")?;
            let rx = dma_alloc(device, 1, at + 0x20_0000).map_err(|_| "no DMA pages")?;
            let tx = dma_alloc(device, 1, at + 0x30_0000).map_err(|_| "no DMA pages")?;
            t.negotiate(0)?;
            let rxq = t.queue(0, entry, rings, 0, phys)?;
            let txq = t.queue(1, entry, rings, 4096, phys + 4096)?;
            Ok((rxq, txq, rx, tx))
        })();
        match setup {
            Ok((rx, tx, (rx_mem, rx_phys), (tx_mem, tx_phys))) => {
                let mut c = Self {
                    t,
                    rx,
                    tx,
                    rx_mem,
                    rx_phys,
                    tx_mem,
                    tx_phys,
                    posted: [false; BUFFERS],
                    busy: [false; BUFFERS],
                };
                for i in 0..c.rx.size {
                    c.post(i);
                }
                c.t.ready();
                c.rx.kick();
                Ok(c)
            }
            Err(why) => {
                t.fail();
                Err(why)
            }
        }
    }

    fn post(&mut self, i: u16) {
        let at = self.rx_phys + u64::from(i) * RX_BUFFER as u64;
        self.rx.set(i, at, RX_BUFFER as u32, WRITE, 0);
        self.rx.offer(i);
        self.posted[usize::from(i)] = true;
    }

    /// Takes the bytes of one received buffer into `out` (at least
    /// [`RX_BUFFER`] bytes), reposting it. `Ok(None)` if none is waiting.
    pub fn recv(&mut self, out: &mut [u8]) -> Result<Option<usize>, &'static str> {
        let advance = self.rx.used_advance();
        if advance == 0 {
            return Ok(None);
        }
        let posted = self.posted.iter().filter(|p| **p).count();
        let (id, len) = self.rx.take_used();
        let now = self.posted;
        let (id, n) = check_used(
            advance,
            posted,
            id,
            self.rx.size,
            |i| now[i],
            len,
            RX_BUFFER,
        )?;
        self.posted[id] = false;
        let out = out.get_mut(..n).ok_or("receive buffer too small")?;
        for (o, b) in out.iter_mut().enumerate() {
            *b = self.rx_mem.read8(id * RX_BUFFER + o);
        }
        self.post(id as u16);
        self.rx.kick();
        Ok(Some(n))
    }

    /// Frees transmit buffers the device is done with.
    pub fn reclaim(&mut self) -> Result<(), &'static str> {
        let mut advance = self.tx.used_advance();
        while advance > 0 {
            let busy = self.busy.iter().filter(|b| **b).count();
            let (id, len) = self.tx.take_used();
            let now = self.busy;
            // The device writes nothing into a transmit buffer.
            let (id, _) = check_used(advance, busy, id, self.tx.size, |i| now[i], len, TX_BUFFER)?;
            self.busy[id] = false;
            advance -= 1;
        }
        Ok(())
    }

    /// Writes `bytes` (at most [`TX_BUFFER`]). Fails, without waiting, if
    /// every transmit buffer is in flight.
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.is_empty() || bytes.len() > TX_BUFFER {
            return Err("bad write length");
        }
        self.reclaim()?;
        let size = usize::from(self.tx.size);
        let i = self.busy[..size]
            .iter()
            .position(|b| !b)
            .ok_or("transmit queue full")?;
        for (o, &b) in bytes.iter().enumerate() {
            self.tx_mem.write8(i * TX_BUFFER + o, b);
        }
        let at = self.tx_phys + (i * TX_BUFFER) as u64;
        self.tx.set(i as u16, at, bytes.len() as u32, 0, 0);
        self.busy[i] = true;
        self.tx.offer(i as u16);
        self.tx.kick();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_values_are_checked() {
        let all = |_| true;
        assert_eq!(check_used(1, 16, 3, 16, all, 5, 64), Ok((3, 5)));
        assert_eq!(
            check_used(16, 16, 15, 16, all, 64, 64),
            Ok((15, 64)),
            "full"
        );
        assert_eq!(check_used(1, 1, 0, 16, all, 0, 64), Ok((0, 0)), "empty");
        assert!(
            check_used(2, 1, 0, 16, all, 1, 64).is_err(),
            "more than outstanding"
        );
        assert!(
            check_used(1, 16, 16, 16, all, 1, 64).is_err(),
            "ID out of range"
        );
        assert!(
            check_used(1, 16, 2, 16, |i| i != 2, 1, 64).is_err(),
            "not posted"
        );
        assert!(
            check_used(1, 16, 0, 16, all, 65, 64).is_err(),
            "past the buffer"
        );
        assert!(check_used(1, 16, 0, 16, all, u32::MAX, 64).is_err());
    }
}
