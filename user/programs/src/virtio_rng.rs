//! virtio-rng over the shared virtio transport (tls.md, randomness; #271):
//! the TLS service's seed. One request queue (queue 0) with one
//! device-writable buffer of up to a page, polled (no interrupt vector):
//! the service asks for a seed before each handshake, at most a few times
//! a second. The device's answer is checked ([`check_used`]) and is never
//! trusted to be random: it is mixed with RDSEED where the CPU has it.

use pharos_user::{Handle, Mapped, dma_alloc, sleep, uptime};

use crate::virtio::{Queue, Transport, WRITE};
use crate::virtio_console::check_used;

/// PCI vendor and device ID of a modern virtio-rng device.
pub const VIRTIO_RNG_ID: u32 = 0x1044_1af4;
/// Most bytes one [`Rng::fill`] asks for.
pub const MAX_FILL: usize = 4096;
/// No MSI-X vector: the queue is polled.
const NO_VECTOR: u16 = 0xffff;

/// One virtio-rng device.
pub struct Rng {
    t: Transport,
    q: Queue,
    mem: Mapped,
    phys: u64,
}

impl Rng {
    /// Resets and sets up `device`, using user addresses `at` to
    /// `at + 0x20_1000`. On failure the device is left `FAILED`.
    pub fn init(device: Handle, at: u64) -> Result<Self, &'static str> {
        let t = Transport::open(device, VIRTIO_RNG_ID, 0, at)?;
        let setup = (|| {
            let (ring, ring_phys) =
                dma_alloc(device, 1, at + 0x10_0000).map_err(|_| "no DMA pages")?;
            let (mem, phys) = dma_alloc(device, 1, at + 0x20_0000).map_err(|_| "no DMA pages")?;
            t.negotiate(0)?;
            let q = t.queue(0, NO_VECTOR, ring, 0, ring_phys)?;
            Ok((q, mem, phys))
        })();
        match setup {
            Ok((q, mem, phys)) => {
                t.ready();
                Ok(Self { t, q, mem, phys })
            }
            Err(why) => {
                t.fail();
                Err(why)
            }
        }
    }

    /// Fills `out` (at most [`MAX_FILL`] bytes) from the device, asking
    /// again while it gives fewer; fails if it is not full within
    /// `timeout_us`.
    pub fn fill(&mut self, out: &mut [u8], timeout_us: u64) -> Result<(), &'static str> {
        if out.len() > MAX_FILL {
            return Err("too many bytes asked for");
        }
        let deadline = uptime().saturating_add(timeout_us);
        let mut got = 0;
        while got < out.len() {
            // A device that keeps answering with nothing runs out the time.
            if uptime() >= deadline {
                return Err("no random bytes in time");
            }
            let want = out.len() - got;
            self.q.set(0, self.phys, want as u32, WRITE, 0);
            self.q.offer(0);
            self.q.kick();
            let n = loop {
                let advance = self.q.used_advance();
                if advance > 0 {
                    let (id, len) = self.q.take_used();
                    let (_, n) = check_used(advance, 1, id, self.q.size, |i| i == 0, len, want)?;
                    break n;
                }
                if uptime() >= deadline {
                    // The buffer stays with the device; stop it so it can
                    // never write the page after this.
                    self.t.reset();
                    return Err("no random bytes in time");
                }
                sleep(1);
            };
            for (i, b) in out[got..got + n].iter_mut().enumerate() {
                *b = self.mem.read8(i);
            }
            got += n;
        }
        Ok(())
    }
}
