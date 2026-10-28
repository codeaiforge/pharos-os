//! virtio-net probe for the `virtio_net` test kernel (issue #62).
//!
//! Handles: 1 debug console, 2 the virtio-net device
//! (`MAP | CONFIG | IRQ`), 3 an endpoint with `SEND` only. Binds the device's interrupt to an endpoint with
//! `irq_notify`, prints the MAC, resolves the slirp gateway `10.0.2.2` with
//! ARP, and pings it, waking on notifications only. Frames are built by
//! hand here; the network stack comes with the network service (#63).
//! With argument 1 it crashes (stack overflow) right after sending, while
//! the device is busy. Each step prints `ok <step>` or `FAIL <step>`; the
//! exit code is the number of failures.

#![no_std]
#![no_main]

use pharos_programs::virtio_net::Net;
use pharos_user::{
    Error, Received, debug_write, endpoint_create, irq_create, irq_notify, irq_wait, receive,
};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const DEVICE: u64 = 2;
const SEND_ONLY: u64 = 3;
const BASE: u64 = 0x1000_0000;
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];

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

/// `<label> xx:xx:xx:xx:xx:xx`.
fn print_mac(label: &[u8], mac: [u8; 6]) {
    let mut line = [0u8; 32];
    line[..label.len()].copy_from_slice(label);
    let mut n = label.len();
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            line[n] = b':';
            n += 1;
        }
        line[n] = b"0123456789abcdef"[usize::from(b >> 4)];
        line[n + 1] = b"0123456789abcdef"[usize::from(b & 15)];
        n += 2;
    }
    let _ = debug_write(CONSOLE, &line[..n]);
}

/// The Internet checksum of `bytes`.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn arp_request(mac: [u8; 6]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&OUR_IP);
    f[38..42].copy_from_slice(&GATEWAY);
    f
}

fn ping(mac: [u8; 6], to: [u8; 6]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&to);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    // IPv4: 20 bytes, total 28, TTL 64, ICMP.
    f[14..24].copy_from_slice(&[0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1]);
    f[26..30].copy_from_slice(&OUR_IP);
    f[30..34].copy_from_slice(&GATEWAY);
    let ip = checksum(&f[14..34]).to_be_bytes();
    f[24..26].copy_from_slice(&ip);
    // ICMP echo request, id 0x5048, sequence 1.
    f[34..42].copy_from_slice(&[8, 0, 0, 0, 0x50, 0x48, 0, 1]);
    let icmp = checksum(&f[34..42]).to_be_bytes();
    f[36..38].copy_from_slice(&icmp);
    f
}

/// Recurses until the stack runs out: a page fault in user mode.
fn overflow(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if frame[0] == u64::MAX {
        return 0;
    }
    overflow(depth + 1) + frame[1]
}

/// Waits for frames until `want` accepts one (at most 200 wake-ups). It
/// sleeps on the endpoint first and looks at the device only after a
/// notification: every frame sent or received raises the interrupt, so
/// nothing is missed, and the probe depends on `irq_notify` working.
fn wait_for(
    net: &mut Net,
    events: u64,
    mut want: impl FnMut(&[u8]) -> bool,
) -> Result<(), &'static str> {
    let mut frame = [0u8; 2048];
    let mut buf = [0u8; 8];
    for _ in 0..200 {
        match receive(events, &mut buf) {
            Ok(Received::Notification(1)) => {}
            _ => return Err("unexpected event"),
        }
        net.reclaim()?;
        while let Some(n) = net.recv(&mut frame)? {
            if want(&frame[..n]) {
                return Ok(());
            }
        }
    }
    Err("no matching frame")
}

fn main(arg: u64) -> u64 {
    let mut f = 0;
    let (Ok(irq), Ok(events)) = (irq_create(DEVICE, 0), endpoint_create()) else {
        report(&mut f, "irq_create and endpoint_create", false);
        return f;
    };
    report(
        &mut f,
        "irq_notify needs RECEIVE: MISSING_RIGHT",
        irq_notify(irq, SEND_ONLY, 0) == Err(Error::MissingRight),
    );
    report(
        &mut f,
        "irq_notify binds the interrupt",
        irq_notify(irq, events, 0).is_ok(),
    );
    report(
        &mut f,
        "a bound interrupt: irq_wait IN_USE",
        irq_wait(irq) == Err(Error::InUse),
    );
    report(
        &mut f,
        "bound once: IN_USE",
        irq_notify(irq, events, 1) == Err(Error::InUse),
    );

    let mut net = match Net::init(DEVICE, 0, BASE) {
        Ok(net) => net,
        Err(why) => {
            report(&mut f, why, false);
            return f;
        }
    };
    report(&mut f, "virtio-net set up", true);
    print_mac(b"mac ", net.mac);
    report(
        &mut f,
        "send an ARP request",
        net.send(&arp_request(net.mac)).is_ok(),
    );
    if arg == 1 {
        return overflow(0);
    }

    let mut gateway = [0u8; 6];
    let arp = wait_for(&mut net, events, |fr| {
        let reply = fr.len() >= 42
            && fr[12..14] == [0x08, 0x06]
            && fr[20..22] == [0, 2]
            && fr[28..32] == GATEWAY;
        if reply {
            gateway.copy_from_slice(&fr[22..28]);
        }
        reply
    });
    report(&mut f, "ARP reply from the gateway 10.0.2.2", arp.is_ok());
    print_mac(b"gateway ", gateway);

    report(
        &mut f,
        "send a ping to the gateway",
        net.send(&ping(net.mac, gateway)).is_ok(),
    );
    let echo = wait_for(&mut net, events, |fr| {
        fr.len() >= 42
            && fr[12..14] == [0x08, 0x00]
            && fr[23] == 1
            && fr[26..30] == GATEWAY
            && fr[34] == 0
            && fr[38..42] == [0x50, 0x48, 0, 1]
    });
    report(&mut f, "ping reply from the gateway", echo.is_ok());
    net.reset();
    f
}
