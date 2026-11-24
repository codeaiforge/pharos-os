//! The `channel` test kernel's probe (#297, bridge.md, D-036): the Tier 3
//! channel's Pharos end, until the bridge service (#298). It holds the
//! second virtio-console (handle 2), whose port 0 `cargo xtask` joins to
//! the guest's `org.pharos.bridge` port through one host unix socket. It
//! waits up to 120 s for the guest's line `hello from the guest`, answers
//! `hello from pharos`, and exits 0; any other line, a device that breaks
//! the queue rules, or the time running out exits nonzero.

#![no_std]
#![no_main]

use pharos_programs::virtio_console::{Console, RX_BUFFER};
use pharos_user::{Handle, debug_write, endpoint_create, irq_create, irq_notify};
use pharos_user::{receive_timeout, uptime};

pharos_user::entry!(main);

const CONSOLE: Handle = 1;
const DEVICE: Handle = 2;
const BASE: u64 = 0x1000_0000;
const HELLO: &[u8] = b"hello from the guest";
const ANSWER: &[u8] = b"hello from pharos\n";
const WAIT_MICROS: u64 = 120_000_000;

fn say(line: &[u8]) {
    let _ = debug_write(CONSOLE, line);
}

fn main(_: u64) -> u64 {
    let Ok(ep) = endpoint_create() else {
        return 1;
    };
    let Ok(irq) = irq_create(DEVICE, 0) else {
        return 2;
    };
    if irq_notify(irq, ep, 0).is_err() {
        return 3;
    }
    let Ok(mut console) = Console::init(DEVICE, 0, BASE) else {
        say(b"channelprobe: the second virtio-console did not start");
        return 4;
    };
    say(b"channelprobe: waiting for the guest");
    let mut line = [0u8; 64];
    let mut len = 0;
    let mut bytes = [0u8; RX_BUFFER];
    let mut msg = [0u8; 256];
    let deadline = uptime() + WAIT_MICROS;
    loop {
        // Buffers already filled before the first interrupt are taken too.
        loop {
            match console.recv(&mut bytes) {
                Ok(Some(n)) => {
                    for &b in &bytes[..n] {
                        if b == b'\n' {
                            if &line[..len] != HELLO {
                                say(b"channelprobe: the guest sent another line");
                                return 5;
                            }
                            say(b"channelprobe: got hello from the guest");
                            let idle = console.free();
                            if console.send(ANSWER).is_err() {
                                return 6;
                            }
                            // The answer leaves before the probe ends.
                            while console.free() < idle && uptime() < deadline {}
                            say(b"channelprobe: answered");
                            return 0;
                        }
                        if len == line.len() {
                            say(b"channelprobe: the guest's line is too long");
                            return 7;
                        }
                        line[len] = b;
                        len += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => return 8,
            }
        }
        let now = uptime();
        if now >= deadline {
            say(b"channelprobe: no line from the guest in 120 s");
            return 9;
        }
        // A notification, a timeout, or a stray message: look again.
        let _ = receive_timeout(ep, &mut msg, deadline - now);
    }
}
