//! Clients of the network service for the `network` test kernel (issue
//! #63). Handles: 1 debug console, 2 the network capability (`SEND` on the
//! service endpoint, badged by `init` with this client's UDP port), 3
//! `init`'s report endpoint (the echoer only).
//!
//! - Argument 1, port 40000: pings the gateway, exchanges a datagram with
//!   the host echo server at `10.0.2.2:47000` (run by `cargo xtask`, issue
//!   #64), sends a datagram to port 40001 on our own address and gets `pong` back, sends one to a port no
//!   client holds, and checks the service's counters.
//! - Argument 2, port 40001: registers, reports ready, answers one
//!   datagram with `pong`, then idles.
//! - Argument 3, badge 0: must be refused.
//!
//! Each step prints `ok <step>` or `FAIL <step>`; the exit code is the
//! number of failures.

#![no_std]
#![no_main]

use pharos_programs::net::client::{NO_PORT, OK, ping, raw, recv, send_to, stats};
use pharos_programs::net::{GATEWAY, OUR_IP, stat};
use pharos_proto::net::{NAME, Request, VERSION, encode};
use pharos_proto::{Info, versions};
use pharos_user::{Error, debug_write, endpoint_create, receive, send, try_send};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;
const NET: u64 = 2;
const REPORT: u64 = 3;
/// The UDP echo server `cargo xtask` runs on the host (networking.md).
const HOST_ECHO_PORT: u16 = 47000;

fn report(failures: &mut u64, step: &str, ok: bool) {
    let mut line = [0u8; 96];
    let prefix: &[u8] = if ok { b"ok " } else { b"FAIL " };
    let n = (prefix.len() + step.len()).min(line.len());
    line[..prefix.len()].copy_from_slice(prefix);
    line[prefix.len()..n].copy_from_slice(&step.as_bytes()[..n - prefix.len()]);
    let _ = debug_write(CONSOLE, &line[..n]);
    if !ok {
        *failures += 1;
    }
}

fn idle() -> ! {
    let mut buf = [0u8; 8];
    if let Ok(e) = endpoint_create() {
        loop {
            let _ = receive(e, &mut buf);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

fn main(arg: u64) -> u64 {
    let mut f = 0;
    let Ok(reply) = endpoint_create() else {
        return 1;
    };
    let mut buf = [0u8; 256];
    match arg {
        1 => {
            report(
                &mut f,
                "sender: non-blocking send with nobody waiting: WOULD_BLOCK",
                try_send(reply, b"x") == Err(Error::WouldBlock),
            );
            report(
                &mut f,
                "sender: ping 10.0.2.2 answered",
                ping(NET, reply, GATEWAY, 1) == Ok(OK),
            );
            report(
                &mut f,
                "sender: datagram to the host echo server accepted",
                send_to(NET, reply, GATEWAY, HOST_ECHO_PORT, b"echo me") == Ok(OK),
            );
            let got = recv(NET, reply, &mut buf);
            report(
                &mut f,
                "sender: echo from 10.0.2.2:47000",
                got.is_ok_and(|(s, ip, port, n)| {
                    s == OK && ip == GATEWAY && port == HOST_ECHO_PORT && &buf[..n] == b"echo me"
                }),
            );
            report(
                &mut f,
                "sender: datagram to 10.0.2.15:40001 accepted",
                send_to(NET, reply, OUR_IP, 40001, b"hello from 40000") == Ok(OK),
            );
            let got = recv(NET, reply, &mut buf);
            report(
                &mut f,
                "sender: pong from 10.0.2.15:40001",
                got.is_ok_and(|(s, ip, port, n)| {
                    s == OK && ip == OUR_IP && port == 40001 && &buf[..n] == b"pong"
                }),
            );
            report(
                &mut f,
                "sender: datagram to a port nobody holds accepted",
                send_to(NET, reply, OUR_IP, 40999, b"lost") == Ok(OK),
            );
            let counters = stats(NET, reply);
            report(
                &mut f,
                "sender: counters show frames both ways and the lost datagram",
                counters.is_ok_and(|(s, c)| {
                    s == OK && c[stat::RECEIVED] > 0 && c[stat::SENT] > 0 && c[stat::NO_PORT] >= 1
                }),
            );
            let mut v2 = [0u8; 8];
            let n = encode(&Request::Stats, &mut v2).unwrap_or(0);
            v2[0] = VERSION + 1;
            report(
                &mut f,
                "sender: version 2: VERSION, supported 1 to 1",
                raw(NET, reply, &v2[..n])
                    .is_ok_and(|(r, len)| versions(&r[..len]) == Some((VERSION, VERSION))),
            );
            let n = encode(&Request::Info, &mut v2).unwrap_or(0);
            report(
                &mut f,
                "sender: INFO names the interface and its versions",
                raw(NET, reply, &v2[..n]).is_ok_and(|(r, len)| {
                    Info::parse(&r[..len])
                        .is_some_and(|i| i.name == NAME && (i.low, i.high) == (1, 1))
                }),
            );
            f
        }
        2 => {
            // A request registers port 40001 before anyone sends to it.
            report(
                &mut f,
                "echoer: registered",
                stats(NET, reply).is_ok_and(|(s, _)| s == OK),
            );
            if send(REPORT, b"ready", 0, 0, 0).is_err() {
                return 1;
            }
            let got = recv(NET, reply, &mut buf);
            let from = got
                .ok()
                .filter(|(s, _, _, n)| *s == OK && &buf[..*n] == b"hello from 40000");
            report(
                &mut f,
                "echoer: hello from 10.0.2.15:40000",
                from.is_some_and(|(_, ip, port, _)| ip == OUR_IP && port == 40000),
            );
            if let Some((_, ip, port, _)) = from {
                report(
                    &mut f,
                    "echoer: pong sent",
                    send_to(NET, reply, ip, port, b"pong") == Ok(OK),
                );
            }
            idle()
        }
        3 => {
            report(
                &mut f,
                "unbadged: refused with NO_PORT",
                send_to(NET, reply, GATEWAY, 1, b"x") == Ok(NO_PORT),
            );
            f
        }
        _ => 99,
    }
}
