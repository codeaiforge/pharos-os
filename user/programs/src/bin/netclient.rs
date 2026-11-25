//! Clients of the network service for the `network` test kernel (issue
//! #63). Handles: 1 debug console, 2 the network capability (`SEND` on the
//! service endpoint, badged by `init` with this client's UDP port), 3
//! `init`'s report endpoint (the echoer only).
//!
//! - Argument 1, port 40000: pings the gateway, exchanges a datagram with
//!   the host echo server at `10.0.2.2:47000` (run by `cargo xtask`, issue
//!   #64), sends a datagram to port 40001 on our own address and gets `pong` back, sends one to a port no
//!   client holds, and checks the service's counters. Each is a
//!   destination `init` listed for it (#109); one it did not list, a ping
//!   to an address it did not list, and an `ALLOW` of its own are refused
//!   with `NO_ACCESS`, and `POLL` with nothing waiting answers `NOT_FOUND`.
//! - Argument 2, port 40001: registers, reports ready, answers one
//!   datagram with `pong`, then idles.
//! - Argument 3, a badge over 16 bits: must be refused.
//! - Argument 4, port 40002 (#270, tls.md): attaches a buffer, opens TCP to
//!   the host echo server at `10.0.2.2:47000`, writes and reads its echo
//!   back, closes, and is refused: a write on the closed connection
//!   (`CLOSED`), a destination not listed for TCP (`NO_ACCESS`), a listed
//!   port nothing listens on (`REFUSED`), and a TCP request as version 1.
//!
//! - Argument 5 (#271): the TLS service's refusals that need no server.
//! - Argument 6, the `tls` kernel (#273): an HTTPS round trip with the
//!   host's `openssl s_server` on destination 0, and destinations 1 to 3
//!   (expired, another name, an authority not pinned) each refused with
//!   their reason; an index not listed is `NO_ACCESS`.
//! - Argument 7, the `tls_norandom` kernel (#273): `OPEN` is `NO_RANDOM`.
//! - Argument 8, the `secrets` kernel (#281): the vault's client, as the
//!   gateway (handle 2, badge 1) and as another client (handle 3, badge
//!   2). A route's prefix and secret are released into its buffer; a
//!   route whose secret is missing, one with none, one that does not
//!   exist, a release before `ATTACH`, and any release by badge 2 are
//!   refused; `secrets_read` without the capability is refused. It never
//!   prints a secret.
//!
//! Each step prints `ok <step>` or `FAIL <step>`; the exit code is the
//! number of failures.

#![no_std]
#![no_main]

use pharos_programs::net::client::{NO_PORT, OK, ping, raw, recv, send_to, stats};
use pharos_programs::net::{GATEWAY, OUR_IP, stat};
use pharos_proto::net::{
    Allowed, BAD_REQUEST, CLOSED, NAME, NO_ACCESS, NOT_FOUND, REFUSED, Request, TCP_VERSION,
    VERSION, encode, parse_count,
};
use pharos_proto::{Info, versions};
use pharos_user::rights::{READ, WRITE};
use pharos_user::{
    Error, Handle, debug_write, endpoint_create, mem_map, mem_share, receive, send, try_send,
};

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
            report(
                &mut f,
                "sender: datagram to an unlisted destination refused with NO_ACCESS",
                send_to(NET, reply, GATEWAY, HOST_ECHO_PORT + 1, b"no") == Ok(NO_ACCESS),
            );
            report(
                &mut f,
                "sender: ping to an unlisted address refused with NO_ACCESS",
                ping(NET, reply, [10, 0, 2, 3], 2) == Ok(NO_ACCESS),
            );
            let mut msg = [0u8; 64];
            let allow = Request::Allow {
                client: 40000,
                dests: Allowed::new(&[([10, 0, 2, 3], 53)]).unwrap_or(Allowed::NONE),
            };
            let n = encode(&allow, &mut msg).unwrap_or(0);
            report(
                &mut f,
                "sender: its own ALLOW refused with NO_ACCESS",
                raw(NET, reply, &msg[..n]).is_ok_and(|(r, len)| len == 1 && r[0] == NO_ACCESS),
            );
            let n = encode(&Request::Poll, &mut msg).unwrap_or(0);
            report(
                &mut f,
                "sender: POLL with nothing waiting answers NOT_FOUND",
                raw(NET, reply, &msg[..n]).is_ok_and(|(r, len)| len == 1 && r[0] == NOT_FOUND),
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
            v2[0] = TCP_VERSION + 1;
            report(
                &mut f,
                "sender: version 3: VERSION, supported 1 to 2",
                raw(NET, reply, &v2[..n])
                    .is_ok_and(|(r, len)| versions(&r[..len]) == Some((VERSION, TCP_VERSION))),
            );
            let n = encode(&Request::Info, &mut v2).unwrap_or(0);
            report(
                &mut f,
                "sender: INFO names the interface and its versions",
                raw(NET, reply, &v2[..n]).is_ok_and(|(r, len)| {
                    Info::parse(&r[..len])
                        .is_some_and(|i| i.name == NAME && (i.low, i.high) == (1, 2))
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
        4 => tcp(reply),
        5 => tls_smoke(reply),
        6 => tls_round(reply),
        7 => tls_no_random(reply),
        8 => vaulter(reply),
        3 => {
            report(
                &mut f,
                "unported: refused with NO_PORT",
                send_to(NET, reply, GATEWAY, 1, b"x") == Ok(NO_PORT),
            );
            f
        }
        _ => 99,
    }
}

/// The TLS service's refusals that need no server (argument 5, #271):
/// its capability is `SEND` on the TLS service, badged client 1, with one
/// destination; the table gives the service no audit trail.
fn tls_smoke(reply: Handle) -> u64 {
    use pharos_proto::tls::{self, Request as Tls};
    let mut f = 0;
    let call = |req: Tls<'_>| -> Option<([u8; 256], usize)> {
        let mut msg = [0u8; 96];
        let n = tls::encode(&req, &mut msg)?;
        raw(NET, reply, &msg[..n]).ok()
    };
    let info = call(Tls::Info);
    report(
        &mut f,
        "tlser: INFO names tls v1",
        info.is_some_and(|(r, n)| {
            Info::parse(&r[..n]).is_some_and(|i| i.name == tls::NAME && (i.low, i.high) == (1, 1))
        }),
    );
    let allow = Tls::Allow {
        client: 1,
        destination: 1,
        dest: tls::Destination {
            ip: GATEWAY,
            port: 443,
            name: b"elsewhere.test",
        },
    };
    report(
        &mut f,
        "tlser: its own ALLOW refused with NO_ACCESS",
        call(allow).is_some_and(|(r, _)| r[0] == tls::NO_ACCESS),
    );
    let opened =
        |d| call(Tls::Open { destination: d }).and_then(|(r, n)| tls::parse_opened(&r[..n]));
    report(
        &mut f,
        "tlser: a destination not listed refused with NO_ACCESS",
        opened(1).is_some_and(|(s, ..)| s == tls::NO_ACCESS),
    );
    // Clock and seed pass (else NO_CLOCK, NO_RANDOM); nothing is sent
    // without an intent stored.
    report(
        &mut f,
        "tlser: OPEN without an audit trail is NO_AUDIT, after the clock and seed",
        opened(0).is_some_and(|(s, ..)| s == tls::NO_AUDIT),
    );
    report(
        &mut f,
        "tlser: READ on no connection is CLOSED",
        call(Tls::Read {
            conn: 0,
            offset: 0,
            max: 1,
        })
        .and_then(|(r, n)| parse_count(&r[..n]))
        .is_some_and(|(s, _)| s == tls::CLOSED),
    );
    report(
        &mut f,
        "tlser: version 2: VERSION, supported 1 to 1",
        raw(NET, reply, &[2, tls::op::OPEN, 0])
            .is_ok_and(|(r, n)| versions(&r[..n]) == Some((1, 1))),
    );
    f
}

/// `tls` v1 `call` on handle 2; the reply's bytes.
fn tls_call(reply: Handle, req: pharos_proto::tls::Request<'_>) -> Option<([u8; 256], usize)> {
    let mut msg = [0u8; 96];
    let n = pharos_proto::tls::encode(&req, &mut msg)?;
    raw(NET, reply, &msg[..n]).ok()
}

/// `OPEN` of destination `d`: status, connection, reason.
fn tls_open(reply: Handle, d: u8) -> Option<(u8, u8, u8)> {
    use pharos_proto::tls::{Request as Tls, parse_opened};
    tls_call(reply, Tls::Open { destination: d }).and_then(|(r, n)| parse_opened(&r[..n]))
}

/// The `tls` kernel's client (argument 6, #273).
fn tls_round(reply: Handle) -> u64 {
    use pharos_proto::tls::{self, Request as Tls, reason};
    let mut f = 0;
    const LEN: u64 = 16 * 1024;
    let buffer = mem_map(LEN).ok();
    let attached = buffer.as_ref().is_some_and(|b| {
        let mut msg = [0u8; 16];
        let n = tls::encode(&Tls::Attach { len: LEN }, &mut msg).unwrap_or(0);
        mem_share(b).is_ok_and(|m| send(NET, &msg[..n], m, READ | WRITE, 0).is_ok())
    });
    report(&mut f, "tlsclient: buffer attached", attached);
    let open = tls_open(reply, 0);
    report(
        &mut f,
        "tlsclient: the good server's handshake completed",
        open.is_some_and(|(s, ..)| s == OK),
    );
    let (Some(buffer), Some((OK, conn, _))) = (buffer, open) else {
        return f + 1;
    };
    const GET: &[u8] = b"GET / HTTP/1.0\r\n\r\n";
    buffer.write_bytes(0, GET);
    let count = |req: Tls<'_>| tls_call(reply, req).and_then(|(r, n)| parse_count(&r[..n]));
    report(
        &mut f,
        "tlsclient: the HTTP request written",
        count(Tls::Write {
            conn,
            offset: 0,
            len: GET.len() as u32,
        }) == Some((OK, GET.len() as u32)),
    );
    // The reply up to s_server's close, at most 12 KiB of it.
    let mut got = 0u32;
    while got < 12 * 1024 {
        match count(Tls::Read {
            conn,
            offset: 1024 + got,
            max: 12 * 1024 - got,
        }) {
            Some((OK, n)) if n > 0 => got += n,
            _ => break,
        }
    }
    const STATUS: &[u8] = b"HTTP/1.0 200 ok";
    let mut head = [0u8; STATUS.len()];
    buffer.read_bytes(1024, &mut head);
    report(
        &mut f,
        "tlsclient: the HTTP reply came back over TLS",
        got as usize > STATUS.len() && head == *STATUS,
    );
    report(
        &mut f,
        "tlsclient: closed",
        tls_call(reply, Tls::Close { conn }).is_some_and(|(r, _)| r[0] == OK),
    );
    // CLOSE while the handshake runs (review F4, #274): destination 4
    // never answers, so the OPEN is left waiting (a 1 ms timeout); its
    // connection (slot 0, the first free) is closed, and the outcome
    // recorded as `closed`.
    let mut msg = [0u8; 8];
    let n = tls::encode(&Tls::Open { destination: 4 }, &mut msg).unwrap_or(0);
    let mut out = [0u8; 16];
    let left = pharos_user::call_timeout(NET, &msg[..n], reply, &mut out, 1_000).is_err();
    report(
        &mut f,
        "tlsclient: CLOSE during the handshake answers OK",
        left && tls_call(reply, Tls::Close { conn: 0 }).is_some_and(|(r, _)| r[0] == OK),
    );
    for (d, why, step) in [
        (
            1,
            reason::EXPIRED,
            "tlsclient: an expired certificate refused with EXPIRED",
        ),
        (
            2,
            reason::NAME,
            "tlsclient: a certificate for another name refused with NAME",
        ),
        (
            3,
            reason::UNKNOWN_ISSUER,
            "tlsclient: an authority not pinned refused with UNKNOWN_ISSUER",
        ),
    ] {
        report(
            &mut f,
            step,
            tls_open(reply, d) == Some((tls::HANDSHAKE, 0, why)),
        );
    }
    report(
        &mut f,
        "tlsclient: a destination not listed refused with NO_ACCESS",
        tls_open(reply, 5).is_some_and(|(s, ..)| s == tls::NO_ACCESS),
    );
    // A loop of OPENs (#275): past the burst, refused with OVER_LIMIT and
    // nothing recorded (the runner counts the intents); a second later,
    // one more is earned.
    let mut handshakes = 0;
    let limited = (0..32).any(|_| match tls_open(reply, 1) {
        Some((tls::HANDSHAKE, ..)) => {
            handshakes += 1;
            false
        }
        other => other.is_some_and(|(s, ..)| s == tls::OVER_LIMIT),
    });
    pharos_user::sleep(1_100_000);
    report(
        &mut f,
        "tlsclient: a loop of OPENs refused with OVER_LIMIT, then one earned back",
        limited
            && handshakes < 32
            && tls_open(reply, 1) == Some((tls::HANDSHAKE, 0, reason::EXPIRED)),
    );
    f
}

/// The `tls_norandom` kernel's client (argument 7, #273).
fn tls_no_random(reply: Handle) -> u64 {
    let mut f = 0;
    report(
        &mut f,
        "tlsclient: OPEN without virtio-rng is NO_RANDOM",
        tls_open(reply, 0).is_some_and(|(s, ..)| s == pharos_proto::tls::NO_RANDOM),
    );
    f
}

/// The `secrets` kernel's client (argument 8, #281).
fn vaulter(reply: Handle) -> u64 {
    use pharos_proto::vault::{self, NO_ACCESS, NO_BUFFER, NO_SECRET, NOT_FOUND, Request as V};
    let mut f = 0;
    let call = |to: Handle, req: V| {
        let mut msg = [0u8; 16];
        let n = vault::encode(&req, &mut msg)?;
        raw(to, reply, &msg[..n]).ok()
    };
    let release = |to: Handle, route| {
        call(to, V::Release { route }).and_then(|(r, n)| vault::parse_released(&r[..n]))
    };
    report(
        &mut f,
        "vaulter: a release before ATTACH is NO_BUFFER",
        release(NET, 0).is_some_and(|(s, _)| s == NO_BUFFER),
    );
    const LEN: u64 = 4096;
    let buffer = mem_map(LEN).ok();
    let attached = buffer.as_ref().is_some_and(|b| {
        let mut msg = [0u8; 16];
        let n = vault::encode(&V::Attach { len: LEN }, &mut msg).unwrap_or(0);
        mem_share(b).is_ok_and(|m| send(NET, &msg[..n], m, READ | WRITE, 0).is_ok())
    });
    report(&mut f, "vaulter: buffer attached", attached);
    let want = [
        b"Bearer ".as_slice(),
        pharos_services::TEST_SECRET_VALUE.as_bytes(),
    ]
    .concat();
    let released = release(NET, 0)
        .zip(buffer.as_ref())
        .is_some_and(|((s, n), b)| {
            let mut got = [0u8; 64];
            let n = usize::from(n);
            n == want.len() && n <= got.len() && {
                b.read_bytes(0, &mut got[..n]);
                s == OK && got[..n] == want[..]
            }
        });
    report(
        &mut f,
        "vaulter: route 0's prefix and secret are released",
        released,
    );
    for (route, want, step) in [
        (
            1,
            NO_SECRET,
            "vaulter: a route whose secret the file lacks is NO_SECRET",
        ),
        (2, NO_SECRET, "vaulter: a route with no secret is NO_SECRET"),
        (
            9,
            NOT_FOUND,
            "vaulter: a route that does not exist is NOT_FOUND",
        ),
    ] {
        report(&mut f, step, release(NET, route) == Some((want, 0)));
    }
    report(
        &mut f,
        "vaulter: another client's release is NO_ACCESS",
        release(REPORT, 0) == Some((NO_ACCESS, 0)),
    );
    report(
        &mut f,
        "vaulter: secrets_read without the capability is refused",
        pharos_user::secrets_read(NET, &mut []).is_err(),
    );
    let info = call(NET, V::Info);
    report(
        &mut f,
        "vaulter: INFO names vault, version 1",
        info.is_some_and(|(r, n)| {
            Info::parse(&r[..n]).is_some_and(|i| i.name == vault::NAME && i.low == 1)
        }),
    );
    f
}

/// The TCP steps (argument 4).
fn tcp(reply: Handle) -> u64 {
    let mut f = 0;
    let call = |req: Request<'_>| -> Option<([u8; 256], usize)> {
        let mut msg = [0u8; 64];
        let n = encode(&req, &mut msg)?;
        raw(NET, reply, &msg[..n]).ok()
    };
    let count = |req: Request<'_>| call(req).and_then(|(r, n)| parse_count(&r[..n]));
    let opened = |ip, port| call(Request::TcpOpen { ip, port }).map(|(r, _)| (r[0], r[1]));
    const LEN: u64 = 4096;
    let buffer = mem_map(LEN).ok();
    let attached = buffer.as_ref().is_some_and(|b| {
        let mut msg = [0u8; 16];
        let n = encode(&Request::Attach { len: LEN }, &mut msg).unwrap_or(0);
        mem_share(b).is_ok_and(|m| send(NET, &msg[..n], m, READ | WRITE, 0).is_ok())
    });
    report(&mut f, "tcper: buffer attached", attached);
    let open = opened(GATEWAY, HOST_ECHO_PORT);
    report(
        &mut f,
        "tcper: connected to the host echo server",
        open.is_some_and(|(s, _)| s == OK),
    );
    let (Some(buffer), Some((OK, conn))) = (buffer, open) else {
        return f + 1;
    };
    const HELLO: &[u8] = b"hello over tcp";
    buffer.write_bytes(0, HELLO);
    let wrote = count(Request::TcpWrite {
        conn,
        offset: 0,
        len: HELLO.len() as u32,
    });
    report(
        &mut f,
        "tcper: write queued",
        wrote == Some((OK, HELLO.len() as u32)),
    );
    let mut got = 0u32;
    for _ in 0..8 {
        match count(Request::TcpRead {
            conn,
            offset: 1024 + got,
            max: HELLO.len() as u32 - got,
        }) {
            Some((OK, n)) if n > 0 => got += n,
            _ => break,
        }
        if got as usize == HELLO.len() {
            break;
        }
    }
    let mut back = [0u8; HELLO.len()];
    buffer.read_bytes(1024, &mut back);
    report(
        &mut f,
        "tcper: the echo came back",
        got as usize == HELLO.len() && back == *HELLO,
    );
    report(
        &mut f,
        "tcper: closed",
        call(Request::TcpClose { conn }).is_some_and(|(r, _)| r[0] == OK),
    );
    report(
        &mut f,
        "tcper: a write on the closed connection answers CLOSED",
        count(Request::TcpWrite {
            conn,
            offset: 0,
            len: 1,
        })
        .is_some_and(|(s, _)| s == CLOSED),
    );
    report(
        &mut f,
        "tcper: a destination not listed for TCP refused with NO_ACCESS",
        opened(GATEWAY, 47003).is_some_and(|(s, _)| s == NO_ACCESS),
    );
    report(
        &mut f,
        "tcper: a listed port nothing listens on answers REFUSED",
        opened(GATEWAY, 47002).is_some_and(|(s, _)| s == REFUSED),
    );
    // TCP_CONNECT and TCP_POLL (#271): answered at once.
    let started = call(Request::TcpConnect {
        ip: GATEWAY,
        port: HOST_ECHO_PORT,
    })
    .map(|(r, _)| (r[0], r[1]));
    report(
        &mut f,
        "tcper: TCP_CONNECT answers at once with a connection",
        started.is_some_and(|(s, _)| s == OK),
    );
    if let Some((OK, conn)) = started {
        let poll = |offset| {
            count(Request::TcpPoll {
                conn,
                offset,
                max: HELLO.len() as u32,
            })
        };
        // Writes take nothing until it is connected; then the echo.
        let mut sent = false;
        let mut back = None;
        for _ in 0..200 {
            if !sent {
                sent = count(Request::TcpWrite {
                    conn,
                    offset: 0,
                    len: HELLO.len() as u32,
                }) == Some((OK, HELLO.len() as u32));
            }
            match poll(2048) {
                Some((OK, n)) if n > 0 => {
                    back = Some(n);
                    break;
                }
                Some((NOT_FOUND, _)) => pharos_user::sleep(10_000),
                _ => break,
            }
        }
        let mut echo = [0u8; HELLO.len()];
        buffer.read_bytes(2048, &mut echo);
        report(
            &mut f,
            "tcper: TCP_POLL gets the echo, NOT_FOUND until then",
            back == Some(HELLO.len() as u32) && echo == *HELLO,
        );
        let _ = call(Request::TcpClose { conn });
    }
    let refused = call(Request::TcpConnect {
        ip: GATEWAY,
        port: 47002,
    })
    .and_then(|(r, _)| (r[0] == OK).then_some(r[1]))
    .is_some_and(|conn| {
        (0..200).any(|_| {
            let r = count(Request::TcpPoll {
                conn,
                offset: 0,
                max: 1,
            });
            if r.is_some_and(|(s, _)| s == NOT_FOUND) {
                pharos_user::sleep(10_000);
            }
            r.is_some_and(|(s, _)| s == REFUSED)
        })
    });
    report(
        &mut f,
        "tcper: TCP_POLL on a refused TCP_CONNECT answers REFUSED",
        refused,
    );
    // A refused connection its client closes without polling frees its
    // slot (review F2, #274): five in a row, past the limit of 4.
    let freed = (0..5).all(|_| {
        let conn = call(Request::TcpConnect {
            ip: GATEWAY,
            port: 47002,
        })
        .and_then(|(r, _)| (r[0] == OK).then_some(r[1]));
        pharos_user::sleep(300_000);
        conn.is_some_and(|conn| call(Request::TcpClose { conn }).is_some_and(|(r, _)| r[0] == OK))
    });
    report(
        &mut f,
        "tcper: a refused TCP_CONNECT closed unpolled frees its slot, five times",
        freed,
    );
    let mut v1 = [0u8; 16];
    let n = encode(&Request::TcpClose { conn }, &mut v1).unwrap_or(0);
    v1[0] = VERSION;
    report(
        &mut f,
        "tcper: a TCP request as version 1 is BAD_REQUEST",
        raw(NET, reply, &v1[..n]).is_ok_and(|(r, len)| len >= 1 && r[0] == BAD_REQUEST),
    );
    f
}
