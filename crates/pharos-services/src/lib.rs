//! The service tables `init` starts (services.md, D-026, D-027): each
//! entry is a service's manifest, every capability written out as the
//! object, the rights, and the badge it gets, and what it may gain while it
//! runs. `init` grants exactly the entry; the host tests below check the
//! rules every table keeps ([`check`]); the `system` test kernel compares
//! each live service with its entry.
//!
//! `no_std`, no dependencies, `unsafe` forbidden (workspace lint): the
//! kernel's test kernels use it too, as a dev-dependency.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod config;
mod tables;

pub use tables::*;

/// Capability rights, as the kernel and `pharos_user::rights` number them
/// (`pharos-programs` tests that they agree).
pub mod rights {
    pub const SEND: u32 = 1;
    pub const RECEIVE: u32 = 1 << 1;
    pub const GRANT: u32 = 1 << 2;
    pub const WRITE: u32 = 1 << 3;
    pub const READ: u32 = 1 << 4;
    pub const MAP: u32 = 1 << 5;
    pub const IRQ: u32 = 1 << 6;
    pub const CONFIG: u32 = 1 << 7;
    pub const WAIT: u32 = 1 << 8;
    pub const STOP: u32 = 1 << 9;
    /// `fs_mount`: `init`'s own, never given (only `READ` on the root).
    pub const MOUNT: u32 = 1 << 10;
    /// What a driver gets on its device.
    pub const DEVICE: u32 = MAP | CONFIG | IRQ;
}

use rights::*;

/// Most capabilities one `spawn` passes (the kernel's `MAX_SPAWN_CAPS`).
pub const MAX_CAPS: usize = 12;
/// Most entries in a table (one notification bit each).
pub const MAX_SERVICES: usize = 32;

/// An IPv4 address and UDP port (`pharos_proto::net::Dest`).
pub type Dest = ([u8; 4], u16);
/// A TLS destination: address, port, and the server's name
/// (`pharos_proto::tls::Destination`).
pub type TlsDest = ([u8; 4], u16, &'static [u8]);

/// What happens when a service crashes, exits, or sends no `ready` in
/// time (#150). A service the user stopped is never restarted, whatever
/// this says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    Never,
    /// Up to this many restarts per boot.
    Up(u8),
}

impl Restart {
    /// Most restarts it allows.
    pub fn limit(self) -> u8 {
        match self {
            Self::Never => 0,
            Self::Up(n) => n,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Succeeds by exiting with code 0.
    OneShot,
    /// Succeeds by sending `ready`; must not end.
    Daemon,
}

/// One of `init`'s endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ep {
    /// `init`'s report endpoint: `ready`, and `trust`'s `SERVICES`.
    Events,
    Net,
    Store,
    Infer,
    Trust,
    Agents,
    Audit,
    Knowledge,
    /// The TLS service's (M6.1, tls.md): a client's badge is its client
    /// number, 1 to 8.
    Tls,
    /// The vault's (M6.2, gateway.md): its only client, the gateway, has
    /// badge 1.
    Vault,
    /// The egress gateway's (M6.2, gateway.md): the agent runtime is
    /// client 1; test programs 2.
    Gateway,
    /// A test table's proxy in front of the TLS service's network and
    /// audit services (#277): the TLS service's network requests have
    /// badge 1, its audit requests badge 2.
    Proxy,
}

impl Ep {
    /// The service that receives on it (`None`: `init` itself).
    pub fn receiver(self) -> Option<&'static str> {
        Some(match self {
            Self::Events => return None,
            Self::Net => "net",
            Self::Store => "store",
            Self::Infer => "infer",
            Self::Trust => "trust",
            Self::Agents => "agents",
            Self::Audit => "audit",
            Self::Knowledge => "knowledge",
            Self::Tls => "tls",
            Self::Vault => "vault",
            Self::Gateway => "gateway",
            Self::Proxy => "proxy",
        })
    }
}

/// What a capability refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// The kernel's serial debug console.
    DebugConsole,
    /// The root filesystem.
    Root,
    /// The `nth` device (from 0) with this PCI vendor and device ID.
    Device(u32, u8),
    Endpoint(Ep),
    /// The device with this PCI ID that arrived in a hotplug slot (M4.4,
    /// drivers.md): an entry holding it is a driver, started when one
    /// arrives and never at boot.
    Arrived(u32),
    /// The `AuditAnchor` key, derived from the device secret (D-047,
    /// release-integrity.md): `READ` only, and only for the `audit` entry.
    AuditAnchor,
    /// The host's secrets file (D-035, gateway.md): `READ` only, and only
    /// for the `vault` entry.
    Secrets,
}

/// A route (D-035, gateway.md): the one request shape the gateway sends to
/// a destination, and the secret it carries. Compiled into each table
/// ([`routes`]); the vault and the gateway both read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// What agents' grants and the audit trail name: as an agent's name.
    pub name: &'static str,
    /// An index into the gateway's TLS destinations.
    pub dest: u8,
    pub method: &'static str,
    /// Literal segments and `*`, one segment each.
    pub path: &'static str,
    /// Whether a query may follow the path.
    pub query: bool,
    /// The secret's name in the host's file, if the route carries one.
    pub secret: Option<&'static str>,
    /// Where the secret goes: one header's name, and a fixed prefix.
    pub header: (&'static str, &'static str),
    /// Fixed headers, at most [`MAX_ROUTE_HEADERS`].
    pub headers: &'static [(&'static str, &'static str)],
    pub max_body: u32,
    pub max_answer: u32,
    /// The gateway's clients that may use it.
    pub clients: &'static [u8],
    /// How many people approve each request's bytes on the trusted path
    /// first (D-037, approval.md); the gateway refuses one without.
    pub approve: Approve,
}

/// A route's mark (D-037): who approves its requests' bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Approve {
    /// Grant-only, as every route before M6.4.
    None,
    One,
    Two,
}

impl Approve {
    /// The approvers it needs.
    pub const fn count(self) -> u8 {
        self as u8
    }
}

/// Most approved bytes of one request (`pharos_proto::trust::MAX_PAYLOAD`;
/// this crate has no dependencies, and a host test checks they agree).
pub const MAX_APPROVABLE: usize = 4096;
/// Most bytes of a request's target: a path of 256 and a query of `?`
/// and 256 (gateway.md, "Paths").
pub const MAX_TARGET: usize = 256 + 1 + 256;
/// `trust`'s badge at the gateway (#325): it sends approvals, never
/// requests, and attaches no buffer.
pub const GATEWAY_TRUST: u8 = 3;

/// Most fixed headers on a route.
pub const MAX_ROUTE_HEADERS: usize = 4;
/// Most routes in a table (a route is a byte in `vault` and `gateway`).
pub const MAX_ROUTES: usize = 32;

impl Service {
    /// The PCI ID this entry drives, if it is a driver entry
    /// ([`Object::Arrived`]).
    pub fn driver(&self) -> Option<u32> {
        self.caps.iter().find_map(|g| match g.object {
            Object::Arrived(id) => Some(id),
            _ => None,
        })
    }

    /// True for the agent runtime's entry: the one that receives on its
    /// endpoint. `init` gives it agents' budgets and hands `trust` its
    /// `STOP` (M4.6, #183: found by its manifest, not its program, so a
    /// stand-in under the same manifest is treated the same).
    pub fn is_runtime(&self) -> bool {
        self.caps
            .iter()
            .any(|g| g.object == Object::Endpoint(Ep::Agents) && g.rights & rights::RECEIVE != 0)
    }
}

/// Services that can be restarted but never stopped (D-029): the trusted
/// console, the audit trail, and the store under it.
pub const PROTECTED: [&str; 3] = ["trust", "audit", "store"];

/// The bit of `init`'s report endpoint that slot events set (M4.4): one
/// above every entry's end notification, so a table with a driver entry
/// has at most 31 entries.
pub const SLOT_BIT: u32 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    None,
    Fixed(u32),
    /// The entry's index + 1: its report badge on [`Ep::Events`].
    Own,
}

impl Badge {
    /// The badge for entry `index`.
    pub fn value(self, index: usize) -> u32 {
        match self {
            Self::None => 0,
            Self::Fixed(b) => b,
            Self::Own => index as u32 + 1,
        }
    }
}

/// One capability a service gets, in handle order from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Give {
    pub object: Object,
    pub rights: u32,
    pub badge: Badge,
}

/// What a service may hold beyond its [`Give`]s (D-027). Objects it
/// created itself (an endpoint no other process holds, an interrupt
/// object of one of its devices) every service may hold; one-shot reply
/// capabilities live only during a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gain {
    /// Process capabilities with `STOP | WAIT`: `trust` (the runtime and
    /// each agent) and the runtime (its agents).
    Processes,
    /// `SEND` on [`Ep::Agents`] badged `agents::TRUST`, which the runtime
    /// gives `trust` (`CHANNEL`).
    RuntimeChannel,
}

#[derive(Clone, Copy)]
pub struct Service {
    pub name: &'static str,
    pub path: &'static [u8],
    pub arg: u64,
    pub kind: Kind,
    pub restart: Restart,
    /// Its manifest: each capability, in handle order.
    pub caps: &'static [Give],
    /// The destinations its network capability may send to (#109).
    pub net: &'static [Dest],
    /// The destinations its network capability may open TCP to (M6.1,
    /// tls.md); empty for every service that does not use TCP.
    pub tcp: &'static [Dest],
    /// The TLS destinations of its TLS capability, by index (M6.1,
    /// tls.md); empty for every service that is no TLS client.
    pub tls: &'static [TlsDest],
    /// Indexes of earlier entries that must have succeeded first.
    pub after: &'static [usize],
    /// Pages it may `mem_map` (0: none).
    pub limit: u32,
    pub gains: &'static [Gain],
}

/// `Give` shorthands; each still names the object, rights, and badge.
pub const fn give(object: Object, rights: u32, badge: Badge) -> Give {
    Give {
        object,
        rights,
        badge,
    }
}
/// `WRITE` on the debug console.
pub const CONSOLE: Give = give(Object::DebugConsole, WRITE, Badge::None);
/// `SEND` on `init`'s report endpoint, badged with the entry's number.
pub const REPORT: Give = give(Object::Endpoint(Ep::Events), SEND, Badge::Own);
/// `READ` on the root filesystem.
pub const ROOT: Give = give(Object::Root, READ, Badge::None);
/// `RECEIVE` on `e`: the service itself.
pub const fn receive(e: Ep) -> Give {
    give(Object::Endpoint(e), RECEIVE, Badge::None)
}
/// `SEND` on `e`, badged `badge`.
pub const fn send(e: Ep, badge: u32) -> Give {
    give(Object::Endpoint(e), SEND, Badge::Fixed(badge))
}
/// A driver's rights on the device with PCI ID `id` that arrived.
pub const fn arrived(id: u32) -> Give {
    give(Object::Arrived(id), DEVICE, Badge::None)
}
/// The driver's rights on the `nth` device with PCI ID `id`.
pub const fn device(id: u32, nth: u8) -> Give {
    give(Object::Device(id, nth), DEVICE, Badge::None)
}

/// A rule a table breaks (services.md, D-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// More entries than notification bits, or more capabilities than
    /// `spawn` passes.
    TooMany,
    /// `after` names this entry or a later one.
    After,
    /// `SEND` on another service's endpoint with badge 0, `init`'s own.
    BadgeZero,
    /// Two capabilities on one endpoint with the same badge.
    SameBadge,
    /// A second receiver, or a receiver other than the service named for
    /// the endpoint.
    Receiver,
    /// `GRANT` without `RECEIVE` on the endpoint.
    Grant,
    /// Rights that do not fit the object: device rights only on devices,
    /// `READ` only on the root, `WRITE` only on the console.
    Rights,
    /// The `AuditAnchor` key given to an entry other than `audit`, or the
    /// secrets file to one other than `vault`.
    Key,
    /// A device given twice.
    SameDevice,
    /// A daemon without exactly one [`REPORT`], or a one-shot with one, or
    /// [`Badge::Own`] anywhere else.
    Report,
    /// A vault and a gateway with different arguments: each reads its
    /// routes by its own (`routes(arg)`), and the gateway asks for a
    /// route by index, so the vault would release one route's secret
    /// into another's request (#288, M6.2 review R-5).
    Routes,
    /// A driver entry ([`Object::Arrived`]) that is not a daemon, is
    /// protected, is in another entry's `after`, has more than one
    /// `Arrived`, or is in a table of 32 entries ([`SLOT_BIT`]).
    Driver,
}

/// A rule a table's routes break (gateway.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokenRoute {
    /// More than [`MAX_ROUTES`] routes, or more than [`MAX_ROUTE_HEADERS`]
    /// fixed headers on one.
    TooMany,
    /// A name that is not 1 to 32 bytes of `a`-`z`, `0`-`9`, `-`, `_`,
    /// or one given twice.
    Name,
    /// A secret's name the secrets file could not hold, a secret without
    /// a header to carry it, or a header without a secret.
    Secret,
    /// A method the gateway does not send.
    Method,
    /// A path pattern that is not `/` and segments of RFC 3986's
    /// unreserved characters or `*`, at most 128 bytes.
    Path,
    /// A header name that is not a token, one only the gateway writes
    /// (`Host`, `Content-Length`, `Connection`, `Accept-Encoding`,
    /// `Transfer-Encoding`), the secret's header among the fixed ones, or a
    /// value that is not visible ASCII.
    Header,
    /// `max_body` or `max_answer` over 60 KiB, or a body on `GET` or
    /// `DELETE`.
    Limit,
    /// A destination the gateway's entry does not list.
    Dest,
    /// No client, or one outside the gateway's badges (1 and 2).
    Clients,
    /// A route marked for approval whose longest request (its name, two
    /// zero bytes, the longest target, and `max_body`) is over
    /// [`MAX_APPROVABLE`]: no one could read it whole (approval.md, open
    /// question 1).
    Approvable,
}

/// Largest body or answer on a route.
pub const MAX_ROUTE_BYTES: u32 = 60 * 1024;
/// The gateway's clients: the agent runtime (1) and test programs (2).
pub const GATEWAY_CLIENTS: u8 = 2;

// The route rules below mirror `pharos_proto::http` (this crate has no
// dependencies); the gateway checks paths against them again at run time.

fn token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn reserved_header(name: &str) -> bool {
    [
        "host",
        "content-length",
        "connection",
        "accept-encoding",
        "transfer-encoding",
    ]
    .iter()
    .any(|r| r.eq_ignore_ascii_case(name))
}

fn header_value(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !value.starts_with(' ')
        && !value.ends_with(' ')
}

fn path_pattern(p: &str) -> bool {
    let unreserved = |b: u8| b.is_ascii_alphanumeric() || b"-._~".contains(&b);
    p.len() <= 128
        && p.starts_with('/')
        && p[1..]
            .split('/')
            .all(|s| s == "*" || (s.bytes().all(unreserved) && s != "." && s != ".."))
}

/// Whether `name` is a route's or a secret's name: 1 to 32 bytes of
/// `a`-`z`, `0`-`9`, `-`, `_` (`pharos_proto::vault::valid_name`).
pub fn valid_route_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Checks the rules the vault and the gateway rely on for `routes`; the
/// first broken one, with its route. `dests` is how many TLS destinations
/// the table's gateway entry lists (`None`: the table has no gateway).
pub fn check_routes(routes: &[Route], dests: Option<usize>) -> Result<(), (usize, BrokenRoute)> {
    if routes.len() > MAX_ROUTES {
        return Err((MAX_ROUTES, BrokenRoute::TooMany));
    }
    for (i, r) in routes.iter().enumerate() {
        let fail = |b| Err((i, b));
        if r.headers.len() > MAX_ROUTE_HEADERS {
            return fail(BrokenRoute::TooMany);
        }
        if !valid_route_name(r.name) || routes[..i].iter().any(|o| o.name == r.name) {
            return fail(BrokenRoute::Name);
        }
        let carried = match r.secret {
            Some(s) => valid_route_name(s) && !r.header.0.is_empty(),
            None => r.header == ("", ""),
        };
        if !carried {
            return fail(BrokenRoute::Secret);
        }
        if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&r.method) {
            return fail(BrokenRoute::Method);
        }
        if !path_pattern(r.path) {
            return fail(BrokenRoute::Path);
        }
        let secret_header = (r.secret.is_some()).then_some(r.header.0);
        let headers_ok = r.headers.iter().all(|(n, v)| {
            token(n)
                && !reserved_header(n)
                && header_value(v)
                && !secret_header.is_some_and(|s| s.eq_ignore_ascii_case(n))
        });
        let secret_ok = secret_header.is_none_or(|n| token(n) && !reserved_header(n))
            && header_value(r.header.1.trim_end());
        if !headers_ok || !secret_ok {
            return fail(BrokenRoute::Header);
        }
        let bodiless = matches!(r.method, "GET" | "DELETE");
        if r.max_body > MAX_ROUTE_BYTES
            || r.max_answer > MAX_ROUTE_BYTES
            || (bodiless && r.max_body != 0)
        {
            return fail(BrokenRoute::Limit);
        }
        if dests.is_some_and(|n| usize::from(r.dest) >= n) {
            return fail(BrokenRoute::Dest);
        }
        if r.clients.is_empty() || r.clients.iter().any(|c| !(1..=GATEWAY_CLIENTS).contains(c)) {
            return fail(BrokenRoute::Clients);
        }
        if r.approve != Approve::None && longest_request(r) > MAX_APPROVABLE {
            return fail(BrokenRoute::Approvable);
        }
    }
    Ok(())
}

/// The longest approved bytes a request on `r` can have: `route ‖ 0 ‖
/// target ‖ 0 ‖ body` (approval.md, "What is approved").
pub const fn longest_request(r: &Route) -> usize {
    let target = if r.query { MAX_TARGET } else { 256 };
    r.name.len() + 2 + target + r.max_body as usize
}

/// Whether `table`'s `trust` can approve its marked routes (#325): it
/// holds `SEND` on the gateway with badge [`GATEWAY_TRUST`].
pub fn trust_approves(table: &[Service]) -> bool {
    let wanted = Give {
        object: Object::Endpoint(Ep::Gateway),
        rights: SEND,
        badge: Badge::Fixed(GATEWAY_TRUST as u32),
    };
    table
        .iter()
        .find(|s| s.name == "trust")
        .is_some_and(|t| t.caps.contains(&wanted))
}

/// How many TLS destinations `table`'s gateway entry lists, if it has one.
pub fn gateway_dests(table: &[Service]) -> Option<usize> {
    table
        .iter()
        .find(|s| s.name == "gateway")
        .map(|g| g.tls.len())
}

/// Checks every rule on `table`; the first broken one, with its entry.
pub fn check(table: &[Service]) -> Result<(), (usize, Broken)> {
    if table.len() > MAX_SERVICES {
        return Err((MAX_SERVICES, Broken::TooMany));
    }
    for (i, s) in table.iter().enumerate() {
        let fail = |b| Err((i, b));
        if s.caps.len() > MAX_CAPS {
            return fail(Broken::TooMany);
        }
        if s.after.iter().any(|&a| a >= i) {
            return fail(Broken::After);
        }
        let reports = s.caps.iter().filter(|g| **g == REPORT).count();
        let own = s.caps.iter().filter(|g| g.badge == Badge::Own).count();
        if own != reports || reports != usize::from(s.kind == Kind::Daemon) {
            return fail(Broken::Report);
        }
        if s.driver().is_some() {
            let arrived = (s.caps.iter())
                .filter(|g| matches!(g.object, Object::Arrived(_)))
                .count();
            let needed = table.iter().any(|t| t.after.contains(&i));
            if s.kind != Kind::Daemon
                || PROTECTED.contains(&s.name)
                || needed
                || arrived != 1
                || table.len() > SLOT_BIT as usize
            {
                return fail(Broken::Driver);
            }
        }
        for g in s.caps {
            let fits = match g.object {
                Object::DebugConsole => g.rights == WRITE,
                Object::Root => g.rights == READ,
                Object::Device(..) | Object::Arrived(_) => g.rights == DEVICE,
                Object::Endpoint(_) => g.rights & !(SEND | RECEIVE | GRANT) == 0 && g.rights != 0,
                Object::AuditAnchor | Object::Secrets => g.rights == READ,
            };
            if g.object == Object::AuditAnchor && s.name != "audit" {
                return fail(Broken::Key);
            }
            if g.object == Object::Secrets && s.name != "vault" {
                return fail(Broken::Key);
            }
            if !fits {
                return fail(Broken::Rights);
            }
            if g.badge != Badge::None && !matches!(g.object, Object::Endpoint(_)) {
                return fail(Broken::Rights);
            }
            let Object::Endpoint(e) = g.object else {
                continue;
            };
            if g.rights & GRANT != 0 && g.rights & RECEIVE == 0 {
                return fail(Broken::Grant);
            }
            if g.rights & RECEIVE != 0 && e.receiver() != Some(s.name) {
                return fail(Broken::Receiver);
            }
            // Its own endpoint may be unbadged: no one else receives there.
            if g.rights & SEND != 0 && g.badge.value(i) == 0 && g.rights & RECEIVE == 0 {
                return fail(Broken::BadgeZero);
            }
        }
    }
    // Pairs across the table: receivers, badges, devices.
    let all = || (table.iter().enumerate()).flat_map(|(i, s)| s.caps.iter().map(move |g| (i, g)));
    for (n, (i, a)) in all().enumerate() {
        for (j, b) in all().skip(n + 1) {
            if a.object != b.object {
                continue;
            }
            let fail = |r| Err((j, r));
            match a.object {
                Object::Device(..) | Object::Arrived(_) => return fail(Broken::SameDevice),
                Object::AuditAnchor | Object::Secrets => return fail(Broken::Key),
                Object::Endpoint(_) if a.rights & b.rights & RECEIVE != 0 => {
                    return fail(Broken::Receiver);
                }
                Object::Endpoint(_)
                    if a.rights & b.rights & SEND != 0 && a.badge.value(i) == b.badge.value(j) =>
                {
                    return fail(Broken::SameBadge);
                }
                _ => {}
            }
        }
    }
    let route_args =
        (table.iter().enumerate()).filter(|(_, s)| matches!(s.name, "vault" | "gateway"));
    if let Some((j, _)) = route_args
        .clone()
        .find(|(_, s)| route_args.clone().any(|(_, t)| t.arg != s.arg))
    {
        return Err((j, Broken::Routes));
    }
    Ok(())
}

/// The argument `table`'s vault and gateway share, if it has either: the
/// route table they both read ([`check`] refuses two).
pub fn route_table(table: &[Service]) -> Option<u64> {
    (table.iter())
        .find(|s| matches!(s.name, "vault" | "gateway"))
        .map(|s| s.arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_keeps_the_rules() {
        for (name, table) in [
            ("boot", BOOT),
            ("test", TEST),
            ("network", NETWORK),
            ("supervision", SUPERVISE),
            ("health", HEALTH),
            ("aifail", AIFAIL),
            ("compromised", COMPROMISED),
            ("soak", SOAK),
            ("tls", TLS),
            ("tls_norandom", TLS_NORANDOM),
            ("secrets", SECRETS),
            ("vault", VAULT),
            ("bridge", BRIDGE),
        ] {
            assert_eq!(check(table), Ok(()), "{name}");
        }
    }

    #[test]
    fn only_trust_holds_the_identity_namespace_at_its_handle_6() {
        // #310 (identity.md): the people's records, written only by `trust`.
        for n in 0..=12 {
            for s in table(n) {
                for (i, g) in s.caps.iter().enumerate() {
                    let identity = matches!(g.object, Object::Endpoint(Ep::Store))
                        && matches!(g.badge, Badge::Fixed(b) if b & 0xffff == IDENTITY_STORE);
                    assert!(
                        !identity || (s.name == "trust" && i == 5),
                        "table {n}: {}",
                        s.name
                    );
                }
                if s.name == "trust" {
                    let g = s.caps.get(5).expect("trust's handle 6");
                    assert!(matches!(g.badge, Badge::Fixed(IDENTITY_STORE)), "table {n}");
                }
            }
        }
    }

    #[test]
    fn a_vault_and_gateway_read_their_own_tables_routes() {
        // Each table's vault and gateway name the table itself (#288).
        for n in 0..=12 {
            let t = table(n);
            assert!(route_table(t).is_none_or(|a| a == n), "table {n}");
        }
        assert_eq!(route_table(VAULT), Some(11));
        assert_eq!(route_table(TLS), None);
        // A gateway reading another table's routes than its vault's.
        let mut t = std::vec::Vec::from(VAULT);
        let g = t.iter().position(|s| s.name == "gateway").unwrap();
        t[g].arg = 10;
        let v = t.iter().position(|s| s.name == "vault").unwrap();
        assert_eq!(check(&t), Err((v.min(g), Broken::Routes)));
    }

    #[test]
    fn every_tables_routes_keep_the_rules() {
        for arg in 0..=12 {
            let dests = gateway_dests(table(arg));
            assert_eq!(check_routes(routes(arg), dests), Ok(()), "table {arg}");
        }
        assert_eq!(routes(10).len(), 3);
        assert_eq!(routes(11).len(), 6);
        assert_eq!(routes(12).len(), 6);
        assert_eq!(gateway_dests(BRIDGE), Some(1));
        assert_eq!(gateway_dests(VAULT), Some(1));
        // A table with a marked route lets its `trust` approve (#325).
        for arg in 0..=12 {
            if routes(arg).iter().any(|r| r.approve != Approve::None) {
                assert!(trust_approves(table(arg)), "table {arg}");
            }
        }
        assert!(routes(11).iter().any(|r| r.approve == Approve::One));
    }

    #[test]
    fn a_marked_route_must_be_readable_whole() {
        let r = |max_body, query, approve| Route {
            name: "issues",
            dest: 0,
            method: "POST",
            path: "/x",
            query,
            secret: None,
            header: ("", ""),
            headers: &[],
            max_body,
            max_answer: 0,
            clients: &[1],
            approve,
        };
        // 6 + 2 + 256 + 3832 = 4096.
        assert_eq!(check_routes(&[r(3832, false, Approve::One)], None), Ok(()));
        assert_eq!(
            check_routes(&[r(3833, false, Approve::Two)], None),
            Err((0, BrokenRoute::Approvable))
        );
        assert_eq!(
            check_routes(&[r(3832, true, Approve::One)], None),
            Err((0, BrokenRoute::Approvable))
        );
        assert_eq!(
            check_routes(&[r(60 * 1024, true, Approve::None)], None),
            Ok(())
        );
        assert_eq!(Approve::Two.count(), 2);
    }

    #[test]
    fn routes_breaking_each_rule_are_refused() {
        let good = routes(10)[0];
        let with = |f: fn(&mut Route)| {
            let mut r = good;
            f(&mut r);
            r
        };
        let cases: [(Route, BrokenRoute); 21] = [
            (with(|r| r.name = ""), BrokenRoute::Name),
            (with(|r| r.name = "Upper"), BrokenRoute::Name),
            (with(|r| r.secret = Some("a.b")), BrokenRoute::Secret),
            (with(|r| r.header = ("", "Bearer ")), BrokenRoute::Secret),
            (with(|r| r.secret = None), BrokenRoute::Secret),
            (
                with(|r| r.headers = &[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]),
                BrokenRoute::TooMany,
            ),
            (with(|r| r.method = "HEAD"), BrokenRoute::Method),
            (with(|r| r.method = "get"), BrokenRoute::Method),
            (with(|r| r.path = "items"), BrokenRoute::Path),
            (with(|r| r.path = "/a/../b"), BrokenRoute::Path),
            (with(|r| r.path = "/a%20b"), BrokenRoute::Path),
            (with(|r| r.path = "/a*"), BrokenRoute::Path),
            (with(|r| r.headers = &[("Host", "x")]), BrokenRoute::Header),
            (
                with(|r| r.headers = &[("content-length", "1")]),
                BrokenRoute::Header,
            ),
            (
                with(|r| r.headers = &[("authorization", "x")]),
                BrokenRoute::Header,
            ),
            (with(|r| r.headers = &[("X Y", "x")]), BrokenRoute::Header),
            (
                with(|r| r.headers = &[("Accept", "a\r\nX: y")]),
                BrokenRoute::Header,
            ),
            (with(|r| r.header = ("Connection", "")), BrokenRoute::Header),
            (with(|r| r.max_body = 1), BrokenRoute::Limit),
            (
                with(|r| {
                    r.method = "POST";
                    r.max_body = MAX_ROUTE_BYTES + 1;
                }),
                BrokenRoute::Limit,
            ),
            (with(|r| r.clients = &[]), BrokenRoute::Clients),
        ];
        for (route, broken) in cases {
            assert_eq!(check_routes(&[route], None), Err((0, broken)), "{route:?}");
        }
        let post = with(|r| {
            r.method = "POST";
            r.max_body = MAX_ROUTE_BYTES;
            r.headers = &[("Accept", "application/json")];
        });
        assert_eq!(check_routes(&[post], Some(1)), Ok(()));
        assert_eq!(check_routes(&[good], Some(0)), Err((0, BrokenRoute::Dest)));
        let third = with(|r| r.clients = &[3]);
        assert_eq!(check_routes(&[third], None), Err((0, BrokenRoute::Clients)));
        assert_eq!(
            check_routes(&[good, good], None),
            Err((1, BrokenRoute::Name))
        );
        assert_eq!(
            check_routes(&[good; MAX_ROUTES + 1], None),
            Err((MAX_ROUTES, BrokenRoute::TooMany))
        );
    }

    #[test]
    fn the_secrets_file_goes_only_to_the_vault() {
        const OTHER: [Give; 2] = [CONSOLE, give(Object::Secrets, READ, Badge::None)];
        let mut caps = std::vec::Vec::from(SECRETS[2].caps);
        let mut t = std::vec::Vec::from(SECRETS);
        let other = Service {
            name: "other",
            caps: &OTHER,
            kind: Kind::OneShot,
            after: &[],
            ..SECRETS[3]
        };
        t.push(other);
        assert_eq!(check(&t), Err((4, Broken::Key)));
        caps[3] = give(Object::Secrets, READ | GRANT, Badge::None);
        let leaked: &'static [Give] = std::vec::Vec::leak(caps);
        let t = [Service {
            caps: leaked,
            after: &[],
            ..SECRETS[2]
        }];
        assert_eq!(check(&t[..]), Err((0, Broken::Rights)));
    }

    /// Only the runtime's entry is the runtime, in every table.
    #[test]
    fn the_runtime_is_found_by_its_manifest() {
        let runtimes = |t: &[Service]| {
            t.iter()
                .filter(|s| s.is_runtime())
                .map(|s| s.name)
                .collect::<std::vec::Vec<_>>()
        };
        assert_eq!(runtimes(BOOT), ["agents"]);
        assert_eq!(runtimes(COMPROMISED), ["agents"]);
        assert_eq!(runtimes(SOAK), ["agents"]);
        for t in [TEST, NETWORK, SUPERVISE, HEALTH, TLS, TLS_NORANDOM, SECRETS] {
            assert!(runtimes(t).is_empty());
        }
    }

    /// The `soak` table is the boot table, the runtime on its test policy
    /// table, and one client after it (#189).
    #[test]
    fn the_soak_table_is_the_boot_table_and_a_client() {
        assert_eq!(SOAK.len(), BOOT.len() + 1);
        for (i, (a, b)) in SOAK.iter().zip(BOOT).enumerate() {
            let arg = if i == AGENTS { 1 } else { b.arg };
            assert_eq!(
                (a.name, a.path, a.arg, a.caps, a.after, a.limit),
                (b.name, b.path, arg, b.caps, b.after, b.limit)
            );
        }
        let client = &SOAK[BOOT.len()];
        assert_eq!((client.name, client.after), ("soaker", &[AGENTS][..]));
    }

    /// The `aifail` and `compromised` tables are the boot table with only
    /// `rogue`'s entries' program and argument changed, so it holds exactly
    /// the shipped manifests (M4.6, D-031).
    #[test]
    fn the_rogue_tables_are_the_boot_table_but_their_programs() {
        let fields = |s: &Service| {
            (
                s.name, s.kind, s.restart, s.caps, s.net, s.tcp, s.tls, s.after, s.limit, s.gains,
            )
        };
        for (table, swapped) in [
            (AIFAIL, &[(INFER, "infer", 3)][..]),
            (COMPROMISED, &[(INFER, "infer", 1), (AGENTS, "agents", 2)]),
        ] {
            assert_eq!(table.len(), BOOT.len());
            for (i, (a, b)) in table.iter().zip(BOOT).enumerate() {
                assert_eq!(fields(a), fields(b), "{}", b.name);
                match swapped.iter().find(|s| s.0 == i) {
                    Some(&(_, name, arg)) => {
                        assert_eq!((b.name, a.path, a.arg), (name, &b"bin/rogue"[..], arg));
                    }
                    None => assert_eq!((a.path, a.arg), (b.path, b.arg), "{}", b.name),
                }
            }
        }
    }

    /// `table` with entry `i`'s capabilities replaced by `caps`.
    fn with(table: &'static [Service], i: usize, caps: &'static [Give]) -> std::vec::Vec<Service> {
        (table.iter().enumerate())
            .map(|(j, s)| Service {
                caps: if i == j { caps } else { s.caps },
                ..*s
            })
            .collect()
    }

    #[test]
    fn a_table_breaking_each_rule_is_refused() {
        const BLK: Give = device(VIRTIO_BLK, 0);
        // BOOT: 0 virtio-blk, 1 net, 2 store, 3 infer, 4 audit, 5
        // knowledge, 6 trust, 7 agents.
        const CASES: [(usize, &[Give], Broken); 13] = [
            // `init`'s own badge on the store.
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, send(Ep::Store, 0)],
                Broken::BadgeZero,
            ),
            // The audit service's storage badge taken by the inference service.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    send(Ep::Store, AUDIT_TRAIL),
                ],
                Broken::SameBadge,
            ),
            // Receiving on the store's endpoint.
            (3, &[CONSOLE, receive(Ep::Store), REPORT], Broken::Receiver),
            // GRANT to pass on its storage capability.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(
                        Object::Endpoint(Ep::Store),
                        SEND | GRANT,
                        Badge::Fixed(MODELS_READ_ONLY),
                    ),
                ],
                Broken::Grant,
            ),
            // The root filesystem written, the console read.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(Object::Root, READ | WRITE, Badge::None),
                ],
                Broken::Rights,
            ),
            // The right to mount images (#163): `init`'s only.
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(Object::Root, READ | MOUNT, Badge::None),
                ],
                Broken::Rights,
            ),
            (
                3,
                &[
                    give(Object::DebugConsole, READ, Badge::None),
                    receive(Ep::Infer),
                    REPORT,
                ],
                Broken::Rights,
            ),
            // The read-only disk to a second driver.
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, BLK],
                Broken::SameDevice,
            ),
            // A daemon with no report capability, or two.
            (3, &[CONSOLE, receive(Ep::Infer)], Broken::Report),
            (
                3,
                &[CONSOLE, receive(Ep::Infer), REPORT, REPORT],
                Broken::Report,
            ),
            // A one-shot with one.
            (0, &[CONSOLE, BLK, REPORT], Broken::Report),
            // The audit trail's signing key to another service (D-047).
            (
                3,
                &[
                    CONSOLE,
                    receive(Ep::Infer),
                    REPORT,
                    give(Object::AuditAnchor, READ, Badge::None),
                ],
                Broken::Key,
            ),
            // Thirteen capabilities.
            (3, &[CONSOLE; 13], Broken::TooMany),
        ];
        for (i, caps, broken) in CASES {
            let t = with(BOOT, i, caps);
            assert_eq!(check(&t).map_err(|e| e.1), Err(broken), "{caps:?}");
        }
        // `after` naming a later entry.
        let t: std::vec::Vec<Service> = (BOOT.iter().enumerate())
            .map(|(j, s)| Service {
                after: if j == 1 { &[2] } else { s.after },
                ..*s
            })
            .collect();
        assert_eq!(check(&t), Err((1, Broken::After)));
    }

    #[test]
    fn driver_entries_keep_their_rules() {
        // The boot table's driver entry is last.
        let last = BOOT.len() - 1;
        assert_eq!(BOOT[last].driver(), Some(VIRTIO_BLK));
        assert_eq!(BOOT[..last].iter().find_map(Service::driver), None);
        const HOT: Give = arrived(VIRTIO_BLK);
        // Arrived with other rights, twice, or with a badge.
        for (caps, broken) in [
            (
                &[
                    CONSOLE,
                    give(Object::Arrived(VIRTIO_BLK), MAP, Badge::None),
                    REPORT,
                ][..],
                Broken::Rights,
            ),
            (&[CONSOLE, HOT, HOT, REPORT][..], Broken::Driver),
            (
                &[
                    CONSOLE,
                    give(Object::Arrived(VIRTIO_BLK), DEVICE, Badge::Fixed(1)),
                    REPORT,
                ][..],
                Broken::Rights,
            ),
        ] {
            let caps: &'static [Give] = std::boxed::Box::leak(caps.to_vec().into_boxed_slice());
            assert_eq!(
                check(&with(BOOT, last, caps)).map_err(|e| e.1),
                Err(broken),
                "{caps:?}"
            );
        }
        // A one-shot driver.
        let mut t = BOOT.to_vec();
        t[last] = Service {
            kind: Kind::OneShot,
            caps: &[CONSOLE, HOT],
            ..t[last]
        };
        assert_eq!(check(&t), Err((last, Broken::Driver)));
        // A protected one, or one another entry needs.
        let mut t = BOOT.to_vec();
        t[last] = Service {
            name: "store",
            ..t[last]
        };
        assert_eq!(check(&t).map(|_| ()), Err((last, Broken::Driver)));
        // An entry after it that needs it (BOOT's driver is entry 8).
        let mut t = BOOT.to_vec();
        t.push(Service {
            name: "user",
            caps: &[CONSOLE],
            kind: Kind::OneShot,
            after: &[8],
            ..BOOT[0]
        });
        assert_eq!(check(&t), Err((last, Broken::Driver)));
        // The same device to two drivers.
        let mut t = BOOT.to_vec();
        t.push(t[last]);
        assert_eq!(check(&t).map_err(|e| e.1), Err(Broken::SameDevice));
        // 32 entries: no bit left for slot events.
        let mut t = BOOT.to_vec();
        while t.len() < 32 {
            t.insert(
                0,
                Service {
                    name: "pad",
                    caps: &[CONSOLE],
                    kind: Kind::OneShot,
                    after: &[],
                    ..BOOT[0]
                },
            );
        }
        assert_eq!(check(&t), Err((31, Broken::Driver)));
    }

    #[test]
    fn own_badges_are_entry_numbers() {
        assert_eq!(Badge::Own.value(0), 1);
        assert_eq!(Badge::Fixed(7).value(3), 7);
        assert_eq!(Badge::None.value(3), 0);
        assert_eq!((Restart::Never.limit(), Restart::Up(3).limit()), (0, 3));
    }
}
