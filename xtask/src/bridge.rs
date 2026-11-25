//! The Tier 3 launch tool (#297, bridge.md, D-036): Pharos and the guest
//! as two VMs, each with one virtio-serial port, joined by one host unix
//! socket with no relay. Pharos's QEMU is the socket's server and the
//! guest's the client. Both run in the run's directory, so the socket's
//! path is short (Linux allows 107 bytes).
//!
//! Before the guest starts, [`check_guest`] refuses any command line but
//! the one [`guest_args`] writes: no network device, disk, or shared
//! filesystem, exactly one channel, and each value the one the launch tool
//! writes (#305). [`check_image`] refuses a kernel or initrd whose SHA-256
//! is not the one its build recorded. Once both run, [`check_vms`] asks
//! each QEMU over QMP (a host socket the guest cannot reach) for its PCI
//! devices: the guest must have exactly the q35 chipset's and its one
//! `virtio-serial-pci`, and no block device; Pharos must have its second
//! virtio-console.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::Result;

/// The channel's socket, in the run's directory.
pub const SOCKET: &str = "bridge.sock";
pub const PHAROS_QMP: &str = "pharos-qmp.sock";
pub const GUEST_QMP: &str = "guest-qmp.sock";
/// The guest's serial console (output only), in the run's directory.
pub const GUEST_LOG: &str = "guest-serial.log";
/// The guest's port name; Linux shows it as `/dev/virtio-ports/<name>`.
pub const PORT: &str = "org.pharos.bridge";

/// PCI (vendor, device) of a modern virtio-console (`virtio-serial-pci`).
const VIRTIO_CONSOLE: (u16, u16) = (0x1af4, 0x1043);
/// The guest's devices, sorted: q35's host bridge, LPC, AHCI (with no
/// drive), and SMBus, and the one `virtio-serial-pci`.
const GUEST_PCI: [(u16, u16); 5] = [
    VIRTIO_CONSOLE,
    (0x8086, 0x2918),
    (0x8086, 0x2922),
    (0x8086, 0x2930),
    (0x8086, 0x29c0),
];

/// What Pharos's VM adds to its command line: a second `virtio-serial-pci`
/// (after every other device, so `trust` keeps the first) whose port 0 is
/// the socket's server end, and QMP.
pub fn pharos_args() -> Vec<OsString> {
    [
        "-device".into(),
        "virtio-serial-pci,disable-legacy=on,iommu_platform=on".into(),
        "-chardev".into(),
        format!("socket,id=bridge,path={SOCKET},server=on,wait=off"),
        "-device".into(),
        "virtconsole,chardev=bridge".into(),
        "-qmp".into(),
        format!("unix:{PHAROS_QMP},server=on,wait=off"),
    ]
    .map(OsString::from)
    .to_vec()
}

/// The guest image's files in its directory, as `cargo xtask guest`
/// (`scripts/guest-image.py`) writes them, and their SHA-256 beside them.
pub const KERNEL: &str = "vmlinuz-virt";
pub const INITRD: &str = "initramfs";
pub const HASHES: &str = "image.sha256";
/// The guest kernel's command line.
const APPEND: &str = "console=ttyS0 quiet panic=-1";
/// QEMU's memory for the guest.
const MEMORY: &str = "512M";

/// The guest's whole command line: the image in `image` (the directory
/// with [`KERNEL`] and [`INITRD`]) in RAM, no defaults, no network device,
/// the serial console to [`GUEST_LOG`], one port on the socket's client
/// end, and QMP. `kvm`: `-accel kvm -cpu host`, else TCG on `-cpu max`
/// (the wheels need more than QEMU's default CPU).
pub fn guest_args(image: &Path, kvm: bool) -> Vec<OsString> {
    let accel: [&str; 4] = if kvm {
        ["-accel", "kvm", "-cpu", "host"]
    } else {
        ["-accel", "tcg", "-cpu", "max"]
    };
    let mut args: Vec<OsString> = accel.map(OsString::from).to_vec();
    args.extend(
        [
            "-machine",
            "q35",
            "-m",
            MEMORY,
            "-nodefaults",
            "-no-user-config",
            "-nic",
            "none",
            "-display",
            "none",
            "-no-reboot",
        ]
        .map(OsString::from),
    );
    args.extend(["-serial".into(), format!("file:{GUEST_LOG}").into()]);
    args.extend(["-kernel".into(), image.join(KERNEL).into_os_string()]);
    args.extend(["-initrd".into(), image.join(INITRD).into_os_string()]);
    args.extend(
        [
            "-append".into(),
            APPEND.into(),
            "-chardev".into(),
            format!("socket,id=bridge,path={SOCKET}"),
            "-device".into(),
            "virtio-serial-pci,disable-legacy=on".into(),
            "-device".into(),
            format!("virtserialport,chardev=bridge,name={PORT}"),
            "-qmp".into(),
            format!("unix:{GUEST_QMP},server=on,wait=off"),
        ]
        .map(OsString::from),
    );
    args
}

/// The options [`guest_args`] writes once each, with no value or with one.
const ONCE: [&str; 3] = ["-nodefaults", "-no-user-config", "-no-reboot"];
const ONCE_WITH_VALUE: [&str; 11] = [
    "-accel", "-cpu", "-machine", "-m", "-nic", "-display", "-serial", "-kernel", "-initrd",
    "-append", "-qmp",
];

/// Refuses a guest command line that is not exactly what [`guest_args`]
/// writes for `image`, naming what it found: every option must be on the
/// list with the value the launch tool writes, each option but `-device`
/// given once, `-nodefaults` and `-no-user-config` present, one channel,
/// and the devices only the channel's two.
pub fn check_guest(args: &[OsString], image: &Path) -> Result<()> {
    let refuse = |why: String| Err(format!("refusing the guest's configuration: {why}"));
    let (kernel, initrd) = (image.join(KERNEL), image.join(INITRD));
    let mut it = args.iter();
    let mut seen: Vec<&str> = Vec::new();
    let (mut accel, mut cpu) = (String::new(), String::new());
    let (mut chardevs, mut serial_pci, mut ports) = (0, 0, 0);
    while let Some(raw) = it.next() {
        let lossy = raw.to_string_lossy();
        let opt = lossy.as_ref();
        if let Some(once) = ONCE.iter().chain(&ONCE_WITH_VALUE).find(|o| **o == opt) {
            if seen.contains(once) {
                return refuse(format!("{opt} is given more than once"));
            }
            seen.push(once);
        }
        match opt {
            "-nodefaults" | "-no-user-config" | "-no-reboot" => {}
            "-netdev" | "-net" => return refuse(format!("{opt} gives it a network device")),
            "-virtfs" | "-fsdev" => return refuse(format!("{opt} gives it a shared filesystem")),
            "-drive" | "-hda" | "-hdb" | "-cdrom" | "-blockdev" | "-sd" | "-pflash" => {
                return refuse(format!("{opt} gives it a disk"));
            }
            _ if ONCE_WITH_VALUE.contains(&opt) || opt == "-chardev" || opt == "-device" => {
                let Some(raw_value) = it.next() else {
                    return refuse(format!("{opt} has no value"));
                };
                let value = raw_value.to_string_lossy();
                let ok = match opt {
                    "-accel" => {
                        accel = value.to_string();
                        value == "kvm" || value == "tcg"
                    }
                    "-cpu" => {
                        cpu = value.to_string();
                        value == "host" || value == "max"
                    }
                    "-machine" => value == "q35",
                    "-m" => value == MEMORY,
                    "-nic" | "-display" => value == "none",
                    "-serial" => value == format!("file:{GUEST_LOG}"),
                    "-qmp" => value == format!("unix:{GUEST_QMP},server=on,wait=off"),
                    "-kernel" => raw_value.as_os_str() == kernel.as_os_str(),
                    "-initrd" => raw_value.as_os_str() == initrd.as_os_str(),
                    "-append" => value == APPEND,
                    "-chardev" => {
                        chardevs += 1;
                        value == format!("socket,id=bridge,path={SOCKET}")
                    }
                    _ => {
                        let driver = value.split(',').next().unwrap_or("");
                        if driver == "virtio-serial-pci" {
                            serial_pci += 1;
                            value == "virtio-serial-pci,disable-legacy=on"
                        } else if driver == "virtserialport" {
                            ports += 1;
                            value == format!("virtserialport,chardev=bridge,name={PORT}")
                        } else {
                            return refuse(format!(
                                "-device {driver} is not on the list (only the channel's \
                                 virtio-serial-pci and virtserialport)"
                            ));
                        }
                    }
                };
                if !ok {
                    return refuse(format!("{opt} {value} is not allowed"));
                }
            }
            other => return refuse(format!("{other} is not on the list")),
        }
    }
    if !seen.contains(&"-nodefaults") {
        return refuse("no -nodefaults, so QEMU would add its default devices".into());
    }
    if !seen.contains(&"-no-user-config") {
        return refuse("no -no-user-config, so QEMU would read its configuration files".into());
    }
    if let Some(missing) = ONCE_WITH_VALUE.iter().find(|o| !seen.contains(o)) {
        return refuse(format!("no {missing}, which the launch tool always writes"));
    }
    if !matches!(
        (accel.as_str(), cpu.as_str()),
        ("kvm", "host") | ("tcg", "max")
    ) {
        return refuse(format!(
            "-accel {accel} with -cpu {cpu} (only kvm with host, or tcg with max)"
        ));
    }
    if chardevs != 1 || serial_pci != 1 || ports != 1 {
        return refuse(format!(
            "it needs exactly one channel: {chardevs} chardevs, {serial_pci} \
             virtio-serial-pci, {ports} virtserialport"
        ));
    }
    Ok(())
}

/// Refuses a guest image whose [`KERNEL`] or [`INITRD`] in `image` has a
/// SHA-256 other than the one its build recorded in [`HASHES`], or a
/// [`HASHES`] that is not exactly those two lines.
pub fn check_image(image: &Path) -> Result<()> {
    let hashes = image.join(HASHES);
    let text = std::fs::read_to_string(&hashes).map_err(|e| {
        format!(
            "cannot read {}: {e} (run `cargo xtask guest`)",
            hashes.display()
        )
    })?;
    let lines: Vec<&str> = text.lines().collect();
    let [kernel, initrd] = lines.as_slice() else {
        return Err(format!(
            "{} has {} lines, not the kernel's and the initrd's",
            hashes.display(),
            lines.len()
        ));
    };
    for (line, name) in [(kernel, KERNEL), (initrd, INITRD)] {
        let want = match line.split_once("  ") {
            Some((hash, n))
                if n == name
                    && hash.len() == 64
                    && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                hash
            }
            _ => {
                return Err(format!(
                    "{}: expected `<sha256>  {name}`, found {line:?}",
                    hashes.display()
                ));
            }
        };
        let path = image.join(name);
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let got = crate::sign::hex(&pharos_store::sha256(&[&bytes]));
        if got != want {
            return Err(format!(
                "refusing the guest's image: {} has SHA-256 {got}, not the {want} its build \
                 recorded in {HASHES} (run `cargo xtask guest`)",
                path.display()
            ));
        }
    }
    Ok(())
}

/// The running guest; stopped when dropped.
pub struct Guest(Child);

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Checks `args` against `image` and the image against its recorded
/// hashes, then waits up to 120 s for `marker` in Pharos's serial
/// log, which Pharos prints once its own driver has reset the channel's
/// device, and only then starts the guest in `dir`.
///
/// Not earlier: Pharos's UEFI firmware (OVMF) takes every virtio-console
/// as a console, so a guest connected during the firmware would read its
/// output and could type into it. With no client on the socket, QEMU drops
/// what the firmware writes. Pharos's QEMU runs with `-no-reboot`, so a
/// reset, which would run the firmware again, ends the run instead.
pub fn start_guest(
    dir: &Path,
    image: &Path,
    args: &[OsString],
    pharos_log: &Path,
    marker: &str,
) -> Result<Guest> {
    check_guest(args, image)?;
    check_image(image)?;
    let start = Instant::now();
    while !std::fs::read_to_string(pharos_log).is_ok_and(|l| l.contains(marker)) {
        if start.elapsed() > Duration::from_secs(120) {
            return Err(format!("Pharos did not print '{marker}' in 120 s"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !dir.join(SOCKET).exists() {
        return Err(format!("Pharos's QEMU made no {SOCKET}"));
    }
    let err = File::create(dir.join("guest-qemu.err"))
        .map_err(|e| format!("cannot create guest-qemu.err in {}: {e}", dir.display()))?;
    let child = Command::new("qemu-system-x86_64")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err)
        .spawn()
        .map_err(|e| format!("cannot start the guest's QEMU: {e}"))?;
    Ok(Guest(child))
}

fn wait_for(path: &Path, limit: Duration) -> Result<()> {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > limit {
            return Err(format!("{} did not appear in {limit:?}", path.display()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Checks both VMs over QMP (module docs). An error names what differs.
pub fn check_vms(dir: &Path) -> Result<()> {
    let mut guest = Qmp::open(dir, GUEST_QMP)?;
    let mut found = pci_ids(&guest.ask("query-pci")?);
    found.sort_unstable();
    if found != GUEST_PCI {
        return Err(format!(
            "the guest's PCI devices are {}, not the expected {}",
            show(&found),
            show(&GUEST_PCI)
        ));
    }
    let blocks = guest.ask("query-block")?;
    if blocks.trim() != r#"{"return": []}"# {
        return Err(format!("the guest has a block device: {blocks}"));
    }
    let consoles = pci_ids(&Qmp::open(dir, PHAROS_QMP)?.ask("query-pci")?)
        .into_iter()
        .filter(|&id| id == VIRTIO_CONSOLE)
        .count();
    if consoles != 2 {
        return Err(format!(
            "Pharos has {consoles} virtio-consoles, not 2 (the trusted console and the channel)"
        ));
    }
    Ok(())
}

/// Stops the VM whose QMP socket is `name` in `dir`, if it still runs.
pub fn quit(dir: &Path, name: &str) {
    if let Ok(mut q) = Qmp::open(dir, name) {
        let _ = q.ask("quit");
    }
}

fn show(ids: &[(u16, u16)]) -> String {
    let all: Vec<String> = ids
        .iter()
        .map(|(v, d)| format!("{v:04x}:{d:04x}"))
        .collect();
    all.join(" ")
}

/// Each `"id": {...}` object's vendor and device, in a `query-pci` reply.
fn pci_ids(reply: &str) -> Vec<(u16, u16)> {
    let number = |obj: &str, key: &str| -> Option<u16> {
        let at = obj.find(key)? + key.len();
        let digits: String = obj[at..].chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    let mut ids = Vec::new();
    let mut rest = reply;
    while let Some(at) = rest.find(r#""id": {"#) {
        rest = &rest[at + 7..];
        let obj = &rest[..rest.find('}').unwrap_or(rest.len())];
        if let (Some(v), Some(d)) = (number(obj, r#""vendor": "#), number(obj, r#""device": "#)) {
            ids.push((v, d));
        }
    }
    ids
}

/// A QMP connection, through `/proc/self/fd` so the socket's path stays
/// short however deep the run's directory is.
struct Qmp {
    _dir: File,
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Qmp {
    fn open(dir: &Path, name: &str) -> Result<Self> {
        wait_for(&dir.join(name), Duration::from_secs(30))?;
        let d = File::open(dir).map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
        let short = format!("/proc/self/fd/{}/{name}", d.as_raw_fd());
        let stream = UnixStream::connect(OsStr::new(&short))
            .map_err(|e| format!("cannot connect to {name}: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("{name}: {e}"))?;
        let reader = BufReader::new(stream.try_clone().map_err(|e| format!("{name}: {e}"))?);
        let mut q = Self {
            _dir: d,
            stream,
            reader,
        };
        q.line()?; // the greeting
        q.ask("qmp_capabilities")?;
        Ok(q)
    }

    fn line(&mut self) -> Result<String> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err("QMP closed".into()),
            Ok(_) => Ok(line),
            Err(e) => Err(format!("QMP: {e}")),
        }
    }

    /// The reply to `command`, skipping events.
    fn ask(&mut self, command: &str) -> Result<String> {
        writeln!(self.stream, r#"{{"execute": "{command}"}}"#).map_err(|e| format!("QMP: {e}"))?;
        loop {
            let line = self.line()?;
            if line.starts_with(r#"{"return""#) {
                return Ok(line);
            }
            if line.starts_with(r#"{"error""#) {
                return Err(format!("QMP {command}: {line}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "/img";

    fn guest() -> Vec<OsString> {
        guest_args(Path::new(IMAGE), true)
    }

    fn with(extra: &[&str]) -> Vec<OsString> {
        let mut a = guest();
        a.extend(extra.iter().map(OsString::from));
        a
    }

    /// The line with `opt`'s value replaced.
    fn set(opt: &str, value: &str) -> Vec<OsString> {
        let mut a = guest();
        let at = a.iter().position(|x| x == opt).expect(opt) + 1;
        a[at] = value.into();
        a
    }

    /// The line without `opt` (and its value, if it takes one).
    fn without(opt: &str, takes_value: bool) -> Vec<OsString> {
        let mut a = guest();
        let at = a.iter().position(|x| x == opt).expect(opt);
        a.drain(at..at + 1 + usize::from(takes_value));
        a
    }

    fn refused(args: &[OsString], why: &str) {
        let err = check_guest(args, Path::new(IMAGE)).expect_err(why);
        assert!(err.contains(why), "{err} should say {why}");
    }

    #[test]
    fn the_written_guest_lines_pass() {
        let image = Path::new(IMAGE);
        assert_eq!(check_guest(&guest(), image), Ok(()));
        assert_eq!(check_guest(&guest_args(image, false), image), Ok(()));
    }

    #[test]
    fn values_the_launch_tool_does_not_write_are_refused() {
        refused(&set("-cpu", "qemu64"), "-cpu qemu64 is not allowed");
        refused(&set("-cpu", "max"), "-accel kvm with -cpu max");
        refused(&set("-accel", "tcg"), "-accel tcg with -cpu host");
        refused(&set("-m", "64G"), "-m 64G is not allowed");
        refused(
            &set("-kernel", "/elsewhere/vmlinuz-virt"),
            "-kernel /elsewhere/vmlinuz-virt is not allowed",
        );
        refused(
            &set("-initrd", "/img/other"),
            "-initrd /img/other is not allowed",
        );
        refused(
            &set("-append", "console=ttyS0 quiet panic=-1 init=/bin/sh"),
            "-append console=ttyS0 quiet panic=-1 init=/bin/sh is not allowed",
        );
        refused(
            &set("-serial", "file:/home/x/.bashrc"),
            "-serial file:/home/x/.bashrc is not allowed",
        );
        refused(
            &set("-qmp", "unix:/tmp/q.sock,server=on,wait=off"),
            "is not allowed",
        );
        refused(&set("-qmp", "tcp:0:4444,server=on"), "is not allowed");
    }

    #[test]
    fn options_given_twice_are_refused() {
        refused(
            &with(&["-serial", "file:guest-serial.log"]),
            "-serial is given more than once",
        );
        refused(
            &with(&["-qmp", "unix:guest-qmp.sock,server=on,wait=off"]),
            "-qmp is given more than once",
        );
        refused(&with(&["-m", "512M"]), "-m is given more than once");
        refused(
            &with(&["-nodefaults"]),
            "-nodefaults is given more than once",
        );
    }

    #[test]
    fn missing_options_are_refused() {
        refused(&without("-no-user-config", false), "no -no-user-config");
        refused(&without("-kernel", true), "no -kernel");
        refused(&without("-qmp", true), "no -qmp");
        refused(&without("-cpu", true), "no -cpu");
    }

    struct Dir(std::path::PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A built image in a fresh directory: the files and their hashes.
    fn image(name: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("pharos-image-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(KERNEL), b"kernel").unwrap();
        std::fs::write(dir.join(INITRD), b"initrd").unwrap();
        let h = |b: &[u8]| crate::sign::hex(&pharos_store::sha256(&[b]));
        let text = format!("{}  {KERNEL}\n{}  {INITRD}\n", h(b"kernel"), h(b"initrd"));
        std::fs::write(dir.join(HASHES), text).unwrap();
        Dir(dir)
    }

    fn image_refused(dir: &Path, why: &str) {
        let err = check_image(dir).expect_err(why);
        assert!(err.contains(why), "{err} should say {why}");
    }

    #[test]
    fn the_built_image_passes() {
        let d = image("ok");
        assert_eq!(check_image(&d.0), Ok(()));
    }

    #[test]
    fn an_image_file_whose_hash_differs_is_refused() {
        let d = image("kernel");
        std::fs::write(d.0.join(KERNEL), b"other kernel").unwrap();
        image_refused(&d.0, "vmlinuz-virt has SHA-256");
        let d = image("initrd");
        std::fs::write(d.0.join(INITRD), b"initrd, longer").unwrap();
        image_refused(&d.0, "initramfs has SHA-256");
    }

    #[test]
    fn a_missing_or_malformed_hash_record_is_refused() {
        let d = image("none");
        std::fs::remove_file(d.0.join(HASHES)).unwrap();
        image_refused(&d.0, "run `cargo xtask guest`");
        let d = image("extra");
        let text = std::fs::read_to_string(d.0.join(HASHES)).unwrap();
        std::fs::write(d.0.join(HASHES), format!("{text}{text}")).unwrap();
        image_refused(&d.0, "has 4 lines");
        let d = image("swapped");
        let text = std::fs::read_to_string(d.0.join(HASHES)).unwrap();
        let swapped: Vec<&str> = text.lines().rev().collect();
        std::fs::write(d.0.join(HASHES), swapped.join("\n")).unwrap();
        image_refused(&d.0, "expected `<sha256>  vmlinuz-virt`");
        let d = image("upper");
        let text = std::fs::read_to_string(d.0.join(HASHES)).unwrap();
        let upper: Vec<String> = text
            .lines()
            .map(|l| {
                let (hash, name) = l.split_once("  ").unwrap();
                format!("{}  {name}", hash.to_ascii_uppercase())
            })
            .collect();
        std::fs::write(d.0.join(HASHES), upper.join("\n")).unwrap();
        image_refused(&d.0, "expected `<sha256>  vmlinuz-virt`");
    }

    #[test]
    fn the_guest_is_not_started_from_a_changed_image() {
        let d = image("start");
        std::fs::write(d.0.join(INITRD), b"changed").unwrap();
        let log = d.0.join("pharos.log");
        std::fs::write(&log, "bridge: ready\n").unwrap();
        let args = guest_args(&d.0, true);
        let Err(err) = start_guest(&d.0, &d.0, &args, &log, "bridge: ready") else {
            panic!("a changed initrd was started");
        };
        assert!(err.contains("initramfs has SHA-256"), "{err}");
    }

    #[test]
    fn network_disks_and_shared_filesystems_are_refused() {
        refused(&with(&["-netdev", "user,id=n"]), "network device");
        refused(&with(&["-net", "nic"]), "network device");
        refused(&set("-nic", "user"), "-nic user is not allowed");
        refused(
            &with(&["-virtfs", "local,path=/,mount_tag=h"]),
            "shared filesystem",
        );
        refused(&with(&["-fsdev", "local,id=f,path=/"]), "shared filesystem");
        refused(&with(&["-drive", "file=x"]), "disk");
        refused(&with(&["-cdrom", "x.iso"]), "disk");
        refused(&with(&["-blockdev", "driver=file"]), "disk");
        refused(
            &with(&["-device", "vhost-user-fs-pci"]),
            "is not on the list",
        );
        refused(&with(&["-device", "virtio-net-pci"]), "is not on the list");
        refused(&with(&["-device", "virtio-9p-pci"]), "is not on the list");
    }

    #[test]
    fn a_second_channel_is_refused() {
        refused(
            &with(&["-chardev", "socket,id=bridge,path=bridge.sock"]),
            "exactly one channel",
        );
        refused(
            &with(&[
                "-device",
                "virtserialport,chardev=bridge,name=org.pharos.bridge",
            ]),
            "exactly one channel",
        );
        refused(
            &with(&["-device", "virtio-serial-pci,disable-legacy=on"]),
            "exactly one channel",
        );
        refused(
            &with(&["-chardev", "socket,id=other,path=x"]),
            "is not allowed",
        );
        refused(
            &with(&["-device", "virtconsole,chardev=bridge"]),
            "is not on the list",
        );
    }

    #[test]
    fn defaults_and_unlisted_options_are_refused() {
        let no_defaults: Vec<OsString> =
            guest().into_iter().filter(|a| a != "-nodefaults").collect();
        refused(&no_defaults, "-nodefaults");
        refused(&with(&["-usb"]), "is not on the list");
        refused(&with(&["-monitor", "stdio"]), "is not on the list");
        refused(&set("-machine", "pc"), "is not allowed");
        refused(&set("-serial", "stdio"), "is not allowed");
        refused(&with(&["-device"]), "has no value");
    }

    #[test]
    fn pharos_gets_the_server_end_after_its_devices() {
        let a: Vec<String> = pharos_args()
            .iter()
            .map(|a| a.to_string_lossy().into())
            .collect();
        assert!(a.contains(&format!(
            "socket,id=bridge,path={SOCKET},server=on,wait=off"
        )));
        assert!(a.contains(&"virtconsole,chardev=bridge".to_owned()));
        let g: Vec<String> = guest().iter().map(|a| a.to_string_lossy().into()).collect();
        assert!(
            !g.iter()
                .any(|a| a.contains("server=on") && a.contains("id=bridge"))
        );
    }

    #[test]
    fn pci_ids_are_read_from_qmp() {
        // From QEMU 8.2.2's reply for the guest (trimmed).
        let reply = r#"{"return": [{"bus": 0, "devices": [{"irq_pin": 0, "bus": 0, "qdev_id": "", "slot": 0, "class_info": {"class": 1536, "desc": "Host bridge"}, "id": {"device": 10688, "subsystem-vendor": 6900, "vendor": 32902, "subsystem": 4352}, "function": 0, "regions": []}, {"slot": 1, "id": {"device": 4163, "subsystem-vendor": 6900, "vendor": 6900, "subsystem": 1100}}]}]}"#;
        assert_eq!(pci_ids(reply), [(0x8086, 0x29c0), VIRTIO_CONSOLE]);
        assert_eq!(pci_ids(r#"{"return": []}"#), []);
    }
}
