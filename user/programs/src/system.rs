//! What `init` needs to boot from an image slot (#163, boot.md section 8)
//! that can be tested on the host: the public key it was built with, the
//! reason codes it sends `trust`, and the updates it offered (#165).

use pharos_image::slots::{Mode, Record};
use pharos_proto::trust::image::REASONS;
use pharos_proto::trust::{MAX_NAME, valid_name};
use pharos_services::Service;
use pharos_services::config::{self, Config};

/// How long an offered update waits for the user's answer (#165).
pub const OFFER_US: u64 = 60_000_000;
/// Most incoming images `update` looks at.
pub const MAX_INCOMING: usize = 4;
/// Most files agents may have waiting in `incoming` (#167): one place is
/// kept, so agents cannot hide a file the host stages.
pub const MAX_PROPOSED: usize = MAX_INCOMING - 1;

/// An incoming image shown to the user: its file in `system/incoming`,
/// the SHA-256 it had then (an answer applies only that image), and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub number: u16,
    name: [u8; MAX_NAME],
    len: usize,
    pub sha256: [u8; 32],
    at: u64,
}

impl Offer {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

/// Why an answer finds no offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gone {
    Unknown,
    /// Not answered within [`OFFER_US`]: it is no longer applied.
    Expired,
}

/// The updates offered since the last `update`, each numbered by `init`
/// (never 0), so an answer cannot reach the runtime's requests.
pub struct Offers {
    list: [Option<Offer>; MAX_INCOMING],
    next: u16,
}

impl Default for Offers {
    fn default() -> Self {
        Self::new()
    }
}

impl Offers {
    pub const fn new() -> Self {
        Self {
            list: [None; MAX_INCOMING],
            next: 1,
        }
    }

    /// Forgets every offer: a new `update` offers afresh.
    pub fn clear(&mut self) {
        self.list = [None; MAX_INCOMING];
    }

    /// Offers `name` with `sha256` at `now`: its number, or `None` if the
    /// name is not valid or every place is taken.
    pub fn offer(&mut self, name: &[u8], sha256: [u8; 32], now: u64) -> Option<u16> {
        if !valid_name(name) {
            return None;
        }
        let free = self.list.iter_mut().find(|o| o.is_none())?;
        let number = self.next;
        self.next = self.next.checked_add(1).unwrap_or(1);
        let mut o = Offer {
            number,
            name: [0; MAX_NAME],
            len: name.len(),
            sha256,
            at: now,
        };
        o.name[..name.len()].copy_from_slice(name);
        *free = Some(o);
        Some(number)
    }

    /// The answer to offer `number` at `now`: the offer, which is gone
    /// afterwards either way.
    pub fn take(&mut self, number: u16, now: u64) -> Result<Offer, Gone> {
        let place = (self.list.iter_mut())
            .find(|o| o.is_some_and(|o| o.number == number))
            .ok_or(Gone::Unknown)?;
        let offer = place.take().ok_or(Gone::Unknown)?;
        if now.saturating_sub(offer.at) > OFFER_US {
            return Err(Gone::Expired);
        }
        Ok(offer)
    }
}

/// Why a slot was refused, as an index into [`REASONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The store could not read it.
    Unreadable,
    /// Its SHA-256 is not the one the record names.
    Replaced,
    /// `fs_mount` refused it.
    NotMounted,
    /// `init` was built without a key, so it trusts no slot.
    NoKey,
    Image(pharos_image::Error),
    /// An update with the image of a bad slot (#165).
    WasBad,
    /// An update whose file is not the image offered.
    Changed,
    /// Its `etc/system.conf` was refused (M4.5).
    Config,
}

impl Refusal {
    /// Its index in [`REASONS`].
    pub fn code(self) -> u32 {
        let text = self.text();
        (REASONS.iter().position(|r| *r == text)).unwrap_or(0) as u32
    }

    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Unreadable => REASONS[0],
            Self::Replaced => REASONS[1],
            Self::NotMounted => REASONS[2],
            Self::NoKey => REASONS[3],
            Self::Image(e) => e.reason().as_bytes(),
            Self::WasBad => REASONS[13],
            Self::Changed => REASONS[14],
            Self::Config => REASONS[15],
        }
    }
}

/// The configuration in `image`, a filesystem image's bytes (M4.5,
/// services.md): its `etc/system.conf` checked against `table`, or every
/// compiled value if it has none. An image that does not mount cannot be
/// read.
pub fn image_config(image: &[u8], table: &[Service]) -> Result<Config, config::Error> {
    let unreadable = config::Error {
        line: 0,
        why: config::Why::Unreadable,
    };
    let fs = pharos_fs::Image::mount(image).map_err(|_| unreadable)?;
    let file = match fs.lookup(config::PATH) {
        Ok(file) => file,
        Err(pharos_fs::FsError::NotFound) => return Ok(Config::COMPILED),
        Err(_) => return Err(unreadable),
    };
    let size = fs.size(file).map_err(|_| unreadable)?;
    if size > config::MAX_SIZE as u64 {
        return Err(config::Error {
            line: 0,
            why: config::Why::TooLarge,
        });
    }
    let mut text = [0u8; config::MAX_SIZE];
    let text = &mut text[..size as usize];
    if fs.read(file, 0, text) != Ok(text.len()) {
        return Err(unreadable);
    }
    config::parse(text, table)
}

/// `init`'s argument (#164): the service table (bits 0–7), the kernel's
/// mode (bits 8 and up: 0 normal, 1 safe, 2 recovery, 3 recovery because
/// `root` failed and its copy was mounted), and whether that copy runs.
/// An unknown mode is normal.
pub fn split_arg(arg: u64) -> (u64, Mode, bool) {
    let mode = match arg >> 8 {
        1 => Mode::Safe,
        2 | 3 => Mode::Recovery,
        _ => Mode::Normal,
    };
    (arg & 0xff, mode, arg >> 8 == 3)
}

/// The factory image's version, as `PHAROS_IMAGE_VERSION` holds it when
/// `init` is built (#167); 0 without it or for anything but a number.
pub fn parse_version(decimal: Option<&str>) -> u64 {
    decimal.and_then(|d| d.parse().ok()).unwrap_or(0)
}

/// Whether an incoming image with `version` and `sha256` may be offered
/// or applied, after its signature (#165, #167): not a bad slot's image,
/// then newer than every slot and than the factory image (`factory`).
pub fn admit(
    record: &Record,
    factory: u64,
    version: u64,
    sha256: &[u8; 32],
) -> Result<(), Refusal> {
    if record.was_bad(sha256) {
        return Err(Refusal::WasBad);
    }
    if version < record.min_version(factory) {
        return Err(Refusal::Image(pharos_image::Error::Old));
    }
    Ok(())
}

/// The public key in 64 hex digits, as `PHAROS_IMAGE_KEY` holds it when
/// `init` is built; `None` for anything else.
pub fn parse_key(hex: Option<&str>) -> Option<[u8; 32]> {
    let hex = hex?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() {
        *k = digit(hex[2 * i])? << 4 | digit(hex[2 * i + 1])?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_image::Error;
    use std::string::ToString;

    fn image(files: &[(&[u8], &[u8])]) -> std::vec::Vec<u8> {
        let mut b = pharos_fs::Builder::new();
        for (path, data) in files {
            b.add(path, data).unwrap();
        }
        b.build().unwrap()
    }

    #[test]
    fn an_image_s_configuration_is_read_and_checked() {
        use pharos_services::BOOT;
        let knowledge = BOOT.iter().position(|s| s.name == "knowledge").unwrap();
        // No file: every compiled value.
        let none = image(&[(b"etc/motd", b"hi")]);
        assert_eq!(image_config(&none, BOOT), Ok(Config::COMPILED));
        let good = image(&[(
            config::PATH,
            b"config = 1\n[service knowledge]\nrestarts = 1\n",
        )]);
        let c = image_config(&good, BOOT).unwrap();
        assert_eq!(
            c.restart(knowledge, pharos_services::Restart::Up(3))
                .limit(),
            1
        );
        let over = image(&[(
            config::PATH,
            b"config = 1\n[service knowledge]\nrestarts = 9\n",
        )]);
        let e = image_config(&over, BOOT).unwrap_err();
        assert_eq!(e.to_string(), "line 3: restarts 9 over 3 for knowledge");
        let big = std::vec![b'#'; config::MAX_SIZE + 1];
        let e = image_config(&image(&[(config::PATH, &big)]), BOOT).unwrap_err();
        assert_eq!(e.why, config::Why::TooLarge);
        // Not an image, or a corrupt one.
        let mut corrupt = good.clone();
        // A byte of the file's text: its checksum no longer matches.
        let at = corrupt.windows(8).position(|w| w == b"restarts").unwrap();
        corrupt[at] ^= 1;
        for bad in [&b"not an image"[..], &corrupt] {
            assert_eq!(
                image_config(bad, BOOT).unwrap_err().why,
                config::Why::Unreadable
            );
        }
    }

    #[test]
    fn every_refusal_has_its_own_reason() {
        let all = [
            Refusal::Unreadable,
            Refusal::Replaced,
            Refusal::NotMounted,
            Refusal::NoKey,
            Refusal::Image(Error::Truncated),
            Refusal::Image(Error::Magic),
            Refusal::Image(Error::HeaderVersion),
            Refusal::Image(Error::Reserved),
            Refusal::Image(Error::TooLarge),
            Refusal::Image(Error::Length),
            Refusal::Image(Error::Signature),
            Refusal::Image(Error::Hash),
            Refusal::Image(Error::Old),
            Refusal::WasBad,
            Refusal::Changed,
            Refusal::Config,
        ];
        assert_eq!(all.len(), REASONS.len());
        for (i, r) in all.iter().enumerate() {
            assert_eq!(r.code(), i as u32, "{r:?}");
            assert_eq!(REASONS[i], r.text());
        }
    }

    #[test]
    fn offers_are_numbered_answered_once_and_expire() {
        let mut o = Offers::new();
        let a = o.offer(b"agent-1", [1; 32], 0).unwrap();
        let b = o.offer(b"host", [2; 32], 0).unwrap();
        assert_eq!((a, b), (1, 2));
        assert_eq!(o.offer(b"bad name", [3; 32], 0), None);
        assert_eq!(o.offer(b"", [3; 32], 0), None);
        let got = o.take(b, OFFER_US).unwrap();
        assert_eq!((got.name(), got.sha256), (&b"host"[..], [2; 32]));
        assert_eq!(o.take(b, OFFER_US), Err(Gone::Unknown), "answered once");
        assert_eq!(
            o.take(a, OFFER_US + 1),
            Err(Gone::Expired),
            "no answer in time"
        );
        assert_eq!(o.take(a, 0), Err(Gone::Unknown), "an expired offer is gone");
        assert_eq!(o.take(0, 0), Err(Gone::Unknown));
        // Four at most; a new `update` forgets them, numbers keep rising.
        for n in 0..MAX_INCOMING {
            assert!(o.offer(b"x", [0; 32], 0).is_some(), "{n}");
        }
        assert_eq!(o.offer(b"x", [0; 32], 0), None, "full");
        o.clear();
        assert_eq!(o.take(3, 0), Err(Gone::Unknown));
        assert_eq!(o.offer(b"x", [0; 32], 0), Some(7));
        let mut wrap = Offers::new();
        wrap.next = u16::MAX;
        assert_eq!(wrap.offer(b"x", [0; 32], 0), Some(u16::MAX));
        assert_eq!(wrap.offer(b"y", [0; 32], 0), Some(1), "never 0");
    }

    #[test]
    fn the_argument_holds_the_table_and_the_kernels_mode() {
        assert_eq!(split_arg(0), (0, Mode::Normal, false));
        assert_eq!(split_arg(3), (3, Mode::Normal, false));
        assert_eq!(split_arg(0x100), (0, Mode::Safe, false));
        assert_eq!(split_arg(0x200), (0, Mode::Recovery, false));
        assert_eq!(split_arg(0x300), (0, Mode::Recovery, true));
        assert_eq!(split_arg(0x900), (0, Mode::Normal, false));
    }

    #[test]
    fn an_update_is_not_a_bad_image_then_newer_than_all() {
        use pharos_image::slots::{Slot, SlotInfo, State};
        let slot = |state, version: u64| SlotInfo {
            state,
            attempts: 0,
            version,
            sha256: [version as u8; 32],
        };
        let r = Record {
            active: Some(Slot::A),
            slots: [slot(State::Good, 6), slot(State::Bad, 10)],
            ..Record::EMPTY
        };
        // The bad slot's image says so, though it is also too old.
        assert_eq!(admit(&r, 0, 10, &[10; 32]), Err(Refusal::WasBad));
        assert_eq!(
            admit(&r, 0, 10, &[1; 32]),
            Err(Refusal::Image(pharos_image::Error::Old))
        );
        assert_eq!(admit(&r, 0, 11, &[1; 32]), Ok(()));
        assert_eq!(admit(&Record::EMPTY, 0, 1, &[1; 32]), Ok(()));
        assert_eq!(
            admit(&Record::EMPTY, 4, 4, &[1; 32]),
            Err(Refusal::Image(pharos_image::Error::Old)),
            "not older than the factory image"
        );
        assert_eq!(parse_version(Some("12")), 12);
        assert_eq!(parse_version(Some("x")), 0);
        assert_eq!(parse_version(None), 0);
    }

    #[test]
    fn keys_parse_from_64_hex_digits_only() {
        assert_eq!(parse_key(Some(&"0f".repeat(32))), Some([0x0f; 32]));
        assert_eq!(parse_key(Some(&"AB".repeat(32))), Some([0xab; 32]));
        assert_eq!(parse_key(None), None);
        assert_eq!(parse_key(Some("")), None);
        assert_eq!(parse_key(Some(&"0f".repeat(31))), None);
        assert_eq!(parse_key(Some(&"zz".repeat(32))), None);
        assert_eq!(parse_key(Some(&"é".repeat(32))), None);
    }
}
