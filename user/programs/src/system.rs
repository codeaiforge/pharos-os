//! What `init` needs to boot from an image slot (#163, boot.md section 8)
//! that can be tested on the host: the public key it was built with, and
//! the reason codes it sends `trust`.

use pharos_image::slots::Mode;
use pharos_proto::trust::image::REASONS;

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
        }
    }
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
        ];
        assert_eq!(all.len(), REASONS.len());
        for (i, r) in all.iter().enumerate() {
            assert_eq!(r.code(), i as u32, "{r:?}");
            assert_eq!(REASONS[i], r.text());
        }
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
