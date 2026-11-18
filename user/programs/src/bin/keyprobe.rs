//! Key probe for the `device_key` test kernel (#255, D-047).
//!
//! Handles: 1 debug console, 2 the `AuditAnchor` key (`READ`), 3 the
//! `SlotRecord` key without `READ`. Prints `key <64 hex digits>` (handle
//! 2's key), then `ok <step>` or `FAIL <step>` for each refusal; the exit
//! code is the number of failures.

#![no_std]
#![no_main]

use pharos_user::{Error, debug_write, key_read};

pharos_user::entry!(main);

const CONSOLE: u64 = 1;

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

fn main(_: u64) -> u64 {
    let mut f = 0;
    match key_read(2) {
        Ok(key) => {
            let mut line = *b"key 0000000000000000000000000000000000000000000000000000000000000000";
            for (i, b) in key.iter().enumerate() {
                line[4 + 2 * i] = b"0123456789abcdef"[usize::from(b >> 4)];
                line[5 + 2 * i] = b"0123456789abcdef"[usize::from(b & 0xf)];
            }
            let _ = debug_write(CONSOLE, &line);
        }
        Err(_) => report(&mut f, "key_read of the AuditAnchor key", false),
    }
    report(
        &mut f,
        "a key without READ: MISSING_RIGHT",
        key_read(3).err() == Some(Error::MissingRight),
    );
    report(
        &mut f,
        "the console is not a key: MISSING_RIGHT",
        key_read(CONSOLE).err() == Some(Error::MissingRight),
    );
    report(&mut f, "no such handle: refused", key_read(9).is_err());
    f
}
