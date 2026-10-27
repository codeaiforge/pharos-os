//! System calls (D-014, syscalls-ipc.md): numbers, error codes, argument
//! decoding, and the handler the entry stub calls.
//!
//! Every argument is untrusted. [`decode`] checks what needs no state (call
//! number, lengths, user address ranges) and is host-tested with random
//! input. The handler then checks the handle and its rights in the caller's
//! capability table, and copies user memory only through
//! `AddressSpace::read_user`/`write_user`. Check order: number, length,
//! address range, handle, rights, then the pages themselves.

use crate::arch::x86_64::paging::{MapError, user_range_ok};
use crate::cap::{self, CapError, Handle};

/// Call numbers.
pub mod number {
    pub const EXIT: u64 = 0;
    pub const YIELD: u64 = 1;
    pub const DEBUG_WRITE: u64 = 2;
    pub const SEND: u64 = 3;
    pub const RECEIVE: u64 = 4;
    pub const DELETE: u64 = 5;
    pub const REVOKE: u64 = 6;
}

/// Largest buffer `debug_write` accepts (and the IPC message size).
pub const MAX_MESSAGE: usize = 256;

/// Error codes returned in `rax` (0 is success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Error {
    UnknownCall = 1,
    InvalidHandle = 2,
    Revoked = 3,
    MissingRight = 4,
    BadAddress = 5,
    TooLarge = 6,
    NoMemory = 7,
}

impl From<CapError> for Error {
    fn from(error: CapError) -> Self {
        match error {
            CapError::InvalidHandle => Self::InvalidHandle,
            CapError::Revoked => Self::Revoked,
            CapError::MissingRight => Self::MissingRight,
            CapError::TableFull => Self::NoMemory,
        }
    }
}

impl From<MapError> for Error {
    fn from(_: MapError) -> Self {
        Self::BadAddress
    }
}

/// A decoded system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Exit {
        code: u64,
    },
    Yield,
    DebugWrite {
        handle: Handle,
        addr: u64,
        len: usize,
    },
    Delete {
        handle: Handle,
    },
    Send {
        handle: Handle,
        addr: u64,
        len: usize,
        /// Capability to pass (0 = none).
        cap: Handle,
        /// Rights the receiver gets, at most those of `cap`.
        rights: cap::Rights,
    },
    Receive {
        handle: Handle,
        addr: u64,
        max_len: usize,
    },
    Revoke {
        handle: Handle,
    },
}

/// Checks a user buffer argument: length first, then the address range.
fn buffer(addr: u64, len: u64) -> Result<usize, Error> {
    if len > MAX_MESSAGE as u64 {
        return Err(Error::TooLarge);
    }
    if !user_range_ok(addr, len) {
        return Err(Error::BadAddress);
    }
    Ok(len as usize)
}

/// Decodes call `number` with `args` (`rdi`, `rsi`, `rdx`, `r10`, `r8`,
/// `r9`). Checks everything that needs no state.
pub fn decode(number: u64, args: [u64; 6]) -> Result<Call, Error> {
    match number {
        number::EXIT => Ok(Call::Exit { code: args[0] }),
        number::YIELD => Ok(Call::Yield),
        number::DEBUG_WRITE => Ok(Call::DebugWrite {
            handle: args[0],
            addr: args[1],
            len: buffer(args[1], args[2])?,
        }),
        number::SEND => Ok(Call::Send {
            handle: args[0],
            addr: args[1],
            len: buffer(args[1], args[2])?,
            cap: args[3],
            // Rights are a 32-bit mask; higher bits name no right.
            rights: args[4] as cap::Rights,
        }),
        number::RECEIVE => Ok(Call::Receive {
            handle: args[0],
            addr: args[1],
            max_len: buffer(args[1], args[2])?,
        }),
        number::DELETE => Ok(Call::Delete { handle: args[0] }),
        number::REVOKE => Ok(Call::Revoke { handle: args[0] }),
        _ => Err(Error::UnknownCall),
    }
}

/// Needed right for each capability-using call.
pub fn needed_rights(call: &Call) -> cap::Rights {
    match call {
        Call::DebugWrite { .. } => cap::WRITE,
        Call::Send { .. } => cap::SEND,
        Call::Receive { .. } => cap::RECEIVE,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
pub use kernel::handle;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::syscall::SyscallFrame;
    use crate::cap::{MAX_HANDLES, Object};
    use crate::ipc::{self, Message};
    use crate::{process, sched};

    /// The endpoint behind `handle`, if the caller holds `needed` on it.
    fn endpoint(
        process: &process::Process,
        handle: Handle,
        needed: cap::Rights,
    ) -> Result<alloc::sync::Arc<ipc::Endpoint>, Error> {
        match process.caps.lock().get(handle, needed)?.object() {
            Object::Endpoint(endpoint) => Ok(endpoint.clone()),
            _ => Err(Error::MissingRight),
        }
    }

    /// The system-call handler (installed by `process::init`). Runs on the
    /// calling thread's kernel stack with interrupts disabled.
    pub fn handle(frame: &mut SyscallFrame) {
        let result = decode(frame.rax, frame.args()).and_then(execute);
        let (status, value) = match result {
            Ok(value) => (0, value),
            Err(error) => (error as u64, 0),
        };
        frame.rax = status;
        frame.rdx = value;
    }

    fn execute(call: Call) -> Result<u64, Error> {
        let process = process::current().ok_or(Error::UnknownCall)?;
        match call {
            Call::Exit { code } => {
                drop(process);
                process::exit_current(code)
            }
            Call::Yield => {
                drop(process);
                sched::yield_now();
                Ok(0)
            }
            Call::DebugWrite { handle, addr, len } => {
                let cap = process.caps.lock().get(handle, needed_rights(&call))?;
                if !matches!(cap.object(), Object::DebugConsole) {
                    return Err(Error::MissingRight);
                }
                let mut buf = [0u8; MAX_MESSAGE];
                sched::with_current_space(|space| space.read_user(addr, &mut buf[..len]))
                    .ok_or(Error::BadAddress)??;
                process::debug_write(&buf[..len]);
                Ok(len as u64)
            }
            Call::Delete { handle } => {
                process.caps.lock().delete(handle)?;
                Ok(0)
            }
            Call::Send {
                handle,
                addr,
                len,
                cap,
                rights,
            } => {
                let endpoint = endpoint(&process, handle, cap::SEND)?;
                let mut message = Message {
                    data: [0; MAX_MESSAGE],
                    len,
                    cap: None,
                };
                sched::with_current_space(|space| space.read_user(addr, &mut message.data[..len]))
                    .ok_or(Error::BadAddress)??;
                if cap != 0 {
                    let passed = process.caps.lock().get(cap, cap::GRANT)?;
                    message.cap = Some(passed.derive(rights));
                }
                drop(process);
                ipc::send(&endpoint, message);
                Ok(0)
            }
            Call::Receive {
                handle,
                addr,
                max_len,
            } => {
                let endpoint = endpoint(&process, handle, cap::RECEIVE)?;
                // Check everything before taking a message, so none is lost.
                sched::with_current_space(|space| space.check_user(addr, max_len, true))
                    .ok_or(Error::BadAddress)??;
                if process.caps.lock().len() >= MAX_HANDLES {
                    return Err(Error::NoMemory);
                }
                let message = ipc::receive(&endpoint).ok_or(Error::UnknownCall)?;
                // Longer messages are cut to the buffer; the value reports
                // the full length.
                let copied = message.len.min(max_len);
                sched::with_current_space(|space| space.write_user(addr, &message.data[..copied]))
                    .ok_or(Error::BadAddress)??;
                let new_handle = match message.cap {
                    Some(cap) => process.caps.lock().insert(cap)?,
                    None => 0,
                };
                Ok(message.len as u64 | new_handle << 32)
            }
            Call::Revoke { handle } => {
                let cap = process.caps.lock().get(handle, 0)?;
                Ok(cap.revoke() as u64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::paging::LAST_USER_PAGE;

    #[test]
    fn decodes_valid_calls() {
        assert_eq!(decode(0, [7, 0, 0, 0, 0, 0]), Ok(Call::Exit { code: 7 }));
        assert_eq!(decode(1, [9; 6]), Ok(Call::Yield));
        assert_eq!(
            decode(2, [1, 0x40_0000, 256, 0, 0, 0]),
            Ok(Call::DebugWrite {
                handle: 1,
                addr: 0x40_0000,
                len: 256
            })
        );
        assert_eq!(
            decode(5, [3, 0, 0, 0, 0, 0]),
            Ok(Call::Delete { handle: 3 })
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        assert_eq!(decode(99, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(decode(u64::MAX, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(decode(7, [0; 6]), Err(Error::UnknownCall));
        assert_eq!(
            decode(3, [1, 0x40_0000, 300, 0, 0, 0]),
            Err(Error::TooLarge),
            "send checks its buffer"
        );
        assert_eq!(
            decode(4, [1, 0, 16, 0, 0, 0]),
            Err(Error::BadAddress),
            "receive checks its buffer"
        );
        assert_eq!(
            decode(3, [1, 0x40_0000, 8, 2, u64::MAX, 0]),
            Ok(Call::Send {
                handle: 1,
                addr: 0x40_0000,
                len: 8,
                cap: 2,
                rights: u32::MAX
            })
        );
        assert_eq!(
            decode(6, [4, 0, 0, 0, 0, 0]),
            Ok(Call::Revoke { handle: 4 })
        );
        let write = |addr, len| decode(2, [1, addr, len, 0, 0, 0]);
        assert_eq!(write(0x40_0000, 257), Err(Error::TooLarge));
        assert_eq!(write(0x40_0000, u64::MAX), Err(Error::TooLarge));
        assert_eq!(
            write(0xffff_ffff_8000_0000, 8),
            Err(Error::BadAddress),
            "kernel"
        );
        assert_eq!(write(0, 8), Err(Error::BadAddress), "null page");
        assert_eq!(write(LAST_USER_PAGE - 4, 8), Err(Error::BadAddress));
        assert_eq!(write(u64::MAX - 4, 16), Err(Error::BadAddress), "overflow");
    }

    #[test]
    fn random_input_never_panics_and_accepts_only_safe_buffers() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0;
        for _ in 0..200_000 {
            // Small numbers and lengths often, huge ones sometimes.
            let number = next() % 10;
            let args: [u64; 6] = core::array::from_fn(|_| next() >> (next() % 64));
            match decode(number, args) {
                Ok(
                    Call::DebugWrite { addr, len, .. }
                    | Call::Send { addr, len, .. }
                    | Call::Receive {
                        addr, max_len: len, ..
                    },
                ) => {
                    accepted += 1;
                    assert!(len <= MAX_MESSAGE);
                    assert!(user_range_ok(addr, len as u64));
                }
                Ok(_) => assert!(matches!(number, 0 | 1 | 5 | 6)),
                Err(error) => assert!(error as u64 >= 1 && error as u64 <= 7),
            }
        }
        assert!(accepted > 0, "the generator must reach valid buffers");
    }
}
