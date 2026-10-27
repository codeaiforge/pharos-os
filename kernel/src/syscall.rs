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
}

/// Decodes call `number` with `args` (`rdi`, `rsi`, `rdx`, `r10`, `r8`,
/// `r9`). Checks everything that needs no state.
pub fn decode(number: u64, args: [u64; 6]) -> Result<Call, Error> {
    match number {
        number::EXIT => Ok(Call::Exit { code: args[0] }),
        number::YIELD => Ok(Call::Yield),
        number::DEBUG_WRITE => {
            let (handle, addr, len) = (args[0], args[1], args[2]);
            if len > MAX_MESSAGE as u64 {
                return Err(Error::TooLarge);
            }
            if !user_range_ok(addr, len) {
                return Err(Error::BadAddress);
            }
            Ok(Call::DebugWrite {
                handle,
                addr,
                len: len as usize,
            })
        }
        number::DELETE => Ok(Call::Delete { handle: args[0] }),
        // SEND, RECEIVE, REVOKE: IPC (#41).
        _ => Err(Error::UnknownCall),
    }
}

/// Needed right for each capability-using call.
pub fn needed_rights(call: &Call) -> cap::Rights {
    match call {
        Call::DebugWrite { .. } => cap::WRITE,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
pub use kernel::handle;

#[cfg(target_os = "none")]
mod kernel {
    use super::*;
    use crate::arch::x86_64::syscall::SyscallFrame;
    use crate::cap::Object;
    use crate::{process, sched};

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
                if *cap.object() != Object::DebugConsole {
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
        assert_eq!(
            decode(3, [0; 6]),
            Err(Error::UnknownCall),
            "IPC comes in #41"
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
                Ok(Call::DebugWrite { addr, len, .. }) => {
                    accepted += 1;
                    assert!(len <= MAX_MESSAGE);
                    assert!(user_range_ok(addr, len as u64));
                }
                Ok(_) => assert!(matches!(number, 0 | 1 | 5)),
                Err(error) => assert!(error as u64 >= 1 && error as u64 <= 7),
            }
        }
        assert!(accepted > 0, "the generator must reach valid buffers");
    }
}
