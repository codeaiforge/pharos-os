//! Architecture-specific hardware layer (D-004 constraint 1).
//!
//! Other kernel modules use the safe interfaces exported here and never touch
//! hardware directly.

pub mod x86_64;
