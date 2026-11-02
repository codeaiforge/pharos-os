//! Code shared by the Pharos OS user programs (drivers.md).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod fp;
pub mod models;
pub mod net;
pub mod tasks;
pub mod virtio;
pub mod virtio_console;
pub mod virtio_net;
