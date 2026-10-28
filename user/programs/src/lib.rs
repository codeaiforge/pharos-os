//! Code shared by the Pharos OS user programs (drivers.md).

#![cfg_attr(not(test), no_std)]

pub mod net;
pub mod virtio;
pub mod virtio_net;
