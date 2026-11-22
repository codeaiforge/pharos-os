//! Code shared by the Pharos OS user programs (drivers.md).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod budgets;
pub mod fp;
pub mod grants;
pub mod groups;
pub mod knowledge;
pub mod mailbox;
pub mod manage;
pub mod models;
pub mod net;
pub mod output;
pub mod sequence;
pub mod supervise;
pub mod system;
pub mod tasks;
#[cfg(test)]
mod tcp_fuzz;
pub mod tools;
pub mod virtio;
pub mod virtio_console;
pub mod virtio_net;
pub mod virtio_rng;
