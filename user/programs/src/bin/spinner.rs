//! A malfunctioning agent runtime for the `recovery` test kernel (#167):
//! put in a slot's image as `bin/agents`, it spins at full speed forever
//! and never reports ready, so `init` must still fall back on its own
//! deadline.

#![no_std]
#![no_main]

pharos_user::entry!(main);

fn main(_: u64) -> u64 {
    loop {
        core::hint::spin_loop();
    }
}
