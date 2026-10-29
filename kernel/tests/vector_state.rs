//! Test kernel: vector state of user programs on QEMU's default CPU, which has no AVX: FXSAVE (issue #74, D-016).
//! The checks are in `common/vector_state.rs`. Runs under UEFI (D-009).

#![no_std]
#![no_main]

extern crate alloc;

#[path = "common/vector_state.rs"]
mod body;

use pharos_kernel::arch::x86_64::fpu::Mode;
use pharos_kernel::testing::TestRun;

pharos_kernel::test_kernel!(run);

fn run(t: &mut TestRun) {
    body::run(t, Mode::Fxsave);
}
