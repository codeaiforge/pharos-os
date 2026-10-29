// The linker script and flags for user programs come from `cargo xtask`,
// which builds them for x86_64-unknown-linux-gnu (user-environment.md). This
// only tells Cargo to rebuild when the script changes.
fn main() {
    println!("cargo:rerun-if-changed=user.ld");
}
