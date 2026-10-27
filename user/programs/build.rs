// Link user programs at USER_BASE with the user linker script when building
// for the bare-metal target (drivers.md).
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo");
    if std::env::var("TARGET").as_deref() == Ok("x86_64-unknown-none") {
        println!("cargo:rustc-link-arg-bins=-T{dir}/user.ld");
    }
    println!("cargo:rerun-if-changed=user.ld");
}
