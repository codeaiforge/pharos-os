// Link the kernel binary with the project linker script when building for the
// bare-metal target. Host builds (library unit tests) are unaffected.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo");
    if std::env::var("TARGET").as_deref() == Ok("x86_64-unknown-none") {
        println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld");
    }
    println!("cargo:rerun-if-changed=linker.ld");
}
