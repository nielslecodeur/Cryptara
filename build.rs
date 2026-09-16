use std::env;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir =
        env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{manifest_dir}/target"));

    let output = format!("{target_dir}/debug/libseedforge");
    let status = Command::new("odin")
        .args([
            "build",
            "seedforge/src/",
            "-build-mode:dll",
            &format!("-out:{output}"),
        ])
        .status()
        .expect("Failed to execute Odin");

    if !status.success() {
        panic!("Odin build failed");
    }

    println!("cargo:rustc-link-search=native={target_dir}/debug");
    println!("cargo:rustc-link-lib=dylib=seedforge");
}
