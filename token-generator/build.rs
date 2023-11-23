use std::process::Command;

fn main() {
    if let (Some(val), Some(hash)) = (
        std::env::var("CARGO_PKG_VERSION")
            .ok()
            .filter(|v| v.ends_with("-git")),
        Command::new("git")
            .args(&["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok()),
    ) {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={}-{}", val, hash);
    }
}
