use std::time::SystemTime;

fn main() {
    if let (Some(val), Ok(ts)) = (
        std::env::var("CARGO_PKG_VERSION")
            .ok()
            .filter(|v| v.ends_with("-git")),
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH),
    ) {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={}-{}", val, ts.as_secs());
    }
}
