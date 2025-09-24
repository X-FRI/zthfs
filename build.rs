use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Generate build timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("cargo:rustc-env=VERGEN_BUILD_TIMESTAMP={timestamp}");

    // Get rustc version
    if let Ok(output) = Command::new("rustc").arg("--version").output() {
        let version = String::from_utf8_lossy(&output.stdout);
        println!("cargo:rustc-env=VERGEN_RUSTC_SEMVER={}", version.trim());
    }

    // Get git commit hash if available
    if let Ok(output) = Command::new("git").args(["rev-parse", "HEAD"]).output() {
        let hash = String::from_utf8_lossy(&output.stdout);
        println!("cargo:rustc-env=VERGEN_GIT_SHA={}", hash.trim());
    }
}
