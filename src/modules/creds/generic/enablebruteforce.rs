use anyhow::{Result, anyhow};
use std::process::Command;

/// Module entry point for raising ulimit
pub async fn run(_target: &str) -> Result<()> {
    raise_ulimit().await
}

/// Raise ulimit to 65535
async fn raise_ulimit() -> Result<()> {
    println!("[*] Attempting to raise open file limit (ulimit -n 65535)");

    // Try to set limit using bash
    let output = Command::new("bash")
        .arg("-c")
        .arg("ulimit -n 65535")
        .output()
        .map_err(|e| anyhow!("Failed to run bash: {}", e))?;

    if !output.status.success() {
        println!("[-] Warning: Could not change ulimit. (maybe run as root?)");
    } else {
        println!("[+] Successfully ran ulimit -n 65535.");
    }

    // Check current limit
    let check_output = Command::new("bash")
        .arg("-c")
        .arg("ulimit -n")
        .output()
        .map_err(|e| anyhow!("Failed to check ulimit: {}", e))?;

    if check_output.status.success() {
        let limit = String::from_utf8_lossy(&check_output.stdout);
        println!("[+] Current open file limit: {}", limit.trim());
    } else {
        println!("[-] Warning: Could not verify new ulimit.");
    }

    Ok(())
}
