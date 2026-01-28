use anyhow::{Result, Context};
use colored::*;
use reqwest;
use std::time::Duration;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   Sample Default Credential Checker                       ║".cyan());
    println!("{}", "║   HTTP Basic Auth Test Module                             ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// A sample credential check - tries a basic auth login
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    println!("{}", format!("[*] Target: {}", target).cyan());
    println!("{}", "[*] Checking default credentials (admin:admin)...".cyan());
    println!();

    let url = format!("http://{}/login", target);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    let resp = client
        .post(&url)
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .context("Failed to send login request")?;

    if resp.status().is_success() {
        println!("{}", "[+] Default credentials admin:admin are valid!".green().bold());
    } else {
        println!("{}", "[-] Default credentials admin:admin failed.".yellow());
    }

    Ok(())
}
