use anyhow::{Result, Context};
use reqwest;

/// A sample credential check - tries a basic auth login
pub async fn run(target: &str) -> Result<()> {
    println!("[*] Checking default creds on: {}", target);

    let url = format!("http://{}/login", target);
    let client = reqwest::Client::new();

    // Hypothetical login using "admin:admin"
    let resp = client
        .post(&url)
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .context("Failed to send login request")?;

    if resp.status().is_success() {
        println!("[+] Default credentials admin:admin are valid!");
    } else {
        println!("[-] Default credentials admin:admin failed.");
    }

    Ok(())
}
