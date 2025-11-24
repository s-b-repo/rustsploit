use anyhow::{Result, Context};
use reqwest;

/// A simple scanner that tries an HTTP GET and prints the response code
pub async fn run(target: &str) -> Result<()> {
    println!("[*] Running sample_scanner on: {}", target);

    let url = format!("http://{}", target);
    let resp = reqwest::get(&url)
        .await
        .context("Failed to send request")?;

    println!("[*] Status code: {}", resp.status());
    Ok(())
}
