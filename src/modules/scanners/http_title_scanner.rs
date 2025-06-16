use anyhow::{Result, Context};
use regex::Regex;
use reqwest::Client;

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

pub async fn run_interactive(target: &str) -> Result<()> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    let title_re = Regex::new(r"(?i)<title>(.*?)</title>")?;
    for scheme in ["http", "https"] {
        let url = format!("{}://{}", scheme, target);
        match client.get(&url).send().await {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                if let Some(cap) = title_re.captures(&text) {
                    println!("[+] {} -> {}", url, cap.get(1).unwrap().as_str());
                } else {
                    println!("[+] {} -> <no title>", url);
                }
            }
            Err(e) => {
                println!("[-] Failed {}: {}", url, e);
            }
        }
    }
    Ok(())
}
