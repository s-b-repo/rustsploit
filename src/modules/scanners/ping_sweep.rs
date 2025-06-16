use anyhow::{Result, Context};
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::{
    process::Command,
    sync::Semaphore,
    time::{timeout, Duration},
};
use std::io::{self, Write};

/// Main entry point for the RouterSploit auto-dispatch system
pub async fn run(target: &str) -> Result<()> {
    let cidr = prompt_for_cidr(target).await?;
    execute_ping_sweep(&cidr).await
}

/// Prompt for a valid CIDR until received
async fn prompt_for_cidr(initial: &str) -> Result<String> {
    // // Start with any provided value
    let mut input = initial.trim().to_string();
    loop {
        // // If empty, ask user
        if input.is_empty() {
            print!("Enter target (CIDR, e.g., 192.168.1.0/24): ");
            io::stdout().flush().ok();
            input.clear();
            io::stdin().read_line(&mut input)?;
            input = input.trim().to_string();
        }
        // // Try to parse as CIDR
        match input.parse::<IpNet>() {
            Ok(_) => return Ok(input),
            Err(_) => {
                eprintln!("[!] Module failed: Use CIDR notation like 192.168.1.0/24\n\nCaused by:\n    invalid IP address syntax");
                input.clear();
                continue;
            }
        }
    }
}

/// Executes a ping sweep across the provided CIDR subnet
pub async fn execute_ping_sweep(target: &str) -> Result<()> {
    // // Parse the target as CIDR (e.g., 192.168.1.0/24)
    let net: IpNet = target.parse().context("Use CIDR notation like 192.168.1.0/24")?;
    // // Collect all host IPs in the subnet
    let hosts: Vec<IpAddr> = net.hosts().collect();
    // // Use a semaphore to limit concurrency to 50
    let semaphore = Arc::new(Semaphore::new(50));
    let mut tasks = Vec::new();

    for ip in hosts {
        let sem = semaphore.clone();
        let ip_str = ip.to_string();
        tasks.push(tokio::spawn(async move {
            // // Limit concurrent pings using the semaphore
            let _permit = sem.acquire_owned().await.unwrap();
            // // Use "ping" for IPv4, "ping6" for IPv6
            let cmd = if ip.is_ipv4() { "ping" } else { "ping6" };
            let result = timeout(
                Duration::from_secs(3),
                Command::new(cmd)
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output(),
            )
            .await;
            // // If ping succeeded, print that the host is up
            if let Ok(Ok(out)) = result {
                if out.status.success() {
                    println!("[+] Host {} is up", ip_str);
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}
