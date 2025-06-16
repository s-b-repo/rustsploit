use anyhow::{Result, Context};
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::{process::Command, sync::Semaphore, time::{timeout, Duration}};

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

pub async fn run_interactive(target: &str) -> Result<()> {
    let net: IpNet = target.parse().context("Use CIDR notation like 192.168.1.0/24")?;
    let hosts: Vec<IpAddr> = net.hosts().collect();
    let semaphore = Arc::new(Semaphore::new(50));
    let mut tasks = Vec::new();

    for ip in hosts {
        let sem = semaphore.clone();
        let ip_str = ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let cmd = if ip.is_ipv4() { "ping" } else { "ping6" };
            let result = timeout(
                Duration::from_secs(3),
                Command::new(cmd)
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output(),
            )
            .await;
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
