use anyhow::{anyhow, Result};
use colored::*;
use suppaftp::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector};
use suppaftp::async_native_tls::TlsConnector;
use tokio::time::{timeout, Duration};

const DEFAULT_TIMEOUT_SECS: u64 = 5;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   FTP Anonymous Login Checker                             ║".cyan());
    println!("{}", "║   Supports FTP and FTPS (TLS) with IPv4/IPv6              ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Format IPv4 or IPv6 addresses with port
fn format_addr(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
        }
    }
}

/// Anonymous FTP/FTPS login test with IPv6 support
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    let addr = format_addr(target, 21);
    let domain = target
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(target);

    println!("{}", format!("[*] Target: {}", target).cyan());
    println!("{}", format!("[*] Connecting to FTP service on {}...", addr).cyan());
    println!();

    // 1️⃣ Try plain FTP first
    match timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncFtpStream::connect(&addr)).await {
        Ok(Ok(mut ftp)) => {
            let result = ftp.login("anonymous", "anonymous").await;
            if result.is_ok() {
                println!("{}", "[+] Anonymous login successful (FTP)".green().bold());
                let _ = ftp.quit().await;
                return Ok(());
            } else if let Err(e) = result {
                if e.to_string().contains("530") {
                    println!("{}", "[-] Anonymous login rejected (FTP)".yellow());
                    return Ok(());
                } else if e.to_string().contains("550 SSL") {
                    println!("{}", "[*] FTP server requires TLS — upgrading to FTPS...".cyan());
                } else {
                    return Err(anyhow!("FTP error: {}", e));
                }
            }
        }
        Ok(Err(e)) => println!("{}", format!("[!] FTP connection error: {}", e).red()),
        Err(_) => println!("{}", "[-] FTP connection timed out".yellow()),
    }

    // 2️⃣ Fallback to FTPS
    println!("{}", "[*] Attempting FTPS connection...".cyan());
    
    let mut ftps = AsyncNativeTlsFtpStream::connect(&addr)
        .await
        .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    ftps = ftps
        .into_secure(connector, domain)
        .await
        .map_err(|e| anyhow!("FTPS TLS upgrade failed: {}", e))?;

    match ftps.login("anonymous", "anonymous").await {
        Ok(_) => {
            println!("{}", "[+] Anonymous login successful (FTPS)".green().bold());
            let _ = ftps.quit().await;
        }
        Err(e) if e.to_string().contains("530") => {
            println!("{}", "[-] Anonymous login rejected (FTPS)".yellow());
        }
        Err(e) => return Err(anyhow!("FTPS login error: {}", e)),
    }

    Ok(())
}
