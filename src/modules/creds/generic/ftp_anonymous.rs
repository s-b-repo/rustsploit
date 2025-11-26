use anyhow::{anyhow, Result};
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector};
use suppaftp::async_native_tls::TlsConnector as AsyncTlsConnector;
use tokio::time::{timeout, Duration};

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
    let addr = format_addr(target, 21);
    let domain = target
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(target);

    println!("[*] Connecting to FTP service on {}...", addr);

    // 1️⃣ Try plain FTP first
    match timeout(Duration::from_secs(5), AsyncFtpStream::connect(&addr)).await {
        Ok(Ok(mut ftp)) => {
            let result = ftp.login("anonymous", "anonymous").await;
            if let Ok(_) = result {
                println!("[+] Anonymous login successful (FTP)");
                let _ = ftp.quit().await;
                return Ok(());
            } else if let Err(e) = result {
                if e.to_string().contains("530") {
                    println!("[-] Anonymous login rejected (FTP)");
                    return Ok(());
                } else if e.to_string().contains("550 SSL") {
                    println!("[*] FTP server requires TLS — upgrading to FTPS...");
                } else {
                    return Err(anyhow!("FTP error: {}", e));
                }
            }
        }
        Ok(Err(e)) => println!("[!] FTP connection error: {}", e),
        Err(_) => println!("[-] FTP connection timed out"),
    }

    // 2️⃣ Fallback to FTPS
    let mut ftps = AsyncNativeTlsFtpStream::connect(&addr)
        .await
        .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

    // Build native_tls connector builder and pass it directly to suppaftp
    // The builder pattern methods return &mut Self, so we need to move the builder
    // by chaining the calls and moving the result
    let native_builder = {
        let mut builder = native_tls::TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        builder
    };
    // Move the builder (not a reference) - From<TlsConnectorBuilder> is implemented
    let async_tls_connector = AsyncTlsConnector::from(native_builder);
    let connector = AsyncNativeTlsConnector::from(async_tls_connector);

    ftps = ftps
        .into_secure(connector, domain)
        .await
        .map_err(|e| anyhow!("FTPS TLS upgrade failed: {}", e))?;

    match ftps.login("anonymous", "anonymous").await {
        Ok(_) => {
            println!("[+] Anonymous login successful (FTPS)");
            let _ = ftps.quit().await;
        }
        Err(e) if e.to_string().contains("530") => {
            println!("[-] Anonymous login rejected (FTPS)");
        }
        Err(e) => return Err(anyhow!("FTPS login error: {}", e)),
    }

    Ok(())
}
