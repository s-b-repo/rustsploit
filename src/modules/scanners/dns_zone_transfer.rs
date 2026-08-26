use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "DNS Zone Transfer (AXFR)".into(),
        description: "Attempts AXFR zone transfer against discovered nameservers to \
            enumerate all subdomains in one shot."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://en.wikipedia.org/wiki/DNS_zone_transfer".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: Some(53),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    crate::mprintln!(
        "{}",
        format!("[*] DNS Zone Transfer attempt: {}", target)
            .cyan()
            .bold()
    );
    let mut outcome = ModuleOutcome::ok();
    let ns_servers: &[(&str, u16)] = &[("8.8.8.8", 53), ("1.1.1.1", 53), ("9.9.9.9", 53)];
    let domain = target.split(':').next().unwrap_or(target);
    for (ns, port) in ns_servers {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(domain).await;
        let addr = format!("{}:{}", ns, port);
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("UDP bind failed: {}", e);
                continue;
            }
        };
        let query = build_axfr_query(domain);
        if let Err(e) = socket.send_to(&query, &addr).await {
            tracing::debug!("AXFR send to {} failed: {}", ns, e);
            continue;
        }
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 12 => {
                crate::mprintln!(
                    "{}",
                    format!("[+] AXFR response from {} ({} bytes)", ns, n).green()
                );
                if n > 200 {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[+] Zone transfer SUCCESS via {} — {} bytes received!",
                            ns, n
                        )
                        .green()
                        .bold()
                    );
                    outcome.findings.push(Finding {
                        target: domain.to_string(),
                        kind: FindingKind::Vulnerable,
                        message: format!("AXFR zone transfer succeeded via {} — {} bytes", ns, n),
                        data: Some(
                            serde_json::json!({"domain": domain, "nameserver": ns, "bytes": n}),
                        ),
                    });
                }
            }
            _ => {
                crate::mprintln!("{}", format!("[-] AXFR refused by {}", ns).dimmed());
            }
        }
    }
    Ok(outcome)
}

fn build_axfr_query(domain: &str) -> Vec<u8> {
    use rand::RngExt;
    let mut buf = vec![0u8; 512];
    let txid: u16 = rand::rng().random();
    buf[0] = (txid >> 8) as u8;
    buf[1] = txid as u8;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[5] = 0x01;
    buf[11] = 0x01;
    let mut pos: usize = 12;
    for label in domain.split('.') {
        buf[pos] = label.len() as u8;
        pos += 1;
        buf[pos..pos + label.len()].copy_from_slice(label.as_bytes());
        pos += label.len();
    }
    buf[pos] = 0x00;
    pos += 1;
    buf[pos] = 0x00;
    buf[pos + 1] = 0xFC;
    pos += 2;
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;
    buf.truncate(pos);
    buf
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "dns_zone_transfer",
    native
);
