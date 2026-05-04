//! cPanel / WHM / Webmail exposure detector.
//!
//! Probes the standard cPanel control-plane ports (2082/2083 cPanel,
//! 2086/2087 WHM, 2095/2096 Webmail) and the auxiliary admin ports
//! 8888/8889 for reachable HTTP(S) responses. A reachable management
//! interface — especially over plain HTTP or without IP allow-listing —
//! is a recurring high-impact finding (OWASP A05:2021).

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range, cfg_prompt_yes_no};

const HTTP_TIMEOUT_SECS: u64 = 8;

const PANEL_PORTS: &[(u16, &str, bool)] = &[
    (2082, "cPanel (HTTP)", false),
    (2083, "cPanel (HTTPS)", true),
    (2086, "WHM (HTTP)", false),
    (2087, "WHM (HTTPS)", true),
    (2095, "Webmail (HTTP)", false),
    (2096, "Webmail (HTTPS)", true),
    (8888, "Admin/Backend (HTTP)", false),
    (8889, "Admin/Backend (HTTPS)", true),
];

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   cPanel / WHM / Webmail Exposure Detector                   ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Flags reachable hosting-control-plane interfaces           ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "cPanel / WHM / Webmail Exposure Detector".to_string(),
        description: "Probes the cPanel control-plane ports (2082/2083, 2086/2087, 2095/2096) \
                      plus 8888/8889 for reachable HTTP(S) endpoints. Reports each panel that \
                      responds, its Server header, and any redirect chain — useful for finding \
                      management interfaces exposed to the internet without IP allow-lists."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
            "https://docs.cpanel.net/whm/cpanel-webmail-and-whm-ports/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

pub async fn check(target: &str) -> CheckResult {
    let host = sanitize_host(target);
    let client = match build_http_client(Duration::from_secs(HTTP_TIMEOUT_SECS)) {
        Ok(c) => c,
        Err(e) => return CheckResult::Error(format!("HTTP client build failed: {}", e)),
    };
    let mut hits = Vec::new();
    for &(port, label, https) in PANEL_PORTS {
        if probe_panel(&client, &host, port, https).await {
            hits.push(format!("{} on :{}", label, port));
            if hits.len() >= 2 {
                break;
            }
        }
    }
    if hits.is_empty() {
        CheckResult::NotVulnerable("No cPanel/WHM/webmail panels reachable on standard ports".into())
    } else {
        CheckResult::Vulnerable(format!("Exposed panels: {}", hits.join(", ")))
    }
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    let host = sanitize_host(target);
    crate::mprintln!("{}", format!("[*] Target host: {}", host).cyan());

    let timeout_secs = cfg_prompt_int_range(
        "timeout",
        "Per-port HTTP timeout (seconds)",
        HTTP_TIMEOUT_SECS as i64,
        2,
        60,
    )
    .await? as u64;
    let include_aux = cfg_prompt_yes_no(
        "include_aux_ports",
        "Probe 8888/8889 in addition to 2082-2096?",
        true,
    )
    .await?;

    let client = build_http_client(Duration::from_secs(timeout_secs))
        .context("Failed to build HTTP client")?;

    let mut exposed = 0usize;
    crate::mprintln!();
    for &(port, label, https) in PANEL_PORTS {
        if !include_aux && (port == 8888 || port == 8889) {
            continue;
        }
        let scheme = if https { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, host, port);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let server = resp
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("?")
                    .to_string();
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(e) => {
                        crate::mprintln!("{} body decode failed: {}", "[-]".red(), e);
                        String::new()
                    }
                };
                let title = extract_title(&body).unwrap_or_else(|| "<no title>".into());
                let looks_panel = title_indicates_panel(&title)
                    || server.to_ascii_lowercase().contains("cpsrvd")
                    || location.contains(":2087")
                    || location.contains(":2083")
                    || location.contains(":2096");
                if status.is_success() || status.is_redirection() || looks_panel {
                    exposed += 1;
                    let line = format!(
                        "Exposed: {} ({}): status={} server='{}' title='{}'{}",
                        url,
                        label,
                        status,
                        server,
                        title,
                        if location.is_empty() {
                            String::new()
                        } else {
                            format!(" -> {}", location)
                        }
                    );
                    crate::mprintln!("{}", format!("[+] {}", line).green().bold());
                    crate::events::emit(crate::events::ModuleEvent::ServiceDetected {
                        host: host.clone(),
                        port,
                        service: format!("panel:{}", label),
                        version: Some(server),
                    });
                } else {
                    crate::mprintln!(
                        "{}",
                        format!("[-] {} -> {} (server='{}')", url, status, server).dimmed()
                    );
                }
            }
            Err(e) => {
                crate::mprintln!(
                    "{}",
                    format!("[-] {} unreachable: {}", url, redact_err(&e.to_string())).dimmed()
                );
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "═══ Summary ═══".bold());
    crate::mprintln!("  Host:           {}", host);
    crate::mprintln!("  Exposed panels: {}", exposed);

    Ok(())
}

async fn probe_panel(client: &reqwest::Client, host: &str, port: u16, https: bool) -> bool {
    let scheme = if https { "https" } else { "http" };
    let url = format!("{}://{}:{}/", scheme, host, port);
    matches!(
        client.get(&url).send().await,
        Ok(r) if r.status().is_success() || r.status().is_redirection()
    )
}

fn title_indicates_panel(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    t.contains("cpanel") || t.contains("whm") || t.contains("webmail")
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after_open = body[start..].find('>')? + start + 1;
    let end = body[after_open..]
        .to_ascii_lowercase()
        .find("</title>")?
        + after_open;
    Some(body[after_open..end].trim().to_string())
}

fn redact_err(s: &str) -> String {
    s.replace('\n', " ").chars().take(200).collect()
}

fn sanitize_host(target: &str) -> String {
    let t = target.trim();
    let t = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split(':').next().unwrap_or(t);
    t.to_string()
}
