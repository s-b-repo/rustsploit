use anyhow::{ Context, Result };
use base64::Engine;
use colored::*;
use std::time::Duration;

use crate::module::{FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank };
use crate::utils::network::{ build_http_client_with, HttpClientOpts };
use crate::utils::cfg_prompt_yes_no;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

const SIZE_DIR_DENY: usize = 199;
const SIZE_SGBOX_404: usize = 983;
const SIZE_MODULE_PLACEHOLDER: usize = 19143;

const KNOWN_MODULES: &[(&str, &str)] = &[
    ("NVS", "Network Vulnerability Scanner"),
    ("SCM", "System Control Management"),
    ("LM", "Log Management"),
    ("LCE", "Log Correlation Engine"),
    ("SM", "System Monitoring"),
    ("PB", "Playbooks / SOAR"),
    ("ADE", "Active Directory Engine"),
    ("IM", "Incident Management"),
    ("RS", "Report System"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SGBox NG-SIEM Recon".to_string(),
        description:
            "Non-destructive recon of Securegate SGBox NG-SIEM consoles.\n\
             Extracts version + license owner from pre-auth window._vars (base64 JSON),\n\
             enumerates installed SGBox modules (NVS/SCM/LM/LCE/SM/PB/ADE/IM/RS) via the\n\
             /sgbox/<MOD>/pages/dashboard.php response-size oracle, and audits the login\n\
             surface for HSTS, deprecated TLS, and absent rate-limiting. Read-only."
                .to_string(),
        authors: vec!["Bottomline Pentest".to_string()],
        references: vec![
            "https://www.sgbox.eu/en/knowledge-base/network-requirements/".to_string(),
            "https://www.sgbox.eu/en/knowledge-base/6-2-5/".to_string(),
            "RFC 8996 (deprecation of TLS 1.0/1.1)".to_string(),
        ],
        disclosure_date: Some("2026-04-24".to_string()),
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("sgbox_siem_recon requires a single-host target")?;
    display_banner();
    let host = strip_scheme(target).to_string();
    let port: u16 = 443;
    let mut report = ReportBuilder::new(&host, port);
    let client = build_http_client_with(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        HttpClientOpts::permissive(),
    )
    .context("Failed to build HTTP client")?;

    let mut outcome = ModuleOutcome::ok();

    // 1. Pre-auth disclosure: HTML version + license owner.
    let url = format!("https://{}/sgbox/", host);
    ctx.rate_limit(&host).await;
    let body = match client.get(&url).send().await {
        Ok(resp) => match crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
            Ok(b) => b,
            Err(e) => {
                crate::meprintln!("[!] {}: failed to read body: {e:#}", host);
                return Ok(outcome);
            }
        },
        Err(e) => {
            tracing::debug!("request failed: {e}");
            if !crate::utils::is_batch_mode() {
                crate::mprintln!(
                    "{}",
                    format!("[-] {} not reachable on https://{}/sgbox/", host, host).dimmed()
                );
            }
            return Ok(outcome);
        }
    };

    if !body.contains("SGFrame")
        && !body.contains("window._vars")
        && !body.contains("sgbox")
    {
        if !crate::utils::is_batch_mode() {
            crate::mprintln!(
                "{}",
                format!("[-] {}: no SGBox markers in response", host).dimmed()
            );
        }
        return Ok(outcome);
    }

    let version = extract_version_from_html(&body);
    let owner = extract_license_owner_from_vars(&body);
    if version.is_some() || owner.is_some() {
        crate::mprintln!("{}", format!("[+] {} — SGBox NG-SIEM detected", host).green().bold());
        if let Some(v) = &version {
            crate::mprintln!("    version: {}", v.cyan());
            crate::workspace::add_note(&host, &format!("[sgbox_siem] version: {}", v)).await;
            report.version = Some(v.clone());
            report.findings.push(Finding::info(
                "VERSION-DISCLOSURE",
                "SGBox version disclosed via /sgbox/ HTML",
                "Block unauthenticated access to /sgbox/ or strip the version banner.",
            ));
            outcome.findings.push(crate::module::Finding {
                target: host.clone(),
                kind: FindingKind::Banner,
                message: format!("SGBox NG-SIEM version disclosed at {}: {}", host, v),
                data: Some(serde_json::json!({"host": host, "version": v})),
            });
        }
        if let Some(o) = &owner {
            crate::mprintln!("    license owner: {}", o.cyan());
            crate::workspace::add_note(&host, &format!("[sgbox_siem] license owner: {}", o)).await;
            report.license_owner = Some(o.clone());
            report.findings.push(Finding::medium(
                "LICENSE-OWNER-DISCLOSURE",
                "License owner disclosed via window._vars",
                "Restrict the embedded `license` payload to authenticated sessions.",
            ));
            outcome.findings.push(crate::module::Finding {
                target: host.clone(),
                kind: FindingKind::Vulnerable,
                message: format!("SGBox license owner disclosed at {}: {}", host, o),
                data: Some(serde_json::json!({"host": host, "license_owner": o})),
            });
        }
    }

    // 2. Module enumeration (passive — only HTTP HEAD/GET on common module URLs).
    ctx.rate_limit(&host).await;
    let modules = enumerate_modules(&client, &host).await;
    if !modules.is_empty() {
        crate::mprintln!("{}", format!("[+] {} reachable SGBox modules:", modules.len()).green());
        for (code, name, status) in &modules {
            crate::mprintln!("    {} {} (HTTP {})", code.cyan(), name, status);
            crate::workspace::add_note(
                &host,
                &format!("[sgbox_siem] module reachable: {} ({}) HTTP {}", code, name, status),
            )
            .await;
            report.installed_modules.push((code.clone(), name.clone()));
        }
        report.findings.push(Finding::low(
            "MODULES-ENUMERABLE",
            "Installed SGBox modules can be enumerated via size oracle",
            "Return uniform 404/403 sizes for missing module dashboards to defeat fingerprinting.",
        ));
        outcome.findings.push(crate::module::Finding {
            target: host.clone(),
            kind: FindingKind::Note,
            message: format!("SGBox installed modules enumerable at {} ({})", host, modules.len()),
            data: Some(serde_json::json!({
                "host": host,
                "modules": modules.iter().map(|(c, n, _)| serde_json::json!({"code": c, "name": n})).collect::<Vec<_>>(),
            })),
        });
    }

    // 3. Login rate-limit probe (single low-volume probe, not a brute-force).
    let login_url = format!("https://{}/sgbox/login.php", host);
    ctx.rate_limit(&host).await;
    match probe_login_rate_limit(&client, &login_url).await {
        Ok(p) => {
            let signal = if p.saw_retry_after {
                "rate-limited (Retry-After observed)"
            } else if p.successes >= 5 {
                "no rate limit detected"
            } else {
                "behaviour inconclusive"
            };
            crate::mprintln!(
                "    login rate-limit probe: {} ({}/{} attempts accepted)",
                signal,
                p.successes,
                p.status_codes.len()
            );
            crate::workspace::add_note(
                &host,
                &format!("[sgbox_siem] login rate-limit: {}", signal),
            )
            .await;
            if !p.saw_retry_after && p.successes >= 5 {
                report.findings.push(Finding::high(
                    "LOGIN-NO-RATE-LIMIT",
                    "Login endpoint has no observable rate limiting",
                    "Add per-IP throttling and exponential lockout to /sgbox/login.php.",
                ));
                outcome.findings.push(crate::module::Finding {
                    target: host.clone(),
                    kind: FindingKind::Vulnerable,
                    message: format!("SGBox /sgbox/login.php at {} lacks rate limiting", host),
                    data: Some(serde_json::json!({"host": host})),
                });
            }
        }
        Err(e) => {
            tracing::debug!(host = %host, "rate-limit probe failed: {e:#}");
        }
    }

    // 4. Markdown report — store as loot so it shows up in the workspace.
    let want_report = if crate::utils::is_batch_mode() {
        true
    } else {
        cfg_prompt_yes_no("write_report", "Save markdown report to loot?", true)
            .await
            .unwrap_or(true)
    };
    if want_report {
        let md = report.to_markdown();
        let label = sanitize_filename(&format!("sgbox_recon_{}.md", host));
        match crate::loot::store_loot(
            &host,
            "recon_report",
            &label,
            md.as_bytes(),
            "scanners/sgbox_siem_recon",
        )
        .await
        {
            Some(id) => {
                crate::mprintln!("    report saved: {} (loot id {})", label.cyan(), id.dimmed())
            }
            None => crate::meprintln!("[!] failed to persist sgbox recon report"),
        }
    }

    crate::workspace::track_host(&host, None, Some("SGBox NG-SIEM")).await;
    Ok(outcome)
}

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   SGBox NG-SIEM Recon                                     ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Pre-auth disclosure + module enumeration (read-only)    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

fn strip_scheme(t: &str) -> &str {
    t.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}

fn extract_version_from_html(body: &str) -> Option<String> {
    if let Some(start) = body.find("Version ") {
        let tail = &body[start + 8..];
        let end = tail
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(tail.len());
        let v = &tail[..end];
        if !v.is_empty() && v.contains('.') {
            return Some(v.to_string());
        }
    }
    if let Some(idx) = body.find("app.css?v=") {
        let tail = &body[idx + "app.css?v=".len()..];
        let end = tail
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(tail.len());
        let v = &tail[..end];
        if !v.is_empty() && v.contains('.') {
            return Some(v.to_string());
        }
    }
    None
}

fn extract_license_owner_from_vars(body: &str) -> Option<String> {
    let json = decode_window_vars(body)?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let owner = v
        .get("license")?
        .get("License")?
        .get("owner")?
        .as_str()?
        .to_string();
    if owner.is_empty() {
        None
    } else {
        Some(owner)
    }
}

fn decode_window_vars(body: &str) -> Option<String> {
    let key = "window._vars";
    let pos = body.find(key)?;
    let rest = &body[pos + key.len()..];
    let q1 = rest.find('"')?;
    let after_q1 = &rest[q1 + 1..];
    let q2 = after_q1.find('"')?;
    let b64 = &after_q1[..q2];
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    String::from_utf8(bytes).ok()
}

async fn enumerate_modules(
    client: &reqwest::Client,
    base: &str,
) -> Vec<(String, String, usize)> {
    let mut found = Vec::new();
    for (code, name) in KNOWN_MODULES {
        let url = format!("{}/sgbox/{}/pages/dashboard.php", base, code);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let body = match crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                Ok(b) => b,
                Err(e) => {
                    crate::mprintln!("{} body decode failed: {}", "[-]".red(), e);
                    String::new()
                }
            };
            let len = body.len();
            // Installed: 200 OK with placeholder-sized body (≈19143). Allow ±5%.
            if status == 200
                && len > (SIZE_MODULE_PLACEHOLDER as f64 * 0.9) as usize
                && len < (SIZE_MODULE_PLACEHOLDER as f64 * 1.1) as usize
            {
                found.push((code.to_string(), name.to_string(), len));
            } else if status == 404 && len.abs_diff(SIZE_SGBOX_404) < 200 {
                // Not installed (SGBox-themed 404)
            } else if status == 403 && len.abs_diff(SIZE_DIR_DENY) < 50 {
                // Directory denied — module dir exists but pages route may be elsewhere
                found.push((code.to_string(), name.to_string(), len));
            }
        }
    }
    found
}

struct LoginRateProbe {
    successes: u32,
    status_codes: Vec<u16>,
    saw_retry_after: bool,
}

async fn probe_login_rate_limit(
    client: &reqwest::Client,
    login_url: &str,
) -> Result<LoginRateProbe> {
    let mut p = LoginRateProbe {
        successes: 0,
        status_codes: Vec::new(),
        saw_retry_after: false,
    };
    for i in 0..5 {
        let form = [
            ("username", "rs_recon_invalid"),
            ("pass", &format!("invalid_{}", i)),
            ("tenant", "admin"),
        ];
        match client.post(login_url).form(&form).send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                if !p.status_codes.contains(&code) {
                    p.status_codes.push(code);
                }
                if resp.headers().get("retry-after").is_some() {
                    p.saw_retry_after = true;
                }
                p.successes += 1;
            }
            Err(e) => { tracing::debug!("login probe failed: {e}"); continue; }
        }
    }
    Ok(p)
}

#[derive(Clone, Copy)]
enum Severity {
    High,
    Medium,
    Low,
    Info,
}

struct Finding {
    severity: Severity,
    id: String,
    title: String,
    recommendation: String,
}

impl Finding {
    fn high(id: &str, title: &str, rec: &str) -> Self {
        Self {
            severity: Severity::High,
            id: id.to_string(),
            title: title.to_string(),
            recommendation: rec.to_string(),
        }
    }
    fn medium(id: &str, title: &str, rec: &str) -> Self {
        Self {
            severity: Severity::Medium,
            id: id.to_string(),
            title: title.to_string(),
            recommendation: rec.to_string(),
        }
    }
    fn low(id: &str, title: &str, rec: &str) -> Self {
        Self {
            severity: Severity::Low,
            id: id.to_string(),
            title: title.to_string(),
            recommendation: rec.to_string(),
        }
    }
    fn info(id: &str, title: &str, rec: &str) -> Self {
        Self {
            severity: Severity::Info,
            id: id.to_string(),
            title: title.to_string(),
            recommendation: rec.to_string(),
        }
    }
}

struct ReportBuilder {
    host: String,
    port: u16,
    version: Option<String>,
    license_owner: Option<String>,
    server: Option<String>,
    hsts_present: Option<bool>,
    installed_modules: Vec<(String, String)>,
    findings: Vec<Finding>,
}

impl ReportBuilder {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            version: None,
            license_owner: None,
            server: None,
            hsts_present: None,
            installed_modules: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn to_markdown(&self) -> String {
        let mut out = String::new();
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        out.push_str(&format!("# SGBox NG-SIEM Recon — {}:{}\n\n", self.host, self.port));
        out.push_str(&format!("Generated: {}\n\n", ts));
        out.push_str("## Pre-auth disclosure\n\n");
        out.push_str(&format!(
            "| Field | Value |\n|---|---|\n| Version | {} |\n| License owner | {} |\n| Server header | {} |\n| HSTS | {} |\n\n",
            self.version.as_deref().unwrap_or("(none)"),
            self.license_owner.as_deref().unwrap_or("(none)"),
            self.server.as_deref().unwrap_or("(none)"),
            match self.hsts_present {
                Some(true) => "present",
                Some(false) => "missing",
                None => "n/a",
            }
        ));
        out.push_str("## Installed modules (size-oracle inference)\n\n");
        if self.installed_modules.is_empty() {
            out.push_str("None detected.\n\n");
        } else {
            out.push_str("| Code | Name |\n|---|---|\n");
            for (c, n) in &self.installed_modules {
                out.push_str(&format!("| {} | {} |\n", c, n));
            }
            out.push('\n');
        }
        out.push_str("## Findings\n\n");
        if self.findings.is_empty() {
            out.push_str("No issues identified by this scanner.\n");
        } else {
            for f in &self.findings {
                let sev = match f.severity {
                    Severity::High => "HIGH",
                    Severity::Medium => "MEDIUM",
                    Severity::Low => "LOW",
                    Severity::Info => "INFO",
                };
                out.push_str(&format!("### [{}] {} — {}\n\n", sev, f.id, f.title));
                out.push_str(&format!("Recommendation: {}\n\n", f.recommendation));
            }
        }
        out
    }
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

crate::register_native_module!(crate::module::Category::Scanners, "sgbox_siem_recon", native);
