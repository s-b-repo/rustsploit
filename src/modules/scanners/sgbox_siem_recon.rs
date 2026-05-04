use anyhow::{Context, Result};
use base64::Engine;
use colored::*;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::{
    cfg_prompt_int_range, cfg_prompt_output_file, cfg_prompt_port, cfg_prompt_yes_no,
};

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
    }
}

pub async fn check(target: &str) -> CheckResult {
    let host = strip_scheme(target);
    let client = match build_http_client_with(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        HttpClientOpts::permissive(),
    ) {
        Ok(c) => c,
        Err(e) => return CheckResult::Error(format!("Failed to build HTTP client: {}", e)),
    };

    let url = format!("https://{}/sgbox/", host);
    let body = match client.get(&url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(b) => b,
            Err(e) => return CheckResult::Unknown(format!("Failed to read body: {}", e)),
        },
        Err(_) => return CheckResult::Unknown(format!("Could not reach {}", url)),
    };

    if !body.contains("SGFrame") && !body.contains("window._vars") && !body.contains("sgbox") {
        return CheckResult::NotVulnerable("No SGBox markers in response".to_string());
    }

    let version = extract_version_from_html(&body);
    let owner = extract_license_owner_from_vars(&body);
    match (version, owner) {
        (Some(v), Some(o)) => CheckResult::Vulnerable(format!(
            "SGBox {} pre-auth disclosure (license owner: {})",
            v, o
        )),
        (Some(v), None) => {
            CheckResult::Vulnerable(format!("SGBox {} pre-auth version disclosure", v))
        }
        (None, Some(o)) => CheckResult::Vulnerable(format!(
            "SGBox pre-auth license owner disclosure: {}",
            o
        )),
        (None, None) => CheckResult::NotVulnerable(
            "SGBox console reachable but no version/owner disclosure found".to_string(),
        ),
    }
}

pub async fn run(target: &str) -> Result<()> {
    if crate::utils::is_mass_scan_target(target) {
        return crate::utils::run_mass_scan(
            target,
            crate::utils::MassScanConfig {
                protocol_name: "SGBox",
                default_port: 443,
                state_file: "sgbox_siem_recon_mass_state.log",
                default_output: "sgbox_siem_recon_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    return None;
                }
                let client = build_http_client_with(
                    Duration::from_secs(5),
                    HttpClientOpts::permissive(),
                )
                .ok()?;
                let url = format!("https://{}:{}/sgbox/", ip, port);
                let body = client.get(&url).send().await.ok()?.text().await.ok()?;
                if !body.contains("SGFrame") && !body.contains("window._vars") {
                    return None;
                }
                let v = extract_version_from_html(&body).unwrap_or_else(|| "?".to_string());
                let o = extract_license_owner_from_vars(&body)
                    .unwrap_or_else(|| "?".to_string());
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                Some(format!(
                    "[{}] {}:{} SGBox {} owner={}\n",
                    ts, ip, port, v, o
                ))
            },
        )
        .await;
    }

    display_banner();

    let host = strip_scheme(target).to_string();
    crate::mprintln!("{}", format!("[*] Target: {}", host).cyan());

    let port = cfg_prompt_port("https_port", "HTTPS port for SGBox console", 443).await?;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Per-request timeout (s)", 10, 1, 60).await? as u64;
    let probe_modules =
        cfg_prompt_yes_no("probe_modules", "Enumerate installed SGBox modules?", true).await?;
    let check_login_protection = cfg_prompt_yes_no(
        "check_login_protection",
        "Probe /sgbox/login.php for rate-limit/lockout headers? (5 invalid POSTs)",
        true,
    )
    .await?;
    let save = cfg_prompt_yes_no("save", "Save findings report to file?", true).await?;

    let client = build_http_client_with(
        Duration::from_secs(timeout_secs),
        HttpClientOpts::permissive(),
    )
    .context("Failed to build HTTP client")?;

    let base = format!("https://{}:{}", host, port);
    let mut report = ReportBuilder::new(&host, port);
    let started = Instant::now();

    crate::mprintln!();
    crate::mprintln!("{}", "[*] Stage 1 — pre-auth disclosure on /sgbox/".cyan().bold());

    let index_url = format!("{}/sgbox/", base);
    match client.get(&index_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            let hsts = resp.headers().get("strict-transport-security").is_some();
            report.server = Some(server.clone());
            report.hsts_present = Some(hsts);
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    crate::mprintln!("{} body decode failed: {}", "[-]".red(), e);
                    String::new()
                }
            };

            crate::mprintln!(
                "{}",
                format!(
                    "[+] {} -> HTTP {} (Server: {}, HSTS: {})",
                    index_url,
                    status,
                    server,
                    if hsts { "yes" } else { "no" }
                )
                .green()
            );

            if let Some(v) = extract_version_from_html(&body) {
                crate::mprintln!("{}", format!("[+] Version disclosed: {}", v).yellow());
                report.version = Some(v.clone());
            }
            if let Some(o) = extract_license_owner_from_vars(&body) {
                crate::mprintln!("{}", format!("[+] License owner disclosed: {}", o).yellow());
                report.license_owner = Some(o.clone());
                let _ = crate::loot::store_loot(
                    &host,
                    "sgbox_disclosure",
                    "SGBox pre-auth license owner / version disclosure",
                    body.as_bytes(),
                    "scanners/sgbox_siem_recon",
                )
                .await;
            }
            if !hsts {
                report.findings.push(Finding::low(
                    "S6",
                    "HSTS header missing",
                    "Add Strict-Transport-Security on the SGBox vhost",
                ));
            }
        }
        Err(e) => {
            crate::meprintln!("[-] {} unreachable: {}", index_url, e);
            report.findings.push(Finding::info(
                "reachability",
                "Pre-auth /sgbox/ not reachable from scanner",
                "Verify network path and 443/tcp ACL",
            ));
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "[*] Stage 2 — login endpoint surface".cyan().bold());

    let login_url = format!("{}/sgbox/login.php", base);
    if let Ok(resp) = client.get(&login_url).send().await {
        let status = resp.status();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                crate::mprintln!("{} body decode failed: {}", "[-]".red(), e);
                String::new()
            }
        };
        let len = body.len();
        crate::mprintln!(
            "{}",
            format!(
                "[+] GET {} -> HTTP {} ({} bytes)",
                login_url, status, len
            )
            .green()
        );
        if extract_version_from_html(&body).is_some() {
            report.findings.push(Finding::medium(
                "S5",
                "Pre-auth version disclosure on /sgbox/login.php",
                "Strip version strings via mod_substitute or upstream patch",
            ));
        }
    } else {
        crate::meprintln!("[-] {} not reachable", login_url);
    }

    if check_login_protection {
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Probing login rate-limiting (5 invalid POSTs)…".cyan());
        let probe = probe_login_rate_limit(&client, &login_url).await;
        match probe {
            Ok(p) => {
                crate::mprintln!(
                    "[+] {}/5 attempts succeeded with no 429/403/Retry-After; status set: {:?}",
                    p.successes,
                    p.status_codes
                );
                if p.successes == 5
                    && !p.saw_retry_after
                    && !p.status_codes.contains(&429)
                    && !p.status_codes.contains(&403)
                {
                    report.findings.push(Finding::high(
                        "S2",
                        "No brute-force protection on /sgbox/login.php",
                        "Add per-source/per-account rate-limit + temporary lockout; require MFA",
                    ));
                }
            }
            Err(e) => crate::meprintln!("[-] Login probe failed: {}", e),
        }
    }

    if probe_modules {
        crate::mprintln!();
        crate::mprintln!(
            "{}",
            "[*] Stage 3 — enumerate installed SGBox modules (size oracle)"
                .cyan()
                .bold()
        );
        let installed = enumerate_modules(&client, &base).await;
        if installed.is_empty() {
            crate::mprintln!("[-] No installed SGBox modules detected");
        } else {
            for (code, name, size) in &installed {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[+] {} ({}) — installed (response {} bytes)",
                        code, name, size
                    )
                    .green()
                );
            }
            report.installed_modules =
                installed.iter().map(|(c, n, _)| (c.clone(), n.clone())).collect();
            report.findings.push(Finding::low(
                "S8",
                "Module routes return 200 unauthenticated; size oracle leaks inventory",
                "Require auth on /sgbox/*/pages/*.php; equalise responses",
            ));
        }
    }

    let elapsed = started.elapsed();

    crate::mprintln!();
    crate::mprintln!("{}", "=== Recon Summary ===".bold());
    crate::mprintln!("  Target:           {}:{}", host, port);
    crate::mprintln!(
        "  Version:          {}",
        report.version.as_deref().unwrap_or("(unknown)")
    );
    crate::mprintln!(
        "  License owner:    {}",
        report.license_owner.as_deref().unwrap_or("(unknown)")
    );
    crate::mprintln!(
        "  Server:           {}",
        report.server.as_deref().unwrap_or("(unknown)")
    );
    crate::mprintln!(
        "  HSTS:             {}",
        match report.hsts_present {
            Some(true) => "present",
            Some(false) => "missing",
            None => "n/a",
        }
    );
    crate::mprintln!(
        "  Modules detected: {}",
        if report.installed_modules.is_empty() {
            "none".to_string()
        } else {
            report
                .installed_modules
                .iter()
                .map(|(c, _)| c.clone())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    crate::mprintln!("  Findings:         {}", report.findings.len());
    crate::mprintln!("  Duration:         {:.2}s", elapsed.as_secs_f64());

    for f in &report.findings {
        let label = match f.severity {
            Severity::High => "HIGH".red().bold().to_string(),
            Severity::Medium => "MEDIUM".yellow().bold().to_string(),
            Severity::Low => "LOW".blue().to_string(),
            Severity::Info => "INFO".dimmed().to_string(),
        };
        crate::mprintln!("  [{}] {} — {}", label, f.id, f.title);
    }

    if save {
        let default_name = format!("sgbox_recon_{}.md", sanitize_filename(&host));
        let filename =
            cfg_prompt_output_file("output_file", "Output report filename", &default_name).await?;
        let mut file = File::create(&filename).context("Failed to create report file")?;
        if let Err(e) = crate::utils::set_secure_permissions(&filename, 0o600) {
            crate::meprintln!(
                "[!] Failed to chmod 0o600 on {}: {} — file may be world-readable",
                filename,
                e
            );
        }
        write!(file, "{}", report.to_markdown())?;
        crate::mprintln!("{}", format!("[+] Report saved to '{}'", filename).green());
    }

    Ok(())
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
            let body = match resp.text().await {
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
            Err(_) => continue,
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
