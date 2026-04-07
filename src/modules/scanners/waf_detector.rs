//! WAF/CDN Detection Scanner
//!
//! Sends HTTP requests and analyzes responses to identify Web Application
//! Firewalls and CDN providers. Also sends malicious payloads to trigger
//! WAF block pages for more accurate detection.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context};
use colored::*;
use std::time::Duration;
use std::collections::HashMap;
use crate::utils::{cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "WAF/CDN Detector".into(),
        description: "Detects Web Application Firewalls and CDN providers by analyzing HTTP \
            response headers, cookies, and body content. Sends benign and malicious payloads \
            to trigger WAF signatures for higher-confidence detection. Identifies Cloudflare, \
            AWS WAF, Akamai, Imperva, F5 BIG-IP, ModSecurity, Sucuri, Barracuda, Fortinet, \
            and Citrix NetScaler."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://github.com/EnableSecurity/wafw00f".into(),
            "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/waf-bypass.html".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   WAF / CDN Detection Scanner                                ║".cyan());
    crate::mprintln!("{}", "║   Fingerprint web application firewalls and CDN providers    ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

#[derive(Debug, Clone)]
struct WafSignature {
    name: &'static str,
    header_checks: Vec<(&'static str, &'static str)>,
    cookie_checks: Vec<&'static str>,
    body_checks: Vec<&'static str>,
}

fn get_waf_signatures() -> Vec<WafSignature> {
    vec![
        WafSignature {
            name: "Cloudflare",
            header_checks: vec![
                ("cf-ray", ""),
                ("server", "cloudflare"),
                ("cf-cache-status", ""),
            ],
            cookie_checks: vec!["__cfduid", "__cf_bm"],
            body_checks: vec!["cloudflare", "cf-error-details"],
        },
        WafSignature {
            name: "AWS WAF / CloudFront",
            header_checks: vec![
                ("x-amz-cf-id", ""),
                ("x-amz-cf-pop", ""),
                ("server", "CloudFront"),
                ("x-amzn-requestid", ""),
            ],
            cookie_checks: vec!["awsalb", "awsalbcors", "AWSALB"],
            body_checks: vec!["aws", "cloudfront"],
        },
        WafSignature {
            name: "Akamai",
            header_checks: vec![
                ("x-akamai-transformed", ""),
                ("server", "AkamaiGHost"),
                ("x-akamai-session-info", ""),
            ],
            cookie_checks: vec!["akamai", "ak_bmsc"],
            body_checks: vec!["akamai", "akam"],
        },
        WafSignature {
            name: "Imperva / Incapsula",
            header_checks: vec![
                ("x-iinfo", ""),
                ("x-cdn", "Incapsula"),
            ],
            cookie_checks: vec!["incap_ses_", "visid_incap_", "nlbi_"],
            body_checks: vec!["incapsula", "imperva"],
        },
        WafSignature {
            name: "F5 BIG-IP",
            header_checks: vec![
                ("x-cnection", ""),
                ("server", "BIG-IP"),
                ("server", "BigIP"),
            ],
            cookie_checks: vec!["BIGipServer", "TS0", "f5_cspm"],
            body_checks: vec!["BIG-IP", "F5 Networks"],
        },
        WafSignature {
            name: "ModSecurity",
            header_checks: vec![
                ("server", "ModSecurity"),
                ("server", "mod_security"),
            ],
            cookie_checks: vec![],
            body_checks: vec!["mod_security", "ModSecurity", "NOYB"],
        },
        WafSignature {
            name: "Sucuri",
            header_checks: vec![
                ("x-sucuri-id", ""),
                ("server", "Sucuri"),
                ("x-sucuri-cache", ""),
            ],
            cookie_checks: vec!["sucuri_"],
            body_checks: vec!["sucuri", "cloudproxy"],
        },
        WafSignature {
            name: "Barracuda",
            header_checks: vec![
                ("server", "Barracuda"),
            ],
            cookie_checks: vec!["barra_counter_session", "BNI__BARRACUDA"],
            body_checks: vec!["barracuda"],
        },
        WafSignature {
            name: "Fortinet / FortiWeb",
            header_checks: vec![
                ("server", "FortiWeb"),
            ],
            cookie_checks: vec!["FORTIWAFSID", "cookiesession1"],
            body_checks: vec!["fortigate", "fortiweb", "fortinet"],
        },
        WafSignature {
            name: "Citrix NetScaler",
            header_checks: vec![
                ("Citrix-TransactionId", ""),
                ("server", "NetScaler"),
                ("cneonction", ""),
            ],
            cookie_checks: vec!["ns_af", "citrix_ns_id", "NSC_"],
            body_checks: vec!["netscaler", "citrix"],
        },
    ]
}

/// Malicious payloads to trigger WAF block responses
const TRIGGER_PAYLOADS: &[&str] = &[
    "/?id=1' OR '1'='1",
    "/?q=<script>alert(1)</script>",
    "/?file=../../etc/passwd",
    "/?cmd=;cat /etc/passwd",
    "/?search=UNION SELECT 1,2,3--",
];

#[derive(Debug, Clone)]
struct WafDetection {
    name: String,
    confidence: &'static str,
    methods: Vec<String>,
}

/// Check headers/cookies/body against WAF signatures
fn check_signatures(
    headers: &HashMap<String, String>,
    cookies: &str,
    body: &str,
    sig: &WafSignature,
) -> Option<(Vec<String>, u32)> {
    let mut methods = Vec::new();
    let mut score = 0u32;

    // Check headers
    for (header_name, header_value) in &sig.header_checks {
        let key = header_name.to_lowercase();
        if let Some(val) = headers.get(&key) {
            if header_value.is_empty() || val.to_lowercase().contains(&header_value.to_lowercase()) {
                methods.push(format!("header '{}' = '{}'", header_name, val));
                score += 3;
            }
        }
    }

    // Check cookies
    let cookies_lower = cookies.to_lowercase();
    for cookie_pattern in &sig.cookie_checks {
        if cookies_lower.contains(&cookie_pattern.to_lowercase()) {
            methods.push(format!("cookie pattern '{}'", cookie_pattern));
            score += 2;
        }
    }

    // Check body
    let body_lower = body.to_lowercase();
    for body_pattern in &sig.body_checks {
        if body_lower.contains(&body_pattern.to_lowercase()) {
            methods.push(format!("body pattern '{}'", body_pattern));
            score += 1;
        }
    }

    if score > 0 {
        Some((methods, score))
    } else {
        None
    }
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "WAF-Detect",
            default_port: 80,
            state_file: "waf_detector_mass_state.log",
            default_output: "waf_detector_mass_results.txt",
            default_concurrency: 200,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} HTTP open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let timeout_secs = cfg_prompt_int_range("timeout", "HTTP timeout (seconds)", 10, 1, 60).await? as u64;
    let send_triggers = cfg_prompt_yes_no("send_triggers", "Send malicious payloads to trigger WAF?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);

    let client = crate::utils::build_http_client(timeout_dur)
        .context("Failed to build HTTP client")?;

    // Build base URL — try HTTPS first for modern targets, fall back to HTTP
    let base_url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        let https_url = format!("https://{}", target);
        if client.get(&https_url).send().await.is_ok() {
            https_url
        } else {
            format!("http://{}", target)
        }
    };
    crate::mprintln!("{}", format!("[*] Using URL: {}", base_url).dimmed());

    let signatures = get_waf_signatures();
    let mut detections: Vec<WafDetection> = Vec::new();

    // Phase 1: Normal request
    crate::mprintln!();
    crate::mprintln!("{}", "[*] Phase 1: Analyzing normal HTTP response...".bold());

    match client.get(&base_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            crate::mprintln!("{}", format!("[*] Status: {}", status).dimmed());

            // Collect headers
            let mut headers: HashMap<String, String> = HashMap::new();
            let mut cookies = String::new();
            for (key, val) in resp.headers() {
                let key_str = key.as_str().to_lowercase();
                let val_str = val.to_str().unwrap_or("").to_string();
                if key_str == "set-cookie" {
                    cookies.push_str(&val_str);
                    cookies.push(';');
                }
                headers.insert(key_str, val_str);
            }

            // Limit response body to 128KB to prevent OOM
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body = if body_bytes.len() > 128 * 1024 {
                String::from_utf8_lossy(&body_bytes[..128 * 1024]).to_string()
            } else {
                String::from_utf8_lossy(&body_bytes).to_string()
            };

            // Check all signatures
            for sig in &signatures {
                if let Some((methods, score)) = check_signatures(&headers, &cookies, &body, sig) {
                    let confidence = if score >= 5 { "High" } else if score >= 3 { "Medium" } else { "Low" };
                    detections.push(WafDetection {
                        name: sig.name.to_string(),
                        confidence,
                        methods,
                    });
                }
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] Normal request failed: {}", e).yellow());
        }
    }

    // Phase 2: Malicious payloads to trigger WAF
    if send_triggers {
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Phase 2: Sending trigger payloads...".bold());

        for payload in TRIGGER_PAYLOADS {
            let url = format!("{}{}", base_url, payload);
            crate::mprintln!("{}", format!("  [*] Testing: {}", payload).dimmed());

            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let blocked = status.as_u16() == 403
                        || status.as_u16() == 406
                        || status.as_u16() == 429
                        || status.as_u16() == 503;

                    if blocked {
                        crate::mprintln!("{}", format!("  [+] Blocked! Status: {}", status).green());
                    }

                    let mut headers: HashMap<String, String> = HashMap::new();
                    let mut cookies = String::new();
                    for (key, val) in resp.headers() {
                        let key_str = key.as_str().to_lowercase();
                        let val_str = val.to_str().unwrap_or("").to_string();
                        if key_str == "set-cookie" {
                            cookies.push_str(&val_str);
                            cookies.push(';');
                        }
                        headers.insert(key_str, val_str);
                    }

                    let body_bytes = resp.bytes().await.unwrap_or_default();
                    let body = if body_bytes.len() > 128 * 1024 {
                        String::from_utf8_lossy(&body_bytes[..128 * 1024]).to_string()
                    } else {
                        String::from_utf8_lossy(&body_bytes).to_string()
                    };

                    for sig in &signatures {
                        if let Some((methods, score)) = check_signatures(&headers, &cookies, &body, sig) {
                            // Only add if not already detected
                            let already = detections.iter().any(|d| d.name == sig.name);
                            if !already {
                                let confidence = if score >= 5 { "High" } else if score >= 3 { "Medium" } else { "Low" };
                                detections.push(WafDetection {
                                    name: sig.name.to_string(),
                                    confidence,
                                    methods,
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    crate::mprintln!("{}", format!("  [-] Request blocked/failed for: {}", payload).dimmed());
                }
            }
        }
    }

    // Results
    crate::mprintln!();
    crate::mprintln!("{}", "=== WAF Detection Results ===".bold());
    crate::mprintln!("  Target: {}", base_url);

    if detections.is_empty() {
        crate::mprintln!("  {}", "No WAF/CDN detected".dimmed());
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Note: Absence of detection does not mean no WAF is present.".yellow());
    } else {
        crate::mprintln!("  Detected WAF/CDN(s):");
        crate::mprintln!();

        for det in &detections {
            let conf_colored = match det.confidence {
                "High" => det.confidence.red().bold().to_string(),
                "Medium" => det.confidence.yellow().to_string(),
                _ => det.confidence.dimmed().to_string(),
            };
            crate::mprintln!("  {} {} (confidence: {})",
                "[+]".green(), det.name.green().bold(), conf_colored);
            for method in &det.methods {
                crate::mprintln!("      - {}", method);
            }
        }
    }

    if save_results && !detections.is_empty() {
        let output_path = cfg_prompt_output_file("output_file", "Output file", "waf_detect_results.txt").await?;
        let mut content = format!("WAF Detection Results - {}\n\n", base_url);
        for det in &detections {
            content.push_str(&format!("WAF: {} (confidence: {})\n", det.name, det.confidence));
            for method in &det.methods {
                content.push_str(&format!("  - {}\n", method));
            }
            content.push('\n');
        }
        std::fs::write(&output_path, content)
            .with_context(|| format!("Failed to write results to {}", output_path))?;
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}
