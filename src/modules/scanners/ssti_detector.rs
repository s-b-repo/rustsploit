use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

/// SSTI polyglot payloads with engine-specific markers.
struct SstiPayload {
    name: &'static str,
    payload: &'static str,
    engine_fingerprints: &'static [&'static str],
}

const SSTI_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        name: "polyglot",
        payload: "${{<%[%'\"}}%\\",
        engine_fingerprints: &[],
    },
    SstiPayload {
        name: "jinja2/basic",
        payload: "{{7*7}}",
        engine_fingerprints: &["49"],
    },
    SstiPayload {
        name: "jinja2/config",
        payload: "{{config}}",
        engine_fingerprints: &["<Config", "DEBUG"],
    },
    SstiPayload {
        name: "twig",
        payload: "{{7*'7'}}",
        engine_fingerprints: &["7777777"],
    },
    SstiPayload {
        name: "erb",
        payload: "<%= 7*7 %>",
        engine_fingerprints: &["49"],
    },
    SstiPayload {
        name: "freemarker",
        payload: "${7*7}",
        engine_fingerprints: &["49"],
    },
    SstiPayload {
        name: "handlebars",
        payload: "{{constructor.constructor('return 7*7')()}}",
        engine_fingerprints: &["49"],
    },
    SstiPayload {
        name: "velocity",
        payload: "#set($x=7*7)$x",
        engine_fingerprints: &["49"],
    },
    SstiPayload {
        name: "smarty",
        payload: "{$smarty.version}",
        engine_fingerprints: &["Smarty-", "3."],
    },
];

const PARAM_NAMES: &[&str] = &[
    "q", "search", "id", "name", "page", "query", "s", "url", "user", "email",
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("ssti_detector requires a single-host target")?;

    crate::mprintln!(
        "{}",
        format!("[*] SSTI Detector — target: {}", target).cyan()
    );

    let port = ctx.options.get_or("port", 443u16);
    let timeout_secs = ctx.options.get_or("timeout", 10u64).clamp(1, 60);

    let client = crate::utils::build_http_client(Duration::from_secs(timeout_secs))?;
    let base_url = format!("https://{}:{}", target, port);

    let mut outcome = ModuleOutcome::ok();
    let mut tested = 0u32;
    let mut vulnerable = 0u32;

    for payload in SSTI_PAYLOADS {
        // Test each payload against common parameter names
        for param in PARAM_NAMES {
            let url = format!("{}/?{}={}", base_url, param, payload.payload);
            match client.get(&url).send().await {
                Ok(resp) => {
                    tested += 1;
                    let body = match resp.text().await {
                        Ok(b) => b,
                        Err(e) => {
                            crate::meprintln!(
                                "[-] Failed to read body for SSTI '{}' on param '{}': {}",
                                payload.name,
                                param,
                                e
                            );
                            continue;
                        }
                    };

                    // Check for engine fingerprints OR the computed value 49
                    let mut matched = false;
                    let mut engine_hint = "";

                    for fp in payload.engine_fingerprints {
                        if body.contains(fp) {
                            matched = true;
                            engine_hint = fp;
                            break;
                        }
                    }

                    if matched {
                        let msg = format!(
                            "SSTI detected with payload '{}' on param '{}': reflected '{}' in response",
                            payload.name, param, engine_hint,
                        );
                        crate::mprintln!("{}", format!("[+] {}", msg).green());
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Vulnerable,
                            message: msg,
                            data: None,
                        });
                        vulnerable += 1;
                        // Short-circuit: one hit per payload is enough
                        break;
                    }
                }
                Err(e) => {
                    crate::meprintln!(
                        "[-] SSTI '{}' on param '{}' failed: {:#}",
                        payload.name,
                        param,
                        e
                    );
                }
            }
        }
    }

    // Header-based SSTI test with polyglot only
    crate::mprintln!("{}", "[*] Testing header-based SSTI (polyglot)".dimmed());
    let polyglot = "${{<%[%'\"}}%\\";
    for header_name in &["User-Agent", "Referer", "X-Forwarded-For", "Cookie"] {
        match client
            .get(&base_url)
            .header(*header_name, polyglot)
            .send()
            .await
        {
            Ok(resp) => {
                tested += 1;
                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(e) => {
                        crate::meprintln!(
                            "[-] Failed to read body for SSTI header '{}': {}",
                            header_name,
                            e
                        );
                        continue;
                    }
                };
                // SSTI engines often echo the polyglot raw; look for partial reflection
                if body.contains("{{<%[%") || body.contains("7*7") {
                    let msg = format!(
                        "SSTI polyglot reflected via '{}' header in response body",
                        header_name
                    );
                    crate::mprintln!("{}", format!("[+] {}", msg).green());
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Vulnerable,
                        message: msg,
                        data: None,
                    });
                    vulnerable += 1;
                    break;
                }
            }
            Err(e) => {
                crate::meprintln!("[-] SSTI header '{}' failed: {:#}", header_name, e);
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== SSTI Scan Summary ===".bold());
    crate::mprintln!("  Target:         {}", target);
    crate::mprintln!("  Payloads sent:  {}", tested);
    crate::mprintln!("  Vulnerabilities: {}", vulnerable);

    Ok(outcome)
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SSTI Detector".to_string(),
        description: "Probes for Server-Side Template Injection (SSTI) using a polyglot payload and engine-specific probes (Jinja2, Twig, ERB, FreeMarker, Handlebars, Velocity, Smarty) across GET parameters and HTTP headers.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://portswigger.net/web-security/server-side-template-injection".to_string(),
            "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(443),
    }
}

crate::register_native_module!(crate::module::Category::Scanners, "ssti_detector", native);
