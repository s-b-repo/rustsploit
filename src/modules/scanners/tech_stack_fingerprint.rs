use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::build_http_client;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Tech Stack Fingerprinter".into(),
        description: "Multi-signature technology detection: Wappalyzer-style \
            header/body/cookie fingerprinting for CMS, frameworks, JS libraries, \
            CDNs, analytics, and server software."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://www.wappalyzer.com/".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: Some(443),
    }
}

const TECH_SIGNATURES: &[(&str, &str, &[&str])] = &[
    (
        "WordPress",
        "wp-content",
        &["wordpress", "wp-json", "wp-includes"],
    ),
    ("Drupal", "drupal", &["drupal", "drupal.settings"]),
    ("Joomla", "joomla", &["joomla", "com_content"]),
    ("React", "react", &["react", "react-dom"]),
    ("Vue.js", "vue", &["vue", "vue.js"]),
    ("Angular", "angular", &["angular", "ng-version"]),
    ("jQuery", "jquery", &["jquery"]),
    ("Bootstrap", "bootstrap", &["bootstrap"]),
    ("Laravel", "laravel_session", &["laravel"]),
    ("Django", "csrftoken", &["django"]),
    ("Ruby on Rails", "rails", &["rails"]),
    ("ASP.NET", "ASP.NET_SessionId", &["asp.net", "__viewstate"]),
    ("PHP", "PHPSESSID", &["x-powered-by: php"]),
    ("Nginx", "nginx", &["server: nginx"]),
    ("Apache", "apache", &["server: apache"]),
    ("Cloudflare", "__cf_bm", &["cloudflare", "cf-ray"]),
    ("Google Analytics", "gtag", &["google-analytics", "ga\""]),
    ("Stripe", "stripe", &["stripe", "js.stripe.com"]),
    ("Shopify", "shopify", &["shopify", "myshopify.com"]),
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    let timeout = Duration::from_secs(10);
    let client = build_http_client(timeout).context("build http client")?;
    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let mut outcome = ModuleOutcome::ok();

    crate::mprintln!(
        "{}",
        format!("[*] Tech Stack Fingerprint: {}", base_url)
            .cyan()
            .bold()
    );
    match tokio::time::timeout(timeout, client.get(&base_url).send()).await {
        Ok(Ok(resp)) => {
            let headers = resp.headers().clone();
            let headers_lower: String = headers
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}: {}",
                        k.as_str().to_lowercase(),
                        v.to_str().unwrap_or("").to_lowercase()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let cookies = headers
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let body = resp.text().await.unwrap_or_else(|e| {
                tracing::trace!("body read failed: {}", e);
                String::new()
            });
            let body_lower = body.to_lowercase();

            for (name, cookie_sig, body_sigs) in TECH_SIGNATURES {
                let mut matched = false;
                if !cookie_sig.is_empty() && cookies.contains(cookie_sig) {
                    matched = true;
                }
                if !matched {
                    for sig in *body_sigs {
                        if body_lower.contains(sig) || headers_lower.contains(sig) {
                            matched = true;
                            break;
                        }
                    }
                }
                if matched {
                    crate::mprintln!("{}", format!("[+] Detected: {}", name).green());
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Banner,
                        message: format!("Tech stack: {} detected on {}", name, target),
                        data: Some(serde_json::json!({"host": target, "tech": name})),
                    });
                }
            }
        }
        _ => {
            crate::meprintln!("[-] Could not reach target");
        }
    }
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "tech_stack_fingerprint",
    native
);
