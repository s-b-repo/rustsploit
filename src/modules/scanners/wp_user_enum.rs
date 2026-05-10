//! WordPress user enumeration scanner.
//!
//! Probes three independent enum primitives that produced 6 findings + 11
//! commands across the corpus (Canterbury, Pureplesier, Tasteofcannabis):
//!   1. `/wp-json/wp/v2/users` — REST API listing
//!   2. `/?author=N` — author archive 301 redirect leaks slug
//!   3. `/wp-json/oembed/1.0/embed?url=<post>` — author URL/slug disclosure

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_int_range, is_batch_mode, url_encode};

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   WordPress User Enumeration                                 ║".cyan());
    crate::mprintln!("{}", "║   wp-json/users + ?author=N + oembed disclosure              ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "WordPress User Enumeration".to_string(),
        description: "Three-vector WordPress user enumeration: /wp-json/wp/v2/users, ?author=N \
                      slug-leak via redirect, and /wp-json/oembed/1.0/embed author disclosure."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://hackerone.com/reports/138146".to_string(),
            "https://wpscan.com/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() }
    else { format!("https://{}", t.trim_end_matches('/')) }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("wp_user_enum requires a single-host target")?;

    banner();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();
    let max_author_id = cfg_prompt_int_range("max_author_id", "Max author ID for ?author=N probe", 10, 1, 200).await?;

    let client = build_http_client(Duration::from_secs(10))?;
    let mut users: Vec<(String, String, String)> = Vec::new(); // (id/source, slug, name)
    let mut outcome = ModuleOutcome::ok();

    // 1) wp-json/wp/v2/users
    let url = format!("{}/wp-json/wp/v2/users", base);
    crate::mprintln!("{}", format!("[*] GET {}", url).cyan());
    if let Ok(r) = client.get(&url).send().await {
        let s = r.status().as_u16();
        let body = r.text().await.unwrap_or_default();
        if s == 200 && body.starts_with('[') {
            crate::mprintln!("{}", "[+] /wp-json/wp/v2/users returned a JSON array".green().bold());
            // crude id/slug/name extraction
            for chunk in body.split("\"id\":") {
                let id: String = chunk.chars().take_while(|c| c.is_ascii_digit()).collect();
                let slug = chunk.split("\"slug\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap_or("").to_string();
                let name = chunk.split("\"name\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap_or("").to_string();
                if !id.is_empty() && !slug.is_empty() {
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: format!("WP user disclosed via /wp-json/wp/v2/users id={} slug={} name={}", id, slug, name),
                        data: Some(serde_json::json!({
                            "vector": "wp_json_users",
                            "id": id,
                            "slug": slug,
                            "name": name,
                        })),
                    });
                    users.push((format!("wp-json id={}", id), slug, name));
                }
            }
        } else {
            crate::mprintln!("{}", format!("[~] /wp-json/wp/v2/users -> {} ({})", s, body.chars().take(80).collect::<String>()).dimmed());
        }
    }

    // 2) ?author=N redirect — use the framework client with redirects OFF so we
    //    can read the Location header. build_http_client already sets follow_redirects=false
    //    *and* honours --strict-tls; rolling our own would bypass both.
    crate::mprintln!("{}", format!("[*] Probing ?author=1..{}", max_author_id).cyan());
    let redir_client = build_http_client_with(Duration::from_secs(10), HttpClientOpts {
        follow_redirects: false,
        ..HttpClientOpts::permissive()
    })?;
    for n in 1..=max_author_id {
        let url = format!("{}/?author={}", base, n);
        if let Ok(r) = redir_client.get(&url).send().await
            && r.status().is_redirection()
                && let Some(loc) = r.headers().get("location").and_then(|v| v.to_str().ok())
                    && let Some(slug) = loc.split("/author/").nth(1).and_then(|s| s.split('/').next()) {
                        crate::mprintln!("{}", format!("[+] ?author={} -> /author/{} (slug)", n, slug).green());
                        users.push((format!("?author={}", n), slug.to_string(), String::new()));
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Note,
                            message: format!("WP user slug leak: ?author={} -> /author/{}", n, slug),
                            data: Some(serde_json::json!({
                                "vector": "author_redirect",
                                "author_id": n,
                                "slug": slug,
                            })),
                        });
                    }
    }

    // 3) oembed author disclosure (needs a known post URL — try /?p=1 redirect first)
    let probe = format!("{}/?p=1", base);
    if let Ok(r) = client.get(format!("{}/wp-json/oembed/1.0/embed?url={}", base, url_encode(&probe))).send().await {
        let s = r.status().as_u16();
        let body = r.text().await.unwrap_or_default();
        if s == 200 && body.contains("author_name") {
            crate::mprintln!("{}", format!("[+] oembed disclosed author for {}: {}",
                probe, body.chars().take(200).collect::<String>()).green());
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Discovered users ===".bold());
    if users.is_empty() {
        crate::mprintln!("{}", "  None.".green());
    } else {
        for (src, slug, name) in &users {
            crate::mprintln!("  - [{}] slug='{}' name='{}'", src, slug, name);
        }
    }

    Ok(outcome)
}


crate::register_native_module!(crate::module::Category::Scanners, "wp_user_enum", native);
