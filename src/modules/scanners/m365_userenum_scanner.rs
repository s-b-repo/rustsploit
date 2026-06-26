//! Microsoft 365 / Azure AD user enumeration via GetCredentialType.
//!
//! Listed as gap #9 in `_analysis/gaps_and_opportunities.md`: Optus's
//! `singteloptus.onmicrosoft.com` GetCredentialType primitive was never
//! cross-applied to Twilio / Zendesk / Playtika tenants. This module
//! mechanizes the workflow:
//!   1. Probe `https://login.microsoftonline.com/<tenant>.onmicrosoft.com/
//!      .well-known/openid-configuration` to confirm tenant exists.
//!   2. POST `https://login.microsoftonline.com/common/GetCredentialType`
//!      `{"Username": "user@domain"}` and parse `IfExistsResult`:
//!      0 = exists, 1 = does-not-exist, 5 = federated, 6 = exists-throttled.
//!
//! Non-destructive; widely accepted as P3 finding.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::throttle::{with_backoff, BackoffConfig};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_yes_no, is_batch_mode};

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Microsoft 365 User Enumeration (GetCredentialType)         ║".cyan());
    crate::mprintln!("{}", "║   Tenant existence + per-user IfExistsResult                 ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "M365 GetCredentialType User Enum".to_string(),
        description: "Confirms Azure AD / M365 tenant existence via OIDC .well-known, then \
                      enumerates user existence by POSTing GetCredentialType. Returns \
                      IfExistsResult (0=exists, 1=missing, 5=federated, 6=throttled)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/dafthack/MSOLSpray".to_string(),
            "https://posts.specterops.io/azure-ad-and-the-getcredentialtype-endpoint-77ddc91dc94d".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

async fn probe_tenant(client: &reqwest::Client, tenant_label: &str) -> Result<bool> {
    let url = format!("https://login.microsoftonline.com/{}/.well-known/openid-configuration", tenant_label);
    let r = client.get(&url).send().await.context("OIDC config request failed")?;
    let s = r.status();
    let body = match crate::utils::network::read_http_body_text_capped(r, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to read response body: {}", e);
            String::new()
        }
    };
    if s.is_success() && body.contains("token_endpoint") {
        crate::mprintln!("{}", format!("[+] Tenant '{}' exists ({} bytes OIDC config)", tenant_label, body.len()).green().bold());
        Ok(true)
    } else {
        crate::mprintln!("{}", format!("[~] Tenant '{}' OIDC -> {} (likely does not exist)", tenant_label, s.as_u16()).dimmed());
        Ok(false)
    }
}

async fn check_user(client: &reqwest::Client, username: &str) -> Result<i64> {
    let url = "https://login.microsoftonline.com/common/GetCredentialType";
    let body = serde_json::json!({
        "Username": username,
        "isOtherIdpSupported": true,
        "checkPhones": false,
        "isRemoteNGCSupported": true,
        "isCookieBannerShown": false,
        "isFidoSupported": false,
        "originalRequest": "",
        "flowToken": ""
    }).to_string();

    // GetCredentialType throttles aggressively past ~5 rps. with_backoff
    // honours `Retry-After` from MS, falling back to jittered exponential
    // backoff when the header is absent.
    let r = with_backoff(BackoffConfig::aggressive(), username.to_string(), || async {
        client.post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.clone())
            .send().await
    })
    .await
    .context("GetCredentialType request failed")?;

    let txt = match crate::utils::network::read_http_body_text_capped(r, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to read response body: {}", e);
            String::new()
        }
    };
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or(serde_json::Value::Null);
    let result = v.get("IfExistsResult").and_then(|x| x.as_i64()).unwrap_or(-1);
    Ok(result)
}

fn label_result(code: i64) -> &'static str {
    match code {
        0 => "EXISTS",
        1 => "missing",
        2 => "throttled (treat as exists)",
        3 => "EXISTS (Microsoft account)",
        4 => "error",
        5 => "EXISTS (federated)",
        6 => "EXISTS (throttled, very high confidence)",
        _ => "unknown",
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("m365_userenum_scanner requires a single-host target")?;
    banner();

    let tenant = cfg_prompt_default(
        "tenant",
        "Tenant label (e.g. contoso → contoso.onmicrosoft.com), or full domain",
        target,
    ).await?;
    let tenant_label = if tenant.contains('.') { tenant.clone() } else { format!("{}.onmicrosoft.com", tenant) };

    let client = build_http_client(Duration::from_secs(10))?;
    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(&tenant_label).await;
    let exists = probe_tenant(&client, &tenant_label).await?;
    if !exists {
        return Ok(outcome);
    }
    outcome.findings.push(Finding {
        target: tenant_label.clone(),
        kind: FindingKind::Note,
        message: format!("Azure AD / M365 tenant {tenant_label} confirmed via OIDC .well-known"),
        data: None,
    });

    let want_users = cfg_prompt_yes_no("enumerate", "Enumerate users via GetCredentialType?", true).await?;
    if !want_users {
        return Ok(outcome);
    }

    let path = cfg_prompt_existing_file("user_list", "Path to newline-separated user@domain list").await?;
    let users = tokio::fs::read_to_string(&path).await.context("Failed to read user list")?;
    let candidates: Vec<&str> = users.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    crate::mprintln!("{}", format!("[*] Probing {} users via GetCredentialType (paced)...", candidates.len()).cyan());

    let mut hits: Vec<(String, i64)> = Vec::new();
    for u in candidates {
        if ctx.is_cancelled() { break; }
        ctx.rate_limit(&tenant_label).await;
        match check_user(&client, u).await {
            Ok(code) => {
                let label = label_result(code);
                let line = format!("[{}] {} -> {} ({})", code, u, label, code);
                if matches!(code, 0 | 3 | 5 | 6) {
                    crate::mprintln!("{}", line.green().bold());
                    hits.push((u.to_string(), code));
                    outcome.findings.push(Finding {
                        target: tenant_label.clone(),
                        kind: FindingKind::Credential,
                        message: format!("M365 user {u} exists ({label})"),
                        data: Some(serde_json::json!({
                            "tenant": tenant_label,
                            "username": u,
                            "if_exists_result": code,
                            "label": label,
                        })),
                    });
                } else {
                    crate::mprintln!("{}", line.dimmed());
                }
            }
            Err(e) => crate::mprintln!("{}", format!("[-] {} -> {}", u, e).red()),
        }
        // Light baseline pacing — actual 429 handling is in `with_backoff`.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    crate::mprintln!("  Confirmed users: {} (file as P3 user-enum primitive)", hits.len());
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "m365_userenum_scanner", native);
