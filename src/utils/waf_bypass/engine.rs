use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use http::Method;

use super::config::WafBypassConfig;
use super::detection::{BypassVerdict, classify_response};
use super::techniques::{self, Technique};

pub struct BypassOutcome {
    pub response: reqwest::Response,
    pub technique_used: Option<Technique>,
    pub attempts: u32,
    pub waf_detected: Vec<String>,
}

pub async fn send_with_bypass(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    config: &WafBypassConfig,
) -> Result<BypassOutcome> {
    let mut waf_detected: Vec<String> = Vec::new();
    let orig_method = method.clone();
    let orig_body = body.clone();

    if !config.enabled || config.mode == super::config::BypassMode::Off {
        let response = send_raw(client, &orig_method, url, headers, orig_body.as_deref())
            .await
            .context("send original request (bypass disabled)")?;
        return Ok(BypassOutcome {
            response,
            technique_used: None,
            attempts: 1,
            waf_detected,
        });
    }

    // Attempt 0: send the original request first
    let (status, resp_body, resp_headers) = send_single(
        client,
        &orig_method,
        url,
        headers,
        orig_body.as_deref(),
        config.timeout,
    )
    .await?;

    let verdict = classify_response(status, &resp_body, &resp_headers);
    match verdict {
        BypassVerdict::Success | BypassVerdict::Unknown { .. } => {
            // Re-send the original request so the caller gets the Response object
            let response = send_raw(client, &orig_method, url, headers, orig_body.as_deref())
                .await
                .context("re-send original request")?;
            return Ok(BypassOutcome {
                response,
                technique_used: None,
                attempts: 1,
                waf_detected,
            });
        }
        BypassVerdict::Blocked { ref reason, .. } => {
            waf_detected = super::detection::detect_waf(&resp_headers, &resp_body);
            tracing::debug!(
                "WAF bypass: original request blocked ({}), detected: {:?}",
                reason,
                waf_detected
            );
        }
        BypassVerdict::Challenged { ref reason } => {
            tracing::debug!("WAF bypass: original request challenged ({})", reason);
        }
        BypassVerdict::Error { ref message } => {
            tracing::debug!("WAF bypass: original request failed ({})", message);
        }
    }

    let max_attempts = config.max_retries.min(config.techniques.len() as u32);
    for attempt in 0..max_attempts {
        let tech = match config.techniques.get(attempt as usize) {
            Some(t) => *t,
            None => break,
        };

        let (tech_method, tech_body, extra_headers, modified_url) =
            apply_technique(&orig_method, orig_body.as_deref(), url, tech);

        let effective_url = modified_url.as_deref().unwrap_or(url);
        let merged_headers = merge_headers(headers, &extra_headers);

        let (status, resp_body, resp_headers) = send_single(
            client,
            &tech_method,
            effective_url,
            &merged_headers,
            tech_body.as_deref(),
            config.timeout,
        )
        .await?;

        let verdict = classify_response(status, &resp_body, &resp_headers);
        match verdict {
            BypassVerdict::Success => {
                let response = send_raw(
                    client,
                    &tech_method,
                    effective_url,
                    &merged_headers,
                    tech_body.as_deref(),
                )
                .await
                .context("re-send bypassed request")?;
                return Ok(BypassOutcome {
                    response,
                    technique_used: Some(tech),
                    attempts: attempt + 2,
                    waf_detected,
                });
            }
            _ => {
                tracing::debug!(
                    "WAF bypass: technique '{}' resulted in {:?} (status {})",
                    tech.name(),
                    verdict,
                    status
                );
            }
        }

        if config.stop_on_success {
            // Only stop on Success, continue on all other verdicts
        }
    }

    // All techniques exhausted — return the original response as best effort
    let response = send_raw(client, &orig_method, url, headers, orig_body.as_deref())
        .await
        .context("re-send original after bypass exhaustion")?;
    Ok(BypassOutcome {
        response,
        technique_used: None,
        attempts: max_attempts + 1,
        waf_detected,
    })
}

fn apply_technique(
    method: &Method,
    body: Option<&[u8]>,
    url: &str,
    tech: Technique,
) -> (
    Method,
    Option<Vec<u8>>,
    Vec<(&'static str, &'static str)>,
    Option<String>,
) {
    let mut m = method.clone();
    let mut b = body.map(|b| b.to_vec());
    let mut extra_headers: Vec<(&'static str, &'static str)> = Vec::new();
    let mut modified_url: Option<String> = None;

    match tech {
        Technique::GetBodySmuggle => {
            techniques::get_body::apply(&mut m, &mut b, url);
            if let Some(ref mut body_vec) = b {
                techniques::get_body::add_random_padding(body_vec);
            }
        }
        Technique::UrlEncodeSpecials | Technique::DoubleUrlEncode | Technique::UnicodeNormalize => {
            if let Some(ref payload) = b {
                match techniques::encoding::encode_payload(payload, tech) {
                    Ok(encoded) => b = Some(encoded),
                    Err(e) => {
                        tracing::debug!("WAF bypass encoding failed: {}", e);
                    }
                }
            }
        }
        Technique::MethodOverride => {
            techniques::method_override::apply(&mut m);
            extra_headers.extend_from_slice(techniques::method_override::OVERRIDE_HEADERS);
            for _qp in techniques::method_override::OVERRIDE_QUERY_PARAMS {
                tracing::trace!("WAF bypass: method override query param available: {}", _qp);
            }
        }
        Technique::ContentTypeSpoof => {
            if let Some(ref payload) = b {
                b = Some(techniques::content_type::wrap_body_as_multipart(
                    payload,
                    "----wafbypass",
                ));
            }
            extra_headers.push((
                "Content-Type",
                "multipart/form-data; boundary=----wafbypass",
            ));
        }
        Technique::HeaderSmuggle => {
            extra_headers.extend_from_slice(techniques::header_smuggle::SMUGGLE_HEADERS);
        }
        Technique::ChunkedTe => {
            if let Some(ref payload) = b {
                let sizes = techniques::chunked::chunk_sizes();
                let chunk_sz = sizes.first().copied().unwrap_or(8);
                let exts = techniques::chunked::chunk_extensions();
                let ext = exts.first().copied().unwrap_or("comment=bypass");
                b = Some(techniques::chunked::chunk_body(
                    payload,
                    chunk_sz,
                    Some(ext),
                ));
            }
            extra_headers.push(("Transfer-Encoding", "chunked"));
        }
        Technique::Desync => {
            if let Some(ref payload) = b {
                b = Some(techniques::protocol::cl_te_body(payload));
            }
            extra_headers.push(("Transfer-Encoding", "chunked"));
            extra_headers.push(("Content-Length", "0"));
            for (te, _cl) in techniques::protocol::TE_CL_PAIRS {
                tracing::trace!("WAF bypass: desync pair te={}", te);
            }
        }
        Technique::Http10Downgrade => {
            let (_method, req_line) = techniques::protocol::http_10_request(url);
            tracing::trace!("WAF bypass: HTTP/1.0 downgrade: {}", req_line);
            extra_headers.push(("Connection", "close"));
        }
        Technique::WebSocketUpgrade => {
            extra_headers.extend_from_slice(techniques::websocket::WS_UPGRADE_HEADERS);
        }
        Technique::ParamPollution => {
            for dup in techniques::param_pollution::HPP_DUPLICATE {
                let sep = if url.contains('?') { "&" } else { "?" };
                modified_url = Some(format!("{}{}{}", url, sep, dup));
                break;
            }
            for key in techniques::param_pollution::HPP_JSON_KEYS {
                tracing::trace!("WAF bypass: HPP JSON key: {}", key);
            }
        }
        Technique::CaseWhitespace => {
            if let Some(ref payload) = b {
                if let Ok(s) = std::str::from_utf8(payload) {
                    let obf = techniques::case_whitespace::obfuscate_keyword(s);
                    let ws = techniques::case_whitespace::insert_whitespace(&obf);
                    b = Some(ws.into_bytes());
                }
            }
        }
    }

    (m, b, extra_headers, modified_url)
}

async fn send_single(
    client: &reqwest::Client,
    method: &Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String, HashMap<String, String>)> {
    let resp = tokio::time::timeout(timeout, send_raw(client, method, url, headers, body))
        .await
        .map_err(|e| anyhow::anyhow!("WAF bypass request timed out: {}", e))??;

    let status = resp.status().as_u16();
    let resp_headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("<non-utf8>").to_string(),
            )
        })
        .collect();

    let body_text = resp
        .text()
        .await
        .unwrap_or_else(|e| format!("[body_read_error: {}]", e));

    Ok((status, body_text, resp_headers))
}

async fn send_raw(
    client: &reqwest::Client,
    method: &Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<reqwest::Response> {
    let mut req = client.request(method.clone(), url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }
    req.send().await.map_err(anyhow::Error::from)
}

fn merge_headers<'a>(
    base: &'a [(&str, &str)],
    extra: &'a [(&'static str, &'static str)],
) -> Vec<(&'a str, &'a str)> {
    let mut merged: Vec<(&str, &str)> = Vec::with_capacity(base.len() + extra.len());
    for (k, v) in base {
        merged.push((*k, *v));
    }
    for (k, v) in extra {
        merged.push((*k, *v));
    }
    merged
}
