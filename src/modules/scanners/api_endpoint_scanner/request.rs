//! Per-request transport for the API scanner.
//!
//! `perform_request` is the single chokepoint that issues an HTTP request
//! with a random Chrome User-Agent, optional spoof header, and optional
//! generic JSON payload, then hands the response to `log_response` for
//! disk persistence (with body caps to keep memory bounded).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use colored::*;
use futures::StreamExt;
use rand::seq::IndexedRandom;
use reqwest::{Client, Method, Response};

use super::config::{GenericPayload, ScanConfig, CHROME_USER_AGENTS};

pub(super) struct RequestSpec<'a> {
    pub client: &'a Client,
    pub url: &'a str,
    pub method: Method,
    pub result_file: &'a Path,
    pub method_name: &'a str,
    pub valid_label: &'a str,
    pub header: Option<(&'a str, &'a str)>,
    pub custom_json: Option<serde_json::Value>,
    pub config: &'a ScanConfig,
}

pub(super) async fn perform_request(spec: &RequestSpec<'_>) {
    let user_agent = match CHROME_USER_AGENTS.choose(&mut rand::rng()) {
        Some(ua) => *ua,
        None => "Mozilla/5.0",
    };

    let mut req_builder = spec.client.request(spec.method.clone(), spec.url).header("User-Agent", user_agent);

    if let Some((k, v)) = spec.header {
        req_builder = req_builder.header(k, v);
    }

    if let Some(json) = &spec.custom_json {
        req_builder = req_builder.json(json);
    } else if spec.config.use_generic_payload && (spec.method == Method::POST || spec.method == Method::PUT) {
        req_builder = req_builder.json(&GenericPayload {
            name: "test_api_scanner".to_string(),
            description: "Automated scan".to_string(),
            test: true,
        });
    }

    let full_label = format!("{} [{}]", spec.method_name, spec.valid_label);

    match req_builder.send().await {
        Ok(resp) => {
            if let Err(e) = log_response(resp, spec.result_file, &full_label, spec.url, user_agent).await {
                crate::meprintln!(
                    "\n{}",
                    format!("[!] Failed to log response for {}: {}", full_label, e).red()
                );
            }
        }
        Err(e) => {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(spec.result_file)
                && let Err(write_err) = writeln!(
                    file,
                    "=== {} {} ===\nError: {}\n",
                    full_label, spec.url, e
                )
            {
                crate::meprintln!("[!] Failed to write error log: {}", write_err);
            }
        }
    }
}

async fn log_response(
    resp: Response,
    path: &Path,
    method: &str,
    url: &str,
    user_agent: &str,
) -> Result<()> {
    let status = resp.status();
    let headers = resp.headers().clone();

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    // Early short-circuit: when the server advertises a body too large to
    // safely capture, don't even start the stream.
    if let Some(cl) = headers.get("content-length")
        && let Ok(s) = cl.to_str()
        && let Ok(len) = s.parse::<usize>()
        && len > 5_000_000
    {
        writeln!(file, "Body skipped (Content-Length: {} > 5MB)", len)?;
        return Ok(());
    }

    // Streaming body capture with a hard 5 MiB cap so a misbehaving server
    // can't OOM the scanner.
    let max_body = 5_000_000usize;
    let mut body_data = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk_bytes) => {
                body_data.extend_from_slice(&chunk_bytes);
                if body_data.len() > max_body {
                    writeln!(file, "  Body truncated (exceeded {}B limit)", max_body)?;
                    break;
                }
            }
            Err(e) => { tracing::debug!("stream read error: {e}"); break; }
        }
    }
    let body_bytes = bytes::Bytes::from(body_data);
    let body_len = body_bytes.len();
    let max_len = 1_000_000;
    let truncated = body_len > max_len;
    let body = if truncated {
        &body_bytes[..max_len]
    } else {
        &body_bytes[..]
    };

    writeln!(file, "=======================================================")?;
    writeln!(file, "Timestamp: {}", chrono::Local::now().to_rfc3339())?;
    writeln!(file, "Request: {} {}", method, url)?;
    writeln!(file, "User-Agent: {}", user_agent)?;
    writeln!(file, "-------------------------------------------------------")?;
    writeln!(file, "Status: {}", status)?;
    writeln!(file, "Headers:")?;

    for (k, v) in headers.iter() {
        writeln!(file, "  {}: {:?}", k, v)?;
    }
    writeln!(file, "Body Length: {} bytes", body.len())?;
    writeln!(file, "-------------------------------------------------------")?;

    if let Ok(body_str) = String::from_utf8(body.to_vec()) {
        writeln!(
            file,
            "Body Preview{}:\n{}",
            if truncated { " (TRUNCATED)" } else { "" },
            body_str
        )?;
    } else {
        writeln!(file, "Body is binary or non-UTF8")?;
    }
    writeln!(file, "=======================================================\n")?;

    Ok(())
}
