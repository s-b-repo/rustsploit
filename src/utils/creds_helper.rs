// src/utils/creds_helper.rs
//
// Shared single-target credential brute-force harness. Modules supply only
// the protocol probe closure; the harness handles wordlist prompting,
// TCP precheck, generic engine wiring, result printing, loot persistence,
// and workspace tracking.
//
// All scheduler fan-out (CIDR / random / file / multi) happens **outside**
// this helper — modules see one host per `run()` invocation.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use colored::*;

use crate::module::{Finding, FindingKind, ModuleOutcome};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_yes_no, generate_combos_mode, load_lines, normalize_target,
    parse_combo_mode, run_bruteforce, BruteforceConfig, LoginResult,
};

/// `read_exact` with a wall-clock timeout, flattened to a single
/// `io::Result<()>`. Avoids the nested-match `Ok(Ok(_)) / Ok(Err) / Err(_)`
/// pattern that's easy to miswrite.
pub async fn read_exact_with_timeout<R>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Duration,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    tokio::time::timeout(deadline, reader.read_exact(buf))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("read timeout: {e}")))?
        ?;
    Ok(())
}

/// TCP connect with a wall-clock timeout and global source port support.
pub async fn connect_with_timeout(
    addr: &str,
    deadline: Duration,
) -> std::io::Result<tokio::net::TcpStream> {
    crate::utils::network::tcp_connect_str(addr, deadline).await
}

/// Per-module configuration — keeps the call site small.
pub struct CredsRun {
    pub service_name: &'static str,
    pub default_port: u16,
    /// Module path used as `source_module` in loot, also drives prompt
    /// cache keys (`module_path::option_name`).
    pub source_module: &'static str,
    /// Default credentials always tried first. Empty → wordlist-only.
    pub defaults: &'static [(&'static str, &'static str)],
    /// True if the protocol uses passwords only (no usernames). Disables
    /// the username-wordlist prompt.
    pub password_only: bool,
}

/// Run a single-target credential probe with prompt-driven wordlists +
/// the generic `run_bruteforce` engine. The scheduler hands us one target
/// per call (CIDR / random / file fan-out happens at the scheduler tier).
///
/// `probe` receives `(host, port, username, password)` and returns a
/// `LoginResult`. It owns any protocol-specific state (TLS flags, timeouts,
/// session secrets) by capturing in the closure.
pub async fn run<F, Fut>(target: &str, cfg: CredsRun, probe: F) -> Result<ModuleOutcome>
where
    F: Fn(String, u16, String, String, Duration) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = LoginResult> + Send,
{
    if !crate::utils::is_batch_mode() {
        crate::mprintln!(
            "{}",
            format!("=== {} brute-force ===", cfg.service_name)
                .bold()
                .cyan()
        );
    }

    // Parse target → host:port (default port if not specified).
    let (host, port) = parse_host_port(target, cfg.default_port)?;

    // Quick TCP precheck — skip the wordlist prompt round-trip for closed
    // ports during big batch scans.
    if !is_port_open(&host, port).await {
        if !crate::utils::is_batch_mode() {
            crate::mprintln!(
                "{}",
                format!("[-] {}:{} closed/filtered — skipping", host, port).dimmed()
            );
        }
        return Ok(ModuleOutcome::ok());
    }

    // Prompt for wordlists. cfg_prompt_* answers are cached across the
    // batch via the prompt cache, so a /16 scan asks once.
    let username_path = if cfg.password_only {
        None
    } else {
        Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
    };
    let password_path =
        cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
    let combo_input = cfg_prompt_default(
        "combo_mode",
        "Combo mode (cartesian / paired / cred-file:<path>)",
        "cartesian",
    )
    .await?;
    let mode = parse_combo_mode(&combo_input);
    let concurrency =
        cfg_prompt_int_range("concurrency", "Concurrency", 16, 1, 256).await? as usize;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Per-attempt timeout (seconds)", 5, 1, 60).await? as u64;
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;

    let usernames: Vec<String> = match username_path.as_deref() {
        Some(p) => load_lines(p)?,
        None => vec![String::new()],
    };
    let passwords: Vec<String> = load_lines(&password_path)?;

    if !cfg.password_only && usernames.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }

    // Defaults first — common cred lists are the highest-yield rows.
    let mut combos: Vec<(String, String)> = cfg
        .defaults
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect();
    combos.extend(generate_combos_mode(&usernames, &passwords, mode));

    let bf_config = BruteforceConfig {
        target: host.clone(),
        port,
        concurrency,
        stop_on_success,
        verbose: false,
        delay_ms: 0,
        jitter_ms: 0,
        max_retries: 1,
        service_name: cfg.service_name,
        source_module: cfg.source_module,
    };

    let probe_for_engine = {
        let probe = probe.clone();
        let timeout = Duration::from_secs(timeout_secs);
        let outer_timeout = timeout + Duration::from_secs(2);
        move |t: String, p: u16, u: String, pw: String| {
            let probe = probe.clone();
            async move {
                match tokio::time::timeout(outer_timeout, probe(t, p, u, pw, timeout)).await {
                    Ok(r) => r,
                    Err(e) => LoginResult::Error {
                        message: format!("attempt timed out after {}s: {e}", outer_timeout.as_secs()),
                        retryable: true,
                    },
                }
            }
        }
    };

    let result = run_bruteforce(&bf_config, combos, probe_for_engine).await?;
    result.print_found();

    // Auto-store every found credential as loot — operators don't have to
    // remember to run `loot save`. Also build a `ModuleOutcome` with one
    // `Credential` Finding per success so the scheduler routes them through
    // the events bus + Workspace alongside the LootStore write below.
    let mut outcome = ModuleOutcome::ok();
    for (addr, user, pass) in &result.found {
        let payload = serde_json::json!({
            "service": cfg.service_name,
            "host": host,
            "port": port,
            "username": user,
            "password": pass,
        });
        let serialized = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                crate::meprintln!("[!] Serialization failed: {}", e);
                return Err(e.into());
            }
        };
        if crate::loot::store_loot(
            &host,
            "credential",
            &format!("{} {}:{}@{}", cfg.service_name, user, pass, addr),
            serialized.as_bytes(),
            cfg.source_module,
        )
        .await
        .is_none() {
            eprintln!("[!] Failed to store loot for {}:{}", host, addr);
        }
        crate::workspace::track_service(&host, port, "tcp", cfg.service_name, None).await;

        outcome.findings.push(Finding {
            target: host.clone(),
            kind: FindingKind::Credential,
            message: format!(
                "{} login {}:{} ({}@{})",
                cfg.service_name, user, pass, user, addr
            ),
            data: Some(payload),
        });
    }
    Ok(outcome)
}

/// Parse a `target` arg as `host[:port]` (handles bare hostnames, IPv4, and
/// `[v6]:port`). Falls back to `default_port` when none is given. Used by
/// every module that takes a single host/port pair from the scheduler.
pub fn parse_host_port(raw: &str, default_port: u16) -> Result<(String, u16)> {
    let trimmed = raw.trim();
    // [v6]:port → (v6, port)
    if let Some(after_brk) = trimmed.strip_prefix('[')
        && let Some(end) = after_brk.find(']') {
            let host = after_brk[..end].to_string();
            let after = &after_brk[end + 1..];
            let port = after
                .strip_prefix(':')
                .and_then(|s| s.parse().ok())
                .unwrap_or(default_port);
            return Ok((host, port));
        }
    // host:port (only when port is digits — avoids splitting v6 hosts).
    if let Some((before, after)) = trimmed.rsplit_once(':')
        && after.chars().all(|c| c.is_ascii_digit())
            && let Ok(port) = after.parse::<u16>() {
                return Ok((before.to_string(), port));
            }
    let normalised = normalize_target(trimmed).unwrap_or_else(|e| {
        tracing::debug!("normalize_target failed for '{}': {e}", trimmed);
        trimmed.to_string()
    });
    Ok((normalised, default_port))
}

async fn is_port_open(host: &str, port: u16) -> bool {
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(e) => {
            tracing::debug!("parse IP failed: {e}");
            let lookup = format!("{}:{}", host, port);
            match tokio::net::lookup_host(&lookup).await {
                Ok(mut iter) => match iter.next() {
                    Some(sa) => sa.ip(),
                    None => return false,
                },
                Err(e) => { tracing::debug!("DNS lookup for {host} failed: {e}"); return false; }
            }
        }
    };
    crate::utils::tcp_port_open(ip, port, Duration::from_secs(2)).await
}
