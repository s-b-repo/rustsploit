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
    cfg_prompt_yes_no, file_size, generate_combos_mode, generate_mask_passwords,
    load_credential_file, load_lines, normalize_target, parse_combo_mode, run_bruteforce,
    run_bruteforce_streaming, BruteforceConfig, LoginResult, STREAMING_THRESHOLD,
};

/// Per-host bruteforce concurrency cap when running inside a mass-scan fan-out.
/// The scheduler already parallelises across hosts, so this keeps the total open
/// socket count (scheduler_hosts x this) well under typical RLIMIT_NOFILE.
const BATCH_PER_HOST_CONCURRENCY: usize = 4;

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
    // Wordlists are OPTIONAL when the module ships built-in defaults. A missing
    // wordlist (e.g. an unattended mass scan with no `setg password_wordlist`)
    // falls back to defaults-only instead of erroring on every host — which is
    // what made bruteforce mass-scans look stuck/broken. If the module has no
    // defaults, a wordlist is still required.
    let have_defaults = !cfg.defaults.is_empty();
    let username_path: Option<String> = if cfg.password_only {
        None
    } else {
        match cfg_prompt_existing_file("username_wordlist", "Username wordlist").await {
            Ok(p) => Some(p),
            Err(e) if have_defaults => {
                tracing::debug!("{}: no username wordlist ({e}); using built-in defaults only", cfg.service_name);
                None
            }
            Err(e) => return Err(e),
        }
    };
    let password_path: Option<String> = match cfg_prompt_existing_file("password_wordlist", "Password wordlist").await {
        Ok(p) => Some(p),
        Err(e) if have_defaults => {
            tracing::debug!("{}: no password wordlist ({e}); using built-in defaults only", cfg.service_name);
            None
        }
        Err(e) => return Err(e),
    };
    // `cartesian` = full cross-product (every user × every password);
    // `paired` = user[i] with pass[i]. (cred-file mode is not implemented here.)
    let combo_input = cfg_prompt_default(
        "combo_mode",
        "Combo mode (cartesian / paired)",
        "cartesian",
    )
    .await?;
    let mode = parse_combo_mode(&combo_input);
    let mut concurrency =
        cfg_prompt_int_range("concurrency", "Concurrency", 16, 1, 256).await? as usize;
    // In a mass-scan fan-out the scheduler already runs many hosts concurrently,
    // so a high PER-HOST bruteforce concurrency multiplies into the total open
    // socket count (e.g. 50 hosts x 16 = 800) and can blow past RLIMIT_NOFILE.
    // Cap per-host concurrency in batch mode; the scheduler supplies the breadth.
    if crate::utils::is_batch_mode() {
        concurrency = concurrency.min(BATCH_PER_HOST_CONCURRENCY);
    }
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Per-attempt timeout (seconds)", 5, 1, 60).await? as u64;
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;

    let usernames: Vec<String> = match username_path.as_deref() {
        Some(p) => load_lines(p)?,
        None => vec![String::new()],
    };

    // Large password lists must NOT go through `load_lines` — its 100 MB
    // `MAX_FILE_SIZE` cap turns a big rockyou-class list into a hard error.
    // Instead, route them into the streaming brute-force engine, which reads
    // the file in bounded batches. Small files keep the exact eager path.
    // Hydra `-C` exclusive mode: when `setg credential_file_only y`, the combo
    // file replaces the user/pass lists, so the password wordlist (and its
    // streaming path) is ignored entirely.
    let cred_file_only = opt_bool("credential_file_only");
    let stream_passwords = !cred_file_only
        && password_path
            .as_deref()
            .map(|p| file_size(p) > STREAMING_THRESHOLD)
            .unwrap_or(false);

    // For the small-file path we load eagerly so we can validate emptiness and
    // preserve the historical "defaults first" combo ordering. No password
    // wordlist (defaults-only mode) yields an empty list — the defaults below
    // still run.
    let passwords: Vec<String> = if stream_passwords {
        Vec::new()
    } else {
        match password_path.as_deref() {
            Some(p) => load_lines(p)?,
            None => Vec::new(),
        }
    };

    if !cfg.password_only && usernames.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    // An empty password set is only an error when there are no built-in defaults
    // to fall back on; otherwise defaults-only is a valid run.
    if !stream_passwords && passwords.is_empty() && !have_defaults {
        return Err(anyhow!(
            "Password wordlist is empty and module has no built-in defaults"
        ));
    }

    // Defaults are the highest-yield rows. In the eager path they go first; in
    // the streaming path they're passed as `extra_combos` (the engine runs them
    // after the streamed batches).
    let mut defaults: Vec<(String, String)> = cfg
        .defaults
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect();

    // Hydra-style `-e nsr`: for each username also try an empty password (null),
    // the username as its own password (same), and the reversed username. Opt in
    // via `setg cred_extras <subset of n/s/r>` (e.g. "nsr"); default off. Appended
    // to the high-yield "defaults first" rows so they run before the wordlist.
    // Skipped for password-only services (no username to derive from).
    if !cfg.password_only {
        let extras = cred_extras();
        if extras.any() {
            for u in &usernames {
                if u.is_empty() {
                    continue;
                }
                if extras.null {
                    defaults.push((u.clone(), String::new()));
                }
                if extras.same {
                    defaults.push((u.clone(), u.clone()));
                }
                if extras.reversed {
                    defaults.push((u.clone(), u.chars().rev().collect::<String>()));
                }
            }
        }
    }

    // Hydra `-C`: a colon-separated user:pass credential file, if provided via
    // `setg credential_file`, is loaded and tried alongside the defaults.
    if let Some(cred_file) = opt_str("credential_file") {
        match load_credential_file(&cred_file) {
            Ok(pairs) => {
                tracing::debug!(
                    "{}: loaded {} credential pair(s) from {}",
                    cfg.service_name,
                    pairs.len(),
                    cred_file
                );
                if cred_file_only {
                    // Exact hydra -C: the file is the ONLY credential source.
                    defaults = pairs;
                } else {
                    defaults.extend(pairs);
                }
            }
            Err(e) => return Err(anyhow!("credential_file '{}': {}", cred_file, e)),
        }
    }

    // Hydra `-w`-style throttle to dodge account lockout: `setg bruteforce_delay_ms`
    // (fixed delay after each attempt) + `setg bruteforce_jitter_ms` (random extra).
    let delay_ms = opt_u64("bruteforce_delay_ms");
    let jitter_ms = opt_u64("bruteforce_jitter_ms");

    // medusa `-r`-style connection retries: `setg bruteforce_retries N` re-tries a
    // retryable (transient/connection) error up to N times per combo. Unset → 1
    // (historical default); explicit 0 → no retries; clamped to a sane ceiling so
    // a fat-fingered huge value can't turn one combo into a billion attempts.
    const MAX_BRUTEFORCE_RETRIES: usize = 10;
    let max_retries = match opt_str("bruteforce_retries") {
        None => 1,
        Some(s) => match s.trim().parse::<usize>() {
            Ok(n) => n.min(MAX_BRUTEFORCE_RETRIES),
            Err(e) => {
                tracing::debug!("bruteforce_retries '{}' invalid ({e}); using 1", s.trim());
                1
            }
        },
    };

    let bf_config = BruteforceConfig {
        target: host.clone(),
        port,
        concurrency,
        stop_on_success,
        verbose: false,
        delay_ms,
        jitter_ms,
        max_retries,
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

    // Hydra `-x`-style mask brute force: `setg bruteforce_mask MIN:MAX:CHARSET`
    // enumerates candidate passwords (e.g. "1:4:a1" = 1–4 chars of [a-z0-9];
    // `a`→a-z, `A`→A-Z, `1`→0-9, other chars literal). These are the lowest-yield
    // rows, so they run AFTER the wordlist. Generated up-front (needs `usernames`
    // before it's moved into the streaming call). Skipped in credential_file_only
    // mode, where the combo file is the sole credential source.
    let mask_combos: Vec<(String, String)> = if cred_file_only {
        Vec::new()
    } else {
        match opt_str("bruteforce_mask") {
            Some(spec) => {
                let masks = generate_mask_passwords(&spec)?;
                if !crate::utils::is_batch_mode() {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[*] Mask '{}' generated {} candidate password(s)",
                            spec,
                            masks.len()
                        )
                        .cyan()
                    );
                }
                generate_combos_mode(&usernames, &masks, mode)
            }
            None => Vec::new(),
        }
    };

    let result = if stream_passwords {
        // Streamed wordlist runs first; defaults + mask combos run afterwards as
        // `extra_combos` (the engine processes them once the stream is drained).
        let mut extra = defaults;
        extra.extend(mask_combos);
        run_bruteforce_streaming(
            &bf_config,
            usernames,
            password_path.as_deref(),
            passwords,
            mode,
            extra,
            probe_for_engine,
        )
        .await?
    } else {
        // Defaults first — common cred lists are the highest-yield rows. In
        // credential_file_only mode `defaults` already holds the file's pairs and
        // the user/pass wordlists are intentionally ignored. The mask brute is
        // appended last (lowest yield).
        let mut combos = defaults;
        if !cred_file_only {
            combos.extend(generate_combos_mode(&usernames, &passwords, mode));
            combos.extend(mask_combos);
        }
        run_bruteforce(&bf_config, combos, probe_for_engine).await?
    };
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
            // An unbracketed IPv6 literal (e.g. `::1`) would produce an
            // unparseable `::1:port` and fail every lookup. Bracket
            // colon-containing hosts so `lookup_host` sees `[::1]:port`.
            let lookup = if host.contains(':') && !host.starts_with('[') {
                format!("[{}]:{}", host, port)
            } else {
                format!("{}:{}", host, port)
            };
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

/// Hydra-style `-e` extra-credential flags: null password, password == login
/// (same), and reversed login.
struct CredExtras {
    null: bool,
    same: bool,
    reversed: bool,
}

impl CredExtras {
    fn any(&self) -> bool {
        self.null || self.same || self.reversed
    }
}

/// Parse `setg cred_extras` (a hydra-style subset of `n`/`s`/`r`, e.g. "nsr").
/// Empty / "none" / "off" / "no" disables it (the default when unset).
fn cred_extras() -> CredExtras {
    let none = CredExtras { null: false, same: false, reversed: false };
    let raw = match crate::tenant::resolve().global_options().try_get("cred_extras") {
        Some(s) => s.to_lowercase(),
        None => return none,
    };
    if matches!(raw.trim(), "" | "none" | "off" | "no" | "0") {
        return none;
    }
    CredExtras {
        null: raw.contains('n'),
        same: raw.contains('s'),
        reversed: raw.contains('r'),
    }
}

/// Read a boolean-ish global option (`setg <key> y`); false when unset.
fn opt_bool(key: &str) -> bool {
    match crate::tenant::resolve().global_options().try_get(key) {
        Some(v) => matches!(
            v.trim().to_lowercase().as_str(),
            "y" | "yes" | "true" | "1" | "on"
        ),
        None => false,
    }
}

/// Read a non-empty global option (`setg <key>`), or `None` if unset/blank.
fn opt_str(key: &str) -> Option<String> {
    crate::tenant::resolve()
        .global_options()
        .try_get(key)
        .filter(|s| !s.trim().is_empty())
}

/// Read a `u64` global option (`setg <key>`), defaulting to 0 when unset or
/// unparseable (the error is surfaced at debug, not silently dropped).
fn opt_u64(key: &str) -> u64 {
    let raw = match crate::tenant::resolve().global_options().try_get(key) {
        Some(v) => v,
        None => return 0,
    };
    match raw.trim().parse::<u64>() {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!("{key} is not a valid u64 ('{}'): {e}; using 0", raw.trim());
            0
        }
    }
}
