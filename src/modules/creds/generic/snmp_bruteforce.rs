use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    io::Write,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::{
    sync::Mutex,
    sync::Semaphore,
    task::spawn_blocking,
    time::sleep,
};

use crate::utils::{
    prompt_yes_no, prompt_existing_file, prompt_int_range,
    load_lines, prompt_default, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;

pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== SNMPv1/v2c Brute Force Module ===".bold().cyan());
    println!("{}", "    Community String Discovery Tool".cyan());
    println!();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let default_port = 161;
    let port = prompt_int_range("SNMP Port", default_port as i64, 1, 65535).await? as u16;
    
    let communities_file = prompt_existing_file("Community string wordlist file path").await?;
    
    // Custom prompt for version since it's specific
    let snmp_version = loop {
        let input = prompt_default("SNMP Version (1 or 2c)", "2c").await?;
        match input.trim().to_lowercase().as_str() {
            "1" => break 0,  // SNMPv1
            "2c" | "2" => break 1,  // SNMPv2c
            _ => println!("Invalid version. Enter '1' or '2c'."),
        }
    };
    
    let concurrency = prompt_int_range("Max concurrent tasks", 50, 1, 1000).await? as usize;
    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    
    // Output file handled by saving results at the end usually, but old code asked upfront.
    // I'll stick to standard flow: prompt for save at end OR automatically if specified.
    // Existing modules prompted for output file upfront. I'll do that for consistency with new standard.
    let output_file = prompt_default("Output file", "snmp_results.txt").await?;
    
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let timeout_secs = prompt_int_range("Timeout (seconds)", 3, 1, 300).await? as u64;

    let connect_addr = format!("{}:{}", normalize_target(target)?, port);

    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());

    println!("\n[*] Starting SNMP brute-force on {}", connect_addr);
    println!("[*] SNMP Version: {}", if snmp_version == 0 { "v1" } else { "v2c" });

    let communities = load_lines(&communities_file)?;
    if communities.is_empty() {
        println!("[!] Community wordlist is empty. Exiting.");
        return Ok(());
    }
    println!("{}", format!("[*] Loaded {} community strings", communities.len()).cyan());
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    let _start_time = Instant::now();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
            stats_clone.print_progress();
        }
    });

    let communities = Arc::new(communities);
    let mut tasks = FuturesUnordered::new();
    let semaphore = Arc::new(Semaphore::new(concurrency));

    for community in communities.iter() {
        if stop_on_success && stop.load(Ordering::Relaxed) {
            break;
        }

        let permit = semaphore.clone().acquire_owned().await?;
        let addr_clone = connect_addr.clone();
        let community_clone = community.clone();
        let found_clone = Arc::clone(&found);
        let stop_clone = Arc::clone(&stop);
        let stats_clone = Arc::clone(&stats);
        let stop_flag = stop_on_success;
        let verbose_flag = verbose;
        let version = snmp_version;
        let timeout = Duration::from_secs(timeout_secs);

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            
            if stop_flag && stop_clone.load(Ordering::Relaxed) {
                return;
            }

            match try_snmp_community(&addr_clone, &community_clone, version, timeout).await {
                Ok(true) => {
                    println!("\r{}", format!("[+] {} -> community: '{}'", addr_clone, community_clone).green().bold());
                    found_clone
                        .lock()
                        .await
                        .push((addr_clone.clone(), community_clone.clone()));
                    stats_clone.record_success();
                    if stop_flag {
                        stop_clone.store(true, Ordering::Relaxed);
                    }
                }
                Ok(false) => {
                    stats_clone.record_failure();
                    if verbose_flag {
                        println!("\r{}", format!("[-] {} -> community: '{}'", addr_clone, community_clone).dimmed());
                    }
                }
                Err(e) => {
                    stats_clone.record_error(e.to_string()).await;
                    if verbose_flag {
                        println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                    }
                }
            }

            sleep(Duration::from_millis(10)).await;
        }));
        
        // Drain
        while let std::task::Poll::Ready(Some(_)) = futures::future::poll_fn(|cx| std::task::Poll::Ready(tasks.poll_next_unpin(cx))).await {}
    }

    while let Some(_) = tasks.next().await {}

    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No valid community strings found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid community string(s):", creds.len()).green().bold());
        
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&output_file) {
            for (host, community) in creds.iter() {
                println!("     {} -> community: '{}'", host, community);
                let _ = writeln!(file, "{} -> community: '{}'", host, community);
            }
            println!("[+] Results saved to '{}'", output_file);
        }
    }

    Ok(())
}

async fn try_snmp_community(
    normalized_addr: &str,
    community: &str,
    version: u8,  // 0 = v1, 1 = v2c
    timeout: Duration,
) -> Result<bool> {
    let community_owned = community.to_string();
    let addr_owned = normalized_addr.to_string();

    let result = spawn_blocking(move || -> Result<bool, anyhow::Error> {
        // Parse the address
        let addr: SocketAddr = addr_owned
            .parse()
            .map_err(|e| anyhow!("Invalid address '{}': {}", addr_owned, e))?;

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| anyhow!("Failed to bind socket: {}", e))?;
        
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| anyhow!("Failed to set read timeout: {}", e))?;

        // Build SNMP GET request manually
        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        let message = build_snmp_get_request(&community_owned, version);

        // Send request
        socket
            .send_to(&message, &addr)
            .map_err(|e| anyhow!("Failed to send SNMP request: {}", e))?;

        // Receive response
        let mut buf = vec![0u8; 4096];
        let result: bool = match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                let response = &buf[..size];
                
                // Parse SNMP response to verify it's valid
                // A valid SNMP response should:
                // 1. Start with 0x30 (SEQUENCE)
                // 2. Contain version, community, and PDU
                // 3. Have error status = 0 (noError) in the response PDU
                if size >= 20 && response[0] == 0x30 {
                    // Try to parse the response to check error status
                    // If we can parse it and error status is 0, it's valid
                    match parse_snmp_response(response) {
                        Ok(true) => true,  // Valid community string
                        Ok(false) => false, // Invalid community (error in response)
                        Err(_) => {
                            // Can't parse, but got a response - might be valid
                            // Some devices send malformed responses but still indicate valid community
                            true
                        }
                    }
                } else {
                    // Malformed response - likely invalid
                    false
                }
            }
            Err(e) => {
                // Handle timeout and EAGAIN/EWOULDBLOCK errors as invalid community
                // EAGAIN (os error 11) can occur on Linux when socket would block
                let error_kind = e.kind();
                if error_kind == std::io::ErrorKind::TimedOut 
                    || error_kind == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(11) // EAGAIN on Linux
                    || e.raw_os_error() == Some(35) // EAGAIN on macOS
                {
                    // Timeout or would block - community string is likely invalid
                    false
                } else {
                    // Other errors might be transient, but log them
                    // For now, treat as invalid to avoid false positives
                    false
                }
            }
        };
        Ok(result)
    })
    .await
    .map_err(|e| anyhow!("Task join error: {}", e))?;

    result
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
    let message = build_tlv(0x30, &message_content); // 0x30 = SEQUENCE
    
    message
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



