//! Native RDP authentication - replaces external xfreerdp/rdesktop CLI dependency.
//!
//! Implements X.224 negotiation → TLS upgrade → CredSSP/NTLM authentication
//! to check RDP credentials without spawning external processes.

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// ============================================================================
// RDP Protocol Constants
// ============================================================================

const TPKT_VERSION: u8 = 3;
const X224_TYPE_CR: u8 = 0xE0;
const X224_TYPE_CC: u8 = 0xD0;
const RDP_NEG_REQ: u8 = 0x01;
const RDP_NEG_RSP: u8 = 0x02;
const RDP_NEG_FAILURE: u8 = 0x03;

pub const PROTO_RDP: u32 = 0x00000000;
pub const PROTO_SSL: u32 = 0x00000001;
pub const PROTO_HYBRID: u32 = 0x00000002; // NLA (CredSSP)

// NTLM negotiate flags
const NTLM_FLAGS: u32 =
    0x00000001 | // UNICODE
    0x00000004 | // REQUEST_TARGET
    0x00000200 | // NTLM
    0x00008000 | // ALWAYS_SIGN
    0x00080000 | // EXTENDED_SESSIONSECURITY
    0x20000000 | // 128-bit
    0x80000000;  // 56-bit

const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";

// ============================================================================
// Public API
// ============================================================================

/// Result of an RDP login attempt.
#[derive(Debug)]
pub enum RdpLoginResult {
    /// Credentials accepted
    Success,
    /// Credentials rejected (wrong user/pass)
    AuthFailed,
    /// Could not connect / host unreachable
    ConnectionFailed(String),
    /// Protocol or TLS error
    ProtocolError(String),
}

/// Attempt native RDP login. Returns Ok(RdpLoginResult).
pub async fn try_login(
    addr: &str,
    user: &str,
    pass: &str,
    timeout_duration: Duration,
    requested_protocols: u32,
) -> Result<RdpLoginResult> {
    // 1. TCP connect
    let stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Ok(RdpLoginResult::ConnectionFailed(e.to_string())),
        Err(_) => return Ok(RdpLoginResult::ConnectionFailed("Connection timeout".into())),
    };

    // 2. X.224 Connection Request
    let cookie = if user.is_empty() { "rustsploit" } else { user };
    let cr_pdu = build_x224_cr(cookie, requested_protocols);

    let mut stream = stream;
    if let Err(e) = timeout(timeout_duration, stream.write_all(&cr_pdu)).await {
        return Ok(RdpLoginResult::ConnectionFailed(format!("Write CR: {}", e)));
    }

    // 3. Read X.224 Connection Confirm (read full TPKT frame)
    let mut buf = vec![0u8; 1024];
    let n = match timeout(timeout_duration, read_tpkt_frame(&mut stream, &mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Ok(RdpLoginResult::ConnectionFailed(format!("Read CC: {}", e))),
        Err(_) => return Ok(RdpLoginResult::ConnectionFailed("CC timeout".into())),
    };

    let selected = match parse_x224_cc(&buf[..n]) {
        Ok(p) => p,
        Err(e) => return Ok(RdpLoginResult::ProtocolError(format!("X.224 CC: {}", e))),
    };

    // 4. If NLA or TLS selected → upgrade to TLS
    if selected == PROTO_HYBRID || selected == PROTO_SSL {
        // TLS upgrade
        let tls_stream = match tls_upgrade(stream, addr, timeout_duration).await {
            Ok(s) => s,
            Err(e) => return Ok(RdpLoginResult::ProtocolError(format!("TLS: {}", e))),
        };

        if selected == PROTO_HYBRID {
            // CredSSP + NTLM authentication
            return credssp_authenticate(tls_stream, user, pass, timeout_duration).await;
        }
        // TLS-only: server doesn't require NLA, can't auth-check without full
        // RDP handshake; treat connection success as "host alive, auth untested"
        return Ok(RdpLoginResult::ProtocolError(
            "Server uses TLS without NLA; cannot auth-check natively".into(),
        ));
    }

    // 5. Standard RDP (no NLA/TLS) - legacy mode
    Ok(RdpLoginResult::ProtocolError(
        "Server uses legacy RDP security; cannot auth-check natively".into(),
    ))
}

// ============================================================================
// TPKT Frame Reader — ensures full PDU is read (handles partial TCP reads)
// ============================================================================

async fn read_tpkt_frame<S: AsyncReadExt + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<usize> {
    // Read at least 4 bytes for the TPKT header
    let mut total = 0;
    while total < 4 {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 { return Err(anyhow!("Connection closed before TPKT header")); }
        total += n;
    }
    if buf[0] != TPKT_VERSION {
        return Err(anyhow!("Bad TPKT version 0x{:02x}", buf[0]));
    }
    let frame_len = ((buf[2] as usize) << 8) | buf[3] as usize;
    if frame_len > buf.len() {
        return Err(anyhow!("TPKT frame too large: {} bytes", frame_len));
    }
    // Read remaining bytes
    while total < frame_len {
        let n = stream.read(&mut buf[total..frame_len]).await?;
        if n == 0 { return Err(anyhow!("Connection closed mid-TPKT frame")); }
        total += n;
    }
    Ok(total)
}

// ============================================================================
// X.224 Protocol
// ============================================================================

fn build_x224_cr(cookie: &str, protocols: u32) -> Vec<u8> {
    let cookie_str = format!("Cookie: mstshash={}\r\n", cookie);
    let cookie_bytes = cookie_str.as_bytes();
    // Negotiation Request: type(1) + flags(1) + length(2) + protocols(4) = 8
    let x224_payload_len = 6 + cookie_bytes.len() + 8; // 6 = CR fields after length
    let tpkt_len = 4 + 1 + x224_payload_len; // TPKT(4) + LI(1) + payload

    let mut pdu = Vec::with_capacity(tpkt_len);
    // TPKT header
    pdu.extend_from_slice(&[TPKT_VERSION, 0, (tpkt_len >> 8) as u8, tpkt_len as u8]);
    // X.224 CR
    pdu.push(x224_payload_len as u8); // length indicator
    pdu.push(X224_TYPE_CR);
    pdu.extend_from_slice(&[0, 0, 0, 0, 0]); // dst-ref(2) + src-ref(2) + class(1)
    pdu.extend_from_slice(cookie_bytes);
    // RDP Negotiation Request
    pdu.push(RDP_NEG_REQ);
    pdu.push(0x00); // flags
    pdu.extend_from_slice(&8u16.to_le_bytes()); // length = 8
    pdu.extend_from_slice(&protocols.to_le_bytes());
    pdu
}

fn parse_x224_cc(data: &[u8]) -> Result<u32> {
    if data.len() < 11 {
        return Err(anyhow!("CC too short ({}B)", data.len()));
    }
    if data[0] != TPKT_VERSION {
        return Err(anyhow!("Bad TPKT version 0x{:02x}", data[0]));
    }
    let tpkt_len = ((data[2] as usize) << 8) | data[3] as usize;
    if data.len() < tpkt_len {
        return Err(anyhow!("Truncated CC"));
    }
    if data[5] & 0xF0 != X224_TYPE_CC {
        return Err(anyhow!("Not CC (type=0x{:02x})", data[5]));
    }
    // Check for negotiation response (last 8 bytes of TPKT)
    if tpkt_len >= 19 && data.len() >= tpkt_len {
        let off = tpkt_len - 8;
        if off + 8 <= data.len() {
            if data[off] == RDP_NEG_RSP {
                return Ok(u32::from_le_bytes([
                    data[off + 4], data[off + 5], data[off + 6], data[off + 7],
                ]));
            } else if data[off] == RDP_NEG_FAILURE {
                let failure_code = u32::from_le_bytes([
                    data[off + 4], data[off + 5], data[off + 6], data[off + 7],
                ]);
                return Err(anyhow!("Server rejected negotiation (failure code: 0x{:08x})", failure_code));
            }
        }
    }
    Ok(PROTO_RDP)
}

// ============================================================================
// TLS Upgrade
// ============================================================================

async fn tls_upgrade(
    stream: TcpStream,
    addr: &str,
    timeout_duration: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = crate::native::async_tls::make_dangerous_tls_connector();
    // Extract host — handle IPv6 bracket notation like [::1]:3389
    let host = if addr.starts_with('[') {
        addr.split(']').next().unwrap_or("localhost").trim_start_matches('[')
    } else {
        addr.split(':').next().unwrap_or("localhost")
    };
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
        .map_err(|_| anyhow!("Invalid server name"))?;

    match timeout(timeout_duration, connector.connect(server_name, stream)).await {
        Ok(Ok(tls)) => Ok(tls),
        Ok(Err(e)) => Err(anyhow!("TLS handshake failed: {}", e)),
        Err(_) => Err(anyhow!("TLS handshake timeout")),
    }
}

// ============================================================================
// CredSSP + NTLM Authentication
// ============================================================================

async fn credssp_authenticate<S>(
    mut stream: S,
    user: &str,
    pass: &str,
    timeout_duration: Duration,
) -> Result<RdpLoginResult>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Step 1: Send TSRequest with NTLM Negotiate (Type 1)
    let ntlm_negotiate = build_ntlm_negotiate();
    let spnego_init = wrap_spnego_init(&ntlm_negotiate);
    let ts_req1 = build_ts_request(6, Some(&spnego_init), None, None);

    if timeout(timeout_duration, stream.write_all(&ts_req1)).await.is_err() {
        return Ok(RdpLoginResult::ConnectionFailed("CredSSP write timeout".into()));
    }

    // Step 2: Read TSRequest with NTLM Challenge (Type 2)
    let mut buf = vec![0u8; 8192];
    let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => return Ok(RdpLoginResult::ConnectionFailed("Empty CredSSP response".into())),
        Ok(Err(e)) => return Ok(RdpLoginResult::ProtocolError(format!("CredSSP read: {}", e))),
        Err(_) => return Ok(RdpLoginResult::ConnectionFailed("CredSSP read timeout".into())),
    };

    let ts_resp = match parse_ts_request(&buf[..n]) {
        Ok(r) => r,
        Err(e) => return Ok(RdpLoginResult::ProtocolError(format!("TSRequest parse: {}", e))),
    };

    // Check for error code → auth failed
    if let Some(err_code) = ts_resp.error_code {
        if err_code != 0 {
            return Ok(RdpLoginResult::AuthFailed);
        }
    }

    let nego_token = match ts_resp.nego_tokens {
        Some(t) => t,
        None => return Ok(RdpLoginResult::ProtocolError("No negoToken in challenge".into())),
    };

    // Unwrap SPNEGO to get NTLM Challenge
    let ntlm_challenge_bytes = unwrap_spnego_response(&nego_token)
        .unwrap_or(nego_token.clone());

    let challenge = match parse_ntlm_challenge(&ntlm_challenge_bytes) {
        Ok(c) => c,
        Err(e) => return Ok(RdpLoginResult::ProtocolError(format!("NTLM challenge: {}", e))),
    };

    // Step 3: Build NTLM Authenticate (Type 3) and send
    let ntlm_auth = build_ntlm_authenticate(user, pass, "", &challenge);
    let spnego_resp = wrap_spnego_response(&ntlm_auth);
    let ts_req3 = build_ts_request(6, Some(&spnego_resp), None, None);

    if timeout(timeout_duration, stream.write_all(&ts_req3)).await.is_err() {
        return Ok(RdpLoginResult::ConnectionFailed("CredSSP auth write timeout".into()));
    }

    // Step 4: Read final response
    let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        // Connection closed = auth failed (server drops connection on bad creds)
        Ok(Ok(_)) => return Ok(RdpLoginResult::AuthFailed),
        Ok(Err(_)) => return Ok(RdpLoginResult::AuthFailed),
        Err(_) => return Ok(RdpLoginResult::AuthFailed),
    };

    // Parse final TSRequest
    match parse_ts_request(&buf[..n]) {
        Ok(resp) => {
            if let Some(err) = resp.error_code {
                if err != 0 {
                    return Ok(RdpLoginResult::AuthFailed);
                }
            }
            // If we get pubKeyAuth back → success
            if resp.pub_key_auth.is_some() {
                return Ok(RdpLoginResult::Success);
            }
            // If we get negoTokens back, check for SPNEGO accept
            if resp.nego_tokens.is_some() {
                // Server sent more negotiation → could be success continuation
                return Ok(RdpLoginResult::Success);
            }
            Ok(RdpLoginResult::AuthFailed)
        }
        Err(_) => Ok(RdpLoginResult::AuthFailed),
    }
}

// ============================================================================
// NTLM Message Building
// ============================================================================

fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn build_ntlm_negotiate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(40);
    msg.extend_from_slice(NTLMSSP_SIG);
    msg.extend_from_slice(&1u32.to_le_bytes()); // Type 1
    msg.extend_from_slice(&NTLM_FLAGS.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]); // DomainName (empty)
    msg.extend_from_slice(&[0u8; 8]); // Workstation (empty)
    msg
}

struct NtlmChallenge {
    flags: u32,
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
}

fn parse_ntlm_challenge(data: &[u8]) -> Result<NtlmChallenge> {
    if data.len() < 32 { return Err(anyhow!("Challenge too short")); }
    if &data[0..8] != NTLMSSP_SIG { return Err(anyhow!("Bad NTLMSSP sig")); }
    if u32::from_le_bytes([data[8], data[9], data[10], data[11]]) != 2 {
        return Err(anyhow!("Not Type 2"));
    }
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    let mut target_info = Vec::new();
    if data.len() >= 48 {
        let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let ti_off = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        if ti_off + ti_len <= data.len() {
            target_info = data[ti_off..ti_off + ti_len].to_vec();
        }
    }
    Ok(NtlmChallenge { flags, server_challenge, target_info })
}

fn build_ntlm_authenticate(user: &str, pass: &str, domain: &str, ch: &NtlmChallenge) -> Vec<u8> {
    // NT Hash = MD4(UTF16LE(password))
    let nt_hash = md4_hash(&to_utf16le(pass));
    // ResponseKeyNT = HMAC_MD5(NT_Hash, UTF16LE(UPPER(user) + domain))
    let identity = format!("{}{}", user.to_uppercase(), domain);
    let response_key = hmac_md5(&nt_hash, &to_utf16le(&identity));

    // Client blob
    let client_challenge: [u8; 8] = rand::random();
    let timestamp = windows_filetime_now();
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&timestamp);
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&[0x00; 4]);
    blob.extend_from_slice(&ch.target_info);
    blob.extend_from_slice(&[0x00; 4]);

    // NTProofStr + blob
    let mut proof_input = ch.server_challenge.to_vec();
    proof_input.extend_from_slice(&blob);
    let nt_proof = hmac_md5(&response_key, &proof_input);
    let mut nt_response = nt_proof.to_vec();
    nt_response.extend_from_slice(&blob);

    let lm_response = vec![0u8; 24];
    let domain_b = to_utf16le(domain);
    let user_b = to_utf16le(user);
    let ws_b = to_utf16le("RST");

    let base: u32 = 88;
    let lm_off = base;
    let nt_off = lm_off + lm_response.len() as u32;
    let dom_off = nt_off + nt_response.len() as u32;
    let usr_off = dom_off + domain_b.len() as u32;
    let ws_off = usr_off + user_b.len() as u32;
    let sk_off = ws_off + ws_b.len() as u32;

    let mut msg = Vec::new();
    msg.extend_from_slice(NTLMSSP_SIG);
    msg.extend_from_slice(&3u32.to_le_bytes()); // Type 3

    // Security buffer fields: Len(2) + MaxLen(2) + Offset(4)
    fn push_secbuf(v: &mut Vec<u8>, len: u16, off: u32) {
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&off.to_le_bytes());
    }
    push_secbuf(&mut msg, lm_response.len() as u16, lm_off);
    push_secbuf(&mut msg, nt_response.len() as u16, nt_off);
    push_secbuf(&mut msg, domain_b.len() as u16, dom_off);
    push_secbuf(&mut msg, user_b.len() as u16, usr_off);
    push_secbuf(&mut msg, ws_b.len() as u16, ws_off);
    push_secbuf(&mut msg, 0, sk_off); // EncryptedRandomSessionKey (empty)
    msg.extend_from_slice(&ch.flags.to_le_bytes());

    // Pad to base offset
    while msg.len() < base as usize { msg.push(0); }

    // Payloads in order
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_b);
    msg.extend_from_slice(&user_b);
    msg.extend_from_slice(&ws_b);
    msg
}

fn windows_filetime_now() -> [u8; 8] {
    // Windows FILETIME: 100ns intervals since 1601-01-01
    // Unix epoch offset: 116444736000000000
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ft = (now.as_nanos() / 100) as u64 + 116_444_736_000_000_000u64;
    ft.to_le_bytes()
}

// ============================================================================
// Inline MD4 (RFC 1320) - for NTLM NT password hash
// ============================================================================

fn md4_hash(data: &[u8]) -> [u8; 16] {
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a, mut b, mut c, mut d) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    for block in msg.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([block[i*4], block[i*4+1], block[i*4+2], block[i*4+3]]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);

        macro_rules! round1 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = ($a.wrapping_add(($b & $c) | (!$b & $d)).wrapping_add(x[$k])).rotate_left($s);
            };
        }
        round1!(a,b,c,d,0,3);  round1!(d,a,b,c,1,7);  round1!(c,d,a,b,2,11);  round1!(b,c,d,a,3,19);
        round1!(a,b,c,d,4,3);  round1!(d,a,b,c,5,7);  round1!(c,d,a,b,6,11);  round1!(b,c,d,a,7,19);
        round1!(a,b,c,d,8,3);  round1!(d,a,b,c,9,7);  round1!(c,d,a,b,10,11); round1!(b,c,d,a,11,19);
        round1!(a,b,c,d,12,3); round1!(d,a,b,c,13,7); round1!(c,d,a,b,14,11); round1!(b,c,d,a,15,19);

        macro_rules! round2 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = ($a.wrapping_add(($b & $c) | ($b & $d) | ($c & $d)).wrapping_add(x[$k]).wrapping_add(0x5A827999)).rotate_left($s);
            };
        }
        round2!(a,b,c,d,0,3);  round2!(d,a,b,c,4,5);  round2!(c,d,a,b,8,9);   round2!(b,c,d,a,12,13);
        round2!(a,b,c,d,1,3);  round2!(d,a,b,c,5,5);  round2!(c,d,a,b,9,9);   round2!(b,c,d,a,13,13);
        round2!(a,b,c,d,2,3);  round2!(d,a,b,c,6,5);  round2!(c,d,a,b,10,9);  round2!(b,c,d,a,14,13);
        round2!(a,b,c,d,3,3);  round2!(d,a,b,c,7,5);  round2!(c,d,a,b,11,9);  round2!(b,c,d,a,15,13);

        macro_rules! round3 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = ($a.wrapping_add($b ^ $c ^ $d).wrapping_add(x[$k]).wrapping_add(0x6ED9EBA1)).rotate_left($s);
            };
        }
        round3!(a,b,c,d,0,3);  round3!(d,a,b,c,8,9);  round3!(c,d,a,b,4,11);  round3!(b,c,d,a,12,15);
        round3!(a,b,c,d,2,3);  round3!(d,a,b,c,10,9); round3!(c,d,a,b,6,11);  round3!(b,c,d,a,14,15);
        round3!(a,b,c,d,1,3);  round3!(d,a,b,c,9,9);  round3!(c,d,a,b,5,11);  round3!(b,c,d,a,13,15);
        round3!(a,b,c,d,3,3);  round3!(d,a,b,c,11,9); round3!(c,d,a,b,7,11);  round3!(b,c,d,a,15,15);

        a = a.wrapping_add(aa); b = b.wrapping_add(bb);
        c = c.wrapping_add(cc); d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

// ============================================================================
// Inline HMAC-MD5 - for NTLMv2
// ============================================================================

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let h = md5::compute(key);
        key_block[..16].copy_from_slice(&h.0);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= key_block[i]; opad[i] ^= key_block[i]; }

    let mut inner = ipad.to_vec();
    inner.extend_from_slice(data);
    let inner_hash = md5::compute(&inner);

    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash.0);
    md5::compute(&outer).0
}

// ============================================================================
// CredSSP TSRequest ASN.1 (minimal BER)
// ============================================================================

struct TsRequestData {
    nego_tokens: Option<Vec<u8>>,
    auth_info: Option<Vec<u8>>,
    pub_key_auth: Option<Vec<u8>>,
    error_code: Option<i64>,
}

fn ber_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else if len < 0x1000000 {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn ber_read_len(data: &[u8], pos: &mut usize) -> usize {
    if *pos >= data.len() { return 0; }
    let b = data[*pos]; *pos += 1;
    if b < 0x80 { return b as usize; }
    let nb = (b & 0x7f) as usize;
    let mut val = 0usize;
    for _ in 0..nb {
        if *pos >= data.len() { return 0; }
        val = (val << 8) | data[*pos] as usize;
        *pos += 1;
    }
    val
}

fn build_ts_request(version: u32, nego: Option<&[u8]>, auth: Option<&[u8]>, pubkey: Option<&[u8]>) -> Vec<u8> {
    let mut inner = Vec::new();

    // version [0] INTEGER
    let ver_bytes = encode_ber_int(version as i64);
    let mut ver_val = vec![0x02]; // INTEGER tag
    ber_len(&mut ver_val, ver_bytes.len());
    ver_val.extend(&ver_bytes);
    let mut ver_ctx = vec![0xA0]; // [0]
    ber_len(&mut ver_ctx, ver_val.len());
    ver_ctx.extend(ver_val);
    inner.extend(ver_ctx);

    // negoTokens [1]
    if let Some(token) = nego {
        let mut octet = vec![0x04]; ber_len(&mut octet, token.len()); octet.extend(token);
        let mut ctx0 = vec![0xA0]; ber_len(&mut ctx0, octet.len()); ctx0.extend(octet);
        let mut seq1 = vec![0x30]; ber_len(&mut seq1, ctx0.len()); seq1.extend(ctx0);
        let mut seqof = vec![0x30]; ber_len(&mut seqof, seq1.len()); seqof.extend(seq1);
        let mut ctx1 = vec![0xA1]; ber_len(&mut ctx1, seqof.len()); ctx1.extend(seqof);
        inner.extend(ctx1);
    }

    if let Some(a) = auth {
        let mut octet = vec![0x04]; ber_len(&mut octet, a.len()); octet.extend(a);
        let mut ctx2 = vec![0xA2]; ber_len(&mut ctx2, octet.len()); ctx2.extend(octet);
        inner.extend(ctx2);
    }

    if let Some(pk) = pubkey {
        let mut octet = vec![0x04]; ber_len(&mut octet, pk.len()); octet.extend(pk);
        let mut ctx3 = vec![0xA3]; ber_len(&mut ctx3, octet.len()); ctx3.extend(octet);
        inner.extend(ctx3);
    }

    let mut result = vec![0x30]; // SEQUENCE
    ber_len(&mut result, inner.len());
    result.extend(inner);
    result
}

fn parse_ts_request(data: &[u8]) -> Result<TsRequestData> {
    let mut pos = 0;
    if pos >= data.len() || data[pos] != 0x30 { return Err(anyhow!("Not a SEQUENCE")); }
    pos += 1;
    let _seq_len = ber_read_len(data, &mut pos);

    let mut result = TsRequestData {
        nego_tokens: None, auth_info: None, pub_key_auth: None, error_code: None,
    };

    while pos < data.len() {
        let tag = data[pos]; pos += 1;
        let field_len = ber_read_len(data, &mut pos);
        if pos + field_len > data.len() { break; }
        let field_data = &data[pos..pos + field_len];

        match tag {
            0xA0 => { /* version - skip */ }
            0xA1 => {
                // negoTokens: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
                // Drill down to get the OCTET STRING content
                result.nego_tokens = Some(extract_nested_octet(field_data));
            }
            0xA2 => {
                result.auth_info = Some(extract_octet(field_data));
            }
            0xA3 => {
                result.pub_key_auth = Some(extract_octet(field_data));
            }
            0xA4 => {
                // errorCode: INTEGER
                if let Some(val) = extract_integer(field_data) {
                    result.error_code = Some(val);
                }
            }
            _ => {}
        }
        pos += field_len;
    }
    Ok(result)
}

fn extract_octet(data: &[u8]) -> Vec<u8> {
    let mut pos = 0;
    if pos < data.len() && data[pos] == 0x04 {
        pos += 1;
        let len = ber_read_len(data, &mut pos);
        if pos + len <= data.len() {
            return data[pos..pos + len].to_vec();
        }
    }
    data.to_vec()
}

fn extract_nested_octet(data: &[u8]) -> Vec<u8> {
    // Drill: SEQUENCE { SEQUENCE { [0] OCTET_STRING { ... } } }
    let mut pos = 0;
    // Skip SEQUENCE tags
    for _ in 0..3 {
        if pos >= data.len() { return data.to_vec(); }
        let tag = data[pos];
        if tag == 0x30 || tag == 0xA0 || tag == 0x04 {
            pos += 1;
            let _len = ber_read_len(data, &mut pos);
            if tag == 0x04 {
                let remaining = data.len() - pos;
                let actual_len = _len.min(remaining);
                return data[pos..pos + actual_len].to_vec();
            }
        } else {
            break;
        }
    }
    data.to_vec()
}

fn extract_integer(data: &[u8]) -> Option<i64> {
    let mut pos = 0;
    if pos < data.len() && data[pos] == 0x02 {
        pos += 1;
        let len = ber_read_len(data, &mut pos);
        if len == 0 || pos + len > data.len() { return None; }
        // Sign-extend: if first byte has high bit set, the value is negative
        let mut val: i64 = if data[pos] & 0x80 != 0 { -1 } else { 0 };
        for i in 0..len {
            val = (val << 8) | data[pos + i] as i64;
        }
        return Some(val);
    }
    None
}

fn encode_ber_int(val: i64) -> Vec<u8> {
    if val == 0 { return vec![0x00]; }
    let bytes = val.to_be_bytes();
    if val > 0 {
        // Skip leading zero bytes, but keep a 0x00 prefix if high bit is set
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        if bytes[start] & 0x80 != 0 {
            let mut r = vec![0x00];
            r.extend_from_slice(&bytes[start..]);
            r
        } else {
            bytes[start..].to_vec()
        }
    } else {
        // Negative: skip leading 0xFF bytes, but keep one if next byte's high bit is 0
        let start = bytes.iter().position(|&b| b != 0xFF).unwrap_or(7);
        if bytes[start] & 0x80 == 0 {
            let mut r = vec![0xFF];
            r.extend_from_slice(&bytes[start..]);
            r
        } else {
            bytes[start..].to_vec()
        }
    }
}

// ============================================================================
// SPNEGO Wrapping (minimal - just enough for NTLM transport)
// ============================================================================

fn wrap_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    // SPNEGO OID
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    // NTLM OID
    let ntlm_oid: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

    // mechToken [2] OCTET STRING
    let mut mech_token = vec![0xA2];
    let mut mt_octet = vec![0x04]; ber_len(&mut mt_octet, ntlm_token.len()); mt_octet.extend(ntlm_token);
    ber_len(&mut mech_token, mt_octet.len()); mech_token.extend(mt_octet);

    // mechTypes [0] SEQUENCE
    let mut mech_types_seq = vec![0x30]; ber_len(&mut mech_types_seq, ntlm_oid.len()); mech_types_seq.extend(ntlm_oid);
    let mut mech_types = vec![0xA0]; ber_len(&mut mech_types, mech_types_seq.len()); mech_types.extend(mech_types_seq);

    // NegTokenInit SEQUENCE
    let mut neg_init_inner: Vec<u8> = Vec::new();
    neg_init_inner.extend(&mech_types);
    neg_init_inner.extend(&mech_token);
    let mut neg_init = vec![0xA0]; // [0] constructed
    let mut neg_init_seq = vec![0x30]; ber_len(&mut neg_init_seq, neg_init_inner.len()); neg_init_seq.extend(neg_init_inner);
    ber_len(&mut neg_init, neg_init_seq.len()); neg_init.extend(neg_init_seq);

    // Application [0] { OID + NegTokenInit }
    let mut app_inner: Vec<u8> = Vec::new();
    app_inner.extend(spnego_oid);
    app_inner.extend(&neg_init);
    let mut result = vec![0x60]; // Application [0]
    ber_len(&mut result, app_inner.len());
    result.extend(app_inner);
    result
}

fn wrap_spnego_response(ntlm_token: &[u8]) -> Vec<u8> {
    // NegTokenResp [1] SEQUENCE { responseToken [2] OCTET STRING }
    let mut rt_octet = vec![0x04]; ber_len(&mut rt_octet, ntlm_token.len()); rt_octet.extend(ntlm_token);
    let mut rt = vec![0xA2]; ber_len(&mut rt, rt_octet.len()); rt.extend(rt_octet);
    let mut seq = vec![0x30]; ber_len(&mut seq, rt.len()); seq.extend(rt);
    let mut result = vec![0xA1]; // [1] constructed
    ber_len(&mut result, seq.len());
    result.extend(seq);
    result
}

fn unwrap_spnego_response(data: &[u8]) -> Option<Vec<u8>> {
    // Try to find the NTLM token inside SPNEGO response
    // Look for NTLMSSP signature anywhere in the data
    if let Some(idx) = data.windows(8).position(|w| w == NTLMSSP_SIG) {
        return Some(data[idx..].to_vec());
    }
    None
}
