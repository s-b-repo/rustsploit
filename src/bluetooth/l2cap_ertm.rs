//! L2CAP Enhanced Retransmission Mode (ERTM) — Core Specification Vol 3, Part A §5.
//!
//! Basic Mode (what the framework's `L2capChannel` speaks) has no
//! segmentation and no flow control: an SDU larger than the MTU simply
//! cannot be sent, and the channel stalls if the peer is slow. ERTM fixes
//! both, and the fix is what a heap-spray style attack needs: ERTM lets a
//! sender push a LARGE SDU as a sequence of fragments, each of which the
//! peer allocates and copies separately. That is the primitive behind
//! "BlueBlue"-class Android Fluoride attacks, where a fragmented
//! configuration request is used to shape the peer's heap before the
//! overflow.
//!
//! This module is the wire half:
//!   - building the `L2CAP_CONFIG_REQ` that negotiates ERTM and the MTU
//!   - parsing the peer's configuration response
//!   - framing and segmenting SDUs with the FCR header
//!   - reassembling received fragments
//!
//! It is a pure codec — no I/O — so it is unit-testable.

use anyhow::{Result, anyhow};

/// L2CAP signalling command codes.
pub const L2CAP_CONN_REQ: u8 = 0x02;
pub const L2CAP_CONFIG_REQ: u8 = 0x04;
pub const L2CAP_CONFIG_RSP: u8 = 0x05;
pub const L2CAP_DISCONNECT_REQ: u8 = 0x06;

/// L2CAP configuration option types.
pub const L2CAP_OPT_MTU: u8 = 0x01;
pub const L2CAP_OPT_FLUSH_TIMEOUT: u8 = 0x02;
pub const L2CAP_OPT_TX_WINDOW: u8 = 0x03;
pub const L2CAP_OPT_MAX_TRANSMIT: u8 = 0x04;
pub const L2CAP_OPT_ACK_DELAY: u8 = 0x05;
pub const L2CAP_OPT_RECEIVE_MTU: u8 = 0x06;
pub const L2CAP_OPT_ERTM: u8 = 0x07;

/// The L2CAP signalling MTU — the size of a configuration PDU.
pub const L2CAP_SIGNALLING_MTU: u16 = 1024;
/// The smallest MTU ERTM permits.
pub const ERTM_MIN_MTU: u16 = 64;
/// The FCR header is 2 bytes on every fragment.
pub const FCR_HEADER_LEN: usize = 2;

/// Segmentation-and-reassembly values (Vol 3, Part A, Table 11.2).
pub const SAR_CONTINUATION: u8 = 0b000;
pub const SAR_FIRST: u8 = 0b001;
pub const SAR_COMPLETE: u8 = 0b010;
pub const SAR_COMPLETE_L2CAP: u8 = 0b011;

/// The negotiated ERTM parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErtmConfig {
    /// The peer's receive MTU — the largest fragment payload we may send.
    pub receive_mtu: u16,
    /// The peer's transmit window.
    pub tx_window: u16,
    /// The peer's maximum transmit count.
    pub max_transmit: u8,
    /// Whether the peer accepted ERTM at all.
    pub ertm_enabled: bool,
}

impl Default for ErtmConfig {
    fn default() -> Self {
        Self {
            receive_mtu: L2CAP_SIGNALLING_MTU,
            tx_window: 8,
            max_transmit: 8,
            ertm_enabled: false,
        }
    }
}

/// Build one L2CAP configuration option.
fn option(option_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(option_type);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

/// Build the `L2CAP_CONFIG_REQ` that negotiates ERTM.
///
/// The option order matters to some stacks: MTU, then the ERTM flag, then
/// the retransmission parameters. A peer that does not understand ERTM
/// simply omits the option from its response, which
/// [`parse_config_response`] reports as `ertm_enabled = false`.
pub fn build_ertm_config_request(src_cid: u16, mtu: u16) -> Vec<u8> {
    let mtu = mtu.clamp(ERTM_MIN_MTU, L2CAP_SIGNALLING_MTU);
    let mut options = Vec::new();
    options.extend(option(L2CAP_OPT_MTU, &mtu.to_le_bytes()));
    // ERTM enabled.
    options.extend(option(L2CAP_OPT_ERTM, &[0x01]));
    // Flush timeout: infinite.
    options.extend(option(L2CAP_OPT_FLUSH_TIMEOUT, &0xFFFFu16.to_le_bytes()));
    // Transmit window.
    options.extend(option(L2CAP_OPT_TX_WINDOW, &8u16.to_le_bytes()));
    // Maximum transmit.
    options.extend(option(L2CAP_OPT_MAX_TRANSMIT, &[8]));
    // Acknowledgement delay.
    options.extend(option(L2CAP_OPT_ACK_DELAY, &0u16.to_le_bytes()));

    let mut sig = Vec::with_capacity(4 + options.len());
    sig.push(L2CAP_CONFIG_REQ);
    sig.push(0x11); // identifier
    sig.extend_from_slice(&src_cid.to_le_bytes());
    sig.extend_from_slice(&0x0000u16.to_le_bytes()); // flags: continuation
    sig.extend_from_slice(&options);
    sig
}

/// Parse a `L2CAP_CONFIG_RSP` into the negotiated ERTM parameters.
pub fn parse_config_response(pdu: &[u8]) -> Result<ErtmConfig> {
    let mut cfg = ErtmConfig::default();
    if pdu.len() < 4 {
        return Err(anyhow!(
            "L2CAP config response too short: {} bytes",
            pdu.len()
        ));
    }
    if pdu[0] != L2CAP_CONFIG_RSP {
        return Err(anyhow!(
            "not an L2CAP config response (code 0x{:02X})",
            pdu[0]
        ));
    }
    // Skip: code(1) id(1) src_cid(2) flags(2) → options start at 6.
    let options = pdu.get(6..).unwrap_or(&[]);
    let mut offset = 0usize;
    while offset + 2 <= options.len() {
        let opt_type = options[offset];
        let opt_len = options[offset + 1] as usize;
        let value = options
            .get(offset + 2..offset + 2 + opt_len)
            .ok_or_else(|| anyhow!("L2CAP config option truncated"))?;
        match opt_type {
            L2CAP_OPT_MTU | L2CAP_OPT_RECEIVE_MTU => {
                if value.len() >= 2 {
                    let mtu = u16::from_le_bytes([value[0], value[1]]);
                    if opt_type == L2CAP_OPT_MTU {
                        cfg.receive_mtu = mtu;
                    } else {
                        cfg.receive_mtu = mtu;
                    }
                }
            }
            L2CAP_OPT_TX_WINDOW => {
                if value.len() >= 2 {
                    cfg.tx_window = u16::from_le_bytes([value[0], value[1]]);
                }
            }
            L2CAP_OPT_MAX_TRANSMIT => {
                if !value.is_empty() {
                    cfg.max_transmit = value[0];
                }
            }
            L2CAP_OPT_ERTM => {
                // The option is present with value 1 when ERTM is enabled.
                cfg.ertm_enabled = value.first().map(|v| *v != 0).unwrap_or(false);
            }
            _ => {}
        }
        offset += 2 + opt_len;
    }
    Ok(cfg)
}

/// Build the 2-byte FCR header that prefixes every ERTM fragment.
///
/// Layout (Vol 3, Part A, §5.1): `SAR(3) | reqseq(6) | txseq(6) | FCS(1)`.
pub fn fcr_header(sar: u8, reqseq: u8, txseq: u8) -> [u8; 2] {
    let word =
        ((sar as u16 & 0x07) << 13) | ((reqseq as u16 & 0x3F) << 7) | ((txseq as u16 & 0x3F) << 1);
    word.to_be_bytes()
}

/// Split the FCR header back into its fields.
pub fn parse_fcr_header(header: [u8; 2]) -> (u8, u8, u8) {
    let word = u16::from_be_bytes(header);
    (
        ((word >> 13) & 0x07) as u8,
        ((word >> 7) & 0x3F) as u8,
        ((word >> 1) & 0x3F) as u8,
    )
}

/// Segment an SDU into ERTM fragments.
///
/// Each fragment is `FCR header(2) | payload`. The first fragment carries
/// `SAR_FIRST`, the last carries `SAR_COMPLETE`, and the ones in between
/// carry `SAR_CONTINUATION`. The payload of each fragment is at most
/// `receive_mtu - FCR_HEADER_LEN` bytes, because the FCR header counts
/// against the MTU.
///
/// Returns the fragments in order.
pub fn segment_sdu(sdu: &[u8], receive_mtu: u16) -> Result<Vec<Vec<u8>>> {
    let payload_max = (receive_mtu as usize).saturating_sub(FCR_HEADER_LEN).max(1);
    if sdu.is_empty() {
        return Err(anyhow!("cannot segment an empty SDU"));
    }
    if sdu.len() <= payload_max {
        let mut frag = Vec::with_capacity(FCR_HEADER_LEN + sdu.len());
        frag.extend_from_slice(&fcr_header(SAR_COMPLETE, 0, 0));
        frag.extend_from_slice(sdu);
        return Ok(vec![frag]);
    }

    // Split the payload into chunks FIRST, so the last one can be marked
    // SAR_COMPLETE. A trailing SAR_CONTINUATION would leave the peer waiting
    // for a fragment that never arrives — the SDU would never complete.
    let mut chunks: Vec<&[u8]> = Vec::new();
    let mut offset = 0usize;
    while offset < sdu.len() {
        let end = (offset + payload_max).min(sdu.len());
        chunks.push(&sdu[offset..end]);
        offset = end;
    }

    let last = chunks.len() - 1;
    let mut fragments = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.iter().enumerate() {
        let txseq = match u8::try_from(idx) {
            Ok(v) => v,
            Err(_) => u8::MAX,
        };
        let sar = if idx == 0 {
            SAR_FIRST
        } else if idx == last {
            SAR_COMPLETE
        } else {
            SAR_CONTINUATION
        };
        let mut frag = Vec::with_capacity(FCR_HEADER_LEN + chunk.len());
        frag.extend_from_slice(&fcr_header(sar, 0, txseq));
        frag.extend_from_slice(chunk);
        fragments.push(frag);
    }
    Ok(fragments)
}

/// A reassembly buffer for received ERTM fragments.
#[derive(Debug, Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    active: bool,
}

impl Reassembler {
    /// A fresh reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one received fragment.
    ///
    /// Returns the complete SDU once the final fragment arrives, and `None`
    /// while the SDU is still incomplete.
    pub fn push(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>> {
        if fragment.len() < FCR_HEADER_LEN {
            return Err(anyhow!("ERTM fragment shorter than the FCR header"));
        }
        let header = [fragment[0], fragment[1]];
        let (sar, _reqseq, _txseq) = parse_fcr_header(header);
        let payload = &fragment[FCR_HEADER_LEN..];
        match sar {
            SAR_COMPLETE | SAR_COMPLETE_L2CAP => {
                // The final fragment carries the tail of the SDU. It must be
                // APPENDED to what came before, not replace it — returning
                // only the last chunk would silently truncate the SDU.
                self.buffer.extend_from_slice(payload);
                self.active = false;
                let out = std::mem::take(&mut self.buffer);
                return Ok(Some(out));
            }
            SAR_FIRST => {
                self.buffer.clear();
                self.buffer.extend_from_slice(payload);
                self.active = true;
                Ok(None)
            }
            SAR_CONTINUATION => {
                if !self.active {
                    return Err(anyhow!(
                        "ERTM continuation fragment with no preceding first fragment"
                    ));
                }
                self.buffer.extend_from_slice(payload);
                Ok(None)
            }
            other => Err(anyhow!("unknown ERTM SAR value {other}")),
        }
    }

    /// Is a partially reassembled SDU in flight?
    pub fn in_progress(&self) -> bool {
        self.active
    }

    /// The bytes received so far for the SDU in flight.
    pub fn pending_len(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_request_carries_the_ertm_option() {
        let pdu = build_ertm_config_request(0x0040, 1024);
        assert_eq!(pdu[0], L2CAP_CONFIG_REQ);
        // The ERTM option (type 0x07) must be present.
        let text = pdu.windows(1).any(|w| w == [L2CAP_OPT_ERTM]);
        assert!(text, "ERTM option missing from the config request");
    }

    #[test]
    fn config_response_reports_ertm_and_the_mtu() {
        // code(1)=0x05 id(1) src_cid(2) flags(2) then options.
        let mut pdu = vec![L2CAP_CONFIG_RSP, 0x11, 0x40, 0x00, 0x00, 0x00];
        pdu.extend(option(L2CAP_OPT_MTU, &1024u16.to_le_bytes()));
        pdu.extend(option(L2CAP_OPT_ERTM, &[0x01]));
        pdu.extend(option(L2CAP_OPT_TX_WINDOW, &8u16.to_le_bytes()));
        pdu.extend(option(L2CAP_OPT_MAX_TRANSMIT, &[8]));
        let cfg = parse_config_response(&pdu).expect("should parse");
        assert!(cfg.ertm_enabled);
        assert_eq!(cfg.receive_mtu, 1024);
        assert_eq!(cfg.tx_window, 8);
        assert_eq!(cfg.max_transmit, 8);
    }

    #[test]
    fn config_response_without_ertm_is_reported() {
        let mut pdu = vec![L2CAP_CONFIG_RSP, 0x11, 0x40, 0x00, 0x00, 0x00];
        pdu.extend(option(L2CAP_OPT_MTU, &1024u16.to_le_bytes()));
        let cfg = parse_config_response(&pdu).expect("should parse");
        assert!(!cfg.ertm_enabled);
    }

    #[test]
    fn fcr_header_round_trips() {
        let h = fcr_header(SAR_FIRST, 0x2A, 0x15);
        let (sar, reqseq, txseq) = parse_fcr_header(h);
        assert_eq!(sar, SAR_FIRST);
        assert_eq!(reqseq, 0x2A);
        assert_eq!(txseq, 0x15);
    }

    #[test]
    fn a_small_sdu_is_one_complete_fragment() {
        let frags = segment_sdu(b"hello", 1024).expect("should segment");
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0][0] >> 5, SAR_COMPLETE);
        assert_eq!(&frags[0][FCR_HEADER_LEN..], b"hello");
    }

    #[test]
    fn a_large_sdu_is_segmented_and_reassembles() {
        // MTU 64 → 62-byte payloads.
        let sdu: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let frags = segment_sdu(&sdu, 64).expect("should segment");
        assert!(frags.len() > 1, "expected multiple fragments");
        for f in &frags {
            assert!(f.len() <= 64, "fragment exceeded the MTU");
        }

        let mut reasm = Reassembler::new();
        let mut out = None;
        for f in &frags {
            if let Some(done) = reasm.push(f).expect("should reassemble") {
                out = Some(done);
            }
        }
        assert_eq!(out.expect("should complete"), sdu);
    }

    #[test]
    fn a_continuation_without_a_first_is_an_error() {
        let mut reasm = Reassembler::new();
        let frag = [fcr_header(SAR_CONTINUATION, 0, 1).as_slice(), &[0xAA]].concat();
        assert!(reasm.push(&frag).is_err());
    }
}
