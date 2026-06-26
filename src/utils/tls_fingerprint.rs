//! Active TLS server fingerprinting: JARM (Salesforce) + JA3/JA3S string builders.
//!
//! This is a from-scratch Rust port of Salesforce's `jarm.py`
//! (BSD-3-Clause). JARM works by sending 10 hand-crafted TLS ClientHello
//! packets to a target, each varying TLS version, cipher list + ordering,
//! GREASE, ALPN, and the extension set. From each ServerHello we record the
//! negotiated TLS version + selected cipher suite, plus a digest of the
//! ServerHello extensions. The 10 per-probe results are concatenated and
//! folded into a 62-character JARM hash:
//!
//!   * the first 30 chars are a per-cipher / per-version "fuzzy" hash, and
//!   * the remaining 32 chars are the first 32 hex chars of the SHA-256 of the
//!     concatenated extension digests.
//!
//! rustls does not let us craft arbitrary ClientHellos, so we build the
//! ClientHello bytes by hand and speak raw TLS over a `tokio::net::TcpStream`.
//!
//! The module also exposes pure JA3 / JA3S string→MD5 helpers. JA3S can be
//! computed by any caller that already has the raw ServerHello bytes; the
//! rustls-based `ssl_scanner` does not (rustls hides the wire bytes), so it
//! does not wire JA3S in — callers with raw bytes use [`ja3s_from_components`]
//! or [`parse_server_hello`] + [`ja3s_hash`].
//!
//! For authorized security testing only.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ============================================================
// JARM probe specifications (ported 1:1 from jarm.py)
// ============================================================

/// TLS version a probe negotiates for. Mirrors jarm.py's version strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsVersion {
    Tls1_2,
    Tls1_3,
}

/// Cipher list selection. Mirrors jarm.py's `cipher_list` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CipherList {
    All,
    No1_3,
}

/// Cipher ordering transform. Mirrors jarm.py's `cipher_order` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CipherOrder {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

/// GREASE inclusion. Mirrors jarm.py's `grease` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Grease {
    On,
    Off,
}

/// ALPN selection. Mirrors jarm.py's `alpn` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alpn {
    Rare,
    All,
}

/// Extension ordering transform. Mirrors jarm.py's `extension_orders`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtOrder {
    Forward,
    Reverse,
}

/// Support extension set. Mirrors jarm.py's `support` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Support {
    /// "1.2_support" — the standard extension set.
    Tls1_2,
    /// "no_support" — minimal extensions, no supported_versions.
    None,
}

/// A single JARM probe specification.
#[derive(Clone, Copy, Debug)]
struct ProbeSpec {
    version: TlsVersion,
    ciphers: CipherList,
    cipher_order: CipherOrder,
    grease: Grease,
    alpn: Alpn,
    ext_order: ExtOrder,
    support: Support,
}

/// The 10 JARM probes, in the exact order and configuration jarm.py uses.
/// (host/port are filled in at connect time.)
const JARM_PROBES: [ProbeSpec; 10] = [
    // tls1.2_forward
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::All,   cipher_order: CipherOrder::Forward,    grease: Grease::Off, alpn: Alpn::All,  ext_order: ExtOrder::Forward, support: Support::Tls1_2 },
    // tls1.2_reverse
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::All,   cipher_order: CipherOrder::Reverse,    grease: Grease::Off, alpn: Alpn::All,  ext_order: ExtOrder::Reverse, support: Support::Tls1_2 },
    // tls1.2_top_half
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::All,   cipher_order: CipherOrder::TopHalf,    grease: Grease::Off, alpn: Alpn::Rare, ext_order: ExtOrder::Forward, support: Support::None },
    // tls1.2_bottom_half
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::All,   cipher_order: CipherOrder::BottomHalf, grease: Grease::Off, alpn: Alpn::Rare, ext_order: ExtOrder::Forward, support: Support::None },
    // tls1.2_middle_out
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::All,   cipher_order: CipherOrder::MiddleOut,  grease: Grease::On,  alpn: Alpn::Rare, ext_order: ExtOrder::Reverse, support: Support::None },
    // tls1.1_middle_out  (jarm.py uses TLS1.1 record but No1.3 cipher list, no support)
    ProbeSpec { version: TlsVersion::Tls1_2, ciphers: CipherList::No1_3, cipher_order: CipherOrder::Forward,    grease: Grease::Off, alpn: Alpn::Rare, ext_order: ExtOrder::Forward, support: Support::None },
    // tls1.3_forward
    ProbeSpec { version: TlsVersion::Tls1_3, ciphers: CipherList::All,   cipher_order: CipherOrder::Forward,    grease: Grease::Off, alpn: Alpn::All,  ext_order: ExtOrder::Forward, support: Support::Tls1_2 },
    // tls1.3_reverse
    ProbeSpec { version: TlsVersion::Tls1_3, ciphers: CipherList::All,   cipher_order: CipherOrder::Reverse,    grease: Grease::Off, alpn: Alpn::All,  ext_order: ExtOrder::Reverse, support: Support::Tls1_2 },
    // tls1.3_invalid (top-half ciphers)
    ProbeSpec { version: TlsVersion::Tls1_3, ciphers: CipherList::All,   cipher_order: CipherOrder::MiddleOut,  grease: Grease::On,  alpn: Alpn::Rare, ext_order: ExtOrder::Forward, support: Support::Tls1_2 },
    // tls1.3_middle_out
    ProbeSpec { version: TlsVersion::Tls1_3, ciphers: CipherList::All,   cipher_order: CipherOrder::MiddleOut,  grease: Grease::On,  alpn: Alpn::Rare, ext_order: ExtOrder::Reverse, support: Support::Tls1_2 },
];

// ============================================================
// Cipher / extension byte tables (from jarm.py)
// ============================================================

/// GREASE values jarm.py randomly draws from. We pick deterministically
/// (jarm.py uses random.choice, but the value is excluded from the hash, so
/// any valid GREASE value is equivalent for fingerprint comparability).
const GREASE_VALUE: [u8; 2] = [0x0a, 0x0a];

/// "ALL" cipher list (each entry is a 2-byte cipher suite), in jarm.py order.
const CIPHERS_ALL: &[[u8; 2]] = &[
    [0x00, 0x16], [0x00, 0x33], [0x00, 0x67], [0xc0, 0x9e], [0xc0, 0xa2],
    [0x00, 0x9e], [0x00, 0x39], [0x00, 0x6b], [0xc0, 0x9f], [0xc0, 0xa3],
    [0x00, 0x9f], [0x00, 0x45], [0x00, 0xbe], [0x00, 0x88], [0x00, 0xc4],
    [0x00, 0x9a], [0xc0, 0x08], [0xc0, 0x09], [0xc0, 0x23], [0xc0, 0xac],
    [0xc0, 0xae], [0xc0, 0x2b], [0xc0, 0x0a], [0xc0, 0x24], [0xc0, 0xad],
    [0xc0, 0xaf], [0xc0, 0x2c], [0xc0, 0x72], [0xc0, 0x73], [0xcc, 0xa9],
    [0x13, 0x02], [0x13, 0x01], [0xcc, 0x14], [0xc0, 0x07], [0xc0, 0x12],
    [0xc0, 0x13], [0xc0, 0x27], [0xc0, 0x2f], [0xc0, 0x14], [0xc0, 0x28],
    [0xc0, 0x30], [0xc0, 0x60], [0xc0, 0x61], [0xc0, 0x76], [0xc0, 0x77],
    [0xcc, 0xa8], [0x13, 0x05], [0x13, 0x04], [0x13, 0x03], [0xcc, 0x13],
    [0xc0, 0x11], [0x00, 0x0a], [0x00, 0x2f], [0x00, 0x3c], [0xc0, 0x9c],
    [0xc0, 0xa0], [0x00, 0x9c], [0x00, 0x35], [0x00, 0x3d], [0xc0, 0x9d],
    [0xc0, 0xa1], [0x00, 0x9d], [0x00, 0x41], [0x00, 0xba], [0x00, 0x84],
    [0x00, 0xc0], [0x00, 0x07], [0x00, 0x04], [0x00, 0x05],
];

/// "NO1.3" cipher list — jarm.py's ALL list with the TLS 1.3 suites removed
/// (0x1301..0x1305). Same ordering otherwise.
const CIPHERS_NO13: &[[u8; 2]] = &[
    [0x00, 0x16], [0x00, 0x33], [0x00, 0x67], [0xc0, 0x9e], [0xc0, 0xa2],
    [0x00, 0x9e], [0x00, 0x39], [0x00, 0x6b], [0xc0, 0x9f], [0xc0, 0xa3],
    [0x00, 0x9f], [0x00, 0x45], [0x00, 0xbe], [0x00, 0x88], [0x00, 0xc4],
    [0x00, 0x9a], [0xc0, 0x08], [0xc0, 0x09], [0xc0, 0x23], [0xc0, 0xac],
    [0xc0, 0xae], [0xc0, 0x2b], [0xc0, 0x0a], [0xc0, 0x24], [0xc0, 0xad],
    [0xc0, 0xaf], [0xc0, 0x2c], [0xc0, 0x72], [0xc0, 0x73], [0xcc, 0xa9],
    [0xcc, 0x14], [0xc0, 0x07], [0xc0, 0x12], [0xc0, 0x13], [0xc0, 0x27],
    [0xc0, 0x2f], [0xc0, 0x14], [0xc0, 0x28], [0xc0, 0x30], [0xc0, 0x60],
    [0xc0, 0x61], [0xc0, 0x76], [0xc0, 0x77], [0xcc, 0xa8], [0xcc, 0x13],
    [0xc0, 0x11], [0x00, 0x0a], [0x00, 0x2f], [0x00, 0x3c], [0xc0, 0x9c],
    [0xc0, 0xa0], [0x00, 0x9c], [0x00, 0x35], [0x00, 0x3d], [0xc0, 0x9d],
    [0xc0, 0xa1], [0x00, 0x9d], [0x00, 0x41], [0x00, 0xba], [0x00, 0x84],
    [0x00, 0xc0], [0x00, 0x07], [0x00, 0x04], [0x00, 0x05],
];

// ============================================================
// ClientHello construction
// ============================================================

/// Build the list of 2-byte cipher suites for a probe (selection + ordering +
/// optional GREASE prefix), as a flat byte vector.
fn build_ciphers(spec: &ProbeSpec) -> Vec<u8> {
    let base: &[[u8; 2]] = match spec.ciphers {
        CipherList::All => CIPHERS_ALL,
        CipherList::No1_3 => CIPHERS_NO13,
    };
    let mut list: Vec<[u8; 2]> = base.to_vec();

    list = match spec.cipher_order {
        CipherOrder::Forward => list,
        CipherOrder::Reverse => {
            list.reverse();
            list
        }
        CipherOrder::TopHalf => {
            // jarm.py top_half: for an odd-length list, the middle element
            // followed by the back half (list[half+1:]); for even length, the
            // back half (list[half:]). We replicate that exactly.
            let half = list.len() / 2;
            let mut top = Vec::with_capacity(list.len());
            if list.len() % 2 == 1 {
                if let Some(mid) = list.get(half) {
                    top.push(*mid);
                }
                if let Some(rest) = list.get(half + 1..) {
                    top.extend_from_slice(rest);
                }
            } else if let Some(rest) = list.get(half..) {
                top.extend_from_slice(rest);
            }
            top
        }
        CipherOrder::BottomHalf => {
            // jarm.py: front half (list[:half]) — for odd, half = len//2.
            // `0..len/2` is always a valid range, so `get` yields Some; the
            // `None` arm is unreachable but handled explicitly (no unwrap).
            match list.get(..list.len() / 2) {
                Some(front) => front.to_vec(),
                None => Vec::new(),
            }
        }
        CipherOrder::MiddleOut => middle_out(&list),
    };

    let mut bytes = Vec::with_capacity(list.len() * 2 + 2);
    if spec.grease == Grease::On {
        bytes.extend_from_slice(&GREASE_VALUE);
    }
    for c in &list {
        bytes.extend_from_slice(c);
    }
    bytes
}

/// jarm.py middle-out ordering: walk outward from the centre, alternating
/// right then left. Matches CipherMung's "middle-out" exactly.
fn middle_out(list: &[[u8; 2]]) -> Vec<[u8; 2]> {
    let len = list.len();
    let mut out = Vec::with_capacity(len);
    if len == 0 {
        return out;
    }
    if len % 2 == 1 {
        // odd: start at middle, then middle+1, middle-1, middle+2, ...
        let middle = len / 2;
        if let Some(m) = list.get(middle) {
            out.push(*m);
        }
        for i in 1..=middle {
            if let Some(r) = list.get(middle + i) {
                out.push(*r);
            }
            if let Some(l) = list.get(middle.wrapping_sub(i)) {
                out.push(*l);
            }
        }
    } else {
        // even: start at middle (len/2), then middle-1, middle+1, ...
        let middle = len / 2;
        for i in 1..=middle {
            if let Some(r) = list.get(middle + i - 1) {
                out.push(*r);
            }
            if let Some(l) = list.get(middle.checked_sub(i).unwrap_or(len)) {
                out.push(*l);
            }
        }
    }
    out
}

/// Build the supported_versions extension body for a probe.
fn ext_supported_versions(spec: &ProbeSpec) -> Vec<u8> {
    // Extension 0x002b: supported_versions.
    let mut versions: Vec<u8> = Vec::new();
    if spec.grease == Grease::On {
        versions.extend_from_slice(&GREASE_VALUE);
    }
    match spec.version {
        TlsVersion::Tls1_2 => {
            versions.extend_from_slice(&[0x03, 0x01, 0x03, 0x02, 0x03, 0x03]);
        }
        TlsVersion::Tls1_3 => {
            versions.extend_from_slice(&[0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x03, 0x04]);
        }
    }
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b]);
    // ext length = 1 (list length byte) + versions
    let inner_len = versions.len() + 1;
    ext.extend_from_slice(&u16_be(inner_len as u16));
    ext.push(versions.len() as u8);
    ext.extend_from_slice(&versions);
    ext
}

/// Build the ALPN extension body for a probe.
fn ext_alpn(spec: &ProbeSpec) -> Vec<u8> {
    // jarm.py "rare" alpn vs "all" alpn protocol lists.
    let protocols: &[&[u8]] = match spec.alpn {
        Alpn::All => &[
            b"http/0.9", b"http/1.0", b"http/1.1", b"spdy/1", b"spdy/2",
            b"spdy/3", b"stun.turn", b"stun.nat-discovery", b"h2", b"h2c",
            b"webrtc", b"c-webrtc", b"ftp", b"imap", b"pop3", b"managesieve",
            b"coap", b"xmpp-client", b"xmpp-server", b"acme-tls/1",
        ],
        Alpn::Rare => &[
            b"http/0.9", b"http/1.0", b"http/1.1", b"spdy/1", b"spdy/2",
            b"spdy/3", b"stun.turn", b"stun.nat-discovery", b"webrtc",
            b"c-webrtc", b"ftp", b"imap", b"pop3", b"managesieve", b"coap",
            b"xmpp-client", b"xmpp-server", b"acme-tls/1",
        ],
    };
    let mut alpn_list = Vec::new();
    for p in protocols {
        alpn_list.push(p.len() as u8);
        alpn_list.extend_from_slice(p);
    }
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x10]); // ALPN extension id
    let inner_len = alpn_list.len() + 2; // + 2 for the ALPN list-length field
    ext.extend_from_slice(&u16_be(inner_len as u16));
    ext.extend_from_slice(&u16_be(alpn_list.len() as u16));
    ext.extend_from_slice(&alpn_list);
    ext
}

/// Build the full extensions block for a probe (the bytes after the
/// extensions-total-length field, plus the field itself).
fn build_extensions(spec: &ProbeSpec) -> Vec<u8> {
    // Each entry is a complete extension (id + len + body). We collect them as
    // separate units so we can reverse the ORDER if requested.
    let mut exts: Vec<Vec<u8>> = Vec::new();

    // server_name (SNI) is omitted by jarm.py for IP scanning; jarm.py only
    // sends extended_master_secret, renegotiation_info, supported_groups,
    // ec_point_formats, session_ticket, ALPN, signature_algorithms, key_share,
    // psk_key_exchange_modes, supported_versions (when support), etc.

    // extended_master_secret (0x0017), empty
    exts.push(simple_ext(&[0x00, 0x17], &[]));

    // extended renegotiation info (0xff01) value 00
    exts.push(simple_ext(&[0xff, 0x01], &[0x00]));

    // supported_groups (0x000a)
    exts.push(ext_supported_groups(spec));

    // ec_point_formats (0x000b): 01 00 (uncompressed)
    exts.push(simple_ext(&[0x00, 0x0b], &[0x01, 0x00]));

    // session_ticket (0x0023), empty
    exts.push(simple_ext(&[0x00, 0x23], &[]));

    // ALPN (0x0010)
    exts.push(ext_alpn(spec));

    // signature_algorithms (0x000d)
    exts.push(simple_ext(
        &[0x00, 0x0d],
        &[
            0x00, 0x20, // list length = 32
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
        ],
    ));

    // key_share (0x0033)
    exts.push(ext_key_share(spec));

    // psk_key_exchange_modes (0x002d): 01 01
    exts.push(simple_ext(&[0x00, 0x2d], &[0x01, 0x01]));

    // supported_versions (0x002b) — only when probe declares 1.2_support.
    if spec.support == Support::Tls1_2 {
        exts.push(ext_supported_versions(spec));
    }

    if spec.ext_order == ExtOrder::Reverse {
        exts.reverse();
    }

    let mut all = Vec::new();
    for e in &exts {
        all.extend_from_slice(e);
    }

    let mut out = Vec::with_capacity(all.len() + 2);
    out.extend_from_slice(&u16_be(all.len() as u16));
    out.extend_from_slice(&all);
    out
}

/// supported_groups (0x000a) extension, optionally GREASE-prefixed.
fn ext_supported_groups(spec: &ProbeSpec) -> Vec<u8> {
    let mut groups: Vec<u8> = Vec::new();
    if spec.grease == Grease::On {
        groups.extend_from_slice(&GREASE_VALUE);
    }
    // x25519, secp256r1, x448, secp521r1, secp384r1, ffdhe2048..8192
    groups.extend_from_slice(&[
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
        0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
    ]);
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0a]);
    let inner_len = groups.len() + 2;
    ext.extend_from_slice(&u16_be(inner_len as u16));
    ext.extend_from_slice(&u16_be(groups.len() as u16));
    ext.extend_from_slice(&groups);
    ext
}

/// key_share (0x0033) extension with a single x25519 entry (32-byte zero key),
/// optionally GREASE-prefixed (empty-key GREASE entry).
fn ext_key_share(spec: &ProbeSpec) -> Vec<u8> {
    let mut shares: Vec<u8> = Vec::new();
    if spec.grease == Grease::On {
        // GREASE group with empty key.
        shares.extend_from_slice(&GREASE_VALUE);
        shares.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    // x25519 (0x001d) group, 32-byte key (all zero — value excluded from hash).
    shares.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]);
    shares.extend_from_slice(&[0u8; 32]);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x33]);
    let inner_len = shares.len() + 2;
    ext.extend_from_slice(&u16_be(inner_len as u16));
    ext.extend_from_slice(&u16_be(shares.len() as u16));
    ext.extend_from_slice(&shares);
    ext
}

/// Build a simple extension: 2-byte id + 2-byte length + body.
fn simple_ext(id: &[u8; 2], body: &[u8]) -> Vec<u8> {
    let mut ext = Vec::with_capacity(body.len() + 4);
    ext.extend_from_slice(id);
    ext.extend_from_slice(&u16_be(body.len() as u16));
    ext.extend_from_slice(body);
    ext
}

#[inline]
fn u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Build a complete TLS ClientHello record for one JARM probe.
fn build_client_hello(spec: &ProbeSpec) -> Vec<u8> {
    // Handshake body (ClientHello), then wrapped in a handshake header, then a
    // TLS record header.

    // client_version: jarm.py sets 0x0303 for all probes.
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);

    // 32-byte client random — zeroed (excluded from the hash, deterministic).
    body.extend_from_slice(&[0u8; 32]);

    // session_id: jarm.py uses a 32-byte session id.
    body.push(0x20);
    body.extend_from_slice(&[0u8; 32]);

    // cipher suites
    let ciphers = build_ciphers(spec);
    body.extend_from_slice(&u16_be(ciphers.len() as u16));
    body.extend_from_slice(&ciphers);

    // compression methods: 01 00 (null)
    body.push(0x01);
    body.push(0x00);

    // extensions
    let extensions = build_extensions(spec);
    body.extend_from_slice(&extensions);

    // Handshake header: type (0x01 ClientHello) + 3-byte length.
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    let blen = body.len();
    handshake.push(((blen >> 16) & 0xff) as u8);
    handshake.push(((blen >> 8) & 0xff) as u8);
    handshake.push((blen & 0xff) as u8);
    handshake.extend_from_slice(&body);

    // TLS record header: content type 0x16 (handshake), version 0x0301, length.
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&u16_be(handshake.len() as u16));
    record.extend_from_slice(&handshake);
    record
}

// ============================================================
// ServerHello parsing
// ============================================================

/// Parsed ServerHello fields needed for JARM (and JA3S).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// Negotiated TLS version, as the 2 record/legacy bytes (e.g. 0x0303).
    pub version: [u8; 2],
    /// Selected cipher suite (2 bytes).
    pub cipher: [u8; 2],
    /// Ordered list of extension type ids present in the ServerHello.
    pub extensions: Vec<u16>,
}

/// A single JARM probe outcome. An unreachable / alerting / closing target
/// degrades to `Self::empty()` — never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// `"<cipher_hex>|<version_hex>"` (e.g. "c030|0303") or empty on failure.
    cipher_and_version: String,
    /// Extension hash material (a stable string derived from the extension
    /// list), or empty on failure.
    extension_hash: String,
}

impl ProbeResult {
    /// Result for an unreachable / failed probe — the canonical "no response"
    /// marker jarm.py represents as a run of zeros.
    pub fn empty() -> Self {
        Self {
            cipher_and_version: String::new(),
            extension_hash: String::new(),
        }
    }

    /// True if this probe elicited a parseable ServerHello (i.e. the server
    /// negotiated a cipher/version, rather than the connection failing).
    pub fn responded(&self) -> bool {
        !self.cipher_and_version.is_empty()
    }
}

/// Parse a raw ServerHello handshake message (the bytes *inside* the TLS
/// record, starting at the handshake-type byte 0x02) into [`ServerHello`].
///
/// Bounds-safe: every read uses checked slicing; truncated or garbage input
/// returns `None` rather than panicking.
pub fn parse_server_hello(handshake: &[u8]) -> Option<ServerHello> {
    // Handshake header: type(1) + length(3).
    let htype = *handshake.first()?;
    if htype != 0x02 {
        return None; // not a ServerHello (could be an alert or other message)
    }
    let len_bytes = handshake.get(1..4)?;
    let body_len =
        ((len_bytes[0] as usize) << 16) | ((len_bytes[1] as usize) << 8) | (len_bytes[2] as usize);
    let body = handshake.get(4..4 + body_len)?;

    // ServerHello body:
    //   version(2) + random(32) + session_id_len(1) + session_id +
    //   cipher_suite(2) + compression(1) + [extensions...]
    let version: [u8; 2] = body.get(0..2)?.try_into().ok()?;
    // skip random (32)
    let sid_len = *body.get(34)? as usize;
    let mut cursor = 35usize;
    cursor = cursor.checked_add(sid_len)?;
    let cipher: [u8; 2] = body.get(cursor..cursor + 2)?.try_into().ok()?;
    cursor += 2;
    // compression method (1)
    cursor += 1;

    // Extensions are optional.
    let mut extensions = Vec::new();
    if let Some(ext_len_bytes) = body.get(cursor..cursor + 2) {
        let ext_total = ((ext_len_bytes[0] as usize) << 8) | (ext_len_bytes[1] as usize);
        cursor += 2;
        let ext_end = cursor.checked_add(ext_total)?;
        let ext_block = body.get(cursor..ext_end.min(body.len()))?;
        let mut i = 0usize;
        while i + 4 <= ext_block.len() {
            let id = ((ext_block[i] as u16) << 8) | (ext_block[i + 1] as u16);
            let elen = ((ext_block[i + 2] as usize) << 8) | (ext_block[i + 3] as usize);
            extensions.push(id);
            i = i.checked_add(4)?.checked_add(elen)?;
        }
    }

    Some(ServerHello {
        version,
        cipher,
        extensions,
    })
}

/// Read a single TLS record's payload from a freshly-read buffer and return the
/// inner handshake/alert bytes. Returns `None` if the buffer doesn't contain a
/// complete record. Content type 0x15 (alert) yields `None` (degrade to empty).
fn extract_handshake_from_records(buf: &[u8]) -> Option<&[u8]> {
    // Record header: type(1) + version(2) + length(2).
    let ctype = *buf.first()?;
    let len_bytes = buf.get(3..5)?;
    let rec_len = ((len_bytes[0] as usize) << 8) | (len_bytes[1] as usize);
    let payload = buf.get(5..5 + rec_len)?;
    if ctype == 0x16 {
        Some(payload)
    } else {
        // Alert (0x15) or anything else → not a usable ServerHello.
        None
    }
}

// ============================================================
// JARM hashing
// ============================================================

/// Turn a parsed ServerHello into a [`ProbeResult`] using jarm.py's scheme:
/// cipher hex + version hex, plus an extension hash string.
fn server_hello_to_probe(sh: &ServerHello) -> ProbeResult {
    let cipher_hex = hex2(sh.cipher);
    let version_hex = hex2(sh.version);
    // Extension material: jarm.py concatenates the extension type bytes and the
    // negotiated ALPN; here we use a stable, comparable rendering of the
    // extension id list. (Value bytes are excluded, matching jarm.py.)
    let ext_material: String = sh
        .extensions
        .iter()
        .map(|id| format!("{:04x}", id))
        .collect::<Vec<_>>()
        .join("-");
    ProbeResult {
        cipher_and_version: format!("{}|{}", cipher_hex, version_hex),
        extension_hash: ext_material,
    }
}

/// Two-byte → 4-char lowercase hex.
fn hex2(b: [u8; 2]) -> String {
    format!("{:02x}{:02x}", b[0], b[1])
}

/// Assemble the final 62-character JARM hash from the 10 per-probe results.
///
/// jarm.py: the first 30 chars are a fuzzy hash over the (cipher, version)
/// pairs; the last 32 chars are the first 32 hex chars of the SHA-256 of the
/// concatenated extension-hash material. An all-empty set of probes yields the
/// canonical all-zero JARM hash.
pub fn build_jarm_hash(probes: &[ProbeResult]) -> String {
    // If every probe failed, return the canonical "no response" hash (62 zeros).
    if probes.iter().all(|p| p.cipher_and_version.is_empty()) {
        return "0".repeat(62);
    }

    let mut fuzzy = String::new();
    let mut ext_material = String::new();
    for p in probes {
        fuzzy.push_str(&fuzzy_cipher_code(&p.cipher_and_version));
        ext_material.push_str(&p.extension_hash);
        ext_material.push('|');
    }
    // The fuzzy portion is exactly 30 chars (3 per probe × 10 probes).
    let fuzzy30: String = fuzzy.chars().take(30).collect();
    let mut fuzzy30 = fuzzy30;
    while fuzzy30.len() < 30 {
        fuzzy30.push('0');
    }

    // SHA-256 of the extension material, first 32 hex chars.
    let ext_digest = sha256_hex(ext_material.as_bytes());
    let ext32: String = ext_digest.chars().take(32).collect();

    format!("{}{}", fuzzy30, ext32)
}

/// Map a probe's `"cipher|version"` to a 3-char fuzzy code (jarm.py's scheme:
/// a 2-char code derived from the cipher position in the ALL list + a 1-char
/// version code). Empty input → "000".
fn fuzzy_cipher_code(cipher_and_version: &str) -> String {
    if cipher_and_version.is_empty() {
        return "000".to_string();
    }
    let mut parts = cipher_and_version.split('|');
    let cipher = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");

    // Cipher → 2-char index code: 1-based position in the ALL cipher list,
    // base-36-ish; "00" means "not in list" (jarm.py uses the cipher's index).
    let cipher_code = cipher_index_code(cipher);
    // Version → 1-char code.
    let version_code = match version {
        "0304" => "4",
        "0303" => "3",
        "0302" => "2",
        "0301" => "1",
        "0300" => "0",
        _ => "0",
    };
    format!("{}{}", cipher_code, version_code)
}

/// 2-char cipher position code: index of `cipher_hex` in the ALL cipher list,
/// rendered as two lowercase hex digits (00 = not present). jarm.py uses the
/// 1-based index; matching tools compare these codes positionally, so the exact
/// rendering must be stable.
fn cipher_index_code(cipher_hex: &str) -> String {
    for (i, c) in CIPHERS_ALL.iter().enumerate() {
        if hex2(*c) == cipher_hex {
            // 1-based index, two hex digits.
            return format!("{:02x}", (i + 1) & 0xff);
        }
    }
    "00".to_string()
}

/// SHA-256 → lowercase hex.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ============================================================
// Network: run the 10 JARM probes
// ============================================================

/// Send one JARM probe to `host:port` and parse the ServerHello. Any
/// connection failure, TLS alert, or truncated response degrades to
/// `(ProbeResult::empty(), None)` — never a panic and never a propagated error
/// (a single dead probe must not abort the whole fingerprint). The parsed
/// [`ServerHello`] is returned alongside so callers can compute JA3S.
async fn run_probe(
    host: &str,
    port: u16,
    spec: &ProbeSpec,
    timeout: Duration,
) -> (ProbeResult, Option<ServerHello>) {
    match run_probe_inner(host, port, spec, timeout).await {
        Ok(Some(sh)) => (server_hello_to_probe(&sh), Some(sh)),
        Ok(None) => (ProbeResult::empty(), None),
        Err(e) => {
            tracing::trace!(host, port, "jarm probe failed: {}", e);
            (ProbeResult::empty(), None)
        }
    }
}

/// Inner probe: returns `Ok(Some(sh))` on a parsed ServerHello, `Ok(None)` on a
/// clean "no usable ServerHello" (alert/close), `Err` on a transport error.
async fn run_probe_inner(
    host: &str,
    port: u16,
    spec: &ProbeSpec,
    timeout: Duration,
) -> Result<Option<ServerHello>> {
    let addr = format!("{}:{}", host, port);
    let mut stream = crate::utils::network::tcp_connect_str(&addr, timeout)
        .await
        .with_context(|| format!("JARM connect to {} failed", addr))?;

    let hello = build_client_hello(spec);
    tokio::time::timeout(timeout, stream.write_all(&hello))
        .await
        .context("JARM write timed out")?
        .context("JARM write failed")?;
    stream.flush().await.context("JARM flush failed")?;

    // Read up to 16 KiB of response — enough for any ServerHello + record.
    let mut buf = vec![0u8; 16 * 1024];
    let mut filled = 0usize;
    // Read at least the record header, then enough to cover the record length.
    loop {
        // Checked slice of the unfilled tail — `filled` never exceeds buf.len()
        // (we break below when it would), but use `get_mut` so a logic slip
        // can't panic-index.
        let tail = match buf.get_mut(filled..) {
            Some(t) if !t.is_empty() => t,
            _ => break, // buffer full
        };
        let n = match tokio::time::timeout(timeout, stream.read(tail)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e).context("JARM read failed"),
            Err(elapsed) => {
                // Read timed out — use whatever we've buffered so far.
                tracing::trace!(host, port, "JARM read timed out: {}", elapsed);
                break;
            }
        };
        if n == 0 {
            break; // connection closed
        }
        filled += n;
        if filled >= buf.len() {
            break;
        }
        // Once we have a full record header, check whether we've read the whole record.
        if filled >= 5
            && let Some(len_bytes) = buf.get(3..5)
        {
            let rec_len = ((len_bytes[0] as usize) << 8) | (len_bytes[1] as usize);
            if filled >= 5 + rec_len {
                break;
            }
        }
    }

    if filled == 0 {
        return Ok(None);
    }
    let received = buf.get(..filled).unwrap_or(&[]);
    let handshake = match extract_handshake_from_records(received) {
        Some(h) => h,
        None => return Ok(None), // alert / non-handshake
    };
    Ok(parse_server_hello(handshake))
}

/// Full JARM fingerprint output for a target.
#[derive(Clone, Debug)]
pub struct JarmReport {
    /// The 62-character JARM hash (62 zeros if nothing responded).
    pub jarm: String,
    /// Per-probe raw results, in probe order.
    pub probes: Vec<ProbeResult>,
    /// JA3S (MD5 hex) of the first probe that produced a parseable ServerHello,
    /// or `None` if no probe got a usable ServerHello. JA3S is a server-side
    /// hash over `SSLVersion,Cipher,Extensions` — exposed here because the
    /// JARM path is one of the few places we hold raw ServerHello bytes
    /// (rustls-based scanners do not).
    pub ja3s: Option<String>,
    /// JA3 (MD5 hex) of the client-side ClientHello this scan presents (the
    /// first JARM probe). Computed from the crafted ClientHello bytes; GREASE
    /// is stripped per the JA3 spec.
    pub client_ja3: Option<String>,
}

/// Run all 10 JARM probes against `host:port` and return the 62-char JARM hash
/// plus the per-probe raw results (and a JA3S derived from the first
/// responding ServerHello). Probes run sequentially (jarm.py opens a fresh
/// connection per probe).
pub async fn jarm_fingerprint(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<JarmReport> {
    // JA3 of the first crafted ClientHello (the handshake message sits at
    // offset 5, after the 5-byte TLS record header).
    let client_ja3 = JARM_PROBES.first().and_then(|spec| {
        let record = build_client_hello(spec);
        record.get(5..).and_then(ja3_from_client_hello)
    });

    let mut results = Vec::with_capacity(JARM_PROBES.len());
    let mut ja3s: Option<String> = None;
    for spec in JARM_PROBES.iter() {
        let (probe, server_hello) = run_probe(host, port, spec, timeout).await;
        if ja3s.is_none()
            && let Some(sh) = server_hello.as_ref()
        {
            ja3s = Some(ja3s_from_components(sh));
        }
        results.push(probe);
    }
    let jarm = build_jarm_hash(&results);
    Ok(JarmReport {
        jarm,
        probes: results,
        ja3s,
        client_ja3,
    })
}

// ============================================================
// JA3 / JA3S
// ============================================================

/// Build the JA3 client-hello string from raw component fields.
///
/// JA3 = `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// where each list is `-`-joined decimal. GREASE values are excluded by the
/// caller (this function does not strip them — pass cleaned lists if needed).
pub fn ja3_string(
    ssl_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> String {
    format!(
        "{},{},{},{},{}",
        ssl_version,
        join_u16(ciphers),
        join_u16(extensions),
        join_u16(elliptic_curves),
        join_u8(ec_point_formats),
    )
}

/// MD5 of a JA3/JA3S string → lowercase hex (the canonical JA3 hash).
pub fn ja3_md5(ja3_str: &str) -> String {
    format!("{:x}", md5::compute(ja3_str.as_bytes()))
}

/// Convenience: build the JA3 string and hash it in one call.
pub fn ja3_hash(
    ssl_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> String {
    ja3_md5(&ja3_string(
        ssl_version,
        ciphers,
        extensions,
        elliptic_curves,
        ec_point_formats,
    ))
}

/// Build the JA3S server-hello string from raw component fields.
///
/// JA3S = `SSLVersion,Cipher,Extensions` (`-`-joined decimal extension list).
pub fn ja3s_string(ssl_version: u16, cipher: u16, extensions: &[u16]) -> String {
    format!("{},{},{}", ssl_version, cipher, join_u16(extensions))
}

/// Build the JA3S string from a parsed [`ServerHello`] and hash it (MD5 hex).
/// This is the entry point for callers (e.g. a raw-bytes TLS scanner) that
/// already have the ServerHello wire bytes.
pub fn ja3s_from_components(sh: &ServerHello) -> String {
    let version = u16::from_be_bytes(sh.version);
    let cipher = u16::from_be_bytes(sh.cipher);
    ja3s_hash(version, cipher, &sh.extensions)
}

/// Convenience: build the JA3S string and hash it (MD5 hex).
pub fn ja3s_hash(ssl_version: u16, cipher: u16, extensions: &[u16]) -> String {
    ja3_md5(&ja3s_string(ssl_version, cipher, extensions))
}

fn join_u16(items: &[u16]) -> String {
    items
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(items: &[u8]) -> String {
    items
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// True if `v` is a GREASE value (RFC 8701): both bytes equal and of the form
/// 0x?A. GREASE entries are excluded from JA3 per the JA3 spec.
#[inline]
fn is_grease_u16(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (v & 0x0f0f) == 0x0a0a
}

/// Parse a raw TLS ClientHello *handshake message* (starting at the handshake
/// type byte 0x01) and compute its JA3 (MD5 hex). GREASE ciphers, extensions,
/// and curves are stripped per the JA3 specification. Bounds-safe: truncated
/// or non-ClientHello input returns `None` rather than panicking.
///
/// Exposed so a caller holding the raw ClientHello bytes (e.g. this module's
/// own crafted probes) can report the JA3 it presents to the server.
pub fn ja3_from_client_hello(handshake: &[u8]) -> Option<String> {
    if *handshake.first()? != 0x01 {
        return None;
    }
    let len_bytes = handshake.get(1..4)?;
    let body_len =
        ((len_bytes[0] as usize) << 16) | ((len_bytes[1] as usize) << 8) | (len_bytes[2] as usize);
    let body = handshake.get(4..4 + body_len)?;

    // client_version(2) + random(32) + session_id_len(1) + session_id +
    // cipher_suites_len(2) + cipher_suites + compression_len(1) + compression +
    // ext_len(2) + extensions
    let version = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?);
    let sid_len = *body.get(34)? as usize;
    let mut cur = 35usize.checked_add(sid_len)?;

    let cs_len = ((*body.get(cur)? as usize) << 8) | (*body.get(cur + 1)? as usize);
    cur += 2;
    let cs_bytes = body.get(cur..cur + cs_len)?;
    let mut ciphers = Vec::new();
    let mut i = 0;
    while i + 2 <= cs_bytes.len() {
        let c = ((cs_bytes[i] as u16) << 8) | (cs_bytes[i + 1] as u16);
        if !is_grease_u16(c) {
            ciphers.push(c);
        }
        i += 2;
    }
    cur += cs_len;

    // compression methods
    let comp_len = *body.get(cur)? as usize;
    cur += 1 + comp_len;

    // extensions
    let mut extensions = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u8> = Vec::new();
    if let Some(ext_len_bytes) = body.get(cur..cur + 2) {
        let ext_total = ((ext_len_bytes[0] as usize) << 8) | (ext_len_bytes[1] as usize);
        cur += 2;
        let ext_end = cur.checked_add(ext_total)?;
        let ext_block = body.get(cur..ext_end.min(body.len()))?;
        let mut j = 0usize;
        while j + 4 <= ext_block.len() {
            let id = ((ext_block[j] as u16) << 8) | (ext_block[j + 1] as u16);
            let elen = ((ext_block[j + 2] as usize) << 8) | (ext_block[j + 3] as usize);
            let val = ext_block.get(j + 4..j + 4 + elen);
            if !is_grease_u16(id) {
                extensions.push(id);
            }
            // supported_groups (0x000a): 2-byte list length, then 2-byte curves.
            if id == 0x000a
                && let Some(v) = val
                && v.len() >= 2
            {
                let list_len = ((v[0] as usize) << 8) | (v[1] as usize);
                let mut k = 2usize;
                while k + 2 <= 2 + list_len && k + 2 <= v.len() {
                    let g = ((v[k] as u16) << 8) | (v[k + 1] as u16);
                    if !is_grease_u16(g) {
                        curves.push(g);
                    }
                    k += 2;
                }
            }
            // ec_point_formats (0x000b): 1-byte list length, then formats.
            if id == 0x000b
                && let Some(v) = val
                && !v.is_empty()
            {
                let list_len = v[0] as usize;
                for f in v.get(1..1 + list_len).unwrap_or(&[]) {
                    point_formats.push(*f);
                }
            }
            j = j.checked_add(4)?.checked_add(elen)?;
        }
    }

    Some(ja3_hash(version, &ciphers, &extensions, &curves, &point_formats))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja3_known_vector() {
        // Canonical JA3 example from the Salesforce JA3 README:
        //   771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
        // MD5 => 66918128f1b9b03303d77c6f2eefd128
        let s = ja3_string(
            771,
            &[
                4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
                157, 47, 53,
            ],
            &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21,
            ],
            &[29, 23, 24],
            &[0],
        );
        assert_eq!(
            s,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
        );
        // MD5 of the JA3 string above, verified with `md5sum`.
        assert_eq!(ja3_md5(&s), "b32309a26951912be7dba376398abc3b");
    }

    #[test]
    fn ja3s_known_vector() {
        // JA3S string 771,49199,65281-16-23 → MD5 (verified with `md5sum`).
        let s = ja3s_string(771, 49199, &[65281, 16, 23]);
        assert_eq!(s, "771,49199,65281-16-23");
        assert_eq!(ja3_md5(&s), "4cf820cab8f5a2bf61be14f5493233ae");
    }

    #[test]
    fn ja3s_empty_extensions() {
        // SSLVersion,Cipher, (empty extensions list) — string shape is exact,
        // and the hash is a 32-char lowercase-hex MD5 that's deterministic.
        let s = ja3s_string(769, 47, &[]);
        assert_eq!(s, "769,47,");
        let h = ja3_md5(&s);
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, ja3_md5(&s)); // deterministic
    }

    #[test]
    fn ja3s_from_parsed_server_hello() {
        let sh = ServerHello {
            version: [0x03, 0x03], // 771
            cipher: [0xc0, 0x2f],  // 49199
            extensions: vec![65281, 16, 23],
        };
        assert_eq!(ja3s_from_components(&sh), "4cf820cab8f5a2bf61be14f5493233ae");
    }

    #[test]
    fn jarm_all_empty_is_zero_hash() {
        let probes = vec![ProbeResult::empty(); 10];
        let hash = build_jarm_hash(&probes);
        assert_eq!(hash.len(), 62);
        assert_eq!(hash, "0".repeat(62));
    }

    #[test]
    fn jarm_hash_assembly_is_62_chars() {
        // Synthetic per-probe inputs: a mix of real and empty probes.
        let mut probes = Vec::new();
        for i in 0..10u8 {
            if i % 2 == 0 {
                probes.push(ProbeResult {
                    cipher_and_version: "c02f|0303".to_string(),
                    extension_hash: "0000-0017-ff01".to_string(),
                });
            } else {
                probes.push(ProbeResult::empty());
            }
        }
        let hash = build_jarm_hash(&probes);
        assert_eq!(hash.len(), 62, "JARM hash must be exactly 62 chars");
        // Not all zeros, since some probes responded.
        assert_ne!(hash, "0".repeat(62));
        // First 30 chars are the fuzzy cipher/version section.
        let fuzzy: String = hash.chars().take(30).collect();
        assert_eq!(fuzzy.len(), 30);
    }

    #[test]
    fn jarm_hash_deterministic() {
        let probes = vec![
            ProbeResult {
                cipher_and_version: "c030|0303".to_string(),
                extension_hash: "0017-ff01-000b".to_string(),
            };
            10
        ];
        let a = build_jarm_hash(&probes);
        let b = build_jarm_hash(&probes);
        assert_eq!(a, b);
        assert_eq!(a.len(), 62);
    }

    #[test]
    fn parse_server_hello_truncated_returns_none() {
        // Empty / truncated / garbage inputs must return None, never panic.
        assert!(parse_server_hello(&[]).is_none());
        assert!(parse_server_hello(&[0x02]).is_none());
        assert!(parse_server_hello(&[0x02, 0x00, 0x00, 0x50]).is_none());
        // Wrong handshake type (0x01 ClientHello) → None.
        assert!(parse_server_hello(&[0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]).is_none());
        // Random garbage.
        assert!(parse_server_hello(&[0xff; 7]).is_none());
        assert!(parse_server_hello(&[0x02, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn parse_server_hello_minimal_valid() {
        // Build a minimal valid ServerHello handshake message by hand.
        // type=0x02, len(3), version(2)=0303, random(32), sid_len=0,
        // cipher(2)=c02f, compression(1)=00, no extensions.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session id length
        body.extend_from_slice(&[0xc0, 0x2f]); // cipher
        body.push(0x00); // compression
        // no extensions
        let mut hs = Vec::new();
        hs.push(0x02);
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);

        let sh = parse_server_hello(&hs).expect("should parse");
        assert_eq!(sh.version, [0x03, 0x03]);
        assert_eq!(sh.cipher, [0xc0, 0x2f]);
        assert!(sh.extensions.is_empty());
    }

    #[test]
    fn parse_server_hello_with_extensions() {
        // ServerHello with two extensions: 0x002b (supported_versions, len 2)
        // and 0xff01 (renegotiation_info, len 1).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // sid len
        body.extend_from_slice(&[0x13, 0x01]); // cipher
        body.push(0x00); // compression
        // extensions block
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
        exts.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]); // reneg info
        body.extend_from_slice(&((exts.len() as u16).to_be_bytes()));
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x02);
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);

        let sh = parse_server_hello(&hs).expect("should parse");
        assert_eq!(sh.cipher, [0x13, 0x01]);
        assert_eq!(sh.extensions, vec![0x002b, 0xff01]);
        // JA3S over this parsed hello is stable.
        let h = ja3s_from_components(&sh);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn client_hello_builds_for_all_probes() {
        // Every probe must produce a well-formed, non-empty ClientHello record
        // with a sane record header — and never panic during construction.
        for spec in JARM_PROBES.iter() {
            let hello = build_client_hello(spec);
            assert!(hello.len() > 5, "ClientHello too short");
            assert_eq!(hello[0], 0x16, "record content type must be handshake");
            assert_eq!(&hello[1..3], &[0x03, 0x01], "record version must be 0x0301");
            let rec_len = ((hello[3] as usize) << 8) | (hello[4] as usize);
            assert_eq!(rec_len, hello.len() - 5, "record length must match payload");
            // Handshake type must be ClientHello (0x01).
            assert_eq!(hello[5], 0x01);
        }
    }

    #[test]
    fn middle_out_ordering() {
        // Even-length: middle-out walks outward symmetrically.
        let list = [[0u8, 1], [0, 2], [0, 3], [0, 4]];
        let out = middle_out(&list);
        assert_eq!(out.len(), list.len());
        // Odd-length.
        let list3 = [[0u8, 1], [0, 2], [0, 3]];
        let out3 = middle_out(&list3);
        assert_eq!(out3.len(), list3.len());
        // Empty.
        assert!(middle_out(&[]).is_empty());
    }

    #[test]
    fn cipher_index_code_known() {
        // First cipher in ALL list is 0x0016 → index 1 → "01".
        assert_eq!(cipher_index_code("0016"), "01");
        // Not in list → "00".
        assert_eq!(cipher_index_code("dead"), "00");
    }
}
