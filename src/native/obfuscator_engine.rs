//! Obfuscator engine — pure encoding primitives + emitters.
//!
//! Extracted from `modules/exploits/payloadgens/obfuscator.rs` so any module
//! can call into the same chain encoder/emitter without going through the
//! interactive prompt flow. The user-facing wrapper (banner, `cfg_prompt_*`,
//! risk-preview, save-to-file) lives back in the `obfuscator` module and
//! delegates here for everything except UI.
//!
//! Public surface:
//!
//! - [`Method`] — the 24-method enum (xor, b64, gzip, zw, …) with random
//!   per-method state baked in (XOR keys, Caesar shifts, etc.)
//! - [`instantiate`] — build a `Method` from its short id (`"xor"`, `"b64"`)
//! - [`apply_method`] — run one round of the chain
//! - [`growth_factor`] / [`predict_output_size`] / [`caveat`] — risk preview
//! - [`OutputFormat`] / [`parse_format`] / [`supports`] — emitter selection
//! - [`emit`] — render a chain + final blob in the chosen format
//!
//! Constants (defaults + hard caps) are also re-exported so the wrapper can
//! drive `cfg_prompt_int_range` calls without hard-coding numbers.

use anyhow::{anyhow, Context, Result};
use data_encoding::{BASE32, BASE32HEX, BASE64, BASE64URL, HEXUPPER};
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::seq::IndexedRandom;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::io::Write as _;

/// Saturating capacity helper. `Vec::with_capacity` takes `usize`, so we never
/// want a multiplication to overflow into a small value (which would defeat
/// the pre-allocation). Caps the result at the max output ceiling — any value
/// above that is irrelevant since the engine refuses such allocations anyway.
#[inline]
fn safe_capacity(input_len: usize, factor: usize) -> usize {
    input_len
        .saturating_mul(factor)
        .min(HARD_MAX_OUTPUT_BYTES as usize)
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
// All three caps below are user-overridable via prompts in the wrapper. The
// HARD_* ceilings are the absolute upper bound — beyond them the host's
// allocator becomes the next failure mode (OOM kill, panic in alloc), so we
// refuse instead.

pub const DEFAULT_ROUNDS: usize = 4;

pub const DEFAULT_MAX_ROUNDS: i64 = 32;
pub const HARD_MAX_ROUNDS: i64 = 256;

pub const DEFAULT_MAX_INPUT_BYTES: i64 = 4 * 1024 * 1024;
pub const HARD_MAX_INPUT_BYTES: i64 = 64 * 1024 * 1024;

pub const DEFAULT_MAX_OUTPUT_BYTES: i64 = 16 * 1024 * 1024;
pub const HARD_MAX_OUTPUT_BYTES: i64 = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Method definitions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Method {
    XorMulti(Vec<u8>),
    Xor1(u8),
    B16,
    B32,
    B32Hex,
    B64,
    B64Url,
    B85,
    B91,
    Rot13,
    Rot47,
    Reverse,
    Rc4(Vec<u8>),
    Gzip,
    Url,
    Caesar(u8),
    BitRot(u8),       // 1..=7
    Vigenere(Vec<u8>),
    ZeroWidth,
    HexSplit,
    Utf16Le,
    CharSubst([u8; 256]),
    AnsiEscape,
    Chunk(Vec<usize>), // permutation of 0..n
}

impl Method {
    pub fn id(&self) -> &'static str {
        match self {
            Method::XorMulti(_) => "xor",
            Method::Xor1(_) => "xor1",
            Method::B16 => "b16",
            Method::B32 => "b32",
            Method::B32Hex => "b32hex",
            Method::B64 => "b64",
            Method::B64Url => "b64url",
            Method::B85 => "b85",
            Method::B91 => "b91",
            Method::Rot13 => "rot13",
            Method::Rot47 => "rot47",
            Method::Reverse => "rev",
            Method::Rc4(_) => "rc4",
            Method::Gzip => "gzip",
            Method::Url => "url",
            Method::Caesar(_) => "caesar",
            Method::BitRot(_) => "bitrot",
            Method::Vigenere(_) => "vigenere",
            Method::ZeroWidth => "zw",
            Method::HexSplit => "hexsplit",
            Method::Utf16Le => "utf16le",
            Method::CharSubst(_) => "csub",
            Method::AnsiEscape => "ansi",
            Method::Chunk(_) => "chunk",
        }
    }
}

/// Set of method IDs the user can request explicitly.
pub const ALL_METHOD_IDS: &[&str] = &[
    "xor", "xor1", "b16", "b32", "b32hex", "b64", "b64url", "b85", "b91",
    "rot13", "rot47", "rev", "rc4", "gzip", "url", "caesar", "bitrot",
    "vigenere", "zw", "hexsplit", "utf16le", "csub", "ansi", "chunk",
];

/// Conservative upper bound on output size for a given input length. Used
/// to refuse a round BEFORE its allocation (load-bearing OOM gate). Adds
/// a 64-byte fudge for fixed headers (gzip preamble, encoder padding).
pub fn predict_output_size(method: &Method, input_len: usize) -> usize {
    let factor = growth_factor(method);
    let predicted = (input_len as f64 * factor).ceil() as usize;
    predicted.saturating_add(64)
}

/// Per-method size-amplification factor (output / input). For methods whose
/// growth varies with the *content* of the input (gzip, ansi, url, hexsplit
/// when input has only `\x` already), this is a worst-case estimate. The
/// risk preview uses this to predict the final blob size.
pub fn growth_factor(method: &Method) -> f64 {
    match method {
        // 1.0× (in-place transforms)
        Method::XorMulti(_) | Method::Xor1(_) | Method::Rc4(_) => 1.0,
        Method::Rot13 | Method::Rot47 | Method::Reverse => 1.0,
        Method::Caesar(_) | Method::BitRot(_) | Method::Vigenere(_) => 1.0,
        Method::CharSubst(_) | Method::Chunk(_) => 1.0,

        // Encodings with fixed expansion ratios.
        Method::B16 => 2.00,
        Method::B32 | Method::B32Hex => 1.60,
        Method::B64 | Method::B64Url => 1.34,
        Method::B85 => 1.25,
        Method::B91 => 1.23,
        Method::Utf16Le => 2.00,
        Method::HexSplit => 4.00,
        Method::AnsiEscape => 7.00,
        Method::Url => 3.00,        // %XX per byte
        Method::ZeroWidth => 24.0,  // each bit → 3-byte UTF-8 codepoint

        // Variable; gzip *usually* shrinks but worst-case is ~1.001 + 18 bytes.
        Method::Gzip => 1.05,
    }
}

/// Free-form caveat describing risks the user should know about for a method.
/// Empty string means "nothing unusual".
pub fn caveat(method: &Method) -> &'static str {
    match method {
        Method::ZeroWidth => "24× growth — invisible UTF-8 only; payload is huge",
        Method::Url => "3× growth; only safe if URL semantics are preserved downstream",
        Method::AnsiEscape => "7× growth; emits shell-quote literals",
        Method::HexSplit => "4× growth; output is the literal `\\xNN` form, not hex bytes",
        Method::Gzip => "size depends on input; may *grow* slightly on incompressible bytes",
        Method::Rot47 => "destructive on bytes outside 33..=126 (passes them through unchanged)",
        Method::Rot13 => "passes non-letters unchanged — chain randomness reduced",
        Method::B91 => "encoding only; basE91 has no `=` padding character",
        Method::Vigenere(_) => "alpha-only key; non-letter bytes shifted but key shift = 0 → identity",
        Method::Chunk(_) => "permutation embedded in decoder ⇒ blob carries full perm vector",
        Method::CharSubst(_) => "256-byte substitution table embedded ⇒ adds 256 bytes to decoder",
        _ => "",
    }
}

/// Build a `Method` instance from its short id, generating random state where
/// the method requires it. Sized inputs (`Chunk`) defer permutation generation
/// to the encode step where the actual length is known.
pub fn instantiate(id: &str) -> Result<Method> {
    let id = id.trim().to_lowercase();
    let mut rng = rand::rng();
    Ok(match id.as_str() {
        "xor" => {
            let mut k = vec![0u8; 16];
            rng.fill(k.as_mut_slice());
            // Reject all-zero keys (degenerates to identity).
            if k.iter().all(|&b| b == 0) { k[0] = 0x5a; }
            Method::XorMulti(k)
        }
        "xor1" => {
            let mut b = [0u8; 1];
            rng.fill(b.as_mut_slice());
            if b[0] == 0 { b[0] = 0x5a; }
            Method::Xor1(b[0])
        }
        "b16" | "hex" => Method::B16,
        "b32" => Method::B32,
        "b32hex" => Method::B32Hex,
        "b64" | "base64" => Method::B64,
        "b64url" => Method::B64Url,
        "b85" | "ascii85" => Method::B85,
        "b91" | "base91" => Method::B91,
        "rot13" => Method::Rot13,
        "rot47" => Method::Rot47,
        "rev" | "reverse" => Method::Reverse,
        "rc4" => {
            let mut k = vec![0u8; 16];
            rng.fill(k.as_mut_slice());
            // Reject all-zero keys (degenerates to a deterministic, weak stream).
            if k.iter().all(|&b| b == 0) { k[0] = 0x5a; }
            Method::Rc4(k)
        }
        "gzip" => Method::Gzip,
        "url" => Method::Url,
        "caesar" => {
            let mut b = [0u8; 1];
            loop {
                rng.fill(b.as_mut_slice());
                if b[0] != 0 { break; }
            }
            Method::Caesar(b[0])
        }
        "bitrot" => {
            let mut b = [0u8; 1];
            rng.fill(b.as_mut_slice());
            let shift = (b[0] % 7) + 1; // 1..=7
            Method::BitRot(shift)
        }
        "vigenere" => {
            // Random 8-byte printable-ASCII key. Reject keys that map every
            // byte to shift 0 — the alphabet is letters only so any non-empty
            // mix produces a non-identity shift, but all-A is theoretically
            // possible (1/52⁸).
            let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let mut key: Vec<u8> = (0..8)
                .map(|_| {
                    let mut b = [0u8; 1];
                    rng.fill(b.as_mut_slice());
                    alphabet[(b[0] as usize) % alphabet.len()]
                })
                .collect();
            // Defense-in-depth: if every byte is 'a' or 'A' (shift 0), force
            // one byte to a different shift.
            if key.iter().all(|&b| b == b'a' || b == b'A') {
                key[0] = b'b';
            }
            Method::Vigenere(key)
        }
        "zw" => Method::ZeroWidth,
        "hexsplit" => Method::HexSplit,
        "utf16le" => Method::Utf16Le,
        "csub" => {
            // Random byte-permutation table (Fisher-Yates).
            let mut tbl = [0u8; 256];
            for (i, b) in tbl.iter_mut().enumerate() { *b = i as u8; }
            for i in (1..256).rev() {
                let mut buf = [0u8; 4];
                rng.fill(buf.as_mut_slice());
                let j = (u32::from_le_bytes(buf) as usize) % (i + 1);
                tbl.swap(i, j);
            }
            // Reject identity permutation (extremely unlikely but possible).
            if tbl.iter().enumerate().all(|(i, &b)| b == i as u8) {
                tbl.swap(0, 1);
            }
            Method::CharSubst(tbl)
        }
        "ansi" => Method::AnsiEscape,
        "chunk" => Method::Chunk(Vec::new()), // length-dependent; populated at encode
        other => anyhow::bail!("unknown obfuscation method '{}'", other),
    })
}

/// Pick a random method id from `ALL_METHOD_IDS`. Used by the "random" mode.
///
/// Panics if `ALL_METHOD_IDS` is empty — that would be a build/refactor bug,
/// not a runtime input issue, so a panic is the right shape.
pub fn random_method_id() -> &'static str {
    let mut rng = rand::rng();
    match ALL_METHOD_IDS.choose(&mut rng).copied() {
        Some(id) => id,
        // ALL_METHOD_IDS is a hardcoded non-empty &[&str] in this module —
        // an empty slice would be a compile-time mistake. We still avoid
        // panicking by returning the first canonical method as a safe
        // fallback (the function is non-critical: it picks an obfuscation
        // method id).
        None => {
            // Fall back to the first compile-time constant. Tested by the
            // crate's unit suite.
            "xor"
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding primitives
// ---------------------------------------------------------------------------

fn xor_multi(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("xor key cannot be empty"));
    }
    let n = key.len();
    Ok(input.iter().enumerate().map(|(i, b)| b ^ key[i % n]).collect())
}

fn rot13(input: &[u8]) -> Vec<u8> {
    input.iter().map(|&b| match b {
        b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
        b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
        _ => b,
    }).collect()
}

fn rot47(input: &[u8]) -> Vec<u8> {
    input.iter().map(|&b| {
        if (33..=126).contains(&b) { 33 + ((b - 33 + 47) % 94) } else { b }
    }).collect()
}

fn caesar(input: &[u8], shift: u8) -> Vec<u8> {
    input.iter().map(|&b| b.wrapping_add(shift)).collect()
}

fn bit_rotate_left(input: &[u8], shift: u8) -> Vec<u8> {
    input.iter().map(|&b| b.rotate_left(shift as u32)).collect()
}

fn vigenere(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("vigenere key cannot be empty"));
    }
    // Key bytes map A=0..Z=25 (already restricted to letters at instantiate).
    let shifts: Vec<u8> = key.iter().map(|&b| {
        match b {
            b'a'..=b'z' => b - b'a',
            b'A'..=b'Z' => b - b'A',
            _ => 0,
        }
    }).collect();
    if shifts.iter().all(|&s| s == 0) {
        return Err(anyhow!("vigenere key reduces to identity (all letters map to shift 0)"));
    }
    let n = shifts.len();
    Ok(input.iter().enumerate().map(|(i, &b)| b.wrapping_add(shifts[i % n])).collect())
}

fn rc4(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("rc4 key cannot be empty"));
    }
    if key.iter().all(|&b| b == 0) {
        return Err(anyhow!("rc4 key cannot be all-zero"));
    }
    // Standard RC4 KSA + PRGA.
    let mut s: [u8; 256] = [0; 256];
    for (i, b) in s.iter_mut().enumerate() { *b = i as u8; }
    let key_len = key.len();
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key_len] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut out = Vec::with_capacity(input.len());
    let (mut i, mut j) = (0usize, 0usize);
    for &byte in input {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(byte ^ k);
    }
    Ok(out)
}

fn gzip_encode(input: &[u8]) -> Result<Vec<u8>> {
    // Reserve input.len() + 32 (header + trailer + small slack). gzip *usually*
    // shrinks the data, but on incompressible bytes the output is roughly
    // input.len() + ~20 B fixed overhead — start there to avoid reallocs.
    let prealloc = input.len().saturating_add(32);
    let mut enc = GzEncoder::new(Vec::with_capacity(prealloc), Compression::default());
    enc.write_all(input).context("gzip write")?;
    enc.finish().context("gzip finish")
}

fn url_encode_full(input: &[u8]) -> Vec<u8> {
    // Encode every byte as %XX so the result is purely [%0-9A-F].
    let mut out = Vec::with_capacity(safe_capacity(input.len(), 3));
    for &b in input {
        out.push(b'%');
        out.extend_from_slice(&crate::native::hex::byte_to_upper(b));
    }
    out
}

fn ascii85_encode(input: &[u8]) -> Vec<u8> {
    // Adobe-style Ascii85 (no <~ ~> wrappers) with all-zero shortcut.
    let mut out: Vec<u8> = Vec::new();
    let chunks = input.chunks(4);
    for chunk in chunks {
        if chunk.len() == 4 && chunk.iter().all(|&b| b == 0) {
            out.push(b'z');
            continue;
        }
        let mut padded = [0u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let mut n = u32::from_be_bytes(padded);
        let mut chars = [0u8; 5];
        for c in chars.iter_mut().rev() {
            *c = (n % 85) as u8 + 33;
            n /= 85;
        }
        let take = chunk.len() + 1;
        out.extend_from_slice(&chars[..take]);
    }
    out
}

/// basE91 encoder (simplified; emits only the 91 printable ASCII chars).
fn base91_encode(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 91] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
          0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    let mut out = Vec::with_capacity(safe_capacity(input.len(), 2));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buf |= (b as u32) << bits;
        bits += 8;
        if bits > 13 {
            let mut v = buf & 0x1fff;
            if v > 88 {
                buf >>= 13;
                bits -= 13;
            } else {
                v = buf & 0x3fff;
                buf >>= 14;
                bits -= 14;
            }
            out.push(TABLE[(v as usize) % 91]);
            out.push(TABLE[(v as usize / 91) % 91]);
        }
    }
    if bits > 0 {
        out.push(TABLE[(buf as usize) % 91]);
        if bits > 7 || buf > 90 {
            out.push(TABLE[(buf as usize / 91) % 91]);
        }
    }
    out
}

fn zero_width_encode(data: &[u8]) -> Vec<u8> {
    // Each bit becomes one of two zero-width code points.
    // 0 → U+200B (3 bytes UTF-8), 1 → U+200C (3 bytes UTF-8).
    let zw0: [u8; 3] = [0xe2, 0x80, 0x8b];
    let zw1: [u8; 3] = [0xe2, 0x80, 0x8c];
    let mut out = Vec::with_capacity(safe_capacity(data.len(), 24));
    for &b in data {
        for i in (0..8).rev() {
            if (b >> i) & 1 == 1 {
                out.extend_from_slice(&zw1);
            } else {
                out.extend_from_slice(&zw0);
            }
        }
    }
    out
}

fn hex_split_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(safe_capacity(input.len(), 4));
    for &b in input {
        out.push(b'\\');
        out.push(b'x');
        out.extend_from_slice(&crate::native::hex::byte_to_lower(b));
    }
    out
}

fn utf16le_encode(input: &[u8]) -> Vec<u8> {
    // Decode bytes as Latin-1 (byte == codepoint) to preserve any value;
    // emit each codepoint as little-endian u16.
    let mut out = Vec::with_capacity(safe_capacity(input.len(), 2));
    for &b in input {
        out.push(b);
        out.push(0);
    }
    out
}

fn char_subst(input: &[u8], table: &[u8; 256]) -> Vec<u8> {
    input.iter().map(|&b| table[b as usize]).collect()
}

fn ansi_escape_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(safe_capacity(input.len(), 7));
    for &b in input {
        out.push(b'$');
        out.push(b'\'');
        out.push(b'\\');
        out.push(b'x');
        out.extend_from_slice(&crate::native::hex::byte_to_lower(b));
        out.push(b'\'');
    }
    out
}

fn chunk_permute(input: &[u8], perm: &[usize]) -> Result<Vec<u8>> {
    // perm[i] tells us which source byte goes at position i.
    if perm.len() != input.len() {
        return Err(anyhow!(
            "chunk permutation length {} does not match input length {}",
            perm.len(),
            input.len()
        ));
    }
    // Validate that perm is a permutation of 0..input.len() (every index used
    // exactly once). Without this guard, a malformed perm corrupts data and
    // the decoder cannot recover the original.
    let mut seen = vec![false; input.len()];
    for &src in perm {
        if src >= input.len() {
            return Err(anyhow!(
                "chunk permutation contains out-of-range index {} (input len {})",
                src,
                input.len()
            ));
        }
        if seen[src] {
            return Err(anyhow!(
                "chunk permutation is not a bijection (index {} repeated)",
                src
            ));
        }
        seen[src] = true;
    }
    let mut out = vec![0u8; input.len()];
    for (i, &src) in perm.iter().enumerate() {
        out[i] = input[src];
    }
    Ok(out)
}

fn ensure_chunk_permutation(method: &mut Method, len: usize) {
    if let Method::Chunk(perm) = method {
        if perm.len() != len {
            let mut p: Vec<usize> = (0..len).collect();
            // Fisher-Yates over the index vector.
            let mut rng = rand::rng();
            for i in (1..p.len()).rev() {
                let mut buf = [0u8; 4];
                rng.fill(buf.as_mut_slice());
                let j = (u32::from_le_bytes(buf) as usize) % (i + 1);
                p.swap(i, j);
            }
            *perm = p;
        }
    }
}

/// Apply one round of the chain. `method` is `&mut` because `Chunk` populates
/// its permutation lazily based on the *current* buffer length.
///
/// Validates parameters first (empty keys, identity Caesar/BitRot shifts,
/// permutation length/bijection) so a `Method` constructed by hand cannot
/// panic the engine or silently corrupt output.
pub fn apply_method(method: &mut Method, input: &[u8]) -> Result<Vec<u8>> {
    // Reject identity-value variants that would silently produce input
    // unchanged. These can only arise from direct enum construction —
    // `instantiate` already filters them at creation time.
    match method {
        Method::Caesar(0) => return Err(anyhow!("caesar shift=0 is identity; reject")),
        Method::BitRot(s) if *s == 0 || *s > 7 => {
            return Err(anyhow!("bitrot shift must be in 1..=7 (got {})", s));
        }
        _ => {}
    }

    Ok(match method {
        Method::XorMulti(k) => xor_multi(input, k)?,
        Method::Xor1(b) => xor_multi(input, &[*b])?,
        Method::B16 => HEXUPPER.encode(input).into_bytes(),
        Method::B32 => BASE32.encode(input).into_bytes(),
        Method::B32Hex => BASE32HEX.encode(input).into_bytes(),
        Method::B64 => BASE64.encode(input).into_bytes(),
        Method::B64Url => BASE64URL.encode(input).into_bytes(),
        Method::B85 => ascii85_encode(input),
        Method::B91 => base91_encode(input),
        Method::Rot13 => rot13(input),
        Method::Rot47 => rot47(input),
        Method::Reverse => input.iter().rev().copied().collect(),
        Method::Rc4(k) => rc4(input, k)?,
        Method::Gzip => gzip_encode(input)?,
        Method::Url => url_encode_full(input),
        Method::Caesar(s) => caesar(input, *s),
        Method::BitRot(s) => bit_rotate_left(input, *s),
        Method::Vigenere(k) => vigenere(input, k)?,
        Method::ZeroWidth => zero_width_encode(input),
        Method::HexSplit => hex_split_encode(input),
        Method::Utf16Le => utf16le_encode(input),
        Method::CharSubst(t) => char_subst(input, t),
        Method::AnsiEscape => ansi_escape_encode(input),
        Method::Chunk(_) => {
            // Generate the permutation lazily based on the *current* length.
            ensure_chunk_permutation(method, input.len());
            // Re-bind after `ensure_chunk_permutation` updated the
            // permutation in place. The match arm pattern is exhaustive,
            // so the new pattern read is total.
            match method {
                Method::Chunk(p) => chunk_permute(input, p)?,
                // SAFETY: the outer match already selected Method::Chunk;
                // no other variant can reach here.
                other => return Err(anyhow::anyhow!(
                    "internal: outer match was Chunk but inner saw {:?}",
                    std::mem::discriminant(other)
                )),
            }
        }
    })
}

/// Apply one round of the chain with a hard pre-flight cap. Bails *before*
/// allocation if [`predict_output_size`] for this method+input exceeds
/// `max_output_bytes`. Use this from any caller that wants OOM-safe encoding.
pub fn apply_method_capped(
    method: &mut Method,
    input: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>> {
    let predicted = predict_output_size(method, input.len());
    if predicted > max_output_bytes {
        return Err(anyhow!(
            "method '{}' would produce ~{} B from {} B input, exceeding cap of {} B",
            method.id(),
            predicted,
            input.len(),
            max_output_bytes
        ));
    }
    apply_method(method, input)
}

/// Encoded blob plus the per-round trail (for recipe / debugging / tests).
pub struct ObfuscateResult {
    pub blob: Vec<u8>,
    /// Final state of every method in the chain, in encode order. Captures
    /// any random material generated lazily during encoding (e.g. `Chunk`
    /// permutations).
    pub chain: Vec<Method>,
    /// Per-round summary: `[NN] <method> | in=<X>B → out=<Y>B | <details>`.
    pub recipe_lines: Vec<String>,
}

/// Pure programmatic obfuscation: run `chain` over `input`, enforcing
/// `max_output_bytes` at every round. No prompts, no UI, no I/O — usable
/// from any module that wants to obfuscate an in-memory buffer.
///
/// `chain` is consumed and the (possibly-updated) methods are returned in
/// [`ObfuscateResult::chain`] so callers can persist them or pass them to
/// [`emit`].
///
/// Returns an error if the chain is empty, any round exceeds the output cap,
/// or any encoder rejects its inputs (e.g. empty key on `XorMulti`).
pub fn obfuscate_bytes(
    input: &[u8],
    chain: Vec<Method>,
    max_output_bytes: usize,
) -> Result<ObfuscateResult> {
    if chain.is_empty() {
        return Err(anyhow!("obfuscation chain cannot be empty"));
    }
    let mut state = chain;
    let mut buf = input.to_vec();
    let mut recipe_lines: Vec<String> = Vec::with_capacity(state.len());
    for (i, method) in state.iter_mut().enumerate() {
        let before = buf.len();
        buf = apply_method_capped(method, &buf, max_output_bytes)
            .with_context(|| format!("round {} ({})", i + 1, method.id()))?;
        recipe_lines.push(format!(
            "[{:02}] {:<10} | in={:>8}B → out={:>8}B | {}",
            i + 1,
            method.id(),
            before,
            buf.len(),
            describe_method(method)
        ));
    }
    Ok(ObfuscateResult {
        blob: buf,
        chain: state,
        recipe_lines,
    })
}

/// Build a 4-round random chain. Convenience for callers that want a quick
/// obfuscation without picking methods themselves.
pub fn random_chain(rounds: usize) -> Result<Vec<Method>> {
    (0..rounds).map(|_| instantiate(random_method_id())).collect()
}

/// SHA-256 of the original input bytes (hex-encoded, lowercase). Embedded
/// in the recipe header so a manual decoder can verify they recovered the
/// original after running the inverse chain.
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    HEXUPPER.encode(&digest).to_lowercase()
}

// ---------------------------------------------------------------------------
// Output formats
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Raw,
    Recipe,
    Python,
    PowerShell,
    Bash,
    JavaScript,
    CArray,
}

pub fn parse_format(s: &str) -> Result<OutputFormat> {
    Ok(match s.trim().to_lowercase().as_str() {
        "raw" => OutputFormat::Raw,
        "recipe" => OutputFormat::Recipe,
        "python" | "py" => OutputFormat::Python,
        "powershell" | "ps" | "ps1" => OutputFormat::PowerShell,
        "bash" | "sh" => OutputFormat::Bash,
        "javascript" | "js" | "node" => OutputFormat::JavaScript,
        "c_array" | "c" | "carray" => OutputFormat::CArray,
        other => anyhow::bail!("unknown output format '{}'", other),
    })
}

// ---------------------------------------------------------------------------
// Decoder-stub support matrix
// ---------------------------------------------------------------------------

pub fn supports(method: &Method, fmt: OutputFormat) -> bool {
    use Method::*;
    match (method, fmt) {
        // Raw / Recipe / CArray require no decoder, so they accept everything.
        (_, OutputFormat::Raw) | (_, OutputFormat::Recipe) | (_, OutputFormat::CArray) => true,

        // Python: full coverage.
        (_, OutputFormat::Python) => true,

        // PowerShell.
        (B64, OutputFormat::PowerShell) => true,
        (B16, OutputFormat::PowerShell) => true,
        (XorMulti(_), OutputFormat::PowerShell) => true,
        (Xor1(_), OutputFormat::PowerShell) => true,
        (Url, OutputFormat::PowerShell) => true,
        (Reverse, OutputFormat::PowerShell) => true,
        (Rot13, OutputFormat::PowerShell) => true,
        (Caesar(_), OutputFormat::PowerShell) => true,
        (Utf16Le, OutputFormat::PowerShell) => true,
        (_, OutputFormat::PowerShell) => false,

        // Bash. NOTE: bash strings cannot hold null bytes, so XOR / Caesar /
        // Xor1 stages route through `python3` on stdin/stdout (binary-safe).
        // The "covered" set therefore implies python3-in-PATH for those three.
        (B64, OutputFormat::Bash) => true,
        (B16, OutputFormat::Bash) => true,
        (XorMulti(_), OutputFormat::Bash) => true,
        (Xor1(_), OutputFormat::Bash) => true,
        (Url, OutputFormat::Bash) => true,
        (Reverse, OutputFormat::Bash) => true,
        (Rot13, OutputFormat::Bash) => true,
        (Caesar(_), OutputFormat::Bash) => true,
        (AnsiEscape, OutputFormat::Bash) => true,
        (_, OutputFormat::Bash) => false,

        // JavaScript.
        // NOTE: B32 is intentionally NOT here — Node's Buffer has no built-in
        // base32 decode and shipping a hand-rolled one would balloon the stub.
        (B64, OutputFormat::JavaScript) => true,
        (B64Url, OutputFormat::JavaScript) => true,
        (B16, OutputFormat::JavaScript) => true,
        (XorMulti(_), OutputFormat::JavaScript) => true,
        (Xor1(_), OutputFormat::JavaScript) => true,
        (Url, OutputFormat::JavaScript) => true,
        (Reverse, OutputFormat::JavaScript) => true,
        (Rot13, OutputFormat::JavaScript) => true,
        (Caesar(_), OutputFormat::JavaScript) => true,
        (HexSplit, OutputFormat::JavaScript) => true,
        (_, OutputFormat::JavaScript) => false,
    }
}

// ---------------------------------------------------------------------------
// Method describers (used by recipe / debug output)
// ---------------------------------------------------------------------------

pub fn describe_method(m: &Method) -> String {
    match m {
        Method::XorMulti(k) => format!("key={}", hex_pretty(k)),
        Method::Xor1(b) => format!("key=0x{:02x}", b),
        Method::Caesar(s) => format!("shift={}", s),
        Method::BitRot(s) => format!("shift={}", s),
        Method::Vigenere(k) => format!("key={:?}", String::from_utf8_lossy(k)),
        Method::Rc4(k) => format!("key={}", hex_pretty(k)),
        Method::CharSubst(_) => "table=<256-byte permutation>".into(),
        Method::Chunk(p) if !p.is_empty() => format!("perm-len={}", p.len()),
        Method::Chunk(_) => "perm=<deferred>".into(),
        _ => String::new(),
    }
}

fn hex_pretty(bytes: &[u8]) -> String {
    crate::native::hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Output emitters
// ---------------------------------------------------------------------------

pub fn emit(
    fmt: OutputFormat,
    blob: &[u8],
    chain: &[Method],
    recipe_lines: &[String],
    original: &[u8],
) -> String {
    match fmt {
        OutputFormat::Raw => emit_raw(blob),
        OutputFormat::Recipe => emit_recipe(blob, chain, recipe_lines, original),
        OutputFormat::CArray => emit_c_array(blob),
        OutputFormat::Python => emit_python(blob, chain, original),
        OutputFormat::PowerShell => emit_powershell(blob, chain, original),
        OutputFormat::Bash => emit_bash(blob, chain, original),
        OutputFormat::JavaScript => emit_javascript(blob, chain, original),
    }
}

fn emit_raw(blob: &[u8]) -> String {
    // If the blob is valid UTF-8 we print it as-is (most encoders produce
    // ASCII); otherwise we hex-encode for safety.
    match std::str::from_utf8(blob) {
        Ok(s) => s.to_string(),
        Err(_) => HEXUPPER.encode(blob),
    }
}

fn emit_recipe(blob: &[u8], chain: &[Method], recipe_lines: &[String], original: &[u8]) -> String {
    let mut out = String::new();
    out.push_str("# Obfuscator recipe — apply the inverse of each round in REVERSE order:\n");
    out.push_str("#\n");
    for line in recipe_lines.iter().rev() {
        out.push_str("#   ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("#\n");
    out.push_str("# Forward (encoding) order:\n");
    for (i, m) in chain.iter().enumerate() {
        out.push_str(&format!("#   {:02}. {} {}\n", i + 1, m.id(), describe_method(m)));
    }
    out.push_str("#\n");
    out.push_str(&format!(
        "# original: {} B, sha256={}\n",
        original.len(),
        sha256_hex(original)
    ));
    out.push_str("#\n");
    out.push_str("# Encoded blob follows.\n");
    match std::str::from_utf8(blob) {
        Ok(s) => out.push_str(s),
        Err(_) => out.push_str(&HEXUPPER.encode(blob)),
    }
    out.push('\n');
    out
}

fn emit_c_array(blob: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "/* obfuscator output — {} bytes; user must supply matching decoder. */\n",
        blob.len()
    ));
    out.push_str(&format!("unsigned char obf_payload[{}] = {{\n    ", blob.len()));
    for (i, b) in blob.iter().enumerate() {
        out.push_str(&format!("0x{:02x}", b));
        if i != blob.len() - 1 {
            out.push_str(", ");
            if (i + 1) % 16 == 0 {
                out.push_str("\n    ");
            }
        }
    }
    out.push_str("\n};\n");
    out
}

fn emit_python(blob: &[u8], chain: &[Method], original: &[u8]) -> String {
    let blob_b64 = BASE64.encode(blob);
    let mut out = String::new();
    out.push_str("#!/usr/bin/env python3\n");
    out.push_str("# obfuscator-generated self-decoder. DO NOT EDIT THE BLOB.\n");
    out.push_str("import base64, gzip, sys, codecs, os\n");
    out.push_str("\n");
    out.push_str("# helper functions for every method we may have used:\n");
    out.push_str(PY_HELPERS);
    out.push_str("\n");
    out.push_str(&format!("BLOB = base64.b64decode({:?})\n", blob_b64));
    out.push_str("DATA = BLOB  # final encoded form\n");
    out.push_str("\n");
    out.push_str("# decode chain (inverse of encoding):\n");
    for m in chain.iter().rev() {
        let line = py_inverse(m);
        out.push_str(&format!("DATA = {}\n", line));
    }
    out.push_str("\n");
    out.push_str(&format!(
        "# Original was {} bytes. Uncomment to execute:\n",
        original.len()
    ));
    out.push_str("# os.write(1, DATA)\n");
    out.push_str("if __name__ == '__main__':\n");
    out.push_str("    sys.stdout.buffer.write(DATA)\n");
    out
}

const PY_HELPERS: &str = r#"
def _xor(data, key):
    if not key: return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
def _rot13_bytes(data):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        if 0x41 <= b <= 0x5a: out[i] = 0x41 + (b - 0x41 + 13) % 26
        elif 0x61 <= b <= 0x7a: out[i] = 0x61 + (b - 0x61 + 13) % 26
        else: out[i] = b
    return bytes(out)
def _rot47_bytes(data):
    return bytes((33 + (b - 33 + 47) % 94) if 33 <= b <= 126 else b for b in data)
def _caesar(data, shift):
    return bytes((b - shift) & 0xff for b in data)
def _bitrot_dec(data, shift):
    return bytes(((b >> shift) | (b << (8 - shift))) & 0xff for b in data)
def _vigenere_dec(data, key):
    shifts = [(b - 0x41) % 26 if 0x41 <= b <= 0x5a else (b - 0x61) % 26 if 0x61 <= b <= 0x7a else 0 for b in key]
    return bytes((b - shifts[i % len(shifts)]) & 0xff for i, b in enumerate(data))
def _rc4(data, key):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)
def _b85_dec(data):
    import base64 as _b
    return _b.a85decode(data)
def _b91_dec(data):
    table = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    inv = {c: i for i, c in enumerate(table)}
    v = -1; b = 0; n = 0; out = bytearray()
    for c in data:
        if c not in inv: continue
        if v < 0:
            v = inv[c]
        else:
            v += inv[c] * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 0xff); b >>= 8; n -= 8
            v = -1
    if v + 1: out.append((b | v << n) & 0xff)
    return bytes(out)
def _zw_dec(data):
    bits = []
    s = data.decode('utf-8', 'ignore')
    for ch in s:
        if ch == '‌': bits.append(1)
        elif ch == '​': bits.append(0)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for j in range(8): v = (v << 1) | bits[i + j]
        out.append(v)
    return bytes(out)
def _hexsplit_dec(data):
    s = data.decode('latin-1') if isinstance(data, bytes) else data
    out = bytearray(); i = 0
    while i < len(s):
        if s[i:i+2] == '\\x' and i + 4 <= len(s):
            out.append(int(s[i+2:i+4], 16)); i += 4
        else:
            i += 1
    return bytes(out)
def _utf16_dec(data):
    if len(data) % 2: data = data[:-1]
    return bytes(data[i] for i in range(0, len(data), 2))
def _ansi_dec(data):
    s = data.decode('latin-1') if isinstance(data, bytes) else data
    out = bytearray(); i = 0
    while i < len(s):
        if s[i:i+4] == "$'\\x" and i + 7 <= len(s) and s[i+6] == "'":
            out.append(int(s[i+4:i+6], 16)); i += 7
        else:
            i += 1
    return bytes(out)
def _csub_dec(data, table):
    inv = [0] * 256
    for i, b in enumerate(table): inv[b] = i
    return bytes(inv[b] for b in data)
def _chunk_dec(data, perm):
    out = bytearray(len(data))
    for dst, src in enumerate(perm):
        if src < len(data) and dst < len(out): out[src] = data[dst]
    return bytes(out)
def _url_dec(data):
    s = data.decode('latin-1') if isinstance(data, bytes) else data
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '%' and i + 3 <= len(s):
            out.append(int(s[i+1:i+3], 16)); i += 3
        else:
            out.append(ord(s[i])); i += 1
    return bytes(out)
"#;

fn py_inverse(m: &Method) -> String {
    match m {
        Method::XorMulti(k) | Method::Rc4(k) => {
            let key_b64 = BASE64.encode(k);
            if matches!(m, Method::Rc4(_)) {
                format!("_rc4(DATA, base64.b64decode({:?}))", key_b64)
            } else {
                format!("_xor(DATA, base64.b64decode({:?}))", key_b64)
            }
        }
        Method::Xor1(b) => format!("_xor(DATA, bytes([0x{:02x}]))", b),
        Method::B16 => "base64.b16decode(DATA, casefold=True)".into(),
        Method::B32 => "base64.b32decode(DATA)".into(),
        Method::B32Hex => "base64.b32hexdecode(DATA)".into(),
        Method::B64 => "base64.b64decode(DATA)".into(),
        Method::B64Url => "base64.urlsafe_b64decode(DATA)".into(),
        Method::B85 => "_b85_dec(DATA)".into(),
        Method::B91 => "_b91_dec(DATA)".into(),
        Method::Rot13 => "_rot13_bytes(DATA)".into(),
        Method::Rot47 => "_rot47_bytes(DATA)".into(),
        Method::Reverse => "DATA[::-1]".into(),
        Method::Gzip => "gzip.decompress(DATA)".into(),
        Method::Url => "_url_dec(DATA)".into(),
        Method::Caesar(s) => format!("_caesar(DATA, {})", s),
        Method::BitRot(s) => format!("_bitrot_dec(DATA, {})", s),
        Method::Vigenere(k) => format!("_vigenere_dec(DATA, {:?})", k),
        Method::ZeroWidth => "_zw_dec(DATA)".into(),
        Method::HexSplit => "_hexsplit_dec(DATA)".into(),
        Method::Utf16Le => "_utf16_dec(DATA)".into(),
        Method::CharSubst(t) => {
            let key_b64 = BASE64.encode(&t[..]);
            format!("_csub_dec(DATA, base64.b64decode({:?}))", key_b64)
        }
        Method::AnsiEscape => "_ansi_dec(DATA)".into(),
        Method::Chunk(p) => {
            let json: String = p.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
            format!("_chunk_dec(DATA, [{}])", json)
        }
    }
}

// ---------------------------------------------------------------------------
// PowerShell emitter (subset)
// ---------------------------------------------------------------------------

fn emit_powershell(blob: &[u8], chain: &[Method], original: &[u8]) -> String {
    let blob_b64 = BASE64.encode(blob);
    let mut out = String::new();
    out.push_str("# obfuscator-generated PowerShell self-decoder.\n");
    out.push_str("# Methods covered: b64, b16, xor, xor1, url, rev, rot13, caesar, utf16le.\n");
    out.push_str(&format!(
        "$blob = [Convert]::FromBase64String('{}')\n",
        blob_b64
    ));
    out.push_str("$DATA = $blob\n");
    out.push_str(PS_HELPERS);
    for m in chain.iter().rev() {
        out.push_str(&ps_inverse(m));
        out.push('\n');
    }
    out.push_str(&format!(
        "# Original was {} bytes. Uncomment to execute:\n",
        original.len()
    ));
    out.push_str("# Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($DATA))\n");
    out.push_str("[System.Text.Encoding]::UTF8.GetString($DATA)\n");
    out
}

// Each helper writes into `$script:_obf_buf` instead of returning a value, so
// PowerShell's pipeline-unrolling can't accidentally collect the byte[] into
// `Object[]` (which corrupts it for the next stage). Callers consume the
// global, then re-assign $DATA. Slightly verbose but bulletproof.
const PS_HELPERS: &str = r#"
$script:_obf_buf = $null
function _Xor([byte[]]$d, [byte[]]$k) {
    $o = New-Object byte[] $d.Length
    for ($i=0; $i -lt $d.Length; $i++) { $o[$i] = $d[$i] -bxor $k[$i % $k.Length] }
    $script:_obf_buf = $o
}
function _Rot13Bytes([byte[]]$d) {
    $o = New-Object byte[] $d.Length
    for ($i=0; $i -lt $d.Length; $i++) {
        $b = $d[$i]
        if ($b -ge 0x41 -and $b -le 0x5a) { $o[$i] = 0x41 + ((($b - 0x41) + 13) % 26) }
        elseif ($b -ge 0x61 -and $b -le 0x7a) { $o[$i] = 0x61 + ((($b - 0x61) + 13) % 26) }
        else { $o[$i] = $b }
    }
    $script:_obf_buf = $o
}
function _Caesar([byte[]]$d, [byte]$s) {
    $o = New-Object byte[] $d.Length
    for ($i=0; $i -lt $d.Length; $i++) { $o[$i] = ($d[$i] - $s) -band 0xff }
    $script:_obf_buf = $o
}
function _UrlDec([byte[]]$d) {
    $s = [System.Text.Encoding]::Latin1.GetString($d)
    $o = New-Object System.Collections.Generic.List[byte]
    $i = 0
    while ($i -lt $s.Length) {
        if ($s[$i] -eq '%' -and $i + 3 -le $s.Length) {
            $o.Add([Convert]::ToByte($s.Substring($i+1, 2), 16)); $i += 3
        } else { $o.Add([byte]$s[$i]); $i++ }
    }
    $script:_obf_buf = $o.ToArray()
}
# Binary-safe hex decode: walk every two latin-1 chars and parse as u8.
function _Hex16Dec([byte[]]$d) {
    $s = [System.Text.Encoding]::Latin1.GetString($d)
    $o = New-Object byte[] ($s.Length / 2)
    for ($i = 0; $i + 1 -lt $s.Length; $i += 2) {
        $o[$i / 2] = [Convert]::ToByte($s.Substring($i, 2), 16)
    }
    $script:_obf_buf = $o
}
# Strip every other byte (the high byte zero injected by utf16le_encode).
function _Utf16LeStrip([byte[]]$d) {
    $o = New-Object byte[] (($d.Length + 1) / 2)
    for ($i = 0; $i -lt $o.Length; $i++) { $o[$i] = $d[$i * 2] }
    $script:_obf_buf = $o
}
"#;

fn ps_inverse(m: &Method) -> String {
    // Helpers write to `$script:_obf_buf` (a global byte[]) instead of
    // returning a value — PowerShell's pipeline can otherwise collect a
    // returned byte[] into Object[], which corrupts the chain at the next
    // stage. Callers re-assign $DATA from the global immediately after.
    match m {
        Method::XorMulti(k) => {
            let bytes = k.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(",");
            format!("_Xor $DATA @({}); $DATA = $script:_obf_buf", bytes)
        }
        Method::Xor1(b) => format!("_Xor $DATA @(0x{:02x}); $DATA = $script:_obf_buf", b),
        Method::B64 => "$DATA = [Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($DATA))".into(),
        // Binary-safe: avoid round-trip through [char] (UTF-16 widening corrupts 0x80–0xFF).
        Method::B16 => "_Hex16Dec $DATA; $DATA = $script:_obf_buf".into(),
        Method::Url => "_UrlDec $DATA; $DATA = $script:_obf_buf".into(),
        Method::Reverse => "[Array]::Reverse($DATA)".into(),
        Method::Rot13 => "_Rot13Bytes $DATA; $DATA = $script:_obf_buf".into(),
        Method::Caesar(s) => format!("_Caesar $DATA 0x{:02x}; $DATA = $script:_obf_buf", s),
        Method::Utf16Le => "_Utf16LeStrip $DATA; $DATA = $script:_obf_buf".into(),
        _ => format!("# unsupported in PowerShell: {}", m.id()),
    }
}

// ---------------------------------------------------------------------------
// Bash emitter (subset)
// ---------------------------------------------------------------------------

fn emit_bash(blob: &[u8], chain: &[Method], original: &[u8]) -> String {
    let blob_b64 = BASE64.encode(blob);
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\n");
    out.push_str("# obfuscator-generated bash self-decoder.\n");
    out.push_str("# Methods covered: b64, b16, url, rev, rot13, ansi (pure bash);\n");
    out.push_str("#                  xor, xor1, caesar (require python3 in PATH).\n");
    out.push_str("# WARNING: bash strings cannot hold null bytes — this decoder is\n");
    out.push_str("#          unreliable for binary payloads. Prefer the python format.\n");
    out.push_str(&format!("DATA=$(printf %s '{}' | base64 -d)\n", blob_b64));
    out.push_str(BASH_HELPERS);
    for m in chain.iter().rev() {
        out.push_str(&bash_inverse(m));
        out.push('\n');
    }
    out.push_str(&format!(
        "# Original was {} bytes. Uncomment to eval:\n",
        original.len()
    ));
    out.push_str("# eval \"$DATA\"\n");
    out.push_str("printf %s \"$DATA\"\n");
    out
}

const BASH_HELPERS: &str = r#"
# Force byte-oriented locale — every helper that walks bytes assumes the
# shell does no UTF-8 normalization in between.
export LC_ALL=C
# Always pipe via `printf %s "$DATA"` (no trailing newline). The `<<<` here-
# string adds a trailing newline that corrupts byte-exact decoders.
_rot13() { DATA=$(printf %s "$DATA" | tr 'A-Za-z' 'N-ZA-Mn-za-m'); }
# python3-backed reverse — pure-bash `rev` is line-oriented and falls over
# on binary buffers with embedded newlines.
_rev_py() { DATA=$(printf %s "$DATA" | python3 -c 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])'); }
_url()   { DATA=$(printf %s "$DATA" | sed -E 's/%([0-9A-Fa-f]{2})/\\\x\1/g' | xargs -I{} printf '%b' '{}'); }
# python3-backed byte-level XOR — bash strings can't hold null bytes, but a
# subshell pipe through python keeps the buffer intact for the next stage.
_xor_py() { DATA=$(printf %s "$DATA" | python3 -c 'import sys;d=sys.stdin.buffer.read();k=bytes.fromhex(sys.argv[1]);sys.stdout.buffer.write(bytes(b^k[i%len(k)] for i,b in enumerate(d)))' "$1"); }
"#;

fn bash_inverse(m: &Method) -> String {
    match m {
        Method::B64 => "DATA=$(printf %s \"$DATA\" | base64 -d)".into(),
        Method::B16 => "DATA=$(printf %s \"$DATA\" | xxd -r -p)".into(),
        Method::Reverse => "_rev_py".into(),
        Method::Rot13 => "_rot13".into(),
        Method::Url => "_url".into(),
        Method::Xor1(b) => format!("_xor_py {:02x}", b),
        Method::XorMulti(k) => {
            format!("_xor_py {}", crate::native::hex::encode(k))
        }
        Method::Caesar(s) => format!(
            "DATA=$(printf %s \"$DATA\" | python3 -c 'import sys;d=sys.stdin.buffer.read();sys.stdout.buffer.write(bytes((b-{})&0xff for b in d))')",
            s
        ),
        Method::AnsiEscape => "DATA=$(eval \"printf %s $DATA\")".into(),
        _ => format!("# unsupported in bash: {}", m.id()),
    }
}

// ---------------------------------------------------------------------------
// JavaScript emitter (subset)
// ---------------------------------------------------------------------------

fn emit_javascript(blob: &[u8], chain: &[Method], original: &[u8]) -> String {
    let blob_b64 = BASE64.encode(blob);
    let mut out = String::new();
    out.push_str("// obfuscator-generated JS / Node self-decoder.\n");
    out.push_str("// Methods covered: b64, b64url, b16, xor, xor1, url, rev, rot13, caesar, hexsplit.\n");
    out.push_str(&format!(
        "let DATA = Buffer.from('{}', 'base64');\n",
        blob_b64
    ));
    out.push_str(JS_HELPERS);
    for m in chain.iter().rev() {
        out.push_str(&js_inverse(m));
        out.push('\n');
    }
    out.push_str(&format!(
        "// Original was {} bytes. Uncomment to execute:\n",
        original.len()
    ));
    out.push_str("// eval(DATA.toString());\n");
    out.push_str("process.stdout.write(DATA);\n");
    out
}

const JS_HELPERS: &str = r#"
function _xor(d, k) {
    const out = Buffer.alloc(d.length);
    for (let i = 0; i < d.length; i++) out[i] = d[i] ^ k[i % k.length];
    return out;
}
function _rot13(d) {
    return Buffer.from([...d].map(b => {
        if (b >= 0x41 && b <= 0x5a) return 0x41 + (b - 0x41 + 13) % 26;
        if (b >= 0x61 && b <= 0x7a) return 0x61 + (b - 0x61 + 13) % 26;
        return b;
    }));
}
function _caesar(d, s) {
    return Buffer.from([...d].map(b => (b - s) & 0xff));
}
function _urlDec(d) {
    const s = d.toString('latin1');
    const out = [];
    for (let i = 0; i < s.length; ) {
        if (s[i] === '%' && i + 3 <= s.length) {
            out.push(parseInt(s.substr(i + 1, 2), 16)); i += 3;
        } else {
            out.push(s.charCodeAt(i)); i++;
        }
    }
    return Buffer.from(out);
}
function _hexsplitDec(d) {
    const s = d.toString('latin1');
    const out = [];
    for (let i = 0; i < s.length; ) {
        if (s.substr(i, 2) === '\\x' && i + 4 <= s.length) {
            out.push(parseInt(s.substr(i + 2, 2), 16)); i += 4;
        } else { i++; }
    }
    return Buffer.from(out);
}
"#;

fn js_inverse(m: &Method) -> String {
    match m {
        Method::B64 => "DATA = Buffer.from(DATA.toString(), 'base64');".into(),
        Method::B64Url => "DATA = Buffer.from(DATA.toString().replace(/-/g,'+').replace(/_/g,'/'), 'base64');".into(),
        Method::B16 => "DATA = Buffer.from(DATA.toString(), 'hex');".into(),
        Method::Reverse => "DATA = Buffer.from([...DATA].reverse());".into(),
        Method::Rot13 => "DATA = _rot13(DATA);".into(),
        Method::Caesar(s) => format!("DATA = _caesar(DATA, {});", s),
        Method::Url => "DATA = _urlDec(DATA);".into(),
        Method::HexSplit => "DATA = _hexsplitDec(DATA);".into(),
        Method::XorMulti(k) => {
            let bytes = k.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(",");
            format!("DATA = _xor(DATA, Buffer.from([{}]));", bytes)
        }
        Method::Xor1(b) => format!("DATA = _xor(DATA, Buffer.from([0x{:02x}]));", b),
        _ => format!("// unsupported in JS: {}", m.id()),
    }
}
