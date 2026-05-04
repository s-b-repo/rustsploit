// Vendored from hex 0.4.3 (MIT/Apache-2.0). Maintained in-tree.

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Encode a single byte as a lowercase hex pair (e.g. `0xab` -> `[b'a', b'b']`).
/// Avoids the `format!("{:02x}", b)` allocation in tight loops.
#[inline]
pub fn byte_to_lower(b: u8) -> [u8; 2] {
    [
        HEX_CHARS_LOWER[(b >> 4) as usize],
        HEX_CHARS_LOWER[(b & 0x0f) as usize],
    ]
}

/// Encode a single byte as an uppercase hex pair (e.g. `0xab` -> `[b'A', b'B']`).
#[inline]
pub fn byte_to_upper(b: u8) -> [u8; 2] {
    [
        HEX_CHARS_UPPER[(b >> 4) as usize],
        HEX_CHARS_UPPER[(b & 0x0f) as usize],
    ]
}

/// Encode bytes as a lowercase hex string.
#[inline]
pub fn encode(data: &[u8]) -> String {
    let mut buf = vec![0u8; data.len().saturating_mul(2)];
    encode_into(data, &mut buf);
    // SAFETY: `encode_into` only writes bytes from `HEX_CHARS_LOWER`, all of
    // which are valid ASCII (and therefore valid UTF-8).
    unsafe { String::from_utf8_unchecked(buf) }
}

/// Encode bytes as an uppercase hex string.
#[inline]
pub fn encode_upper(data: &[u8]) -> String {
    let mut buf = vec![0u8; data.len().saturating_mul(2)];
    encode_upper_into(data, &mut buf);
    // SAFETY: only ASCII bytes from `HEX_CHARS_UPPER` are written.
    unsafe { String::from_utf8_unchecked(buf) }
}

/// Encode `data` into the start of `out`. Caller must ensure `out.len() >= data.len() * 2`.
#[inline]
fn encode_into(data: &[u8], out: &mut [u8]) {
    debug_assert!(out.len() >= data.len() * 2);
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX_CHARS_LOWER[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS_LOWER[(byte & 0x0f) as usize];
    }
}

#[inline]
fn encode_upper_into(data: &[u8], out: &mut [u8]) {
    debug_assert!(out.len() >= data.len() * 2);
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX_CHARS_UPPER[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS_UPPER[(byte & 0x0f) as usize];
    }
}

/// Decode a hex string into bytes. Accepts uppercase and lowercase.
/// Returns `Err` on odd-length input or invalid hex characters.
pub fn decode(hex: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DecodeError::OddLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn nibble(b: u8) -> Result<u8, DecodeError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DecodeError::InvalidChar(b as char)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    OddLength,
    InvalidChar(char),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength => write!(f, "odd-length hex string"),
            Self::InvalidChar(c) => write!(f, "invalid hex character: {:?}", c),
        }
    }
}

impl std::error::Error for DecodeError {}

