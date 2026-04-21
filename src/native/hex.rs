// Vendored from hex 0.4.3 (MIT/Apache-2.0). Maintained in-tree.

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as a lowercase hex string.
#[inline]
pub fn encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().saturating_mul(2));
    for &byte in data {
        s.push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char);
        s.push(HEX_CHARS_LOWER[(byte & 0x0f) as usize] as char);
    }
    s
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

