// Vendored from hex 0.4.3 (MIT/Apache-2.0). Maintained in-tree.
//
// Provides lowercase hex encoding without pulling in an external crate.
// Decode support and uppercase encoding were removed — no callers exist.

// ── lookup tables ──────────────────────────────────────────────────

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

// ── public API ─────────────────────────────────────────────────────

/// Encode bytes as a lowercase hex string.
#[inline]
pub fn encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        s.push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char);
        s.push(HEX_CHARS_LOWER[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_basic() {
        assert_eq!(encode(b"Hello world!"), "48656c6c6f20776f726c6421");
    }

    #[test]
    fn encode_ff() {
        assert_eq!(encode(b"\xff\x00"), "ff00");
    }

    #[test]
    fn empty() {
        assert_eq!(encode(b""), "");
    }
}
