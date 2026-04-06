// Vendored from urlencoding 2.1.3 (MIT). Maintained in-tree.
//
// Zero-copy percent-encoding using Cow<str>.
// Decode support was removed — no callers exist (react2shell uses its own
// form-urlencoded decoder with + → space semantics).

use std::borrow::Cow;

// ── encoding ───────────────────────────────────────────────────────

/// Percent-encode a UTF-8 string.
///
/// Every byte except alphanumerics and `-`, `_`, `.`, `~` is encoded.
/// Returns `Cow::Borrowed` when no encoding is needed.
#[inline(always)]
pub fn encode(data: &str) -> Cow<'_, str> {
    encode_binary(data.as_bytes())
}

/// Percent-encode arbitrary bytes.
#[inline]
pub fn encode_binary(data: &[u8]) -> Cow<'_, str> {
    let mut escaped = String::with_capacity(data.len() | 15);
    let unmodified = append_string(data, &mut escaped, true);
    if unmodified {
        // SAFETY: encode_into only returns true when every byte matched the ASCII-safe set
        // (alphanumerics and `-._~`), which is always valid UTF-8.
        if let Ok(s) = std::str::from_utf8(data) {
            return Cow::Borrowed(s);
        }
        // Fallback: non-UTF-8 input that happened to be all safe bytes — encode it.
        // This shouldn't happen in practice but avoids a panic.
    }
    Cow::Owned(escaped)
}

fn append_string(data: &[u8], escaped: &mut String, may_skip: bool) -> bool {
    encode_into(data, may_skip, |s| {
        escaped.push_str(s);
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible: closure returns Ok with Infallible error type")
}

fn encode_into<E>(
    mut data: &[u8],
    may_skip_write: bool,
    mut push_str: impl FnMut(&str) -> Result<(), E>,
) -> Result<bool, E> {
    let mut pushed = false;
    loop {
        let ascii_len = data
            .iter()
            .take_while(|&&c| {
                matches!(c, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~')
            })
            .count();

        let (safe, rest) = if ascii_len >= data.len() {
            if !pushed && may_skip_write {
                return Ok(true);
            }
            (data, &[][..])
        } else {
            data.split_at(ascii_len)
        };
        pushed = true;
        if !safe.is_empty() {
            // safe bytes are guaranteed to be ASCII alphanumeric or -._~ — always valid UTF-8
            let safe_str = std::str::from_utf8(safe).unwrap_or("");
            push_str(safe_str)?;
        }
        if rest.is_empty() {
            break;
        }

        match rest.split_first() {
            Some((byte, rest)) => {
                let enc = [b'%', to_hex_digit(byte >> 4), to_hex_digit(byte & 15)];
                // hex digits are always ASCII — safe to convert
                let hex_str = std::str::from_utf8(&enc).unwrap_or("%3F");
                push_str(hex_str)?;
                data = rest;
            }
            None => break,
        }
    }
    Ok(false)
}

#[inline]
fn to_hex_digit(digit: u8) -> u8 {
    match digit {
        0..=9 => b'0' + digit,
        10..=255 => b'A' - 10 + digit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_special() {
        let encoded = encode("hello world! foo@bar");
        assert_eq!(encoded, "hello%20world%21%20foo%40bar");
    }

    #[test]
    fn borrow_when_clean() {
        assert!(matches!(encode("pureascii"), Cow::Borrowed(_)));
    }

    #[test]
    fn emoji() {
        assert_eq!(encode("👾"), "%F0%9F%91%BE");
    }
}
