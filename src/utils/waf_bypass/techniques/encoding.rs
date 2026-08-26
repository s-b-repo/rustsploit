use anyhow::{Context, Result};

use super::Technique;

pub fn encode_payload(payload: &[u8], technique: Technique) -> Result<Vec<u8>> {
    let s = std::str::from_utf8(payload).context("payload is not valid UTF-8")?;
    let encoded = match technique {
        Technique::UrlEncodeSpecials => url_encode_specials(s),
        Technique::DoubleUrlEncode => url_encode_double(s),
        Technique::UnicodeNormalize => unicode_normalize(s),
        _ => return Ok(payload.to_vec()),
    };
    Ok(encoded.into_bytes())
}

fn url_encode_specials(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\'' => "%27".into(),
            '"' => "%22".into(),
            '<' => "%3C".into(),
            '>' => "%3E".into(),
            ' ' => "%20".into(),
            ';' => "%3B".into(),
            '=' => "%3D".into(),
            '&' => "%26".into(),
            '#' => "%23".into(),
            '%' => "%25".into(),
            '\0' => "%00".into(),
            '\n' => "%0A".into(),
            '\r' => "%0D".into(),
            '\\' => "%5C".into(),
            _ => c.to_string(),
        })
        .collect()
}

fn url_encode_double(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\'' => "%2527".into(),
            '"' => "%2522".into(),
            '<' => "%253C".into(),
            '>' => "%253E".into(),
            ' ' => "%2520".into(),
            '\0' => "%2500".into(),
            '\n' => "%250A".into(),
            '\r' => "%250D".into(),
            ';' => "%253B".into(),
            '%' => "%2525".into(),
            other => format!("%25{:02X}", other as u8),
        })
        .collect()
}

fn unicode_normalize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\'' => "%u0027".into(),
            '"' => "%u0022".into(),
            '<' => "%u003C".into(),
            '>' => "%u003E".into(),
            ';' => "%u003B".into(),
            _ => c.to_string(),
        })
        .collect()
}
