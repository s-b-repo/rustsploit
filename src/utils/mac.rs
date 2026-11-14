// src/utils/mac.rs
//
// Bluetooth device-address helpers.
//
// These live OUTSIDE the `bluetooth` feature gate on purpose: the framework
// itself has to recognise a device address as a *target* — `set target
// AA:BB:CC:DD:EE:FF`, `run -t AA:BB:CC:DD:EE:FF` — and it has to be able to
// say "this is not an IP host" even in a `--no-default-features` build that
// has no Bluetooth support at all.
//
// A device address has five colons, so it looks like a malformed IPv6
// literal to the generic target parser. `normalize_target` therefore used to
// reject every MAC with "Invalid IPv6 address format", which made the
// documented per-run Bluetooth targeting unreachable (`setg target_mac` was
// the only working path).

use anyhow::Result;

/// True if `s` looks like a Bluetooth device address `AA:BB:CC:DD:EE:FF`.
///
/// `-` separators are accepted as well (`AA-BB-CC-DD-EE-FF`).
pub fn is_mac_addr(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Parse `AA:BB:CC:DD:EE:FF` (also `-` separated) into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        anyhow::bail!("malformed MAC address: {s}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|e| anyhow::anyhow!("bad MAC octet '{p}' in {s}: {e}"))?;
    }
    Ok(out)
}

/// Format 6 bytes as `AA:BB:CC:DD:EE:FF`.
pub fn mac_to_string(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}:"))
        .collect::<String>()
        .trim_end_matches(':')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_shape_is_recognised() {
        assert!(is_mac_addr("AA:BB:CC:DD:EE:FF")); // audit-allow: test
        assert!(is_mac_addr("aa:bb:cc:dd:ee:ff")); // audit-allow: test
        assert!(is_mac_addr("AA-BB-CC-DD-EE-FF")); // audit-allow: test
        assert!(!is_mac_addr("AA:BB:CC")); // audit-allow: test
        assert!(!is_mac_addr("AA:BB:CC:DD:EE:GG")); // audit-allow: test
        assert!(!is_mac_addr("127.0.0.1")); // audit-allow: test
        assert!(!is_mac_addr("")); // audit-allow: test
    }

    #[test]
    fn mac_roundtrip() {
        let bytes = parse_mac("AA:BB:CC:DD:EE:FF").expect("parse"); // audit-allow: test
        assert_eq!(bytes, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // audit-allow: test
        assert_eq!(mac_to_string(&bytes), "AA:BB:CC:DD:EE:FF"); // audit-allow: test
    }
}
