use super::signatures::known_signatures;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassVerdict {
    Success,
    Blocked { status: u16, reason: String },
    Challenged { reason: String },
    Unknown { status: u16 },
    Error { message: String },
}

pub fn is_blocked(
    status: u16,
    body: &str,
    headers: &std::collections::HashMap<String, String>,
) -> Option<BypassVerdict> {
    let sigs = known_signatures();
    // Check if status code matches any known WAF block code
    for sig in sigs.iter() {
        if sig.status_codes.contains(&status) {
            return Some(BypassVerdict::Blocked {
                status,
                reason: format!(
                    "status {} matches {} (vendor: {})",
                    status,
                    sig.name,
                    sig.vendor_name()
                ),
            });
        }
    }

    let body_lower = body.to_lowercase();
    for sig in known_signatures().iter() {
        for pattern in sig.body_patterns {
            if body_lower.contains(pattern) {
                return Some(BypassVerdict::Blocked {
                    status,
                    reason: format!("body matches '{}' ({})", pattern, sig.name),
                });
            }
        }
    }

    for sig in known_signatures().iter() {
        for header_sig in sig.headers {
            if let Some((key_part, val_part)) = header_sig.split_once(':') {
                let key_lower = key_part.trim().to_lowercase();
                let val_lower = val_part.trim().to_lowercase();
                if headers.iter().any(|(k, v)| {
                    k.to_lowercase().contains(&key_lower) && v.to_lowercase().contains(&val_lower)
                }) {
                    return Some(BypassVerdict::Challenged {
                        reason: format!("header '{}' matches ({})", header_sig, sig.name),
                    });
                }
            } else {
                let key_lower = header_sig.trim().to_lowercase();
                if headers
                    .iter()
                    .any(|(k, _)| k.to_lowercase().contains(&key_lower))
                {
                    return Some(BypassVerdict::Challenged {
                        reason: format!("header '{}' matches ({})", header_sig, sig.name),
                    });
                }
            }
        }
    }

    None
}

pub fn classify_response(
    status: u16,
    body: &str,
    headers: &std::collections::HashMap<String, String>,
) -> BypassVerdict {
    if status == 0 {
        return BypassVerdict::Error {
            message: "connection failed".into(),
        };
    }
    if let Some(verdict) = is_blocked(status, body, headers) {
        return verdict;
    }
    if (200..400).contains(&status) {
        return BypassVerdict::Success;
    }
    BypassVerdict::Unknown { status }
}

pub fn detect_waf(headers: &std::collections::HashMap<String, String>, body: &str) -> Vec<String> {
    let body_lower = body.to_lowercase();
    let mut detected: Vec<String> = Vec::new();
    for sig in known_signatures().iter() {
        let mut matched = false;
        for pattern in sig.body_patterns {
            if body_lower.contains(pattern) {
                matched = true;
                break;
            }
        }
        if !matched {
            for cookie in sig.cookies {
                if headers.iter().any(|(k, v)| {
                    k.to_lowercase().contains("set-cookie") && v.to_lowercase().contains(cookie)
                }) {
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            for hdr in sig.headers {
                if let Some((key_part, val_part)) = hdr.split_once(':') {
                    let key_lower = key_part.trim().to_lowercase();
                    let val_lower = val_part.trim().to_lowercase();
                    if headers.iter().any(|(k, v)| {
                        k.to_lowercase().contains(&key_lower)
                            && v.to_lowercase().contains(&val_lower)
                    }) {
                        matched = true;
                        break;
                    }
                } else {
                    let key_lower = hdr.trim().to_lowercase();
                    if headers
                        .iter()
                        .any(|(k, _)| k.to_lowercase().contains(&key_lower))
                    {
                        matched = true;
                        break;
                    }
                }
            }
        }
        if matched {
            detected.push(sig.name.to_string());
        }
    }
    detected
}
