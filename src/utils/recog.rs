//! Recog fingerprint engine — service / product / OS detection from banners.
//!
//! This is a Rust port of the matcher loop from Rapid7's **Recog**
//! (<https://github.com/rapid7/recog>) and the `recog-go` reference
//! implementation. Recog is distributed under the **BSD-2-Clause** license.
//!
//! The vendored XML fingerprint databases under `src/utils/recog_db/` are
//! trimmed subsets of the upstream Recog databases (BSD-2-Clause,
//! <https://github.com/rapid7/recog/tree/main/xml>). They retain the upstream
//! `<fingerprints>` / `<fingerprint>` / `<param>` schema so the matcher logic
//! mirrors Recog exactly.
//!
//! ## Format
//!
//! ```xml
//! <fingerprints matches="...">
//!   <fingerprint pattern="REGEX">
//!     <description>..</description>
//!     <example>..</example>
//!     <param pos="0" name="service.product" value="OpenSSH"/>
//!     <param pos="1" name="service.version"/>
//!   </fingerprint>
//! </fingerprints>
//! ```
//!
//! Matching rule (per Recog):
//! - Compile each `<fingerprint>` `pattern` (case-insensitive) once at load.
//! - For an input banner, the first fingerprint whose regex matches wins.
//! - Build the result map from its `<param>`s:
//!   - `pos="0"` → literal `value` (interpolating `{field}` placeholders that
//!     refer to already-extracted fields).
//!   - `pos>=1` → the value comes from regex capture group N.

use once_cell::sync::Lazy;
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use std::collections::BTreeMap;

/// A single compiled fingerprint: its regex plus the parameter recipe.
struct Fingerprint {
    regex: Regex,
    /// Each entry: (pos, name, literal_value). For `pos == 0` the value is the
    /// literal (possibly with `{field}` placeholders); for `pos >= 1` the value
    /// comes from capture group `pos` and `literal_value` is empty.
    params: Vec<RecogParam>,
}

struct RecogParam {
    pos: usize,
    name: String,
    value: String,
}

/// One named fingerprint database (e.g. the SSH banners DB).
pub struct RecogDb {
    name: &'static str,
    fingerprints: Vec<Fingerprint>,
}

/// The outcome of matching a banner against a database.
#[derive(Debug, Clone, Default)]
pub struct RecogMatch {
    pub matched: bool,
    pub fields: BTreeMap<String, String>,
}

impl RecogMatch {
    /// Convenience accessor for a field (e.g. `"service.product"`).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// Detected product name, if any (`service.product`).
    pub fn product(&self) -> Option<&str> {
        self.get("service.product")
    }

    /// Detected version, if any (`service.version`).
    pub fn version(&self) -> Option<&str> {
        self.get("service.version")
    }

    /// Detected vendor, if any (`service.vendor`).
    pub fn vendor(&self) -> Option<&str> {
        self.get("service.vendor")
    }

    /// Detected OS product, if any (`os.product`).
    pub fn os_product(&self) -> Option<&str> {
        self.get("os.product")
    }

    /// A compact human-readable "product version" summary, falling back to
    /// whatever fields exist. Returns `None` when nothing useful was extracted.
    pub fn summary(&self) -> Option<String> {
        let product = self.product();
        let version = self.version();
        match (product, version) {
            (Some(p), Some(v)) => Some(format!("{} {}", p, v)),
            (Some(p), None) => Some(p.to_string()),
            (None, Some(v)) => Some(v.to_string()),
            (None, None) => self.os_product().map(|s| s.to_string()),
        }
    }
}

impl RecogDb {
    /// Match a banner against this DB; first matching fingerprint wins.
    pub fn match_banner(&self, banner: &str) -> RecogMatch {
        // Recog typically matches against a single line; try the whole banner
        // first, then fall back to the first non-empty line so multi-line
        // greetings (e.g. an FTP 220-multiline banner) still resolve.
        let candidates: [&str; 1] = [banner.trim()];
        for candidate in candidates {
            if let Some(m) = self.match_one(candidate) {
                tracing::trace!(db = self.name, "recog: banner matched");
                return m;
            }
        }
        // Fall back to the first non-empty line.
        if let Some(line) = banner.lines().map(|l| l.trim()).find(|l| !l.is_empty()) {
            if line != banner.trim() {
                if let Some(m) = self.match_one(line) {
                    tracing::trace!(db = self.name, "recog: banner matched (first line)");
                    return m;
                }
            }
        }
        RecogMatch::default()
    }

    fn match_one(&self, input: &str) -> Option<RecogMatch> {
        for fp in &self.fingerprints {
            let caps = match fp.regex.captures(input) {
                Some(c) => c,
                None => continue,
            };

            let mut fields: BTreeMap<String, String> = BTreeMap::new();

            // Two passes, matching Recog semantics: a param carrying a non-empty
            // `value` is a literal/interpolated assignment; a param with no
            // `value` reads regex capture group `pos`. Capture params must run
            // first so that `{service.version}`-style placeholders in a literal
            // (e.g. a `cpe23` template) resolve even when the literal param
            // appears before its source field in the XML — and even when the
            // template param also carries a `pos` attribute.
            //
            // Pass 1: capture-group params.
            for param in &fp.params {
                if !param.value.is_empty() {
                    continue;
                }
                // A non-participating optional group is simply skipped.
                if let Some(g) = caps.get(param.pos) {
                    let text = g.as_str();
                    if !text.is_empty() {
                        fields.insert(param.name.clone(), text.to_string());
                    }
                }
            }

            // Pass 2: literal / interpolated params.
            for param in &fp.params {
                if param.value.is_empty() {
                    continue;
                }
                let interpolated = interpolate(&param.value, &fields);
                fields.insert(param.name.clone(), interpolated);
            }

            return Some(RecogMatch {
                matched: true,
                fields,
            });
        }
        None
    }
}

/// Replace `{field.name}` placeholders in a literal param value with previously
/// extracted field values. Unknown placeholders are left untouched.
fn interpolate(value: &str, fields: &BTreeMap<String, String>) -> String {
    if !value.contains('{') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                match fields.get(key) {
                    Some(v) => out.push_str(v),
                    None => {
                        // Keep the placeholder verbatim if we can't resolve it.
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unbalanced brace — emit the remainder literally and stop.
                out.push('{');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse one embedded Recog XML document into a `RecogDb`. A fingerprint whose
/// `pattern` fails to compile is logged and skipped (never panics).
fn parse_db(name: &'static str, xml: &str) -> RecogDb {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut fingerprints: Vec<Fingerprint> = Vec::new();

    // State for the fingerprint currently being assembled.
    let mut cur_pattern: Option<String> = None;
    let mut cur_params: Vec<RecogParam> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"fingerprint" => {
                cur_pattern = read_pattern_attr(e, name);
                cur_params.clear();
            }
            Ok(Event::Empty(ref e)) if e.name().as_ref() == b"param" => {
                if let Some(param) = read_param(e, name) {
                    cur_params.push(param);
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"fingerprint" => {
                if let Some(pattern) = cur_pattern.take() {
                    match build_regex(&pattern) {
                        Ok(regex) => fingerprints.push(Fingerprint {
                            regex,
                            params: std::mem::take(&mut cur_params),
                        }),
                        Err(err) => {
                            tracing::warn!(
                                db = name,
                                pattern = %pattern,
                                "recog: skipping fingerprint with invalid regex: {}",
                                err
                            );
                            cur_params.clear();
                        }
                    }
                } else {
                    cur_params.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                tracing::warn!(db = name, "recog: XML parse error, stopping: {}", err);
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    RecogDb { name, fingerprints }
}

/// Decode a raw attribute value: UTF-8 decode the bytes, then resolve XML
/// entities (`&amp;`, `&lt;`, etc). Avoids quick-xml's deprecated
/// `unescape_value` while still being entity-correct.
fn attr_value(a: &quick_xml::events::attributes::Attribute, db: &str) -> Option<String> {
    let raw = match std::str::from_utf8(a.value.as_ref()) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(db, "recog: attribute value is not valid UTF-8: {}", err);
            return None;
        }
    };
    match quick_xml::escape::unescape(raw) {
        Ok(v) => Some(v.into_owned()),
        Err(err) => {
            tracing::warn!(db, "recog: failed to unescape attribute value: {}", err);
            None
        }
    }
}

/// Read the `pattern` attribute off a `<fingerprint>` start tag.
fn read_pattern_attr(e: &quick_xml::events::BytesStart, db: &str) -> Option<String> {
    for attr in e.attributes() {
        match attr {
            Ok(a) if a.key.as_ref() == b"pattern" => return attr_value(&a, db),
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(db, "recog: bad attribute on <fingerprint>: {}", err);
            }
        }
    }
    None
}

/// Read a `<param pos="N" name="..." value="..."/>` element into a `RecogParam`.
fn read_param(e: &quick_xml::events::BytesStart, db: &str) -> Option<RecogParam> {
    let mut pos: Option<usize> = None;
    let mut pname: Option<String> = None;
    let mut value = String::new();

    for attr in e.attributes() {
        let a = match attr {
            Ok(a) => a,
            Err(err) => {
                tracing::warn!(db, "recog: bad attribute on <param>: {}", err);
                continue;
            }
        };
        match a.key.as_ref() {
            b"pos" => {
                let raw = match attr_value(&a, db) {
                    Some(v) => v,
                    None => continue,
                };
                match raw.parse::<usize>() {
                    Ok(n) => pos = Some(n),
                    Err(err) => {
                        tracing::warn!(db, pos = %raw, "recog: non-numeric param pos: {}", err);
                    }
                }
            }
            b"name" => {
                if let Some(v) = attr_value(&a, db) {
                    pname = Some(v);
                }
            }
            b"value" => {
                if let Some(v) = attr_value(&a, db) {
                    value = v;
                }
            }
            _ => {}
        }
    }

    match (pos, pname) {
        (Some(pos), Some(name)) => Some(RecogParam { pos, name, value }),
        _ => {
            tracing::warn!(db, "recog: <param> missing pos or name attribute; skipping");
            None
        }
    }
}

/// Compile a Recog pattern. Recog patterns are case-insensitive by default and
/// the `^`/`$` anchors match at string boundaries (not per-line), matching the
/// upstream Ruby `Regexp` defaults used by recog-go.
fn build_regex(pattern: &str) -> Result<Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
}

// ---------------------------------------------------------------------------
// Lazy registry — parse each embedded XML once, pre-compiling all regexes.
// ---------------------------------------------------------------------------

static SSH_DB: Lazy<RecogDb> =
    Lazy::new(|| parse_db("ssh", include_str!("recog_db/ssh_banners.xml")));
static FTP_DB: Lazy<RecogDb> =
    Lazy::new(|| parse_db("ftp", include_str!("recog_db/ftp_banners.xml")));
static SMTP_DB: Lazy<RecogDb> =
    Lazy::new(|| parse_db("smtp", include_str!("recog_db/smtp_banners.xml")));
static HTTP_DB: Lazy<RecogDb> =
    Lazy::new(|| parse_db("http", include_str!("recog_db/http_servers.xml")));
static MYSQL_DB: Lazy<RecogDb> =
    Lazy::new(|| parse_db("mysql", include_str!("recog_db/mysql_banners.xml")));

/// Look up a fingerprint database by short name (`ssh`, `ftp`, `smtp`, `http`,
/// `mysql`). Returns `None` for unknown names.
pub fn db(name: &str) -> Option<&'static RecogDb> {
    match name {
        "ssh" => Some(&SSH_DB),
        "ftp" => Some(&FTP_DB),
        "smtp" => Some(&SMTP_DB),
        "http" => Some(&HTTP_DB),
        "mysql" => Some(&MYSQL_DB),
        _ => None,
    }
}

/// Match a banner against the named database. If the database name is unknown
/// the returned `RecogMatch` has `matched == false`.
pub fn match_banner(db_name: &str, banner: &str) -> RecogMatch {
    match db(db_name) {
        Some(database) => database.match_banner(banner),
        None => {
            tracing::warn!(db = db_name, "recog: requested unknown fingerprint database");
            RecogMatch::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_openssh_with_os_comment() {
        let m = match_banner("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
        assert!(m.matched, "expected OpenSSH banner to match");
        assert_eq!(m.product(), Some("OpenSSH"));
        assert_eq!(m.version(), Some("8.9"));
        assert_eq!(m.vendor(), Some("OpenBSD"));
        assert_eq!(
            m.get("service.cpe23"),
            Some("cpe:/a:openbsd:openssh:8.9"),
            "interpolated CPE should embed the extracted version"
        );
    }

    #[test]
    fn ssh_openssh_no_comment() {
        let m = match_banner("ssh", "SSH-2.0-OpenSSH_7.4");
        assert!(m.matched);
        assert_eq!(m.product(), Some("OpenSSH"));
        assert_eq!(m.version(), Some("7.4"));
    }

    #[test]
    fn ssh_dropbear() {
        let m = match_banner("ssh", "SSH-2.0-dropbear_2020.81");
        assert!(m.matched);
        assert_eq!(m.product(), Some("Dropbear SSH"));
        assert_eq!(m.version(), Some("2020.81"));
    }

    #[test]
    fn ssh_routeros_os_fields() {
        let m = match_banner("ssh", "SSH-2.0-ROSSSH");
        assert!(m.matched);
        assert_eq!(m.product(), Some("RouterOS"));
        assert_eq!(m.os_product(), Some("RouterOS"));
    }

    #[test]
    fn ftp_proftpd() {
        let m = match_banner(
            "ftp",
            "220 ProFTPD 1.3.5b Server (Debian) [::ffff:10.0.0.1]",
        );
        assert!(m.matched, "expected ProFTPD banner to match");
        assert_eq!(m.product(), Some("ProFTPD"));
        assert_eq!(m.version(), Some("1.3.5b"));
        assert_eq!(m.get("service.cpe23"), Some("cpe:/a:proftpd:proftpd:1.3.5b"));
    }

    #[test]
    fn ftp_vsftpd() {
        let m = match_banner("ftp", "220 (vsFTPd 3.0.3)");
        assert!(m.matched);
        assert_eq!(m.product(), Some("vsftpd"));
        assert_eq!(m.version(), Some("3.0.3"));
    }

    #[test]
    fn ftp_pureftpd_no_version() {
        let m = match_banner("ftp", "220---------- Welcome to Pure-FTPd ----------");
        assert!(m.matched);
        assert_eq!(m.product(), Some("Pure-FTPd"));
        assert_eq!(m.version(), None, "Pure-FTPd hides its version");
    }

    #[test]
    fn smtp_exim() {
        let m = match_banner(
            "smtp",
            "220 mail.example.com ESMTP Exim 4.94.2 Mon, 01 Jan 2024 00:00:00 +0000",
        );
        assert!(m.matched, "expected Exim banner to match");
        assert_eq!(m.product(), Some("Exim"));
        assert_eq!(m.version(), Some("4.94.2"));
        assert_eq!(m.get("service.cpe23"), Some("cpe:/a:exim:exim:4.94.2"));
    }

    #[test]
    fn smtp_postfix() {
        let m = match_banner("smtp", "220 mail.example.com ESMTP Postfix (Ubuntu)");
        assert!(m.matched);
        assert_eq!(m.product(), Some("Postfix"));
    }

    #[test]
    fn smtp_sendmail() {
        let m = match_banner(
            "smtp",
            "220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2; Mon, 1 Jan 2024 00:00:00 GMT",
        );
        assert!(m.matched);
        assert_eq!(m.product(), Some("Sendmail"));
        assert_eq!(m.version(), Some("8.15.2/8.15.2"));
    }

    #[test]
    fn http_apache_with_os() {
        let m = match_banner("http", "Apache/2.4.52 (Ubuntu)");
        assert!(m.matched);
        assert_eq!(m.product(), Some("HTTP Server"));
        assert_eq!(m.vendor(), Some("Apache"));
        assert_eq!(m.version(), Some("2.4.52"));
        assert_eq!(m.os_product(), Some("Ubuntu"));
    }

    #[test]
    fn http_nginx() {
        let m = match_banner("http", "nginx/1.18.0");
        assert!(m.matched);
        assert_eq!(m.product(), Some("nginx"));
        assert_eq!(m.version(), Some("1.18.0"));
    }

    #[test]
    fn http_iis_os_fields() {
        let m = match_banner("http", "Microsoft-IIS/10.0");
        assert!(m.matched);
        assert_eq!(m.product(), Some("IIS"));
        assert_eq!(m.version(), Some("10.0"));
        assert_eq!(m.os_product(), Some("Windows"));
    }

    #[test]
    fn mysql_mariadb() {
        let m = match_banner("mysql", "10.5.12-MariaDB-1:10.5.12+maria~focal");
        assert!(m.matched);
        assert_eq!(m.product(), Some("MariaDB"));
        assert_eq!(m.version(), Some("10.5.12"));
    }

    #[test]
    fn mysql_plain_version() {
        let m = match_banner("mysql", "5.7.38");
        assert!(m.matched);
        assert_eq!(m.product(), Some("MySQL"));
        assert_eq!(m.version(), Some("5.7.38"));
    }

    #[test]
    fn unknown_db_does_not_match() {
        let m = match_banner("does-not-exist", "anything");
        assert!(!m.matched);
        assert!(m.summary().is_none());
    }

    #[test]
    fn non_matching_banner() {
        let m = match_banner("ssh", "not-an-ssh-banner-at-all");
        assert!(!m.matched);
    }

    #[test]
    fn summary_helper() {
        let m = match_banner("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6");
        assert_eq!(m.summary().as_deref(), Some("OpenSSH 8.9"));
    }

    #[test]
    fn malformed_regex_is_skipped_not_panicking() {
        // An unbalanced group is invalid; parse_db must skip it without panic
        // and still load the valid fingerprint that follows.
        let xml = r#"<fingerprints matches="t">
            <fingerprint pattern="(unterminated">
              <param pos="0" name="service.product" value="Broken"/>
            </fingerprint>
            <fingerprint pattern="^GOOD-([\d.]+)$">
              <param pos="0" name="service.product" value="Good"/>
              <param pos="1" name="service.version"/>
            </fingerprint>
        </fingerprints>"#;
        let db = parse_db("test", xml);
        assert_eq!(db.fingerprints.len(), 1, "broken fingerprint must be skipped");
        let m = db.match_banner("GOOD-1.2");
        assert!(m.matched);
        assert_eq!(m.product(), Some("Good"));
        assert_eq!(m.version(), Some("1.2"));
    }

    #[test]
    fn all_databases_load() {
        for name in ["ssh", "ftp", "smtp", "http", "mysql"] {
            let database = db(name).expect("database should resolve");
            assert!(
                !database.fingerprints.is_empty(),
                "db {} parsed zero fingerprints",
                database.name
            );
        }
    }
}
