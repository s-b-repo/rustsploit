//! CI/CD Pipeline Secret Scanner
//!
//! Probes for exposed CI/CD configuration files, pipeline definitions,
//! and development configuration files that may contain embedded secrets
//! (API keys, tokens, credentials, database URLs). Detects common
//! misconfigurations where build/deploy artifacts are inadvertently
//! published to production web roots.
//!
//! Based on bug bounty findings of exposed .git directories, .env files,
//! and CI/CD pipeline configs leaking sensitive credentials.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{BoxFut, run_buffered};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const CICD_CONCURRENCY: usize = 12;

/// CI/CD and config paths to probe. Each entry: (label, path, expected_content_type).
const CICD_PATHS: &[(&str, &str)] = &[
    // Git exposure
    (".git HEAD", "/.git/HEAD"),
    (".git config", "/.git/config"),
    (".git index", "/.git/index"),
    (".git logs HEAD", "/.git/logs/HEAD"),
    (".git refs", "/.git/refs/heads/master"),
    (".git refs main", "/.git/refs/heads/main"),
    // Git hosting configs
    (".gitignore", "/.gitignore"),
    (".gitattributes", "/.gitattributes"),
    // CI/CD pipeline configs
    ("GitHub Actions", "/.github/workflows/ci.yml"),
    ("GitHub Actions (deploy)", "/.github/workflows/deploy.yml"),
    ("GitHub Actions (main)", "/.github/workflows/main.yml"),
    ("GitLab CI", "/.gitlab-ci.yml"),
    ("Jenkinsfile", "/Jenkinsfile"),
    ("CircleCI config", "/.circleci/config.yml"),
    ("Travis CI", "/.travis.yml"),
    ("Drone CI", "/.drone.yml"),
    ("Bitbucket Pipelines", "/bitbucket-pipelines.yml"),
    ("Azure Pipelines", "/azure-pipelines.yml"),
    ("Buildkite", "/.buildkite/pipeline.yml"),
    // Docker configs
    ("Dockerfile", "/Dockerfile"),
    ("docker-compose.yml", "/docker-compose.yml"),
    (".dockerignore", "/.dockerignore"),
    // Environment files
    (".env", "/.env"),
    (".env.production", "/.env.production"),
    (".env.local", "/.env.local"),
    (".env.development", "/.env.development"),
    (".env.staging", "/.env.staging"),
    (".env.example", "/.env.example"),
    (".env.backup", "/.env.backup"),
    (".env.old", "/.env.old"),
    // Config files
    ("wp-config.php", "/wp-config.php"),
    ("config.php", "/config.php"),
    ("config.json", "/config.json"),
    ("config.yml", "/config.yml"),
    ("config.yaml", "/config.yaml"),
    ("settings.py", "/settings.py"),
    ("settings.json", "/settings.json"),
    ("app.config", "/app.config"),
    ("web.config", "/web.config"),
    // Package manager lock files
    ("composer.json", "/composer.json"),
    ("composer.lock", "/composer.lock"),
    ("package.json", "/package.json"),
    ("package-lock.json", "/package-lock.json"),
    ("yarn.lock", "/yarn.lock"),
    ("Gemfile", "/Gemfile"),
    ("requirements.txt", "/requirements.txt"),
    ("Pipfile", "/Pipfile"),
    // IDE / editor configs
    (".vscode settings", "/.vscode/settings.json"),
    (".vscode launch", "/.vscode/launch.json"),
    (".idea workspace", "/.idea/workspace.xml"),
    // Debug / test artifacts
    ("debug.log", "/debug.log"),
    ("error.log", "/error.log"),
    ("phpinfo", "/phpinfo.php"),
    ("info.php", "/info.php"),
    ("test.php", "/test.php"),
    // Common secret files
    ("credentials.json", "/credentials.json"),
    ("secrets.yml", "/secrets.yml"),
    ("secret.key", "/secret.key"),
    ("api-keys.json", "/api-keys.json"),
    // Build artifacts
    ("Makefile", "/Makefile"),
    ("Gruntfile", "/Gruntfile.js"),
    ("gulpfile", "/gulpfile.js"),
    ("webpack config", "/webpack.config.js"),
    ("vite config", "/vite.config.js"),
    // Infrastructure as Code
    ("terraform tfvars", "/terraform.tfvars"),
    (".terraform tfstate", "/.terraform/terraform.tfstate"),
];

/// Secret patterns to scan for in exposed files.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    // API keys
    (
        "Generic API key",
        "api[_-]?key\\s*[=:]\\s*[\"']?[A-Za-z0-9_\\-]{16,}[\"']?",
    ),
    ("AWS Access Key", "AKIA[0-9A-Z]{16}"),
    (
        "AWS Secret Key",
        "aws[_-]?secret[_-]?access[_-]?key\\s*[=:]",
    ),
    ("Google API Key", "AIza[0-9A-Za-z\\-_]{35}"),
    ("GitHub Token", "gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("GitHub PAT", "github[_-]?token\\s*[=:]\\s*[\"']?ghp_"),
    ("Stripe secret key", "sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe test key", "sk_test_[0-9a-zA-Z]{24,}"),
    // Database
    ("MySQL URL", "mysql://[^\\s\"']+"),
    ("PostgreSQL URL", "postgres(ql)?://[^\\s\"']+"),
    ("MongoDB URL", "mongodb(\\+srv)?://[^\\s\"']+"),
    ("Redis URL", "redis://[^\\s\"']+"),
    // Credentials
    (
        "Password in config",
        "(pass(word)?|pwd)\\s*[=:]\\s*[\"']?[^\\s\"']{4,}[\"']?",
    ),
    ("JWT secret", "jwt[_-]?secret\\s*[=:]"),
    (
        "Private key header",
        "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    ),
    // Cloud credentials
    ("Azure connection string", "DefaultEndpointsProtocol=https"),
    ("GCP service account", "type\":\\s*\"service_account\""),
    // Generic tokens
    ("Bearer token", "bearer\\s+[A-Za-z0-9_\\-\\.]{20,}"),
    ("OAuth client secret", "client[_-]?secret\\s*[=:]"),
];

fn banner() {
    if is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   CI/CD Pipeline & Secret Scanner                           ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Discovers exposed pipeline configs, .env files, and keys  ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CI/CD Pipeline Secret Scanner".to_string(),
        description: "Probes for exposed CI/CD pipeline configurations (GitHub Actions, \
                      GitLab CI, Jenkins, CircleCI, Travis), environment files (.env, \
                      .env.production), Docker configs, and development artifacts. Scans \
                      responses for embedded secrets: API keys, database URLs, cloud \
                      credentials, private keys, and authentication tokens."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions".to_string(),
            "https://docs.gitlab.com/ee/ci/variables/".to_string(),
            "https://owasp.org/www-project-top-ten/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

/// Scan body text for secret patterns. Returns list of (label, match snippet).
fn scan_secrets(body: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();

    for (label, pattern) in SECRET_PATTERNS {
        if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
            for m in re.find_iter(body).take(3) {
                let snippet = &body[m.start()..m.end()];
                // Truncate very long matches
                let short = if snippet.len() > 60 {
                    format!("{}...", &snippet[..60])
                } else {
                    snippet.to_string()
                };
                // Only add if not already found this label
                if !found.iter().any(|(l, _)| l == label) {
                    found.push((label.to_string(), short));
                }
            }
        }
    }

    found
}

/// Check if body looks like a valid git object.
fn is_git_content(body: &str) -> bool {
    // Git objects start with specific markers
    body.starts_with("ref:")
        || body.starts_with("blob ")
        || body.starts_with("tree ")
        || body.starts_with("commit ")
        || body.starts_with("tag ")
        || body.contains("[core]")
        || body.contains("[remote \"origin\"]")
}

/// Check if body looks like env/config content (key=value pairs, export statements).
fn is_env_content(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().take(10).collect();
    let kv_lines = lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.starts_with('#')
                && !t.starts_with("//")
                && !t.starts_with("/*")
                && !t.starts_with('<')
                && (t.contains('=') || t.starts_with("export "))
        })
        .count();
    // At least half of non-blank lines should be key=value
    let total = lines.iter().filter(|l| !l.trim().is_empty()).count();
    total > 0 && kv_lines as f64 / total as f64 >= 0.4
}

/// Check if body looks like a CI/CD pipeline definition.
fn is_pipeline_content(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    (lower.contains("pipeline") || lower.contains("jobs:") || lower.contains("stages:"))
        && !lower.contains("<html")
        && !lower.contains("<!doctype")
}

/// Result from probing a single path.
type ProbeResult = (String, String, Option<(u16, String, String)>);

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("cicd_secret_scanner requires a single-host target")?;
    banner();

    let mut outcome = ModuleOutcome::ok();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();
    let scan_secrets_flag = cfg_prompt_yes_no(
        "scan_secrets",
        "Deep-scan responses for embedded secrets?",
        true,
    )
    .await?;
    let timeout_secs: u64 = ctx.options.get_or("timeout", 12u64);

    let client = build_http_client(Duration::from_secs(timeout_secs))?;

    // Baseline probe for SPA detection
    let baseline_url = format!("{}/__rustsploit_ci_nonexistent_9f2a__", base);
    let baseline_len = match client.get(&baseline_url).send().await {
        Ok(r) => {
            let b = crate::utils::network::read_http_body_text_capped(
                r,
                crate::utils::safe_io::DEFAULT_BODY_CAP,
            )
            .await
            .unwrap_or_default();
            b.len()
        }
        Err(e) => {
            tracing::debug!("baseline request: {e:#}");
            0
        }
    };
    let spa_detected = baseline_len > 500;

    if spa_detected {
        crate::mprintln!(
            "{}",
            format!(
                "[*] SPA detected: nonexistent path returns {} bytes — filtering noise.",
                baseline_len
            )
            .dimmed()
        );
    }

    crate::mprintln!("{}", format!("[*] Target: {}", base).cyan());
    crate::mprintln!(
        "{}",
        format!(
            "[*] Probing {} CI/CD, config, and secret paths...",
            CICD_PATHS.len()
        )
        .cyan()
    );
    crate::mprintln!();

    // Probe all paths concurrently
    let work: Vec<BoxFut<ProbeResult>> = CICD_PATHS
        .iter()
        .map(|(label, path)| {
            let full = format!("{}{}", base, path);
            let client = client.clone();
            let label = label.to_string();
            Box::pin(async move {
                let resp = client.get(&full).send().await;
                match resp {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        if status >= 400 {
                            return (label, full, None);
                        }
                        let ct = r
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let body = crate::utils::network::read_http_body_text_capped(
                            r,
                            crate::utils::safe_io::DEFAULT_BODY_CAP,
                        )
                        .await
                        .unwrap_or_default();
                        (label, full, Some((status, ct, body)))
                    }
                    Err(e) => {
                        tracing::debug!("CICD probe failed for {}: {e}", full);
                        (label, full, None)
                    }
                }
            }) as _
        })
        .collect();

    let results = run_buffered(work, CICD_CONCURRENCY).await;

    let mut hits: Vec<(String, String, String, Vec<(String, String)>)> = Vec::new();

    for (label, full, fetched) in results {
        let (status, ct, body) = match fetched {
            Some(v) => v,
            None => continue,
        };
        if body.is_empty() || body.len() < 5 {
            continue;
        }

        // SPA noise filter: skip HTML responses that match baseline length
        if spa_detected
            && ct.contains("text/html")
            && (body.len() as isize - baseline_len as isize).unsigned_abs() < 128
        {
            continue;
        }

        // Classify the hit
        let mut severity = "LOW";
        let mut msg = format!(
            "Sensitive file '{}' accessible ({} bytes)",
            label,
            body.len()
        );
        let mut secrets: Vec<(String, String)> = Vec::new();

        if is_git_content(&body) {
            severity = "CRITICAL";
            msg = ".git directory exposed — full source code history accessible".to_string();
        } else if is_env_content(&body) {
            severity = "CRITICAL";
            msg = "Environment file exposed — may contain credentials and secrets".to_string();
            if scan_secrets_flag {
                secrets = scan_secrets(&body);
            }
        } else if is_pipeline_content(&body) {
            severity = "HIGH";
            msg = "CI/CD pipeline configuration exposed".to_string();
            if scan_secrets_flag {
                secrets = scan_secrets(&body);
            }
        } else if label.starts_with(".env") {
            severity = "CRITICAL";
            msg = format!("{} file exposed", label);
            if scan_secrets_flag {
                secrets = scan_secrets(&body);
            }
        } else if label.contains("Docker") {
            severity = "MEDIUM";
            msg = "Docker configuration exposed".to_string();
        } else if label.contains("config") || label.contains(".json") || label.contains(".yml") {
            severity = "MEDIUM";
            msg = format!("Configuration file '{}' exposed", label);
            if scan_secrets_flag {
                secrets = scan_secrets(&body);
            }
        }

        // Always scan for secrets in non-HTML responses when flag is set
        if scan_secrets_flag && !ct.contains("text/html") && secrets.is_empty() && body.len() > 20 {
            let found = scan_secrets(&body);
            if !found.is_empty() {
                secrets = found;
                if severity == "LOW" {
                    severity = "HIGH";
                    msg = format!(
                        "Secrets found in '{}': {} patterns matched",
                        label,
                        secrets.len()
                    );
                }
            }
        }

        let colored_sev = match severity {
            "CRITICAL" => severity.red().bold().to_string(),
            "HIGH" => severity.yellow().bold().to_string(),
            "MEDIUM" => severity.yellow().to_string(),
            _ => severity.dimmed().to_string(),
        };

        let snippet: String = body
            .chars()
            .take(140)
            .collect::<String>()
            .replace(['\n', '\r'], " ");
        crate::mprintln!(
            "[{}] {} status={} ct='{}' len={} :: {}",
            colored_sev,
            full,
            status,
            ct,
            body.len(),
            snippet.dimmed()
        );

        if !secrets.is_empty() {
            crate::mprintln!("{}", "      *** SECRETS DETECTED ***".red().bold());
            for (pattern_name, match_snip) in &secrets {
                crate::mprintln!(
                    "{}",
                    format!("        {}: {}", pattern_name, match_snip).red()
                );
            }
        }

        hits.push((full, severity.to_string(), msg, secrets));
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== CI/CD Secret Scan Results ===".bold());
    crate::mprintln!("  Target: {}", base);

    if hits.is_empty() {
        crate::mprintln!("  {}", "No exposed CI/CD configs or secrets found.".green());
    } else {
        let critical = hits.iter().filter(|(_, s, _, _)| s == "CRITICAL").count();
        let high = hits.iter().filter(|(_, s, _, _)| s == "HIGH").count();
        let total_secrets: usize = hits.iter().map(|(_, _, _, secs)| secs.len()).sum();
        crate::mprintln!(
            "{}",
            format!(
                "  {} findings: {} CRITICAL, {} HIGH ({} total secrets detected)",
                hits.len(),
                critical,
                high,
                total_secrets
            )
            .yellow()
        );

        for (url, severity, msg, secrets) in &hits {
            let kind = if severity == "CRITICAL" || severity == "HIGH" {
                FindingKind::Vulnerable
            } else {
                FindingKind::Note
            };
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind,
                message: format!("CI/CD exposure at {}: {}", url, msg),
                data: Some(serde_json::json!({
                    "url": url,
                    "severity": severity,
                    "detail": msg,
                    "secrets_found": secrets.iter().map(|(l, _)| l).collect::<Vec<_>>(),
                })),
            });
        }
    }

    crate::mprintln!();
    crate::mprintln!(
        "{}",
        "[*] Review all CRITICAL/HIGH findings immediately — exposed credentials may be active."
            .yellow()
    );

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "cicd_secret_scanner",
    native
);
