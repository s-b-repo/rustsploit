use anyhow::{Context, Result};
use colored::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Backup File Finder v2".into(),
        description: "Probes 200+ backup/config file patterns with 50 concurrency. \
            Finds .bak, .old, .save, .swp, .git/config, .env, .sql, .zip exposures."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://github.com/maurosoria/dirsearch".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: Some(443),
    }
}

const BACKUP_PATTERNS: &[&str] = &[
    ".git/config",
    ".env",
    ".env.bak",
    ".env.local",
    ".env.production",
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.save",
    "wp-config.php.old",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.rar",
    "db_backup.sql",
    "database.sql.gz",
    "config.php.bak",
    "config.json.bak",
    "adminer.php",
    "phpinfo.php",
    "info.php",
    "composer.json",
    "package.json",
    "Gemfile.lock",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    ".gitignore",
    ".htaccess.bak",
    "robots.txt",
    "sitemap.xml",
    "server-status",
    "server-info",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    ".DS_Store",
    ".svn/entries",
    ".hg/store",
    "web.config",
    "WEB-INF/web.xml",
    "phpunit.xml",
    "vendor/composer/installed.json",
    "yarn.lock",
    "pnpm-lock.yaml",
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    let timeout = Duration::from_secs(
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 3, 1, 15).await? as u64,
    );
    let client = build_http_client(timeout).context("Failed to build HTTP client")?;
    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let mut outcome = ModuleOutcome::ok();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(50));
    let findings = Arc::new(Mutex::new(Vec::new()));
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for &pattern in BACKUP_PATTERNS {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(target).await;
        let url = format!("{}/{}", base_url, pattern);
        let client = client.clone();
        let permit = sem.clone();
        let t = target.to_string();
        let f = findings.clone();
        let h = tokio::spawn(async move {
            // Hold the permit for the whole task — binding to `let _` would
            // drop it immediately and unthrottle the scan.
            let _guard = match permit.acquire().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::debug!("backup probe {} skipped: semaphore closed ({e})", url);
                    return;
                }
            };
            match tokio::time::timeout(timeout, client.get(&url).send()).await {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        let size = resp.content_length().unwrap_or(0);
                        crate::mprintln!(
                            "{}",
                            format!("[+] Found: {} (HTTP 200, {} bytes)", pattern, size).green()
                        );
                        let mut guard = f.lock().await;
                        guard.push(Finding {
                            target: t.clone(),
                            kind: FindingKind::Note,
                            message: format!("Backup file {} at {} ({} bytes)", pattern, url, size),
                            data: Some(
                                serde_json::json!({"url": url, "pattern": pattern, "size": size}),
                            ),
                        });
                    }
                }
                e => {
                    tracing::debug!("backup probe {} failed: {:?}", url, e);
                }
            }
        });
        tasks.push(h);
    }

    for h in tasks {
        if let Err(e) = h.await {
            tracing::warn!("backup probe subtask panicked: {}", e);
        }
    }
    let mut guard = findings.lock().await;
    outcome.findings.append(&mut *guard);
    crate::mprintln!(
        "{}",
        format!(
            "[*] Backup scan complete — {} patterns tested.",
            BACKUP_PATTERNS.len()
        )
        .cyan()
    );
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "backup_file_finder",
    native
);
