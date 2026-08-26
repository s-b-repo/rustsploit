use anyhow::{Context, Result};
use colored::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

const EXPOSURE_PATHS: &[(&str, &str)] = &[
    (".git/HEAD", "Git repository exposed"),
    (".git/config", "Git configuration exposed"),
    (".git/index", "Git index exposed"),
    (".env", "Environment file exposed"),
    (".env.backup", "Backup env file exposed"),
    (".env.local", "Local env file exposed"),
    (".env.production", "Production env file exposed"),
    ("config.json", "JSON config exposed"),
    ("config.yml", "YAML config exposed"),
    ("config.yaml", "YAML config exposed"),
    ("settings.json", "Settings file exposed"),
    ("appsettings.json", ".NET appsettings exposed"),
    ("application.properties", "Spring config exposed"),
    ("backup.zip", "Backup archive exposed"),
    ("backup.tar.gz", "Backup archive exposed"),
    ("backup.sql", "Database backup exposed"),
    ("dump.sql", "Database dump exposed"),
    ("database.sql", "Database backup exposed"),
    ("db_backup.sql", "Database backup exposed"),
    ("wp-config.php.bak", "WordPress config backup exposed"),
    ("wp-config.php.old", "WordPress config backup exposed"),
    ("wp-config.php~", "WordPress config backup exposed"),
    ("wp-config.php.save", "WordPress config backup exposed"),
    ("wp-config.php.swp", "WordPress config backup exposed"),
    (".DS_Store", "macOS metadata file exposed"),
    ("docker-compose.yml", "Docker Compose config exposed"),
    ("docker-compose.yaml", "Docker Compose config exposed"),
    ("Dockerfile", "Docker build file exposed"),
    ("Makefile", "Build makefile exposed"),
    ("package.json", "Node.js package manifest exposed"),
    ("composer.json", "PHP Composer manifest exposed"),
    ("Gemfile", "Ruby Gemfile exposed"),
    ("requirements.txt", "Python requirements exposed"),
    ("Pipfile", "Python Pipenv file exposed"),
    (".travis.yml", "Travis CI config exposed"),
    (".gitlab-ci.yml", "GitLab CI config exposed"),
    ("Jenkinsfile", "Jenkins pipeline exposed"),
    (
        ".github/workflows/ci.yml",
        "GitHub Actions workflow exposed",
    ),
    ("id_rsa", "Private SSH key exposed"),
    ("id_ed25519", "Private SSH key exposed"),
    (".ssh/id_rsa", "SSH private key exposed"),
    (".ssh/authorized_keys", "SSH authorized keys exposed"),
    (".svn/entries", "SVN repository exposed"),
    (".hg/store", "Mercurial repository exposed"),
    (".bzr/branch-format", "Bazaar repository exposed"),
    ("debug.log", "Debug log exposed"),
    ("error.log", "Error log exposed"),
    ("access.log", "Access log exposed"),
    ("php_errors.log", "PHP error log exposed"),
    ("phpinfo.php", "PHP info page exposed"),
    ("info.php", "PHP info page exposed"),
    ("test.php", "PHP test file exposed"),
    ("admin.php", "Admin script exposed"),
    ("admin/", "Admin directory accessible"),
    ("wp-admin/", "WordPress admin accessible"),
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("exposure_scanner requires a single-host target")?;

    crate::mprintln!(
        "{}",
        format!("[*] Exposure Scanner — target: {}", target).cyan()
    );

    let port = ctx.options.get_or("port", 443u16);
    let timeout_secs = ctx.options.get_or("timeout", 10u64).clamp(1, 60);
    let timeout_dur = Duration::from_secs(timeout_secs);

    let client = crate::utils::build_http_client(timeout_dur)?;
    let base_url = format!("https://{}:{}", target, port);
    let http_url = format!("http://{}:{}", target, if port == 443 { 80 } else { port });

    let mut outcome = ModuleOutcome::ok();

    crate::mprintln!(
        "{}",
        format!(
            "[*] Probing {} paths on HTTPS + HTTP (concurrency=20)...",
            EXPOSURE_PATHS.len()
        )
        .dimmed()
    );

    let sem = Arc::new(Semaphore::new(20));
    let tested = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let exposed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let findings_lock = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for (path, description) in EXPOSURE_PATHS.iter() {
        if ctx.is_cancelled() {
            break;
        }
        let path = *path;
        let description = *description;
        let client = client.clone();
        let base = base_url.clone();
        let http = http_url.clone();
        let t = target.to_string();
        let permit = sem.clone();
        let tested_c = tested.clone();
        let exposed_c = exposed.clone();
        let findings = findings_lock.clone();

        let h = tokio::spawn(async move {
            // Hold the permit for the task lifetime; a closed semaphore means
            // shutdown — skip this probe.
            let _p = match permit.acquire().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::debug!("exposure probe skipped: semaphore closed ({e})");
                    return;
                }
            };
            let url = format!("{}/{}", base, path);
            if let Ok(Ok(resp)) = tokio::time::timeout(timeout_dur, client.get(&url).send()).await {
                tested_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let status = resp.status().as_u16();
                if status == 200 || status == 301 || status == 302 || status == 403 {
                    let suffix = if status == 403 {
                        " (403 Forbidden — file exists)"
                    } else if status >= 300 {
                        " (redirected)"
                    } else {
                        ""
                    };
                    let msg = format!("{}{}", description, suffix);
                    crate::mprintln!(
                        "{}",
                        format!("[+] {}: {} (HTTP {})", url, msg, status).green()
                    );
                    exposed_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(mut guard) = findings.lock() {
                        guard.push(Finding {
                            target: t.clone(),
                            kind: FindingKind::Note,
                            message: format!("{} at {} (status {})", msg, url, status),
                            data: None,
                        });
                    }
                }
            }
            let url = format!("{}/{}", http, path);
            if let Ok(Ok(resp)) = tokio::time::timeout(timeout_dur, client.get(&url).send()).await {
                tested_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let status = resp.status().as_u16();
                if status == 200 || status == 301 || status == 302 || status == 403 {
                    let suffix = if status == 403 {
                        " (403 Forbidden — file exists)"
                    } else if status >= 300 {
                        " (redirected)"
                    } else {
                        ""
                    };
                    let msg = format!("{}{}", description, suffix);
                    crate::mprintln!(
                        "{}",
                        format!("[+] {}: {} (HTTP {})", url, msg, status).green()
                    );
                    exposed_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(mut guard) = findings.lock() {
                        guard.push(Finding {
                            target: t.clone(),
                            kind: FindingKind::Note,
                            message: format!("{} at {} (status {})", msg, url, status),
                            data: None,
                        });
                    }
                }
            }
        });
        tasks.push(h);
    }

    for h in tasks {
        if let Err(e) = h.await {
            tracing::warn!("exposure scan subtask panicked: {}", e);
        }
    }

    // Drain findings into outcome
    if let Ok(mut guard) = findings_lock.lock() {
        outcome.findings.append(&mut *guard);
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Exposure Scan Summary ===".bold());
    crate::mprintln!("  Target:         {}", target);
    crate::mprintln!(
        "  Paths tested:   {}",
        tested.load(std::sync::atomic::Ordering::Relaxed)
    );
    crate::mprintln!(
        "  Exposed files:  {}",
        exposed.load(std::sync::atomic::Ordering::Relaxed)
    );

    Ok(outcome)
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Sensitive File Exposure Scanner".to_string(),
        description: "Probes for exposed sensitive files with 20-way concurrency. Covers .git, .env, backup archives, config files, database dumps, SSH keys, version control metadata, CI/CD, debug logs.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(443),
    }
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "exposure_scanner",
    native
);
