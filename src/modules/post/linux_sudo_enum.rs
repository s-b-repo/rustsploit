use anyhow::{Context, Result};
use colored::*;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Linux Privilege Escalation Checklist".into(),
        description: "Reference checklist of privilege escalation vectors (CHECKLIST ONLY — \
            does not execute commands). Lists sudo rights, SUID binaries, writable paths, \
            cron jobs, capabilities, kernel exploits to check manually on host."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://github.com/carlospolop/PEASS-ng".into()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("requires single-host target")?;
    let mut outcome = ModuleOutcome::ok();
    crate::mprintln!(
        "{}",
        format!("[*] Linux Privilege Escalation Enumeration")
            .cyan()
            .bold()
    );

    let checks = &[
        ("sudo -l", "sudo rights"),
        ("find / -perm -4000 -type f 2>/dev/null", "SUID binaries"),
        ("find / -perm -2000 -type f 2>/dev/null", "SGID binaries"),
        (
            "find / -writable -type f 2>/dev/null | head -20",
            "writable files",
        ),
        ("cat /etc/crontab 2>/dev/null", "cron jobs"),
        ("uname -a", "kernel version"),
        ("cat /proc/version", "kernel info"),
        ("capsh --print 2>/dev/null", "capabilities"),
        (
            "ls -la /etc/passwd /etc/shadow 2>/dev/null",
            "password files",
        ),
        ("cat /etc/exports 2>/dev/null", "NFS exports"),
    ];

    for (cmd, description) in checks {
        crate::mprintln!("{}", format!("  [*] {}: {}", description, cmd).dimmed());
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("PrivEsc check — {}: {}", description, cmd),
            data: Some(serde_json::json!({"target": target, "check": description, "command": cmd})),
        });
    }

    Ok(outcome)
}
crate::register_native_module!(crate::module::Category::Post, "linux/sudo_enum", native);
