use anyhow::{Context, Result};
use colored::*;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Windows Privilege Escalation Checklist".into(),
        description: "Reference checklist of privilege escalation vectors for Windows \
            (CHECKLIST ONLY — does not execute commands). Lists service paths, token \
            privileges, registry keys, scheduled tasks, unquoted paths, DLL hijacking."
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
        format!("[*] Windows Privilege Escalation Checklist")
            .cyan()
            .bold()
    );

    let checks = &[
        ("whoami /all", "current user privileges"),
        ("systeminfo", "system information / hotfixes"),
        (
            "wmic service get name,pathname,startmode,startname",
            "services with unquoted paths",
        ),
        ("schtasks /query /fo LIST /v", "scheduled tasks"),
        (
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "service registry keys",
        ),
        (
            "icacls C:\\* /findsid *S-1-5-32-545",
            "writable paths by Users group",
        ),
        ("cmdkey /list", "stored credentials"),
        (
            "wmic qfe get Caption,Description,HotFixID,InstalledOn",
            "installed patches",
        ),
        (
            "powershell Get-ExecutionPolicy",
            "PowerShell execution policy",
        ),
        ("net localgroup Administrators", "local admin group members"),
    ];

    for (cmd, description) in checks {
        crate::mprintln!("{}", format!("  [*] {}: {}", description, cmd).dimmed());
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("WinPE check — {}: {}", description, cmd),
            data: Some(serde_json::json!({"target": target, "check": description, "command": cmd})),
        });
    }
    Ok(outcome)
}
crate::register_native_module!(crate::module::Category::Post, "windows/pe_enum", native);
