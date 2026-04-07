use anyhow::{Result, anyhow};
use colored::*;
use rlimit::Resource;

const TARGET_FILE_LIMIT: u64 = 65535;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "System Ulimit Configuration".to_string(),
        description: "Raises file descriptor limits (ulimit) for the current process to support high-concurrency brute-force operations. Provides guidance for persistent system configuration.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   System Ulimit Configuration Utility                     ║".cyan());
    crate::mprintln!("{}", "║   Raises file descriptor limits for brute forcing         ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Module entry point for raising ulimit
pub async fn run(target: &str) -> Result<()> {
    // Target parameter is part of standard module interface
    // For ulimit operations, target is informational only
    if !target.is_empty() {
        crate::mprintln!("{}", format!("[*] Target context: {}", target).dimmed());
    }
    raise_ulimit().await
}

/// Get current resource limits
fn get_current_limits() -> Result<(u64, u64)> {
    let (soft, hard) = Resource::NOFILE.get()
        .map_err(|e| anyhow!("Failed to get current limits: {}", e))?;
    Ok((soft, hard))
}

/// Set resource limits directly in the current process
fn set_file_limit(soft: u64, hard: u64) -> Result<()> {
    Resource::NOFILE.set(soft, hard)
        .map_err(|e| anyhow!("Failed to set limits: {}", e))
}

/// Raise ulimit to 65535 using setrlimit syscall (actually works for current process)
async fn raise_ulimit() -> Result<()> {
    display_banner();
    
    // Get current limits
    let (current_soft, current_hard) = match get_current_limits() {
        Ok(limits) => limits,
        Err(e) => {
            crate::mprintln!("{}", format!("[-] Failed to get current limits: {}", e).red());
            (0, 0)
        }
    };
    
    crate::mprintln!("{}", format!("[*] Current limits - Soft: {}, Hard: {}", current_soft, current_hard).cyan());
    
    if current_soft >= TARGET_FILE_LIMIT {
        crate::mprintln!("{}", format!("[+] Open file limit already at {} or higher.", current_soft).green().bold());
        return Ok(());
    }
    
    crate::mprintln!("{}", format!("[*] Attempting to raise open file limit to {}", TARGET_FILE_LIMIT).cyan());
    
    // Determine the target limits
    let target_hard = if current_hard >= TARGET_FILE_LIMIT {
        current_hard
    } else {
        TARGET_FILE_LIMIT
    };
    
    let target_soft = TARGET_FILE_LIMIT.min(target_hard);
    
    // Try to set the limit using setrlimit syscall (works for current process)
    match set_file_limit(target_soft, target_hard) {
        Ok(()) => {
            crate::mprintln!("{}", format!("[+] Successfully set file limit to {}", target_soft).green().bold());
        }
        Err(e) => {
            // If we can't raise hard limit, try just raising soft to current hard
            crate::mprintln!("{}", format!("[-] Could not set to {}: {}", TARGET_FILE_LIMIT, e).yellow());
            
            if current_hard > current_soft {
                crate::mprintln!("{}", format!("[*] Trying to raise soft limit to hard limit ({})...", current_hard).cyan());
                match set_file_limit(current_hard, current_hard) {
                    Ok(()) => {
                        crate::mprintln!("{}", format!("[+] Raised soft limit to {}", current_hard).green());
                    }
                    Err(e2) => {
                        crate::mprintln!("{}", format!("[-] Could not raise soft limit: {}", e2).red());
                        crate::mprintln!("{}", "[!] Try running as root or adjust /etc/security/limits.conf".yellow());
                    }
                }
            } else {
                crate::mprintln!("{}", "[!] Hard limit is the same as soft limit.".yellow());
                crate::mprintln!("{}", "[!] To increase further, run as root or edit /etc/security/limits.conf".yellow());
            }
        }
    }
    
    // Verify the new limits
    match get_current_limits() {
        Ok((new_soft, new_hard)) => {
            crate::mprintln!("{}", format!("[*] New limits - Soft: {}, Hard: {}", new_soft, new_hard).cyan());
            if new_soft >= TARGET_FILE_LIMIT {
                crate::mprintln!("{}", "[+] File descriptor limit successfully raised!".green().bold());
            } else if new_soft > current_soft {
                crate::mprintln!("{}", format!("[+] Limit raised from {} to {}", current_soft, new_soft).green());
            } else {
                crate::mprintln!("{}", "[-] Limit unchanged.".yellow());
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[-] Could not verify new limits: {}", e).yellow());
        }
    }
    
    // Also show shell instructions for reference
    crate::mprintln!();
    crate::mprintln!("{}", "=== Shell Instructions ===".bold());
    crate::mprintln!("{}", "To raise limits in your shell before running rustsploit:".dimmed());
    crate::mprintln!("{}", "  ulimit -n 65535".white());
    crate::mprintln!("{}", "Or to make permanent, add to /etc/security/limits.conf:".dimmed());
    crate::mprintln!("{}", "  * soft nofile 65535".white());
    crate::mprintln!("{}", "  * hard nofile 65535".white());
    
    Ok(())
}
