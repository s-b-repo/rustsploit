use anyhow::{Result, anyhow};
use colored::*;
use libc::{rlimit, setrlimit, getrlimit, RLIMIT_NOFILE};

const TARGET_FILE_LIMIT: u64 = 65535;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   System Ulimit Configuration Utility                     ║".cyan());
    println!("{}", "║   Raises file descriptor limits for brute forcing         ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Module entry point for raising ulimit
pub async fn run(_target: &str) -> Result<()> {
    raise_ulimit().await
}

/// Get current resource limits
fn get_current_limits() -> Result<(u64, u64)> {
    let mut rlim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    
    let result = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
    if result != 0 {
        return Err(anyhow!("Failed to get current limits: {}", std::io::Error::last_os_error()));
    }
    
    Ok((rlim.rlim_cur, rlim.rlim_max))
}

/// Set resource limits directly in the current process
fn set_file_limit(soft: u64, hard: u64) -> Result<()> {
    let rlim = rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    
    let result = unsafe { setrlimit(RLIMIT_NOFILE, &rlim) };
    if result != 0 {
        return Err(anyhow!("Failed to set limits: {}", std::io::Error::last_os_error()));
    }
    
    Ok(())
}

/// Raise ulimit to 65535 using setrlimit syscall (actually works for current process)
async fn raise_ulimit() -> Result<()> {
    display_banner();
    
    // Get current limits
    let (current_soft, current_hard) = match get_current_limits() {
        Ok(limits) => limits,
        Err(e) => {
            println!("{}", format!("[-] Failed to get current limits: {}", e).red());
            (0, 0)
        }
    };
    
    println!("{}", format!("[*] Current limits - Soft: {}, Hard: {}", current_soft, current_hard).cyan());
    
    if current_soft >= TARGET_FILE_LIMIT {
        println!("{}", format!("[+] Open file limit already at {} or higher.", current_soft).green().bold());
        return Ok(());
    }
    
    println!("{}", format!("[*] Attempting to raise open file limit to {}", TARGET_FILE_LIMIT).cyan());
    
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
            println!("{}", format!("[+] Successfully set file limit to {}", target_soft).green().bold());
        }
        Err(e) => {
            // If we can't raise hard limit, try just raising soft to current hard
            println!("{}", format!("[-] Could not set to {}: {}", TARGET_FILE_LIMIT, e).yellow());
            
            if current_hard > current_soft {
                println!("{}", format!("[*] Trying to raise soft limit to hard limit ({})...", current_hard).cyan());
                match set_file_limit(current_hard, current_hard) {
                    Ok(()) => {
                        println!("{}", format!("[+] Raised soft limit to {}", current_hard).green());
                    }
                    Err(e2) => {
                        println!("{}", format!("[-] Could not raise soft limit: {}", e2).red());
                        println!("{}", "[!] Try running as root or adjust /etc/security/limits.conf".yellow());
                    }
                }
            } else {
                println!("{}", "[!] Hard limit is the same as soft limit.".yellow());
                println!("{}", "[!] To increase further, run as root or edit /etc/security/limits.conf".yellow());
            }
        }
    }
    
    // Verify the new limits
    match get_current_limits() {
        Ok((new_soft, new_hard)) => {
            println!("{}", format!("[*] New limits - Soft: {}, Hard: {}", new_soft, new_hard).cyan());
            if new_soft >= TARGET_FILE_LIMIT {
                println!("{}", "[+] File descriptor limit successfully raised!".green().bold());
            } else if new_soft > current_soft {
                println!("{}", format!("[+] Limit raised from {} to {}", current_soft, new_soft).green());
            } else {
                println!("{}", "[-] Limit unchanged.".yellow());
            }
        }
        Err(e) => {
            println!("{}", format!("[-] Could not verify new limits: {}", e).yellow());
        }
    }
    
    // Also show shell instructions for reference
    println!();
    println!("{}", "=== Shell Instructions ===".bold());
    println!("{}", "To raise limits in your shell before running rustsploit:".dimmed());
    println!("{}", "  ulimit -n 65535".white());
    println!("{}", "Or to make permanent, add to /etc/security/limits.conf:".dimmed());
    println!("{}", "  * soft nofile 65535".white());
    println!("{}", "  * hard nofile 65535".white());
    
    Ok(())
}
