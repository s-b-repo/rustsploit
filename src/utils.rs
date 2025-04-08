use std::collections::HashSet;

/// Check if a module path is valid (exploits/..., scanners/..., creds/...)
pub fn module_exists(module_path: &str) -> bool {
    // For demonstration, we only hard-code the known modules
    let known_modules = [
        "exploits/sample_exploit",
        "scanners/sample_scanner",
        "creds/sample_cred_check",
    ];
    known_modules.contains(&module_path)
}

/// List all known modules
pub fn list_all_modules() {
    let modules = [
        "exploits/sample_exploit",
        "scanners/sample_scanner",
        "creds/sample_cred_check",
    ];
    println!("Available modules:");
    for m in modules {
        println!("  {}", m);
    }
}
