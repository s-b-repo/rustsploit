// src/utils/mod.rs
//
// Re-export hub — all existing `use crate::utils::*` imports continue to work.

pub mod prompt;
pub mod sanitize;
pub mod target;
pub mod network;
pub mod modules;

use colored::*;

// ============================================================
// URL ENCODING HELPER (replaces unmaintained `urlencoding` crate)
// ============================================================

/// URL-encode a string (equivalent to `urlencoding::encode`).
///
/// Uses our vendored `native::url_encoding` (based on urlencoding 2.1.3).
pub fn url_encode(s: &str) -> String {
    crate::native::url_encoding::encode(s).into_owned()
}

// ============================================================
// LOGGING (small enough to live here)
// ============================================================

/// Helper for verbose logging
pub fn verbose_log(verbose: bool, message: &str) {
    if verbose {
        crate::meprintln!("{} {}", "[VERBOSE]".dimmed(), message.dimmed());
    }
}

// ============================================================
// RE-EXPORTS — keeps `use crate::utils::foo` working everywhere
// ============================================================

// --- prompt.rs ---
pub use prompt::{
    prompt_required,
    prompt_default,
    prompt_yes_no,
    cfg_prompt_required,
    cfg_prompt_default,
    cfg_prompt_yes_no,
    cfg_prompt_port,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_output_file,
    cfg_prompt_wordlist,
};

// --- sanitize.rs ---
pub use sanitize::{
    sanitize_target_simple,
    validate_command_input,
    validate_file_path,
    validate_url,
    escape_shell_command,
    escape_js_command,
};

// --- target.rs ---
pub use target::{
    normalize_target,
    extract_ip_from_target,
    is_domain,
    prompt_domain_target,
};

// --- network.rs ---
pub use network::tcp_port_open;
pub use network::get_global_source_port;
pub use network::blocking_tcp_connect;
pub use network::udp_bind;
pub use network::blocking_udp_bind;
pub use network::build_http_client;

// --- modules.rs ---
pub use modules::{
    module_exists,
    list_all_modules,
    find_modules,
    load_lines,
    get_filename_in_current_dir,
    safe_read_to_string,
    safe_read_to_string_async,
};
