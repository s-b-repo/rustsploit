// src/utils/mod.rs
//
// Re-export hub — all existing `use crate::utils::*` imports continue to work.

pub mod bruteforce;
pub mod creds_helper;
pub mod exploit_helper;
pub mod modules;
pub mod network;
pub mod parallel;
pub mod privilege;
pub mod prompt;
pub mod safe_io;
pub mod sanitize;
pub mod target;
pub mod throttle;
pub mod wordlist;

use colored::*;

pub use privilege::{is_root, require_root, set_secure_permissions};

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

/// Check if we're running inside a batch/concurrent dispatch context
/// (mass scan, CIDR subnet, or file-based target list).
///
/// Modules can use this to suppress headers and other non-prompt output
/// that would otherwise be printed once per concurrent task.
pub fn is_batch_mode() -> bool {
    if crate::context::is_batch_active() {
        return true;
    }
    crate::context::RUN_CONTEXT
        .try_with(|ctx| ctx.prompt_cache.is_some())
        .unwrap_or(false)
}

// ============================================================
// RE-EXPORTS — keeps `use crate::utils::foo` working everywhere
// ============================================================

// --- prompt.rs ---
pub use prompt::{
    cfg_prompt_default,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_output_file,
    cfg_prompt_port,
    cfg_prompt_required,
    cfg_prompt_wordlist,
    cfg_prompt_yes_no,
    prompt_default,
    prompt_required,
    prompt_yes_no,
};

// --- sanitize.rs ---
pub use sanitize::{
    escape_js_command,
    escape_shell_command,
    sanitize_target_simple,
    validate_command_input,
    validate_file_path,
    validate_url,
};

// --- target.rs ---
pub use target::{
    is_domain,
    normalize_target,
    prompt_domain_target,
};

// --- safe_io.rs ---
pub use safe_io::read_http_body_capped;

// --- network.rs ---
pub use network::blocking_tcp_connect;
pub use network::blocking_udp_bind;
pub use network::build_http_client;
pub use network::get_global_source_port;
pub use network::header_string;
pub use network::http_get_status_body;
pub use network::http_get_status_headers_body;
pub use network::tcp_connect_str;
pub use network::tcp_port_open;
pub use network::udp_bind;
// tcp_connect_addr, build_http_client_with, HttpClientOpts live in
// crate::utils::network — call via the fully-qualified path until Phase B2b /
// future work adopts them; we don't add re-exports here to keep the lint
// clean without #[allow(unused_imports)].

// --- modules.rs ---
pub use modules::{
    find_modules,
    get_filename_in_current_dir,
    list_all_modules,
    file_size,
    module_exists,
    safe_read_to_string,
    safe_read_to_string_async,
    STREAMING_THRESHOLD,
};

// --- wordlist.rs (line-loading functions migrated from modules.rs) ---
pub use wordlist::{
    load_lines,
    load_lines_batched,
    load_lines_cached,
    load_lines_uncapped,
};

// --- bruteforce.rs (migrated from modules/creds/utils.rs) ---
// `run_mass_scan` and `MassScanConfig` were removed in v0.5.1 — universal
// mass-scan fan-out is handled by `crate::scheduler::run` for every module.
pub use bruteforce::{
    backoff_delay,
    BruteforceConfig,
    EXCLUDED_RANGES,
    generate_combos_mode,
    generate_random_public_ip,
    is_mass_scan_target,
    is_subnet_target,
    load_credential_file,
    LoginResult,
    parse_combo_mode,
    parse_subnet,
    run_bruteforce,
    run_bruteforce_streaming,
    run_subnet_bruteforce,
    subnet_host_count,
    SubnetScanConfig,
};
