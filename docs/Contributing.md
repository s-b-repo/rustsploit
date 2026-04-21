# Contributing

Contributions are welcome — bug reports, new modules, framework improvements, and wordlist additions are all appreciated.

---

## Workflow

1. **Fork** the repository and create a branch from `main`
2. **Add your module** under the appropriate category in `src/modules/`
3. **Register it** — add `pub mod your_module;` to the sibling `mod.rs`
4. **Run checks:**
   ```bash
   cargo fmt
   cargo check
   cargo test
   ```
5. **Open a PR** — describe what the module does, the CVE (if applicable), and how to test it

---

## Module Placement

| Type | Path |
|------|------|
| Exploit | `src/modules/exploits/<vendor_or_category>/` |
| Scanner | `src/modules/scanners/` |
| Credential | `src/modules/creds/generic/` or `creds/<vendor>/` |
| Plugin | `src/modules/plugins/` |

Use subfolders for vendor families (e.g., `exploits/cisco/`, `exploits/cameras/`).

### Recommended: Add Module Metadata

Consider adding `info()` and/or `check()` functions to your module:

```rust
use crate::module_info::{ModuleInfo, ModuleRank, CheckResult};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "My Module".to_string(),
        description: "What this module does.".to_string(),
        authors: vec!["Your Name".to_string()],
        references: vec!["CVE-XXXX-YYYY".to_string()],
        disclosure_date: Some("2025-01-15".to_string()),
        rank: ModuleRank::Good,
    }
}

pub async fn check(target: &str) -> CheckResult {
    // Non-destructive verification only
    CheckResult::Unknown("Not implemented".to_string())
}
```

### Auto-Store Findings

If your module discovers credentials, hosts, or services, use the framework helpers:

```rust
crate::cred_store::store_credential(host, port, "ssh", user, pass,
    crate::cred_store::CredType::Password, "my_module");
crate::workspace::track_host(ip, Some("hostname"), None);
crate::workspace::track_service(ip, 22, "tcp", "ssh", Some("OpenSSH 8.9"));
```

---

## Code Rules

These rules are enforced across the entire codebase:

- **No `unsafe` blocks.** Do not use `unsafe` Rust anywhere in this codebase.
- **No dead code.** All code must be intentional and used. Do not leave unused functions, imports, or variables.
- **All prompts must use `cfg_prompt_*()` variants** (from `src/utils/prompt.rs`), not raw `prompt_*()` functions. The `cfg_prompt_*` functions check API custom_prompts and global options before falling back to interactive stdin, which is required for API compatibility. Using raw prompt functions will cause modules to block when called via the API.

## Code Style

- Run `cargo fmt` — no manual formatting required
- Use `[+]` / `[-]` / `[!]` / `[*]` prefixes for output (`.green()` / `.red()` / `.yellow()` / `.cyan()`)
- Keep output concise and actionable
- Document CVE IDs and affected products in comments and output
- No `unwrap()` or `unwrap_or_default()` in critical paths — use `?` with `anyhow::Context`
- All targets pass through `crate::utils::normalize_target` — no custom normalization

---

## Mass-Scan Modules

If adding a module with 0.0.0.0/0 support:
- Copy the `EXCLUDED_RANGES` pattern from an existing mass-scan module
- Disable honeypot detection in scan-loop mode
- Default to a sane concurrency limit (mention it in output)

---

## Wordlists

- Store under `lists/` and document in `lists/readme.md`
- Prefer Seclists derivations or well-known public sources
- Keep file sizes reasonable — large lists should support streaming

---

## Bug Reports & Ideas

Open a GitHub issue or reach out with PoCs. Feature requests and module ideas are appreciated — please open a discussion before large refactors.

---

> ⚠️ All contributions must target authorized security testing scenarios. Commit messages and module descriptions must reflect controlled research usage.
