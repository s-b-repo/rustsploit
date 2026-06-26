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

Add an `info()` function describing your module. Rustsploit is **exploitation-only**
— do not add a `check()` / `CheckResult` verification phase; modules run an exploit
and report `Finding`s (see _Auto-Store Findings_ below).

```rust
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "My Module".to_string(),
        description: "What this module does.".to_string(),
        authors: vec!["Your Name".to_string()],
        references: vec!["CVE-XXXX-YYYY".to_string()],
        disclosure_date: Some("2025-01-15".to_string()),
        rank: ModuleRank::Good,
        default_port: Some(8080),
    }
}
```

### Auto-Store Findings

**Native modules (preferred):** Emit `Finding` structs in `ModuleOutcome` — the
scheduler routes them to LootStore, Workspace, and the events bus automatically:

```rust
outcome.findings.push(Finding {
    target: target.to_string(),
    kind: FindingKind::Credential,
    message: format!("Valid SSH creds: {}:{}", user, pass),
    data: Some(serde_json::json!({"username": user, "password": pass})),
});
```

**Legacy modules:** Can still call framework helpers directly:

```rust
crate::cred_store::store_credential(crate::cred_store::NewCred {
    host, port: 22, service: "ssh", username: &user, secret: &pass,
    cred_type: crate::cred_store::CredType::Password,
    source_module: "creds/generic/ssh_bruteforce",
}).await;
```

---

## Code Rules

These rules are enforced across the entire codebase:

- **No `unsafe` blocks.** Do not use `unsafe` Rust anywhere in module code (framework FFI in `src/native/` is the only exception).
- **No dead code.** All code must be intentional and used. Do not leave unused functions, imports, or variables. No `#[allow(dead_code)]` or `_variable` suppression.
- **All prompts must use `cfg_prompt_*()` variants** (from `src/utils/prompt.rs`), not raw `prompt_*()` functions. The `cfg_prompt_*` functions check API custom_prompts and global options before falling back to interactive stdin, which is required for API compatibility.
- **All network connections must use framework wrappers** (`tcp_connect_str`, `tcp_connect_addr`, `blocking_tcp_connect`, `udp_bind`) — never raw `TcpStream::connect` or `UdpSocket::bind`. Third-party libraries must receive pre-connected streams.
- **No error swallowing.** Every `Err(_)` must capture the error variable and log/display it. No `let _ = <result>`.
- See [`BAD_PATTERNS.md`](BAD_PATTERNS.md) for the complete 95+ pattern audit checklist.

## Code Style

- Run `cargo fmt` — no manual formatting required
- Use `[+]` / `[-]` / `[!]` / `[*]` prefixes for output (`.green()` / `.red()` / `.yellow()` / `.cyan()`)
- Keep output concise and actionable
- Document CVE IDs and affected products in comments and output
- No `unwrap()` or `unwrap_or_default()` in critical paths — use `?` with `anyhow::Context`
- All targets pass through `crate::utils::normalize_target` — no custom normalization

---

## Mass-Scan Compatibility

All modules automatically support mass scan via the scheduler's fan-out
(CIDR, file, random, comma-separated targets). **Do NOT implement your own
target iteration or `EXCLUDED_RANGES`.** The scheduler handles exclusions,
concurrency, and honeypot detection.

Module-level requirements for mass-scan compatibility:
- **Use target-specific filenames** — `format!("results_{}.txt", safe_target)`
- **Guard interactive/REPL code** — `if is_batch_mode() { bail!("..."); }`
- **Use framework network wrappers** — never raw `TcpStream::connect`
- **No hardcoded timeouts in probes** — accept the user-configured timeout

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
