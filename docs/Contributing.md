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

Use subfolders for vendor families (e.g., `exploits/cisco/`, `exploits/cameras/`).

---

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
