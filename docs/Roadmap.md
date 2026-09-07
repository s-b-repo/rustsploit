# Roadmap

Consolidated plan of record — merges the former *Future-Features* and *Module-Wishlist* docs (both retired). Historical engagement artifacts live under `reports/`.

**Current state:** v0.5.1 · 468 modules (exploits 352, scanners 73, creds 34, osint 3, plugins 4, post 2) · 0-warning build · 136-pattern audit gate clean.

---

## Recently Completed

| Feature | Notes |
|---|---|
| Framework services (Metasploit parity) | `info` metadata, `setg`/`unsetg`, cred store, hosts/services tracking, loot, resource scripts, `spool`, background jobs (`run -j`), JSON/CSV/summary export |
| Dynamic source-port binding (v0.5.0) | `setg source_port` honoured framework-wide via `socket2` + network wrappers; third-party libs receive pre-connected streams |
| MCP on official `rmcp` SDK (v0.5.0) | 29 tools + 7 resources, per-call timeout, stdout isolation |
| Recog + JARM/JA3/JA3S fingerprinting (v0.5.0) | `utils::recog`, `utils::tls_fingerprint` |
| SecLists wordlist catalog (v0.5.0) | Checksum-pinned `wordlist::resolve`, 6 seeded entries |
| io_uring connect probes (v0.5.0–0.5.1) | Async + blocking bridge, DNS resolve cache; see [perf/io_uring-migration-plan.md](perf/io_uring-migration-plan.md) |
| `post/` module category | `post/linux_sudo_enum`, `post/windows_pe_enum` |
| Nmap import | `db_import <nmap_xml>` (`src/nmap_import.rs`) populates hosts/services |
| Session + SOCKS foundations | `src/sessions.rs` (`SessionStore`), `src/socks.rs` (`SocksProxy`), `sessions`/`socks` shell commands |
| Per-run output auto-save | `~/.rustsploit/loot/<module> <ts> results.txt`, append mode |
| Full-internet sweep hardening | Sweep advisory + confirmation, ZMap cyclic permutation, exclusion set, sequential order with checkpoint/resume |

---

## Planned Framework Features

1. **Instant configuration profiles.** Load scan parameters (wordlists, threads, timeouts) from a structured file — `run <module> --config profiles/aggressive.toml` or `set config <file>` in the shell. (`save_profile`/`load_profile` cover session state; this covers module option sets.)
2. **Full session/handler management.** Reverse/bind shell listeners, session interaction, backgrounded sessions. Foundations exist in `src/sessions.rs`; needs multi/handler-style listener framework and interactive session I/O.
3. **Network pivoting.** SOCKS proxying and port forwarding through established sessions (`src/socks.rs` is the foundation). Depends on feature 2.
4. **io_uring UDP.** Blocked on tokio-uring's high-level UDP opcodes; the 6 UDP module families (SNMP, NBNS, SSDP, L2TP, TFTP, IPMI) remain on `socket2` — tracked from the v0.5.1 io_uring expansion (G5).

---

## Module Wishlist — Remaining Gaps

21 of the 24 post-engagement wishlist modules shipped between v0.5.1 and now (CRLF→SSRF, HTTP smuggling detect + exploit, DNS zone transfer, CDN origin discovery, reverse-proxy mapping, TLS cipher enum, service versioning, Host-header SSRF, WebSocket tunneling, HTTP/2 downgrade, JWT analyzer, GraphQL introspection, OAuth misconfig, CORS exploit, tech-stack fingerprint, API schema extraction, backup file finder, XXE injector, deserialization probes, exposure scanner, port scanner hardening). The WAF-bypass wishlist item shipped as the framework-level `utils/waf_bypass` engine (see [WAF-Bypass-Engine-Design.md](WAF-Bypass-Engine-Design.md)).

Still open:

| Module | Category | Purpose |
|---|---|---|
| `subdomain_wordlist` | Scanners | Dictionary-based subdomain brute-force (current `subdomain_scanner` is resolution-only; `wordlist::resolve("subdomains-top5k")` is the natural feed) |
| `cache_poisoning` | Exploits | Web cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`) |
| `race_condition` | Exploits | Concurrent-request race tester (TOCTOU, limit-overrun) |

Known-issue tracking (module bugs found during engagements) lives in the dated audit snapshots under `reports/` and the per-release sections of [Changelog.md](Changelog.md).

---

*Want to pick one of these up? See the [Contributing Guide](Contributing.md), then [Module Development](Module-Development.md) before writing code.*
