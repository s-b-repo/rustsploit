# Rustsploit Wiki

Documentation hub for Rustsploit — a modular offensive-security framework in Rust. One binary, four interfaces (interactive shell · CLI runner · PQ-encrypted REST/WebSocket API · MCP server), 468 self-registering modules.

> ⚠️ Rustsploit is intended for **authorized security testing and research only**. Always obtain explicit written permission before targeting any system you do not own.

---

## Start Here

| Document | Description |
|----------|-------------|
| [Getting Started](Getting-Started.md) | Installation, build, quick-start, Docker deployment |
| [Interactive Shell](Interactive-Shell.md) | Shell walkthrough, command palette, chaining, shortcuts |
| [CLI Reference](CLI-Reference.md) | Command-line flags, non-shell usage, output formats |

## Architecture & Transports

| Document | Description |
|----------|-------------|
| [Architecture](Architecture.md) | Dispatch path, scheduler fan-out, runtime context, tenancy, state, output |
| [API Server](API-Server.md) | REST + WebSocket API, PQ encryption, endpoints, rate limiting |
| [API Usage Examples](API-Usage-Examples.md) | Practical curl workflows, request/response samples |
| [MCP Integration](MCP-Integration.md) | 29 MCP tools + 7 resources for AI-assisted pentesting over stdio |

## Modules

| Document | Description |
|----------|-------------|
| [Module Catalog](Module-Catalog.md) | All 468 modules by category — auto-generated via `rustsploit --gen-module-catalog`, never hand-edited |
| [Module Development](Module-Development.md) | How to author new modules — `Module` trait, lifecycle hooks, registration macro, scheduler contract |
| [Exploit Modules Guide](Exploit-Modules-Guide.md) | Best practices for exploit modules — mass-scan compat, batch guards, artifacts |
| [Credential Modules Guide](Credential-Modules-Guide.md) | Best practices for credential modules — `creds_helper`, source port, timeout passthrough |
| [Bluetooth Framework](Bluetooth-Framework.md) | Full Bluetooth reference — hardware tiers, core layer, 26-module catalog, setg options |
| [Fast Pair / WhisperPair Guide](Fast-Pair-WhisperPair-Guide.md) | CVE-2025-36911 Fast Pair exploitation — ECDH key-based pairing, hardware runbook |

## Security & Quality

| Document | Description |
|----------|-------------|
| [Bad Patterns](BAD_PATTERNS.md) | Banned code patterns — 136-regex matrix enforced by `scripts/audit-bad-patterns.sh` |
| [Security & Validation](Security-Validation.md) | Input validation constants, security patterns, honeypot detection |
| [Testing & QA](Testing-QA.md) | Build checks (0 errors, 0 warnings), smoke tests, wordlist validation, docs gate |
| [Utilities & Helpers](Utilities-Helpers.md) | Network wrappers, `cfg_prompt_*`, `creds_helper`, Recog, TLS fingerprinting, wordlists |

## Project

| Document | Description |
|----------|-------------|
| [Roadmap](Roadmap.md) | Planned features and module wishlist |
| [Legacy / Migration Status](Legacy.md) | Pre-v0.5.0 code paths kept on purpose, in-flight migrations, findings ledger |
| [WAF Bypass Engine](WAF-Bypass-Engine-Design.md) | As-built reference for the `utils/waf_bypass` engine — options, techniques, signatures |
| [Edition 2026 Migration](edition-2026-migration.md) | Planning notes for the Rust 2026 edition bump |
| [Performance: io_uring](perf/io_uring-migration-plan.md) | io_uring connect-probe migration — as-built design and benchmark results |
| [Changelog](Changelog.md) | Release notes and version history (latest: v0.5.1 — 2026-07-01) |
| [Contributing](Contributing.md) | Fork guide, PR checklist, code style |
| [Credits](Credits.md) | Authors, acknowledgements, legal notice |

---

## Quick Navigation

- **New user?** → Start with [Getting Started](Getting-Started.md)
- **Writing a module?** → See [Module Development](Module-Development.md) and [Bad Patterns](BAD_PATTERNS.md)
- **Using the API?** → See [API Server](API-Server.md) + [API Usage Examples](API-Usage-Examples.md)
- **Driving it from an LLM?** → See [MCP Integration](MCP-Integration.md)
- **Running from CLI?** → See [CLI Reference](CLI-Reference.md)
- **What's planned?** → See [Roadmap](Roadmap.md)
