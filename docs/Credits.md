# Credits

---

## Project

| Role | Name |
|------|------|
| Project Lead | s-b-repo |
| Language | 100% Rust |

---

## Inspiration

- [RouterSploit](https://github.com/threat9/routersploit) — modular embedded exploitation framework
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — industry-standard exploitation framework
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF exploit library

---

## Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) — the majority of bundled wordlists
- Custom additions in `lists/` — documented in `lists/readme.md`

---

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `reqwest` | HTTP client |
| `clap` | CLI argument parsing |
| `anyhow` | Error handling |
| `colored` | Terminal color output |
| `axum` | REST API framework |
| `suppaftp` | FTP/FTPS (v7, tokio async) |
| `hickory-client` | DNS (v0.25, builder pattern) |
| `ipnetwork` | CIDR range matching |
| `rustls` | TLS (v0.23+) |
| `bytes` | Buffer management (`BytesMut`) |
| `subtle` | Constant-time API key comparison |
| `strsim` | Fuzzy module name matching (Levenshtein) |
| `rustyline` | Interactive shell line editing |
| `serde` / `serde_json` | Serialization / JSON persistence |
| `ssh2` | SSH protocol support |
| `des` / `aes` / `cipher` | Cryptographic primitives |
| `chrono` | Date/time handling |
| `uuid` | Unique identifier generation |
| `ratatui` | Terminal UI framework (WPair TUI) |
| `crossterm` | Terminal backend for ratatui |
| `btleplug` | Bluetooth Low Energy (WPair BLE) |
| `rlimit` | Safe resource limit management |
| `tracing` | Structured logging framework |
| `num_cpus` | CPU core detection |
| `gag` | Stdout capture (deprecated, replaced by mprintln!) |

---

## Legal

> ⚠️ Rustsploit is intended for **authorized security testing and research only**.  
> Obtain explicit written permission before targeting any system you do not own.  
> The authors accept no liability for misuse.

Licensed under the terms in [LICENSE](../LICENSE).
