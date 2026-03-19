# CLI Reference

Rustsploit modules can be executed without the interactive shell using Clap-based flags. The CLI dispatcher (`src/cli.rs`) maps directly to the same modules used in the shell.

---

## Basic Syntax

```bash
cargo run -- [FLAGS] --command <TYPE> --module <NAME> --target <HOST>
```

Or if using the compiled binary:
```bash
./rustsploit [FLAGS] --command <TYPE> --module <NAME> --target <HOST>
```

---

## Commands

| Flag | Values | Description |
|------|--------|-------------|
| `--command` / `-c` | `exploit`, `scanner`, `creds` | Module category to run |
| `--module` / `-m` | module name or path | Module to execute (short name or qualified path) |
| `--target` / `-t` | IP / hostname / CIDR | Target to run against |

---

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--list-modules` | | Print all available modules and exit |
| `--verbose` | `-v` | Enable detailed logging |
| `--output-format` | | Control output: `text` (default) or `json` |
| `--api` | | Start the REST API server instead of shell/CLI |
| `--api-key <key>` | | API authentication key (required with `--api`) |
| `--harden` | | Enable hardening mode (requires `--api`) |
| `--interface <addr:port>` | | Bind address for API server (default: `0.0.0.0:8080`) |
| `--ip-limit <n>` | | Max unique IPs before key rotation (default: 10, requires `--harden`) |

---

## Examples

```bash
# Run an exploit
cargo run -- --command exploit --module heartbleed --target 192.168.1.1

# Run a scanner
cargo run -- --command scanner --module port_scanner --target 192.168.1.1

# Run a credential module
cargo run -- --command creds --module ssh_bruteforce --target 192.168.1.1

# List all modules
cargo run -- --list-modules

# Run with verbose logging
cargo run -- -m exploits/sample_exploit -t 127.0.0.1 -v

# Run with JSON output
cargo run -- --command scanner --module port_scanner --target 10.0.0.1 --output-format json
```

---

## Module Names

Modules can be referenced by:
- **Short name:** `ssh_bruteforce`, `heartbleed`, `port_scanner`
- **Qualified path:** `creds/generic/ssh_bruteforce`, `exploits/heartbleed`, `scanners/port_scanner`

Both forms resolve to the same underlying function via the build-generated dispatcher.

Use `--list-modules` or the shell's `modules` command for the authoritative list.

---

## Error Handling & Warnings

| Situation | Message |
|-----------|---------|
| `-m` used without `-t` | `⚠ Warning: module set but no target specified` |
| `-t` used without `-m` | `ℹ Note: target available in shell` |
| `--harden` without `--api` | Error — hardening requires API mode |

---

## Interactive Prompts in CLI Mode

If a module requires additional parameters (e.g., wordlist paths for brute-force), it will prompt interactively even in CLI mode. For automated pipelines, modules should use sensible defaults or accept environment variables where applicable.
