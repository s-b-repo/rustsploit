# CLI Reference

Rustsploit modules can be executed without the interactive shell using Clap-based flags. The CLI dispatcher (`src/cli.rs`) maps directly to the same modules used in the shell.

---

## Basic Syntax

```bash
cargo run -- [FLAGS] -m <MODULE> -t <TARGET>
```

Or if using the compiled binary:
```bash
./rustsploit [FLAGS] -m <MODULE> -t <TARGET>
```

An optional positional argument (`exploit`, `scanner`, `creds`) can be used to specify the module category, but it is not required -- the dispatcher resolves modules by name automatically.

---

## Commands

| Flag | Values | Description |
|------|--------|-------------|
| `--module` / `-m` | module name or path | Module to execute (short name or qualified path) |
| `--target` / `-t` | IP / hostname / CIDR | Target to run against |
| *(positional)* | `exploit`, `scanner`, `creds` | Optional module category subcommand |

---

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--list-modules` | | Print all available modules and exit |
| `--verbose` | `-v` | Enable detailed logging |
| `--output-format` | | Control output: `text` (default) or `json` |
| `--api` | | Start the PQ-encrypted REST + WebSocket API server |
| `--mcp` | | Start as MCP (Model Context Protocol) server on stdio |
| `--interface <addr:port>` | | Bind address for API server (default: `127.0.0.1:8080`) |
| `--pq-host-key <path>` | | PQ host key file (default: `~/.rustsploit/pq_host_key`) |
| `--pq-authorized-keys <path>` | | Authorized client keys file (default: `~/.rustsploit/pq_authorized_keys`) |
| `--resource` | `-r` | Execute a resource script file on startup |

---

## Examples

```bash
# Run an exploit
cargo run -- -m heartbleed -t 192.168.1.1

# Run a scanner
cargo run -- -m port_scanner -t 192.168.1.1

# Run a credential module
cargo run -- -m ssh_bruteforce -t 192.168.1.1

# Run using a qualified module path
cargo run -- -m exploits/sample_exploit -t 127.0.0.1

# List all modules
cargo run -- --list-modules

# Run with verbose logging
cargo run -- -m exploits/sample_exploit -t 127.0.0.1 -v

# Run with JSON output
cargo run -- -m port_scanner -t 10.0.0.1 --output-format json

# Execute a resource script
cargo run -- -r scripts/scan.rc
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
| `-m` used without `-t` | `⚠ Warning: --module specified without --target. Launching shell...` |
| `-t` used without `-m` | Target is stored and available in the interactive shell |

---

## Interactive Prompts in CLI Mode

If a module requires additional parameters (e.g., wordlist paths for brute-force), it will prompt interactively even in CLI mode. For automated pipelines, modules should use sensible defaults or accept environment variables where applicable.
