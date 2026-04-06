# Interactive Shell

Rustsploit's shell (`src/shell.rs`) provides an ergonomic command palette with shortcuts, module/target state tracking, and honeypot detection. Launch it with:

```bash
cargo run
```

---

## Command Palette

All commands are **case-insensitive** and support aliases:

| Command | Shortcuts | Description |
|---------|-----------|-------------|
| `help` | `h`, `?` | Show command reference |
| `modules` | `list`, `ls`, `m` | List all discovered modules |
| `find <kw>` | `search`, `f`, `f1` | Search modules by keyword |
| `use <path>` | `u <path>` | Select a module |
| `info [path]` | `i` | Show module metadata (CVE, author, rank) |
| `back` | `b`, `clear`, `reset` | Deselect current module and target |
| `set target <val>` | `t <val>` | Set target (IPv4/IPv6/hostname/CIDR) |
| `set subnet <CIDR>` | `sn <CIDR>` | Set target to a CIDR subnet |
| `show_target` | `st`, `showtarget` | Display current target |
| `clear_target` | `ct`, `cleartarget` | Clear target |
| `run` | `go`, `exec` | Execute the selected module |
| `run -j` | | Run module as background job |
| `run_all` | `runall`, `ra` | Run module against all IPs in subnet |
| `check` | `ch` | Non-destructive vulnerability check |
| `setg <key> <val>` | `sg` | Set a global option (persists across modules) |
| `unsetg <key>` | `ug` | Remove a global option |
| `show options` | `so` | Display all global options |
| `creds` | | List stored credentials |
| `creds add` | | Add a credential interactively |
| `creds search <q>` | | Search credentials by host/service/user |
| `creds delete <id>` | | Delete a credential by ID |
| `creds clear` | | Clear all credentials |
| `hosts` | | List tracked hosts |
| `hosts add <ip>` | | Add a host to workspace |
| `services` | `svcs` | List tracked services |
| `services add` | | Add a service interactively |
| `notes <ip> <text>` | | Add a note to a host |
| `workspace [name]` | `ws` | Show or switch workspaces |
| `loot` | | List collected loot |
| `loot add` | | Add loot interactively |
| `loot search <q>` | | Search loot |
| `resource <file>` | `rc` | Execute a resource script |
| `makerc <file>` | | Save command history to file |
| `spool <file>` | | Log console output to file |
| `spool off` | | Stop console logging |
| `export json <f>` | | Export all data to JSON |
| `export csv <f>` | | Export all data to CSV |
| `export summary <f>` | | Export human-readable report |
| `jobs` | `j` | List background jobs |
| `jobs -k <id>` | | Kill a background job |
| `jobs clean` | | Clean up finished jobs |
| `exit` | `quit`, `q` | Leave the shell |

---

## Example Session

```text
rsf> f1 ssh
rsf> u creds/generic/ssh_bruteforce
rsf> set target 10.10.10.10
rsf> go
```

---

## Command Chaining

Execute multiple commands on one line using the `&` separator:

```text
rsf> u creds/generic/ssh_bruteforce & set target 10.10.10.10 & go
rsf> f1 ssh & u creds/generic/ssh_bruteforce & set target 192.168.1.1
```

Commands are parsed and executed left-to-right. Useful for scripting quick workflows.

---

## Target Normalization

When you run `set target`, the value is normalized and validated automatically. Supported formats:

| Format | Example |
|--------|---------|
| IPv4 | `192.168.1.1` |
| IPv4 + port | `192.168.1.1:8080` |
| IPv6 | `::1`, `2001:db8::1` |
| IPv6 + port | `[::1]:8080` |
| Hostname | `example.com`, `example.com:443` |
| URL | `http://example.com:8080` |
| CIDR | `192.168.1.0/24`, `2001:db8::/32` |

Security checks (length, control characters, path traversal) are enforced at the framework level.

### Multi-Target Support

The framework-level dispatcher handles multiple target types transparently for all modules. You do not need per-module support for these formats:

| Format | Example |
|--------|---------|
| Comma-separated | `t 192.168.1.1, 192.168.1.2, 192.168.1.3` |
| CIDR range | `t 192.168.1.0/24` |
| File of targets | `t /path/to/targets.txt` |
| Random scanning | `t random` or `t 0.0.0.0/0` |

All modules benefit from this automatically -- the dispatcher expands multi-target values and invokes the module once per resolved target.

---

## Honeypot Detection

After a target is set, Rustsploit automatically runs a honeypot check before module execution:

- Scans **200 common ports** with a 250 ms timeout each.
- If **11 or more** ports are open, it warns that the target is likely a honeypot.
- Runs automatically on every `run`/`go` invocation.

Manual call (from module code): `utils::basic_honeypot_check(&ip).await`

---

## Global Options

Use `setg` to set options that persist across all module executions. These are checked by `cfg_prompt_*` functions after API custom_prompts but before interactive stdin:

```text
rsf> setg port 8080
rsf> setg concurrency 50
rsf> show options
rsf> unsetg port
```

Global options are saved to `~/.rustsploit/global_options.json` and loaded on startup.

### Common Global Options

| Option | Example | Effect |
|--------|---------|--------|
| `port` | `setg port 443` | Default port for all modules |
| `source_port` | `setg source_port 31337` | Outbound source port |
| `honeypot_detection` | `setg honeypot_detection n` | Disable honeypot checks before `run` |
| `timeout` | `setg timeout 30` | Connection timeout (seconds) |
| `concurrency` | `setg concurrency 50` | Default thread count |
| `verbose` | `setg verbose y` | Verbose output |
| `username_wordlist` | `setg username_wordlist users.txt` | Default username wordlist |
| `password_wordlist` | `setg password_wordlist pass.txt` | Default password wordlist |
| `stop_on_success` | `setg stop_on_success y` | Stop on first valid credential |
| `save_results` | `setg save_results y` | Auto-save results to file |
| `combo_mode` | `setg combo_mode y` | Full user x pass combination mode |
| Any custom key | `setg my_key value` | Modules read via `cfg_prompt_*` |

---

## Resource Scripts

Automate workflows by writing commands to a file and executing them:

```text
rsf> resource scan_network.rc
```

Script format (one command per line, `#` for comments):
```text
# scan_network.rc
set target 192.168.1.0/24
use scanners/port_scanner
run
```

Auto-loads `~/.rustsploit/startup.rc` on shell startup if it exists. Use `makerc history.rc` to save your command history.

---

## Data Management

Rustsploit tracks engagement data across sessions:

- **Credentials** (`creds`): Store discovered credentials with host, port, service, username, and type
- **Hosts** (`hosts`): Track discovered hosts with hostname, OS, and notes
- **Services** (`services`): Track discovered services per host
- **Loot** (`loot`): Store collected evidence (configs, hashes, firmware)
- **Workspaces** (`workspace`): Isolate data per engagement

Export all data with `export json report.json`, `export csv report.csv`, or `export summary report.txt`.

---

## Background Jobs

Run modules in the background with `run -j`:

```text
rsf> use creds/generic/ssh_bruteforce
rsf> set target 192.168.1.1
rsf> run -j
[*] Job 1 started: creds/generic/ssh_bruteforce against 192.168.1.1
rsf> jobs
rsf> jobs -k 1
```

---

## Shell Architecture

Key details from `src/shell.rs`:

- **`ShellContext`** — stores `current_module`, `current_target`, and `verbose` flag.
- **`execute_single_command()`** — the command dispatcher, extracted as a standalone function for resource script support.
- **`split_command` / `resolve_command`** — normalize shortcut aliases to canonical keys.
- **`render_help()`** — prints the colorized command table.
- **Selective persistence** — `global_options.json`, `creds.json`, workspace files, and loot are persisted across sessions in `~/.rustsploit/`. Transient shell state (selected module, current target, verbose flag) is reset on exit.

Tab completion and command history are powered by `rustyline`.
