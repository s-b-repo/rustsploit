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
| `run` | `go`, `exec`, `ra` | Execute the selected module |
| `run -j` | | Run module as background job |
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

Execute multiple commands on one line using the `&` or `;` separator (both are
sequential — there is no parallel/background semantics implied by `&`):

```text
rsf> u creds/generic/ssh_bruteforce & set target 10.10.10.10 & go
rsf> f1 ssh ; u creds/generic/ssh_bruteforce ; set target 192.168.1.1
```

Commands are parsed and executed left-to-right. Useful for scripting quick workflows.

To run a module against every host in a subnet, just `set target <CIDR>` (or
`random`) and `run` — the dispatcher fans out automatically; there is no
separate `run_all` command.

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
| Sequential scanning | `t seq` (from `1.0.0.0`), `t seq:1.2.3.4` (explicit start) |

All modules benefit from this automatically -- the dispatcher expands multi-target values and invokes the module once per resolved target.

> **Note:** Only `random` and `0.0.0.0/0` trigger a full-internet random mass
> scan. Bare `0.0.0.0` is treated as a normal single host, **not** a mass-scan
> keyword, so `t 0.0.0.0` will not launch an internet-wide scan.

### Mass-scan order: random vs. sequential

A full-public-IPv4 sweep can run in two orders, both honoring the exclusion list
(`setg exclusions …`):

- **Random** (default) — `t random` / `t 0.0.0.0/0`: samples random public IPs up
  to `max_random_hosts` (default 10,000).
- **Sequential** — `t seq` / `t seq:<start-ip>`, or flip `0.0.0.0/0`/`random` into
  order with `setg scan_order sequential`: walks `1.0.0.0 → 223.255.255.255` in
  order, skipping excluded/reserved ranges. **Unbounded** by default (Ctrl+C to
  stop) unless you set `max_random_hosts`; it checkpoints the high-water IP, so a
  killed scan **resumes** from where it left off on the next run. Set
  `setg scan_order random` to switch back.

---

## Honeypot Detection

After a target is set, Rustsploit automatically runs a honeypot check before module execution:

- Scans **30 common ports** with a 200 ms timeout each.
- If **11 or more** ports are open, it warns that the target is likely a honeypot.
- Runs automatically on every `run`/`go` invocation.

Manual call (from module code): `crate::utils::network::quick_honeypot_check(ip)`

---

## Global Options (`set` / `setg`)

`set` and `setg` both write to the persistent global options store
(`~/.rustsploit/global_options.json`). They are functionally identical — `set`
is the shorter form, `setg` is kept for Metasploit muscle memory. Both are
checked by `cfg_prompt_*` functions after API custom_prompts but before
interactive stdin.

```text
rsf> set port 8080
rsf> setg concurrency 50
rsf> show options
rsf> unset port
rsf> unsetg concurrency
```

### Metasploit Aliases

The shell accepts Metasploit-style option names and maps them to Rustsploit keys:

| Metasploit name | Rustsploit key | Example |
|-----------------|----------------|---------|
| `RHOST` / `RHOSTS` | `target` | `set RHOST 10.0.0.1` |
| `RPORT` | `port` | `set RPORT 443` |
| `LPORT` | `source_port` | `set LPORT 31337` |
| `THREADS` | `concurrency` | `set THREADS 100` |
| `MODULE_TIMEOUT` | `timeout` | `set MODULE_TIMEOUT 30` |

### Common Global Options

| Option | Example | Effect |
|--------|---------|--------|
| `port` | `set port 443` | Default port for all modules |
| `source_port` | `set source_port 31337` | Outbound source port for all TCP/UDP connections |
| `honeypot_detection` | `set honeypot_detection n` | Disable honeypot checks before `run` |
| `timeout` | `set timeout 30` | Connection/probe timeout (seconds) — passed through to probe functions |
| `concurrency` | `set concurrency 50` | Default thread/task count for brute-force and fan-out |
| `verbose` | `set verbose y` | Verbose output |
| `username_wordlist` | `set username_wordlist users.txt` | Default username wordlist |
| `password_wordlist` | `set password_wordlist pass.txt` | Default password wordlist |
| `stop_on_success` | `set stop_on_success y` | Stop on first valid credential |
| `save_results` | `set save_results y` | Auto-save results to file |
| `combo_mode` | `set combo_mode y` | Full user x pass combination mode |
| `module_timeout` | `set module_timeout 60` | Per-target deadline in scheduler |
| `max_random_hosts` | `set max_random_hosts 10000` | Cap for random mass scan |
| `global_rps` | `set global_rps 100` | Process-wide rate limit (requests/sec) |
| `module_rps` | `set module_rps 50` | Per-module rate limit |
| `target_rps` | `set target_rps 10` | Per-target rate limit |
| `prescan` | `set prescan auto` | Pre-scan tool for CIDR (auto/masscan/zmap/none) |
| `prescan_rate` | `set prescan_rate 1000` | Pre-scan packets per second |
| `scan_order` | `set scan_order sequential` | Mass-scan order for `0.0.0.0/0`/`random`: `random` (default) or `sequential` |
| `target_mac` | `setg target_mac AA:BB:CC:DD:EE:FF` | wpair: target a single Fast Pair device |
| `adapter` | `setg adapter 1` | wpair: BLE adapter index |
| `scan_secs` | `setg scan_secs 20` | wpair: BLE scan window (3–300 s) |
| `model_id` | `setg model_id 0x0582FD` | wpair: Fast Pair model ID when not in the advert |
| `antispoofing_key` | `setg antispoofing_key <base64>` | wpair: Provider Anti-Spoofing public key |
| `gfp_metadata_url` | `setg gfp_metadata_url <tmpl>` | wpair: metadata API URL template (`{model_id}`/`{api_key}`) |
| `gfp_api_key` | `setg gfp_api_key <key>` | wpair: metadata API key |
| Any custom key | `set my_key value` | Modules read via `cfg_prompt_*` |

### Source Port Binding

`set source_port <port>` binds all outbound TCP and UDP connections to the
specified source port. This is enforced at the framework level through the
network wrappers (`tcp_connect_str`, `tcp_connect_addr`, `blocking_tcp_connect`,
`udp_bind`) — including connections made through third-party libraries (FTP,
Telnet) that receive pre-connected streams from these wrappers.

```text
rsf> set source_port 31337
rsf> use creds/generic/ssh_bruteforce
rsf> set target 10.0.0.1
rsf> run
[*] All connections will originate from source port 31337
```

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
