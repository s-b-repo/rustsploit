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
| `help` | `help`, `h`, `?` | Show command reference |
| `modules` | `modules`, `ls`, `m` | List all discovered modules |
| `find <kw>` | `find <kw>`, `f1 <kw>` | Search modules by keyword |
| `use <path>` | `use <path>`, `u <path>` | Select a module |
| `set target <value>` | `set target <value>` | Set current target (IPv4 / IPv6 / hostname / CIDR) |
| `run` | `run`, `go` | Execute the current module |
| `exit` | `exit`, `quit`, `q` | Leave the shell |

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

---

## Honeypot Detection

After a target is set, Rustsploit automatically runs a honeypot check before module execution:

- Scans **200 common ports** with a 250 ms timeout each.
- If **11 or more** ports are open, it warns that the target is likely a honeypot.
- Runs automatically on every `run`/`go` invocation.

Manual call (from module code): `utils::basic_honeypot_check(&ip).await`

---

## Shell Architecture

Key details from `src/shell.rs`:

- **`ShellContext`** — stores `current_module` and `current_target`.
- **`split_command` / `resolve_command`** — normalize shortcut aliases to canonical keys.
- **`render_help()`** — prints the colorized command table.
- **State reset on exit** — nothing is persisted for OPSEC.

Tab completion and session history are not included by default (to keep dependencies minimal), but can be added by wrapping the loop with a line-editor crate.
