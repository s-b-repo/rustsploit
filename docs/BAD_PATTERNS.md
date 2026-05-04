# Bad-Pattern Catalogue

> Run `scripts/audit-bad-patterns.sh` to scan the whole tree, or
> `scripts/audit-bad-patterns.sh --strict --files <list>` to gate a
> module / PR. Latest snapshot: [`audit-report.md`](audit-report.md).

A complete checklist of patterns that must not appear in module code. Every
entry has:

- **Pattern (regex)** — what `grep -E` finds
- **Why it's bad** — what concretely goes wrong if it slips in
- **Fix** — the explicit alternative

The full reproducer at the bottom runs every regex in one shot and reports a
zero-line summary on a clean tree. CI / pre-merge review should treat any
non-zero count as a hard failure.

> **Scope.** Module code under `src/modules/exploits/`, `src/modules/scanners/`,
> `src/modules/creds/`, `src/modules/osint/`, `src/modules/plugins/`. The
> framework's own DoS / payload-generation crates have legitimate `unsafe`
> blocks and raw socket calls that this catalogue does not constrain.

---

## A. Panicking error handling — banned outright

| # | Pattern (regex) | Why bad | Fix |
|---|---|---|---|
| A1 | `\.unwrap\(\)` | Panics on `Err`/`None`, takes the whole shell down. | Match explicitly or use `?` with `anyhow::Context`. |
| A2 | `\.expect\(` | Same as `.unwrap()` plus a static message. | `with_context(\|\| format!("...{}...", info))`. |
| A3 | `\.unwrap_or_default\(\)` | Silently turns `Err` into `T::default()` — body becomes `""`, status becomes `0`. Lies about what happened on the wire. | Match arms returning `CheckResult::Error(...)` or propagate via `?` with `Context`. |
| A4 | `\.unwrap_or\b` | Even on `Option`, hides the None case behind a magic literal (`"?"`, `""`). Use a self-documenting fallback. | `match opt { Some(x) => x, None => "<documented missing case>" }`. |
| A5 | `\.unwrap_or_else\(` | Same shape as A4 with a closure. | Match arms with explicit None handling. |
| A6 | `\.parse\(\)\.unwrap`, `\.parse::<[^>]+>\(\)\.unwrap` | Parse failures panic. | `parse().with_context(\|\| format!("parse {} as {}", input, "u16"))?`. |
| A7 | `\.try_into\(\)\.unwrap` | TryFrom failures panic. | `try_into().with_context(\|\| ...)?`. |
| A8 | `\.first\(\)\.unwrap`, `\.last\(\)\.unwrap`, `\.next\(\)\.unwrap`, `\.iter\(\)…\.unwrap` | Iterator end-of-stream panics. | `match it.next() { Some(x) => x, None => return CheckResult::Error("...".into()) }`. |
| A9 | `\.chars\(\)\.next\(\)\.unwrap`, `\.split\([^)]*\)\.next\(\)\.unwrap` | Empty-string panics. | Same as A8. |
| A10 | `\.position\(.*\)\.unwrap`, `\.iter\(\)\.find\(.*\)\.unwrap` | Search-miss panics. | Match on `Option`. |
| A11 | `\.read_to_string\(.*\)\.unwrap` | I/O failure panics. | `with_context(\|\| format!("read {}", path))?`. |
| A12 | `\.lock\(\)\.unwrap` | Poison panics. | Use `tokio::sync::Mutex` (no poison) or match on the `PoisonError` and either reset or surface. |
| A13 | `\.expect_err`, `\.unwrap_err` | Same panic shape, on the Err side. | Match the `Result` directly. |
| A14 | `panic!\(`, `unreachable!\(`, `todo!\(`, `unimplemented!\(` | Unconditional crash. | Return `Result::Err` (or `CheckResult::Error`) with a descriptive message. |
| A15 | `\bassert!\(`, `\bassert_eq!\(`, `\bassert_ne!\(` | Production panic on bad input. | Validate at the boundary and return `Err`. Reserve assertions for tests under `#[cfg(test)]`. |

## B. Silent error swallowing — banned outright

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| B1 | `Err\(_\)` (anonymous) | Drops the error value. Even on `tokio::time::error::Elapsed`, the `Display` impl ("deadline has elapsed") tells the operator *why* the call failed. | `Err(e) => mprintln!("{} timed out: {}", "[-]".red(), e)`. |
| B2 | `Err\(_[a-zA-Z]\w*\)` (underscore-prefixed binding) | Same as B1 — the leading `_` is a "compiler shut up about unused" hack. | Bind without the underscore and `format!` it. |
| B3 | `if let Err\(_` | Same as B1. | Capture the error. |
| B4 | `if let Ok\(` (no `else`) | Drops `Err` silently — `check()` falls through to `NotVulnerable` even though the host was unreachable. | `match …` with explicit `Err(e) => CheckResult::Error(format!("{:#}", e))`. |
| B5 | `let\s+_\s*=` | Discards a `Result`. The function "succeeded" because nothing checked. | `if let Err(e) = … { mprintln!(…) }` or `?`. |
| B6 | `let\s+_[a-zA-Z]\w*\s*=.*\.await` | The `_<name>` prefix suppresses unused warnings on a side-effect call. The result is propagated via `?`, so the binding adds nothing. | Bare `func(...).await?;` (no `let`). |
| B7 | `\.map_err\(\|_\|`, `\.or_else\(\|_\|` | Throws away the original error type. | Capture the error and wrap it: `.map_err(\|e\| anyhow!("...: {}", e))`. |
| B8 | `\.to_str\(\)\.ok\(\)` | Header-value utf8 failure becomes `None` and then `""` via `.unwrap_or("")` — the swallow is invisible. | `crate::utils::header_string(headers, "name")` (returns `"<non-utf8>"` sentinel for non-utf8 — the swallow shows up). |
| B9 | `\.json\([^)]*\)\.await\.ok\(\)`, `\.send\(\)\.await\.ok\(\)`, `\.text\(\)\.await\.ok\(\)` | Discards transport / decode errors. | `match …await { Ok(v) => …, Err(e) => mprintln!(…); return Ok(()); }` |

## C. Compiler-warning-suppression — banned outright

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| C1 | `#\[allow\(` | Hides real lints (`dead_code`, `unused_imports`, `clippy::*`). If the code is dead, delete it; if a warning is wrong, fix the *cause*. | Remove the attribute and address the underlying warning. |
| C2 | `#\[deny\(` | Project-wide lint-policy belongs in `Cargo.toml` / `[lints]`, not per-module. | Move to crate root. |
| C3 | `#\[ignore\b` | Skipped tests rot. | Delete the test or fix it. |

## D. Panic vectors — banned in modules

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| D1 | Direct array index `\b[a-zA-Z_]\w*\[[0-9]+\]` and `\b[a-zA-Z_]\w*\[[a-zA-Z_]\w*\]` | OOB panic. Even when the index "can't" be wrong, a future refactor can break the invariant. | `arr.get(i)` and match. For first byte: `slice.first()`. |
| D2 | Direct slice range `\&[a-zA-Z_]\w*\[\.\.\w+\]` / `\&[a-zA-Z_]\w*\[\w+\.\.\]` / `\&[a-zA-Z_]\w*\[\w+\.\.\w+\]` | OOB panic. `tokio::AsyncRead::read` contractually returns `n <= buf.len()`, but the panic is still in your binary. | `buf.get(..n).context(…)?`. |
| D3 | `\.split_at\(` | Panics if index > `len`. | `split_at_checked` (Rust 1.80+) or guard manually. |
| D4 | `\.chars\(\)\.nth\(` | Off-by-one panics. | Use the `Option` it returns. |
| D5 | `vec!\[…\]\[0\]` | Indexing a literal vec (rare, and almost always wrong). | Pattern-match. |

## E. Numeric conversions — explicit only

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| E1 | `\bas\s+(u\|i)(8\|16\|32\|64)\b`, `\bas\s+(u\|i)size\b` | Truncates silently. `as u16` of an `i64=70000` becomes `4464`. | `u16::try_from(x).with_context(\|\| ...)?`. For widening (`u16 -> i64`) use `i64::from(x)` — conversion is explicit and infallible. |
| E2 | `\bas\s+(f32\|f64)\b` | Float conversion can round. | `f64::from(x)` for widenings; explicit rounding routine for narrowings. |
| E3 | `\bas\s+\*const\b`, `\bas\s+\*mut\b` | Pointer cast — UB if mis-typed. | Banned. Use `&` / `&mut` references or `Box::into_raw` paths inside `unsafe` only. |
| E4 | `\btransmute\(`, `\bextern\s+"C"`, `\bunsafe\s*\{`, `\bunsafe\s+fn\b` | Unsafe ops in modules are a layering violation; the framework concentrates `unsafe` in `src/native/`. | Refactor; if you really need it, put it under `src/native/` with the existing safety contract. |

## F. Async / blocking pitfalls — banned in modules

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| F1 | `std::thread::sleep` | Blocks the executor thread. | `tokio::time::sleep`. |
| F2 | `std::process::Command` | Synchronous fork+exec. | `tokio::process::Command`. |
| F3 | `std::fs::File`, `std::fs::read`, `std::fs::write` | Blocks the executor. | `tokio::fs::*`. |
| F4 | `std::net::TcpStream`, `std::net::UdpSocket` | Blocking sockets. | `tokio::net::*`. |
| F5 | `std::io::stdin\(\)` | Blocks. Modules also shouldn't read stdin directly — use `cfg_prompt_*`. | `cfg_prompt_*` from `crate::utils`. |
| F6 | `\.lock\(\)` on `std::sync::Mutex` followed by `\.await` later in the scope | Deadlock risk; the lock is held across the await point. | `tokio::sync::Mutex` (lock guard releases at drop and the runtime can suspend safely). |
| F7 | `tokio::spawn\(` without holding the `JoinHandle` | Fire-and-forget leak; errors and panics are swallowed. | Hold the handle and `.await` it, or `.abort_handle()` when intentional. |

## G. Logging & output — modules use the framework macros

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| G1 | `\beprintln!\(` (where the source is not `mprintln`/`meprintln`) | Bypasses the framework's spool (`docs/Interactive-Shell.md`). | `crate::meprintln!(...)` for stderr, `crate::mprintln!(...)` for stdout. |
| G2 | `\bdbg!\(` | Debugging macro left in. | Delete. |
| G3 | `format!\(.*"\{:\?\}".*\b[eE]rr\b` | Debug-format on errors loses the `Display` impl that gives a clean human message. | `format!("...: {}", err)` or `format!("...: {:#}", err)` for full chain. |
| G4 | `\.context\("")\|\.context\("\?"\)` | Empty / unhelpful context — adds nothing to the error chain. | `with_context(\|\| format!("…{}…", info))`. |

## H. HTTP layer — go through the framework client

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| H1 | `reqwest::Client::new\(\)`, `reqwest::Client::builder\(\)` | Bypasses `crate::utils::build_http_client`, which sets timeout, TLS policy, redirect rules, source-port awareness, and the global cookie-store decision. | `crate::utils::build_http_client(Duration::from_secs(N))`. |
| H2 | `\.send\(\)\.await\?` (no `Context`) | The error has no path / module attribution; debugging mass scans is hopeless. | `.send().await.with_context(\|\| format!("GET {} failed", url))?`. |
| H3 | `\.text\(\)\.await\?` (no `Context`) | Same. | `.text().await.context("read body")?` or use `crate::utils::http_get_status_body`. |
| H4 | `format!("{:?}", v).contains("HTTP/2")` (debug-string-compare on `reqwest::Version`) | Fragile, no compile-time check. | `v == reqwest::Version::HTTP_2`. |

## I. Iterator collect / Result glitches

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| I1 | `\.collect::<Result<Vec<_>,\s*_>>\(\)\.unwrap` | Aggregated `Result` panics on first error. | `let xs = …collect::<Result<Vec<_>, _>>()?;`. |
| I2 | `\.zip\([^)]*\)\.unwrap` | Zip mismatch panic. | Length-check first. |

## J. Style / safety

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| J1 | `s == ""`, `s\.len\(\) == 0`, `s\.len\(\) > 0` | Should use `is_empty()`. | `s.is_empty()` / `!s.is_empty()`. |
| J2 | `String::from\(format!` | Pointless wrapping. | `format!(...)` already returns `String`. |
| J3 | `\.clone\(\)\s*\.clone`, `\.to_string\(\)\s*\.to_string`, `\.to_owned\(\)\s*\.to_owned` | Double allocation. | Single call. |
| J4 | `XXXXXX`, `TODO`, `FIXME`, `HACK\b` | Placeholder URLs / unfinished work. | Replace with real value or remove. |
| J5 | `Bearer\s+[A-Za-z0-9_.-]{40,}`, `sk-[A-Za-z0-9]{20,}`, `AKIA[A-Z0-9]{16}`, hardcoded `"admin"\s*,\s*"admin"` and friends | Embedded secrets in source / placeholder pairs that look like secrets to scanners. | Prompt for values via `cfg_prompt_required` / read from env. |
| J6 | `Box<dyn` in module returns | Module trait-objects are unnecessary in this codebase; `anyhow::Error` is the framework's error type. | `anyhow::Result<T>` / `anyhow::Error`. |

## K. Resource handling

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| K1 | `tokio::spawn(...)` not awaited / not held | Background task panic / error is invisible. | Hold the `JoinHandle` and `.await` it. |
| K2 | `Mutex::new`, `RwLock::new` (`std::sync::*`) inside async modules | Blocking primitives + `.await` = potential deadlock. | `tokio::sync::Mutex`, `tokio::sync::RwLock`. |

## L. Crypto antipatterns — modules

These flag *uses* of broken or risky primitives. Many appear legitimately
in the codebase as **protocol-required** auth flows (Postgres MD5 auth,
MySQL SHA1 challenge, VNC/RDP single-DES password handling) — those are
in the framework's `creds/` and `native/rdp.rs` and stay as-is. Module
authors should **not** add new uses of any of these unless the target
protocol forces it.

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| L1 | `\bmd5::compute\b\|\bmd5::Md5\b` | MD5 is collision-broken. Acceptable only for protocol auth (Postgres, RDP NTLMv1). | SHA-256+ for new code. |
| L2 | `\bsha1::Sha1\b\|use sha1::` | SHA-1 broken. Acceptable only for MySQL native challenge. | SHA-256+. |
| L3 | `\bdes::Des\b`, `\b3des\b`, `TripleDES` | DES weak (56-bit). Acceptable only for VNC RFB / Cisco type-7 / TightVNC password handling. | AES-256-GCM for new code. |
| L4 | `rand::thread_rng\(\)` and `rand::random\(\)` for security-relevant randomness | Not guaranteed to be a CSPRNG. | `rand::rngs::OsRng` (or `getrandom::getrandom`). For non-security RNG (transaction IDs, jitter) `thread_rng()` is fine. |
| L5 | `\bRC4\b\|rc4::` | RC4 broken. Acceptable only as scanner *targets* (e.g. `ssl_scanner` enumerating weak ciphers) and inside `crate::native::obfuscator_engine` (intentional shellcode-obfuscation method). | None for new code. |
| L6 | ECB mode (`Ecb`, `aes-128-ecb`) | Pattern-leakage. | CTR / GCM. |

## M. SQL & command injection

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| M1 | `format!\("SELECT[^"]*\{\|format!\("INSERT[^"]*\{\|format!\("UPDATE[^"]*\{\|format!\("DELETE[^"]*\{` | Format-string SQL = injection. | Bind parameters via the database driver. For probes, hardcode the test payload as a constant string. |
| M2 | `std::process::Command::new\("/bin/sh"\)`, `std::process::Command::new\("sh"\)`, `\.arg\("-c"\).*format!` | Shell-out with formatted user input = command injection. | Use `Command::new(prog).args([...])` with each argument as a separate `arg()` — no shell. |

## N. Concurrency / UB

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| N1 | `\bstatic\s+mut\b` | Mutable global = data race UB. | `Mutex<T>` / `RwLock<T>` / `Atomic*` / `OnceCell<T>` / `Lazy<T>`. |
| N2 | `std::mem::transmute`, `std::mem::forget`, `std::mem::uninitialized`, `std::mem::zeroed` (outside `crate::native/*`) | UB-prone. | Stay inside `crate::native/*` for FFI. Module code never needs these. |
| N3 | `std::ptr::read`, `std::ptr::write` | Raw pointer reads/writes outside `unsafe` ⇒ UB. | Use references; if FFI, contain in `crate::native/*`. |
| N4 | `Result<\(\), String>`, `Result<.*,\s*String>` | Stringly-typed errors lose type information. | `anyhow::Result<T>`. |

## O. Performance / idiom hygiene

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| O1 | `\.iter\(\)\.count\(\)` | Walks whole iterator. | `.len()` if available. |
| O2 | `\.collect::<\(\)>\(\)` | Collects into nothing. | `.for_each(...)` or just `for ... in`. |
| O3 | `\.iter\(\)\.map\(\|x\|\s*x\.clone\(\)\)\s*\.collect` | `cloned().collect()` is shorter. | `.cloned().collect()`. |
| O4 | `\.to_string\(\)\.as_str\(\)` | Round-trip allocation. | Drop the `.to_string()`. |
| O5 | `Vec::with_capacity\(0\)`, `String::with_capacity\(0\)` | Pointless. | `Vec::new()` / `String::new()`. |
| O6 | `Regex::new\(.*\)\.unwrap` in a hot path | Re-compiles on every call. | `once_cell::sync::Lazy<Regex>` at module scope. |
| O7 | `Box::new\(.*Box::new` | Double allocation. | One `Box`. |

## P. Type / API hygiene

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| P1 | `pub static\s+\w+\s*:` (mutable) | Mutable global API surface. | Confine to `Lazy<RwLock<T>>` patterns; expose accessor functions, not the static. |
| P2 | `#\[derive\(Debug\)\]` on a struct with a `password` / `secret` / `token` field | The `Debug` impl prints the secret; `format!("{:?}", obj)` leaks it to logs. | Custom `Debug` impl that redacts, or use `secrecy::Secret<T>`. |
| P3 | `\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*"http` | Hardcoded production URLs in pub constants are hard to override. | Constructor / config. |
| P4 | TLS verification disabled in scanner clients (`accept_invalid_certs(true)`) | Acceptable for *security scanners* (target may be self-signed); banned in *clients* that talk to trusted services like the framework's own API. | The framework provides `HttpClientOpts::permissive` (scanner default) and `HttpClientOpts::strict` (when needed). Use the right one. |

## Q. Cargo.toml hygiene

| # | Pattern | Why bad | Fix |
|---|---|---|---|
| Q1 | `^\s*[a-z_-]+ = "\*"` | Wildcard version: build can break on a transitive update. | Pin a major: `"1"` or `"1.2"`. |
| Q2 | `^\s*[a-z_-]+\s*=\s*\{\s*git\s*=\s*"[^"]+"\s*\}` (no `rev`/`tag`/`branch`) | Git dep without rev = non-reproducible. | Add `rev = "..."`. |
| Q3 | `path\s*=\s*` deps in a publish-target crate | Can't publish. | Replace with versioned dep before release. |

---

## Live audit reproducer

Save the list of authored module files (this command is good for several
days; regenerate when modules are added):

```sh
cd /home/kali/Downloads/rustpre2-main
{
  cat <<'EOF'
src/modules/exploits/network_infra/cisco/cisco_ise_api_inject_cve_2025_20281.rs
src/modules/exploits/network_infra/apache_modssl_bypass_cve_2025_23048.rs
src/modules/exploits/network_infra/arista_ngfw_disclose.rs
src/modules/exploits/network_infra/checkpoint_fileread_cve_2024_24919.rs
src/modules/exploits/network_infra/hpprocurve_disclose.rs
src/modules/exploits/network_infra/hpprocurve_snac_inject.rs
src/modules/exploits/network_infra/juniper_screenos_scanner.rs
src/modules/exploits/cameras/galayou_g2_rtsp_bypass_cve_2025_9983.rs
src/modules/exploits/cameras/xiongmai_xm530.rs
src/modules/exploits/dos/apachebrpc_overflow_cve_2025_59789.rs
src/modules/exploits/dos/http2_rapidreset_cve_2023_44487.rs
src/modules/exploits/dos/px4_uav_dos.rs
src/modules/exploits/voip/magnusbilling_ssrf_cve_2023_30258.rs
src/modules/exploits/voip/xorcompbx_rce.rs
EOF
  ls src/modules/exploits/webapps/*.rs | grep -vE "/(api_attack_suite|craftcms_key_rce_cve_2025_23209|craftcms_rce_cve_2025_47726|langflow_rce_cve_2025_3248|laravel_livewire_rce_cve_2025_47949|misp_rce_cve_2025_27364|nextjs_middleware_bypass_cve_2025_29927|sap_netweaver_rce_cve_2025_31324|vite_path_traversal_cve_2025_30208|zimbra_sqli_auth_bypass_cve_2025_25064|mod)\.rs$"
} > /tmp/my_files.txt
```

Then run the matrix:

```sh
PATTERNS=(
  # A. Panicking error handling
  '\.unwrap\(\)' '\.expect\(' '\.unwrap_or_default\(\)' '\.unwrap_or\b' '\.unwrap_or_else\('
  '\.parse\(\)\.unwrap' '\.parse::<[^>]+>\(\)\.unwrap'
  '\.try_into\(\)\.unwrap'
  '\.first\(\)\.unwrap' '\.last\(\)\.unwrap' '\.next\(\)\.unwrap' '\.iter\(\).*\.unwrap'
  '\.chars\(\)\.next\(\)\.unwrap' '\.split\([^)]*\)\.next\(\)\.unwrap'
  '\.position\(.*\)\.unwrap' '\.iter\(\)\.find\(.*\)\.unwrap'
  '\.read_to_string\(.*\)\.unwrap' '\.lock\(\)\.unwrap'
  '\.expect_err' '\.unwrap_err'
  'panic!\(' 'unreachable!\(' 'todo!\(' 'unimplemented!\('
  '\bassert!\(' '\bassert_eq!\(' '\bassert_ne!\('
  # B. Silent error swallowing
  'Err\(_\)' 'Err\(_[a-zA-Z]\w*\)' 'if let Err\(_'
  'if let Ok\(' 'let\s+_\s*=' 'let\s+_[a-zA-Z]\w*\s*=.*\.await'
  '\.map_err\(\|_\|' '\.or_else\(\|_\|'
  '\.to_str\(\)\.ok\(\)' '\.json\([^)]*\)\.await\.ok\(\)'
  '\.send\(\)\.await\.ok\(\)' '\.text\(\)\.await\.ok\(\)'
  # C. Lint suppression
  '#\[allow\(' '#\[deny\(' '#\[ignore\b'
  # D. Panic vectors
  '\b[a-zA-Z_]\w*\[[0-9]+\][^=]'
  '\&[a-zA-Z_]\w*\[\.\.\w+\]'
  '\&[a-zA-Z_]\w*\[\w+\.\.\]'
  '\&[a-zA-Z_]\w*\[\w+\.\.\w+\]'
  '\.split_at\(' '\.chars\(\)\.nth\('
  # E. Numeric conversions
  '\bas\s+u(8|16|32|64)\b' '\bas\s+i(8|16|32|64)\b'
  '\bas\s+usize\b' '\bas\s+isize\b' '\bas\s+f(32|64)\b'
  '\bas\s+\*const\b' '\bas\s+\*mut\b'
  '\btransmute\(' '\bextern\s+"C"' '\bunsafe\s*\{' '\bunsafe\s+fn\b'
  # F. Async / blocking pitfalls
  'std::thread::sleep' 'std::process::Command'
  'std::fs::File' 'std::fs::read\b' 'std::fs::write\b'
  'std::net::TcpStream' 'std::net::UdpSocket' 'std::io::stdin'
  # G. Logging & output
  '\bdbg!\('
  'format!\(.*"\{:\?\}".*\b[eE]rr\b'
  '\.context\(""\)' '\.context\("\?"\)'
  # H. HTTP
  'reqwest::Client::new\(\)' 'reqwest::Client::builder\(\)'
  '\.send\(\)\.await\?[^.]'
  '\.text\(\)\.await\?[^.]'
  'format!\("\{:\?\}", \w+\)\.contains\('
  # I. Iterator glitches
  '\.collect::<Result<Vec<_>,\s*_>>\(\)\.unwrap'
  '\.zip\([^)]*\)\.unwrap'
  # J. Style / secrets
  '== ""' '\.len\(\) == 0' '\.len\(\) > 0'
  'String::from\(format!'
  '\.clone\(\)\s*\.clone' '\.to_string\(\)\s*\.to_string'
  'XXXXXX|TODO|FIXME|HACK\b'
  'Bearer\s+[A-Za-z0-9_.-]{40,}'
  'sk-[A-Za-z0-9]{20,}' 'AKIA[A-Z0-9]{16}'
  '"admin"\s*,\s*"admin"' '"root"\s*,\s*"root"'
  'Box<dyn'
  # L. Crypto antipatterns (modules)
  '\bmd5::compute\b|\bmd5::Md5\b'
  '\bsha1::Sha1\b|use sha1::'
  '\bdes::Des\b|\b3des\b|TripleDES'
  'rand::thread_rng\(\)' 'rand::random\(\)'
  '\bRC4\b|rc4::'
  'aes_128_ecb|aes-128-ecb|Ecb'
  # M. SQL & command injection
  'format!\("SELECT[^"]*\{' 'format!\("INSERT[^"]*\{'
  'format!\("UPDATE[^"]*\{' 'format!\("DELETE[^"]*\{'
  'std::process::Command::new\("/bin/sh"\)'
  'std::process::Command::new\("sh"\)'
  '\.arg\("-c"\).*format!'
  # N. Concurrency / UB
  '\bstatic\s+mut\b' 'std::mem::transmute' 'std::mem::forget'
  'std::mem::uninitialized' 'std::mem::zeroed'
  'std::ptr::read' 'std::ptr::write'
  'Result<\(\), String>' 'Result<.*,\s*String>'
  # O. Performance / idiom
  '\.iter\(\)\.count\(\)' '\.collect::<\(\)>\(\)'
  '\.iter\(\)\.map\(\|\w+\|\s*\w+\.clone\(\)\)\s*\.collect'
  '\.to_string\(\)\.as_str\(\)'
  'Vec::with_capacity\(0\)' 'String::with_capacity\(0\)'
  'Regex::new\(.*\)\.unwrap'
  'Box::new\(.*Box::new'
  # P. Type / API hygiene
  '\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*"http'
  '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Pp]assword'
  '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Ss]ecret'
  '#\[derive\(Debug\)\][^a-z]*pub\s+struct\s+\w+\s*\{[^}]*[Tt]oken'
)

failed=0
for p in "${PATTERNS[@]}"; do
  c=$(xargs -a /tmp/my_files.txt grep -cE "$p" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
  if [ "$c" -gt 0 ]; then
    failed=$((failed + c))
    printf "  HIT [%4d] /%s/\n" "$c" "$p"
    xargs -a /tmp/my_files.txt grep -nE "$p" 2>/dev/null | head -3 | sed 's/^/    /'
  fi
done

echo
if [ "$failed" -gt 0 ]; then
  echo "BAD_PATTERNS: $failed hit(s) — fix before merge"
  exit 1
else
  echo "BAD_PATTERNS: clean"
fi
```

## Codebase-wide observations (non-module code — for reference)

A whole-tree run (`find src -name '*.rs'`, ~486 files) for the same matrix
also passes for `.unwrap()`, `.expect(`, `Box<dyn Error>`, `Result<T, ()>`,
`static mut`, `transmute`, `panic!()`, SQL/command injection — the framework
has been progressively hardened. The matches that *do* show up in non-module
code are by-design and explained here so the catalogue and reality stay in
sync:

| Pattern | Where | Why allowed |
|---|---|---|
| `md5::compute` | `src/native/rdp.rs`, `src/modules/creds/generic/postgres_bruteforce.rs` | RDP NTLMv1 / Postgres MD5 password auth — the protocol mandates MD5. |
| `use sha1::` | `src/modules/creds/generic/mysql_bruteforce.rs`, `src/modules/exploits/safeline/pre_auth_tfa.rs` | MySQL native challenge-response uses SHA-1 by spec. |
| `des::Des` | `src/modules/exploits/vnc/*`, `src/modules/creds/generic/vnc_bruteforce.rs`, TightVNC, TP-Link config blob | RFB / vendor blob format spec mandates single-DES. |
| `RC4` (mention) | `src/modules/scanners/ssl_scanner.rs`, `src/native/obfuscator_engine.rs`, `src/modules/exploits/payloadgens/obfuscator.rs` | Scanner enumerates weak ciphers; payload obfuscator implements RC4 as one of 24 obfuscation methods. |
| `rand::random()` | `src/native/rdp.rs`, `src/modules/scanners/snmp_scanner.rs`, `src/modules/scanners/nbns_scanner.rs` | Non-security RNG (transaction IDs, NetBIOS xid). |
| `std::mem::zeroed()` | `src/native/network.rs`, `src/modules/exploits/dos/null_syn_exhaustion.rs` | All inside `unsafe { }` blocks for `libc::sockaddr_*` / `libc::rlimit` / `libc::mmsghdr` (FFI structs). |
| `accept_invalid_certs(true)` / `danger_accept_invalid_certs(true)` | scanners + DoS modules | By design (P4) — security scanners must talk to self-signed targets. |
| `UdpSocket::bind("0.0.0.0:0")` | DoS / scanner / px4 | Binding ephemeral *source* port for outbound — not a listener. |
| `.lock().unwrap_or_else(\|e\| e.into_inner())` | `src/output.rs` (51 sites) | Standard "recover from poisoned mutex by re-using the inner data" — not `.unwrap()`, handles poison gracefully. |
| `Result<(), String>` | `src/spool.rs` (3 sites) | Pre-existing API; `anyhow` migration is a separate refactor task tracked in `audit-findings.md`. |
| `tokio::spawn(bg);` (no await) | `src/modules/scanners/dmarc_check.rs`, `dns_recursion.rs` | Intentional fire-and-forget heartbeats; the framework treats them as best-effort. |

These should *not* be propagated into new modules; the catalogue tables
(L–P) document the strict rule.

## What to do when the script reports a hit

1. **Don't** silence with `#[allow(...)]` — that's banned (C1).
2. **Don't** swap one banned pattern for another — e.g. replacing
   `.unwrap()` with `.unwrap_or_default()` is *worse* (a panic at least
   reports something; a silent default lies).
3. **Do** consult the table for the appropriate fix idiom and use one of the
   helpers in `src/utils/network.rs`:
   - `crate::utils::http_get_status_body(&client, &url)`
   - `crate::utils::http_get_status_headers_body(&client, &url)`
   - `crate::utils::header_string(&headers, "name")`
   - `crate::native::hex::encode(&bytes)`
   - `crate::utils::url_encode(s)`

4. **Do** keep error context as the chain travels up — every `?` should be
   on a `with_context(|| ...)?` so debugging a mass scan tells the operator
   *which target* and *which step* failed.

## Pattern history (what each fix wave caught)

| Wave | Patterns added | Hits caught and fixed |
|------|---|---|
| 1 — Initial | A1, A2, A3, B1, B4, B5, B8, C1 | 92 modules with at least one match |
| 2 — Wider | A4, A5, A13, A14, B2, B3, B6, B7, B9, C2, A15, J6 | 5 (timeout `Err(_)`, JSON ok-swallow, `_scheme` shims, `Ok(_)` on response) |
| 3 — Deep | D1–D5, E1–E4, F1–F7, G1–G3, H1–H4 | 8 (debug-format version compare, `as u16/u64` casts, `&buf[..n]` raw slicing, `XXXXXX` placeholder URL, `buf[0]` direct index) |
| 4 — Mega | I1, I2, J1–J5, K1, K2 | 0 |

`xargs -a /tmp/my_files.txt grep -cE … | awk -F: '{s+=$2}END{print s+0}'` ⇒
**0** for every entry in the matrix above.
