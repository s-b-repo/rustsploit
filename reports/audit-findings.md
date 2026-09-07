# RustSploit Audit — OOM, Error Handling, and Coding Flaws

Scope: every Rust file under `src/` (374 files, ~111 K LOC). Findings consolidated from four parallel module-area audits, then spot-verified against source. Items marked **(verified)** were re-read in source to confirm line numbers and severity. Items the agents reported but that the source contradicts are listed in the *Corrections* section at the end.

Severity legend: **CRIT** → exploitable by remote/untrusted input; **HIGH** → likely DoS or resource exhaustion in normal use; **MED** → real flaw, narrow trigger; **LOW** → robustness/robustness or defense-in-depth.

---

## Cross-cutting / systemic patterns

These show up in many files; fixing the pattern once typically fixes ten findings.

| # | Pattern | Where | Severity | Recommended fix |
|---|---------|-------|----------|-----------------|
| S1 | `read_to_end` / `read_to_string` / `.text().await` / `.bytes().await` against attacker-controlled servers (~36 exploit modules + several scanners + `cert_transparency.rs:68`) | exploits/, scanners/, osint/ | HIGH (aggregate) | Wrap with `AsyncRead::take(MAX)` or check `Content-Length` first. Standardize a `safe_read_to_end(reader, MAX)` helper and migrate. |
| S2 | `tokio::spawn` in a per-target/per-combo loop with the semaphore acquired *inside* the spawn — gates concurrency but not spawn rate, so all N tasks materialize at once | `utils/bruteforce.rs:845`, `creds/utils.rs:447+`, scan modules | HIGH | Acquire the semaphore permit *before* `spawn`, or feed work through a bounded `mpsc` to a fixed pool. |
| S3 | `FuturesUnordered::new()` fed without a cap | `scanners/ipmi_enum_exploit.rs:224`, `utils/bruteforce.rs:845` | MED | Drain in batches (`while futs.len() >= K { futs.next().await; }`) or use `JoinSet` with a permit gate. |
| S4 | `.danger_accept_invalid_certs(true)` blanket on HTTP clients | `scanners/dir_brute.rs:325`, `http_title_scanner.rs:89`, `http_method_scanner.rs:112`, `creds/generic/http_basic_bruteforce.rs:168`, ~19 exploit modules | MED | Acceptable for a pentest tool *if* user-opt-in; today it's the default. Add a `--insecure` flag, default to verify, log when bypassed. |
| S5 | Resolve-once DNS (`to_socket_addrs()` at start of run) then reuse for all subsequent connections — DNS rebinding window | `exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass.rs:114`, others | MED | Resolve once, pin the IP, and connect by **IP** + send hostname in TLS SNI / HTTP Host. Don't re-resolve mid-flight. |
| S6 | `let _ = ...` discarding fallible I/O across ~109 sites | exploits/, creds/ | LOW | Mostly contextual (ignored timeouts on banner reads). Audit the ~20 in critical paths and either `?` or comment why ignored. |
| S7 | Mutex-poison handling: `lock().unwrap_or_else(|e| e.into_inner())` silently continues with poisoned state | `output.rs:46,54`, `cred_store.rs`, several `loot.rs` paths | MED | Decide policy: either propagate as error or panic on poison. Silent recovery hides the original panic indefinitely. |

---

## CRITICAL — none confirmed

No CRIT-severity findings (no remote-trigger arbitrary code execution, no auth bypass in the framework itself, no plaintext secret transmission to an attacker).

---

## HIGH

### H1 — Unbounded HTTP body read in cert.sh OSINT *(verified)*

**`src/modules/osint/cert_transparency.rs:68-70`**
```rust
let body = resp.text().await.context(...)?;
let entries: Vec<CrtEntry> = serde_json::from_str(&body).context(...)?;
```
crt.sh routinely returns 5–50 MB JSON for popular domains; queries with wildcard `%25.<tld>` can return hundreds of MB. The full body is copied into `String`, then parsed into `Vec<CrtEntry>`, doubling memory at peak.
- **Fix**: cap response with `resp.bytes_stream()` + size accumulator (e.g. 50 MB), or stream-parse with `serde_json::Deserializer::from_reader`.

### H2 — `Vec::with_capacity` from untrusted MySQL wire length *(verified)*

**`src/modules/exploits/dionaea/mysql_sqli.rs:64-65`**
```rust
let pkt_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], 0]) as usize;
let mut body = vec![0u8; pkt_len];
```
Wire format makes this effectively u24, so the cap is 16 MiB per packet — not catastrophic but uncapped per call, and `recv_all_until_eof` calls it up to 50 times. Worst case per scan: ~800 MB. A malicious responder controls the value entirely.
- **Fix**: clamp `pkt_len` to a sane MySQL packet size (1 MiB is more than enough for handshake/error packets here).

### H3 — Per-combo `tokio::spawn` storm in bruteforce *(verified)*

**`src/utils/bruteforce.rs:845-870`**

`FuturesUnordered` is fed `tokio::spawn(async move { let _permit = sem.acquire_owned().await; ... })` — one spawn per `(user, pass)` combo. With a 10 K × 10 K wordlist (100 M combos), the spawn loop materializes 100 M task structs before the semaphore even activates; each task is ~hundreds of bytes plus its captured `Arc`s. Many GB of allocator pressure.
- **Fix**: acquire the permit *before* `spawn`:
  ```rust
  let permit = sem_c.clone().acquire_owned().await?;
  tasks.push(tokio::spawn(async move { let _permit = permit; ... }));
  ```
  …or feed combos through a bounded `mpsc::channel(N)` to a fixed worker pool.

### H4 — Mass-scan unbounded spawn

**`src/modules/creds/utils.rs:447-540`** — same pattern as H3 in `run_mass_scan`. For a `/16` CIDR (65 K hosts) every host gets a `tokio::spawn` immediately; the semaphore only throttles execution, not allocation.
- **Fix**: same — gate spawn rate, not just running tasks.

### H5 — WebSocket frame buffered before size check *(verified)*

**`src/ws.rs:260-270`**
```rust
let frame_bytes = match msg {
    Message::Binary(b) => b.to_vec(),       // <-- already in RAM
    ...
};
if frame_bytes.len() > MAX_WS_FRAME_SIZE { ... }
```
By the time we check, tungstenite has already buffered the frame. If tungstenite isn't configured with `max_message_size` / `max_frame_size`, an attacker can force arbitrarily large allocations.
- **Fix**: configure the underlying tungstenite client with `WebSocketConfig { max_message_size: Some(MAX), max_frame_size: Some(MAX), ... }` so the lib enforces the limit on the wire.

---

## MED

### M1 — `cred_store.rs` plaintext on disk

`src/cred_store.rs` stores discovered credentials JSON-on-disk with `chmod 0o600`. File mode is fine; plaintext is the issue if the workspace dir is ever copied/synced. Document explicitly, or offer a passphrase-encrypted-at-rest mode.

### M2 — Loot directory TOCTOU on parent symlink

**`src/loot.rs:107-129`** — `file_path = self.loot_dir.join(filename)` then `starts_with(&self.loot_dir)`. The filename is sanitized (alphanumeric + underscore only), so traversal isn't realistic. The genuine issue: `self.loot_dir` itself can be a symlink replaced between calls. Also `clear()` (line 213) deletes files individually with no rollback — partial clear leaves the index out of sync.
- **Fix**: `canonicalize` the loot dir once at startup; hold an open dir-fd and use `openat` for writes. Make `clear` two-phase (delete-all-files; rewrite-index) or write the new index first.

### M3 — Workspace mutex-poison policy

**`src/output.rs:46,54`**, **`src/config.rs:63,84,122`**, **`src/cred_store.rs`** — `lock().unwrap_or_else(|e| e.into_inner())` recovers silently. Original panic context is lost; subsequent reads see whatever half-mutated state caused the poison. Pick a policy: surface as `Err` or fail-fast.

### M4 — DNS resolution returns unbounded `Vec`

**`src/utils/target.rs:331-341`** (`resolve_domain_all`), **`src/utils/network.rs:95-97`** (`to_socket_addrs().collect()`). DNS can return hundreds of A/AAAA records (round-robin, glue, attacker-controlled). No cap.
- **Fix**: `take(16)` after collect, or refuse to scan if N > some reasonable bound.

### M5 — TLS handshake without timeout

**`src/native/async_tls.rs:81-86`** — `connector.connect(...).await` has no `tokio::time::timeout` wrapper. A slow/malicious peer hangs the task forever. Most callers wrap their own outer timeout, but not all.
- **Fix**: add an inner `timeout(Duration::from_secs(15), ...)` here; defense-in-depth.

### M6 — `port_scanner.rs:55` allocates 65 535-element Vec eagerly

`PortRange::All => (1..=65535).collect()` — only ~130 KB so not OOM, but combined with multi-target scans this is 130 KB × N hosts held simultaneously. Use a lazy iterator.

### M7 — `mongobleed.rs` 50 K probe loop with no per-target rate limit

**`src/modules/exploits/frameworks/mongo/mongobleed.rs:277-298`** — sweeps offsets 0..50000 without any pacing. Easy to trip rate limiters / IDS, and accumulates `all_leaked` (line 291) without size cap. Add a global `total_leaked.len() > 100 MB` short-circuit.

### M8 — `dos/http_flood.rs:255-325` spawn count = user input

`config.concurrency` from CLI; no clamp, no `JoinSet`. User can request 1 M workers; each `tokio::spawn` is bytes but the open-sockets/file-descriptor cap on the host is the actual ceiling — fail mode is cryptic.
- **Fix**: clamp `concurrency` to `min(user, 4096)` and use `JoinSet`.

### M9 — IPMI enum unbounded `FuturesUnordered`

**`src/modules/scanners/ipmi_enum_exploit.rs:224`** — `FuturesUnordered` fed without drain. Same pattern as H3 but smaller blast radius.

### M10 — VNC `libvnc_checkrect_overflow.rs:84` integer multiply on attacker u16s

`(w as usize) * (h as usize) * BPP` — `w`,`h` from wire. On 64-bit platforms `usize` is 64-bit so no UB, but result drives an allocation. Use `checked_mul`.

### M11 — `tightvnc_ft_path_traversal.rs:160-174` chunk accumulation without per-iteration cap

Vec grows in a loop, only checked at end. If the server streams forever, you OOM before the cap fires. Check inside the loop.

### M12 — `dlink_dcs_930l_auth_bypass.rs:52` `.bytes().await` no Content-Length check

Same family as S1. Dangerous because the attacker is the router responding to your probe.

### M13 — Job lifecycle: orphaned spawns on WS disconnect

**`src/ws.rs:312-349`** — subscription/cleanup tasks `tokio::spawn`'d without tracking; on connection drop they're never aborted. Survives until they hit their own timeout. Track handles per connection and abort in the drop path.

### M14 — `rpc_add_loot` body cap is implicit (axum default 2 MiB)

**`src/api.rs:518-521`** — relies on Axum's `DefaultBodyLimit` (2 MiB). Reasonable, but not explicit; if anyone adds `.layer(DefaultBodyLimit::disable())` upstream, the cap silently disappears. Add an explicit `.layer(DefaultBodyLimit::max(2 * 1024 * 1024))` in the router builder.

### M15 — `cred_store.rs:70-73` corrupted file = empty-vec silent fallback

Read failure returns `Vec::new()` rather than `Err`. Caller cannot distinguish "no creds yet" from "creds file got truncated and we just lost everything". Surface the error; let UI decide whether to fall back.

### M16 — `output.rs:30` per-task buffer × concurrent jobs

`MAX_BUFFER_LINES = 100_000` is per-task; with the framework happily running dozens of jobs, total RAM scales with job count. Add a global ring-buffer cap and trim oldest.

### M17 — `subdomain_scanner.rs:122-268` and `creds/utils.rs:447+` semaphore gates execution but not spawn

Same pattern as H3/H4; lower severity because typical wordlists / subnets don't blow up the way bruteforce inputs do.

---

## LOW

- **`config.rs:74`** `.canonicalize()` on user path — TOCTOU between resolve and use. Resolve once at startup.
- **`spool.rs:45-58, 123-130`** symlink-parent guard incomplete; bind via dir-fd + `openat`.
- **`global_options.rs:95-103`** spin-loop with 1 ms `thread::sleep` from inside async. Refactor to async `try_read`.
- **`api.rs:287-288`** `s.parse::<u64>()` then cast to `u32` without bounds check. Use `u32::try_from`.
- **`ws.rs:1113`** `kill_job` casts `as u32`; everywhere else uses `try_from`. Be consistent.
- **`context.rs:29-35`** `cache_insert` racy check-then-insert; do both inside the lock.
- **`utils/prompt.rs:45-53`** `prompt_required` loops on empty answer with no max-retry cap.
- **`utils/target.rs:39-51`** comma-separated target list has no cap; 1 M comma-separated entries → 1 M-element Vec.
- **`utils/bruteforce.rs:300`** `tokio::fs::read_to_string` on user-supplied state file with no size cap.
- **`scanners/snmp_scanner.rs:277`** custom wordlist `read_to_string` no size cap. Use `utils::wordlist::stream_lines` instead.
- **`creds/generic/ssh_user_enum.rs:89-125`** timing-based username enum — *intentional*, this is the attack. Keep but document.
- **`exploits/frameworks/exim/exim_etrn_sqli_cve_2025_26794.rs:80`** hardcoded 0.3 s threshold for time-based SQLi; no baseline variance. Multi-sample mean / stddev would be more robust on noisy networks.
- **`exploits/vnc/tightvnc_decompression_bomb.rs:72`** `.unwrap_or(0x7FFF_FFFF)` on parse — bail with an error instead.
- **`exploits/frameworks/apache_camel/.../cve_2025_27636_camel_header_injection.rs:148,190`** `.text().await.unwrap_or_default()` masks errors as empty string.
- **`exploits/routers/tplink/tplink_ax1800_rce_cve_2024_53375.rs:73,115`** same pattern.
- **`output.rs`** poison "recovery" hides the upstream panic indefinitely (see M3).
- **`exploits/dionaea/mssql_dos.rs:64`** `u16::from_be_bytes(...) as usize` — 64 KiB cap is implicit but worth being explicit.

---

## What's actually solid

To balance the negative findings — these patterns are well done and worth preserving:

- **`utils/wordlist.rs`** has `MAX_BYTES = 256 MiB` cap, streaming reader, content-length check before download. Migrate other wordlist consumers to use this.
- **`utils/sanitize.rs`** has a strict `MAX_COMMAND_LENGTH`, null-byte rejection, conservative shell escape. Solid.
- **`utils/privilege.rs`** is a thin read-only wrapper around `geteuid` — no TOCTOU surface.
- **VNC modules** have a `MAX_FT_MSG = 16 MiB` and `MAX_DOWNLOAD = 64 MiB` cap, and `tightvnc_decompression_bomb` is *deliberately* the bomb under test.
- **`telnet_bruteforce.rs`** has a `MAX_DRAIN_BYTES = 64 KiB` and `RECENT_BUF_CAP = 2048` ring buffer — exactly the pattern other read loops should adopt.
- **Bounded channels** (`mpsc::channel(1024)`) are used in most multi-target scan dispatchers.
- **Most `unwrap`/`expect` calls** are in build/test paths; the production network paths overwhelmingly use `?` with `anyhow::Context`.

---

## Corrections to the parallel-agent reports

Spot-checking surfaced a few inflated claims:

1. **`loot.rs:110` "symlink traversal" — overstated.** Filename is sanitized to alphanumeric + underscore. Real risk is TOCTOU on a replaced parent directory (now M2).
2. **`utils/bruteforce.rs:677/687/697` `Vec::with_capacity` "HIGH" — wrong target.** The `with_capacity` is *clamped* to 10 M (line 673). The real bug is the spawn-storm two functions later (now H3).
3. **`api.rs:1009` "100 MB user upload" — wrong size.** Axum's default body limit is 2 MiB; 100 MB is not configured anywhere. Concern downgraded to "implicit limit" (now M14).
4. **`native/rdp.rs:132` "integer overflow on shift" — false positive.** `frame_len` is a 16-bit field shifted into `usize`; max 65 535, then bounds-checked against `buf.len()` on the next line. Not a flaw.
5. **`native/rdp.rs:366-369` "unchecked offset addition" — would need source verification before treating as HIGH.** Listed but not promoted into the table above.

---

## Recommended priority

1. **Fix H3/H4 spawn-storm** (one-line refactor in `utils/bruteforce.rs` and `creds/utils.rs`, biggest user-facing impact).
2. **Standardize a `safe_read_to_end(reader, MAX)` helper** and migrate the ~36 exploit-module callers + `cert_transparency.rs` (S1, H1).
3. **Configure tungstenite max_message_size in ws.rs** (H5).
4. **Cap MySQL `pkt_len`** at 1 MiB (H2) and audit other binary-protocol modules for the same idiom.
5. **Pick a mutex-poison policy** project-wide (M3 / S7).
6. **`--insecure`-flag the TLS-bypass clients** (S4) — currently silent default.

Numbers in this report are line-accurate as of audit date. Any large refactor will move them; treat the *patterns* (S1–S7) as the load-bearing findings, not the specific line numbers.

---

## Round 2 follow-up — surfaced after re-verification

### F1 — WebSocket sub-session has no DH rekey *(partially addressed)*

**`src/pq_channel.rs`** WsSubSession + derive_ws_subsession + encrypt/decrypt_ws_frame.

**Original observation**: `WsSubSession` had no `rekey_after`, `encrypt_ws_frame` never called `dh_ratchet_send`, and the `epoch > u32::MAX` guard was effectively dead code because nothing advanced epoch. By contrast, the HTTP session forces a DH ratchet every `DEFAULT_REKEY_AFTER = 100` messages.

**Status update**: Two of the three originally-proposed mitigations have landed:

- **Per-connection HKDF binding** — `derive_ws_subsession(session, role, connection_nonce)` now mixes a 16-byte `connection_nonce` into HKDF-info, so two concurrent WS opens from the same parent session derive *distinct* chain keys. The server picks the nonce at upgrade time and sends it in the clear as the first 16 bytes of the WS stream so the client can derive matching chains.
- **Role-distinct chain labels** — `WsRole::Server` uses `(send=ws-s2c, recv=ws-c2s)` while `WsRole::Client` uses `(send=ws-c2s, recv=ws-s2c)`. Without this, both ends would derive identical chains and the first frame each side sent would reuse `(key, nonce)` because `epoch || send_counter` both start at zero.
- **Doc comments** — `WsSubSession` and `derive_ws_subsession` both carry rustdoc explaining the forward-secrecy property, the residual concern, and the dead-code epoch guard.

**Residual concern (not yet addressed)**: a single long-lived WS connection still has weaker post-compromise security than the HTTP path. If a chain key leaks mid-connection, every subsequent frame on *that* connection remains decryptable until tear-down. The HTTP DH ratchet on the parent `PqSession` does not propagate into existing WS sub-sessions.

Severity: LOW (defense-in-depth gap, not an active flaw).

**Remaining mitigation options**, if the threat model demands it:

1. **Tear-down hint** — at e.g. 10 000 frames sent or received, return a `WsRekeyRequired` error from `encrypt_ws_frame`/`decrypt_ws_frame` so callers must re-derive the sub-session from the (possibly DH-ratcheted) parent. The existing dead `epoch > u32::MAX` check could be repurposed as a softer threshold.
2. **Re-derive on parent rotation** — wire `dh_ratchet_send`/`dh_ratchet_receive` so that any HTTP-side rekey also bumps the WS `epoch` and forces the WS reader/writer tasks to re-derive. Most invasive.

### F2 — Defensive observation: WS sub-session counter is u64 with no per-message ceiling

Same code: `WsSubSession.send_counter` (line 641) is u64 incremented per frame. At realistic frame rates this never wraps, but combined with F1 (no rekey) the counter is the *only* uniqueness anchor for nonces (`nonce_bytes[4..]` at line 674). If F1 is addressed via option 2 or 3 above, the rekey threshold also caps the counter as a side effect — F2 then becomes moot.

Severity: LOW (theoretical only).

### Re-verification corrections to round 1's "Corrections" section

Two `[FP]` entries from round 2's planning were added during Phase 1 of that round and are **already** documented in `/home/cortix/.claude/plans/ok-audit-all-framework-lucky-kettle.md`:

- `pq_channel.rs:674` "nonce off-by-one" — false positive; nonce uses pre-increment counter, matching `ratchet_step`'s input.
- `pq_channel.rs:568-615` "AAD epoch asymmetry" — false positive; both encrypt and decrypt apply the ratchet *before* invoking the AAD builder.

No further action on those.
