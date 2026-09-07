# RustSploit backend bug audit (2026-04-28)

Companion to `arcticalopex_audit.md` (panel audit). Bug-focused review of the
Rust backend at `/home/kali/Downloads/rustpre2-main/`. ~119k LOC across 50
core files + 325 module files. Methodology: 4 parallel investigation passes
covering the PQ/transport stack, API/dispatch/jobs, persistence/filesystem,
and a representative module sample. Findings deduplicated and spot-verified
against the live tree before writing.

**Spot-check posture.** Sub-agent reports occasionally overstate severity
(e.g. one flagged a "stack overflow" in `src/native/rdp.rs:132` that's
actually safe — the buffer is heap-allocated and the bounds check is
correct). Findings below are filtered to claims I verified on disk; treat
file:line references as starting points and re-verify before fixing.

---

## Summary

| Severity | Count | Theme |
|---|---|---|
| **P0** | 4 | Process-global state shared across PQ tenants; default-disabled TLS verification in many web exploit modules; sender-side identity proof is dead code; salt protection collapses if the on-disk host identity is read |
| **P1** | 14 | Snapshot-then-save race in cred/loot/options stores; predictable job IDs + missing job-ownership checks let one tenant hijack another's jobs; CIDR expansion uncapped; DoS modules don't honor SSRF guard; symlink/TOCTOU windows on multiple file writers; identity proof never validated; rate limiter bypassable behind proxy; module DESTROY mode lacks confirmation; many input-validation gaps at the RPC boundary |
| **P2** | 38 | WS frame size / decryption DoS; chain-key info lacks epoch; per-session lock held during crypto; HKDF salt-chain-info inconsistencies; spool/output truncation silent after first warn; enrollment token printed plaintext to stdout; presigned-URL-like windows in workspace I/O; TLS verification disabled in module-level HTTP clients; service-mapping and rank inflation issues; honeypot module dry-run prompts ignored |
| **P3** | 22 | Documentation drift; rank consistency; minor parsing assumptions; misleading code comments |

**Top blockers** (verified against the tree):

1. **Multi-tenancy is structurally absent.** `WORKSPACE`, `CRED_STORE`,
   `LOOT_STORE`, `GLOBAL_OPTIONS`, and the job manager are all process-wide
   `Lazy<...>` singletons (`workspace.rs:392`, `cred_store.rs:259`,
   `loot.rs:324`, `global_options.rs:182`). The PQ middleware identifies
   tenants by `client_name` but no RPC arm filters by it. Tenant A sees /
   modifies tenant B's credentials, hosts, loot, jobs, and global options.
2. **`accept_invalid_certs: true` is the default in dozens of web-exploit
   modules** (`smartermail/admin_password_reset_cve_2026_23760.rs:297`,
   `voip/cve_2025_64328_freepbx_cmdi.rs:52`, plus ~10 others). MITM
   protection against HTTPS targets is off by default. Designed for lab
   testing but not gated behind an explicit insecure flag.
3. **Snapshot-then-save race** in `cred_store.rs:124-129` (and the same
   pattern in `global_options.rs`, `loot.rs`, `workspace.rs`). The clone
   is taken inside the write lock, but `save_locked` runs after the lock
   is released — two concurrent writers can land their disk writes in the
   wrong order so the persisted file disagrees with the in-memory state.
4. **Sequential job IDs + no per-tenant job filter** lets a user subscribe
   to or kill another tenant's jobs by guessing IDs (`jobs.rs:124-129`,
   `ws.rs:339-372`).
5. **CIDR expansion has no upper bound** (`commands/mod.rs:515-520`):
   `target=0.0.0.0/1` spawns ~2B tokio tasks before the per-IP SSRF check
   ever fires.

---

## P0 — Critical

### P0-1 — Global state shared across PQ tenants (no isolation) ❗

`workspace.rs:392`, `cred_store.rs:259`, `loot.rs:324`, `global_options.rs:182`,
`jobs.rs::JOB_MANAGER`. All are `Lazy<...>` singletons. The PQ middleware
authenticates `client_name` per session (`pq_middleware.rs:85`), but every
RPC arm in `ws.rs::dispatch_rpc` operates on the singletons unconditionally:

- `rpc_list_creds` → `CRED_STORE.list().await`
- `rpc_list_hosts` → `WORKSPACE.hosts()`
- `rpc_list_jobs` → `JOB_MANAGER.list()`
- `rpc_set_target`, `rpc_set_option`, `rpc_switch_workspace` → `GLOBAL_*`

**Effect.** Any authenticated PQ client sees every other tenant's
credentials, loot, hosts, services, target, jobs, and can mutate global
options that affect all tenants' subsequent module runs.

**Fix.** Partition each store by tenant ID. Extract `client_name` from the
PQ session at every RPC entry point and pass it to `*_store` methods as a
filter. The middleware already injects identity into the request extension
on the HTTP path (`pq_middleware.rs:382`); plumb the same into the WS
handlers, then filter at every read/write.

### P0-2 — `accept_invalid_certs: true` is the default in many HTTP-based exploit modules ❗

Verified callsites (sample, not exhaustive):
- `webapps/smartermail/admin_password_reset_cve_2026_23760.rs:297`
- `webapps/sharepoint/cve_2024_38094.rs:182`
- `webapps/langflow_rce_cve_2025_3248.rs:51`
- `webapps/nextjs_middleware_bypass_cve_2025_29927.rs` (HttpClientOpts)
- `voip/cve_2025_64328_freepbx_cmdi.rs:52`
- And ~10 others

Pattern: `HttpClientOpts { accept_invalid_certs: true, follow_redirects: true, .. }`

**Effect.** Module fires its exploit/credential probe over HTTPS with no
certificate verification. A network-positioned attacker can MITM, capture
the credential or payload, and silently substitute a different response.

**Fix.** Default `accept_invalid_certs: false`. Add a global CLI flag
(`--insecure-tls`) gated behind a confirmation that prints a clear warning.
Per-module: optional `verify_ssl` prompt that defaults to `yes`. Audit all
~13 callsites to see which actually need cert tolerance for lab targets.

### P0-3 — Identity proof field is dead code; mutual auth depends entirely on the DH

`pq_channel.rs:395` (`HandshakeRequest.identity_proof`) is deserialized but
never read by `process_handshake` (`pq_channel.rs:412-560`). The server
*generates* its own proof at line 562 and sends it in the response, but
the client's proof is ignored. Authentication relies on:

1. The client X25519 pub matching `pq_authorized_keys` (constant-time, line 437).
2. The identity DH succeeding (which is implicitly proven by the AEAD tag
   on the first encrypted request — wrong key → tag fails).

This is *almost* fine — the DH is a real proof of possession — but the
field's presence on the wire suggests it's an active check, which is
misleading and creates a refactor trap (a future contributor could remove
the AEAD-check assumption and break authentication).

**Effect.** Today: no exploitability — the AEAD-bound DH still binds
identity. Tomorrow: a refactor that "tightens" auth by relying on
`identity_proof` would silently weaken it because no one verifies the
field.

**Fix.** Either delete the field from both schemas (TS + Rust) and tighten
to a single proof model, or actually validate it: receive
`request.identity_proof`, recompute against `(ss_id, server_eph_pub,
client_eph_pub)`, and reject mismatches with constant-time compare.

### P0-4 — Host identity stored as plaintext JSON on disk

`pq_channel.rs:126-152` `HostIdentity::save()` writes the X25519 secret as
base64 JSON to `~/.rustsploit/pq_host_key`. No encryption, no master-key
derivation, no permission enforcement that I could verify (the file mode
isn't set explicitly in `save`).

**Effect.** Anyone with read access to the user's home dir gets the
server's long-term identity. With this key plus the public-on-the-wire
client identity pubs, an attacker can recompute `derive_salt(...)` and
forge salt-bound traffic. The PQ ratchet still protects in-flight
sessions, but a stolen host key fully compromises future server identity
and lets the attacker impersonate the server to any client.

**Fix.** At minimum: write with mode `0o600` and verify on load. Better:
encrypt the secret with a passphrase / master-key derivation
(`MASTER_KEY` style, like the panel uses for tenant identity). Best: TPM
or HSM binding when available.

---

## P1 — High

### P1-1 — Snapshot-then-save race in `cred_store`, `loot_store`, `global_options`, `workspace`

Verified at `cred_store.rs:124-129` (pattern repeats in
`global_options.rs:61-69`, `loot.rs`, `workspace.rs`):

```rust
let snapshot = {
    let mut entries = self.entries.write().await;
    entries.push(entry);
    entries.clone()        // snapshot inside lock
};                          // <-- lock released here
self.save_locked(&snapshot).await;  // disk write outside lock
```

Two concurrent writers can take their snapshots correctly, but the
save-to-disk order is not the same as the lock-release order. T1 saves
`[A]`, T2 saves `[A, B]`, but if T1's save lands *after* T2's, the disk
ends up with `[A]` and the in-memory state has `[A, B]`. Subsequent
restart loads `[A]`; B is gone.

**Fix.** Either hold the lock across the save, or version each save with
the in-memory generation counter and only commit if the on-disk gen is
older. The lock-during-save approach is simpler; saves are fast (small
JSON), so the contention cost is bounded.

### P1-2 — Sequential job IDs + missing per-tenant job-ownership checks

`jobs.rs:124-129` starts job IDs at a random `1..(1<<24)` seed, then
increments by 1. `ws.rs:339-372` (`subscribe:output`) accepts any
`jobId` integer the client sends and looks it up globally without
checking which tenant owns it.

**Effect.** Tenant A enumerates a few of their own jobs, sees the IDs are
sequential, and increments to discover/subscribe to/kill tenant B's
jobs. Combined with P0-1, this is straightforward.

**Fix.** Generate UUIDs (or 8+ bytes random) per job. Track owner tenant
on each job. Filter `list_jobs`, `get_job_detail`, `kill_job`, and
`subscribe:output` by `caller.client_name == job.owner`.

### P1-3 — CIDR expansion has no upper bound

`commands/mod.rs:515-520`. The code computes `host_count` for the subnet,
warns if it's large, then iterates every IP at line 551
(`for ip in network.iter()`) spawning a tokio task per IP. A user
specifying `0.0.0.0/0` triggers ~4.3 billion task spawns before the
per-IP SSRF check ever fires.

**Effect.** Memory exhaustion in seconds. Process-wide DoS.

**Fix.** Hard cap (`if host_count > 10_000_000 { bail!(...) }`) before
the iteration begins. Pre-validate the network address against
`is_blocked_target` so a `/8` private subnet rejects upfront.

### P1-4 — DoS modules don't call `is_blocked_target`

`exploits/dos/slowloris.rs:115-120` (and `http_flood.rs`,
`connection_exhaustion_flood.rs`, etc.) accept the user-provided target
verbatim and start the attack. Unlike the other module categories, no
`is_blocked_target` gate.

**Effect.** Operator can be socially engineered into pointing the flood
at `127.0.0.1`, internal RFC1918 ranges, or cloud metadata. The framework
itself becomes the attacker; the attack appears to come from the
operator's IP.

**Fix.** Run `is_blocked_target(&target)?` in every DoS module's `run()`,
matching the gate already used by exploit modules. Combine with a
prominent confirmation banner on first use.

### P1-5 — `accept_invalid_certs: true` modules also enable `follow_redirects: true` without re-validating the redirect target

Same callsites as P0-2. The `reqwest::Client` is built with
`follow_redirects: true`. After a redirect, the new URL is not re-checked
against `is_blocked_target` — the redirect can land at `127.0.0.1:6379`
or `169.254.169.254` and the module proceeds.

**Effect.** Second-order SSRF: operator targets a "real" host, but a
malicious redirect lands inside the operator's network or hits cloud
metadata.

**Fix.** Either set `redirect: Policy::none()` and handle redirects
manually with an explicit `is_blocked_target` re-check, or set the
client's redirect policy to a custom one that re-validates each hop.

### P1-6 — DESTROY scan mode in `dir_brute` lacks a confirmation prompt

`scanners/dir_brute.rs:43`. Modes are `1=GET, 2=NUKE (Safe), 3=DESTROY (Delete)`.
A numeric prompt `mode=3` immediately starts deleting files via DELETE
requests with no second confirmation.

**Effect.** Typo turns reconnaissance into destruction.

**Fix.** When `scan_mode == 3`, run a second `cfg_prompt_required("confirm",
"Type 'DELETE' to confirm destructive scan")` and reject anything other
than the literal string `DELETE`.

### P1-7 — Symlink TOCTOU on workspace + spool + loot writers

Multiple file-writing paths check for symlinks at validation time but
don't bind that check to the actual write:

- `workspace.rs:153` — file is `tokio::fs::write()`'d, then chmodded; the
  window between create and chmod leaves the file world-readable.
- `spool.rs:120-143` — parent symlink check happens once at start; a
  late-bound parent-symlink swap redirects later writes.
- `loot.rs:109-118` — `starts_with(loot_dir)` check is followed by
  `OpenOptions::open()` without `O_NOFOLLOW`.

**Effect.** Local attacker with write access to the parent directory can
race a symlink into place between check and write to redirect output.

**Fix.** Use `OpenOptions::custom_flags(libc::O_NOFOLLOW)` everywhere a
secrets-bearing or attacker-influenced file gets opened. For mode
enforcement: use `OpenOptions::mode(0o600)` *atomically with create*, never
truncate-then-chmod.

### P1-8 — `is_blocked_target_resolved` does no DNS pinning

`api.rs:208-249`. Each RPC call re-resolves the hostname; no caching with
TTL bound. An attacker controls a DNS authority (`A` records flipping at
1-second TTL): first lookup returns 8.8.8.8 (allowed), the validation
passes, the actual fetch happens 50ms later and now resolves to 127.0.0.1.

**Fix.** Resolve once at validation time; pass the *resolved IP* (not the
hostname) to whatever does the network operation. Or maintain a tiny
TTL-bounded resolver cache (60s) and trust only the cached value.

### P1-9 — Handshake rate limiter uses raw `ConnectInfo(addr).ip()`

`pq_middleware.rs:71-82`. The IP is taken from the TCP socket's peer
address. If the server is fronted by any L4/L7 proxy or load balancer,
all requests appear to come from one IP and the per-IP rate limit becomes
effectively a global one.

**Fix.** Optionally trust an `X-Forwarded-For` header when the deployment
operator says so. Add a `--trust-proxy` CLI flag; without it, behavior is
unchanged. With it, parse XFF and use the leftmost (or rightmost-trusted)
IP.

### P1-10 — Source-IP spoofing in `null_syn_exhaustion` lacks legal/ethical prompt

`exploits/dos/null_syn_exhaustion.rs:46-47`. The module accepts
`use_random_source_ip: bool` and `local_ip_override: Option<Ipv4Addr>`
with no warning that spoofing is illegal in most jurisdictions and may
implicate uninvolved third parties.

**Fix.** Add a `confirm_legal_spoofing` prompt that requires typing a
specific phrase before any spoofed packet is sent. Print a banner
explaining the legal stakes.

### P1-11 — `MAX_PQ_SESSIONS` eviction can race with in-flight requests

`pq_middleware.rs:108-137`. When the cap is hit, the oldest-by-activity
session is evicted from the map. But a request currently mid-flight on
that session holds an `Arc<Mutex<PqSession>>` outside the map, so the
session continues to be used after eviction. The eviction does nothing
useful — the session isn't reclaimed until the in-flight handler drops
its Arc, and meanwhile the cap might be exceeded by 1+ as new sessions
are inserted.

**Effect.** Cap is loosely honored under load. Memory grows past 1000.
Worse: the just-evicted session could re-handshake (creating a second
entry for the same client) while the original is still being processed.

**Fix.** Don't evict sessions with active handlers. Add an
in-flight refcount to the session and skip eviction if non-zero. Or
move to an LRU implementation that respects refcounts.

### P1-12 — Per-session crypto holds the session lock during decrypt + encrypt

`pq_middleware.rs:327-407`. The session mutex is acquired for decrypt
(line 327), released across `next.run()` (good), then re-acquired for
encrypt (line 398). Two requests to the same session serialize through
the lock pair, even though the actual crypto on each side is independent
of the other side's state.

**Effect.** No concurrent in-flight requests per session. For a busy
tenant, request rate is bounded by single-thread crypto throughput.

**Fix.** Snapshot the chain key into a local before crypto, do the work
without the lock, then atomically advance the counter under the lock.
Requires careful ordering vs. the rekey path; not trivial.

### P1-13 — Enrollment token timing leak

`pq_middleware.rs:206-209`:

```rust
let token_ok = supplied.len() == expected_b.len()
            && supplied.ct_eq(expected_b).unwrap_u8() == 1;
```

Length compare short-circuits before `ct_eq`. An attacker probes lengths
and infers the token's exact length from response timing.

**Fix.** Pad both sides to a common length and run `ct_eq` unconditionally,
or use `subtle::ConstantTimeEq` on a fixed-size array. The wrapping
function `constant_time_eq_n` from the same crate works.

### P1-14 — `process_handshake` runs ML-KEM + 3 HKDF expansions while holding `pq.sessions.write()`

`pq_middleware.rs:107-137`. The eviction scan and handshake insert run
under the write lock; the crypto inside `process_handshake` (called at
line 89) is *outside* the lock — but the read-lock on `authorized_keys`
is held while the crypto runs, blocking key registration / removal.

**Effect.** Under handshake load, key-management RPCs back up.

**Fix.** Move the crypto out of the read-lock scope: copy the matched
authorized entry into a local before the long-running operations.

---

## P2 — Medium (38 items, grouped)

### Crypto / transport

- **P2-C1.** `ratchet_step` uses `info = "msg:{counter}"` without epoch
  (`pq_channel.rs:582-590`). Today: safe because the chain key changes
  per epoch. Future-fragile if a refactor reuses the chain key.
- **P2-C2.** `derive_chain_key` (Sha256, no salt) and `ratchet_root`
  (Sha512, per-session salt) are split between two HKDF
  configurations (`pq_channel.rs:567-583` vs `594-620`). Domain
  separation works today but is implicit; a future refactor could
  collide.
- **P2-C3.** Nonce parsed from the client header is *trusted as-is* on
  decrypt (`pq_middleware.rs:271-274`). The AEAD tag protects integrity,
  but there's no nonce-replay cache, so a captured request whose
  counter hasn't yet advanced can be replayed before the legitimate
  next message arrives.
- **P2-C4.** WS frames are 1 MB max but no per-connection rate limit on
  decryption work (`pq_channel.rs:825`, `ws.rs:19,297-310`). A
  connection sending repeated 1 MB frames burns CPU.
- **P2-C5.** `derive_ws_subsession` exists but the WS path lacks
  in-band DH rekey (`pq_channel.rs:732-743` notes this explicitly).
  Long-lived WS connections aren't forward-secret relative to the
  parent session's ratchet. Enforce a max WS connection lifetime, or
  reuse the parent rekey trigger.
- **P2-C6.** `X-PQ-Method` is honored in AAD but never validated
  against the wire HTTP method (`pq_middleware.rs:287-372`). If the
  AEAD tag is forged (it can't be in practice), the dispatcher would
  use the spoofed method.
- **P2-C7.** `ratchet_step` HKDF info doesn't include epoch — see
  P2-C1.

### API / dispatch / jobs

- **P2-A1.** RPC `port` parameter not range-checked
  (`ws.rs:632-633`). Insert into prompts as a string; module receives
  `99999` or worse.
- **P2-A2.** RPC `concurrency` parameter not range-checked
  (`ws.rs:641-642`). Same pattern.
- **P2-A3.** `validate_module_name` not applied at every entry
  (`ws.rs:512` `rpc_search_modules` only checks length, not character
  class).
- **P2-A4.** Multi-target comma-split (`commands/mod.rs:171-185`) doesn't
  re-validate each token.
- **P2-A5.** Event bus is process-global broadcast
  (`events.rs:36`, `ws.rs:228`). Tenants see each other's events.
  Combine with P0-1.
- **P2-A6.** `MAX_LOOT_DATA = 100 MB` per entry, no global quota
  (`ws.rs:1064`). 10 entries = 1 GB.
- **P2-A7.** WS frame decryption errors `tracing::warn` without
  rate-limiting (`ws.rs:315-320`). Log flood attack.
- **P2-A8.** `kill_job` uses `task.abort()` after a 2s grace
  (`jobs.rs:314-324`). Hard-aborted tasks leak FDs, child processes,
  unflushed output.
- **P2-A9.** Job output buffer caps at 5000 lines but each line can be
  arbitrarily long (`jobs.rs:50-84`). 5000 × 1 MB = 5 GB.
- **P2-A10.** Module panics aren't caught — `tokio::spawn` swallows
  them; the job stays "Running" forever (`jobs.rs:232-260`).
- **P2-A11.** No HTTP request-body timeout
  (`api.rs:764`). Slowloris on the panel-proxy path.
- **P2-A12.** `/health` is unauthenticated and unconditional; layer-7
  flood vector. Add a per-IP token-bucket.
- **P2-A13.** `dispatch_with_cidr` doesn't pre-validate the network
  address itself before iterating (`commands/mod.rs:488-490`).

### Persistence / filesystem

- **P2-P1.** Concurrent bruteforce runs to the same `output_file`
  interleave (`utils/bruteforce.rs:439-453`). Append mode is per-task,
  not per-file.
- **P2-P2.** Workspace JSON corruption silently rolls back to default
  state (`workspace.rs:75-85`) — operator may not notice the backup.
- **P2-P3.** RDP NTLM message length field unchecked in CredSSP parsing
  (`native/rdp.rs:150-300`). A rogue server can probably overrun.
- **P2-P4.** `derive_salt` mixes inputs by concatenation without length
  prefixes (`pq_channel.rs:64-71`). Today fixed-length so safe; a
  future variable-length input would risk collision.
- **P2-P5.** Spool error after first failure goes silent
  (`output.rs:33-43`). Operator doesn't know logging stopped.
- **P2-P6.** Output buffer truncation warning fires once
  (`output.rs:33-43`). Subsequent dropped lines invisible.
- **P2-P7.** Cached wordlist SHA-256 verified on every fetch — but
  between fetches, a local attacker can modify the file and the next
  fetch (with same path, file exists) re-verifies and detects it.
  Wait — actually `verify_sha256` runs every fetch
  (`utils/wordlist.rs:67-72`), so this is fine. Disregard.
- **P2-P8.** Concurrent wordlist downloads not deduped
  (`utils/wordlist.rs:63-75`). 2 modules requesting the same uncached
  list cause 2 downloads.
- **P2-P9.** RDP timeout per-read instead of total handshake
  (`native/rdp.rs:64-68,75,81`). A slow server can pin a worker for
  N × per-read-timeout.

### Modules

- **P2-M1.** SSH command exec (`exploits/ssh/sshpwn_session.rs:598`) —
  user command passed through `validate_command_input` which I
  couldn't locate by grep; if it doesn't reject `;`, `|`, `$()`,
  `\`backticks\``, the module is a shell-injection gadget against the
  *target*, not the operator. Verify the validator's regex.
- **P2-M2.** Wordlist path prompts accept absolute paths and `..`
  (`creds/generic/ssh_bruteforce.rs:106-107`,
  `scanners/dir_brute.rs:150`). Operator can be socially engineered
  into reading `/etc/passwd`.
- **P2-M3.** Module result file written without explicit `0o600` in
  multiple places. The pattern *is* present in
  `creds/generic/ssh_bruteforce.rs:299-303` but not consistently.
- **P2-M4.** Verbose-mode logging includes plaintext credentials in
  stdout/terminal scrollback. Many modules.
- **P2-M5.** Service responses written verbatim to result files
  (`creds/generic/ssh_bruteforce.rs:305-329`). ANSI-escape injection
  exposes the operator's terminal when they `cat` results later.
- **P2-M6.** SafeLine `nginx_injection` accepts a `dry_run` prompt but
  ignores it (`exploits/safeline/nginx_injection.rs:109-113`). A
  documented dry-run path that always executes is a bait-and-switch.
- **P2-M7.** Slowloris `connections=1000000` accepted
  (`exploits/dos/slowloris.rs:115-120`). Caps memory before the
  semaphore even tries to open sockets — local DoS.
- **P2-M8.** `MysqlResult::Success` reads `response[0]` without
  emptiness check (`creds/generic/mysql_bruteforce.rs:709`). Server
  closing the connection mid-handshake panics.
- **P2-M9.** `from_utf8_lossy` silently replaces with U+FFFD in module
  error messages — operator sees garbled diagnostics rather than
  raw-bytes complaints.
- **P2-M10.** Rogue-server modules (SSH/VNC) bind a listening socket
  and `tokio::spawn` the accept loop without joining the handle on
  module exit. TIME_WAIT delays on subsequent runs.

### Cross-cutting

- **P2-X1.** Workspace hostname regex permits `_`
  (`workspace.rs:214-216`). RFC 1123 disallows; doesn't break
  rustsploit, breaks downstream consumers.
- **P2-X2.** Loot type sanitizer silently rewrites empty
  to `"unknown"` (`loot.rs:102-106`).
- **P2-X3.** Loot file_path returns `None` for invalid filenames; some
  callers don't log (`loot.rs:248-258`). Orphaned files possible.
- **P2-X4.** Spool `start()` resolves path relative to CWD
  (`spool.rs:113-143`); CWD change after start invalidates path.
- **P2-X5.** Bruteforce concurrency=0 from API config bypasses
  range check (`utils/bruteforce.rs:414-421`); creates `Semaphore::new(0)`
  → permanent hang.
- **P2-X6.** `output_file` validation rejects `..`, `/`, `\0` but not
  dot-prefix (`ws.rs:613-616`); `.bashrc` pass.
- **P2-X7.** Heartbeat doesn't probe internal state
  (`ws.rs:257-273`); a deadlocked dispatch keeps sending heartbeats.
- **P2-X8.** WS subscriptions limited to 100 per connection
  (`ws.rs:351-371`) but per-job output isn't bounded; one fat job
  fills the 256-slot mpsc buffer.
- **P2-X9.** Heartbeat loop checks session existence every 30s
  (`ws.rs:257-273`); revoked sessions stay live for up to 30s.

---

## P3 — Low / nice-to-have

- **P3-1.** `DEFAULT_REKEY_AFTER = 100` is a fixed integer, not
  configurable by deployment policy.
- **P3-2.** `derive_salt` mixes inputs by raw concatenation without
  length prefixes (already noted in P2-P4 — fixed-length today, future
  fragile).
- **P3-3.** Enrollment token printed plaintext to stdout
  (`api.rs:786`). Visible in screen/tmux scrollback.
- **P3-4.** `dispatch_rpc` accepts unbounded method names (`ws.rs:336`).
- **P3-5.** `rpc_list_creds` redaction reveals first 2 chars of secret
  (`ws.rs:799-807`). For 4-char passwords this is 50%.
- **P3-6.** WS connection nonce sent in plaintext
  (`ws.rs:74-79,144-145`). Not a secret, but unusual.
- **P3-7.** RDP `get_service_name` hardcodes a small port→service map
  (`scanners/port_scanner.rs:69-92`). SSH on 2222 doesn't match.
- **P3-8.** ~46 modules marked `Rank::Excellent`; spot-check shows
  inconsistent error handling within the tier.
- **P3-9.** Many modules have empty `references: vec![]` and
  `disclosure_date: None`.
- **P3-10.** RDP module domain prefix not validated for backslashes
  before NTLM packet (`creds/generic/rdp_bruteforce.rs:407-411`).
- **P3-11.** CSV escape covers only `,` `"` `\n`
  (`export.rs:207`). C0 control characters not escaped.
- **P3-12.** Bruteforce rate calculation comment says "elapsed > 0.0"
  is for "coarse clock resolution" — actually fine, but misleading.
- **P3-13.** `OnceCell` regex re-tries compilation on prior failure
  (`config.rs:160-164`). Defensive but the comment is misleading.
- **P3-14.** No CORS layer set on Axum router (`api.rs:766-776`).
  Currently no CORS = safe; a future contributor adding
  `CorsLayer::permissive()` opens a hole.
- **P3-15.** Job state-transition events not emitted on panic; no
  `catch_unwind` boundary (`jobs.rs:232-260`).
- **P3-16.** Random IP generation in mass-scan uses local `HashSet`
  for dedup (`commands/mod.rs:298-300`); duplicate-rate is fine, but
  state isn't shared across reruns.
- **P3-17.** `set_target` via RPC doesn't share `is_mass_scan_target`
  shortcut (`ws.rs:546-564` vs `api.rs:34-36`). Inconsistency between
  REST + WS paths.
- **P3-18.** Search queries not regex-escaped
  (`ws.rs:512-519`). Low impact (search relevance only).
- **P3-19.** Identity name length in `pq_authorized_keys` not bounded
  (`pq_channel.rs:210, 537`). 1 MB names are accepted.
- **P3-20.** `JoinHandle` aborts in `jobs.rs:394` don't await
  cleanup. OS resources leak.
- **P3-21.** Rust deps generally up-to-date; spot-check for known CVEs
  in `axum`/`tokio`/`reqwest`/`ml-kem`/`x25519-dalek` is a follow-up
  task.
- **P3-22.** ~3 known `expect()`-style panics flagged by inventory
  (`payloadgens/obfuscator.rs:446`,
  `native/url_encoding.rs:40`, `native/obfuscator_engine.rs:295`).
  All defensive — defensible, but document why.

---

## Findings the agents flagged that I downgraded or dismissed

Verifying before quoting matters; these claims didn't hold up:

- **TPKT "stack overflow" in `native/rdp.rs:132`** — the buffer is
  `vec![0u8; 1024]` (heap), and the bounds check `frame_len > buf.len()`
  correctly returns Err. Subsequent reads use `&mut buf[total..frame_len]`
  which Rust bounds-checks. No exploitable overflow.
- **CSV "newline injection"** — `export.rs:207` already wraps
  newline-containing values in quotes and escapes inner `"`. The
  P3-11 above tracks the narrower remaining gap (C0 control chars).
- **TLS handshake "5x timeout multiplication"** — claim conflated
  per-read with total. Worth tightening (see P2-P9) but not the
  catastrophe the report described.
- **HKDF "asymmetric availability"** — agent confused the salt
  construction's protection model. The salt is a per-deployment binding,
  not a shared secret; an attacker who steals the host key gets a much
  more direct compromise (server impersonation), not a salt-replay.
  Real concern is P0-4 (host key plaintext at rest), not the salt math.

---

## Phased fix plan

### Phase A — Stop the bleed (1–2w)

P0-1, P0-2, P0-4, P1-1, P1-3, P1-4, P1-6, P1-10. The two
process-wide-state items (P0-1, P1-1) are the biggest correctness blockers
and the most invasive — they touch every store and every RPC arm. Land
together with a hard test that simulates two tenants and verifies they
can't see each other's data.

**Definition of done:**
- Every `*_STORE` operation accepts `tenant_id: &str` and filters by it.
- `accept_invalid_certs: false` is the default; `--insecure-tls` flag
  reintroduces the prior behavior with a banner.
- Host identity file is mode `0o600` and (stretch) encrypted at rest.
- New integration test: 2-tenant scenario across creds/loot/jobs.

### Phase B — Auth + isolation polish (1–2w)

P0-3, P1-2, P1-7, P1-8, P1-9, P1-11, P1-13, P1-14. These are the
authentication / multi-process-correctness wins that follow naturally
from Phase A's tenant scoping. Single-flight handshake, real per-tenant
job IDs, DNS-resolution pinning, proxy-aware rate limit.

### Phase C — Module hardening (2–3w)

P0-2 follow-up + P2-M*. ~15 web-exploit modules need TLS verification
defaults flipped + a per-module `verify_ssl` prompt. ~10 bruteforce
modules need the wordlist path validator. SSH command-exec modules need
the validator regex audited (or rewritten with a strict allowlist).

### Phase D — Crypto correctness polish (1–2w)

P0-3 + P2-C1..C7. These are mostly forward-fragility issues — current
behavior is correct but a refactor could break it. Add the epoch to
`ratchet_step` info, normalize HKDF configs, write the dual-vector test
that pins both Rust and TS implementations against fixed inputs.

### Phase E — Operational polish (1w + ongoing)

P2-A* + P2-P* + P3-* clusters. Body timeouts, log redaction, real
healthchecks, panic-catching boundaries, CSV control-char escapes,
hostname regex, etc. Mostly small, independent PRs.

---

## What's working well (brief)

- Surprisingly clean Rust quality: 3 `expect()` calls in 119k LOC, 0
  `panic!`, 24 `unsafe` blocks all in defensible libc-binding contexts
  (raw sockets, fd manipulation, geteuid).
- Constant-time identity comparison in `pq_channel.rs:437-438` uses
  `subtle::ConstantTimeEq` correctly.
- `is_blocked_target` covers IPv4 + IPv6 link-local + RFC1918 +
  cloud-metadata. The bypass surface is mostly DNS rebinding (P1-8),
  not the matcher itself.
- Module discovery and dispatch via `build.rs` is elegant — adding a new
  module is a single file, no registry edits.
- The wiring-audit's claimed `dh_ratchet_send`/`dh_ratchet_receive` split
  in `pq_channel.rs:619-641` is correct and matches the panel TS now.
- Wordlist SHA-256 verification on every fetch
  (`utils/wordlist.rs:67-72`) catches in-place tampering.
- Spool symlink check, atomic file rename for authorized-keys, mode
  `0o600` on cred-store writes — the framework's *intent* on filesystem
  safety is right; the gaps are missing-pattern rather than wrong-pattern.

---

*Drift warning.* All file:line references were verified at audit time
(2026-04-28) on the working tree; treat them as starting points, not
gospel — verify before fixing.
