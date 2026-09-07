# rustsploit release audit — consolidated findings

Recovered from the multi-agent audit (32 area finders + adversarial verification).

**284 unique findings** (deduped from 284 raw).


By severity: critical=8, high=112, medium=114, low=50

By category: false-positive=128, logic-flaw=35, error-swallowing=32, silent-loss=31, panic-oom=28, resource-leak=13, mass-scan=10, security=7



## CRITICAL


### [silent-loss] src/modules/exploits/frameworks/nginx/nginx_pwner.rs:96
**nginx_pwner discovers vulns into a local Vec but returns empty ModuleOutcome**

The module runs 11 misconfig checks (CRLF, PURGE, variable leak, path traversal, CVE-2017-7529 integer overflow, alias traversal, X-Accel-Redirect bypass, nginx.conf source disclosure, etc.) and pushes every hit into a local `Vec<String> findings`. It prints them and writes them to a file via save_results(), then unconditionally returns `Ok(ModuleOutcome::ok())` with ZERO Finding records. Because it is registered with the `native` shape, the scheduler routes findings from ModuleOutcome only — so loot store, export, workspace tracking, and scheduler hit-count all see nothing. Every confirmed nginx vulnerability is silently lost from the run's structured results; a /16 sweep would report 0 hits even when many hosts are vulnerable.

_Fix:_ Build a `let mut outcome = ModuleOutcome::ok();` and for each entry pushed into the local Vec also push a `Finding { target, kind: FindingKind::Vulnerable, message, data }` into outcome.findings; return `Ok(outcome)` instead of `ModuleOutcome::ok()`.


### [silent-loss] src/modules/exploits/webapps/api_attack_suite.rs:465
**Entire API Attack Suite drops every finding — ModuleOutcome always empty**

The suite accumulates all discovered issues (OpenAPI exposure, auth bypass, BOLA/IDOR, mass assignment, JWT alg:none acceptance, excessive data exposure, GraphQL introspection, etc.) into a private `Report` struct with its own `Finding` type (line 1146-1155). At the end of `run()` it calls `report.render(auto_mode)` which only prints to stdout, then returns `Ok(ModuleOutcome::ok())` — a ModuleOutcome with an empty `findings` vec. None of the suite's results are ever converted into `crate::module::Finding` and pushed into the ModuleOutcome, so nothing reaches loot/export/scheduler hit-counts. A confirmed Critical (e.g. JWT alg:none accepted, mass-assignment privilege escalation) is printed and then silently discarded.

_Fix:_ After render, translate each `Report::Finding` (especially Medium+/High/Critical) into a `crate::module::Finding` and push it onto `outcome.findings` before returning the populated outcome instead of `ModuleOutcome::ok()`.


### [panic-oom] src/modules/exploits/webapps/clipbucket_rce_cve_2025_55911.rs:120
**Guaranteed out-of-bounds slice panic building shell filename**

`rce_marker()` returns `format!("RSPLOIT{:08x}", rand::random::<u32>())`. "RSPLOIT" is 7 bytes and `{:08x}` of a u32 is always exactly 8 hex characters (a u32 cannot exceed 8 hex digits), so the marker is always exactly 15 bytes long. Line 120 then slices `&marker[8..16]`, whose end index 16 exceeds the length 15, causing an immediate `byte index 16 is out of bounds` panic. Because the module always reaches Phase 3 (it only bails early on auth failure), this panics on essentially every run, aborting the module and discarding any earlier ClipBucket-detected finding.

_Fix:_ Use `&marker[7..15]` (the 8 hex chars after the 7-char "RSPLOIT" prefix) or `&marker[marker.len().saturating_sub(8)..]`, or build the filename from the random value directly without slicing.


### [false-positive] src/modules/creds/camera/acti/acti_camera_default.rs:243
**HTTP login success inferred from ABSENCE of ">Password<" substring — body read error reports valid creds**

check_http_form decides a credential is valid when the response body does NOT contain the substring ">Password<". On line 235-241 a failed response-body read is swallowed and replaced with String::new(); an empty string trivially does not contain ">Password<", so a transient body-read error (timeout, reset, decode failure) is reported as VALID credentials. The same false positive fires for any error page, redirect, or non-ACTi page that doesn't happen to render the literal HTML token ">Password<". This both swallows a real network error and produces a bogus Credential finding stored to loot.

_Fix:_ Require a positive success signal (e.g. HTTP status 200 AND presence of a known post-login marker, or a redirect to a known authenticated page), and treat a body-read error as LoginResult::Error rather than silently mapping it to an empty body. Never infer success from the mere absence of a login-form token.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_reyee_ssrf_cve_2024_48874.rs:107
**SSRF 'confirmed' on any HTML/keyword in the response**

detect_ssrf_signs() returns true (and run() pushes a Vulnerable finding) if the response merely contains '<!DOCTYPE'/'<html>', mentions 'apache'/'nginx', or contains the words 'internal'/'private'. Hitting /api/cloud/sync etc. on any device almost always returns an HTML error/login page, so this reports SSRF VULNERABLE on essentially any web endpoint. The GET path additionally flags on text.len() > 500 alone (line 213).

_Fix:_ Replace heuristic signature matching with positive proof of SSRF: use a unique out-of-band callback token (OAST) in ssrf_target and confirm the device fetched it, or embed a unique marker the internal service would return. Do not treat generic HTML/keywords/length as confirmation.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_rsr_router_ci_cve_2024_31616.rs:153
**RSR command-injection 'confirmed' when any endpoint returns 200 with >100 bytes**

execute_injection treats cmd_executed as true if `text.len() > 100 && status.is_success()`, in addition to uid=/root/gid= markers. Any diagnostic endpoint that returns a normal HTML page (>100 bytes, HTTP 200) is reported as a confirmed command injection and pushes a Vulnerable finding. This is a near-guaranteed false positive on any web server, including benign hosts.

_Fix:_ Remove the `(text.len() > 100 && status.is_success())` clause. Confirm injection only on actual command-output markers (uid=/gid= regex), ideally by injecting a unique echo marker and matching it in the response.


### [false-positive] src/modules/exploits/routers/tenda/tenda_cp3_rce_cve_2023_30353.rs:64
**Tenda CP3 reports VULNERABLE after merely sending a UDP datagram**

The module pushes a FindingKind::Vulnerable finding immediately after socket.send() of the UDP XML payload (line 58). UDP is connectionless, so socket.send() succeeds locally regardless of whether the target host exists, is listening on 5012, or is vulnerable. Under per-host fan-out across a CIDR, EVERY host is flagged 'VULNERABLE'. The optional recv() at line 73 does not gate the finding. This pollutes loot/export with bogus confirmed RCE findings for every scanned address.

_Fix:_ Do not record a Vulnerable finding for a blind UDP send. Either gate the finding on a validated response (e.g. an out-of-band callback or a meaningful recv()), or downgrade to a FindingKind::Note describing that a blind payload was delivered and require external confirmation.


### [false-positive] src/modules/exploits/voip/magnusbilling_ssrf_cve_2023_30258.rs:56
**MagnusBilling path-traversal detection fires on any non-HTML 200 response**

The path-traversal success condition is `status.is_success() && body.len() > 10 && (body.contains("root:") || body.contains("[") || !body.contains("<html"))`. The clauses `body.contains("[")` (matches almost any JSON/array/text) and `!body.contains("<html")` (matches any non-HTML body) make this true for virtually every live endpoint returning a 200 with >10 bytes of non-HTML content. The module then pushes a FindingKind::Vulnerable and returns. The follow-up SSRF check at line 87 is equally loose: `body.contains("Connection")` matches the word "Connection" present in countless normal responses. This guarantees false-positive CVE-2023-30258 reports across benign hosts.

_Fix:_ Require a real LFI marker: for /etc/passwd verify `body.contains("root:") && body.contains(":/bin/")` (or `:x:0:0:`); drop the `contains("[")` / `!contains("<html")` heuristics entirely. For the SSRF check require the actual SSH banner regex `SSH-2.0` rather than the substring "Connection".



## HIGH


### [security] src/mcp/tools.rs:555
**MCP run_module SSRF guard only validates `target`; alternate prompt keys (url/host/endpoint/lhost) bypass it**

handle_run_module runs the full SSRF block-check chain (validate_target / is_blocked_target / is_blocked_target_resolved) against the `target` argument only, and then strips just the `target` key from the attacker-supplied `prompts` map (the comment claims this 'prevents SSRF bypass via prompt injection'). But many modules read their actual connection destination from a different prompt key. e.g. src/modules/scanners/security_headers_scanner.rs:66 does `cfg_prompt_default("url", ...)` and then issues `client.get(&url).send()` (line 77). Modules also accept `host`, `endpoint`, and `lhost` prompt keys. An MCP client can call run_module with a benign `target` (e.g. 1.2.3.4) plus `prompts: {"url": "http://169.254.169.254/latest/meta-data/"}`; the SSRF filter never inspects `url`, so the module connects to the cloud-metadata / link-local / loopback address. The guard is therefore trivially bypassable for any module that takes a URL/host via a custom prompt.

_Fix:_ Do not rely on stripping a single key. Either (a) run is_blocked_target / is_blocked_target_resolved over every value in `prompts` that could be a URL/host, or (b) enforce the SSRF policy at the network egress layer (a shared HTTP/socket client wrapper that rejects blocked IPs after DNS resolution, with DNS-rebinding protection) so module prompt keys cannot smuggle a destination past the filter.


### [security] src/modules/exploits/vnc/libvnc_websocket_overflow.rs:56
**DoS confirmation skipped for hostname / IPv6 WebSocket-overflow targets**

Same bypass pattern as the decompression bomb: the heap-overflow probe (which sends a frame claiming 0xFFFFFFFFFFFF bytes to trigger a crash) only calls confirm_dos_target when the target string parses as an IPv4 address. A hostname or IPv6 target skips the `if let Ok` block entirely (no else) and the crash-inducing frame is sent without operator confirmation.

_Fix:_ Resolve host to IP before the guard, or require confirmation for any unparseable host. Do not silently skip the destructive-action confirmation when the target is not a bare IPv4 literal.


### [security] src/modules/exploits/vnc/tightvnc_decompression_bomb.rs:63
**DESTRUCTIVE DoS guard silently bypassed for hostname / IPv6 targets**

confirm_dos_target() (the operator confirmation gate for this destructive heap-exhaustion attack) is only invoked when `host.parse::<Ipv4Addr>()` succeeds. If the target is a DNS hostname (e.g. 'vnc.corp.example') or an IPv6 address, the parse fails, the `if let Ok` branch is skipped with no else, and the module proceeds to send the 2 GiB decompression bomb to a production target with NO confirmation prompt. The module is explicitly labelled DESTRUCTIVE.

_Fix:_ Resolve the host to an IP (or require confirmation for the raw host string) before sending the bomb. For non-IPv4/unresolvable hosts, either resolve-then-confirm or refuse with bail!() rather than firing the destructive payload unguarded. Add IPv6 support to confirm_dos_target.


### [security] src/ws.rs:632
**SSRF filter is TOCTOU/DNS-rebinding bypassable: resolved IPs are checked then discarded, module re-resolves**

rpc_run_module (632), rpc_check_module (780) and rpc_honeypot_check (794) gate the target with `is_blocked_target_resolved(target)`, which calls resolve_and_check and only returns a bool, throwing away the resolved SocketAddrs. The doc comment on resolve_and_check (api.rs:240-241) explicitly states: "Callers should connect to the returned addresses directly (not re-resolve) to prevent DNS rebinding attacks." But these handlers pass the raw `target` hostname string on to the module/job, which re-resolves it at connect time. An attacker-controlled DNS name can return a public IP for the validation lookup and 127.0.0.1 / 169.254.169.254 / an RFC1918 metadata endpoint for the subsequent module connection, fully bypassing the SSRF filter. rpc_set_target (603) has the same pattern: it stores the unresolved string for later module runs.

_Fix:_ Call resolve_and_check, keep the returned Vec<SocketAddr>, and pass those pinned addresses into the module/job so it connects to the validated IPs instead of re-resolving the hostname. At minimum, document and enforce a single-resolution path (resolver cache pinned for the request) so the validation lookup and the connect lookup cannot diverge.


### [error-swallowing] src/modules/creds/camera/acti/acti_camera_default.rs:233
**Single transient HTTP request error aborts the entire credential loop with `?`**

Inside the per-credential loop, the HTTP POST uses `.send().await.context(...)?`. A single transient request failure (timeout/connect reset) on any credential propagates an Err out of check_http_form, abandoning all remaining credentials for the host. Combined with the join! in run(), one transient blip turns the whole HTTP service check into an error rather than continuing to the next credential.

_Fix:_ Match on the send() result and `continue` (or record a retryable error) on transient failures instead of `?`-propagating, mirroring the FTP/SSH/Telnet loops in the same file which `continue` on connect errors.


### [error-swallowing] src/modules/creds/generic/h3c_oem_kvm_bruteforce.rs:293
**try_login swallows all request/body errors as None, indistinguishable from auth-denied; no retry**

try_login returns Option<String> and uses `client.post(...).send().await.ok()?` (line 293) and `resp.text().await.ok()?` (line 307). Every transport error — timeout, connection refused, TLS failure, reset — is collapsed to None, which the caller (line 228) treats exactly like a denied credential. A transient network error therefore makes a valid KVM credential appear invalid, and there is no retry/backoff and no error surfaced. On default H3C builds with no rate limit, a momentary blip silently drops a real hit.

_Fix:_ Return a tri-state (e.g. Result<Option<String>, Error> or a LoginResult-style enum) distinguishing transport error (retryable) from a genuine 401 denial, and retry transient errors with backoff before recording a credential as not-valid.


### [error-swallowing] src/modules/exploits/dos/null_syn_exhaustion.rs:648
**Local source-IP detection failure silently falls back to 127.0.0.1, producing a non-functional flood**

In non-spoofed mode (the default, use_random_source_ip=false), the source IP for every crafted SYN packet is obtained via get_local_ipv4_for(config.target_ip).unwrap_or(Ipv4Addr::new(127,0,0,1)). get_local_ipv4_for (lines 817-824) uses `.ok()?` on blocking_udp_bind / connect / local_addr, so ANY failure (bind error, no route, etc.) is swallowed into None and silently becomes loopback 127.0.0.1. The packet builder then stamps src=127.0.0.1 into the IP header. The kernel treats a loopback source on an egress raw socket as a martian and drops it (or it is filtered upstream), so the flood sends zero effective packets while the stats still report 'packets queued to kernel'. The same swallowing fallback exists in gather_config at line 543. The operator gets a green 'Attack started!' and a packet count with no indication the run is dead.

_Fix:_ Do not silently substitute loopback. If get_local_ipv4_for returns None in non-spoofed mode, return Err with a clear message (e.g. 'could not determine a local source IP for <target>; set local_ip=<addr> or enable spoof_ip'), or at minimum print a loud warning and refuse to start. Propagate the underlying error from get_local_ipv4_for instead of `.ok()?`.


### [error-swallowing] src/modules/exploits/network_infra/vmware/vcenter_backup_rce.rs:159
**attack_exec swallows the exploit error and always returns Ok(true)**

`attack_exec` runs the injected command with `if let Err(e) = vcenter_shell_exec(...) { print red }` and then unconditionally returns `Ok(true)`, printing "Command sent". If the SSH exec fails (auth/channel error, patched target rejecting the injection, network drop), the error is only printed and the function still reports success to the caller. The operator is told the command ran as root when it may have completely failed; combined with the missing-Finding bug this also means no verification of the result occurs at all (unlike mode 1/3 which at least attempt a verify step).

_Fix:_ Propagate the error from vcenter_shell_exec (`vcenter_shell_exec(&sess, &exploit_cmd)?;`) or return Ok(false) on failure, and verify the effect before reporting success rather than printing the error and continuing.


### [error-swallowing] src/modules/exploits/snare/cookie_dos.rs:70
**Oversized/erroring HTTP response is swallowed and misreported as a worker crash**

http_raw() ends with `.await.ok()?.ok()?`. The second `.ok()?` discards the Err returned by read_async_capped when the peer sends more than 16384 bytes (a perfectly healthy large HTTP page), turning a successful response into None. In the liveness check (step 3) None is mapped to `crashed = true`, which then pushes a FindingKind::Vulnerable. So a snare instance that simply returns a >16KB body — or hits any transient read error/timeout on one probe — is falsely reported as a confirmed DoS, and the real error (cap exceeded / IO failure) is silently lost.

_Fix:_ Distinguish IO/timeout/cap errors from a genuinely closed connection. Raise the cap or read the status line specifically, and only treat a clean connection failure (not a cap-exceeded Err) as evidence of a crash; log the real error instead of mapping it to None.


### [error-swallowing] src/modules/scanners/sharepoint_doc_harvest.rs:931
**SharePoint harvest swallows file-write error then prints 'Saved' unconditionally**

In the common-filename download branch the harvested document is written with `let _ = std::fs::write(&filepath, &bytes);` discarding any error (permission denied, disk full, invalid path), then it unconditionally prints '[+] Saved: {}'. The operator is told the loot was saved even when it was not, causing silent data loss of harvested documents. The other download branch in the same file (line 840) correctly handles the write Result with an if/else and reports write errors — proving this is an inconsistent oversight, not intentional.

_Fix:_ Mirror the line-840 branch: `match std::fs::write(&filepath, &bytes) { Ok(_) => print Saved, Err(e) => crate::mprintln!("    [-] Write error: {}", e) }`.


### [silent-loss] src/jobs.rs:388
**Failed background job is reported as "Completed"; failure reason is dropped from the job record**

When a background module run fails, the spawned task (lines 296-303) computes the error message, pushes it to the progress log, and broadcasts a JobEvent::Failed, but it NEVER writes JobStatus::Failed(msg) back into the Job entry in the `jobs` map. The Job's status stays JobStatus::Running. Later, when an operator queries job state via `list()` (line 388-391) or `get_detail()` (line 423-426), the code sees the handle is finished and the status is still Running, so it unconditionally flips it to JobStatus::Completed. Result: every failed background job is permanently surfaced as "Completed" in the jobs table and in API detail responses, and the failure reason is lost from the durable record (it survives only in the bounded 5000-line progress ring buffer and the transient broadcast event, both of which are gone once a WS client disconnects or the buffer rolls). An operator polling `jobs`/job detail can never tell a crashed/errored scan from a successful one.

_Fix:_ Have the spawned task write the terminal status back into the JobManager (e.g. pass a weak ref / call a `mark_failed(id, msg)` / `mark_completed(id)` method that takes the write lock and sets job.status = JobStatus::Failed(msg) or Completed and finished_at). Then in list()/get_detail() only fall back to Completed for handles that finished without the task recording a terminal status, never overwriting a Failed/Cancelled status.


### [silent-loss] src/module.rs:355
**build_run_context never copies module_path into the scoped RunContext — all workspace findings attributed to "workspace"**

ModuleCtx::build_run_context constructs the RunContext that the register_native_module! macro installs as the task-local RUN_CONTEXT for the entire module run. It copies options, prompt_cache, cancellation and tenant_id, but it never sets rc.module_path (the RunContext field stays the empty default from with_target/with_prompt_cache). The crate provides RunContext::with_module_path() precisely for this, but it is never called here. Consequence: crate::context::current_module_path() (context.rs:211) returns an empty string for every running module, and workspace.rs::emitting_module() (workspace.rs:485-492) therefore falls back to the literal "workspace" for every add_finding/track_host/track_service emission. Every finding routed through the workspace helpers is mis-attributed to "workspace" instead of the real category/name, corrupting loot/workspace attribution and export provenance for all modules that use those helpers.

_Fix:_ After setting tenant_id, add `rc.module_path = self.module_path.clone();` (or `rc = rc.with_module_path(self.module_path.clone());`) so current_module_path()/emitting_module() resolve to the real module path.


### [silent-loss] src/modules/creds/camxploit/exploit.rs:520
**Detected camera brand / login pages / live streams are printed but never pushed into ModuleOutcome**

fingerprint_camera (brand detection), check_login_pages (exposed auth pages), and detect_live_streams (exposed/unauthenticated streams) all print discoveries to stdout but push NOTHING into `outcome.findings`. Only open ports (line 217) and successful credentials reach the outcome. So a fingerprinted Hikvision/Dahua/Axis camera or an exposed unauthenticated MJPEG/RTSP stream is shown on screen but never recorded as a Finding, so it never reaches loot/export/scheduler hit-count.

_Fix:_ Have fingerprint_camera, check_login_pages, and detect_live_streams take `&mut ModuleOutcome` (or return discovered items) and push Finding entries (kind Info/Note for brand & exposed stream) so detections are exported, not just printed.


### [silent-loss] src/modules/creds/generic/redis_bruteforce.rs:518
**Redis bruteforce drops all found credentials — never pushed into ModuleOutcome**

In the single-target path, the brute-force result is computed at line 447 and `result.found` is printed (line 460) and saved to file (line 462), but the found credentials are NEVER pushed into `outcome.findings`. The only finding ever added to `outcome` is the pre-flight unauthenticated-PONG case (line 323), which returns early at line 329. So when a valid AUTH credential is actually discovered by the brute force, the function returns `Ok(outcome)` with an empty findings vector. The scheduler therefore routes nothing into LootStore/Workspace/events for discovered Redis creds, the hit-count is wrong, and exports miss them. Sibling modules (pop3 line 280-292, smtp line 176-188, ssh line 379-391, proxy line 422-435) all correctly loop over `result.found` and push Credential findings; redis is the lone module that omits this loop.

_Fix:_ Before `Ok(outcome)`, add the same loop the other modules use:
    for (host, user, pass) in &result.found {
        outcome.findings.push(Finding { target: host.clone(), kind: FindingKind::Credential, message: format!("Valid Redis credentials found: {}:{}", user, pass), data: Some(serde_json::json!({"username": user, "password": pass, "service": "redis", "port": port})) });
    }


### [silent-loss] src/modules/exploits/cameras/avtech/cve_2024_7029_avtech_camera.rs:257
**Vulnerable finding discarded when interactive_shell errors in batch/API mode**

In single-target/file mode, immediately after pushing the Vulnerable Finding into `outcome`, the code calls `interactive_shell(&client, &url).await?`. interactive_shell returns an Err in API mode (line 49-51) and in batch/mass-scan mode (line 52-54). Under the framework's universal per-host fan-out, the module runs in batch mode, so on a genuinely vulnerable host this `?` propagates the Err out of `run`, causing the whole module invocation to fail and the already-pushed Vulnerable finding (in `outcome`) to be dropped — it never reaches loot/export/hit-count. The exploit silently loses exactly the hits it was meant to record.

_Fix:_ Do not call interactive_shell with `?` here. Only enter the interactive shell in confirmed interactive CLI mode; in batch/API mode skip it entirely (or log) and continue, returning Ok(outcome) so the finding is preserved. Alternatively ignore the interactive_shell error: `let _ = interactive_shell(...)` only after gating on !is_batch_mode() && !api_mode.


### [silent-loss] src/modules/exploits/cameras/avtech/cve_2024_7029_avtech_camera.rs:169
**Mass-scan mode prints VULNERABLE but never records a Finding (results dropped)**

When target is empty/0.0.0.0/0.0.0.0/0/'random', run() dispatches to run_mass_scan_legacy(), which scans random public IPs in an unbounded loop, prints '[+] VULNERABLE: <ip>' for hits, and increments an in-memory counter — but it returns `()` and run() then returns `ModuleOutcome::ok()` (empty). No Finding is ever pushed, so every vulnerable host discovered by the mass scan is silently lost: nothing reaches loot, export, or the scheduler hit-count. The loop also runs forever until ctrl_c and ignores module_timeout.

_Fix:_ Have run_mass_scan_legacy collect findings (e.g. via a shared Vec/channel) and return them so run() can populate ModuleOutcome.findings, and bound the loop by module_timeout / cancellation instead of relying solely on ctrl_c.


### [silent-loss] src/modules/exploits/frameworks/apache_tomcat/cve_2025_24813_tomcat_put_rce.rs:278
**PUT-RCE module prints VULNERABLE but never pushes a Finding**

The module confirms PUT write capability ('[+] PUT write confirmed!'), tracks the host as vulnerable to CVE-2025-24813, uploads the serialized payload, and reports a likely-triggered deserialization (HTTP 500), yet the function unconditionally returns `Ok(ModuleOutcome::ok())`. No Finding is ever added to the outcome, so a confirmed-vulnerable host never reaches loot/export/scheduler hit-count. All the detection work is computed and discarded.

_Fix:_ Build a `let mut outcome = ModuleOutcome::ok();` at the top, and on confirmed PUT-write / HTTP-500 trigger push `outcome.findings.push(Finding { kind: FindingKind::Vulnerable, ... })`, then `Ok(outcome)`.


### [silent-loss] src/modules/exploits/frameworks/nginx/nginx_pwner.rs:96
**NginxPwner collects findings into a local Vec and discards them from the outcome**

Every check (CRLF injection, PURGE, variable leakage, path traversal, CVE-2017-7529, alias traversal, X-Accel-Redirect bypass, nginx.conf source disclosure) pushes into a local `Vec<String>` that is only printed and written to a file. `run` always returns `Ok(ModuleOutcome::ok())`, so none of the discovered vulnerabilities are ever recorded as Findings in the ModuleOutcome and never reach loot/export/scheduler. Confirmed CVE-2017-7529 / path-traversal hits are silently lost.

_Fix:_ Map the collected `findings: Vec<String>` (or each detection site) into `outcome.findings.push(Finding { kind: FindingKind::Vulnerable, message, ... })` and return that outcome instead of `ModuleOutcome::ok()`.


### [silent-loss] src/modules/exploits/network_infra/apache_modssl_bypass_cve_2025_23048.rs:33
**Apache mod_ssl detection prints VULNERABLE-style hit but never pushes a Finding**

`run()` binds the outcome as `let outcome = ModuleOutcome::ok();` (immutable, line 33). When the Apache fingerprint matches (lines 43-46) the module prints '[+] Apache fingerprint matched...' and calls `track_host`, but it NEVER pushes a Finding into `outcome.findings`. The scheduler routes findings into LootStore/Workspace and the hit-count from `outcome.findings`, so a positive detection here is completely invisible to loot/export/scheduler. The result is computed and printed, then dropped. (The binding is also `let` not `let mut`, so a finding could not be pushed without changing it — a strong signal the push was forgotten.)

_Fix:_ Change to `let mut outcome = ModuleOutcome::ok();` and, inside the match arm, push a `Finding { kind: FindingKind::Vulnerable (or Info), target: normalized.clone(), message: ..., data: ... }` into `outcome.findings` so detections reach loot/export/scheduler.


### [silent-loss] src/modules/exploits/network_infra/arista_ngfw_disclose.rs:63
**Body-read `?` inside command loop aborts the whole module and discards prior detection state**

Inside `for cmd in &cmds`, the body is read with `let body = r.text().await.context("read body")?;`. A `?` here returns Err from the entire `run()`. If the first command already set `leaked = true` (a confirmed disclosure) but a later command's body read fails (e.g. connection reset mid-stream, decode error), the module bails out before the `if leaked { outcome.findings.push(...) }` block at lines 84-94. The confirmed Finding is never constructed and the remaining commands are skipped — a real detection is silently lost, and a transient read error masquerades as 'no result / module error'.

_Fix:_ Match on `r.text().await` like the `send()` call above (print the read error and `continue`), instead of propagating with `?`. This keeps the loop alive and preserves the `leaked` flag so a real disclosure is still reported.


### [silent-loss] src/modules/exploits/network_infra/vmware/vcenter_backup_rce.rs:262
**vcenter_backup_rce modes 2 and 3 record no Finding on successful RCE / backdoor creation**

Only mode 1 (check) pushes a Finding. Mode 2 (`attack_exec`) executes an arbitrary root command and mode 3 (`attack_add_user`) creates a sudo-capable backdoor user, both via the CVE-2024-22274 flag injection, yet `run()` invokes them with the return value discarded (`attack_exec(...).await?;` / `attack_add_user(...).await?;`) and never pushes a Finding. A successful exploitation (backdoor user added, command executed as root) is therefore never recorded in ModuleOutcome and never reaches loot/export/hit-count.

_Fix:_ Push a Finding (FindingKind::Vulnerable, with cve/host/port and action details such as the created username) when attack_exec/attack_add_user report success, mirroring the mode-1 branch.


### [silent-loss] src/modules/exploits/network_infra/vmware/vcenter_file_read.rs:211
**vcenter_file_read never pushes a Finding even when sensitive files are read**

`run()` returns `Ok(ModuleOutcome::ok())` unconditionally with zero findings. `attack_enum` successfully reads and prints files such as /etc/shadow, vpxd.cfg, vcdb.properties (returning `found_any = true`), and `read_file` returns full file contents, but both return values are discarded in `run()` (`attack_enum(...).await?;` with the bool thrown away; the Ok branch of `read_file` only prints). Consequently a confirmed CVE-2024-22275 arbitrary file read — including credential material from vcdb.properties/shadow — is printed to stdout but never recorded in the ModuleOutcome, so it never reaches loot, export, or the scheduler hit-count.

_Fix:_ Build a `let mut outcome = ModuleOutcome::ok();`, and when `attack_enum` returns true (or `read_file` returns content) push a `Finding { kind: FindingKind::Vulnerable, data: Some(... readable files / contents ...) }`, then return `Ok(outcome)`.


### [silent-loss] src/modules/exploits/routers/tplink/tplink_wdr740n_path_traversal.rs:9
**Successful arbitrary file read is printed but never recorded as a Finding**

On a successful path-traversal file read the module prints the file content (lines 62, 69) but never pushes any Finding into the outcome. `outcome` is declared immutable at line 9 (`let outcome = ModuleOutcome::ok();`) and returned untouched, so even a genuine /etc/shadow disclosure never reaches loot/export/scheduler hit-count. The result is computed then dropped.

_Fix:_ Make `outcome` mutable and push a FindingKind::Vulnerable (or a Credential/Note carrying the retrieved file path and a snippet) when the traversal returns file content, so the disclosure is persisted.


### [silent-loss] src/modules/exploits/webapps/drupal11_pathdisclose_cve_2024_45440.rs:33
**Path-disclosure leak detected but no Finding ever pushed**

`outcome` is bound immutably as `let outcome = ModuleOutcome::ok();` and is never mutated. When the per-path loop detects a leak (`leak == true`), the module prints "(leak/banner)" and calls `crate::workspace::track_host(...)` (line 60) but never pushes a `Finding` into `outcome.findings`. The function returns the empty outcome, so a confirmed full-path-disclosure / Drupal detection never reaches loot/export/scheduler hit-count. The result is computed and dropped.

_Fix:_ Make `outcome` mutable and, inside the `if leak` branch, push a `Finding` (Note/Vulnerable) with the matched path and leaked snippet so it is exported and counted.


### [silent-loss] src/modules/exploits/webapps/sap_netweaver_rce_cve_2025_31324.rs:199
**Confirmed webshell/RCE produces no Finding when upload status is non-2xx**

The only outcome.findings.push() is in the `else` branch gated on `upload_status.is_success()` (line 211-223). The module's own comment (line 209) acknowledges 'some SAP versions return non-200 but still write the file', and Phases 3 and 4 then go on to confirm the webshell is accessible/operational and even capture command output — but none of Phase 3's success branch (line 271-279), the alternate-path success branch (line 255-263), nor Phase 4's command-output branch (line 304-317) push a Finding. So a host where RCE is fully confirmed via command output, but whose upload response was e.g. HTTP 500, yields an empty ModuleOutcome and never reaches loot/export/scheduler.

_Fix:_ Track a `rce_confirmed` flag set in the Phase 3 accessible/operational branches and the Phase 4 command-output branch, and push a FindingKind::Vulnerable when confirmed regardless of the upload HTTP status.


### [silent-loss] src/modules/exploits/webapps/zimbra_sqli_auth_bypass_cve_2025_25064.rs:197
**Phase 3 email extraction prints success and stores loot but never pushes a Finding**

When the targeted UNION extraction 'succeeds' the module prints "[+] Email metadata found in response!" and calls store_loot, but never pushes a Finding into the outcome. The successful data-extraction result therefore never reaches export / scheduler hit-counts. Compounding it, the trigger condition `body.contains(&target_email) || body.contains("mail")` is extremely loose: the substring "mail" is present in nearly every Zimbra/HTML page (email, mailto, Gmail, mailbox), so this branch fires on benign responses — a false positive whose result is also silently dropped.

_Fix:_ Tighten the detection (require the actual injected marker / the target_email plus a UNION sentinel value) and, on a genuine match, push a FindingKind::Vulnerable (or Credential) into outcome.findings so the extraction is recorded.


### [silent-loss] src/modules/scanners/api_endpoint_scanner/mod.rs:358
**API endpoint scanner never produces a single Finding (results dropped from loot/export)**

The entire api_endpoint_scanner pipeline (baseline, SQLi/NoSQLi/CMDi/Path-Traversal injection, spoofing, ID enumeration) writes every response to per-endpoint result files on disk but never pushes a single Finding into a ModuleOutcome. run() unconditionally returns ModuleOutcome::ok() (empty findings). Per module.rs, the scheduler routes findings into LootStore/Workspace automatically, so nothing this module discovers (including confirmed injection hits) ever reaches loot, export, the scheduler hit-count, or batch output. scan_endpoint() even returns () — there is no channel back to the outcome at all. idenum.rs emits a ServiceDetected event (idenum.rs:96) which also does not land in the ModuleOutcome.

_Fix:_ Thread a shared findings collector (e.g. Arc<Mutex<Vec<Finding>>> or an mpsc channel) through scan_endpoint/perform_request/perform_id_enumeration, push a Finding whenever an interesting status / injection signature / discovered endpoint is observed, and move them into ModuleOutcome.findings before returning.


### [silent-loss] src/modules/scanners/wp_user_enum.rs:143
**oembed author disclosure printed but never recorded as a Finding**

The third enumeration vector (oembed) detects a disclosed WordPress author (status 200 + body contains "author_name") and prints a green [+] line to stdout, but never pushes a Finding into `outcome.findings` and never appends to the `users` vec. The discovered author is computed then dropped — it never reaches loot/export, the workspace, or the scheduler hit-count, and is omitted from the final '=== Discovered users ===' table. The other two vectors (wp-json, ?author=N) correctly push Findings, so this vector silently loses results.

_Fix:_ On the oembed hit, parse the author_name/author_url and push a Finding (kind Note) into outcome.findings and add an entry to `users`, mirroring the wp-json and ?author=N vectors, so the result is exported and counted.


### [silent-loss] src/utils/bruteforce.rs:954
**run_subnet_bruteforce findings never reach ModuleOutcome / scheduler hit-count**

run_subnet_bruteforce discovers valid credentials, prints '[+] FOUND', writes them to a file, and stores them in cred_store, but its signature returns Result<()>. It provides no channel to surface a Finding. Every one of the 8 callers (ssh/ftp/smtp/imap/pop3/redis/proxy/http_basic _bruteforce) therefore returns a bare `ModuleOutcome::ok()` with zero findings after a subnet scan. Concrete example: ssh_bruteforce.rs:146-147 builds `let outcome = ModuleOutcome::ok(); return Ok(outcome);` immediately after the subnet run. The result is that subnet credential hits are invisible to the scheduler's hit-count, the events bus, and the loot/export pipeline that drive on ModuleOutcome.findings — exactly the silent-loss class the maintainer is worried about. Single-host runs (creds_helper::run) correctly push Credential findings; subnet mode does not.

_Fix:_ Have run_subnet_bruteforce return the list of (ip, user, pass) hits (or a Vec<Finding>) so callers can push a FindingKind::Credential per success into their ModuleOutcome, mirroring creds_helper::run (lines 243-252). At minimum collect stats_found into a returned struct and have callers translate to findings.


### [panic-oom] src/modules/creds/generic/fortinet_bruteforce.rs:106
**Byte-slice of response body at fixed offset 80 panics on non-UTF-8-char-boundary**

`&txt[..txt.len().min(80)]` slices the (attacker-controlled) HTTPS response String at byte index 80. If byte 80 falls in the middle of a multi-byte UTF-8 sequence, Rust string slicing panics (`byte index 80 is not a char boundary`). A FortiGate (or any host on :443) that returns an unexpected body with a multibyte character straddling offset 80 crashes the probe task.

_Fix:_ Use a char-boundary-safe truncation, e.g. `txt.chars().take(80).collect::<String>()` or `&txt[..txt.char_indices().take(80).last().map(|(i,c)| i+c.len_utf8()).unwrap_or(0)]`.


### [panic-oom] src/modules/exploits/network_infra/citrix/cve_2025_5777_citrixbleed2.rs:108
**Char-boundary panic slicing leaked memory in Citrix Bleed parser**

extract_leaked_data builds `text = String::from_utf8_lossy(body)` from raw leaked server memory, then slices `&text[*pos..end]` where `end = (*pos + 64).min(text.len())`. `*pos` is a valid char boundary (from match_indices) but `*pos + 64` is an arbitrary byte offset. Because the body is leaked memory, it routinely contains multi-byte UTF-8 sequences, so when byte offset *pos+64 lands inside a multi-byte char the slice panics ('byte index N is not a char boundary'). The same flaw exists at line 92 (`&text[start..end]` where end can be `(start + 128).min(text.len())`). This crashes precisely on the vulnerable targets the module is designed to exploit.

_Fix:_ Operate on bytes (`body`) and validate boundaries, or clamp end down to a char boundary, e.g. `let mut end = (*pos+64).min(text.len()); while !text.is_char_boundary(end) { end -= 1; }`, or use `text.get(*pos..end)` and skip on None. Apply the same fix to the start..end slice at line 92.


### [panic-oom] src/modules/exploits/ssh/erlang_otp_ssh_rce_cve_2025_32433.rs:208
**Zero-length SSH packet causes index-out-of-bounds panic (Erlang OTP SSH RCE)**

Identical pattern to the libssh module: a 4-byte length is read from the untrusted SSH server, only `> 262144` is rejected, then `vec![0u8; packet_length]` is allocated. If the server returns length 0, `packet_buf[0]` panics on the empty vec. The Erlang OTP SSH target is exactly the kind of host (often a honeypot or instrumented service) that can send crafted short packets, so this is reachable in normal exploit runs.

_Fix:_ Reject packet_length == 0 before allocation/index, e.g. `if !(1..=262144).contains(&packet_length) { bail!(...) }`.


### [panic-oom] src/modules/exploits/ssh/libssh_auth_bypass_cve_2018_10933.rs:163
**Zero-length SSH packet causes index-out-of-bounds panic**

read_ssh_packet reads a 4-byte big-endian length from the attacker-controlled SSH server, rejects only lengths > 262144, then does `vec![0u8; packet_length]` and `read_exact`. When the server sends a length of 0, the vec is empty, read_exact succeeds reading 0 bytes, and `packet_buf[0]` panics with 'index out of bounds: the len is 0 but the index is 0'. A malicious or buggy SSH server can crash the scanner thread on a single response. The checked_sub on padding_len does not help because the panic is the bare index on byte 0 before that.

_Fix:_ After reading packet_length, add `if packet_length == 0 { bail!("empty SSH packet"); }` (or require `packet_length >= 1`) before allocating/indexing, e.g. validate `(1..=262144).contains(&packet_length)`.


### [panic-oom] src/modules/exploits/voip/cve_2025_64328_freepbx_cmdi.rs:256
**Byte-index slice of attacker-controlled response body can panic on UTF-8 boundary**

On the unexpected-status path the module slices the response body by byte index: &body[..body.len().min(500)]. `body` comes from `resp.text().await` and is attacker-controlled. String byte-slicing panics if byte index 500 lands inside a multi-byte UTF-8 sequence (e.g. a response whose 500th byte is mid-character). A malicious or merely non-ASCII target can crash the module/host task with a panic.

_Fix:_ Use a char-safe truncation, e.g. `body.chars().take(500).collect::<String>()` (the pattern already used elsewhere in this codebase), or `&body[..body.floor_char_boundary(500)]`.


### [panic-oom] src/utils/bruteforce.rs:547
**load_credential_file 'streaming' branch still accumulates the entire file into an unbounded Vec**

load_credential_file claims to 'use streaming for large files to avoid OOM with huge credential lists'. When should_stream(path) is true (file >16 MiB) it calls load_lines_batched, but the batch callback pushes every parsed (user,pass) pair into the same in-memory `combos` Vec (line 553) which is then returned whole. There is no size cap on this path (load_lines_batched has no MAX_BYTES guard), so a multi-GB cred file is read fully into RAM — the streaming branch provides zero memory bound and is strictly worse than the eager branch, which at least inherits load_lines' 100 MB cap. Callers across 8 modules do `combos.extend(load_credential_file(&cred_path)?)`, so the unbounded Vec is then merged into the brute-force combo set. Defeats the stated OOM protection.

_Fix:_ Either remove the false streaming branch and just enforce a hard byte/entry cap, or actually stream: hand batches to run_bruteforce_streaming instead of collecting all pairs into one Vec. Add an entry cap (e.g. MAX_COMBOS) and bail/warn when exceeded.


### [panic-oom] src/utils/network.rs:515
**Shared HTTP client sets no response-body size limit (systemic OOM)**

build_http_client_with constructs the reqwest::Client used by virtually every HTTP scanner/exploit but never sets a maximum response body size. Across the codebase there are ~380 direct `.text().await` / `.bytes().await` calls (e.g. s3_bucket_scanner.rs:111, vuln_checker.rs:186, wellknown_scanner.rs, cpanel_exposure.rs, sharepoint_doc_harvest.rs:447, source_map_scanner.rs:161) that buffer the entire response into memory with no cap. A malicious server -- or any host hit during a /16 mass-scan -- can stream gigabytes (or a Content-Length-less chunked stream) and OOM-kill the scanner. The project already provides read_http_body_capped() for exactly this, but the default client does not enforce it, so every direct .text()/.bytes() caller is exposed.

_Fix:_ Either (a) replace direct .text()/.bytes() calls with read_http_body_capped(resp, DEFAULT_BODY_CAP), or (b) wrap responses so the body is capped by default. reqwest has no built-in max_response_size, so the robust fix is to route all body reads through the capped helper and lint/deny raw .text()/.bytes() on untrusted responses.


### [logic-flaw] src/checkpoint.rs:264
**Crash-resume checkpoints are not tenant-scoped — concurrent tenants scanning the same module+target share one checkpoint file**

Unlike workspace/loot/creds/global_options/jobs (which the tenant registry isolates by giving each tenant its own base_dir in TenantData::new), checkpoints have no tenant dimension. `auto_scan_id(module, target)` (line 264) hashes only module+target, and `checkpoint_path` (line 218) always resolves to the process-global `~/.rustsploit/checkpoints/<scan_id>.json`. CheckpointWriter::open / scheduler::open_checkpoint never consult CURRENT_TENANT or RunContext.tenant_id. In multi-tenant API mode, if tenant A and tenant B both run scanners/port_scanner against 10.0.0.0/16, they map to the same scan_id and the same file: tenant B's auto-resume will load and skip the targets tenant A already processed (cross-tenant data leak of which hosts were scanned, and B silently skips hosts it never scanned), their record() appends interleave in one file, and one tenant's finish() deletes the file out from under the other. This is a direct multi-tenant isolation break for the in-scope concern "concurrent access to shared stores / does a background job keep its tenant."

_Fix:_ Fold the resolved tenant id into the scan_id (or into the checkpoint directory path) so each tenant gets its own checkpoint namespace, e.g. auto_scan_id(tenant, module, target) and checkpoint_path under a per-tenant base_dir, mirroring how TenantData isolates the other stores. Shell mode (no tenant) keeps the current global path for backwards compatibility.


### [logic-flaw] src/modules/creds/generic/ssh_bruteforce.rs:423
**SSH wrong-password classified as retryable Error, not AuthFailed — triggers retries, false lockout, wrong stats**

`try_ssh_login` calls `sess.userauth_password(...).context("Authentication failed")?`. The ssh2 crate returns `Err` when authentication is REJECTED (wrong password), so the `?` propagates that as an error. Every wrong-password attempt therefore returns `Err(..)` from `try_ssh_login`, which `run`'s closure maps to `LoginResult::Error { retryable: true }` (lines 142 and 302), never `LoginResult::AuthFailed`. The `Ok(false)` / `sess.authenticated()` branch (line 427) is effectively unreachable for failed auth. Consequences in the engine (src/utils/bruteforce.rs:776-795): (1) every failed password is retried `max_retries` times with exponential backoff (500ms+), massively slowing the brute force; (2) failures are recorded as `error_attempts` and `consecutive_errors`, so `is_lockout_likely(10)` fires after ~10 normal failures and the engine pauses 30s thinking it is being rate-limited; (3) `failed_attempts` stat stays ~0 and the error list fills with normal auth failures. The sibling `ssh_spray.rs::try_ssh_auth` (lines 162-165) demonstrates the correct pattern: `match sess.userauth_password(..) { Ok(_) => Ok(sess.authenticated()), Err(e) => Ok(false) }`.

_Fix:_ Mirror ssh_spray: replace the `?`-propagating call with a match that treats auth rejection as a failed login rather than an error:
    match sess.userauth_password(&user_owned, &pass_owned) {
        Ok(_) => {}
        Err(e) => { tracing::trace!("SSH auth rejected: {e}"); let _ = sess.disconnect(None, "", None); return Ok(false); }
    }
    let _ = sess.disconnect(None, "", None);
    Ok(sess.authenticated())


### [logic-flaw] src/modules/exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass.rs:150
**Config file opened with append (not truncate); corrupts data on re-scan and litters CWD**

leak_config opens config_<host>.bin with .create(true).append(true). On a re-run or repeated host in a mass scan, the new response body is appended to the stale file, producing block-misaligned/corrupted data that decrypt_ecb_nopad then either rejects or silently mis-decrypts. The file is also written into the current working directory (no temp dir), so a /16 scan litters CWD with per-host .bin/.xml files. The 0o600 chmod is applied after creation (TOCTOU window where the file exists with default perms).

_Fix:_ Use .write(true).create(true).truncate(true), write into a unique temp path (tempfile) under a controlled directory, and create the file with restrictive mode atomically (e.g. OpenOptions::mode(0o600) on Unix) rather than chmod-after-create.


### [logic-flaw] src/modules/exploits/webapps/pluck_upload.rs:178
**Pluck login treats any set cookie as successful authentication**

pluck_login() returns Ok (login successful) when `!cookie_str.is_empty()`. cookie_str is built from pre_cookies obtained on the initial GET of admin.php plus any post-login cookies, so the pre-login session cookie alone satisfies the condition. Consequently authentication is declared successful even with a wrong password, and the module proceeds to upload a PHP webshell and then report findings against an unauthenticated/failed session. This both wastes the exploit attempt and can lead to misleading 'upload attempted' notes on non-vulnerable hosts.

_Fix:_ Remove the `!cookie_str.is_empty()` clause. Confirm authentication by a positive signal (presence of an authenticated-only marker such as a logout link / admin nav, or a Set-Cookie that changed the session id), and bail when only the pre-login session cookie is present.


### [logic-flaw] src/modules/scanners/sharepoint_doc_harvest.rs:1312
**Module registered with category-prefixed name produces doubled path 'scanners/scanners/sharepoint_doc_harvest'**

Every other scanner registers with a bare leaf name (e.g. "redis_scanner"), but this module registers as "scanners/sharepoint_doc_harvest". The full module path is built by the registry as format!("{}/{}", e.category, e.name) (src/module.rs:489), so this module's canonical path becomes 'scanners/scanners/sharepoint_doc_harvest'. This breaks the canonical category/name lookup (module.rs:459 'exact match on entry.name with optional category constraint' expects the name to be just 'sharepoint_doc_harvest'), corrupts the displayed/exported module path, and mis-keys the per-module rate-limit bucket (ModuleCtx.module_path).

_Fix:_ Change the registration name to the bare leaf "sharepoint_doc_harvest" to match every other module: crate::register_native_module!(crate::module::Category::Scanners, "sharepoint_doc_harvest", native);


### [logic-flaw] src/pq_channel.rs:628
**Client ML-KEM encapsulation key is taken from the request, never validated against the enrolled authorized key — PQ leg provides no authentication**

process_handshake authorizes a client purely by matching its X25519 identity pubkey in authorized_keys (lines 604-610), but then encapsulates the ML-KEM shared secret to the *client-supplied* request.client_mlkem_ek (lines 626-633) instead of the enrolled authorized.mlkem_ek that was registered for that identity. authorized.mlkem_ek is never read anywhere in the handshake. Consequently the ML-KEM secret ss_mlkem that feeds the IKM is bound to whatever key the caller put in the request, not to the enrolled identity. The only thing that actually authenticates the peer is the classical X25519 identity DH (ss_id). An attacker who can break X25519 (the entire harvest-now/quantum threat the ML-KEM leg exists to defend) can forge ss_id and supply any ML-KEM ek, so the hybrid handshake delivers ZERO post-quantum *authentication* — the registered ML-KEM key is decorative. This defeats the module's stated 'ML-KEM-768 + X25519 hybrid' identity guarantee.

_Fix:_ After matching the authorized identity, compare request.client_mlkem_ek (constant-time) against authorized.mlkem_ek and bail on mismatch; encapsulate to the enrolled key, not the request-supplied one. This binds the KEM leg to the enrolled identity and restores PQ authentication.


### [logic-flaw] src/pq_channel.rs:87
**Server ML-KEM decapsulation key (mlkem_dk) is loaded/stored/zeroized but never used — server's PQ keypair contributes nothing to the handshake**

HostIdentity.mlkem_dk is generated (line 120-130), persisted, loaded (lines 300-306, 324-332), and zeroized on drop, but grep across the whole crate shows no decapsulate call anywhere. The server only ever ENCAPSULATES to the client's ek (line 633); it never decapsulates a client-sent ciphertext. So the server's ML-KEM long-term keypair plays no role in deriving the shared secret. The ML-KEM contribution is one-directional (only the client's KEM key matters), which — combined with the client ek not being checked against the enrolled key (see related finding) — means the server's advertised ML-KEM identity (mlkem_ek/fingerprint) cannot be used to authenticate the server in a post-quantum sense, and the maintained secret dk is dead key material whose only effect is added attack surface and disk-secret exposure.

_Fix:_ Make the handshake mutually KEM-authenticated: have the client encapsulate to the server's enrolled mlkem_ek and send that ciphertext, and have the server decapsulate it with mlkem_dk, mixing that secret into the IKM. Otherwise remove the unused server dk and stop claiming server-side PQ identity.


### [logic-flaw] src/shell.rs:1081
**run -j passes config: None, silently disabling cooperative cancellation of background jobs**

The shell's background-run path calls JOB_MANAGER.spawn(module_path, t, verbose, None). In jobs.rs the spawned task only wraps run_module in run_with_context_target_and_cancel (which installs a RUN_CONTEXT carrying the job's cancel_token) when config is Some(_); with None it calls crate::commands::run_module directly with NO RUN_CONTEXT in scope (jobs.rs:250-260). The scheduler obtains its cancel token via crate::context::cancellation_token().unwrap_or_default() (scheduler.rs:252-253), which reads the current RUN_CONTEXT — absent here, so it gets a fresh, disconnected default token. Consequently the job's cancel_token that `jobs -k <id>` triggers (jobs.rs:360) is never observed by the scheduler's `cancel.is_cancelled()` loop checks (scheduler.rs:508,534,621,798) nor by modules calling crate::context::is_cancelled() (which returns false with no RUN_CONTEXT, context.rs:192). Cooperative cancellation is therefore dead for every shell-spawned background job; killing one relies entirely on the 2-second blind hard-abort in JobManager::kill, which can truncate work mid-write and cannot stop a tight per-host loop promptly. The API path correctly passes Some(module_config) (ws.rs:725-730), proving the intended pattern.

_Fix:_ Pass Some(crate::config::ModuleConfig::default()) instead of None. ModuleConfig::default() has api_mode=false and empty custom_prompts (config.rs:335-339), so interactive shell prompting is unchanged, but the Some(_) branch in jobs.rs routes through run_with_context_target_and_cancel, establishing a RUN_CONTEXT whose cancel field is the job's token — restoring `jobs -k` cooperative cancellation.


### [false-positive] src/modules/creds/generic/http_basic_bruteforce.rs:491
**Any 2xx status treated as valid HTTP Basic credentials**

try_http_login returns Ok(true) for the whole 200..=299 range. Endpoints that do not actually enforce Basic Auth (return 200 to everyone) or that return 200 to an unauthenticated GET on the configured path will report EVERY credential combination as valid, flooding loot with false positives across a mass scan. A correct check must confirm that the unauthenticated request was rejected (401) and that supplying creds changed the outcome.

_Fix:_ First probe without credentials; only treat a 2xx-with-credentials as success when the same path returned 401/403 without credentials. Optionally restrict success to 200/204 and validate a stable content difference.


### [false-positive] src/modules/exploits/cameras/reolink/reolink_rce_cve_2019_11001.rs:69
**Reolink RCE reported solely on HTTP 2xx status with no command-execution confirmation**

After POSTing the TestEmail command-injection payload, the module marks the target Vulnerable whenever status.is_success() (any 2xx). It never confirms the injected command actually ran, never checks the device model/firmware, and the code itself notes the RCE is 'often blind'. Any Reolink camera (or any web endpoint at /api.cgi) that returns 200 to the request — including patched devices that simply accept the TestEmail call and return success — will be reported as RCE-vulnerable. This is a loose status-only detection that will false-positive on benign/patched hosts.

_Fix:_ Confirm execution out-of-band (e.g. inject a command that produces an observable response field or a callback to an operator-controlled listener) and only report Vulnerable when the marker/effect is observed, or downgrade the finding to an informational 'payload delivered, blind RCE unconfirmed' kind rather than FindingKind::Vulnerable.


### [false-positive] src/modules/exploits/cameras/xiongmai_xm530.rs:44
**Xiongmai XM530 reports Vulnerable on ANY TCP response (no content validation)**

The module connects to TCP/34567, sends a fixed 20-byte probe, and then unconditionally pushes a FindingKind::Vulnerable the moment the read future resolves to Ok(Ok(n)) — for ANY n, including n==0 (a peer that simply closes the connection). There is zero validation of the response bytes against the expected Xiongmai XM530 header/protocol. Any TCP service listening on 34567 (or a honeypot, or a firewall that resets) will be reported as 'Xiongmai XM530 detected' and marked Vulnerable, and the host is also recorded via workspace::track_host. This produces guaranteed false positives across a mass scan.

_Fix:_ Validate the response: require n>0 and that the reply bytes match the expected Xiongmai XM530 20-byte response header (e.g. leading 0xFF/0x01 magic and a plausible payload length) before emitting a Vulnerable/Banner finding. Treat a bare connection-accept or empty read as not-vulnerable.


### [false-positive] src/modules/exploits/cowrie/llm_prompt_injection.rs:211
**LLM prompt-injection always reports Vulnerable; computed leak verdict is dropped**

live_inject() computes a real verdict (whether the LLM actually echoed the system context / leaked hostname/username) at lines 134-151 but only PRINTS it and returns Ok(()). The verdict is never propagated back to run(). run() then unconditionally pushes a FindingKind::Vulnerable as long as the SSH connect+auth succeeded — even when no leak occurred (the 'No direct leak observed' branch ran). This is both silent-loss (the leak verdict is computed then dropped) and a false positive: every reachable cowrie SSH endpoint is reported as confirmed-vulnerable regardless of actual exploitation result.

_Fix:_ Return the verdict (e.g. bool or Option<Vec<String>>) from live_inject() and only push a FindingKind::Vulnerable when a leak was actually observed; otherwise push nothing (or a Note).


### [false-positive] src/modules/exploits/cowrie/ssrf_ipv6.rs:280
**IPv6 SSRF module always reports Vulnerable regardless of live result**

run_live_mode() determines whether cowrie actually attempted the outbound IPv6 connection (lines 234-245) but only prints the verdict and returns Ok(()); the ambiguous/failure branch is not propagated. run() then unconditionally pushes a FindingKind::Vulnerable after spawn_blocking succeeds, so any reachable cowrie that authenticates is reported as SSRF-confirmed even when the outbound attempt did not fire. The static-mode bypass results (the `bypasses` vector) are likewise computed and printed but never turned into findings.

_Fix:_ Return a bool/verdict from run_live_mode and only push Vulnerable when stderr/stdout actually evidenced the outbound connection; push the static-mode bypass list as findings when in static mode.


### [false-positive] src/modules/exploits/crypto/geth_dos_cve_2026_22862.rs:86
**Geth DoS reported VULNERABLE for any node identifying as Geth, regardless of version**

The module pushes FindingKind::Vulnerable (and calls report_vulnerable) whenever the web3_clientVersion response merely contains the substring "Geth". No version parsing or comparison against the CVE-2026-22862 fixed version is performed despite the module description claiming it 'parses the version string'. Every reachable Geth JSON-RPC node, including fully patched ones, is flagged as vulnerable, polluting loot/export and the scheduler hit count.

_Fix:_ Parse the version (e.g. `Geth/v1.x.y`) from the clientVersion string and only report Vulnerable when it is below the patched release; otherwise emit a FindingKind::Note (informational fingerprint) instead of Vulnerable.


### [false-positive] src/modules/exploits/dionaea/mysql_sqli.rs:244
**PRAGMA-injection verdict matches any normal MySQL/COM_FIELD_LIST responder**

The vulnerability decision is `if !names2.is_empty() || pkts2.len() > 1`. Any real MySQL server (or any MySQL-protocol honeypot) that answers a COM_FIELD_LIST for the table name returns one or more field-definition packets, making pkts2.len() > 1 true. The module never compares against the benign baseline (names1/pkts1 are computed and discarded). Result: a benign, non-injectable MySQL endpoint is reported as 'PRAGMA injection confirmed'.

_Fix:_ Compare the injected response against the baseline (e.g. require columns that only sqlite_master would yield, or a packet count/shape that differs from the benign table) before declaring injection; otherwise report inconclusive.


### [false-positive] src/modules/exploits/frameworks/apache_tomcat/catkiller_cve_2025_31650.rs:69
**TomcatKiller reports Vulnerable solely because the server supports HTTP/2**

The only gate before pushing a `FindingKind::Vulnerable` is `check_http2_support()` returning true. The module never verifies any memory leak, OutOfMemoryError, or that the server actually degraded — it explicitly tells the operator to monitor memory 'manually via VisualVM'. Any HTTP/2-capable Tomcat (or any HTTP/2 server at all) will be reported as vulnerable to CVE-2025-31650, producing guaranteed false positives.

_Fix:_ Do not emit a Vulnerable finding on HTTP/2 support alone. Either downgrade to FindingKind::Note ('attack executed, verify memory manually') or gate the Vulnerable finding on an observed reachability/crash signal from monitor_server (e.g. target became unreachable mid-attack).


### [false-positive] src/modules/exploits/frameworks/jenkins/jenkins_2_441_lfi.rs:224
**Jenkins LFI reports Vulnerable whenever the HTTP request merely succeeds**

`read_file` -> `listen_and_print` returns `Ok(())` as long as the POST to /cli completes; it prints the parsed output but never signals whether any file content was actually leaked (it even prints 'File not found.' / 'Could not read file.' and still returns Ok). `run` then unconditionally pushes a `FindingKind::Vulnerable` Finding ('Confirmed CVE-2024-23897'). Any reachable Jenkins (patched or not, with the CLI endpoint present) is reported as vulnerable. Contrast jenkins_cli_rce_cve_2024_23897.rs which correctly requires the 'No such agent "..."' signature with non-empty extracted lines.

_Fix:_ Have read_file/listen_and_print return whether the 'No such agent "..."' expansion actually produced leaked lines, and only push the Vulnerable Finding when leaked content is confirmed (mirror the gating in jenkins_cli_rce_cve_2024_23897.rs).


### [false-positive] src/modules/exploits/frameworks/php/cve_2025_51373_php_rce.rs:167
**PHP CGI RCE flagged on any HTTP 200 with a non-empty body**

The Vulnerable Finding (and loot storage) is gated only on `status == 200 && !body.is_empty()`. The injected payload uses a literal `%AD` in the query string and the command output is never checked for a canary/marker. Any benign PHP page, default IIS/Apache page, or static file returning 200 with content will be reported as 'PHP CGI argument injection RCE confirmed (CVE-2025-51373)'. The sibling module cve_2024_4577 correctly verifies a unique marker ('VULNERABLE_CVE_2024_4577'); this one does not.

_Fix:_ Embed a unique canary in the PHP payload (e.g. `echo 'RS-CVE-2025-51373-<rand>';`) and only push the Finding / store loot when `body.contains(canary)`. A bare 200 must not be treated as proof.


### [false-positive] src/modules/exploits/frameworks/wsus/cve_2025_59287_wsus_rce.rs:339
**WSUS RCE flagged on bare HTTP 500, ignoring the deserialization marker check**

The Vulnerable Finding is pushed whenever the reporting endpoint returns HTTP 500. `print_exploit_result` correctly looks for 'BinaryFormatter'/'SerializationException' in the body to decide 'LIKELY VULNERABLE', but the Finding push ignores that and only checks `status == 500`. Any ASP.NET endpoint returns 500 on a malformed SOAP body (and the built-in payload is an admittedly broken placeholder gadget), so any non-patched-or-not WSUS-like .asmx that errors out is reported as confirmed RCE. False positives on benign servers are near-certain.

_Fix:_ Only push the Vulnerable Finding when status == 500 AND `body.contains("BinaryFormatter") || body.contains("SerializationException")`. Bare 500 should at most be a FindingKind::Note suggesting manual/OOB verification.


### [false-positive] src/modules/exploits/network_infra/apache_modssl_bypass_cve_2025_23048.rs:43
**CVE-2025-23048 'detection' fires on any Apache HTTPD via Server header prefix alone**

The vulnerability decision is `server.to_lowercase().starts_with("apache")`. Apache HTTPD is one of the most common web servers in existence, and this matches every Apache instance regardless of whether mod_ssl is loaded, the version is affected, TLS 1.3 vhost resumption is configured, or client-cert auth is even in use. The module will flag essentially every Apache host on the internet as relevant to CVE-2025-23048, producing massive false positives during a scan.

_Fix:_ At minimum gate on mod_ssl presence (Server header substring 'mod_ssl' or 'OpenSSL') AND an affected version parse, and downgrade the wording to an informational fingerprint rather than implying the CVE applies. Do not treat a bare 'Apache' Server header as a vulnerability signal.


### [false-positive] src/modules/exploits/network_infra/hpprocurve_snac_inject.rs:36
**"PHP Code Injection" module reports Vulnerable on a bare 'snac'/'procurve' substring, ignoring status and never testing injection**

The module is titled 'HP ProCurve SNAC Domain Controller PHP Code Injection' but performs no injection test at all. It GETs /snac/ and, if the body contains the substring 'snac' OR 'procurve' (case-insensitive), it pushes a `FindingKind::Vulnerable` finding. It also discards the HTTP status returned by `http_get_status_body` (binds it as `_`), so a 404/403/500 error page that merely mentions 'procurve' is reported as vulnerable. Any host whose error or product page contains 'procurve' is falsely flagged as exploitable for PHP code injection.

_Fix:_ Either implement the actual injection probe and confirm code execution before reporting, or downgrade this to a detection/fingerprint Finding (FindingKind::Info) and tighten the match (require a 200 status and a SNAC-specific marker, not the generic 'procurve' substring). Do not assert Vulnerable from detection alone.


### [false-positive] src/modules/exploits/network_infra/qnap/qnap_qts_rce_cve_2024_27130.rs:96
**QNAP RCE check reports VULNERABLE on any 5xx or empty body**

The vulnerability decision is `if status.is_server_error() || text.is_empty()`. Any host that returns a 5xx (a WAF/reverse-proxy 502/503, a transient backend error, a generic 500) OR returns an empty 200 body is flagged as VULNERABLE to CVE-2024-27130 and a Finding is pushed. This is a wildly loose detector: empty bodies and 5xx are extremely common on benign, non-QNAP, or already-patched hosts. The earlier fingerprint only bails on a literal 404, so essentially any reachable HTTP server that is not a QNAP NAS can be reported vulnerable. Under mass-scan this produces large numbers of false Vulnerable findings in loot/export.

_Fix:_ Require positive evidence that the target is actually QNAP QTS (e.g. fingerprint the share.cgi/QTS banner, QNAP-specific headers or body markers) AND that the overflow specifically crashed the CGI (e.g. connection reset / 502 from the CGI handler specifically, baseline-vs-overflow differential). Do not treat a bare empty body or generic 5xx as proof of the buffer overflow.


### [false-positive] src/modules/exploits/network_infra/vmware/vcenter_rce_cve_2024_37079.rs:153
**vCenter CVE-2024-37079 version check matches patched releases**

The vulnerable-version test is `["7.0","8.0.0","8.0.1"].iter().any(|v| version_detected.starts_with(v))`. `starts_with("7.0")` matches every 7.0.x build including the fixed 7.0 U3r, and `8.0.0`/`8.0.1` prefix matching ignores build numbers entirely. The advisory fix is keyed to specific build numbers (7.0 U3r / 8.0 U2d), and the module even parses `<build>` (line 147-151) but never uses it in the decision. Result: a fully patched vCenter 7.0 U3r/8.0 U2d is reported as VULNERABLE and a Finding is pushed.

_Fix:_ Incorporate the parsed `<build>` number and compare against the fixed build thresholds (7.0 U3r, 8.0 U2d) rather than prefix-matching the marketing version. Mark below-threshold builds vulnerable and at/above-threshold builds not vulnerable.


### [false-positive] src/modules/exploits/network_infra/vmware/vcenter_rce_cve_2024_37079.rs:173
**vCenter CVE-2024-37079: bare HTTP 500 from /sdk/ reported as vulnerable**

If the SOAP POST to `/sdk/` returns HTTP 500, the module declares the target VULNERABLE and pushes a Finding with indicator `http_500_dcerpc`. A 500 from a SOAP endpoint is the normal response to a malformed/unauthenticated SOAP body and indicates nothing about the DCERPC heap overflow (which the module explicitly does NOT send — see the header comment). Any vCenter (patched or not), or any unrelated SOAP/HTTP server returning 500, is flagged vulnerable.

_Fix:_ Remove the HTTP-500-equals-vulnerable branch. Since the module only does version detection, gate the Finding solely on a confirmed vulnerable build number, or downgrade the 500 case to a Note/Banner rather than FindingKind::Vulnerable.


### [false-positive] src/modules/exploits/routers/netgear/netgear_r6700v3_rce_cve_2022_27646.rs:81
**Netgear circled reports VULNERABLE for any open TCP port 8888**

A FindingKind::Vulnerable finding for CVE-2022-27646 is pushed solely because tcp_connect_str succeeded — i.e. the TCP port is open. There is no validation that the listening service is actually the circled daemon or that it is the vulnerable version. Any host with an open port 8888/8889/8890 (extremely common for proxies, alt-HTTP, etc.) is flagged as 'potentially vulnerable to CVE-2022-27646', polluting results across a mass scan.

_Fix:_ Fingerprint the circled binary protocol (validate a known response signature) before reporting; if only port-open is established, emit FindingKind::OpenPort/Note rather than Vulnerable.


### [false-positive] src/modules/exploits/routers/palo_alto/panos_globalprotect_rce_cve_2024_3400.rs:172
**RCE confirmed on loose 'root' substring in response body**

The command-output check `body.contains("uid=") || body.contains("root")` flags command execution and pushes a Vulnerable finding when the /ssl-vpn/hipreport.esp response merely contains the substring 'root'. Generic PAN-OS HTML/error pages routinely contain 'root' (e.g. 'document root', 'rootCA', 'Reboot'), so benign hosts are reported vulnerable. The injected `id` command would not even produce 'root' unless running as root, making this an unreliable indicator.

_Fix:_ Match a unique injected marker (e.g. echo of a random token) or a precise `uid=NNN(...) gid=` regex rather than the bare word 'root'.


### [false-positive] src/modules/exploits/routers/palo_alto/panos_globalprotect_rce_cve_2024_3400.rs:228
**Time-based RCE confirmation has no baseline; any slow host (>=4s) reported VULNERABLE**

Phase 3 sends a `$(sleep 5)` payload and concludes the target is vulnerable to CVE-2024-3400 if the single request takes >= 4 seconds, pushing a Vulnerable finding. There is no control/baseline timing measurement, so any naturally slow, overloaded, or high-latency host that takes >=4s to respond is reported as confirmed RCE. With a 15s client timeout, slow hosts trivially trip the threshold.

_Fix:_ Measure a baseline (no-sleep) request time first and require the sleep-payload request to exceed baseline + ~5s (the injected delay), repeated to reduce noise, before reporting vulnerable.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_auth_bypass_rce_cve_2023_34644.rs:127
**Auth-bypass 'success' triggered by generic 'token'/'session'/'admin' substrings**

bypass_success is true if the response contains 'token', 'session', 'uid=', a result:0 field, or 'admin' (without 'error'/'fail'). Nearly every web login endpoint mentions 'session'/'token' or contains 'admin' on its login page, so this reports a confirmed CVE-2023-34644 Vulnerable finding (pushed at line 268) on benign hosts.

_Fix:_ Tighten detection to a positively authenticated state — e.g. parse the JSON and require a specific success/result field plus a usable session token issued for the unauthenticated request, and verify it grants privileged access before reporting vulnerable.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_reyee_ssrf_cve_2024_48874.rs:127
**Ruijie Reyee SSRF flagged VULNERABLE on any HTML page (detect_ssrf_signs too loose)**

detect_ssrf_signs() returns ssrf_detected=true if the response simply contains `<!DOCTYPE` or `<html` (or mentions apache/nginx/Server:/127.0.0.1/internal). test_post_endpoints returns Ok(text) whenever ssrf_detected is true, and run() then pushes a FindingKind::Vulnerable CVE-2024-48874. So merely retrieving the device's own login HTML page marks it vulnerable. test_get_endpoints is worse: `if ssrf_detected || text.len() > 500` treats any GET endpoint returning >500 bytes (no "error"/"404") as 'Possible SSRF', also pushed as Vulnerable. Mass-scanning any web host will yield CVE confirmations.

_Fix:_ Confirm SSRF out-of-band (OAST callback) or by injecting a unique internal-only marker URL and verifying that marker's distinctive content is reflected — not generic HTML/length heuristics. Remove the `|| text.len() > 500` shortcut and the `<html>`-presence sign.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_rsr_router_ci_cve_2024_31616.rs:110
**RSR auth treated as success on any non-401 status, then bogus credentials stored as loot**

authenticate() returns Ok when status.is_success() OR the body merely contains 'success'/'token', and even returns Ok on arbitrary non-401 statuses (lines 116-117 'continuing anyway'). run() then unconditionally pushes a FindingKind::Credential record (line 249) with the supplied username/password whenever authenticate returns Ok. This records unverified credentials as valid loot for hosts that returned HTTP 302/403/500 or whose page simply contains the word 'token'.

_Fix:_ Only treat authentication as successful on a concrete signal (session cookie set, explicit success token in a parsed JSON field). Do not push a Credential finding unless auth is positively confirmed; remove the 'continue anyway' Ok path.


### [false-positive] src/modules/exploits/routers/tplink/tapo_c200_vulns.rs:82
**Tapo scanApList info-leak reported on any HTTP 2xx**

exploit_scan_ap_list pushes a Vulnerable CVE-2025-14300 finding whenever the POST returns status.is_success(), without checking that the JSON actually contains a 'result' AP list. The Tapo cloud protocol normally requires an encrypted handshake; a benign error response (e.g. {"error_code":-40401}) is still HTTP 200 and would be reported as a confirmed pre-auth info leak.

_Fix:_ Parse the JSON and require a populated 'result' AP list (and absence of an error_code) before reporting the info leak as vulnerable.


### [false-positive] src/modules/exploits/routers/tplink/tapo_c200_vulns.rs:182
**Tapo hijack/DoS findings pushed unconditionally; a request error is treated as success**

exploit_wifi_hijack, exploit_dos_onvif, and exploit_dos_https push Vulnerable findings after merely sending the payload, with no confirmation of effect. exploit_wifi_hijack explicitly interprets a request error as success ('Device likely switched networks', lines 176-180) and still records the finding. So an unreachable host or one that simply errors is reported as successfully hijacked/DoSed.

_Fix:_ Do not record Vulnerable on a send error. For destructive actions, confirm effect where possible (e.g. re-query device state) before recording; otherwise downgrade unconfirmed sends to a Note.


### [false-positive] src/modules/exploits/routers/tplink/tp_link_vn020_dos.rs:173
**VN020 DoS records VULNERABLE even if every PoC request errored**

After the attack loop ends, a FindingKind::Vulnerable finding ('attack delivered') is pushed unconditionally. Errors from both PoCs are logged (lines 164-169) but ignored, so a host that never accepted a single request (down/filtered/non-existent) is still reported as a confirmed CVE-2024-12342 DoS.

_Fix:_ Track whether at least one PoC request reached the target, and verify post-attack reachability loss (as tplink_wr740n_dos does) before recording the DoS as confirmed.


### [false-positive] src/modules/exploits/routers/tplink/tplink_archer_c2_c20i_rce.rs:74
**Archer C2/C20i RCE reported on trigger endpoint returning HTTP 2xx**

A FindingKind::Vulnerable finding for CVE-2017-8220 is pushed whenever the trigger POST to /cgi?7 returns status.is_success(). This is blind RCE so no output is expected, but recording a confirmed vulnerability based purely on a 200 status means any device (or unrelated web server) that returns 2xx for that path is flagged vulnerable.

_Fix:_ Use an out-of-band callback or a measurable side effect (e.g. inject a command that pings the operator's listener) to confirm execution; otherwise downgrade to a Note that the payload was accepted.


### [false-positive] src/modules/exploits/routers/tplink/tplink_archer_rce_cve_2024_53375.rs:134
**Archer CVE-2024-53375 RCE reported on any HTTP 2xx from exploit endpoint**

A Vulnerable finding is pushed solely on status.is_success() for the smart_network exploit endpoint, with no verification that the injected command ran. The auth step is best-effort (it proceeds even when no stok token was extracted, line 92), so the finding can be produced for any host returning 200 to the unauthenticated path.

_Fix:_ Require positive proof of command execution (echo marker / OOB callback) before reporting Vulnerable; treat a bare 200 as a Note.


### [false-positive] src/modules/exploits/routers/tplink/tplink_ax1800_rce_cve_2024_53375.rs:129
**AX1800 NTP injection prints 'Target is VULNERABLE' and records finding on HTTP 2xx alone**

After authentication, the module pushes a FindingKind::Vulnerable CVE-2024-53375 finding and prints 'Target is VULNERABLE' whenever the exploit POST returns status.is_success(), with no verification that the NTP-field command injection actually executed. A patched device that still returns 200 to the config write is reported vulnerable.

_Fix:_ Confirm injection via an echo marker or out-of-band callback before declaring vulnerable; a successful config write is not proof of code execution.


### [false-positive] src/modules/exploits/routers/tplink/tplink_deco_m4_rce.rs:104
**Deco M4 HTTP Basic auth 'success' on any 200 records default admin:admin as valid creds**

When LuCI login fails, the fallback does GET / with basic_auth and treats status.is_success() as successful authentication, pushing a Credential finding with admin:admin. Most router root pages return 200 for GET / regardless of basic-auth correctness (the device may not enforce basic auth on /), so bogus default credentials are recorded. Additionally the diagnostics injection finding (line 172) is pushed on a bare 200 with no command-execution verification.

_Fix:_ Verify basic auth against an endpoint that returns 401 when unauthenticated (compare authed vs unauthed responses); gate the diagnostics RCE finding on confirmed command output rather than a 200.


### [false-positive] src/modules/exploits/routers/ubiquiti/ubiquiti_edgerouter_ci_cve_2023_2376.rs:72
**EdgeRouter login 'success' on any 2xx/3xx; stores default ubnt:ubnt as valid credentials**

Login is treated as successful when the response status is_success() OR is_redirection(). EdgeRouter's login form returns a 302 redirect even on failed authentication, so this records a FindingKind::Credential (line 78) for any host that answers with 2xx/3xx — using the default ubnt/ubnt credentials when the operator does not override them. False credential loot is produced for non-EdgeRouter and unauthenticated hosts.

_Fix:_ Confirm authentication via a positive signal (session cookie set, access to an authenticated-only endpoint) rather than 2xx/3xx, before recording credentials.


### [false-positive] src/modules/exploits/routers/ubiquiti/ubiquiti_edgerouter_ci_cve_2023_2376.rs:131
**Command injection reported VULNERABLE on any HTTP 200 from the endpoint**

The CVE-2023-2376 command-injection Vulnerable finding is pushed solely because client.post(endpoint) returned status.is_success(). No verification that the injected command executed. Any host returning 200 on /api/edge/batch.json (or similar) is flagged as vulnerable.

_Fix:_ Inject a unique echo marker and confirm it in the response (or use an out-of-band callback) before reporting Vulnerable; a 200 alone should be a Note at most.


### [false-positive] src/modules/exploits/routers/zte/zte_zxv10_h201l_rce_authenticationbypass.rs:304
**ZTE config-leak/credential/injection findings pushed unconditionally regardless of actual result**

exploit() pushes a Vulnerable 'config leak retrieved' finding (line 304) right after leak_config returns Ok, but leak_config returns Ok even when no body was written (the `\r\n\r\n` split at line 148 may fail and the file is never created — no error). It then pushes a Credential finding (line 313) using username/password that default to 'unknown' when the XML markers aren't found (lines 193/200), and a DDNS command-injection Vulnerable finding (line 328) after set_ddns merely POSTs without inspecting the response. Any host that accepts a TCP connection therefore yields confirmed config-leak + credential + RCE findings.

_Fix:_ Gate each finding on positive evidence: verify the leaked config body is non-empty and decodes; only push a Credential finding when extracted username/password are non-empty and not 'unknown'; verify command execution before claiming the DDNS injection succeeded.


### [false-positive] src/modules/exploits/telnet/telnet_auth_bypass_cve_2026_24061.rs:442
**Auth-bypass reported VULNERABLE on any server that negotiates NEW_ENVIRON**

quick_check() returns true if, after sending `IAC WILL NEW_ENVIRON`, the server replies with `IAC DO NEW_ENVIRON` or `IAC SB NEW_ENVIRON` anywhere in the first read. Offering/accepting the NEW_ENVIRON option is standard, RFC-1572 telnet negotiation supported by the vast majority of telnet daemons (including fully patched ones). The module then pushes FindingKind::Vulnerable for CVE-2026-24061 purely on this negotiation, so virtually every telnet server is flagged vulnerable.

_Fix:_ Negotiation support alone is not the vulnerability. Either fingerprint the vulnerable inetutils-telnetd version, or actually attempt the `-f <user>` USER NEW_ENVIRON bypass and confirm a shell/prompt is reached before pushing a Vulnerable finding; otherwise report only a Note.


### [false-positive] src/modules/exploits/vnc/libvnc_websocket_overflow.rs:118
**WebSocket overflow flagged VULNERABLE on any normal connection teardown**

After the WS upgrade succeeds, the module treats nearly every outcome as 'heap overflow likely': a write error on the frame, a write error on the subsequent ping, a 0-byte read (clean EOF), or a pong read timeout all push a FindingKind::Vulnerable finding. A normally-behaving (or simply busy / firewalled) server that closes the idle WebSocket, or any transient network drop, will be reported as vulnerable. The only non-vulnerable branch is the case where the server still answers the ping. This will report benign WS-capable servers as RCE-vulnerable, especially across a mass scan.

_Fix:_ An overflow PoC that sends a 0-byte body cannot reliably distinguish a crash from a normal idle-close. Require a stronger oracle (e.g. confirm the port is dead via a fresh reconnect, like the decompression-bomb module does) before emitting Vulnerable, and treat ordinary EOF/timeout as inconclusive rather than vulnerable.


### [false-positive] src/modules/exploits/vnc/tightvnc_ft_path_traversal.rs:64
**Reports TightVNC FT path-traversal VULNERABLE on ANY RFB server**

The module's only check is whether the 12-byte banner starts with "RFB ". Every VNC server (RealVNC, TigerVNC, UltraVNC, x11vnc, libvncserver, etc.) sends an `RFB 003.xxx` banner, so this calls report_vulnerable() (which prints '[+] VULNERABLE', adds a workspace note, and stores loot) and pushes a Finding for literally any reachable VNC host — including ones that are not TightVNC and do not expose the file-transfer extension. The module name and the loot record both assert a path-traversal vulnerability that was never tested. On a /16 scan every live VNC port becomes a false 'vulnerable' hit polluting loot/export and scheduler hit-counts.

_Fix:_ Do not report Vulnerable / call report_vulnerable on a bare RFB banner. At minimum downgrade to FindingKind::Banner only (the second Finding push already uses Banner), drop the report_vulnerable() call, and gate any 'vulnerable' claim behind an actual TightVNC fingerprint + file-transfer capability probe.


### [false-positive] src/modules/exploits/vnc/x11vnc_dns_injection.rs:77
**Unconditionally reports x11vnc DNS injection VULNERABLE with zero verification**

The module never connects to the target or checks anything. It only parses host/port, prints a manual setup recipe, then unconditionally pushes a FindingKind::Vulnerable for the target. The message even says 'setup recipe generated', yet it is recorded as a confirmed vulnerability. Running this against any host (or a CIDR) yields a guaranteed false 'vulnerable' finding for every target. Rank is Manual, but a Manual rank does not justify emitting a Vulnerable Finding without evidence.

_Fix:_ Do not push a Vulnerable Finding for a recipe-only module. Either push FindingKind::Info, or push no Finding at all and return ModuleOutcome::ok() after printing the recipe.


### [false-positive] src/modules/exploits/vnc/x11vnc_env_injection.rs:75
**Unconditionally reports x11vnc RFB_CLIENT_IP env injection VULNERABLE with zero verification**

Same defect as x11vnc_dns_injection: no network interaction, no probe, no fingerprint. The module prints a setup recipe and then unconditionally pushes a FindingKind::Vulnerable finding ('setup recipe generated'). Every target this is run against is falsely marked vulnerable and the result reaches loot/export/scheduler hit-counts.

_Fix:_ Replace FindingKind::Vulnerable with FindingKind::Info (or push no Finding) for this recipe-only Manual module.


### [false-positive] src/modules/exploits/voip/cve_2025_64328_freepbx_cmdi.rs:368
**Command injection reported VULNERABLE on any 2xx/500 filestore response**

exploit_filestore() returns Some(body) for any success status OR HTTP 500 (lines 240-251), and run() unconditionally pushes a FindingKind::Vulnerable whenever the result is Some(_) (lines 359-373). There is no verification that the injected command actually executed (no marker echo, no output capture, no timing/oracle). A patched FreePBX, a generic 200 page, or any 500 error from the AJAX endpoint will be reported as a confirmed command-injection vulnerability, producing false positives across benign/authenticated hosts.

_Fix:_ Inject a command with a unique random marker (e.g. `echo <nonce>`) and only push a Vulnerable finding if the marker is reflected in the response or via an out-of-band/blind oracle; otherwise downgrade to a Note that the payload was delivered but execution was unconfirmed.


### [false-positive] src/modules/exploits/voip/magnusbilling_ssrf_cve_2023_30258.rs:56
**Path-traversal 'leak' detection matches almost any non-HTML success response**

The leak condition is `status.is_success() && body.len()>10 && (body.contains("root:") || body.contains("[") || !body.contains("<html"))`. The `body.contains("[")` and `!body.contains("<html")` clauses match essentially any JSON, plain-text, error, or redirect-stripped response over 10 bytes. A benign 200 response that isn't a full HTML document (e.g. a JSON API error, a short text page) is reported as a confirmed `/etc/passwd` leak and pushed as a Vulnerable finding with return-on-first-hit.

_Fix:_ Require a strong file-content signature for the requested file (for /etc/passwd: a line matching `root:.*:0:0:` via regex), not generic punctuation or absence of an <html> tag.


### [false-positive] src/modules/exploits/voip/xorcompbx_rce.rs:66
**RCE confirmed by reflecting the supplied command string (body.contains(&cmd))**

Command-injection success is declared if the response body contains the literal command string the operator supplied (`body.contains(&cmd)`), with default cmd="id". The two-character string "id" appears in countless benign HTML pages (e.g. id=, void, valid, candidate, hidden). Any page that echoes the URL/query or simply contains the substring will be flagged as confirmed RCE. Combined with the loose `body.contains("root:")` check, this reports VULNERABLE on non-vulnerable hosts.

_Fix:_ Drop the `body.contains(&cmd)` clause; require a strong execution oracle such as `uid=` AND `gid=` from `id`, or echo a random nonce and match the nonce, not the command name.


### [false-positive] src/modules/exploits/webapps/azuriom_csti_cve_2025_65271.rs:62
**CSTI reported as vulnerable merely because payload is reflected**

After sending `{{7*7}}`, the module computes `reflected = resp_body.contains(CSTI_CANARY)` and then `if evaluated || reflected` pushes a Vulnerable Finding. Plain reflection of `{{7*7}}` in a search-results page is normal, benign echo of user input — it is NOT client-side template injection. Any site that echoes the query string (a 404 page, a search box that shows the term, an error message) will be flagged as vulnerable to CVE-2025-65271. Only the `evaluated` branch (output 49 with the canary absent) is sound.

_Fix:_ Only treat `evaluated` as a confirmed finding. Demote the bare-reflection case to an informational note (or drop it), since reflecting the literal template string is the opposite of template evaluation.


### [false-positive] src/modules/exploits/webapps/cbitrix_translate_upload_cve_2025_67887.rs:76
**Any non-404 status on probe paths reports CVE-2025-67887 as vulnerable**

The module probes three Bitrix admin paths and counts a 'hit' for any status code that is not exactly 404 (`if s != 404 { hits += 1; }`). If `hits > 0` it pushes a Vulnerable Finding for the arbitrary-file-upload CVE. A 401/403 (auth required), 500, 302 redirect to login, or a generic catch-all 200 landing page all count as hits, so a hardened/patched Bitrix (or any server that doesn't 404 these paths) is reported as vulnerable. There is no fingerprint of Bitrix and no proof the Translate module is exploitable.

_Fix:_ Require a 200 response AND a Bitrix/Translate-module-specific body marker before counting a hit; downgrade mere 'endpoint exists' to a Note, and gate the Vulnerable finding on actual upload confirmation.


### [false-positive] src/modules/exploits/webapps/cleo_harmony_filewrite_cve_2024_55956.rs:58
**HTTP 200 alone flags Cleo CVE-2024-55956 as vulnerable**

For each probed path the module pushes a Vulnerable Finding if the `Server` header contains "cleo" OR the status is 200 (`if server.to_lowercase().contains("cleo") || s == 200`). The `|| s == 200` clause means any web server that returns 200 for `/Synchronization` or `/Cleo/Lexi/Synchronization` (including unrelated apps with catch-all routing) is reported as the unauthenticated file-write RCE. No Cleo-specific content verification or actual file-write test is performed.

_Fix:_ Drop the `|| s == 200` shortcut; require the Cleo `Server` banner or a Cleo-specific body signature, and confirm the autorun directory behaviour before declaring the file-write vulnerability.


### [false-positive] src/modules/exploits/webapps/craftcms_rce_cve_2025_47726.rs:139
**SSTI confirmed on bare substring "49" in response body**

The benign SSTI probe sends `{{7*7}}` and concludes SSTI is confirmed (and pushes a Vulnerable Finding plus emits a `vulnerable:CVE-2025-47726` event) merely because the response body contains the substring "49" anywhere. "49" appears in countless benign responses (timestamps, numeric IDs, pixel sizes, hex/asset hashes, content lengths, year/version strings), so this will report a 9.8 RCE on hosts that never evaluated the template. It does not verify that the literal `{{7*7}}` was absent (proving evaluation) or that "49" appears where the payload was reflected.

_Fix:_ Use a unique randomized arithmetic canary (e.g. {{91823*7}} expecting the exact product) and require both that the computed product is present AND the raw `{{...}}` payload is absent from the response before declaring SSTI.


### [false-positive] src/modules/exploits/webapps/flowise_js_inject_cve_2025_59528.rs:335
**Flowise reports RCE from an over-broad output heuristic and bare 200/500 responses**

has_system_output matches any response line that merely contains ':' and '/' and not 'http' (e.g. any timestamp, path, or JSON value), and output_confirmed additionally fires on `predict_status==200 && !body.is_empty() && !body.contains("error") && body.len()>2`. Combined with the 500/'sandbox'/'vm2' branch, a benign Flowise returning a normal prediction (200 with any non-trivial JSON) or any 500 is reported as a confirmed/likely JS-injection RCE.

_Fix:_ Drop the `':' && '/' && !http` heuristic and the bare-200 output_confirmed clause; require the marker or uid=/root: for a Vulnerable verdict. Demote the 500/sandbox-keyword branch to a Note.


### [false-positive] src/modules/exploits/webapps/hpe_oneview_rce.rs:266
**HPE OneView reports RCE on any 2xx or HTTP 500 response**

After POSTing a hand-rolled (and non-functional, see build_java_deser_payload) 'Java serialized' blob, the module treats `status.is_success() || status.as_u16() == 500` as a confirmed deserialization RCE and pushes a Vulnerable finding. Any benign endpoint that returns 200 (e.g. a normal REST response, an auth error page rendered 200) or 500 (a routine server error from the malformed body) is reported as exploited. The payload cannot actually achieve RCE, so a positive here is always a false positive.

_Fix:_ Only push a Vulnerable finding when has_rce_output (uid=/root:/www-data) is actually present. Demote the 2xx/500/deser-error cases to FindingKind::Note (informational) and require out-of-band/marker confirmation for a Vulnerable verdict.


### [false-positive] src/modules/exploits/webapps/hpe_oneview_rce.rs:291
**HPE OneView reports RCE when the request merely times out**

In the error arm, `e.is_timeout()` is treated as 'command may have caused delay' and pushes a Vulnerable finding. With TIMEOUT_SECS=15, any slow or unresponsive host (extremely common at scale / over the internet) is falsely reported as deserialization RCE. Network latency, not exploitation, drives this verdict.

_Fix:_ Do not infer exploitation from a timeout. Log the timeout as a Note at most, or drop it entirely; a generic gadget chain returning command output is the only safe confirmation.


### [false-positive] src/modules/exploits/webapps/ictbroadcast_rce.rs:226
**ICTBroadcast reports RCE on any 2xx from three endpoints**

When no command output is found, the module falls back to `campaign_status.is_success() || orig_status.is_success() || form_status.is_success()` and pushes a Vulnerable 'RCE payload delivered' finding. A correctly functioning ICTBroadcast (or any host with a catch-all 200) that simply accepts the campaign-create/originate/form POST and returns 2xx is reported as RCE without any evidence the injected command ran.

_Fix:_ Restrict the Vulnerable finding to the has_rce_output branch (uid=/root:/www-data/RSPLOIT_RCE). Demote the 'HTTP success' fallback to a Note, since 2xx alone does not demonstrate command execution.


### [false-positive] src/modules/exploits/webapps/invoiceninja_inject.rs:227
**Invoice Ninja reports RCE on HTTP 500 or any body containing 'error'**

When the injected PHP marker is absent, the module still pushes a Vulnerable finding if `preview_status == 500 || combined_output.to_lowercase().contains("error")`. The substring 'error' matches virtually any JSON error payload, validation message, or even a benign field named 'error', and a 500 from a benign/patched server is common. This reports template-injection RCE on hosts where the payload provably did not execute (its marker was not reflected).

_Fix:_ Gate Vulnerable on `combined_output.contains(&marker)` (or uid=/root:). Demote the 500/'error' heuristic to a Note; an error response is not proof of code execution.


### [false-positive] src/modules/exploits/webapps/langflow_rce_cve_2025_3248.rs:222
**Langflow reports RCE purely from a 2xx status on the validate endpoint**

The module declares CVE-2025-3248 'code-validation RCE confirmed' when `exploit_status.is_success() || output_status.is_success()`. The /api/v1/validate/code endpoint returns HTTP 200 on patched (>=1.3.0) and benign servers too — it validates code and returns results regardless of whether exec() ran. No command-output / marker check gates the finding, so any reachable Langflow (vulnerable or not) is reported as RCE.

_Fix:_ Use the build_output_payload subprocess result: require the command's stdout (e.g. the operator command echo / uid=) to appear in output_body before declaring Vulnerable. A bare 2xx should be a Note at most.


### [false-positive] src/modules/exploits/webapps/laravel_livewire_rce_cve_2025_47949.rs:214
**Laravel Livewire reports RCE on any non-empty 2xx body**

A Vulnerable deserialization-RCE finding is pushed whenever `exploit_status.is_success() && !exploit_body.is_empty()`. The injected payload (build_livewire_payload) is malformed JSON (the `updates` array/object braces are unbalanced and the JSON is truncated), so it cannot actually trigger deserialization; meanwhile a benign Livewire endpoint commonly answers 2xx with a CSRF/validation error body. Any such host is falsely reported as RCE.

_Fix:_ Require positive evidence of code execution (a unique marker echoed back, or command output) before the Vulnerable verdict; fix the payload JSON so the probe is well-formed. Treat a bare 2xx response as a Note.


### [false-positive] src/modules/exploits/webapps/librenms_inject.rs:261
**LibreNMS pushes a Vulnerable finding even when the payload produced no evidence**

The else branch — reached only when neither the unique marker nor uid=/root: was found in the response — still pushes a FindingKind::Vulnerable 'payload delivered' finding. Since the marker is injected into the community field and a successful store would reflect it on the GET, reaching this branch means the injection did NOT take (HTTP 4xx, sanitized, or no rendering). A benign/patched LibreNMS with valid API auth and at least one device is therefore always reported Vulnerable.

_Fix:_ Make the else branch emit FindingKind::Note (or no finding). Reserve Vulnerable for the branch where the marker / command output is actually observed.


### [false-positive] src/modules/exploits/webapps/limesurvey_filedownload.rs:54
**LimeSurvey file-download reports arbitrary file read on almost any 200 response**

The success condition is `status.is_success() && !body.is_empty() && body.len()>10 && (body.contains("root:") || body.contains("[") || !body.contains("<html"))`. The `body.contains("[")` alternative matches nearly any JSON/JS/page, and `!body.contains("<html")` matches any non-HTML 200 body (JSON APIs, plain text, '<!DOCTYPE html>' without lowercase '<html', etc.). The module never requires that the requested file's content (e.g. 'root:' for /etc/passwd) is actually present, so benign LimeSurvey hosts are reported as leaking /etc/passwd.

_Fix:_ Validate that the response actually contains content specific to the requested file (e.g. for /etc/passwd require a /^[^:]+:[^:]*:\d+:\d+:/ line). Remove the `contains("[")` and `!contains("<html")` alternatives entirely.


### [false-positive] src/modules/exploits/webapps/mantisbt_exec.rs:440
**MantisBT config-injection reports VULNERABLE when the trigger shows no command output**

In the config-injection fallback, when the trigger page does NOT contain command output (has_output == false), the code still pushes a FindingKind::Vulnerable finding and sets rce_confirmed = true. manage_config_set.php returns 2xx/302 for any authenticated admin (including fully patched MantisBT where stored config strings are never eval'd as PHP), so this reports a confirmed RCE with zero evidence of code execution on every authenticated target.

_Fix:_ Only set rce_confirmed/push a Vulnerable finding when has_output is true. For the unverified case emit a FindingKind::Note describing that delivery succeeded but execution was not confirmed.


### [false-positive] src/modules/exploits/webapps/pihole_redis_rce_cve_2024_34361.rs:263
**Pi-hole RCE reports VULNERABLE merely because the SSRF endpoint returned HTTP 2xx**

After the webshell/marker check fails, Phase 5 pushes a FindingKind::Vulnerable finding whenever `ssrf_status.is_success() || cron_status.is_success()`. The /admin/api.php?customdns endpoint returns HTTP 200 on virtually any reachable Pi-hole (and the cron POST goes to the same endpoint), so this records a confirmed CVE-2024-34361 RCE finding even when no Redis is present, the gopher SSRF was rejected, and nothing was written. Any benign/patched Pi-hole that authenticates will be reported as exploited, polluting loot/export and scheduler hit counts.

_Fix:_ Do not emit a Vulnerable finding for unconfirmed payload delivery. Either downgrade to FindingKind::Note ("payload delivered, unverified") or require out-of-band/marker confirmation before classifying as Vulnerable. A 2xx from the customdns endpoint is not evidence the gopher->Redis write executed.


### [false-positive] src/modules/exploits/webapps/wp_storychief_rce_cve_2025_7441.rs:264
**Vulnerable finding pushed merely because the webhook returned any 2xx**

Phase 5 pushes a FindingKind::Vulnerable claiming 'File write likely succeeded' whenever `exploit_status.is_success()`, with no confirmation that any PHP file was actually written or that RCE occurred. WordPress REST endpoints routinely return 200 for handled requests; the StoryChief webhook may accept and 200 the JSON body on a fully patched plugin. This reports unauth RCE on hosts where nothing was exploited (the plugin merely exists and the webhook is reachable).

_Fix:_ Only push FindingKind::Vulnerable from Phase 4 where the webshell output (`uid=`/`storychief_rce_ready`) is actually observed. For the webhook-200-only case, downgrade to FindingKind::Note (potential/unconfirmed).


### [false-positive] src/modules/exploits/webapps/zimbra_postjournal_rce.rs:254
**RCE reported as Vulnerable whenever SMTP server accepts the recipient (250 / 2xx)**

Phase 5 declares CVE-2024-45519 RCE confirmed and pushes a FindingKind::Vulnerable when `rcpt_accepted` is true, i.e. the RCPT TO response merely `starts_with("250")` or `starts_with("2")`. The injection payload is a quoted-string local part (`"aaa]\"$(cmd)\"["@zimbra.local`) which is RFC-5321-valid, so virtually any SMTP server — including fully patched Zimbra and completely unrelated mail servers like Postfix/Exim — returns `250 Recipient OK`. Accepting the recipient does not demonstrate command execution. This reports critical RCE on benign / patched hosts. The time-based branch (`time_delay = rcpt_elapsed.as_secs() >= 4`) is the only real signal, but it is OR'd with the meaningless `rcpt_accepted`.

_Fix:_ Only treat the host as Vulnerable on a real exploitation signal (time-based delay from a `sleep`/`$(sleep N)` payload, or an OOB callback). Demote the bare `rcpt_accepted` case to FindingKind::Note ("payload delivered, unconfirmed") and require the time delay (or canary) for the Vulnerable finding.


### [false-positive] src/modules/exploits/webapps/zimbra_sqli_auth_bypass_cve_2025_25064.rs:149
**SQLi confirmed on bare substring 'SQL'/'syntax'/'PostgreSQL' in response body**

Phase 2 marks the target injectable and pushes FindingKind::Vulnerable whenever the response body contains the substring `"SQL"`, `"syntax"`, `"mysql_"`, `"ORA-"`, or `"PostgreSQL"`. The strings `SQL`, `MySQL`, `NoSQL`, and `syntax` appear in countless benign pages, JS error messages, marketing copy, and Zimbra's own UI. This produces CVSS-9.8 Vulnerable findings on benign hosts that simply mention those words anywhere in HTML/JS.

_Fix:_ Match specific DB error signatures (e.g. "You have an error in your SQL syntax", "SQLSTATE[", "Warning: mysqli", "ORA-00933") and/or differential behaviour between the quote-injection and baseline requests, instead of the substrings "SQL" and "syntax".


### [false-positive] src/modules/osint/cname_chain.rs:111
**A-record lookup failure swallowed, producing false-positive 'Dangling CNAME' Vulnerable findings**

In chain_for(), the terminal A-record resolution is computed as `dns_lookup(host, A).await.map(|v| !v.is_empty()).unwrap_or(false)`. Any error from the A lookup (timeout, SERVFAIL, UDP packet loss, resolver unreachable) is silently coerced to `resolves = false`. At line 159 `let dangling_tag = !resolves && !chain.is_empty();` and at lines 170-176 this pushes a `FindingKind::Vulnerable` 'Dangling CNAME ... (terminal does not resolve)' finding. Because UDP DNS over a public resolver (1.1.1.1) is inherently lossy and the per-lookup timeout is only 4s, a single transient A-query failure on any host that has a CNAME chain will be reported as an exploitable subdomain-takeover candidate. Under mass-scan fan-out this manufactures Vulnerable findings on completely benign hosts.

_Fix:_ Distinguish a successful NXDOMAIN/empty-answer (genuine non-resolution → dangling candidate) from a transport error (unknown). Match on the Result: on Err, set a third 'lookup_failed' state and do NOT emit a Vulnerable finding (skip the host or emit a Note that resolution could not be determined). Optionally retry the A lookup a couple of times before concluding non-resolution.


### [false-positive] src/modules/scanners/h3c_cloudos_api_enum.rs:299
**Default-credentials probe reports 'default credentials accepted' for endpoints that need no auth at all**

The default-creds phase re-requests every CloudOS and discovery endpoint with a fixed Basic auth header and flags any 2xx as 'CloudOS default credentials accepted'. It never compares against the unauthenticated baseline already gathered in the first loop. Any endpoint that returns 200 with no authentication (the very condition the first loop flags as 'data disclosed without auth') is re-counted here and mislabeled as default-credential access. On a benign host that serves a 200 landing/login page on '/', this produces duplicate, incorrect 'default credentials' Vulnerable findings.

_Fix:_ Only flag default-credential success when the same endpoint returned 401/403 (or a different status/body) without the header, i.e. when the credential materially changes the response. Skip endpoints already found unauthenticated.


### [false-positive] src/modules/scanners/php_version_eol.rs:194
**Vicidial probe reports VULNERABLE on any 200/302/401 response**

For each Vicidial path the module flags `FindingKind::Vulnerable` whenever the response status is success OR 401 OR 302, without verifying the body/headers actually belong to Vicidial. 302 (redirect to login) and 401 (auth required) are returned by a huge fraction of ordinary web endpoints, so any reachable web server with one of the probed paths gets reported as a Vicidial vulnerability. The X-Powered-By banner is captured but not required for the finding.

_Fix:_ Require a Vicidial-specific fingerprint in the body/headers (e.g. body.contains("VICIDIAL") or a Vicidial-specific cookie/title) before pushing a finding, and downgrade kind to Note for mere reachability.


### [resource-leak] src/prescan.rs:141
**Prescan masscan/zmap child process is never killed on timeout — orphaned root packet scanner keeps flooding the network**

discover_live wraps run_capture_lines in tokio::time::timeout. On the timeout arm (Err(e) => ... Ok(Vec::new())) the run_capture_lines future is dropped, which drops the tokio::process::Child. tokio::process::Command does NOT kill the child on drop unless kill_on_drop(true) is set, and neither masscan_cmd nor zmap_cmd set it (lines 177-203) and the code never calls child.kill()/start_kill(). Result: when prescan 'times out and falls back to per-IP fan-out', the masscan/zmap process — a root-privileged SYN flooder running at `--rate` pps — keeps running orphaned in the background. The operator believes the scan stopped; it has not. Under a mass scan this leaks one orphaned packet-blaster per CIDR that times out, continuing to send traffic to out-of-scope hosts long after rustsploit moved on.

_Fix:_ Set .kill_on_drop(true) on the Command in masscan_cmd/zmap_cmd, or take ownership of the Child and explicitly child.start_kill()/child.wait() on the timeout path before returning. kill_on_drop is the minimal fix so the orphan dies when the future is dropped.


### [resource-leak] src/ws.rs:188
**WS connection-slot counter leaked when tenant resolution fails after slot is claimed**

ws_upgrade atomically increments TOTAL_WS_CONNECTIONS (lines 122-128) before calling on_upgrade. Inside handle_ws, the only decrements of TOTAL_WS_CONNECTIONS are on the nonce-send-failure path (line 163) and at the normal end of the function (line 443). But at lines 188-194, if crate::tenant::resolve_for(&client_name) returns Err (e.g. the tenant registry cap is reached or the name is rejected after sanitization), the function returns early WITHOUT calling TOTAL_WS_CONNECTIONS.fetch_sub(...). Every such failed upgrade permanently consumes one of the MAX_TOTAL_CONNECTIONS=100 slots. After 100 tenant-rejected upgrades the server returns SERVICE_UNAVAILABLE to all WebSocket clients forever (until restart). This is a denial-of-service via a normal, reachable error path.

_Fix:_ Before the early `return`, decrement the counter and abort the already-spawned writer task: `writer_handle.abort(); TOTAL_WS_CONNECTIONS.fetch_sub(1, Ordering::AcqRel); return;`. Better: resolve the tenant in ws_upgrade BEFORE claiming the connection slot, or use a RAII guard that decrements on Drop so every exit path is covered.


### [mass-scan] src/modules/creds/generic/m365_activesync_spray.rs:325
**Module ignores ctx.target and always sprays hardcoded office365 endpoints — re-runs per host under fan-out**

run() binds the target as `let _target` and never uses it; all attempts go to the fixed constants ACTIVESYNC_URL / EWS_URL / smtp.office365.com. Under the universal per-host scheduler fan-out, scanning a CIDR or target file causes the entire user×password spray against Microsoft 365 to be repeated once for every host in the input — wasting attempts, multiplying lockout risk on real M365 accounts, and producing duplicate findings all attributed to outlook.office365.com.

_Fix:_ Either gate the module so it runs exactly once (reject multi-host/CIDR targets, or detect and skip duplicate fan-out invocations), or make the tenant/endpoint host derive from ctx.target so it is not silently re-sprayed per host.


### [mass-scan] src/modules/exploits/dos/tcp_connection_flood.rs:45
**tcp_connection_flood ignores ctx.cancel entirely; infinite-duration mode is uncancellable under fan-out/loop/API**

run() receives ctx but never passes or consults ctx.cancel — execute_stress takes only &config. The only ways the attack stops are (a) the duration timer elapsing, or (b) tokio::signal::ctrl_c() in the duration_secs==0 'INFINITE' mode (an offered default). Under the universal per-host fan-out, /loop, or API/batch execution there is no interactive Ctrl-C tied to this module, so the framework cancellation token cannot stop it. With duration=0 the worker pool floods forever, and even with a finite duration a cancellation request is ignored until the timer fires. Every sibling flood module (udp_flood, icmp_flood, dns/ntp/ssdp/memcached/syn_ack/null_syn) races tokio::select! on cancel.cancelled(); this module is the outlier, confirming an oversight rather than design.

_Fix:_ Thread ctx.cancel into execute_stress and replace the bare sleep / ctrl_c wait with tokio::select! { _ = sleep(duration) => {}, _ = cancel.cancelled() => {} } (and for infinite mode, select on cancel.cancelled() instead of ctrl_c), matching the other flood modules.


### [mass-scan] src/modules/exploits/frameworks/apache_tomcat/catkiller_cve_2025_31650.rs:44
**DoS fan-out hardcodes 300 tasks x 100000 requests, ignores module_timeout and cancellation**

num_tasks=300 and requests_per_task=100000 mean up to 30 million HTTP/2 requests per host with a 300ms per-request client timeout, fully serial within each task. The join loop `for handle in handles { handle.await }` has no timeout and the worker loop never checks `ctx.cancel`/`ctx.is_cancelled()` nor calls `ctx.rate_limit`. Under the universal per-host fan-out a /16 (or even one host) makes the module run effectively unbounded, ignoring the module timeout, and it cannot be cancelled. monitor_server is aborted but the 300 worker tasks are awaited to completion.

_Fix:_ Bound total work and honour the framework: check `ctx.is_cancelled()` inside send_invalid_priority_requests's loop, wrap the join in a timeout/select against `ctx.cancel.cancelled()`, derive request counts from a configurable duration, and call `ctx.rate_limit` to respect global limits.


### [mass-scan] src/modules/exploits/routers/palo_alto/panos_authbypass_cve_2025_0108.rs:218
**Launches a system web browser per vulnerable host, even in batch/mass-scan mode**

check_host() calls open_browser(&full_url) on every host detected as vulnerable, spawning xdg-open/start/open as an OS process. This is not gated by ctx.batch_mode / is_batch_mode (the banner is, but this is not). Under the universal per-host fan-out across a CIDR or file target, a scan of N vulnerable PanOS hosts opens N browser windows/processes on the operator's machine — a denial-of-usability and an unexpected side effect during automated scanning.

_Fix:_ Only call open_browser in interactive mode (guard with `if !crate::utils::is_batch_mode()`), and ideally only when a single target is supplied. Default to not launching a browser.


### [mass-scan] src/modules/scanners/snmp_scanner.rs:194
**SNMP scanner never calls ctx.rate_limit — unthrottled packet flood under fan-out**

snmp_scanner sends every SNMP GET via test_community/socket.send_to with no ctx.rate_limit(target).await call anywhere in the module. Its sibling UDP scanners (nbns_scanner:327, reflect_scanner:323) both acquire a rate-limit permit before each round trip. With a custom wordlist this fires (wordlist_size × versions × up to 3 OIDs) UDP packets per host as fast as possible, and under the universal per-host CIDR fan-out this ignores the global/per-module/per-target limiter entirely, hammering targets and tripping IDS.

_Fix:_ Thread `ctx` (or the limiter) into probe_batch/test_community and call ctx.rate_limit(target).await before each socket.send_to, matching nbns_scanner and reflect_scanner.



## MEDIUM


### [security] src/modules/creds/generic/ssh_user_enum.rs:414
**ssh_user_enum output file path used unsanitized — directory traversal / arbitrary write**

The output path is taken from `cfg_prompt_default("output_file", "Output file", "valid_ssh_users.txt")` and passed directly to `OpenOptions::open(&output_path)` with `write/create/truncate`. There is no basename enforcement, so an operator-/config-supplied value like `../../etc/cron.d/x` or `/tmp/evil` writes (and truncates) a file outside the current directory. The sibling `ssh_spray.rs` (lines 519-524) explicitly defends against exactly this by forcing `Path::new(&raw).file_name()` and rejecting names starting with '.'; ssh_user_enum omits that protection, so a value sourced from custom_prompts/options/state (which in API/multi-tenant mode may not be fully trusted) can truncate arbitrary writable paths.

_Fix:_ Reduce the path to its basename before opening, as ssh_spray does: `let safe = std::path::Path::new(&output_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "valid_ssh_users.txt".to_string());` and reject empty / dot-prefixed names, or route through `crate::utils::get_filename_in_current_dir(&output_path)` like the bruteforce engine does.


### [error-swallowing] src/api.rs:498
**DELETE /api/options always returns 200 OK even when every delete fails**

The bulk delete handler loops over body keys, dispatching delete_option per key, accumulating successes into `deleted` and failures into `errors`, then unconditionally returns `ok(...)` (HTTP 200) with `{deleted, errors}`. There is no status-code differentiation: if all keys are NOT_FOUND or all hit OPTION_ERROR/STORE failures, the client still receives 200 OK with the real errors buried inside the response body. A REST client checking only the HTTP status will treat a wholesale failure as success. This is exactly the 'failures swallowed into 200 OK' pattern. Every other handler routes through invoke_rpc/rpc_status and surfaces a real 4xx/5xx; this one diverges.

_Fix:_ Return a non-2xx status when `deleted` is empty and `errors` is non-empty (e.g. map to 404/409 via rpc_status of the first/most-severe error code), or use 207-style semantics. At minimum return BAD_REQUEST/CONFLICT when nothing was deleted but errors occurred, so callers can detect total failure from the status line.


### [error-swallowing] src/modules/creds/generic/m365_activesync_spray.rs:477
**ActiveSync/EWS/SMTP transport errors only logged when verbose, then dropped**

In the per-user spray tasks, try_http_basic and try_smtp_auth errors are handled by printing only if `verbose`, then discarded (lines 477-485 ActiveSync, 524-528 EWS, 556-565 SMTP). A transient network error on a given account is silently treated as 'not sprayed' — the account is never retried, never re-queued for the next round, and no error is recorded. In a password-spray where each account gets one shot per round, a single blip can permanently skip a valid account without any trace in non-verbose mode.

_Fix:_ Track per-account errors and either retry them within the round or carry them forward to a later round; at minimum surface an error count in the summary so silently-skipped accounts are visible without verbose mode.


### [error-swallowing] src/modules/exploits/frameworks/nginx/nginx_pwner.rs:99
**Every nginx_pwner check uses `if let Ok(resp) = send().await` with no else — request failures look identical to 'not vulnerable'**

All probe helpers (check_version, check_crlf, check_purge, check_variable_leak, check_merge_slashes, check_integer_overflow, check_alias_traversal, check_x_accel_redirect, check_raw_backend_reading, check_php) wrap the HTTP send in `if let Ok(resp) = client.get(...).send().await { ... }` with no else arm. Connection resets, TLS errors, timeouts, and DNS failures are silently discarded, so a transient network failure is reported indistinguishably from a clean (patched) host. With no logging at all on the error path the operator cannot tell a scan actually reached the target.

_Fix:_ Match on the send Result and at minimum log Err(e) at warn level (or surface a 'host unreachable' note) so request failures are not conflated with 'not vulnerable'.


### [error-swallowing] src/modules/exploits/honeytrap/ftp_panic.rs:49
**recv_ftp_line conflates timeout, EOF, and read error into an empty string**

recv_ftp_line only surfaces the read-error case (Ok(Err(e))) and even then merely prints it; an outer timeout (the whole timeout() returning Err) is silently ignored and the partial/empty line is returned. Callers cannot tell 'server timed out' from 'server cleanly closed' from 'no data yet'. In the malformed-PORT step an empty line is immediately interpreted as 'connection dropped as goroutine panicked', and the banner step treats an empty (possibly timed-out) read as 'no FTP banner' and aborts. Real errors are discarded.

_Fix:_ Return Result<Option<String>> (or a small enum) distinguishing timeout / EOF / error, and have callers branch on the real outcome instead of inferring a crash from an empty string.


### [error-swallowing] src/modules/exploits/network_infra/hpprocurve_disclose.rs:51
**Body-read `?` aborts the credential-path loop on a single failure**

Inside `for (path, label) in &cred_paths`, the body is read with `let body = r.text().await.context("read body")?;`. The `send()` call uses a proper `match`, but the body read propagates with `?`. A single body-read failure (e.g. one path returns a chunked/aborted response) returns Err from `run()` and skips all remaining credential paths that have not yet been tried — turning a per-path transient error into a whole-module failure rather than continuing.

_Fix:_ Replace `?` with a `match`/`if let Err` that prints the read error and `continue`s to the next path, mirroring the send() error handling, so one bad path does not abort the remaining probes.


### [error-swallowing] src/modules/osint/cname_chain.rs:108
**CNAME lookup error logged only at debug then chain truncated silently**

Inside the CNAME-following loop, a failed lookup is handled with `Err(e) => { tracing::debug!("CNAME lookup for {} failed: {}", current, e); break; }`. A transient network error mid-chain is recorded only at debug level (invisible by default) and the chain is silently truncated. The caller cannot tell the difference between 'chain genuinely ended here' and 'lookup failed', which then feeds the dangling/provider classification with incomplete data and contributes to the false-positive at line 159.

_Fix:_ Propagate the error state out of chain_for (e.g. return an enum/Result distinguishing 'chain complete' vs 'lookup errored') so the classifier does not treat an errored partial chain as authoritative; at minimum surface the failure at warn level when not in batch mode.


### [error-swallowing] src/modules/osint/jwks_inspector.rs:147
**All JWKS probe failures collapse to debug-logged 'No JWKS found', masking real network errors**

In the candidate-probe loop, a connection/send error is handled with `Err(e) => { tracing::debug!("JWKS probe {} failed: {}", url, e); continue }`, a non-success status `continue`s, and a body-read error also `continue`s. If every candidate fails for a transient reason (DNS failure, connection refused, TLS handshake error, timeout), `found_url` stays None and at line 165 the module returns the definitive error `"No JWKS found at any common path under {base}"`. A transient connectivity failure is thus reported identically to a host that genuinely exposes no JWKS, hiding the real error from the operator and from any retry logic. The per-probe error is only visible at debug level.

_Fix:_ Track whether any probe produced a transport-level error vs a clean negative response. If all attempts errored at the transport layer, return an error that names the underlying cause (e.g. include the last connection error) rather than the misleading 'No JWKS found', so a transient failure is not reported as a confirmed absence.


### [error-swallowing] src/modules/scanners/sequential_fuzzer.rs:561
**Fuzzer request failures silently dropped (no error path)**

Each spawned fuzz task does `if let Ok(resp) = req.send().await { ... }` with no else branch. Connection resets, timeouts, DNS failures, and TLS errors are silently discarded — the task records nothing, so a host that fails every request looks identical to a clean scan with zero hits. There is no error counter or diagnostic, so the operator cannot distinguish 'target unreachable / rate-limiting us' from 'target responded, nothing found'. Combined with resp.content_length().unwrap_or(0) (line 563), responses without Content-Length are recorded with size 0.

_Fix:_ Add an else arm that records/aggregates request errors (an error counter surfaced in the summary, or at least a tracing::warn) so the operator can tell when the target is failing all requests; consider falling back to body length when Content-Length is absent.


### [error-swallowing] src/utils/bruteforce.rs:1059
**Fire-and-forget subnet tasks swallow panics; failed host is neither marked checked nor surfaced**

In run_subnet_bruteforce each per-IP worker is tokio::spawn'ed and never joined — there is no JoinHandle collection and the drain barrier only waits on Semaphore permits. If a worker panics (e.g. a bug in the try_login closure, an unwrap inside the protocol probe), the panic is silently absorbed by the dropped JoinHandle: no log, no error, the IP is never marked in the state file, and any partial progress is lost. Contrast run_bruteforce (line 817) which checks join results and prints '[!] Task join error'. This hides real failures during large subnet scans.

_Fix:_ Collect the JoinHandles (or use a JoinSet) and inspect results after the drain, logging join errors like run_bruteforce does, so panicked/aborted host tasks are reported rather than silently dropped.


### [error-swallowing] src/utils/creds_helper.rs:285
**is_port_open conflates DNS-resolution failure with 'port closed', silently skipping reachable hosts**

creds_helper::run gates the entire brute-force on `if !is_port_open(&host, port)` (line 92) and returns Ok(ModuleOutcome::ok()) when it is false. is_port_open returns false not only for closed ports but for any DNS lookup failure (line 303: lookup_host Err -> return false) and for an empty resolver result. A transient resolver hiccup or IPv6-only host therefore makes the module report 'closed/filtered — skipping' and produce a clean empty outcome, hiding a real, reachable target. The failure is only logged at debug level (tracing::debug!) then discarded.

_Fix:_ Distinguish 'resolution/connect error' from 'port closed': return an enum or Result so the caller can surface a real error (or warn) for DNS/connect failures instead of silently treating them as a closed port.


### [silent-loss] src/checkpoint.rs:139
**record() silently stops persisting once MAX_CHECKPOINT_ENTRIES is hit, breaking resume for the remainder of a huge scan**

When the in-memory `seen` set reaches MAX_CHECKPOINT_ENTRIES (10M), record() returns Ok(()) without inserting the target or flagging it (lines 141-143). The caller record_checkpoint (scheduler.rs:1004) only logs at trace/debug on Err, and here there is no Err at all — the cap is hit completely silently. For a scan larger than 10M targets (e.g. a /8 = 16.7M hosts), every target past 10M is processed but never recorded as done. On a crash + resume, already_processed() returns false for all of them, so the scan re-processes millions of hosts it already finished, and the operator gets no warning that resume coverage is degraded. The 'completed' count and resume semantics silently diverge from reality past the cap.

_Fix:_ When the cap is reached, log once at warn/error (not debug) so the operator knows resume is no longer being recorded, or return an Err so record_checkpoint surfaces it. Better: raise/remove the cap for the in-memory HashSet or stream `seen` to disk so coverage isn't silently dropped on very large scans.


### [silent-loss] src/exclusions.rs:114
**Failed `@file` exclusion load proceeds with defaults only — scan runs against ranges the operator meant to exclude, with no way for callers to detect the failure**

from_global_options() handles `setg exclusions @/path/to/file`. If read_exclusion_file fails (typo, permissions, missing file) the error is only logged via tracing::warn! and execution falls through returning the DEFAULTS-only ExclusionSet. The comment says 'Fail LOUD' but the function does not fail — it returns a set that omits the operator's custom exclusions. The single consumer (scheduler.rs:768 `let exclusion_set = crate::exclusions::shared();`) receives an Arc<ExclusionSet> with no error channel, so it cannot tell the custom file was dropped and proceeds to scan. For an offensive tool the operator points at an exclusion file precisely to keep specific (often legally out-of-scope) ranges OUT of a mass scan; silently scanning them anyway is an operational/legal hazard, not just a log line. A warn! at the default `warn` log level is easily lost in mass-scan output.

_Fix:_ Make from_global_options()/shared() fallible (return Result) so a failed @file load aborts the scan instead of silently scanning. At minimum, surface the failure through the ExclusionSet (e.g. a `load_failed` flag) that the scheduler must check and refuse to proceed on, rather than relying on a warn log.


### [silent-loss] src/mcp/tools.rs:690
**add_host reports success even when the workspace silently rejected the host**

handle_add_host only validates ip length and control chars, then calls WORKSPACE.add_host(...) (which returns ()) and unconditionally replies `Host {} added/updated`. But workspace.rs add_host (lines 243-256) silently `return`s without storing anything when `ip` is neither a parseable IpAddr nor a 'hostname shape' (must contain a '.' and be alphanumeric+`.-_`). So inputs the MCP layer accepts but the store rejects -- e.g. ip="localhost", ip="myhost" (no dot), or any value with a space -- are dropped, yet the MCP tool tells the client/LLM the host was added. The client believes data is persisted when it was not.

_Fix:_ Make WORKSPACE.add_host return a bool (added/updated vs rejected) and have handle_add_host return ToolResult::error when it returns false, or replicate the exact IP/hostname-shape validation in the MCP handler and reject up front so the success message is truthful.


### [silent-loss] src/mcp/tools.rs:578
**run_module discards the RunContext's structured Finding list, returning only free-text stdout**

run_with_context_target returns (result, ctx) where ctx.output is an OutputAccumulator that modules populate via output::add_finding() with structured Finding records (type/host/port/severity/detail) -- see src/context.rs:104 and src/output.rs:304-345. handle_run_module binds this as `_ctx` and drops it, then builds the ToolResult purely from output_buf stdout/stderr text. Every structured finding a module computed for this run is silently discarded before reaching the MCP client, so an LLM driving the server only ever sees the human-readable log text and never the machine-readable findings (no reliable VULNERABLE signal, host/port/severity). (The sibling ws.rs surface drops run_ctx the same way at ws.rs:757, so this is a framework-wide gap, but it is a real loss on the MCP run_module path.)

_Fix:_ Call ctx.output.take() after the run and include the structured ModuleOutput (findings) in the ToolResult (e.g. ToolResult::json with both the captured text and the findings array) so the MCP client receives the structured results that were actually produced.


### [silent-loss] src/modules/exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection.rs:212
**Camel command-injection phase computes success but never records a Finding**

Phase 3 sends three exec payloads and sets `any_success = true` whenever any response has a non-empty body, then prints '[+] Payloads delivered' and calls track_host. But it never pushes a Finding for delivered command-execution payloads — only the Phase-2 canary reflection path pushes a Finding. On a blind-but-vulnerable target (canary not reflected in body, line 156-158 explicitly notes 'may still be vulnerable (blind)') the module produces no Finding even though it reported success and tracked the host. Result computed then dropped.

_Fix:_ When `any_success` (or, better, when command output is verified via a canary in the executed command), push a FindingKind::Vulnerable/Note Finding into `outcome` so blind-but-delivered exploitation is recorded.


### [silent-loss] src/modules/exploits/ftp/pachev_ftp_path_traversal_1_0.rs:134
**List-mode successes write to file but never push a Finding into ModuleOutcome**

In single-target mode a successful traversal pushes a FindingKind::Vulnerable into outcome (lines 178-183). In list mode (use_list) the success branch only prints and calls save_result() to a per-target file (lines 134-137); it never extends outcome.findings. So when scanning a list, confirmed path-traversal hits are computed and logged to disk but never reach loot/export/the scheduler hit-count, silently losing the results.

_Fix:_ Collect findings from the spawned list tasks (e.g. via a channel or shared Mutex<Vec<Finding>>) and extend outcome.findings, mirroring the single-target branch.


### [silent-loss] src/modules/scanners/wp_user_enum.rs:143
**wp_user_enum oembed author disclosure printed but never pushed as a Finding**

The module's three enum vectors are documented as equal. Vectors 1 (wp-json users) and 2 (?author=N redirect) each push a Finding into outcome.findings. Vector 3 (oembed author disclosure) detects `s == 200 && body.contains("author_name")`, prints a green '[+] oembed disclosed author' line, but does NOT push any Finding. The disclosed author data therefore never reaches loot/export/scheduler hit-count — a real result computed then dropped.

_Fix:_ After the green print, push `outcome.findings.push(Finding { target, kind: FindingKind::Note, message: "WP author disclosed via oembed ...", data: Some(json!({"vector":"oembed", ...})) })` like the other two vectors.


### [silent-loss] src/shell.rs:772
**makerc reads stale on-disk history and silently omits the current session's commands**

makerc reads history_path() from disk (~/.rustsploit/history.txt) and writes it to the target file, claiming '[+] Command history saved'. However rustyline is configured with auto_add_history(true) which only appends to the in-memory history buffer; the file is written exclusively by rl.save_history(&hist) at shell exit (shell.rs:344). No incremental/append_history call exists. Therefore makerc invoked mid-session captures only commands from PREVIOUS sessions (whatever was on disk at startup) and silently drops every command typed in the current session — directly contradicting its documented purpose ('Snapshot current session', shell.rs:1869; 'Save recent history', shell.rs:1860). The operator gets a success message and a resource file that is wrong/empty, with no error.

_Fix:_ Snapshot the live in-memory history instead of the disk file: iterate rl.history() (rustyline exposes the History/SearchResult API) to write current-session entries, or call rl.append_history(&hist)/rl.save_history(&hist) immediately before reading the file in makerc so the on-disk copy reflects the current session. The Editor must be threaded into the makerc handler for this.


### [silent-loss] src/ws.rs:371
**subscribe:output silently drops the request when jobId is missing or non-numeric**

The subscribe:output handler wraps its entire body in `if let Some(job_id_u64) = params.get("jobId").and_then(|v| v.as_u64())`. There is a proper error response for a jobId that exceeds u32 range (lines 374-385), but if `jobId` is absent entirely or is sent as a JSON string (e.g. "5") rather than a number, the outer `if let` is false, the whole block is skipped, and control falls through to the unconditional `continue` at line 413. No ack and no error frame is ever sent. A JSON-RPC client that keys pending promises by req_id will hang forever waiting for a response that never comes, and the operator never learns the subscription failed. unsubscribe:output (lines 415-421) has the same silent-no-op behavior.

_Fix:_ Add an `else` that returns an INVALID_INPUT/INVALID_JOB_ID error frame carrying req_id when jobId is missing or not a u64, mirroring the existing out-of-range branch, so every subscribe request gets exactly one ack or error response.


### [panic-oom] src/modules/creds/generic/h3c_oem_kvm_bruteforce.rs:170
**Full cartesian user×password product materialized in memory with no cap (and read_lines is unbounded)**

When both a user and password wordlist are supplied, the module builds the full cartesian product into a single `pairs: Vec<(String,String)>` via nested loops (lines 170-198) with no MAX_COMBOS cap. The wordlists themselves are loaded by read_lines (line 337) which uses `tokio::fs::read_to_string` with no size limit and no streaming. A rockyou-class password list crossed with a username list can allocate hundreds of millions of String pairs and OOM. The shared engine has MAX_COMBOS/streaming protection; this hand-rolled loop bypasses it.

_Fix:_ Stream the password wordlist (or route through run_bruteforce_streaming / load_lines_batched) and cap the materialized combo count, instead of read_to_string + nested clone into one Vec.


### [panic-oom] src/modules/exploits/frameworks/h3c_bmc/h3c_redfish_config_dump.rs:642
**Byte-slice &body[..body.len().min(300)] panics on multibyte UTF-8 boundary**

`body` is the attacker-controlled HTTP response from the BMC. `&body[..body.len().min(300)]` slices by byte index; if byte 300 falls in the middle of a multibyte UTF-8 sequence (trivially induced by a malicious/garbage response), Rust panics with 'byte index 300 is not a char boundary'. The same pattern appears at line 672. Token slices in this file and in h3c_bmc_firewall_dump.rs (`&token[..token.len().min(12)]`) have the same hazard for non-ASCII tokens.

_Fix:_ Use a char-safe truncation, e.g. `body.chars().take(300).collect::<String>()` (as other modules already do), or `body.get(..300).unwrap_or(&body)` guarded on char boundaries.


### [panic-oom] src/modules/exploits/ftp/pachev_ftp_path_traversal_1_0.rs:64
**Unbounded copy of remote-controlled file into local disk dump**

ftp.retr(...) uses std::io::copy(reader, &mut file) with no size cap. The 'file' being retrieved is whatever the remote FTP server returns for the traversal path; a malicious or misconfigured server can stream an effectively unbounded amount of data (e.g. /dev/zero on the server, or a huge file), filling the local disk. The outer 10s timeout limits time but not bytes-per-second throughput * accumulated size.

_Fix:_ Wrap the reader with a byte-capped reader (e.g. reader.take(MAX_BYTES)) before copying so a hostile server cannot exhaust local disk.


### [panic-oom] src/modules/exploits/network_infra/vmware/vcenter_file_read.rs:94
**vcenter_file_read mode 2 reads arbitrary file via `cat` into an uncapped String (OOM)**

`read_file` runs `rvc ... 'shell.run cat {file}'` and a fallback `cat {file}`, and `vcenter_shell_exec` does `channel.read_to_string(&mut stdout)?` with no size limit. The target file path is operator-supplied and the file size is target-controlled (e.g. /var/log/vmware/vpxd/vpxd.log, /storage/db/vcdb/vcdb can be multi-GB). The entire file is buffered into a String in memory before the size-200/printing logic runs, so a large target file can exhaust memory and abort the process. (attack_enum correctly uses `head -5`; read_file does not bound it.)

_Fix:_ Bound the read: use `head -c <N>` (the CVE is a *partial* read anyway), or read at most N bytes from the channel via `take(N).read_to_end`/a fixed buffer, and document the cap.


### [panic-oom] src/modules/exploits/routers/tplink/tplink_wdr842n_configure_disclosure.rs:44
**Unbounded read of attacker-controlled /config.bin via res.bytes()**

The config download uses res.bytes().await? with no size cap. The server is the attacker-controlled peer; a malicious host can stream gigabytes to exhaust memory, and the subsequent DES decrypt allocates a second full-size buffer. Under mass-scan concurrency this is an OOM risk. Other modules in this repo (dlink_dcs_930l, tplink_ax1800) explicitly use read_http_body_capped to avoid exactly this.

_Fix:_ Use crate::utils::read_http_body_capped with a sane cap (e.g. a few MiB) instead of res.bytes(), matching the other modules.


### [panic-oom] src/modules/exploits/vnc/libvnc_websocket_overflow.rs:92
**Infinite busy-loop on EOF while reading WebSocket upgrade response**

The header-read loop has no check for `n == 0`. If the server accepts the TCP connection but closes it (or sends an empty/headerless response) before sending '\r\n\r\n', read() returns Ok(0) on every iteration, `resp` never grows, the terminator test never matches, and `resp.len() > 65536` never becomes true. The loop spins forever consuming 100% CPU (the per-iteration timeout does not fire because each read returns immediately with Ok(0)). On a mass scan a single such host hangs the module.

_Fix:_ Break (or bail!) when n == 0: `if n == 0 { anyhow::bail!("connection closed before WS upgrade response"); }` at the top of the loop body.


### [panic-oom] src/modules/exploits/webapps/flowise_js_inject_cve_2025_59528.rs:201
**Byte-slicing attacker-controlled response bodies can panic on a UTF-8 boundary**

Several places slice the response body by byte index, e.g. `&create_body[..create_body.len().min(300)]` (also lines 257, 409, 427). Rust's str range indexing panics if the index does not fall on a char boundary. A server returning a body whose 300th (or 500th/Nth) byte lands in the middle of a multi-byte UTF-8 sequence — trivially attacker-controlled — will panic the module task instead of printing a preview.

_Fix:_ Use a char-safe truncation, e.g. body.chars().take(300).collect::<String>() (as other modules in this codebase already do), or str::char_indices to find a valid boundary.


### [panic-oom] src/modules/exploits/webapps/git_exposure_rce.rs:558
**Char-boundary panic when truncating server-controlled secret preview**

A secret value extracted from server-served .git data is previewed with `&value[..80]` guarded only by `value.len() > 80`. `value` originates from attacker/server-controlled git config/object bytes and can contain multi-byte UTF-8. If byte index 80 is not a char boundary the slice panics, crashing the module while building findings (after work is done). The length check guards length but not UTF-8 boundary.

_Fix:_ Use a char-safe truncation, e.g. `value.chars().take(80).collect::<String>()` or clamp to the nearest char boundary with `value.is_char_boundary`.


### [panic-oom] src/modules/exploits/webapps/invoiceninja_inject.rs:130
**Byte-slice of attacker-controlled design response can panic on UTF-8 boundary**

`&design_body[..design_body.len().min(300)]` slices the server's response by byte index. If the 300th byte falls mid-codepoint (server returns non-ASCII content at that offset), str indexing panics, aborting the module run on an otherwise recoverable error path.

_Fix:_ Replace byte slicing with design_body.chars().take(300).collect::<String>().


### [panic-oom] src/modules/exploits/webapps/librenms_inject.rs:186
**Byte-slice of attacker-controlled injection response can panic on UTF-8 boundary**

`&inject_resp_body[..inject_resp_body.len().min(300)]` slices the response by byte index when printing the injection result. A response whose 300th byte is in the middle of a multi-byte UTF-8 character (attacker-controlled) causes a slice-boundary panic.

_Fix:_ Use inject_resp_body.chars().take(300).collect::<String>() instead of byte-range slicing.


### [panic-oom] src/modules/exploits/webapps/mantisbt_exec.rs:91
**Byte-slice of attacker-controlled CSRF token can panic on a non-char boundary**

The extracted CSRF token (parsed from the target's HTML value="..." attribute, fully attacker-controlled) is sliced with `&token[..token.len().min(16)]`. String indexing slices by byte offset; if a multibyte UTF-8 character straddles byte 16, Rust panics ('byte index is not a char boundary'). A malicious or merely UTF-8 server response aborts the module run.

_Fix:_ Use a char-safe truncation, e.g. token.chars().take(16).collect::<String>(), or token.get(..16).unwrap_or(token).


### [panic-oom] src/modules/exploits/webapps/redash_rce_hash.rs:119
**Byte-slice of server-controlled API key can panic on a non-char boundary**

The api_key extracted from the JSON session response (server-controlled) is sliced with `&key[..key.len().min(8)]`. This slices by byte offset; a multibyte UTF-8 character in the first 8 bytes causes a 'byte index is not a char boundary' panic, aborting the run on a crafted/non-ASCII key.

_Fix:_ Use key.chars().take(8).collect::<String>() (or key.get(..8)) instead of byte slicing.


### [panic-oom] src/modules/exploits/webapps/tapestry_fileread_cve_2021_27850.rs:600
**extract_xml_attr / <property> scan compute byte offsets on to_lowercase() then slice the original string**

extract_xml_attr finds the search string in `fragment.to_lowercase()` and then indexes the ORIGINAL `fragment` (`&fragment[val_start..val_start+end]`). Likewise extract_credentials searches `lower_body` (= body.to_lowercase()) for "<property" then slices the original `body` at those offsets (line 568-571). Rust's to_lowercase() can change a string's byte length for non-ASCII input (e.g. some Unicode characters lowercase to a different number of bytes), so the offsets no longer align with the original. Leaked config files are server/attacker-influenced UTF-8 and can contain non-ASCII (comments, UTF-8 BOM, accented values); a mismatched offset that lands mid-codepoint causes a panic on string slicing, aborting the scan for that host.

_Fix:_ Search within the original (case-preserving) string, or use a case-insensitive matcher that returns byte offsets into the original buffer; do all subsequent slicing against the same string the offset came from. Alternatively guard slices with get(..) / is_char_boundary().


### [panic-oom] src/modules/osint/jwks_inspector.rs:149
**Uncapped r.text() read of attacker-controlled JWKS body violates the project's own untrusted-body policy (OOM risk)**

The JWKS probe reads each candidate response with `r.text().await` with no size cap. The framework explicitly documents (src/utils/safe_io.rs:5-6) that `reqwest::Response::text()` must be replaced with `read_http_body_capped` for untrusted peers precisely to avoid OOM, and the cert_transparency module in the same scope already follows this rule. A malicious or misconfigured endpoint at one of the 8 well-known JWKS paths can return a multi-gigabyte body and exhaust memory. The risk is amplified because up to 8 paths are probed per host and the module runs per-host under mass-scan fan-out.

_Fix:_ Replace `r.text().await` with `crate::utils::read_http_body_capped(r, CAP)` (e.g. a few MiB; JWKS documents are tiny) and parse the resulting bytes with serde_json::from_slice, matching the pattern used in cert_transparency.rs.


### [panic-oom] src/modules/scanners/dir_brute.rs:353
**One tokio task spawned per wordlist line up front — unbounded memory on large wordlists**

execute_scan iterates the entire wordlist and tokio::spawns a task for every word before any of them run, collecting all JoinHandles into `tasks`. The Semaphore only throttles concurrent *execution*, not task allocation. With a large wordlist (common dir-brute lists are millions of lines, e.g. raft/seclists merged) this allocates millions of futures/JoinHandles simultaneously, risking high memory use or OOM, independent of the concurrency setting.

_Fix:_ Stream the wordlist with futures::stream::iter(...).map(...).buffer_unordered(concurrency) (as enumerate.rs already does) instead of pre-spawning a task per word, so only `concurrency` futures are alive at once.


### [panic-oom] src/utils/wordlist.rs:358
**BatchedReader::next_batch reads a full line before enforcing MAX_BYTES, defeating the advertised OOM cap**

BatchedReader is documented as the OOM-safe streaming reader bounding memory to 'batch_size * average_line_length + 64 KiB' regardless of input size, with a MAX_BYTES (256 MiB) cap. But next_batch calls read_line into a single String and only checks self.bytes_seen > MAX_BYTES AFTER read_line returns (line 369). read_line reads until '\n' or EOF, so a hostile/corrupt wordlist that is one giant newline-less blob (e.g. a 2 GB line, a /dev/zero-style pipe, a binary dump) is fully materialised into `line` before any cap check — an unbounded allocation that OOMs the process. The per-batch and total caps never get a chance to fire. The same flaw exists in load_lines/load_lines_batched/load_lines_uncapped which all use reader.lines().

_Fix:_ Use read_until with a per-line byte limit, or wrap the reader in AsyncReadExt::take(MAX_BYTES) so a single pathological line cannot allocate beyond the cap. Truncate/skip lines longer than a sane bound (e.g. 64 KiB).


### [logic-flaw] src/jobs.rs:234
**Job spawn captures tenant only from CURRENT_TENANT, not from RunContext — a job spawned inside a module run loses tenant isolation**

spawn() captures the tenant to re-establish in the background task solely from the CURRENT_TENANT task-local (line 234). But tenant identity can also live in RunContext.tenant_id, which tenant::resolve() (tenant.rs:198-201) deliberately also checks via context::current_tenant_id(). If JobManager::spawn is ever called from code already running inside a RUN_CONTEXT scope where the tenant was propagated through RunContext rather than CURRENT_TENANT (e.g. a module that backgrounds a sub-scan), tenant_for_task is None, and the spawned job runs against the process-global stores — leaking that tenant's findings/loot/hosts into the global singletons and across tenants. The re-establishment logic is asymmetric with the resolver it is meant to feed.

_Fix:_ Resolve the tenant the same way tenant::resolve() does: `CURRENT_TENANT.try_with(|t| t.clone()).ok().or_else(crate::context::current_tenant_id)` so a job inherited from a RunContext-scoped caller keeps its tenant.


### [logic-flaw] src/mcp/server.rs:153
**MCP server request loop is strictly sequential with no per-call timeout; one hung tool wedges the whole server**

run_mcp_server processes requests one at a time: `let response = handle_request(request).await;` is awaited inline in the read loop, and tools/call -> call_tool -> handle_run_module has no server-side timeout. The 30s timeout in client.rs:80 only protects rustsploit's own outbound client, not this server. A single run_module against a slow/unreachable host (or a module that hangs) blocks the await indefinitely, so the server stops reading stdin and every subsequent JSON-RPC request (including cancellations / other tools) is stalled until that one call returns. There is no concurrency and no module_timeout enforcement on this path.

_Fix:_ Wrap handle_request (or at least tools/call) in tokio::time::timeout using a configurable module_timeout, returning a JSON-RPC/tool error on expiry; and/or spawn each request on its own task so a slow tool does not block the read loop and the server can keep servicing other requests.


### [logic-flaw] src/modules/exploits/cameras/avtech/cve_2024_7029_avtech_camera.rs:247
**Single check_vuln network error aborts whole target loop and drops collected findings**

When iterating a file of targets, `if check_vuln(&client, &url).await?` uses `?` so a network/HTTP failure on ANY single target (connection refused, timeout, TLS error, body read error) propagates out of `run`, terminating the entire multi-target loop and discarding the ModuleOutcome built up so far (all prior findings are lost). A scan of N hosts where host 1 is vulnerable and host 2 is down will return Err and lose host 1's finding.

_Fix:_ Match on the Result per target: on Err, print/log the per-host error and `continue` to the next target instead of `?`-propagating, so one unreachable host does not abort the scan or drop accumulated findings.


### [logic-flaw] src/modules/exploits/cowrie/ansi_log_injection.rs:160
**\xNN unescape emits UTF-8-encoded codepoints instead of raw bytes for values > 0x7F**

unescape_shell_dollar_quote builds a String and does `result.push(b as char)` where b is a u8 parsed from a \xNN sequence. For any byte >= 0x80, `b as char` yields the Unicode scalar U+0080..U+00FF, which is encoded as two UTF-8 bytes when the String is later sent via `literal.as_bytes()`. So `\xff` is transmitted as 0xC3 0xBF, not 0xFF. The bundled payloads only use bytes < 0x80 (0x1b, 0x07, 0x0d) so they happen to work, but any operator-supplied payload with a high byte is silently corrupted on the wire.

_Fix:_ Build a Vec<u8> for the literal payload and push raw bytes (result_bytes.push(b)), or write the bytes directly to the channel rather than round-tripping through a Rust String.


### [logic-flaw] src/modules/exploits/frameworks/exim/exim_etrn_sqli_cve_2025_26794.rs:106
**Time-based SQLi measurement uses a single read() that returns on the first byte, undermining timing**

measure_response times from sending the command (line 102) to the first `stream.read()` returning (line 106). A single read() returns as soon as any bytes are available; for a multi-line SMTP reply the server may flush an initial line immediately, so the measured 'delayed' time can reflect first-byte latency rather than full-response completion. This makes the diff>0.3s AND ratio>=2x detection unreliable and can both miss real injections and (with network jitter on the baseline) produce false positives. There is also no read loop to consume the full reply before timing ends.

_Fix:_ Read until the SMTP reply is complete (final line, i.e. '250 ' / status with space, or connection idle) before measuring elapsed time, and average several baseline samples to stabilise the ratio comparison.


### [logic-flaw] src/modules/exploits/network_infra/vmware/vcenter_backup_rce.rs:76
**Blocking ssh2 calls run on the async runtime without spawn_blocking**

vcenter_backup_rce (and the identical helpers in vcenter_file_read) call the synchronous, blocking ssh2 API directly inside async functions: `sess.handshake()`, `sess.userauth_password()`, `channel.read_to_string()`, `channel.wait_close()`, `channel.exit_status()`. These block the current tokio worker thread for up to DEFAULT_TIMEOUT_SECS (30s) each. The rest of the codebase wraps ssh2 in `tokio::task::spawn_blocking` (see src/modules/exploits/ssh/sshpwn_session.rs:140, paramiko_*.rs, asyncssh_beginauthpass.rs:157). Under the universal per-host fan-out, many of these tasks running concurrently will each pin a worker thread for the full timeout, starving the runtime / serializing the scan and ignoring cooperative cancellation (the blocking calls cannot observe ctx.cancel).

_Fix:_ Move the SSH session creation and each shell exec into `tokio::task::spawn_blocking(...)` (joined with `.await`), as the ssh/* modules already do, so blocking I/O does not occupy async worker threads.


### [logic-flaw] src/modules/exploits/vnc/rfb.rs:67
**rfb_negotiate_security mis-parses RFB 3.3 servers (claims to peek but doesn't)**

The comment says it peeks the first byte to distinguish RFB 3.3 (4-byte security type) from 3.7/3.8 (1-byte count + list), but the code only ever treats the first byte as a 3.7/3.8 count. In RFB 3.3 the server sends the chosen security type as a single 4-byte big-endian word (e.g. 00 00 00 02 for VNC auth); first[0] is 0x00, which this code interprets as the 'server error' path and then reads a 4-byte reason length and bails with 'server refused'. So every RFB 3.3 server is mis-handled and aborts. This breaks tigervnc_timing_oracle, tightvnc_predictable_challenge and tightvnc_decompression_bomb against any 3.3 server, and conflates a real 3.3 negotiation with a genuine server-refusal error.

_Fix:_ Branch on the negotiated protocol version returned by rfb_handshake. For RFB 3.3, read the full 4-byte security type word and treat 0 as failure only there; for 3.7/3.8 use the count-byte + list logic. Do not assume first[0]==0 always means a server error.


### [logic-flaw] src/modules/exploits/webapps/api_attack_suite.rs:371
**DoS confirmation gate silently skipped for hostnames and IPv6 targets**

The DoS confirmation gate (`confirm_dos_target`) only runs when `host_only(&base_url)` parses successfully as an `Ipv4Addr`. If the target is a DNS hostname (the common case) or an IPv6 literal, `host.parse::<Ipv4Addr>()` returns Err and the entire `if`-let chain short-circuits, so the gate is silently bypassed. The user can then have the rate-limit burst (`do_rate`) and GraphQL deep-nest DoS (`do_graphql_dos`) probes execute against a hostname target with no DoS confirmation, defeating the documented safety control.

_Fix:_ Run the confirmation gate for ALL DoS-shaped runs: resolve the hostname (or accept a hostname/IPv6-aware confirm function), and if resolution/parse fails still require an explicit confirmation prompt rather than silently proceeding.


### [logic-flaw] src/modules/exploits/webapps/flatcore_upload_cve_2019_13961.rs:77
**Admin login treated as successful whenever any cookie is set**

flatcore_login returns success on `body.contains("logout") || body.contains("dashboard") || !cookie_str.is_empty()`. Almost every web server sets a session cookie on the login POST regardless of credential validity, so `!cookie_str.is_empty()` is true even for failed logins. The module then proceeds to the upload phase under a false belief that it is authenticated, wasting requests and producing misleading '[+] login successful' output. (The same flawed predicate appears in flatpress_xsrf_shell.rs:108 and guppycms_shell.rs:98.)

_Fix:_ Drop the `!cookie_str.is_empty()` clause; verify authentication by requesting an admin-only page and checking for an authenticated marker (or absence of the login form) before declaring success.


### [logic-flaw] src/modules/exploits/webapps/redash_rce_hash.rs:122
**Redash cookie-based session is discarded: cookies joined into Authorization header on a client with no cookie store**

When /api/session does not return an api_key, the code falls back to `auth_header = session_cookies.join("; ")` and then sends it via `.header("Authorization", &auth_header)` on all later requests (data sources, query_results, jobs, users). Cookie values placed in an Authorization header do not authenticate; additionally the client is built via build_http_client (cookie_store defaults to false), so the session cookie is not persisted either. For any Redash instance that uses cookie sessions rather than returning an api_key, every authenticated request silently fails and the module reports no RCE / no hashes despite valid credentials — a silent false negative.

_Fix:_ Build the client with HttpClientOpts { cookie_store: true, .. } (e.g. pentest_session) so the session cookie persists automatically, and stop stuffing cookies into the Authorization header. Only send `Authorization: Key <api_key>` when an api_key was actually obtained; otherwise rely on the cookie jar.


### [logic-flaw] src/modules/scanners/dmarc_check.rs:205
**registrable_domain mishandles multi-label TLDs, querying the wrong _dmarc name**

registrable_domain() naively takes the last two labels. For domains under multi-label public suffixes (e.g. example.co.uk, example.com.au, foo.gov.uk) it returns 'co.uk' / 'com.au', so the module queries _dmarc.co.uk instead of _dmarc.example.co.uk. That lookup will almost always return no record, producing a false 'No DMARC record — open to email spoofing' Vulnerable finding for domains that actually have correct DMARC, and reporting/keying the wrong target.

_Fix:_ Use a Public Suffix List (e.g. the publicsuffix crate) to compute the registrable domain, or query the DMARC record at the exact host first and only fall back to a PSL-derived parent. Avoid blindly taking the last two labels.


### [logic-flaw] src/pq_channel.rs:619
**X25519 DH results never checked for contributory behavior (was_contributory) on attacker-supplied public keys**

x25519-dalek 2.0.1's diffie_hellman does not reject low-order / small-subgroup public keys; it returns a SharedSecret with a was_contributory() flag the caller is expected to check. The handshake performs DH against fully attacker-controlled inputs — client ephemeral pub (line 619), client identity pub (line 623) — and the receive/send ratchets DH against peer-supplied rekey pubs (lines 800, 819) without ever calling was_contributory(). A peer that supplies a low-order point forces a known all-zero shared secret on that DH leg, weakening the entropy mixed into the IKM/ratchet root (ss_eph becomes attacker-known; in the ratchet the entire new root degenerates to HKDF over a constant DH). With multiple secrets combined the immediate impact is limited, but the DH-ratchet rekey path (ratchet_root via dh_ratchet_receive) can be driven to a fully predictable DH input by a peer sending a low-order rekey_pub.

_Fix:_ Use the SharedSecret returned by diffie_hellman and reject when was_contributory() is false (anyhow::bail) for each of the ephemeral, identity, and ratchet DH operations, so low-order/contributory-failure points cannot weaken the derived keys.


### [logic-flaw] src/prescan.rs:144
**Prescan timeout returns Ok(empty) indistinguishable from a genuine zero-live-host result, triggering a full per-IP fan-out of the entire CIDR**

On the wall_timeout arm, discover_live returns Ok(Vec::new()) — the exact same value as a successful prescan that legitimately found zero live hosts. The scheduler (scheduler.rs:463-466) maps `Ok(ips) if !ips.is_empty() => Some(ips)` and `Ok(_) => None`, where None means 'fall back to scanning every host in the CIDR'. So a prescan that hangs/misconfigures and times out causes rustsploit to scan ALL hosts of the range (e.g. all 65536 hosts of a /16) — the precise behavior prescan exists to avoid. Compounding this, wall_timeout is `est_secs.saturating_mul(4).min(3600)` (line 128): the 1-hour cap means any range that legitimately needs more than ~15 min of masscan time (e.g. a /8 at the default 1000 pps needs ~4.6h) will always hit the timeout and silently degrade to a full per-IP fan-out. The timeout outcome and the genuine-empty outcome must be distinguishable so the caller can decide between 'scan nothing' and 'scan everything'.

_Fix:_ Return a distinct result for timeout vs. clean-empty — e.g. Err(timeout) or an enum {LiveHosts(Vec), CleanEmpty, ToolUnavailable} — so the scheduler can choose to abort/skip rather than fan out over the whole range. Also reconsider the fixed 3600s cap or scale it with module_timeout/host_count so large legitimate scans are not forced into full fan-out.


### [logic-flaw] src/rate_limit.rs:107
**Rate-limiter config is frozen at first init and per-module buckets are cached forever — operator `setg *_rps` changes are silently ignored**

GlobalLimiter is a process-wide Lazy (line 162) constructed once from global_options on first ctx.acquire(). The global bucket's rps is fixed at construction with no way to update it, and although module_default/target_default are AtomicUsize there is no .store() anywhere in the file (verified by grep), so the atomics are dead/misleading. Worse, module_bucket() caches each module's Bucket in per_module and returns the cached value on every subsequent call without re-reading module_rps:<name> (lines 108-116). Consequences: (1) An operator who issues `setg global_rps 50` (or module_rps / target_rps) after the limiter has initialized to throttle a runaway mass scan has NO effect — they believe traffic is now throttled but it is not. (2) Even changing module_rps:<name> mid-session never takes effect once that module has acquired once. This silently disregards operator rate-limit intent, which for an offensive tool is a real operational hazard (continued high-rate scanning of targets the operator tried to slow down).

_Fix:_ Either document the limiter as start-only and read all RPS options before the first acquire, or make it reconfigurable: add store()-based setters for the defaults (wired to `setg`), store the global rps in an AtomicUsize the Bucket consults, and invalidate/recreate the per_module bucket when its module_rps option changes (e.g. store the rps alongside the bucket and rebuild on mismatch).


### [false-positive] src/modules/creds/generic/h3c_oem_kvm_bruteforce.rs:308
**Success determined by loose `body.contains("X-Auth-Token")` substring match**

After a 2xx status, the credential is treated as valid if the response body merely contains the substring "X-Auth-Token" anywhere. A host that echoes the literal header name in an error/help page, JS, or generic 200 page (the endpoint is a guessed path that may not exist on non-H3C hosts) is reported as a valid credential. Combined with the cartesian wordlist, this can mass-report bogus hits on benign hosts.

_Fix:_ Require the 200/201 status AND a properly parsed token (the `extract_token` JSON/header parse must succeed) before treating it as success; do not fall back to `Some("(present)")` on a bare substring match.


### [false-positive] src/modules/creds/generic/http_basic_bruteforce.rs:497
**Redirect to any non-login URL treated as successful authentication**

For 3xx responses, success is inferred whenever the Location header does NOT contain login/auth/signin/sso. Many sites 302 unauthenticated requests to a homepage, a language selector, or a marketing page whose URL has none of those tokens, which this code reports as valid credentials. This produces false-positive credentials on benign hosts.

_Fix:_ Do not treat a redirect as success by default. Compare against the unauthenticated baseline redirect target; only flag success if authenticated and unauthenticated requests diverge into an authenticated area.


### [false-positive] src/modules/creds/generic/pop3_bruteforce.rs:306
**POP3 auth uses single `read` with no partial-read handling — false negatives and swallowed disconnects**

`pop3_authenticate` reads the USER and PASS responses with a single `stream.read(&mut buffer)` and then checks `String::from_utf8_lossy(&buffer[..n]).starts_with("+OK")`. A single TCP read is not guaranteed to deliver the whole response line; if the server's `+OK ...` is split across segments and the first read returns `+O` (or just whitespace/IAC), the `starts_with("+OK")` check fails and the function returns `Ok(false)` (AuthFailed), so a valid credential is reported as invalid. Worse, if the peer closes the connection `n == 0` and `buffer[..0]` is empty: the code still returns `Ok(false)` rather than surfacing a connection-closed error, so a dead/erroring connection is silently classified as a clean auth failure (no retry, no error stat). The banner read at line 301 also discards its byte count entirely.

_Fix:_ Read full response lines (e.g. wrap the stream in a BufReader and `read_line` until a CRLF-terminated status line, like smtp_bruteforce's `read_smtp_line`), and treat `n == 0` / EOF as a classified ConnectionRefused error rather than `Ok(false)`. Match `+OK` / `-ERR` on the parsed status line.


### [false-positive] src/modules/creds/generic/proxy_bruteforce.rs:125
**HTTP CONNECT proxy success detected by loose substring `resp.contains("200")`**

`try_http_connect_auth` classifies the proxy response by `if resp.contains("200")` over the entire raw response (status line + headers). This is a substring match anywhere in the buffer, not a parse of the status line. A genuinely auth-rejecting proxy that returns e.g. `HTTP/1.1 407 Proxy Authentication Required` with a header such as `Content-Length: 1200`, a `Date:` containing the digits 200, or a body mentioning 200 will be classified as `LoginResult::Success` because the `contains("200")` branch is checked before the 407/401/403 branch. This reports a valid proxy credential on hosts where authentication actually failed, producing false-positive credential findings (the result also gets persisted to cred_store/loot by the engine).

_Fix:_ Parse the first line and check the status code on the status line only, e.g. `let status_line = resp.lines().next().unwrap_or(""); if status_line.contains(" 200") { Success } else if status_line.contains(" 407") || ... { AuthFailed }`. Match against the response start (`resp.starts_with("HTTP/1.1 200")` / `"HTTP/1.0 200"`) rather than an unanchored substring.


### [false-positive] src/modules/creds/generic/ssh_user_enum.rs:133
**Timing user-enum measures full connect+handshake time, making the 300ms threshold noise-dominated**

`time_auth_attempt` starts the clock before the TCP connect (line 93) and measures `start.elapsed()` after the whole connect + SSH handshake + single auth attempt (line 133). The detection (lines 274-275) flags a user as valid when `(avg_time - baseline).abs() > 0.3s`. Because the measured interval is dominated by TCP/handshake latency and jitter (which on real networks routinely swings well beyond 300ms between connections), and each user is sampled with only `DEFAULT_SAMPLES = 3` fresh connections, normal network variance alone will exceed the threshold and flag arbitrary usernames as 'likely-valid'. The technique should isolate the auth-handler timing, not total connection time. As written it will emit false-positive Note findings on most targets.

_Fix:_ Start the timer only immediately before `sess.userauth_password(...)` and stop right after it, so the measured delta reflects only the auth handler. Increase sample count and compare against the baseline using a statistical test (e.g. median + stddev) rather than a fixed absolute threshold, and raise the rank/qualify the finding given the technique's inherent unreliability.


### [false-positive] src/modules/exploits/cameras/avtech/cve_2024_7029_avtech_camera.rs:38
**AVTech detection relies on reflection of a non-executing marker token**

check_vuln / quick_check inject brightness=`1;echo_CVE7029;` and conclude vulnerability if the response body contains the literal `echo_CVE7029`. Because `echo_CVE7029` has no space it is a single token, not a shell `echo <arg>` command, so even on a truly injectable device it would attempt to run a command named `echo_CVE7029` (which does not exist) rather than echo the marker. The only way the marker appears in the body is if the device merely reflects the supplied brightness value back — meaning benign devices that echo request parameters in an error/debug page are flagged Vulnerable, while genuinely vulnerable devices may not match. This is both a false-positive and a likely-broken positive detection.

_Fix:_ Use a proper injected command that produces a unique, value-distinct marker (e.g. `1;echo rs-<uuid>;` with a space, or `$(echo <uuid>)`) and confirm the marker appears WITHOUT being a verbatim copy of the submitted parameter (e.g. transform it: echo a value derived from the marker so reflection alone cannot satisfy the match).


### [false-positive] src/modules/exploits/cowrie/ansi_log_injection.rs:228
**ANSI log-injection reports Vulnerable on mere delivery, never verifies the injection landed**

After spawn_blocking returns Ok, run() unconditionally pushes a FindingKind::Vulnerable stating the payload was 'delivered'. connect_and_inject reads the post-injection channel output (lines 118-122) but only traces it at trace level and never checks whether cowrie accepted/logged the command. Any reachable SSH service that accepts the configured credentials (even a real SSHd or a non-cowrie honeypot) is reported as confirmed ANSI-log-injection-vulnerable.

_Fix:_ Either downgrade the unverified outcome to FindingKind::Note ('payload delivered, manual log review required'), or inspect the drained response to confirm cowrie behaved like cowrie before claiming Vulnerable.


### [false-positive] src/modules/exploits/dionaea/mqtt_underflow.rs:164
**MQTT underflow DoS confirmed from one failed reconnect (try_connect_mqtt swallows all errors)**

The crash finding fires when try_connect_mqtt() returns false on the post-trigger liveness check. try_connect_mqtt swallows every failure mode (connect error, write error, missing/short CONNACK) into a bare `false` with only trace/debug logging. A single transient connection failure, or a broker that rate-limits / briefly refuses the reconnect, yields false and pushes FindingKind::Vulnerable 'crashed handler'. No re-confirmation is performed.

_Fix:_ Retry the liveness reconnect a few times before concluding a crash, and avoid mapping a single connect/CONNACK failure straight to a confirmed-DoS finding.


### [false-positive] src/modules/exploits/dionaea/tftp_crash.rs:162
**UDP no-reply treated as confirmed TFTP crash despite UDP being unreliable**

udp_send_recv returns None on any recv error/timeout (UDP gives no delivery guarantee). Step 3 maps `resp3.is_none()` directly to a confirmed crash and pushes FindingKind::Vulnerable. A dropped UDP datagram, a firewall, or a honeypot that simply doesn't reply to a repeated RRQ produces None and a false DoS finding. Additionally the original recv error is only logged at debug and otherwise discarded.

_Fix:_ Send multiple liveness datagrams and require consistent silence; since UDP is connectionless, gate the finding on stronger evidence (e.g. several retries all timing out) rather than a single missing reply.


### [false-positive] src/modules/exploits/frameworks/nginx/nginx_pwner.rs:197
**Header-bypass check flags any 50-byte response-size difference as a possible bypass**

check_headers_bypass flags a 'Possible IP restriction bypass' whenever the status differs OR the Content-Length differs from the baseline by more than 50 bytes, across 11 spoof headers x 4 IPs. Many normal sites vary response length per request (CSRF tokens, timestamps, ads) or omit Content-Length (chunked), so `content_length().unwrap_or(0)` makes any chunked vs non-chunked variance trip the 50-byte threshold. This generates large numbers of false-positive findings on benign hosts.

_Fix:_ Require a meaningful status-class change (e.g. baseline 403/401 -> 200) rather than raw length deltas, handle missing Content-Length explicitly, and confirm with a content diff before reporting a bypass.


### [false-positive] src/modules/exploits/frameworks/nginx/nginx_pwner.rs:197
**nginx header-bypass check flags 'IP restriction bypass' on a 50-byte length delta**

check_headers_bypass compares each spoofed-header response against the baseline and reports a 'Possible IP restriction bypass' finding when the status differs OR `(len - baseline_len).abs() > 50`. Body length naturally fluctuates by more than 50 bytes between requests on dynamic pages (CSRF tokens, timestamps, ads, session ids), so this fires on benign hosts. Content-length is also frequently absent (returns 0), making the delta meaningless. (Compounds the silent-loss issue: even these noisy findings never reach ModuleOutcome.)

_Fix:_ Only consider a status-code change (e.g. baseline 403 -> 200 with the header) as a candidate, and require a much larger / proportional body-size change with a stable baseline; ignore the comparison entirely when content_length is None/0.


### [false-positive] src/modules/exploits/ftp/ftp_bounce_test.rs:235
**Bounce 'vulnerability' flagged whenever PORT returns 200, which is normal FTP behavior**

The module declares a host vulnerable to FTP bounce if a PORT command to a third-party/internal IP returns status 200. Accepting the PORT command syntactically (200 PORT command successful) is the default reply of many FTP servers even when they will not actually open the data connection to the foreign host. RFC2577-conformant or modern servers still 200-ACK the PORT command and only reject at data-transfer time. Flagging on the 200 to PORT alone (without attempting a data transfer / RETR to confirm the bounce actually reaches the third party) over-reports the bounce vulnerability.

_Fix:_ After PORT 200, issue a data-transfer command (e.g. LIST/RETR) and confirm the server actually attempts/establishes the connection to the specified foreign host before declaring the bounce vulnerability; otherwise label as 'PORT accepted (unconfirmed)'.


### [false-positive] src/modules/exploits/honeytrap/docker_panic.rs:135
**Single dropped liveness probe is treated as confirmed daemon DoS**

The crash verdict depends on one liveness probe: `alive.map(|r| !r.is_empty()).unwrap_or(false)`. http_raw returns None on any connect failure/timeout and Some(empty) on a read timeout. A single transient network hiccup, RST, or a honeypot that simply closes idle keep-alive-less HTTP/1.0 connections quickly will produce None/empty on this one probe and immediately push a FindingKind::Vulnerable 'daemon exited'. No retry or re-confirmation is done.

_Fix:_ Re-probe several times with backoff before declaring the daemon dead, and only conclude DoS if the service was confirmed up in step 1 and is consistently unreachable afterward.


### [false-positive] src/modules/exploits/ipmi/ipmi_enum_exploit.rs:895
**scan_supermicro_upnp returns true on ANY UDP reply and is misused for port 49152**

scan_supermicro_upnp sends an SSDP M-SEARCH datagram and returns true on the first received datagram with NO size check (Ok(Ok(n)) => return true), so even a 0-byte datagram or an unrelated UDP reply marks the service 'open'. Worse, the same SSDP M-SEARCH probe is reused against port 49152 (lines 518-519), which is not an SSDP/UPnP service — sending an SSDP discovery to 49152 is the wrong protocol entirely, and any UDP response (or none-but-buffered datagram) flags supermicro_49152_open. Both produce FindingKind::OpenPort false positives for 'Supermicro UPnP'/'management port' on non-Supermicro and non-listening hosts. These checks also run for every IPMI host unconditionally, not just Supermicro-identified ones.

_Fix:_ Require n>0 and validate the SSDP reply (e.g. starts with 'HTTP/1.1 200' and contains a SERVER/USN header) before returning true for port 1900. For port 49152, use a protocol-appropriate probe (it is a TCP HTTP management port on Supermicro, not UDP/SSDP) — e.g. a TCP connect + HTTP request — rather than reusing the SSDP UDP probe.


### [false-positive] src/modules/exploits/ipmi/ipmi_enum_exploit.rs:487
**anonymous_access flagged Vulnerable from username-existence check, not actual anonymous access**

test_credentials only sends a Get Session Challenge and returns true when the completion code is 0x00 (i.e. the username is accepted / exists); the password argument is ignored (parameter named _password) and no session is ever activated. Calling test_credentials(socket, "", "") therefore tests only whether an empty username is accepted in the session-challenge step, which is NOT the same as anonymous access being granted. Yet a true result sets info.anonymous_access=true and pushes a FindingKind::Vulnerable 'IPMI anonymous authentication accepted'. Many BMCs return success to a null-user challenge without permitting anonymous login, yielding false-positive Vulnerable findings.

_Fix:_ Actually attempt to activate a session for the null user (Activate Session after the challenge) and only report anonymous access when activation succeeds, or relabel the finding as 'null-username session challenge accepted' (informational) rather than FindingKind::Vulnerable.


### [false-positive] src/modules/exploits/ipmi/ipmi_enum_exploit.rs:494
**Default-credential Finding emitted without ever verifying the password**

The default-credential loop calls test_credentials(socket, user, pass), but test_credentials ignores the password and only checks that the username exists (completion code 0x00). On the first existing username it sets valid_creds and emits a FindingKind::Credential (and writes DEFAULT_CREDS to the CSV). So on any BMC where, e.g., the username 'root' or 'admin' exists, the module reports a default credential (mislabeled with whatever vendor row matched first, e.g. 'Dell iDRAC root:calvin') even though calvin/admin/etc. was never validated. Although the password string is suffixed '(default, unverified)', it is still surfaced as a Credential finding and as DEFAULT_CREDS in the exploit column, which is a false positive that will mislead operators and reports.

_Fix:_ Perform full IPMI session activation (Activate Session with the password-derived auth code) to actually verify the credential before emitting a Credential finding; otherwise emit only a low-severity 'username exists' Banner finding and do not record it as DEFAULT_CREDS/Credential.


### [false-positive] src/modules/exploits/network_infra/arista_ngfw_disclose.rs:64
**Disclosure confirmed on loose substring match (body.contains("version"/"Arista"))**

The success condition is `status.is_success() && (body.contains("result") || body.contains("version") || body.contains("Arista"))`. Any HTTP 200 whose body contains the substring 'version' (extremely common in HTML, JS bundles, JSON error envelopes, API docs, login pages) or 'Arista' (any Arista product page, including patched/authenticated ones) will be reported as a confirmed unauthenticated RPC disclosure and pushed as a Vulnerable finding. This over-reports on benign or patched hosts.

_Fix:_ Parse the response as JSON-RPC and require the structured `result` array for the issued command (e.g. presence of a non-error `result` keyed to id 'rsploit'), not a raw substring. Reject responses that contain a JSON-RPC `error` object.


### [false-positive] src/modules/exploits/network_infra/hpprocurve_disclose.rs:53
**Credential-dump verdict on generic substrings like "password"/"manager"/"username"**

A successful (non-empty 200) response is reported as a leaked-credentials Finding if the body contains any of 'password', 'community', 'snmp-server', 'username', or 'manager'. Practically any HTML login form contains the strings 'password' and 'username', and many product pages contain 'manager'. This flags ordinary login pages and benign config pages as a confirmed credential dump and pushes a Vulnerable finding plus stores loot output.

_Fix:_ Require evidence of an actual credential disclosure (e.g. a parsed key/value such as `password <value>` from a config dump, or a regex matching hashed/cleartext secret lines), and exclude HTML form pages (e.g. when body contains '<input' / '<form'). Do not treat the word 'manager' or a login form as a leak.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_rg_ew_update_version_rce_cve_2021_43164.rs:164
**RCE confirmed on loose 'root' substring in update/check endpoint response**

execute_injection treats `text.contains("uid=") || text.contains("root") || text.contains("gid=")` as confirmed RCE and pushes a Vulnerable finding. The bare 'root' substring is a frequent false-positive trigger in JSON/HTML error pages and config responses (paths like /root/, 'root account'), so benign hosts can be reported vulnerable.

_Fix:_ Require a unique injected echo marker or a precise `uid=NNN(... ) gid=` regex; drop the bare 'root' substring match.


### [false-positive] src/modules/exploits/routers/ruijie/ruijie_rg_uac_ci_cve_2024_4508.rs:118
**Command injection confirmed on loose 'root' substring**

execute_injection (line 118) and try_alternate_endpoint (line 170) treat the presence of 'root' (or uid=/gid=) in the response as confirmed command execution and push a Vulnerable CVE-2024-4508 finding. The bare 'root' substring commonly appears in benign error/config pages, yielding false positives.

_Fix:_ Inject a unique echo marker and match it, or use a strict uid=/gid= regex; remove the bare 'root' substring check.


### [false-positive] src/modules/exploits/routers/tplink/tplink_tapo_c200.rs:68
**Marker-echo detection matches reflected JSON-RPC error containing the payload**

The setLanguage payload sets language to ';echo <marker>;#' and detection is body_text.contains(&marker). JSON-RPC services commonly echo invalid parameter values back in error responses (e.g. {"error":"invalid language: ;echo rs-tapo-...;#"}), which contains the marker substring with no command execution, producing a false-positive Vulnerable finding.

_Fix:_ Distinguish executed output from reflected input: require the marker to appear outside the literal injection string (the bare marker without ';echo'/';#'), or use a command whose echoed output differs structurally from the request payload.


### [false-positive] src/modules/exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457.rs:59
**Device fingerprint reported as a confirmed Vulnerable finding (auth-required, unverified)**

The module is documented as detection-only (the exploit requires authentication and is not performed), yet it pushes a FindingKind::Vulnerable for CVE-2026-1457 whenever the root page contains 'VIGI' or 'C385'. This records a mere device-presence fingerprint as a confirmed vulnerability in loot/export. 'C385' is also a loose substring that could appear in unrelated content.

_Fix:_ Report device detection as FindingKind::Note/Banner (potentially-vulnerable, requires creds) rather than Vulnerable, and tighten the fingerprint to a specific VIGI C385 banner string.


### [false-positive] src/modules/exploits/routers/tplink/tplink_wr740n_dos.rs:106
**DoS 'crash' confirmation: any failed 1s reachability probe is treated as a crash**

After sending the payload, the module probes the port with a hardcoded 1-second tcp_connect_str timeout and treats ANY connection error/timeout as 'crashed -> VULNERABLE'. A single dropped packet, transient firewall rate-limit, or a host on a slow link that does not answer within 1s is reported as a confirmed buffer-overflow DoS. The fixed 1s timeout also ignores module_timeout.

_Fix:_ Confirm the port was reachable before the attack, retry the post-attack probe a few times with a more generous timeout, and only report crashed if it was up before and is consistently down after.


### [false-positive] src/modules/exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890.rs:69
**Marker-echo detection also matches a reflected (non-executed) parameter value**

The injection URL is mtu=$(echo+<marker>) and detection is body.contains(&marker). If the device merely reflects the raw mtu parameter into an error/status page (a common behaviour, e.g. 'Invalid MTU value: $(echo+rs-zyxel-...)') without executing the command, the marker substring is present and the host is reported as vulnerable command injection. The check cannot distinguish executed output (bare marker) from reflected input (marker inside the $(echo+...) wrapper).

_Fix:_ Require the marker to appear WITHOUT the surrounding '$(echo+' wrapper (i.e. evidence of execution), e.g. search for the marker on a boundary that the literal injection string cannot produce, or use two distinct tokens so a reflected payload cannot satisfy the executed-output check.


### [false-positive] src/modules/exploits/voip/magnusbilling_ssrf_cve_2023_30258.rs:87
**SSRF confirmation matches the generic substring 'Connection'**

SSRF success is declared if the body contains "SSH" OR "OpenSSH" OR "Connection". The word 'Connection' (or 'connection') is present in countless benign HTTP error messages and pages (e.g. "Connection refused", "keep the connection", HTTP header echoes). This will report a confirmed internal-SSH-banner SSRF on hosts that merely return an error mentioning a connection.

_Fix:_ Remove the "Connection" clause and require an actual SSH protocol banner pattern such as `SSH-2.0-` / `SSH-1.99-` to confirm the internal service banner leaked.


### [false-positive] src/modules/exploits/webapps/api_attack_suite.rs:1085
**JWT alg:none 'Accepted' decided purely on matching status codes**

The alg:none check replays the forged none-alg token, then replays the ORIGINAL request as a baseline, and reports Critical 'JWT alg:none Accepted' if both responses are <400 and have equal status codes (`s == bs`). Status-code equality is a weak oracle: if the endpoint returns 200 regardless of token validity (public endpoint, soft-auth, or an error rendered with HTTP 200), or simply returns the same generic page for both, this fires a false Critical. There is no content comparison confirming the forged token actually granted the same authenticated view.

_Fix:_ Compare response bodies (or an authenticated-content marker) between the original and forged-token responses, and additionally send a deliberately-corrupted-signature token to confirm the server actually rejects invalid signatures before claiming alg:none is accepted.


### [false-positive] src/modules/exploits/webapps/cloudbleed_scanner.rs:66
**Memory-leak heuristic fires on any binary response containing a NUL run and a high byte**

A response is flagged as a 'Cloudbleed candidate' (Vulnerable Finding) if the hex of the body contains the substring "00000000" (i.e. at least two consecutive NUL bytes) AND any byte > 0x7f exists. This trivially matches benign binary/compressed/image responses (gzip, PNG, WebP, favicon, padded buffers), all of which routinely contain NUL runs and high bytes. It is not evidence of memory disclosure, so benign HTTPS endpoints will be reported as Cloudbleed candidates.

_Fix:_ Detect the actual Cloudbleed signature class (uninitialized-heap artifacts: cookie/Set-Cookie fragments, neighbouring-host names, JS framing leaking after malformed HTML) rather than a generic NUL-run heuristic, and require the leaked content to differ from the requested content.


### [false-positive] src/modules/exploits/webapps/commvault_cli_rce_cve_2025_57788.rs:198
**RCE Finding on HTTP success and on echoed 'RSPLOIT' marker**

Two over-broad detections: (1) `combined_output.contains("RSPLOIT")` is part of the RCE-confirmation test, but the injected deploy body literally contains `echo+RSPLOIT`, so any server that reflects the request body (error page, echo, WAF block page quoting the payload) trips the confirmed-RCE branch. (2) The `else if exploit_status.is_success() || deploy_status.is_success()` branch pushes a Vulnerable Finding purely because one endpoint returned 2xx, with no command output — a reachable but patched Commvault returns 200 and is reported as RCE.

_Fix:_ Remove `RSPLOIT` from the success markers (or use an out-of-band/echoed-back distinct token that is NOT present in the sent payload), and demote the bare-2xx branch to a Note rather than a Vulnerable finding.


### [false-positive] src/modules/exploits/webapps/craftcms_ssti_scanner.rs:38
**SSTI 'detected' whenever body contains "49"**

The scanner submits `{{7*7}}` and reports 'Twig SSTI detected' (pushes a Finding) if the response body contains the bare substring "49". As above, "49" is extremely common in benign HTML/JS/CSS, so this flags arbitrary non-Craft hosts as SSTI candidates. There is no check that the raw payload was not simply reflected unevaluated.

_Fix:_ Use a randomized product canary and require the unevaluated `{{...}}` form to be absent; ideally also fingerprint Craft first.


### [false-positive] src/modules/exploits/webapps/crafty_controller_rce_cve_2025_14700.rs:222
**SSTI RCE Finding pushed on HTTP 2xx without proof of execution**

When neither the marker nor command-output strings (uid=/root:/www-data) are present, the module falls back to `else if create_status.is_success() || settings_status.is_success()` and pushes a `Vulnerable` Finding claiming the SSTI payload was 'delivered'. A 200/201 from `/api/v2/servers` (server created with the payload stored as a literal name) does not mean Tornado rendered/executed it; this reports CVE-2025-14700 RCE on any reachable Crafty Controller that accepts a server-create request, including patched versions that safely store the name.

_Fix:_ Only push a Vulnerable finding when the rce marker or command output is observed; for the bare-2xx case record a Note ('payload delivered, execution unverified') instead of Vulnerable.


### [false-positive] src/modules/exploits/webapps/dnnplatform_upload_cve_2025_64095.rs:369
**Emits 'vulnerable:CVE-2025-64095' event even when nothing was confirmed**

In the final `None` arm (webshell not found AND benign canary not retrievable), the module still emits a `ServiceDetected { service: "vulnerable:CVE-2025-64095" }` event and pushes a Finding. At this point neither code execution nor the file-write primitive was confirmed — the upload may have been rejected entirely (the earlier non-2xx/302 upload warning is non-fatal). Tagging the host as `vulnerable:` and recording a finding for an unconfirmed, possibly-failed upload over-reports the CVE on patched/unaffected hosts.

_Fix:_ In the unconfirmed arm, do not emit a `vulnerable:` ServiceDetected event; either emit a neutral 'upload attempted' service tag or skip the event, and gate the `vulnerable:` event/finding on a confirmed shell or canary round-trip.


### [false-positive] src/modules/exploits/webapps/drupal11_pathdisclose_cve_2024_45440.rs:56
**Leak heuristic flags any Drupal page via `body.contains("Drupal")`**

The detection treats a response as a path-disclosure 'leak' if the body merely contains the substring "Drupal" (in addition to the genuine `/var/www` etc. path markers). The probe list includes `/CHANGELOG.txt` and `/core/CHANGELOG.txt`, which on every healthy Drupal site contain the word "Drupal" without disclosing any filesystem path. So any normal Drupal install is flagged as leaking, conflating mere fingerprinting with the actual CVE-2024-45440 path-disclosure condition.

_Fix:_ Drop the `|| body.contains("Drupal")` clause from the leak test (use it only as a separate fingerprint signal), and require an actual absolute-path pattern (e.g. a regex for `/[a-z0-9_/-]+/(modules|sites|core)/`) to claim path disclosure.


### [false-positive] src/modules/exploits/webapps/eramba_grc_rce_cve_2023_36255.rs:147
**Command-injection RCE Finding pushed on bare HTTP 2xx**

When no command output (uid=/root:/www-data) is found, the module falls back to `else if exploit_status.is_success() || output_status.is_success()` and pushes a `Vulnerable` Finding stating the CVE-2023-36255 payload was delivered. The download-test-pdf endpoint returning 200 does not prove `$(cmd)`/`|cmd` executed; a patched or non-vulnerable Eramba returning 200 will be reported as exploited.

_Fix:_ Gate the Vulnerable finding on observed command output; record only a Note for the unverified bare-2xx case.


### [false-positive] src/modules/exploits/webapps/git_exposure_rce.rs:261
**git_exposure flags .git/index and generic paths 'EXPOSED' on any 200 over a tiny size**

For /.git/index the exposure condition is `body.starts_with("DIRC") || body.len() > 100`, and for other paths it is `!body.contains("404") && !body.contains("Not Found") && body.len() > 5`. Soft-404 sites that return HTTP 200 with a generic page (>100 / >5 bytes, no literal '404' string) will be marked as having an exposed git repository, populating exposed_paths and driving the module's vulnerable conclusion and workspace::track_host. This produces false git-exposure reports on misconfigured-but-not-vulnerable hosts.

_Fix:_ Require the DIRC magic bytes for /.git/index (drop the `|| body.len() > 100`) and validate content type / structure for other git paths instead of a 5-byte non-404 heuristic; gate the overall finding on a content-validated git artifact (HEAD/config) only.


### [false-positive] src/modules/exploits/webapps/gravcms_sandbox_bypass_cve_2025_66294.rs:64
**Grav CMS reports SSTI RCE when the {{7*7}} canary is merely reflected**

The module pushes a Vulnerable finding on `evaluated || reflected`, where reflected = resp_body.contains("{{7*7}}"). Requesting /{{7*7}} causes most apps to 404 and echo the requested path back, so the literal canary is reflected without any template evaluation. The 'evaluated' branch (contains "49") is also weak ('49' is extremely common). Benign Grav (or any reflecting 404 page) is reported as Twig sandbox-bypass RCE.

_Fix:_ Only treat `evaluated` (a uniquely-valued arithmetic canary not present verbatim in the request, e.g. {{31337*1337}} -> a long product unlikely to appear by chance) as Vulnerable. Mere reflection should be a Note, not a Vulnerable RCE.


### [false-positive] src/modules/exploits/webapps/ias25_idor.rs:51
**IAS IDOR counts any 200 page containing 'Name'/'email' as a leaked record**

An IDOR 'hit' is counted when `status == 200 && (body.contains("Student") || body.contains("Name") || body.contains("email"))`. The words 'Name' and 'email' appear on nearly every web page (forms, footers, login screens, 200 error pages). A site that returns 200 with a generic template for unknown IDs will accumulate hits and report 'IDOR confirmed -- N records leaked' as Vulnerable on benign hosts.

_Fix:_ Require an IAS-specific record marker and detect a stable baseline (compare an invalid/out-of-range id to a valid one) so that a uniform 200-template doesn't register as leaked records. Tighten markers beyond ubiquitous words like 'Name'/'email'.


### [false-positive] src/modules/exploits/webapps/ias25_upload.rs:46
**IAS upload module reports Vulnerable purely on HTTP 200 reachability**

The module GETs /admin/upload.php and pushes a Vulnerable finding whenever `s == 200`, with no content fingerprint and no actual upload attempt. Any host that returns 200 for that path (catch-all homepage, a login-gated upload form, an unrelated app) is reported as a vulnerable IAS upload endpoint. The module description even claims 'chained with default creds -> PHP RCE' but never authenticates or uploads.

_Fix:_ Fingerprint the IAS upload form in the body (specific field/marker) before reporting; downgrade bare reachability to a Note. Ideally perform a benign canary upload + read-back to actually demonstrate the vulnerability.


### [false-positive] src/modules/exploits/webapps/iemm_eli_inject_cve_2025_4427.rs:266
**Ivanti EPMM treats a bare HTTP 500 as confirmed EL injection**

Both the canary stage (line 128) and the final verdict (line 266) accept `canary_status == 500` / `exploit_status == 500` / `shell_status == 500` as proof of EL injection and push a Vulnerable finding. A patched or unrelated server frequently returns 500 when handed an unexpected `format` value, so a 500 alone is reported as confirmed CVE-2025-4427/4428 even though the safe math-canary (the only sound signal) did not evaluate.

_Fix:_ Require the math-canary reflection (canary_body.contains(&expected_result)) or a specific EL exception marker for the Vulnerable verdict. Drop status==500 as a confirmation signal, or downgrade it to a Note.


### [false-positive] src/modules/exploits/webapps/invision_csti_cve_2025_ic506.rs:59
**Invision Community reports CSTI when the {{7*7}} canary is merely reflected**

Identical pattern to gravcms: a Vulnerable finding is pushed on `evaluated || reflected`, where reflected = resp_body.contains("{{7*7}}"). The probe is sent as a query parameter (/?q={{7*7}}); search pages and 404s routinely echo the query verbatim, so the canary is reflected with no template evaluation, falsely reporting CSTI on benign hosts.

_Fix:_ Confirm CSTI only via a hard-to-coincide arithmetic canary that is evaluated (result present, expression absent). Reflection of the raw payload should be downgraded to a Note.


### [false-positive] src/modules/exploits/webapps/opensisce_sqli.rs:137
**SQLi 'confirmed' on the substring 'Warning:' (and 'mysqli') — false positive on benign PHP pages**

The error-based detection marker list includes "Warning:" and "mysqli". PHP emits 'Warning:' notices on countless benign/misconfigured pages unrelated to SQL, and 'mysqli' appears in plenty of normal output. When any marker is found the module pushes a FindingKind::Vulnerable 'openSIS SQLi confirmed' finding, so non-vulnerable openSIS hosts (or any host that reflects a PHP warning) are reported as SQL-injectable.

_Fix:_ Drop the generic 'Warning:' and bare 'mysqli' substrings; restrict to high-signal markers (e.g. 'You have an error in your SQL syntax', 'SQLSTATE[', 'mysqli_sql_exception', the injected ~marker~ tilde delimiters). Better yet require the time-based oracle or the extracted tilde value before classifying as Vulnerable.


### [false-positive] src/modules/exploits/webapps/phpipam_sqli.rs:116
**SQLi 'confirmed' on the substring 'Warning:' (and 'mysqli') — false positive on benign PHP pages**

Error-based detection treats a response containing 'Warning:' or 'mysqli' as proof of SQL injection and pushes a FindingKind::Vulnerable 'phpIPAM SQLi confirmed' finding. Both substrings occur routinely on benign PHP applications, so non-vulnerable phpIPAM hosts will be reported as SQL-injectable.

_Fix:_ Remove 'Warning:' and bare 'mysqli'; require a specific SQL-error signature or the time-based oracle before marking the finding Vulnerable.


### [false-positive] src/modules/exploits/webapps/phpmyadmin_sqli.rs:192
**SQLi 'confirmed' on the substring 'Warning:' — false positive on benign PHP pages**

phpMyAdmin SQLi error-based detection includes the 'Warning:' substring in its marker list; a match pushes a FindingKind::Vulnerable 'phpMyAdmin 5.0.0 SQLi confirmed' finding. PHP 'Warning:' output is extremely common and unrelated to SQL injection, so authenticated phpMyAdmin instances that surface any PHP warning are misreported as injectable.

_Fix:_ Remove the generic 'Warning:' marker; require a specific SQL-error signature or the time-based oracle before recording a Vulnerable finding.


### [false-positive] src/modules/exploits/webapps/piwigo_sqli.rs:136
**SQLi 'confirmed' on the substring 'Warning:' (and 'mysqli') — false positive on benign PHP pages**

The error-based marker list includes 'Warning:' and 'mysqli'; when matched, a FindingKind::Vulnerable 'Piwigo 13.6.0 SQLi confirmed' finding is recorded. These substrings appear on ordinary PHP pages, so benign Piwigo installs that emit any PHP warning get reported as SQL-injectable.

_Fix:_ Drop the generic 'Warning:' / bare 'mysqli' markers; gate the Vulnerable finding on a high-signal SQL error string or the time-based confirmation already computed.


### [false-positive] src/modules/exploits/webapps/tapestry_fileread_cve_2021_27850.rs:509
**is_config_content() treats any body >20 bytes containing a credential keyword as a leaked config**

After the structured YAML/XML/properties checks, is_config_content falls back to returning true for any body longer than 20 bytes that merely contains one of the broad CREDENTIAL_PATTERNS substrings such as "token", "ldap", "secret", "password". Many benign HTML pages (login forms with the word 'password', pages mentioning 'token' or 'LDAP') match. Because the traversal-read loop pushes FindingKind::Vulnerable + stores loot whenever status==200 && is_config_content(body), an ordinary 200 page (e.g. an SPA fallback or login page returned for the traversal URL) is reported as a successful WEB-INF file read.

_Fix:_ Drop the generic >20-byte keyword fallback, or require it together with a strong config-structure marker (e.g. presence of YAML/XML/properties syntax) and verify the body is not HTML (no '<html'/'<!doctype') before declaring a file-read success.


### [false-positive] src/modules/exploits/webapps/vite_path_traversal_cve_2025_30208.rs:156
**File-read success determined solely by status==200 && non-empty body**

Each /@fs/<path>?import&raw read is declared a successful arbitrary file read (FindingKind::Vulnerable + loot) on `status == 200 && !body.is_empty()`, with no validation that the body actually contains the requested file's content. Vite dev servers and SPAs commonly return HTTP 200 with the index.html fallback (or a JS module wrapper) for unmatched paths, so this can flag a patched/benign Vite server as vulnerable for every probe target (etc/passwd, win.ini, etc.).

_Fix:_ Validate the body matches the requested file (e.g. /etc/passwd contains 'root:' and ':/' lines, win.ini contains '[', proc/version contains 'Linux version') and reject HTML/JS-module fallbacks (body starting with '<' or containing 'export default') before recording a file-read finding.


### [false-positive] src/modules/exploits/webapps/wpcpi_upload.rs:46
**Reports Vulnerable on mere presence of plugin readme.txt (HTTP 200)**

The module pushes FindingKind::Vulnerable solely because `/wp-content/plugins/wp-for-cpi/readme.txt` returns HTTP 200. A served readme only proves the plugin is installed — not its version, not that the unauth upload endpoint exists or is exploitable. This flags any site with the plugin installed (including patched versions) as Vulnerable. The sibling module wpgivewp_inject correctly uses FindingKind::Note for the equivalent readme probe.

_Fix:_ Either parse the version from the readme and gate on the vulnerable range, or actually probe the upload endpoint; otherwise use FindingKind::Note for plugin-presence detection.


### [false-positive] src/modules/scanners/cpanel_exposure.rs:84
**check() flags Vulnerable on any redirect/200 without the panel-content heuristic used by run()**

probe_panel() returns true for any response that is_success() OR is_redirection(), and check() reports CheckResult::Vulnerable('Exposed panels') on that alone. Unlike run() (which additionally requires looks_panel: title/Server 'cpsrvd'/location pointing at :2087/:2083/:2096), check() has no content verification. A host that 301-redirects every port (common catch-all / load balancer behavior) is reported as an exposed cPanel/WHM panel. This divergence means the cheap check used by orchestration/scheduling false-positives where the full run would not.

_Fix:_ Make probe_panel() apply the same looks_panel heuristic as run() (title/server/location markers) before returning true, so check() and run() agree on what constitutes an exposed panel.


### [false-positive] src/modules/scanners/h3c_cloudos_api_enum.rs:186
**Any 2xx response flagged as 'unauthenticated data disclosure' regardless of body content**

Both the CloudOS and discovery loops treat status.is_success() alone as 'data disclosed without auth' / 'accessible without auth' and push a Vulnerable Finding, including for empty bodies (body.len()==0), generic HTML login pages that return 200, SPA index pages, or redirect-to-login responses that resolve to 200. There is no check that the body looks like the expected API/JSON payload. On most ordinary web hosts this reports many spurious CloudOS vulnerabilities.

_Fix:_ Require positive evidence before flagging: non-trivial body length, JSON content-type or successful serde_json parse into the expected shape, and absence of login/redirect markers. Treat empty or HTML-login 200s as not-vulnerable.


### [false-positive] src/modules/scanners/php_version_eol.rs:194
**Vicidial 'detected' on any 200/302/401 to common paths, reported as Vulnerable**

The Vicidial probe treats any response with status is_success() OR 401 OR 302 to paths like /vicidial/welcome.php as 'Vicidial endpoint reachable' and pushes a FindingKind::Vulnerable. Many web servers (and SPAs / catch-all redirectors) return 302 to a login page or 401 for arbitrary paths, so a benign non-Vicidial host trivially trips this. The check makes no attempt to confirm Vicidial-specific body markers, so it false-positives broadly and mislabels a generic redirect as a vulnerability.

_Fix:_ Confirm a Vicidial-specific fingerprint in the response body/headers (e.g. 'VICIDIAL', 'vicidial', a known title/asset) before flagging, and demote a bare reachable endpoint to a Note rather than Vulnerable; drop the 302/401-as-hit heuristic or require the Vicidial marker on those statuses.


### [false-positive] src/modules/scanners/reflect_scanner.rs:113
**DNS amplification check flags non-recursive authoritative servers as open resolvers**

check_dns reports an 'open resolver / DNS amplifier' for any DNS response with QR=1 whose RCODE is not REFUSED (rcode != 5). It never inspects the Recursion-Available (RA) bit, so a benign authoritative-only nameserver that simply answers the ANY query for google.com with NOERROR or SERVFAIL is reported as a vulnerable DNS amplification reflector and pushed as a Vulnerable finding. The comment ('Even SERVFAIL means the server accepted the query') reflects the over-broad logic.

_Fix:_ Require the RA bit (buf[3] >> 7 & 1) to be set and answer_count > 0 (recursion actually performed) before flagging an open resolver; treat SERVFAIL/empty answers as not-open.


### [false-positive] src/modules/scanners/sgbox_siem_recon.rs:437
**Login rate-limit probe counts 429 as a 'success', flags rate-limited servers as having NO rate limit**

probe_login_rate_limit increments p.successes on ANY HTTP response, including 429 Too Many Requests / 503 — i.e. exactly the responses a rate-limiting server returns. The run() logic then reports 'no rate limit detected' and emits a HIGH 'LOGIN-NO-RATE-LIMIT' vulnerability finding whenever p.successes >= 5 and no Retry-After header was seen. A server that rate-limits via 429/503 without a Retry-After header (very common) is therefore falsely reported as having no rate limiting.

_Fix:_ Only count 2xx (or non-429/non-503) responses toward p.successes, and treat repeated 429/503 (or growing latency / connection drops) as evidence that rate limiting IS present before asserting its absence.


### [false-positive] src/modules/scanners/ssdp_msearch.rs:276
**SSDP response accepted as a discovered device on any 'HTTP/1.1' status line**

parse_ssdp_response computes status_ok = status_line.contains("200") || status_line.contains("HTTP/1.1"). The `|| contains("HTTP/1.1")` makes the `contains("200")` redundant and accepts ANY HTTP/1.1 status line — e.g. 'HTTP/1.1 404 Not Found' or 'HTTP/1.1 503' — as a successfully discovered UPnP device, emitting a Banner finding and a ServiceDetected event. Any HTTP-speaking host on the probed UDP port (or a captive responder) is reported as a UPnP device.

_Fix:_ Require a genuine SSDP success line, e.g. status_line.starts_with("HTTP/1.1 200") (or split the status code and check == 200) plus at least one SSDP-specific header (USN/ST/Location).


### [false-positive] src/modules/scanners/vuln_checker.rs:206
**Open-port-only TCP probes surface dozens of CVE 'possible' findings on any host with common ports open**

ProbeType::Tcp returns CheckResult::Unknown('port N open') purely on a successful TCP connect, with no service/version confirmation, and run() pushes every Unknown into outcome.findings as a Note. Because many distinct CVE probes map to the same bare port (e.g. heartbleed, http2_rapid_reset, citrixbleed2 family and others on 443; ~15 VNC CVEs all on tcp(5900); several on tcp(80)), any host that merely has 443/5900/80 open is reported as 'Detected / Possible' for a long list of unrelated CVEs. Under fan-out this floods loot/export with low-signal findings.

_Fix:_ Do not emit a per-CVE finding for a bare open port; either grab/inspect a banner before flagging, or collapse open-port results into a single 'port N open' note rather than one Note per CVE probe sharing that port.


### [resource-leak] src/checkpoint.rs:139
**record() after finish() resurrects the deleted checkpoint file (no closed guard)**

finish() (lines 165-173) sets closed=true and removes the file, signalling the checkpoint is complete and should be gone. flush() correctly guards on `if !g.closed`, but record() has no such guard: it pushes to cp.processed and, every FLUSH_EVERY_N, calls flush_locked which opens the path with create(true).append(true) (line 201-206) and re-creates the just-deleted file. Worse, header_written is left true by the prior clean run, so the resurrected file has NO header line — load_from_path (line 60-62) treats the first processed-target line as the header and fails to parse, so the file is unreadable/skipped on the next resume. The current scheduler flow happens to drain all record() tasks before finalize (so it isn't triggered today), but the CheckpointWriter API is Arc-shared and exposes record() and finish() with no ordering contract; any caller that records after finishing silently leaves a corrupt orphan checkpoint on disk.

_Fix:_ Add `if g.closed { return Ok(()); }` at the top of record() (and guard flush_locked likewise) so a post-finish record is a no-op and cannot re-create the deleted file with a missing header.


### [resource-leak] src/context.rs:234
**Deferred-spawn fallback registers tasks after abort_all_spawned drains the JoinSet — orphaned tasks run unbounded and survive cancellation**

context::spawn first tries `ctx.spawned.try_lock()`; on contention it falls back to `tokio::spawn(async move { let mut js = ctx.spawned.lock().await; js.spawn(future); })`, deferring registration. abort_all_spawned (line 250) takes the same lock, calls abort_all(), then drains via join_next(). If abort_all_spawned acquires and releases the lock (or is mid-drain) before the deferred closure acquires it, the future is spawned into a JoinSet that has already been abort_all()'d/drained, so it is never aborted and runs to completion regardless of cancellation. Because the macro calls abort_all_spawned() at the very end of every run, this window is hit precisely when a module spawns a task late in run() under lock contention — exactly the cancellation/cleanup path the tracking exists to protect. The code comment acknowledges the race but it is a real leak/cancellation-escape, not merely theoretical.

_Fix:_ Avoid deferred registration: hold the JoinSet behind a std::sync::Mutex (sync lock, always available) so spawn() can register synchronously, or set a generation/closed flag on the RunContext that abort_all sets and the deferred closure checks before spawning (aborting the future immediately if the run already ended).


### [resource-leak] src/module.rs:654
**check() macro arms (@with_check, @native_with_check) never call abort_all_spawned — tracked spawns leak after check returns**

Both run arms of the macro wrap the body in `RUN_CONTEXT.scope(ctx_arc, async move { let r = run(...).await; abort_all_spawned().await; r })` so tasks registered via ctx.spawn()/crate::context::spawn() are aborted when the run completes. The two check arms (@with_check at lines 654-665 and @native_with_check at lines 739-750) scope the RunContext and run check(), but omit the abort_all_spawned() drain entirely. Any task a module spawns inside check() (e.g. a background banner-grab or timeout watchdog) is registered into the scoped RunContext's JoinSet, then orphaned: when the scope ends the Arc<RunContext> is dropped while its JoinSet still holds live, un-aborted handles. check_module (commands/mod.rs:198) is a real caller, so this leaks tasks on every non-destructive check that spawns.

_Fix:_ Wrap check the same way as run: `.scope(ctx_arc, async move { let r = check(&t).await; $crate::context::abort_all_spawned().await; r })` (and the &ModuleCtx variant for @native_with_check).


### [resource-leak] src/modules/exploits/dos/rudy.rs:303
**RUDY worker tasks not aborted; 10s default byte interval exceeds 5s join timeout, leaking detached connections**

Same pattern as slowloris: execute_attack joins workers with tokio::time::timeout(5s, handle) and never aborts the handles. The drip loop sleeps byte_interval_ms (default 10000ms) between byte writes and only checks stop around the sleep, so a worker can take up to ~10s to observe stop_flag. The 5s join timeout fires first, the handle is dropped un-aborted, and the worker keeps dripping on its TCP/TLS connection (holding the FD) after the module reports 'Attack Complete'. Cancellation is not prompt and connections/FDs leak past the run.

_Fix:_ Call handle.abort() on the timeout branch, or make the drip loop responsive to stop by sleeping in short increments / selecting on a cancellation signal so workers exit within a fraction of a second.


### [resource-leak] src/modules/exploits/dos/slowloris.rs:266
**Worker tasks holding connections are never aborted; long keepalive interval outlives the 5s join timeout, leaking detached tasks/sockets**

On shutdown, execute_attack joins each connection worker with tokio::time::timeout(5s, handle) but never calls handle.abort(); only stats_task is aborted. Each worker's drip loop sleeps for keepalive_interval_secs (default 15s) and only checks stop between sleeps, so when stop_flag is set the worker can take up to a full interval (15s by default) to exit. The 5s join timeout therefore expires first, the JoinHandle is dropped without aborting, and the task keeps running detached — holding its TCP/TLS connection (and FD) well past the module's reported completion. This breaks prompt cancellation and leaks sockets across module runs.

_Fix:_ On the timeout path, call handle.abort() to terminate the detached worker (or restructure the drip loop to sleep in short slices / use tokio::select! on a stop notify so it reacts within well under 5s). Apply the same fix to rudy.rs (byte_interval_ms default 10s vs the same 5s join timeout).


### [resource-leak] src/modules/exploits/routers/tplink/tp_link_vn020_dos.rs:141
**Detached stdin-reader thread and timer task leak per host; can block scheduler fan-out**

In interactive mode with duration==0, the module spawns a std::thread that blocks reading stdin and is never joined or signalled to stop after run() returns. With duration==0 and not api_mode, the stop timer branch (line 127) is not taken, so the flood loop runs until 'stop' is typed — blocking the per-host fan-out on the first host indefinitely. The detached stdin thread persists across the run and competes for global stdin; the timer tokio::spawn is likewise untracked.

_Fix:_ Bound the loop with an effective duration even when duration==0 (as the comment elsewhere intends), avoid spawning an unmanaged stdin thread per host (gate to single-target interactive runs only), and use ctx.spawn / a cancellation token so tasks are cleaned up.


### [resource-leak] src/prescan.rs:222
**Output-cap truncation breaks the read loop but then blocks on child.wait() without killing the child**

When prescan output exceeds max_output (100 MiB) the loop `break`s (line 228) and stops reading stdout, but execution falls through to child.wait().await at line 252 without killing the child. Because nothing is draining stdout anymore, a still-running masscan/zmap will fill the OS pipe buffer and block on write, so it never exits and child.wait() hangs until the outer wall_timeout fires — at which point the child is dropped un-killed (see related finding), leaking the process. The truncation path is meant to protect against a misconfigured tool spewing gigabytes, but it actually leaves that exact misbehaving tool running and orphaned.

_Fix:_ On the truncation break, explicitly kill the child (child.start_kill() / child.kill().await) before draining stderr and calling wait(), and/or set kill_on_drop(true). Do not rely on wait() returning when stdout is no longer being read.


### [resource-leak] src/utils/bruteforce.rs:707
**run_bruteforce accumulates up to MAX_COMBOS JoinHandles in FuturesUnordered without reaping during the spawn loop**

The spawn loop pushes every tokio::spawn handle into `tasks` (FuturesUnordered) but never polls it until after the entire loop finishes (the drain at line 816). The semaphore correctly gates how many tasks RUN concurrently, but completed tasks' JoinHandles are never reaped while spawning continues, so `tasks` grows by one handle per combo — up to MAX_COMBOS (10,000,000). The code comment at 714-716 only addresses runtime task structs, not the JoinHandle backlog. For a 10M-combo run this pins hundreds of MB of JoinHandle/result state for the whole run and delays result/error reaping, contradicting the bounded-memory intent.

_Fix:_ Drain completed handles inside the spawn loop (e.g. `while tasks.len() >= cap { tasks.next().await; }`) or restructure with buffer_unordered over a stream of work so JoinHandles are reaped as tasks finish.


### [mass-scan] src/modules/creds/camxploit/exploit.rs:19
**Hardcoded scan timeouts and ~270-port sweep per host ignore module_timeout under fan-out**

camxploit uses fixed PORT_SCAN_TIMEOUT=2s and TIMEOUT=5s and sweeps the full COMMON_PORTS list (~270 ports) plus many HTTP path probes for every host. The module never consults the configured module_timeout. Under the universal per-host fan-out across a large CIDR/target file this is extremely heavy and unbounded by the operator's timeout setting, and the fingerprint/login/stream functions print per-port lines to stdout via mprintln! with no batch-mode gating (only the banner is gated), spamming output on a large scan.

_Fix:_ Derive connect/read timeouts from ctx module_timeout, and gate per-port discovery prints behind is_batch_mode() (as the banner already is) so mass scans don't flood stdout; consider trimming the default port list.


### [mass-scan] src/modules/exploits/dos/connection_exhaustion_flood.rs:424
**Main wait loop ignores ctx.cancel; finite run sleeps full duration and infinite mode relies on ctrl_c**

execute_stress does not receive or consult ctx.cancel. For a finite run it does a plain tokio::time::sleep(duration) (line 424-425) that is not raced against cancellation, and the infinite mode (duration_secs==0) blocks on tokio::signal::ctrl_c(). Although the workers poll the *global* cancellation_token() and will break, the function will not set stop_flag, print its report, or return until the full duration elapses (or an interactive Ctrl-C arrives). Under /loop or API execution where no Ctrl-C reaches this module, an infinite-duration run cannot be terminated through the framework, and finite runs are unresponsive to ctx.cancel.

_Fix:_ Pass ctx.cancel into execute_stress and replace the duration sleep / ctrl_c wait with a tokio::select! over sleep(duration) and cancel.cancelled() (infinite mode: select only on cancel.cancelled()). Set stop_flag as soon as cancellation fires.


### [mass-scan] src/modules/scanners/honeypot_scanner.rs:136
**Per-host progress table and summary printed to stdout unconditionally (spams under fan-out)**

Mass-scan fan-out is universal (module.rs: modules only ever see Target::Single per invocation, scheduler fans out per host). honeypot_scanner gates only its title banner behind is_batch_mode() (line 229), but scan_targets() prints '[*] Honeypot scan progress' (line 136) and run() always calls print_results() plus a full '=== Summary ===' block (lines 311-324) with no batch-mode gating. Running this module against a /16 produces a results table and summary block per host, flooding stdout.

_Fix:_ Wrap the progress prints, print_results, and the summary block in `if !crate::utils::is_batch_mode()` (as the header already is), relying on ModuleOutcome.findings for batch reporting.



## LOW


### [security] src/modules/exploits/dionaea/mqtt_underflow.rs:116
**MQTT DoS module lacks the SSRF/private-target guard its sibling mssql_dos has**

mssql_dos.rs and snare/cookie_dos.rs both call crate::api::is_blocked_target() to refuse DoS against private/loopback/metadata addresses, but mqtt_underflow.rs (and tftp_crash.rs) never perform this check before sending crash payloads. Under the per-host fan-out these DoS modules will happily attack RFC1918/loopback/metadata hosts, contradicting the framework's own SSRF mitigation policy.

_Fix:_ Add the same `if crate::api::is_blocked_target(&normalized) { ... return Ok(outcome); }` guard to mqtt_underflow.rs and tftp_crash.rs for consistency with the other DoS modules.


### [security] src/modules/exploits/dionaea/tftp_crash.rs:98
**TFTP DoS module lacks the SSRF/private-target guard its sibling mssql_dos has**

tftp_crash.rs sends crash-inducing UDP payloads but never calls crate::api::is_blocked_target(), unlike mssql_dos.rs. This lets the module DoS private/loopback/metadata addresses under fan-out, inconsistent with the framework's SSRF policy applied to other DoS modules in the same package.

_Fix:_ Add the `crate::api::is_blocked_target(&normalized)` guard before sending the malformed RRQ, matching mssql_dos.rs.


### [error-swallowing] src/module.rs:184
**ModuleOptions::get_or silently swallows parse failures and returns the default**

get_or does `self.inner.get(key).and_then(|v| v.parse().ok()).unwrap_or(default)`. When the operator supplies a value that is present but unparseable for the target type (e.g. `port=80x`, `threads=-1`, `port=abc`), the `.ok()` discards the parse error and the call silently returns the default as if the operator had set nothing. This hides operator typos: a module configured with an invalid port/threads value runs against the wrong (default) parameter with no warning, which for an offensive tool can mean scanning the wrong port entirely. There is no way for the caller to distinguish 'key absent' from 'key present but malformed'.

_Fix:_ Provide a fallible accessor (e.g. `get_parsed<T>(&self, key) -> Result<Option<T>>`) used in pre_check so a present-but-malformed value surfaces a single error before fan-out, and have get_or at minimum log a warning (not trace/debug) when a present value fails to parse before falling back.


### [error-swallowing] src/modules/creds/camxploit/exploit.rs:701
**RTSP auth check silently treats connect/read errors as auth-failed**

test_rtsp_auth uses `if let Ok(mut stream) = tcp_connect...` and `if let Ok(Ok(n)) = timeout(...)` with no else branch, returning false on any connection or read error. A transient error during the RTSP OPTIONS probe is indistinguishable from a definitive auth failure, so a momentarily-unreachable camera is reported as having no valid RTSP credentials. There is also no retry.

_Fix:_ Distinguish transport errors from auth failures (return a tri-state) and retry transient connect/read errors before concluding the credential is invalid.


### [error-swallowing] src/modules/creds/generic/snmp_bruteforce.rs:111
**SNMP UDP recv timeout silently classified as AuthFailed**

In `probe`, a recv timeout on the UDP socket is mapped to `LoginResult::AuthFailed` (a definitive 'community string is wrong') rather than a retryable error. For connectionless UDP, a missing response far more often means the datagram was dropped, the host is filtered, or the agent is slow than that the community was rejected (SNMPv2c agents typically just stay silent for a bad community — there is no negative ack). Classifying every silent/lost-packet case as AuthFailed means a single dropped probe permanently marks that (host, community) as failed with no retry, so valid communities on lossy paths are silently missed, and genuine reachability problems are hidden as auth failures.

_Fix:_ Return `LoginResult::Error { message: "snmp recv timeout".into(), retryable: true }` on the timeout branch so the engine retries the datagram before giving up, instead of treating packet loss as an authoritative auth failure.


### [error-swallowing] src/modules/exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection.rs:138
**Capped body read errors swallowed with .unwrap_or_default()**

`read_http_body_capped` returns a real error on stream failure or when the body exceeds the 4 MiB cap, but both the canary phase and the payload loop discard that error via `.map(...).unwrap_or_default()`, turning any read/cap failure into an empty string. A truncated/oversized response is then silently treated as 'canary not reflected' / empty body, masking the real network error from the operator.

_Fix:_ Match on the Result and log/propagate the error (e.g. print '[-] body read failed/exceeded cap: {e}') instead of silently substituting an empty body.


### [error-swallowing] src/modules/exploits/frameworks/apache_camel/cve_2025_27636_camel_header_injection.rs:116
**Baseline probe failure printed at red but otherwise ignored, run continues regardless**

The Phase-1 baseline GET failure is only printed and the module proceeds to send canary/exec payloads against an unreachable host. Combined with the body-error swallowing above, a host that is down or rejecting connections produces a noisy but inconclusive run. While printing is better than nothing, the failure does not influence control flow or the final outcome.

_Fix:_ Consider bailing (or short-circuiting subsequent phases) when the baseline connection fails, so the module does not report ambiguous 'payloads delivered' against an unreachable target.


### [error-swallowing] src/modules/exploits/ftp/ftp_bounce_test.rs:222
**FTP login error discarded at debug; connection treated identically to bad-creds**

On ftp.login() failure the error is logged only at tracing::debug and the function returns false (not vulnerable). A real failure such as a TLS/auth/protocol error, server overload, or transient disconnect is silently collapsed into the same 'not vulnerable' result as a legitimate credential rejection, so genuine errors are invisible in normal output and the host is recorded as clean.

_Fix:_ Distinguish authentication-rejected (530/incorrect) from transport/protocol errors; surface the latter to the operator (or as an Error/Note) instead of silently returning false.


### [error-swallowing] src/modules/exploits/ipmi/ipmi_enum_exploit.rs:481
**Cipher-0, anonymous, and RAKP checks swallow all errors via `if let Ok(...)`**

The cipher-0, anonymous, default-cred, and RAKP probes are all gated with `if let Ok(true) = f().await` / `if let Ok(Some(..)) = f().await` and no else branch. Any error returned by these probes (send failure, recv error, timeout) is silently discarded and treated identically to 'not vulnerable'. A transient network failure during, say, the cipher-0 probe will quietly downgrade a vulnerable host to not-vulnerable with no log at info level. This is the error-swallowing pattern the maintainer is most concerned about.

_Fix:_ Match the full Result and at least log probe errors at warn level (distinguishing 'errored' from 'confirmed not vulnerable'), so a network failure during a sub-check is not silently reported as 'feature absent'.


### [error-swallowing] src/modules/exploits/network_infra/checkpoint_fileread_cve_2024_24919.rs:61
**send() `?` inside payload loop aborts before trying the operator-supplied payload**

Inside `for body in payloads`, the request is `let resp = client.post(&url).body(body.clone()).send().await.context("probe")?;`. A transient network error on the first (canonical /etc/shadow) payload propagates with `?` and aborts the loop, so the second, operator-supplied custom file-path payload is never attempted. A single failed request prevents the fallback payload from running.

_Fix:_ Wrap send()/text() in a match that logs the error and `continue`s to the next payload, so a failure on one payload does not skip the remaining payload(s).


### [error-swallowing] src/modules/exploits/vnc/tigervnc_timing_oracle.rs:70
**Per-sample auth RTT errors silently dropped, skewing the oracle**

Both sampling loops use `if let Ok(rtt) = measure_auth_rtt(...).await { ... }` with no else. Connection failures, RST, rate-limit drops, or auth-result read timeouts are silently discarded — they never increment a failure count and never warn. If the server rate-limits and only the fast-rejecting attempts succeed while slow ones time out, the surviving sample set is biased, yet the module still computes a mean and can emit a 'timing oracle signal detected' Vulnerable finding from a non-representative sample. Failures are invisible to the operator.

_Fix:_ Track and log failed samples (e.g. count errors, warn if failure rate is high) and refuse to report a finding when a large fraction of samples failed, since selective dropping biases the timing comparison.


### [error-swallowing] src/modules/exploits/voip/xorcompbx_rce.rs:51
**Authentication failure is logged but ignored; exploit proceeds with no session**

The login POST result is only printed; on Err it prints "Login failed" and continues. There is no cookie/session capture and no check that authentication actually succeeded before attempting the 'auth-required' command-injection endpoints. A failed auth (wrong creds, connection error) silently proceeds to the injection loop, so a negative result is indistinguishable from an unauthenticated probe and the module never reports the real auth error.

_Fix:_ Capture and reuse the session cookie from the login response, verify authentication succeeded (status / dashboard marker), and abort with the error if login fails instead of continuing.


### [error-swallowing] src/modules/scanners/m365_userenum_scanner.rs:104
**GetCredentialType non-JSON / throttled responses silently collapse to 'unknown' and are dropped**

check_user parses the response with serde_json::from_str(&txt).unwrap_or(Value::Null) and then IfExistsResult.as_i64().unwrap_or(-1). When Microsoft returns a non-JSON body (HTML throttle/interstitial, WAF block, or a body that omits IfExistsResult), the function returns -1, which label_result maps to 'unknown' and run() silently treats as not-a-hit. A sustained 429/non-JSON condition therefore yields an entirely empty user-enum result with no error surfaced, masking that the enumeration never actually worked.

_Fix:_ Distinguish parse/transport failure from a genuine 'missing' result: return an Err (or a dedicated variant) when the body is not valid JSON or lacks IfExistsResult, and surface a warning/abort if a high fraction of probes fail, so the operator knows enumeration was throttled rather than empty.


### [error-swallowing] src/modules/scanners/redfish_unauth_enum.rs:110
**Redfish check() conflates connection failure with 'not vulnerable'**

In the non-destructive check(), `if let Ok(resp) = client.get(&root_url).send().await { ... }` has no else arm; on a connection error it falls through to try the next scheme, and if both schemes error it returns CheckResult::NotVulnerable("Redfish endpoint not reachable"). A transient TLS/timeout/connection-refused error is therefore reported as NotVulnerable rather than an Error, so the UI/automation treats an unreachable-due-to-error host the same as a confirmed-safe host.

_Fix:_ Track whether any send() returned Err and, if no scheme produced a response, return CheckResult::Error("target unreachable: <last error>") instead of NotVulnerable so genuine connectivity failures are distinguishable.


### [error-swallowing] src/modules/scanners/waf_detector.rs:236
**Scheme-selection probe discards response and silently swallows the error path**

When the target has no scheme, the module issues an extra HTTPS request solely to pick a scheme via `.is_ok()`, throwing away the actual response (wasting a round trip and any headers it could have analyzed) and silently falling back to plain HTTP on any error — including transient timeouts that would also make the subsequent HTTP probe fail. Combined with resp.bytes().await.unwrap_or_default() (lines 270/327), body-read failures are treated as an empty body (no WAF), so a WAF that resets the connection mid-body is reported as 'No WAF detected'.

_Fix:_ Reuse the scheme-selection response (analyze it directly instead of discarding it), and surface body-read errors (don't silently default to an empty body) so a mid-transfer reset isn't reported as 'no WAF'.


### [error-swallowing] src/pq_middleware.rs:423
**Malformed X-PQ-Method silently falls back to wire POST instead of being rejected (`if let Ok` with no else)**

The semantic HTTP method (already AEAD-authenticated as part of the AAD at line 392) is parsed with `if let Ok(restored) = semantic_method.parse::<Method>()` and applied; on parse failure there is no else branch, so the request silently proceeds with the wire method (always POST). A client that authenticated a non-standard/invalid method string in its AAD will have its request dispatched against POST routes rather than failing closed, which can cause confusing routing or a request that the client believes was a GET/DELETE being handled by a POST handler. The error is fully swallowed (not even logged).

_Fix:_ Return StatusCode::BAD_REQUEST (and log) when semantic_method fails to parse into a Method, since the value was authenticated and an unparseable method indicates a malformed/compromised request.


### [error-swallowing] src/utils/bruteforce.rs:357
**is_ip_checked silently returns 'not checked' for invalid state-file names, defeating resume without any signal**

is_ip_checked rejects any state_file that is absolute or contains '..', '\0', '/', or '\\' by returning false (treated as 'IP not yet checked'). mark_ip_checked applies the same validation but instead prints an error and no-ops the write. So if an operator configures a state_file name that trips validation, is_ip_checked silently reports every IP as un-checked and mark_ip_checked silently writes nothing: the resume/checkpoint feature does nothing, every IP is rescanned, and the only signal is on the write side (and only via meprintln, not on the read side). The read path swallows the misconfiguration entirely.

_Fix:_ Validate the state-file name once, up front (in run_subnet_bruteforce / SubnetScanConfig construction) and fail loudly, rather than per-call silently. Return Result from is_ip_checked so an invalid path is an error, not a false negative.


### [error-swallowing] src/workspace.rs:222
**list_workspaces() silently stops enumerating on the first directory-iteration error**

The `while let Ok(Some(entry)) = entries.next_entry().await` loop terminates the moment next_entry() yields an Err (e.g. a transient EIO / a single bad dirent), silently truncating the workspace list rather than skipping the bad entry or reporting the error. An operator could be shown a partial list of their workspaces with no indication anything was dropped, and could believe a workspace was lost.

_Fix:_ Use `loop { match entries.next_entry().await { Ok(Some(e)) => ..., Ok(None) => break, Err(e) => { eprintln!("[!] error reading workspaces dir: {e}"); continue/break } } }` so iteration errors are surfaced rather than silently truncating the result.


### [silent-loss] src/module.rs:620
**Legacy macro arms (@no_check, @with_check) discard RunContext.output — structured findings recorded via output::add_finding never reach ModuleOutcome**

The legacy run arms scope a fresh RunContext, run the legacy `run(&str)` body (which records structured findings into the task-local RunContext.output via crate::output::add_finding, output.rs:342-345), then throw the RunContext away and return `ModuleOutcome::ok()` with an empty findings vec. route_findings (scheduler.rs:1078) only iterates outcome.findings, so anything a legacy module accumulated into RunContext.output is silently dropped — it never reaches loot/workspace/events/export or the scheduler hit-count. The RunContext Arc is constructed locally inside the macro and never read back (rc.output.take() is never called). Currently lower-impact because all 382 in-tree modules use the `native` shape, but the legacy arms remain a live API documented as supported ('cfg_prompt_* / ctx.spawn / is_cancelled work uniformly'), so any future legacy module silently loses its findings.

_Fix:_ Capture the RunContext Arc, and after the scope returns convert its accumulated output into Findings: e.g. `let out = ctx_arc.output.take(); let mut outcome = ModuleOutcome::ok(); outcome.findings = map_module_output_to_findings(out); Ok(outcome)`, so legacy modules' structured output is routed like native outcomes.


### [panic-oom] src/modules/exploits/network_infra/qnap/qnap_qts_rce_cve_2024_27130.rs:77
**Unbounded `payload_size` causes huge allocation**

`payload_size` is parsed into a `usize` and then `"A".repeat(size)` allocates that many bytes with no upper bound. The default is 1024, but an operator option/global (`payload_size`) of e.g. 99999999999 will attempt a multi-GB/TB allocation and abort the process before any request is sent. Lower severity because the value is operator-supplied rather than attacker-controlled, but it is an unguarded allocation off untrusted-ish config input.

_Fix:_ Clamp `size` to a sane maximum (e.g. reject or cap at a few KB/MB) before calling `"A".repeat(size)`, returning a clear error if the requested size is unreasonable.


### [panic-oom] src/modules/exploits/webapps/craftcms_key_rce_cve_2025_23209.rs:233
**UTF-8 boundary panic when truncating discovered security key for display**

After parsing a security key out of a leaked `.env` body, the module prints a preview via `&key[..key.len().min(8)]`. This is a byte slice; if the parsed key value contains a multi-byte UTF-8 character whose boundary falls within the first 8 bytes (attacker-controlled `.env` content is returned verbatim by the target), the slice panics with 'byte index N is not a char boundary', aborting the module after it already found the key.

_Fix:_ Use a char-safe truncation, e.g. `key.chars().take(8).collect::<String>()`, instead of byte-index slicing.


### [panic-oom] src/modules/exploits/webapps/n8n/n8n_rce_cve_2025_68613.rs:172
**Char-boundary panic truncating server-issued token for logging**

The auth token returned by the server (self.token) is previewed via `&t[..20]` guarded only by `t.len() > 20`. A token containing multi-byte UTF-8 whose byte 20 is not a char boundary will panic the slice. Lower severity than the others since tokens are usually ASCII, but it is still attacker-influenceable output.

_Fix:_ Use `t.chars().take(20).collect::<String>()` instead of a byte-index slice.


### [panic-oom] src/ws.rs:1444
**rpc_get_result reads result files fully into memory with no size cap**

rpc_get_result reads the entire result file via tokio::fs::read_to_string with no length limit and returns the full content plus content.len() in the JSON response. The write side caps loot at 100 MiB (rpc_add_loot, line 1164) and the request body at 2 MiB (api.rs:823), but module-produced result .txt files (e.g. bruteforce output_file) can be arbitrarily large. Reading such a file fully into a String, then re-serializing it into a JSON value and a 2 MiB-capped... actually unbounded ws frame buffer, can spike memory and OOM the server. The audit's panic-oom category flags exactly this kind of unbounded read.

_Fix:_ Stat the file first and reject (or stream/paginate with an offset like rpc_get_job does) if it exceeds a sane cap (e.g. a few MiB). Read with a bounded reader (take(MAX)) rather than read_to_string of the whole file.


### [logic-flaw] src/module.rs:412
**Module::cleanup / ModuleCtx::spawn docs claim the scheduler aborts tracked spawns in cleanup, but the scheduler cleanup path runs outside any RUN_CONTEXT scope**

The doc comments on Module::cleanup (lines 412-421) and ModuleCtx::spawn (lines 343-348) state that 'the scheduler aborts every tracked spawn in Module::cleanup' so cancelled/failed runs don't leak. In reality abort_all_spawned() reads the task-local RUN_CONTEXT, which is only installed inside the macro's per-run scope; the scheduler's cleanup path (scheduler.rs:303-309) builds a brand-new ModuleCtx and calls module.cleanup() with no RUN_CONTEXT scope, so an abort_all_spawned() invoked from a cleanup hook would be a silent no-op (try_with returns Err and the function returns without aborting anything). The actual aborting happens per-host at the end of each run inside the macro. This stale/incorrect documentation will mislead a maintainer into relying on cleanup to reap long-lived spawns that need to outlive a single per-host run — they will leak because cleanup cannot reach the (already-dropped) per-run JoinSets.

_Fix:_ Correct the docs to state spawns are aborted at the end of each per-host run() (inside the registration macro), not in cleanup; and if cross-run cleanup of spawns is desired, have the scheduler scope the cleanup_ctx's RunContext (or pass the JoinSet) so abort_all_spawned() actually has a context to operate on.


### [logic-flaw] src/modules/exploits/frameworks/h3c_bmc/h3c_bmc_firewall_dump.rs:489
**sanitize_host truncates IPv6 literals at the first colon, corrupting the host**

sanitize_host does `if let Some(colon) = t.find(':') { t.truncate(colon); }`. For an IPv6 target like '2001:db8::1' or '[2001:db8::1]' this truncates at the first ':' yielding '2001' (or '' after bracket stripping), so the BMC is queried at the wrong/empty host. The same flawed helper is duplicated in h3c_ipmi_hash_dump.rs, h3c_kvm_protocol_probe.rs, h3c_redfish_config_dump.rs, and h3c_websocket_dump.rs. Under the per-host fan-out an IPv6 scope silently scans the wrong address.

_Fix:_ Detect bracketed IPv6 (`[...]`) and bare IPv6 (more than one ':') and preserve the address; only strip a trailing ':port'. Prefer the shared normalize_target/URL parsing used elsewhere in the codebase.


### [logic-flaw] src/modules/exploits/frameworks/jenkins/jenkins_args4j_rce_cve_2024_24549.rs:204
**Module file/registration name CVE-2024-24549 contradicts its actual CVE (CVE-2024-23897)**

The file is named jenkins_args4j_rce_cve_2024_24549.rs and registered as 'frameworks/jenkins/jenkins_args4j_rce_cve_2024_24549', but every reference, finding message, info() block, and exploit logic targets CVE-2024-23897 (args4j @-expansion file read). CVE-2024-24549 is an unrelated Jenkins DoS. Operators selecting the module by its CVE-2024-24549 path get a different vulnerability than advertised, and reporting/loot is mislabeled relative to the module path.

_Fix:_ Rename the file and registration path to reflect CVE-2024-23897 (and deduplicate against the near-identical jenkins_cli_rce_cve_2024_23897.rs module), or correct the contents if CVE-2024-24549 was actually intended.


### [logic-flaw] src/modules/exploits/vnc/tightvnc_predictable_challenge.rs:136
**srand seed reconstruction uses a non-glibc LCG, so it never matches**

simulate_srand_challenge claims to reproduce glibc srand(seed)+rand() but implements a raw 32-bit LCG (state = state*1103515245+12345; byte = state>>16). glibc's rand() since ~1995 uses an additive feedback (TYPE_3) generator, not this LCG, and TightVNC runs on Windows where the CRT rand() is yet another LCG with different output extraction. The predicted challenge will therefore essentially never equal the real 16-byte challenge, so the 'Challenge reconstructed' finding can never legitimately fire. (It does not false-positive because it requires an exact 16-byte match, so impact is a dead/misleading feature rather than a bad report.)

_Fix:_ Implement the actual PRNG of the target platform (Windows MSVCRT rand() for TightVNC, or glibc TYPE_3 if targeting libvncserver) for the seed-reconstruction path, or remove the reconstruction claim and rely solely on the identical-challenge comparison.


### [logic-flaw] src/modules/exploits/webapps/beego_traversal_lfi.rs:67
**Custom file probe hardcodes 'root:' marker, breaking confirmation for non-passwd files**

When the operator sets a custom file to read (e.g. `windows/win.ini`, `etc/shadow`, an app config), the module builds the traversal payload for that file but pairs it with the fixed marker `"root:"` (line 67). Confirmation at line 91 only succeeds if the response contains `root:`. So a successful arbitrary read of any file that does not literally contain `root:` is treated as 'not confirmed' — a false negative that silently fails to record a real LFI. The comment even claims the custom file 'uses the same marker heuristic as a passwd read', which is wrong for arbitrary files.

_Fix:_ For the operator-supplied file, confirm the read using a content-independent signal (e.g. status 200 with a body length/diff that differs from a known-bad traversal target, or a baseline comparison), or let the operator supply the expected marker — don't assume every custom file contains `root:`.


### [logic-flaw] src/modules/exploits/webapps/casdoor_traversal_cve_2023_34927.rs:61
**Confirmed traversal recorded as FindingKind::Note instead of Vulnerable**

When `body.contains("root:") || body.contains("[fonts]")` confirms the directory traversal (an actual arbitrary file read of /etc/passwd or win.ini), the module pushes the finding with `kind: FindingKind::Note` rather than `FindingKind::Vulnerable`. This under-classifies a confirmed CVE-2023-34927 exploit, so downstream severity-based filtering/export/hit-counting that keys on Vulnerable will miss it. (The sibling beego module correctly uses Vulnerable for the same class of bug.)

_Fix:_ Use `FindingKind::Vulnerable` for the confirmed file-read, matching the beego_traversal_lfi module.


### [logic-flaw] src/modules/scanners/dir_brute.rs:383
**Cancellation only checked once per task, not between methods in NUKE/DESTROY modes**

Each spawned task checks cancellation only at entry (line 374). In scan_mode 2/3 the inner `for method in methods` loop issues up to 9 requests (including DELETE/PUT) per word with no per-iteration cancellation check. After the operator cancels, in-flight tasks continue firing all remaining destructive methods for their current word, so DELETE/PUT requests keep hitting the target after Ctrl+C/cancel.

_Fix:_ Add `if cancel.is_cancelled() || crate::context::is_cancelled() { return Ok(()); }` at the top of the `for method in methods` loop so destructive requests stop promptly on cancellation.


### [logic-flaw] src/pq_channel.rs:604
**Handshake creates and stores a session with no client proof-of-possession; enables session-eviction DoS using only public keys**

process_handshake authorizes solely on the client's *public* identity key matching authorized_keys (lines 604-610) and unconditionally builds and stores a PqSession (caller inserts it into the bounded MAX_PQ_SESSIONS=1000 store, evicting the oldest by last_activity). Proof that the client actually holds the matching identity private key is only implicit — it surfaces later via AEAD on the first encrypted request, not during the handshake. Since identity public keys are by definition public (and authorized_keys may be shared/leaked or readable by any low-privilege authorized client), an actor knowing a victim identity's public key can spam handshakes to mint sessions and evict legitimate live sessions, degrading service for other tenants. Per-IP rate limiting (10/min) and the X-Forwarded-For rightmost handling bound but do not eliminate this with multiple sources.

_Fix:_ Either require an explicit client-side proof-of-possession (e.g. a client-computed identity_proof over ss_id echoed back before the session is committed to the store), or evict only sessions that have never completed an authenticated request, so unauthenticated handshake spam cannot displace established sessions.


### [logic-flaw] src/shell.rs:294
**Command-chain splitter mangles option values containing '&' or ';'**

The whole input line is split on '&' and ';' (CHAIN_SEPARATORS) before any command is parsed, with no quoting/escaping. Any legitimate option value containing those characters is silently broken into separate 'commands'. For example `setg wordlist /tmp/a&b.txt` becomes the chain segments `setg wordlist /tmp/a` and `b.txt`, so the wordlist is stored as `/tmp/a` and `b.txt` is reported as an unknown command — without any indication the value was truncated. URLs with query strings (`set url http://h/?a=1&b=2`) are similarly corrupted. Because option setting reports success on the truncated value, the operator silently runs with a wrong configuration.

_Fix:_ Only treat '&'/';' as separators when surrounded by whitespace (e.g. split on ' & ' / ' ; '), or support quoting so values with these characters can be passed verbatim. At minimum, document and warn when a set/setg value would be split.


### [logic-flaw] src/shell.rs:344
**Shell exit performs no job cleanup despite help promising 'Active background jobs are cancelled'**

The `help exit` man page states 'Active background jobs are cancelled; workspace data is persisted.' (shell.rs:1912). On exit the main loop only calls rl.save_history and returns Ok(()) — there is no call to JOB_MANAGER to cancel or await running jobs, and main.rs (main.rs:234-246) does no cleanup after interactive_shell returns. Running background tasks are merely aborted abruptly when the tokio runtime tears down on process exit, not cooperatively cancelled. Combined with finding #1 (cooperative cancel is broken for shell jobs), in-flight module work (e.g. a partially written output_file or loot store) can be cut off without the documented graceful cancellation, and the help text is misleading.

_Fix:_ Before returning from the shell loop, enumerate JOB_MANAGER jobs and call kill on each running one (and optionally await a brief grace period), or correct the help text to state that jobs are aborted on exit rather than cancelled gracefully.


### [logic-flaw] src/utils/bruteforce.rs:296
**generate_random_public_ip fallback returns an IP that may be in the exclusion set, violating its own contract**

The function's final fallback (after both the main 500k-attempt loop and the 1024-attempt 44.0.0.0/0..46 loop are exhausted) returns `IpAddr::V4(last)` unconditionally. `last` is whatever the final iteration produced and is NOT re-checked against `exclusions`. The surrounding comments explicitly claim it 'still honour the exclusions' and 'an unchecked return could hand the scanner an address the operator explicitly excluded (owned/Cloudflare/etc)' — yet that is exactly what this return does. If the operator's exclusion list covers 44-45.x, the scanner can be handed an excluded (potentially owned/CDN) address to probe.

_Fix:_ Either return Result/Option so the caller can handle exhaustion explicitly, or pick a hardcoded address verified to be outside the exclusion set; do not return an unchecked candidate that contradicts the documented guarantee.


### [logic-flaw] src/workspace.rs:222
**list_workspaces() reports backup/temp sidecar files as bogus workspaces**

list_workspaces collects file_stem of every entry in the workspaces dir with no extension filter (lines 222-226). The save path writes `<name>.json.tmp` and the corruption paths create `<name>.json.bak` / `<name>.json.unreadable`. The file_stem of `default.json.bak` is `default.json`, so these sidecar files surface as fake workspaces named e.g. `default.json`. Selecting one would `load()` a non-existent `default.json.json` and silently produce an empty workspace. (Loot's checkpoint listing correctly filters by extension == json; workspace does not.)

_Fix:_ Only include entries whose extension is exactly `json` (path.extension() == Some("json")) before taking the file_stem, matching the filter used in checkpoint::list_checkpoints.


### [logic-flaw] src/ws.rs:188
**Cross-tenant data leak: per-request resolve() silently falls back to process-global stores on registry rejection**

handle_ws validates the tenant once via resolve_for (which returns Err on registry cap), but every RPC handler invoked thereafter (rpc_set_target, rpc_add_cred, rpc_list_creds, etc.) calls crate::tenant::resolve(), which on a registry get_or_create failure logs a warning and returns the PROCESS-GLOBAL singleton stores (tenant.rs:202-209, Stores accessors return crate::cred_store::CRED_STORE etc. when tenant is None). If the registry cap is reached between connect-time validation and a later dispatch, two different tenants both fall back to the same global CRED_STORE/WORKSPACE/GLOBAL_OPTIONS, so one client can read and write another client's credentials, hosts and loot. The error (tenant rejection) is swallowed to a debug/warn log and the request proceeds against shared state instead of being rejected.

_Fix:_ Make resolve() return a Result and have the WS/API RPC handlers reject with an error code when the tenant cannot be resolved, instead of silently degrading to the shared global stores. Never serve one authenticated tenant's request out of the process-global store.


### [false-positive] src/mcp/resources.rs:63
**resources/read of an unknown URI returns a successful read containing an error string instead of an error**

read_resource's catch-all arm returns a ResourceContent with mimeType text/plain and text "Unknown resource: <uri>", and handle_resources_read (server.rs:261-264) wraps any returned ResourceContent in JsonRpcResponse::success. So a typo'd or nonexistent resource URI is reported to the client as a successful resources/read whose body happens to contain the words 'Unknown resource', rather than a JSON-RPC error. A client cannot programmatically distinguish a real resource from a missing one, and may treat the error text as legitimate resource content.

_Fix:_ Have read_resource return Result<ResourceContent, String> (or Option) and have handle_resources_read emit JsonRpcResponse::error (code -32602 'Resource not found') for unknown URIs instead of a success response.


### [false-positive] src/modules/creds/generic/m365_activesync_spray.rs:133
**Bare HTTP 200 classified as 'VALID CREDENTIALS - MFA BYPASSED' for ActiveSync/EWS**

classify_http_response maps status 200 directly to a valid-credential hit and the spray task pushes a SprayHit on status==200 alone. M365 EWS/ActiveSync can return 200 for some unauthenticated or informational responses; relying solely on the 200 status (without inspecting the X-MS-Diagnostics body or an authenticated-content marker) risks reporting MFA-bypass credentials that are not actually valid.

_Fix:_ Confirm success using the X-MS-Diagnostics header / response semantics (no 'UserNotFound'/lockout diagnostics and an authenticated response signature) in addition to the 200 status before recording a credential.


### [false-positive] src/modules/exploits/cameras/uniview/uniview_nvr_pwd_disclosure.rs:134
**Uniview disclosure proceeds and emits credential findings without confirming a Uniview NVR or request success**

model/sw_ver are parsed with .unwrap_or("Unknown") and the module continues regardless of the HTTP status or whether the response is actually from a Uniview NVR. It then parses the config XML and pushes a FindingKind::Credential for every <User .../> element found. There is no check that cmd=116/cmd=255 actually returned Uniview-format data; any HTTP server that returns XML containing empty <User> elements, or that reflects/serves an unrelated XML doc with such tags, will yield credential findings (with empty decoded passwords). Combined with the model defaulting to 'Unknown', the module can report 'disclosed credentials' against non-Uniview hosts.

_Fix:_ Verify the version response status and that szDevName/szSoftwareVersion were actually present (bail out if both are 'Unknown') before attempting config extraction, and skip <User> elements that lack a non-empty UserName/RvsblePass so benign XML cannot produce empty credential findings.


### [false-positive] src/modules/exploits/frameworks/jenkins/jenkins_cli_rce_cve_2024_23897.rs:181
**extract_leaked_lines harvests arbitrary plaintext lines as 'leaked file content'**

In addition to the reliable `No such agent "..."` regex, extract_leaked_lines appends every non-empty body line that does not start with ERROR/'<'. The Vulnerable finding gate at line 87 correctly also requires `body.contains("No such agent \"")`, so this does not cause a false-positive Finding, but it pollutes the 'Leaked File Content' display with unrelated response lines (proxy banners, plaintext error text), misleading the operator about what was actually exfiltrated.

_Fix:_ Restrict extraction to the captured `No such agent "(.*)"` groups only; drop the catch-all line loop or clearly separate it as 'other response lines' rather than presenting it as leaked file content.


### [false-positive] src/modules/exploits/webapps/azureapim_checker.rs:49
**Azure APIM 'vulnerable' Finding on mere fingerprint substring**

The module's name advertises a 'cross-tenant signup bypass' check, but the only test performed is fetching `/internal-status-...` and checking `body.contains("ApimUid")`. If present it pushes a `FindingKind::Vulnerable`. This only fingerprints that an Azure APIM developer portal exists; it does not test the cross-tenant signup-bypass weakness at all, so it labels every detected APIM portal as Vulnerable regardless of whether the signup bypass is actually present.

_Fix:_ Either actually exercise the signup-bypass path before claiming Vulnerable, or change the kind to `FindingKind::Note` ("APIM portal detected") so a detection is not reported as an exploitable vulnerability.


### [false-positive] src/modules/exploits/webapps/eduplus_idor.rs:61
**IDOR confirmed if any response contains the word 'payment'**

An ID is counted as 'accessible without auth' when the response is HTTP 200 and the body contains `"amount"` OR `"payment"`. The endpoint path itself is `/api/v1/student/payment/{id}`, so a generic 200 error/landing page, a login redirect rendered with 200, or a JSON error that echoes the word 'payment' will match. With a single such match (`found > 0`) the module pushes a Vulnerable IDOR Finding. A real IDOR check should compare distinct records and confirm they belong to different students.

_Fix:_ Require the response to be valid JSON with a per-student payment record and that distinct IDs return distinct, non-error bodies (as the api_attack_suite BOLA probe does), before declaring IDOR.


### [false-positive] src/modules/exploits/webapps/jsonpath_plus_rce_cve_2025_1302.rs:51
**JSONPath Plus detection matches the literal '$..' it sent in the request**

Detection is `body.to_lowercase().contains("jsonpath") || body.contains("$..")`. The module's own request is /api/jsonpath?expr=$..*, so any endpoint that reflects the query string (including generic 404 pages echoing the URL) contains '$..' and triggers a finding. It only emits a Note (not Vulnerable), limiting impact, but it still produces spurious notes on benign hosts.

_Fix:_ Require a JSONPath-evaluation signal that is not simply the reflected expression (e.g. evaluated output of a probe expression), not the presence of '$..' which the module itself supplied.


### [false-positive] src/modules/exploits/webapps/react_rsc_rce_cve_2025_55182.rs:181
**React RSC RCE confirmed on loose substrings ('root:', 'www-data') without the unique marker**

Besides the unique random marker check, the module also treats any response containing 'uid=', 'root:', or 'www-data' as confirmed RCE and pushes a FindingKind::Vulnerable finding. These probes are sent to the site root '/', whose normal HTML/JSON can legitimately contain 'root:' (docs, /etc/passwd examples, JSON keys) or 'www-data', producing a false 'CVE-2025-55182 RCE likely' finding on benign Next.js sites.

_Fix:_ Confirm RCE only via the unique injected marker (echo MARKER && cmd). If the marker is absent, do not classify as Vulnerable based on generic 'root:'/'www-data' substrings; at most emit a Note for manual review.


### [false-positive] src/modules/scanners/redfish_unauth_enum.rs:251
**Redfish auxiliary-endpoint probe marks any 200 as an unauthenticated leak**

In the auxiliary-endpoint loop a FindingKind::Vulnerable is pushed for any path that returns a success status, counting the byte length but never inspecting the body for sensitive content. A BMC that returns a 200 with an empty or benign body (login redirect rendered as 200, marketing page, etc.) is reported as 'Auxiliary unauth endpoint ... returned N bytes'. The primary SENSITIVE_ENDPOINTS loop correctly requires a matching sensitive field; the aux loop does not, so it is comparatively over-eager.

_Fix:_ Require a minimum body size and/or an endpoint-specific content marker before flagging the aux endpoints as Vulnerable, or downgrade them to FindingKind::Note pending body validation.


### [resource-leak] src/modules/osint/cname_chain.rs:92
**Detached DNS background driver tasks spawned per lookup are never tracked or aborted**

dns_lookup() calls `Client::connect(stream)` and spawns the background driver with raw `tokio::spawn(bg)`. These tasks are detached and are NOT registered with the framework's RunContext spawn tracking, so the macro's `abort_all_spawned()` cleanup does not reach them. Each host triggers up to 11 lookups (10 CNAME hops + 1 A), each spawning a driver task and opening a fresh UDP socket. Under mass-scan fan-out across a large host list these accumulate sockets/tasks until the client handles drop, and on cancellation they are not torn down promptly.

_Fix:_ Use the framework's tracked spawn (e.g. ctx.spawn / the RunContext-aware spawn helper) for the background driver so it is aborted on module completion/cancellation, or reuse a single client/connection across the lookups for a host instead of reconnecting per query.


### [resource-leak] src/modules/scanners/subdomain_takeover_scanner.rs:105
**Background DNS client task spawned per lookup is never aborted, leaking tasks under brute-force**

dns_lookup builds a UdpClientStream, calls Client::connect, and tokio::spawn(bg) for the connection background future on every single lookup. resolve_cname_chain calls dns_lookup up to 10 times and resolves_to_a once, each spawning a new background task and a new UDP socket; the spawned `bg` tasks are never joined or aborted and the client/socket are dropped at function end. The spawns are plain tokio::spawn (not ctx.spawn / tracked), so they are not registered for cleanup. In a CIDR fan-out this leaks one detached task + socket per CNAME hop per host.

_Fix:_ Capture the JoinHandle and abort it once the query completes (or use ctx.spawn so the scheduler aborts it in cleanup), and reuse a single resolver client across the CNAME chain instead of reconnecting per lookup.


### [resource-leak] src/pq_middleware.rs:260
**Bad-token path of register_key_handler inserts into the rate-limiter map without the stale-entry eviction the handshake path performs**

handshake_handler (lines 105-117) prunes empty IP buckets from the shared HandshakeRateLimiter map after every call. The bad-token branch of register_key_handler (lines 260-271) reuses the same map and pushes a timestamp for the caller IP, but performs no map-level eviction. A stream of bad-token attempts from many distinct source IPs therefore accrues one never-removed HashMap entry per IP until a subsequent /pq/handshake call happens to prune them. Under a distributed bad-token flood targeting only /pq/register-key, the limiter map grows unbounded (memory pressure / OOM over time).

_Fix:_ After updating the bucket in the register_key bad-token path, run the same `limiter.retain(|_, ts| !ts.is_empty())` eviction used in handshake_handler (or factor the rate-limit check into a shared helper that always evicts).


### [mass-scan] src/modules/exploits/dos/px4_uav_dos.rs:61
**PX4 probe uses a hard-coded 3s recv timeout instead of the module timeout**

The MAVLink response wait is fixed at Duration::from_secs(3) regardless of any configured module_timeout. Under a large per-host fan-out this fixed 3s-per-host wait dominates runtime and cannot be tuned down for fast scans or up for slow links. Minor relative to the flood findings, but it diverges from timeout-aware behavior expected under fan-out.

_Fix:_ Derive the recv timeout from the module/context timeout (or expose it as a prompt) rather than hard-coding 3 seconds, so it scales with mass-scan configuration.


### [mass-scan] src/modules/scanners/vuln_checker.rs:67
**vuln_checker fires ~200 probes per host with no rate limiting**

run() iterates the full probe registry (~200 entries) issuing an HTTP request or TCP connect per probe, and never calls ctx.rate_limit(target).await. Under the universal per-host CIDR/file fan-out this generates a ~200x request burst per host with no global/per-module/per-target throttle, ignoring module_timeout pacing and risking IDS trips / target overload across a /16.

_Fix:_ Call ctx.rate_limit(&target).await before each run_probe network round trip (thread ctx into run_probe or acquire in the loop).
