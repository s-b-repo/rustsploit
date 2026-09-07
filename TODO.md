# Rustsploit — Comprehensive Feature & Improvement TODO

**Updated: 2026-06-18** (docs pass 2026-09-01) — Verified against current codebase (468 registered modules). Many previously-listed issues are **already fixed**; stale items below have been re-marked so the remaining list is actionable.

---

## 🔴 CRITICAL FIXES (Still Need Work)

### 1. HTTP Body Read without Cap — Systemic (S1)
**Pattern:** `resp.text().await` / `resp.bytes().await` without size limit
**Modules affected:** ~36 exploit modules + scanners
**Fix:** Use `crate::utils::safe_io::read_http_body_capped()` or `read_http_body_text_capped()`

| Module | Status | Notes |
|--------|--------|-------|
| `cert_transparency.rs:68` | ❌ Unfixed | crt.sh returns 50+ MB JSON |
| `mysql_sqli.rs:64` | ❌ Unfixed | Untrusted packet length |
| `mongobleed.rs:277` | ❌ Unfixed | 50K loop no body cap |
| Most DoS modules | ❌ Unfixed | Unbounded reads |

### 2. Spawn Storm — Systemic (S2, S3)
**Pattern:** `tokio::spawn` with semaphore *inside* spawn
**Modules affected:**
- `bruteforce.rs:845` (`run_bruteforce`) — per-combo spawn storm
- ~~`creds/utils.rs:447` (`run_mass_scan`)~~ — **closed**: the file and `run_mass_scan` were deleted in v0.5.1 (scheduler fans out universally)
- `ipmi_enum_exploit.rs:224` — `FuturesUnordered` without cap
- `subdomain_scanner.rs:122` — semaphore gates execution not spawn

**Fix:** Acquire permit *before* `spawn`, or feed through bounded `mpsc` channel

### 3. TLS Verify Bypass by Default — Systemic (S4)
**Pattern:** `.danger_accept_invalid_certs(true)` as default
**Modules:** ~19 exploit modules + scanners
**Fix:** Add `--insecure` flag, default to verify, log when bypassed

### 4. DNS Rebinding Window — Systemic (S5)
**Pattern:** `to_socket_addrs()` once then reuse for all connections
**Modules:** `zte_zxv10...rs:114`, others
**Fix:** Resolve once, pin IP, connect by IP + send hostname in SNI/Host

### 5. Mutex Poison Silent Recovery — Systemic (S7)
**Pattern:** `lock().unwrap_or_else(|e| e.into_inner())`
**Locations:** `output.rs:46,54`, `cred_store.rs`, `loot.rs`
**Fix:** Decide policy: propagate as error or panic on poison

---

## 🔴 SPECIFIC HIGH-SEVERITY (From Audit)

| ID | Module | Issue | Status | Fix |
|----|--------|-------|--------|-----|
| H1 | `cert_transparency.rs:68` | Unbounded body from crt.sh | ❌ Unfixed | Cap response (50 MB) or stream-parse |
| H2 | `mysql_sqli.rs:64` | `Vec::with_capacity` from untrusted u24 | ❌ Unfixed | Clamp `pkt_len` to 1 MiB |
| H3 | `bruteforce.rs:845` | Per-combo `tokio::spawn` storm | ❌ Unfixed | Acquire permit *before* spawn |
| H4 | `creds/utils.rs:447` | Mass-scan unbounded spawn | ✅ Closed | `run_mass_scan` + the file deleted in v0.5.1; scheduler owns fan-out |
| H5 | `ws.rs:260` | WS frame buffered before size check | ❌ Unfixed | Configure tungstenite `max_message_size` |

| ID | Module | Issue | Status | Fix |
|----|--------|-------|--------|-----|
| M1 | `cred_store.rs` | Plaintext credentials on disk | ❌ Unfixed | Document; offer passphrase-encrypted mode |
| M2 | `loot.rs:107` | TOCTOU on parent symlink | ❌ Unfixed | Canonicalize loot dir at startup; dir-fd + `openat` |
| M3 | `output.rs:46` | Mutex-poison silent recovery | ❌ Unfixed | Pick policy: propagate or panic |
| M4 | `target.rs:331` | DNS resolution unbounded `Vec` | ❌ Unfixed | `take(16)` or refuse if N > bound |
| M5 | `async_tls.rs:81` | TLS handshake without timeout | ❌ Unfixed | Add inner `timeout(15s)` |
| M6 | `port_scanner.rs:55` | Eager 65K-element Vec | ❌ Unfixed | Use lazy iterator |
| M7 | `mongobleed.rs:277` | 50K loop no rate limit/cap | ❌ Unfixed | Add pacing + `total_leaked > 100MB` cap |
| M8 | `http_flood.rs:255` | Concurrency = user input, no clamp | ❌ Unfixed | Clamp to 4096, use `JoinSet` |

---

## ✅ ALREADY FIXED (Verified in Current Codebase)

### Silent Finding Loss — FIXED
| Module | Fix Applied |
|--------|-------------|
| `api_attack_suite.rs` | Lines 472-489: pushes all `report.findings` → `outcome.findings` |
| `redis_bruteforce.rs` | Lines 252-266, 337-342, 482-494: pushes findings in subnet/single mode |
| `avtech/cve_2024_7029...rs` | Lines 269-274: pushes Finding; guards shell with `is_batch_mode()` |
| `nginx_pwner.rs` | Pushed findings via `outcome.findings.push()` |
| `camxploit/exploit.rs` | Pushes `FindingKind::Note` for brand/streams |
| `tomcat/cve_2025_24813_tomcat_put_rce.rs` | Pushes `FindingKind::Vulnerable` |
| `apache_modssl_bypass...rs` | Pushes `FindingKind::Vulnerable` |
| `arista_ngfw_disclose.rs` | Matches body read, `continue` on error |
| `vmware/vcenter_backup_rce.rs` | Pushes Finding on successful attack |
| `vmware/vcenter_file_read.rs` | Pushes `FindingKind::Vulnerable` with file list |
| `tplink/tplink_wdr740n_path_traversal.rs` | Mutable outcome, pushes Finding |
| `drupal11_pathdisclose...rs` | Pushes Finding in `if leak` branch |
| `sap_netweaver_rce...rs` | Tracks `rce_confirmed` flag across phases |
| `zimbra_sqli_auth_bypass...rs` | Pushes Finding on genuine extraction |
| `api_endpoint_scanner/*.rs` | Threads `Arc<Mutex<Vec<Finding>>>` through pipeline |
| `wp_user_enum.rs` | oEmbed disclosure pushes Finding + adds to `users` |
| `bruteforce.rs::run_subnet_bruteforce` | Returns hits for callers to push |
| `sharepoint_doc_harvest.rs` | Registration name fixed to bare leaf |

### False Positives — FIXED
| Module | Fix Applied |
|--------|-------------|
| `acti_camera_default.rs` | Lines 230-267: `match` on send/body read; requires positive success signal |
| `ruijie_reyee_ssrf...rs` | Uses OAST callback / unique marker |
| `ruijie_rsr_router_ci...rs` | Only `uid=`/`gid=`/`root=` markers |
| `tenda_cp3_rce...rs` | Requires validated response |
| `magnusbilling_ssrf...rs` | Lines 64-65: requires `root:` + `:/bin/` + `:/root:` |
| `libvnc_websocket_overflow.rs` | Resolves host before guard |
| `tightvnc_decompression_bomb.rs` | Resolves host before guard |
| `acti_camera_default.rs` | HTTP errors `continue` instead of aborting |
| `h3c_oem_kvm_bruteforce.rs` | Returns tri-state: Success/AuthFailed/Error(retryable) |
| `null_syn_exhaustion.rs` | Returns Err if no source IP |
| `vcenter_backup_rce.rs` | Propagates error or returns `Ok(false)` |
| `snare/cookie_dos.rs` | Distinguishes cap error from connection close |
| `sharepoint_doc_harvest.rs` | Matches write Result |
| `ssh_bruteforce.rs` | Maps auth rejection → `AuthFailed` |
| `zte_zxv10...rs` | `.write().create().truncate()` + temp file |
| `pluck_upload.rs` | Removes `!cookie_str.is_empty()` |
| `http_basic_bruteforce.rs` | Probes unauth first; 2xx-after-401 = success |
| `reolink_rce...rs` | Embeds canary, verifies output |
| `xiongmai_xm530.rs` | Validates protocol response header |
| `cowrie/llm_prompt_injection.rs` | Returns verdict; pushes Finding only on leak |
| `cowrie/ssrf_ipv6.rs` | Returns verdict from live mode |
| `geth_dos...rs` | Parses version, compares against patched |
| `dionaea/mysql_sqli.rs` | Compares injected vs baseline |
| `catkiller...rs` | Requires observed crash |
| `jenkins_2_441_lfi.rs` | Requires "No such agent" signature |
| `php/cve_2025_51373...rs` | Embeds canary, verifies |
| `wsus/cve_2025_59287...rs` | Requires "BinaryFormatter"/"SerializationException" |
| `apache_modssl_bypass...rs` | Verifies bypass actually works |

### Panic/OOM — FIXED
| Module | Fix Applied |
|--------|-------------|
| `clipbucket_rce...rs` | Line 120: `marker[marker.len().saturating_sub(8)..]` |
| `fortinet_bruteforce.rs` | Line 113: `txt.chars().take(80).collect::<String>()` |
| `citrix/citrixbleed2.rs` | Clamps to char boundary |
| `erlang_otp_ssh_rce...rs` | `if packet_length < 1 { bail!() }` |
| `libssh_auth_bypass...rs` | Same fix |
| `freepbx_cmdi.rs` | `body.chars().take(500).collect()` |
| `bruteforce.rs` streaming | Uses `read_http_body_capped` now |
| HTTP client | `read_http_body_capped()` standard helper |

### Error Swallowing / Logic — FIXED
| Module | Fix Applied |
|--------|-------------|
| `module.rs build_run_context` | Line: `rc.module_path = self.module_path.clone()` |
| `pq_channel.rs` | Line 691-696: Compares request ek vs authorized ek (constant-time) |
| `pq_channel.rs` | Lines 718-735: Implements mutual ML-KEM auth (server decapsulates) |
| `shell.rs` | Passes `Some(ModuleConfig::default())` for `run -j` |
| `ws.rs` SSRF filter | Re-runs checks inline (partial fix) |
| `checkpoint.rs` | Still needs tenant scoping ❌ |

---

## 🏗 ARCHITECTURAL WORK (In Progress)

### Native Module Migration: COMPLETE
**Status:** all 468 registered modules are native — `run(&ModuleCtx) -> Result<ModuleOutcome>`.
The 2-arg legacy macro arm survives only as an unused shim (see `docs/Module-Development.md` § Legacy Shape).

### Planned Features (from docs/Roadmap.md)
| Feature | Status |
|---------|--------|
| Config profiles (`--config`) | Planned |
| Session/Handler (`multi/handler`) | Foundations done (`src/sessions.rs`, `sessions` command) — interaction/listeners remain |
| Post-exploitation category | ✅ Done (`post/linux_sudo_enum`, `post/windows_pe_enum`) |
| Network pivoting | Foundations done (`src/socks.rs`) — routing through sessions remains |
| Nmap import (`db_import`) | ✅ Done (`src/nmap_import.rs`) |

### Arcticalopex REST API Wiring (P0-1) — ✅ DONE (v0.5.1)
`src/api.rs` ships the full `/api/*` REST surface behind the PQ middleware:
modules/runs, target, options, creds (+search/import/clear), hosts/notes,
services, workspace(s), loot, jobs, spool, results, export. See
`docs/API-Server.md`.

---

## 🔬 BUG-BOUNTY DRIVEN MODULE GAPS

Source: engagement gap analyses under `reports/` (the former `_analysis/` corpus).

| Pattern | Module Needed | Priority | Status |
|---------|---------------|----------|--------|
| M365 GetCredentialType user enum | `scanners/m365_userenum` (generalize) | High | ✅ Shipped (`m365_userenum_scanner`) |
| JWT alg-confusion (RS256→HS256) | `exploits/webapps/jwt_alg_confusion.rs` | High | Partial — `jwt_analyzer` ships; alg-confusion attack open |
| Apple Sign-In aud confusion | `exploits/webapps/apple_id_aud_confusion.rs` | Medium | Open |
| PostMessage wildcard interception | `exploits/webapps/postmessage_intercept.rs` | Medium | Open |
| Source map disclosure | Extend `scanners/sourcemap_scanner` | Medium | ✅ Shipped (`source_map_scanner`) |
| Dangling CNAME / SDT | `scanners/subdomain_takeover_scanner` (mass-scan) | High | ✅ Shipped |
| AEM / Helix probes | `scanners/aem_scanner`, `scanners/helix_scanner` | Medium | Open |
| Mobile/APK static analysis | `scanners/apk_static_analysis` wrapper | Medium | Open |
| WebView → Native bridge | `exploits/mobile/webview_bridge.rs` | Low | Open |

---

## 📋 ADDITIONAL GAPS FOUND DURING CODE REVIEW

### 1. Testing Infrastructure Gaps
- **No CI/CD pipeline** — No `.github/workflows/` directory, no automated testing
- **142 unit tests** across the codebase — low coverage for 468 modules
- **No integration tests** — No Docker Compose for vulnerable targets (Metasploitable, DVWA, bWAPP)
- **No property-based testing** — No proptest for parser modules
- **No fuzzing** — No cargo-fuzz / libFuzzer for protocol parsers

### 2. Documentation Gaps
- **No architecture decision records (ADRs)** — No `docs/adr/` directory
- **No module authoring video/tutorial** — Only written docs
- **No API client SDKs** — No Python/Go/TypeScript clients for PQ REST/WS
- ~~**API-Server.md** doesn't document all endpoints~~ — **Fixed** (full route tables incl. `/api/run`; `src/api.rs` remains the source of truth)

### 3. Configuration Gaps
- **No config profiles** — `--config profiles/aggressive.toml` not implemented
- **Prescan tools** — masscan/zmap support but no auto-install helpers
- **No config validation on startup** — No schema validation for global_options.json

### 4. Security Hardening Gaps
- **Credential store plaintext** — `cred_store.rs` stores secrets in plaintext JSON (M1)
- **WS frame size check after buffering** — tungstenite buffers before check (H5)
- **DNS resolution unbounded** — `target.rs:331` returns unbounded `Vec` (M4)
- **TLS handshake no timeout** — `async_tls.rs:81` (M5)
- **Checkpoints not tenant-scoped** — `checkpoint.rs` uses global path (from audit findings)

### 5. Module Coverage Gaps (from Module-Catalog.md)
| Category | Missing |
|----------|---------|
| ~~**Post-Exploitation**~~ | ✅ `post/` category exists (`linux_sudo_enum`, `windows_pe_enum`) — expand |
| **Container/K8s** | K8s API, Containerd, CRI-O, Kubelet |
| **Cloud** | AWS IAM, GCP IAM, Azure AD, CloudFormation |
| **AI/ML** | MLflow, Kubeflow, Ray, Triton, vLLM, Ollama |
| **Supply Chain** | SBOM, Signing, Provenance, CI/CD (GitHub Actions, GitLab) |
| **IoT/OT** | PLC, HMI, SCADA, Modbus, BACnet, OPC-UA, DLMS/COSEM |

### 6. Performance/Observability Gaps
- **No metrics/telemetry** — No Prometheus metrics, no OpenTelemetry
- **No structured logging** — Only `tracing` with basic env filter
- **No health check endpoints** — API has `/health` but no detailed readiness/liveness
- **No distributed tracing** — No Jaeger/Zipkin integration

### 7. CLI/UX Gaps
- **No command aliases** — `use` → `u`, `setg` → `sg`, `background` → `bg`
- **No syntax highlighting** — Module output not colored/structured
- **No session recording/playback** — No mkcast/asciicast integration
- **No config profiles** — Can't save/load `setg` profiles

### 8. MCP/API Gaps
- **No OpenAPI/Swagger spec** — REST API not self-documenting
- **MCP resource templates** — No dynamic resource discovery
- **WebSocket event filtering** — Can't subscribe to specific event types
- **No API rate limit dashboard** — No per-tenant usage visualization

### 9. Export/Reporting Gaps
- **No HTML report template** — Only JSON/CSV/summary text
- **No SARIF export** — No IDE/GitHub Code Scanning integration
- **No ATT&CK mapping** — Findings not tagged with technique IDs
- **No compliance reports** — No PCI-DSS/NIST/ISO 27001 control mapping

### 10. Native Module/Code Gaps
- **`tommy.rs`** — Unclear purpose, no docs
- **`async_tls.rs` line 81** — TLS handshake no timeout (M5)
- **`rate_limit.rs`** — No per-IP handshake rate limit for non-API mode
- **`prescan.rs`** — No auto-install for masscan/zmap
- **`context.rs`** — `cache_insert` racy check-then-insert (from audit)

---

## 📋 FIX PRIORITY MATRIX (Current)

| Phase | Task | Impact | Effort | Target |
|-------|------|--------|--------|--------|
| 1 | Fix H1-H5, M1-M15 (specific audit findings) | Critical | High | v0.6.0 |
| 2 | Fix systemic S1-S7 (patterns across 50+ modules) | Critical | High | v0.6.0 |
| 3 | Native module migration (159 remaining) | Critical | High | v0.6.0 |
| 4 | Arcticalopex REST wiring | High | Medium | v0.6.0 |
| 5 | Config profiles (`--config`) | Medium | Low | v0.6.0 |
| 6 | Session/Handler framework | High | High | v0.7.0 |
| 7 | CI/CD pipeline + testing infrastructure | High | Medium | v0.6.0 |
| 8 | Post-exploitation category + pivoting | High | High | v0.7.0 |
| 9 | Security hardening (M1-M8) | High | Medium | v0.7.0 |
| 10 | Module coverage gaps | Medium | High | v0.8.0+ |

---

## 🚀 QUICK WINS (This Week)

```bash
# 1. Fix spawn storm (S2/S3) - biggest user-facing impact
#    bruteforce.rs: acquire semaphore BEFORE tokio::spawn

# 2. Add safe_read_to_end helper + migrate all .text().await calls
#    utils::network::safe_read_to_end(reader, max)

# 3. Add --insecure flag for TLS (default verify, opt-in bypass)
#    cli.rs + network.rs

# 4. Module-path fix already done in module.rs

# 5. Add DNS pinning to network.rs helpers
#    Resolve once, pin IP, connect by IP

# 6. Add body cap to all direct HTTP reads
grep -rn '\.text()\.await\|\.bytes()\.await' src/modules/ | grep -v 'read_http_body_capped'

# 7. Add mutex poison policy decision
#    output.rs, cred_store.rs, loot.rs

# 8. Add CI/CD pipeline
mkdir -p .github/workflows
# Add workflow with: cargo fmt && cargo check && cargo test && audit-bad-patterns.sh --strict

# 9. Fix SSH brute force: wrong pwd → AuthFailed not Error
#    ssh_bruteforce.rs (mirror ssh_spray.rs match pattern)

# 10. Add MAX_COMBOS cap to bruteforce streaming branch
#    bruteforce.rs:553

# 11. Add response body cap to HTTP client
#    network.rs: build_http_client_with() + read_http_body_capped()

# 12. Add tenant scoping to checkpoints
#    checkpoint.rs: fold tenant_id into scan_id
```

---

## 📊 VERIFICATION SUMMARY

| Category | Total | Fixed | Remaining |
|----------|-------|-------|-----------|
| Silent Finding Loss (modules) | 50+ | **45+** ✅ | ~5 |
| False Positives (modules) | 30+ | **28+** ✅ | ~2 |
| Panic/OOM Vectors (modules) | 8 | **8** ✅ | 0 |
| Error Swallowing/Logic (modules) | 10 | **9** ✅ | 1 |
| Systemic Patterns | 7 | **0** ❌ | 7 |
| Specific Audit Findings | 20 | **5** ✅ | 15 |
| Testing Infrastructure | 5 | **0** ❌ | 5 |
| Documentation Gaps | 4 | **0** ❌ | 4 |
| Security Hardening | 8 | **0** ❌ | 8 |
| Module Coverage | 6 categories | **0** ❌ | 6 |

**Overall:** ~85% of module-level issues were already fixed in the codebase. 
Remaining work is primarily **systemic patterns** affecting 50+ modules simultaneously,
**architectural completion** (native migration, REST wiring, session handler),
and **infrastructure** (CI/CD, testing, docs).

---

*Last verified: 2026-06-18; stale entries re-marked in the 2026-09-01 docs pass.*