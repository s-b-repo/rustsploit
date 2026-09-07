# Legacy Systems & Deliberately-Untouched Code

This document inventories pre-v0.5.0 code paths that survive in the current codebase, why each one was kept, and where to find the historical context. Read this before deleting anything that "looks unused" — most of these are load-bearing and intentionally preserved.

For the v0.5.0 module-system rewrite that produced this document, see [Changelog.md § v0.5.0](Changelog.md). For the history that introduced each legacy item, see the per-version sections referenced below.

---

## Quick map (updated as of v0.5.1 — the live registry holds 468 modules)

### Removed

| Legacy item | Released | Reason |
|---|---|---|
| Per-category build.rs dispatch codegen (`exploit_dispatch.rs`, etc.) | v0.5.0 | Replaced by inventory-based registry |
| `src/commands/{scanner,exploit,creds,osint,plugins}.rs` stubs | v0.5.0 | Were one-line `include!` files for the dispatchers |
| `commands::dispatch_with_cidr` / `dispatch_single_target` | v0.5.0 | Replaced by `scheduler::run` |
| `utils::bruteforce::run_mass_scan` + `MassScanConfig` | v0.5.1 | Scheduler does fan-out for every module — no module-level mass-scan branches |
| `Capabilities::native_mass_scan` flag | v0.5.1 | Mass-scan is universal; no opt-in needed |
| `creds/utils.rs` (duplicate of `utils/bruteforce.rs`) | v0.5.1 | Orphaned, never imported |
| `EXCLUDED_RANGES: &[&str]` const in `utils/bruteforce.rs` | v0.5.2 | Replaced by `crate::exclusions::ExclusionSet` (pluggable) |
| `ModuleCtx::legacy_run_ctx` field | v0.5.2 | Was declared, never read or set |
| `ModuleAdapter` runtime shim (`src/module.rs`) | v0.5.6 | All 363 modules self-register via `register_native_module!` — adapter is unreferenced |
| `synthesize_info` fallback | v0.5.6 | Only ever called by the adapter's `info_fn`; both gone together |
| `build.rs` regex-grep codegen + `module_inventory.rs` include | v0.5.6 | No remaining modules go through the build-time bridge |
| `[build-dependencies]` (`regex`, `walkdir`) | v0.5.6 | Build script deleted, no longer required |

### Promoted to standard pattern (was "legacy")

| Item | Status | Reason |
|---|---|---|
| `utils::bruteforce::run_bruteforce` / `_streaming` / `run_subnet_bruteforce` | Standard library | Credential modules invoke these as a library, not via dispatch |
| `register_native_module!` macro | **Standard pattern (v0.5.6)** | Each module file ends with `crate::register_native_module!(Category::X, "name", native[, interactive])`. The macro generates a per-module `impl Module` that bridges into the file's free `info()` / `run()` functions and `inventory::submit!`s an entry. No build script, no central registry table, no check phase (exploitation-only). |

### Still needing manual work

_None — all 31 stubs from v0.5.1 have been reimplemented. 6 in v0.5.3, 25 in v0.5.5._

### Out of scope

| Item | Reason |
|---|---|
| `arcticalopex/` panel + REST endpoint table in `DESIGN.md` | TypeScript panel lives outside `src/`; REST surface is owned by panel maintainers |
| Historical audit reports (`reports/audit-findings.md`, `reports/arcticalopex_audit.md`, `reports/rustsploit_audit.md`, …) | Time-stamped forensic findings — editing them rewrites history |
| `docs/Changelog.md:89` reference to `registry::dispatch_by_category` | Inside the v0.4.10 section, describes the architecture *of that release* |
| PQ rekey deadlock (P0-1/P0-2), SSRF bypass (P0-3) | Encryption + handshake hardening — separate workstream |

---

## Migrated in v0.5.1 — universal mass scan

### `utils::bruteforce::run_mass_scan` and `MassScanConfig` — **REMOVED**

**Was at:** `src/utils/bruteforce.rs` lines 386–657 (now deleted).

**What it was:** A 250-line async fan-out engine that ~270 modules called from inside their own `run()` to handle `Target::Random` / CIDR targets. Each module had a dedicated `if is_mass_scan_target(target) { return run_mass_scan(...).await; }` branch wrapping a per-host probe closure.

**Why it was removed:** Mass-scan fan-out is now **universal** — `crate::scheduler::run` fans out every `Target::Cidr` / `Target::File` / `Target::Multi` / `Target::Random` for every module. Modules only ever see `Target::Single`. Per-module mass-scan branches were duplicated logic of the same shape — we collapsed them into one engine.

**Migration outcome:**
- 110 modules: branch stripped cleanly, single-target `run()` body intact, mass-scan now happens via scheduler fan-out.
- 37 modules: the mechanical strip damaged the surrounding code beyond automatic recovery — `run()` is now a stub that prints a migration warning and returns `Ok(())`. Listed below.
- All 363 modules still register through `crate::module::registered()` and dispatch through `crate::scheduler::run`. Mass scan works on every one of them — the difference is whether the per-host probe is intact (110) or stubbed (37).

### Modules reimplemented from stubs in v0.5.2

These had preserved helpers and were straightforward to wire as single-target probes:

```
src/modules/osint/cert_transparency.rs
src/modules/scanners/ping_sweep.rs
src/modules/scanners/sgbox_siem_recon.rs
src/modules/exploits/vnc/tightvnc_des_hardcoded_key.rs
src/modules/exploits/telnet/telnet_auth_bypass_cve_2026_24061.rs
src/modules/creds/generic/telnet_hose.rs
```

### Modules still stubbed (need manual reimplementation)

_None — all 31 stubs from v0.5.1 have been reimplemented as of 2026-06-30._
_0 stub modules remain. All 31 listed below now have full implementations._

Previously-stubbed modules (now fully implemented):
```
src/modules/creds/generic/couchdb_bruteforce.rs     — creds_helper::run
src/modules/creds/generic/elasticsearch_bruteforce.rs
src/modules/creds/generic/fortinet_bruteforce.rs
src/modules/creds/generic/l2tp_bruteforce.rs
src/modules/creds/generic/memcached_bruteforce.rs
src/modules/creds/generic/mqtt_bruteforce.rs
src/modules/creds/generic/mysql_bruteforce.rs
src/modules/creds/generic/postgres_bruteforce.rs
src/modules/creds/generic/rdp_bruteforce.rs
src/modules/creds/generic/rtsp_bruteforce.rs         — fixed \n line-ending parsing
src/modules/creds/generic/snmp_bruteforce.rs
src/modules/creds/generic/telnet_bruteforce.rs       — setg port honored via creds_helper
src/modules/creds/generic/vnc_bruteforce.rs
src/modules/exploits/bluetooth/wpair/mod.rs           — quote stripping + native shape
src/modules/exploits/cameras/abus/abussecurity_camera_cve202326609variant1.rs
src/modules/exploits/cameras/acti/acm_5611_rce.rs
src/modules/exploits/cameras/hikvision/hikvision_rce_cve_2021_36260.rs
src/modules/exploits/crypto/geth_dos_cve_2026_22862.rs
src/modules/exploits/network_infra/fortinet/fortiweb_sqli_rce_cve_2025_25257.rs
src/modules/exploits/network_infra/ivanti/cve_2025_0282_ivanti_preauth_rce.rs
src/modules/exploits/network_infra/ivanti/cve_2025_22457_ivanti_ics_rce.rs
src/modules/exploits/network_infra/sonicwall/cve_2025_40602_sonicwall_sma_rce.rs
src/modules/exploits/routers/tplink/tplink_tapo_c200.rs
src/modules/exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457.rs
src/modules/exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890.rs
src/modules/exploits/vnc/tightvnc_ft_path_traversal.rs
src/modules/exploits/webapps/mcpjam/cve_2026_23744_mcpjam_rce.rs
src/modules/exploits/webapps/n8n/n8n_form_afr_cve_2026_21858.rs
src/modules/exploits/webapps/react/react2shell.rs
src/modules/exploits/webapps/smartermail/admin_password_reset_cve_2026_23760.rs
src/modules/exploits/webapps/solarwinds/cve_2025_40551_solarwinds_whd_rce.rs
```

**To reimplement:** for each file, write a single-target `pub async fn run(target: &str) -> Result<()>` that does ONE probe against ONE host. Don't add `if is_mass_scan_target` / `if is_subnet_target` branches — the scheduler does fan-out (CIDR/random/file/multi).

**History:** `run_mass_scan` was introduced under v0.4.x as `modules/creds/utils.rs::run_subnet_bruteforce`. Migrated to `src/utils/bruteforce.rs` and renamed during the November 2025 hardening sweep (see `changelogs/archives/2025/changelog.md` line 2696, "v0.4.0 — Comprehensive Security Hardening"). Deleted in v0.5.1 in favour of universal scheduler fan-out.

## Live legacy code (intentional)

### Module bodies still take `target: &str` (not `ctx: &ModuleCtx`)

**Status:** none. All 468 registered modules use the native `ModuleCtx` shape.
The macro's 2-arg arm (`register_native_module!(Cat::X, "name")`) survives only
as an unused compatibility shim — see [Module-Development.md](Module-Development.md) § _Legacy Shape_.

---

## Out-of-scope by design

### `arcticalopex/` panel + REST API tables

**Location:** `arcticalopex/DESIGN.md`, lines around 1261–1263 (and elsewhere in the panel docs).

**What it documents:** The panel's expected REST surface (`GET /api/creds`, `POST /api/creds`, `DELETE /api/creds`, etc.) — written from the panel's perspective.

**Status update (v0.5.1):** the wiring gap this section described is **closed**. `src/api.rs` now ships the full `/api/*` REST surface behind the PQ middleware — modules, runs, target, options, creds (incl. search/import/clear), hosts/notes, services, workspace(s), loot, jobs, spool, results, export. The panel-facing endpoint tables in `arcticalopex/DESIGN.md` should be treated as historical design intent, not as a description of what the Rust side lacks.

**If you change the Rust API:** still coordinate with the panel maintainers and update both `arcticalopex/DESIGN.md` and `docs/API-Server.md` in the same PR.

### Historical audit reports

**Files (under `reports/`):**
- `reports/audit-findings.md`
- `reports/arcticalopex_audit.md`
- `reports/arcticalopex_audit_phase_a_b_d_summary.md`
- `reports/arcticalopex_wiring_audit.md`
- `reports/rustsploit_audit.md`
- `reports/audit-report.md` (dated bad-pattern audit snapshot)

**Why untouched:** These are **dated forensic reports** of the codebase state at a specific point in time. Each P0/P1/H-level finding cross-references commits and line numbers from that snapshot. Editing them retroactively would invalidate every reference and make subsequent audits hard to compare.

**The right way to record fixes:** Add a remediation entry in `docs/Changelog.md` (or here in `Legacy.md`) that cites the audit by filename + finding ID, then leave the original audit alone. Example: "P0-1 (arcticalopex_audit.md) — DH ratchet rekey deadlock — fixed in v0.5.0 by ..." rather than amending the original report.

### `docs/Changelog.md:89` mention of `registry::dispatch_by_category`

**Why untouched:** That line lives inside the v0.4.10 section. It describes the *architecture of v0.4.10* — namely, that `commands::run_module` flowed through `registry::dispatch_by_category` and into the codegenerated `exploit_dispatch.rs`. This was accurate when v0.4.10 shipped and remains accurate as a historical record of what v0.4.10 did. Rewriting historical changelog entries to reflect later refactors makes the changelog useless as a release-by-release reference.

**Where to look for the new architecture:** [Changelog.md § v0.5.0](Changelog.md) has the post-migration call graph.

---

## Cross-references to historical changelogs

The current `changelogs/` layout:

```
changelogs/
├── changelog-latest.md          # newest release notes (v0.5.1)
├── releases/                    # per-release announcement artifacts
└── archives/
    └── 2025/
        └── changelog.md         # everything before April 2026
```

> **Note on version numbers:** v0.5.x numbering is non-monotonic across
> 2026-05 → 2026-07 (duplicate `v0.5.0`/`v0.5.1` labels appear in
> `docs/Changelog.md` history). When cross-referencing, rely on the **date**
> column in the table below, not the version label alone.

Versions and the legacy systems they introduced (so you can grep the right archive when investigating "why does X exist"):

| Version | Date | Files | Legacy item it introduced |
|---|---|---|---|
| v0.4.0 | November 2025 | `archives/2025/changelog.md:2696` | First mass-scan + bruteforce utilities (later moved to `utils/bruteforce.rs`) |
| v0.4.1 | November 2025 | `archives/2025/changelog.md:2850` | SSHPWN integration — multiple modules that still call `run_mass_scan` directly |
| v0.4.8 | 2026-04-19 | `docs/Changelog.md:196` | Original per-category dispatcher codegen (`build.rs` → `*_dispatch.rs`) — removed in v0.5.0 |
| v0.4.9 | 2026-04-26 | `docs/Changelog.md:97` | Batch-mode prompt cache, PQ rekey hardening, mass-scan capability detection |
| v0.4.10 | 2026-04-28 | `docs/Changelog.md:7` | December 2025 PacketStorm batch (~80 webapp exploits); last release on the legacy dispatcher |
| v0.5.0 | 2026-05-07 | `docs/Changelog.md` (new entry) | Module trait + unified scheduler; build.rs slimmed to inventory bridge |
| v0.5.1–0.5.6 | 2026-05 → 2026-07 | `docs/Changelog.md` (dated entries) | Stub reimplementations, universal mass scan, rmcp MCP, io_uring; version labels repeat — match by date |

If a piece of code looks like dead weight, find the version that introduced it in the table above and read that section before deleting. Many "obviously redundant" helpers exist because a specific module needs their exact behaviour.

---

## Migration paths going forward

If you want to retire any of the surviving legacy items, here are the unblockers:

1. **Body migration is complete** — all 468 modules use the native `ModuleCtx` shape; the legacy macro arm is an unused shim.
2. **Drop `utils::bruteforce::run_mass_scan`** — DONE in v0.5.1. Scheduler handles fan-out universally.
3. **Wire the `arcticalopex` REST routes** — DONE in v0.5.1. `src/api.rs` ships the full `/api/*` REST surface (see § _Out-of-scope by design_ above for the coordination note).

Each of these is a discrete project. None blocks day-to-day use.
