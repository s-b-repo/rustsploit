// src/module.rs
//
// Module trait + compile-time registry. Every module implements `Module`,
// self-registers via `register_native_module!` (which expands to an
// `inventory::submit!`), and gets dispatched by the unified `Scheduler`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::module_info::ModuleInfo;

// ============================================================
// CATEGORY
// ============================================================

/// Module category — corresponds to `src/modules/<category>/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Scanners,
    Exploits,
    Creds,
    Osint,
    Plugins,
}

impl Category {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scanners => "scanners",
            Self::Exploits => "exploits",
            Self::Creds => "creds",
            Self::Osint => "osint",
            Self::Plugins => "plugins",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "scanners" | "scanner" => Some(Self::Scanners),
            "exploits" | "exploit" => Some(Self::Exploits),
            "creds" | "credential" | "credentials" => Some(Self::Creds),
            "osint" => Some(Self::Osint),
            "plugins" | "plugin" => Some(Self::Plugins),
            _ => None,
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================
// TARGET
// ============================================================

/// A scan target. Replaces the loose `&str` plumbed through every module.
#[derive(Debug, Clone)]
pub enum Target {
    /// Single host: `"10.0.0.1"`, `"example.com"`, `"[2001:db8::1]:80"`.
    Single(String),
    /// CIDR range, normalized: `"10.0.0.0/24"`.
    Cidr(String),
    /// Multiple targets — recursively any other variant.
    Multi(Vec<Target>),
    /// File containing one target per line (blank/comment lines skipped).
    File(PathBuf),
    /// Random public-internet scan.
    Random,
    /// Sequential public-internet sweep starting at the given IPv4 (as a u32),
    /// running in order up to the last public address.
    Sequential(u32),
}

/// First public IPv4 address (`1.0.0.0`) — `0.0.0.0/8` is reserved.
pub const FIRST_PUBLIC_IPV4: u32 = 0x0100_0000;

impl Target {
    /// Parse a raw user-supplied string into a `Target`. Delegates host/port
    /// validation to `crate::utils::normalize_target` and reuses
    /// `crate::utils::bruteforce::is_subnet_target` / `is_mass_scan_target`
    /// to stay consistent with the legacy dispatcher.
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("Target cannot be empty");
        }
        // `Target::Random` is reserved for the explicit mass-scan markers
        // `random` and `0.0.0.0/0`. Bare `0.0.0.0` is NOT a mass-scan keyword
        // (M45): it resolves to a normal single host so `t 0.0.0.0` does not
        // silently launch a full-internet random scan. CIDR ranges and file
        // paths are handled below as `Cidr` / `File`.
        if trimmed == "random" || trimmed == "0.0.0.0/0" {
            return Ok(Target::Random);
        }
        // Sequential full-public-IPv4 sweep: `seq`/`sequential` start at the
        // first public address; `seq:<ip>`/`sequential:<ip>` start at <ip>.
        let lower = trimmed.to_ascii_lowercase();
        if lower == "seq" || lower == "sequential" {
            return Ok(Target::Sequential(FIRST_PUBLIC_IPV4));
        }
        if let Some(rest) = lower
            .strip_prefix("seq:")
            .or_else(|| lower.strip_prefix("sequential:"))
        {
            let ip: std::net::Ipv4Addr = rest
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid sequential start IP '{}': {e}", rest.trim()))?;
            return Ok(Target::Sequential(u32::from(ip)));
        }
        if trimmed.contains(',') {
            const MAX: usize = 4096;
            let parts: Vec<&str> = trimmed
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .take(MAX + 1)
                .collect();
            if parts.len() > MAX {
                anyhow::bail!("Too many comma-separated targets (max {})", MAX);
            }
            if parts.len() == 1 {
                return Self::parse(parts[0]);
            }
            let mut out = Vec::with_capacity(parts.len());
            for p in parts {
                out.push(Self::parse(p)?);
            }
            return Ok(Target::Multi(out));
        }
        // File targets must be detected before normalize_target rejects them
        // as containing path traversal. Only honour them when they actually
        // exist on disk and aren't a CIDR.
        if !crate::utils::is_subnet_target(trimmed) && std::path::Path::new(trimmed).is_file() {
            return Ok(Target::File(PathBuf::from(trimmed)));
        }
        if crate::utils::is_subnet_target(trimmed) {
            return Ok(Target::Cidr(crate::utils::normalize_target(trimmed)?));
        }
        Ok(Target::Single(crate::utils::normalize_target(trimmed)?))
    }

    /// True if this target requires fan-out across many hosts.
    pub fn is_mass(&self) -> bool {
        matches!(
            self,
            Target::Cidr(_)
                | Target::Multi(_)
                | Target::File(_)
                | Target::Random
                | Target::Sequential(_)
        )
    }

    /// Borrow the underlying single-host string, if any.
    pub fn as_single(&self) -> Option<&str> {
        match self {
            Target::Single(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Render back into the canonical string form modules expect.
    /// `Multi` joins with `, `; `Random` becomes `"random"`; `File` becomes
    /// the file path. This is the value passed into legacy `run(&str)` shims.
    pub fn as_legacy_str(&self) -> String {
        match self {
            Target::Single(s) | Target::Cidr(s) => s.clone(),
            Target::Multi(parts) => parts
                .iter()
                .map(Self::as_legacy_str)
                .collect::<Vec<_>>()
                .join(", "),
            Target::File(p) => p.to_string_lossy().into_owned(),
            Target::Random => "random".to_string(),
            Target::Sequential(start) => {
                format!("seq:{}", std::net::Ipv4Addr::from(*start))
            }
        }
    }
}

// ============================================================
// OPTIONS
// ============================================================

/// Typed module options. Replaces ad-hoc `args: &str` parsing.
///
/// Modules read with `opts.get_or("port", 22u16)` etc. Values are also fed
/// into `RunContext.config.custom_prompts` so legacy `cfg_prompt_*` callers
/// see the same answers.
#[derive(Debug, Clone, Default)]
pub struct ModuleOptions {
    inner: HashMap<String, String>,
}

impl ModuleOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(String::as_str)
    }

    pub fn get_or<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        self.inner
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.inner.insert(key.into(), value.into());
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter()
    }

    pub fn into_inner(self) -> HashMap<String, String> {
        self.inner
    }

    pub fn from_map(map: HashMap<String, String>) -> Self {
        Self { inner: map }
    }
}

// ============================================================
// CAPABILITIES
// ============================================================

/// Capabilities advertised by a module.
///
/// Mass-scan fan-out is **universal** — handled by `crate::scheduler` for
/// every module. There is no per-module mass-scan flag any more; modules
/// only ever see `Target::Single` per invocation.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// Module is rate-limit-friendly; safe to run with high concurrency.
    pub safe_for_high_concurrency: bool,
    /// Module needs root (raw sockets, ICMP, etc.).
    pub requires_root: bool,
    /// Module performs a non-destructive check and never writes to targets.
    pub check_only: bool,
    /// Module makes outbound network connections.
    pub network: bool,
    /// Module runs an interactive / long-lived session and manages its own
    /// lifetime — the scheduler must NOT wrap it in the per-target timeout.
    pub interactive: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            safe_for_high_concurrency: false,
            requires_root: false,
            check_only: false,
            network: true,
            interactive: false,
        }
    }
}

// ============================================================
// FINDINGS / OUTCOME
// ============================================================

#[derive(Debug, Clone)]
pub enum FindingKind {
    Vulnerable,
    Credential,
    OpenPort,
    Banner,
    Note,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub target: String,
    pub kind: FindingKind,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Outcome of a module run. The scheduler routes findings into
/// `LootStore`/`Workspace` automatically.
#[derive(Debug, Default)]
pub struct ModuleOutcome {
    pub success: bool,
    pub findings: Vec<Finding>,
}

impl ModuleOutcome {
    pub fn ok() -> Self {
        Self {
            success: true,
            findings: Vec::new(),
        }
    }

    pub fn fail() -> Self {
        Self {
            success: false,
            findings: Vec::new(),
        }
    }

    pub fn with(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }
}

// ============================================================
// CONTEXT
// ============================================================

/// Per-run module context. Constructed by the scheduler before `run` /
/// `check`. Modules read everything they need from here — no global state,
/// no string parsing, no ad-hoc parameter conventions.
pub struct ModuleCtx {
    pub target: Target,
    pub options: ModuleOptions,
    pub cancel: tokio_util::sync::CancellationToken,
    pub batch_mode: bool,
    pub verbose: bool,
    /// Tenant identity (multi-tenant API isolation). `None` in CLI/shell mode.
    pub tenant_id: Option<String>,
    /// Optional shared prompt cache (mass-scan / CIDR runs share answers).
    pub prompt_cache: Option<crate::context::PromptCache>,
    /// Process-wide hierarchical rate limiter (global → per-module → per-target).
    /// Native modules call `ctx.rate_limit(target).await` before each network
    /// round trip.
    pub limiter: Arc<crate::rate_limit::GlobalLimiter>,
    /// Module path (`"category/name"`) — set by the scheduler before
    /// invoking `run` so the rate limiter can key per-module buckets.
    pub module_path: String,
}

impl ModuleCtx {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            options: ModuleOptions::default(),
            cancel: tokio_util::sync::CancellationToken::new(),
            batch_mode: false,
            verbose: false,
            tenant_id: None,
            prompt_cache: None,
            limiter: crate::rate_limit::shared(),
            module_path: String::new(),
        }
    }

    /// Acquire one permit at every rate-limit tier (global / module / target).
    /// No-op when all tiers have RPS = 0 (the default).
    pub async fn rate_limit(&self, target_host: &str) {
        self.limiter.acquire(&self.module_path, target_host).await;
    }

    /// Spawn a tracked tokio task whose handle is registered on the
    /// active `RunContext`. The scheduler aborts every tracked spawn in
    /// `Module::cleanup`, so cancelled / failed runs don't leak orphan
    /// tasks. Falls back to a plain `tokio::spawn` when invoked outside
    /// a scheduled run.
    pub fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        crate::context::spawn(future);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Convert into a `RunContext` for executing legacy modules.
    pub fn build_run_context(&self, target_str: String) -> crate::context::RunContext {
        let mut cfg = crate::config::get_module_config();
        // Surface ModuleOptions into custom_prompts so legacy `cfg_prompt_*`
        // callers see the operator's answers without further plumbing.
        for (k, v) in self.options.iter() {
            cfg.custom_prompts.insert(k.clone(), v.clone());
        }
        let mut rc = if let Some(cache) = &self.prompt_cache {
            crate::context::RunContext::with_prompt_cache(cfg, cache.clone(), target_str)
        } else {
            crate::context::RunContext::with_target(cfg, target_str)
        };
        rc = rc.with_cancellation(self.cancel.clone());
        rc.tenant_id = self.tenant_id.clone();
        rc.module_path = self.module_path.clone();
        rc
    }
}

// ============================================================
// MODULE TRAIT
// ============================================================

/// Every module implements this. Registered via `inventory::submit!`.
#[async_trait]
pub trait Module: Send + Sync {
    /// Static metadata (name, description, references, rank).
    fn info(&self) -> ModuleInfo;

    /// Capabilities — defaults to "single-target, network-bound module".
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    /// Pre-flight validation, run by the scheduler **once** per CLI/API
    /// invocation, *before* any per-host fan-out.
    ///
    /// Use this to validate `ctx.options` (required wordlist exists,
    /// supplied port is in 1..=65535, root privilege available, etc.) so
    /// the operator gets a single error instead of `N` identical errors
    /// across `N` hosts in a /16 scan. Default: succeed.
    async fn pre_check(&self, _ctx: &ModuleCtx) -> Result<()> {
        Ok(())
    }

    /// Cleanup hook, run by the scheduler **once** after the whole
    /// fan-out completes (or is cancelled). Use this to release
    /// long-lived resources (open files, persistent connections) that
    /// would otherwise leak.
    ///
    /// `outcome` is the final aggregate (`success` count, total findings).
    /// Default: no-op.
    async fn cleanup(&self, _ctx: &ModuleCtx, _outcome: &ModuleOutcome) -> Result<()> {
        Ok(())
    }

    /// Run the module against `ctx.target`. The scheduler dispatches this
    /// once per host. Mass-scan fan-out is handled at the scheduler tier;
    /// modules only ever see `Target::Single` here.
    async fn run(&self, ctx: &ModuleCtx) -> Result<ModuleOutcome>;
}

// ============================================================
// REGISTRY (compile-time, via `inventory`)
// ============================================================

/// One entry per module — registered with `inventory::submit!`.
pub struct ModuleEntry {
    pub category: Category,
    /// Slash-separated short name within its category, e.g. `"ssh/known_vuln"`.
    pub name: &'static str,
    /// Constructs the module instance. Modules are typically zero-sized.
    pub factory: fn() -> Box<dyn Module>,
}

inventory::collect!(ModuleEntry);

/// Walk every registered module.
pub fn registered() -> impl Iterator<Item = &'static ModuleEntry> {
    inventory::iter::<ModuleEntry>.into_iter()
}

/// Look up a module by:
///  - `"category/name/with/path"` (full match — exact `entry.name`),
///  - `"name/with/path"` (any category — exact `entry.name`),
///  - `"leaf"` (the part after the last `/` in `entry.name` — first match
///    wins, matching legacy short-name behaviour).
pub fn find(path: &str) -> Option<Box<dyn Module>> {
    let (maybe_cat, body) = match path.split_once('/') {
        Some((c, rest)) if Category::parse(c).is_some() => (Some(c), rest),
        _ => (None, path),
    };
    // Pass 1: exact match on entry.name (with optional category constraint).
    for entry in registered() {
        if let Some(c) = maybe_cat
            && entry.category.as_str() != c && Category::parse(c) != Some(entry.category) {
                continue;
            }
        if entry.name == body {
            return Some((entry.factory)());
        }
    }
    // Pass 2: short-leaf match — final segment after the last `/` in `entry.name`.
    if maybe_cat.is_none() {
        for entry in registered() {
            let leaf = entry.name.rsplit('/').next().unwrap_or(entry.name);
            if leaf == path {
                return Some((entry.factory)());
            }
        }
    }
    None
}

/// Total number of registered modules.
pub fn count() -> usize {
    registered().count()
}

/// All module paths in `category/name` form, sorted.
pub fn all_paths() -> Vec<String> {
    let mut v: Vec<String> = registered()
        .map(|e| format!("{}/{}", e.category, e.name))
        .collect();
    v.sort();
    v
}

/// Render a Markdown module catalog from the live registry. Used by
/// `--gen-module-catalog` to replace the hand-maintained
/// `docs/Module-Catalog.md`.
pub fn render_catalog_markdown() -> String {
    let mut by_cat: std::collections::BTreeMap<&'static str, Vec<&'static ModuleEntry>> =
        std::collections::BTreeMap::new();
    for e in registered() {
        by_cat.entry(e.category.as_str()).or_default().push(e);
    }
    for v in by_cat.values_mut() {
        v.sort_by_key(|e| e.name);
    }

    let total = registered().count();
    let mut out = String::new();
    out.push_str("# Module Catalog\n\n");
    out.push_str("> Auto-generated from the inventory registry by ");
    out.push_str("`rustsploit --gen-module-catalog`. Do not edit by hand.\n\n");
    out.push_str(&format!("**Total registered modules: {}**\n\n", total));

    out.push_str(
        "All modules support mass scan universally — `random` / CIDR / file targets / \
         comma-separated lists fan out through `crate::scheduler::run` regardless of \
         the module.\n\n",
    );

    for cat in ["scanners", "exploits", "creds", "osint", "plugins"] {
        let Some(entries) = by_cat.get(cat) else { continue };
        out.push_str(&format!("## {} ({})\n\n", cat, entries.len()));
        out.push_str(&format!("- {} modules\n\n", entries.len()));
        out.push_str("| Module | Description | Rank |\n");
        out.push_str("|---|---|---|\n");
        for e in entries {
            let inst = (e.factory)();
            let info = inst.info();
            let desc = info
                .description
                .lines()
                .next()
                .unwrap_or("")
                .replace('|', "\\|");
            out.push_str(&format!(
                "| `{}/{}` | {} | {} |\n",
                e.category.as_str(),
                e.name,
                desc,
                info.rank,
            ));
        }
        out.push('\n');
    }
    out
}

// ============================================================
// PER-MODULE REGISTRATION MACRO
// ============================================================

/// Generate a per-module `Module` impl + inventory registration that calls
/// the module file's local `pub fn info()` and `pub async fn run(...)`. Used
/// at the bottom of every module file.
///
/// Two body shapes are supported, picked via the trailing `native` token:
///
/// **Legacy shape (default — most existing modules):**
/// ```ignore
/// pub fn info() -> ModuleInfo { ... }
/// pub async fn run(target: &str) -> anyhow::Result<()> { ... }
///
/// crate::register_native_module!(crate::module::Category::Scanners, "x");
/// ```
/// The macro translates `ctx.target → target_str` and discards return values
/// into `ModuleOutcome::ok()`. No findings flow into the scheduler.
///
/// **Native shape (preferred for new modules and migrations):**
/// ```ignore
/// pub fn info() -> ModuleInfo { ... }
/// pub async fn run(ctx: &ModuleCtx) -> anyhow::Result<ModuleOutcome> { ... }
///
/// crate::register_native_module!(crate::module::Category::Scanners, "x", native);
/// ```
/// The module receives `&ModuleCtx` directly and returns `ModuleOutcome`
/// with `Finding` records. The scheduler routes findings into LootStore /
/// Workspace / events automatically.
///
/// Both shapes share `RunContext` scoping + `abort_all_spawned()` cleanup
/// so `cfg_prompt_*` / `ctx.spawn(...)` / `is_cancelled()` work uniformly.
#[macro_export]
macro_rules! register_native_module {
    ($category:expr, $name:expr) => {
        $crate::__register_native_module_impl!(@no_check $category, $name);
    };
    ($category:expr, $name:expr, native) => {
        $crate::__register_native_module_impl!(@native $category, $name, false);
    };
    // Interactive native module: the scheduler runs it without the per-target
    // timeout (it owns its own REPL / long-lived session lifetime).
    ($category:expr, $name:expr, native, interactive) => {
        $crate::__register_native_module_impl!(@native $category, $name, true);
    };
}

/// Internal macro arm — do not call directly; use `register_native_module!`.
#[macro_export]
#[doc(hidden)]
macro_rules! __register_native_module_impl {
    (@no_check $category:expr, $name:expr) => {
        struct __ModuleImpl;
        impl ::std::default::Default for __ModuleImpl {
            fn default() -> Self { Self }
        }
        #[::async_trait::async_trait]
        impl $crate::module::Module for __ModuleImpl {
            fn info(&self) -> $crate::module_info::ModuleInfo { info() }
            async fn run(&self, ctx: &$crate::module::ModuleCtx)
                -> ::anyhow::Result<$crate::module::ModuleOutcome>
            {
                let t = ctx.target.as_legacy_str();
                let rc = ctx.build_run_context(t.clone());
                let ctx_arc = ::std::sync::Arc::new(rc);
                let result = $crate::context::RUN_CONTEXT
                    .scope(ctx_arc, async move {
                        let r = run(&t).await;
                        $crate::context::abort_all_spawned().await;
                        r
                    })
                    .await;
                result?;
                ::std::result::Result::Ok($crate::module::ModuleOutcome::ok())
            }
        }
        inventory::submit! {
            $crate::module::ModuleEntry {
                category: $category,
                name: $name,
                factory: || ::std::boxed::Box::new(__ModuleImpl),
            }
        }
    };
    // Native shape: `run(ctx) -> Result<ModuleOutcome>`.
    (@native $category:expr, $name:expr, $interactive:expr) => {
        struct __ModuleImpl;
        impl ::std::default::Default for __ModuleImpl {
            fn default() -> Self { Self }
        }
        #[::async_trait::async_trait]
        impl $crate::module::Module for __ModuleImpl {
            fn info(&self) -> $crate::module_info::ModuleInfo { info() }
            fn capabilities(&self) -> $crate::module::Capabilities {
                $crate::module::Capabilities {
                    interactive: $interactive,
                    ..::core::default::Default::default()
                }
            }
            async fn run(&self, ctx: &$crate::module::ModuleCtx)
                -> ::anyhow::Result<$crate::module::ModuleOutcome>
            {
                // Keep `RunContext` scope so `cfg_prompt_*` / `is_cancelled()`
                // helpers used inside the body still resolve. Pass the
                // canonical target string for compatibility with helpers
                // that read `RunContext.target`.
                let t = ctx.target.as_legacy_str();
                let rc = ctx.build_run_context(t);
                let ctx_arc = ::std::sync::Arc::new(rc);
                let outcome = $crate::context::RUN_CONTEXT
                    .scope(ctx_arc, async move {
                        let r = run(ctx).await;
                        $crate::context::abort_all_spawned().await;
                        r
                    })
                    .await?;
                ::std::result::Result::Ok(outcome)
            }
        }
        inventory::submit! {
            $crate::module::ModuleEntry {
                category: $category,
                name: $name,
                factory: || ::std::boxed::Box::new(__ModuleImpl),
            }
        }
    };
}

