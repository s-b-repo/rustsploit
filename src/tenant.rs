// src/tenant.rs
//
// Multi-tenant isolation for API mode. Each PQ session's `client_name`
// maps to a separate set of data stores (workspace, credentials, loot,
// options, jobs) so tenants cannot see or mutate each other's data.
//
// Shell mode does not set a tenant context and falls back to the
// process-global singletons, preserving backwards compatibility.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::cred_store::CredStore;
use crate::global_options::GlobalOptions;
use crate::jobs::JobManager;
use crate::loot::LootStore;
use crate::workspace::Workspace;

const MAX_TENANTS: usize = 256;

pub struct TenantData {
    pub workspace: Workspace,
    pub cred_store: CredStore,
    pub loot_store: LootStore,
    pub global_options: GlobalOptions,
    pub job_manager: JobManager,
}

impl TenantData {
    fn new(base_dir: PathBuf) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&base_dir)
        {
            eprintln!(
                "[!] Failed to create tenant directory {}: {}",
                base_dir.display(),
                e
            );
        }
        Self {
            workspace: Workspace::with_base_dir(base_dir.clone()),
            cred_store: CredStore::with_base_dir(base_dir.clone()),
            loot_store: LootStore::with_base_dir(base_dir.clone()),
            global_options: GlobalOptions::with_base_dir(base_dir),
            job_manager: JobManager::new(),
        }
    }
}

struct TenantRegistry {
    tenants: std::sync::RwLock<HashMap<String, Arc<TenantData>>>,
}

impl TenantRegistry {
    fn new() -> Self {
        Self {
            tenants: std::sync::RwLock::new(HashMap::new()),
        }
    }

    fn get_or_create(&self, tenant_id: &str) -> Result<Arc<TenantData>, String> {
        let sanitized = sanitize_tenant_name(tenant_id);
        if sanitized.is_empty() {
            return Err("tenant name is empty after sanitization".to_string());
        }
        {
            let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
            if let Some(data) = tenants.get(&sanitized) {
                return Ok(data.clone());
            }
        }
        let mut tenants = self.tenants.write().unwrap_or_else(|e| e.into_inner());
        if let Some(data) = tenants.get(&sanitized) {
            return Ok(data.clone());
        }
        // Evict tenants with no active references (Arc strong_count == 1 means only the registry holds it)
        if tenants.len() >= MAX_TENANTS {
            let before = tenants.len();
            tenants.retain(|name, data| {
                let active = Arc::strong_count(data) > 1;
                if !active {
                    tracing::info!("Evicting idle tenant '{}' to make room", name);
                }
                active
            });
            let evicted = before - tenants.len();
            if evicted > 0 {
                tracing::info!("Evicted {} idle tenant(s), {} remaining", evicted, tenants.len());
            }
        }
        if tenants.len() >= MAX_TENANTS {
            tracing::error!(
                "Tenant cap ({}) reached — rejecting new tenant '{}' (all tenants active)",
                MAX_TENANTS,
                tenant_id
            );
            return Err(format!(
                "server at capacity ({} active tenants) — connection refused",
                MAX_TENANTS
            ));
        }
        let base_dir = tenant_base_dir_sanitized(&sanitized);
        let data = Arc::new(TenantData::new(base_dir));
        tenants.insert(sanitized, data.clone());
        tracing::info!("Created tenant store for '{}'", tenant_id);
        Ok(data)
    }
}

static REGISTRY: Lazy<TenantRegistry> = Lazy::new(TenantRegistry::new);

tokio::task_local! {
    /// Task-local tenant identity. Set by the API dispatcher and WebSocket
    /// handler before invoking RPC handlers. Shell mode does not set this.
    pub static CURRENT_TENANT: String;
}

fn sanitize_tenant_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect::<String>()
        .to_lowercase()
}

fn tenant_base_dir_sanitized(sanitized_name: &str) -> PathBuf {
    home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rustsploit")
        .join("tenants")
        .join(sanitized_name)
}

/// Resolved store references for the current request. Holds the Arc alive
/// so callers can borrow the per-tenant stores for the duration of the
/// RPC handler. When no tenant context is active (shell mode), accessors
/// return the process-global singletons.
pub struct Stores {
    tenant: Option<Arc<TenantData>>,
}

impl Stores {
    pub fn workspace(&self) -> &Workspace {
        match &self.tenant {
            Some(t) => &t.workspace,
            None => &crate::workspace::WORKSPACE,
        }
    }

    pub fn cred_store(&self) -> &CredStore {
        match &self.tenant {
            Some(t) => &t.cred_store,
            None => &crate::cred_store::CRED_STORE,
        }
    }

    pub fn loot_store(&self) -> &LootStore {
        match &self.tenant {
            Some(t) => &t.loot_store,
            None => &crate::loot::LOOT_STORE,
        }
    }

    pub fn global_options(&self) -> &GlobalOptions {
        match &self.tenant {
            Some(t) => &t.global_options,
            None => &crate::global_options::GLOBAL_OPTIONS,
        }
    }

    pub fn job_manager(&self) -> &JobManager {
        match &self.tenant {
            Some(t) => &t.job_manager,
            None => &crate::jobs::JOB_MANAGER,
        }
    }
}

/// Resolve the current tenant context and return store references.
///
/// Checks (in order):
/// 1. The task-local `CURRENT_TENANT` (set by API/WS dispatchers)
/// 2. The `RunContext::tenant_id` (set for module execution)
/// 3. Falls back to global singletons (shell mode)
///
/// If a tenant ID is present but the registry rejects it (cap reached,
/// invalid name), logs a warning and falls back to global singletons
/// rather than panicking — the caller is typically deep in module code
/// where a hard error would be surprising. The PQ handshake layer is
/// responsible for rejecting connections before they get this far.
pub fn resolve() -> Stores {
    let tenant_id = CURRENT_TENANT
        .try_with(|t| t.clone())
        .ok()
        .or_else(crate::context::current_tenant_id);
    let tenant = tenant_id.and_then(|id| match REGISTRY.get_or_create(&id) {
        Ok(data) => Some(data),
        Err(e) => {
            tracing::warn!("tenant resolve failed for '{}': {}", id, e);
            None
        }
    });
    Stores { tenant }
}

/// Resolve stores for a specific tenant by name. Returns `Err` if the
/// tenant cannot be created (cap reached, invalid name after sanitization).
pub fn resolve_for(tenant_id: &str) -> Result<Stores, String> {
    let data = REGISTRY.get_or_create(tenant_id)?;
    Ok(Stores {
        tenant: Some(data),
    })
}
