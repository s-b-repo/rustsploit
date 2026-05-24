// src/events.rs
//
// Structured module-event broadcast channel.
//
// This is a parallel surface to the human-facing `mprintln!` text macros:
// modules emit machine-readable findings here, and the API / MCP / WebSocket
// layers subscribe to consume them. The text macros stay — humans still read
// stdout / spool — but consumers that want to know "did a credential get
// found" no longer need to grep stdout.
//
// ## Versioning discipline
//
// `ModuleEvent` is `#[non_exhaustive]`. Adding a new variant is **not** a
// breaking change for downstream consumers, because the compiler forces
// every `match` to include a `_` arm. New variants will be added over time
// without bumping the API version.
//
// New variants must be additive — never re-purpose, rename, or change the
// shape of an existing variant. If a variant turns out to be wrong, deprecate
// it and add a new one alongside; remove the old one only across a major
// version boundary.
//
// ## Adoption is voluntary
//
// Modules that don't call `emit(...)` produce no events. Subscribers that
// don't `subscribe()` are unaffected. The channel is designed so that v1
// callers can opt in incrementally without coordinated rollout.

use serde::Serialize;
use tokio::sync::broadcast;

/// Per-process broadcast channel capacity. When the channel is full, the
/// oldest events are dropped (broadcast semantics) — subscribers see a
/// `RecvError::Lagged(N)` they must handle. 1024 is enough for bursty
/// workloads (mass scans) without unbounded memory.
const CHANNEL_CAPACITY: usize = 1024;

/// A structured event emitted by a module to describe a finding or progress
/// signal.
///
/// **Stability**: this enum is `#[non_exhaustive]`. New variants will be
/// added; consumers MUST include a `_` arm in every `match`.
///
/// **v1 surface (committed)**:
///   - `ModuleStarted` — a module is beginning execution against a target.
///   - `ModuleFinished` — a module has finished, with a success/failure flag.
///   - `HostUp` — discovered host is responsive.
///   - `ServiceDetected` — a host:port is running an identified service.
///   - `CredentialFound` — valid credential was confirmed on a service.
///   - `LootStored` — module saved an artefact to the loot store.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModuleEvent {
    ModuleStarted {
        module: String,
        target: String,
    },
    ModuleFinished {
        module: String,
        target: String,
        success: bool,
    },
    HostUp {
        host: String,
    },
    ServiceDetected {
        host: String,
        port: u16,
        service: String,
        version: Option<String>,
    },
    CredentialFound {
        host: String,
        port: u16,
        service: String,
        username: String,
    },
    LootStored {
        id: String,
        host: String,
        kind: String,
    },
    /// PQ handshake was accepted; a new session is now live for `client_name`.
    /// Emitted by `pq_middleware::handshake_handler` on success.
    PqHandshakeAccepted {
        client_name: String,
    },
    /// PQ handshake was rejected. `reason` is a short, non-secret summary;
    /// `peer` is the remote socket address as a string (no resolution).
    PqHandshakeRejected {
        reason: String,
        peer: String,
    },
    /// An authorized key was revoked. `sessions_terminated` is the number of
    /// in-memory sessions torn down as a side effect.
    PqIdentityRevoked {
        name: String,
        by: String,
        sessions_terminated: usize,
    },
    /// A session was evicted from the in-memory store, either because the
    /// per-process cap was hit or as part of an explicit revocation.
    PqSessionEvicted {
        client_name: String,
    },
    /// Generic structured finding emitted by a module run. Used by the
    /// unified scheduler to surface results without losing them in stdout.
    Finding {
        module: String,
        target: String,
        kind: String,
        message: String,
    },
}

/// Envelope that carries a module event along with the tenant that produced it.
/// Subscribers filter on `tenant_id` to enforce cross-tenant isolation.
#[derive(Debug, Clone, Serialize)]
pub struct TenantEvent {
    pub tenant_id: Option<String>,
    pub event: ModuleEvent,
}

/// Singleton event bus. One per process, lazily initialised.
static EVENT_BUS: std::sync::OnceLock<broadcast::Sender<TenantEvent>> =
    std::sync::OnceLock::new();

fn bus() -> &'static broadcast::Sender<TenantEvent> {
    EVENT_BUS.get_or_init(|| broadcast::channel(CHANNEL_CAPACITY).0)
}

/// Subscribe to the module-event stream.
///
/// Returns a `broadcast::Receiver<TenantEvent>`. Subscribers MUST filter
/// on `tenant_id` to prevent cross-tenant data leakage.
pub fn subscribe() -> broadcast::Receiver<TenantEvent> {
    bus().subscribe()
}

/// Emit a structured event. Automatically tags with the current tenant
/// context (from `CURRENT_TENANT` task-local or `RunContext::tenant_id`).
pub fn emit(event: ModuleEvent) {
    let tenant_id = crate::context::current_tenant_id()
        .or_else(|| {
            crate::tenant::CURRENT_TENANT
                .try_with(|t| t.clone())
                .ok()
        });
    if let Err(e) = bus().send(TenantEvent { tenant_id, event }) {
        tracing::trace!("Event bus: no active subscribers ({})", e);
    }
}

/// Subscriber count, useful for debug logging.
pub fn subscriber_count() -> usize {
    bus().receiver_count()
}
