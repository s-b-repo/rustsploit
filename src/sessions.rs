use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: u32,
    pub session_type: String,
    pub target: String,
    pub port: u16,
    pub info: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_active: chrono::DateTime<chrono::Utc>,
}

#[derive(Default)]
pub struct SessionStore {
    sessions: HashMap<u32, Session>,
    next_id: u32,
    listeners: HashMap<String, Arc<tokio::sync::Notify>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            listeners: HashMap::new(),
        }
    }

    pub fn create(&mut self, session_type: &str, target: &str, port: u16, info: &str) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let now = chrono::Utc::now();
        self.sessions.insert(
            id,
            Session {
                id,
                session_type: session_type.to_string(),
                target: target.to_string(),
                port,
                info: info.to_string(),
                connected_at: now,
                last_active: now,
            },
        );
        id
    }

    pub fn list(&self) -> Vec<&Session> {
        let mut sessions: Vec<&Session> = self.sessions.values().collect();
        sessions.sort_by_key(|s| s.id);
        sessions
    }

    pub fn get(&self, id: u32) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<Session> {
        self.sessions.remove(&id)
    }

    pub fn touch(&mut self, id: u32) -> bool {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.last_active = chrono::Utc::now();
            true
        } else {
            false
        }
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

static SESSION_STORE: std::sync::LazyLock<Arc<Mutex<SessionStore>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(SessionStore::new())));

pub fn store() -> Arc<Mutex<SessionStore>> {
    SESSION_STORE.clone()
}

pub async fn list_sessions() -> Vec<Session> {
    let guard = SESSION_STORE.lock().await;
    guard.list().into_iter().cloned().collect()
}

pub async fn create_session(session_type: &str, target: &str, port: u16, info: &str) -> u32 {
    let mut guard = SESSION_STORE.lock().await;
    guard.create(session_type, target, port, info)
}

pub async fn remove_session(id: u32) -> Option<Session> {
    let mut guard = SESSION_STORE.lock().await;
    guard.remove(id)
}

pub async fn start_tcp_listener(bind_addr: &str) -> Result<u16> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener on {}", bind_addr))?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let id = create_session(
                        "reverse_tcp",
                        &addr.ip().to_string(),
                        addr.port(),
                        "Reverse TCP shell",
                    )
                    .await;
                    tracing::info!("New reverse TCP session {} from {}", id, addr);
                    tokio::spawn(handle_session_stream(id, stream));
                }
                Err(e) => {
                    tracing::error!("TCP listener accept failed: {}", e);
                    break;
                }
            }
        }
    });

    Ok(port)
}

async fn handle_session_stream(id: u32, mut stream: TcpStream) {
    let (mut reader, _writer) = stream.split();
    let result = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    match result {
        Ok(n) => tracing::info!("session {} closed after {} bytes", id, n),
        Err(e) => tracing::info!("session {} disconnected: {}", id, e),
    }
    remove_session(id).await;
}
