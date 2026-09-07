use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SocksSession {
    pub id: u32,
    pub target: String,
    pub stream: Arc<Mutex<Option<TcpStream>>>,
}

pub struct SocksProxy {
    sessions: Mutex<Vec<SocksSession>>,
}

impl SocksProxy {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
        }
    }

    pub async fn register(&self, id: u32, target: &str, stream: TcpStream) {
        self.sessions.lock().await.push(SocksSession {
            id,
            target: target.to_string(),
            stream: Arc::new(Mutex::new(Some(stream))),
        });
    }

    pub async fn list(&self) -> Vec<SocksSession> {
        self.sessions.lock().await.clone()
    }
}

static GLOBAL_PROXY: std::sync::LazyLock<SocksProxy> = std::sync::LazyLock::new(SocksProxy::new);

pub fn global_proxy() -> &'static SocksProxy {
    &GLOBAL_PROXY
}
