use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

use tokio::sync::{Mutex, broadcast};

static BROADCAST_MAP: std::sync::LazyLock<Mutex<HashMap<u64, broadcast::Sender<String>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub async fn create_stream() -> (u64, broadcast::Receiver<String>) {
    let (tx, rx) = broadcast::channel(2048);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    BROADCAST_MAP.lock().await.insert(id, tx);
    (id, rx)
}

pub async fn push_line(stream_id: u64, line: String) {
    if let Some(tx) = BROADCAST_MAP.lock().await.get(&stream_id) {
        if let Err(e) = tx.send(line) {
            // No live receivers for this stream (normal after a client
            // disconnects) — trace-level so the discard is visible in logs.
            tracing::trace!("stream {stream_id} has no receivers: {}", e);
        }
    }
}

pub async fn close_stream(stream_id: u64) {
    BROADCAST_MAP.lock().await.remove(&stream_id);
}
