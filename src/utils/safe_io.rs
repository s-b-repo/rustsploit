//! Bounded read helpers — never let an attacker-controlled stream OOM us.
//!
//! Use `read_async_capped` instead of `AsyncReadExt::read_to_end` whenever the
//! peer is untrusted (cameras, IPMI BMCs, honeypots, routers, anything we
//! probe). Use `read_http_body_capped` instead of `reqwest::Response::text()`
//! / `.bytes()` for the same reason.

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};
use std::io::Read;

/// Default upper bound for "I expect a small response" callers — 8 MiB.
///
/// Picked to be generous for banner / handshake / config-leak responses
/// without letting a malicious server force gigabyte allocations.
pub const DEFAULT_BODY_CAP: usize = 8 * 1024 * 1024;

/// Read up to `max` bytes from `reader` into a `Vec<u8>`. Returns `Err` if
/// the stream produces more than `max` (so the caller can decide whether to
/// treat truncation as a vulnerability indicator).
pub async fn read_async_capped<R>(reader: &mut R, max: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = Vec::new();
    let mut limited = AsyncReadExt::take(reader, max as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .await
        .context("read_async_capped: underlying read failed")?;
    if buf.len() > max {
        return Err(anyhow!(
            "response exceeded {} byte cap (peer sent at least {} bytes)",
            max,
            buf.len()
        ));
    }
    Ok(buf)
}

/// Synchronous twin of [`read_async_capped`] for blocking readers (e.g. ssh2
/// channels, raw `TcpStream`s used in spawn_blocking helpers). Caps reads at
/// `max` bytes and returns `Err` if the peer would have sent more.
pub fn read_sync_capped<R>(reader: &mut R, max: usize) -> Result<Vec<u8>>
where
    R: Read + ?Sized,
{
    let mut buf = Vec::new();
    let mut limited = Read::take(reader, max as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .context("read_sync_capped: underlying read failed")?;
    if buf.len() > max {
        return Err(anyhow!(
            "response exceeded {} byte cap (peer sent at least {} bytes)",
            max,
            buf.len()
        ));
    }
    Ok(buf)
}

/// Stream a reqwest response body into a `Vec<u8>`, refusing if it exceeds
/// `max`. Honours `Content-Length` early when present.
pub async fn read_http_body_capped(resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length()
        && len > max as u64 {
            return Err(anyhow!(
                "response Content-Length {} exceeds {} byte cap",
                len,
                max
            ));
        }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read_http_body_capped: stream error")?;
        if buf.len().saturating_add(chunk.len()) > max {
            return Err(anyhow!(
                "response exceeded {} byte cap during streaming",
                max
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
