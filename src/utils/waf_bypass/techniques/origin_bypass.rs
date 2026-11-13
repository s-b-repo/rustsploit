//! Origin-server reachability probe for WAF/CDN bypass.
//!
//! [`probe_origin`] connects directly to a candidate origin IP with the real
//! `Host` header and returns the HTTP response, bounded by an explicit
//! timeout. It is the shared primitive behind origin-discovery modules such as
//! `exploits/webapps/cloudflare_origin_bypass`, which walk a list of candidate
//! IPs and check whether any serves the target's content directly — i.e.
//! outside the CDN/WAF, which defeats the protection entirely.
//!
//! For authorized penetration testing only.

use reqwest::Client;
use std::time::Duration;

/// Probe a candidate origin: `GET scheme://origin_ip:port/` carrying
/// `host_header` as the `Host` header, bounded by `timeout`.
///
/// Returns the response (body left unread for the caller to consume) on
/// success, or an error string on failure. A timeout is surfaced as a
/// `"timed out …"` message so callers can categorise it the same way they
/// categorise a transport error, without depending on the HTTP client having
/// its own deadline configured.
pub async fn probe_origin(
    client: &Client,
    scheme: &str,
    origin_ip: &str,
    port: u16,
    host_header: &str,
    timeout: Duration,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}://{}:{}/", scheme, origin_ip, port);
    match tokio::time::timeout(timeout, client.get(&url).header("Host", host_header).send()).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(anyhow::Error::from(e).context("origin request failed")),
        Err(elapsed) => Err(anyhow::anyhow!("timed out after {timeout:?}: {elapsed}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real loopback socket + reqwest; Miri has no host sockets
    async fn probe_origin_hits_real_listener() {
        // Deterministic success path: an async loopback listener serves one
        // canned HTTP/1.1 200 and then returns. Every wait is bounded, so the
        // test can never hang (the previous blocking-accept version could).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        let server = tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(5), listener.accept()).await {
                Ok(Ok((mut sock, _))) => {
                    sock.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap_or_else(|e| tracing::debug!("test server write failed: {e}"));
                    sock.flush()
                        .await
                        .unwrap_or_else(|e| tracing::debug!("test server flush failed: {e}"));
                }
                Ok(Err(e)) => tracing::debug!("test server accept failed: {e}"),
                Err(elapsed) => tracing::debug!("test server accept timed out: {elapsed}"),
            }
        });

        // reqwest is built with the `rustls-no-provider` feature, so a raw
        // `reqwest::Client::new()` needs the process-default rustls CryptoProvider
        // installed first or rustls panics at build time with "No provider set".
        // Production reaches this client through `utils::network::build_http_client*`,
        // which installs the ring provider; a raw client in a test must install it
        // itself (idempotent, guarded by a `std::sync::Once`).
        crate::utils::network::ensure_crypto_provider();
        let client = reqwest::Client::new();
        let result = probe_origin(
            &client,
            "http",
            &addr.ip().to_string(),
            addr.port(),
            "localhost",
            Duration::from_secs(5),
        )
        .await;

        // Bound the join so a stuck server thread can never hang the test.
        match tokio::time::timeout(Duration::from_secs(5), server).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!("server task error: {e}"),
            Err(elapsed) => tracing::debug!("server task join timed out: {elapsed}"),
        }

        assert_eq!(result.ok().map(|r| r.status().as_u16()), Some(200));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real loopback socket + reqwest; Miri has no host sockets
    async fn probe_origin_closed_port_completes_within_timeout() {
        // Unreachable-origin path: nothing (deterministically) listens on port
        // 9 (discard). Assert only that the probe COMPLETES inside its deadline
        // — the exact outcome varies (ECONNREFUSED, or a sandbox transparent
        // proxy answering) but it must never hang.
        // See the sibling test: with the `rustls-no-provider` feature a raw
        // `reqwest::Client::new()` panics at build time with "No provider set"
        // unless the process-default rustls CryptoProvider is installed first.
        // Idempotent (guarded by a `std::sync::Once`).
        crate::utils::network::ensure_crypto_provider();
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let result = probe_origin(
            &client,
            "http",
            "127.0.0.1",
            9,
            "localhost",
            Duration::from_secs(2),
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "probe must not hang"
        );
        drop(result);
    }
}
