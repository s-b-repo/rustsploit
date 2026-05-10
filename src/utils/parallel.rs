//! Bounded-concurrency helpers for batched async work.
//!
//! Most scanners that iterate over 10-200 candidate URLs / origins / paths
//! get a 5-20× speed-up by running probes concurrently. This module wraps
//! `futures::stream::buffered` so callers don't have to spell out the
//! `Pin<Box<dyn Future + Send>>` boilerplate.
//!
//! Usage idiom: build a `Vec<Pin<Box<dyn Future<Output = R> + Send>>>` of
//! work futures (typically via `Box::pin(async move { … })` in a `.map()`
//! chain) and hand it to [`run_buffered`]. Output is in input order.
//!
//! ```ignore
//! use crate::utils::parallel::run_buffered;
//!
//! let work: Vec<_> = urls.into_iter().map(|u| {
//!     let client = client.clone();
//!     Box::pin(async move {
//!         let r = client.get(&u).send().await;
//!         (u, r)
//!     }) as _
//! }).collect();
//! let results = run_buffered(work, 16).await;
//! ```
//!
//! Erasing the future type via `Pin<Box<dyn Future + Send>>` sidesteps
//! HRTB Send-inference brittleness that otherwise leaks into the
//! framework's `tokio::spawn`-based mass-scan dispatch.

use std::future::Future;
use std::pin::Pin;

use futures::stream::{self, StreamExt};

/// Boxed, dynamic, Send-bound future. Use this as the `Vec`'s element type
/// when building a batch of work for [`run_buffered`].
pub type BoxFut<R> = Pin<Box<dyn Future<Output = R> + Send>>;

/// Run a batch of futures with at most `max_concurrency` polling at the
/// same time. Returns results **in input order**.
pub async fn run_buffered<R>(work: Vec<BoxFut<R>>, max_concurrency: usize) -> Vec<R>
where
    R: Send + 'static,
{
    let max = max_concurrency.max(1);
    stream::iter(work).buffered(max).collect().await
}

/// Same as [`run_buffered`] but yields results in completion order.
#[allow(dead_code)] // public utility for future scanners that prefer streaming-as-ready output
pub async fn run_buffered_unordered<R>(work: Vec<BoxFut<R>>, max_concurrency: usize) -> Vec<R>
where
    R: Send + 'static,
{
    let max = max_concurrency.max(1);
    stream::iter(work).buffer_unordered(max).collect().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn buffered_preserves_order() {
        let work: Vec<BoxFut<u64>> = (0..4u64).rev().map(|x| {
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(10 * x)).await;
                x * 2
            }) as _
        }).collect();
        let out = run_buffered(work, 4).await;
        assert_eq!(out, vec![6, 4, 2, 0]);
    }
}
