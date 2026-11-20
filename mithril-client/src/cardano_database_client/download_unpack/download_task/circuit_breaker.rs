use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A circuit breaker for a download location, meant to be shared across every location backed by
/// the same downloader kind within one batch (e.g., one per download_unpack() call for all Ipfs locations).
#[derive(Clone)]
pub struct CircuitBreaker(Arc<AtomicBool>);

impl CircuitBreaker {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    #[cfg(test)]
    pub fn new_triggered() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn trigger(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_triggered(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}
