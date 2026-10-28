//! Discoverer module interface

use crate::orchestrator::store::Store;
/// Discoverer trait defines the interface for discovering configuration values
pub trait Discoverer {
    /// Run the discoverer to discover configuration values
    fn run() -> anyhow::Result<Self>
    where
        Self: Sized;
}

/// Orchestrator trait, working with a mutable store
pub trait Orchestrator {
    /// Run the discovery and update store with discovered values
    fn discover(&self) -> anyhow::Result<Store>
    where
        Self: Sized;
}
