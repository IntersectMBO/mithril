//! Discoverer module interface
/// Discoverer trait defines the interface for discovering configuration values
pub trait Discoverer {
    /// Run the discoverer to discover configuration values
    fn run() -> anyhow::Result<Self>
    where
        Self: Sized;
}
