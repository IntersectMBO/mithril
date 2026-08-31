//! A module used for a fake implementation of a circuit verification key certifier
//!

use anyhow::anyhow;
use async_trait::async_trait;

use crate::StdResult;
use crate::crypto_helper::{CircuitVerificationKeyCertifier, CircuitVerificationKeyRegistry};

/// A fake [CircuitVerificationKeyCertifier] serving a configured registry as verified.
pub struct FakeCircuitVerificationKeyCertifier {
    registry: Option<CircuitVerificationKeyRegistry>,
}

impl FakeCircuitVerificationKeyCertifier {
    /// Create a fake certifier serving the given registry as verified.
    pub fn from_registry(registry: CircuitVerificationKeyRegistry) -> Self {
        Self {
            registry: Some(registry),
        }
    }

    /// Create a fake certifier failing every check, as when no registry can be retrieved.
    pub fn that_fails() -> Self {
        Self { registry: None }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for FakeCircuitVerificationKeyCertifier {
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        self.registry
            .clone()
            .ok_or_else(|| anyhow!("Verified registry not available"))
    }
}
