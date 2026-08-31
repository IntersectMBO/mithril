//! A module used for a fake implementation of a circuit verification key certifier
//!

use anyhow::anyhow;
use async_trait::async_trait;

use mithril_stm::CircuitVerificationKeyDigest;

use crate::StdResult;
use crate::certificate_chain::CircuitVerificationKeyCertifier;
use crate::entities::Epoch;

/// A fake [CircuitVerificationKeyCertifier] failing every check, as when no registry can be
/// retrieved.
pub struct FakeCircuitVerificationKeyCertifier;

impl FakeCircuitVerificationKeyCertifier {
    /// Create a fake certifier failing every check.
    pub fn that_fails() -> Self {
        Self
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for FakeCircuitVerificationKeyCertifier {
    async fn check(
        &self,
        _digests: &[CircuitVerificationKeyDigest],
        _epoch: Epoch,
    ) -> StdResult<()> {
        Err(anyhow!("Verified registry not available"))
    }
}
