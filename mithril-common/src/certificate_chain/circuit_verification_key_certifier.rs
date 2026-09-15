//! Certification of the circuit verification keys of SNARK certificates.

use async_trait::async_trait;

use mithril_stm::CircuitVerificationKeyDigest;

use crate::StdResult;
use crate::entities::Epoch;

/// Certifies the circuit verification key digests carried by a SNARK certificate.
///
/// Implemented over the genesis-signed circuit verification key registry, which lives in its own
/// crate, so the certificate verifier only depends on the check itself.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CircuitVerificationKeyCertifier: Sync + Send {
    /// Check that every digest is allowed for the given epoch.
    async fn check(&self, digests: &[CircuitVerificationKeyDigest], epoch: Epoch) -> StdResult<()>;
}
