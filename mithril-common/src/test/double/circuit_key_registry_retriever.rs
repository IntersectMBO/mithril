//! A module used for a fake implementation of a circuit verification key registry retriever
//!

use anyhow::anyhow;
use async_trait::async_trait;

use crate::crypto_helper::{
    CircuitVerificationKeyRegistryRetriever, CircuitVerificationKeyRegistryRetrieverError,
    SignedCircuitVerificationKeyRegistry,
};

/// A fake [CircuitVerificationKeyRegistryRetriever] that returns a configured signed registry.
pub struct FakeCircuitVerificationKeyRegistryRetriever {
    signed_registry: Option<SignedCircuitVerificationKeyRegistry>,
}

impl FakeCircuitVerificationKeyRegistryRetriever {
    /// Create a fake retriever returning the given signed registry.
    pub fn from_signed_registry(signed_registry: SignedCircuitVerificationKeyRegistry) -> Self {
        Self {
            signed_registry: Some(signed_registry),
        }
    }

    /// Create a fake retriever failing every retrieval.
    pub fn that_fails() -> Self {
        Self {
            signed_registry: None,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryRetriever for FakeCircuitVerificationKeyRegistryRetriever {
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>
    {
        self.signed_registry.clone().ok_or_else(|| {
            CircuitVerificationKeyRegistryRetrieverError(anyhow!("Signed registry not found"))
        })
    }
}
