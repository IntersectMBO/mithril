//! Retrieval of the signed circuit verification key registry from its published source.

#[cfg(not(target_family = "wasm"))]
use std::path::PathBuf;

use anyhow::Context;
use async_trait::async_trait;
use thiserror::Error;

use crate::StdError;

use super::SignedCircuitVerificationKeyRegistry;

/// [CircuitVerificationKeyRegistryRetriever] related errors.
#[derive(Debug, Error)]
#[error("Error when retrieving circuit verification key registry")]
pub struct CircuitVerificationKeyRegistryRetrieverError(#[source] pub StdError);

/// Retrieves the signed circuit verification key registry published at the root of the repository.
///
/// Implementations return the signed document unverified: the genesis signature and version
/// checks belong to the caller, so an untrusted transport cannot bypass them.
#[cfg_attr(test, mockall::automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CircuitVerificationKeyRegistryRetriever: Sync + Send {
    /// Retrieve the signed registry from its source.
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>;
}

/// A [CircuitVerificationKeyRegistryRetriever] reading the signed registry JSON from a local file.
#[cfg(not(target_family = "wasm"))]
pub struct FileCircuitVerificationKeyRegistryRetriever {
    registry_file_path: PathBuf,
}

#[cfg(not(target_family = "wasm"))]
impl FileCircuitVerificationKeyRegistryRetriever {
    /// Build a retriever reading the given signed registry JSON file.
    pub fn new(registry_file_path: PathBuf) -> Self {
        Self { registry_file_path }
    }

    /// Read the signed registry JSON file and parse it.
    fn read_and_parse_registry_file(
        registry_file_path: &PathBuf,
    ) -> Result<SignedCircuitVerificationKeyRegistry, StdError> {
        let json = std::fs::read_to_string(registry_file_path).with_context(|| {
            format!(
                "Failed to read signed registry file at '{}'",
                registry_file_path.display()
            )
        })?;
        serde_json::from_str(&json).with_context(|| {
            format!(
                "Failed to parse signed registry file at '{}'",
                registry_file_path.display()
            )
        })
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl CircuitVerificationKeyRegistryRetriever for FileCircuitVerificationKeyRegistryRetriever {
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>
    {
        let registry_file_path = self.registry_file_path.clone();
        tokio::task::spawn_blocking(move || Self::read_and_parse_registry_file(&registry_file_path))
            .await
            .map_err(|e| CircuitVerificationKeyRegistryRetrieverError(e.into()))?
            .map_err(CircuitVerificationKeyRegistryRetrieverError)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto_helper::{
        CircuitVerificationKeyRegistry, GenesisEd25519Signer, GenesisSigner,
    };
    use crate::temp_dir_create;

    use super::*;

    fn signed_registry() -> SignedCircuitVerificationKeyRegistry {
        let genesis_signer =
            GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
        SignedCircuitVerificationKeyRegistry::try_new(
            CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![],
            },
            &genesis_signer,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn file_retriever_reads_a_signed_registry_json_file() {
        let temp_dir = temp_dir_create!();
        let registry_file_path = temp_dir.join("signed-registry.json");
        let signed_registry = signed_registry();
        std::fs::write(
            &registry_file_path,
            serde_json::to_string(&signed_registry).unwrap(),
        )
        .unwrap();

        let retrieved = FileCircuitVerificationKeyRegistryRetriever::new(registry_file_path)
            .retrieve_signed_registry()
            .await
            .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn file_retriever_fails_on_a_missing_file() {
        let temp_dir = temp_dir_create!();

        FileCircuitVerificationKeyRegistryRetriever::new(temp_dir.join("missing.json"))
            .retrieve_signed_registry()
            .await
            .expect_err("a missing registry file must fail retrieval");
    }

    #[tokio::test]
    async fn file_retriever_fails_on_an_invalid_json_file() {
        let temp_dir = temp_dir_create!();
        let registry_file_path = temp_dir.join("signed-registry.json");
        std::fs::write(&registry_file_path, "not a signed registry").unwrap();

        FileCircuitVerificationKeyRegistryRetriever::new(registry_file_path)
            .retrieve_signed_registry()
            .await
            .expect_err("an invalid registry file must fail retrieval");
    }
}
