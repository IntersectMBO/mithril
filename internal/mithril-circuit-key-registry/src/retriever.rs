//! Retrieval of the signed circuit verification key registry from its published source.

#[cfg(not(target_family = "wasm"))]
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use reqwest::Url;
use thiserror::Error;

use mithril_common::{StdError, StdResult};

use crate::{BoundedHttpDownloader, SignedCircuitVerificationKeyRegistry};

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
    ) -> StdResult<SignedCircuitVerificationKeyRegistry> {
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

/// A [CircuitVerificationKeyRegistryRetriever] downloading the signed registry JSON from a URL.
pub struct HttpCircuitVerificationKeyRegistryRetriever {
    registry_url: String,
    downloader: BoundedHttpDownloader,
}

impl HttpCircuitVerificationKeyRegistryRetriever {
    /// Build a retriever downloading the signed registry from the given HTTPS URL: plain HTTP is
    /// refused, so an on-path attacker cannot serve an outdated signed registry or block its
    /// refreshes.
    pub fn new(registry_url: String) -> StdResult<Self> {
        Self::check_url_is_https(&registry_url)?;

        Ok(Self {
            registry_url,
            downloader: BoundedHttpDownloader::new()?,
        })
    }

    /// Build a retriever also accepting a plain HTTP URL, for the tests served by a local server.
    #[cfg(all(test, not(target_family = "wasm")))]
    fn new_allowing_plain_http(registry_url: String) -> StdResult<Self> {
        Ok(Self {
            registry_url,
            downloader: BoundedHttpDownloader::new_allowing_plain_http()?,
        })
    }

    /// Fail unless the URL uses the HTTPS scheme.
    fn check_url_is_https(registry_url: &str) -> StdResult<()> {
        let url = Url::parse(registry_url).with_context(|| {
            format!("Invalid circuit verification key registry URL '{registry_url}'")
        })?;
        if url.scheme() != "https" {
            return Err(anyhow!(
                "The circuit verification key registry URL '{registry_url}' must use HTTPS"
            ));
        }

        Ok(())
    }

    /// Download and parse the signed registry.
    async fn download_registry(&self) -> StdResult<SignedCircuitVerificationKeyRegistry> {
        let registry_json = self.downloader.download_with_retry(&self.registry_url).await?;

        serde_json::from_str(&registry_json).with_context(|| {
            format!(
                "Failed to parse signed registry downloaded from '{}'",
                self.registry_url
            )
        })
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryRetriever for HttpCircuitVerificationKeyRegistryRetriever {
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>
    {
        self.download_registry()
            .await
            .map_err(CircuitVerificationKeyRegistryRetrieverError)
    }
}

/// A [CircuitVerificationKeyRegistryRetriever] for nodes without a configured registry source,
/// failing every retrieval so the certificates requiring the registry are rejected.
pub struct UnconfiguredCircuitVerificationKeyRegistryRetriever;

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryRetriever
    for UnconfiguredCircuitVerificationKeyRegistryRetriever
{
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>
    {
        Err(CircuitVerificationKeyRegistryRetrieverError(anyhow!(
            "No circuit verification key registry source is configured"
        )))
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};

    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};
    use mithril_common::temp_dir_create;

    use crate::CircuitVerificationKeyRegistry;

    use super::*;

    fn genesis_signer() -> GenesisSigner {
        GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer())
    }

    fn signed_registry() -> SignedCircuitVerificationKeyRegistry {
        SignedCircuitVerificationKeyRegistry::try_new(
            CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![],
            },
            &genesis_signer(),
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

    #[tokio::test]
    async fn http_retriever_downloads_a_signed_registry() {
        let server = MockServer::start();
        let signed_registry = signed_registry();
        server.mock(|when, then| {
            when.method(Method::GET).path("/registry.json");
            then.status(200)
                .body(serde_json::to_string(&signed_registry).unwrap());
        });

        let retrieved = HttpCircuitVerificationKeyRegistryRetriever::new_allowing_plain_http(
            server.url("/registry.json"),
        )
        .unwrap()
        .retrieve_signed_registry()
        .await
        .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn http_retriever_fails_on_an_invalid_document() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::GET).path("/registry.json");
            then.status(200).body("not a signed registry");
        });

        HttpCircuitVerificationKeyRegistryRetriever::new_allowing_plain_http(
            server.url("/registry.json"),
        )
        .unwrap()
        .retrieve_signed_registry()
        .await
        .expect_err("an invalid document must fail retrieval");
    }

    #[test]
    fn http_retriever_accepts_an_https_registry_url() {
        HttpCircuitVerificationKeyRegistryRetriever::new(
            "https://example.com/registry.json".to_string(),
        )
        .expect("an HTTPS registry URL must be accepted");
    }

    #[test]
    fn http_retriever_refuses_a_plain_http_registry_url() {
        assert!(
            HttpCircuitVerificationKeyRegistryRetriever::new(
                "http://example.com/registry.json".to_string()
            )
            .is_err(),
            "a plain HTTP registry URL must be refused"
        );
    }

    #[test]
    fn http_retriever_refuses_an_invalid_registry_url() {
        assert!(
            HttpCircuitVerificationKeyRegistryRetriever::new("not a url".to_string()).is_err(),
            "an invalid registry URL must be refused"
        );
    }

    #[tokio::test]
    async fn unconfigured_retriever_fails_every_retrieval() {
        UnconfiguredCircuitVerificationKeyRegistryRetriever
            .retrieve_signed_registry()
            .await
            .expect_err("an unconfigured registry source must fail retrieval");
    }
}
