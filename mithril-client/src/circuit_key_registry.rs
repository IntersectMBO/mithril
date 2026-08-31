//! Retrieval of the signed circuit verification key registry of the client's network, resolved
//! from the networks configuration file published in the Mithril repository.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde::Deserialize;

use mithril_common::StdResult;
#[cfg(not(target_family = "wasm"))]
pub use mithril_common::crypto_helper::FileCircuitVerificationKeyRegistryRetriever;
use mithril_common::crypto_helper::{
    CircuitVerificationKeyRegistryRetriever, CircuitVerificationKeyRegistryRetrieverError,
    SignedCircuitVerificationKeyRegistry,
};

/// URL of the networks configuration file published in the Mithril repository.
pub const DEFAULT_NETWORKS_CONFIGURATION_URL: &str =
    "https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json";

const DOWNLOAD_MAX_ATTEMPTS: usize = 3;

#[cfg(not(target_family = "wasm"))]
const DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS: u64 = 1000;

#[cfg(not(target_family = "wasm"))]
const DOWNLOAD_TIMEOUT_IN_SECONDS: u64 = 10;

const DOWNLOAD_MAX_BODY_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Representation of a Cardano network environment in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct CardanoNetworkConfiguration {
    /// Mithril networks of the environment, keyed by their name.
    #[serde(rename = "mithril-networks", default)]
    mithril_networks: Vec<HashMap<String, MithrilNetworkConfiguration>>,
}

/// Representation of a Mithril network in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct MithrilNetworkConfiguration {
    /// Aggregators serving the network.
    #[serde(default)]
    aggregators: Vec<AggregatorConfiguration>,

    /// Reference to the signed circuit verification key registry of the network.
    #[serde(rename = "circuit-verification-key-registry")]
    circuit_verification_key_registry: Option<UrlReference>,
}

impl MithrilNetworkConfiguration {
    /// Whether one of the network's aggregators serves the given endpoint.
    fn is_served_by(&self, aggregator_endpoint: &str) -> bool {
        self.aggregators.iter().any(|aggregator| {
            Self::normalize_endpoint(&aggregator.url)
                == Self::normalize_endpoint(aggregator_endpoint)
        })
    }

    /// Return the registry URL referenced by the network.
    fn registry_url(&self) -> Option<String> {
        self.circuit_verification_key_registry
            .as_ref()
            .map(|registry| registry.url.clone())
    }

    /// Normalize an aggregator endpoint for comparison, ignoring surrounding whitespace and
    /// trailing slashes.
    fn normalize_endpoint(endpoint: &str) -> &str {
        endpoint.trim().trim_end_matches('/')
    }
}

/// Representation of an aggregator in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct AggregatorConfiguration {
    /// Endpoint of the aggregator.
    url: String,
}

/// Reference to a remote resource by URL in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct UrlReference {
    /// URL of the resource.
    url: String,
}

/// The Mithril networks listed in the networks configuration file.
struct MithrilNetworksConfiguration {
    networks: Vec<MithrilNetworkConfiguration>,
}

impl MithrilNetworksConfiguration {
    /// Parse the networks configuration file, tolerating top-level entries that do not follow the
    /// Cardano network environment shape, so a future metadata field cannot fail the whole
    /// resolution.
    fn parse(networks_configuration_json: &str) -> StdResult<Self> {
        let root: HashMap<String, serde_json::Value> =
            serde_json::from_str(networks_configuration_json)?;
        let networks = root
            .into_values()
            .filter_map(|cardano_network| {
                serde_json::from_value::<CardanoNetworkConfiguration>(cardano_network).ok()
            })
            .flat_map(|cardano_network| cardano_network.mithril_networks)
            .flat_map(|mithril_networks| mithril_networks.into_values())
            .collect();

        Ok(Self { networks })
    }

    /// Return the registry URL of the network served by the given aggregator endpoint.
    fn registry_url_of_aggregator(&self, aggregator_endpoint: &str) -> Option<String> {
        self.networks
            .iter()
            .find(|network| network.is_served_by(aggregator_endpoint))
            .and_then(MithrilNetworkConfiguration::registry_url)
    }
}

/// HTTP downloader of the documents involved in the registry resolution, bounding the request
/// duration and the response size, and retrying failed attempts.
struct BoundedHttpDownloader {
    client: reqwest::Client,
}

impl BoundedHttpDownloader {
    /// Build a downloader with a request timeout, so a hung download cannot stall certificate
    /// verification.
    #[cfg(not(target_family = "wasm"))]
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_IN_SECONDS))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Build a downloader relying on the browser to bound the request duration, as the request
    /// timeout builder is not available on WASM.
    #[cfg(target_family = "wasm")]
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Download the document at the given URL, retrying failed attempts up to
    /// [DOWNLOAD_MAX_ATTEMPTS] times.
    async fn download_with_retry(&self, url: &str) -> StdResult<String> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.download(url).await {
                Ok(document) => return Ok(document),
                Err(_) if attempts < DOWNLOAD_MAX_ATTEMPTS => Self::wait_before_retry().await,
                Err(error) => {
                    return Err(error.context(format!(
                        "Failed to download '{url}' after {DOWNLOAD_MAX_ATTEMPTS} attempts"
                    )));
                }
            }
        }
    }

    /// Download the document at the given URL, failing on a non success status or a response
    /// exceeding the size limit.
    async fn download(&self, url: &str) -> StdResult<String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to download '{url}'"))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download '{url}': status {}",
                response.status()
            ));
        }
        Self::check_size_limit(url, response.content_length().unwrap_or_default())?;
        let document = response
            .text()
            .await
            .with_context(|| format!("Failed to read the response of '{url}'"))?;
        Self::check_size_limit(url, document.len() as u64)?;

        Ok(document)
    }

    /// Fail when the response size exceeds [DOWNLOAD_MAX_BODY_SIZE_IN_BYTES], the memory bound
    /// on the documents served by the untrusted routing URLs.
    fn check_size_limit(url: &str, size_in_bytes: u64) -> StdResult<()> {
        if size_in_bytes > DOWNLOAD_MAX_BODY_SIZE_IN_BYTES {
            return Err(anyhow!(
                "Failed to download '{url}': response of {size_in_bytes} bytes exceeds the {DOWNLOAD_MAX_BODY_SIZE_IN_BYTES} bytes limit"
            ));
        }

        Ok(())
    }

    /// Wait for [DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS] before the next download attempt.
    #[cfg(not(target_family = "wasm"))]
    async fn wait_before_retry() {
        tokio::time::sleep(std::time::Duration::from_millis(
            DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS,
        ))
        .await;
    }

    /// Retry immediately: no timer is available on WASM.
    #[cfg(target_family = "wasm")]
    async fn wait_before_retry() {}
}

/// A [CircuitVerificationKeyRegistryRetriever] resolving the signed registry of the client's
/// network from the networks configuration file, then downloading it over HTTP.
///
/// The network entry is selected by matching the aggregator endpoint. The networks
/// configuration is pure routing, never trust: a wrong selection can only yield a registry that
/// fails the genesis signature verification of the certifier.
pub struct RemoteCircuitVerificationKeyRegistryRetriever {
    networks_configuration_url: String,
    aggregator_endpoint: String,
    downloader: BoundedHttpDownloader,
}

impl RemoteCircuitVerificationKeyRegistryRetriever {
    /// Build a retriever for the network served by the given aggregator endpoint.
    pub fn new(aggregator_endpoint: String) -> Self {
        Self::new_with_networks_configuration_url(
            DEFAULT_NETWORKS_CONFIGURATION_URL.to_string(),
            aggregator_endpoint,
        )
    }

    /// Build a retriever resolving from the given networks configuration file URL.
    pub fn new_with_networks_configuration_url(
        networks_configuration_url: String,
        aggregator_endpoint: String,
    ) -> Self {
        Self {
            networks_configuration_url,
            aggregator_endpoint,
            downloader: BoundedHttpDownloader::new(),
        }
    }

    /// Resolve the registry URL of the client's network from the networks configuration file,
    /// then download and parse the signed registry.
    async fn resolve_and_download_registry(
        &self,
    ) -> StdResult<SignedCircuitVerificationKeyRegistry> {
        let networks_configuration_json = self
            .downloader
            .download_with_retry(&self.networks_configuration_url)
            .await?;
        let networks_configuration = MithrilNetworksConfiguration::parse(
            &networks_configuration_json,
        )
        .with_context(|| {
            format!(
                "Failed to parse networks configuration downloaded from '{}'",
                self.networks_configuration_url
            )
        })?;
        let registry_url = networks_configuration
            .registry_url_of_aggregator(&self.aggregator_endpoint)
            .ok_or_else(|| {
                anyhow!(
                    "No circuit verification key registry is referenced in '{}' for the network of aggregator '{}'",
                    self.networks_configuration_url,
                    self.aggregator_endpoint
                )
            })?;
        let registry_json = self.downloader.download_with_retry(&registry_url).await?;

        serde_json::from_str(&registry_json).with_context(|| {
            format!("Failed to parse signed registry downloaded from '{registry_url}'")
        })
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryRetriever for RemoteCircuitVerificationKeyRegistryRetriever {
    async fn retrieve_signed_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetrieverError>
    {
        self.resolve_and_download_registry()
            .await
            .map_err(CircuitVerificationKeyRegistryRetrieverError)
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use httpmock::MockServer;

    use mithril_common::crypto_helper::{
        CircuitVerificationKeyRegistry, GenesisEd25519Signer, GenesisSigner,
    };

    use super::*;

    const AGGREGATOR_ENDPOINT: &str = "https://aggregator.devnet.example/aggregator";

    fn genesis_signer() -> GenesisSigner {
        GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer())
    }

    fn signed_registry(genesis_signer: &GenesisSigner) -> SignedCircuitVerificationKeyRegistry {
        SignedCircuitVerificationKeyRegistry::try_new(
            CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![],
            },
            genesis_signer,
        )
        .unwrap()
    }

    fn networks_configuration_json(server: &MockServer, aggregator_endpoint: &str) -> String {
        format!(
            r#"{{
                "devnet": {{
                    "mithril-networks": [
                        {{
                            "release-devnet": {{
                                "aggregators": [{{ "url": "{aggregator_endpoint}" }}],
                                "circuit-verification-key-registry": {{ "url": "{registry_url}" }}
                            }}
                        }}
                    ]
                }}
            }}"#,
            registry_url = server.url("/registry.json"),
        )
    }

    fn retriever_over(
        server: &MockServer,
        aggregator_endpoint: &str,
    ) -> RemoteCircuitVerificationKeyRegistryRetriever {
        RemoteCircuitVerificationKeyRegistryRetriever::new_with_networks_configuration_url(
            server.url("/networks.json"),
            aggregator_endpoint.to_string(),
        )
    }

    #[tokio::test]
    async fn resolves_the_registry_of_the_network_matching_the_aggregator_endpoint() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        let signed_registry = signed_registry(&genesis_signer);
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(200)
                .body(serde_json::to_string(&signed_registry).unwrap());
        });

        let retrieved = retriever_over(&server, AGGREGATOR_ENDPOINT)
            .retrieve_signed_registry()
            .await
            .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn tolerates_top_level_metadata_entries_in_the_networks_configuration() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        let signed_registry = signed_registry(&genesis_signer);
        let networks_configuration_with_metadata = format!(
            r#"{{ "version": 2, {} }}"#,
            networks_configuration_json(&server, AGGREGATOR_ENDPOINT)
                .trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
        );
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200).body(networks_configuration_with_metadata);
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(200)
                .body(serde_json::to_string(&signed_registry).unwrap());
        });

        let retrieved = retriever_over(&server, AGGREGATOR_ENDPOINT)
            .retrieve_signed_registry()
            .await
            .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn fails_on_a_response_exceeding_the_body_size_limit_before_using_it() {
        let server = MockServer::start();
        let oversized_networks_configuration = format!(
            "{}{}",
            networks_configuration_json(&server, AGGREGATOR_ENDPOINT),
            " ".repeat(DOWNLOAD_MAX_BODY_SIZE_IN_BYTES as usize)
        );
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200).body(oversized_networks_configuration);
        });
        let registry = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(200);
        });

        retriever_over(&server, AGGREGATOR_ENDPOINT)
            .retrieve_signed_registry()
            .await
            .expect_err("an oversized response must fail retrieval");

        assert_eq!(0, registry.hits());
    }

    #[tokio::test]
    async fn fails_when_no_network_is_served_by_the_aggregator_endpoint() {
        let server = MockServer::start();
        let registry = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(200);
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });

        retriever_over(&server, "https://another-network.example/aggregator")
            .retrieve_signed_registry()
            .await
            .expect_err("an unmatched aggregator endpoint must fail retrieval");

        assert_eq!(0, registry.hits());
    }

    #[tokio::test]
    async fn retries_a_failed_download() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });
        let failing_registry = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(500);
        });

        retriever_over(&server, AGGREGATOR_ENDPOINT)
            .retrieve_signed_registry()
            .await
            .expect_err("a persistently failing download must fail retrieval");

        assert_eq!(DOWNLOAD_MAX_ATTEMPTS, failing_registry.hits());
    }
}
