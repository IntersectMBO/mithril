//! Retrieval of the signed circuit verification key registry of the client's network, resolved
//! from the networks configuration file published in the Mithril repository.
//!
//! The registry retriever trait and the registry types are re-exported here, so a custom
//! retriever can be given to the client builder without depending on the registry crate.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde::Deserialize;

use mithril_circuit_key_registry::BoundedHttpDownloader;
#[cfg(not(target_family = "wasm"))]
pub use mithril_circuit_key_registry::FileCircuitVerificationKeyRegistryRetriever;
pub use mithril_circuit_key_registry::{
    CircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetriever,
    CircuitVerificationKeyRegistryRetrieverError, SignedCircuitVerificationKeyRegistry,
};
use mithril_common::StdResult;

/// URL of the networks configuration file published in the Mithril repository.
pub const DEFAULT_NETWORKS_CONFIGURATION_URL: &str =
    "https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json";

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

/// A [CircuitVerificationKeyRegistryRetriever] resolving the signed registry of the client's
/// network from the networks configuration file, then downloading it over HTTP.
///
/// The network entry is selected by matching the aggregator endpoint. The networks
/// configuration is routing, never trust: the certifier verifies the genesis signature of the
/// registry it points to, so a wrong route can only yield a registry that fails that
/// verification or an older registry of the same network.
pub struct RemoteCircuitVerificationKeyRegistryRetriever {
    networks_configuration_url: String,
    aggregator_endpoint: String,
    downloader: BoundedHttpDownloader,
}

impl RemoteCircuitVerificationKeyRegistryRetriever {
    /// Build a retriever for the network served by the given aggregator endpoint.
    pub fn new(aggregator_endpoint: String) -> StdResult<Self> {
        Self::new_with_networks_configuration_url(
            DEFAULT_NETWORKS_CONFIGURATION_URL.to_string(),
            aggregator_endpoint,
        )
    }

    /// Build a retriever resolving from the given networks configuration file URL.
    pub fn new_with_networks_configuration_url(
        networks_configuration_url: String,
        aggregator_endpoint: String,
    ) -> StdResult<Self> {
        Ok(Self {
            networks_configuration_url,
            aggregator_endpoint,
            downloader: BoundedHttpDownloader::new()?,
        })
    }

    /// Build a retriever also accepting plain HTTP URLs, for the tests served by a local server.
    #[cfg(all(test, not(target_family = "wasm")))]
    fn new_allowing_plain_http(
        networks_configuration_url: String,
        aggregator_endpoint: String,
    ) -> StdResult<Self> {
        Ok(Self {
            networks_configuration_url,
            aggregator_endpoint,
            downloader: BoundedHttpDownloader::new_allowing_plain_http()?,
        })
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

    use mithril_circuit_key_registry::{DOWNLOAD_MAX_ATTEMPTS, DOWNLOAD_MAX_BODY_SIZE_IN_BYTES};
    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};

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
        RemoteCircuitVerificationKeyRegistryRetriever::new_allowing_plain_http(
            server.url("/networks.json"),
            aggregator_endpoint.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn parses_a_network_without_registry_reference() {
        let configuration = MithrilNetworksConfiguration::parse(&format!(
            r#"{{ "devnet": {{ "mithril-networks": [ {{ "release-devnet": {{ "aggregators": [ {{ "url": "{AGGREGATOR_ENDPOINT}" }} ] }} }} ] }} }}"#
        ))
        .unwrap();

        assert_eq!(1, configuration.networks.len());
        assert_eq!(
            None,
            configuration.registry_url_of_aggregator(AGGREGATOR_ENDPOINT)
        );
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
