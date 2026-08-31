//! Retrieval of the signed circuit verification key registry of the client's network, resolved
//! from the networks configuration file published in the Mithril repository.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde::Deserialize;

use mithril_common::StdError;
use mithril_common::crypto_helper::{
    CircuitVerificationKeyRegistryRetriever, CircuitVerificationKeyRegistryRetrieverError,
    GenesisEd25519VerificationKey, GenesisVerifier, SignedCircuitVerificationKeyRegistry,
};

/// URL of the networks configuration file published in the Mithril repository.
pub const DEFAULT_NETWORKS_CONFIGURATION_URL: &str =
    "https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json";

const DOWNLOAD_MAX_ATTEMPTS: usize = 3;

const DOWNLOAD_RETRY_DELAY_IN_MILLISECONDS: u64 = 1000;

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

    /// Genesis section of the network.
    genesis: Option<GenesisConfiguration>,

    /// Reference to the signed circuit verification key registry of the network.
    #[serde(rename = "circuit-verification-key-registry")]
    circuit_verification_key_registry: Option<UrlReference>,
}

/// Representation of an aggregator in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct AggregatorConfiguration {
    /// Endpoint of the aggregator.
    url: String,
}

/// Representation of the genesis section of a Mithril network in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct GenesisConfiguration {
    /// Reference to the genesis verification key of the network.
    #[serde(rename = "verification-key")]
    verification_key: Option<UrlReference>,
}

/// Reference to a remote resource by URL in the networks configuration file.
#[derive(Debug, Clone, Deserialize)]
struct UrlReference {
    /// URL of the resource.
    url: String,
}

/// A [CircuitVerificationKeyRegistryRetriever] resolving the signed registry of the client's
/// network from the networks configuration file, then downloading it over HTTP with retries.
///
/// The network entry is selected by matching the aggregator endpoint, falling back to matching
/// the genesis verification key. The networks configuration is pure routing, never trust: a
/// wrong selection can only yield a registry that fails the genesis signature verification of
/// the certifier.
pub struct RemoteCircuitVerificationKeyRegistryRetriever {
    networks_configuration_url: String,
    aggregator_endpoint: String,
    genesis_verification_key: String,
    client: reqwest::Client,
}

impl RemoteCircuitVerificationKeyRegistryRetriever {
    /// Build a retriever for the network served by the given aggregator endpoint and verified
    /// with the given genesis verification key.
    pub fn new(aggregator_endpoint: String, genesis_verification_key: String) -> Self {
        Self::new_with_networks_configuration_url(
            DEFAULT_NETWORKS_CONFIGURATION_URL.to_string(),
            aggregator_endpoint,
            genesis_verification_key,
        )
    }

    /// Build a retriever resolving from the given networks configuration file URL.
    pub fn new_with_networks_configuration_url(
        networks_configuration_url: String,
        aggregator_endpoint: String,
        genesis_verification_key: String,
    ) -> Self {
        Self {
            networks_configuration_url,
            aggregator_endpoint,
            genesis_verification_key,
            client: Self::build_http_client(),
        }
    }

    /// Build the HTTP client, with a request timeout so a hung download cannot stall
    /// certificate verification (browsers bound requests themselves on WASM).
    #[cfg(not(target_family = "wasm"))]
    fn build_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_IN_SECONDS))
            .build()
            .unwrap_or_default()
    }

    /// Build the HTTP client (the request timeout builder is not available on WASM).
    #[cfg(target_family = "wasm")]
    fn build_http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    /// Resolve the registry URL of the client's network from the networks configuration file,
    /// then download and parse the signed registry.
    async fn resolve_and_download_registry(
        &self,
    ) -> Result<SignedCircuitVerificationKeyRegistry, StdError> {
        let networks_configuration_json =
            self.download_with_retry(&self.networks_configuration_url).await?;
        let networks =
            Self::parse_mithril_networks(&networks_configuration_json).with_context(|| {
                format!(
                    "Failed to parse networks configuration downloaded from '{}'",
                    self.networks_configuration_url
                )
            })?;

        let registry_url =
            self.resolve_registry_url(&networks).await?.ok_or_else(|| {
                anyhow!(
                    "No circuit verification key registry is referenced in '{}' for the network of aggregator '{}' or of the genesis verification key",
                    self.networks_configuration_url,
                    self.aggregator_endpoint
                )
            })?;
        let registry_json = self.download_with_retry(&registry_url).await?;

        serde_json::from_str(&registry_json).with_context(|| {
            format!("Failed to parse signed registry downloaded from '{registry_url}'")
        })
    }

    /// Resolve the registry URL of the client's network, matching the aggregator endpoint first
    /// and falling back to matching the genesis verification key.
    async fn resolve_registry_url(
        &self,
        networks: &[MithrilNetworkConfiguration],
    ) -> Result<Option<String>, StdError> {
        if let Some(network) = networks
            .iter()
            .find(|network| self.is_served_by_aggregator_endpoint(network))
        {
            return Ok(Self::registry_url_of(network));
        }

        let own_genesis_verification_key =
            GenesisVerifier::try_from_hex(&self.genesis_verification_key)
                .with_context(|| "Invalid genesis verification key")?
                .to_ed25519_verification_key();
        for network in networks {
            if network.circuit_verification_key_registry.is_some()
                && self
                    .has_genesis_verification_key(network, &own_genesis_verification_key)
                    .await
            {
                return Ok(Self::registry_url_of(network));
            }
        }

        Ok(None)
    }

    /// Collect every Mithril network of the networks configuration file, tolerating top-level
    /// entries that do not follow the Cardano network environment shape, so a future metadata
    /// field cannot fail the whole resolution.
    fn parse_mithril_networks(
        networks_configuration_json: &str,
    ) -> Result<Vec<MithrilNetworkConfiguration>, StdError> {
        let root: HashMap<String, serde_json::Value> =
            serde_json::from_str(networks_configuration_json)?;

        Ok(root
            .into_values()
            .filter_map(|cardano_network| {
                serde_json::from_value::<CardanoNetworkConfiguration>(cardano_network).ok()
            })
            .flat_map(|cardano_network| cardano_network.mithril_networks)
            .flat_map(|mithril_networks| mithril_networks.into_values())
            .collect())
    }

    /// Whether one of the network's aggregators serves the client's aggregator endpoint.
    fn is_served_by_aggregator_endpoint(&self, network: &MithrilNetworkConfiguration) -> bool {
        network.aggregators.iter().any(|aggregator| {
            Self::normalize_endpoint(&aggregator.url)
                == Self::normalize_endpoint(&self.aggregator_endpoint)
        })
    }

    /// Whether the network publishes the given genesis verification key, false when the key
    /// cannot be downloaded or parsed.
    async fn has_genesis_verification_key(
        &self,
        network: &MithrilNetworkConfiguration,
        genesis_verification_key: &GenesisEd25519VerificationKey,
    ) -> bool {
        let Some(verification_key) = network
            .genesis
            .as_ref()
            .and_then(|genesis| genesis.verification_key.as_ref())
        else {
            return false;
        };
        let Ok(genesis_verification_key_hex) = self.download(&verification_key.url).await else {
            return false;
        };
        let Ok(genesis_verifier) = GenesisVerifier::try_from_hex(&genesis_verification_key_hex)
        else {
            return false;
        };

        genesis_verifier.to_ed25519_verification_key().as_bytes()
            == genesis_verification_key.as_bytes()
    }

    /// Return the registry URL referenced by the network.
    fn registry_url_of(network: &MithrilNetworkConfiguration) -> Option<String> {
        network
            .circuit_verification_key_registry
            .as_ref()
            .map(|registry| registry.url.clone())
    }

    /// Download the resource at the given URL, retrying failed attempts up to
    /// [DOWNLOAD_MAX_ATTEMPTS] times.
    async fn download_with_retry(&self, url: &str) -> Result<String, StdError> {
        let mut last_error = anyhow!("Failed to download '{url}'");
        for attempt in 1..=DOWNLOAD_MAX_ATTEMPTS {
            match self.download(url).await {
                Ok(body) => return Ok(body),
                Err(error) => last_error = error,
            }
            if attempt < DOWNLOAD_MAX_ATTEMPTS {
                Self::wait_before_retry().await;
            }
        }

        Err(last_error.context(format!(
            "Failed to download '{url}' after {DOWNLOAD_MAX_ATTEMPTS} attempts"
        )))
    }

    /// Download the resource at the given URL, failing on a non success status.
    async fn download(&self, url: &str) -> Result<String, StdError> {
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
        if let Some(content_length) = response.content_length()
            && content_length > DOWNLOAD_MAX_BODY_SIZE_IN_BYTES
        {
            return Err(anyhow!(
                "Failed to download '{url}': response of {content_length} bytes exceeds the {DOWNLOAD_MAX_BODY_SIZE_IN_BYTES} bytes limit"
            ));
        }
        let body = response
            .text()
            .await
            .with_context(|| format!("Failed to read the response of '{url}'"))?;
        if body.len() as u64 > DOWNLOAD_MAX_BODY_SIZE_IN_BYTES {
            return Err(anyhow!(
                "Failed to download '{url}': response of {} bytes exceeds the {DOWNLOAD_MAX_BODY_SIZE_IN_BYTES} bytes limit",
                body.len()
            ));
        }

        Ok(body)
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

    /// Normalize an aggregator endpoint for comparison, ignoring surrounding whitespace and
    /// trailing slashes.
    fn normalize_endpoint(endpoint: &str) -> &str {
        endpoint.trim().trim_end_matches('/')
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
        CircuitVerificationKeyRegistry, GenesisEd25519SecretKey, GenesisEd25519Signer,
        GenesisSigner,
    };

    use super::*;

    const AGGREGATOR_ENDPOINT: &str = "https://aggregator.devnet.example/aggregator";

    fn genesis_signer() -> GenesisSigner {
        GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer())
    }

    fn genesis_verification_key_hex(genesis_signer: &GenesisSigner) -> String {
        genesis_signer.ed25519.verification_key().to_json_hex().unwrap()
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
                                "genesis": {{ "verification-key": {{ "url": "{genesis_url}" }} }},
                                "circuit-verification-key-registry": {{ "url": "{registry_url}" }}
                            }}
                        }}
                    ]
                }}
            }}"#,
            genesis_url = server.url("/genesis.vkey"),
            registry_url = server.url("/registry.json"),
        )
    }

    fn retriever_over(
        server: &MockServer,
        aggregator_endpoint: &str,
        genesis_signer: &GenesisSigner,
    ) -> RemoteCircuitVerificationKeyRegistryRetriever {
        RemoteCircuitVerificationKeyRegistryRetriever::new_with_networks_configuration_url(
            server.url("/networks.json"),
            aggregator_endpoint.to_string(),
            genesis_verification_key_hex(genesis_signer),
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

        let retrieved = retriever_over(&server, AGGREGATOR_ENDPOINT, &genesis_signer)
            .retrieve_signed_registry()
            .await
            .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn falls_back_to_the_network_matching_the_genesis_verification_key() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        let signed_registry = signed_registry(&genesis_signer);
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/genesis.vkey");
            then.status(200).body(genesis_verification_key_hex(&genesis_signer));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(200)
                .body(serde_json::to_string(&signed_registry).unwrap());
        });

        let retrieved = retriever_over(
            &server,
            "https://a-mirror-of-the-aggregator.example/aggregator",
            &genesis_signer,
        )
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

        let retrieved = retriever_over(&server, AGGREGATOR_ENDPOINT, &genesis_signer)
            .retrieve_signed_registry()
            .await
            .unwrap();

        assert_eq!(signed_registry, retrieved);
    }

    #[tokio::test]
    async fn fails_on_a_response_exceeding_the_body_size_limit() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(" ".repeat((DOWNLOAD_MAX_BODY_SIZE_IN_BYTES + 1) as usize));
        });

        let error = retriever_over(&server, AGGREGATOR_ENDPOINT, &genesis_signer)
            .retrieve_signed_registry()
            .await
            .expect_err("an oversized response must fail retrieval");

        assert!(
            format!("{error:?}").contains("exceeds"),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn fails_when_no_network_matches() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        let other_genesis_verification_key = GenesisEd25519Signer::from_secret_key(
            GenesisEd25519SecretKey::from_bytes(&[9u8; 32]).unwrap(),
        )
        .verification_key()
        .to_json_hex()
        .unwrap();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/genesis.vkey");
            then.status(200).body(genesis_verification_key_hex(&genesis_signer));
        });

        RemoteCircuitVerificationKeyRegistryRetriever::new_with_networks_configuration_url(
            server.url("/networks.json"),
            "https://another-network.example/aggregator".to_string(),
            other_genesis_verification_key,
        )
        .retrieve_signed_registry()
        .await
        .expect_err("an unmatched network must fail retrieval");
    }

    #[tokio::test]
    async fn retries_a_failed_download() {
        let server = MockServer::start();
        let genesis_signer = genesis_signer();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/networks.json");
            then.status(200)
                .body(networks_configuration_json(&server, AGGREGATOR_ENDPOINT));
        });
        let failing_registry = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/registry.json");
            then.status(500);
        });

        retriever_over(&server, AGGREGATOR_ENDPOINT, &genesis_signer)
            .retrieve_signed_registry()
            .await
            .expect_err("a persistently failing download must fail retrieval");

        assert_eq!(DOWNLOAD_MAX_ATTEMPTS, failing_registry.hits());
    }
}
