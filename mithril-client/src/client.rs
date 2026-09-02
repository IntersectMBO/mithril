use std::collections::HashMap;
#[cfg(all(feature = "future_snark", not(target_family = "wasm")))]
use std::path::PathBuf;
#[cfg(not(target_family = "wasm"))]
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, anyhow};
#[cfg(any(feature = "fs", not(target_family = "wasm")))]
use chrono::Utc;
#[cfg(not(target_family = "wasm"))]
use rand::SeedableRng;
#[cfg(not(target_family = "wasm"))]
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use slog::{Logger, o, warn};

use mithril_aggregator_client::AggregatorHttpClient;
#[cfg(not(target_family = "wasm"))]
use mithril_aggregator_discovery::{
    AggregatorDiscoverer, AggregatorEndpoint, AggregatorEndpointWithCapabilities,
    CapableAggregatorDiscoverer, HttpConfigAggregatorDiscoverer, RequiredAggregatorCapabilities,
    ShuffleAggregatorDiscoverer,
};
#[cfg(feature = "future_snark")]
use mithril_common::crypto_helper::CircuitVerificationKeyRegistryRetriever;
#[cfg(all(feature = "future_snark", not(target_family = "wasm")))]
use mithril_common::crypto_helper::FileCircuitVerificationKeyRegistryRetriever;
use mithril_common::{MITHRIL_CLIENT_TYPE_HEADER, MITHRIL_ORIGIN_TAG_HEADER};

use crate::MithrilResult;
#[cfg(feature = "unstable")]
use crate::cardano_block_client::CardanoBlockClient;
use crate::cardano_database_client::CardanoDatabaseClient;
use crate::cardano_stake_distribution_client::CardanoStakeDistributionClient;
use crate::cardano_transaction_client::CardanoTransactionClient;
#[cfg(feature = "unstable")]
use crate::cardano_transaction_v2_client::CardanoTransactionV2Client;
#[cfg(feature = "unstable")]
use crate::certificate_client::CertificateVerifierCache;
use crate::certificate_client::{
    CertificateClient, CertificateVerifier, MithrilCertificateVerifier,
};
#[cfg(feature = "future_snark")]
use crate::circuit_key_registry::RemoteCircuitVerificationKeyRegistryRetriever;
#[cfg(not(target_family = "wasm"))]
use crate::common::MithrilNetwork;
use crate::era::{EraFetcher, MithrilEraClient};
use crate::feedback::{FeedbackReceiver, FeedbackSender};
#[cfg(feature = "fs")]
use crate::file_downloader::{
    FileDownloadRetryPolicy, FileDownloader, HttpFileDownloader, RetryDownloader,
};
use crate::mithril_stake_distribution_client::MithrilStakeDistributionClient;
#[cfg(feature = "fs")]
use crate::utils::AncillaryVerifier;
#[cfg(feature = "fs")]
use crate::utils::TimestampTempDirectoryProvider;

const DEFAULT_CLIENT_TYPE: &str = "LIBRARY";

#[cfg(target_family = "wasm")]
const fn one_week_in_seconds() -> u32 {
    604800
}

/// The type of discovery to use to find the aggregator to connect to.
pub enum AggregatorDiscoveryType {
    /// Use a specific URL to connect to the aggregator.
    Url(String),
    /// Automatically discover the aggregator.
    #[cfg(not(target_family = "wasm"))]
    Automatic(MithrilNetwork),
}

#[cfg(not(target_family = "wasm"))]
impl FromStr for AggregatorDiscoveryType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(network) = s.strip_prefix("auto:") {
            Ok(AggregatorDiscoveryType::Automatic(MithrilNetwork::new(
                network.to_string(),
            )))
        } else {
            Ok(AggregatorDiscoveryType::Url(s.to_string()))
        }
    }
}

/// The genesis verification key.
pub enum GenesisVerificationKey {
    /// The verification key is provided as a JSON Hex-encoded string.
    JsonHex(String),
}

/// Options that can be used to configure the client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientOptions {
    /// HTTP headers to include in the client requests.
    pub http_headers: Option<HashMap<String, String>>,

    /// Tag to retrieve the origin of the client requests.
    #[cfg(target_family = "wasm")]
    #[cfg_attr(target_family = "wasm", serde(default))]
    pub origin_tag: Option<String>,

    /// Whether to enable unstable features in the WASM client.
    #[cfg(target_family = "wasm")]
    #[cfg_attr(target_family = "wasm", serde(default))]
    pub unstable: bool,

    /// Whether to enable certificate chain verification caching in the WASM client.
    ///
    /// `unstable` must be set to `true` for this option to have any effect.
    ///
    /// DANGER: This feature is highly experimental and insecure, and it must not be used in production
    #[cfg(target_family = "wasm")]
    #[cfg_attr(target_family = "wasm", serde(default))]
    pub enable_certificate_chain_verification_cache: bool,

    /// Duration in seconds of certificate chain verification cache in the WASM client.
    ///
    /// Default to one week (604800 seconds).
    ///
    /// `enable_certificate_chain_verification_cache` and `unstable` must both be set to `true`
    /// for this option to have any effect.
    #[cfg(target_family = "wasm")]
    #[cfg_attr(target_family = "wasm", serde(default = "one_week_in_seconds"))]
    pub certificate_chain_verification_cache_duration_in_seconds: u32,
}

impl ClientOptions {
    /// Instantiate a new [ClientOptions].
    pub fn new(http_headers: Option<HashMap<String, String>>) -> Self {
        Self {
            http_headers,
            #[cfg(target_family = "wasm")]
            origin_tag: None,
            #[cfg(target_family = "wasm")]
            unstable: false,
            #[cfg(target_family = "wasm")]
            enable_certificate_chain_verification_cache: false,
            #[cfg(target_family = "wasm")]
            certificate_chain_verification_cache_duration_in_seconds: one_week_in_seconds(),
        }
    }

    /// Enable unstable features in the WASM client.
    #[cfg(target_family = "wasm")]
    pub fn with_unstable_features(self, unstable: bool) -> Self {
        Self { unstable, ..self }
    }
}

/// Structure that aggregates the available clients for each of the Mithril types of certified data.
///
/// Use the [ClientBuilder] to instantiate it easily.
#[derive(Clone)]
pub struct Client {
    certificate_client: Arc<CertificateClient>,
    mithril_stake_distribution_client: Arc<MithrilStakeDistributionClient>,
    cardano_database_client: Arc<CardanoDatabaseClient>,
    cardano_transaction_client: Arc<CardanoTransactionClient>,
    #[cfg(feature = "unstable")]
    cardano_transaction_v2_client: Arc<CardanoTransactionV2Client>,
    #[cfg(feature = "unstable")]
    cardano_block_client: Arc<CardanoBlockClient>,
    cardano_stake_distribution_client: Arc<CardanoStakeDistributionClient>,
    mithril_era_client: Arc<MithrilEraClient>,
}

impl Client {
    /// Get the client that fetches and verifies Mithril certificates.
    pub fn certificate(&self) -> Arc<CertificateClient> {
        self.certificate_client.clone()
    }

    /// Get the client that fetches Mithril stake distributions.
    pub fn mithril_stake_distribution(&self) -> Arc<MithrilStakeDistributionClient> {
        self.mithril_stake_distribution_client.clone()
    }

    /// Get the client that fetches and downloads Cardano database snapshots.
    pub fn cardano_database_v2(&self) -> Arc<CardanoDatabaseClient> {
        self.cardano_database_client.clone()
    }

    /// Get the client that fetches and verifies Mithril Cardano transaction proof.
    pub fn cardano_transaction(&self) -> Arc<CardanoTransactionClient> {
        self.cardano_transaction_client.clone()
    }

    cfg_unstable! {
        /// Get the client that fetches and verifies Mithril Cardano transaction v2 proof.
        pub fn cardano_transaction_v2(&self) -> Arc<CardanoTransactionV2Client> {
            self.cardano_transaction_v2_client.clone()
        }

        /// Get the client that fetches and verifies Mithril Cardano block proof.
        pub fn cardano_block(&self) -> Arc<CardanoBlockClient> {
            self.cardano_block_client.clone()
        }
    }
    /// Get the client that fetches Cardano stake distributions.
    pub fn cardano_stake_distribution(&self) -> Arc<CardanoStakeDistributionClient> {
        self.cardano_stake_distribution_client.clone()
    }

    /// Get the client that fetches the current Mithril era.
    pub fn mithril_era_client(&self) -> Arc<MithrilEraClient> {
        self.mithril_era_client.clone()
    }
}

/// Builder that can be used to create a [Client] easily or with custom dependencies.
pub struct ClientBuilder {
    aggregator_discovery: AggregatorDiscoveryType,
    #[cfg(not(target_family = "wasm"))]
    aggregator_capabilities: Option<RequiredAggregatorCapabilities>,
    #[cfg(not(target_family = "wasm"))]
    aggregator_discoverer: Option<Arc<dyn AggregatorDiscoverer<AggregatorEndpoint>>>,
    genesis_verification_key: Option<GenesisVerificationKey>,
    origin_tag: Option<String>,
    client_type: Option<String>,
    #[cfg(feature = "fs")]
    ancillary_verification_key: Option<String>,
    certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
    #[cfg(feature = "fs")]
    http_file_downloader: Option<Arc<dyn FileDownloader>>,
    #[cfg(feature = "unstable")]
    certificate_verifier_cache: Option<Arc<dyn CertificateVerifierCache>>,
    #[cfg(feature = "future_snark")]
    circuit_key_registry_retriever: Option<Arc<dyn CircuitVerificationKeyRegistryRetriever>>,
    era_fetcher: Option<Arc<dyn EraFetcher>>,
    logger: Option<Logger>,
    feedback_receivers: Vec<Arc<dyn FeedbackReceiver>>,
    options: ClientOptions,
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder` that fetches data from the aggregator at the given
    /// endpoint and with the given genesis verification key.
    #[deprecated(
        since = "0.12.36",
        note = "Use `new` method instead and set the genesis verification key with `set_genesis_verification_key`"
    )]
    pub fn aggregator(endpoint: &str, genesis_verification_key: &str) -> ClientBuilder {
        Self::new(AggregatorDiscoveryType::Url(endpoint.to_string())).set_genesis_verification_key(
            GenesisVerificationKey::JsonHex(genesis_verification_key.to_string()),
        )
    }

    /// Constructs a new `ClientBuilder` that automatically discovers the aggregator for the given
    /// Mithril network and with the given genesis verification key.
    #[cfg(not(target_family = "wasm"))]
    pub fn automatic(network: &str, genesis_verification_key: &str) -> ClientBuilder {
        Self::new(AggregatorDiscoveryType::Automatic(MithrilNetwork::new(
            network.to_string(),
        )))
        .set_genesis_verification_key(GenesisVerificationKey::JsonHex(
            genesis_verification_key.to_string(),
        ))
    }

    /// Constructs a new `ClientBuilder` without any dependency set.
    pub fn new(aggregator_discovery: AggregatorDiscoveryType) -> ClientBuilder {
        Self {
            aggregator_discovery,
            #[cfg(not(target_family = "wasm"))]
            aggregator_capabilities: None,
            #[cfg(not(target_family = "wasm"))]
            aggregator_discoverer: None,
            genesis_verification_key: None,
            origin_tag: None,
            client_type: None,
            #[cfg(feature = "fs")]
            ancillary_verification_key: None,
            certificate_verifier: None,
            #[cfg(feature = "fs")]
            http_file_downloader: None,
            #[cfg(feature = "unstable")]
            certificate_verifier_cache: None,
            #[cfg(feature = "future_snark")]
            circuit_key_registry_retriever: None,
            era_fetcher: None,
            logger: None,
            feedback_receivers: vec![],
            options: ClientOptions::default(),
        }
    }

    /// Sets the genesis verification key to use when verifying certificates.
    pub fn set_genesis_verification_key(
        mut self,
        genesis_verification_key: GenesisVerificationKey,
    ) -> ClientBuilder {
        self.genesis_verification_key = Some(genesis_verification_key);

        self
    }

    /// Sets the aggregator capabilities expected to be matched by the aggregator with which the client will interact.
    #[cfg(not(target_family = "wasm"))]
    pub fn with_capabilities(
        mut self,
        capabilities: RequiredAggregatorCapabilities,
    ) -> ClientBuilder {
        self.aggregator_capabilities = Some(capabilities);

        self
    }

    /// Sets the aggregator discoverer to use to find the aggregator endpoint when in automatic discovery.
    #[cfg(not(target_family = "wasm"))]
    pub fn with_aggregator_discoverer(
        mut self,
        discoverer: Arc<dyn AggregatorDiscoverer<AggregatorEndpoint>>,
    ) -> ClientBuilder {
        self.aggregator_discoverer = Some(discoverer);

        self
    }

    /// Returns a `Client` that uses the dependencies provided to this `ClientBuilder`.
    ///
    /// The builder will try to create the missing dependencies using default implementations
    /// if possible.
    pub fn build(self) -> MithrilResult<Client> {
        let logger = self
            .logger
            .clone()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));

        let genesis_verification_key = match self.genesis_verification_key {
            Some(GenesisVerificationKey::JsonHex(ref key)) => key,
            None => {
                return Err(anyhow!(
                    "The genesis verification key must be provided to build the client with the 'set_genesis_verification_key' function"
                ));
            }
        };

        let feedback_sender = FeedbackSender::new(&self.feedback_receivers);

        let aggregator_endpoint = self.resolve_aggregator_endpoint()?;
        let aggregator_client =
            Arc::new(self.build_aggregator_client(aggregator_endpoint.clone(), logger.clone())?);

        let mithril_era_client = match self.era_fetcher {
            None => Arc::new(MithrilEraClient::new(aggregator_client.clone())),
            Some(era_fetcher) => Arc::new(MithrilEraClient::new(era_fetcher)),
        };

        #[cfg(feature = "future_snark")]
        let circuit_key_registry_retriever = match self.circuit_key_registry_retriever {
            Some(circuit_key_registry_retriever) => circuit_key_registry_retriever,
            None => Self::default_circuit_key_registry_retriever(
                &aggregator_endpoint,
                genesis_verification_key,
                &logger,
            ),
        };
        let certificate_verifier = match self.certificate_verifier {
            None => Arc::new(
                MithrilCertificateVerifier::new(
                    aggregator_client.clone(),
                    genesis_verification_key,
                    feedback_sender.clone(),
                    #[cfg(feature = "unstable")]
                    self.certificate_verifier_cache,
                    #[cfg(feature = "future_snark")]
                    Some(circuit_key_registry_retriever),
                    logger.clone(),
                )
                .with_context(|| "Building certificate verifier failed")?,
            ),
            Some(verifier) => verifier,
        };
        let certificate_client = Arc::new(CertificateClient::new(
            aggregator_client.clone(),
            certificate_verifier,
            logger.clone(),
        ));

        let mithril_stake_distribution_client = Arc::new(MithrilStakeDistributionClient::new(
            aggregator_client.clone(),
        ));

        #[cfg(feature = "fs")]
        let http_file_downloader = match self.http_file_downloader {
            None => Arc::new(RetryDownloader::new(
                Arc::new(
                    HttpFileDownloader::new(feedback_sender.clone(), logger.clone())
                        .with_context(|| "Building http file downloader failed")?,
                ),
                FileDownloadRetryPolicy::default(),
            )),
            Some(http_file_downloader) => http_file_downloader,
        };

        #[cfg(feature = "fs")]
        let ancillary_verifier = match self.ancillary_verification_key {
            None => None,
            Some(verification_key) => Some(Arc::new(AncillaryVerifier::new(
                verification_key
                    .try_into()
                    .with_context(|| "Building ancillary verifier failed")?,
            ))),
        };

        let cardano_database_client = Arc::new(CardanoDatabaseClient::new(
            aggregator_client.clone(),
            #[cfg(feature = "fs")]
            http_file_downloader,
            #[cfg(feature = "fs")]
            ancillary_verifier,
            #[cfg(feature = "fs")]
            feedback_sender,
            #[cfg(feature = "fs")]
            Arc::new(TimestampTempDirectoryProvider::new(&format!(
                "{}",
                Utc::now().timestamp_micros()
            ))),
            #[cfg(feature = "fs")]
            logger,
        ));

        let cardano_transaction_client =
            Arc::new(CardanoTransactionClient::new(aggregator_client.clone()));

        #[cfg(feature = "unstable")]
        let cardano_transaction_v2_client =
            Arc::new(CardanoTransactionV2Client::new(aggregator_client.clone()));

        #[cfg(feature = "unstable")]
        let cardano_block_client = Arc::new(CardanoBlockClient::new(aggregator_client.clone()));

        let cardano_stake_distribution_client =
            Arc::new(CardanoStakeDistributionClient::new(aggregator_client));

        Ok(Client {
            certificate_client,
            mithril_stake_distribution_client,
            cardano_database_client,
            cardano_transaction_client,
            #[cfg(feature = "unstable")]
            cardano_transaction_v2_client,
            #[cfg(feature = "unstable")]
            cardano_block_client,
            cardano_stake_distribution_client,
            mithril_era_client,
        })
    }

    /// Discover available aggregator endpoints for the given Mithril network and required capabilities.
    #[cfg(not(target_family = "wasm"))]
    pub fn discover_aggregator(
        &self,
        network: &MithrilNetwork,
    ) -> MithrilResult<impl Iterator<Item = AggregatorEndpointWithCapabilities>> {
        let discoverer = self
            .aggregator_discoverer
            .clone()
            .unwrap_or_else(|| Self::default_aggregator_discoverer());
        let discoverer = if let Some(capabilities) = &self.aggregator_capabilities {
            Arc::new(CapableAggregatorDiscoverer::new(
                capabilities.to_owned(),
                discoverer.clone(),
            )) as Arc<dyn AggregatorDiscoverer<AggregatorEndpointWithCapabilities>>
        } else {
            Arc::new(CapableAggregatorDiscoverer::new(
                RequiredAggregatorCapabilities::All,
                discoverer.clone(),
            )) as Arc<dyn AggregatorDiscoverer<AggregatorEndpointWithCapabilities>>
        };

        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                discoverer
                    .get_available_aggregators(network.to_owned())
                    .await
                    .with_context(|| "Discovering aggregator endpoint failed")
            })
        })
    }

    /// Default aggregator discoverer to use to find the aggregator endpoint when in automatic discovery.
    #[cfg(not(target_family = "wasm"))]
    fn default_aggregator_discoverer() -> Arc<dyn AggregatorDiscoverer<AggregatorEndpoint>> {
        Arc::new(ShuffleAggregatorDiscoverer::new(
            Arc::new(HttpConfigAggregatorDiscoverer::default()),
            {
                let mut seed = [0u8; 32];
                let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
                seed[..8].copy_from_slice(&timestamp.to_le_bytes());

                StdRng::from_seed(seed)
            },
        ))
    }

    /// Resolve the aggregator endpoint from the configured URL or through discovery.
    fn resolve_aggregator_endpoint(&self) -> MithrilResult<String> {
        match self.aggregator_discovery {
            AggregatorDiscoveryType::Url(ref url) => Ok(url.clone()),
            #[cfg(not(target_family = "wasm"))]
            AggregatorDiscoveryType::Automatic(ref network) => Ok(self
                .discover_aggregator(network)?
                .next()
                .with_context(|| "No aggregator was available through discovery")?
                .into()),
        }
    }

    fn build_aggregator_client(
        &self,
        aggregator_endpoint: String,
        logger: Logger,
    ) -> MithrilResult<AggregatorHttpClient> {
        let headers = self.compute_http_headers();

        AggregatorHttpClient::builder(aggregator_endpoint)
            .with_logger(logger)
            .with_headers(headers)
            .build()
    }

    /// Build the default registry retriever: the signed registry of the client's network resolved
    /// from the published networks configuration, or read from the file at the path set in the
    /// `MITHRIL_CIRCUIT_VERIFICATION_KEY_REGISTRY_FILE` environment variable when defined (a
    /// development and test facility).
    #[cfg(feature = "future_snark")]
    fn default_circuit_key_registry_retriever(
        aggregator_endpoint: &str,
        genesis_verification_key: &str,
        logger: &Logger,
    ) -> Arc<dyn CircuitVerificationKeyRegistryRetriever> {
        #[cfg(target_family = "wasm")]
        let _ = logger;
        #[cfg(not(target_family = "wasm"))]
        if let Ok(registry_file_path) =
            std::env::var("MITHRIL_CIRCUIT_VERIFICATION_KEY_REGISTRY_FILE")
        {
            warn!(
                logger,
                "The circuit verification key registry is read from a local file instead of the published networks configuration (MITHRIL_CIRCUIT_VERIFICATION_KEY_REGISTRY_FILE is set, a development and test facility)";
                "registry_file_path" => &registry_file_path,
            );
            return Arc::new(FileCircuitVerificationKeyRegistryRetriever::new(
                PathBuf::from(registry_file_path),
            ));
        }

        Arc::new(RemoteCircuitVerificationKeyRegistryRetriever::new(
            aggregator_endpoint.to_string(),
            genesis_verification_key.to_string(),
        ))
    }

    fn compute_http_headers(&self) -> HashMap<String, String> {
        let mut headers = self.options.http_headers.clone().unwrap_or_default();
        if let Some(origin_tag) = self.origin_tag.clone() {
            headers.insert(MITHRIL_ORIGIN_TAG_HEADER.to_string(), origin_tag);
        }
        if let Some(client_type) = self.client_type.clone() {
            headers.insert(MITHRIL_CLIENT_TYPE_HEADER.to_string(), client_type);
        } else if !headers.contains_key(MITHRIL_CLIENT_TYPE_HEADER) {
            headers.insert(
                MITHRIL_CLIENT_TYPE_HEADER.to_string(),
                DEFAULT_CLIENT_TYPE.to_string(),
            );
        }

        headers
    }

    /// Sets the [EraFetcher] that will be used by the client to retrieve the current Mithril era.
    pub fn with_era_fetcher(mut self, era_fetcher: Arc<dyn EraFetcher>) -> ClientBuilder {
        self.era_fetcher = Some(era_fetcher);
        self
    }

    /// Set the [CertificateVerifier] that will be used to validate certificates.
    pub fn with_certificate_verifier(
        mut self,
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> ClientBuilder {
        self.certificate_verifier = Some(certificate_verifier);
        self
    }

    cfg_unstable! {
        /// Set the [CertificateVerifierCache] that will be used to cache certificate validation results.
        ///
        /// Passing a `None` value will disable the cache if any was previously set.
        pub fn with_certificate_verifier_cache(
            mut self,
            certificate_verifier_cache: Option<Arc<dyn CertificateVerifierCache>>,
        ) -> ClientBuilder {
            self.certificate_verifier_cache = certificate_verifier_cache;
            self
        }
    }

    /// Set a custom registry retriever for the circuit verification key registry check on
    /// certificate verification, replacing the default one resolving the registry of the
    /// client's network from the published networks configuration.
    #[cfg(feature = "future_snark")]
    pub fn with_circuit_verification_key_registry_retriever(
        mut self,
        circuit_key_registry_retriever: Arc<dyn CircuitVerificationKeyRegistryRetriever>,
    ) -> ClientBuilder {
        self.circuit_key_registry_retriever = Some(circuit_key_registry_retriever);
        self
    }

    cfg_fs! {
        /// Set the [FileDownloader] that will be used to download artifacts with HTTP.
        pub fn with_http_file_downloader(
            mut self,
            http_file_downloader: Arc<dyn FileDownloader>,
        ) -> ClientBuilder {
            self.http_file_downloader = Some(http_file_downloader);
            self
        }

        /// Set the ancillary verification key to use when verifying the downloaded ancillary files.
        pub fn set_ancillary_verification_key<T: Into<Option<String>>>(
            mut self,
            ancillary_verification_key: T,
        ) -> ClientBuilder {
            self.ancillary_verification_key = ancillary_verification_key.into();
            self
        }
    }

    /// Set the [Logger] to use.
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Set the origin tag.
    pub fn with_origin_tag(mut self, origin_tag: Option<String>) -> Self {
        self.origin_tag = origin_tag;
        self
    }

    /// Set the client type.
    pub fn with_client_type(mut self, client_type: Option<String>) -> Self {
        self.client_type = client_type;
        self
    }

    /// Sets the options to be used by the client.
    pub fn with_options(mut self, options: ClientOptions) -> Self {
        self.options = options;
        self
    }

    /// Add a [feedback receiver][FeedbackReceiver] to receive [events][crate::feedback::MithrilEvent]
    /// for tasks that can have a long duration (ie: snapshot download or a long certificate chain
    /// validation).
    pub fn add_feedback_receiver(mut self, receiver: Arc<dyn FeedbackReceiver>) -> Self {
        self.feedback_receivers.push(receiver);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_headers() -> HashMap<String, String> {
        HashMap::from([(
            MITHRIL_CLIENT_TYPE_HEADER.to_string(),
            DEFAULT_CLIENT_TYPE.to_string(),
        )])
    }

    #[tokio::test]
    async fn compute_http_headers_returns_options_http_headers() {
        let http_headers = default_headers();
        let client_builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            });

        let computed_headers = client_builder.compute_http_headers();

        assert_eq!(computed_headers, http_headers);
    }

    #[tokio::test]
    async fn compute_http_headers_with_origin_tag_returns_options_http_headers_with_origin_tag() {
        let http_headers = default_headers();
        let client_builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            })
            .with_origin_tag(Some("CLIENT_TAG".to_string()));
        let mut expected_headers = http_headers.clone();
        expected_headers.insert(
            MITHRIL_ORIGIN_TAG_HEADER.to_string(),
            "CLIENT_TAG".to_string(),
        );

        let computed_headers = client_builder.compute_http_headers();
        assert_eq!(computed_headers, expected_headers);
    }

    #[tokio::test]
    async fn test_with_origin_tag_not_overwrite_other_client_options_attributes() {
        let builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions { http_headers: None })
            .with_origin_tag(Some("TEST".to_string()));
        assert_eq!(None, builder.options.http_headers);
        assert_eq!(Some("TEST".to_string()), builder.origin_tag);

        let http_headers = HashMap::from([("Key".to_string(), "Value".to_string())]);
        let builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            })
            .with_origin_tag(Some("TEST".to_string()));
        assert_eq!(Some(http_headers), builder.options.http_headers);
        assert_eq!(Some("TEST".to_string()), builder.origin_tag);
    }

    #[tokio::test]
    async fn test_with_origin_tag_can_be_unset() {
        let http_headers = HashMap::from([("Key".to_string(), "Value".to_string())]);
        let client_options = ClientOptions {
            http_headers: Some(http_headers.clone()),
        };
        let builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(client_options)
            .with_origin_tag(None);

        assert_eq!(Some(http_headers), builder.options.http_headers);
        assert_eq!(None, builder.origin_tag);
    }

    #[tokio::test]
    async fn compute_http_headers_with_client_type_returns_options_http_headers_with_client_type() {
        let http_headers = HashMap::from([("Key".to_string(), "Value".to_string())]);
        let client_builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            })
            .with_client_type(Some("CLIENT_TYPE".to_string()));

        let computed_headers = client_builder.compute_http_headers();

        assert_eq!(
            computed_headers,
            HashMap::from([
                ("Key".to_string(), "Value".to_string()),
                (
                    MITHRIL_CLIENT_TYPE_HEADER.to_string(),
                    "CLIENT_TYPE".to_string()
                )
            ])
        );
    }

    #[tokio::test]
    async fn compute_http_headers_with_options_containing_client_type_returns_client_type() {
        let http_headers = HashMap::from([(
            MITHRIL_CLIENT_TYPE_HEADER.to_string(),
            "client type from options".to_string(),
        )]);
        let client_builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            });

        let computed_headers = client_builder.compute_http_headers();

        assert_eq!(computed_headers, http_headers);
    }

    #[tokio::test]
    async fn test_with_client_type_not_overwrite_other_client_options_attributes() {
        let builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions { http_headers: None })
            .with_client_type(Some("TEST".to_string()));
        assert_eq!(None, builder.options.http_headers);
        assert_eq!(Some("TEST".to_string()), builder.client_type);

        let http_headers = HashMap::from([("Key".to_string(), "Value".to_string())]);
        let builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            })
            .with_client_type(Some("TEST".to_string()));
        assert_eq!(Some(http_headers), builder.options.http_headers);
        assert_eq!(Some("TEST".to_string()), builder.client_type);
    }

    #[tokio::test]
    async fn test_given_a_none_client_type_compute_http_headers_will_set_client_type_to_default_value()
     {
        let builder_without_client_type =
            ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()));
        let computed_headers = builder_without_client_type.compute_http_headers();

        assert_eq!(
            computed_headers,
            HashMap::from([(
                MITHRIL_CLIENT_TYPE_HEADER.to_string(),
                DEFAULT_CLIENT_TYPE.to_string()
            )])
        );

        let builder_with_none_client_type =
            ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string())).with_client_type(None);
        let computed_headers = builder_with_none_client_type.compute_http_headers();

        assert_eq!(
            computed_headers,
            HashMap::from([(
                MITHRIL_CLIENT_TYPE_HEADER.to_string(),
                DEFAULT_CLIENT_TYPE.to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_compute_http_headers_will_compute_client_type_header_from_struct_attribute_over_options()
     {
        let http_headers = HashMap::from([(
            MITHRIL_CLIENT_TYPE_HEADER.to_string(),
            "client type from options".to_string(),
        )]);
        let client_builder = ClientBuilder::new(AggregatorDiscoveryType::Url("".to_string()))
            .with_options(ClientOptions {
                http_headers: Some(http_headers.clone()),
            })
            .with_client_type(Some("client type".to_string()));

        let computed_headers = client_builder.compute_http_headers();

        assert_eq!(
            computed_headers,
            HashMap::from([(
                MITHRIL_CLIENT_TYPE_HEADER.to_string(),
                "client type".to_string()
            )])
        );
    }
}
