use anyhow::Context;
use config::{ConfigError, Map, Source, Value};
use mithril_cli_helper::{register_config_value, serde_deserialization};
use mithril_dmq::DmqNetwork;
use mithril_doc::{Documenter, DocumenterDefault, StructDoc};
use mithril_protocol_config::builder::AdapterConfig;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::{
    CardanoNetwork, StdResult,
    crypto_helper::ProtocolConfigurationMarkersSigner,
    entities::{BlockNumber, PartyId},
};
use mithril_era::{
    EraReaderAdapter,
    adapters::{EraReaderAdapterBuilder, EraReaderAdapterType},
};

#[derive(Debug, Clone, Deserialize)]
pub struct SignaturePublisherConfig {
    /// Number of retry attempts when publishing the signature
    pub retry_attempts: u8,

    /// Delay (in milliseconds) between two retry attempts when publishing the signature
    pub retry_delay_ms: u64,

    /// Delay (in milliseconds) between two separate publications done by the delayer signature publisher
    pub delayer_delay_ms: u64,

    /// Whether to skip the delayer when publishing the signature
    pub skip_delayer: bool,
}

/// Client configuration
#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct Configuration {
    /// Cardano CLI tool path
    #[example = "`cardano-cli`"]
    pub cardano_cli_path: PathBuf,

    /// Path of the socket opened by the Cardano node
    #[example = "`/ipc/node.socket`"]
    pub cardano_node_socket_path: PathBuf,

    /// Path of the socket opened by the DMQ node
    #[example = "`/ipc/dmq.socket`"]
    pub dmq_node_socket_path: Option<PathBuf>,

    /// Cardano network
    #[example = "`mainnet` or `preprod` or `devnet`"]
    pub network: String,

    /// Cardano network magic number
    /// useful for TestNet & DevNet
    #[example = "`1097911063` or `42`"]
    pub network_magic: Option<u64>,

    /// DMQ network magic number
    ///
    /// useful for TestNet & DevNet
    #[example = "`1097911063` or `42`"]
    pub dmq_network_magic: Option<u64>,

    /// Also known as `k`, it defines the number of blocks that are required for the blockchain to
    /// be considered final, preventing any further rollback `[default: 2160]`.
    pub network_security_parameter: BlockNumber,

    /// Blocks offset, from the tip of the chain, to exclude during the Cardano transactions preload,
    /// default to 2160.
    #[example = "`2160`"]
    pub preload_security_parameter: BlockNumber,

    /// Aggregator endpoint
    #[example = "`https://aggregator.pre-release-preview.api.mithril.network/aggregator`"]
    pub aggregator_endpoint: String,

    /// Relay endpoint
    pub relay_endpoint: Option<String>,

    /// Party Id
    ///
    /// Used only for testing when SPO pool id is not certified
    #[example = "`pool1pxaqe80sqpde7902er5kf6v0c7y0sv6d5g676766v2h829fvs3x`"]
    pub party_id: Option<PartyId>,

    /// Run Interval
    #[example = "`60000`"]
    pub run_interval: u64,

    /// Directory to snapshot
    pub db_directory: PathBuf,

    /// Directory to store signer data (Stakes, Protocol initializers, ...)
    #[example = "`./mithril-signer/stores`"]
    pub data_stores_directory: PathBuf,

    /// Store retention limit. If set to None, no limit will be set.
    pub store_retention_limit: Option<usize>,

    /// File path to the KES secret key of the pool
    pub kes_secret_key_path: Option<PathBuf>,

    /// File path to the operational certificate of the pool
    pub operational_certificate_path: Option<PathBuf>,

    /// Disable immutables digests cache.
    pub disable_digests_cache: bool,

    /// If set the existing immutables digests cache will be reset.
    ///
    /// Will be ignored if set in conjunction with `disable_digests_cache`.
    pub reset_digests_cache: bool,

    /// Era reader adapter type
    pub era_reader_adapter_type: EraReaderAdapterType,

    /// Era reader adapter parameters
    pub era_reader_adapter_params: Option<String>,

    /// Protocol configuration reader adapter configuration
    #[example = "\
    - cardano-chain:<br/>`{ \"type\": \"cardano-chain\", \"address\": \"test_address\",  \"verification_key\": \"136372c3138312c3138382c3130352c3233312c3135\" }`<br/>\
    "]
    #[serde(deserialize_with = "serde_deserialization::string_or_struct")]
    pub protocol_configuration_reader_adapter_config: AdapterConfig,

    /// Enable metrics server (Prometheus endpoint on /metrics).
    pub enable_metrics_server: bool,

    /// Metrics HTTP Server IP.
    pub metrics_server_ip: String,

    /// Metrics HTTP Server listening port.
    pub metrics_server_port: u16,

    /// If set no error is returned in case of unparsable block and an error log is written instead.
    ///
    /// Will be ignored on (pre)production networks.
    pub allow_unparsable_block: bool,

    /// If set, the signer will prune the cardano transactions in database older than the
    /// [network_security_parameter][Self::network_security_parameter] blocks after each import
    /// `[default: true]`.
    pub enable_transaction_pruning: bool,

    /// Chunk size for importing transactions, combined with transaction pruning it reduces the
    /// storage footprint of the signer by reducing the number of transactions stored on disk
    /// at any given time.
    pub transactions_import_block_chunk_size: BlockNumber,

    /// The maximum number of roll forwards during a poll of the block streamer when importing transactions.
    pub cardano_transactions_block_streamer_max_roll_forwards_per_poll: usize,

    /// Minimum duration between two consecutive block streamer polls in milliseconds `[default: 400]`.
    ///
    /// Set this value to `0` to disable throttling.
    pub cardano_transactions_block_streamer_throttling_interval: Option<u64>,

    /// Preloading refresh interval in seconds
    pub preloading_refresh_interval_in_seconds: u64,

    /// Signature publisher configuration
    #[example = "`{ retry_attempts: 3, retry_delay_ms: 2000, delayer_delay_ms: 10000, skip_delayer: false }`"]
    pub signature_publisher_config: SignaturePublisherConfig,
}

impl Configuration {
    /// Create a sample configuration mainly for tests
    #[doc(hidden)]
    pub fn new_sample<P: Into<PartyId>>(party_id: P) -> Self {
        let party_id: PartyId = party_id.into();
        let signer_temp_dir =
            mithril_common::test::crypto_helper::setup_temp_directory_for_signer(&party_id, false);
        Self {
            aggregator_endpoint: "http://0.0.0.0:8000".to_string(),
            relay_endpoint: None,
            cardano_cli_path: PathBuf::new(),
            cardano_node_socket_path: PathBuf::new(),
            dmq_node_socket_path: None,
            db_directory: PathBuf::new(),
            network: "devnet".to_string(),
            network_magic: Some(42),
            dmq_network_magic: Some(3141592),
            network_security_parameter: BlockNumber(2160),
            preload_security_parameter: BlockNumber(30),
            party_id: Some(party_id),
            run_interval: 5000,
            data_stores_directory: PathBuf::new(),
            store_retention_limit: None,
            kes_secret_key_path: signer_temp_dir.as_ref().map(|dir| dir.join("kes.sk")),
            operational_certificate_path: signer_temp_dir
                .as_ref()
                .map(|dir| dir.join("opcert.cert")),
            disable_digests_cache: false,
            reset_digests_cache: false,
            era_reader_adapter_type: EraReaderAdapterType::Bootstrap,
            era_reader_adapter_params: None,
            protocol_configuration_reader_adapter_config: AdapterConfig::CardanoChain {
                address: "address".to_string(),
                verification_key: ProtocolConfigurationMarkersSigner::create_deterministic_signer()
                    .verification_key(),
            },
            enable_metrics_server: true,
            metrics_server_ip: "0.0.0.0".to_string(),
            metrics_server_port: 9090,
            allow_unparsable_block: false,
            enable_transaction_pruning: false,
            transactions_import_block_chunk_size: BlockNumber(1000),
            cardano_transactions_block_streamer_max_roll_forwards_per_poll: 1000,
            cardano_transactions_block_streamer_throttling_interval: None,
            preloading_refresh_interval_in_seconds: 60,
            signature_publisher_config: SignaturePublisherConfig {
                retry_attempts: 1,
                retry_delay_ms: 1,
                delayer_delay_ms: 1,
                skip_delayer: false,
            },
        }
    }

    /// Return the Cardano network value from the configuration.
    pub fn get_network(&self) -> StdResult<CardanoNetwork> {
        CardanoNetwork::from_code(self.network.clone(), self.network_magic).with_context(|| {
            format!(
                "Could not read Network '{}' from configuration.",
                self.network
            )
        })
    }

    /// Return the DMQ network value from the configuration.
    pub fn get_dmq_network(&self) -> StdResult<DmqNetwork> {
        DmqNetwork::from_code(self.network.clone(), self.dmq_network_magic).with_context(|| {
            format!(
                "Could not read DMQ Network '{}' from configuration.",
                self.network
            )
        })
    }

    /// Create the SQL store directory if not exist and return the path of the
    /// SQLite3 file.
    pub fn get_sqlite_file(&self, sqlite_file_name: &str) -> StdResult<PathBuf> {
        let store_dir = &self.data_stores_directory;

        if !store_dir.exists() {
            std::fs::create_dir_all(store_dir).with_context(|| {
                format!(
                    "Could not create directory '{}' for Sqlite3 file.",
                    store_dir.display()
                )
            })?;
        }

        Ok(self.data_stores_directory.join(sqlite_file_name))
    }

    /// Create era reader adapter from configuration settings.
    pub fn build_era_reader_adapter(
        &self,
        chain_observer: Arc<dyn ChainObserver>,
    ) -> StdResult<Arc<dyn EraReaderAdapter>> {
        EraReaderAdapterBuilder::new(
            &self.era_reader_adapter_type,
            &self.era_reader_adapter_params,
        )
        .build(chain_observer)
        .with_context(|| {
            format!(
                "Configuration: can not create era reader for adapter '{}'.",
                self.era_reader_adapter_type
            )
        })
    }
}

/// Default configuration with all the default values for configurations.
#[derive(Debug, Clone, DocumenterDefault)]
pub struct DefaultConfiguration {
    /// Era reader adapter type
    pub era_reader_adapter_type: String,

    /// Metrics HTTP server IP.
    pub metrics_server_ip: String,

    /// Metrics HTTP server listening port.
    pub metrics_server_port: u16,

    /// Network security parameter
    pub network_security_parameter: u64,

    /// Transaction pruning toggle
    pub enable_transaction_pruning: bool,

    /// Preload security parameter
    pub preload_security_parameter: u64,

    /// Chunk size for importing transactions
    pub transactions_import_block_chunk_size: u64,

    /// The maximum number of roll forwards during a poll of the block streamer when importing transactions.
    pub cardano_transactions_block_streamer_max_roll_forwards_per_poll: u32,

    /// Minimum duration between two consecutive block streamer polls in milliseconds.
    pub cardano_transactions_block_streamer_throttling_interval: u64,
}

impl DefaultConfiguration {
    fn namespace() -> String {
        "default configuration".to_string()
    }
}

impl Default for DefaultConfiguration {
    fn default() -> Self {
        Self {
            era_reader_adapter_type: "bootstrap".to_string(),
            metrics_server_ip: "0.0.0.0".to_string(),
            metrics_server_port: 9090,
            network_security_parameter: 2160, // 2160 is the mainnet value
            preload_security_parameter: 2160,
            enable_transaction_pruning: true,
            transactions_import_block_chunk_size: 1500,
            cardano_transactions_block_streamer_max_roll_forwards_per_poll: 10000,
            cardano_transactions_block_streamer_throttling_interval: 300,
        }
    }
}

impl Source for DefaultConfiguration {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut result = Map::new();
        let namespace = DefaultConfiguration::namespace();
        let myself = self.clone();

        register_config_value!(result, &namespace, myself.era_reader_adapter_type);
        register_config_value!(result, &namespace, myself.metrics_server_ip);
        register_config_value!(result, &namespace, myself.metrics_server_port);
        register_config_value!(result, &namespace, myself.network_security_parameter);
        register_config_value!(result, &namespace, myself.preload_security_parameter);
        register_config_value!(result, &namespace, myself.enable_transaction_pruning);
        register_config_value!(
            result,
            &namespace,
            myself.transactions_import_block_chunk_size
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_transactions_block_streamer_max_roll_forwards_per_poll
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_transactions_block_streamer_throttling_interval
        );

        Ok(result)
    }
}
