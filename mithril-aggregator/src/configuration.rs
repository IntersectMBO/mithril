use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use config::{ConfigError, Map, Source, Value, ValueKind};
use mithril_protocol_config::adapters::ProtocolConfigurationReaderAdapterType;
use semver::Version;
use serde::Deserialize;

use mithril_cardano_node_chain::chain_observer::ChainObserverType;
use mithril_cli_helper::{register_config_value, serde_deserialization};
use mithril_common::crypto_helper::{GenesisEd25519Signer, ManifestSigner};
use mithril_common::entities::{
    BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
    CardanoTransactionsSigningConfig, CompressionAlgorithm, ConfigSecret,
    HexEncodedGenesisVerificationKey, HexEncodedKey, ProtocolParameters, SignedEntityConfig,
    SignedEntityTypeDiscriminants,
};
use mithril_common::{AggregateSignatureType, CardanoNetwork, StdResult};
use mithril_dmq::DmqNetwork;
use mithril_doc::{Documenter, DocumenterDefault, StructDoc};
use mithril_era::adapters::EraReaderAdapterType;

use crate::entities::AggregatorEpochSettings;
use crate::http_server::SERVER_BASE_PATH;
use crate::services::ancillary_signer::GcpCryptoKeyVersionResourceName;
use crate::tools::DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR;
use crate::tools::url_sanitizer::SanitizedUrlWithTrailingSlash;

/// Different kinds of execution environments
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum ExecutionEnvironment {
    /// Test environment, maximum logging, memory stores etc.
    Test,

    /// Production environment, minimum logging, maximum performances,
    /// persistent stores etc.
    Production,
}

impl FromStr for ExecutionEnvironment {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "production" => Ok(Self::Production),
            "test" => Ok(Self::Test),
            _ => Err(ConfigError::Message(format!(
                "Unknown execution environment {s}"
            ))),
        }
    }
}

/// This trait defines the configuration interface for the aggregator.
///
/// By default, each function panics if not overridden, forcing concrete configuration
/// implementations to explicitly provide the necessary values.
pub trait ConfigurationSource {
    /// What kind of runtime environment the configuration is meant to.
    fn environment(&self) -> ExecutionEnvironment;

    /// Cardano CLI tool path
    fn cardano_cli_path(&self) -> PathBuf {
        panic!("cardano_cli_path is not implemented.");
    }

    /// Path of the socket opened by the Cardano node
    fn cardano_node_socket_path(&self) -> PathBuf {
        panic!("cardano_node_socket_path is not implemented.");
    }

    /// Path of the socket opened by the DMQ node
    fn dmq_node_socket_path(&self) -> Option<PathBuf> {
        panic!("dmq_node_socket_path is not implemented.");
    }

    /// Cardano node version.
    ///
    /// **NOTE**: This cannot be verified for now (see [this
    /// issue](https://github.com/input-output-hk/cardano-cli/issues/224)). This
    /// is why it has to be manually given to the Aggregator
    fn cardano_node_version(&self) -> String {
        panic!("cardano_node_version is not implemented.");
    }

    /// Cardano network
    fn network(&self) -> String {
        panic!("network is not implemented.");
    }

    /// Cardano Network Magic number
    ///
    /// useful for TestNet & DevNet
    fn network_magic(&self) -> Option<u64> {
        panic!("network_magic is not implemented.");
    }

    /// DMQ Network Magic number
    ///
    /// useful for TestNet & DevNet
    fn dmq_network_magic(&self) -> Option<u64> {
        panic!("dmq_network_magic is not implemented.");
    }

    /// Cardano chain observer type
    fn chain_observer_type(&self) -> ChainObserverType {
        panic!("chain_observer_type is not implemented.");
    }

    /// Protocol parameters
    fn protocol_parameters(&self) -> Option<ProtocolParameters> {
        panic!("protocol_parameters is not implemented.");
    }

    /// Type of snapshot uploader to use
    fn snapshot_uploader_type(&self) -> SnapshotUploaderType {
        panic!("snapshot_uploader_type is not implemented.");
    }

    /// Bucket name where the snapshots are stored if snapshot_uploader_type is Gcp
    fn snapshot_bucket_name(&self) -> Option<String> {
        panic!("snapshot_bucket_name is not implemented.");
    }

    /// Use CDN domain to construct snapshot urls if snapshot_uploader_type is Gcp
    fn snapshot_use_cdn_domain(&self) -> bool {
        panic!("snapshot_use_cdn_domain is not implemented.");
    }

    /// Server listening IP
    fn server_ip(&self) -> String {
        panic!("server_ip is not implemented.");
    }

    /// Server listening port
    fn server_port(&self) -> u16 {
        panic!("server_port is not implemented.");
    }

    /// Server URL that can be accessed from the outside
    fn public_server_url(&self) -> Option<String> {
        panic!("public_server_url is not implemented.");
    }

    /// Run Interval is the interval between two runtime cycles in ms
    fn run_interval(&self) -> u64 {
        panic!("run_interval is not implemented.");
    }

    /// Directory of the Cardano node store.
    fn db_directory(&self) -> PathBuf {
        panic!("db_directory is not implemented.");
    }

    /// Directory to store snapshot
    fn snapshot_directory(&self) -> PathBuf {
        panic!("snapshot_directory is not implemented.");
    }

    /// Directory to store aggregator databases
    fn data_stores_directory(&self) -> PathBuf {
        panic!("data_stores_directory is not implemented.");
    }

    /// Genesis verification key
    fn genesis_verification_key(&self) -> HexEncodedGenesisVerificationKey {
        panic!("genesis_verification_key is not implemented.");
    }

    /// Should the immutable cache be reset or not
    fn reset_digests_cache(&self) -> bool {
        panic!("reset_digests_cache is not implemented.");
    }

    /// Use the digest caching strategy
    fn disable_digests_cache(&self) -> bool {
        panic!("disable_digests_cache is not implemented.");
    }

    /// Max number of records in stores.
    /// When new records are added, oldest records are automatically deleted so
    /// there can always be at max the number of records specified by this
    /// setting.
    fn store_retention_limit(&self) -> Option<usize> {
        panic!("store_retention_limit is not implemented.");
    }

    /// Era reader adapter type
    fn era_reader_adapter_type(&self) -> EraReaderAdapterType {
        panic!("era_reader_adapter_type is not implemented.");
    }

    /// Era reader adapter parameters
    fn era_reader_adapter_params(&self) -> Option<String> {
        panic!("era_reader_adapter_params is not implemented.");
    }

    /// Protocol configuration reader adapter type
    fn protocol_configuration_reader_adapter_type(&self) -> ProtocolConfigurationReaderAdapterType {
        panic!("protocol_configuration_reader_adapter_type is not implemented.");
    }

    /// Protocol configuration reader adapter parameters
    fn protocol_configuration_reader_adapter_params(&self) -> Option<String> {
        panic!("protocol_configuration_reader_adapter_params is not implemented.");
    }

    /// Configuration of the ancillary files signer
    ///
    /// **IMPORTANT**: The cryptographic scheme used is ED25519
    fn ancillary_files_signer_config(&self) -> AncillaryFilesSignerConfig {
        panic!("ancillary_files_signer_config is not implemented.");
    }

    /// Signed entity types parameters (discriminants names in an ordered, case-sensitive,
    /// comma-separated list).
    ///
    /// The value `MithrilStakeDistribution` is prepended automatically to the list.
    fn signed_entity_types(&self) -> Option<String> {
        panic!("signed_entity_types is not implemented.");
    }

    /// Compression algorithm used for the snapshot archive artifacts.
    fn snapshot_compression_algorithm(&self) -> CompressionAlgorithm {
        panic!("snapshot_compression_algorithm is not implemented.");
    }

    /// Specific parameters when [CompressionAlgorithm] is set to
    /// [zstandard][CompressionAlgorithm::Zstandard].
    fn zstandard_parameters(&self) -> Option<ZstandardCompressionParameters> {
        panic!("zstandard_parameters is not implemented.");
    }

    /// Blockfrost api configuration
    fn blockfrost_parameters(&self) -> Option<BlockfrostParameters> {
        panic!("blockfrost_parameters is not implemented.");
    }

    /// Time interval at which the pools names and ticker in blockfrost will be imported (in minutes).
    fn signer_importer_run_interval(&self) -> u64 {
        panic!("signer_importer_run_interval is not implemented.");
    }

    /// If set no error is returned in case of unparsable block and an error log is written instead.
    ///
    /// Will be ignored on (pre)production networks.
    fn allow_unparsable_block(&self) -> bool {
        panic!("allow_unparsable_block is not implemented.");
    }

    /// Cardano blocks and transactions prover cache pool size
    fn cardano_blocks_transactions_prover_cache_pool_size(&self) -> usize {
        panic!("cardano_blocks_transactions_prover_cache_pool_size is not implemented.");
    }

    /// Cardano and transactions database connection pool size
    fn cardano_blocks_transactions_database_connection_pool_size(&self) -> usize {
        panic!("cardano_blocks_transactions_database_connection_pool_size is not implemented.");
    }

    /// Cardano transactions prover cache pool size
    fn cardano_transactions_prover_cache_pool_size(&self) -> usize {
        panic!("cardano_transactions_prover_cache_pool_size is not implemented.");
    }

    /// Cardano transactions database connection pool size
    fn cardano_transactions_database_connection_pool_size(&self) -> usize {
        panic!("cardano_transactions_database_connection_pool_size is not implemented.");
    }

    /// Cardano transactions signing configuration
    fn cardano_transactions_signing_config(&self) -> Option<CardanoTransactionsSigningConfig> {
        panic!("cardano_transactions_signing_config is not implemented.");
    }

    /// Cardano blocks and transactions signing configuration
    fn cardano_blocks_transactions_signing_config(
        &self,
    ) -> Option<CardanoBlocksTransactionsSigningConfig> {
        panic!("cardano_blocks_transactions_signing_config is not implemented.");
    }

    /// Blocks offset, from the tip of the chain, to exclude during the cardano transactions preload
    fn preload_security_parameter(&self) -> BlockNumber {
        panic!("preload_security_parameter is not implemented.");
    }

    /// Maximum number of hashes allowed by request to the Cardano prover.
    ///
    /// This unified limit is applied to both transaction-hash and block-hash proving routes.
    fn cardano_prover_max_hashes_allowed_by_request(&self) -> usize {
        panic!("cardano_prover_max_hashes_allowed_by_request is not implemented.");
    }

    /// The maximum number of roll forwards during a poll of the block streamer when importing transactions.
    fn cardano_transactions_block_streamer_max_roll_forwards_per_poll(&self) -> usize {
        panic!(
            "cardano_transactions_block_streamer_max_roll_forwards_per_poll is not implemented."
        );
    }

    /// Minimum duration between two consecutive block streamer polls in milliseconds.
    fn cardano_transactions_block_streamer_throttling_interval(&self) -> Option<u64> {
        panic!("cardano_transactions_block_streamer_throttling_interval is not implemented.");
    }

    /// Enable metrics server (Prometheus endpoint on /metrics).
    fn enable_metrics_server(&self) -> bool {
        panic!("enable_metrics_server is not implemented.");
    }

    /// Metrics HTTP Server IP.
    fn metrics_server_ip(&self) -> String {
        panic!("metrics_server_ip is not implemented.");
    }

    /// Metrics HTTP Server listening port.
    fn metrics_server_port(&self) -> u16 {
        panic!("metrics_server_port is not implemented.");
    }

    /// Time interval at which usage metrics are persisted in event database (in seconds).
    fn persist_usage_report_interval_in_seconds(&self) -> u64 {
        panic!("persist_usage_report_interval_in_seconds is not implemented.");
    }

    /// Leader aggregator endpoint
    ///
    /// This is the endpoint of the aggregator that will be used to fetch the latest epoch settings
    /// and store the signer registrations when the aggregator is running in a follower mode.
    /// If this is not set, the aggregator will run in a leader mode.
    fn leader_aggregator_endpoint(&self) -> Option<String> {
        panic!("leader_aggregator_endpoint is not implemented.");
    }

    /// Custom origin tag of client request added to the whitelist (comma
    /// separated list).
    fn custom_origin_tag_white_list(&self) -> Option<String> {
        panic!("custom_origin_tag_white_list is not implemented.");
    }

    /// Get the server URL.
    fn get_server_url(&self) -> StdResult<SanitizedUrlWithTrailingSlash> {
        panic!("get_server_url is not implemented.");
    }

    /// Get a representation of the Cardano network.
    fn get_network(&self) -> StdResult<CardanoNetwork> {
        CardanoNetwork::from_code(self.network(), self.network_magic())
            .with_context(|| "Invalid network configuration")
    }

    /// Get a representation of the DMQ network.
    fn get_dmq_network(&self) -> StdResult<DmqNetwork> {
        DmqNetwork::from_code(self.network(), self.dmq_network_magic())
            .with_context(|| "Invalid DMQ network configuration")
    }

    /// Get the directory of the SQLite stores.
    fn get_sqlite_dir(&self) -> PathBuf {
        let store_dir = &self.data_stores_directory();

        if !store_dir.exists() {
            std::fs::create_dir_all(store_dir).unwrap();
        }

        self.data_stores_directory()
    }

    /// Get the snapshots directory.
    fn get_snapshot_dir(&self) -> StdResult<PathBuf> {
        if !&self.snapshot_directory().exists() {
            std::fs::create_dir_all(self.snapshot_directory())?;
        }

        Ok(self.snapshot_directory())
    }

    /// Get the parsed Cardano node version.
    fn parsed_cardano_node_version(&self) -> StdResult<semver::Version> {
        Version::parse(&self.cardano_node_version())
        .with_context(||format!("Could not parse configuration setting 'cardano_node_version' value '{}' as Semver.", self.cardano_node_version()) )
    }

    /// Get the safe epoch retention limit.
    fn safe_epoch_retention_limit(&self) -> Option<u64> {
        self.store_retention_limit()
            .map(|limit| if limit > 3 { limit as u64 } else { 3 })
    }

    /// Compute the list of signed entity discriminants that are allowed to be processed.
    fn compute_allowed_signed_entity_types_discriminants(
        &self,
    ) -> StdResult<BTreeSet<SignedEntityTypeDiscriminants>> {
        let allowed_discriminants = self
            .signed_entity_types()
            .as_ref()
            .map(SignedEntityTypeDiscriminants::parse_list_lossy)
            .unwrap_or_default();
        let allowed_discriminants =
            SignedEntityConfig::append_allowed_signed_entity_types_discriminants(
                allowed_discriminants,
            );

        Ok(allowed_discriminants)
    }

    /// Check if the HTTP server can serve static directories.
    fn allow_http_serve_directory(&self) -> bool {
        match self.snapshot_uploader_type() {
            SnapshotUploaderType::Local => true,
            SnapshotUploaderType::Gcp => false,
        }
    }

    /// `leader aggregator only` Infer the [AggregatorEpochSettings] from the configuration.
    fn get_leader_aggregator_epoch_settings_configuration(
        &self,
    ) -> StdResult<AggregatorEpochSettings> {
        let allowed_discriminants = self.compute_allowed_signed_entity_types_discriminants()?;
        let cardano_transactions_signing_config = self.cardano_transactions_signing_config();
        let cardano_blocks_transactions_signing_config =
            self.cardano_blocks_transactions_signing_config();

        if allowed_discriminants.contains(&SignedEntityTypeDiscriminants::CardanoTransactions)
            && cardano_transactions_signing_config.is_none()
        {
            anyhow::bail!(
                "Configuration `cardano_transactions_signing_config` is mandatory for a Leader Aggregator when `CardanoTransactions` is enabled in `signed_entity_types`"
            );
        }

        if allowed_discriminants.contains(&SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
            && cardano_blocks_transactions_signing_config.is_none()
        {
            anyhow::bail!(
                "Configuration `cardano_blocks_transactions_signing_config` is mandatory for a Leader Aggregator when `CardanoBlocksTransactions` is enabled in `signed_entity_types`"
            );
        }

        Ok(AggregatorEpochSettings {
            protocol_parameters: self.protocol_parameters().with_context(
                || "Configuration `protocol_parameters` is mandatory for a Leader Aggregator",
            )?,
            cardano_transactions_signing_config,
            cardano_blocks_transactions_signing_config,
        })
    }

    /// Check if the aggregator is running in follower mode.
    fn is_follower_aggregator(&self) -> bool {
        self.leader_aggregator_endpoint().is_some()
    }

    /// White list for origin client request.
    fn compute_origin_tag_white_list(&self) -> HashSet<String> {
        let mut white_list = HashSet::from([
            "EXPLORER".to_string(),
            "BENCHMARK".to_string(),
            "CI".to_string(),
            "NA".to_string(),
        ]);
        if let Some(custom_tags) = &self.custom_origin_tag_white_list() {
            white_list.extend(custom_tags.split(',').map(|tag| tag.trim().to_string()));
        }

        white_list
    }

    /// Aggregate signature type
    fn aggregate_signature_type(&self) -> AggregateSignatureType {
        panic!("get_aggregate_signature_type is not implemented.");
    }

    /// Signature processor wait delay on error in milliseconds
    fn signature_processor_wait_delay_on_error_ms(&self) -> u64 {
        panic!("signature_processor_wait_delay_on_error_ms is not implemented.");
    }
}

/// Serve command configuration
#[derive(Debug, Clone, Deserialize, Documenter)]
pub struct ServeCommandConfiguration {
    /// What kind of runtime environment the configuration is meant to.
    pub environment: ExecutionEnvironment,

    /// Cardano CLI tool path
    #[example = "`cardano-cli`"]
    pub cardano_cli_path: PathBuf,

    /// Path of the socket opened by the Cardano node
    #[example = "`/ipc/node.socket`"]
    pub cardano_node_socket_path: PathBuf,

    /// Path of the socket opened by the DMQ node
    #[example = "`/ipc/dmq.socket`"]
    pub dmq_node_socket_path: Option<PathBuf>,

    /// Cardano node version.
    ///
    /// **NOTE**: This cannot be verified for now (see [this
    /// issue](https://github.com/input-output-hk/cardano-cli/issues/224)). This
    /// is why it has to be manually given to the Aggregator
    pub cardano_node_version: String,

    /// Cardano network
    #[example = "`mainnet` or `preprod` or `devnet`"]
    pub network: String,

    /// Cardano network magic number
    ///
    /// useful for TestNet & DevNet
    #[example = "`1097911063` or `42`"]
    pub network_magic: Option<u64>,

    /// Dmq network magic number
    ///
    /// useful for TestNet & DevNet
    #[example = "`1097911063` or `42`"]
    pub dmq_network_magic: Option<u64>,

    /// Cardano chain observer type
    pub chain_observer_type: ChainObserverType,

    /// Protocol parameters
    #[example = "`{ k: 5, m: 100, phi_f: 0.65 }`"]
    pub protocol_parameters: Option<ProtocolParameters>,

    /// Type of snapshot uploader to use
    #[example = "`gcp` or `local`"]
    pub snapshot_uploader_type: SnapshotUploaderType,

    /// Bucket name where the snapshots are stored if snapshot_uploader_type is Gcp
    pub snapshot_bucket_name: Option<String>,

    /// Use CDN domain to construct snapshot urls if snapshot_uploader_type is Gcp
    pub snapshot_use_cdn_domain: bool,

    /// Server listening IP
    pub server_ip: String,

    /// Server listening port
    pub server_port: u16,

    /// Server URL that can be accessed from the outside
    pub public_server_url: Option<String>,

    /// Run Interval is the interval between two runtime cycles in ms
    #[example = "`60000`"]
    pub run_interval: u64,

    /// Directory of the Cardano node store.
    pub db_directory: PathBuf,

    /// Directory to store snapshot
    pub snapshot_directory: PathBuf,

    /// Directory to store aggregator databases
    #[example = "`./mithril-aggregator/stores`"]
    pub data_stores_directory: PathBuf,

    /// Genesis verification key
    pub genesis_verification_key: HexEncodedGenesisVerificationKey,

    /// Should the immutable cache be reset or not
    pub reset_digests_cache: bool,

    /// Use the digest caching strategy
    pub disable_digests_cache: bool,

    /// Max number of records in stores.
    /// When new records are added, oldest records are automatically deleted so
    /// there can always be at max the number of records specified by this
    /// setting.
    pub store_retention_limit: Option<usize>,

    /// Era reader adapter type
    pub era_reader_adapter_type: EraReaderAdapterType,

    /// Era reader adapter parameters
    pub era_reader_adapter_params: Option<String>,

    /// Configuration of the ancillary files signer
    ///
    /// Can either be a secret key or a key stored in a Google Cloud Platform KMS account.
    ///
    /// **IMPORTANT**: The cryptographic scheme used is ED25519
    #[example = "\
    - secret-key:<br/>`{ \"type\": \"secret-key\", \"secret_key\": \"136372c3138312c3138382c3130352c3233312c3135\" }`<br/>\
    - Gcp kms:<br/>`{ \"type\": \"gcp-kms\", \"resource_name\": \"projects/project_name/locations/_location_name/keyRings/key_ring_name/cryptoKeys/key_name/cryptoKeyVersions/key_version\" }`\
    "]
    #[serde(deserialize_with = "serde_deserialization::string_or_struct")]
    pub ancillary_files_signer_config: AncillaryFilesSignerConfig,

    /// Signed entity types parameters (discriminants names in an ordered, case-sensitive, comma
    /// separated list).
    ///
    /// The value `MithrilStakeDistribution` is prepended is automatically to the list.
    #[example = "`CardanoStakeDistribution,CardanoDatabase,CardanoTransactions`"]
    pub signed_entity_types: Option<String>,

    /// Compression algorithm used for the snapshot archive artifacts.
    #[example = "`gzip` or `zstandard`"]
    pub snapshot_compression_algorithm: CompressionAlgorithm,

    /// Specific parameters when [snapshot_compression_algorithm][Self::snapshot_compression_algorithm]
    /// is set to [zstandard][CompressionAlgorithm::Zstandard].
    #[example = "`{ level: 9, number_of_workers: 4 }`"]
    pub zstandard_parameters: Option<ZstandardCompressionParameters>,

    /// Optional parameters to connect to the Blockfrost API. Used to fetch the ticker and name of
    /// the registered stake pools.
    ///
    /// `base_url` (optional) allows you to override the default URL, which is otherwise automatically determined from the project ID.
    #[example = "\
    `{ \"project_id\": \"preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ\" }`<br/>\
    or `{ \"project_id\": \"preprodWuV1ICdtOWfZYfdcxpZ0tsS1N9rVZomQ\", \"base_url\": \"https://your-custom-blockfrost-server.io/api/v0/\" }`\
    "]
    #[serde(
        default,
        deserialize_with = "serde_deserialization::string_or_struct_optional"
    )]
    pub blockfrost_parameters: Option<BlockfrostParameters>,

    /// Time interval at which the pools names and ticker in blockfrost will be imported (in minutes).
    pub signer_importer_run_interval: u64,

    /// If set no error is returned in case of unparsable block and an error log is written instead.
    ///
    /// Will be ignored on (pre)production networks.
    pub allow_unparsable_block: bool,

    /// Cardano blocks and transactions prover cache pool size
    pub cardano_blocks_transactions_prover_cache_pool_size: usize,

    /// Cardano blocks and transactions database connection pool size
    pub cardano_blocks_transactions_database_connection_pool_size: usize,

    /// Cardano transactions prover cache pool size
    pub cardano_transactions_prover_cache_pool_size: usize,

    /// Cardano transactions database connection pool size
    pub cardano_transactions_database_connection_pool_size: usize,

    /// Cardano transactions signing configuration
    #[example = "`{ security_parameter: 3000, step: 120 }`"]
    pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,

    /// Cardano blocks and transactions signing configuration
    #[example = "`{ security_parameter: 3000, step: 120 }`"]
    pub cardano_blocks_transactions_signing_config: Option<CardanoBlocksTransactionsSigningConfig>,

    /// Blocks offset, from the tip of the chain, to exclude during the Cardano transactions preload,
    /// default to 2160.
    #[example = "`2160`"]
    pub preload_security_parameter: BlockNumber,

    /// Maximum number of hashes allowed by request to the Cardano prover.
    ///
    /// This unified limit is applied to both transaction-hash and block-hash proving routes.
    pub cardano_prover_max_hashes_allowed_by_request: usize,

    /// The maximum number of roll forwards during a poll of the block streamer when importing transactions.
    pub cardano_transactions_block_streamer_max_roll_forwards_per_poll: usize,

    /// Minimum duration between two consecutive block streamer polls in milliseconds `[default: 400]`.
    ///
    /// Set this value to `0` to disable throttling.
    pub cardano_transactions_block_streamer_throttling_interval: Option<u64>,

    /// Enable metrics server (Prometheus endpoint on /metrics).
    pub enable_metrics_server: bool,

    /// Metrics HTTP Server IP.
    pub metrics_server_ip: String,

    /// Metrics HTTP Server listening port.
    pub metrics_server_port: u16,

    /// Time interval at which usage metrics are persisted in event database (in seconds).
    pub persist_usage_report_interval_in_seconds: u64,

    // Leader aggregator endpoint
    ///
    /// This is the endpoint of the aggregator that will be used to fetch the latest epoch settings
    /// and store the signer registrations when the aggregator is running in a follower mode.
    /// If this is not set, the aggregator will run in a leader mode.
    pub leader_aggregator_endpoint: Option<String>,

    /// Custom origin tag of client request added to the whitelist (comma
    /// separated list).
    pub custom_origin_tag_white_list: Option<String>,

    /// Aggregate signature type used to create certificates
    pub aggregate_signature_type: AggregateSignatureType,

    /// Delay to wait between two signature processing attempts after an error
    pub signature_processor_wait_delay_on_error_ms: u64,
}

/// Uploader needed to copy the snapshot once computed.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotUploaderType {
    /// Uploader to GCP storage.
    Gcp,
    /// Uploader to local storage.
    Local,
}

/// [Zstandard][CompressionAlgorithm::Zstandard] specific parameters
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct ZstandardCompressionParameters {
    /// Level of compression, default to 9.
    pub level: i32,

    /// Number of workers when compressing, 0 will disable multithreading, default to 4.
    pub number_of_workers: u32,
}

impl Default for ZstandardCompressionParameters {
    fn default() -> Self {
        Self {
            level: 9,
            number_of_workers: 4,
        }
    }
}

/// Configuration to connect to the Blockfrost API.
///
/// Currently only used to fetch the ticker and name for registered pools.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BlockfrostParameters {
    /// Project ID of the Blockfrost project.
    pub project_id: ConfigSecret<String>,

    /// Optional base URL for Blockfrost API, if not provided, the default URL will be determined
    /// automatically from the project ID.
    pub base_url: Option<String>,
}

impl FromStr for BlockfrostParameters {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// Configuration of the ancillary files signer
///
/// **IMPORTANT**: The cryptographic scheme used is ED25519
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum AncillaryFilesSignerConfig {
    /// Sign with a secret key
    SecretKey {
        /// Hex encoded secret key
        secret_key: HexEncodedKey,
    },
    /// Sign with a key stored in a Google Cloud Platform KMS account
    GcpKms {
        /// GCP KMS resource name
        resource_name: GcpCryptoKeyVersionResourceName,
        /// Environment variable containing the credentials JSON, if not set `GOOGLE_APPLICATION_CREDENTIALS_JSON` will be used
        #[serde(default = "default_gcp_kms_credentials_json_env_var")]
        credentials_json_env_var: String,
    },
}

fn default_gcp_kms_credentials_json_env_var() -> String {
    DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR.to_string()
}

impl FromStr for AncillaryFilesSignerConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl ServeCommandConfiguration {
    /// Create a sample configuration mainly for tests
    pub fn new_sample(tmp_path: PathBuf) -> Self {
        let genesis_verification_key = GenesisEd25519Signer::create_deterministic_signer()
            .create_verifier()
            .to_verification_key();
        let ancillary_files_signer_secret_key =
            ManifestSigner::create_deterministic_signer().secret_key();

        Self {
            environment: ExecutionEnvironment::Test,
            cardano_cli_path: PathBuf::new(),
            cardano_node_socket_path: PathBuf::new(),
            dmq_node_socket_path: None,
            cardano_node_version: "0.0.1".to_string(),
            network: "devnet".to_string(),
            network_magic: Some(42),
            dmq_network_magic: Some(3141592),
            chain_observer_type: ChainObserverType::Fake,
            protocol_parameters: Some(ProtocolParameters {
                k: 5,
                m: 100,
                phi_f: 0.95,
            }),
            snapshot_uploader_type: SnapshotUploaderType::Local,
            snapshot_bucket_name: None,
            snapshot_use_cdn_domain: false,
            server_ip: "0.0.0.0".to_string(),
            server_port: 8000,
            public_server_url: None,
            run_interval: 5000,
            db_directory: PathBuf::new(),
            // Note: this is a band-aid solution to avoid IO operations in the `mithril-aggregator`
            // crate directory.
            // Know issue:
            // - There may be collision of the `snapshot_directory` between tests. Tests that
            // depend on the `snapshot_directory` should specify their own,
            // and they can use the `temp_dir` macro for that.
            snapshot_directory: tmp_path,
            data_stores_directory: PathBuf::from(":memory:"),
            genesis_verification_key: genesis_verification_key.to_json_hex().unwrap(),
            reset_digests_cache: false,
            disable_digests_cache: false,
            store_retention_limit: None,
            era_reader_adapter_type: EraReaderAdapterType::Bootstrap,
            era_reader_adapter_params: None,
            ancillary_files_signer_config: AncillaryFilesSignerConfig::SecretKey {
                secret_key: ancillary_files_signer_secret_key.to_json_hex().unwrap(),
            },
            signed_entity_types: None,
            snapshot_compression_algorithm: CompressionAlgorithm::Zstandard,
            zstandard_parameters: Some(ZstandardCompressionParameters::default()),
            blockfrost_parameters: None,
            signer_importer_run_interval: 1,
            allow_unparsable_block: false,
            cardano_blocks_transactions_prover_cache_pool_size: 3,
            cardano_blocks_transactions_database_connection_pool_size: 5,
            cardano_transactions_prover_cache_pool_size: 3,
            cardano_transactions_database_connection_pool_size: 5,
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(120),
                step: BlockNumber(15),
            }),
            cardano_blocks_transactions_signing_config: Some(
                CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(120),
                    step: BlockNumber(15),
                },
            ),
            preload_security_parameter: BlockNumber(30),
            cardano_prover_max_hashes_allowed_by_request: 100,
            cardano_transactions_block_streamer_max_roll_forwards_per_poll: 1000,
            cardano_transactions_block_streamer_throttling_interval: None,
            enable_metrics_server: true,
            metrics_server_ip: "0.0.0.0".to_string(),
            metrics_server_port: 9090,
            persist_usage_report_interval_in_seconds: 10,
            leader_aggregator_endpoint: None,
            custom_origin_tag_white_list: None,
            aggregate_signature_type: AggregateSignatureType::Concatenation,
            signature_processor_wait_delay_on_error_ms: 5000,
        }
    }

    /// Build the local server URL from configuration.
    pub fn get_local_server_url(&self) -> StdResult<SanitizedUrlWithTrailingSlash> {
        SanitizedUrlWithTrailingSlash::parse(&format!(
            "http://{}:{}/{SERVER_BASE_PATH}/",
            self.server_ip, self.server_port
        ))
    }
}

impl ConfigurationSource for ServeCommandConfiguration {
    fn environment(&self) -> ExecutionEnvironment {
        self.environment.clone()
    }

    fn cardano_cli_path(&self) -> PathBuf {
        self.cardano_cli_path.clone()
    }

    fn cardano_node_socket_path(&self) -> PathBuf {
        self.cardano_node_socket_path.clone()
    }

    fn dmq_node_socket_path(&self) -> Option<PathBuf> {
        self.dmq_node_socket_path.clone()
    }

    fn cardano_node_version(&self) -> String {
        self.cardano_node_version.clone()
    }

    fn network(&self) -> String {
        self.network.clone()
    }

    fn network_magic(&self) -> Option<u64> {
        self.network_magic
    }

    fn dmq_network_magic(&self) -> Option<u64> {
        self.dmq_network_magic
    }

    fn chain_observer_type(&self) -> ChainObserverType {
        self.chain_observer_type.clone()
    }

    fn protocol_parameters(&self) -> Option<ProtocolParameters> {
        self.protocol_parameters.clone()
    }

    fn snapshot_uploader_type(&self) -> SnapshotUploaderType {
        self.snapshot_uploader_type
    }

    fn snapshot_bucket_name(&self) -> Option<String> {
        self.snapshot_bucket_name.clone()
    }

    fn snapshot_use_cdn_domain(&self) -> bool {
        self.snapshot_use_cdn_domain
    }

    fn server_ip(&self) -> String {
        self.server_ip.clone()
    }

    fn server_port(&self) -> u16 {
        self.server_port
    }

    fn public_server_url(&self) -> Option<String> {
        self.public_server_url.clone()
    }

    fn run_interval(&self) -> u64 {
        self.run_interval
    }

    fn db_directory(&self) -> PathBuf {
        self.db_directory.clone()
    }

    fn snapshot_directory(&self) -> PathBuf {
        self.snapshot_directory.clone()
    }

    fn data_stores_directory(&self) -> PathBuf {
        self.data_stores_directory.clone()
    }

    fn genesis_verification_key(&self) -> HexEncodedGenesisVerificationKey {
        self.genesis_verification_key.clone()
    }

    fn reset_digests_cache(&self) -> bool {
        self.reset_digests_cache
    }

    fn disable_digests_cache(&self) -> bool {
        self.disable_digests_cache
    }

    fn store_retention_limit(&self) -> Option<usize> {
        self.store_retention_limit
    }

    fn era_reader_adapter_type(&self) -> EraReaderAdapterType {
        self.era_reader_adapter_type.clone()
    }

    fn era_reader_adapter_params(&self) -> Option<String> {
        self.era_reader_adapter_params.clone()
    }

    fn ancillary_files_signer_config(&self) -> AncillaryFilesSignerConfig {
        self.ancillary_files_signer_config.clone()
    }

    fn signed_entity_types(&self) -> Option<String> {
        self.signed_entity_types.clone()
    }

    fn snapshot_compression_algorithm(&self) -> CompressionAlgorithm {
        self.snapshot_compression_algorithm
    }

    fn zstandard_parameters(&self) -> Option<ZstandardCompressionParameters> {
        self.zstandard_parameters
    }

    fn blockfrost_parameters(&self) -> Option<BlockfrostParameters> {
        self.blockfrost_parameters.clone()
    }

    fn signer_importer_run_interval(&self) -> u64 {
        self.signer_importer_run_interval
    }

    fn allow_unparsable_block(&self) -> bool {
        self.allow_unparsable_block
    }

    fn cardano_blocks_transactions_prover_cache_pool_size(&self) -> usize {
        self.cardano_blocks_transactions_prover_cache_pool_size
    }

    fn cardano_blocks_transactions_database_connection_pool_size(&self) -> usize {
        self.cardano_blocks_transactions_database_connection_pool_size
    }

    fn cardano_transactions_prover_cache_pool_size(&self) -> usize {
        self.cardano_transactions_prover_cache_pool_size
    }

    fn cardano_transactions_database_connection_pool_size(&self) -> usize {
        self.cardano_transactions_database_connection_pool_size
    }

    fn cardano_transactions_signing_config(&self) -> Option<CardanoTransactionsSigningConfig> {
        self.cardano_transactions_signing_config.clone()
    }

    fn cardano_blocks_transactions_signing_config(
        &self,
    ) -> Option<CardanoBlocksTransactionsSigningConfig> {
        self.cardano_blocks_transactions_signing_config.clone()
    }

    fn preload_security_parameter(&self) -> BlockNumber {
        self.preload_security_parameter
    }

    fn cardano_prover_max_hashes_allowed_by_request(&self) -> usize {
        self.cardano_prover_max_hashes_allowed_by_request
    }

    fn cardano_transactions_block_streamer_max_roll_forwards_per_poll(&self) -> usize {
        self.cardano_transactions_block_streamer_max_roll_forwards_per_poll
    }

    fn cardano_transactions_block_streamer_throttling_interval(&self) -> Option<u64> {
        self.cardano_transactions_block_streamer_throttling_interval
    }

    fn enable_metrics_server(&self) -> bool {
        self.enable_metrics_server
    }

    fn metrics_server_ip(&self) -> String {
        self.metrics_server_ip.clone()
    }

    fn metrics_server_port(&self) -> u16 {
        self.metrics_server_port
    }

    fn persist_usage_report_interval_in_seconds(&self) -> u64 {
        self.persist_usage_report_interval_in_seconds
    }

    fn leader_aggregator_endpoint(&self) -> Option<String> {
        self.leader_aggregator_endpoint.clone()
    }

    fn custom_origin_tag_white_list(&self) -> Option<String> {
        self.custom_origin_tag_white_list.clone()
    }

    fn get_server_url(&self) -> StdResult<SanitizedUrlWithTrailingSlash> {
        match &self.public_server_url {
            Some(url) => SanitizedUrlWithTrailingSlash::parse(url),
            None => self.get_local_server_url(),
        }
    }

    fn aggregate_signature_type(&self) -> AggregateSignatureType {
        self.aggregate_signature_type
    }

    fn signature_processor_wait_delay_on_error_ms(&self) -> u64 {
        self.signature_processor_wait_delay_on_error_ms
    }
}

/// Default configuration with all the default values for configurations.
#[derive(Debug, Clone, DocumenterDefault)]
pub struct DefaultConfiguration {
    /// Execution environment
    pub environment: ExecutionEnvironment,

    /// Server listening IP
    pub server_ip: String,

    /// Server listening port
    pub server_port: String,

    /// Directory of the Cardano node database
    pub db_directory: String,

    /// Directory to store snapshot
    pub snapshot_directory: String,

    /// Type of snapshot uploader to use
    pub snapshot_uploader_type: String,

    /// Era reader adapter type
    pub era_reader_adapter_type: String,

    /// Chain observer type
    pub chain_observer_type: String,

    /// ImmutableDigesterCacheProvider default setting
    pub reset_digests_cache: String,

    /// ImmutableDigesterCacheProvider default setting
    pub disable_digests_cache: String,

    /// Snapshot compression algorithm default setting
    pub snapshot_compression_algorithm: String,

    /// Use CDN domain to construct snapshot urls default setting (if snapshot_uploader_type is Gcp)
    pub snapshot_use_cdn_domain: String,

    /// Signer importer run interval default setting
    pub signer_importer_run_interval: u64,

    /// If set no error is returned in case of unparsable block and an error log is written instead.
    ///
    /// Will be ignored on (pre)production networks.
    pub allow_unparsable_block: String,

    /// Cardano blocks and transactions prover cache pool size
    pub cardano_blocks_transactions_prover_cache_pool_size: u32,

    /// Cardano blocks and transactions database connection pool size
    pub cardano_blocks_transactions_database_connection_pool_size: u32,

    /// Cardano transactions prover cache pool size
    pub cardano_transactions_prover_cache_pool_size: u32,

    /// Cardano transactions database connection pool size
    pub cardano_transactions_database_connection_pool_size: u32,

    /// Cardano transactions signing configuration
    pub cardano_transactions_signing_config: CardanoTransactionsSigningConfig,

    /// Cardano blocks and transactions signing configuration
    pub cardano_blocks_transactions_signing_config: CardanoBlocksTransactionsSigningConfig,

    /// Blocks offset, from the tip of the chain, to exclude during the Cardano transactions preload
    pub preload_security_parameter: u64,

    /// Maximum number of hashes allowed by request to the Cardano prover.
    ///
    /// This unified limit is applied to both transaction-hash and block-hash proving routes.
    pub cardano_prover_max_hashes_allowed_by_request: u32,

    /// The maximum number of roll forwards during a poll of the block streamer when importing transactions.
    pub cardano_transactions_block_streamer_max_roll_forwards_per_poll: u32,

    /// Minimum duration between two consecutive block streamer polls in milliseconds.
    pub cardano_transactions_block_streamer_throttling_interval: u64,

    /// Enable metrics server (Prometheus endpoint on /metrics).
    pub enable_metrics_server: String,

    /// Metrics HTTP server IP.
    pub metrics_server_ip: String,

    /// Metrics HTTP server listening port.
    pub metrics_server_port: u16,

    /// Time interval at which metrics are persisted in event database (in seconds).
    pub persist_usage_report_interval_in_seconds: u64,

    /// Aggregate signature type used to create certificates
    pub aggregate_signature_type: String,

    /// Delay to wait between two signature processing attempts after an error
    pub signature_processor_wait_delay_on_error_ms: u64,
}

impl Default for DefaultConfiguration {
    fn default() -> Self {
        Self {
            environment: ExecutionEnvironment::Production,
            server_ip: "0.0.0.0".to_string(),
            server_port: "8080".to_string(),
            db_directory: "/db".to_string(),
            snapshot_directory: ".".to_string(),
            snapshot_uploader_type: "gcp".to_string(),
            era_reader_adapter_type: "bootstrap".to_string(),
            chain_observer_type: "pallas".to_string(),
            reset_digests_cache: "false".to_string(),
            disable_digests_cache: "false".to_string(),
            snapshot_compression_algorithm: "zstandard".to_string(),
            snapshot_use_cdn_domain: "false".to_string(),
            signer_importer_run_interval: 720,
            allow_unparsable_block: "false".to_string(),
            cardano_blocks_transactions_prover_cache_pool_size: 10,
            cardano_blocks_transactions_database_connection_pool_size: 10,
            cardano_transactions_prover_cache_pool_size: 10,
            cardano_transactions_database_connection_pool_size: 10,
            cardano_transactions_signing_config: CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(3000),
                step: BlockNumber(120),
            },
            cardano_blocks_transactions_signing_config: CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(3000),
                step: BlockNumber(120),
            },
            preload_security_parameter: 2160,
            cardano_prover_max_hashes_allowed_by_request: 100,
            cardano_transactions_block_streamer_max_roll_forwards_per_poll: 10000,
            cardano_transactions_block_streamer_throttling_interval: 50,
            enable_metrics_server: "false".to_string(),
            metrics_server_ip: "0.0.0.0".to_string(),
            metrics_server_port: 9090,
            persist_usage_report_interval_in_seconds: 10,
            aggregate_signature_type: "Concatenation".to_string(),
            signature_processor_wait_delay_on_error_ms: 1000,
        }
    }
}

impl DefaultConfiguration {
    fn namespace() -> String {
        "default configuration".to_string()
    }
}

impl From<ExecutionEnvironment> for ValueKind {
    fn from(value: ExecutionEnvironment) -> Self {
        match value {
            ExecutionEnvironment::Production => ValueKind::String("Production".to_string()),
            ExecutionEnvironment::Test => ValueKind::String("Test".to_string()),
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
        register_config_value!(result, &namespace, myself.environment);
        register_config_value!(result, &namespace, myself.server_ip);
        register_config_value!(result, &namespace, myself.server_port);
        register_config_value!(result, &namespace, myself.db_directory);
        register_config_value!(result, &namespace, myself.snapshot_directory);
        register_config_value!(result, &namespace, myself.snapshot_uploader_type);
        register_config_value!(result, &namespace, myself.era_reader_adapter_type);
        register_config_value!(result, &namespace, myself.reset_digests_cache);
        register_config_value!(result, &namespace, myself.disable_digests_cache);
        register_config_value!(result, &namespace, myself.snapshot_compression_algorithm);
        register_config_value!(result, &namespace, myself.snapshot_use_cdn_domain);
        register_config_value!(result, &namespace, myself.signer_importer_run_interval);
        register_config_value!(result, &namespace, myself.allow_unparsable_block);
        register_config_value!(
            result,
            &namespace,
            myself.cardano_blocks_transactions_prover_cache_pool_size
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_blocks_transactions_database_connection_pool_size
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_transactions_prover_cache_pool_size
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_transactions_database_connection_pool_size
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_prover_max_hashes_allowed_by_request
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
        register_config_value!(result, &namespace, myself.enable_metrics_server);
        register_config_value!(result, &namespace, myself.metrics_server_ip);
        register_config_value!(result, &namespace, myself.metrics_server_port);
        register_config_value!(
            result,
            &namespace,
            myself.persist_usage_report_interval_in_seconds
        );
        register_config_value!(result, &namespace, myself.preload_security_parameter);
        register_config_value!(
            result,
            &namespace,
            myself.cardano_transactions_signing_config,
            |v: CardanoTransactionsSigningConfig| HashMap::from([
                (
                    "security_parameter".to_string(),
                    ValueKind::from(*v.security_parameter),
                ),
                ("step".to_string(), ValueKind::from(*v.step),)
            ])
        );
        register_config_value!(
            result,
            &namespace,
            myself.cardano_blocks_transactions_signing_config,
            |v: CardanoBlocksTransactionsSigningConfig| HashMap::from([
                (
                    "security_parameter".to_string(),
                    ValueKind::from(*v.security_parameter),
                ),
                ("step".to_string(), ValueKind::from(*v.step),)
            ])
        );
        register_config_value!(result, &namespace, myself.aggregate_signature_type);
        register_config_value!(
            result,
            &namespace,
            myself.signature_processor_wait_delay_on_error_ms
        );
        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use mithril_common::temp_dir;
    use mithril_common::test::double::Dummy;
    use mithril_common::test::double::fake_data;

    use super::*;

    #[test]
    fn safe_epoch_retention_limit_wont_change_a_value_higher_than_three() {
        for limit in 4..=10u64 {
            let configuration = ServeCommandConfiguration {
                store_retention_limit: Some(limit as usize),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            };
            assert_eq!(configuration.safe_epoch_retention_limit(), Some(limit));
        }
    }

    #[test]
    fn safe_epoch_retention_limit_wont_change_a_none_value() {
        let configuration = ServeCommandConfiguration {
            store_retention_limit: None,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };
        assert_eq!(configuration.safe_epoch_retention_limit(), None);
    }

    #[test]
    fn safe_epoch_retention_limit_wont_yield_a_value_lower_than_three() {
        for limit in 0..=3 {
            let configuration = ServeCommandConfiguration {
                store_retention_limit: Some(limit),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            };
            assert_eq!(configuration.safe_epoch_retention_limit(), Some(3));
        }
    }

    #[test]
    fn can_build_config_with_ctx_signing_config_from_default_configuration() {
        #[derive(Debug, Deserialize)]
        struct TargetConfig {
            cardano_transactions_signing_config: CardanoTransactionsSigningConfig,
        }

        let config_builder = config::Config::builder().add_source(DefaultConfiguration::default());
        let target: TargetConfig = config_builder.build().unwrap().try_deserialize().unwrap();

        assert_eq!(
            target.cardano_transactions_signing_config,
            DefaultConfiguration::default().cardano_transactions_signing_config
        );
    }

    #[test]
    fn can_build_config_with_cardano_blocks_tx_signing_config_from_default_configuration() {
        #[derive(Debug, Deserialize)]
        struct TargetConfig {
            cardano_blocks_transactions_signing_config: CardanoBlocksTransactionsSigningConfig,
        }

        let config_builder = config::Config::builder().add_source(DefaultConfiguration::default());
        let target: TargetConfig = config_builder.build().unwrap().try_deserialize().unwrap();

        assert_eq!(
            target.cardano_blocks_transactions_signing_config,
            DefaultConfiguration::default().cardano_blocks_transactions_signing_config
        );
    }

    #[test]
    fn compute_allowed_signed_entity_types_discriminants_append_default_discriminants() {
        let config = ServeCommandConfiguration {
            signed_entity_types: None,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert_eq!(
            config.compute_allowed_signed_entity_types_discriminants().unwrap(),
            BTreeSet::from(SignedEntityConfig::DEFAULT_ALLOWED_DISCRIMINANTS)
        );
    }

    #[test]
    fn allow_http_serve_directory() {
        let config = ServeCommandConfiguration {
            snapshot_uploader_type: SnapshotUploaderType::Local,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert!(config.allow_http_serve_directory());

        let config = ServeCommandConfiguration {
            snapshot_uploader_type: SnapshotUploaderType::Gcp,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert!(!config.allow_http_serve_directory());
    }

    #[test]
    fn get_server_url_return_local_url_with_server_base_path_if_public_url_is_not_set() {
        let config = ServeCommandConfiguration {
            server_ip: "1.2.3.4".to_string(),
            server_port: 5678,
            public_server_url: None,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert_eq!(
            config.get_server_url().unwrap().as_str(),
            &format!("http://1.2.3.4:5678/{SERVER_BASE_PATH}/")
        );
    }

    #[test]
    fn get_server_url_return_sanitized_public_url_if_it_is_set() {
        let config = ServeCommandConfiguration {
            server_ip: "1.2.3.4".to_string(),
            server_port: 5678,
            public_server_url: Some("https://example.com".to_string()),
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert_eq!(
            config.get_server_url().unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn joining_to_local_server_url_keep_base_path() {
        let config = ServeCommandConfiguration {
            server_ip: "1.2.3.4".to_string(),
            server_port: 6789,
            public_server_url: None,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        let joined_url = config.get_local_server_url().unwrap().join("some/path").unwrap();
        assert!(
            joined_url.as_str().contains(SERVER_BASE_PATH),
            "Joined URL `{joined_url}`, does not contain base path `{SERVER_BASE_PATH}`"
        );
    }

    #[test]
    fn joining_to_public_server_url_without_trailing_slash() {
        let subpath_without_trailing_slash = "subpath_without_trailing_slash";
        let config = ServeCommandConfiguration {
            public_server_url: Some(format!(
                "https://example.com/{subpath_without_trailing_slash}"
            )),
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        let joined_url = config.get_server_url().unwrap().join("some/path").unwrap();
        assert!(
            joined_url.as_str().contains(subpath_without_trailing_slash),
            "Joined URL `{joined_url}`, does not contain subpath `{subpath_without_trailing_slash}`"
        );
    }

    #[test]
    fn is_follower_aggregator_returns_true_when_in_follower_mode() {
        let config = ServeCommandConfiguration {
            leader_aggregator_endpoint: Some("some_endpoint".to_string()),
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert!(config.is_follower_aggregator());
    }

    #[test]
    fn is_follower_aggregator_returns_false_when_in_leader_mode() {
        let config = ServeCommandConfiguration {
            leader_aggregator_endpoint: None,
            ..ServeCommandConfiguration::new_sample(temp_dir!())
        };

        assert!(!config.is_follower_aggregator());
    }

    #[test]
    fn deserializing_blockfrost_parameters() {
        let deserialized_without_base_url: BlockfrostParameters =
            serde_json::from_str(r#"{ "project_id": "preprodWuV1ICdtOWfZYf" }"#).unwrap();
        assert_eq!(
            deserialized_without_base_url,
            BlockfrostParameters {
                project_id: ConfigSecret::new("preprodWuV1ICdtOWfZYf".to_string()),
                base_url: None,
            }
        );

        let deserialized_with_base_url: BlockfrostParameters = serde_json::from_str(
            r#"{ "project_id": "preprodWuV1ICdtOWfZYf", "base_url": "https://test.foo.bar" }"#,
        )
        .unwrap();
        assert_eq!(
            deserialized_with_base_url,
            BlockfrostParameters {
                project_id: ConfigSecret::new("preprodWuV1ICdtOWfZYf".to_string()),
                base_url: Some("https://test.foo.bar".to_string()),
            }
        );
    }

    mod get_leader_aggregator_epoch_settings_configuration {
        use mithril_common::entities::BlockNumberOffset;

        use super::*;

        #[test]
        fn succeed_when_cardano_transactions_is_disabled_and_regardless_if_cardano_transactions_signing_config_is_set()
         {
            // Succeed without a configuration set
            {
                let epoch_settings = ServeCommandConfiguration {
                    signed_entity_types: None,
                    cardano_transactions_signing_config: None,
                    protocol_parameters: Some(ProtocolParameters::new(1, 2, 3.1)),
                    ..ServeCommandConfiguration::new_sample(temp_dir!())
                }
                .get_leader_aggregator_epoch_settings_configuration()
                .unwrap();

                assert_eq!(None, epoch_settings.cardano_transactions_signing_config);
            }
            // Succeed with a configuration set
            {
                let epoch_settings = ServeCommandConfiguration {
                    signed_entity_types: None,
                    cardano_transactions_signing_config: Some(
                        CardanoTransactionsSigningConfig::dummy(),
                    ),
                    protocol_parameters: Some(ProtocolParameters::new(1, 2, 3.1)),
                    ..ServeCommandConfiguration::new_sample(temp_dir!())
                }
                .get_leader_aggregator_epoch_settings_configuration()
                .unwrap();

                assert_eq!(
                    Some(CardanoTransactionsSigningConfig::dummy()),
                    epoch_settings.cardano_transactions_signing_config
                );
            }
        }

        #[test]
        fn succeed_when_cardano_transactions_is_enabled_and_cardano_transactions_signing_config_is_set()
         {
            let epoch_settings = ServeCommandConfiguration {
                signed_entity_types: Some(
                    SignedEntityTypeDiscriminants::CardanoTransactions.to_string(),
                ),
                cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(10),
                    step: BlockNumber(30),
                }),
                protocol_parameters: Some(ProtocolParameters::new(2, 3, 4.1)),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            }
            .get_leader_aggregator_epoch_settings_configuration()
            .unwrap();

            assert_eq!(
                Some(CardanoTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(10),
                    step: BlockNumber(30),
                }),
                epoch_settings.cardano_transactions_signing_config
            );
        }

        #[test]
        fn fails_when_cardano_transactions_is_enabled_without_associated_config() {
            let error = ServeCommandConfiguration {
                cardano_transactions_signing_config: None,
                signed_entity_types: Some(
                    SignedEntityTypeDiscriminants::CardanoTransactions.to_string(),
                ),
                protocol_parameters: Some(fake_data::protocol_parameters()),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            }
            .get_leader_aggregator_epoch_settings_configuration()
            .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("Configuration `cardano_transactions_signing_config` is mandatory")
            );
        }

        #[test]
        fn succeed_when_cardano_blocks_transactions_is_disabled_and_regardless_if_cardano_blocks_transactions_signing_config_is_set()
         {
            // Succeed without a configuration set
            {
                let epoch_settings = ServeCommandConfiguration {
                    signed_entity_types: None,
                    cardano_blocks_transactions_signing_config: None,
                    protocol_parameters: Some(ProtocolParameters::new(1, 2, 3.1)),
                    ..ServeCommandConfiguration::new_sample(temp_dir!())
                }
                .get_leader_aggregator_epoch_settings_configuration()
                .unwrap();

                assert_eq!(
                    None,
                    epoch_settings.cardano_blocks_transactions_signing_config
                );
            }
            // Succeed with a configuration set
            {
                let epoch_settings = ServeCommandConfiguration {
                    signed_entity_types: None,
                    cardano_blocks_transactions_signing_config: Some(
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                    ),
                    protocol_parameters: Some(ProtocolParameters::new(1, 2, 3.1)),
                    ..ServeCommandConfiguration::new_sample(temp_dir!())
                }
                .get_leader_aggregator_epoch_settings_configuration()
                .unwrap();

                assert_eq!(
                    Some(CardanoBlocksTransactionsSigningConfig::dummy()),
                    epoch_settings.cardano_blocks_transactions_signing_config
                );
            }
        }

        #[test]
        fn succeed_when_cardano_blocks_transactions_is_enabled_and_cardano_blocks_transactions_signing_config_is_set()
         {
            let epoch_settings = ServeCommandConfiguration {
                signed_entity_types: Some(
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions.to_string(),
                ),
                cardano_blocks_transactions_signing_config: Some(
                    CardanoBlocksTransactionsSigningConfig {
                        security_parameter: BlockNumberOffset(10),
                        step: BlockNumber(30),
                    },
                ),
                protocol_parameters: Some(ProtocolParameters::new(2, 3, 4.1)),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            }
            .get_leader_aggregator_epoch_settings_configuration()
            .unwrap();

            assert_eq!(
                Some(CardanoBlocksTransactionsSigningConfig {
                    security_parameter: BlockNumberOffset(10),
                    step: BlockNumber(30),
                }),
                epoch_settings.cardano_blocks_transactions_signing_config
            );
        }

        #[test]
        fn fails_when_cardano_blocks_transactions_is_enabled_without_associated_config() {
            let error = ServeCommandConfiguration {
                cardano_blocks_transactions_signing_config: None,
                signed_entity_types: Some(
                    SignedEntityTypeDiscriminants::CardanoBlocksTransactions.to_string(),
                ),
                protocol_parameters: Some(fake_data::protocol_parameters()),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            }
            .get_leader_aggregator_epoch_settings_configuration()
            .unwrap_err();

            assert!(error.to_string().contains(
                "Configuration `cardano_blocks_transactions_signing_config` is mandatory"
            ));
        }
    }

    #[test]
    fn serialized_ancillary_files_signer_config_use_snake_case_for_keys_and_kebab_case_for_type_value()
     {
        let serialized_json = r#"{
            "type": "secret-key",
            "secret_key": "whatever"
        }"#;

        let deserialized: AncillaryFilesSignerConfig =
            serde_json::from_str(serialized_json).unwrap();
        assert_eq!(
            deserialized,
            AncillaryFilesSignerConfig::SecretKey {
                secret_key: "whatever".to_string()
            }
        );
    }

    #[test]
    fn deserializing_ancillary_signing_gcp_kms_configuration() {
        let serialized_json = r#"{
            "type": "gcp-kms",
            "resource_name": "projects/123456789/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
            "credentials_json_env_var": "CUSTOM_ENV_VAR"
        }"#;

        let deserialized: AncillaryFilesSignerConfig =
            serde_json::from_str(serialized_json).unwrap();
        assert_eq!(
            deserialized,
            AncillaryFilesSignerConfig::GcpKms {
                resource_name: GcpCryptoKeyVersionResourceName {
                    project: "123456789".to_string(),
                    location: "global".to_string(),
                    key_ring: "my-keyring".to_string(),
                    key_name: "my-key".to_string(),
                    version: "1".to_string(),
                },
                credentials_json_env_var: "CUSTOM_ENV_VAR".to_string()
            }
        );
    }

    #[test]
    fn deserializing_ancillary_signing_gcp_kms_configuration_without_credentials_json_env_var_fallback_to_default()
     {
        let serialized_json = r#"{
            "type": "gcp-kms",
            "resource_name": "projects/123456789/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1"
        }"#;

        let deserialized: AncillaryFilesSignerConfig =
            serde_json::from_str(serialized_json).unwrap();
        if let AncillaryFilesSignerConfig::GcpKms {
            credentials_json_env_var,
            ..
        } = deserialized
        {
            assert_eq!(
                credentials_json_env_var,
                DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR
            );
        } else {
            panic!("Expected GcpKms variant but got {deserialized:?}");
        }
    }

    mod origin_tag {
        use super::*;

        #[test]
        fn default_origin_tag_white_list_is_not_empty() {
            let config = ServeCommandConfiguration {
                custom_origin_tag_white_list: None,
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            };
            assert_ne!(config.compute_origin_tag_white_list().len(), 0,);
        }

        #[test]
        fn custom_origin_tag_are_added_to_default_white_list() {
            let config = ServeCommandConfiguration {
                custom_origin_tag_white_list: Some("TAG_A,TAG_B , TAG_C".to_string()),
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            };

            let default_white_list = ServeCommandConfiguration {
                custom_origin_tag_white_list: None,
                ..ServeCommandConfiguration::new_sample(temp_dir!())
            }
            .compute_origin_tag_white_list();

            let mut expected_white_list = default_white_list.clone();
            assert!(expected_white_list.insert("TAG_A".to_string()));
            assert!(expected_white_list.insert("TAG_B".to_string()));
            assert!(expected_white_list.insert("TAG_C".to_string()));

            assert_eq!(expected_white_list, config.compute_origin_tag_white_list());
        }
    }
}
