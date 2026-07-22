mod enablers;
mod protocol;
mod support;

use anyhow::Context;
use slog::{Logger, debug};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    sync::{
        Mutex,
        mpsc::{UnboundedReceiver, UnboundedSender},
        watch,
    },
    time::Duration,
};
use warp::Filter;

use mithril_aggregator_client::AggregatorHttpClient;
use mithril_cardano_node_chain::{
    chain_observer::{CardanoCliRunner, ChainObserver},
    chain_reader::ChainBlockReader,
    chain_scanner::BlockScanner,
};
use mithril_cardano_node_internal_database::{
    ImmutableFileObserver,
    digesters::{ImmutableDigester, cache::ImmutableFileDigestCacheProvider},
};
use mithril_common::{
    api_version::APIVersionProvider,
    certificate_chain::CertificateVerifier,
    crypto_helper::GenesisVerifier,
    entities::SupportedEra,
    signable_builder::{SignableBuilderService, SignableSeedBuilder},
};
use mithril_era::{EraChecker, EraReader, EraReaderAdapter};
use mithril_persistence::sqlite::{SqliteConnection, SqliteConnectionPool};
use mithril_protocol_config::{
    ProtocolConfigurationReader, ProtocolConfigurationReaderAdapter,
    interface::MithrilNetworkConfigurationProvider,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;
use mithril_ticker::TickerService;

use crate::{
    AggregatorConfig, AggregatorRunner, AggregatorRuntime, EpochSettingsStorer,
    ImmutableFileDigestMapper, MetricsService, MithrilSignerRegistrationLeader, MultiSigner,
    ProtocolParametersRetriever, ServeCommandDependenciesContainer, SignerRegisterer,
    SignerRegistrationRoundOpener, SignerRegistrationVerifier, SingleSignatureAuthenticator,
    VerificationKeyStorer,
    configuration::ConfigurationSource,
    database::repository::{
        AggregatorCardanoChainDataRepository, CertificateRepository, EpochSettingsStore,
        OpenMessageRepository, SignedEntityStorer, SignerStore, StakePoolStore,
    },
    dependency_injection::ProtocolConfigurationCommandDependenciesContainer,
    event_store::{EventMessage, TransmitterService},
    file_uploaders::FileUploader,
    http_server::routes::router::{self, RouterConfig, RouterState},
    services::{
        AggregatorChainDataImporter, CertificateChainSynchronizer, CertifierService,
        LegacyProverService, MessageService, MithrilSignerRegistrationFollower, ProverService,
        SignedEntityService, SignerSynchronizer, Snapshotter, StakeDistributionService,
        UpkeepService,
    },
    tools::file_archiver::FileArchiver,
};

use super::{
    DatabaseCommandDependenciesContainer, DependenciesBuilderError, EpochServiceWrapper,
    GenesisCommandDependenciesContainer, Result, ToolsCommandDependenciesContainer,
};

/// Retrieve attribute stored in the builder.
/// If not yet initialized, we instantiate it by calling the associated build function (build_<attribute_name>).
/// If we don't want to to use the default build function, we can pass an expression that build the value.
/// Usage examples:
/// get_dependency!(self.signer_registerer)
/// get_dependency!(self.signer_registerer = self.build_signer_registerer().await?)
#[macro_export]
macro_rules! get_dependency {
    ( $self:ident.$attribute:ident ) => {{
        paste::paste! {
            get_dependency!($self.$attribute = $self.[<build_ $attribute>]().await?)
        }
    }};
    ( $self:ident.$attribute:ident = $builder:expr ) => {{
        paste::paste! {
            if $self.$attribute.is_none() {
                slog::debug!($self.root_logger(), "Building dependency {}", stringify!($attribute));
                $self.$attribute = Some($builder);
            }

            let r:Result<_> = Ok($self.$attribute.as_ref().cloned().unwrap());
            r
        }
    }};
}

const SQLITE_FILE: &str = "aggregator.sqlite3";
const SQLITE_FILE_CARDANO_TRANSACTION: &str = "cardano-transaction.sqlite3";
const SQLITE_MONITORING_FILE: &str = "monitoring.sqlite3";
const CARDANO_DB_ARTIFACTS_DIR: &str = "cardano-database";
const SNAPSHOT_ARTIFACTS_DIR: &str = "cardano-immutable-files-full";
/// Maximum offset that can be applied to the latest epoch when fetching artifacts.
const MAX_ARTIFACT_EPOCH_OFFSET: u64 = 5;

/// ## Dependencies container builder
///
/// This is meant to create SHARED DEPENDENCIES, ie: dependencies instances that
/// must be shared amongst several Tokio tasks. For example, database
/// repositories are NOT shared dependencies and therefor can be created ad hoc
/// whereas the database connection is a shared dependency.
///
/// Each shared dependency must implement a `build` and a `get` function. The
/// build function creates the dependency, the get function creates the
/// dependency at first call then return a clone of the Arc containing the
/// dependency for all further calls.
pub struct DependenciesBuilder {
    /// Configuration parameters
    pub configuration: Arc<dyn ConfigurationSource>,

    /// Application root logger
    pub root_logger: Logger,

    /// SQLite database connection
    pub sqlite_connection: Option<Arc<SqliteConnection>>,

    /// Event store SQLite database connection
    pub sqlite_connection_event_store: Option<Arc<SqliteConnection>>,

    /// Cardano transactions SQLite database connection pool
    pub sqlite_connection_cardano_transaction_pool: Option<Arc<SqliteConnectionPool>>,

    /// Stake Store used by the StakeDistributionService
    /// It shall be a private dependency.
    pub stake_store: Option<Arc<StakePoolStore>>,

    /// Snapshot uploader service.
    pub snapshot_uploader: Option<Arc<dyn FileUploader>>,

    /// Multisigner service.
    pub multi_signer: Option<Arc<dyn MultiSigner>>,

    /// Certificate repository.
    pub certificate_repository: Option<Arc<CertificateRepository>>,

    /// Open message repository.
    pub open_message_repository: Option<Arc<OpenMessageRepository>>,

    /// Verification key store.
    pub verification_key_store: Option<Arc<dyn VerificationKeyStorer>>,

    /// Epoch settings store.
    pub epoch_settings_store: Option<Arc<EpochSettingsStore>>,

    /// Cardano CLI Runner for the [ChainObserver]
    pub cardano_cli_runner: Option<Box<CardanoCliRunner>>,

    /// Chain observer service.
    pub chain_observer: Option<Arc<dyn ChainObserver>>,

    /// Chain block reader
    pub chain_block_reader: Option<Arc<Mutex<dyn ChainBlockReader>>>,

    /// Cardano chain data repository.
    pub chain_data_repository: Option<Arc<AggregatorCardanoChainDataRepository>>,

    /// Cardano block scanner.
    pub block_scanner: Option<Arc<dyn BlockScanner>>,

    /// Immutable file digester service.
    pub immutable_digester: Option<Arc<dyn ImmutableDigester>>,

    /// Immutable file observer service.
    pub immutable_file_observer: Option<Arc<dyn ImmutableFileObserver>>,

    /// Immutable cache provider service.
    pub immutable_cache_provider: Option<Arc<dyn ImmutableFileDigestCacheProvider>>,

    /// Immutable file digest mapper service.
    pub immutable_file_digest_mapper: Option<Arc<dyn ImmutableFileDigestMapper>>,

    /// Digester service.
    pub digester: Option<Arc<dyn ImmutableDigester>>,

    /// File archiver service.
    pub file_archiver: Option<Arc<FileArchiver>>,

    /// Snapshotter service.
    pub snapshotter: Option<Arc<dyn Snapshotter>>,

    /// Certificate verifier service.
    pub certificate_verifier: Option<Arc<dyn CertificateVerifier>>,

    /// Genesis signature verifier service.
    pub genesis_verifier: Option<Arc<GenesisVerifier>>,

    /// Certificate chain synchronizer service
    pub certificate_chain_synchronizer: Option<Arc<dyn CertificateChainSynchronizer>>,

    /// Mithril signer registration leader service
    pub mithril_signer_registration_leader: Option<Arc<MithrilSignerRegistrationLeader>>,

    /// Mithril signer registration follower service
    pub mithril_signer_registration_follower: Option<Arc<MithrilSignerRegistrationFollower>>,

    /// Signer registerer service
    pub signer_registerer: Option<Arc<dyn SignerRegisterer>>,

    /// Signer synchronizer service
    pub signer_synchronizer: Option<Arc<dyn SignerSynchronizer>>,

    /// Signer registration verifier
    pub signer_registration_verifier: Option<Arc<dyn SignerRegistrationVerifier>>,

    /// Signer registration round opener service
    pub signer_registration_round_opener: Option<Arc<dyn SignerRegistrationRoundOpener>>,

    /// Era checker service
    pub era_checker: Option<Arc<EraChecker>>,

    /// Adapter for [EraReader]
    pub era_reader_adapter: Option<Arc<dyn EraReaderAdapter>>,

    /// Era reader service
    pub era_reader: Option<Arc<EraReader>>,

    /// Adapter for [ProtocolConfigurationReader]
    pub protocol_configuration_reader_adapter: Option<Arc<dyn ProtocolConfigurationReaderAdapter>>,

    ///Protocol configuration reader service
    pub protocol_configuration_reader: Option<Arc<ProtocolConfigurationReader>>,

    /// Event Transmitter Service
    pub event_transmitter: Option<Arc<TransmitterService<EventMessage>>>,

    /// Event transmitter Channel Sender endpoint
    pub event_transmitter_channel: (
        Option<UnboundedReceiver<EventMessage>>,
        Option<UnboundedSender<EventMessage>>,
    ),

    /// API Version provider
    pub api_version_provider: Option<Arc<APIVersionProvider>>,

    /// Stake Distribution Service
    pub stake_distribution_service: Option<Arc<dyn StakeDistributionService>>,

    /// Ticker Service
    pub ticker_service: Option<Arc<dyn TickerService>>,

    /// Signer Store
    pub signer_store: Option<Arc<SignerStore>>,

    /// Signable Seed Builder
    pub signable_seed_builder: Option<Arc<dyn SignableSeedBuilder>>,

    /// Signable Builder Service
    pub signable_builder_service: Option<Arc<dyn SignableBuilderService>>,

    /// Signed Entity Service
    pub signed_entity_service: Option<Arc<dyn SignedEntityService>>,

    /// Certifier service
    pub certifier_service: Option<Arc<dyn CertifierService>>,

    /// Epoch service.
    pub epoch_service: Option<EpochServiceWrapper>,

    /// Mithril network configuration provider
    pub mithril_network_configuration_provider:
        Option<Arc<dyn MithrilNetworkConfigurationProvider>>,

    /// Signed Entity storer
    pub signed_entity_storer: Option<Arc<dyn SignedEntityStorer>>,

    /// HTTP Message service
    pub message_service: Option<Arc<dyn MessageService>>,

    /// Legacy Prover service
    pub legacy_prover_service: Option<Arc<dyn LegacyProverService>>,

    /// Prover service
    pub prover_service: Option<Arc<dyn ProverService>>,

    /// Signed Entity Type Lock
    pub signed_entity_type_lock: Option<Arc<SignedEntityTypeLock>>,

    /// Chain Data Importer
    pub chain_data_importer: Option<Arc<AggregatorChainDataImporter>>,

    /// Upkeep service
    pub upkeep_service: Option<Arc<dyn UpkeepService>>,

    /// Single signer authenticator
    pub single_signature_authenticator: Option<Arc<SingleSignatureAuthenticator>>,

    /// Metrics service
    pub metrics_service: Option<Arc<MetricsService>>,

    /// Leader aggregator client
    pub leader_aggregator_client: Option<Arc<AggregatorHttpClient>>,

    /// Protocol parameters retriever
    pub protocol_parameters_retriever: Option<Arc<dyn ProtocolParametersRetriever>>,

    /// Stop signal channel
    pub stop_signal_channel: Option<(watch::Sender<()>, watch::Receiver<()>)>,
}

impl DependenciesBuilder {
    /// Create a new clean dependency builder
    pub fn new(root_logger: Logger, configuration: Arc<dyn ConfigurationSource>) -> Self {
        Self {
            configuration,
            root_logger,
            sqlite_connection: None,
            sqlite_connection_event_store: None,
            sqlite_connection_cardano_transaction_pool: None,
            stake_store: None,
            snapshot_uploader: None,
            multi_signer: None,
            certificate_repository: None,
            open_message_repository: None,
            verification_key_store: None,
            epoch_settings_store: None,
            cardano_cli_runner: None,
            chain_observer: None,
            chain_block_reader: None,
            block_scanner: None,
            immutable_digester: None,
            immutable_file_observer: None,
            immutable_cache_provider: None,
            immutable_file_digest_mapper: None,
            digester: None,
            file_archiver: None,
            snapshotter: None,
            certificate_verifier: None,
            genesis_verifier: None,
            certificate_chain_synchronizer: None,
            mithril_signer_registration_leader: None,
            mithril_signer_registration_follower: None,
            signer_registerer: None,
            signer_synchronizer: None,
            signer_registration_verifier: None,
            signer_registration_round_opener: None,
            era_reader_adapter: None,
            era_checker: None,
            era_reader: None,
            protocol_configuration_reader_adapter: None,
            protocol_configuration_reader: None,
            event_transmitter: None,
            event_transmitter_channel: (None, None),
            api_version_provider: None,
            stake_distribution_service: None,
            ticker_service: None,
            signer_store: None,
            signable_seed_builder: None,
            signable_builder_service: None,
            signed_entity_service: None,
            certifier_service: None,
            epoch_service: None,
            mithril_network_configuration_provider: None,
            signed_entity_storer: None,
            message_service: None,
            legacy_prover_service: None,
            prover_service: None,
            signed_entity_type_lock: None,
            chain_data_importer: None,
            upkeep_service: None,
            single_signature_authenticator: None,
            metrics_service: None,
            leader_aggregator_client: None,
            protocol_parameters_retriever: None,
            stop_signal_channel: None,
            chain_data_repository: None,
        }
    }

    fn get_cardano_db_artifacts_dir(&self) -> Result<PathBuf> {
        let cardano_db_artifacts_dir =
            self.configuration.get_snapshot_dir()?.join(CARDANO_DB_ARTIFACTS_DIR);

        if !cardano_db_artifacts_dir.exists() {
            std::fs::create_dir(&cardano_db_artifacts_dir).map_err(|e| {
                DependenciesBuilderError::Initialization {
                    message: format!("Cannot create '{cardano_db_artifacts_dir:?}' directory."),
                    error: Some(e.into()),
                }
            })?;
        }

        Ok(cardano_db_artifacts_dir)
    }

    /// Return an unconfigured [ServeCommandDependenciesContainer]
    pub async fn build_serve_dependencies_container(
        &mut self,
    ) -> Result<ServeCommandDependenciesContainer> {
        #[allow(deprecated)]
        let dependencies_manager = ServeCommandDependenciesContainer {
            root_logger: self.root_logger(),
            stake_store: self.get_stake_store().await?,
            certificate_repository: self.get_certificate_repository().await?,
            verification_key_store: self.get_verification_key_store().await?,
            epoch_settings_storer: self.get_epoch_settings_store().await?,
            certificate_chain_synchronizer: self.get_certificate_chain_synchronizer().await?,
            signer_registerer: self.get_signer_registerer().await?,
            signer_synchronizer: self.get_signer_synchronizer().await?,
            signer_registration_round_opener: self.get_signer_registration_round_opener().await?,
            era_checker: self.get_era_checker().await?,
            era_reader: self.get_era_reader().await?,
            protocol_configuration_reader: self.get_protocol_configuration_reader().await?,
            event_transmitter: self.get_event_transmitter().await?,
            api_version_provider: self.get_api_version_provider().await?,
            stake_distribution_service: self.get_stake_distribution_service().await?,
            signer_recorder: self.get_signer_store().await?,
            signable_builder_service: self.get_signable_builder_service().await?,
            signed_entity_service: self.get_signed_entity_service().await?,
            certifier_service: self.get_certifier_service().await?,
            epoch_service: self.get_epoch_service().await?,
            ticker_service: self.get_ticker_service().await?,
            signed_entity_storer: self.get_signed_entity_storer().await?,
            signer_getter: self.get_signer_store().await?,
            message_service: self.get_message_service().await?,
            legacy_prover_service: self.get_legacy_prover_service().await?,
            prover_service: self.get_prover_service().await?,
            signed_entity_type_lock: self.get_signed_entity_type_lock().await?,
            upkeep_service: self.get_upkeep_service().await?,
            single_signer_authenticator: self.get_single_signature_authenticator().await?,
            metrics_service: self.get_metrics_service().await?,
        };

        self.handle_discrepancies_at_startup().await?;

        Ok(dependencies_manager)
    }

    /// Create the AggregatorRunner
    pub async fn create_aggregator_runner(&mut self) -> Result<AggregatorRuntime> {
        let dependency_container = Arc::new(self.build_serve_dependencies_container().await?);

        let config = AggregatorConfig::new(
            Duration::from_millis(self.configuration.run_interval()),
            self.configuration.is_follower_aggregator(),
        );
        let runtime = AggregatorRuntime::new(
            config,
            None,
            Arc::new(AggregatorRunner::new(dependency_container)),
            self.root_logger(),
        )
        .await
        .map_err(|e| DependenciesBuilderError::Initialization {
            message: "Cannot initialize Aggregator runtime.".to_string(),
            error: Some(e.into()),
        })?;

        Ok(runtime)
    }

    /// Create the HTTP route instance
    pub async fn create_http_routes(
        &mut self,
    ) -> Result<
        impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<>,
    > {
        let dependency_container = Arc::new(self.build_serve_dependencies_container().await?);
        let router_state = RouterState::new(
            dependency_container.clone(),
            RouterConfig {
                network: self.configuration.get_network()?,
                allowed_discriminants: self
                    .configuration
                    .compute_allowed_signed_entity_types_discriminants()?,
                cardano_prover_max_hashes_allowed_by_request: self
                    .configuration
                    .cardano_prover_max_hashes_allowed_by_request(),
                cardano_db_artifacts_directory: self.get_cardano_db_artifacts_dir()?,
                max_artifact_epoch_offset: MAX_ARTIFACT_EPOCH_OFFSET,
                cardano_node_version: self.configuration.cardano_node_version(),
                allow_http_serve_directory: self.configuration.allow_http_serve_directory(),
                origin_tag_white_list: self.configuration.compute_origin_tag_white_list(),
                aggregate_signature_type: self.configuration.aggregate_signature_type(),
            },
        );

        Ok(router::routes(Arc::new(router_state)))
    }

    /// Create dependencies for genesis commands
    pub async fn create_genesis_container(
        &mut self,
        mithril_era: SupportedEra,
    ) -> Result<GenesisCommandDependenciesContainer> {
        let network = self.configuration.get_network().with_context(
            || "Dependencies Builder can not get Cardano network while building genesis container",
        )?;

        let dependencies = GenesisCommandDependenciesContainer {
            network,
            chain_observer: self.get_chain_observer().await?,
            certificate_repository: self.get_certificate_repository().await?,
            protocol_parameters_retriever: self.get_protocol_parameters_retriever().await?,
            verification_key_store: self.get_verification_key_store().await?,
            mithril_era,
            logger: self.root_logger(),
        };

        Ok(dependencies)
    }

    /// Create dependencies for protocol configuration commands
    pub async fn create_protocol_configuration_container(
        &mut self,
    ) -> Result<ProtocolConfigurationCommandDependenciesContainer> {
        let network = self.configuration.get_network().with_context(
            || "Dependencies Builder can not get Cardano network while building protocol configuration container",
        )?;
        let dependencies = ProtocolConfigurationCommandDependenciesContainer {
            network,
            chain_observer: self.get_chain_observer().await?,
            protocol_configuration_reader: self.get_protocol_configuration_reader().await?,
            logger: self.root_logger(),
        };

        Ok(dependencies)
    }

    /// Create dependencies for database command
    pub async fn create_database_command_container(
        &mut self,
    ) -> Result<DatabaseCommandDependenciesContainer> {
        let main_db_connection = self
            .get_sqlite_connection()
            .await
            .with_context(|| "Dependencies Builder can not get sqlite connection")?;

        self.get_event_store_sqlite_connection()
            .await
            .with_context(|| "Dependencies Builder can not get event store sqlite connection")?;

        self.get_sqlite_connection_cardano_transaction_pool()
            .await
            .with_context(
                || "Dependencies Builder can not get cardano transaction pool sqlite connection",
            )?;

        let dependencies = DatabaseCommandDependenciesContainer { main_db_connection };

        Ok(dependencies)
    }

    /// Create dependencies for tools command
    pub async fn create_tools_command_container(
        &mut self,
    ) -> Result<ToolsCommandDependenciesContainer> {
        let db_connection = self
            .get_sqlite_connection()
            .await
            .with_context(|| "Dependencies Builder can not get sqlite connection")?;

        let dependencies = ToolsCommandDependenciesContainer { db_connection };

        Ok(dependencies)
    }

    /// Look for discrepancies in stored data and fix them.
    ///
    /// Fix discrepancies for:
    /// - epoch settings: ensure that the network configuration parameters for the three working epochs
    ///   window are stored in the database (see [mithril_protocol_config::model::MithrilNetworkConfiguration])
    pub async fn handle_discrepancies_at_startup(&mut self) -> Result<()> {
        let logger = self.root_logger();
        let current_epoch = self
            .get_chain_observer()
            .await?
            .get_current_epoch()
            .await
            .map_err(|e| DependenciesBuilderError::Initialization {
                message: "cannot handle startup discrepancies: failed to retrieve current epoch."
                    .to_string(),
                error: Some(e.into()),
            })?
            .ok_or(DependenciesBuilderError::Initialization {
                message: "cannot handle startup discrepancies: no epoch returned.".to_string(),
                error: None,
            })?;
        let network_configuration = self
            .get_mithril_network_configuration_provider()
            .await?
            .get_network_configuration(current_epoch)
            .await
            .map_err(|e| DependenciesBuilderError::Initialization {
                message: format!("cannot handle startup discrepancies: failed to retrieve network configuration for epoch {current_epoch}"),
                error: Some(e),
            })?;
        let epoch_settings_store = self.get_epoch_settings_store().await?;

        debug!(
            logger,
            "Handle discrepancies at startup of epoch settings store, will record epoch settings from the configuration for epoch {current_epoch}";
            "network_configuration" => ?network_configuration,
        );
        epoch_settings_store
            .handle_discrepancies_at_startup(&network_configuration)
            .await
            .map_err(|e| DependenciesBuilderError::Initialization {
                message: "can not create aggregator runner".to_string(),
                error: Some(e),
            })?;
        Ok(())
    }

    /// Remove the dependencies builder from memory to release Arc instances.
    pub async fn vanish(self) {
        self.drop_sqlite_connections().await;
    }
}

#[cfg(test)]
impl DependenciesBuilder {
    pub(crate) fn new_with_stdout_logger(configuration: Arc<dyn ConfigurationSource>) -> Self {
        Self::new(crate::test::TestLogger::stdout(), configuration)
    }
}
