use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use slog::Logger;
use tokio::sync::{Mutex, RwLock};

use mithril_aggregator_client::AggregatorHttpClient;
use mithril_cardano_node_chain::{
    chain_importer::{
        CardanoChainDataImporter, ChainDataImporterByChunk, ChainDataImporterWithPruner,
    },
    chain_observer::{CardanoCliRunner, ChainObserver, ChainObserverBuilder, ChainObserverType},
    chain_reader::PallasChainReader,
    chain_scanner::CardanoBlockScanner,
};
use mithril_cardano_node_internal_database::{
    ImmutableFileObserver, ImmutableFileSystemObserver,
    digesters::CardanoImmutableDigester,
    digesters::cache::{
        ImmutableFileDigestCacheProvider, JsonImmutableFileDigestCacheProviderBuilder,
    },
    signable_builder::CardanoDatabaseSignableBuilder,
};
use mithril_common::api_version::APIVersionProvider;
use mithril_common::crypto_helper::{
    KesSigner, KesSignerStandard, OpCert, ProtocolPartyId, SerDeShelleyFileFormat,
};
use mithril_common::messages::RegisterSignatureMessageDmq;
use mithril_common::signable_builder::{
    CardanoBlocksTransactionsSignableBuilder, CardanoStakeDistributionSignableBuilder,
    CardanoTransactionsSignableBuilder, MithrilSignableBuilderService,
    MithrilStakeDistributionSignableBuilder, SignableBuilderServiceDependencies,
};
use mithril_common::{MITHRIL_SIGNER_VERSION_HEADER, StdResult};

use mithril_era::{EraChecker, EraReader};
use mithril_signed_entity_lock::SignedEntityTypeLock;
use mithril_signed_entity_preloader::CardanoTransactionsPreloader;
use mithril_ticker::{MithrilTickerService, TickerService};

use mithril_persistence::database::{ApplicationNodeType, SqlMigration};
use mithril_persistence::sqlite::{
    ConnectionBuilder, ConnectionOptions, SqliteConnection, SqliteConnectionPool,
};

use mithril_protocol_config::{
    builder::build_protocol_configuration_adapter,
    markers::MarkersMithrilNetworkConfigurationProvider,
};

use mithril_dmq::{DmqMessageBuilder, DmqPublisherClientPallas};

use crate::database::repository::{
    ProtocolInitializerRepository, SignedBeaconRepository, SignerCardanoChainDataRepository,
    StakePoolStore,
};
use crate::dependency_injection::SignerDependencyContainer;
use crate::services::{
    CardanoTransactionsPreloaderActivationSigner, ChainDataImporterWithVacuum, MithrilEpochService,
    MithrilSingleSigner, SignaturePublishRetryPolicy, SignaturePublisher,
    SignaturePublisherDelayer, SignaturePublisherDmq, SignaturePublisherNoop,
    SignaturePublisherRetrier, SignerCertifierService, SignerChainDataImporter,
    SignerSignableSeedBuilder, SignerSignedEntityConfigProvider, SignerUpkeepService,
};
use crate::store::MKTreeStoreSqlite;
use crate::{
    Configuration, HTTP_REQUEST_TIMEOUT_DURATION, MetricsService, SQLITE_FILE,
    SQLITE_FILE_CARDANO_TRANSACTION,
};

/// The `DependenciesBuilder` is intended to manage Services instance creation.
///
/// The goal of this is to put all this code out of the way of business code.
pub struct DependenciesBuilder<'a> {
    config: &'a Configuration,
    chain_observer_builder: fn(&Configuration) -> StdResult<Arc<dyn ChainObserver>>,
    immutable_file_observer_builder:
        fn(&Configuration) -> StdResult<Arc<dyn ImmutableFileObserver>>,
    root_logger: Logger,
}

impl<'a> DependenciesBuilder<'a> {
    /// Create a new `DependenciesBuilder`.
    pub fn new(config: &'a Configuration, root_logger: Logger) -> Self {
        let chain_observer_builder: fn(&Configuration) -> StdResult<Arc<dyn ChainObserver>> =
            |config: &Configuration| {
                let chain_observer_type = ChainObserverType::Pallas;
                let cardano_cli_path = &config.cardano_cli_path;
                let cardano_node_socket_path = &config.cardano_node_socket_path;
                let cardano_network = &config.get_network().with_context(|| {
                    "Dependencies Builder can not get Cardano network while building the chain observer"
                })?;
                let cardano_cli_runner = &CardanoCliRunner::new(
                    cardano_cli_path.to_owned(),
                    cardano_node_socket_path.to_owned(),
                    cardano_network.to_owned(),
                );

                let chain_observer_builder = ChainObserverBuilder::new(
                    &chain_observer_type,
                    cardano_node_socket_path,
                    cardano_network,
                    Some(cardano_cli_runner),
                );

                chain_observer_builder
                    .build()
                    .with_context(|| "Dependencies Builder can not build chain observer")
            };

        let immutable_file_observer_builder: fn(
            &Configuration,
        )
            -> StdResult<Arc<dyn ImmutableFileObserver>> = |config: &Configuration| {
            Ok(Arc::new(ImmutableFileSystemObserver::new(
                &config.db_directory,
            )))
        };

        Self {
            config,
            chain_observer_builder,
            immutable_file_observer_builder,
            root_logger,
        }
    }

    /// Override immutable file observer builder.
    pub fn override_immutable_file_observer_builder(
        &mut self,
        builder: fn(&Configuration) -> StdResult<Arc<dyn ImmutableFileObserver>>,
    ) -> &mut Self {
        self.immutable_file_observer_builder = builder;

        self
    }

    /// Return a copy of the root logger.
    pub fn root_logger(&self) -> Logger {
        self.root_logger.clone()
    }

    /// Override default chain observer builder.
    pub fn override_chain_observer_builder(
        &mut self,
        builder: fn(&Configuration) -> StdResult<Arc<dyn ChainObserver>>,
    ) -> &mut Self {
        self.chain_observer_builder = builder;

        self
    }

    /// Compute protocol party id
    fn compute_protocol_party_id(&self) -> StdResult<ProtocolPartyId> {
        match &self.config.operational_certificate_path {
            Some(operational_certificate_path) => {
                let opcert: OpCert = OpCert::from_file(operational_certificate_path)
                    .with_context(|| "Could not decode operational certificate")?;
                Ok(opcert
                    .compute_protocol_party_id()
                    .with_context(|| "Could not compute party_id from operational certificate")?)
            }
            _ => Ok(self
                .config
                .party_id
                .to_owned()
                .with_context(|| "A party_id should at least be provided")?),
        }
    }

    async fn build_digester_cache_provider(
        &self,
    ) -> StdResult<Option<Arc<dyn ImmutableFileDigestCacheProvider>>> {
        if self.config.disable_digests_cache {
            return Ok(None);
        }

        let cache_provider = JsonImmutableFileDigestCacheProviderBuilder::new(
            &self.config.data_stores_directory,
            &format!("immutables_digests_{}.json", self.config.network),
        )
        .should_reset_digests_cache(self.config.reset_digests_cache)
        .with_logger(self.root_logger())
        .build()
        .await?;

        Ok(Some(Arc::new(cache_provider)))
    }

    /// Build an SQLite connection for the main database.
    pub async fn build_main_sqlite_connection(
        &self,
        sqlite_file_name: &str,
    ) -> StdResult<SqliteConnection> {
        self.setup_sqlite_connection_builder(
            sqlite_file_name,
            crate::database::migration::get_migrations(),
            &[],
        )?
        .build()
        .with_context(|| "Main database connection initialisation error")
    }

    /// Build an SQLite connection pool for the Cardano transactions database.
    pub async fn build_cardano_tx_sqlite_connection_pool(
        &self,
        sqlite_file_name: &str,
        pool_size: usize,
    ) -> StdResult<SqliteConnectionPool> {
        self.setup_sqlite_connection_builder(
            sqlite_file_name,
            mithril_persistence::database::cardano_transaction_migration::get_migrations(),
            &[ConnectionOptions::EnableForeignKeys],
        )?
        .build_pool(pool_size)
        .with_context(|| "'cardano_tx' Database connection initialisation error")
    }

    fn setup_sqlite_connection_builder(
        &self,
        sqlite_file_name: &str,
        migrations: Vec<SqlMigration>,
        options: &[ConnectionOptions],
    ) -> StdResult<ConnectionBuilder> {
        let sqlite_db_path = self.config.get_sqlite_file(sqlite_file_name)?;
        let builder = ConnectionBuilder::open_file(&sqlite_db_path)
            .with_node_type(ApplicationNodeType::Signer)
            .with_migrations(migrations)
            .with_options(options)
            .with_logger(self.root_logger());

        Ok(builder)
    }

    fn build_aggregator_client(
        &self,
        api_version_provider: &Arc<APIVersionProvider>,
    ) -> StdResult<Arc<AggregatorHttpClient>> {
        let client = AggregatorHttpClient::builder(self.config.aggregator_endpoint.clone())
            .with_headers(HashMap::from([(
                MITHRIL_SIGNER_VERSION_HEADER.to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            )]))
            .with_relay_endpoint(self.config.relay_endpoint.clone())
            .with_api_version_provider(api_version_provider.clone())
            .with_timeout(Duration::from_millis(HTTP_REQUEST_TIMEOUT_DURATION))
            .with_logger(self.root_logger())
            .build()?;
        Ok(Arc::new(client))
    }

    /// Build dependencies for the Production environment.
    pub async fn build(&self) -> StdResult<SignerDependencyContainer> {
        if !self.config.data_stores_directory.exists() {
            fs::create_dir_all(self.config.data_stores_directory.clone()).with_context(|| {
                format!(
                    "Could not create data stores directory: `{}`",
                    self.config.data_stores_directory.display()
                )
            })?;
        }

        let network = self.config.get_network()?;
        let sqlite_connection = Arc::new(self.build_main_sqlite_connection(SQLITE_FILE).await?);
        let sqlite_connection_cardano_transaction_pool = Arc::new(
            self.build_cardano_tx_sqlite_connection_pool(SQLITE_FILE_CARDANO_TRANSACTION, 1)
                .await?,
        );

        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());

        let protocol_initializer_store = Arc::new(ProtocolInitializerRepository::new(
            sqlite_connection.clone(),
            self.config.store_retention_limit.map(|limit| limit as u64),
        ));

        let digester = Arc::new(CardanoImmutableDigester::new(
            self.build_digester_cache_provider().await?,
            self.root_logger(),
        ));
        let stake_store = Arc::new(StakePoolStore::new(
            sqlite_connection.clone(),
            self.config.store_retention_limit.map(|limit| limit as u64),
        ));
        let chain_observer = {
            let builder = self.chain_observer_builder;
            builder(self.config)?
        };
        let ticker_service = {
            let builder = self.immutable_file_observer_builder;
            Arc::new(MithrilTickerService::new(
                chain_observer.clone(),
                builder(self.config)?,
            ))
        };

        let era_reader = Arc::new(EraReader::new(
            self.config.build_era_reader_adapter(chain_observer.clone())?,
        ));
        let era_epoch_token = era_reader
            .read_era_epoch_token(ticker_service.get_current_epoch().await?)
            .await?;
        let era_checker = Arc::new(EraChecker::new(
            era_epoch_token.get_current_supported_era()?,
            era_epoch_token.get_current_epoch(),
        ));

        let api_version_provider = Arc::new(APIVersionProvider::new(era_checker.clone()));
        let aggregator_client = self.build_aggregator_client(&api_version_provider)?;

        let mithril_stake_distribution_signable_builder =
            Arc::new(MithrilStakeDistributionSignableBuilder::default());
        let chain_data_store = Arc::new(SignerCardanoChainDataRepository::new(
            sqlite_connection_cardano_transaction_pool.clone(),
        ));
        let chain_block_reader = PallasChainReader::new(
            &self.config.cardano_node_socket_path,
            network,
            self.root_logger(),
        );
        let block_scanner = Arc::new(
            CardanoBlockScanner::new(
                Arc::new(Mutex::new(chain_block_reader)),
                self.config
                    .cardano_transactions_block_streamer_max_roll_forwards_per_poll,
                self.root_logger(),
            )
            .set_throttling_interval(
                self.config
                    .cardano_transactions_block_streamer_throttling_interval
                    .map(Duration::from_millis),
            ),
        );
        let chain_data_importer = Arc::new(CardanoChainDataImporter::new(
            block_scanner,
            chain_data_store.clone(),
            self.root_logger(),
        ));
        // Wrap the transaction importer with decorator to prune the transactions after import
        let chain_data_importer = Arc::new(ChainDataImporterWithPruner::new(
            self.config
                .enable_transaction_pruning
                .then_some(self.config.network_security_parameter),
            chain_data_store.clone(),
            chain_data_importer,
            self.root_logger(),
        ));
        // Wrap the transaction importer with decorator to chunk its workload, so it prunes
        // transactions after each chunk, reducing the storage footprint
        let state_machine_transactions_importer = Arc::new(SignerChainDataImporter::new(Arc::new(
            ChainDataImporterByChunk::new(
                chain_data_store.clone(),
                chain_data_importer.clone(),
                self.config.transactions_import_block_chunk_size,
                self.root_logger(),
            ),
        )));
        // For the preloader, we want to vacuum the database after each chunk, to reclaim disk space
        // earlier than with just auto_vacuum (that execute only after the end of all import).
        let preloader_chain_data_importer = Arc::new(SignerChainDataImporter::new(Arc::new(
            ChainDataImporterByChunk::new(
                chain_data_store.clone(),
                Arc::new(ChainDataImporterWithVacuum::new(
                    sqlite_connection_cardano_transaction_pool.clone(),
                    chain_data_importer.clone(),
                    self.root_logger(),
                )),
                self.config.transactions_import_block_chunk_size,
                self.root_logger(),
            ),
        )));
        let block_range_root_retriever = chain_data_store.clone();
        let cardano_transactions_builder = Arc::new(CardanoTransactionsSignableBuilder::<
            MKTreeStoreSqlite,
        >::new(
            state_machine_transactions_importer.clone(),
            block_range_root_retriever.clone(),
        ));
        let cardano_blocks_transactions_builder = Arc::new(
            CardanoBlocksTransactionsSignableBuilder::<MKTreeStoreSqlite>::new(
                state_machine_transactions_importer,
                block_range_root_retriever,
            ),
        );
        let cardano_stake_distribution_signable_builder = Arc::new(
            CardanoStakeDistributionSignableBuilder::new(stake_store.clone()),
        );
        let cardano_database_signable_builder = Arc::new(CardanoDatabaseSignableBuilder::new(
            digester.clone(),
            &self.config.db_directory,
            self.root_logger(),
        ));
        let epoch_service = Arc::new(RwLock::new(MithrilEpochService::new(
            era_checker.clone(),
            stake_store.clone(),
            protocol_initializer_store.clone(),
            self.root_logger(),
        )));
        let single_signer = Arc::new(MithrilSingleSigner::new(
            self.compute_protocol_party_id()?,
            epoch_service.clone(),
            self.root_logger(),
        ));
        let signable_seed_builder_service = Arc::new(SignerSignableSeedBuilder::new(
            epoch_service.clone(),
            protocol_initializer_store.clone(),
        ));
        let signable_builders_dependencies = SignableBuilderServiceDependencies::new(
            mithril_stake_distribution_signable_builder,
            cardano_transactions_builder,
            cardano_blocks_transactions_builder,
            cardano_stake_distribution_signable_builder,
            cardano_database_signable_builder,
            #[cfg(feature = "future_snark")]
            era_checker.clone(),
        );
        let signable_builder_service = Arc::new(MithrilSignableBuilderService::new(
            signable_seed_builder_service,
            signable_builders_dependencies,
            self.root_logger(),
        ));
        let metrics_service = Arc::new(MetricsService::new(self.root_logger())?);

        let protocol_configuration_adapter = build_protocol_configuration_adapter(
            self.config.protocol_configuration_reader_adapter_config.clone(),
            chain_observer.clone(),
        );
        let network_configuration_service =
            Arc::new(MarkersMithrilNetworkConfigurationProvider::new(
                self.root_logger(),
                protocol_configuration_adapter,
            ));

        let preloader_activation = CardanoTransactionsPreloaderActivationSigner::new(
            network_configuration_service.clone(),
            ticker_service.clone(),
        );
        let cardano_transactions_preloader = Arc::new(CardanoTransactionsPreloader::new(
            signed_entity_type_lock.clone(),
            preloader_chain_data_importer,
            self.config.preload_security_parameter,
            chain_observer.clone(),
            self.root_logger(),
            Arc::new(preloader_activation),
        ));
        let signed_beacon_repository = Arc::new(SignedBeaconRepository::new(
            sqlite_connection.clone(),
            self.config.store_retention_limit.map(|limit| limit as u64),
        ));
        let upkeep_service = Arc::new(SignerUpkeepService::new(
            sqlite_connection.clone(),
            sqlite_connection_cardano_transaction_pool,
            signed_entity_type_lock.clone(),
            vec![
                signed_beacon_repository.clone(),
                stake_store.clone(),
                protocol_initializer_store.clone(),
            ],
            self.root_logger(),
        ));

        let kes_signer = match (
            &self.config.kes_secret_key_path,
            &self.config.operational_certificate_path,
        ) {
            (Some(kes_secret_key_path), Some(operational_certificate_path)) => {
                Some(Arc::new(KesSignerStandard::new(
                    kes_secret_key_path.clone(),
                    operational_certificate_path.clone(),
                )) as Arc<dyn KesSigner>)
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(anyhow!(
                    "kes_secret_key and operational_certificate are both mandatory".to_string(),
                ));
            }
            _ => None,
        };

        let signature_publisher = {
            let first_publisher = SignaturePublisherRetrier::new(
                match &self.config.dmq_node_socket_path {
                    Some(dmq_node_socket_path) => {
                        let dmq_network = &self.config.get_dmq_network()?;
                        let dmq_message_builder = DmqMessageBuilder::new(
                            kes_signer.clone().with_context(
                                || "A KES signer is mandatory to sign DMQ messages",
                            )?,
                            chain_observer.clone(),
                        );
                        Arc::new(SignaturePublisherDmq::new(Arc::new(
                            DmqPublisherClientPallas::<RegisterSignatureMessageDmq>::new(
                                dmq_node_socket_path.to_owned(),
                                *dmq_network,
                                dmq_message_builder,
                                self.root_logger(),
                            ),
                        ))) as Arc<dyn SignaturePublisher>
                    }
                    _ => Arc::new(SignaturePublisherNoop) as Arc<dyn SignaturePublisher>,
                },
                SignaturePublishRetryPolicy::never(),
            );

            let second_publisher = SignaturePublisherRetrier::new(
                aggregator_client.clone(),
                SignaturePublishRetryPolicy {
                    attempts: self.config.signature_publisher_config.retry_attempts,
                    delay_between_attempts: Duration::from_millis(
                        self.config.signature_publisher_config.retry_delay_ms,
                    ),
                },
            );

            if self.config.signature_publisher_config.skip_delayer {
                Arc::new(first_publisher) as Arc<dyn SignaturePublisher>
            } else {
                Arc::new(SignaturePublisherDelayer::new(
                    Arc::new(first_publisher),
                    Arc::new(second_publisher),
                    Duration::from_millis(self.config.signature_publisher_config.delayer_delay_ms),
                    self.root_logger(),
                )) as Arc<dyn SignaturePublisher>
            }
        };

        let certifier = Arc::new(SignerCertifierService::new(
            signed_beacon_repository,
            Arc::new(SignerSignedEntityConfigProvider::new(epoch_service.clone())),
            signed_entity_type_lock.clone(),
            single_signer.clone(),
            signature_publisher,
            self.root_logger(),
        ));

        let services = SignerDependencyContainer {
            ticker_service,
            chain_observer,
            digester,
            single_signer,
            stake_store,
            protocol_initializer_store,
            era_checker,
            era_reader,
            api_version_provider,
            signable_builder_service,
            metrics_service,
            signed_entity_type_lock,
            cardano_transactions_preloader,
            upkeep_service,
            epoch_service,
            certifier,
            signer_registration_publisher: aggregator_client.clone(),
            signers_registration_retriever: aggregator_client,
            kes_signer,
            network_configuration_service,
        };

        Ok(services)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mithril_aggregator_client::query::GetAggregatorFeaturesQuery;
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::{
        entities::TimePoint,
        messages::AggregatorFeaturesMessage,
        test::{TempDir, api_version_extensions::ApiVersionProviderTestExtension, double::Dummy},
    };

    use crate::test::TestLogger;

    use super::*;

    fn get_test_dir(test_name: &str) -> PathBuf {
        TempDir::create("signer_service", test_name)
    }

    #[tokio::test]
    async fn test_auto_create_stores_directory() {
        let stores_dir = get_test_dir("test_auto_create_stores_directory").join("stores");
        let config = Configuration {
            data_stores_directory: stores_dir.clone(),
            ..Configuration::new_sample("party-123456")
        };

        assert!(!stores_dir.exists());
        let chain_observer_builder: fn(&Configuration) -> StdResult<Arc<dyn ChainObserver>> =
            |_config| Ok(Arc::new(FakeChainObserver::new(Some(TimePoint::dummy()))));
        let immutable_file_observer_builder: fn(
            &Configuration,
        )
            -> StdResult<Arc<dyn ImmutableFileObserver>> =
            |_config: &Configuration| Ok(Arc::new(DumbImmutableFileObserver::default()));

        let mut dependencies_builder = DependenciesBuilder::new(&config, TestLogger::stdout());
        dependencies_builder
            .override_chain_observer_builder(chain_observer_builder)
            .override_immutable_file_observer_builder(immutable_file_observer_builder)
            .build()
            .await
            .expect("service builder build should not fail");
        assert!(stores_dir.exists());
    }

    #[tokio::test]
    async fn set_signer_version_header_to_built_aggregator_client() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.is_true(|req| {
                req.headers()
                    .get(MITHRIL_SIGNER_VERSION_HEADER)
                    .is_some_and(|header| header == env!("CARGO_PKG_VERSION"))
            });
            then.status(200)
                .json_body(serde_json::json!(AggregatorFeaturesMessage::dummy()));
        });

        let config = Configuration {
            aggregator_endpoint: server.base_url(),
            ..Configuration::new_sample("party-123456")
        };
        let dependencies_builder = DependenciesBuilder::new(&config, TestLogger::stdout());
        let aggregator_client = dependencies_builder
            // Note: api version doesn't matter for this test
            .build_aggregator_client(&Arc::new(APIVersionProvider::new_failing()))
            .unwrap();

        aggregator_client
            .send(GetAggregatorFeaturesQuery::current())
            .await
            .unwrap();
    }
}
