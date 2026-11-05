#![allow(dead_code)]
use std::{
    collections::BTreeMap, fmt::Debug, ops::RangeInclusive, path::Path, sync::Arc, time::Duration,
};

use anyhow::{Context, anyhow};
use prometheus_parse::Value;
use slog_scope::debug;
use thiserror::Error;
use tokio::sync::RwLock;

use mithril_aggregator_client::AggregatorHttpClient;
use mithril_cardano_node_chain::{
    chain_importer::CardanoChainDataImporter,
    chain_observer::ChainObserver,
    entities::ScannedBlock,
    test::double::{DumbBlockScanner, FakeChainObserver},
};
use mithril_cardano_node_internal_database::{
    ImmutableFileObserver,
    signable_builder::CardanoDatabaseSignableBuilder,
    test::double::{DumbImmutableDigester, DumbImmutableFileObserver},
};
use mithril_common::{
    StdError,
    api_version::APIVersionProvider,
    crypto_helper::{KesSigner, KesSignerStandard},
    entities::{
        BlockNumber, ChainPoint, Epoch, SignedEntityType, Signer, SignerWithStake, SlotNumber,
        SupportedEra, TimePoint,
    },
    signable_builder::{
        CardanoBlocksTransactionsSignableBuilder, CardanoStakeDistributionSignableBuilder,
        CardanoTransactionsSignableBuilder, MithrilSignableBuilderService,
        MithrilStakeDistributionSignableBuilder, SignableBuilderServiceDependencies,
    },
    test::double::Dummy,
};
use mithril_era::{EraChecker, EraMarker, EraReader, adapters::EraReaderDummyAdapter};
use mithril_metric::{MetricCollector, MetricsServiceExporter};
use mithril_persistence::store::StakeStorer;
use mithril_protocol_config::{
    http::HttpMithrilNetworkConfigurationProvider, model::MithrilNetworkConfigurationForEpoch,
    test::double::FakeMithrilNetworkConfigurationProviderWithEpochMarkers,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;
use mithril_signed_entity_preloader::{
    CardanoTransactionsPreloader, CardanoTransactionsPreloaderActivation, PreloadTaskRunner,
};
use mithril_signer::{
    Configuration, MetricsService, RuntimeError, SignerRunner, SignerState, StateMachine,
    database::repository::{
        ProtocolInitializerRepository, SignedBeaconRepository, SignerCardanoChainDataRepository,
        StakePoolStore,
    },
    dependency_injection::{DependenciesBuilder, SignerDependencyContainer},
    services::{
        MithrilEpochService, MithrilSingleSigner, SignerCertifierService, SignerChainDataImporter,
        SignerSignableSeedBuilder, SignerSignedEntityConfigProvider, SignerUpkeepService,
    },
    store::{MKTreeStoreSqlite, ProtocolInitializerStorer},
};
use mithril_ticker::{MithrilTickerService, TickerService};

use super::{FakeAggregatorHttpServer, stdout_logger};

type Result<T> = std::result::Result<T, TestError>;

#[derive(Debug, Error)]
pub enum TestError {
    #[error("Assertion failed: {0}")]
    AssertFailed(String),
    #[error("Subsystem error: {0:?}")]
    SubsystemError(#[from] StdError),
    #[error("Value error: {0}")]
    ValueError(String),
}

impl From<RuntimeError> for TestError {
    fn from(value: RuntimeError) -> Self {
        Self::SubsystemError(value.into())
    }
}

pub struct StateMachineTester {
    state_machine: StateMachine,
    immutable_observer: Arc<DumbImmutableFileObserver>,
    chain_observer: Arc<FakeChainObserver>,
    fake_aggregator: Arc<FakeAggregatorHttpServer>,
    protocol_initializer_store: Arc<dyn ProtocolInitializerStorer>,
    stake_store: Arc<dyn StakeStorer>,
    era_checker: Arc<EraChecker>,
    era_reader_adapter: Arc<EraReaderDummyAdapter>,
    block_scanner: Arc<DumbBlockScanner>,
    signed_beacon_repository: Arc<SignedBeaconRepository>,
    metrics_service: Arc<MetricsService>,
    expected_metrics_service: Arc<MetricsService>,
    comment_no: u32,
    _logs_guard: slog_scope::GlobalLoggerGuard,
}

impl Debug for StateMachineTester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug!("Debug called after comment N°{}.", self.comment_no);
        write!(f, "DEBUG")
    }
}

impl StateMachineTester {
    pub async fn init(
        work_folder: &Path,
        signers_with_stake: &[SignerWithStake],
        initial_time_point: TimePoint,
    ) -> Result<Self> {
        let selected_signer_with_stake = signers_with_stake.first().ok_or_else(|| {
            TestError::AssertFailed("there should be at least one signer with stakes".to_string())
        })?;
        let selected_signer_party_id = selected_signer_with_stake.party_id.clone();
        let config = Configuration {
            db_directory: work_folder.join("db"),
            data_stores_directory: work_folder.join("stores"),
            ..Configuration::new_sample(&selected_signer_party_id)
        };

        let logger = stdout_logger();
        let logs_guard = slog_scope::set_global_logger(logger.clone());

        let dependencies_builder = DependenciesBuilder::new(&config, logger.clone());
        let sqlite_connection =
            Arc::new(dependencies_builder.build_main_sqlite_connection("signer.db").await?);
        let sqlite_connection_cardano_transaction_pool = dependencies_builder
            .build_cardano_tx_sqlite_connection_pool("cardano_tx.db", 1)
            .await
            .map(Arc::new)?;

        let immutable_observer = Arc::new(DumbImmutableFileObserver::new());
        immutable_observer.shall_return(Some(1)).await;

        let chain_observer = Arc::new(FakeChainObserver::new(Some(initial_time_point.clone())));
        let ticker_service = Arc::new(MithrilTickerService::new(
            chain_observer.clone(),
            immutable_observer.clone(),
        ));

        let fake_aggregator = Arc::new(FakeAggregatorHttpServer::spawn(
            ticker_service.clone(),
            Arc::new(FakeMithrilNetworkConfigurationProviderWithEpochMarkers::default()),
            logger.clone(),
        )?);

        let digester = Arc::new(DumbImmutableDigester::default().with_digest("DIGEST"));
        let protocol_initializer_store = Arc::new(ProtocolInitializerRepository::new(
            sqlite_connection.clone(),
            config.store_retention_limit.map(|limit| limit as u64),
        ));
        let stake_store = Arc::new(StakePoolStore::new(
            sqlite_connection.clone(),
            config.store_retention_limit.map(|limit| limit as u64),
        ));
        let era_reader_adapter = Arc::new(EraReaderDummyAdapter::from_markers(vec![
            (EraMarker {
                name: SupportedEra::dummy().to_string(),
                epoch: Some(Epoch(0)),
            }),
        ]));
        let era_reader = Arc::new(EraReader::new(era_reader_adapter.clone()));
        let era_epoch_token = era_reader
            .read_era_epoch_token(ticker_service.get_current_epoch().await.unwrap())
            .await
            .unwrap();
        let era_checker = Arc::new(EraChecker::new(
            era_epoch_token.get_current_supported_era().unwrap(),
            era_epoch_token.get_current_epoch(),
        ));

        let api_version_provider = Arc::new(APIVersionProvider::new(era_checker.clone()));

        let mithril_stake_distribution_signable_builder =
            Arc::new(MithrilStakeDistributionSignableBuilder::default());
        let block_scanner = Arc::new(DumbBlockScanner::new());
        let chain_data_store = Arc::new(SignerCardanoChainDataRepository::new(
            sqlite_connection_cardano_transaction_pool.clone(),
        ));
        // Add some blocks to the scanner, else first signing of CardanoTransactions will fail because
        // the signed merkle tree will be empty
        block_scanner.add_forwards(vec![Self::build_blocks_to_scan(
            1..=*initial_time_point.chain_point.block_number,
        )]);

        let transactions_importer = Arc::new(SignerChainDataImporter::new(Arc::new(
            CardanoChainDataImporter::new(
                block_scanner.clone(),
                chain_data_store.clone(),
                logger.clone(),
            ),
        )));
        let block_range_root_retriever = chain_data_store.clone();
        let cardano_transactions_builder = Arc::new(CardanoTransactionsSignableBuilder::<
            MKTreeStoreSqlite,
        >::new(
            transactions_importer.clone(),
            block_range_root_retriever.clone(),
        ));
        let cardano_blocks_transactions_builder = Arc::new(
            CardanoBlocksTransactionsSignableBuilder::<MKTreeStoreSqlite>::new(
                transactions_importer.clone(),
                block_range_root_retriever,
            ),
        );
        let cardano_stake_distribution_builder = Arc::new(
            CardanoStakeDistributionSignableBuilder::new(stake_store.clone()),
        );
        let cardano_database_signable_builder = Arc::new(CardanoDatabaseSignableBuilder::new(
            digester.clone(),
            Path::new(""),
            logger.clone(),
        ));
        let epoch_service = Arc::new(RwLock::new(MithrilEpochService::new(
            era_checker.clone(),
            stake_store.clone(),
            protocol_initializer_store.clone(),
            logger.clone(),
        )));
        let single_signer = Arc::new(MithrilSingleSigner::new(
            config.party_id.to_owned().unwrap_or_default(),
            epoch_service.clone(),
            logger.clone(),
        ));
        let signable_seed_builder_service = Arc::new(SignerSignableSeedBuilder::new(
            epoch_service.clone(),
            protocol_initializer_store.clone(),
        ));
        let signable_builders_dependencies = SignableBuilderServiceDependencies::new(
            mithril_stake_distribution_signable_builder,
            cardano_transactions_builder,
            cardano_blocks_transactions_builder,
            cardano_stake_distribution_builder,
            cardano_database_signable_builder,
            #[cfg(feature = "snark")]
            era_checker.clone(),
        );
        let signable_builder_service = Arc::new(MithrilSignableBuilderService::new(
            signable_seed_builder_service,
            signable_builders_dependencies,
            logger.clone(),
        ));
        let metrics_service = Arc::new(MetricsService::new(logger.clone()).unwrap());
        let expected_metrics_service = Arc::new(MetricsService::new(logger.clone()).unwrap());
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let security_parameter = BlockNumber(0);
        let cardano_transactions_preloader = Arc::new(PreloadTaskRunner::new(
            CardanoTransactionsPreloader::new(
                transactions_importer.clone(),
                security_parameter,
                chain_observer.clone(),
                Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
            ),
            signed_entity_type_lock.clone(),
            logger.clone(),
        ));
        let upkeep_service = Arc::new(SignerUpkeepService::new(
            sqlite_connection.clone(),
            sqlite_connection_cardano_transaction_pool,
            signed_entity_type_lock.clone(),
            vec![],
            logger.clone(),
        ));
        let signed_beacon_repository =
            Arc::new(SignedBeaconRepository::new(sqlite_connection.clone(), None));
        let aggregator_client = AggregatorHttpClient::builder(fake_aggregator.url().to_string())
            .with_logger(logger.clone())
            .build()
            .map(Arc::new)?;

        let network_configuration_service = Arc::new(HttpMithrilNetworkConfigurationProvider::new(
            aggregator_client.clone(),
            logger.clone(),
        ));
        let certifier = Arc::new(SignerCertifierService::new(
            signed_beacon_repository.clone(),
            Arc::new(SignerSignedEntityConfigProvider::new(epoch_service.clone())),
            signed_entity_type_lock.clone(),
            single_signer.clone(),
            aggregator_client.clone(),
            logger.clone(),
        ));
        let kes_signer = Some(Arc::new(KesSignerStandard::new(
            config.kes_secret_key_path.clone().unwrap(),
            config.operational_certificate_path.clone().unwrap(),
        )) as Arc<dyn KesSigner>);

        let services = SignerDependencyContainer {
            signers_registration_retriever: aggregator_client.clone(),
            ticker_service: ticker_service.clone(),
            chain_observer: chain_observer.clone(),
            digester: digester.clone(),
            protocol_initializer_store: protocol_initializer_store.clone(),
            single_signer: single_signer.clone(),
            stake_store: stake_store.clone(),
            era_checker: era_checker.clone(),
            era_reader,
            api_version_provider,
            signable_builder_service,
            metrics_service: metrics_service.clone(),
            signed_entity_type_lock: Arc::new(SignedEntityTypeLock::default()),
            cardano_transactions_preloader,
            upkeep_service,
            epoch_service,
            certifier,
            signer_registration_publisher: aggregator_client.clone(),
            kes_signer,
            network_configuration_service: network_configuration_service.clone(),
        };
        // set up stake distribution
        chain_observer.set_signers(signers_with_stake.to_owned()).await;

        let runner = Box::new(SignerRunner::new(config, services, logger.clone()));

        let state_machine = StateMachine::new(
            SignerState::Init,
            runner,
            Duration::from_secs(5),
            metrics_service.clone(),
            logger.clone(),
        );

        Ok(StateMachineTester {
            state_machine,
            immutable_observer,
            chain_observer,
            fake_aggregator,
            protocol_initializer_store,
            stake_store,
            era_checker,
            era_reader_adapter,
            block_scanner,
            signed_beacon_repository,
            metrics_service,
            expected_metrics_service,
            comment_no: 0,
            _logs_guard: logs_guard,
        })
    }

    fn assert(&mut self, condition: bool, description: String) -> Result<&mut Self> {
        if !condition {
            Err(TestError::AssertFailed(description))
        } else {
            Ok(self)
        }
    }

    /// trigger a cycle in the state machine
    async fn cycle(&mut self) -> Result<&mut Self> {
        self.expected_metrics_service
            .get_runtime_cycle_total_since_startup_counter()
            .increment();

        self.state_machine.cycle().await?;

        self.expected_metrics_service
            .get_runtime_cycle_success_since_startup_counter()
            .increment();

        Ok(self)
    }

    /// Is the state machine in `Init` state?
    pub async fn is_init(&mut self) -> Result<&mut Self> {
        self.assert(
            self.state_machine.get_state().await.is_init(),
            "state machine shall be in Init state".to_string(),
        )
    }

    /// cycle the state machine and test the resulting state
    pub async fn cycle_ready_to_sign(&mut self) -> Result<&mut Self> {
        self.cycle().await?;

        self.assert(
            self.state_machine.get_state().await.is_ready_to_sign(),
            format!(
                "state machine is in {} state (ReadyToSign was expected)",
                self.state_machine.get_state().await
            ),
        )
    }

    pub async fn cycle_ready_to_sign_without_signature_registration(
        &mut self,
    ) -> Result<&mut Self> {
        let metric_before = self
            .metrics_service
            .get_signature_registration_success_since_startup_counter()
            .get();

        self.cycle_ready_to_sign().await?;

        let expected_metric = metric_before;
        self.check_total_signature_registrations_metrics(expected_metric)
    }

    pub async fn cycle_ready_to_sign_with_signature_registration(
        &mut self,
        expected_beacon: SignedEntityType,
    ) -> Result<&mut Self> {
        let metric_before = self
            .metrics_service
            .get_signature_registration_success_since_startup_counter()
            .get();

        self.cycle_ready_to_sign().await?;

        self.check_last_signed_beacon(Some(expected_beacon))?;

        let expected_metric = metric_before + 1;
        self.check_total_signature_registrations_metrics(expected_metric)
    }

    /// cycle the state machine and test the resulting state
    pub async fn cycle_registered_not_able_to_sign(&mut self) -> Result<&mut Self> {
        self.cycle().await?;

        self.assert(
            self.state_machine.get_state().await.is_registered_not_able_to_sign(),
            format!(
                "state machine is in {} state (RegisteredNotAbleToSign was expected)",
                self.state_machine.get_state().await
            ),
        )
    }

    /// cycle the state machine and test the resulting state
    pub async fn cycle_unregistered(&mut self) -> Result<&mut Self> {
        self.cycle().await?;

        self.assert(
            self.state_machine.get_state().await.is_unregistered(),
            format!(
                "state machine is in {} state (Unregistered was expected)",
                self.state_machine.get_state().await
            ),
        )
    }

    /// make the aggregator send the epoch settings from now on
    pub async fn aggregator_send_epoch_settings(&mut self) -> &mut Self {
        self.fake_aggregator.release_epoch_settings().await;
        self
    }

    /// Set a network configuration marker for the given epoch.
    pub async fn set_network_configuration_marker(
        &mut self,
        marker_epoch: Epoch,
        marker: MithrilNetworkConfigurationForEpoch,
    ) -> &mut Self {
        self.fake_aggregator
            .set_network_configuration_marker(marker_epoch, marker)
            .await;
        self
    }

    pub async fn send_unknown_and_discontinued_signed_entities_in_network_configuration(
        &mut self,
    ) -> &mut Self {
        self.fake_aggregator
            .protocol_config_send_unknown_signed_entities()
            .await;
        self.fake_aggregator
            .protocol_config_send_discontinued_signed_entities()
            .await;
        self
    }

    /// check there is a protocol initializer for the given Epoch
    pub async fn check_protocol_initializer(&mut self, epoch: Epoch) -> Result<&mut Self> {
        let maybe_protocol_initializer = self
            .protocol_initializer_store
            .get_protocol_initializer(epoch)
            .await
            .map_err(TestError::SubsystemError)?;

        self.assert(maybe_protocol_initializer.is_some(), format!(
                "there should be a protocol initializer in store for Epoch {}, here is the last 3 in store: {:?}",
                epoch,
                self.protocol_initializer_store
                    .get_last_protocol_initializer(2)
                    .await
                    .unwrap(),
            ))
    }

    /// check there is a stake for the given Epoch
    pub async fn check_stake_store(&mut self, epoch: Epoch) -> Result<&mut Self> {
        let maybe_stakes = self
            .stake_store
            .get_stakes(epoch)
            .await
            .map_err(TestError::SubsystemError)?;

        self.assert(
            maybe_stakes.is_some(),
            format!("there should be stake distribution saved for {epoch:?}"),
        )
    }

    /// increase the epoch in the chain observer
    pub async fn increase_epoch(&mut self, expected: u64) -> Result<&mut Self> {
        let new_epoch = self
            .chain_observer
            .next_epoch()
            .await
            .ok_or_else(|| TestError::ValueError("no epoch returned".to_string()))?;

        self.assert(
            expected == new_epoch,
            format!("Epoch increased by 1 to {new_epoch} ({expected} expected)"),
        )
    }

    /// increase the immutable file number in the dumb beacon provider
    pub async fn increase_immutable(&mut self, increment: u64, expected: u64) -> Result<&mut Self> {
        let immutable_number = self
            .immutable_observer
            .get_last_immutable_number()
            .await
            .map_err(TestError::SubsystemError)?;
        let new_immutable = immutable_number + increment;
        self.assert(
            expected == new_immutable,
            format!("expected to increase immutable number up to {expected}, got {new_immutable}"),
        )?;
        self.immutable_observer.shall_return(Some(new_immutable)).await;

        Ok(self)
    }

    /// increase the block number and the slot number in the fake observer
    pub async fn increase_block_number_and_slot_number(
        &mut self,
        increment: u64,
        expected_slot_number: SlotNumber,
        expected_block_number: BlockNumber,
    ) -> Result<&mut Self> {
        let new_slot_number = self
            .chain_observer
            .increase_slot_number(increment)
            .await
            .ok_or_else(|| TestError::ValueError("no slot number returned".to_string()))?;

        let new_block_number = self
            .chain_observer
            .increase_block_number(increment)
            .await
            .ok_or_else(|| TestError::ValueError("no block number returned".to_string()))?;

        self.assert(
            expected_slot_number == new_slot_number,
            format!("expected to increase slot number up to {expected_slot_number}, got {new_slot_number}"),
        )?;

        self.assert(
            expected_block_number == new_block_number,
            format!("expected to increase block number up to {expected_block_number}, got {new_block_number}"),
        )?;

        // Make the block scanner return new blocks
        self.block_scanner.add_forwards(vec![Self::build_blocks_to_scan(
            (*expected_block_number - increment + 1)..=*expected_block_number,
        )]);

        Ok(self)
    }

    fn build_blocks_to_scan(block_number_interval: RangeInclusive<u64>) -> Vec<ScannedBlock> {
        block_number_interval
            .map(|index_number| {
                let block_hash = format!("block_hash-{index_number}");
                ScannedBlock::new(
                    block_hash,
                    BlockNumber(index_number),
                    SlotNumber(index_number),
                    vec![format!("tx_hash-{index_number}-1")],
                )
            })
            .collect()
    }

    pub async fn cardano_chain_send_rollback(
        &mut self,
        rollback_to_slot_number: SlotNumber,
        rollback_to_block_number: BlockNumber,
    ) -> Result<&mut Self> {
        let chain_point = self
            .chain_observer
            .get_current_chain_point()
            .await
            .map_err(|err| TestError::SubsystemError(anyhow!(err)))?
            .with_context(|| "no chain point returned")?;

        let decrement_slot_number = chain_point.slot_number - rollback_to_slot_number;
        let decrement_block_number = chain_point.block_number - rollback_to_block_number;

        let new_slot_number = self
            .chain_observer
            .decrease_slot_number(*decrement_slot_number)
            .await
            .ok_or_else(|| TestError::ValueError("no slot number returned".to_string()))?;

        let new_block_number = self
            .chain_observer
            .decrease_block_number(*decrement_block_number)
            .await
            .ok_or_else(|| TestError::ValueError("no block number returned".to_string()))?;

        self.assert(
            rollback_to_slot_number == new_slot_number,
            format!("expected to decrease slot number to {rollback_to_slot_number}, got {new_slot_number}"),
        )?;

        self.assert(
            rollback_to_block_number == new_block_number,
            format!("expected to decrease block number to {rollback_to_block_number}, got {new_block_number}"),
        )?;

        let chain_point = ChainPoint {
            slot_number: rollback_to_slot_number,
            block_number: rollback_to_block_number,
            block_hash: format!("block_hash-{rollback_to_slot_number}-{rollback_to_block_number}"),
        };
        self.block_scanner.add_backward(chain_point);

        Ok(self)
    }

    async fn current_epoch(&self) -> Result<Epoch> {
        self.chain_observer
            .get_current_epoch()
            .await
            .map_err(|e| TestError::SubsystemError(e.into()))
            .transpose()
            .unwrap_or_else(|| Err(TestError::ValueError("no epoch returned".to_string())))
    }

    /// add a comment in the logs
    pub fn comment(&mut self, comment: &str) -> &mut Self {
        self.comment_no += 1;
        debug!("COMMENT {:02} 💬 {}", self.comment_no, comment);

        self
    }

    /// register the signer in the aggregator client
    pub async fn register_signers(
        &mut self,
        signers_with_stake: &[SignerWithStake],
    ) -> Result<&mut Self> {
        let epoch = self
            .chain_observer
            .current_time_point
            .read()
            .await
            .as_ref()
            .unwrap()
            .epoch;
        for signer_with_stake in signers_with_stake {
            let signer: Signer = signer_with_stake.clone().into();
            self.fake_aggregator.register_signer(epoch, signer.into()).await;
        }

        Ok(self)
    }

    /// Check when the era_checker has been updated
    pub async fn check_era_checker_last_updated_at(&mut self, epoch: Epoch) -> Result<&mut Self> {
        self.assert(
            self.era_checker.current_epoch() == epoch,
            format!("The epoch the EraChecker has been the last updated '{}' is different from expected epoch '{}'.", self.era_checker.current_epoch(), epoch)
        )
    }

    /// Set Era markers
    pub fn set_era_markers(&mut self, markers: Vec<EraMarker>) -> &mut Self {
        debug!("Era markers set: {:?}", markers);
        self.era_reader_adapter.set_markers(markers);

        self
    }

    fn parse_exported_metrics(metrics_service: &MetricsService) -> Result<BTreeMap<String, Value>> {
        Ok(prometheus_parse::Scrape::parse(
            metrics_service.export_metrics()?.lines().map(|s| Ok(s.to_owned())),
        )
        .map_err(|e| TestError::ValueError(e.to_string()))?
        .samples
        .into_iter()
        .map(|s| (s.metric, s.value))
        .collect::<BTreeMap<_, _>>())
    }

    pub fn check_total_signature_registrations_metrics(
        &mut self,
        expected_metric: u32,
    ) -> Result<&mut Self> {
        let metric = self
            .metrics_service
            .get_signature_registration_success_since_startup_counter()
            .get();

        self.assert(
            expected_metric == metric,
            format!("Total signature registrations metric: given {metric:?}, expected {expected_metric:?}"),
        )
    }

    // Check that the metrics service exports the expected metrics
    pub async fn check_metrics(
        &mut self,
        total_signer_registrations_expected: u64,
        total_signature_registrations_expected: u64,
    ) -> Result<&mut Self> {
        let metrics = Self::parse_exported_metrics(&self.metrics_service)?;
        let mut expected_metrics = Self::parse_exported_metrics(&self.expected_metrics_service)?;
        expected_metrics.insert(
            self.metrics_service
                .get_signature_registration_success_last_epoch_gauge()
                .name(),
            Value::Gauge(self.current_epoch().await?.0 as f64),
        );
        expected_metrics.insert(
            self.metrics_service
                .get_signature_registration_success_since_startup_counter()
                .name(),
            Value::Counter(total_signature_registrations_expected as f64),
        );
        expected_metrics.insert(
            self.metrics_service
                .get_signature_registration_total_since_startup_counter()
                .name(),
            Value::Counter(total_signature_registrations_expected as f64),
        );
        expected_metrics.insert(
            self.metrics_service
                .get_signer_registration_success_last_epoch_gauge()
                .name(),
            Value::Gauge(self.current_epoch().await?.0 as f64),
        );
        expected_metrics.insert(
            self.metrics_service
                .get_signer_registration_success_since_startup_counter()
                .name(),
            Value::Counter(total_signer_registrations_expected as f64),
        );
        expected_metrics.insert(
            self.metrics_service
                .get_signer_registration_total_since_startup_counter()
                .name(),
            Value::Counter(total_signer_registrations_expected as f64),
        );
        self.assert(
            expected_metrics == metrics,
            format!("Metrics service should export expected metrics: given {metrics:?}, expected {expected_metrics:?}"),
        )?;

        Ok(self)
    }

    pub fn check_last_signed_beacon(
        &mut self,
        expected_beacon: Option<SignedEntityType>,
    ) -> Result<&mut Self> {
        let last_signed_beacon = self
            .signed_beacon_repository
            .get_last()?
            .map(|b| b.signed_entity_type);

        self.assert(
            expected_beacon == last_signed_beacon,
            format!(
                "Last signed beacon: given {last_signed_beacon:?}, expected {expected_beacon:?}"
            ),
        )
    }
}
