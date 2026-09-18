use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug, warn};
use thiserror::Error;
use tokio::sync::RwLockReadGuard;

use mithril_common::StdResult;
use mithril_common::crypto_helper::{OpCert, ProtocolOpCert, SerDeShelleyFileFormat};
use mithril_common::entities::{
    Epoch, PartyId, ProtocolMessage, SignedEntityType, Signer, TimePoint,
};
use mithril_common::logging::LoggerExtensions;
use mithril_protocol_config::model::MithrilNetworkConfiguration;

use crate::Configuration;
use crate::dependency_injection::SignerDependencyContainer;
use crate::entities::{BeaconToSign, RegisteredSigners};
use crate::services::{EpochService, MithrilProtocolInitializerBuilder};

/// This trait is mainly intended for mocking.
#[async_trait]
pub trait Runner: Send + Sync {
    /// Fetch the configuration parameters of the Mithril network
    async fn get_mithril_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration>;

    /// Fetch the current epoch settings if any.
    async fn get_signer_registrations_from_aggregator(&self) -> StdResult<RegisteredSigners>;

    /// Fetch the beacon to sign if any.
    async fn get_beacon_to_sign(&self, time_point: TimePoint) -> StdResult<Option<BeaconToSign>>;

    /// Fetch the current time point from the Cardano node.
    async fn get_current_time_point(&self) -> StdResult<TimePoint>;

    /// Register the signer verification key to the aggregator.
    async fn register_signer_to_aggregator(&self) -> StdResult<()>;

    /// Read the stake distribution and store it.
    async fn update_stake_distribution(&self, epoch: Epoch) -> StdResult<()>;

    /// Check if the signer can sign the current epoch.
    async fn can_sign_current_epoch(&self) -> StdResult<bool>;

    /// Register epoch information
    async fn inform_epoch_settings(
        &self,
        aggregator_signer_registration_epoch: Epoch,
        mithril_network_configuration: MithrilNetworkConfiguration,
        current_signer: Vec<Signer>,
        next_signer: Vec<Signer>,
    ) -> StdResult<()>;

    /// Create the message to be signed with the single signature.
    async fn compute_message(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<ProtocolMessage>;

    /// Create the single signature.
    async fn compute_publish_single_signature(
        &self,
        beacon_to_sign: &BeaconToSign,
        message: &ProtocolMessage,
    ) -> StdResult<()>;

    /// Read the current era and update the EraChecker.
    async fn update_era_checker(&self, epoch: Epoch) -> StdResult<()>;

    /// Perform the upkeep tasks.
    async fn upkeep(&self, current_epoch: Epoch) -> StdResult<()>;
}

/// This type represents the errors thrown from the Runner.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RunnerError {
    /// Value was expected from a subsystem but None was returned.
    #[error("No value returned by the subsystem for `{0}`.")]
    NoValueError(String),
    /// Could not associate my node with a stake.
    #[error("No stake associated with myself.")]
    NoStakeForSelf(),
    /// Could not find the stake for one of the signers.
    #[error("No stake associated with this signer, party_id: {0}.")]
    NoStakeForSigner(PartyId),
    /// Parse file error
    #[error("File parse failed: {0}.")]
    FileParse(String),
}

/// Controller methods for the Signer's state machine.
pub struct SignerRunner {
    config: Configuration,
    services: SignerDependencyContainer,
    logger: Logger,
}

impl SignerRunner {
    /// Create a new Runner instance.
    pub fn new(config: Configuration, services: SignerDependencyContainer, logger: Logger) -> Self {
        Self {
            services,
            config,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn epoch_service_read(&self) -> RwLockReadGuard<'_, dyn EpochService> {
        self.services.epoch_service.read().await
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
impl Runner for SignerRunner {
    async fn get_mithril_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration> {
        debug!(self.logger, ">> get_mithril_network_configuration");

        self.services
            .network_configuration_service
            .get_network_configuration(epoch)
            .await
    }

    async fn get_signer_registrations_from_aggregator(&self) -> StdResult<RegisteredSigners> {
        debug!(self.logger, ">> get_epoch_settings");

        self.services
            .signers_registration_retriever
            .retrieve_all_signer_registrations()
            .await
    }

    async fn get_beacon_to_sign(&self, time_point: TimePoint) -> StdResult<Option<BeaconToSign>> {
        debug!(
            self.logger,
            ">> get_beacon_to_sign(time_point: {time_point})"
        );

        self.services.certifier.get_beacon_to_sign(time_point).await
    }

    async fn get_current_time_point(&self) -> StdResult<TimePoint> {
        debug!(self.logger, ">> get_current_time_point");

        self.services
            .ticker_service
            .get_current_time_point()
            .await
            .with_context(|| "Runner can not get current time point")
    }

    async fn register_signer_to_aggregator(&self) -> StdResult<()> {
        debug!(self.logger, ">> register_signer_to_aggregator");

        let (epoch, protocol_parameters) = {
            let epoch_service = self.services.epoch_service.read().await;
            let epoch = epoch_service.epoch_of_current_data()?;
            let protocol_parameters = epoch_service.registration_protocol_parameters()?;

            (epoch, protocol_parameters.clone())
        };

        let epoch_offset_to_recording_epoch = epoch.offset_to_recording_epoch();
        let stake_distribution = self
            .services
            .stake_store
            .get_stakes(epoch_offset_to_recording_epoch)
            .await?
            .ok_or_else(|| {
                RunnerError::NoValueError(format!(
                    "stakes at epoch {epoch_offset_to_recording_epoch}"
                ))
            })?;
        let stake = stake_distribution
            .get(&self.services.single_signer.get_party_id())
            .ok_or_else(RunnerError::NoStakeForSelf)?;
        let (operational_certificate, protocol_operational_certificate) = match &self
            .config
            .operational_certificate_path
        {
            Some(operational_certificate_path) => {
                let opcert: OpCert = OpCert::from_file(operational_certificate_path)
                    .map_err(|_| RunnerError::FileParse("operational_certificate_path".to_string()))
                    .with_context(
                        || "register_signer_to_aggregator can not decode OpCert from file",
                    )?;
                (Some(opcert.clone()), Some(ProtocolOpCert::new(opcert)))
            }
            _ => (None, None),
        };
        let current_kes_period = self.services.chain_observer.get_current_kes_period().await?;
        let kes_evolutions = operational_certificate.map(|operational_certificate| {
            current_kes_period.unwrap_or_default() - operational_certificate.get_start_kes_period()
        });

        let protocol_initializer = self
            .services
            .protocol_initializer_store
            .get_protocol_initializer(epoch_offset_to_recording_epoch)
            .await
            .with_context(
                || "register_signer_to_aggregator can not retrieve protocol initializer from store",
            )?;

        if protocol_initializer.is_none() {
            let protocol_initializer = MithrilProtocolInitializerBuilder::build(
                stake,
                &protocol_parameters,
                self.services.kes_signer.clone(),
                current_kes_period,
                #[cfg(feature = "future_snark")]
                epoch_offset_to_recording_epoch,
            )?;

            let signer = Signer {
                party_id: self.services.single_signer.get_party_id(),
                verification_key_for_concatenation: protocol_initializer
                    .verification_key_for_concatenation()
                    .into(),
                verification_key_signature_for_concatenation: protocol_initializer
                    .verification_key_signature_for_concatenation(),
                operational_certificate: protocol_operational_certificate,
                kes_evolutions,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: protocol_initializer
                    .verification_key_for_snark()
                    .map(Into::into),
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: protocol_initializer
                    .verification_key_signature_for_snark(),
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: protocol_initializer
                    .proof_of_bound_possession_for_snark(),
            };
            self.services
                .signer_registration_publisher
                .register_signer(epoch_offset_to_recording_epoch, &signer)
                .await?;

            self.services
                .protocol_initializer_store
                .save_protocol_initializer(epoch_offset_to_recording_epoch, protocol_initializer)
                .await?;
        }

        Ok(())
    }

    async fn update_stake_distribution(&self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> update_stake_distribution(epoch: {epoch})");

        let exists_stake_distribution = !self
            .services
            .stake_store
            .get_stakes(epoch.offset_to_recording_epoch())
            .await?
            .unwrap_or_default()
            .is_empty();
        if exists_stake_distribution {
            return Ok(());
        }

        let stake_distribution = self
            .services
            .chain_observer
            .get_current_stake_distribution()
            .await?
            .ok_or_else(|| RunnerError::NoValueError("current_stake_distribution".to_string()))?;
        self.services
            .stake_store
            .save_stakes(epoch.offset_to_recording_epoch(), stake_distribution)
            .await?;

        Ok(())
    }

    async fn can_sign_current_epoch(&self) -> StdResult<bool> {
        let epoch_service = self.epoch_service_read().await;
        epoch_service.can_signer_sign_current_epoch(self.services.single_signer.get_party_id())
    }

    async fn inform_epoch_settings(
        &self,
        aggregator_signer_registration_epoch: Epoch,
        mithril_network_configuration: MithrilNetworkConfiguration,
        current_signer: Vec<Signer>,
        next_signer: Vec<Signer>,
    ) -> StdResult<()> {
        debug!(
            self.logger,
            ">> inform_epoch_settings(epoch:{})", aggregator_signer_registration_epoch
        );

        self.services
            .epoch_service
            .write()
            .await
            .inform_epoch_settings(
                aggregator_signer_registration_epoch,
                mithril_network_configuration,
                current_signer,
                next_signer,
            )
            .await
    }

    async fn compute_message(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<ProtocolMessage> {
        debug!(self.logger, ">> compute_message({signed_entity_type:?})");

        let protocol_message = self
            .services
            .signable_builder_service
            .compute_protocol_message(signed_entity_type.to_owned())
            .await
            .with_context(|| format!("Runner can not compute protocol message for signed entity type: '{signed_entity_type}'"))?;

        Ok(protocol_message)
    }

    async fn compute_publish_single_signature(
        &self,
        beacon_to_sign: &BeaconToSign,
        message: &ProtocolMessage,
    ) -> StdResult<()> {
        debug!(self.logger, ">> compute_publish_single_signature"; "beacon_to_sign" => ?beacon_to_sign);
        self.services
            .certifier
            .compute_publish_single_signature(beacon_to_sign, message)
            .await
    }

    async fn update_era_checker(&self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> update_era_checker(epoch:{epoch})");

        let era_token = self
            .services
            .era_reader
            .read_era_epoch_token(epoch)
            .await
            .map_err(Box::new)?;
        let current_era = era_token.get_current_supported_era()?;
        self.services
            .era_checker
            .change_era(current_era, era_token.get_current_epoch());
        debug!(
            self.logger,
            "Current Era is {} (Epoch {}).",
            current_era,
            era_token.get_current_epoch()
        );

        if era_token.get_next_supported_era().is_err() {
            let era_name = &era_token.get_next_era_marker().unwrap().name;
            warn!(
                self.logger,
                "Upcoming Era '{era_name}' is not supported by this version of the software. Please update!"
            );
        }

        Ok(())
    }

    async fn upkeep(&self, current_epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> upkeep(current_epoch:{current_epoch})");
        self.services.upkeep_service.run(current_epoch).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::{path::Path, sync::Arc};

    use mockall::predicate::eq;
    use tokio::sync::RwLock;

    use mithril_cardano_node_chain::chain_importer::CardanoChainDataImporter;
    use mithril_cardano_node_chain::test::double::{
        DumbBlockScanner, FakeChainObserver, InMemoryChainDataStore,
    };
    use mithril_cardano_node_internal_database::{
        signable_builder::CardanoDatabaseSignableBuilder,
        test::double::{DumbImmutableDigester, DumbImmutableFileObserver},
    };
    use mithril_common::{
        api_version::APIVersionProvider,
        crypto_helper::MKTreeStoreInMemory,
        entities::{BlockNumber, Epoch, SignedEntityTypeDiscriminants},
        signable_builder::{
            CardanoBlocksTransactionsSignableBuilder, CardanoStakeDistributionSignableBuilder,
            CardanoTransactionsSignableBuilder, MithrilSignableBuilderService,
            MithrilStakeDistributionSignableBuilder, SignableBuilderServiceDependencies,
        },
        test::{
            builder::MithrilFixtureBuilder,
            double::{Dummy, fake_data},
        },
    };
    use mithril_era::{EraChecker, EraReader, adapters::EraReaderBootstrapAdapter};
    use mithril_protocol_config::model::MithrilNetworkConfigurationForEpoch;
    use mithril_protocol_config::test::double::configuration_provider::FakeMithrilNetworkConfigurationProvider;
    use mithril_signed_entity_lock::SignedEntityTypeLock;
    use mithril_signed_entity_preloader::{
        CardanoTransactionsPreloader, CardanoTransactionsPreloaderActivation,
    };
    use mithril_ticker::{MithrilTickerService, TickerService};

    use crate::database::repository::{
        ProtocolInitializerRepository, SignedBeaconRepository, StakePoolStore,
    };
    use crate::database::test_helper::main_db_connection;
    use crate::metrics::MetricsService;
    use crate::services::{
        MithrilEpochService, MithrilSingleSigner, MockUpkeepService, SignaturePublisherNoop,
        SignerCertifierService, SignerChainDataImporter, SignerSignableSeedBuilder,
        SignerSignedEntityConfigProvider,
    };
    use crate::test::TestLogger;
    use crate::test::double::mocks::{
        MockBlockRangeRootRetriever, MockFakeTimePointProvider, MockLegacyBlockRangeRootRetriever,
    };
    use crate::test::double::{DumbSignersRegistrationRetriever, SpySignerRegistrationPublisher};

    use super::*;

    const DIGESTER_RESULT: &str = "a digest";

    async fn init_services() -> SignerDependencyContainer {
        let logger = TestLogger::stdout();
        let sqlite_connection = Arc::new(main_db_connection().unwrap());
        let stake_distribution_signers = fake_data::signers_with_stakes(2);
        let party_id = stake_distribution_signers[1].party_id.clone();
        let fake_observer = FakeChainObserver::default();
        fake_observer.set_signers(stake_distribution_signers).await;
        let chain_observer = Arc::new(fake_observer);
        let ticker_service = Arc::new(MithrilTickerService::new(
            chain_observer.clone(),
            Arc::new(DumbImmutableFileObserver::default()),
        ));
        let era_reader = Arc::new(EraReader::new(Arc::new(EraReaderBootstrapAdapter)));
        let era_epoch_token = era_reader
            .read_era_epoch_token(ticker_service.get_current_epoch().await.unwrap())
            .await
            .unwrap();
        let era_checker = Arc::new(EraChecker::new(
            era_epoch_token.get_current_supported_era().unwrap(),
            era_epoch_token.get_current_epoch(),
        ));

        let api_version_provider = Arc::new(APIVersionProvider::new(era_checker.clone()));
        let digester = Arc::new(DumbImmutableDigester::default().with_digest(DIGESTER_RESULT));
        let mithril_stake_distribution_signable_builder =
            Arc::new(MithrilStakeDistributionSignableBuilder::default());
        let transaction_parser = Arc::new(DumbBlockScanner::new());
        let transaction_store = Arc::new(InMemoryChainDataStore::default());
        let transactions_importer = Arc::new(SignerChainDataImporter::new(Arc::new(
            CardanoChainDataImporter::new(
                transaction_parser.clone(),
                transaction_store.clone(),
                logger.clone(),
            ),
        )));
        let legacy_block_range_root_retriever =
            Arc::new(MockLegacyBlockRangeRootRetriever::<MKTreeStoreInMemory>::new());
        let cardano_transactions_builder = Arc::new(CardanoTransactionsSignableBuilder::new(
            transactions_importer.clone(),
            legacy_block_range_root_retriever,
        ));
        let block_range_root_retriever =
            Arc::new(MockBlockRangeRootRetriever::<MKTreeStoreInMemory>::new());
        let cardano_blocks_transactions_builder =
            Arc::new(CardanoBlocksTransactionsSignableBuilder::new(
                transactions_importer.clone(),
                block_range_root_retriever,
            ));
        let stake_store = Arc::new(StakePoolStore::new(sqlite_connection.clone(), None));
        let cardano_stake_distribution_builder = Arc::new(
            CardanoStakeDistributionSignableBuilder::new(stake_store.clone()),
        );
        let cardano_database_signable_builder = Arc::new(CardanoDatabaseSignableBuilder::new(
            digester.clone(),
            Path::new(""),
            logger.clone(),
        ));
        let protocol_initializer_store = Arc::new(ProtocolInitializerRepository::new(
            sqlite_connection.clone(),
            None,
        ));
        let epoch_service = Arc::new(RwLock::new(MithrilEpochService::new(
            era_checker.clone(),
            stake_store.clone(),
            protocol_initializer_store.clone(),
            logger.clone(),
        )));
        let single_signer = Arc::new(MithrilSingleSigner::new(
            party_id,
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
            #[cfg(feature = "future_snark")]
            era_checker.clone(),
        );
        let signable_builder_service = Arc::new(MithrilSignableBuilderService::new(
            signable_seed_builder_service,
            signable_builders_dependencies,
            logger.clone(),
        ));
        let metrics_service = Arc::new(MetricsService::new(logger.clone()).unwrap());
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let security_parameter = BlockNumber(0);
        let cardano_transactions_preloader = Arc::new(CardanoTransactionsPreloader::new(
            signed_entity_type_lock.clone(),
            transactions_importer.clone(),
            security_parameter,
            chain_observer.clone(),
            logger.clone(),
            Arc::new(CardanoTransactionsPreloaderActivation::new(true)),
        ));
        let upkeep_service = Arc::new(MockUpkeepService::new());
        let certifier = Arc::new(SignerCertifierService::new(
            Arc::new(SignedBeaconRepository::new(sqlite_connection.clone(), None)),
            Arc::new(SignerSignedEntityConfigProvider::new(epoch_service.clone())),
            signed_entity_type_lock.clone(),
            single_signer.clone(),
            Arc::new(SignaturePublisherNoop),
            logger.clone(),
        ));
        let kes_signer = None;

        let configuration_for_aggregation = MithrilNetworkConfigurationForEpoch::dummy();
        let configuration_for_next_aggregation = MithrilNetworkConfigurationForEpoch::dummy();
        let configuration_for_registration = MithrilNetworkConfigurationForEpoch::dummy();

        let network_configuration_service = Arc::new(FakeMithrilNetworkConfigurationProvider::new(
            configuration_for_aggregation,
            configuration_for_next_aggregation,
            configuration_for_registration,
        ));

        SignerDependencyContainer {
            stake_store,
            chain_observer,
            digester,
            single_signer,
            ticker_service,
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
            signer_registration_publisher: Arc::new(SpySignerRegistrationPublisher::default()),
            signers_registration_retriever: Arc::new(DumbSignersRegistrationRetriever::default()),
            kes_signer,
            network_configuration_service,
        }
    }

    async fn init_runner(
        maybe_services: Option<SignerDependencyContainer>,
        maybe_config: Option<Configuration>,
    ) -> SignerRunner {
        SignerRunner::new(
            maybe_config.unwrap_or(Configuration::new_sample("1")),
            maybe_services.unwrap_or(init_services().await),
            TestLogger::stdout(),
        )
    }

    #[tokio::test]
    async fn test_get_current_time_point() {
        let mut services = init_services().await;
        let expected = TimePoint::dummy();
        let mut ticker_service = MockFakeTimePointProvider::new();
        ticker_service
            .expect_get_current_time_point()
            .once()
            .returning(move || Ok(TimePoint::dummy()));
        services.ticker_service = Arc::new(ticker_service);
        let runner = init_runner(Some(services), None).await;

        assert_eq!(
            expected,
            runner
                .get_current_time_point()
                .await
                .expect("Get current time point should not fail.")
        );
    }

    #[tokio::test]
    async fn test_update_stake_distribution() {
        let services = init_services().await;
        let stake_store = services.stake_store.clone();
        let current_epoch = services
            .chain_observer
            .get_current_epoch()
            .await
            .expect("chain observer should not fail")
            .expect("the observer should return an epoch");
        let runner = init_runner(Some(services), None).await;
        assert!(
            stake_store
                .get_stakes(current_epoch)
                .await
                .expect("getting stakes from store should not fail")
                .is_none()
        );

        runner
            .update_stake_distribution(current_epoch)
            .await
            .expect("update_stake_distribution should not fail.");

        let stake_distribution = stake_store
            .get_stakes(current_epoch.offset_to_recording_epoch())
            .await
            .expect("getting stakes from store should not fail")
            .expect("there should be stakes for this epoch");

        assert_eq!(2, stake_distribution.len());
    }

    #[tokio::test]
    async fn test_register_signer_to_aggregator() {
        let mut services = init_services().await;
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let registration_publisher_spy = Arc::new(SpySignerRegistrationPublisher::default());
        services.signer_registration_publisher = registration_publisher_spy.clone();
        let protocol_initializer_store = services.protocol_initializer_store.clone();
        let current_epoch = services.ticker_service.get_current_epoch().await.unwrap();

        let stakes = services
            .chain_observer
            .get_current_stake_distribution()
            .await
            .unwrap()
            .unwrap();
        services
            .stake_store
            .save_stakes(current_epoch.offset_to_recording_epoch(), stakes)
            .await
            .unwrap();

        let runner = init_runner(Some(services), None).await;

        let mithril_network_configuration = MithrilNetworkConfiguration {
            epoch: current_epoch,
            ..MithrilNetworkConfiguration::dummy()
        };

        runner
            .inform_epoch_settings(
                current_epoch,
                mithril_network_configuration,
                fixture.signers(),
                fixture.signers(),
            )
            .await
            .unwrap();

        runner
            .register_signer_to_aggregator()
            .await
            .expect("registering a signer to the aggregator should not fail");

        let last_registered_signer_first_registration =
            registration_publisher_spy.get_last_registered_signer().await.unwrap();
        let maybe_protocol_initializer_first_registration = protocol_initializer_store
            .get_protocol_initializer(current_epoch.offset_to_recording_epoch())
            .await
            .expect("get_protocol_initializer should not fail");
        assert!(
            maybe_protocol_initializer_first_registration.is_some(),
            "A protocol initializer should have been registered at the 'Recording' epoch"
        );

        let total_registered_signers =
            registration_publisher_spy.get_total_registered_signers().await;
        assert_eq!(1, total_registered_signers);

        runner
            .register_signer_to_aggregator()
            .await
            .expect("registering a signer to the aggregator should not fail");

        let last_registered_signer_second_registration =
            registration_publisher_spy.get_last_registered_signer().await.unwrap();
        let maybe_protocol_initializer_second_registration = protocol_initializer_store
            .get_protocol_initializer(current_epoch.offset_to_recording_epoch())
            .await
            .expect("get_protocol_initializer should not fail");
        assert!(
            maybe_protocol_initializer_second_registration.is_some(),
            "A protocol initializer should have been registered at the 'Recording' epoch"
        );
        assert_eq!(
            serde_json::to_string(&last_registered_signer_first_registration).unwrap(),
            serde_json::to_string(&last_registered_signer_second_registration).unwrap(),
            "The signer registration should be the same and should have been registered twice"
        );

        let total_registered_signers =
            registration_publisher_spy.get_total_registered_signers().await;
        assert_eq!(1, total_registered_signers);
    }

    #[tokio::test]
    async fn test_update_era_checker() {
        let services = init_services().await;
        let ticker_service = services.ticker_service.clone();
        let era_checker = services.era_checker.clone();
        let mut time_point = ticker_service.get_current_time_point().await.unwrap();

        assert_eq!(time_point.epoch, era_checker.current_epoch());
        let runner = init_runner(Some(services), None).await;
        time_point.epoch += 1;
        runner.update_era_checker(time_point.epoch).await.unwrap();

        assert_eq!(time_point.epoch, era_checker.current_epoch());
    }

    #[tokio::test]
    async fn test_upkeep() {
        let mut services = init_services().await;
        let mut upkeep_service_mock = MockUpkeepService::new();
        upkeep_service_mock
            .expect_run()
            .with(eq(Epoch(17)))
            .returning(|_| Ok(()))
            .once();
        services.upkeep_service = Arc::new(upkeep_service_mock);

        let runner = init_runner(Some(services), None).await;
        runner.upkeep(Epoch(17)).await.expect("upkeep should not fail");
    }

    #[tokio::test]
    async fn test_inform_epoch_setting_pass_available_signed_entity_types_to_epoch_service() {
        let services = init_services().await;
        let runner = init_runner(Some(services), None).await;

        let epoch = Epoch(1);
        let signers = fake_data::signers(5);
        let current_signers = signers[1..3].to_vec();
        let next_signers = signers[2..5].to_vec();

        let mithril_network_configuration = MithrilNetworkConfiguration {
            epoch,
            configuration_for_aggregation: MithrilNetworkConfigurationForEpoch {
                enabled_signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoTransactions,
                ]),
                ..Dummy::dummy()
            },
            ..Dummy::dummy()
        };

        runner
            .inform_epoch_settings(
                epoch,
                mithril_network_configuration,
                current_signers,
                next_signers,
            )
            .await
            .unwrap();

        let epoch_service = runner.services.epoch_service.read().await;
        let recorded_allowed_discriminants = epoch_service.allowed_discriminants().unwrap();

        assert_eq!(
            &BTreeSet::from([
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            recorded_allowed_discriminants
        );
    }
}
