use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug, warn};
use std::sync::Arc;
use std::time::Duration;

use mithril_common::StdResult;
use mithril_common::entities::{Certificate, Epoch, ProtocolMessage, SignedEntityType, TimePoint};
use mithril_common::logging::LoggerExtensions;
use mithril_persistence::store::StakeStorer;

use crate::ServeCommandDependenciesContainer;
use crate::entities::OpenMessage;

/// Configuration structure dedicated to the AggregatorRuntime.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Interval between each snapshot, in ms
    pub interval: Duration,

    /// Whether the aggregator is a follower
    pub is_follower: bool,
}

impl AggregatorConfig {
    /// Create a new instance of AggregatorConfig.
    pub fn new(interval: Duration, is_follower: bool) -> Self {
        Self {
            interval,
            is_follower,
        }
    }
}

/// This trait is intended to allow mocking the AggregatorRunner in tests.
/// It exposes all the methods needed by the state machine.
#[async_trait]
pub trait AggregatorRunnerTrait: Sync + Send {
    /// Return the current [TimePoint] from the chain
    async fn get_time_point_from_chain(&self) -> StdResult<TimePoint>;

    /// Retrieves the current open message for a given signed entity type.
    async fn get_current_open_message_for_signed_entity_type(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<OpenMessage>>;

    /// Retrieves the current non-certified open message.
    async fn get_current_non_certified_open_message(
        &self,
        current_time_point: &TimePoint,
    ) -> StdResult<Option<OpenMessage>>;

    /// Returns the epoch of the last genesis certificate, if any.
    async fn last_genesis_certificate_epoch(&self) -> StdResult<Option<Epoch>>;

    /// Check if a certificate chain is valid.
    async fn is_certificate_chain_valid(&self, time_point: &TimePoint) -> StdResult<()>;

    /// Read the stake distribution from the blockchain and store it.
    async fn update_stake_distribution(&self, new_time_point: &TimePoint) -> StdResult<()>;

    /// Open the signer registration round of an epoch.
    async fn open_signer_registration_round(&self, new_time_point: &TimePoint) -> StdResult<()>;

    /// Close the signer registration round of an epoch.
    async fn close_signer_registration_round(&self) -> StdResult<()>;

    /// Check if the follower aggregator is running the same epoch as the leader.
    async fn is_follower_aggregator_at_same_epoch_as_leader(
        &self,
        time_point: &TimePoint,
    ) -> StdResult<bool>;

    /// Synchronize the follower aggregator signer registration.
    async fn synchronize_follower_aggregator_signer_registration(&self) -> StdResult<()>;

    /// Synchronize the follower aggregator certificate chain
    async fn synchronize_follower_aggregator_certificate_chain(
        &self,
        time_point: &TimePoint,
        force_sync: bool,
    ) -> StdResult<()>;

    /// Compute the protocol message
    async fn compute_protocol_message(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<ProtocolMessage>;

    /// Mark expired open message.
    async fn mark_open_message_if_expired(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<OpenMessage>>;

    /// Tell the certifier to try to create a new certificate.
    async fn create_certificate(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<Certificate>>;

    /// Create an artifact and persist it.
    async fn create_artifact(
        &self,
        signed_entity_type: &SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<()>;

    /// Update the EraChecker with EraReader information.
    async fn update_era_checker(&self, epoch: Epoch) -> StdResult<()>;

    /// Ask services to update themselves for the new epoch
    async fn inform_new_epoch(&self, epoch: Epoch) -> StdResult<()>;

    /// Perform the upkeep tasks.
    async fn upkeep(&self, epoch: Epoch) -> StdResult<()>;

    /// Precompute what doesn't change for the actual epoch
    async fn precompute_epoch_data(&self) -> StdResult<()>;

    /// Create new open message
    async fn create_open_message(
        &self,
        signed_entity_type: &SignedEntityType,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<OpenMessage>;

    /// Checks if the open message is considered outdated.
    async fn is_open_message_outdated(
        &self,
        open_message_signed_entity_type: SignedEntityType,
        last_time_point: &TimePoint,
    ) -> StdResult<bool>;

    /// Increment the runtime cycle success metric.
    fn increment_runtime_cycle_success_since_startup_counter(&self);

    /// Increment the runtime cycle total metric.
    fn increment_runtime_cycle_total_since_startup_counter(&self);
}

/// The runner responsibility is to expose a code API for the state machine. It
/// holds services and configuration.
pub struct AggregatorRunner {
    dependencies: Arc<ServeCommandDependenciesContainer>,
    logger: Logger,
}

impl AggregatorRunner {
    /// Create a new instance of the Aggregator Runner.
    pub fn new(dependencies: Arc<ServeCommandDependenciesContainer>) -> Self {
        let logger = dependencies.root_logger.new_with_component_name::<Self>();
        Self {
            dependencies,
            logger,
        }
    }

    async fn list_available_signed_entity_types(
        &self,
        time_point: &TimePoint,
    ) -> StdResult<Vec<SignedEntityType>> {
        let signed_entity_types = self
            .dependencies
            .epoch_service
            .read()
            .await
            .signed_entity_config()?
            .list_allowed_signed_entity_types(time_point)?;
        let unlocked_signed_entities = self
            .dependencies
            .signed_entity_type_lock
            .filter_unlocked_entries(signed_entity_types)
            .await;

        Ok(unlocked_signed_entities)
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
impl AggregatorRunnerTrait for AggregatorRunner {
    /// Return the current time point from the chain
    async fn get_time_point_from_chain(&self) -> StdResult<TimePoint> {
        debug!(self.logger, ">> get_time_point_from_chain");
        let time_point = self.dependencies.ticker_service.get_current_time_point().await?;

        Ok(time_point)
    }

    async fn get_current_open_message_for_signed_entity_type(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<OpenMessage>> {
        debug!(self.logger,">> get_current_open_message_for_signed_entity_type"; "signed_entity_type" => ?signed_entity_type);
        self.mark_open_message_if_expired(signed_entity_type).await?;

        Ok(self
            .dependencies
            .certifier_service
            .get_open_message(signed_entity_type)
            .await
            .with_context(|| format!("CertifierService can not get open message for signed_entity_type: '{signed_entity_type}'"))?)
    }

    async fn get_current_non_certified_open_message(
        &self,
        current_time_point: &TimePoint,
    ) -> StdResult<Option<OpenMessage>> {
        debug!(self.logger,">> get_current_non_certified_open_message"; "time_point" => #?current_time_point);
        let signed_entity_types =
            self.list_available_signed_entity_types(current_time_point).await?;

        for signed_entity_type in signed_entity_types {
            let current_open_message = self.get_current_open_message_for_signed_entity_type(&signed_entity_type)
                .await
                .with_context(|| format!("AggregatorRunner can not get current open message for signed entity type: '{}'", signed_entity_type))?;
            match current_open_message {
                None => {
                    let protocol_message = self.compute_protocol_message(&signed_entity_type).await.with_context(|| format!("AggregatorRunner can not compute protocol message for signed_entity_type: '{signed_entity_type}'"))?;
                    let open_message_new = self.create_open_message(&signed_entity_type, &protocol_message)
                        .await
                        .with_context(|| format!("AggregatorRunner can not create open message for signed_entity_type: '{signed_entity_type}'"))?;

                    return Ok(Some(open_message_new));
                }
                Some(open_message) => {
                    if !open_message.is_certified && !open_message.is_expired {
                        return Ok(Some(open_message));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn last_genesis_certificate_epoch(&self) -> StdResult<Option<Epoch>> {
        debug!(self.logger, ">> last_genesis_certificate_epoch");
        let epoch = self
            .dependencies
            .certificate_repository
            .get_latest_genesis_certificate::<Certificate>()
            .await?
            .map(|c| c.epoch);
        Ok(epoch)
    }

    async fn is_certificate_chain_valid(&self, time_point: &TimePoint) -> StdResult<()> {
        debug!(self.logger, ">> is_certificate_chain_valid");
        self.dependencies
            .certifier_service
            .verify_certificate_chain(time_point.epoch)
            .await?;

        Ok(())
    }

    async fn update_stake_distribution(&self, new_time_point: &TimePoint) -> StdResult<()> {
        debug!(self.logger,">> update_stake_distribution"; "time_point" => #?new_time_point);
        self.dependencies
            .stake_distribution_service
            .update_stake_distribution()
            .await
            .with_context(|| format!("AggregatorRunner could not update stake distribution for time_point: '{new_time_point}'"))
    }

    async fn open_signer_registration_round(&self, new_time_point: &TimePoint) -> StdResult<()> {
        debug!(self.logger,">> open_signer_registration_round"; "time_point" => #?new_time_point);
        let registration_epoch = new_time_point.epoch.offset_to_recording_epoch();

        let stakes = self
            .dependencies
            .stake_store
            .get_stakes(registration_epoch)
            .await?
            .unwrap_or_default();

        self.dependencies
            .signer_registration_round_opener
            .open_registration_round(registration_epoch, stakes)
            .await
    }

    async fn close_signer_registration_round(&self) -> StdResult<()> {
        debug!(self.logger, ">> close_signer_registration_round");
        self.dependencies
            .signer_registration_round_opener
            .close_registration_round()
            .await
    }

    async fn is_follower_aggregator_at_same_epoch_as_leader(
        &self,
        time_point: &TimePoint,
    ) -> StdResult<bool> {
        self.dependencies
            .signer_synchronizer
            .can_synchronize_signers(time_point.epoch)
            .await
            .map_err(|e| e.into())
    }

    async fn synchronize_follower_aggregator_signer_registration(&self) -> StdResult<()> {
        self.dependencies
            .signer_synchronizer
            .synchronize_all_signers()
            .await
            .map_err(|e| e.into())
    }

    async fn compute_protocol_message(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<ProtocolMessage> {
        debug!(self.logger, ">> compute_protocol_message");
        let protocol_message = self
            .dependencies
            .signable_builder_service
            .compute_protocol_message(signed_entity_type.to_owned())
            .await
            .with_context(|| format!("Runner can not compute protocol message for signed entity type: '{signed_entity_type}'"))?;

        Ok(protocol_message)
    }

    async fn mark_open_message_if_expired(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<OpenMessage>> {
        debug!(self.logger, ">> mark_open_message_if_expired");
        let expired_open_message = self
            .dependencies
            .certifier_service
            .mark_open_message_if_expired(signed_entity_type)
            .await
            .with_context(|| "CertifierService can not mark expired open message")?;

        debug!(
            self.logger, "Marked expired open messages";
            "expired_open_message" => ?expired_open_message
        );

        Ok(expired_open_message)
    }

    async fn create_certificate(
        &self,
        signed_entity_type: &SignedEntityType,
    ) -> StdResult<Option<Certificate>> {
        debug!(self.logger, ">> create_certificate"; "signed_entity_type" => ?signed_entity_type);

        let certificate = self.dependencies
            .certifier_service
            .create_certificate(signed_entity_type)
            .await
            .with_context(|| {
                format!(
                    "CertifierService can not create certificate for signed_entity_type: '{signed_entity_type}'"
                )
            })?;

        if certificate.is_some() {
            self.dependencies
                .metrics_service
                .get_certificate_total_produced_since_startup()
                .increment();
        }

        Ok(certificate)
    }

    async fn create_artifact(
        &self,
        signed_entity_type: &SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<()> {
        debug!(
            self.logger, ">> create_artifact";
            "signed_entity_type" => ?signed_entity_type,
            "certificate_hash" => &certificate.hash
        );

        self.dependencies
            .signed_entity_service
            .create_artifact(signed_entity_type.to_owned(), certificate)
            .await
            .with_context(|| {
                format!(
                    "SignedEntityService can not create artifact for signed_entity_type: '{signed_entity_type}' with certificate hash: '{}'",
                    certificate.hash
                )
            })?;

        Ok(())
    }

    async fn update_era_checker(&self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> update_era_checker({epoch:?})");
        let token = self
            .dependencies
            .era_reader
            .read_era_epoch_token(epoch)
            .await
            .with_context(|| {
                format!("EraReader can not get era epoch token for current epoch: '{epoch}'")
            })?;

        let current_era = token
            .get_current_supported_era()
            .with_context(|| "EraEpochToken can not get current supported era")?;
        self.dependencies
            .era_checker
            .change_era(current_era, token.get_current_epoch());
        debug!(
            self.logger,
            "Current Era is {current_era} (Epoch {}).",
            token.get_current_epoch()
        );

        if token.get_next_supported_era().is_err() {
            let era_name = &token.get_next_era_marker().unwrap().name;
            warn!(
                self.logger,
                "Upcoming Era '{era_name}' is not supported by this version of the software. Please update!"
            );
        }

        Ok(())
    }

    async fn precompute_epoch_data(&self) -> StdResult<()> {
        debug!(self.logger, ">> precompute_epoch_data");
        self.dependencies
            .epoch_service
            .write()
            .await
            .precompute_epoch_data()
            .await?;

        Ok(())
    }

    async fn inform_new_epoch(&self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> inform_new_epoch({epoch:?})");
        self.dependencies.certifier_service.inform_epoch(epoch).await?;

        self.dependencies
            .epoch_service
            .write()
            .await
            .inform_epoch(epoch)
            .await?;

        Ok(())
    }

    async fn upkeep(&self, epoch: Epoch) -> StdResult<()> {
        debug!(self.logger, ">> upkeep");
        self.dependencies.upkeep_service.run(epoch).await
    }

    async fn create_open_message(
        &self,
        signed_entity_type: &SignedEntityType,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<OpenMessage> {
        debug!(self.logger, ">> create_open_message");
        self.dependencies
            .certifier_service
            .create_open_message(signed_entity_type, protocol_message)
            .await
    }

    async fn is_open_message_outdated(
        &self,
        open_message_signed_entity_type: SignedEntityType,
        last_time_point: &TimePoint,
    ) -> StdResult<bool> {
        let current_open_message = self
            .get_current_open_message_for_signed_entity_type(
                &open_message_signed_entity_type,
            )
            .await
            .with_context(|| format!("AggregatorRuntime can not get the current open message for signed entity type: '{}'", open_message_signed_entity_type))?;
        let is_expired_open_message =
            current_open_message.as_ref().map(|om| om.is_expired).unwrap_or(false);

        let exists_newer_open_message = {
            let new_signed_entity_type = self
                .dependencies
                .epoch_service
                .read()
                .await
                .signed_entity_config()?
                .time_point_to_signed_entity(&open_message_signed_entity_type, last_time_point)?;
            new_signed_entity_type != open_message_signed_entity_type
        };

        Ok(exists_newer_open_message || is_expired_open_message)
    }

    fn increment_runtime_cycle_success_since_startup_counter(&self) {
        self.dependencies
            .metrics_service
            .get_runtime_cycle_success_since_startup()
            .increment();
    }

    fn increment_runtime_cycle_total_since_startup_counter(&self) {
        self.dependencies
            .metrics_service
            .get_runtime_cycle_total_since_startup()
            .increment();
    }

    async fn synchronize_follower_aggregator_certificate_chain(
        &self,
        time_point: &TimePoint,
        force_sync: bool,
    ) -> StdResult<()> {
        debug!(
            self.logger,
            ">> synchronize_follower_aggregator_certificate_chain(force_sync:{force_sync})"
        );
        self.dependencies
            .certificate_chain_synchronizer
            .synchronize_certificate_chain(time_point.epoch, force_sync)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use mockall::mock;
    use mockall::predicate::eq;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;
    use mithril_common::{
        StdResult,
        entities::{
            ChainPoint, Epoch, ProtocolMessage, SignedEntityConfig, SignedEntityType,
            SignedEntityTypeDiscriminants, StakeDistribution, TimePoint,
        },
        signable_builder::SignableBuilderService,
        temp_dir,
        test::{
            builder::MithrilFixtureBuilder,
            double::{Dummy, fake_data},
        },
    };
    use mithril_persistence::store::StakeStorer;
    use mithril_signed_entity_lock::SignedEntityTypeLock;
    use mithril_ticker::MithrilTickerService;

    use crate::{
        MithrilSignerRegistrationLeader, ServeCommandConfiguration,
        ServeCommandDependenciesContainer, SignerRegistrationRound,
        dependency_injection::DependenciesBuilder,
        entities::OpenMessage,
        initialize_dependencies,
        runtime::{AggregatorRunner, AggregatorRunnerTrait},
        services::{
            FakeEpochService, FakeEpochServiceBuilder, MockCertifierService, MockUpkeepService,
        },
    };

    mock! {
        SignableBuilderServiceImpl { }

        #[async_trait]
        impl SignableBuilderService for SignableBuilderServiceImpl
        {

            async fn compute_protocol_message(
                &self,
                signed_entity_type: SignedEntityType,
            ) -> StdResult<ProtocolMessage>;
        }
    }

    async fn build_runner_with_fixture_data(
        deps: ServeCommandDependenciesContainer,
    ) -> AggregatorRunner {
        let current_epoch = deps.ticker_service.get_current_epoch().await.unwrap();
        #[cfg(feature = "future_snark")]
        {
            let current_fixture = MithrilFixtureBuilder::default()
                .with_signers(5)
                .with_epoch(current_epoch.offset_to_signer_retrieval_epoch().unwrap())
                .build();
            let next_fixture = MithrilFixtureBuilder::default()
                .with_signers(5)
                .with_epoch(current_epoch)
                .build();
            deps.init_state_from_fixtures(&current_fixture, &next_fixture, current_epoch)
                .await;
        }
        #[cfg(not(feature = "future_snark"))]
        {
            let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
            deps.init_state_from_fixture(&fixture, current_epoch).await;
        }

        AggregatorRunner::new(Arc::new(deps))
    }

    async fn build_runner(
        temp_dir: PathBuf,
        mock_certifier_service: MockCertifierService,
    ) -> AggregatorRunner {
        build_runner_with_discriminants(temp_dir, mock_certifier_service, vec![]).await
    }

    async fn build_runner_with_discriminants(
        temp_dir: PathBuf,
        mock_certifier_service: MockCertifierService,
        allowed_discriminants: Vec<SignedEntityTypeDiscriminants>,
    ) -> AggregatorRunner {
        let mut deps = initialize_dependencies(temp_dir).await;
        deps.certifier_service = Arc::new(mock_certifier_service);

        let mut mock_signable_builder_service = MockSignableBuilderServiceImpl::new();
        mock_signable_builder_service
            .expect_compute_protocol_message()
            .return_once(|_| Ok(ProtocolMessage::default()));
        deps.signable_builder_service = Arc::new(mock_signable_builder_service);

        // Configure EpochService with allowed_discriminants
        if !allowed_discriminants.is_empty() {
            let current_epoch = deps.ticker_service.get_current_epoch().await.unwrap();
            let epoch_service = FakeEpochServiceBuilder {
                signed_entity_config: SignedEntityConfig {
                    allowed_discriminants: allowed_discriminants.into_iter().collect(),
                    ..SignedEntityConfig::dummy()
                },
                ..FakeEpochServiceBuilder::dummy(current_epoch)
            }
            .build();
            deps.epoch_service = Arc::new(RwLock::new(epoch_service));
        }

        let runner = build_runner_with_fixture_data(deps).await;

        let current_epoch = runner.dependencies.ticker_service.get_current_epoch().await.unwrap();
        runner.inform_new_epoch(current_epoch).await.unwrap();
        runner.precompute_epoch_data().await.unwrap();
        runner
    }

    fn init_certifier_service_mock(
        mock_certifier_service: &mut MockCertifierService,
        messages: Vec<OpenMessage>,
    ) {
        for message in messages {
            mock_certifier_service
                .expect_get_open_message()
                .return_once(|_| Ok(Some(message)))
                .times(1);
        }
        // When all messages are retrieved, the function return None
        mock_certifier_service
            .expect_get_open_message()
            .returning(|_| Ok(None));

        mock_certifier_service.expect_inform_epoch().return_once(|_| Ok(()));
        mock_certifier_service
            .expect_mark_open_message_if_expired()
            .returning(|_| Ok(None));
    }

    fn create_open_message(
        is_certified: IsCertified,
        is_expired: IsExpired,
        signed_entity_type: SignedEntityType,
    ) -> OpenMessage {
        OpenMessage {
            signed_entity_type,
            is_certified: is_certified == IsCertified::Yes,
            is_expired: is_expired == IsExpired::Yes,
            ..OpenMessage::dummy()
        }
    }

    #[derive(Eq, PartialEq)]
    enum IsCertified {
        Yes,
        No,
    }

    #[derive(Eq, PartialEq)]
    enum IsExpired {
        Yes,
        No,
    }

    #[tokio::test]
    async fn test_get_time_point_from_chain() {
        let expected = TimePoint::new(2, 17, ChainPoint::dummy());
        let mut dependencies = initialize_dependencies!().await;
        let immutable_file_observer = Arc::new(DumbImmutableFileObserver::default());
        immutable_file_observer
            .shall_return(Some(expected.immutable_file_number))
            .await;
        let ticker_service = Arc::new(MithrilTickerService::new(
            Arc::new(FakeChainObserver::new(Some(expected.clone()))),
            immutable_file_observer,
        ));
        dependencies.ticker_service = ticker_service;
        let runner = AggregatorRunner::new(Arc::new(dependencies));

        // Retrieves the expected time point
        let res = runner.get_time_point_from_chain().await;
        assert_eq!(expected, res.unwrap());
    }

    #[tokio::test]
    async fn test_update_stake_distribution() {
        let chain_observer = Arc::new(FakeChainObserver::default());
        let deps = {
            let config = ServeCommandConfiguration::new_sample(temp_dir!());
            let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));
            builder.chain_observer = Some(chain_observer.clone());

            Arc::new(builder.build_serve_dependencies_container().await.unwrap())
        };
        let runner = AggregatorRunner::new(deps.clone());
        let time_point = runner.get_time_point_from_chain().await.unwrap();
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let expected = fixture.stake_distribution();

        chain_observer.set_signers(fixture.signers_with_stake()).await;
        runner
            .update_stake_distribution(&time_point)
            .await
            .expect("updating stake distribution should not return an error");

        let saved_stake_distribution = deps
            .stake_store
            .get_stakes(time_point.epoch.offset_to_recording_epoch())
            .await
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "I should have a stake distribution for the epoch {:?}",
                    time_point.epoch
                )
            });

        assert_eq!(expected, saved_stake_distribution);
    }

    #[tokio::test]
    async fn test_open_signer_registration_round() {
        let config = ServeCommandConfiguration::new_sample(mithril_common::temp_dir!());
        let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));

        let signer_registration_round_opener = Arc::new(MithrilSignerRegistrationLeader::new(
            builder.get_verification_key_store().await.unwrap(),
            builder.get_signer_store().await.unwrap(),
            builder.get_signer_registration_verifier().await.unwrap(),
        ));
        let mut deps = builder.build_serve_dependencies_container().await.unwrap();
        deps.signer_registration_round_opener = signer_registration_round_opener.clone();
        let stake_store = deps.stake_store.clone();
        let deps = Arc::new(deps);
        let runner = AggregatorRunner::new(deps.clone());

        let time_point = TimePoint::dummy();
        let recording_epoch = time_point.epoch.offset_to_recording_epoch();
        let stake_distribution: StakeDistribution =
            StakeDistribution::from([("a".to_string(), 5), ("b".to_string(), 10)]);

        stake_store
            .save_stakes(recording_epoch, stake_distribution.clone())
            .await
            .expect("Save Stake distribution should not fail");

        runner
            .open_signer_registration_round(&time_point)
            .await
            .expect("opening signer registration should not return an error");

        let saved_current_round = signer_registration_round_opener.get_current_round().await;

        let expected_signer_registration_round =
            SignerRegistrationRound::dummy(recording_epoch, stake_distribution);

        assert_eq!(
            Some(expected_signer_registration_round),
            saved_current_round,
        );
    }

    #[tokio::test]
    async fn test_close_signer_registration_round() {
        let config = ServeCommandConfiguration::new_sample(mithril_common::temp_dir!());
        let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));

        let signer_registration_round_opener = Arc::new(MithrilSignerRegistrationLeader::new(
            builder.get_verification_key_store().await.unwrap(),
            builder.get_signer_store().await.unwrap(),
            builder.get_signer_registration_verifier().await.unwrap(),
        ));
        let mut deps = builder.build_serve_dependencies_container().await.unwrap();
        deps.signer_registration_round_opener = signer_registration_round_opener.clone();
        let deps = Arc::new(deps);
        let runner = AggregatorRunner::new(deps.clone());

        let time_point = TimePoint::dummy();
        runner
            .open_signer_registration_round(&time_point)
            .await
            .expect("opening signer registration should not return an error");

        runner
            .close_signer_registration_round()
            .await
            .expect("closing signer registration should not return an error");

        let saved_current_round = signer_registration_round_opener.get_current_round().await;
        assert!(saved_current_round.is_none());
    }

    #[tokio::test]
    async fn test_expire_open_message() {
        let open_message_expected = OpenMessage {
            signed_entity_type: SignedEntityType::dummy(),
            is_certified: false,
            is_expired: false,
            expires_at: Some(
                DateTime::parse_from_rfc3339("2000-01-19T13:43:05.618857482Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            ..OpenMessage::dummy()
        };
        let open_message_clone = open_message_expected.clone();

        let mut mock_certifier_service = MockCertifierService::new();
        mock_certifier_service
            .expect_mark_open_message_if_expired()
            .return_once(|_| Ok(Some(open_message_clone)));

        let mut deps = initialize_dependencies!().await;
        deps.certifier_service = Arc::new(mock_certifier_service);

        let runner = build_runner_with_fixture_data(deps).await;
        let open_message_expired = runner
            .mark_open_message_if_expired(&open_message_expected.signed_entity_type)
            .await
            .expect("mark_open_message_if_expired should not fail");

        assert_eq!(Some(open_message_expected), open_message_expired);
    }

    #[tokio::test]
    async fn test_update_era_checker() {
        let deps = initialize_dependencies!().await;
        let ticker_service = deps.ticker_service.clone();
        let era_checker = deps.era_checker.clone();
        let mut time_point = ticker_service.get_current_time_point().await.unwrap();

        assert_eq!(time_point.epoch, era_checker.current_epoch());
        let runner = AggregatorRunner::new(Arc::new(deps));
        time_point.epoch += 1;

        runner.update_era_checker(time_point.epoch).await.unwrap();
        assert_eq!(time_point.epoch, era_checker.current_epoch());
    }

    #[tokio::test]
    async fn test_inform_new_epoch() {
        let mut mock_certifier_service = MockCertifierService::new();
        mock_certifier_service
            .expect_inform_epoch()
            .returning(|_| Ok(()))
            .times(1);
        let mut deps = initialize_dependencies!().await;
        let current_epoch = deps.ticker_service.get_current_epoch().await.unwrap();

        deps.certifier_service = Arc::new(mock_certifier_service);
        let fixture = MithrilFixtureBuilder::default();
        #[cfg(feature = "future_snark")]
        let fixture = fixture.with_epoch(current_epoch);
        let fixture = fixture.build();
        deps.epoch_service = Arc::new(RwLock::new(FakeEpochService::from_fixture(
            current_epoch,
            &fixture,
        )));

        let runner = AggregatorRunner::new(Arc::new(deps));

        runner.inform_new_epoch(current_epoch).await.unwrap();
    }

    #[tokio::test]
    async fn test_upkeep_calls_run_on_upkeep_service() {
        let mut upkeep_service = MockUpkeepService::new();
        upkeep_service
            .expect_run()
            .with(eq(Epoch(5)))
            .returning(|_| Ok(()))
            .times(1);

        let mut deps = initialize_dependencies!().await;
        deps.upkeep_service = Arc::new(upkeep_service);

        let runner = AggregatorRunner::new(Arc::new(deps));

        runner.upkeep(Epoch(5)).await.unwrap();
    }

    #[tokio::test]
    async fn test_precompute_epoch_data() {
        let mut deps = initialize_dependencies!().await;
        let current_epoch = deps.ticker_service.get_current_epoch().await.unwrap();

        let fixture = MithrilFixtureBuilder::default();
        #[cfg(feature = "future_snark")]
        let fixture = fixture.with_epoch(current_epoch);
        let fixture = fixture.build();
        deps.epoch_service = Arc::new(RwLock::new(FakeEpochService::from_fixture(
            current_epoch,
            &fixture,
        )));

        let runner = AggregatorRunner::new(Arc::new(deps));

        runner.precompute_epoch_data().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_create_new_open_message_if_none_exists()
     {
        let open_message_created = create_open_message(
            IsCertified::No,
            IsExpired::No,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );
        let open_message_expected = open_message_created.clone();

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(&mut mock_certifier_service, vec![]);

            mock_certifier_service
                .expect_create_open_message()
                .return_once(|_, _| Ok(open_message_created))
                .times(1);
            build_runner(temp_dir!(), mock_certifier_service).await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();
        assert_eq!(Some(open_message_expected), open_message_returned);
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_return_existing_open_message_if_already_exists_and_not_expired()
     {
        let not_certified_and_not_expired = create_open_message(
            IsCertified::No,
            IsExpired::No,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );

        let open_message_expected = not_certified_and_not_expired.clone();

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(
                &mut mock_certifier_service,
                vec![not_certified_and_not_expired],
            );

            mock_certifier_service.expect_create_open_message().never();
            build_runner(temp_dir!(), mock_certifier_service).await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();

        assert_eq!(Some(open_message_expected), open_message_returned);
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_return_existing_open_message_if_already_exists_and_open_message_already_certified()
     {
        let certified_and_not_expired = create_open_message(
            IsCertified::Yes,
            IsExpired::No,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );
        let not_certified_and_not_expired = create_open_message(
            IsCertified::No,
            IsExpired::No,
            SignedEntityType::CardanoStakeDistribution(fake_data::epoch()),
        );

        let open_message_expected = not_certified_and_not_expired.clone();

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(
                &mut mock_certifier_service,
                vec![certified_and_not_expired, not_certified_and_not_expired],
            );

            mock_certifier_service.expect_create_open_message().never();
            build_runner_with_discriminants(
                temp_dir!(),
                mock_certifier_service,
                vec![
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ],
            )
            .await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();

        assert_eq!(Some(open_message_expected), open_message_returned);
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_create_open_message_if_none_exists_and_open_message_already_certified()
     {
        let certified_and_not_expired = create_open_message(
            IsCertified::Yes,
            IsExpired::No,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );
        let open_message_created = create_open_message(
            IsCertified::No,
            IsExpired::No,
            SignedEntityType::CardanoStakeDistribution(fake_data::epoch()),
        );
        let open_message_expected = open_message_created.clone();

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(
                &mut mock_certifier_service,
                vec![certified_and_not_expired],
            );

            mock_certifier_service
                .expect_create_open_message()
                .return_once(|_, _| Ok(open_message_created))
                .times(1);
            build_runner_with_discriminants(
                temp_dir!(),
                mock_certifier_service,
                vec![
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ],
            )
            .await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();

        assert_eq!(Some(open_message_expected), open_message_returned);
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_return_none_if_all_open_message_already_certified()
     {
        let certified_and_not_expired_1 = create_open_message(
            IsCertified::Yes,
            IsExpired::No,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );
        let certified_and_not_expired_2 = create_open_message(
            IsCertified::Yes,
            IsExpired::No,
            SignedEntityType::CardanoStakeDistribution(fake_data::epoch()),
        );

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(
                &mut mock_certifier_service,
                vec![certified_and_not_expired_1, certified_and_not_expired_2],
            );

            mock_certifier_service.expect_create_open_message().never();
            build_runner_with_discriminants(
                temp_dir!(),
                mock_certifier_service,
                vec![
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ],
            )
            .await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();

        assert!(open_message_returned.is_none());
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_should_return_first_not_certified_and_not_expired_open_message()
     {
        let not_certified_and_expired = create_open_message(
            IsCertified::No,
            IsExpired::Yes,
            SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
        );
        let not_certified_and_not_expired = create_open_message(
            IsCertified::No,
            IsExpired::No,
            SignedEntityType::CardanoStakeDistribution(fake_data::epoch()),
        );

        let open_message_expected = not_certified_and_not_expired.clone();

        let runner = {
            let mut mock_certifier_service = MockCertifierService::new();
            init_certifier_service_mock(
                &mut mock_certifier_service,
                vec![not_certified_and_expired, not_certified_and_not_expired],
            );

            mock_certifier_service.expect_create_open_message().never();
            build_runner_with_discriminants(
                temp_dir!(),
                mock_certifier_service,
                vec![
                    SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                    SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ],
            )
            .await
        };

        let open_message_returned = runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();

        assert_eq!(Some(open_message_expected), open_message_returned);
    }

    #[tokio::test]
    async fn test_get_current_non_certified_open_message_called_for_mithril_stake_distribution() {
        let mut mock_certifier_service = MockCertifierService::new();

        mock_certifier_service
            .expect_get_open_message()
            .with(eq(SignedEntityType::MithrilStakeDistribution(
                TimePoint::dummy().epoch,
            )))
            .times(1)
            .return_once(|_| {
                Ok(Some(create_open_message(
                    IsCertified::Yes,
                    IsExpired::No,
                    SignedEntityType::MithrilStakeDistribution(fake_data::epoch()),
                )))
            });

        mock_certifier_service.expect_create_open_message().never();

        mock_certifier_service.expect_inform_epoch().return_once(|_| Ok(()));
        mock_certifier_service
            .expect_mark_open_message_if_expired()
            .returning(|_| Ok(None));

        let runner = build_runner(temp_dir!(), mock_certifier_service).await;

        runner
            .get_current_non_certified_open_message(&TimePoint::dummy())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_available_signed_entity_types_list_all_configured_entities_if_none_are_locked() {
        let runner = {
            let mut dependencies = initialize_dependencies!().await;
            let epoch_service = FakeEpochServiceBuilder {
                signed_entity_config: SignedEntityConfig {
                    allowed_discriminants: SignedEntityTypeDiscriminants::all(),
                    ..SignedEntityConfig::dummy()
                },
                ..FakeEpochServiceBuilder::dummy(Epoch(32))
            }
            .build();
            dependencies.epoch_service = Arc::new(RwLock::new(epoch_service));
            dependencies.signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
            AggregatorRunner::new(Arc::new(dependencies))
        };

        let time_point = TimePoint::dummy();
        let signed_entities: Vec<SignedEntityTypeDiscriminants> = runner
            .list_available_signed_entity_types(&time_point)
            .await
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();

        assert_eq!(
            signed_entities,
            SignedEntityTypeDiscriminants::all().into_iter().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_available_signed_entity_types_exclude_locked_entities() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let runner = {
            let mut dependencies = initialize_dependencies!().await;
            dependencies.signed_entity_type_lock = signed_entity_type_lock.clone();
            let epoch_service = FakeEpochServiceBuilder {
                signed_entity_config: SignedEntityConfig {
                    allowed_discriminants: SignedEntityTypeDiscriminants::all(),
                    ..SignedEntityConfig::dummy()
                },
                ..FakeEpochServiceBuilder::dummy(Epoch(32))
            }
            .build();
            dependencies.epoch_service = Arc::new(RwLock::new(epoch_service));

            AggregatorRunner::new(Arc::new(dependencies))
        };

        signed_entity_type_lock
            .lock(SignedEntityTypeDiscriminants::CardanoTransactions)
            .await;

        let time_point = TimePoint::dummy();
        let signed_entities: Vec<SignedEntityTypeDiscriminants> = runner
            .list_available_signed_entity_types(&time_point)
            .await
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();

        assert!(!signed_entities.is_empty());
        assert!(!signed_entities.contains(&SignedEntityTypeDiscriminants::CardanoTransactions));
    }

    #[tokio::test]
    async fn is_open_message_outdated_return_false_when_message_is_not_expired_and_no_newer_open_message()
     {
        assert!(!is_outdated_returned_when(temp_dir!(), IsExpired::No, false).await);
    }

    #[tokio::test]
    async fn is_open_message_outdated_return_true_when_message_is_expired_and_no_newer_open_message()
     {
        assert!(is_outdated_returned_when(temp_dir!(), IsExpired::Yes, false).await);
    }

    #[tokio::test]
    async fn is_open_message_outdated_return_true_when_message_is_not_expired_and_exists_newer_open_message()
     {
        assert!(is_outdated_returned_when(temp_dir!(), IsExpired::No, true).await);
    }

    #[tokio::test]
    async fn is_open_message_outdated_return_true_when_message_is_expired_and_exists_newer_open_message()
     {
        assert!(is_outdated_returned_when(temp_dir!(), IsExpired::Yes, true).await);
    }

    async fn is_outdated_returned_when(
        tmp_path: PathBuf,
        is_expired: IsExpired,
        newer_open_message: bool,
    ) -> bool {
        let current_time_point = TimePoint {
            epoch: Epoch(2),
            ..TimePoint::dummy()
        };

        let message_epoch = if newer_open_message {
            current_time_point.epoch + 54
        } else {
            current_time_point.epoch
        };
        let open_message_to_verify = OpenMessage {
            signed_entity_type: SignedEntityType::MithrilStakeDistribution(message_epoch),
            is_expired: is_expired == IsExpired::Yes,
            ..OpenMessage::dummy()
        };

        let runner = {
            let mut deps = initialize_dependencies(tmp_path).await;
            let mut mock_certifier_service = MockCertifierService::new();

            let open_message_current = open_message_to_verify.clone();
            mock_certifier_service
                .expect_get_open_message()
                .times(1)
                .return_once(|_| Ok(Some(open_message_current)));
            mock_certifier_service
                .expect_mark_open_message_if_expired()
                .returning(|_| Ok(None));

            deps.certifier_service = Arc::new(mock_certifier_service);

            let epoch_service = FakeEpochServiceBuilder::dummy(current_time_point.epoch).build();
            deps.epoch_service = Arc::new(RwLock::new(epoch_service));

            build_runner_with_fixture_data(deps).await
        };

        runner
            .is_open_message_outdated(
                open_message_to_verify.signed_entity_type,
                &current_time_point,
            )
            .await
            .unwrap()
    }
}
