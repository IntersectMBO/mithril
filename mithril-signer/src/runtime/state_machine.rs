use std::{fmt::Display, sync::Arc, time::Duration};

use anyhow::Error;
use chrono::Local;
use slog::{Logger, debug, info};
use tokio::sync::Mutex;

use mithril_common::{
    crypto_helper::ProtocolInitializerError,
    entities::{Epoch, Signer, TimePoint},
    logging::LoggerExtensions,
};

use mithril_aggregator_client::AggregatorHttpClientError;
use mithril_protocol_config::model::MithrilNetworkConfiguration;

use crate::{MetricsService, entities::BeaconToSign};

use super::{Runner, RuntimeError};

/// Different possible states of the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerState {
    /// Starting state
    Init,
    /// Hold the latest known epoch in order to help synchronisation
    /// with the aggregator
    Unregistered {
        /// Current Epoch
        epoch: Epoch,
    },

    /// `ReadyToSign` state. The signer is registered and ready to sign new messages.
    ReadyToSign {
        /// Epoch when signer transitioned to the state.
        epoch: Epoch,
    },

    /// `RegisteredNotAbleToSign` state. The signer is registered but not able to sign for the duration of the epoch.
    RegisteredNotAbleToSign {
        /// Epoch when signer transitioned to the state.
        epoch: Epoch,
    },
}

enum CycleOutcome {
    TransitionTo(SignerState),
    KeepState,
}

impl SignerState {
    /// Returns `true` if the state in `Init`
    pub fn is_init(&self) -> bool {
        matches!(*self, SignerState::Init)
    }

    /// Returns `true` if the state in `Unregistered`
    pub fn is_unregistered(&self) -> bool {
        matches!(*self, SignerState::Unregistered { .. })
    }

    /// Returns `true` if the state in `ReadyToSign`
    pub fn is_ready_to_sign(&self) -> bool {
        matches!(*self, SignerState::ReadyToSign { .. })
    }

    /// Returns `true` if the state in `RegisteredNotAbleToSign`
    pub fn is_registered_not_able_to_sign(&self) -> bool {
        matches!(*self, SignerState::RegisteredNotAbleToSign { .. })
    }
}

impl Display for SignerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "Init"),
            Self::Unregistered { epoch } => write!(f, "Unregistered - {epoch:?}"),
            Self::RegisteredNotAbleToSign { epoch } => {
                write!(f, "RegisteredNotAbleToSign - {epoch}")
            }
            Self::ReadyToSign { epoch } => {
                write!(f, "ReadyToSign - {epoch}")
            }
        }
    }
}

enum EpochStatus {
    NewEpoch(Epoch),
    Unchanged(TimePoint),
}

enum SignerRegistrationOutcome {
    Registered,
    RegistrationRoundNotYetOpened,
}

/// The state machine is responsible of the execution of the signer automate.
pub struct StateMachine {
    state: Mutex<SignerState>,
    runner: Box<dyn Runner>,
    interval: Duration,
    metrics_service: Arc<MetricsService>,
    logger: Logger,
}

impl StateMachine {
    /// Create a new StateMachine instance.
    pub fn new(
        starting_state: SignerState,
        runner: Box<dyn Runner>,
        interval: Duration,
        metrics_service: Arc<MetricsService>,
        logger: Logger,
    ) -> Self {
        Self {
            state: Mutex::new(starting_state),
            runner,
            interval,
            metrics_service,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Return the current state of the state machine.
    pub async fn get_state(&self) -> SignerState {
        self.state.lock().await.to_owned()
    }

    /// Launch the state machine until an error occurs or it is interrupted.
    pub async fn run(&self) -> Result<(), RuntimeError> {
        info!(self.logger, "Launching State Machine");
        let mut interval = tokio::time::interval(self.interval);

        loop {
            interval.tick().await;
            // Note: the "time" property in logs produced by our formatter (slog_bunyan) uses local
            // time, so we must use it as well to avoid confusion.
            let approximate_next_cycle_time = Local::now() + self.interval;

            if let Err(e) = self.cycle().await {
                e.write_to_log(&self.logger);
                if e.is_critical() {
                    return Err(e);
                }
            }

            info!(
                self.logger, "… Cycle finished";
                "approximate_next_cycle_time" => %approximate_next_cycle_time.time().format("%H:%M:%S%.3f"),
                "run_interval_in_ms" => self.interval.as_millis(),
            );
        }
    }

    /// Perform a cycle of the state machine.
    pub async fn cycle(&self) -> Result<(), RuntimeError> {
        let current_state = self.state.lock().await.clone();
        info!(
            self.logger,
            "================================================================================"
        );
        info!(self.logger, "New cycle: {current_state}");

        self.metrics_service
            .get_runtime_cycle_total_since_startup_counter()
            .increment();

        let outcome = match current_state {
            SignerState::Init => self.cycle_init().await?,
            SignerState::Unregistered { epoch } => self.cycle_unregistered(epoch).await?,
            SignerState::RegisteredNotAbleToSign { epoch } => {
                self.cycle_registered_not_able_to_sign(epoch).await?
            }
            SignerState::ReadyToSign { epoch } => self.cycle_ready_to_sign(epoch).await?,
        };

        match outcome {
            CycleOutcome::TransitionTo(next_state) => {
                info!(self.logger, "Transitioned to state: {next_state}");
                *self.state.lock().await = next_state;
            }
            CycleOutcome::KeepState => {
                info!(self.logger, "Keeping current state: {current_state}");
            }
        }

        self.metrics_service
            .get_runtime_cycle_success_since_startup_counter()
            .increment();

        Ok(())
    }

    async fn cycle_init(&self) -> Result<CycleOutcome, RuntimeError> {
        let current_epoch = self.get_current_time_point("init → unregistered").await?.epoch;
        self.update_era_checker(current_epoch, "init → unregistered").await?;

        Ok(CycleOutcome::TransitionTo(SignerState::Unregistered {
            epoch: current_epoch,
        }))
    }

    async fn cycle_unregistered(&self, epoch: Epoch) -> Result<CycleOutcome, RuntimeError> {
        if let EpochStatus::NewEpoch(new_epoch) = self.has_epoch_changed(epoch).await? {
            info!(
                self.logger,
                "→ Epoch has changed, transitioning to Unregistered"
            );

            self.transition_from_unregistered_to_unregistered(new_epoch)
                .await
                .map(CycleOutcome::TransitionTo)
        } else {
            let signer_registrations = self
                .runner
                .get_signer_registrations_from_aggregator()
                .await
                .map_err(|e| RuntimeError::KeepState {
                    message: format!("could not retrieve epoch settings at epoch {epoch:?}"),
                    nested_error: Some(e),
                })?;
            info!(self.logger, "→ Epoch Signer registrations found");

            let network_configuration: MithrilNetworkConfiguration = self
                .runner
                .get_mithril_network_configuration(epoch)
                .await
                .map_err(|e| RuntimeError::KeepState {
                    message: format!(
                        "could not retrieve Mithril network configuration for epoch {epoch:?}"
                    ),
                    nested_error: Some(e),
                })?;
            info!(self.logger, "→ Mithril network configuration found");
            debug!(
                self.logger,
                "Mithril network configuration fetched";
                "network_configuration" => ?network_configuration
            );

            if signer_registrations.epoch >= epoch {
                info!(self.logger, "New Epoch found");
                info!(self.logger, " ⋅ Transitioning to Registered");

                self.transition_from_unregistered_to_one_of_registered_states(
                    signer_registrations.epoch,
                    network_configuration,
                    signer_registrations.current_signers,
                    signer_registrations.next_signers,
                )
                .await
                .map(CycleOutcome::TransitionTo)
            } else {
                info!(
                    self.logger, " ⋅ Signer settings found, but its epoch is behind the known epoch, waiting…";
                    "network_configuration" => ?network_configuration,
                    "current_singer" => ?signer_registrations.current_signers,
                    "next_signer" => ?signer_registrations.next_signers,
                    "known_epoch" => ?epoch,
                );

                Ok(CycleOutcome::KeepState)
            }
        }
    }

    async fn cycle_registered_not_able_to_sign(
        &self,
        epoch: Epoch,
    ) -> Result<CycleOutcome, RuntimeError> {
        if let EpochStatus::NewEpoch(new_epoch) = self.has_epoch_changed(epoch).await? {
            info!(
                self.logger,
                " → New Epoch detected, transitioning to Unregistered"
            );

            self.transition_from_registered_not_able_to_sign_to_unregistered(new_epoch)
                .await
                .map(CycleOutcome::TransitionTo)
        } else {
            info!(self.logger, " ⋅ Epoch has NOT changed, waiting…");
            Ok(CycleOutcome::KeepState)
        }
    }

    async fn cycle_ready_to_sign(&self, epoch: Epoch) -> Result<CycleOutcome, RuntimeError> {
        match self.has_epoch_changed(epoch).await? {
            EpochStatus::NewEpoch(new_epoch) => {
                info!(
                    self.logger,
                    "→ Epoch has changed, transitioning to Unregistered"
                );
                self.transition_from_ready_to_sign_to_unregistered(new_epoch)
                    .await
                    .map(CycleOutcome::TransitionTo)
            }
            EpochStatus::Unchanged(timepoint) => {
                let beacon_to_sign =
                    self.runner.get_beacon_to_sign(timepoint).await.map_err(|e| {
                        RuntimeError::KeepState {
                            message: "could not fetch the beacon to sign".to_string(),
                            nested_error: Some(e),
                        }
                    })?;

                match beacon_to_sign {
                    Some(beacon) => {
                        info!(
                            self.logger, "→ Epoch has NOT changed we can sign this beacon, transitioning to ReadyToSign";
                            "beacon_to_sign" => ?beacon,
                        );
                        self.transition_from_ready_to_sign_to_ready_to_sign(epoch, beacon)
                            .await
                            .map(CycleOutcome::TransitionTo)
                    }
                    None => {
                        info!(self.logger, " ⋅ No beacon to sign, waiting…");
                        Ok(CycleOutcome::KeepState)
                    }
                }
            }
        }
    }

    /// Return the new epoch if the epoch is different than the given one, otherwise return the current time point.
    async fn has_epoch_changed(&self, epoch: Epoch) -> Result<EpochStatus, RuntimeError> {
        let current_time_point =
            self.get_current_time_point("checking if epoch has changed").await?;

        if current_time_point.epoch > epoch {
            Ok(EpochStatus::NewEpoch(current_time_point.epoch))
        } else {
            Ok(EpochStatus::Unchanged(current_time_point))
        }
    }

    async fn transition_from_unregistered_to_unregistered(
        &self,
        new_epoch: Epoch,
    ) -> Result<SignerState, RuntimeError> {
        self.update_era_checker(new_epoch, "unregistered → unregistered")
            .await?;

        Ok(SignerState::Unregistered { epoch: new_epoch })
    }

    /// Launch the transition process from the `Unregistered` to `ReadyToSign` or `RegisteredNotAbleToSign` state.
    async fn transition_from_unregistered_to_one_of_registered_states(
        &self,
        aggregator_signer_registration_epoch: Epoch,
        mithril_network_configuration: MithrilNetworkConfiguration,
        current_signer: Vec<Signer>,
        next_signer: Vec<Signer>,
    ) -> Result<SignerState, RuntimeError> {
        self.metrics_service
            .get_signer_registration_total_since_startup_counter()
            .increment();

        let time_point = self.get_current_time_point("unregistered → registered").await?;
        let epoch = time_point.epoch;
        self.runner.update_stake_distribution(epoch)
            .await
            .map_err(|e| RuntimeError::KeepState {
                message: format!("Could not update stake distribution in 'unregistered → registered' phase for epoch {epoch:?}."),
                nested_error: Some(e),
            })?;

        self.runner
            .inform_epoch_settings(aggregator_signer_registration_epoch, mithril_network_configuration, current_signer,  next_signer)
            .await
            .map_err(|e| RuntimeError::KeepState {
                message: format!(
                    "Could not register epoch information in 'unregistered → registered' phase for epoch {epoch:?}."
                ),
                nested_error: Some(e),
            })?;

        let register_result = self.runner.register_signer_to_aggregator().await;
        match Self::handle_registration_result(register_result, epoch)? {
            SignerRegistrationOutcome::Registered => {
                self.metrics_service
                    .get_signer_registration_success_since_startup_counter()
                    .increment();

                self.metrics_service
                    .get_signer_registration_success_last_epoch_gauge()
                    .record(epoch);
            }
            SignerRegistrationOutcome::RegistrationRoundNotYetOpened => {
                return Ok(SignerState::Unregistered { epoch });
            }
        }

        self.runner.upkeep(epoch).await.map_err(|e| RuntimeError::KeepState {
            message: "Failed to upkeep signer in 'unregistered → registered' phase".to_string(),
            nested_error: Some(e),
        })?;

        match self
            .runner
            .can_sign_current_epoch()
            .await
            .map_err(|e| RuntimeError::KeepState {
                message: "Failed to check if signer can sign in the current epoch in 'unregistered → ?' phase".to_string(),
                nested_error: Some(e),
            })? {
            true => Ok(SignerState::ReadyToSign { epoch }),
            false => Ok(SignerState::RegisteredNotAbleToSign { epoch }),
        }
    }

    async fn transition_from_registered_not_able_to_sign_to_unregistered(
        &self,
        epoch: Epoch,
    ) -> Result<SignerState, RuntimeError> {
        self.update_era_checker(epoch, "registered not able to sign → unregistered")
            .await?;

        Ok(SignerState::Unregistered { epoch })
    }

    async fn transition_from_ready_to_sign_to_unregistered(
        &self,
        epoch: Epoch,
    ) -> Result<SignerState, RuntimeError> {
        self.update_era_checker(epoch, "ready to sign → unregistered").await?;

        Ok(SignerState::Unregistered { epoch })
    }

    /// Launch the transition process from the `ReadyToSign` to the `ReadyToSign` state.
    async fn transition_from_ready_to_sign_to_ready_to_sign(
        &self,
        current_epoch: Epoch,
        beacon_to_sign: BeaconToSign,
    ) -> Result<SignerState, RuntimeError> {
        let (retrieval_epoch, next_retrieval_epoch) = (
            current_epoch.offset_to_signer_retrieval_epoch()?,
            current_epoch.offset_to_next_signer_retrieval_epoch(),
        );

        debug!(
            self.logger, ">> transition_from_ready_to_sign_to_ready_to_sign";
            "current_epoch" => ?current_epoch,
            "retrieval_epoch" => ?retrieval_epoch,
            "next_retrieval_epoch" => ?next_retrieval_epoch,
        );

        self.metrics_service
            .get_signature_registration_total_since_startup_counter()
            .increment();

        let message = self
            .runner
            .compute_message(&beacon_to_sign.signed_entity_type)
            .await
            .map_err(|e| RuntimeError::KeepState {
                message: format!("Could not compute message during 'ready to sign → ready to sign' phase (current epoch {current_epoch:?})"),
                nested_error: Some(e)
            })?;

        self.runner.compute_publish_single_signature(&beacon_to_sign, &message)
            .await
            .map_err(|e| RuntimeError::KeepState {
                message: format!("Could not compute and publish single signature during 'ready to sign → ready to sign' phase (current epoch {current_epoch:?})"),
                nested_error: Some(e)
            })?;

        self.metrics_service
            .get_signature_registration_success_since_startup_counter()
            .increment();
        self.metrics_service
            .get_signature_registration_success_last_epoch_gauge()
            .record(current_epoch);

        Ok(SignerState::ReadyToSign {
            epoch: current_epoch,
        })
    }

    async fn get_current_time_point(&self, context: &str) -> Result<TimePoint, RuntimeError> {
        let current_time_point =
            self.runner
                .get_current_time_point()
                .await
                .map_err(|e| RuntimeError::KeepState {
                    message: format!(
                        "Could not retrieve current time point in context '{context}'."
                    ),
                    nested_error: Some(e),
                })?;

        Ok(current_time_point)
    }

    async fn update_era_checker(&self, epoch: Epoch, context: &str) -> Result<(), RuntimeError> {
        self.runner
            .update_era_checker(epoch)
            .await
            .map_err(|e| RuntimeError::Critical {
                message: format!(
                    "Could not update Era checker with context '{context}' for epoch {epoch:?}"
                ),
                nested_error: Some(e),
            })
    }

    fn handle_registration_result(
        register_result: Result<(), Error>,
        epoch: Epoch,
    ) -> Result<SignerRegistrationOutcome, RuntimeError> {
        if let Err(e) = register_result {
            if let Some(AggregatorHttpClientError::RegistrationRoundNotYetOpened(_)) =
                e.downcast_ref::<AggregatorHttpClientError>()
            {
                Ok(SignerRegistrationOutcome::RegistrationRoundNotYetOpened)
            } else if e.downcast_ref::<ProtocolInitializerError>().is_some() {
                Err(RuntimeError::Critical {
                    message: format!(
                        "Could not register to aggregator in 'unregistered → registered' phase for epoch {epoch:?}."
                    ),
                    nested_error: Some(e),
                })
            } else {
                Err(RuntimeError::KeepState {
                    message: format!(
                        "Could not register to aggregator in 'unregistered → registered' phase for epoch {epoch:?}."
                    ),
                    nested_error: Some(e),
                })
            }
        } else {
            Ok(SignerRegistrationOutcome::Registered)
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use chrono::DateTime;

    use mithril_common::entities::{ChainPoint, Epoch, ProtocolMessage, SignedEntityType};
    use mithril_common::test::double::Dummy;

    use crate::RegisteredSigners;
    use crate::runtime::runner::MockSignerRunner;
    use crate::test::TestLogger;

    use super::*;

    fn init_state_machine(init_state: SignerState, runner: MockSignerRunner) -> StateMachine {
        let logger = TestLogger::stdout();
        let metrics_service = Arc::new(MetricsService::new(logger.clone()).unwrap());
        StateMachine {
            state: init_state.into(),
            runner: Box::new(runner),
            interval: Duration::from_millis(100),
            metrics_service,
            logger,
        }
    }

    #[tokio::test]
    async fn unregistered_epoch_settings_error() {
        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_signer_registrations_from_aggregator()
            .once()
            .returning(|| Err(anyhow!("error")));
        runner
            .expect_get_current_time_point()
            .once()
            .returning(|| Ok(TimePoint::dummy()));
        let state_machine = init_state_machine(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch,
            },
            runner,
        );
        state_machine
            .cycle()
            .await
            .expect_err("Cycling the state machine should fail");

        assert_eq!(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch
            },
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn unregistered_epoch_settings_behind_known_epoch() {
        let mut runner = MockSignerRunner::new();
        let epoch_settings = RegisteredSigners {
            epoch: Epoch(3),
            current_signers: vec![],
            next_signers: vec![],
        };
        let known_epoch = Epoch(4);
        runner
            .expect_get_signer_registrations_from_aggregator()
            .once()
            .returning(move || Ok(epoch_settings.to_owned()));
        runner
            .expect_get_mithril_network_configuration()
            .once()
            .returning(|_| {
                Ok(MithrilNetworkConfiguration {
                    epoch: Epoch(999),
                    configuration_for_aggregation: Dummy::dummy(),
                    configuration_for_next_aggregation: Dummy::dummy(),
                    configuration_for_registration: Dummy::dummy(),
                })
            });
        runner.expect_get_current_time_point().once().returning(|| {
            Ok(TimePoint {
                epoch: Epoch(4),
                ..TimePoint::dummy()
            })
        });
        let state_machine =
            init_state_machine(SignerState::Unregistered { epoch: known_epoch }, runner);
        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        assert_eq!(
            SignerState::Unregistered { epoch: known_epoch },
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn unregistered_to_registered_not_able_to_sign() {
        let mut runner = MockSignerRunner::new();
        runner.expect_upkeep().returning(|_| Ok(())).once();
        runner
            .expect_get_signer_registrations_from_aggregator()
            .once()
            .returning(|| Ok(RegisteredSigners::dummy()));

        runner
            .expect_get_mithril_network_configuration()
            .once()
            .returning(|_| Ok(MithrilNetworkConfiguration::dummy()));

        runner
            .expect_inform_epoch_settings()
            .once()
            .returning(|_, _, _, _| Ok(()));

        runner
            .expect_get_current_time_point()
            .times(2)
            .returning(|| Ok(TimePoint::dummy()));
        runner.expect_update_stake_distribution().once().returning(|_| Ok(()));
        runner
            .expect_register_signer_to_aggregator()
            .once()
            .returning(|| Ok(()));

        runner.expect_can_sign_current_epoch().once().returning(|| Ok(false));

        let state_machine = init_state_machine(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch,
            },
            runner,
        );

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        if let SignerState::RegisteredNotAbleToSign { epoch: _ } = state_machine.get_state().await {
        } else {
            panic!(
                "state machine did not return a RegisteredNotAbleToSign state but {:?}",
                state_machine.get_state().await
            );
        }
    }

    #[tokio::test]
    async fn unregistered_to_ready_to_sign() {
        let mut runner = MockSignerRunner::new();
        runner.expect_upkeep().returning(|_| Ok(())).once();
        runner
            .expect_get_signer_registrations_from_aggregator()
            .once()
            .returning(|| Ok(RegisteredSigners::dummy()));

        runner
            .expect_get_mithril_network_configuration()
            .once()
            .returning(|_| Ok(MithrilNetworkConfiguration::dummy()));

        runner
            .expect_inform_epoch_settings()
            .once()
            .returning(|_, _, _, _| Ok(()));

        runner
            .expect_get_current_time_point()
            .times(2)
            .returning(|| Ok(TimePoint::dummy()));
        runner.expect_update_stake_distribution().once().returning(|_| Ok(()));
        runner
            .expect_register_signer_to_aggregator()
            .once()
            .returning(|| Ok(()));

        runner.expect_can_sign_current_epoch().once().returning(|| Ok(true));

        let state_machine = init_state_machine(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch,
            },
            runner,
        );

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        assert_eq!(
            SignerState::ReadyToSign {
                epoch: TimePoint::dummy().epoch,
            },
            state_machine.get_state().await
        );

        let metrics_service = state_machine.metrics_service;
        let success_since_startup =
            metrics_service.get_runtime_cycle_success_since_startup_counter();
        assert_eq!(1, success_since_startup.get());
    }

    #[tokio::test]
    async fn unregistered_keeps_state_when_registration_round_not_yet_opened_counter() {
        let mut runner = MockSignerRunner::new();

        runner
            .expect_get_signer_registrations_from_aggregator()
            .once()
            .returning(|| Ok(RegisteredSigners::dummy()));

        runner
            .expect_get_mithril_network_configuration()
            .once()
            .returning(|_| Ok(MithrilNetworkConfiguration::dummy()));

        runner
            .expect_inform_epoch_settings()
            .once()
            .returning(|_, _, _, _| Ok(()));

        runner
            .expect_get_current_time_point()
            .times(2)
            .returning(|| Ok(TimePoint::dummy()));
        runner.expect_update_stake_distribution().once().returning(|_| Ok(()));
        runner.expect_register_signer_to_aggregator().once().returning(|| {
            Err(AggregatorHttpClientError::RegistrationRoundNotYetOpened(
                anyhow!("Not yet opened"),
            ))?
        });

        runner.expect_upkeep().never();
        runner.expect_can_sign_current_epoch().never();

        let state_machine = init_state_machine(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch,
            },
            runner,
        );

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        assert_eq!(
            SignerState::Unregistered {
                epoch: TimePoint::dummy().epoch,
            },
            state_machine.get_state().await
        );

        let metrics_service = state_machine.metrics_service;
        assert_eq!(
            0,
            metrics_service
                .get_signer_registration_success_since_startup_counter()
                .get()
        );

        assert_eq!(
            0f64,
            metrics_service
                .get_signer_registration_success_last_epoch_gauge()
                .get()
        );

        assert_eq!(
            1,
            metrics_service.get_runtime_cycle_total_since_startup_counter().get()
        );
    }

    #[tokio::test]
    async fn registered_not_able_to_sign_to_unregistered() {
        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_current_time_point()
            .once()
            .returning(|| Ok(TimePoint::new(10, 100, ChainPoint::dummy())));
        runner
            .expect_update_era_checker()
            .once()
            .returning(|_e: Epoch| Ok(()));

        let state_machine = init_state_machine(
            SignerState::RegisteredNotAbleToSign { epoch: Epoch(0) },
            runner,
        );

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");
        assert_eq!(
            SignerState::Unregistered { epoch: Epoch(10) },
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn registered_not_able_to_sign_to_registered_not_able_to_sign() {
        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_current_time_point()
            .once()
            .returning(|| Ok(TimePoint::new(10, 100, ChainPoint::dummy())));

        let state_machine = init_state_machine(
            SignerState::RegisteredNotAbleToSign { epoch: Epoch(10) },
            runner,
        );

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");
        assert_eq!(
            SignerState::RegisteredNotAbleToSign { epoch: Epoch(10) },
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn ready_to_sign_to_unregistered() {
        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_current_time_point()
            .once()
            .returning(|| Ok(TimePoint::new(10, 100, ChainPoint::dummy())));
        runner
            .expect_update_era_checker()
            .once()
            .returning(|_e: Epoch| Ok(()));

        let state_machine =
            init_state_machine(SignerState::ReadyToSign { epoch: Epoch(0) }, runner);

        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");
        assert_eq!(
            SignerState::Unregistered { epoch: Epoch(10) },
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn ready_to_sign_to_ready_to_sign_when_there_is_a_beacon_to_sign() {
        let time_point = TimePoint::dummy();
        let beacon_to_sign = BeaconToSign {
            epoch: time_point.epoch,
            signed_entity_type: SignedEntityType::MithrilStakeDistribution(time_point.epoch),
            initiated_at: DateTime::default(),
        };
        let beacon_to_sign_clone = beacon_to_sign.clone();
        let current_epoch = time_point.epoch;

        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_current_time_point()
            .once()
            .returning(move || Ok(time_point.to_owned()));
        runner
            .expect_get_beacon_to_sign()
            .once()
            .returning(move |_| Ok(Some(beacon_to_sign_clone.clone())));
        runner
            .expect_compute_message()
            .once()
            .returning(|_| Ok(ProtocolMessage::new()));
        runner
            .expect_compute_publish_single_signature()
            .once()
            .returning(|_, _| Ok(()));

        let state_machine = init_state_machine(
            SignerState::ReadyToSign {
                epoch: current_epoch,
            },
            runner,
        );
        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        assert_eq!(
            SignerState::ReadyToSign {
                epoch: current_epoch
            },
            state_machine.get_state().await,
            "state machine did not return a ReadyToSign state but {:?}",
            state_machine.get_state().await
        );
    }

    #[tokio::test]
    async fn ready_to_sign_to_ready_to_sign_when_there_no_beacon_to_sign() {
        let time_point = TimePoint::dummy();
        let current_epoch = time_point.epoch;

        let mut runner = MockSignerRunner::new();
        runner
            .expect_get_current_time_point()
            .once()
            .returning(move || Ok(time_point.to_owned()));
        runner.expect_get_beacon_to_sign().once().returning(move |_| Ok(None));

        let state_machine = init_state_machine(
            SignerState::ReadyToSign {
                epoch: current_epoch,
            },
            runner,
        );
        state_machine
            .cycle()
            .await
            .expect("Cycling the state machine should not fail");

        assert_eq!(
            SignerState::ReadyToSign {
                epoch: current_epoch
            },
            state_machine.get_state().await,
            "state machine did not return a ReadyToSign state but {:?}",
            state_machine.get_state().await
        );
    }
}
