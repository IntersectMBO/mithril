use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use mithril_common::{
    StdResult,
    entities::{Epoch, Signer, SignerWithStake, StakeDistribution},
};
use mithril_persistence::store::StakeStorer;

use crate::{
    SignerRegistrationVerifier, VerificationKeyStorer, dependency_injection::EpochServiceWrapper,
};

use super::{
    LeaderAggregatorClient, SignerRecorder, SignerRegisterer, SignerRegistrationError,
    SignerRegistrationRound, SignerRegistrationRoundOpener, SignerSynchronizer,
};

/// A [MithrilSignerRegistrationFollower] supports signer registrations in a follower aggregator
pub struct MithrilSignerRegistrationFollower {
    /// Epoch service
    pub epoch_service: EpochServiceWrapper,

    /// Verification key store
    verification_key_store: Arc<dyn VerificationKeyStorer>,

    /// Signer recorder
    signer_recorder: Arc<dyn SignerRecorder>,

    /// Signer registration verifier
    signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,

    /// Leader aggregator client
    leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,

    /// Stake store
    stake_store: Arc<dyn StakeStorer>,
}

impl MithrilSignerRegistrationFollower {
    /// MithrilSignerRegistererFollower factory
    pub fn new(
        epoch_service: EpochServiceWrapper,
        verification_key_store: Arc<dyn VerificationKeyStorer>,
        signer_recorder: Arc<dyn SignerRecorder>,
        signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
        leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
        stake_store: Arc<dyn StakeStorer>,
    ) -> Self {
        Self {
            epoch_service,
            verification_key_store,
            signer_recorder,
            signer_registration_verifier,
            leader_aggregator_client,
            stake_store,
        }
    }

    async fn synchronize_signers(
        &self,
        epoch: Epoch,
        signers: &[Signer],
        stake_distribution: &StakeDistribution,
    ) -> Result<(), SignerRegistrationError> {
        for signer in signers {
            let signer_with_stake = self
                .signer_registration_verifier
                .verify(signer, stake_distribution, epoch)
                .await
                .map_err(|err| {
                    SignerRegistrationError::InvalidSignerRegistration(
                        signer.party_id.clone(),
                        epoch,
                        err,
                    )
                })?;

            self.signer_recorder
                .record_signer_registration(signer_with_stake.party_id.clone())
                .await
                .map_err(|err| {
                    SignerRegistrationError::FailedSignerRecorder(
                        signer_with_stake.party_id.clone(),
                        epoch,
                        err,
                    )
                })?;

            self
                .verification_key_store
                .save_verification_key(epoch, signer_with_stake.clone())
                .await
                .with_context(|| {
                    format!(
                        "VerificationKeyStorer can not save verification keys for party_id: '{}' for epoch: '{}'",
                        signer_with_stake.party_id,
                        epoch
                    )
                })
                .map_err(SignerRegistrationError::Store)?;
        }

        self.epoch_service
            .write()
            .await
            .update_next_signers_with_stake()
            .await
            .map_err(SignerRegistrationError::EpochService)?;

        Ok(())
    }
}

#[async_trait]
impl SignerSynchronizer for MithrilSignerRegistrationFollower {
    async fn can_synchronize_signers(&self, epoch: Epoch) -> Result<bool, SignerRegistrationError> {
        Ok(self
            .leader_aggregator_client
            .retrieve_epoch_settings()
            .await
            .with_context(|| "can_synchronize_signers failed")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?
            .is_some_and(|leader_epoch_settings| epoch == leader_epoch_settings.epoch))
    }

    async fn synchronize_all_signers(&self) -> Result<(), SignerRegistrationError> {
        let leader_epoch_settings = self
            .leader_aggregator_client
            .retrieve_epoch_settings()
            .await
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?
            .with_context(|| "Leader aggregator did not return any epoch settings")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?;
        let registration_epoch =
            leader_epoch_settings.epoch.offset_to_leader_synchronization_epoch();
        let next_signers = leader_epoch_settings.next_signers;
        let stake_distribution = self
            .stake_store
            .get_stakes(registration_epoch)
            .await
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::Store)?
            .with_context(|| "Follower aggregator did not return any stake distribution")
            .map_err(SignerRegistrationError::Store)?;
        self.synchronize_signers(registration_epoch, &next_signers, &stake_distribution)
            .await?;

        Ok(())
    }
}

#[async_trait]
impl SignerRegisterer for MithrilSignerRegistrationFollower {
    async fn register_signer(
        &self,
        _epoch: Epoch,
        _signer: &Signer,
    ) -> Result<SignerWithStake, SignerRegistrationError> {
        Err(SignerRegistrationError::RegistrationRoundAlwaysClosedOnFollowerAggregator)
    }

    async fn get_current_round(&self) -> Option<SignerRegistrationRound> {
        None
    }
}

#[async_trait]
impl SignerRegistrationRoundOpener for MithrilSignerRegistrationFollower {
    async fn open_registration_round(
        &self,
        _registration_epoch: Epoch,
        _stake_distribution: StakeDistribution,
    ) -> StdResult<()> {
        Ok(())
    }

    async fn close_registration_round(&self) -> StdResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use mithril_common::messages::{
        EpochSettingsMessage, SignerMessagePart, TryFromMessageAdapter,
    };
    use mithril_common::test::{builder::MithrilFixtureBuilder, double::Dummy};

    use crate::{
        database::{repository::SignerRegistrationStore, test_helper::main_db_connection},
        message_adapters::FromEpochSettingsAdapter,
        services::{
            FakeEpochService, MockLeaderAggregatorClient, MockSignerRecorder,
            MockSignerRegistrationVerifier,
        },
        test::double::mocks::MockStakeStore,
    };

    use super::*;

    use test_utils::*;

    mod test_utils {
        use tokio::sync::RwLock;

        use super::*;

        /// MithrilSignerRegistrationFollowerBuilder is a test builder for [MithrilSignerRegistrationFollower]
        pub struct MithrilSignerRegistrationFollowerBuilder {
            epoch_service: EpochServiceWrapper,
            signer_recorder: Arc<dyn SignerRecorder>,
            signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
            leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
            stake_store: Arc<dyn StakeStorer>,
            verification_key_store: Arc<dyn VerificationKeyStorer>,
        }

        impl Default for MithrilSignerRegistrationFollowerBuilder {
            fn default() -> Self {
                Self {
                    epoch_service: Arc::new(RwLock::new(FakeEpochService::without_data())),
                    signer_recorder: Arc::new(MockSignerRecorder::new()),
                    signer_registration_verifier: Arc::new(MockSignerRegistrationVerifier::new()),
                    leader_aggregator_client: Arc::new(MockLeaderAggregatorClient::new()),
                    stake_store: Arc::new(MockStakeStore::new()),
                    verification_key_store: Arc::new(SignerRegistrationStore::new(
                        Arc::new(main_db_connection().unwrap()),
                        None,
                    )),
                }
            }
        }

        impl MithrilSignerRegistrationFollowerBuilder {
            pub fn with_epoch_service(self, epoch_service: FakeEpochService) -> Self {
                Self {
                    epoch_service: Arc::new(RwLock::new(epoch_service)),
                    ..self
                }
            }

            pub fn with_signer_recorder(self, signer_recorder: Arc<dyn SignerRecorder>) -> Self {
                Self {
                    signer_recorder,
                    ..self
                }
            }

            pub fn with_signer_registration_verifier(
                self,
                signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
            ) -> Self {
                Self {
                    signer_registration_verifier,
                    ..self
                }
            }

            pub fn with_leader_aggregator_client(
                self,
                leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
            ) -> Self {
                Self {
                    leader_aggregator_client,
                    ..self
                }
            }

            pub fn with_stake_store(self, stake_store: Arc<dyn StakeStorer>) -> Self {
                Self {
                    stake_store,
                    ..self
                }
            }

            pub fn build(self) -> MithrilSignerRegistrationFollower {
                MithrilSignerRegistrationFollower {
                    epoch_service: self.epoch_service,
                    verification_key_store: self.verification_key_store,
                    signer_recorder: self.signer_recorder,
                    signer_registration_verifier: self.signer_registration_verifier,
                    leader_aggregator_client: self.leader_aggregator_client,
                    stake_store: self.stake_store,
                }
            }
        }
    }

    #[tokio::test]
    async fn open_close_registration_always_succeeds() {
        let signer_registration_follower =
            MithrilSignerRegistrationFollowerBuilder::default().build();
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let stake_distribution = fixture.stake_distribution();

        signer_registration_follower
            .open_registration_round(registration_epoch, stake_distribution)
            .await
            .expect("signer registration round opening should not fail");

        signer_registration_follower
            .close_registration_round()
            .await
            .expect("signer registration round opening should not fail");
    }

    #[tokio::test]
    async fn register_signer_always_fails() {
        let signer_registration_follower =
            MithrilSignerRegistrationFollowerBuilder::default().build();
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();

        signer_registration_follower
            .register_signer(registration_epoch, &signer_to_register)
            .await
            .expect_err("signer registration should always fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_succeeds() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify()
                    .returning(|signer, _, _| {
                        Ok(SignerWithStake::from_signer(signer.to_owned(), 123))
                    })
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower.synchronize_all_signers().await.unwrap();
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_one_signer_registration_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(4);
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Err(anyhow!("an error")))
                    .times(1);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify()
                    .returning(|signer, _, _| {
                        Ok(SignerWithStake::from_signer(signer.to_owned(), 123))
                    })
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_epoch_service_update_next_signers_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_epoch_service({
                let mut epoch_service = FakeEpochService::without_data();
                epoch_service.toggle_errors(false, false, true);

                epoch_service
            })
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify()
                    .returning(|signer, _, _| {
                        Ok(SignerWithStake::from_signer(signer.to_owned(), 123))
                    })
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_fetching_epoch_settings_fails() {
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Err(anyhow!("an error")))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_fetching_stakes_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Err(anyhow!("an error")))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }
}
