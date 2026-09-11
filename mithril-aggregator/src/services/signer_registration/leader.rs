use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::RwLock;

use mithril_common::{
    StdResult,
    entities::{Epoch, Signer, SignerWithStake, StakeDistribution},
};

use crate::{SignerRegistrationVerifier, VerificationKeyStorer};

use super::{
    SignerRecorder, SignerRegisterer, SignerRegistrationError, SignerRegistrationRound,
    SignerRegistrationRoundOpener, SignerSynchronizer,
};

/// A [MithrilSignerRegistrationLeader] supports signer registrations in a leader aggregator
pub struct MithrilSignerRegistrationLeader {
    /// Current signer registration round
    current_round: RwLock<Option<SignerRegistrationRound>>,

    /// Verification key store
    verification_key_store: Arc<dyn VerificationKeyStorer>,

    /// Signer recorder
    signer_recorder: Arc<dyn SignerRecorder>,

    /// Signer registration verifier
    signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
}

impl MithrilSignerRegistrationLeader {
    /// MithrilSignerRegistererLeader factory
    pub fn new(
        verification_key_store: Arc<dyn VerificationKeyStorer>,
        signer_recorder: Arc<dyn SignerRecorder>,
        signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
    ) -> Self {
        Self {
            current_round: RwLock::new(None),
            verification_key_store,
            signer_recorder,
            signer_registration_verifier,
        }
    }

    #[cfg(test)]
    pub(crate) async fn get_current_round(&self) -> Option<SignerRegistrationRound> {
        self.current_round.read().await.as_ref().cloned()
    }
}

#[async_trait]
impl SignerRegistrationRoundOpener for MithrilSignerRegistrationLeader {
    async fn open_registration_round(
        &self,
        registration_epoch: Epoch,
        stake_distribution: StakeDistribution,
    ) -> StdResult<()> {
        let mut current_round = self.current_round.write().await;
        *current_round = Some(SignerRegistrationRound {
            epoch: registration_epoch,
            stake_distribution,
        });

        Ok(())
    }

    async fn close_registration_round(&self) -> StdResult<()> {
        let mut current_round = self.current_round.write().await;
        *current_round = None;

        Ok(())
    }
}

#[async_trait]
impl SignerRegisterer for MithrilSignerRegistrationLeader {
    async fn register_signer(
        &self,
        epoch: Epoch,
        signer: &Signer,
    ) -> Result<SignerWithStake, SignerRegistrationError> {
        let registration_round = self.current_round.read().await;
        let registration_round = registration_round
            .as_ref()
            .ok_or(SignerRegistrationError::RegistrationRoundNotYetOpened)?;
        if registration_round.epoch != epoch {
            return Err(SignerRegistrationError::RegistrationRoundUnexpectedEpoch {
                current_round_epoch: registration_round.epoch,
                received_epoch: epoch,
            });
        }

        let signer_save = self
            .signer_registration_verifier
            .verify(
                signer,
                &registration_round.stake_distribution,
                #[cfg(feature = "future_snark")]
                epoch,
            )
            .await
            .map_err(|err| {
                SignerRegistrationError::InvalidSignerRegistration(
                    signer.party_id.clone(),
                    epoch,
                    err,
                )
            })?;

        self.signer_recorder
            .record_signer_registration(signer_save.party_id.clone())
            .await
            .map_err(|err| {
                SignerRegistrationError::FailedSignerRecorder(
                    signer_save.party_id.clone(),
                    registration_round.epoch,
                    err,
                )
            })?;

        match self
            .verification_key_store
            .save_verification_key(registration_round.epoch, signer_save.clone())
            .await
            .with_context(|| {
                format!(
                    "VerificationKeyStorer can not save verification keys for party_id: '{}' for epoch: '{}'",
                    signer_save.party_id,
                    registration_round.epoch
                )
            })
            .map_err(SignerRegistrationError::Store)?
        {
            Some(_) => Err(SignerRegistrationError::ExistingSigner(Box::new(
                signer_save,
            ))),
            None => Ok(signer_save),
        }
    }

    async fn get_current_round(&self) -> Option<SignerRegistrationRound> {
        self.current_round.read().await.as_ref().cloned()
    }
}

#[async_trait]
impl SignerSynchronizer for MithrilSignerRegistrationLeader {
    async fn can_synchronize_signers(
        &self,
        _epoch: Epoch,
    ) -> Result<bool, SignerRegistrationError> {
        Ok(false)
    }

    async fn synchronize_all_signers(&self) -> Result<(), SignerRegistrationError> {
        Err(SignerRegistrationError::SignerSynchronizationUnavailableOnLeaderAggregator)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use mithril_common::{
        entities::{Epoch, Signer, SignerWithStake},
        test::builder::MithrilFixtureBuilder,
    };

    use crate::{
        MithrilSignerRegistrationLeader, SignerRegisterer, SignerRegistrationRoundOpener,
        VerificationKeyStorer,
        database::{repository::SignerRegistrationStore, test_helper::main_db_connection},
        services::{MockSignerRecorder, MockSignerRegistrationVerifier, SignerSynchronizer},
    };

    use test_utils::*;

    use super::*;

    mod test_utils {
        use super::*;

        /// MithrilSignerRegistrationLeaderBuilder is a test builder for [MithrilSignerRegistrationFollower]
        pub struct MithrilSignerRegistrationLeaderBuilder {
            signer_recorder: Arc<dyn SignerRecorder>,
            signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
            verification_key_store: Arc<dyn VerificationKeyStorer>,
        }

        impl Default for MithrilSignerRegistrationLeaderBuilder {
            fn default() -> Self {
                Self {
                    signer_recorder: Arc::new(MockSignerRecorder::new()),
                    signer_registration_verifier: Arc::new(MockSignerRegistrationVerifier::new()),
                    verification_key_store: Arc::new(SignerRegistrationStore::new(
                        Arc::new(main_db_connection().unwrap()),
                        None,
                    )),
                }
            }
        }

        impl MithrilSignerRegistrationLeaderBuilder {
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

            pub fn build(self) -> MithrilSignerRegistrationLeader {
                MithrilSignerRegistrationLeader {
                    current_round: RwLock::new(None),
                    verification_key_store: self.verification_key_store,
                    signer_recorder: self.signer_recorder,
                    signer_registration_verifier: self.signer_registration_verifier,
                }
            }
        }
    }

    #[tokio::test]
    async fn can_register_signer_if_registration_round_is_opened_with_operational_certificate() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let stake_distribution = fixture.stake_distribution();
        let signer_registration_leader = MithrilSignerRegistrationLeaderBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .once();

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .once();

                Arc::new(signer_registration_verifier)
            })
            .build();

        signer_registration_leader
            .open_registration_round(registration_epoch, stake_distribution)
            .await
            .expect("signer registration round opening should not fail");

        signer_registration_leader
            .register_signer(registration_epoch, &signer_to_register)
            .await
            .expect("signer registration should not fail");

        let registered_signers = &signer_registration_leader
            .verification_key_store
            .get_verification_keys(registration_epoch)
            .await
            .expect("registered signers retrieval should not fail");

        assert_eq!(
            &Some(HashMap::from([(
                signer_to_register.party_id.clone(),
                signer_to_register
            )])),
            registered_signers
        );
    }

    #[tokio::test]
    async fn can_register_signer_if_registration_round_is_opened_without_operational_certificate() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let stake_distribution = fixture.stake_distribution();
        let signer_registration_leader = MithrilSignerRegistrationLeaderBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .once();

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .once();

                Arc::new(signer_registration_verifier)
            })
            .build();

        signer_registration_leader
            .open_registration_round(registration_epoch, stake_distribution)
            .await
            .expect("signer registration round opening should not fail");

        signer_registration_leader
            .register_signer(registration_epoch, &signer_to_register)
            .await
            .expect("signer registration should not fail");

        let registered_signers = &signer_registration_leader
            .verification_key_store
            .get_verification_keys(registration_epoch)
            .await
            .expect("registered signers retrieval should not fail");

        assert_eq!(
            &Some(HashMap::from([(
                signer_to_register.party_id.clone(),
                signer_to_register
            )])),
            registered_signers
        );
    }

    #[tokio::test]
    async fn cant_register_signer_if_registration_round_is_not_opened() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let signer_registration_leader = MithrilSignerRegistrationLeaderBuilder::default().build();

        signer_registration_leader
            .register_signer(registration_epoch, &signer_to_register)
            .await
            .expect_err("signer registration should fail if no round opened");
    }

    #[tokio::test]
    async fn synchronize_all_signers_always_fails() {
        let signer_registration_leader = MithrilSignerRegistrationLeaderBuilder::default().build();

        signer_registration_leader
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_signers");
    }
}
