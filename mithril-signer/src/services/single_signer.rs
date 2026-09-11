use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use hex::ToHex;
use slog::{Logger, info, trace, warn};
use thiserror::Error;

use mithril_common::crypto_helper::{KesPeriod, KesSigner, ProtocolInitializer};
#[cfg(feature = "future_snark")]
use mithril_common::entities::{Epoch, SignerWithStake, SupportedEra};
use mithril_common::entities::{
    PartyId, ProtocolMessage, ProtocolParameters, SingleSignature, Stake,
};
use mithril_common::logging::LoggerExtensions;
use mithril_common::protocol::{SignerBuilder, SingleSigner as ProtocolSingleSigner};
use mithril_common::{StdError, StdResult};

use crate::dependency_injection::EpochServiceWrapper;

/// This is responsible for creating new instances of ProtocolInitializer.
pub struct MithrilProtocolInitializerBuilder {}

impl MithrilProtocolInitializerBuilder {
    /// Create a ProtocolInitializer instance.
    pub fn build(
        stake: &Stake,
        protocol_parameters: &ProtocolParameters,
        kes_signer: Option<Arc<dyn KesSigner>>,
        kes_period: Option<KesPeriod>,
        #[cfg(feature = "future_snark")] epoch: Epoch,
    ) -> StdResult<ProtocolInitializer> {
        let mut rng = rand_core::OsRng;
        let protocol_initializer = ProtocolInitializer::setup(
            protocol_parameters.to_owned().into(),
            kes_signer,
            kes_period,
            stake.to_owned(),
            #[cfg(feature = "future_snark")]
            epoch,
            &mut rng,
        )?;

        Ok(protocol_initializer)
    }
}

/// The SingleSigner is the structure responsible for issuing [SingleSignature].
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SingleSigner: Sync + Send {
    /// Computes single signature
    async fn compute_single_signature(
        &self,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<Option<SingleSignature>>;

    /// Get party id
    fn get_party_id(&self) -> PartyId;
}

/// SingleSigner error structure.
#[derive(Error, Debug)]
pub enum SingleSignerError {
    /// Cryptographic Signer creation error.
    #[error("the protocol signer creation failed")]
    ProtocolSignerCreationFailure(#[source] StdError),

    /// Signature Error
    #[error("Signature Error")]
    SignatureFailed(#[source] StdError),

    /// Avk computation Error
    #[error("Aggregate verification key computation Error")]
    AggregateVerificationKeyComputationFailed(#[source] StdError),
}

/// Implementation of the SingleSigner.
pub struct MithrilSingleSigner {
    party_id: PartyId,
    epoch_service: EpochServiceWrapper,
    logger: Logger,
}

impl MithrilSingleSigner {
    /// Create a new instance of the MithrilSingleSigner.
    pub fn new(party_id: PartyId, epoch_service: EpochServiceWrapper, logger: Logger) -> Self {
        Self {
            party_id,
            epoch_service,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn build_protocol_single_signer(&self) -> StdResult<ProtocolSingleSigner> {
        let epoch_service = self.epoch_service.read().await;
        let protocol_initializer =
            epoch_service.protocol_initializer()?.as_ref().with_context(|| {
                format!(
                    "Can not Sign or Compute AVK, No protocol initializer found for party_id: '{}'",
                    self.party_id.clone()
                )
            })?;

        #[cfg(not(feature = "future_snark"))]
        let protocol_initializer = protocol_initializer.clone();
        #[cfg(feature = "future_snark")]
        let mut protocol_initializer = protocol_initializer.clone();

        let current_signers_with_stake = epoch_service.current_signers_with_stake().await?;

        #[cfg(feature = "future_snark")]
        let current_signers_with_stake = {
            if epoch_service.mithril_era()? == SupportedEra::Pythagoras {
                protocol_initializer.strip_snark_keys();
                SignerWithStake::strip_snark_fields(current_signers_with_stake)
            } else {
                current_signers_with_stake
            }
        };

        let builder = SignerBuilder::new(
            &current_signers_with_stake,
            &protocol_initializer.get_protocol_parameters().into(),
            #[cfg(feature = "future_snark")]
            epoch_service.epoch_of_current_data()?,
        )
        .with_context(|| "Mithril Single Signer can not build signer")
        .map_err(SingleSignerError::ProtocolSignerCreationFailure)?;

        let single_signer = builder
            .restore_signer_from_initializer(self.party_id.clone(), protocol_initializer)
            .with_context(|| {
                format!(
                    "Mithril Single Signer can not restore signer with party_id: '{}'",
                    self.party_id.clone()
                )
            })
            .map_err(SingleSignerError::ProtocolSignerCreationFailure)?;

        Ok(single_signer)
    }
}

#[async_trait]
impl SingleSigner for MithrilSingleSigner {
    async fn compute_single_signature(
        &self,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<Option<SingleSignature>> {
        let protocol_single_signer = self.build_protocol_single_signer().await?;

        info!(
            self.logger, "Signing protocol message";
            "protocol_message" =>  #?protocol_message,
            "signed message" => protocol_message.compute_hash().encode_hex::<String>()
        );
        let signature = protocol_single_signer
            .sign(protocol_message)
            .with_context(|| {
                format!(
                    "Mithril Single Signer can not sign protocol_message: '{protocol_message:?}'"
                )
            })
            .map_err(SingleSignerError::SignatureFailed)?;

        match &signature {
            Some(signature) => {
                trace!(
                    self.logger,
                    "Party #{}: lottery #{:?} won", signature.party_id, &signature.won_indexes
                );
            }
            None => {
                warn!(
                    self.logger,
                    "No signature computed, all lotteries were lost"
                );
            }
        };

        Ok(signature)
    }

    /// Get party id
    fn get_party_id(&self) -> PartyId {
        self.party_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::database::repository::{ProtocolInitializerRepository, StakePoolStore};
    use crate::database::test_helper::main_db_connection;
    use crate::services::MithrilEpochService;
    use crate::test::TestLogger;
    use mithril_common::crypto_helper::ProtocolClerk;
    use mithril_common::entities::{Epoch, ProtocolMessagePartKey};
    use mithril_common::test::builder::MithrilFixtureBuilder;
    use mithril_persistence::store::StakeStorer;

    use super::*;

    use mithril_common::entities::SupportedEra;
    use mithril_era::EraChecker;

    async fn build_single_signer_for_era(
        era: SupportedEra,
        signers: Vec<mithril_common::entities::Signer>,
    ) -> (
        MithrilSingleSigner,
        mithril_common::test::builder::MithrilFixture,
    ) {
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let current_signer = &fixture.signers_fixture()[0];
        let logger = TestLogger::stdout();
        let connection = Arc::new(main_db_connection().unwrap());
        let stake_store = {
            let store = Arc::new(StakePoolStore::new(connection.clone(), None));
            store
                .save_stakes(
                    Epoch(10).offset_to_signer_retrieval_epoch().unwrap(),
                    fixture.stake_distribution(),
                )
                .await
                .unwrap();
            store
        };
        let protocol_initializer_store =
            Arc::new(ProtocolInitializerRepository::new(connection, None));
        let era_checker = Arc::new(EraChecker::new(era, Epoch::default()));
        let epoch_service = MithrilEpochService::new(
            era_checker,
            stake_store,
            protocol_initializer_store,
            logger.clone(),
        )
        .set_data_to_default_or_fake(Epoch(10))
        .alter_data(|data| {
            data.mithril_era = era;
            data.protocol_initializer = Some(current_signer.protocol_initializer.clone());
            data.current_signers = signers;
        });

        let single_signer = MithrilSingleSigner::new(
            current_signer.party_id(),
            Arc::new(RwLock::new(epoch_service)),
            logger,
        );

        (single_signer, fixture)
    }

    async fn sign_and_verify(
        single_signer: &MithrilSingleSigner,
        fixture: &mithril_common::test::builder::MithrilFixture,
    ) {
        let current_signer = &fixture.signers_fixture()[0];
        let clerk = ProtocolClerk::new_clerk_from_signer(&current_signer.protocol_signer);
        let avk = clerk.compute_aggregate_verification_key();

        let mut protocol_message = ProtocolMessage::new();
        protocol_message
            .set_message_part(ProtocolMessagePartKey::SnapshotDigest, "digest".to_string());
        let sign_result = single_signer
            .compute_single_signature(&protocol_message)
            .await
            .expect("single signer should not fail")
            .expect("single signer should produce a signature here");

        let expected_message = protocol_message.compute_hash().as_bytes().to_vec();
        let decoded_sig = sign_result.to_protocol_signature();
        assert!(
            decoded_sig
                .verify(
                    &fixture.protocol_parameters().into(),
                    &current_signer.protocol_signer.get_bls_verification_key(),
                    &current_signer.protocol_signer.get_stake(),
                    &avk,
                    &expected_message,
                    #[cfg(feature = "future_snark")]
                    None,
                )
                .is_ok(),
            "produced single signature should be valid"
        );
    }

    #[tokio::test]
    async fn compute_single_signature_success() {
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let signers = fixture.signers();
        let (single_signer, fixture) =
            build_single_signer_for_era(SupportedEra::Pythagoras, signers).await;
        sign_and_verify(&single_signer, &fixture).await;
    }

    #[cfg(feature = "future_snark")]
    mod snark_key_stripping {
        use super::*;

        #[tokio::test]
        async fn signing_succeeds_in_lagrange_era_with_snark_keys() {
            let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
            let signers = fixture.signers();
            let (single_signer, fixture) =
                build_single_signer_for_era(SupportedEra::Lagrange, signers).await;

            sign_and_verify(&single_signer, &fixture).await;
        }

        #[tokio::test]
        async fn signing_succeeds_in_pythagoras_era_with_snark_keys() {
            let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
            let signers = fixture.signers();
            let (single_signer, fixture) =
                build_single_signer_for_era(SupportedEra::Pythagoras, signers).await;

            sign_and_verify(&single_signer, &fixture).await;
        }

        #[tokio::test]
        async fn signing_succeeds_in_pythagoras_era_when_signers_already_lack_snark_keys() {
            let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
            let signers_without_snark_keys: Vec<_> = fixture
                .signers()
                .into_iter()
                .map(|mut signer| {
                    signer.verification_key_for_snark = None;
                    signer.verification_key_signature_for_snark = None;
                    signer
                })
                .collect();
            let (single_signer, fixture) =
                build_single_signer_for_era(SupportedEra::Pythagoras, signers_without_snark_keys)
                    .await;

            sign_and_verify(&single_signer, &fixture).await;
        }
    }
}
