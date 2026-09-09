use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, debug, warn};

use mithril_common::{
    AggregateSignatureType, AncillaryProofInput, StdResult,
    crypto_helper::ProtocolAggregationError,
    entities::{self},
    logging::LoggerExtensions,
    protocol::{MultiSignatureWithAncillaryData, MultiSigner as ProtocolMultiSigner},
};

use crate::dependency_injection::EpochServiceWrapper;
use crate::entities::OpenMessage;

/// MultiSigner is the cryptographic engine in charge of producing multi signatures from individual signatures
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait MultiSigner: Sync + Send {
    /// Verify a single signature
    async fn verify_single_signature(
        &self,
        message: &str,
        signature: &entities::SingleSignature,
    ) -> StdResult<()>;

    /// Verify a single signature using the stake distribution of the next epoch
    async fn verify_single_signature_for_next_stake_distribution(
        &self,
        message: &str,
        signature: &entities::SingleSignature,
    ) -> StdResult<()>;

    /// Creates a multi signature from single signatures
    async fn create_multi_signature(
        &self,
        open_message: &OpenMessage,
        ancillary_input: AncillaryProofInput,
    ) -> StdResult<Option<MultiSignatureWithAncillaryData>>;
}

/// MultiSignerImpl is an implementation of the MultiSigner
pub struct MultiSignerImpl {
    aggregate_signature_type: AggregateSignatureType,
    epoch_service: EpochServiceWrapper,
    logger: Logger,
}

impl MultiSignerImpl {
    /// MultiSignerImpl factory
    pub fn new(
        aggregate_signature_type: AggregateSignatureType,
        epoch_service: EpochServiceWrapper,
        logger: Logger,
    ) -> Self {
        let logger = logger.new_with_component_name::<Self>();
        debug!(logger, "New MultiSignerImpl created");
        Self {
            aggregate_signature_type,
            epoch_service,
            logger,
        }
    }

    fn run_verify_single_signature(
        &self,
        message: &str,
        single_signature: &entities::SingleSignature,
        protocol_multi_signer: &ProtocolMultiSigner,
    ) -> StdResult<()> {
        debug!(
            self.logger,
            "Verify single signature";
            "message" => ?message,
            "single_signature" => ?single_signature,
        );

        protocol_multi_signer
            .verify_single_signature(&message, single_signature)
            .with_context(|| {
                format!("Multi Signer can not verify single signature for message '{message:?}' from party_id '{}'", single_signature.party_id)
            })
    }
}

#[async_trait]
impl MultiSigner for MultiSignerImpl {
    /// Verify a single signature
    async fn verify_single_signature(
        &self,
        message: &str,
        single_signature: &entities::SingleSignature,
    ) -> StdResult<()> {
        let epoch_service = self.epoch_service.read().await;
        let protocol_multi_signer = epoch_service.protocol_multi_signer().with_context(
            || "Multi Signer could not get protocol multi-signer from epoch service",
        )?;

        self.run_verify_single_signature(message, single_signature, protocol_multi_signer)
    }

    async fn verify_single_signature_for_next_stake_distribution(
        &self,
        message: &str,
        single_signature: &entities::SingleSignature,
    ) -> StdResult<()> {
        let epoch_service = self.epoch_service.read().await;
        let next_protocol_multi_signer = epoch_service.next_protocol_multi_signer().with_context(
            || "Multi Signer could not get next protocol multi-signer from epoch service",
        )?;

        self.run_verify_single_signature(message, single_signature, next_protocol_multi_signer)
    }

    /// Creates a multi signature from single signatures
    async fn create_multi_signature(
        &self,
        open_message: &OpenMessage,
        ancillary_input: AncillaryProofInput,
    ) -> StdResult<Option<MultiSignatureWithAncillaryData>> {
        debug!(self.logger, ">> create_multi_signature"; "open_message" => ?open_message);

        let epoch_service = self.epoch_service.read().await;
        let protocol_multi_signer = epoch_service.protocol_multi_signer().with_context(
            || "Multi Signer could not get protocol multi-signer from epoch service",
        )?;

        match protocol_multi_signer.aggregate_single_signatures(
            &open_message.single_signatures,
            &open_message.protocol_message,
            self.aggregate_signature_type,
            ancillary_input,
        ) {
            Ok(multi_signature_with_ancillary_data) => {
                Ok(Some(multi_signature_with_ancillary_data))
            }
            Err(err) => match err.downcast_ref::<ProtocolAggregationError>() {
                Some(ProtocolAggregationError::NotEnoughSignatures(actual, expected)) => {
                    warn!(
                        self.logger,
                        "Could not compute multi-signature: Not enough signatures. Got only {actual} out of {expected}."
                    );
                    Ok(None)
                }
                _ => Err(err.context(format!(
                    "Multi Signer can not create multi-signature for entity type '{:?}'",
                    open_message.signed_entity_type
                ))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use mithril_common::entities::{CardanoDbBeacon, Epoch, SignedEntityType, SignerWithStake};
    use mithril_common::protocol::ToMessage;
    use mithril_common::test::{
        builder::MithrilFixtureBuilder,
        crypto_helper::setup_message,
        double::{Dummy, fake_data},
    };

    use crate::entities::AggregatorEpochSettings;
    use crate::services::{FakeEpochService, FakeEpochServiceBuilder};
    use crate::test::TestLogger;

    use super::*;

    fn take_signatures_until_quorum_is_almost_reached(
        signatures: &mut Vec<entities::SingleSignature>,
        quorum: usize,
    ) -> Vec<entities::SingleSignature> {
        signatures.sort_by_key(|sig| sig.won_indexes.len());

        let mut result = vec![];
        let mut nb_won_indexes = 0;

        while let Some(signature) = signatures.first() {
            if signature.won_indexes.len() + nb_won_indexes >= quorum {
                break;
            }
            nb_won_indexes += signature.won_indexes.len();
            result.push(signatures.remove(0));
        }

        result
    }

    #[tokio::test]
    async fn test_verify_single_signature() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let next_fixture = MithrilFixtureBuilder::default().with_signers(4).build();
        let multi_signer = MultiSignerImpl::new(
            AggregateSignatureType::default(),
            Arc::new(RwLock::new(
                FakeEpochServiceBuilder {
                    current_epoch_settings: AggregatorEpochSettings {
                        protocol_parameters: fixture.protocol_parameters(),
                        ..AggregatorEpochSettings::dummy()
                    },
                    next_epoch_settings: AggregatorEpochSettings {
                        protocol_parameters: next_fixture.protocol_parameters(),
                        ..AggregatorEpochSettings::dummy()
                    },
                    signer_registration_epoch_settings: AggregatorEpochSettings {
                        protocol_parameters: next_fixture.protocol_parameters(),
                        ..AggregatorEpochSettings::dummy()
                    },
                    current_signers_with_stake: fixture.signers_with_stake(),
                    next_signers_with_stake: next_fixture.signers_with_stake(),
                    ..FakeEpochServiceBuilder::dummy(epoch)
                }
                .build(),
            )),
            TestLogger::stdout(),
        );

        {
            let message = setup_message();
            let signature = fixture.signers_fixture()[0].sign(&message).unwrap();

            multi_signer
                .verify_single_signature(&message.to_message(), &signature)
                .await
                .unwrap();

            multi_signer.verify_single_signature_for_next_stake_distribution(&message.to_message(), &signature).await.expect_err(
                "single signature issued in the current epoch should not be valid for the next epoch",
            );
        }
        {
            let message = setup_message();
            let next_epoch_signature = next_fixture.signers_fixture()[0].sign(&message).unwrap();

            multi_signer
                .verify_single_signature_for_next_stake_distribution(
                    &message.to_message(),
                    &next_epoch_signature,
                )
                .await
                .unwrap();

            multi_signer.verify_single_signature(&message.to_message(), &next_epoch_signature).await.expect_err(
                "single signature issued in the next epoch should not be valid for the current epoch",
            );
        }
    }

    #[tokio::test]
    async fn test_multi_signer_multi_signature_ok() {
        let epoch = Epoch(5);
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let protocol_parameters = fixture.protocol_parameters();
        let multi_signer = MultiSignerImpl::new(
            AggregateSignatureType::default(),
            Arc::new(RwLock::new(FakeEpochService::from_fixture(epoch, &fixture))),
            TestLogger::stdout(),
        );

        let message = setup_message();

        let mut signatures = Vec::new();

        let mut expected_certificate_signers: Vec<SignerWithStake> = Vec::new();
        for signer_fixture in fixture.signers_fixture() {
            if let Some(signature) = signer_fixture.sign(&message) {
                signatures.push(signature);
                expected_certificate_signers.push(signer_fixture.signer_with_stake.to_owned())
            }
        }

        for signature in &signatures {
            multi_signer
                .verify_single_signature(&message.to_message(), signature)
                .await
                .expect("single signature should be valid");
        }

        let signatures_to_almost_reach_quorum = take_signatures_until_quorum_is_almost_reached(
            &mut signatures,
            protocol_parameters.k as usize,
        );
        assert!(
            !signatures_to_almost_reach_quorum.is_empty(),
            "they should be at least one signature that can be registered without reaching the quorum"
        );

        let mut open_message = OpenMessage {
            epoch,
            signed_entity_type: SignedEntityType::CardanoDatabase(CardanoDbBeacon {
                epoch,
                ..fake_data::beacon()
            }),
            protocol_message: message.clone(),
            is_certified: false,
            single_signatures: Vec::new(),
            ..OpenMessage::dummy()
        };

        // No signatures registered: multi-signer can't create the multi-signature
        assert!(
            multi_signer
                .create_multi_signature(&open_message, AncillaryProofInput::dummy())
                .await
                .expect("create multi signature should not fail")
                .is_none()
        );

        // Add some signatures but not enough to reach the quorum: multi-signer should not create the multi-signature
        open_message.single_signatures = signatures_to_almost_reach_quorum;

        assert!(
            multi_signer
                .create_multi_signature(&open_message, AncillaryProofInput::dummy())
                .await
                .expect("create multi signature should not fail")
                .is_none()
        );

        // Add the remaining signatures to reach the quorum: multi-signer should create a multi-signature
        open_message.single_signatures.append(&mut signatures);

        assert!(
            multi_signer
                .create_multi_signature(&open_message, AncillaryProofInput::dummy())
                .await
                .expect("create multi signature should not fail")
                .is_some(),
            "no multi-signature were computed"
        );
    }
}
