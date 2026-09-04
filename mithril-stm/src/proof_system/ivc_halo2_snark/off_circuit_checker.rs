use anyhow::anyhow;

use crate::{
    AggregationError, AncillaryProofInput, BaseFieldElement, StmResult,
    circuits::halo2_ivc::{PREIMAGE_SIZE, ProtocolMessagePreimage, types::MessageHash},
    proof_system::{
        IvcRollingState,
        ivc_halo2_snark::{
            errors::IvcProofError,
            interface::IvcOffCircuitChecker,
            proof::IvcGenesisBootstrapInput,
            prover_input_helpers::{IvcTransitionType, create_snark_message_for_next_state},
        },
    },
};

/// Production implementation of `IvcOffCircuitChecker`. Stateless: every check is a pure
/// function of its arguments, so no setup or trusted material is needed to construct one.
#[derive(Debug)]
pub(crate) struct RealIvcOffCircuitChecker;

impl IvcOffCircuitChecker for RealIvcOffCircuitChecker {
    fn check(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        self.check_genesis(ancillary_input)?;
        self.check_rolling_state(msg, aggregate_verification_key_merkle_root, ancillary_input)?;
        self.check_protocol_message(msg, aggregate_verification_key_merkle_root, ancillary_input)?;
        Ok(())
    }

    fn check_genesis(&self, ancillary_input: &AncillaryProofInput) -> StmResult<()> {
        let genesis_data = ancillary_input.genesis_data();

        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
        genesis_verifying_key.is_valid()?;

        let genesis_message: MessageHash = genesis_data.genesis_message_preimage().try_into()?;

        let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;
        genesis_bootstrap.genesis_signature.verify(
            &[BaseFieldElement::from(genesis_message.as_field())],
            &genesis_verifying_key,
        )?;
        Ok(())
    }

    fn check_rolling_state(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        let rolling_state = ancillary_input
            .prover_data()
            .and_then(|prover_data| prover_data.as_ivc_rolling_state());

        IvcRollingState::ensure_advanceable_rolling_state(rolling_state)?;

        let Some(rolling_state) = rolling_state else {
            return Ok(());
        };

        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        let transition_type =
            IvcTransitionType::try_compute_transition_type(rolling_state, &preimage)?;
        rolling_state.assert_correct_parameters(
            &preimage,
            aggregate_verification_key_merkle_root,
            msg,
            transition_type,
        )?;
        Self::assert_protocol_parameters_unchanged(rolling_state)?;

        Ok(())
    }

    fn check_protocol_message(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        let (certificate_message_hash, _) =
            create_snark_message_for_next_state(aggregate_verification_key_merkle_root, msg)?;

        let recomputed_hash: MessageHash = (&preimage).try_into()?;
        if recomputed_hash != certificate_message_hash {
            return Err(IvcProofError::MessagePreimageMismatch.into());
        }

        Ok(())
    }
}

impl RealIvcOffCircuitChecker {
    /// Asserts that the rolling state's protocol parameters have not diverged from their
    /// lookahead value. At genesis `protocol_parameters` is zeroed while `next_protocol_parameters`
    /// carries the bootstrap value, so genesis is exempt; every step after that must have the two
    /// equal, since changing protocol parameters between epochs isn't currently supported.
    pub(crate) fn assert_protocol_parameters_unchanged(
        rolling_state: &IvcRollingState,
    ) -> StmResult<()> {
        if !rolling_state.is_genesis()
            && rolling_state.state().protocol_parameters
                != rolling_state.state().next_protocol_parameters
        {
            return Err(IvcProofError::ProtocolParametersChanged.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AncillaryGenesisData, AncillaryProverData,
        circuits::halo2_ivc::{
            tests::common::asset_readers::{
                load_embedded_following_certificate_in_epoch_asset,
                load_embedded_genesis_benchmark_fixture, load_embedded_recursive_chain_state_asset,
            },
            types::ProtocolParametersHash,
        },
        signature_scheme::{
            BaseFieldElement, ScalarFieldElement, SchnorrSigningKey, SchnorrVerificationKey,
        },
    };

    use super::*;

    fn rolling_state_from_chain_state() -> IvcRollingState {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        )
    }

    mod check_genesis {
        use super::*;

        #[test]
        fn rejects_missing_genesis_verification_key() {
            let genesis_data = AncillaryGenesisData::new(vec![0u8; PREIMAGE_SIZE], None, None);
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE]);

            let err = RealIvcOffCircuitChecker
                .check_genesis(&ancillary_input)
                .expect_err("missing genesis verification key must be rejected");

            assert_eq!(
                err.downcast_ref::<AggregationError>(),
                Some(&AggregationError::MissingGenesisVerificationKey)
            );
        }

        #[test]
        fn rejects_invalid_genesis_verification_key() {
            let invalid_key = SchnorrVerificationKey::new_from_signing_key(SchnorrSigningKey(
                ScalarFieldElement::get_zero(),
            ));
            let genesis_data =
                AncillaryGenesisData::new(vec![0u8; PREIMAGE_SIZE], None, Some(invalid_key));
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE]);

            RealIvcOffCircuitChecker
                .check_genesis(&ancillary_input)
                .expect_err("invalid genesis verification key must be rejected");
        }

        #[test]
        fn rejects_missing_genesis_signature() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let signing_key = SchnorrSigningKey::generate(&mut rng);
            let genesis_verification_key =
                SchnorrVerificationKey::new_from_signing_key(signing_key);

            let genesis_data = AncillaryGenesisData::new(
                vec![0u8; PREIMAGE_SIZE],
                None,
                Some(genesis_verification_key),
            );
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE]);

            let err = RealIvcOffCircuitChecker
                .check_genesis(&ancillary_input)
                .expect_err("missing genesis signature must be rejected");

            assert_eq!(
                err.root_cause().to_string(),
                "Missing genesis Schnorr signature."
            );
        }

        #[test]
        fn rejects_genesis_signature_over_wrong_message() {
            let genesis_fixture = load_embedded_genesis_benchmark_fixture()
                .expect("genesis benchmark fixture should load");

            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            let unrelated_signing_key = SchnorrSigningKey::generate(&mut rng);
            let wrong_signature = unrelated_signing_key
                .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
                .expect("sign_standard should succeed for a synthetic message");

            let genesis_data = AncillaryGenesisData::new(
                genesis_fixture.genesis_protocol_message_preimage.to_vec(),
                Some(wrong_signature),
                Some(genesis_fixture.genesis_verification_key),
            );
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE]);

            RealIvcOffCircuitChecker
                .check_genesis(&ancillary_input)
                .expect_err("a genesis signature over the wrong message must be rejected");
        }

        #[test]
        fn accepts_valid_genesis_data() {
            let genesis_fixture = load_embedded_genesis_benchmark_fixture()
                .expect("genesis benchmark fixture should load");

            let genesis_data = AncillaryGenesisData::new(
                genesis_fixture.genesis_protocol_message_preimage.to_vec(),
                Some(genesis_fixture.genesis_signature),
                Some(genesis_fixture.genesis_verification_key),
            );
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE]);

            RealIvcOffCircuitChecker
                .check_genesis(&ancillary_input)
                .expect("consistent genesis data should pass");
        }
    }

    mod check_rolling_state {
        use crate::circuits::halo2_ivc::state::State;

        use super::*;

        #[test]
        fn accepts_when_no_rolling_state() {
            let ancillary_input = AncillaryProofInput::new(
                None,
                AncillaryGenesisData::dummy(),
                vec![0u8; PREIMAGE_SIZE],
            );

            RealIvcOffCircuitChecker
                .check_rolling_state(&[0u8; 32], &[0u8; 32], &ancillary_input)
                .expect("no rolling state means nothing to check here");
        }

        #[test]
        fn rejects_genesis_shaped_existing_rolling_state() {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let signing_key = SchnorrSigningKey::generate(&mut rng);
            let genesis_signature = signing_key
                .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
                .expect("genesis signature should be produced");
            let genesis_rolling_state = IvcRollingState::genesis(genesis_signature, &[]);

            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(genesis_rolling_state)),
                AncillaryGenesisData::dummy(),
                vec![0u8; PREIMAGE_SIZE],
            );

            RealIvcOffCircuitChecker
                .check_rolling_state(&[0u8; 32], &[0u8; 32], &ancillary_input)
                .expect_err("a genesis-shaped existing rolling state must be rejected");
        }

        #[test]
        fn accepts_consistent_same_epoch_step() {
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(
                    rolling_state_from_chain_state(),
                )),
                AncillaryGenesisData::dummy(),
                step.message_preimage.to_vec(),
            );

            RealIvcOffCircuitChecker
                .check_rolling_state(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect("consistent same-epoch step should pass");
        }

        #[test]
        fn rejects_when_protocol_parameters_diverged() {
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");

            // Only current `protocol_parameters` diverges from `next_protocol_parameters`;
            // assert_correct_parameters never checks the current value, so this reaches the
            // protocol-parameters-unchanged check specifically.
            let diverged_state = State::new(
                chain_state.state.step_counter,
                chain_state.state.message,
                chain_state.state.merkle_tree_commitment,
                chain_state.state.next_merkle_tree_commitment,
                ProtocolParametersHash::from_field(BaseFieldElement::from(999u64).0),
                chain_state.state.next_protocol_parameters,
                chain_state.state.current_epoch,
            );
            let rolling_state = IvcRollingState::new(
                diverged_state,
                chain_state.ivc_proof,
                chain_state.accumulator,
                chain_state.genesis_signature,
            );
            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(rolling_state)),
                AncillaryGenesisData::dummy(),
                step.message_preimage.to_vec(),
            );

            RealIvcOffCircuitChecker
                .check_rolling_state(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect_err("diverged protocol parameters must be rejected");
        }
    }

    mod check_protocol_message {
        use super::*;

        #[test]
        fn rejects_wrong_size_preimage() {
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let ancillary_input =
                AncillaryProofInput::new(None, AncillaryGenesisData::dummy(), vec![0u8; 3]);

            RealIvcOffCircuitChecker
                .check_protocol_message(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect_err("wrong-size preimage must be rejected");
        }

        #[test]
        fn rejects_mismatched_message_hash() {
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let ancillary_input = AncillaryProofInput::new(
                None,
                AncillaryGenesisData::dummy(),
                vec![0u8; PREIMAGE_SIZE],
            );

            RealIvcOffCircuitChecker
                .check_protocol_message(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect_err("mismatched preimage must be rejected");
        }

        #[test]
        fn accepts_matching_message_hash() {
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let ancillary_input = AncillaryProofInput::new(
                None,
                AncillaryGenesisData::dummy(),
                step.message_preimage.to_vec(),
            );

            RealIvcOffCircuitChecker
                .check_protocol_message(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect("consistent message/preimage should pass");
        }
    }

    #[test]
    fn check_accepts_a_fully_consistent_same_epoch_request() {
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");
        let genesis_fixture = load_embedded_genesis_benchmark_fixture()
            .expect("genesis benchmark fixture should load");
        let genesis_data = AncillaryGenesisData::new(
            genesis_fixture.genesis_protocol_message_preimage.to_vec(),
            Some(genesis_fixture.genesis_signature),
            Some(genesis_fixture.genesis_verification_key),
        );
        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::IvcSnark(
                rolling_state_from_chain_state(),
            )),
            genesis_data,
            step.message_preimage.to_vec(),
        );

        RealIvcOffCircuitChecker
            .check(
                &step.message,
                &step.aggregate_verification_key_merkle_root,
                &ancillary_input,
            )
            .expect("a fully consistent request should pass every check");
    }
}
