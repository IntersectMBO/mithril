use anyhow::anyhow;

use crate::{
    AggregateVerificationKeyForSnark, AggregationError, AncillaryProofInput, BaseFieldElement,
    MembershipDigest, StmResult,
    circuits::halo2_ivc::{PREIMAGE_SIZE, ProtocolMessagePreimage, types::MessageHash},
    proof_system::{
        IvcRollingState,
        halo2_ivc_snark::{
            IvcTransitionType, errors::IvcProofError, interface::IvcOffCircuitChecker,
            proof::IvcGenesisBootstrapInput,
            prover_input_helpers::create_snark_message_for_next_state,
        },
    },
};

/// Production implementation of `IvcOffCircuitChecker`. Stateless: every check is a pure
/// function of its arguments, so no setup or trusted material is needed to construct one.
#[derive(Debug)]
pub(crate) struct MithrilIvcOffCircuitChecker;

impl<D: MembershipDigest> IvcOffCircuitChecker<D> for MithrilIvcOffCircuitChecker {
    fn off_circuit_check(
        &self,
        msg: &[u8],
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        let genesis_data = ancillary_input.genesis_data();

        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
        genesis_verifying_key.is_valid()?;

        let rolling_state = ancillary_input
            .prover_data()
            .and_then(|prover_data| prover_data.as_ivc_rolling_state());
        rolling_state.map(IvcRollingState::ensure_advanceable).transpose()?;

        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        if let Some(rolling_state) = rolling_state {
            let (transition_type, certificate_message_hash, certificate_merkle_tree_commitment) =
                rolling_state.validate_transition(&preimage, aggregate_verification_key, msg)?;
            let preimage_message_hash: MessageHash = (&preimage).try_into()?;
            if preimage_message_hash != certificate_message_hash {
                return Err(IvcProofError::MessagePreimageMismatch.into());
            }
            rolling_state.assert_protocol_parameters_unchanged()?;
        } else {
            let genesis_message: MessageHash =
                genesis_data.genesis_message_preimage().try_into()?;

            let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;
            genesis_bootstrap.genesis_signature.verify(
                &[BaseFieldElement::from(genesis_message.as_field())],
                &genesis_verifying_key,
            )?;
        };

        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        rolling_state.assert_protocol_parameters_unchanged()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AncillaryGenesisData, AncillaryProverData, MithrilMembershipDigest,
        circuits::halo2_ivc::{
            tests::common::asset_readers::{
                load_embedded_first_certificate_in_epoch_asset,
                load_embedded_following_certificate_in_epoch_asset,
                load_embedded_genesis_benchmark_fixture,
                load_embedded_next_epoch_step_output_asset,
                load_embedded_recursive_chain_state_asset,
            },
            types::ProtocolParametersHash,
        },
        signature_scheme::{
            BaseFieldElement, ScalarFieldElement, SchnorrSigningKey, SchnorrVerificationKey,
            StandardSchnorrSignature,
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

    fn genesis_only_ancillary_input(genesis_data: AncillaryGenesisData) -> AncillaryProofInput {
        AncillaryProofInput::new(None, genesis_data, vec![0u8; PREIMAGE_SIZE])
    }

    /// Builds a signature and its matching verification key from a seed, both over the same
    /// synthetic message. Convenient for tests that only need one of the two.
    fn synthetic_signature_and_key(
        seed: [u8; 32],
    ) -> (StandardSchnorrSignature, SchnorrVerificationKey) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let signature = signing_key
            .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
            .expect("sign_standard should succeed for a synthetic message");
        let verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key);
        (signature, verification_key)
    }

    // Creates an avk with a zero root
    fn avk_with_zero_root() -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
        AggregateVerificationKeyForSnark::from_bytes(&[0u8; 40]).unwrap()
    }

    mod check_genesis {
        use super::*;

        #[test]
        fn rejects_missing_genesis_verification_key() {
            let genesis_data = AncillaryGenesisData::new(vec![0u8; PREIMAGE_SIZE], None, None);
            let ancillary_input = genesis_only_ancillary_input(genesis_data);

            let err = MithrilIvcOffCircuitChecker
                .off_circuit_check(&[0u8; 32], &avk_with_zero_root(), &ancillary_input)
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
            let ancillary_input = genesis_only_ancillary_input(genesis_data);

            MithrilIvcOffCircuitChecker
                .off_circuit_check(&[0u8; 32], &avk_with_zero_root(), &ancillary_input)
                .expect_err("invalid genesis verification key must be rejected");
        }

        #[test]
        fn rejects_missing_genesis_signature() {
            let (_, genesis_verification_key) = synthetic_signature_and_key([0u8; 32]);

            let genesis_data = AncillaryGenesisData::new(
                vec![0u8; PREIMAGE_SIZE],
                None,
                Some(genesis_verification_key),
            );
            let ancillary_input = genesis_only_ancillary_input(genesis_data);

            let err = MithrilIvcOffCircuitChecker
                .off_circuit_check(&[0u8; 32], &avk_with_zero_root(), &ancillary_input)
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
            let (wrong_signature, _) = synthetic_signature_and_key([1u8; 32]);

            let genesis_data = AncillaryGenesisData::new(
                genesis_fixture.genesis_protocol_message_preimage.to_vec(),
                Some(wrong_signature),
                Some(genesis_fixture.genesis_verification_key),
            );
            let ancillary_input = genesis_only_ancillary_input(genesis_data);

            MithrilIvcOffCircuitChecker
                .off_circuit_check(&[0u8; 32], &avk_with_zero_root(), &ancillary_input)
                .expect_err("a genesis signature over the wrong message must be rejected");
        }

        #[test]
        fn accepts_valid_genesis_data() {
            let genesis_fixture = load_embedded_genesis_benchmark_fixture()
                .expect("genesis benchmark fixture should load");
            let first_step = load_embedded_first_certificate_in_epoch_asset()
                .expect("first-step certificate asset should load");

            let genesis_data = AncillaryGenesisData::new(
                genesis_fixture.genesis_protocol_message_preimage.to_vec(),
                Some(genesis_fixture.genesis_signature),
                Some(genesis_fixture.genesis_verification_key),
            );
            let ancillary_input =
                AncillaryProofInput::new(None, genesis_data, first_step.message_preimage.to_vec());

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &first_step.message,
                    &first_step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect(
                    "consistent genesis data paired with a matching first certificate should pass",
                );
        }
    }

    mod check_rolling_state {
        use crate::circuits::halo2_ivc::state::State;

        use super::*;

        #[test]
        fn rejects_genesis_shaped_existing_rolling_state() {
            let (genesis_signature, _) = synthetic_signature_and_key([0u8; 32]);
            let genesis_rolling_state = IvcRollingState::genesis(genesis_signature, &[]);

            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(genesis_rolling_state)),
                AncillaryGenesisData::dummy(),
                vec![0u8; PREIMAGE_SIZE],
            );

            MithrilIvcOffCircuitChecker
                .off_circuit_check(&[0u8; 32], &avk_with_zero_root(), &ancillary_input)
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

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect(
                    "consistent same-epoch step should pass every check, including the \
                     message-hash match",
                );
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

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
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
            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(
                    rolling_state_from_chain_state(),
                )),
                AncillaryGenesisData::dummy(),
                vec![0u8; 3],
            );

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
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

            // Flip a byte outside the three decoded slots (next merkle-tree commitment, next
            // protocol parameters, current epoch) so assert_correct_parameters and
            // assert_protocol_parameters_unchanged still pass, isolating the message-hash check.
            let mut corrupted_preimage = step.message_preimage;
            corrupted_preimage[0] ^= 0xFF;

            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(
                    rolling_state_from_chain_state(),
                )),
                AncillaryGenesisData::dummy(),
                corrupted_preimage.to_vec(),
            );

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &step.message,
                    &step.aggregate_verification_key_merkle_root,
                    &ancillary_input,
                )
                .expect_err("mismatched preimage must be rejected");
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

        MithrilIvcOffCircuitChecker
            .off_circuit_check(
                &step.message,
                &step.aggregate_verification_key_merkle_root,
                &ancillary_input,
            )
            .expect("a fully consistent request should pass every check");
    }

    #[test]
    fn check_accepts_a_fully_consistent_next_epoch_request() {
        let step = load_embedded_next_epoch_step_output_asset()
            .expect("next-epoch step output asset should load");
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

        MithrilIvcOffCircuitChecker
            .off_circuit_check(
                &step.message,
                &step.aggregate_verification_key_merkle_root,
                &ancillary_input,
            )
            .expect("a fully consistent next-epoch request should pass every check");
    }
}
