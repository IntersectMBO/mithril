use anyhow::anyhow;

use crate::{
    AggregateVerificationKeyForSnark, AggregationError, AncillaryGenesisData, AncillaryProofInput,
    BaseFieldElement, MembershipDigest, SchnorrVerificationKey, StmResult,
    circuits::halo2_ivc::{
        PREIMAGE_SIZE, ProtocolMessagePreimage,
        errors::{EpochTransitionErrorKind, IvcCircuitError},
        types::MessageHash,
    },
    proof_system::{
        IvcRollingState,
        halo2_ivc_snark::{
            errors::IvcProofError, interface::IvcOffCircuitChecker,
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
        let (genesis_verifying_key, genesis_message, genesis_bootstrap) =
            self.check_genesis_data(genesis_data)?;

        let rolling_state = ancillary_input
            .prover_data()
            .and_then(|prover_data| prover_data.as_ivc_rolling_state());
        rolling_state.map(IvcRollingState::ensure_advanceable).transpose()?;

        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        let certificate_message_hash = if let Some(rolling_state) = rolling_state {
            self.check_rolling_state(msg, aggregate_verification_key, &preimage, rolling_state)?
        } else {
            self.check_genesis_bootstrap(
                msg,
                aggregate_verification_key,
                &preimage,
                &genesis_verifying_key,
                &genesis_message,
                &genesis_bootstrap,
            )?
        };

        let preimage_message_hash: MessageHash = (&preimage).try_into()?;
        if preimage_message_hash != certificate_message_hash {
            return Err(IvcProofError::MessagePreimageMismatch.into());
        }

        Ok(())
    }
}

impl MithrilIvcOffCircuitChecker {
    /// Checks that the genesis verification key is present and structurally valid, and parses
    /// the genesis bootstrap input. Always run since the genesis verification key is
    /// a public input on every proving step.
    fn check_genesis_data(
        &self,
        genesis_data: &AncillaryGenesisData,
    ) -> StmResult<(
        SchnorrVerificationKey,
        MessageHash,
        IvcGenesisBootstrapInput,
    )> {
        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
        genesis_verifying_key.is_valid()?;

        let genesis_message: MessageHash = genesis_data.genesis_message_preimage().try_into()?;
        let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;

        Ok((genesis_verifying_key, genesis_message, genesis_bootstrap))
    }

    /// Verifies the genesis signature and checks that the first real certificate matches the
    /// genesis-announced epoch and Merkle-tree commitment lookahead. Runs only during
    /// the genesis step.
    fn check_genesis_bootstrap<D: MembershipDigest>(
        &self,
        msg: &[u8],
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
        preimage: &ProtocolMessagePreimage,
        genesis_verifying_key: &SchnorrVerificationKey,
        genesis_message: &MessageHash,
        genesis_bootstrap: &IvcGenesisBootstrapInput,
    ) -> StmResult<MessageHash> {
        genesis_bootstrap.genesis_signature.verify(
            &[BaseFieldElement::from(genesis_message.as_field())],
            genesis_verifying_key,
        )?;

        let (certificate_message_hash, certificate_merkle_tree_commitment) =
            create_snark_message_for_next_state(aggregate_verification_key, msg)?;

        let genesis_preimage = &genesis_bootstrap.genesis_protocol_message_preimage;
        let genesis_epoch = genesis_preimage.current_epoch();
        let expected_epoch =
            genesis_epoch
                .next_epoch()
                .ok_or(IvcCircuitError::InvalidEpochTransition {
                    kind: EpochTransitionErrorKind::EpochOverflow,
                    last_committed_epoch: genesis_epoch.as_u64(),
                })?;

        let matches_genesis_lookahead = preimage.current_epoch().is_equal(&expected_epoch)
            && certificate_merkle_tree_commitment == genesis_preimage.next_merkle_tree_commitment();
        if !matches_genesis_lookahead {
            return Err(IvcCircuitError::InvalidEpochTransition {
                kind: EpochTransitionErrorKind::GenesisLookaheadDoesNotMatchProtocolMessage,
                last_committed_epoch: genesis_epoch.as_u64(),
            }
            .into());
        }

        Ok(certificate_message_hash)
    }

    /// Validates the incoming certificate's transition against the existing rolling state and
    /// rejects a next-epoch transition that would promote a diverged protocol-parameters
    /// announcement. Runs only when there is an existing rolling state.
    fn check_rolling_state<D: MembershipDigest>(
        &self,
        msg: &[u8],
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
        preimage: &ProtocolMessagePreimage,
        rolling_state: &IvcRollingState,
    ) -> StmResult<MessageHash> {
        let (transition_type, certificate_message_hash, _) =
            rolling_state.validate_transition(preimage, aggregate_verification_key, msg)?;
        rolling_state.assert_protocol_parameters_unchanged(transition_type)?;
        Ok(certificate_message_hash)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AncillaryGenesisData, AncillaryProverData, MithrilMembershipDigest,
        circuits::halo2_ivc::{
            state::State,
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

    // Builds a rolling state whose `protocol_parameters` diverges from `next_protocol_parameters`
    // (as if an earlier certificate had announced a parameter change for the following epoch),
    // otherwise carrying the same fields as the embedded recursive chain state asset.
    fn diverged_rolling_state() -> IvcRollingState {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let diverged_state = State::new(
            chain_state.state.step_counter,
            chain_state.state.message,
            chain_state.state.merkle_tree_commitment,
            chain_state.state.next_merkle_tree_commitment,
            ProtocolParametersHash::from_field(BaseFieldElement::from(999u64).0),
            chain_state.state.next_protocol_parameters,
            chain_state.state.current_epoch,
        );
        IvcRollingState::new(
            diverged_state,
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

    // Wraps a raw merkle-tree-commitment root (as stored in the fixture assets) into an
    // AggregateVerificationKeyForSnark. Total stake is irrelevant here: off_circuit_check only
    // ever reads `.get_merkle_tree_commitment().root` from it, never the stake.
    fn avk_with_root(root: [u8; 32]) -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
        let mut bytes = [0u8; 40];
        bytes[..32].copy_from_slice(&root);
        AggregateVerificationKeyForSnark::from_bytes(&bytes).unwrap()
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
                    &avk_with_root(first_step.aggregate_verification_key_merkle_root),
                    &ancillary_input,
                )
                .expect(
                    "consistent genesis data paired with a matching first certificate should pass",
                );
        }

        #[test]
        fn rejects_first_certificate_with_wrong_epoch_or_avk() {
            let genesis_fixture = load_embedded_genesis_benchmark_fixture()
                .expect("genesis benchmark fixture should load");
            let mismatched_step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let genesis_data = AncillaryGenesisData::new(
                genesis_fixture.genesis_protocol_message_preimage.to_vec(),
                Some(genesis_fixture.genesis_signature),
                Some(genesis_fixture.genesis_verification_key),
            );
            let ancillary_input = AncillaryProofInput::new(
                None,
                genesis_data,
                mismatched_step.message_preimage.to_vec(),
            );

            let err = MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &mismatched_step.message,
                    &avk_with_root(mismatched_step.aggregate_verification_key_merkle_root),
                    &ancillary_input,
                )
                .expect_err(
                    "a certificate not matching genesis's announced epoch/AVK must be rejected",
                );

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind: EpochTransitionErrorKind::GenesisLookaheadDoesNotMatchProtocolMessage,
                    ..
                }
            ));
        }
    }

    mod check_rolling_state {
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
                    &avk_with_root(step.aggregate_verification_key_merkle_root),
                    &ancillary_input,
                )
                .expect(
                    "consistent same-epoch step should pass every check, including the \
                     message-hash match",
                );
        }

        #[test]
        fn accepts_when_protocol_parameters_diverged_within_same_epoch() {
            // A same-epoch step never consumes `next_protocol_parameters`, so a chain that
            // already carries a divergence can still process the rest of the epoch where it
            // appeared.
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");
            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(diverged_rolling_state())),
                AncillaryGenesisData::dummy(),
                step.message_preimage.to_vec(),
            );

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &step.message,
                    &avk_with_root(step.aggregate_verification_key_merkle_root),
                    &ancillary_input,
                )
                .expect("a same-epoch step must still succeed despite the diverged lookahead");
        }

        #[test]
        fn rejects_when_protocol_parameters_diverged_at_next_epoch() {
            // A next-epoch transition promotes `next_protocol_parameters` into
            // `protocol_parameters`, so this is where a diverged lookahead must be rejected.
            let step = load_embedded_next_epoch_step_output_asset()
                .expect("next-epoch step output asset should load");
            let ancillary_input = AncillaryProofInput::new(
                Some(AncillaryProverData::IvcSnark(diverged_rolling_state())),
                AncillaryGenesisData::dummy(),
                step.message_preimage.to_vec(),
            );

            MithrilIvcOffCircuitChecker
                .off_circuit_check(
                    &step.message,
                    &avk_with_root(step.aggregate_verification_key_merkle_root),
                    &ancillary_input,
                )
                .expect_err(
                    "a next-epoch transition promoting diverged parameters must be rejected",
                );
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
                    &avk_with_root(step.aggregate_verification_key_merkle_root),
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
                    &avk_with_root(step.aggregate_verification_key_merkle_root),
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
                &avk_with_root(step.aggregate_verification_key_merkle_root),
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
                &avk_with_root(step.aggregate_verification_key_merkle_root),
                &ancillary_input,
            )
            .expect("a fully consistent next-epoch request should pass every check");
    }
}
