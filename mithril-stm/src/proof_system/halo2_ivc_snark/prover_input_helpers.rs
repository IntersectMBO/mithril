use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::msm::DualMSM;

use crate::{
    AggregateVerificationKeyForSnark, MembershipDigest, SnarkProof, StmResult,
    circuits::halo2_ivc::{
        accumulator::check_accumulator_fixed_bases_present,
        state::{Global, State},
        types::{MerkleTreeCommitment, MessageHash, ProtocolMessagePreimage},
    },
    proof_system::{
        halo2_ivc_snark::{
            IvcTransitionType, errors::IvcProofError,
            prover_setup::IvcProverInputVerificationContext, rolling_state::IvcRollingState,
        },
        halo2_snark::build_snark_message,
    },
};

/// Runs the off-circuit verifier on the certificate proof and returns the prepared `DualMSM`.
///
/// The certificate verifying key comes from the verification context — the single source shared with the
/// in-circuit IVC verifier gadget — so the off-circuit accumulator built by `prepare_and_check` agrees with
/// the one the gadget produces on the same proof.
pub(crate) fn verify_certificate_proof<D: MembershipDigest>(
    certificate_proof: &SnarkProof<D>,
    certificate_message_bytes: &[u8],
    aggregate_verification_key_for_snark: &AggregateVerificationKeyForSnark<D>,
    verification_context: &IvcProverInputVerificationContext,
) -> StmResult<DualMSM<Bls12>> {
    certificate_proof.prepare_and_check(
        certificate_message_bytes,
        aggregate_verification_key_for_snark,
        verification_context.certificate_verifying_key(),
        verification_context.verifier_params(),
    )
}

/// Builds the certificate's two-element SNARK public-input message from the AVK Merkle root
/// and the certificate's message bytes and returns typed versions that can be used to build
/// a circuit `State`
pub(crate) fn create_snark_message_for_next_state<D: MembershipDigest>(
    aggregate_verification_key_for_snark: &AggregateVerificationKeyForSnark<D>,
    certificate_message_bytes: &[u8],
) -> StmResult<(MessageHash, MerkleTreeCommitment)> {
    let snark_message = build_snark_message(
        &aggregate_verification_key_for_snark.get_merkle_tree_commitment().root,
        certificate_message_bytes,
    )?;
    let certificate_message_hash = MessageHash::from_field(snark_message[1].0);
    let certificate_merkle_tree_commitment = MerkleTreeCommitment::from_field(snark_message[0].0);
    Ok((certificate_message_hash, certificate_merkle_tree_commitment))
}

/// Builds the non-genesis `State` for the next step. Advances the step counter
/// (overflow-checked), selects the next state's protocol parameters from the rolling
/// state (current for same-epoch, next-epoch lookahead promoted for next-epoch
/// transitions), and carries the lookahead fields from the protocol message preimage.
/// The certificate's typed message hash and Merkle tree commitment are passed in by the
/// caller (decoded upstream by `create_snark_message_for_next_state`).
pub(crate) fn build_next_state(
    transition_type: IvcTransitionType,
    rolling_state: &IvcRollingState,
    certificate_message_hash: MessageHash,
    certificate_merkle_tree_commitment: MerkleTreeCommitment,
    protocol_message_preimage: &ProtocolMessagePreimage,
) -> StmResult<State> {
    let new_protocol_parameters = if matches!(transition_type, IvcTransitionType::SameEpoch) {
        rolling_state.state().protocol_parameters
    } else {
        rolling_state.state().next_protocol_parameters
    };
    let new_step_counter = rolling_state.new_step_counter()?;
    Ok(State::new(
        new_step_counter,
        certificate_message_hash,
        certificate_merkle_tree_commitment,
        protocol_message_preimage.next_merkle_tree_commitment(),
        new_protocol_parameters,
        protocol_message_preimage.next_protocol_parameters(),
        protocol_message_preimage.current_epoch(),
    ))
}

/// Folds the certificate proof's accumulator and the previous IVC proof's accumulator
/// into the rolling state's accumulator, then collapses the result.
///
/// The returned accumulator is the off-circuit twin of the one the in-circuit IVC
/// verifier gadget computes from the same inputs; the new IVC proof commits to it.
pub(crate) fn build_next_accumulator(
    certificate_dual_msm: DualMSM<Bls12>,
    rolling_state: &IvcRollingState,
    verification_context: &IvcProverInputVerificationContext,
    global: &Global,
) -> StmResult<Accumulator<BlstrsEmulation>> {
    let certificate_collapsed_accumulator =
        verification_context.certificate_collapsed_accumulator(certificate_dual_msm)?;
    let previous_ivc_proof_collapsed_accumulator = verification_context
        .previous_ivc_proof_collapsed_accumulator(
            rolling_state.ivc_proof().as_bytes(),
            &rolling_state.previous_ivc_proof_public_inputs(global),
        )?;
    let mut next_accumulator = Accumulator::accumulate(&[
        rolling_state.accumulator().clone(),
        certificate_collapsed_accumulator,
        previous_ivc_proof_collapsed_accumulator,
    ]);
    next_accumulator.collapse();
    let combined_fixed_bases = verification_context.combined_fixed_bases();
    check_accumulator_fixed_bases_present(&next_accumulator, &combined_fixed_bases)?;
    // The certificate and previous-IVC-proof accumulators are already individually
    // pairing-checked above; by bilinearity their fold is too. This only fires against
    // `rolling_state.accumulator()`, the one input never independently re-checked here —
    // defense-in-depth for a rolling state loaded from persisted/untrusted storage.
    if !next_accumulator.check(
        verification_context.verifier_params(),
        &combined_fixed_bases,
    ) {
        return Err(IvcProofError::InvalidNextAccumulator.into());
    }
    Ok(next_accumulator)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        circuits::halo2_ivc::{
            PREIMAGE_CURRENT_EPOCH_BYTES, PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
            PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES, PREIMAGE_SIZE,
            accumulator::trivial_accumulator,
            errors::IvcCircuitError,
            types::{EpochNumber, IvcProofBytes, ProtocolParametersHash, StepCounter},
        },
        signature_scheme::{BaseFieldElement, SchnorrSigningKey, StandardSchnorrSignature},
    };

    use super::*;

    /// Deterministic, and none of the helpers under test read it, so one signature is minted for
    /// the whole run rather than a Schnorr key generated per fixture.
    fn build_signature() -> StandardSchnorrSignature {
        static SIGNATURE: OnceLock<StandardSchnorrSignature> = OnceLock::new();
        *SIGNATURE.get_or_init(|| {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let signing_key = SchnorrSigningKey::generate(&mut rng);
            signing_key
                .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
                .expect("standard schnorr signing should succeed for a synthetic message")
        })
    }

    pub(crate) fn build_rolling_state(
        step_counter: StepCounter,
        current_epoch: EpochNumber,
        next_merkle_tree_commitment: MerkleTreeCommitment,
        protocol_parameters: ProtocolParametersHash,
        next_protocol_parameters: ProtocolParametersHash,
    ) -> IvcRollingState {
        IvcRollingState::new(
            State::new(
                step_counter,
                MessageHash::ZERO,
                MerkleTreeCommitment::ZERO,
                next_merkle_tree_commitment,
                protocol_parameters,
                next_protocol_parameters,
                current_epoch,
            ),
            IvcProofBytes::empty(),
            trivial_accumulator(&[]),
            build_signature(),
        )
    }

    pub(crate) fn build_standard_rolling_state(
        step_counter: StepCounter,
        current_epoch: EpochNumber,
    ) -> IvcRollingState {
        build_rolling_state(
            step_counter,
            current_epoch,
            MerkleTreeCommitment::ZERO,
            ProtocolParametersHash::ZERO,
            ProtocolParametersHash::ZERO,
        )
    }

    pub(crate) fn build_preimage(
        current_epoch: EpochNumber,
        next_merkle_tree_commitment_bytes: [u8; 32],
        next_protocol_parameters_bytes: [u8; 32],
    ) -> ProtocolMessagePreimage {
        let mut bytes = [0u8; PREIMAGE_SIZE];
        bytes[PREIMAGE_CURRENT_EPOCH_BYTES].copy_from_slice(&current_epoch.as_u64().to_le_bytes());
        bytes[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES]
            .copy_from_slice(&next_merkle_tree_commitment_bytes);
        bytes[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES]
            .copy_from_slice(&next_protocol_parameters_bytes);
        ProtocolMessagePreimage::new(bytes)
    }

    pub(crate) fn build_standard_preimage(current_epoch: EpochNumber) -> ProtocolMessagePreimage {
        build_preimage(current_epoch, [0u8; 32], [0u8; 32])
    }

    pub(crate) fn merkle_tree_commitment_from_bytes(bytes: [u8; 32]) -> MerkleTreeCommitment {
        MerkleTreeCommitment::from_field(
            BaseFieldElement::from_raw(&bytes)
                .expect("from_raw applies modulus reduction")
                .0,
        )
    }

    mod build_next_state {
        use proptest::prelude::*;

        use super::*;
        use crate::circuits::halo2_ivc::NativeField;

        // --- Field-source property ---
        // The helper's whole job is choosing, per output field, between the rolling state, the
        // certificate arguments and the preimage. Each source is generated independently so that a
        // wrong choice shows up, rather than being hidden by two sources holding the same value.

        fn reduced_field_element(bytes: &[u8; 32]) -> NativeField {
            BaseFieldElement::from_raw(bytes)
                .expect("from_raw applies modulus reduction and cannot fail")
                .0
        }

        prop_compose! {
            /// Counters the examples never reach: either side of the 32-bit boundary, where a
            /// narrowed increment goes wrong, and the last advanceable value.
            fn arb_advanceable_step_counter()(
                counter in prop_oneof![
                    0u64..=64,
                    (1u64 << 32) - 8..=(1u64 << 32) + 8,
                    Just(u64::MAX - 1),
                    0u64..u64::MAX,
                ],
            ) -> StepCounter {
                StepCounter::new(counter)
            }
        }

        /// Built field by field rather than through the shared fixtures, which force several
        /// state fields to zero.
        fn build_fully_populated_rolling_state(
            step_counter: StepCounter,
            current_epoch: EpochNumber,
            message: [u8; 32],
            merkle_tree_commitment: [u8; 32],
            next_merkle_tree_commitment: [u8; 32],
            protocol_parameters: [u8; 32],
            next_protocol_parameters: [u8; 32],
        ) -> IvcRollingState {
            IvcRollingState::new(
                State::new(
                    step_counter,
                    MessageHash::from_field(reduced_field_element(&message)),
                    MerkleTreeCommitment::from_field(reduced_field_element(
                        &merkle_tree_commitment,
                    )),
                    MerkleTreeCommitment::from_field(reduced_field_element(
                        &next_merkle_tree_commitment,
                    )),
                    ProtocolParametersHash::from_field(reduced_field_element(&protocol_parameters)),
                    ProtocolParametersHash::from_field(reduced_field_element(
                        &next_protocol_parameters,
                    )),
                    current_epoch,
                ),
                IvcProofBytes::empty(),
                trivial_accumulator(&[]),
                build_signature(),
            )
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn every_next_state_field_comes_from_its_declared_source(
                previous_step_counter in arb_advanceable_step_counter(),
                previous_epoch in any::<u64>(),
                previous_message in any::<[u8; 32]>(),
                previous_merkle_tree_commitment in any::<[u8; 32]>(),
                previous_next_merkle_tree_commitment in any::<[u8; 32]>(),
                previous_protocol_parameters in any::<[u8; 32]>(),
                previous_next_protocol_parameters in any::<[u8; 32]>(),
                certificate_message in any::<[u8; 32]>(),
                certificate_merkle_tree_commitment in any::<[u8; 32]>(),
                preimage_epoch in any::<u64>(),
                preimage_commitment in any::<[u8; 32]>(),
                preimage_parameters in any::<[u8; 32]>(),
            ) {
                let rolling_state = build_fully_populated_rolling_state(
                    previous_step_counter,
                    EpochNumber::new(previous_epoch),
                    previous_message,
                    previous_merkle_tree_commitment,
                    previous_next_merkle_tree_commitment,
                    previous_protocol_parameters,
                    previous_next_protocol_parameters,
                );
                let preimage = build_preimage(
                    EpochNumber::new(preimage_epoch),
                    preimage_commitment,
                    preimage_parameters,
                );
                let message = MessageHash::from_field(reduced_field_element(&certificate_message));
                let commitment = MerkleTreeCommitment::from_field(reduced_field_element(
                    &certificate_merkle_tree_commitment,
                ));

                let same_epoch = build_next_state(
                    IvcTransitionType::SameEpoch,
                    &rolling_state,
                    message,
                    commitment,
                    &preimage,
                )
                .expect("an advanceable counter should not overflow");
                let next_epoch = build_next_state(
                    IvcTransitionType::NextEpoch,
                    &rolling_state,
                    message,
                    commitment,
                    &preimage,
                )
                .expect("an advanceable counter should not overflow");

                // Expectations come from the generated bytes, not from the preimage accessors,
                // which would only restate that the helper calls them.
                let expected_counter = StepCounter::new(previous_step_counter.as_u64() + 1);
                let expected_next_commitment = MerkleTreeCommitment::from_field(
                    reduced_field_element(&preimage_commitment),
                );
                let expected_next_parameters = ProtocolParametersHash::from_field(
                    reduced_field_element(&preimage_parameters),
                );
                let current_parameters = ProtocolParametersHash::from_field(
                    reduced_field_element(&previous_protocol_parameters),
                );
                let lookahead_parameters = ProtocolParametersHash::from_field(
                    reduced_field_element(&previous_next_protocol_parameters),
                );

                for state in [&same_epoch, &next_epoch] {
                    prop_assert_eq!(state.step_counter, expected_counter);
                    prop_assert_eq!(state.message, message);
                    prop_assert_eq!(state.merkle_tree_commitment, commitment);
                    prop_assert_eq!(state.next_merkle_tree_commitment, expected_next_commitment);
                    prop_assert_eq!(state.next_protocol_parameters, expected_next_parameters);
                    prop_assert_eq!(state.current_epoch, EpochNumber::new(preimage_epoch));
                }

                prop_assert_eq!(same_epoch.protocol_parameters, current_parameters);
                prop_assert_eq!(next_epoch.protocol_parameters, lookahead_parameters);

            }
        }

        #[test]
        fn rejects_step_counter_overflow() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(u64::MAX), EpochNumber::new(3));
            let preimage = build_standard_preimage(EpochNumber::new(3));
            let err = build_next_state(
                IvcTransitionType::SameEpoch,
                &rolling_state,
                MessageHash::ZERO,
                MerkleTreeCommitment::ZERO,
                &preimage,
            )
            .unwrap_err();
            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::StepCounterOverflow { .. }
            ));
        }
    }
}
