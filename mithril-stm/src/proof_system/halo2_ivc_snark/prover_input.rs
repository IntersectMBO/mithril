//! Pre-circuit inputs produced by the IVC prover's preparation step.
//!
//! Holds the witness, the advanced chain state, and the folded accumulator that
//! the in-circuit construction and proof-generation steps consume next.

use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};

use crate::{
    AggregateVerificationKeyForSnark, MembershipDigest, SnarkProof, StmResult,
    circuits::halo2_ivc::{
        state::{Global, State, Witness},
        types::{
            MerkleTreeCommitment, MessageHash, ProtocolMessagePreimage, ProtocolParametersHash,
        },
    },
    proof_system::halo2_ivc_snark::{
        prover_input_helpers::{
            build_next_accumulator, build_next_state, verify_certificate_proof,
        },
        prover_setup::IvcProverInputVerificationContext,
        rolling_state::{IvcRollingState, IvcTransitionType},
    },
};

/// Prover input for the IVC circuit: what the preparation step derives from an
/// `IvcChainStepBundle`, consumed by the circuit-construction and proof-generation steps.
#[derive(Debug)]
pub(crate) struct IvcProverInput {
    /// In-circuit witness for the new step.
    pub(crate) witness: Witness,
    /// Chain state advanced by one step.
    pub(crate) next_state: State,
    /// Folded accumulator the new step's IVC proof commits to.
    pub(crate) next_accumulator: Accumulator<BlstrsEmulation>,
    /// Classification of this step (genesis, same-epoch, or next-epoch).
    pub(crate) transition_type: IvcTransitionType,
}

impl IvcProverInput {
    /// Advances the chain state by one step and bundles the in-circuit witness, the
    /// next state, and the next folded accumulator.
    ///
    /// First classifies the requested step and validates it against the rolling chain state via
    /// [`IvcRollingState::validate_transition`].
    /// The certificate proof is verifier-prepared, then the certificate and previous IVC accumulators are
    /// folded into the chain's accumulator.
    pub(crate) fn prepare<D: MembershipDigest>(
        certificate_proof: &SnarkProof<D>,
        message: &[u8],
        aggregate_verification_key_for_snark: &AggregateVerificationKeyForSnark<D>,
        global: &Global,
        protocol_message_preimage: &ProtocolMessagePreimage,
        rolling_state: &IvcRollingState,
        verification_context: &IvcProverInputVerificationContext,
    ) -> StmResult<Self> {
        let (transition_type, certificate_message_hash, certificate_merkle_tree_commitment) =
            rolling_state.validate_transition(
                protocol_message_preimage,
                aggregate_verification_key_for_snark,
                message,
            )?;

        let certificate_dual_msm = verify_certificate_proof(
            certificate_proof,
            message,
            aggregate_verification_key_for_snark,
            verification_context,
        )?;

        let next_state = build_next_state(
            transition_type,
            rolling_state,
            certificate_message_hash,
            certificate_merkle_tree_commitment,
            protocol_message_preimage,
        )?;

        let next_accumulator = build_next_accumulator(
            certificate_dual_msm,
            rolling_state,
            verification_context,
            global,
        )?;

        let witness = Witness::new(
            rolling_state.genesis_signature(),
            certificate_message_hash,
            certificate_merkle_tree_commitment,
            protocol_message_preimage.clone(),
        );

        Ok(IvcProverInput {
            witness,
            next_state,
            next_accumulator,
            transition_type,
        })
    }

    /// Builds the genesis-step `IvcProverInput`. Verifies the chain's genesis signature,
    /// constructs the base-case state and witness with all certificate-derived fields set
    /// to ZERO and the chain message set to `global.genesis_message`, and passes the
    /// rolling state's trivial accumulator through unchanged.
    pub(crate) fn prepare_genesis(
        rolling_state: &IvcRollingState,
        protocol_message_preimage: &ProtocolMessagePreimage,
        global: &Global,
    ) -> StmResult<Self> {
        rolling_state.verify_genesis_signature(global)?;

        let new_step_counter = rolling_state.new_step_counter()?;
        let next_state = State::new(
            new_step_counter,
            global.genesis_message,
            MerkleTreeCommitment::ZERO,
            protocol_message_preimage.next_merkle_tree_commitment(),
            ProtocolParametersHash::ZERO,
            protocol_message_preimage.next_protocol_parameters(),
            protocol_message_preimage.current_epoch(),
        );

        let witness = Witness::new(
            rolling_state.genesis_signature(),
            MessageHash::ZERO,
            MerkleTreeCommitment::ZERO,
            protocol_message_preimage.clone(),
        );

        Ok(IvcProverInput {
            witness,
            next_state,
            next_accumulator: rolling_state.accumulator().clone(),
            transition_type: IvcTransitionType::Genesis,
        })
    }
}

#[cfg(test)]
mod tests {
    use midnight_proofs::utils::SerdeFormat;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        BaseFieldElement, MithrilMembershipDigest, Parameters, SchnorrSigningKey,
        SchnorrVerificationKey,
        circuits::halo2_ivc::{
            PREIMAGE_CURRENT_EPOCH_BYTES, PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
            PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES, PREIMAGE_SIZE,
            errors::{EpochTransitionErrorKind, IvcCircuitError},
            io::WriteWithFormat,
            tests::common::{
                asset_readers::{
                    load_embedded_following_certificate_in_epoch_asset,
                    load_embedded_genesis_benchmark_fixture,
                    load_embedded_next_epoch_step_output_asset,
                    load_embedded_recursive_chain_state_asset,
                    load_embedded_verification_context_asset,
                },
                generators::setup::{QUORUM_SIZE, SIGNER_COUNT, TOTAL_STAKE},
            },
            types::{
                CertificateCircuitVerificationKeyRepresentation, EpochNumber,
                IvcCircuitVerificationKeyRepresentation, IvcProofBytes, StepCounter,
            },
        },
        proof_system::halo2_ivc_snark::prover_setup::IvcProverInputVerificationContext,
        signature_scheme::SchnorrSignatureError,
    };

    use super::*;

    /// Builds the chain's global public inputs and the verification-side context `prepare` reads,
    /// both from committed assets: no SRS, no key generation and no cache.
    fn build_preparation_context() -> (Global, IvcProverInputVerificationContext) {
        let asset = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let genesis_fixture = load_embedded_genesis_benchmark_fixture()
            .expect("genesis benchmark fixture should load");

        let global = Global::new(
            genesis_fixture.genesis_message_hash(),
            genesis_fixture.genesis_verification_key,
            &asset.certificate_verifying_key,
            &asset.recursive_verifying_key,
        );
        let verification_context = IvcProverInputVerificationContext::from_verifying_keys(
            asset.verifier_params,
            &asset.certificate_verifying_key,
            &asset.recursive_verifying_key,
        );

        (global, verification_context)
    }

    fn wrap_snark_proof(certificate_proof_bytes: Vec<u8>) -> SnarkProof<MithrilMembershipDigest> {
        let parameters = Parameters {
            k: QUORUM_SIZE as u64,
            m: (QUORUM_SIZE * 10) as u64,
            phi_f: 0.2,
        };
        let merkle_tree_depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
        SnarkProof::new(certificate_proof_bytes, parameters, merkle_tree_depth)
    }

    fn wrap_avk(
        aggregate_verification_key_merkle_root: &[u8; 32],
    ) -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
        let mut avk_bytes = [0u8; 40];
        avk_bytes[0..32].copy_from_slice(aggregate_verification_key_merkle_root);
        avk_bytes[32..40].copy_from_slice(&TOTAL_STAKE.to_be_bytes());
        AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_bytes)
            .expect("AVK should decode from asset bytes")
    }

    fn wrap_protocol_message_preimage(preimage: &[u8]) -> ProtocolMessagePreimage {
        let preimage_array: [u8; PREIMAGE_SIZE] = preimage
            .try_into()
            .expect("preimage should be exactly PREIMAGE_SIZE bytes");
        ProtocolMessagePreimage::new(preimage_array)
    }

    fn accumulator_bytes(accumulator: &Accumulator<BlstrsEmulation>) -> Vec<u8> {
        let mut bytes = Vec::new();
        accumulator
            .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
            .expect("accumulator serialization should succeed");
        bytes
    }

    #[test]
    fn prepare_genesis_rejects_invalid_signature() {
        let mut chain_rng = ChaCha20Rng::from_seed([0u8; 32]);
        let chain_signing_key = SchnorrSigningKey::generate(&mut chain_rng);
        let chain_verification_key =
            SchnorrVerificationKey::new_from_signing_key(chain_signing_key);

        let global = Global {
            genesis_message: MessageHash::ZERO,
            genesis_verification_key: chain_verification_key,
            certificate_circuit_verification_key_representation:
                CertificateCircuitVerificationKeyRepresentation::from_field(
                    BaseFieldElement::from(0u64).0,
                ),
            ivc_circuit_verification_key_representation:
                IvcCircuitVerificationKeyRepresentation::from_field(BaseFieldElement::from(0u64).0),
        };

        let mut wrong_rng = ChaCha20Rng::from_seed([1u8; 32]);
        let wrong_signing_key = SchnorrSigningKey::generate(&mut wrong_rng);
        let invalid_signature = wrong_signing_key
            .sign_standard(
                &[BaseFieldElement::from(global.genesis_message.as_field())],
                &mut wrong_rng,
            )
            .expect("sign_standard should succeed for a synthetic message");
        let rolling_state = IvcRollingState::genesis(invalid_signature, &[]);
        let protocol_message_preimage = ProtocolMessagePreimage::new([0u8; PREIMAGE_SIZE]);

        let err =
            IvcProverInput::prepare_genesis(&rolling_state, &protocol_message_preimage, &global)
                .expect_err("prepare_genesis should reject a signature that does not verify");
        let schnorr_error = err
            .downcast::<SchnorrSignatureError>()
            .expect("error chain should carry SchnorrSignatureError");
        assert!(matches!(
            schnorr_error,
            SchnorrSignatureError::StandardSignatureInvalid(_)
        ));
    }

    #[test]
    fn prepare_genesis_produces_expected_state_and_witness() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key.clone());

        let genesis_message = MessageHash::from_field(
            BaseFieldElement::from_raw(&[0x42; 32])
                .expect("from_raw applies modulus reduction")
                .0,
        );
        let global = Global {
            genesis_message,
            genesis_verification_key: verification_key,
            certificate_circuit_verification_key_representation:
                CertificateCircuitVerificationKeyRepresentation::from_field(
                    BaseFieldElement::from(0u64).0,
                ),
            ivc_circuit_verification_key_representation:
                IvcCircuitVerificationKeyRepresentation::from_field(BaseFieldElement::from(0u64).0),
        };

        let genesis_signature = signing_key
            .sign_standard(
                &[BaseFieldElement::from(global.genesis_message.as_field())],
                &mut rng,
            )
            .expect("sign_standard should succeed for the genesis message");
        // Keep the complete fixed-base label set so replacing it with an empty trivial
        // accumulator is observable.
        let combined_fixed_base_names: Vec<String> = load_embedded_verification_context_asset()
            .expect("verification context asset should load")
            .combined_fixed_bases
            .keys()
            .cloned()
            .collect();
        let rolling_state = IvcRollingState::genesis(genesis_signature, &combined_fixed_base_names);
        assert!(
            !rolling_state.accumulator().rhs().fixed_base_scalars().is_empty(),
            "the pass-through fixture must carry fixed-base labels"
        );

        let cert_epoch = EpochNumber::ZERO;
        let mut preimage_bytes = [0u8; PREIMAGE_SIZE];
        preimage_bytes[PREIMAGE_CURRENT_EPOCH_BYTES]
            .copy_from_slice(&cert_epoch.as_u64().to_le_bytes());
        preimage_bytes[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES].copy_from_slice(&[0x11; 32]);
        preimage_bytes[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES].copy_from_slice(&[0x22; 32]);
        let protocol_message_preimage = ProtocolMessagePreimage::new(preimage_bytes);

        let input =
            IvcProverInput::prepare_genesis(&rolling_state, &protocol_message_preimage, &global)
                .expect("prepare_genesis should succeed for a valid genesis signature");

        let expected_next_state = State::new(
            StepCounter::new(1),
            global.genesis_message,
            MerkleTreeCommitment::ZERO,
            protocol_message_preimage.next_merkle_tree_commitment(),
            ProtocolParametersHash::ZERO,
            protocol_message_preimage.next_protocol_parameters(),
            protocol_message_preimage.current_epoch(),
        );
        assert_eq!(input.next_state, expected_next_state);

        let expected_witness = Witness::new(
            genesis_signature,
            MessageHash::ZERO,
            MerkleTreeCommitment::ZERO,
            protocol_message_preimage.clone(),
        );
        assert_eq!(input.witness, expected_witness);

        assert_eq!(input.transition_type, IvcTransitionType::Genesis);
        assert_eq!(
            accumulator_bytes(&input.next_accumulator),
            accumulator_bytes(rolling_state.accumulator()),
            "the genesis step must pass the trivial accumulator through unchanged"
        );
    }

    #[test]
    fn prepare_at_same_epoch_advances_state_correctly() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let chain_genesis_signature = chain_state.genesis_signature;
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let input = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        )
        .expect("prepare should succeed at same-epoch step");

        assert_eq!(input.next_state, step.next_state);
        assert_eq!(
            accumulator_bytes(&input.next_accumulator),
            accumulator_bytes(&step.next_accumulator),
        );
        assert_eq!(input.witness.genesis_signature, chain_genesis_signature);
        assert_eq!(input.witness.message_preimage, protocol_message_preimage);
        assert_eq!(
            input.witness.certificate_merkle_tree_commitment,
            step.next_state.merkle_tree_commitment,
        );
        assert_eq!(input.witness.certificate_message, step.next_state.message);
    }

    #[test]
    fn prepare_at_next_epoch_carries_lookahead_protocol_parameters() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let chain_genesis_signature = chain_state.genesis_signature;
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let input = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        )
        .expect("prepare should succeed at next-epoch step");

        assert_eq!(input.next_state, step.next_state);
        assert_eq!(
            accumulator_bytes(&input.next_accumulator),
            accumulator_bytes(&step.next_accumulator),
        );
        assert_eq!(input.witness.genesis_signature, chain_genesis_signature);
        assert_eq!(input.witness.message_preimage, protocol_message_preimage);
        assert_eq!(
            input.witness.certificate_merkle_tree_commitment,
            step.next_state.merkle_tree_commitment,
        );
        assert_eq!(input.witness.certificate_message, step.next_state.message);
    }

    #[test]
    fn prepare_rejects_invalid_snark_proof() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let mut corrupted = step.certificate_proof.clone().into_vec();
        corrupted[0] ^= 0xFF;

        let snark_proof = wrap_snark_proof(corrupted);
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let result = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        let err = result
            .expect_err("prepare should reject a corrupted certificate proof")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
    }

    #[test]
    fn prepare_rejects_empty_snark_proof() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();

        let snark_proof = wrap_snark_proof(vec![]);
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let result = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        let err = result
            .expect_err("prepare should reject an empty certificate proof")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
    }

    #[test]
    fn prepare_rejects_tampered_certificate_message() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let mut tampered_message = step.message;
        tampered_message[0] ^= 0xFF;

        let result = IvcProverInput::prepare(
            &snark_proof,
            &tampered_message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        let err = result
            .expect_err("prepare should reject a tampered certificate message")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
    }

    #[test]
    fn prepare_rejects_mismatched_aggregate_verification_key() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let mut tampered_root = step.aggregate_verification_key_merkle_root;
        tampered_root[0] ^= 0xFF;

        let result = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &wrap_avk(&tampered_root),
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        // The step's Merkle-tree commitment is derived from the AVK root, so a tampered root is
        // caught by the carry check against the rolling state, before the certificate proof is
        // verified.
        let err = result
            .expect_err("prepare should reject an AVK the proof did not commit to")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(
            matches!(
                err,
                IvcCircuitError::InvalidEpochTransition {
                    kind:
                        EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                    ..
                }
            ),
            "expected InvalidEpochTransition with RollingStateParametersDoesNotMatchProtocolMessage kind, got {err:?}"
        );
    }

    #[test]
    fn prepare_rejects_corrupted_previous_ivc_proof() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);

        let mut corrupted = chain_state.ivc_proof.into_vec();
        corrupted[0] ^= 0xFF;
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            IvcProofBytes::new(corrupted),
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let result = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        let err = result
            .expect_err("prepare should reject a corrupted previous IVC proof")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
    }

    #[test]
    fn prepare_rejects_mismatched_global() {
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let step = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let (global, verification_context) = build_preparation_context();
        let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
        let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
        let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        // `Global` is part of the previous IVC proof's public inputs, so a chain whose genesis
        // message differs from the one the proof committed to must not verify.
        let mut mismatched_global = global.clone();
        mismatched_global.genesis_message =
            MessageHash::from_field(BaseFieldElement::from(0xDEAD_BEEFu64).0);

        let result = IvcProverInput::prepare(
            &snark_proof,
            &step.message,
            &avk,
            &mismatched_global,
            &protocol_message_preimage,
            &rolling_state,
            &verification_context,
        );

        let err = result
            .expect_err("prepare should reject a global the previous IVC proof did not commit to")
            .downcast::<IvcCircuitError>()
            .expect("error should downcast to IvcCircuitError");
        assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
    }
}
