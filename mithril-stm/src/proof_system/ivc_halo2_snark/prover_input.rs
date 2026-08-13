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
    proof_system::ivc_halo2_snark::{
        prover_input_helpers::{
            IvcTransitionType, assert_message_hash_matches_preimage, build_next_accumulator,
            build_next_state, create_snark_message_for_next_state, verify_certificate_proof,
        },
        prover_setup::IvcSnarkProverSetup,
        rolling_state::IvcRollingState,
    },
};

/// Outputs of the IVC prover's preparation step, consumed by the circuit-construction and
/// proof-generation steps.
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
    /// First classifies the requested step via [`IvcTransitionType::try_compute_transition_type`], then
    /// validates the epoch advance against the rolling chain state.
    /// The certificate proof is verifier-prepared, then the certificate and previous IVC accumulators are
    /// folded into the chain's accumulator.
    pub(crate) fn prepare<D: MembershipDigest>(
        certificate_proof: &SnarkProof<D>,
        message: &[u8],
        aggregate_verification_key_for_snark: &AggregateVerificationKeyForSnark<D>,
        global: &Global,
        protocol_message_preimage: &ProtocolMessagePreimage,
        rolling_state: &IvcRollingState,
        prover_setup: &IvcSnarkProverSetup,
    ) -> StmResult<Self> {
        let transition_type = IvcTransitionType::try_compute_transition_type(
            rolling_state,
            protocol_message_preimage,
        )?;

        rolling_state.assert_correct_parameters(
            protocol_message_preimage,
            aggregate_verification_key_for_snark,
            message,
            transition_type,
        )?;

        let (certificate_message_hash, certificate_merkle_tree_commitment) =
            create_snark_message_for_next_state(aggregate_verification_key_for_snark, message)?;

        assert_message_hash_matches_preimage(certificate_message_hash, protocol_message_preimage)?;

        let certificate_dual_msm = verify_certificate_proof(
            certificate_proof,
            message,
            aggregate_verification_key_for_snark,
            prover_setup,
        )?;

        let next_state = build_next_state(
            transition_type,
            rolling_state,
            certificate_message_hash,
            certificate_merkle_tree_commitment,
            protocol_message_preimage,
        )?;

        let next_accumulator =
            build_next_accumulator(certificate_dual_msm, rolling_state, prover_setup, global)?;

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
        assert_message_hash_matches_preimage(global.genesis_message, protocol_message_preimage)?;

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
mod test {
    use super::*;

    mod slow {
        use std::sync::OnceLock;

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
                io::Write as IvcWrite,
                tests::common::{
                    asset_readers::{
                        VerificationContextAsset, load_embedded_first_certificate_in_epoch_asset,
                        load_embedded_following_certificate_in_epoch_asset,
                        load_embedded_next_epoch_step_output_asset,
                        load_embedded_recursive_chain_state_asset,
                        load_embedded_verification_context_asset,
                    },
                    generators::{
                        build_asset_generation_setup_from_cache,
                        build_genesis_base_case_next_state, build_genesis_base_case_witness,
                        build_genesis_protocol_message_preimage, build_recursive_global,
                        setup::{
                            AssetGenerationSetup, GENESIS_EPOCH, QUORUM_SIZE, SIGNER_COUNT,
                            TOTAL_STAKE,
                        },
                    },
                },
                types::{
                    CertificateCircuitVerificationKeyRepresentation, EpochNumber,
                    IvcCircuitVerificationKeyRepresentation, StepCounter,
                },
            },
            signature_scheme::{SchnorrSignatureError, StandardSchnorrSignature},
        };

        use super::*;

        fn shared_ivc_setup() -> &'static IvcSnarkProverSetup {
            static CELL: OnceLock<IvcSnarkProverSetup> = OnceLock::new();
            CELL.get_or_init(|| {
                let parameters = Parameters {
                    k: QUORUM_SIZE as u64,
                    m: (QUORUM_SIZE * 10) as u64,
                    phi_f: 0.2,
                };
                let merkle_tree_depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
                IvcSnarkProverSetup::build_for_test(&parameters, merkle_tree_depth)
                    .expect("IvcSnarkProverSetup::load should succeed under the unsafe SRS")
            })
        }

        fn shared_asset_setup() -> &'static AssetGenerationSetup {
            static CELL: OnceLock<AssetGenerationSetup> = OnceLock::new();
            CELL.get_or_init(build_asset_generation_setup_from_cache)
        }

        fn shared_verification_context() -> &'static VerificationContextAsset {
            static CELL: OnceLock<VerificationContextAsset> = OnceLock::new();
            CELL.get_or_init(|| {
                load_embedded_verification_context_asset()
                    .expect("verification context asset should load")
            })
        }

        fn build_global() -> Global {
            let asset_setup = shared_asset_setup();
            let ctx = shared_verification_context();
            build_recursive_global(
                asset_setup,
                &ctx.certificate_verifying_key,
                &ctx.recursive_verifying_key,
            )
        }

        fn wrap_snark_proof(
            certificate_proof_bytes: Vec<u8>,
        ) -> SnarkProof<MithrilMembershipDigest> {
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
            use crate::circuits::halo2_ivc::PREIMAGE_SIZE;
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

        fn build_rolling_state(
            state: State,
            ivc_proof: crate::circuits::halo2_ivc::types::IvcProofBytes,
            accumulator: midnight_circuits::verifier::Accumulator<BlstrsEmulation>,
            genesis_signature: StandardSchnorrSignature,
        ) -> IvcRollingState {
            IvcRollingState::new(state, ivc_proof, accumulator, genesis_signature)
        }

        #[test]
        fn prepare_genesis_rejects_invalid_signature() {
            let mut chain_rng = ChaCha20Rng::from_seed([0u8; 32]);
            let chain_signing_key = SchnorrSigningKey::generate(&mut chain_rng);
            let chain_verification_key =
                SchnorrVerificationKey::new_from_signing_key(chain_signing_key);

            let preimage_bytes = [0u8; PREIMAGE_SIZE];
            let genesis_message = MessageHash::from_field(
                BaseFieldElement::try_from(preimage_bytes.as_slice())
                    .expect("hashing should not fail")
                    .0,
            );

            let global = Global {
                genesis_message,
                genesis_verification_key: chain_verification_key,
                certificate_circuit_verification_key_representation:
                    CertificateCircuitVerificationKeyRepresentation::from_field(
                        BaseFieldElement::from(0u64).0,
                    ),
                ivc_circuit_verification_key_representation:
                    IvcCircuitVerificationKeyRepresentation::from_field(
                        BaseFieldElement::from(0u64).0,
                    ),
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
            let protocol_message_preimage = ProtocolMessagePreimage::new(preimage_bytes);

            let err = IvcProverInput::prepare_genesis(
                &rolling_state,
                &protocol_message_preimage,
                &global,
            )
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
            let verification_key =
                SchnorrVerificationKey::new_from_signing_key(signing_key.clone());

            let cert_epoch = EpochNumber::ZERO;
            let mut preimage_bytes = [0u8; PREIMAGE_SIZE];
            preimage_bytes[PREIMAGE_CURRENT_EPOCH_BYTES]
                .copy_from_slice(&cert_epoch.as_u64().to_le_bytes());
            preimage_bytes[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES].copy_from_slice(&[0x11; 32]);
            preimage_bytes[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES].copy_from_slice(&[0x22; 32]);
            let protocol_message_preimage = ProtocolMessagePreimage::new(preimage_bytes);

            let genesis_message = MessageHash::from_field(
                BaseFieldElement::try_from(preimage_bytes.as_slice())
                    .expect("hashing should not fail")
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
                    IvcCircuitVerificationKeyRepresentation::from_field(
                        BaseFieldElement::from(0u64).0,
                    ),
            };

            let genesis_signature = signing_key
                .sign_standard(
                    &[BaseFieldElement::from(global.genesis_message.as_field())],
                    &mut rng,
                )
                .expect("sign_standard should succeed for the genesis message");
            let rolling_state = IvcRollingState::genesis(genesis_signature, &[]);

            let input = IvcProverInput::prepare_genesis(
                &rolling_state,
                &protocol_message_preimage,
                &global,
            )
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
        }

        #[test]
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_at_genesis_produces_advanced_state_and_witness() {
            let setup = shared_ivc_setup();
            let asset_setup = shared_asset_setup();
            let first_step = load_embedded_first_certificate_in_epoch_asset()
                .expect("first step cert asset should load");

            let global = build_global();
            let combined_names: Vec<String> = setup.combined_fixed_bases.keys().cloned().collect();
            let rolling_state =
                IvcRollingState::genesis(asset_setup.genesis_signature, &combined_names);

            let snark_proof = wrap_snark_proof(first_step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&first_step.aggregate_verification_key_merkle_root);
            let genesis_preimage_bytes = build_genesis_protocol_message_preimage(asset_setup);
            let protocol_message_preimage = wrap_protocol_message_preimage(&genesis_preimage_bytes);

            let input = IvcProverInput::prepare(
                &snark_proof,
                &first_step.message,
                &avk,
                &global,
                &protocol_message_preimage,
                &rolling_state,
                setup,
            )
            .expect("prepare should succeed at genesis");

            let expected_next_state =
                build_genesis_base_case_next_state(asset_setup, GENESIS_EPOCH);
            assert_eq!(input.next_state, expected_next_state);

            let expected_witness = build_genesis_base_case_witness(asset_setup);
            assert_eq!(input.witness, expected_witness);

            assert_eq!(
                accumulator_bytes(&input.next_accumulator),
                accumulator_bytes(rolling_state.accumulator()),
            );
        }

        #[test]
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_at_same_epoch_advances_state_correctly() {
            let setup = shared_ivc_setup();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let global = build_global();
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
            let chain_genesis_signature = chain_state.genesis_signature;
            let rolling_state = build_rolling_state(
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
                setup,
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
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_at_next_epoch_carries_lookahead_protocol_parameters() {
            let setup = shared_ivc_setup();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_next_epoch_step_output_asset()
                .expect("recursive step output asset should load");

            let global = build_global();
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
            let chain_genesis_signature = chain_state.genesis_signature;
            let rolling_state = build_rolling_state(
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
                setup,
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
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_rejects_invalid_snark_proof() {
            let setup = shared_ivc_setup();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let global = build_global();
            let mut corrupted = step.certificate_proof.clone().into_vec();
            corrupted[0] ^= 0xFF;

            let snark_proof = wrap_snark_proof(corrupted);
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);
            let rolling_state = build_rolling_state(
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
                setup,
            );

            let err = result
                .expect_err("prepare should reject a corrupted certificate proof")
                .downcast::<IvcCircuitError>()
                .expect("error should downcast to IvcCircuitError");
            assert!(matches!(err, IvcCircuitError::CertificateProofRejected(..)));
        }

        #[test]
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_rejects_invalid_genesis_signature() {
            let setup = shared_ivc_setup();
            let asset_setup = shared_asset_setup();
            let first_step = load_embedded_first_certificate_in_epoch_asset()
                .expect("first step cert asset should load");

            let global = build_global();
            let mut sig_bytes = asset_setup.genesis_signature.to_bytes();
            sig_bytes[32] ^= 0x01;
            let bad_signature = StandardSchnorrSignature::from_bytes(&sig_bytes)
                .expect("mutated signature should still deserialize");

            let combined_names: Vec<String> = setup.combined_fixed_bases.keys().cloned().collect();
            let rolling_state = IvcRollingState::genesis(bad_signature, &combined_names);

            let snark_proof = wrap_snark_proof(first_step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&first_step.aggregate_verification_key_merkle_root);
            let genesis_preimage_bytes = build_genesis_protocol_message_preimage(asset_setup);
            let protocol_message_preimage = wrap_protocol_message_preimage(&genesis_preimage_bytes);

            let result = IvcProverInput::prepare(
                &snark_proof,
                &first_step.message,
                &avk,
                &global,
                &protocol_message_preimage,
                &rolling_state,
                setup,
            );

            let err = result
                .expect_err("prepare should reject an invalid genesis signature")
                .downcast::<SchnorrSignatureError>()
                .expect("error should downcast to SchnorrSignatureError");
            assert!(
                matches!(err, SchnorrSignatureError::StandardSignatureInvalid(_)),
                "expected StandardSignatureInvalid, got {err:?}"
            );
        }

        #[test]
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_rejects_invalid_epoch_transition() {
            let setup = shared_ivc_setup();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let modified_state = State::new(
                chain_state.state.step_counter,
                chain_state.state.message,
                chain_state.state.merkle_tree_commitment,
                chain_state.state.next_merkle_tree_commitment,
                chain_state.state.protocol_parameters,
                chain_state.state.next_protocol_parameters,
                EpochNumber::new(u64::MAX - 100),
            );
            let rolling_state = build_rolling_state(
                modified_state,
                chain_state.ivc_proof,
                chain_state.accumulator,
                chain_state.genesis_signature,
            );

            let global = build_global();
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let result = IvcProverInput::prepare(
                &snark_proof,
                &step.message,
                &avk,
                &global,
                &protocol_message_preimage,
                &rolling_state,
                setup,
            );

            let err = result
                .expect_err("prepare should reject a bad epoch transition")
                .downcast::<IvcCircuitError>()
                .expect("error should downcast to IvcCircuitError");
            assert!(
                matches!(
                    err,
                    IvcCircuitError::InvalidEpochTransition {
                        kind: EpochTransitionErrorKind::EpochGap { .. },
                        ..
                    }
                ),
                "expected InvalidEpochTransition with OutOfRange kind, got {err:?}"
            );
        }

        #[test]
        #[ignore = "slow: runs real keygen via shared OnceLock; opt-in only"]
        fn prepare_rejects_step_counter_overflow() {
            let setup = shared_ivc_setup();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let modified_state = State::new(
                StepCounter::new(u64::MAX),
                chain_state.state.message,
                chain_state.state.merkle_tree_commitment,
                chain_state.state.next_merkle_tree_commitment,
                chain_state.state.protocol_parameters,
                chain_state.state.next_protocol_parameters,
                chain_state.state.current_epoch,
            );
            let rolling_state = build_rolling_state(
                modified_state,
                chain_state.ivc_proof,
                chain_state.accumulator,
                chain_state.genesis_signature,
            );

            let global = build_global();
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let protocol_message_preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let result = IvcProverInput::prepare(
                &snark_proof,
                &step.message,
                &avk,
                &global,
                &protocol_message_preimage,
                &rolling_state,
                setup,
            );

            let err = result
                .expect_err("prepare should reject step counter overflow")
                .downcast::<IvcCircuitError>()
                .expect("error should downcast to IvcCircuitError");
            assert!(
                matches!(err, IvcCircuitError::StepCounterOverflow { .. }),
                "expected StepCounterOverflow, got {err:?}"
            );
        }
    }
}
