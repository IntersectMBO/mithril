//! Pre-circuit inputs produced by the IVC prover's preparation step.
//!
//! Holds the witness, the advanced chain state, and the folded accumulator that
//! the in-circuit construction and proof-generation steps consume next.

#[cfg(feature = "future_snark")]
use std::sync::Arc;

use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};
#[cfg(feature = "future_snark")]
use midnight_proofs::transcript::Blake2b256;

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
            build_next_state, verify_certificate_proof,
        },
        prover_setup::IvcSnarkProverSetup,
        rolling_state::{IvcProverInputChecks, IvcRollingState},
    },
};
#[cfg(feature = "future_snark")]
use crate::{
    AncillaryProofInput, AncillaryProverData, AncillaryVerifierData, SingleSignature,
    circuits::halo2::keys::NonRecursiveCircuitVerifyingKey,
    proof_system::{
        SnarkClerk,
        ivc_halo2_snark::proof::{IvcGenesisBootstrapInput, IvcProof},
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
    /// Completes `prepare` once the certificate proof is available: verifies it, advances the
    /// chain state, and folds the accumulator. `checks` must come from [`Self::off_circuit_checks`]
    /// run against the same `protocol_message_preimage` and `rolling_state`.
    pub(crate) fn finish_preparation<D: MembershipDigest>(
        checks: IvcProverInputChecks<D>,
        certificate_proof: &SnarkProof<D>,
        global: &Global,
        protocol_message_preimage: &ProtocolMessagePreimage,
        rolling_state: &IvcRollingState,
        prover_setup: &IvcSnarkProverSetup,
    ) -> StmResult<Self> {
        let IvcProverInputChecks {
            transition_type,
            certificate_message_hash,
            certificate_merkle_tree_commitment,
            message,
            aggregate_verification_key_for_snark,
        } = checks;

        let certificate_dual_msm = verify_certificate_proof(
            certificate_proof,
            message.as_slice(),
            &aggregate_verification_key_for_snark,
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

    /// Advances the chain state by one step and bundles the in-circuit witness, the
    /// next state, and the next folded accumulator.
    ///
    /// Runs [`Self::off_circuit_checks`] then [`Self::finish_preparation`]. Callers that want to reject a
    /// malformed request before the certificate proof is generated should call
    /// [`Self::off_circuit_checks`] directly, ahead of time, instead of using this combined form.
    pub(crate) fn prepare<D: MembershipDigest>(
        certificate_proof: &SnarkProof<D>,
        message: &[u8],
        aggregate_verification_key_for_snark: &AggregateVerificationKeyForSnark<D>,
        global: &Global,
        protocol_message_preimage: &ProtocolMessagePreimage,
        rolling_state: &IvcRollingState,
        prover_setup: &IvcSnarkProverSetup,
    ) -> StmResult<Self> {
        let checks = rolling_state.off_circuit_checks(
            message,
            aggregate_verification_key_for_snark,
            protocol_message_preimage,
        )?;

        Self::finish_preparation(
            checks,
            certificate_proof,
            global,
            protocol_message_preimage,
            rolling_state,
            prover_setup,
        )
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

/// Bundles the outputs of [`prepare_and_check_ivc_snark_request`]: everything [`prove_ivc_snark`] needs to
/// generate the certificate proof and complete IVC proving, once the request has passed every
/// check that doesn't require that proof.
#[cfg(feature = "future_snark")]
pub(crate) struct PreparedIvcSnarkRequest<'a> {
    ivc_prover_setup: Arc<IvcSnarkProverSetup>,
    certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    global: Global,
    protocol_message_preimage: ProtocolMessagePreimage,
    current_rolling_state: Option<&'a IvcRollingState>,
    genesis_bootstrap: IvcGenesisBootstrapInput,
}

impl<'a> PreparedIvcSnarkRequest<'a> {
    /// Loads the IVC prover setup, builds [`Global`], and runs every off circuit check that
    /// doesn't require the certificate proof: genesis verification key validity, rolling-state
    /// presence, protocol parameters unchanged, and message/preimage hash matching (genesis or
    /// non-genesis, depending on whether `ancillary_input` carries a rolling state).
    #[cfg(feature = "future_snark")]
    pub(crate) fn prepare_and_check_ivc_snark_request(
        snark_clerk: &SnarkClerk,
        ancillary_input: &'a AncillaryProofInput,
        msg: &[u8],
    ) -> StmResult<Self> {
        use anyhow::anyhow;

        use crate::{
            AggregationError, MERKLE_TREE_DEPTH_FOR_SNARK, MithrilMembershipDigest,
            circuits::{
                halo2_ivc::PREIMAGE_SIZE, key_provider::KeyProvider,
                trusted_setup::TrustedSetupProvider,
            },
        };

        let genesis_data = ancillary_input.genesis_data();
        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
        let genesis_message = genesis_data.genesis_message_preimage().try_into()?;
        let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;

        let current_rolling_state = ancillary_input
            .prover_data()
            .map(|prover_data| {
                prover_data.as_ivc_rolling_state().ok_or(anyhow!(
                    AggregationError::MissingIvcRollingStateInAncillaryProverData
                ))
            })
            .transpose()?;
        IvcRollingState::ensure_advanceable_rolling_state(current_rolling_state)?;

        let protocol_message_preimage_bytes: [u8; PREIMAGE_SIZE] =
            ancillary_input.message_preimage().try_into()?;
        let protocol_message_preimage = ProtocolMessagePreimage(protocol_message_preimage_bytes);

        let trusted_setup_provider = TrustedSetupProvider::default();
        let certificate_provider = KeyProvider::for_non_recursive_circuit(
            &snark_clerk.parameters,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )?;
        let recursive_key_provider = KeyProvider::for_recursive_circuit(certificate_provider);
        let ivc_prover_setup = Arc::new(IvcSnarkProverSetup::load(
            &trusted_setup_provider,
            &recursive_key_provider,
        )?);
        let certificate_verifying_key = ivc_prover_setup.certificate_verifying_key.clone();

        let global = Global::new(
            genesis_message,
            genesis_verifying_key,
            &certificate_verifying_key,
            &ivc_prover_setup.ivc_verifying_key,
        )?;

        let avk =
            snark_clerk.compute_aggregate_verification_key_for_snark::<MithrilMembershipDigest>();

        match current_rolling_state {
            Some(rolling_state) => {
                rolling_state.assert_protocol_parameters_unchanged()?;
                rolling_state.off_circuit_checks(msg, &avk, &protocol_message_preimage)?;
            }
            None => {
                let combined_fixed_base_names: Vec<String> =
                    ivc_prover_setup.combined_fixed_bases.keys().cloned().collect();
                let genesis_rolling_state = IvcRollingState::genesis(
                    genesis_bootstrap.genesis_signature,
                    &combined_fixed_base_names,
                );
                genesis_rolling_state.off_circuit_genesis_checks(
                    &genesis_bootstrap.genesis_protocol_message_preimage,
                    &global,
                    msg,
                    &avk,
                    &protocol_message_preimage,
                )?;
            }
        }

        Ok(PreparedIvcSnarkRequest {
            ivc_prover_setup,
            certificate_verifying_key,
            global,
            protocol_message_preimage,
            current_rolling_state,
            genesis_bootstrap,
        })
    }

    /// Generates the certificate proof and completes IVC proving for a request already validated by
    /// [`prepare_and_check_ivc_snark_request`].
    ///
    /// Returns `(proof, ancillary_prover_data, ancillary_verifier_data)`. `ancillary_prover_data` is `Some` when
    /// the step advances the epoch and `None` for same-epoch steps.
    ///
    /// # Errors
    /// Fails if the message preimage is not PREIMAGE_SIZE bytes, or the proof itself fails.
    #[cfg(feature = "future_snark")]
    pub(crate) fn prove_ivc_snark(
        self,
        sigs: &[SingleSignature],
        msg: &[u8],
        snark_clerk: &SnarkClerk,
    ) -> StmResult<(
        IvcProof<Blake2b256>,
        Option<AncillaryProverData>,
        AncillaryVerifierData,
    )> {
        use anyhow::Context;
        use rand_core::OsRng;

        use crate::{
            MERKLE_TREE_DEPTH_FOR_SNARK, MithrilMembershipDigest,
            proof_system::{
                SnarkProver,
                ivc_halo2_snark::{proof::IvcProver, verifier_setup::IvcVerifierData},
            },
        };

        let snark_proof = SnarkProver::try_new_non_deterministic(
            &snark_clerk.parameters,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )?
        .aggregate_signatures::<MithrilMembershipDigest>(snark_clerk, sigs, msg)
        .with_context(|| {
            use crate::AggregateSignatureType;

            format!(
                "Signatures failed to aggregate for type {}",
                AggregateSignatureType::Snark
            )
        })?;

        let avk =
            snark_clerk.compute_aggregate_verification_key_for_snark::<MithrilMembershipDigest>();

        let ivc_verifying_key = self.ivc_prover_setup.ivc_verifying_key.clone();

        let mut prover = IvcProver {
            ivc_setup: self.ivc_prover_setup,
            rng: OsRng,
        };

        let (ivc_proof, next_rolling_state) = prover.prove(
            snark_proof,
            msg,
            &avk,
            &self.global,
            &self.protocol_message_preimage,
            &self.genesis_bootstrap,
            self.current_rolling_state,
        )?;

        let next_ancillary_prover_data = next_rolling_state.map(AncillaryProverData::IvcSnark);

        let ancillary_verifier_data = AncillaryVerifierData::IvcSnark(IvcVerifierData::new(
            self.global.genesis_message,
            self.certificate_verifying_key,
            ivc_verifying_key,
        ));

        Ok((
            ivc_proof,
            next_ancillary_prover_data,
            ancillary_verifier_data,
        ))
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
                errors::IvcCircuitError,
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

            let global = build_global();
            let mut sig_bytes = asset_setup.genesis_signature.to_bytes();
            sig_bytes[32] ^= 0x01;
            let bad_signature = StandardSchnorrSignature::from_bytes(&sig_bytes)
                .expect("mutated signature should still deserialize");

            let combined_names: Vec<String> = setup.combined_fixed_bases.keys().cloned().collect();
            let rolling_state = IvcRollingState::genesis(bad_signature, &combined_names);

            let genesis_preimage_bytes = build_genesis_protocol_message_preimage(asset_setup);
            let protocol_message_preimage = wrap_protocol_message_preimage(&genesis_preimage_bytes);

            let result = IvcProverInput::prepare_genesis(
                &rolling_state,
                &protocol_message_preimage,
                &global,
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
    }
}
