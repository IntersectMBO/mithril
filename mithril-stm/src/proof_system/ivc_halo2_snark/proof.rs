//! `IvcProver` and `IvcProof`: the proving-session handle and its emitted IVC proof.

use std::{marker::PhantomData, sync::Arc};

use anyhow::{Context, anyhow};
use ff::FromUniformBytes;
use group::Group;
use midnight_circuits::{
    hash::poseidon::PoseidonState,
    types::Instantiable,
    verifier::{Accumulator, AssignedAccumulator, BlstrsEmulation},
};
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::{
    plonk::{create_proof, prepare},
    poly::{
        commitment::PolynomialCommitmentScheme,
        kzg::{KZGCommitmentScheme, params::ParamsKZG},
    },
    transcript::{Blake2b256, CircuitTranscript, Hashable, Sampleable, Transcript, TranscriptHash},
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    AggregateVerificationKeyForSnark, AncillaryGenesisData, BaseFieldElement, MembershipDigest,
    SnarkProof, StmResult,
    circuits::{
        halo2::types::CircuitBase,
        halo2_ivc::{
            PREIMAGE_SIZE,
            circuit::IvcCircuitData,
            keys::RecursiveCircuitProvingKey,
            state::{Global, State},
            types::{CertificateProofBytes, IvcProofBytes, MessageHash, ProtocolMessagePreimage},
        },
    },
    codec,
    proof_system::ivc_halo2_snark::{
        errors::IvcProofError,
        prover_input::IvcProverInput,
        prover_input_helpers::IvcTransitionType,
        prover_setup::IvcSnarkProverSetup,
        rolling_state::{IvcRollingState, midnight_accumulator_serde},
        verifier_setup::IvcVerifierSetup,
    },
    signature_scheme::StandardSchnorrSignature,
};

/// Per-session IVC prover handle.
pub(crate) struct IvcProver<R: RngCore + CryptoRng> {
    /// Shared, cached setup (SRS, verifying keys, proving key, fixed-base maps).
    pub(crate) ivc_setup: Arc<IvcSnarkProverSetup>,
    /// Randomness source used during proof generation.
    pub(crate) rng: R,
}

/// Bootstrap input for the first [`IvcProver::prove`] call in an IVC chain.
///
/// Always supplied to [`IvcProver::prove`] by reference; used only when `rolling_state = None`
/// (the first certificate) to run the internal genesis IVC step before processing it.
pub(crate) struct IvcGenesisBootstrapInput {
    /// Schnorr half of the Lagrange-era dual genesis signature (Ed25519 + Schnorr). Carried
    /// forward through every rolling state for in-circuit verification of the genesis message.
    /// Populated from `AncillaryGenesisData::genesis_schnorr_signature()` (see issue #3141).
    pub(crate) genesis_signature: StandardSchnorrSignature,
    /// Protocol message preimage of the genesis certificate. Needed by the internal genesis IVC
    /// step to set the lookahead fields in the genesis output state.
    /// Populated from `AncillaryGenesisData::genesis_message_preimage()` (see issue #3141).
    pub(crate) genesis_protocol_message_preimage: ProtocolMessagePreimage,
}

/// Fails if the genesis Schnorr signature is absent
/// or if the message preimage is not exactly PREIMAGE_SIZE bytes.
impl TryFrom<&AncillaryGenesisData> for IvcGenesisBootstrapInput {
    type Error = anyhow::Error;
    fn try_from(ancillary_genesis_data: &AncillaryGenesisData) -> StmResult<Self> {
        let genesis_signature = ancillary_genesis_data
            .genesis_schnorr_signature()
            .ok_or_else(|| anyhow!("Missing genesis Schnorr signature."))?;

        let genesis_protocol_message_preimage: [u8; PREIMAGE_SIZE] = ancillary_genesis_data
            .genesis_message_preimage()
            .0
            .as_slice()
            .try_into()?;

        Ok(Self {
            genesis_protocol_message_preimage: genesis_protocol_message_preimage.into(),
            genesis_signature: *genesis_signature,
        })
    }
}

/// IVC proof emitted at the end of a proving step.
///
/// `H` is the transcript hash used to produce this proof and must be used to verify it.
/// It is a zero-cost phantom: no `H`-dependent data is stored, but it prevents accidentally
/// verifying a Poseidon-produced proof via the Blake2b path and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvcProof<H: TranscriptHash> {
    /// Externally-verifiable proof bytes.
    proof_bytes: IvcProofBytes,
    /// Chain state the proof commits to.
    state: State,
    /// Folded accumulator the proof commits to.
    #[serde(with = "midnight_accumulator_serde")]
    accumulator: Accumulator<BlstrsEmulation>,
    /// Phantom marker tying the proof to its transcript hash type.
    hash: PhantomData<H>,
}

impl<H: TranscriptHash> IvcProof<H> {
    /// Bundle the outputs of a single proving step into a typed proof.
    ///
    /// `H` is inferred from the prover's own type parameter, so the proof's hash type
    /// is bound to the hash used to produce it without any runtime check.
    pub(crate) fn new(
        proof_bytes: IvcProofBytes,
        state: State,
        accumulator: Accumulator<BlstrsEmulation>,
    ) -> Self {
        Self {
            proof_bytes,
            state,
            accumulator,
            hash: PhantomData,
        }
    }

    /// Converts a IvcProof to CBOR bytes with a version prefix.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Deserialise an IVC proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes(&bytes[1..])
        } else {
            Err(anyhow::anyhow!(
                "IvcProof: unsupported encoding, expected a CBOR v1 prefix"
            ))
        }
    }
}

impl<H: TranscriptHash> IvcProof<H>
where
    CircuitBase: Sampleable<H> + Hashable<H>,
    <KZGCommitmentScheme<Bls12> as PolynomialCommitmentScheme<CircuitBase>>::Commitment:
        Hashable<H>,
{
    /// Verifies the IVC proof and its folded accumulator using transcript hash `H`.
    ///
    /// Checks:
    /// 1. The KZG opening equations against the IVC verifying key.
    /// 2. The folded accumulator pairing equation.
    ///
    /// # Invariant
    ///
    /// `global` and `verifier_setup` must be built from the same certificate and IVC verifying
    /// keys. If they differ, the public inputs fed to the KZG opening check will not match the
    /// proof transcript and verification will return [`IvcProofError::KzgOpeningFailed`].
    pub(crate) fn verify(
        &self,
        msg: &[u8],
        global: &Global,
        verifier_setup: &IvcVerifierSetup,
    ) -> StmResult<()> {
        self.check_input_message_matches_state_message(msg)?;
        let public_inputs: Vec<CircuitBase> = [
            global.as_public_input(),
            self.state.as_public_input(),
            AssignedAccumulator::as_public_input(&self.accumulator),
        ]
        .concat();

        let mut transcript = CircuitTranscript::<H>::init_from_bytes(self.proof_bytes.as_bytes());

        let dual_msm = prepare::<CircuitBase, KZGCommitmentScheme<Bls12>, CircuitTranscript<H>>(
            verifier_setup.ivc_verifying_key().verifying_key(),
            &[&[G1Projective::identity()]],
            &[&[&public_inputs]],
            &mut transcript,
        )
        .map_err(|_| IvcProofError::TranscriptPreparationFailed)?;

        transcript
            .assert_empty()
            .map_err(|_| IvcProofError::TranscriptNotFullyConsumed)?;

        if !dual_msm.check(verifier_setup.verifier_params()) {
            return Err(IvcProofError::KzgOpeningFailed.into());
        }

        if !self.accumulator.check(
            verifier_setup.verifier_params(),
            verifier_setup.combined_fixed_bases(),
        ) {
            return Err(IvcProofError::AccumulatorFailed.into());
        }

        Ok(())
    }

    /// Verifies that the input protocol message is the same as the one used to generate
    /// the proof.
    ///
    /// Returns an error if the input message has a wrong format, cannot be converted to a field
    /// element or is different from the message store in the proof state.
    fn check_input_message_matches_state_message(&self, msg: &[u8]) -> StmResult<()> {
        let mut msg_bytes = [0u8; 32];
        match TryInto::<[u8; 32]>::try_into(msg) {
            Ok(bytes) => msg_bytes = bytes,
            Err(_) => {
                // If the message is not 32 bytes, try to decode it as hex.
                hex::decode_to_slice(msg, &mut msg_bytes).with_context(
                || "Message must be exactly 32 bytes hex encoded in 64 bytes if it is not exactly 32 bytes.",
            )?;
            }
        }

        let message_as_base_field_element = BaseFieldElement::from_raw(&msg_bytes)
            .with_context(|| "Failed to convert message to BaseFieldElement.")?;

        if self.state.message != MessageHash::from_field(message_as_base_field_element.0) {
            return Err(IvcProofError::InvalidMessage.into());
        }

        Ok(())
    }
}

impl<H: TranscriptHash> IvcProof<H>
where
    CircuitBase: Sampleable<H> + Hashable<H> + std::hash::Hash + Ord + FromUniformBytes<64>,
    <KZGCommitmentScheme<Bls12> as PolynomialCommitmentScheme<CircuitBase>>::Commitment:
        Hashable<H>,
{
    /// Calls `create_proof` with the committed-instance layout the IVC circuit expects:
    /// `&[&[&[], public_inputs]]` (one circuit, one instance group, empty committed
    /// instance, then the field-element public inputs). Returns the finalised transcript
    /// bytes on success.
    pub(crate) fn prove_with_transcript(
        srs: &ParamsKZG<Bls12>,
        proving_key: &RecursiveCircuitProvingKey,
        circuit_data: &IvcCircuitData,
        public_inputs: &[CircuitBase],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StmResult<Vec<u8>> {
        let mut transcript = CircuitTranscript::<H>::init();
        create_proof::<
            CircuitBase,
            KZGCommitmentScheme<Bls12>,
            CircuitTranscript<H>,
            IvcCircuitData,
        >(
            srs,
            proving_key.proving_key(),
            std::slice::from_ref(circuit_data),
            1,
            &[&[&[], public_inputs]],
            &mut transcript,
            rng,
        )
        .map_err(|e| IvcProofError::ProofGenerationFailed(e.to_string()))?;
        Ok(transcript.finalize())
    }
}

/// Rejects a `rolling_state` that carries a genesis state (`step_counter == 0`).
///
/// The genesis step is only ever produced internally by the bootstrap path; callers reach it by
/// passing `rolling_state = None`. A genesis state supplied as a previous step would instead run
/// a normal step that silently ignores the certificate. Since `genesis_bootstrap` is always
/// supplied, this is the only remaining invalid context: the previously-possible both-`Some` and
/// both-`None` misuses are now unrepresentable.
fn ensure_advanceable_rolling_state(rolling_state: Option<&IvcRollingState>) -> StmResult<()> {
    if rolling_state.is_some_and(|rs| rs.is_genesis()) {
        return Err(IvcProofError::InvalidProvingContext.into());
    }
    Ok(())
}

impl<R: RngCore + CryptoRng> IvcProver<R> {
    /// Advances the IVC chain by one step.
    ///
    /// `genesis_bootstrap` carries the chain's genesis data and is always supplied; whether it
    /// is used depends on `rolling_state`:
    ///
    /// - `rolling_state = Some(rs)`: normal step. `rs` carries the previous step's output. The
    ///   transition type (same-epoch / next-epoch) is determined from the certificate epoch vs
    ///   the chain epoch recorded in `rs`. `genesis_bootstrap` is unused.
    /// - `rolling_state = None`: genesis bootstrap, at the first certificate (Epoch 1).
    ///   Internally runs a genesis IVC step using `genesis_bootstrap.genesis_signature` and
    ///   `genesis_bootstrap.genesis_protocol_message_preimage`, then immediately runs the
    ///   Epoch 1 step with the supplied certificate inputs. Returns the Epoch 1 Blake2b proof
    ///   and the updated rolling state.
    ///
    /// A `rolling_state` carrying a genesis state (`step_counter == 0`) returns
    /// [`IvcProofError::InvalidProvingContext`]: the genesis step is only reachable via the
    /// `rolling_state = None` bootstrap path.
    ///
    /// Returns `(proof, next_rolling_state)`. `next_rolling_state` is `Some` on next-epoch
    /// steps (rolling state must advance) and `None` on same-epoch steps.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove<D: MembershipDigest>(
        &mut self,
        snark_proof: SnarkProof<D>,
        message: &[u8],
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
        global: &Global,
        protocol_message_preimage: &ProtocolMessagePreimage,
        genesis_bootstrap: &IvcGenesisBootstrapInput,
        rolling_state: Option<&IvcRollingState>,
    ) -> StmResult<(IvcProof<Blake2b256>, Option<IvcRollingState>)> {
        ensure_advanceable_rolling_state(rolling_state)?;

        // `rolling_state = None` is the first certificate: bootstrap from genesis internally,
        // then continue with the seeded state. Otherwise advance from the supplied state.
        let effective_rolling_state: &IvcRollingState = match rolling_state {
            None => &self.run_genesis_step(global, genesis_bootstrap)?,
            Some(rolling_state) => rolling_state,
        };

        // Prepare the witness, next state, and folded next accumulator.
        // prepare() borrows snark_proof; snark_proof is still owned afterward.
        let prover_input = IvcProverInput::prepare(
            &snark_proof,
            message,
            aggregate_verification_key,
            global,
            protocol_message_preimage,
            effective_rolling_state,
            &self.ivc_setup,
        )?;

        let certificate_proof_bytes = snark_proof.into_circuit_proof_bytes();

        let circuit_data = IvcCircuitData::try_new(
            global.clone(),
            effective_rolling_state.state().clone(),
            prover_input.witness,
            certificate_proof_bytes,
            effective_rolling_state.ivc_proof().clone(),
            effective_rolling_state.accumulator().clone(),
            &self.ivc_setup.certificate_verifying_key,
            &self.ivc_setup.ivc_verifying_key,
        )?;

        // Public inputs for the new step: [global | next_state | next_accumulator].
        let public_inputs: Vec<CircuitBase> = [
            global.as_public_input(),
            prover_input.next_state.as_public_input(),
            AssignedAccumulator::as_public_input(&prover_input.next_accumulator),
        ]
        .concat();

        // Next-epoch steps update the rolling state with a fresh Poseidon proof.
        // Same-epoch steps leave the rolling state unchanged (return None).
        let next_rolling_state =
            if matches!(prover_input.transition_type, IvcTransitionType::NextEpoch) {
                let poseidon_bytes = IvcProof::<PoseidonState<CircuitBase>>::prove_with_transcript(
                    &self.ivc_setup.srs,
                    &self.ivc_setup.ivc_proving_key,
                    &circuit_data,
                    &public_inputs,
                    &mut self.rng,
                )?;
                Some(IvcRollingState::new(
                    prover_input.next_state.clone(),
                    IvcProofBytes::new(poseidon_bytes),
                    prover_input.next_accumulator.clone(),
                    effective_rolling_state.genesis_signature(),
                ))
            } else {
                None
            };

        let blake2b_bytes = IvcProof::<Blake2b256>::prove_with_transcript(
            &self.ivc_setup.srs,
            &self.ivc_setup.ivc_proving_key,
            &circuit_data,
            &public_inputs,
            &mut self.rng,
        )?;
        let proof = IvcProof::new(
            IvcProofBytes::new(blake2b_bytes),
            prover_input.next_state,
            prover_input.next_accumulator,
        );

        Ok((proof, next_rolling_state))
    }

    /// Runs the genesis IVC step internally during bootstrap.
    ///
    /// Builds a zero genesis rolling state from `bootstrap.genesis_signature`, calls
    /// [`IvcProverInput::prepare_genesis`] with the genesis preimage, and generates a Poseidon proof
    /// to seed the rolling state. The resulting rolling state is returned for immediate use
    /// in the Epoch 1 step.
    fn run_genesis_step(
        &mut self,
        global: &Global,
        bootstrap: &IvcGenesisBootstrapInput,
    ) -> StmResult<IvcRollingState> {
        let combined_fixed_base_names: Vec<String> =
            self.ivc_setup.combined_fixed_bases.keys().cloned().collect();
        let genesis_rolling_state =
            IvcRollingState::genesis(bootstrap.genesis_signature, &combined_fixed_base_names);

        let genesis_prover_input = IvcProverInput::prepare_genesis(
            &genesis_rolling_state,
            &bootstrap.genesis_protocol_message_preimage,
            global,
        )?;

        let genesis_circuit_data = IvcCircuitData::try_new(
            global.clone(),
            genesis_rolling_state.state().clone(),
            genesis_prover_input.witness,
            CertificateProofBytes::empty(),
            genesis_rolling_state.ivc_proof().clone(),
            genesis_rolling_state.accumulator().clone(),
            &self.ivc_setup.certificate_verifying_key,
            &self.ivc_setup.ivc_verifying_key,
        )?;

        let genesis_public_inputs: Vec<CircuitBase> = [
            global.as_public_input(),
            genesis_prover_input.next_state.as_public_input(),
            AssignedAccumulator::as_public_input(&genesis_prover_input.next_accumulator),
        ]
        .concat();

        let poseidon_bytes = IvcProof::<PoseidonState<CircuitBase>>::prove_with_transcript(
            &self.ivc_setup.srs,
            &self.ivc_setup.ivc_proving_key,
            &genesis_circuit_data,
            &genesis_public_inputs,
            &mut self.rng,
        )?;

        Ok(IvcRollingState::new(
            genesis_prover_input.next_state,
            IvcProofBytes::new(poseidon_bytes),
            genesis_prover_input.next_accumulator,
            bootstrap.genesis_signature,
        ))
    }
}

#[cfg(test)]
mod tests {

    use midnight_proofs::transcript::Blake2b256;

    use crate::{
        circuits::halo2_ivc::{
            state::Global,
            tests::common::{
                asset_readers::{
                    load_embedded_following_certificate_in_epoch_asset,
                    load_embedded_next_epoch_step_output_asset,
                    load_embedded_recursive_chain_state_asset,
                    load_embedded_verification_context_asset,
                },
                generators::{build_asset_generation_setup, build_recursive_global},
            },
            types::{IvcProofBytes, MessageHash},
        },
        proof_system::ivc_halo2_snark::{errors::IvcProofError, verifier_setup::IvcVerifierSetup},
    };

    use super::IvcProof;

    const STEP_OUTPUT_MSG: [u8; 32] = [
        22, 148, 87, 37, 149, 0, 124, 10, 156, 94, 108, 6, 78, 59, 239, 80, 126, 213, 158, 211,
        191, 213, 128, 70, 128, 30, 235, 80, 192, 191, 159, 67,
    ];

    const SAME_EPOCH_MSG: [u8; 32] = [
        147, 84, 244, 74, 250, 60, 153, 155, 8, 94, 236, 150, 53, 39, 132, 61, 99, 153, 192, 207,
        20, 90, 16, 130, 216, 12, 87, 134, 230, 4, 190, 175,
    ];

    const CHAIN_STATE_MSG: [u8; 32] = [
        253, 10, 116, 221, 249, 84, 222, 35, 101, 84, 229, 73, 90, 91, 97, 173, 36, 63, 47, 98,
        189, 1, 99, 75, 183, 186, 225, 31, 226, 29, 121, 122,
    ];

    fn build_proof_verifier_context() -> (Global, IvcVerifierSetup) {
        let ctx = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let setup = build_asset_generation_setup();
        let global = build_recursive_global(
            &setup,
            &ctx.certificate_verifying_key,
            &ctx.recursive_verifying_key,
        );
        let verifier_setup = IvcVerifierSetup::from_parts(
            ctx.verifier_params,
            ctx.recursive_verifying_key,
            ctx.combined_fixed_bases,
        );
        (global, verifier_setup)
    }

    #[test]
    fn ivc_proof_verify_accepts_stored_recursive_step_output() {
        // Exercises the `IvcProof::verify` high-level API end-to-end against the
        // stored next-epoch Blake2b proof, confirming that the unified verification
        // path (KZG opening + accumulator pairing) accepts a known-good proof.
        let verification_context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let setup = build_asset_generation_setup();
        let global = build_recursive_global(
            &setup,
            &verification_context.certificate_verifying_key,
            &verification_context.recursive_verifying_key,
        );

        let verifier_setup = IvcVerifierSetup::from_parts(
            verification_context.verifier_params,
            verification_context.recursive_verifying_key,
            verification_context.combined_fixed_bases,
        );

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        proof
            .verify(&STEP_OUTPUT_MSG, &global, &verifier_setup)
            .expect("stored recursive step output should pass IvcProof::verify");
    }

    #[test]
    fn ivc_proof_to_from_bytes_round_trip() {
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let bytes = proof.to_bytes().expect("serialization should not fail");
        let restored =
            IvcProof::<Blake2b256>::from_bytes(&bytes).expect("deserialization should not fail");

        assert_eq!(
            bytes,
            restored.to_bytes().expect("re-serialization should not fail")
        );
    }

    #[test]
    fn ivc_proof_message_verification_accepts_correct_message() {
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        proof
            .check_input_message_matches_state_message(&STEP_OUTPUT_MSG)
            .expect("Correct message should be accepted by verification function");
    }

    #[test]
    fn ivc_proof_message_verification_rejects_wrong_message() {
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let mut wrong_msg = STEP_OUTPUT_MSG;
        wrong_msg[0] ^= 0xff;

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .check_input_message_matches_state_message(&wrong_msg)
            .expect_err("wrong message should be rejected by verification function");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::InvalidMessage),
            "wrong message must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_wrong_message() {
        let verification_context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let mut wrong_msg = STEP_OUTPUT_MSG;
        wrong_msg[0] ^= 0xff;

        let setup = build_asset_generation_setup();
        let global = build_recursive_global(
            &setup,
            &verification_context.certificate_verifying_key,
            &verification_context.recursive_verifying_key,
        );

        let verifier_setup = IvcVerifierSetup::from_parts(
            verification_context.verifier_params,
            verification_context.recursive_verifying_key,
            verification_context.combined_fixed_bases,
        );

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(&wrong_msg, &global, &verifier_setup)
            .expect_err("tampered message should be rejected by IvcProof::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::InvalidMessage),
            "tampered message must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_tampered_proof_bytes() {
        // A single flipped byte anywhere in the proof transcript must cause `verify` to
        // return `Err`: the KZG opening equations are computed over the raw bytes, so
        // any corruption propagates to a bad MSM and the `dual_msm.check` fails.
        let (global, verifier_setup) = build_proof_verifier_context();
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let mut tampered_bytes = step_output.ivc_proof.as_bytes().to_vec();
        let mid = tampered_bytes.len() / 2;
        tampered_bytes[mid] ^= 0xff;

        let proof = IvcProof::<Blake2b256>::new(
            IvcProofBytes::new(tampered_bytes),
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(&STEP_OUTPUT_MSG, &global, &verifier_setup)
            .expect_err("tampered proof bytes should be rejected by IvcProof::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::KzgOpeningFailed),
            "tampered bytes must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_tampered_message_bytes_with_correct_input_message() {
        let (global, verifier_setup) = build_proof_verifier_context();
        let mut step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        step_output.next_state.message = MessageHash::ZERO;

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(&STEP_OUTPUT_MSG, &global, &verifier_setup)
            .expect_err("different protocol message should be rejected by IvcProof::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::InvalidMessage),
            "different protocol message must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_tampered_message_bytes_with_tampered_input_message() {
        let (global, verifier_setup) = build_proof_verifier_context();
        let mut step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        // Set the message and the MessageHash to zero so they match between
        // them but they don't match what was used to create the proof
        let tampered_msg = &[0u8; 32];
        step_output.next_state.message = MessageHash::ZERO;

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(tampered_msg, &global, &verifier_setup)
            .expect_err("different protocol message should be rejected by IvcProof::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::KzgOpeningFailed),
            "different protocol message must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_mismatched_state() {
        // Substituting the state from a different proof step changes the public inputs
        // fed to `prepare`, causing `dual_msm.check` to fail against the unmodified
        // proof bytes.
        let (global, verifier_setup) = build_proof_verifier_context();
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");
        let same_epoch = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            same_epoch.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(&SAME_EPOCH_MSG, &global, &verifier_setup)
            .expect_err("state from a different proof should be rejected by IvcProof::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::KzgOpeningFailed),
            "mismatched state corrupts public inputs and must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_mismatched_accumulator() {
        // Substituting the accumulator from a different proof step corrupts the public
        // inputs fed to `prepare` (the accumulator is serialised into them), so
        // `dual_msm.check` fails before the pairing equation is ever reached.
        let (global, verifier_setup) = build_proof_verifier_context();
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");
        let same_epoch = load_embedded_following_certificate_in_epoch_asset()
            .expect("same-epoch step output asset should load");

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            same_epoch.next_accumulator,
        );

        let err = proof.verify(&STEP_OUTPUT_MSG, &global, &verifier_setup).expect_err(
            "accumulator from a different proof should be rejected by IvcProof::verify",
        );
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::KzgOpeningFailed),
            "mismatched accumulator corrupts public inputs and must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_poseidon_proof_bytes() {
        // Constructing an `IvcProof<Blake2b256>` with Poseidon-transcript bytes
        // and verifying it with the Blake2b path must fail: the two transcript formats
        // are not interchangeable.
        let (global, verifier_setup) = build_proof_verifier_context();
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");

        let proof = IvcProof::<Blake2b256>::new(
            chain_state.ivc_proof,
            chain_state.state,
            chain_state.accumulator,
        );

        let err = proof
            .verify(&CHAIN_STATE_MSG, &global, &verifier_setup)
            .expect_err("Poseidon proof bytes should be rejected by IvcProof::<Blake2b>::verify");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::KzgOpeningFailed),
            "Poseidon bytes via Blake2b path must fail the KZG opening check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_wrong_fixed_bases() {
        // A verifier setup with a wrong fixed bases but otherwise correct parameters passes
        // the KZG opening check and fails at the accumulator pairing equation,
        // exercising the AccumulatorFailed path.
        let ctx = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");
        let setup = build_asset_generation_setup();
        let global = build_recursive_global(
            &setup,
            &ctx.certificate_verifying_key,
            &ctx.recursive_verifying_key,
        );
        // negate every fixed base: KZG opening check still passes, accumulator pairing breaks
        let wrong_fixed_bases = ctx
            .combined_fixed_bases
            .into_iter()
            .map(|(name, base)| (name, -base))
            .collect();
        let verifier_setup = IvcVerifierSetup::from_parts(
            ctx.verifier_params,
            ctx.recursive_verifying_key,
            wrong_fixed_bases,
        );

        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let err = proof
            .verify(&STEP_OUTPUT_MSG, &global, &verifier_setup)
            .expect_err("wrong fixed bases should cause the accumulator pairing check to fail");

        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::AccumulatorFailed),
            "wrong fixed bases must fail the accumulator check (not the KZG check), got: {err}"
        );
    }

    // The context guard is the first thing `IvcProver::prove` runs. It is tested directly here
    // rather than through `prove` so the test stays fast: reaching `prove` would require building
    // an `IvcSnarkProverSetup` (full keygen). With `genesis_bootstrap` now always supplied, a genesis
    // `rolling_state` is the only remaining invalid context; both-`Some`/both-`None` are
    // unrepresentable.
    #[test]
    fn ensure_advanceable_rolling_state_rejects_only_genesis_state() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::{
            proof_system::ivc_halo2_snark::rolling_state::IvcRollingState,
            signature_scheme::{BaseFieldElement, SchnorrSigningKey},
        };

        use super::ensure_advanceable_rolling_state;

        // A genesis signature is needed to build any rolling state; its value is irrelevant
        // because the guard only inspects the step counter.
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let genesis_signature = signing_key
            .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
            .expect("genesis signature should be produced");

        // `None` bootstraps from genesis internally: accepted.
        ensure_advanceable_rolling_state(None).expect("None must be accepted (genesis bootstrap)");

        // A genesis rolling state (`step_counter == 0`) must be rejected.
        let genesis_state = IvcRollingState::genesis(genesis_signature, &[]);
        assert!(genesis_state.is_genesis());
        let err = ensure_advanceable_rolling_state(Some(&genesis_state))
            .expect_err("genesis rolling state must be rejected");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::InvalidProvingContext),
            "genesis rolling state must fail with InvalidProvingContext, got: {err}"
        );

        // A non-genesis rolling state (a previous step's output) is accepted.
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let advanced_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );
        assert!(!advanced_state.is_genesis());
        ensure_advanceable_rolling_state(Some(&advanced_state))
            .expect("a non-genesis rolling state must be accepted");
    }

    mod slow {
        use std::sync::Arc;
        use std::time::Instant;

        use midnight_circuits::{
            hash::poseidon::PoseidonState, verifier::Accumulator, verifier::BlstrsEmulation,
        };
        use midnight_proofs::utils::SerdeFormat;
        use rand_core::OsRng;

        use crate::{
            AggregateVerificationKeyForSnark, MithrilMembershipDigest, Parameters, SnarkProof,
            circuits::{
                halo2::types::CircuitBase,
                halo2_ivc::{
                    io::Write as IvcWrite,
                    state::Global,
                    tests::common::{
                        asset_readers::{
                            RecursiveChainStateAsset,
                            load_embedded_first_certificate_in_epoch_asset,
                            load_embedded_following_certificate_in_epoch_asset,
                            load_embedded_next_epoch_step_output_asset,
                            load_embedded_recursive_chain_state_asset,
                            load_embedded_verification_context_asset,
                        },
                        generators::{
                            build_asset_generation_setup, build_genesis_protocol_message_preimage,
                            build_recursive_global,
                            setup::{AssetGenerationSetup, QUORUM_SIZE, SIGNER_COUNT, TOTAL_STAKE},
                        },
                    },
                    types::{IvcProofBytes, MessageHash, ProtocolMessagePreimage},
                },
            },
            proof_system::ivc_halo2_snark::{
                prover_setup::IvcSnarkProverSetup, rolling_state::IvcRollingState,
                verifier_setup::IvcVerifierSetup,
            },
            signature_scheme::BaseFieldElement,
        };

        use super::super::{IvcGenesisBootstrapInput, IvcProof, IvcProver};

        struct SlowTestContext {
            ivc_setup: Arc<IvcSnarkProverSetup>,
            global: Global,
            verifier_setup: IvcVerifierSetup,
            asset_setup: AssetGenerationSetup,
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

        fn wrap_avk(root: &[u8; 32]) -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
            let mut avk_bytes = [0u8; 40];
            avk_bytes[0..32].copy_from_slice(root);
            avk_bytes[32..40].copy_from_slice(&TOTAL_STAKE.to_be_bytes());
            AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_bytes)
                .expect("AVK should decode from bytes")
        }

        fn wrap_protocol_message_preimage(preimage: &[u8]) -> ProtocolMessagePreimage {
            use crate::circuits::halo2_ivc::PREIMAGE_SIZE;
            let preimage_array: [u8; PREIMAGE_SIZE] = preimage
                .try_into()
                .expect("preimage should be exactly PREIMAGE_SIZE bytes");
            ProtocolMessagePreimage::new(preimage_array)
        }

        fn genesis_bootstrap(asset_setup: &AssetGenerationSetup) -> IvcGenesisBootstrapInput {
            let genesis_preimage_bytes = build_genesis_protocol_message_preimage(asset_setup);
            IvcGenesisBootstrapInput {
                genesis_signature: asset_setup.genesis_signature,
                genesis_protocol_message_preimage: wrap_protocol_message_preimage(
                    &genesis_preimage_bytes,
                ),
            }
        }

        fn rolling_state_from_asset(asset: RecursiveChainStateAsset) -> IvcRollingState {
            IvcRollingState::new(
                asset.state,
                asset.ivc_proof,
                asset.accumulator,
                asset.genesis_signature,
            )
        }

        fn accumulator_bytes(accumulator: &Accumulator<BlstrsEmulation>) -> Vec<u8> {
            let mut bytes = Vec::new();
            accumulator
                .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
                .expect("accumulator serialization should succeed");
            bytes
        }

        fn run_bootstrap_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let first_step = load_embedded_first_certificate_in_epoch_asset()
                .expect("first-step certificate asset should load");
            let avk = wrap_avk(&first_step.aggregate_verification_key_merkle_root);
            let snark_proof = wrap_snark_proof(first_step.certificate_proof.clone().into_vec());
            let epoch1_preimage = wrap_protocol_message_preimage(&first_step.message_preimage);
            let bootstrap = genesis_bootstrap(&ctx.asset_setup);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };

            let (blake2b_proof, rolling) = prover
                .prove(
                    snark_proof,
                    first_step.message.as_ref(),
                    &avk,
                    &ctx.global,
                    &epoch1_preimage,
                    &bootstrap,
                    None,
                )
                .expect("bootstrap prove should succeed");

            let epoch1_rolling = rolling.expect("bootstrap must return a rolling state");

            assert_eq!(
                &blake2b_proof.state, &first_step.next_state,
                "bootstrap Blake2b proof state must match Epoch 1 expected state"
            );
            assert_eq!(
                epoch1_rolling.state(),
                &first_step.next_state,
                "bootstrap rolling state must match Epoch 1 expected state"
            );

            blake2b_proof
                .verify(
                    first_step.message.as_ref(),
                    &ctx.global,
                    &ctx.verifier_setup,
                )
                .expect("bootstrap Blake2b proof must verify");

            IvcProof::<PoseidonState<CircuitBase>>::new(
                epoch1_rolling.ivc_proof().clone(),
                epoch1_rolling.state().clone(),
                epoch1_rolling.accumulator().clone(),
            )
            .verify(
                first_step.message.as_ref(),
                &ctx.global,
                &ctx.verifier_setup,
            )
            .expect("bootstrap Poseidon proof must verify");

            println!("[bootstrap] {:.1}s", t.elapsed().as_secs_f64());
        }

        fn run_next_epoch_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_next_epoch_step_output_asset()
                .expect("next-epoch step output asset should load");

            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let (blake2b_proof, rolling) = prover
                .prove(
                    snark_proof,
                    step.message.as_ref(),
                    &avk,
                    &ctx.global,
                    &preimage,
                    &genesis_bootstrap(&ctx.asset_setup),
                    Some(&rolling_state),
                )
                .expect("next-epoch prove should succeed");

            let next_rolling = rolling.expect("next-epoch must return a rolling state");

            assert_eq!(
                &blake2b_proof.state, &step.next_state,
                "next-epoch Blake2b proof state must match embedded asset output"
            );
            assert_eq!(
                next_rolling.state(),
                &step.next_state,
                "next-epoch rolling state must match embedded asset output"
            );
            assert_eq!(
                accumulator_bytes(next_rolling.accumulator()),
                accumulator_bytes(&step.next_accumulator),
                "next-epoch rolling accumulator must match embedded asset output"
            );

            blake2b_proof
                .verify(step.message.as_ref(), &ctx.global, &ctx.verifier_setup)
                .expect("next-epoch Blake2b proof must verify");

            IvcProof::<PoseidonState<CircuitBase>>::new(
                next_rolling.ivc_proof().clone(),
                next_rolling.state().clone(),
                next_rolling.accumulator().clone(),
            )
            .verify(step.message.as_ref(), &ctx.global, &ctx.verifier_setup)
            .expect("next-epoch Poseidon proof must verify");

            println!("[next-epoch] {:.1}s", t.elapsed().as_secs_f64());
        }

        fn run_same_epoch_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let (blake2b_proof, rolling) = prover
                .prove(
                    snark_proof,
                    step.message.as_ref(),
                    &avk,
                    &ctx.global,
                    &preimage,
                    &genesis_bootstrap(&ctx.asset_setup),
                    Some(&rolling_state),
                )
                .expect("same-epoch prove should succeed");

            assert!(
                rolling.is_none(),
                "same-epoch must not return a rolling state"
            );

            assert_eq!(
                &blake2b_proof.state, &step.next_state,
                "same-epoch Blake2b proof state must match embedded asset output"
            );

            blake2b_proof
                .verify(step.message.as_ref(), &ctx.global, &ctx.verifier_setup)
                .expect("same-epoch Blake2b proof must verify");

            println!("[same-epoch] {:.1}s", t.elapsed().as_secs_f64());
        }

        fn run_rejects_corrupted_cert_proof_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let mut corrupted = step.certificate_proof.clone().into_vec();
            corrupted[0] ^= 0xFF;
            let snark_proof = wrap_snark_proof(corrupted);
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let result = prover.prove(
                snark_proof,
                step.message.as_ref(),
                &avk,
                &ctx.global,
                &preimage,
                &genesis_bootstrap(&ctx.asset_setup),
                Some(&rolling_state),
            );
            assert!(
                result.is_err(),
                "prove should reject a corrupted certificate proof"
            );

            println!(
                "[rejects-corrupted-cert-proof] {:.1}s",
                t.elapsed().as_secs_f64()
            );
        }

        fn run_rejects_mismatched_cert_message_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut tampered_message = step.message;
            tampered_message[0] ^= 0xFF;

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let result = prover.prove(
                snark_proof,
                tampered_message.as_ref(),
                &avk,
                &ctx.global,
                &preimage,
                &genesis_bootstrap(&ctx.asset_setup),
                Some(&rolling_state),
            );
            assert!(
                result.is_err(),
                "prove should reject a tampered certificate message"
            );

            println!(
                "[rejects-mismatched-cert-message] {:.1}s",
                t.elapsed().as_secs_f64()
            );
        }

        fn run_rejects_mismatched_avk_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let mut tampered_root = step.aggregate_verification_key_merkle_root;
            tampered_root[0] ^= 0xFF;
            let wrong_avk = wrap_avk(&tampered_root);
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let result = prover.prove(
                snark_proof,
                step.message.as_ref(),
                &wrong_avk,
                &ctx.global,
                &preimage,
                &genesis_bootstrap(&ctx.asset_setup),
                Some(&rolling_state),
            );
            assert!(
                result.is_err(),
                "prove should reject an AVK that does not match the one the proof committed to"
            );

            println!("[rejects-mismatched-avk] {:.1}s", t.elapsed().as_secs_f64());
        }

        fn run_rejects_corrupted_previous_ivc_proof_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let chain_state = load_embedded_recursive_chain_state_asset()
                .expect("recursive chain state asset should load");
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let mut corrupted = chain_state.ivc_proof.into_vec();
            corrupted[0] ^= 0xFF;
            let rolling_state = IvcRollingState::new(
                chain_state.state,
                IvcProofBytes::new(corrupted),
                chain_state.accumulator,
                chain_state.genesis_signature,
            );

            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let result = prover.prove(
                snark_proof,
                step.message.as_ref(),
                &avk,
                &ctx.global,
                &preimage,
                &genesis_bootstrap(&ctx.asset_setup),
                Some(&rolling_state),
            );
            assert!(
                result.is_err(),
                "prove should reject a corrupted previous IVC proof"
            );

            println!(
                "[rejects-corrupted-prev-ivc-proof] {:.1}s",
                t.elapsed().as_secs_f64()
            );
        }

        fn run_rejects_mismatched_global_path(ctx: &SlowTestContext) {
            let t = Instant::now();
            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let preimage = wrap_protocol_message_preimage(&step.message_preimage);

            let mut wrong_global = ctx.global.clone();
            wrong_global.genesis_message =
                MessageHash::from_field(BaseFieldElement::from(0xDEAD_BEEFu64).0);

            let mut prover = IvcProver {
                ivc_setup: Arc::clone(&ctx.ivc_setup),
                rng: OsRng,
            };
            let result = prover.prove(
                snark_proof,
                step.message.as_ref(),
                &avk,
                &wrong_global,
                &preimage,
                &genesis_bootstrap(&ctx.asset_setup),
                Some(&rolling_state),
            );
            assert!(
                result.is_err(),
                "prove should reject a global whose public inputs do not match the previous IVC proof"
            );

            println!(
                "[rejects-mismatched-global] {:.1}s",
                t.elapsed().as_secs_f64()
            );
        }

        #[test]
        fn prove_all_scenarios() {
            let t_setup = Instant::now();
            let parameters = Parameters {
                k: QUORUM_SIZE as u64,
                m: (QUORUM_SIZE * 10) as u64,
                phi_f: 0.2,
            };
            let merkle_tree_depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
            let ivc_setup = Arc::new(
                IvcSnarkProverSetup::build_for_test(&parameters, merkle_tree_depth)
                    .expect("IvcSnarkProverSetup::load should succeed"),
            );

            let verification_context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");
            let asset_setup = build_asset_generation_setup();

            assert_eq!(
                verification_context
                    .certificate_verifying_key
                    .midnight_vk()
                    .vk()
                    .transcript_repr(),
                ivc_setup
                    .certificate_verifying_key
                    .midnight_vk()
                    .vk()
                    .transcript_repr(),
                "stored verification context cert VK must match freshly generated cert VK"
            );
            assert_eq!(
                verification_context
                    .recursive_verifying_key
                    .verifying_key()
                    .transcript_repr(),
                ivc_setup.ivc_verifying_key.verifying_key().transcript_repr(),
                "stored verification context IVC VK must match freshly generated IVC VK"
            );

            let global = build_recursive_global(
                &asset_setup,
                &verification_context.certificate_verifying_key,
                &verification_context.recursive_verifying_key,
            );
            let verifier_setup = IvcVerifierSetup::from_ivc_setup_with_srs(&ivc_setup);
            println!("[setup] {:.1}s", t_setup.elapsed().as_secs_f64());

            let ctx = SlowTestContext {
                ivc_setup,
                global,
                verifier_setup,
                asset_setup,
            };

            run_bootstrap_path(&ctx);
            run_next_epoch_path(&ctx);
            run_same_epoch_path(&ctx);
            run_rejects_corrupted_cert_proof_path(&ctx);
            run_rejects_mismatched_cert_message_path(&ctx);
            run_rejects_mismatched_avk_path(&ctx);
            run_rejects_corrupted_previous_ivc_proof_path(&ctx);
            run_rejects_mismatched_global_path(&ctx);
        }
    }
}
