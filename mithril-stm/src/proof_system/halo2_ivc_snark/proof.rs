//! `IvcProver` and `IvcProof`: the proving-session handle and its emitted IVC proof.

use std::{marker::PhantomData, sync::Arc, time::Instant};

use anyhow::{Context, anyhow};
use ff::FromUniformBytes;
use group::Group;
use midnight_circuits::{
    hash::poseidon::PoseidonState,
    types::Instantiable,
    verifier::{Accumulator, AssignedAccumulator, BlstrsEmulation},
};
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::circuit::Value;
use midnight_proofs::{
    plonk::{create_proof, prepare},
    poly::{
        commitment::PolynomialCommitmentScheme,
        kzg::{
            KZGCommitmentScheme,
            msm::{DualMSM, MSMKZG},
            params::ParamsKZG,
        },
    },
    transcript::{Blake2b256, CircuitTranscript, Hashable, Sampleable, Transcript, TranscriptHash},
};
use midnight_zk_stdlib::MidnightCircuit;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use slog::{Discard, Logger, info, o};

use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_DEGREE;
use crate::{
    AggregateVerificationKeyForSnark, AggregationError, AncillaryGenesisData, AncillaryProofInput,
    BaseFieldElement, MembershipDigest, SnarkProof, StmResult,
    circuits::{
        halo2::{keys::NonRecursiveCircuitVerifyingKey, types::CircuitBase},
        halo2_ivc::{
            PREIMAGE_SIZE,
            accumulator::check_accumulator_fixed_bases_present,
            circuit::{IvcCircuit, IvcCircuitData},
            keys::{RecursiveCircuitProvingKey, RecursiveCircuitVerifyingKey},
            state::{Global, State},
            types::{CertificateProofBytes, IvcProofBytes, MessageHash, ProtocolMessagePreimage},
        },
    },
    codec,
    proof_system::halo2_ivc_snark::{
        errors::IvcProofError,
        interface::IvcChainProver,
        prover_input::IvcProverInput,
        prover_setup::IvcProverSetup,
        rolling_state::{IvcRollingState, IvcTransitionType, midnight_accumulator_serde},
        verifier_setup::IvcVerifierSetup,
    },
    signature_scheme::StandardSchnorrSignature,
};

/// Per-session IVC prover handle.
pub(crate) struct IvcProver<R: RngCore + CryptoRng> {
    /// Shared, cached setup (SRS, verifying keys, proving key, fixed-base maps).
    pub(crate) ivc_setup: Arc<IvcProverSetup>,
    /// Randomness source used during proof generation.
    pub(crate) rng: R,
    /// Logger of the proving step durations.
    pub(crate) logger: Logger,
}

/// Bootstrap input for the first [`IvcProver::prove`] call in an IVC chain.
///
/// Always supplied to [`IvcProver::prove`] by reference; used only when `rolling_state = None`
/// (the first certificate) to run the internal genesis IVC step before processing it.
#[derive(Debug)]
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
            .as_bytes()
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
    /// Prepares the KZG opening MSM and derives the Fiat-Shamir combiner `r` used to fold the
    /// accumulator's pairing check into it.
    pub(crate) fn prepare_combined_check(
        &self,
        global: &Global,
        verifier_setup: &IvcVerifierSetup,
    ) -> StmResult<(DualMSM<Bls12>, G1Projective, G1Projective, CircuitBase)> {
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

        check_accumulator_fixed_bases_present(
            &self.accumulator,
            verifier_setup.combined_fixed_bases(),
        )?;
        let accumulator_lhs = self.accumulator.lhs().eval(verifier_setup.combined_fixed_bases());
        let accumulator_rhs = self.accumulator.rhs().eval(verifier_setup.combined_fixed_bases());

        // `r` must depend on both `dual_msm` and `self.accumulator` to make sure the combination can't be manipulated.
        // The transcript should already absorb the dual_msm and accumulator but we make it explicit here
        // in case the midnight library changes this in the future.
        let (dual_msm_left_terms, dual_msm_right_terms) = dual_msm.split();
        for (_, scalar, base) in dual_msm_left_terms.into_iter().chain(dual_msm_right_terms) {
            transcript.common(scalar)?;
            transcript.common(base)?;
        }
        transcript.common(&accumulator_lhs)?;
        transcript.common(&accumulator_rhs)?;
        let r: CircuitBase = transcript.squeeze_challenge();

        Ok((dual_msm, accumulator_lhs, accumulator_rhs, r))
    }

    /// Verifies the IVC proof and its folded accumulator using transcript hash `H` by
    /// combining both value as MSMs using a random scalar `r` and performing one
    /// pairing check.
    ///
    /// # Invariant
    ///
    /// `global` and `verifier_setup` must be built from the same certificate and IVC verifying
    /// keys used to produce this proof. If they differ, the combined pairing check will fail and
    /// verification will return [`IvcProofError::MsmPairingCheckFailed`].
    pub(crate) fn verify(
        &self,
        msg: &[u8],
        global: &Global,
        verifier_setup: &IvcVerifierSetup,
    ) -> StmResult<()> {
        self.check_input_message_matches_state_message(msg)?;

        let (dual_msm, accumulator_lhs, accumulator_rhs, r) =
            self.prepare_combined_check(global, verifier_setup)?;

        let mut accumulator_dual_msm = DualMSM::new(
            MSMKZG::from_base(&accumulator_lhs),
            MSMKZG::from_base(&accumulator_rhs),
        );
        accumulator_dual_msm.scale(r);

        let mut combined = dual_msm;
        combined.add_msm(accumulator_dual_msm);

        if !combined.check(verifier_setup.verifier_params()) {
            return Err(IvcProofError::MsmPairingCheckFailed.into());
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
        ivc_circuit: &IvcCircuit,
        circuit_data: &IvcCircuitData,
        public_inputs: &[CircuitBase],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StmResult<Vec<u8>> {
        let circuit = MidnightCircuit::new(
            ivc_circuit,
            Value::known(public_inputs.to_vec()),
            Value::known(circuit_data.clone()),
            Some(RECURSIVE_CIRCUIT_DEGREE),
        );
        let mut transcript = CircuitTranscript::<H>::init();
        create_proof::<
            CircuitBase,
            KZGCommitmentScheme<Bls12>,
            CircuitTranscript<H>,
            MidnightCircuit<IvcCircuit>,
        >(
            srs,
            proving_key.midnight_pk().pk(),
            std::slice::from_ref(&circuit),
            1,
            &[&[&[], public_inputs]],
            &mut transcript,
            rng,
        )
        .map_err(|e| IvcProofError::ProofGenerationFailed(e.to_string()))?;
        Ok(transcript.finalize())
    }
}

/// Everything the IVC prover needs to add one certificate to the chain, assembled by the clerk.
/// The bootstrap path runs an internal genesis step before that certificate's own step.
#[derive(Debug)]
pub(crate) struct IvcChainStepBundle<D: MembershipDigest> {
    /// The current certificate proof that will be verified by the next step
    pub(crate) certificate_proof: SnarkProof<D>,
    /// The message certified in the certificate proof
    pub(crate) message: Vec<u8>,
    /// The aggregate verification key used to create the certificate proof
    pub(crate) aggregate_verification_key: AggregateVerificationKeyForSnark<D>,
    /// A structure that stores genesis information and both circuit verification keys
    pub(crate) global: Global,
    /// The protocol message preimage of the next step
    pub(crate) protocol_message_preimage: ProtocolMessagePreimage,
    /// Genesis signature information
    pub(crate) genesis_bootstrap: IvcGenesisBootstrapInput,
    /// Current rolling state
    pub(crate) rolling_state: Option<IvcRollingState>,
}

impl<D: MembershipDigest> IvcChainStepBundle<D> {
    /// Factory of IvcChainStepBundle
    ///
    /// Fails on a missing genesis verifying key, a prover data without IVC rolling state,
    /// a missing genesis Schnorr signature or a preimage that is not PREIMAGE_SIZE bytes.
    pub(crate) fn try_new(
        certificate_proof: SnarkProof<D>,
        message: &[u8],
        aggregate_verification_key: AggregateVerificationKeyForSnark<D>,
        ancillary_input: AncillaryProofInput,
        certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
        ivc_verifying_key: &RecursiveCircuitVerifyingKey,
    ) -> StmResult<Self> {
        let protocol_message_preimage_bytes: [u8; PREIMAGE_SIZE] =
            ancillary_input.message_preimage().try_into()?;

        let genesis_data = ancillary_input.genesis_data();

        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;

        let genesis_protocol_message_hash = genesis_data.genesis_message_preimage().try_into()?;

        let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;

        let current_rolling_state = ancillary_input
            .into_prover_data()
            .map(|prover_data| {
                prover_data.into_ivc_rolling_state().ok_or(anyhow!(
                    AggregationError::MissingIvcRollingStateInAncillaryProverData
                ))
            })
            .transpose()?;

        let global = Global::new(
            genesis_protocol_message_hash,
            genesis_verifying_key,
            certificate_verifying_key,
            ivc_verifying_key,
        );

        Ok(Self {
            certificate_proof,
            message: message.to_vec(),
            aggregate_verification_key,
            global,
            protocol_message_preimage: ProtocolMessagePreimage(protocol_message_preimage_bytes),
            genesis_bootstrap,
            rolling_state: current_rolling_state,
        })
    }
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
        rolling_state.map(IvcRollingState::ensure_advanceable).transpose()?;
        // `rolling_state = None` is the first certificate: bootstrap from genesis internally,
        // then continue with the seeded state. Otherwise advance from the supplied state.
        let effective_rolling_state: &IvcRollingState = match rolling_state {
            None => &self.run_genesis_step(global, genesis_bootstrap)?,
            Some(rolling_state) => rolling_state,
        };

        // Prepare the witness, next state, and folded next accumulator.
        // prepare() borrows snark_proof; snark_proof is still owned afterward.
        let start = Instant::now();
        let prover_input = IvcProverInput::prepare(
            &snark_proof,
            message,
            aggregate_verification_key,
            global,
            protocol_message_preimage,
            effective_rolling_state,
            &self.ivc_setup.prover_input_verification_context(),
        )?;
        info!(self.logger, "IVC prover input prepared"; "duration_ms" => start.elapsed().as_millis());

        let certificate_proof_bytes = snark_proof.into_circuit_proof_bytes();

        let ivc_circuit = IvcCircuit::try_new(
            &self.ivc_setup.certificate_verifying_key,
            &self.ivc_setup.ivc_verifying_key,
        )?;
        let circuit_data = IvcCircuitData::new(
            global.clone(),
            effective_rolling_state.state().clone(),
            prover_input.witness,
            certificate_proof_bytes,
            effective_rolling_state.ivc_proof().clone(),
            effective_rolling_state.accumulator().clone(),
        );

        // Public inputs for the new step: [global | next_state | next_accumulator].
        let public_inputs: Vec<CircuitBase> = [
            global.as_public_input(),
            prover_input.next_state.as_public_input(),
            AssignedAccumulator::as_public_input(&prover_input.next_accumulator),
        ]
        .concat();

        // Next-epoch steps update the rolling state with a fresh Poseidon proof.
        // Same-epoch steps leave the rolling state unchanged (return None).
        let next_rolling_state = if matches!(
            prover_input.transition_type,
            Some(IvcTransitionType::NextEpoch)
        ) {
            let start = Instant::now();
            let poseidon_bytes = IvcProof::<PoseidonState<CircuitBase>>::prove_with_transcript(
                &self.ivc_setup.srs,
                &self.ivc_setup.ivc_proving_key,
                &ivc_circuit,
                &circuit_data,
                &public_inputs,
                &mut self.rng,
            )?;
            info!(self.logger, "IVC Poseidon proof generated"; "duration_ms" => start.elapsed().as_millis());
            Some(IvcRollingState::new(
                prover_input.next_state.clone(),
                IvcProofBytes::new(poseidon_bytes),
                prover_input.next_accumulator.clone(),
                effective_rolling_state.genesis_signature(),
            ))
        } else {
            None
        };

        let start = Instant::now();
        let blake2b_bytes = IvcProof::<Blake2b256>::prove_with_transcript(
            &self.ivc_setup.srs,
            &self.ivc_setup.ivc_proving_key,
            &ivc_circuit,
            &circuit_data,
            &public_inputs,
            &mut self.rng,
        )?;
        info!(self.logger, "IVC Blake2b proof generated"; "duration_ms" => start.elapsed().as_millis());
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
        let start = Instant::now();
        let combined_fixed_base_names: Vec<String> =
            self.ivc_setup.combined_fixed_bases.keys().cloned().collect();
        let genesis_rolling_state =
            IvcRollingState::genesis(bootstrap.genesis_signature, &combined_fixed_base_names);

        let genesis_prover_input = IvcProverInput::prepare_genesis(
            &genesis_rolling_state,
            &bootstrap.genesis_protocol_message_preimage,
            global,
        )?;

        let genesis_ivc_circuit = IvcCircuit::try_new(
            &self.ivc_setup.certificate_verifying_key,
            &self.ivc_setup.ivc_verifying_key,
        )?;
        let genesis_circuit_data = IvcCircuitData::new(
            global.clone(),
            genesis_rolling_state.state().clone(),
            genesis_prover_input.witness,
            CertificateProofBytes::empty(),
            genesis_rolling_state.ivc_proof().clone(),
            genesis_rolling_state.accumulator().clone(),
        );

        let genesis_public_inputs: Vec<CircuitBase> = [
            global.as_public_input(),
            genesis_prover_input.next_state.as_public_input(),
            AssignedAccumulator::as_public_input(&genesis_prover_input.next_accumulator),
        ]
        .concat();

        let poseidon_bytes = IvcProof::<PoseidonState<CircuitBase>>::prove_with_transcript(
            &self.ivc_setup.srs,
            &self.ivc_setup.ivc_proving_key,
            &genesis_ivc_circuit,
            &genesis_circuit_data,
            &genesis_public_inputs,
            &mut self.rng,
        )?;
        info!(self.logger, "IVC genesis step computed"; "duration_ms" => start.elapsed().as_millis());

        Ok(IvcRollingState::new(
            genesis_prover_input.next_state,
            IvcProofBytes::new(poseidon_bytes),
            genesis_prover_input.next_accumulator,
            bootstrap.genesis_signature,
        ))
    }
}

impl IvcProver<OsRng> {
    /// Creates a prover over `ivc_setup`, which the factory owns the reuse of.
    pub(crate) fn new_non_deterministic(ivc_setup: Arc<IvcProverSetup>) -> Self {
        Self {
            ivc_setup,
            rng: OsRng,
            logger: Logger::root(Discard, o!()),
        }
    }
}

impl<R: RngCore + CryptoRng> IvcProver<R> {
    /// Logs the duration of the proving steps with `logger`, which discards them by default.
    pub(crate) fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = logger.new(o!("src" => "IvcProver"));
        self
    }
}

impl<D: MembershipDigest, R: RngCore + CryptoRng> IvcChainProver<D> for IvcProver<R> {
    fn verifying_key(&self) -> &RecursiveCircuitVerifyingKey {
        &self.ivc_setup.ivc_verifying_key
    }

    fn advance_chain(
        &mut self,
        step_bundle: IvcChainStepBundle<D>,
    ) -> StmResult<(IvcProof<Blake2b256>, Option<IvcRollingState>)> {
        let IvcChainStepBundle {
            certificate_proof,
            message,
            aggregate_verification_key,
            global,
            protocol_message_preimage,
            genesis_bootstrap,
            rolling_state,
        } = step_bundle;
        self.prove(
            certificate_proof,
            message.as_slice(),
            &aggregate_verification_key,
            &global,
            &protocol_message_preimage,
            &genesis_bootstrap,
            rolling_state.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {

    use ff::Field;
    use midnight_proofs::{
        poly::kzg::msm::{DualMSM, MSMKZG},
        transcript::Blake2b256,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        AggregationError, AncillaryGenesisData, AncillaryProofInput, AncillaryProverData,
        MithrilMembershipDigest, Parameters, SnarkProof,
        circuits::{
            halo2::{
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                keys::NonRecursiveCircuitVerifyingKey, types::CircuitBase,
            },
            halo2_ivc::{
                PREIMAGE_SIZE, RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                keys::RecursiveCircuitVerifyingKey,
                state::Global,
                tests::common::{
                    asset_readers::{
                        load_embedded_following_certificate_in_epoch_asset,
                        load_embedded_next_epoch_step_output_asset,
                        load_embedded_recursive_chain_state_asset,
                        load_embedded_verification_context_asset,
                    },
                    generators::{build_asset_generation_setup_from_cache, build_recursive_global},
                },
                types::{EpochNumber, IvcProofBytes, MessageHash, StepCounter},
            },
        },
        codec::TryFromBytes,
        proof_system::{
            AggregateVerificationKeyForSnark, MERKLE_TREE_DEPTH_FOR_SNARK,
            halo2_ivc_snark::{
                build_standard_rolling_state, errors::IvcProofError,
                verifier_setup::IvcVerifierSetup,
            },
        },
        signature_scheme::{BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey},
    };

    use super::{IvcChainStepBundle, IvcProof};

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

    const PROTOCOL_MESSAGE_PREIMAGE: [u8; PREIMAGE_SIZE] = [0u8; PREIMAGE_SIZE];

    fn build_proof_verifier_context() -> (Global, IvcVerifierSetup) {
        let ctx = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let setup = build_asset_generation_setup_from_cache();
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
        // stored next-epoch Blake2b proof, confirming that the combined pairing check
        // accepts a known-good proof.
        let verification_context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");

        let setup = build_asset_generation_setup_from_cache();
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

    // Exactly 32 bytes are the raw message and take precedence; any other width is decoded as hex.
    // Both are then compared as field values, so equality is modulo the field order rather than
    // over bytes.
    mod input_message {
        use proptest::prelude::*;

        use crate::{
            BaseFieldElement,
            circuits::halo2_ivc::{
                accumulator::trivial_accumulator,
                state::State,
                types::{MerkleTreeCommitment, ProtocolParametersHash},
            },
        };

        use super::*;

        fn message_hash(bytes: &[u8; 32]) -> MessageHash {
            MessageHash::from_field(
                BaseFieldElement::from_raw(bytes)
                    .expect("from_raw applies modulus reduction and cannot fail")
                    .0,
            )
        }

        /// The helper reads only the stored message, so the proof around it can be empty.
        fn proof_committing_to(message: &[u8; 32]) -> IvcProof<Blake2b256> {
            let state = State::new(
                StepCounter::new(5),
                message_hash(message),
                MerkleTreeCommitment::ZERO,
                MerkleTreeCommitment::ZERO,
                ProtocolParametersHash::ZERO,
                ProtocolParametersHash::ZERO,
                EpochNumber::new(3),
            );
            IvcProof::<Blake2b256>::new(IvcProofBytes::empty(), state, trivial_accumulator(&[]))
        }

        fn mixed_case_hex(message: &[u8; 32], uppercase_at: &[bool; 64]) -> String {
            hex::encode(message)
                .chars()
                .zip(uppercase_at)
                .map(|(character, upper)| {
                    if *upper {
                        character.to_ascii_uppercase()
                    } else {
                        character
                    }
                })
                .collect()
        }

        /// Every encoding the helper is meant to accept for one message, each named so a failure
        /// says which representation was at fault.
        fn encodings_of(
            message: &[u8; 32],
            uppercase_at: &[bool; 64],
        ) -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("raw", message.to_vec()),
                ("lowercase hex", hex::encode(message).into_bytes()),
                ("uppercase hex", hex::encode_upper(message).into_bytes()),
                (
                    "mixed-case hex",
                    mixed_case_hex(message, uppercase_at).into_bytes(),
                ),
            ]
        }

        proptest! {
            #[test]
            fn a_message_is_accepted_in_every_encoding_of_itself(
                message in any::<[u8; 32]>(),
                uppercase_at in any::<[bool; 64]>(),
            ) {
                let proof = proof_committing_to(&message);

                for (representation, encoding) in encodings_of(&message, &uppercase_at) {
                    prop_assert!(
                        proof.check_input_message_matches_state_message(&encoding).is_ok(),
                        "{representation} of {} should have been accepted",
                        hex::encode(message)
                    );
                }
            }

            #[test]
            fn a_message_with_a_different_field_value_is_rejected_in_every_encoding(
                message in any::<[u8; 32]>(),
                other in any::<[u8; 32]>(),
                uppercase_at in any::<[bool; 64]>(),
            ) {
                // Distinct bytes can reduce to the same element, and those are accepted by design.
                prop_assume!(message_hash(&message) != message_hash(&other));
                let proof = proof_committing_to(&message);

                for (representation, encoding) in encodings_of(&other, &uppercase_at) {
                    match proof.check_input_message_matches_state_message(&encoding) {
                        Ok(()) => {
                            return Err(TestCaseError::fail(format!(
                                "{representation} of {} should have been rejected against {}",
                                hex::encode(other),
                                hex::encode(message)
                            )));
                        }
                        Err(error) => prop_assert_eq!(
                            error.downcast_ref::<IvcProofError>(),
                            Some(&IvcProofError::InvalidMessage)
                        ),
                    }
                }
            }
        }

        /// Two hex shapes a generated message reaches only by chance: an encoding of nothing but
        /// digits, and a letter-rich one whose mixed-case form genuinely differs from both pure
        /// cases. A decoder refusing valid hex unless it contains a letter would pass the
        /// properties and fail here.
        #[test]
        fn the_digit_only_and_letter_rich_encodings_are_accepted() {
            let mut alternating = [false; 64];
            for (index, upper) in alternating.iter_mut().enumerate() {
                *upper = index % 2 == 0;
            }

            for message in [[0u8; 32], [0xabu8; 32]] {
                let proof = proof_committing_to(&message);
                for (representation, encoding) in encodings_of(&message, &alternating) {
                    proof
                        .check_input_message_matches_state_message(&encoding)
                        .unwrap_or_else(|error| {
                            panic!(
                                "{representation} of {} should have been accepted: {error}",
                                hex::encode(message)
                            )
                        });
                }
            }
        }

        /// Lengths that are neither the raw width nor a hex encoding of it, and a hex-length input
        /// carrying a character that is not a hex digit.
        #[test]
        fn a_malformed_encoding_is_rejected() {
            let message = [0xabu8; 32];
            let proof = proof_committing_to(&message);
            let hex_encoding = hex::encode(message);

            let mut not_hex = hex_encoding.clone().into_bytes();
            not_hex[7] = b'z';

            for encoding in [
                message[..31].to_vec(),
                [message.as_slice(), &[0u8]].concat(),
                hex_encoding.as_bytes()[..63].to_vec(),
                [hex_encoding.as_bytes(), b"0"].concat(),
                not_hex,
                // What a 32-byte input would decode to if it were treated as hex.
                vec![0u8; 16],
            ] {
                assert!(
                    proof.check_input_message_matches_state_message(&encoding).is_err(),
                    "malformed encoding of {} bytes should have been rejected",
                    encoding.len()
                );
            }
        }

        /// A 32-byte input is the raw message even when every character is a hex digit — a whole
        /// class of inputs a hex-first implementation would decode to the wrong width and reject.
        #[test]
        fn a_thirty_two_byte_input_of_hex_digits_is_read_as_raw_bytes() {
            let raw: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
            let proof = proof_committing_to(&raw);

            proof
                .check_input_message_matches_state_message(&raw)
                .expect("a 32-byte input is the message itself, not its hex encoding");

            // Had the input been decoded as hex it would be 16 bytes, which is neither width the
            // helper accepts — so that reading is rejected outright rather than silently allowed.
            let decoded = hex::decode(raw).expect("the fixture is valid hex");
            assert!(
                proof.check_input_message_matches_state_message(&decoded).is_err(),
                "the 16-byte hex decoding is not a width the helper accepts"
            );
        }

        /// `from_raw` reduces modulo the field order, so a value and that value plus the modulus
        /// are the same message. Recorded as behaviour: a successful check means the bytes name
        /// the committed field element, not that they are the only bytes that do.
        #[test]
        fn a_message_offset_by_the_field_modulus_is_accepted() {
            let message = [0u8; 32];
            let proof = proof_committing_to(&message);

            // p, little-endian.
            let modulus: [u8; 32] = [
                0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
                0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
                0x53, 0xa7, 0xed, 0x73,
            ];

            proof
                .check_input_message_matches_state_message(&modulus)
                .expect("a representative of the same field element is accepted");
        }
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

        let setup = build_asset_generation_setup_from_cache();
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
            "tampered message must fail message verification in IvcProof::verify, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_tampered_proof_bytes() {
        // A single flipped byte anywhere in the proof transcript corrupts the raw bytes
        // `dual_msm` is built from, so its side of the combined pairing equation no longer
        // holds and `verify` returns `Err`.
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
            Some(&IvcProofError::MsmPairingCheckFailed),
            "tampered bytes must fail the combined pairing check, got: {err}"
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
            "different protocol message must fail message verification in IvcProof::verify, got: {err}"
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
            Some(&IvcProofError::MsmPairingCheckFailed),
            "different protocol message must fail the combined pairing check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_mismatched_state() {
        // Substituting the state from a different proof step changes the public inputs
        // fed to `prepare`, so `dual_msm`'s side of the combined equation no longer matches
        // the unmodified proof bytes.
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
            Some(&IvcProofError::MsmPairingCheckFailed),
            "mismatched state corrupts public inputs and must fail the combined pairing check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_mismatched_accumulator() {
        // Substituting the accumulator from a different proof step corrupts the public
        // inputs fed to `prepare` (the accumulator is serialised into them), so
        // `dual_msm`'s side of the combined equation no longer matches.
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
            Some(&IvcProofError::MsmPairingCheckFailed),
            "mismatched accumulator corrupts public inputs and must fail the combined pairing check, got: {err}"
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
            Some(&IvcProofError::MsmPairingCheckFailed),
            "Poseidon bytes via Blake2b path must fail the combined pairing check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_rejects_wrong_fixed_bases() {
        // A verifier setup with wrong fixed bases but otherwise correct parameters leaves
        // `dual_msm`'s side of the combined equation valid but corrupts the accumulator's
        // side, so `combined.check` still fails.
        let ctx = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");
        let setup = build_asset_generation_setup_from_cache();
        let global = build_recursive_global(
            &setup,
            &ctx.certificate_verifying_key,
            &ctx.recursive_verifying_key,
        );
        // negate every fixed base: dual_msm's side of the equation still holds, only the
        // accumulator's doesn't
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
            .expect_err("wrong fixed bases should cause the combined pairing check to fail");

        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::MsmPairingCheckFailed),
            "wrong fixed bases must fail the combined pairing check, got: {err}"
        );
    }

    #[test]
    fn ivc_proof_verify_combined_check_holds_for_any_scalar_r() {
        let (global, verifier_setup) = build_proof_verifier_context();
        let step_output = load_embedded_next_epoch_step_output_asset()
            .expect("recursive step output asset should load");
        let proof = IvcProof::<Blake2b256>::new(
            step_output.ivc_proof,
            step_output.next_state,
            step_output.next_accumulator,
        );

        let (dual_msm, accumulator_lhs, accumulator_rhs, _) = proof
            .prepare_combined_check(&global, &verifier_setup)
            .expect("prepare_combined_check should succeed for a valid proof");

        let candidate_rs = [
            CircuitBase::ONE,
            CircuitBase::from(2u64),
            CircuitBase::from(123_456_789u64),
            -CircuitBase::ONE,
        ];

        for r in candidate_rs {
            let mut accumulator_dual_msm = DualMSM::new(
                MSMKZG::from_base(&accumulator_lhs),
                MSMKZG::from_base(&accumulator_rhs),
            );
            accumulator_dual_msm.scale(r);

            let mut combined = dual_msm.clone();
            combined.add_msm(accumulator_dual_msm);

            assert!(
                combined.check(verifier_setup.verifier_params()),
                "combined check must hold for a valid proof regardless of the combiner r={r:?}"
            );
        }
    }

    /// Cheapest possible valid inputs for `IvcChainStepBundle::try_new`: a proof/AVK that never get
    /// meaningfully used (only their type matters, not their content), plus the real production
    /// circuit verifying keys (needed unconditionally as arguments, even on failure paths that
    /// never reach the code using them).
    fn ivc_chain_step_bundle_try_new_fixture() -> (
        SnarkProof<MithrilMembershipDigest>,
        AggregateVerificationKeyForSnark<MithrilMembershipDigest>,
        NonRecursiveCircuitVerifyingKey,
        RecursiveCircuitVerifyingKey,
    ) {
        let params = Parameters {
            k: 1,
            m: 10,
            phi_f: 0.9,
        };
        let certificate_proof =
            SnarkProof::<MithrilMembershipDigest>::new(vec![], params, MERKLE_TREE_DEPTH_FOR_SNARK);
        let avk =
            AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&[0u8; 40])
                .expect("all-zero AVK bytes should decode");
        let certificate_verifying_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize");
        let ivc_verifying_key = RecursiveCircuitVerifyingKey::try_from_bytes(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize");
        (
            certificate_proof,
            avk,
            certificate_verifying_key,
            ivc_verifying_key,
        )
    }

    #[test]
    fn ivc_chain_step_bundle_fails_when_prover_data_carries_no_ivc_rolling_state() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::Future),
            AncillaryGenesisData::dummy(),
            PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        );

        let err = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect_err("prover data without an IVC rolling state must be rejected");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingIvcRollingStateInAncillaryProverData),
            "missing IVC rolling state must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_chain_step_bundle_fails_when_genesis_verification_key_is_absent() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let genesis_data =
            AncillaryGenesisData::new(PROTOCOL_MESSAGE_PREIMAGE.to_vec(), None, None);
        let ancillary_input =
            AncillaryProofInput::new(None, genesis_data, PROTOCOL_MESSAGE_PREIMAGE.to_vec());

        let err = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect_err("missing genesis verification key must be rejected");

        assert_eq!(
            err.downcast_ref::<AggregationError>(),
            Some(&AggregationError::MissingGenesisVerificationKey),
            "missing genesis verification key must be rejected, got: {err}"
        );
    }

    #[test]
    fn ivc_chain_step_bundle_fails_when_genesis_signature_is_absent() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let genesis_verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key);

        // verification-key check and fails on the missing signature inside
        // `IvcGenesisBootstrapInput::try_from`.
        let genesis_data = AncillaryGenesisData::new(
            PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
            None,
            Some(genesis_verification_key),
        );
        let ancillary_input =
            AncillaryProofInput::new(None, genesis_data, PROTOCOL_MESSAGE_PREIMAGE.to_vec());

        let err = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect_err("missing genesis signature must be rejected");

        assert_eq!(
            err.root_cause().to_string(),
            "Missing genesis Schnorr signature.",
        );
    }

    #[test]
    fn ivc_chain_step_bundle_fails_when_message_preimage_has_wrong_size() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let ancillary_input =
            AncillaryProofInput::new(None, AncillaryGenesisData::dummy(), vec![0u8; 3]);

        let err = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect_err("wrong-size message preimage must be rejected");

        assert!(
            err.downcast_ref::<std::array::TryFromSliceError>().is_some(),
            "wrong-size message preimage should fail as a slice-to-array conversion, got: {err}"
        );
    }

    #[test]
    fn ivc_chain_step_bundle_fails_when_genesis_message_preimage_has_wrong_size() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let genesis_signature = signing_key
            .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
            .expect("genesis signature should be produced");
        let genesis_verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key);

        let genesis_data = AncillaryGenesisData::new(
            vec![0u8; 3],
            Some(genesis_signature),
            Some(genesis_verification_key),
        );
        let ancillary_input =
            AncillaryProofInput::new(None, genesis_data, PROTOCOL_MESSAGE_PREIMAGE.to_vec());

        let err = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect_err("wrong-size genesis message preimage must be rejected");

        assert!(
            err.downcast_ref::<std::array::TryFromSliceError>().is_some(),
            "wrong-size genesis message preimage should fail as a slice-to-array conversion, got: {err}"
        );
    }

    #[test]
    fn ivc_chain_step_bundle_carries_rolling_state_from_ancillary_prover_data() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let rolling_state = build_standard_rolling_state(StepCounter::new(3), EpochNumber::new(2));
        let ancillary_input = AncillaryProofInput::new(
            Some(AncillaryProverData::IvcSnark(rolling_state)),
            AncillaryGenesisData::dummy(),
            PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        );

        let step_bundle = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect("try_new should succeed with a valid IVC rolling state");

        // checking the step counter should be enough to ensure the rolling
        // state did not change
        assert!(
            step_bundle.rolling_state.as_ref().is_some_and(|rolling_state| {
                rolling_state.state().step_counter == StepCounter::new(3)
            }),
            "the rolling state from ancillary prover data must be carried through unchanged"
        );
    }

    #[test]
    fn ivc_chain_step_bundle_builds_global_from_genesis_data_and_keys() {
        let (certificate_proof, avk, certificate_verifying_key, ivc_verifying_key) =
            ivc_chain_step_bundle_try_new_fixture();

        let genesis_data = AncillaryGenesisData::dummy();
        let genesis_message: MessageHash = genesis_data
            .genesis_message_preimage()
            .try_into()
            .expect("genesis message preimage should hash to a field element");
        let genesis_verification_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .expect("dummy genesis data should carry a verification key");

        let ancillary_input =
            AncillaryProofInput::new(None, genesis_data, PROTOCOL_MESSAGE_PREIMAGE.to_vec());

        let step_bundle = IvcChainStepBundle::try_new(
            certificate_proof,
            &[0u8; 32],
            avk,
            ancillary_input,
            &certificate_verifying_key,
            &ivc_verifying_key,
        )
        .expect("try_new should succeed with valid genesis data");

        let expected_global = Global::new(
            genesis_message,
            genesis_verification_key,
            &certificate_verifying_key,
            &ivc_verifying_key,
        );

        assert_eq!(
            step_bundle.global, expected_global,
            "Global must be built from the values passed to try_new"
        );
    }

    mod slow {
        use std::sync::Arc;
        use std::time::Instant;

        use midnight_circuits::hash::poseidon::PoseidonState;

        use crate::{
            AggregateVerificationKeyForSnark, MithrilMembershipDigest, Parameters, SnarkProof,
            circuits::{
                halo2::types::CircuitBase,
                halo2_ivc::{
                    state::Global,
                    tests::common::{
                        asset_readers::{
                            RecursiveChainStateAsset,
                            load_embedded_first_certificate_in_epoch_asset,
                            load_embedded_following_certificate_in_epoch_asset,
                            load_embedded_genesis_benchmark_fixture,
                            load_embedded_recursive_chain_state_asset,
                            load_embedded_verification_context_asset,
                        },
                        generators::setup::{QUORUM_SIZE, SIGNER_COUNT, TOTAL_STAKE},
                    },
                    types::ProtocolMessagePreimage,
                },
            },
            proof_system::halo2_ivc_snark::{
                prover_setup::IvcProverSetup, rolling_state::IvcRollingState,
                verifier_setup::IvcVerifierSetup,
            },
        };

        use super::super::{IvcGenesisBootstrapInput, IvcProof, IvcProver};

        struct SlowTestContext {
            ivc_setup: Arc<IvcProverSetup>,
            global: Global,
            verifier_setup: IvcVerifierSetup,
            genesis_bootstrap: IvcGenesisBootstrapInput,
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

        fn rolling_state_from_asset(asset: RecursiveChainStateAsset) -> IvcRollingState {
            IvcRollingState::new(
                asset.state,
                asset.ivc_proof,
                asset.accumulator,
                asset.genesis_signature,
            )
        }

        fn build_slow_test_context() -> SlowTestContext {
            let t_setup = Instant::now();
            let parameters = Parameters {
                k: QUORUM_SIZE as u64,
                m: (QUORUM_SIZE * 10) as u64,
                phi_f: 0.2,
            };
            let merkle_tree_depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
            let ivc_setup = Arc::new(
                IvcProverSetup::build_for_test(&parameters, merkle_tree_depth)
                    .expect("IvcProverSetup::build_for_test should succeed"),
            );

            let verification_context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");
            let genesis_fixture = load_embedded_genesis_benchmark_fixture()
                .expect("genesis benchmark fixture should load");

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

            let global = Global::new(
                genesis_fixture.genesis_message_hash(),
                genesis_fixture.genesis_verification_key,
                &verification_context.certificate_verifying_key,
                &verification_context.recursive_verifying_key,
            );
            let genesis_bootstrap = IvcGenesisBootstrapInput {
                genesis_signature: genesis_fixture.genesis_signature,
                genesis_protocol_message_preimage: ProtocolMessagePreimage::new(
                    genesis_fixture.genesis_protocol_message_preimage,
                ),
            };
            let verifier_setup = IvcVerifierSetup::from_ivc_setup_with_srs(&ivc_setup);
            println!("[setup] {:.1}s", t_setup.elapsed().as_secs_f64());

            SlowTestContext {
                ivc_setup,
                global,
                verifier_setup,
                genesis_bootstrap,
            }
        }

        #[test]
        fn prove_bootstrap_produces_first_epoch_proof_and_rolling_state() {
            let ctx = build_slow_test_context();

            let first_step = load_embedded_first_certificate_in_epoch_asset()
                .expect("first-step certificate asset should load");
            let avk = wrap_avk(&first_step.aggregate_verification_key_merkle_root);
            let snark_proof = wrap_snark_proof(first_step.certificate_proof.clone().into_vec());
            let epoch1_preimage = ProtocolMessagePreimage::new(first_step.message_preimage);

            let mut prover = IvcProver::new_non_deterministic(Arc::clone(&ctx.ivc_setup));

            let (blake2b_proof, rolling) = prover
                .prove(
                    snark_proof,
                    first_step.message.as_ref(),
                    &avk,
                    &ctx.global,
                    &epoch1_preimage,
                    &ctx.genesis_bootstrap,
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
        }

        #[test]
        fn prove_same_epoch_produces_proof_without_rolling_state() {
            let ctx = build_slow_test_context();

            let rolling_state = rolling_state_from_asset(
                load_embedded_recursive_chain_state_asset()
                    .expect("recursive chain state asset should load"),
            );
            let step = load_embedded_following_certificate_in_epoch_asset()
                .expect("same-epoch step output asset should load");

            let avk = wrap_avk(&step.aggregate_verification_key_merkle_root);
            let snark_proof = wrap_snark_proof(step.certificate_proof.clone().into_vec());
            let preimage = ProtocolMessagePreimage::new(step.message_preimage);

            let mut prover = IvcProver::new_non_deterministic(Arc::clone(&ctx.ivc_setup));
            let (blake2b_proof, rolling) = prover
                .prove(
                    snark_proof,
                    step.message.as_ref(),
                    &avk,
                    &ctx.global,
                    &preimage,
                    // Ignored when continuing from an existing rolling state.
                    &ctx.genesis_bootstrap,
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
        }
    }

    mod golden {
        use super::*;

        const GOLDEN_R: [u8; 32] = [
            236, 82, 235, 208, 194, 213, 21, 52, 158, 242, 42, 124, 219, 198, 65, 232, 86, 191, 84,
            104, 0, 39, 228, 81, 172, 96, 198, 123, 29, 236, 243, 50,
        ];

        #[test]
        fn golden_combiner_r_for_stored_recursive_step_output() {
            // Pins the exact Fiat-Shamir combiner r for a fixed, known-good proof.
            // This test can fail if the assets are updated or if the dependency of
            // r on the dual_msm and accumulator is changed.
            let (global, verifier_setup) = build_proof_verifier_context();
            let step_output = load_embedded_next_epoch_step_output_asset()
                .expect("recursive step output asset should load");
            let proof = IvcProof::<Blake2b256>::new(
                step_output.ivc_proof,
                step_output.next_state,
                step_output.next_accumulator,
            );

            let (_, _, _, r) = proof
                .prepare_combined_check(&global, &verifier_setup)
                .expect("prepare_combined_check should succeed for a valid proof");

            assert_eq!(r.to_bytes_le(), GOLDEN_R);
        }
    }
}
