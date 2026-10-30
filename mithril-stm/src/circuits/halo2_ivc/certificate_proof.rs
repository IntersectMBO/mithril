//! Off-circuit verifier for the STM cert SNARK proof.
//!
//! Mirrors the in-circuit verification done by the IVC verifier gadget:
//! reads the cert proof's Poseidon transcript, extracts the verifier's
//! `DualMSM`, and pairing-checks it for early abort. The returned `DualMSM`
//! agrees with what the in-circuit verifier gadget produces on the same
//! proof, so it can be wrapped into a certificate accumulator for IVC
//! aggregation.

use group::Group;

use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::{
    plonk::prepare,
    poly::kzg::{KZGCommitmentScheme, msm::DualMSM, params::ParamsVerifierKZG},
    transcript::{CircuitTranscript, Transcript},
};

use crate::{
    StmResult,
    circuits::{
        halo2::types::CircuitBase,
        halo2_ivc::{NativeField, PairingEngine, VerifyingKey, errors::IvcCircuitError},
    },
};

/// Runs the off-circuit verifier for a cert SNARK proof and returns the
/// verifier's intermediate `DualMSM`.
///
/// The transcript hash and public-input encoding match the in-circuit verifier
/// gadget, so the returned `DualMSM` is the off-circuit twin of the
/// accumulator the IVC circuit computes on the same proof. The pairing check
/// on a clone gives cheap early abort; the original `DualMSM` is returned on
/// success for downstream reuse (e.g. wrapping into a certificate accumulator
/// for recursive aggregation).
pub(crate) fn verify_and_prepare_accumulator(
    proof_bytes: &[u8],
    public_inputs: &[CircuitBase],
    circuit_verification_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    verifier_params: &ParamsVerifierKZG<Bls12>,
) -> StmResult<DualMSM<Bls12>> {
    let mut transcript =
        CircuitTranscript::<PoseidonState<CircuitBase>>::init_from_bytes(proof_bytes);

    let dual_msm = prepare::<
        CircuitBase,
        KZGCommitmentScheme<Bls12>,
        CircuitTranscript<PoseidonState<CircuitBase>>,
    >(
        circuit_verification_key,
        // `committed_instances` slot: identity matches what the in-circuit IVC verifier
        // gadget passes, so the off-circuit `DualMSM` is byte-equivalent to its in-circuit twin.
        &[&[G1Projective::identity()]],
        &[&[public_inputs]],
        &mut transcript,
    )
    .map_err(|err| {
        IvcCircuitError::CertificateProofRejected(format!(
            "Error from plonk verifier prepare function: {}",
            err
        ))
    })?;

    transcript.assert_empty().map_err(|err| {
        IvcCircuitError::CertificateProofRejected(format!(
            "Transcript is not empty after the dual msm prepare: {}",
            err
        ))
    })?;

    if !dual_msm.clone().check(verifier_params) {
        return Err(
            IvcCircuitError::CertificateProofRejected("Dual msm check failed".to_string()).into(),
        );
    }

    Ok(dual_msm)
}
