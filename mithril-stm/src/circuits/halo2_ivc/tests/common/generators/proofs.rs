use std::hash::Hash;

use ff::FromUniformBytes;
use group::Group;
use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_curves::Bls12;
use midnight_proofs::circuit::Value;
use midnight_proofs::{
    plonk::{create_proof, prepare},
    poly::{
        commitment::PolynomialCommitmentScheme,
        kzg::{KZGCommitmentScheme, msm::DualMSM, params::ParamsKZG},
    },
    transcript::{Blake2b256, CircuitTranscript, Hashable, Sampleable, Transcript, TranscriptHash},
};
use midnight_zk_stdlib::MidnightCircuit;
use rand_core::{CryptoRng, RngCore};

use crate::circuits::halo2_ivc::keys::RecursiveCircuitProvingKey;
use crate::circuits::halo2_ivc::{
    EmulatedCurve, NativeField, PairingEngine, RECURSIVE_CIRCUIT_DEGREE, VerifyingKey,
    circuit::{IvcCircuit, IvcCircuitData},
};

/// Generates a recursive proof using the chosen transcript hash.
fn prove_ivc_with_transcript<H: TranscriptHash>(
    commitment_parameters: &ParamsKZG<Bls12>,
    proving_key: &RecursiveCircuitProvingKey,
    ivc_circuit: &IvcCircuit,
    ivc_circuit_data: &IvcCircuitData,
    public_inputs: &[NativeField],
    random_generator: &mut (impl RngCore + CryptoRng),
    proof_generation_error: &str,
) -> Vec<u8>
where
    NativeField: Sampleable<H> + Hashable<H> + Hash + Ord + FromUniformBytes<64>,
    <KZGCommitmentScheme<PairingEngine> as PolynomialCommitmentScheme<NativeField>>::Commitment:
        Hashable<H>,
{
    let mut transcript = CircuitTranscript::<H>::init();
    create_proof::<
        NativeField,
        KZGCommitmentScheme<PairingEngine>,
        CircuitTranscript<H>,
        MidnightCircuit<IvcCircuit>,
    >(
        commitment_parameters,
        proving_key.midnight_pk().pk(),
        std::slice::from_ref(&MidnightCircuit::new(
            ivc_circuit,
            Value::known(public_inputs.to_vec()),
            Value::known(ivc_circuit_data.clone()),
            Some(RECURSIVE_CIRCUIT_DEGREE),
        )),
        1,
        &[&[&[], public_inputs]],
        &mut transcript,
        random_generator,
    )
    .expect(proof_generation_error);
    transcript.finalize()
}

/// Verifies a recursive proof and returns the prepared MSM.
fn verify_prepare_ivc_with_transcript<H: TranscriptHash>(
    verifying_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    proof: &[u8],
    public_inputs: &[NativeField],
    verification_error: &str,
    transcript_error: &str,
) -> DualMSM<PairingEngine>
where
    NativeField: Sampleable<H> + Hashable<H> + Hash + Ord + FromUniformBytes<64>,
    <KZGCommitmentScheme<PairingEngine> as PolynomialCommitmentScheme<NativeField>>::Commitment:
        Hashable<H>,
{
    let mut transcript = CircuitTranscript::<H>::init_from_bytes(proof);
    let dual_msm =
        prepare::<NativeField, KZGCommitmentScheme<PairingEngine>, CircuitTranscript<H>>(
            verifying_key,
            &[&[EmulatedCurve::identity()]],
            &[&[public_inputs]],
            &mut transcript,
        )
        .expect(verification_error);
    transcript.assert_empty().expect(transcript_error);
    dual_msm
}

/// Generates a recursive proof using the Poseidon transcript.
pub(crate) fn prove_poseidon_ivc(
    commitment_parameters: &ParamsKZG<Bls12>,
    proving_key: &RecursiveCircuitProvingKey,
    ivc_circuit: &IvcCircuit,
    ivc_circuit_data: &IvcCircuitData,
    public_inputs: &[NativeField],
    random_generator: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    prove_ivc_with_transcript::<PoseidonState<NativeField>>(
        commitment_parameters,
        proving_key,
        ivc_circuit,
        ivc_circuit_data,
        public_inputs,
        random_generator,
        "IVC proof generation should not fail",
    )
}

/// Verifies a recursive proof using the Poseidon transcript and returns the prepared MSM.
pub(crate) fn verify_prepare_poseidon_ivc(
    verifying_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    proof: &[u8],
    public_inputs: &[NativeField],
) -> DualMSM<PairingEngine> {
    verify_prepare_ivc_with_transcript::<PoseidonState<NativeField>>(
        verifying_key,
        proof,
        public_inputs,
        "Poseidon recursive proof verification should succeed",
        "Poseidon transcript should be empty after verification",
    )
}

/// Generates the final recursive proof using the Blake2b transcript.
pub(crate) fn prove_blake2b_ivc(
    commitment_parameters: &ParamsKZG<Bls12>,
    proving_key: &RecursiveCircuitProvingKey,
    ivc_circuit: &IvcCircuit,
    ivc_circuit_data: &IvcCircuitData,
    public_inputs: &[NativeField],
    random_generator: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    prove_ivc_with_transcript::<Blake2b256>(
        commitment_parameters,
        proving_key,
        ivc_circuit,
        ivc_circuit_data,
        public_inputs,
        random_generator,
        "IVC Blake2b proof generation should not fail",
    )
}

/// Attempts to verify a proof using the Poseidon transcript without panicking.
///
/// Returns `None` if the bytes are too malformed to parse (deserialization error
/// or leftover bytes after verification). Returns `Some(dual_msm)` if the bytes
/// parse successfully — the caller must still call `dual_msm.check()` to determine
/// whether the KZG opening equations hold.
///
/// Use this instead of `verify_prepare_poseidon_ivc` when testing with tampered
/// bytes where a panic-on-error would be inappropriate.
pub(crate) fn try_verify_prepare_poseidon_ivc(
    verifying_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    proof: &[u8],
    public_inputs: &[NativeField],
) -> Option<DualMSM<PairingEngine>> {
    let mut transcript = CircuitTranscript::<PoseidonState<NativeField>>::init_from_bytes(proof);
    let dual_msm = prepare::<
        NativeField,
        KZGCommitmentScheme<PairingEngine>,
        CircuitTranscript<PoseidonState<NativeField>>,
    >(
        verifying_key,
        &[&[EmulatedCurve::identity()]],
        &[&[public_inputs]],
        &mut transcript,
    )
    .ok()?;
    transcript.assert_empty().ok()?;
    Some(dual_msm)
}

/// Verifies the final recursive proof using the Blake2b transcript.
pub(crate) fn verify_prepare_blake2b_ivc(
    verifying_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    proof: &[u8],
    public_inputs: &[NativeField],
) -> DualMSM<PairingEngine> {
    verify_prepare_ivc_with_transcript::<Blake2b256>(
        verifying_key,
        proof,
        public_inputs,
        "Blake2b recursive proof verification should succeed",
        "Blake2b transcript should be empty after verification",
    )
}
