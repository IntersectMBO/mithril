use anyhow::Context;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::{self as zk, MidnightVK};

use crate::{
    StmResult,
    circuits::{
        halo2::{
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            keys::NonRecursiveCircuitVerifyingKey,
        },
        halo2_ivc::{
            RECURSIVE_CIRCUIT_DEGREE, RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            circuit::IvcCircuit,
        },
        trusted_setup::TrustedSetupProvider,
    },
};

/// Derive the recursive circuit verification key from the production SRS and the hardcoded
/// non-recursive VK. Used by [`write_recursive_circuit_verification_key_for_production_to_file`]
/// to regenerate `recursive_circuit_verification_key_for_production.bin` when the circuit changes.
fn compute_recursive_circuit_verification_key() -> StmResult<Vec<u8>> {
    let shared_srs_degree = RECURSIVE_CIRCUIT_DEGREE;
    let srs = TrustedSetupProvider::default().get_trusted_setup_parameters()?;
    // The recursive circuit uses a fixed SRS degree RECURSIVE_CIRCUIT_DEGREE, smaller than the full production SRS.
    let mut recursive_commitment_parameters = srs;
    recursive_commitment_parameters.downsize(shared_srs_degree);

    let mut non_recursive_verification_key = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    let certificate_verifying_key = NonRecursiveCircuitVerifyingKey::new(
        MidnightVK::read(&mut non_recursive_verification_key, SerdeFormat::RawBytes)
            .with_context(|| "Failed to deserialize the circuit verification key.")?,
    );

    let default_ivc_circuit = IvcCircuit::for_key_generation(&certificate_verifying_key);
    let recursive_verification_key =
        zk::setup_vk(&recursive_commitment_parameters, &default_ivc_circuit);

    let mut buffer_for_recursive_circuit_verification_key = vec![];
    recursive_verification_key
        .write(
            &mut buffer_for_recursive_circuit_verification_key,
            SerdeFormat::RawBytes,
        )
        .with_context(|| "Failed to write the recursive circuit verification key to a buffer.")?;
    Ok(buffer_for_recursive_circuit_verification_key)
}

/// Function that recomputes the recursive production key and updates
/// the binary file storing its value
#[test]
#[ignore]
pub fn write_recursive_circuit_verification_key_for_production_to_file() {
    let verification_key = compute_recursive_circuit_verification_key().unwrap();

    std::fs::write(
        "src/circuits/halo2_ivc/recursive_circuit_verification_key_for_production.bin",
        verification_key,
    )
    .unwrap();
}

/// Function that recomputes the recursive production key and checks its value
/// against the value used to compile the library
#[test]
#[ignore]
fn integrity_test_for_recursive_production_key() {
    let production_recursive_key = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    let recomputed_recursive_key = compute_recursive_circuit_verification_key().unwrap();
    assert_eq!(production_recursive_key, recomputed_recursive_key);
}
