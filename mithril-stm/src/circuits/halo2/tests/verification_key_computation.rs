use anyhow::Context;
use midnight_proofs::utils::SerdeFormat;

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, Parameters, StmResult,
    circuits::{
        halo2::{
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, circuit::CertificateCircuit,
        },
        trusted_setup::TrustedSetupProvider,
    },
};

/// Constant representing the current STM parameters used for production,
/// i.e. parameters that guarantee the security of the protocol
const STM_PARAMETERS_FOR_PRODUCTION: Parameters = Parameters {
    m: 16948,
    k: 1944,
    phi_f: 0.2,
};

/// Derive the non-recursive circuit verification key from the production SRS and the given
/// protocol parameters. Used by
/// [`write_non_recursive_circuit_verification_key_for_production_to_file`] to regenerate
/// `non_recursive_circuit_verification_key_for_production.bin` when the circuit changes.
fn compute_non_recursive_circuit_verification_key(
    params: &Parameters,
    merkle_tree_depth: u32,
) -> StmResult<Vec<u8>> {
    let circuit = CertificateCircuit::try_new(params, merkle_tree_depth)?;
    let srs = TrustedSetupProvider::default().get_trusted_setup_parameters()?;
    let non_recursive_circuit_verification_key = midnight_zk_stdlib::setup_vk(&srs, &circuit);
    let mut buffer_for_non_recursive_circuit_verification_key = vec![];
    non_recursive_circuit_verification_key
        .write(
            &mut buffer_for_non_recursive_circuit_verification_key,
            SerdeFormat::RawBytes,
        )
        .with_context(
            || "Failed to write the non recursive circuit verification key to a buffer.",
        )?;
    Ok(buffer_for_non_recursive_circuit_verification_key)
}

/// Function that recomputes the non recursive production key and updates
/// the binary file storing its value
#[test]
#[ignore]
pub fn write_non_recursive_circuit_verification_key_for_production_to_file() {
    let verification_key = compute_non_recursive_circuit_verification_key(
        &STM_PARAMETERS_FOR_PRODUCTION,
        MERKLE_TREE_DEPTH_FOR_SNARK,
    )
    .unwrap();

    std::fs::write(
        "src/circuits/halo2/non_recursive_circuit_verification_key_for_production.bin",
        verification_key,
    )
    .unwrap();
}

/// Function that recomputes the non recursive production key and checks its value
/// against the value used to compile the library
#[test]
#[ignore]
fn integrity_test_for_non_recursive_production_key() {
    let production_non_recursive_key = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;

    let recomputed_non_recursive_key = compute_non_recursive_circuit_verification_key(
        &STM_PARAMETERS_FOR_PRODUCTION,
        MERKLE_TREE_DEPTH_FOR_SNARK,
    )
    .unwrap();

    assert_eq!(production_non_recursive_key, recomputed_non_recursive_key);
}
