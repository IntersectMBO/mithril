use std::path::Path;

use midnight_proofs::{
    plonk::{VerifyingKey, keygen_vk_with_k},
    poly::kzg::KZGCommitmentScheme,
    utils::SerdeFormat,
};
use midnight_zk_stdlib::MidnightCircuit;

use crate::{
    Parameters,
    circuits::{
        halo2::circuit::StmCertificateCircuit,
        halo2::keys::NonRecursiveCircuitVerifyingKey,
        halo2_ivc::{
            NativeField, PairingEngine, RECURSIVE_CIRCUIT_DEGREE, circuit::IvcCircuitData,
        },
    },
};

use super::setup::build_deterministic_params;

pub(crate) fn golden_recursive_circuit_verification_key_bytes() -> Vec<u8> {
    let small_parameters = Parameters {
        m: 10,
        k: 1,
        phi_f: 0.2,
    };
    let merkle_tree_depth = 3;
    let circuit = StmCertificateCircuit::try_new(&small_parameters, merkle_tree_depth).unwrap();
    let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();

    let srs_for_non_recursive_circuit = build_deterministic_params(circuit_degree);
    let srs_for_recursive_circuit = build_deterministic_params(RECURSIVE_CIRCUIT_DEGREE);

    let circuit_verification_key = NonRecursiveCircuitVerifyingKey::new(
        midnight_zk_stdlib::setup_vk(&srs_for_non_recursive_circuit, &circuit),
    );

    let default_ivc_circuit =
        IvcCircuitData::unknown(&circuit_verification_key).expect("valid IvcCircuitData unknown");
    let recursive_verifying_key: VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> =
        keygen_vk_with_k(
            &srs_for_recursive_circuit,
            &default_ivc_circuit,
            RECURSIVE_CIRCUIT_DEGREE,
        )
        .expect("recursive verifying key generation should not fail");

    let mut buf_cvk = vec![];
    recursive_verifying_key
        .write(&mut buf_cvk, SerdeFormat::RawBytes)
        .unwrap();
    buf_cvk
}

fn write_golden_recursive_circuit_verification_key_asset(path: &Path) {
    let golden_value = golden_recursive_circuit_verification_key_bytes();
    std::fs::write(path, golden_value)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

#[test]
#[ignore]
fn generate_golden_recursive_circuit_verification_key_only() {
    let output_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/circuits/halo2_ivc/tests/assets/golden_recursive_circuit_verification_key.bin");
    write_golden_recursive_circuit_verification_key_asset(&output_path);
}
