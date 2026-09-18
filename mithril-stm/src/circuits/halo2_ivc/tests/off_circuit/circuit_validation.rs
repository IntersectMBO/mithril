//! Tests that IvcCircuitData constructor validations return the expected typed errors.

use crate::circuits::halo2_ivc::{
    RECURSIVE_CIRCUIT_DEGREE, circuit::IvcCircuit, errors::IvcCircuitError,
    keys::RecursiveCircuitVerifyingKey,
    tests::common::asset_readers::load_embedded_verification_context_asset,
};

#[test]
fn validate_ivc_verification_key_degree_rejects_wrong_degree_vk() {
    // The certificate VK stored in the verification context has degree
    // CERTIFICATE_CIRCUIT_DEGREE (13) != RECURSIVE_CIRCUIT_DEGREE (19), so it is a cheap wrong-degree
    // input for validate_ivc_verification_key_degree without requiring any SRS generation.
    let ctx =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let wrong_degree_vk =
        RecursiveCircuitVerifyingKey::new(ctx.certificate_verifying_key.midnight_vk().clone());
    let actual_degree = wrong_degree_vk.verifying_key().get_domain().k();

    let result = IvcCircuit::validate_ivc_verification_key_degree(&wrong_degree_vk);

    let err = result
        .unwrap_err()
        .downcast::<IvcCircuitError>()
        .expect("error should downcast to IvcCircuitError");
    assert_eq!(
        err,
        IvcCircuitError::IvcVerificationKeyDegreeMismatch {
            expected: RECURSIVE_CIRCUIT_DEGREE,
            actual: actual_degree,
        }
    );
}
