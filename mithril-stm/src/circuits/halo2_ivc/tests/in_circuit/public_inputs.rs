//! Negative public-input tests: tampered global fields and accumulator, checked against the stored
//! proof by the verifier.
//!
//! In-circuit binding of the global fields lives with the genesis negative transition case, and of
//! the accumulator with the negative accumulator case.

use ff::Field;
use midnight_circuits::types::Instantiable;

use crate::circuits::halo2_ivc::{
    AssignedAccumulator, NativeField,
    tests::common::{
        asset_readers::{
            load_embedded_genesis_step_output_asset, load_embedded_verification_context_asset,
        },
        helpers::verify_prepare_blake2b_recursive_proof,
    },
};

/// Loads the genesis assets, applies `tamper` to the three public-input sections
/// (`global`, `state`, `accumulator`), then asserts the verifier rejects the result.
///
/// `global` layout: `[genesis_message, genesis_verification_key.x, genesis_verification_key.y,
/// certificate_circuit_verification_key_representation, ivc_circuit_verification_key_representation]`.
fn assert_genesis_step_output_rejects_tampered_public_inputs(
    tamper: impl FnOnce(&mut Vec<NativeField>, &mut Vec<NativeField>, &mut Vec<NativeField>),
    rejection_message: &str,
) {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let genesis_step_output =
        load_embedded_genesis_step_output_asset().expect("genesis step output asset should load");

    let mut global = verification_context.global_field_elements.clone();
    let mut state = genesis_step_output.next_state.as_public_input();
    let mut accumulator_encoding =
        AssignedAccumulator::as_public_input(&genesis_step_output.next_accumulator);

    tamper(&mut global, &mut state, &mut accumulator_encoding);

    let public_inputs = [global, state, accumulator_encoding].concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        genesis_step_output.ivc_proof.as_bytes(),
        &public_inputs,
    );

    assert!(
        !dual_msm.check(&verification_context.verifier_params),
        "{rejection_message}"
    );
}

#[test]
fn genesis_message_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when genesis_message
    // is replaced in the global public inputs, confirming it is committed at index 0.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |global, _, _| global[0] = NativeField::ONE,
        "proof with tampered genesis_message should be rejected by the verifier",
    );
}

#[test]
fn genesis_verification_key_x_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when the x coordinate of
    // genesis_verification_key is replaced in the global public inputs, confirming index 1 is committed.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |global, _, _| global[1] = NativeField::ONE,
        "proof with tampered genesis_verification_key x coordinate should be rejected by the verifier",
    );
}

#[test]
fn genesis_verification_key_y_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when the y coordinate of
    // genesis_verification_key is replaced in the global public inputs, confirming index 2 is committed.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |global, _, _| global[2] = NativeField::ONE,
        "proof with tampered genesis_verification_key y coordinate should be rejected by the verifier",
    );
}

#[test]
fn certificate_circuit_verification_key_representation_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when
    // certificate_circuit_verification_key_representation is replaced in the global public inputs,
    // confirming it is committed at index 3.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |global, _, _| global[3] = NativeField::ONE,
        "proof with tampered certificate_circuit_verification_key_representation should be rejected by the verifier",
    );
}

#[test]
fn ivc_circuit_verification_key_representation_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when
    // ivc_circuit_verification_key_representation is replaced in the global public inputs,
    // confirming it is committed at index 4.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |global, _, _| global[4] = NativeField::ONE,
        "proof with tampered ivc_circuit_verification_key_representation should be rejected by the verifier",
    );
}

#[test]
fn next_accumulator_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when next_accumulator
    // is replaced in the public inputs, confirming the accumulator output is committed.
    assert_genesis_step_output_rejects_tampered_public_inputs(
        |_, _, accumulator_encoding| accumulator_encoding[0] = NativeField::ONE,
        "proof with tampered next_accumulator should be rejected by the verifier",
    );
}
