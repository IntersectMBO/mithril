//! Positive transition tests.
//!
//! Fast tests verify the stored output proof of each transition context against the full verifier.
//! The slow checks synthesize the current circuit over the stored inputs and assert it accepts the
//! stored expected output, which the stored proof alone cannot establish.

use midnight_circuits::types::Instantiable;

use crate::StmResult;
use crate::circuits::halo2_ivc::{
    AssignedAccumulator,
    tests::common::{
        asset_readers::{
            StepOutputAsset, load_embedded_following_certificate_in_epoch_asset,
            load_embedded_genesis_step_output_asset, load_embedded_next_epoch_step_output_asset,
            load_embedded_verification_context_asset,
        },
        helpers::verify_prepare_blake2b_recursive_proof,
    },
};

/// Loads a step output via `load_step_output` and asserts the verifier accepts
/// the proof against the correct public inputs.
fn assert_step_proof_verifies<T: StepOutputAsset>(
    load_step_output: impl FnOnce() -> StmResult<T>,
    load_label: &str,
    acceptance_message: &str,
) {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let step_output =
        load_step_output().unwrap_or_else(|_| panic!("{load_label} asset should load"));

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        step_output.next_state().as_public_input(),
        AssignedAccumulator::as_public_input(step_output.next_accumulator()),
    ]
    .concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        step_output.ivc_proof().as_bytes(),
        &public_inputs,
    );

    assert!(
        dual_msm.check(&verification_context.verifier_params),
        "{acceptance_message}"
    );
}

#[test]
fn genesis_step_proof_verifies() {
    // Asset-based check that the stored genesis Blake2b proof verifies against the correct
    // public inputs, confirming the genesis base-case asset is valid.
    assert_step_proof_verifies(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        "genesis step proof should verify against the correct public inputs",
    );
}

#[test]
fn same_epoch_step_proof_verifies() {
    // Asset-based check that the stored same-epoch Blake2b proof verifies against the correct
    // public inputs, confirming the same-epoch asset is valid.
    assert_step_proof_verifies(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        "same-epoch step proof should verify against the correct public inputs",
    );
}

#[test]
fn next_epoch_step_proof_verifies() {
    // Asset-based check that the stored next-epoch Blake2b proof verifies against the correct
    // public inputs, confirming the next-epoch asset is valid.
    assert_step_proof_verifies(
        load_embedded_next_epoch_step_output_asset,
        "recursive step output",
        "next-epoch step proof should verify against the correct public inputs",
    );
}

mod slow {
    use crate::circuits::halo2_ivc::tests::common::{
        generators::build_asset_generation_setup_from_cache,
        helpers::{
            assert_recursive_mock_prover_accepts_with_label, build_asset_backed_next_epoch_fixture,
            build_asset_backed_same_epoch_fixture, build_mock_prover_setup_from_assets,
        },
    };

    #[test]
    fn same_epoch_step_circuit_is_accepted() {
        // Satisfiable baseline for the same-epoch negative case.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let fixture = build_asset_backed_same_epoch_fixture(&mock_prover_setup);

        assert_recursive_mock_prover_accepts_with_label(
            fixture.ivc_circuit_data,
            fixture.public_inputs,
            "same-epoch step from committed assets",
        );
    }

    #[test]
    fn next_epoch_step_circuit_is_accepted() {
        // Satisfiable baseline for the next-epoch negative case.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let fixture = build_asset_backed_next_epoch_fixture(&mock_prover_setup);

        assert_recursive_mock_prover_accepts_with_label(
            fixture.ivc_circuit_data,
            fixture.public_inputs,
            "next-epoch step from committed assets",
        );
    }
}
