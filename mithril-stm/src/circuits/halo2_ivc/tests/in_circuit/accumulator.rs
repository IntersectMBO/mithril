//! Tests that the circuit enforces the accumulator output constraint.
//!
//! Fast tests use the asset-based verifier to confirm that a tampered
//! next_accumulator is rejected for each step type. A slow MockProver check
//! confirms the in-circuit accumulator update constraint is wired correctly.

use ff::Field;
use midnight_circuits::types::Instantiable;

use crate::StmResult;
use crate::circuits::halo2_ivc::{
    AssignedAccumulator, NativeField,
    tests::common::{
        asset_readers::{
            StepOutputAsset, load_embedded_following_certificate_in_epoch_asset,
            load_embedded_genesis_step_output_asset, load_embedded_next_epoch_step_output_asset,
            load_embedded_verification_context_asset,
        },
        helpers::verify_prepare_blake2b_recursive_proof,
    },
};

/// Loads a step output via `load_step_output`, replaces `acc[0]` with `NativeField::ONE`
/// in the public inputs, then asserts the verifier rejects the resulting proof.
fn assert_step_output_rejects_tampered_next_accumulator<T: StepOutputAsset>(
    load_step_output: impl FnOnce() -> StmResult<T>,
    load_label: &str,
    rejection_message: &str,
) {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let step_output =
        load_step_output().unwrap_or_else(|_| panic!("{load_label} asset should load"));

    let global = verification_context.global_field_elements.clone();
    let state = step_output.next_state().as_public_input();
    let mut accumulator_encoding =
        AssignedAccumulator::as_public_input(step_output.next_accumulator());

    accumulator_encoding[0] = NativeField::ONE;

    let public_inputs = [global, state, accumulator_encoding].concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        step_output.ivc_proof().as_bytes(),
        &public_inputs,
    );

    assert!(
        !dual_msm.check(&verification_context.verifier_params),
        "{rejection_message}"
    );
}

#[test]
fn genesis_step_rejects_tampered_next_accumulator() {
    // Asset-based check that the verifier rejects the stored genesis proof when
    // next_accumulator is replaced in the public inputs.
    assert_step_output_rejects_tampered_next_accumulator(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        "genesis step with a tampered next_accumulator should be rejected by the verifier",
    );
}

#[test]
fn same_epoch_step_rejects_tampered_next_accumulator() {
    // Asset-based check that the verifier rejects the stored same-epoch proof when
    // next_accumulator is replaced in the public inputs.
    assert_step_output_rejects_tampered_next_accumulator(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        "same-epoch step with a tampered next_accumulator should be rejected by the verifier",
    );
}

#[test]
fn next_epoch_step_rejects_tampered_next_accumulator() {
    // Asset-based check that the verifier rejects the stored next-epoch proof when
    // next_accumulator is replaced in the public inputs.
    assert_step_output_rejects_tampered_next_accumulator(
        load_embedded_next_epoch_step_output_asset,
        "recursive step output",
        "next-epoch step with a tampered next_accumulator should be rejected by the verifier",
    );
}

mod slow {
    use ff::Field;
    use midnight_circuits::types::Instantiable;

    use crate::circuits::halo2_ivc::{
        AssignedAccumulator, NativeField,
        circuit::IvcCircuitData,
        tests::common::{
            asset_readers::load_embedded_recursive_chain_state_asset,
            generators::{
                build_asset_generation_setup_from_cache, build_same_epoch_certificate_asset_data,
            },
            helpers::{
                assert_recursive_mock_prover_rejects, build_recursive_mock_prover_setup,
                compute_expected_next_accumulator,
            },
        },
    };

    #[test]
    fn circuit_rejects_with_wrong_next_accumulator_in_same_epoch_step() {
        // MockProver check that the in-circuit accumulator update constraint holds for
        // a same-epoch step; substituting a wrong next_accumulator in the public inputs
        // causes MockProver to detect the arithmetic constraint violation.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_recursive_mock_prover_setup(&setup);

        let recursive_chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");

        let (certificate_proof, cert_accumulator, next_state, ivc_witness) =
            build_same_epoch_certificate_asset_data(
                &setup,
                &mock_prover_setup.certificate_commitment_parameters,
                &setup.certificate_relation,
                &mock_prover_setup.certificate_verifying_key,
                &recursive_chain_state.state,
                &mut rand_core::OsRng,
            );

        let next_accumulator = compute_expected_next_accumulator(
            &mock_prover_setup,
            &recursive_chain_state,
            cert_accumulator,
        );

        let ivc_circuit_data = IvcCircuitData::try_new(
            mock_prover_setup.global.clone(),
            recursive_chain_state.state.clone(),
            ivc_witness,
            certificate_proof,
            recursive_chain_state.ivc_proof.clone(),
            recursive_chain_state.accumulator.clone(),
            &mock_prover_setup.certificate_verifying_key,
            &mock_prover_setup.recursive_verifying_key,
        )
        .expect("valid IvcCircuitData construction");

        let mut accumulator_encoding = AssignedAccumulator::as_public_input(&next_accumulator);
        accumulator_encoding[0] = NativeField::ONE;

        let public_inputs = [
            mock_prover_setup.global.as_public_input(),
            next_state.as_public_input(),
            accumulator_encoding,
        ]
        .concat();

        assert_recursive_mock_prover_rejects(ivc_circuit_data, public_inputs);
    }
}
