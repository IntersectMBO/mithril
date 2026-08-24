use super::*;

use crate::circuits::halo2_ivc::{
    tests::common::asset_readers::load_embedded_following_certificate_in_epoch_asset,
    types::{EpochNumber, MerkleTreeCommitment, MessageHash, ProtocolParametersHash, StepCounter},
};

#[test]
fn merkle_tree_commitment_tampered_is_rejected() {
    // Asset-based check: circuit enforces merkle_tree_commitment = prev.merkle_tree_commitment in a same-epoch transition.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE),
        "proof with tampered merkle_tree_commitment should be rejected by the verifier",
    );
}

#[test]
fn next_merkle_tree_commitment_tampered_is_rejected() {
    // Asset-based check: circuit enforces next_merkle_tree_commitment is extracted from the certificate message preimage.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.next_merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE),
        "proof with tampered next_merkle_tree_commitment should be rejected by the verifier",
    );
}

#[test]
fn protocol_parameters_tampered_is_rejected() {
    // Asset-based check: circuit enforces protocol_parameters = prev.protocol_parameters in a same-epoch transition.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE),
        "proof with tampered protocol_parameters should be rejected by the verifier",
    );
}

#[test]
fn next_protocol_parameters_tampered_is_rejected() {
    // Asset-based check: circuit enforces next_protocol_parameters is extracted from the certificate message preimage.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.next_protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE),
        "proof with tampered next_protocol_parameters should be rejected by the verifier",
    );
}

#[test]
fn current_epoch_tampered_is_rejected() {
    // Asset-based check: circuit enforces current_epoch is unchanged in a same-epoch transition.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.current_epoch = EpochNumber::from_field(NativeField::ONE),
        "proof with tampered current_epoch should be rejected by the verifier",
    );
}

#[test]
fn counter_tampered_is_rejected() {
    // Asset-based check: circuit enforces step_counter increments by 1 at every recursive step.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.step_counter = StepCounter::from_field(NativeField::ONE),
        "proof with tampered step_counter should be rejected by the verifier",
    );
}

#[test]
fn msg_tampered_is_rejected() {
    // Asset-based check: circuit enforces message equals the certificate message hash verified in-circuit.
    assert_step_output_rejects_tampered_state(
        load_embedded_following_certificate_in_epoch_asset,
        "same-epoch step output",
        |s| s.message = MessageHash::from_field(NativeField::ONE),
        "proof with tampered message should be rejected by the verifier",
    );
}

mod slow {
    use crate::circuits::halo2_ivc::tests::common::{
        failure_signature::{
            assert_recursive_mock_prover_rejects_public_input_rows, mutate_public_input,
        },
        generators::build_asset_generation_setup_from_cache,
        helpers::{build_asset_backed_same_epoch_fixture, build_mock_prover_setup_from_assets},
        public_input_layout::all_state_rows,
    };

    #[test]
    fn circuit_rejects_tampered_same_epoch_state_public_inputs() {
        // Every next-state element is bound to the value the circuit derives for a same-epoch step, so
        // tampering all of them must implicate exactly those public rows and no others. The fixture is the
        // committed step, which is accepted untampered.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let mut fixture = build_asset_backed_same_epoch_fixture(&mock_prover_setup);

        let expected_rows = all_state_rows();
        for row in expected_rows.keys() {
            mutate_public_input(&mut fixture.public_inputs, *row);
        }

        assert_recursive_mock_prover_rejects_public_input_rows(
            fixture.ivc_circuit_data,
            fixture.public_inputs,
            &expected_rows,
        );
    }
}
