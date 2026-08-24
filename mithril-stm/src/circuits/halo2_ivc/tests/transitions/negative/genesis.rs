use super::*;

use crate::circuits::halo2_ivc::{
    tests::common::asset_readers::load_embedded_genesis_step_output_asset,
    types::{EpochNumber, MerkleTreeCommitment, MessageHash, ProtocolParametersHash, StepCounter},
};

#[test]
fn merkle_tree_commitment_tampered_is_rejected() {
    // Asset-based check: circuit enforces merkle_tree_commitment = 0 at the genesis base case.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE),
        "proof with tampered merkle_tree_commitment should be rejected by the verifier",
    );
}

#[test]
fn protocol_parameters_tampered_is_rejected() {
    // Asset-based check: circuit enforces protocol_parameters = 0 at the genesis base case.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE),
        "proof with tampered protocol_parameters should be rejected by the verifier",
    );
}

#[test]
fn next_merkle_tree_commitment_tampered_is_rejected() {
    // Asset-based check: circuit enforces next_merkle_tree_commitment is extracted from the genesis message preimage.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.next_merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE),
        "proof with tampered next_merkle_tree_commitment should be rejected by the verifier",
    );
}

#[test]
fn next_protocol_parameters_tampered_is_rejected() {
    // Asset-based check: circuit enforces next_protocol_parameters is extracted from the genesis message preimage.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.next_protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE),
        "proof with tampered next_protocol_parameters should be rejected by the verifier",
    );
}

#[test]
fn counter_tampered_is_rejected() {
    // Asset-based check: circuit enforces step_counter transitions 0 → 1 at the genesis base case.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.step_counter = StepCounter::new(2),
        "proof with tampered step_counter should be rejected by the verifier",
    );
}

#[test]
fn current_epoch_tampered_is_rejected() {
    // Asset-based check: circuit enforces current_epoch is extracted from the genesis message preimage.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.current_epoch = EpochNumber::from_field(NativeField::ONE),
        "proof with tampered current_epoch should be rejected by the verifier",
    );
}

#[test]
fn msg_tampered_is_rejected() {
    // Asset-based check: circuit enforces message equals the genesis message committed in the Global public inputs.
    assert_step_output_rejects_tampered_state(
        load_embedded_genesis_step_output_asset,
        "genesis step output",
        |s| s.message = MessageHash::from_field(NativeField::ONE),
        "proof with tampered message should be rejected by the verifier",
    );
}

mod slow {
    use std::collections::BTreeMap;

    use crate::circuits::halo2_ivc::{
        state::State,
        tests::common::{
            failure_signature::{
                assert_recursive_mock_prover_rejects_public_input_rows, mutate_public_input,
            },
            generators::{
                GENESIS_EPOCH, build_asset_generation_setup_from_cache,
                build_genesis_base_case_next_state, build_genesis_base_case_witness,
            },
            helpers::{
                build_genesis_mock_prover_circuit, build_genesis_mock_prover_public_inputs,
                build_mock_prover_setup_from_assets,
            },
            public_input_layout::{all_global_rows, all_state_rows},
        },
    };

    #[test]
    fn circuit_rejects_tampered_genesis_global_and_state_public_inputs() {
        // One synthesis covers every element, since MockProver reports all failures, not the first.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let ivc_circuit_data = build_genesis_mock_prover_circuit(
            &mock_prover_setup,
            State::genesis(),
            build_genesis_base_case_witness(&setup),
        );

        let mut public_inputs =
            build_genesis_mock_prover_public_inputs(&mock_prover_setup, &next_state);
        let expected_rows: BTreeMap<usize, &str> =
            all_global_rows().into_iter().chain(all_state_rows()).collect();
        for row in expected_rows.keys() {
            mutate_public_input(&mut public_inputs, *row);
        }

        assert_recursive_mock_prover_rejects_public_input_rows(
            ivc_circuit_data,
            public_inputs,
            &expected_rows,
        );
    }
}
