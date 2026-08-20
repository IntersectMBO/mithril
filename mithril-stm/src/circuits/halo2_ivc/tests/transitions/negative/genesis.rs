use super::*;

use crate::circuits::halo2_ivc::{
    state::State,
    tests::common::{
        asset_readers::load_embedded_genesis_step_output_asset,
        generators::{
            GENESIS_EPOCH, build_asset_generation_setup_from_cache,
            build_genesis_base_case_next_state, build_genesis_base_case_witness,
        },
        helpers::{
            assert_recursive_mock_prover_rejects, build_mock_prover_public_inputs,
            build_mock_prover_setup_from_assets, build_trivial_mock_prover_circuit,
        },
    },
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
    use super::*;

    /// Builds a genesis circuit with a tampered next state and asserts the MockProver rejects it.
    ///
    /// `tamper` receives the correct genesis next state before it is passed to the
    /// public inputs, allowing each test to corrupt exactly the field it wants to verify.
    fn assert_genesis_circuit_rejects_tampered_next_state(tamper: impl FnOnce(&mut State)) {
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);

        let witness = build_genesis_base_case_witness(&setup);

        let mut tampered_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        tamper(&mut tampered_state);

        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, State::genesis(), witness);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state);

        assert_recursive_mock_prover_rejects(ivc_circuit_data, public_inputs);
    }

    #[test]
    fn circuit_rejects_msg_inconsistent_with_preimage() {
        // MockProver check that the in-circuit Blake2b hash constraint between
        // message_preimage bytes and the resulting message field is wired correctly.
        assert_genesis_circuit_rejects_tampered_next_state(|s| {
            s.message = MessageHash::from_field(NativeField::ONE)
        });
    }
}
