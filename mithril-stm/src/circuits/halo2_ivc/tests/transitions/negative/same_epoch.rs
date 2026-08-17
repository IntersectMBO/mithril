use super::*;

use crate::circuits::halo2_ivc::{
    state::Witness,
    tests::common::{
        asset_readers::{
            load_embedded_following_certificate_in_epoch_asset,
            load_embedded_recursive_chain_state_asset,
        },
        generators::{
            build_asset_generation_setup_from_cache, same_epoch_message_and_preimage_for_step,
            same_epoch_next_state_for_step,
        },
        helpers::{
            assert_recursive_mock_prover_rejects_with_label, build_mock_prover_public_inputs,
            build_mock_prover_setup_from_assets, build_trivial_mock_prover_circuit,
        },
    },
    types::{
        EpochNumber, MerkleTreeCommitment, MessageHash, ProtocolMessagePreimage,
        ProtocolParametersHash, StepCounter,
    },
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
    use super::*;

    #[test]
    fn circuit_rejects_merkle_tree_commitment_carry_violation_in_same_epoch_step() {
        // MockProver constraint check: in a same-epoch transition the circuit must carry
        // merkle_tree_commitment unchanged from prev_state. Setting it to ONE violates that constraint.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (message, preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, message);
        tampered_state.merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "merkle_tree_commitment set to ONE (same-epoch: must carry prev.merkle_tree_commitment unchanged)",
        );
    }

    #[test]
    fn circuit_rejects_protocol_parameters_carry_violation_in_same_epoch_step() {
        // MockProver constraint check: in a same-epoch transition the circuit must carry
        // protocol_parameters unchanged from prev_state. Setting it to ONE violates that constraint.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (message, preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, message);
        tampered_state.protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "protocol_parameters set to ONE (same-epoch: must carry prev.protocol_parameters unchanged)",
        );
    }

    #[test]
    fn circuit_rejects_epoch_advance_in_same_epoch_step() {
        // MockProver constraint check: in a same-epoch transition the circuit must keep
        // current_epoch equal to prev_state.current_epoch. Incrementing it violates that constraint.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (message, preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, message);
        tampered_state.current_epoch = EpochNumber::new(tampered_state.current_epoch.as_u64() + 1);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "current_epoch incremented (same-epoch: must equal prev.current_epoch)",
        );
    }
}
