//! Tests that the circuit correctly enforces constraints linking the witness,
//! current state, and next state for same-epoch transitions.
//!
//! All tests are slow MockProver checks confirming the arithmetic constraint
//! wiring for the following in-circuit invariants:
//!
//! `next_merkle_tree_commitment` consistency    — must equal `prev_state.next_merkle_tree_commitment`.
//! `next_protocol_parameters` consistency — must equal `prev_state.next_protocol_parameters`.
//! `message = Blake2b(preimage)`          — must equal the Blake2b hash of the message preimage.
//!
//! The `message = Blake2b(preimage)` constraint is the same gate for same-epoch and
//! next-epoch paths, so only the same-epoch witness is exercised here.

mod slow {
    use ff::Field;

    use crate::circuits::halo2_ivc::{
        NativeField,
        state::Witness,
        tests::common::{
            asset_readers::load_embedded_recursive_chain_state_asset,
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
            MerkleTreeCommitment, MessageHash, ProtocolMessagePreimage, ProtocolParametersHash,
        },
    };

    #[test]
    fn circuit_rejects_wrong_same_epoch_next_merkle_tree_commitment() {
        // MockProver constraint check: next_merkle_tree_commitment set to ONE must violate the
        // in-circuit constraint that pins it to prev_state.next_merkle_tree_commitment.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (same_epoch_message, same_epoch_message_preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(same_epoch_message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                same_epoch_message_preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, same_epoch_message);
        tampered_state.next_merkle_tree_commitment =
            MerkleTreeCommitment::from_field(NativeField::ONE);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state),
            "next_merkle_tree_commitment set to ONE (must equal prev_state.next_merkle_tree_commitment)",
        );
    }

    #[test]
    fn circuit_rejects_wrong_same_epoch_next_protocol_parameters() {
        // MockProver constraint check: next_protocol_parameters set to ONE must violate the
        // in-circuit constraint that pins it to prev_state.next_protocol_parameters.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (same_epoch_message, same_epoch_message_preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(same_epoch_message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                same_epoch_message_preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, same_epoch_message);
        tampered_state.next_protocol_parameters =
            ProtocolParametersHash::from_field(NativeField::ONE);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state),
            "next_protocol_parameters set to ONE (must equal prev_state.next_protocol_parameters)",
        );
    }

    #[test]
    fn circuit_rejects_wrong_same_epoch_msg_blake2b_constraint() {
        // MockProver constraint check: message set to ONE must violate the in-circuit
        // Blake2b constraint enforcing message = Blake2b(message_preimage). The same gate
        // is exercised by both same-epoch and next-epoch paths, so testing it once suffices.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let prev_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load")
            .state;
        let (same_epoch_message, same_epoch_message_preimage_bytes) =
            same_epoch_message_and_preimage_for_step(&setup, &prev_state);
        let witness = Witness::new(
            setup.genesis_signature,
            MessageHash::from_field(same_epoch_message),
            prev_state.merkle_tree_commitment,
            ProtocolMessagePreimage::new(
                same_epoch_message_preimage_bytes
                    .try_into()
                    .expect("same-epoch preimage should be PREIMAGE_SIZE bytes"),
            ),
        );
        let mut tampered_state = same_epoch_next_state_for_step(&prev_state, same_epoch_message);
        tampered_state.message = MessageHash::from_field(NativeField::ONE);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, prev_state, witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            build_mock_prover_public_inputs(&mock_prover_setup, &tampered_state),
            "message set to ONE (must equal Blake2b(message_preimage))",
        );
    }
}
