//! Negative encoding tests: tampered public inputs (fast CI) and MockProver
//! constraint checks (in `mod slow`).

use ff::Field;
use midnight_circuits::types::Instantiable;

use crate::circuits::halo2_ivc::{
    AssignedAccumulator, NativeField, PREIMAGE_CURRENT_EPOCH_BYTES,
    PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES, PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES,
    circuit::IvcCircuitData,
    protocol_message::{DynamicProtocolMessagePartKey, ProtocolMessage},
    state::State,
    tests::common::{
        asset_readers::{
            load_embedded_next_epoch_step_output_asset, load_embedded_verification_context_asset,
        },
        failure_signature::assert_recursive_mock_prover_rejects_public_input_rows,
        generators::{
            AssetGenerationSetup, GENESIS_EPOCH, build_asset_generation_setup_from_cache,
            build_genesis_base_case_next_state, build_genesis_base_case_witness,
        },
        helpers::MockProverSetup,
        helpers::{
            build_genesis_mock_prover_circuit, build_genesis_mock_prover_public_inputs,
            build_mock_prover_setup_from_assets, verify_prepare_blake2b_recursive_proof,
        },
        public_input_layout::StateField,
    },
    types::{EpochNumber, MerkleTreeCommitment, ProtocolParametersHash},
};
use crate::{AggregateVerificationKeyForSnark, MithrilMembershipDigest};

fn valid_snark_aggregate_verification_key()
-> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
    let mut avk_input = [0u8; 40];
    avk_input[39] = 1;
    AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_input)
        .expect("valid test aggregate verification key should decode")
}

fn assert_rigid_preimage_rejects_with_message(message: ProtocolMessage, expected: &str) {
    let error = message
        .try_rigid_preimage()
        .expect_err("rigid preimage should reject invalid message");

    assert!(
        error.to_string().contains(expected),
        "expected error to contain `{expected}`, got `{error}`"
    );
}

#[test]
fn rigid_preimage_rejects_missing_next_snark_aggregate_verification_key() {
    let mut message = ProtocolMessage::new();
    message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode([2u8; 32]),
    );
    message.set_next_protocol_parameters([7u8; 32]);
    message.set_current_epoch(42);

    assert_rigid_preimage_rejects_with_message(
        message,
        "next SNARK aggregate verification key slot is required",
    );
}

#[test]
fn rigid_preimage_rejects_missing_next_protocol_parameters() {
    let mut message = ProtocolMessage::new();
    message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode([2u8; 32]),
    );
    message
        .set_next_snark_aggregate_verification_key(&valid_snark_aggregate_verification_key())
        .expect("test aggregate verification key should project to rigid slot");
    message.set_current_epoch(42);

    assert_rigid_preimage_rejects_with_message(
        message,
        "next protocol parameters slot is required",
    );
}

#[test]
fn rigid_preimage_rejects_missing_current_epoch() {
    let mut message = ProtocolMessage::new();
    message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode([2u8; 32]),
    );
    message
        .set_next_snark_aggregate_verification_key(&valid_snark_aggregate_verification_key())
        .expect("test aggregate verification key should project to rigid slot");
    message.set_next_protocol_parameters([7u8; 32]);

    assert_rigid_preimage_rejects_with_message(message, "current epoch slot is required");
}

#[test]
fn next_merkle_tree_commitment_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when
    // next_merkle_tree_commitment is replaced in the public inputs, confirming the field
    // extracted from PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES is enforced as a public input.
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");

    let mut tampered_state = recursive_step_output.next_state.clone();
    tampered_state.next_merkle_tree_commitment = MerkleTreeCommitment::from_field(NativeField::ONE);

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        tampered_state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_step_output.next_accumulator),
    ]
    .concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        recursive_step_output.ivc_proof.as_bytes(),
        &public_inputs,
    );

    assert!(
        !dual_msm.check(&verification_context.verifier_params),
        "proof with tampered next_merkle_tree_commitment should be rejected by the verifier"
    );
}

#[test]
fn next_protocol_parameters_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when
    // next_protocol_parameters is replaced in the public inputs, confirming the
    // field extracted from PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES is enforced as a public input.
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");

    let mut tampered_state = recursive_step_output.next_state.clone();
    tampered_state.next_protocol_parameters = ProtocolParametersHash::from_field(NativeField::ONE);

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        tampered_state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_step_output.next_accumulator),
    ]
    .concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        recursive_step_output.ivc_proof.as_bytes(),
        &public_inputs,
    );

    assert!(
        !dual_msm.check(&verification_context.verifier_params),
        "proof with tampered next_protocol_parameters should be rejected by the verifier"
    );
}

#[test]
fn current_epoch_tampered_public_input_is_rejected() {
    // Asset-based check that the verifier rejects a stored proof when
    // current_epoch is replaced in the public inputs, confirming the field
    // extracted from PREIMAGE_CURRENT_EPOCH_BYTES is enforced as a public input.
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");

    let mut tampered_state = recursive_step_output.next_state.clone();
    tampered_state.current_epoch = EpochNumber::from_field(NativeField::ONE);

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        tampered_state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_step_output.next_accumulator),
    ]
    .concat();

    let dual_msm = verify_prepare_blake2b_recursive_proof(
        verification_context.recursive_verifying_key.as_ref(),
        recursive_step_output.ivc_proof.as_bytes(),
        &public_inputs,
    );

    assert!(
        !dual_msm.check(&verification_context.verifier_params),
        "proof with tampered current_epoch should be rejected by the verifier"
    );
}

mod slow {
    use std::collections::BTreeMap;
    use std::ops::Range;

    use super::*;

    /// Preimage byte mutated to break the message equality without moving any extracted field.
    ///
    /// It falls inside the dynamic-parts digest, which the circuit hashes but never decodes.
    const MESSAGE_EQUALITY_TAMPER_OFFSET: usize = 6;

    /// Flips the byte at `offset` in the genesis witness preimage and returns the resulting circuit.
    ///
    /// The mutation is an exclusive-or so it cannot land on the value already there, and it touches
    /// a single byte, so at most the one decoded field that byte feeds can move.
    fn build_genesis_circuit_with_flipped_preimage_byte(
        setup: &AssetGenerationSetup,
        mock_prover_setup: &MockProverSetup,
        offset: usize,
    ) -> IvcCircuitData {
        let mut witness = build_genesis_base_case_witness(setup);
        witness.message_preimage.as_mut_bytes()[offset] ^= 0xff;
        build_genesis_mock_prover_circuit(mock_prover_setup, State::genesis(), witness)
    }

    /// Asserts that flipping the first byte of `range` breaks exactly the message equality and
    /// `field`'s public-input binding.
    ///
    /// Any change to the preimage invalidates the whole-preimage hash. In the current layout that
    /// inconsistent equality class reports the message row, and `field` is the one decoded value the
    /// byte window feeds.
    fn assert_flipped_range_breaks_message_and_field(range: Range<usize>, field: StateField) {
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let public_inputs =
            build_genesis_mock_prover_public_inputs(&mock_prover_setup, &next_state);
        let ivc_circuit_data = build_genesis_circuit_with_flipped_preimage_byte(
            &setup,
            &mock_prover_setup,
            range.start,
        );

        assert_recursive_mock_prover_rejects_public_input_rows(
            ivc_circuit_data,
            public_inputs,
            &BTreeMap::from([
                (StateField::Message.row(), StateField::Message.name()),
                (field.row(), field.name()),
            ]),
        );
    }

    #[test]
    fn circuit_rejects_wrong_next_merkle_tree_commitment_byte_range() {
        // Flipping a byte here invalidates the whole-preimage hash and changes exactly the next
        // Merkle-tree commitment. A different decoded row moving would mean the circuit reads the
        // wrong window.
        assert_flipped_range_breaks_message_and_field(
            PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
            StateField::NextMerkleTreeCommitment,
        );
    }

    #[test]
    fn circuit_rejects_wrong_next_protocol_parameters_byte_range() {
        // Same for the next protocol parameters.
        assert_flipped_range_breaks_message_and_field(
            PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES,
            StateField::NextProtocolParameters,
        );
    }

    #[test]
    fn circuit_rejects_wrong_current_epoch_byte_range() {
        // Same for the current epoch.
        assert_flipped_range_breaks_message_and_field(
            PREIMAGE_CURRENT_EPOCH_BYTES,
            StateField::CurrentEpoch,
        );
    }

    #[test]
    fn circuit_rejects_preimage_inconsistent_with_the_message() {
        // Isolates the message equality. The byte is outside every decoded range, so no decoded
        // state field changes and the public values are left untouched; the message row is reported
        // because, in the current layout, that equality class contains the cell bound to it.
        for range in [
            PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
            PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES,
            PREIMAGE_CURRENT_EPOCH_BYTES,
        ] {
            assert!(
                !range.contains(&MESSAGE_EQUALITY_TAMPER_OFFSET),
                "the tampered byte must sit outside every decoded range"
            );
        }

        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let public_inputs =
            build_genesis_mock_prover_public_inputs(&mock_prover_setup, &next_state);
        let ivc_circuit_data = build_genesis_circuit_with_flipped_preimage_byte(
            &setup,
            &mock_prover_setup,
            MESSAGE_EQUALITY_TAMPER_OFFSET,
        );

        assert_recursive_mock_prover_rejects_public_input_rows(
            ivc_circuit_data,
            public_inputs,
            &BTreeMap::from([(StateField::Message.row(), StateField::Message.name())]),
        );
    }
}
