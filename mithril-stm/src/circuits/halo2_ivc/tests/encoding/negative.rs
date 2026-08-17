//! Negative encoding tests: tampered public inputs (fast CI) and MockProver
//! constraint checks (in `mod slow`).

use ff::Field;
use midnight_circuits::types::Instantiable;

use crate::circuits::halo2_ivc::{
    AssignedAccumulator, NativeField, PREIMAGE_CURRENT_EPOCH_BYTES,
    PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES, PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES,
    protocol_message::{DynamicProtocolMessagePartKey, ProtocolMessage},
    state::State,
    tests::common::{
        asset_readers::{
            load_embedded_next_epoch_step_output_asset, load_embedded_verification_context_asset,
        },
        generators::{
            GENESIS_EPOCH, build_asset_generation_setup_from_cache,
            build_genesis_base_case_next_state, build_genesis_base_case_witness,
        },
        helpers::{
            assert_recursive_mock_prover_rejects_with_label, build_mock_prover_public_inputs,
            build_mock_prover_setup_from_assets, build_trivial_mock_prover_circuit,
            verify_prepare_blake2b_recursive_proof,
        },
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
    use super::*;

    #[test]
    fn circuit_rejects_wrong_next_merkle_tree_commitment_byte_range() {
        // MockProver constraint check: filling PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES with 0xff
        // must violate the in-circuit byte-extraction constraint for that preimage region.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &next_state);

        let mut witness = build_genesis_base_case_witness(&setup);
        witness.message_preimage.as_mut_bytes()[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES]
            .fill(0xff);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, State::genesis(), witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "message_preimage[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES] filled with 0xff",
        );
    }

    #[test]
    fn circuit_rejects_wrong_next_protocol_parameters_byte_range() {
        // MockProver constraint check: filling PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES with 0xff
        // must violate the in-circuit byte-extraction constraint for that preimage region.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &next_state);

        let mut witness = build_genesis_base_case_witness(&setup);
        witness.message_preimage.as_mut_bytes()[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES].fill(0xff);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, State::genesis(), witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "message_preimage[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES] filled with 0xff",
        );
    }

    #[test]
    fn circuit_rejects_wrong_current_epoch_byte_range() {
        // MockProver constraint check: filling PREIMAGE_CURRENT_EPOCH_BYTES with 0xff
        // must violate the in-circuit byte-extraction constraint for that preimage region.
        let setup = build_asset_generation_setup_from_cache();
        let mock_prover_setup = build_mock_prover_setup_from_assets(&setup);
        let next_state = build_genesis_base_case_next_state(&setup, GENESIS_EPOCH);
        let public_inputs = build_mock_prover_public_inputs(&mock_prover_setup, &next_state);

        let mut witness = build_genesis_base_case_witness(&setup);
        witness.message_preimage.as_mut_bytes()[PREIMAGE_CURRENT_EPOCH_BYTES].fill(0xff);
        let ivc_circuit_data =
            build_trivial_mock_prover_circuit(&mock_prover_setup, State::genesis(), witness);
        assert_recursive_mock_prover_rejects_with_label(
            ivc_circuit_data,
            public_inputs,
            "message_preimage[PREIMAGE_CURRENT_EPOCH_BYTES] filled with 0xff",
        );
    }
}
