use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib as zk_lib;
use midnight_zk_stdlib::Relation;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::circuits::common::merkle::MerklePath;
use crate::circuits::halo2::circuit::CertificateCircuit;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::halo2::types::CircuitBaseField;
use crate::circuits::halo2::witness::{CircuitMerkleTreeLeaf, CircuitWitnessEntry};
use crate::circuits::halo2_ivc::accumulator::fixed_bases_and_names_from_verifying_key;
use crate::circuits::halo2_ivc::protocol_message::{
    DynamicProtocolMessagePartKey, ProtocolMessage,
};
use crate::circuits::halo2_ivc::state::{State, Witness};
use crate::circuits::halo2_ivc::types::{
    CertificateProofBytes, EpochNumber, MerkleTreeCommitment, MessageHash, ProtocolMessagePreimage,
    ProtocolParametersHash, StepCounter,
};
use crate::circuits::halo2_ivc::{
    Accumulator, CERTIFICATE_FIXED_BASES_PREFIX, NativeField, PREIMAGE_SIZE, RecursiveEmulation,
};
use crate::signature_scheme::{
    BaseFieldElement, SchnorrVerificationKey as StmSchnorrVerificationKey,
};
use crate::{AggregateVerificationKeyForSnark, MithrilMembershipDigest};

use super::super::field_encoding::jubjub_base_from_raw_le_bytes;
use super::proofs::verify_prepare_poseidon_ivc;
use super::setup::{AssetGenerationSetup, GENESIS_EPOCH, QUORUM_SIZE};

/// Builds the genesis protocol message whose hash becomes `setup.genesis_message`.
///
/// This is the same genesis message shape used by the asset generators and the
/// recursive base-case path, so future tests can reuse it without re-encoding
/// the protocol-message layout by hand.
pub(super) fn build_genesis_protocol_message(
    aggregate_verification_key: &AggregateVerificationKeyForSnark<MithrilMembershipDigest>,
    protocol_parameters: [u8; 32],
    genesis_epoch: u64,
) -> ProtocolMessage {
    let mut protocol_message = ProtocolMessage::new();
    protocol_message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode([2u8; 32]),
    );
    protocol_message
        .set_next_snark_aggregate_verification_key(aggregate_verification_key)
        .expect("aggregate verification key rigid slot should be produced");
    protocol_message.set_next_protocol_parameters(protocol_parameters);
    protocol_message.set_current_epoch(genesis_epoch);
    protocol_message
}

/// Returns the raw genesis protocol-message preimage bytes produced by the serializer.
pub(crate) fn build_genesis_protocol_message_preimage(setup: &AssetGenerationSetup) -> Vec<u8> {
    build_genesis_protocol_message(
        &setup.aggregate_verification_key,
        setup.genesis_next_protocol_parameters.to_bytes_le(),
        GENESIS_EPOCH,
    )
    .try_rigid_preimage()
    .expect("genesis protocol message preimage should succeed")
    .to_vec()
}

/// Builds the witness used by the recursive genesis/base-case branch.
pub(crate) fn build_genesis_base_case_witness(setup: &AssetGenerationSetup) -> Witness {
    let preimage: [u8; PREIMAGE_SIZE] = build_genesis_protocol_message_preimage(setup)
        .try_into()
        .expect("genesis protocol message preimage should be PREIMAGE_SIZE bytes");
    Witness::new(
        setup.genesis_signature,
        MessageHash::ZERO,
        MerkleTreeCommitment::ZERO,
        ProtocolMessagePreimage::new(preimage),
    )
}

/// Builds the first next-state public output produced by the recursive base case.
pub(crate) fn build_genesis_base_case_next_state(
    setup: &AssetGenerationSetup,
    genesis_epoch: u64,
) -> State {
    State::new(
        StepCounter::new(1),
        setup.genesis_message,
        MerkleTreeCommitment::ZERO,
        MerkleTreeCommitment::from_field(setup.genesis_next_merkle_tree_commitment),
        ProtocolParametersHash::ZERO,
        ProtocolParametersHash::from_field(setup.genesis_next_protocol_parameters),
        EpochNumber::new(genesis_epoch),
    )
}

/// Builds the fresh certificate-side data for one normal non-genesis recursive step.
pub(crate) fn build_next_certificate_asset_data(
    setup: &AssetGenerationSetup,
    certificate_commitment_parameters: &ParamsKZG<Bls12>,
    certificate_relation: &CertificateCircuit,
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
    recursive_chain_state: &State,
    random_generator: &mut (impl RngCore + CryptoRng),
) -> (
    CertificateProofBytes,
    Accumulator<RecursiveEmulation>,
    State,
    Witness,
) {
    let merkle_tree_commitment = recursive_chain_state.next_merkle_tree_commitment.as_field();
    let (message, message_preimage) =
        next_message_and_preimage_for_step(setup, recursive_chain_state);
    let next_state = next_state_for_step(recursive_chain_state, message);
    build_certificate_asset_data_inner(
        setup,
        certificate_commitment_parameters,
        certificate_relation,
        certificate_verifying_key,
        merkle_tree_commitment,
        message,
        message_preimage,
        next_state,
        random_generator,
    )
}

/// Builds the fresh certificate-side data for one same-epoch recursive step.
pub(crate) fn build_same_epoch_certificate_asset_data(
    setup: &AssetGenerationSetup,
    certificate_commitment_parameters: &ParamsKZG<Bls12>,
    certificate_relation: &CertificateCircuit,
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
    recursive_chain_state: &State,
    random_generator: &mut (impl RngCore + CryptoRng),
) -> (
    CertificateProofBytes,
    Accumulator<RecursiveEmulation>,
    State,
    Witness,
) {
    let merkle_tree_commitment = recursive_chain_state.merkle_tree_commitment.as_field();
    let (message, message_preimage) =
        same_epoch_message_and_preimage_for_step(setup, recursive_chain_state);
    let next_state = same_epoch_next_state_for_step(recursive_chain_state, message);
    build_certificate_asset_data_inner(
        setup,
        certificate_commitment_parameters,
        certificate_relation,
        certificate_verifying_key,
        merkle_tree_commitment,
        message,
        message_preimage,
        next_state,
        random_generator,
    )
}

/// Shared inner implementation for building certificate asset data.
///
/// `merkle_tree_commitment`, `message`, `message_preimage`, and `next_state` are
/// pre-computed by the caller according to the transition type. The signing
/// loop and proof generation are identical for next-epoch and same-epoch steps.
#[allow(clippy::too_many_arguments)]
fn build_certificate_asset_data_inner(
    setup: &AssetGenerationSetup,
    certificate_commitment_parameters: &ParamsKZG<Bls12>,
    certificate_relation: &CertificateCircuit,
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
    merkle_tree_commitment: NativeField,
    message: NativeField,
    message_preimage: Vec<u8>,
    next_state: State,
    random_generator: &mut (impl RngCore + CryptoRng),
) -> (
    CertificateProofBytes,
    Accumulator<RecursiveEmulation>,
    State,
    Witness,
) {
    let certificate_proving_key = zk_lib::setup_pk(
        certificate_relation,
        certificate_verifying_key.midnight_vk(),
    );
    let (certificate_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
        CERTIFICATE_FIXED_BASES_PREFIX,
        certificate_verifying_key.as_ref(),
    );

    assert_eq!(
        merkle_tree_commitment, setup.genesis_next_merkle_tree_commitment,
        "merkle_tree_commitment does not match deterministic setup root"
    );

    let mut certificate_witness_entries: Vec<CircuitWitnessEntry> = vec![];
    for j in 0..QUORUM_SIZE as usize {
        let unique_schnorr_signature = setup.signing_keys[j]
            .sign_unique(
                &[
                    BaseFieldElement::from(merkle_tree_commitment),
                    BaseFieldElement::from(message),
                ],
                random_generator,
            )
            .expect("certificate witness signature should not fail");
        let leaf = setup.merkle_tree_leaves[j];
        let stm_path = setup
            .merkle_tree
            .compute_merkle_tree_path_fixed_length(j, certificate_relation.merkle_tree_depth());
        setup
            .merkle_tree
            .to_merkle_tree_commitment()
            .verify_leaf_membership_from_path(&leaf, &stm_path)
            .unwrap_or_else(|_| panic!("STM Merkle path should verify for signer index {j}"));
        let schnorr_vk =
            StmSchnorrVerificationKey::new_from_signing_key(setup.signing_keys[j].clone());
        assert_eq!(
            schnorr_vk, leaf.0,
            "STM leaf verification key mismatch for signer index {j}"
        );
        unique_schnorr_signature
            .verify(
                &[
                    BaseFieldElement::from(merkle_tree_commitment),
                    BaseFieldElement::from(message),
                ],
                &schnorr_vk,
            )
            .expect("fresh certificate signature should verify");
        let circuit_merkle_path = MerklePath::try_from(&stm_path)
            .expect("STM Merkle path should adapt to the circuit witness path");
        let circuit_leaf = CircuitMerkleTreeLeaf(schnorr_vk, CircuitBaseField::from(leaf.1));
        certificate_witness_entries.push(CircuitWitnessEntry {
            leaf: circuit_leaf,
            merkle_path: circuit_merkle_path,
            unique_schnorr_signature,
            lottery_index: (j + 1) as u64,
        });
    }

    let certificate_instance =
        certificate_public_inputs(merkle_tree_commitment, next_state.message.as_field());

    let certificate_proof = CertificateProofBytes::from_certificate_circuit_proof_bytes(
        zk_lib::prove::<CertificateCircuit, PoseidonState<NativeField>>(
            certificate_commitment_parameters,
            &certificate_proving_key,
            certificate_relation,
            &(
                CircuitBaseField::from(certificate_instance[0]),
                CircuitBaseField::from(certificate_instance[1]),
            ),
            certificate_witness_entries,
            random_generator,
        )
        .expect("Certificate proof generation should not fail"),
    );

    let certificate_dual_msm = verify_prepare_poseidon_ivc(
        certificate_verifying_key.as_ref(),
        certificate_proof.as_bytes(),
        &certificate_instance,
    );
    assert!(
        certificate_dual_msm
            .clone()
            .check(&certificate_commitment_parameters.verifier_params())
    );
    let mut certificate_accumulator: Accumulator<RecursiveEmulation> = Accumulator::from_dual_msm(
        certificate_dual_msm,
        CERTIFICATE_FIXED_BASES_PREFIX,
        &certificate_fixed_bases,
    );

    certificate_accumulator.collapse();

    let ivc_witness = Witness::new(
        setup.genesis_signature,
        MessageHash::from_field(message),
        MerkleTreeCommitment::from_field(merkle_tree_commitment),
        ProtocolMessagePreimage::new(message_preimage.try_into().unwrap()),
    );

    (
        certificate_proof,
        certificate_accumulator,
        next_state,
        ivc_witness,
    )
}

/// Formats a `(merkle_tree_commitment, message)` pair as certificate public inputs.
pub(super) fn certificate_public_inputs(
    merkle_tree_commitment: NativeField,
    message: NativeField,
) -> Vec<NativeField> {
    CertificateCircuit::format_instance(&(
        CircuitBaseField::from(merkle_tree_commitment),
        CircuitBaseField::from(message),
    ))
    .unwrap()
}

/// Returns the certificate public inputs for one recursive-step transition.
pub(crate) fn certificate_public_inputs_for_step(
    previous_state: &State,
    next_state: &State,
) -> Vec<NativeField> {
    certificate_public_inputs(
        previous_state.next_merkle_tree_commitment.as_field(),
        next_state.message.as_field(),
    )
}

/// Returns the deterministic next certificate message and preimage for one
/// non-genesis recursive step.
pub(crate) fn next_message_and_preimage_for_step(
    setup: &AssetGenerationSetup,
    previous_state: &State,
) -> (NativeField, Vec<u8>) {
    let current_epoch = current_epoch_from_state(previous_state);
    let step = step_index_from_state(previous_state);

    let mut protocol_message = ProtocolMessage::new();
    protocol_message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode(vec![(step as u8) + 2; 32]),
    );
    protocol_message
        .set_next_snark_aggregate_verification_key(&setup.aggregate_verification_key)
        .expect("aggregate verification key rigid slot should be produced");
    protocol_message
        .set_next_protocol_parameters(setup.genesis_next_protocol_parameters.to_bytes_le());
    protocol_message.set_current_epoch(current_epoch + 1);

    let preimage = protocol_message
        .try_rigid_preimage()
        .expect("protocol message preimage should succeed");
    let message_hash = Sha256::digest(preimage);
    (
        jubjub_base_from_raw_le_bytes(message_hash.as_ref()),
        preimage.to_vec(),
    )
}

/// Returns the deterministic certificate message and preimage for one
/// same-epoch recursive step.
pub(crate) fn same_epoch_message_and_preimage_for_step(
    setup: &AssetGenerationSetup,
    previous_state: &State,
) -> (NativeField, Vec<u8>) {
    let current_epoch = current_epoch_from_state(previous_state);
    let step = step_index_from_state(previous_state);

    let mut protocol_message = ProtocolMessage::new();
    protocol_message.set_dynamic_message_part(
        DynamicProtocolMessagePartKey::SnapshotDigest,
        hex::encode(vec![(step as u8) + 2; 32]),
    );
    protocol_message
        .set_next_snark_aggregate_verification_key(&setup.aggregate_verification_key)
        .expect("aggregate verification key rigid slot should be produced");
    protocol_message
        .set_next_protocol_parameters(setup.genesis_next_protocol_parameters.to_bytes_le());
    protocol_message.set_current_epoch(current_epoch);

    let preimage = protocol_message
        .try_rigid_preimage()
        .expect("protocol message preimage should succeed");
    let message_hash = Sha256::digest(preimage);
    (
        jubjub_base_from_raw_le_bytes(message_hash.as_ref()),
        preimage.to_vec(),
    )
}

/// Returns the recursive next state for a non-genesis step once the next
/// certificate message has been fixed.
pub(crate) fn next_state_for_step(previous_state: &State, message: NativeField) -> State {
    let current_epoch = current_epoch_from_state(previous_state);
    let step = step_index_from_state(previous_state);

    State::new(
        StepCounter::new((step + 1) as u64),
        MessageHash::from_field(message),
        previous_state.next_merkle_tree_commitment,
        previous_state.next_merkle_tree_commitment,
        previous_state.next_protocol_parameters,
        previous_state.next_protocol_parameters,
        EpochNumber::new(current_epoch + 1),
    )
}

/// Returns the recursive next state for a same-epoch step.
pub(crate) fn same_epoch_next_state_for_step(
    previous_state: &State,
    message: NativeField,
) -> State {
    let current_epoch = current_epoch_from_state(previous_state);
    let step = step_index_from_state(previous_state);

    State::new(
        StepCounter::new((step + 1) as u64),
        MessageHash::from_field(message),
        previous_state.merkle_tree_commitment,
        previous_state.next_merkle_tree_commitment,
        previous_state.protocol_parameters,
        previous_state.next_protocol_parameters,
        EpochNumber::new(current_epoch),
    )
}

fn current_epoch_from_state(previous_state: &State) -> u64 {
    previous_state.current_epoch.as_u64()
}

fn step_index_from_state(previous_state: &State) -> usize {
    previous_state.step_counter.as_u64() as usize
}
