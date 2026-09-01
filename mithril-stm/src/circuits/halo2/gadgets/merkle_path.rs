use midnight_circuits::instructions::{
    AssertionInstructions, ControlFlowInstructions, EccInstructions, ZeroInstructions,
};
use midnight_circuits::types::{AssignedBit, AssignedNative, AssignedNativePoint};
use midnight_proofs::circuit::Layouter;
use midnight_zk_stdlib::ZkStdLib;

use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};

/// Assigned inputs required to verify one Merkle authentication path inside the circuit.
pub(crate) struct MerklePathInputs<'a> {
    /// Assigned verification key stored in the Merkle leaf.
    pub(crate) verification_key: &'a AssignedNativePoint<CircuitCurve>,
    /// Assigned lottery target value stored in the Merkle leaf.
    pub(crate) lottery_target_value: &'a AssignedNative<CircuitBase>,
    /// Assigned public Merkle root committed by the statement.
    pub(crate) merkle_tree_commitment: &'a AssignedNative<CircuitBase>,
    /// Assigned sibling hashes for each Merkle path level.
    pub(crate) merkle_siblings: &'a [AssignedNative<CircuitBase>],
    /// Assigned sibling positions for each Merkle path level.
    pub(crate) merkle_positions: &'a [AssignedBit<CircuitBase>],
    /// Expected Merkle tree depth, used for error reporting on empty paths.    
    pub(crate) merkle_tree_depth: u32,
}

/// Verifies that the assigned Merkle path opens the witness leaf to the public commitment.
pub(crate) fn verify_merkle_path(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<CircuitBase>,
    inputs: MerklePathInputs<'_>,
) -> Result<(), CertificateCircuitError> {
    let verification_key_x = std_lib.jubjub().x_coordinate(inputs.verification_key);
    let verification_key_y = std_lib.jubjub().y_coordinate(inputs.verification_key);
    let leaf = std_lib.poseidon(
        layouter,
        &[
            verification_key_x.clone(),
            verification_key_y.clone(),
            inputs.lottery_target_value.clone(),
        ],
    )?;

    // Compute the root of the merkle tree by ignoring the padding of 0 values
    // present in the merkle path.
    //
    // Example: A merkle tree of depth 2 with merkle path padded to depth 3
    //
    // Regular merkle tree of depth 2, the letter represent the hash of the leaves
    //
    //          root = H(H(A,B), H(C,H(0)))
    //         /    \
    //      H(A,B)   H(C,H(0))
    //      /   \   /
    //     A     B C
    //
    // In this context, the regular merkle path of C is: [H(0), H(A,B)]
    //
    // Padded merkle tree representation to a depth 3
    //
    //             fake root (never computed)
    //             /       \
    //            /         \
    //          root         0
    //         /    \
    //      H(A,B)   H(C,H(0))
    //      /   \   /
    //     A     B C
    //
    // In this context, the merkle path of C is: [H(0), H(A,B), 0]. This process can be
    // extended to any arbitrary depth.
    //
    //  During the computation of the root, the values 0 are ignored in the accumulator
    // so the final result is the root of the original merkle tree.
    //
    // The first sibling can never be padding so there is not need to check for a 0 value.
    // This saves a few constraints per loop.
    let first_sibling = inputs.merkle_siblings.first().ok_or(
        CertificateCircuitError::MerkleSiblingLengthMismatch {
            expected_depth: inputs.merkle_tree_depth,
            actual: 0,
        },
    )?;
    let first_position = inputs.merkle_positions.first().ok_or(
        CertificateCircuitError::MerklePositionLengthMismatch {
            expected_depth: inputs.merkle_tree_depth,
            actual: 0,
        },
    )?;
    let first_left = std_lib.select(layouter, first_position, &leaf, first_sibling)?;
    let first_right = std_lib.select(layouter, first_position, first_sibling, &leaf)?;
    let first_node = std_lib.poseidon(layouter, &[first_left, first_right])?;

    let root = inputs
        .merkle_siblings
        .iter()
        .skip(1)
        .zip(inputs.merkle_positions.iter().skip(1))
        .try_fold(first_node, |acc, (x, pos)| {
            let left = std_lib.select(layouter, pos, &acc, x)?;
            let right = std_lib.select(layouter, pos, x, &acc)?;
            let current_node = std_lib.poseidon(layouter, &[left, right])?;

            let is_zero = std_lib.is_zero(layouter, x)?;
            std_lib.select(layouter, &is_zero, &acc, &current_node)
        })?;

    std_lib
        .assert_equal(layouter, &root, inputs.merkle_tree_commitment)
        .map_err(CertificateCircuitError::from)
}

#[cfg(test)]
mod tests {
    use midnight_circuits::instructions::{AssignmentInstructions, ConversionInstructions};
    use midnight_proofs::plonk::Error;

    use crate::circuits::common::merkle::Position;
    use crate::circuits::halo2::errors::CertificateCircuitError;
    use crate::circuits::halo2::tests::test_helpers::{
        TEST_MERKLE_TREE_DEPTH, TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING, assert_relation_rejected,
        impl_focused_test_relation, jubjub_poseidon_used_chips, prove_and_verify_relation,
        sample_valid_circuit_witness_entry,
    };
    use crate::circuits::halo2::types::{CircuitBase, CircuitBaseField};
    use crate::circuits::halo2::witness::{CircuitWitnessEntry, MerkleRoot};

    use super::{MerklePathInputs, verify_merkle_path};

    impl_focused_test_relation!(
        MerkleRelation,
        (CircuitWitnessEntry, MerkleRoot),
        error = CertificateCircuitError,
        jubjub_poseidon_used_chips(),
        |std_lib, layouter, witness| {
            let verification_key = std_lib.jubjub().assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| entry.leaf.verification_key_point().0),
            )?;
            let lottery_target_value = std_lib.assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| entry.leaf.lottery_target_value().into()),
            )?;
            let merkle_tree_commitment = std_lib.assign(
                layouter,
                witness.clone().map(|(_, commitment)| commitment.into()),
            )?;
            let merkle_siblings = std_lib.assign_many(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| {
                        entry
                            .merkle_path
                            .siblings
                            .iter()
                            .map(|(_, sibling)| (*sibling).into())
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(TEST_MERKLE_TREE_DEPTH)
                    .as_slice(),
            )?;
            let merkle_positions = std_lib.assign_many(
                layouter,
                witness
                    .map(|(entry, _)| {
                        entry
                            .merkle_path
                            .siblings
                            .iter()
                            .map(|(position, _)| CircuitBase::from(*position))
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(TEST_MERKLE_TREE_DEPTH)
                    .as_slice(),
            )?;
            let merkle_positions = merkle_positions
                .iter()
                .map(|position| std_lib.convert(layouter, position))
                .collect::<Result<Vec<_>, Error>>()?;

            verify_merkle_path(
                std_lib,
                layouter,
                MerklePathInputs {
                    verification_key: &verification_key,
                    lottery_target_value: &lottery_target_value,
                    merkle_tree_commitment: &merkle_tree_commitment,
                    merkle_siblings: &merkle_siblings,
                    merkle_positions: &merkle_positions,
                    merkle_tree_depth: TEST_MERKLE_TREE_DEPTH as u32,
                },
            )
        }
    );

    impl_focused_test_relation!(
        MerklePathRelation,
        (CircuitWitnessEntry, MerkleRoot),
        error = CertificateCircuitError,
        jubjub_poseidon_used_chips(),
        |std_lib, layouter, witness| {
            let verification_key = std_lib.jubjub().assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| entry.leaf.verification_key_point().0),
            )?;
            let lottery_target_value = std_lib.assign(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| entry.leaf.lottery_target_value().into()),
            )?;
            let merkle_tree_commitment = std_lib.assign(
                layouter,
                witness.clone().map(|(_, commitment)| commitment.into()),
            )?;
            let merkle_siblings = std_lib.assign_many(
                layouter,
                witness
                    .clone()
                    .map(|(entry, _)| {
                        entry
                            .merkle_path
                            .siblings
                            .iter()
                            .map(|(_, sibling)| (*sibling).into())
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING)
                    .as_slice(),
            )?;
            let merkle_positions = std_lib.assign_many(
                layouter,
                witness
                    .map(|(entry, _)| {
                        entry
                            .merkle_path
                            .siblings
                            .iter()
                            .map(|(position, _)| CircuitBase::from(*position))
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING)
                    .as_slice(),
            )?;
            let merkle_positions = merkle_positions
                .iter()
                .map(|position| std_lib.convert(layouter, position))
                .collect::<Result<Vec<_>, Error>>()?;

            verify_merkle_path(
                std_lib,
                layouter,
                MerklePathInputs {
                    verification_key: &verification_key,
                    lottery_target_value: &lottery_target_value,
                    merkle_tree_commitment: &merkle_tree_commitment,
                    merkle_siblings: &merkle_siblings,
                    merkle_positions: &merkle_positions,
                    merkle_tree_depth: TEST_MERKLE_TREE_DEPTH as u32,
                },
            )
        }
    );

    #[test]
    fn merkle_path_accepts_valid_witness_entry() {
        let relation = MerkleRelation;
        let (entry, merkle_tree_commitment, _) =
            sample_valid_circuit_witness_entry(TEST_MERKLE_TREE_DEPTH as u32)
                .expect("merkle_path_accepts_valid_witness_entry should build fixture");

        prove_and_verify_relation(&relation, &(), (entry, merkle_tree_commitment))
            .expect("merkle_path_accepts_valid_witness_entry should succeed");
    }

    #[test]
    fn merkle_path_rejects_wrong_merkle_tree_commitment() {
        let relation = MerkleRelation;
        let (entry, _, _) = sample_valid_circuit_witness_entry(TEST_MERKLE_TREE_DEPTH as u32)
            .expect("merkle_path_rejects_wrong_merkle_tree_commitment should build fixture");

        assert_relation_rejected(prove_and_verify_relation(
            &relation,
            &(),
            (entry, MerkleRoot::from(999u64)),
        ));
    }

    #[test]
    fn merkle_path_accepts_padding() {
        let relation = MerklePathRelation;

        let (entry, merkle_tree_commitment, _) =
            sample_valid_circuit_witness_entry(TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING as u32)
                .expect("merkle_path_rejects_wrong_merkle_tree_commitment should build fixture");
        assert_eq!(
            entry.merkle_path.siblings.last().unwrap(),
            &(Position::Right, CircuitBaseField::ZERO),
            "The last element of the siblings should be a zero padding"
        );

        prove_and_verify_relation(&relation, &(), (entry.clone(), merkle_tree_commitment))
            .expect("merkle_path_accepts_valid_witness_entry should succeed");
    }

    #[test]
    fn merkle_path_rejects_wrong_padding() {
        let relation = MerklePathRelation;
        let (mut entry, _, _) =
            sample_valid_circuit_witness_entry(TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING as u32)
                .expect("merkle_path_rejects_wrong_merkle_tree_commitment should build fixture");

        let sibling_length = entry.merkle_path.siblings.len();
        entry.merkle_path.siblings[sibling_length - 1] = (Position::Right, CircuitBaseField::ONE);

        assert_relation_rejected(prove_and_verify_relation(
            &relation,
            &(),
            (entry, MerkleRoot::from(999u64)),
        ));
    }
}
