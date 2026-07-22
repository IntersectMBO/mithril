use std::marker::PhantomData;

use digest::{Digest, FixedOutput};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::codec;

use super::{
    MerkleBatchPath, MerkleTreeBatchCommitment, MerkleTreeError, MerkleTreeLeaf, left_child,
    parent, right_child, sibling,
};
#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
use super::{MerklePath, MerkleTreeCommitment};

/// Tree of hashes, providing a commitment of data and its ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree<D: Digest, L: MerkleTreeLeaf> {
    /// The nodes are stored in an array heap:
    /// * `nodes[0]` is the root,
    /// * the parent of `nodes[i]` is `nodes[(i-1)/2]`
    /// * the children of `nodes[i]` are `{nodes[2i + 1], nodes[2i + 2]}`
    /// * All nodes have size `Output<D>::output_size()`, even leafs (which are hashed before committing them).
    nodes: Vec<Vec<u8>>,
    /// The leaves begin at `nodes[leaf_off]`.
    leaf_off: usize,
    /// Number of leaves cached in the merkle tree.
    n: usize,
    /// Phantom type to link the tree with its hasher
    hasher: PhantomData<D>,
    /// Phantom type to link the tree with its leaves
    leaves: PhantomData<L>,
}

impl<D: Digest + FixedOutput, L: MerkleTreeLeaf> MerkleTree<D, L> {
    /// Provided a non-empty list of leaves, `create` generates its corresponding `MerkleTree`.
    pub(crate) fn new(leaves: &[L]) -> MerkleTree<D, L> {
        let n = leaves.len();
        assert!(n > 0, "MerkleTree::create() called with no leaves");

        let num_nodes = n + n.next_power_of_two() - 1;

        let mut nodes = vec![vec![0u8]; num_nodes];

        for i in 0..leaves.len() {
            nodes[num_nodes - n + i] = D::digest(leaves[i].as_bytes_for_merkle_tree()).to_vec();
        }

        let z = D::digest([0u8]).to_vec();
        for i in (0..num_nodes - n).rev() {
            let left = if left_child(i) < num_nodes {
                &nodes[left_child(i)]
            } else {
                &z
            };
            let right = if right_child(i) < num_nodes {
                &nodes[right_child(i)]
            } else {
                &z
            };
            nodes[i] = D::new().chain_update(left).chain_update(right).finalize().to_vec();
        }

        Self {
            nodes,
            n,
            leaf_off: num_nodes - n,
            hasher: PhantomData,
            leaves: PhantomData,
        }
    }

    /// Return the index of the leaf.
    fn get_leaf_index(&self, i: usize) -> usize {
        self.leaf_off + i
    }

    /// Convert merkle tree to a batch compatible commitment.
    /// This function simply returns the root and the number of leaves in the tree.
    pub(crate) fn to_merkle_tree_batch_commitment(&self) -> MerkleTreeBatchCommitment<D, L> {
        MerkleTreeBatchCommitment::new(self.nodes[0].clone(), self.n)
    }

    /// Get a path for a batch of leaves. The indices must be ordered. We use the Octopus algorithm to
    /// avoid redundancy with nodes in the path. Let `x1, . . . , xk` be the indices of elements we
    /// want to produce an opening for. The algorithm takes as input `x1, . . ., xk`, and  proceeds as follows:
    /// 1. Initialise the proof vector, `proof = []`.
    /// 2. Given an input vector `v = v1, . . .,vl`, if `v.len() == 1`, return `proof`, else, continue.
    /// 3. Map each `vi` to the corresponding number of the leaf (by adding the offset).
    /// 4. Initialise a new empty vector `p = []`. Next, iterate over each element `vi`
    ///    a. Append the parent of `vi` to `p`
    ///    b. Compute the sibling, `si` of `vi`
    ///    c. If `si == v(i+1)` then do nothing, and skip step four for `v(i+1)`. Else append `si` to `proof`
    /// 5. Iterate from step 2 with input vector `p`
    ///
    /// # Panics
    /// If the indices provided are out of bounds (higher than the number of elements
    /// committed in the `MerkleTree`) or are not ordered, the function fails.
    // todo: Update doc.
    pub(crate) fn compute_merkle_tree_batch_path(&self, indices: Vec<usize>) -> MerkleBatchPath<D>
    where
        D: FixedOutput,
    {
        assert!(
            !indices.is_empty(),
            "get_batched_path() called with no indices"
        );
        for i in &indices {
            assert!(
                i < &self.n,
                "Proof index out of bounds: asked for {} out of {}",
                i,
                self.n
            );
        }

        let mut ordered_indices: Vec<usize> = indices.clone();
        ordered_indices.sort_unstable();

        assert_eq!(ordered_indices, indices, "Indices should be ordered");

        ordered_indices = ordered_indices.into_iter().map(|i| self.get_leaf_index(i)).collect();

        let mut idx = ordered_indices[0];
        let mut proof = Vec::new();

        while idx > 0 {
            let mut new_indices = Vec::with_capacity(ordered_indices.len());
            let mut i = 0;
            idx = parent(idx);
            while i < ordered_indices.len() {
                new_indices.push(parent(ordered_indices[i]));
                let sibling = sibling(ordered_indices[i]);
                if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sibling {
                    i += 1;
                } else if sibling < self.nodes.len() {
                    proof.push(self.nodes[sibling].clone());
                }
                i += 1;
            }
            ordered_indices.clone_from(&new_indices);
        }

        MerkleBatchPath::new(proof, indices)
    }

    /// Convert a `MerkleTree` into a byte string.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Try to convert a byte string into a `MerkleTree`.
    /// # Error
    /// It returns error if conversion fails.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Try to convert a byte string into a `MerkleTree` using the legacy format.
    /// # Layout
    /// * Number of leaves committed in the Merkle Tree (as u64)
    /// * All nodes of the merkle tree (starting with the root)
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(MerkleTreeError::SerializationError)?);
        let n = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;
        let num_nodes = n
            .checked_next_power_of_two()
            .and_then(|num_nodes| num_nodes.checked_add(n))
            .and_then(|num_nodes| num_nodes.checked_sub(1))
            .ok_or(MerkleTreeError::SerializationError)?;
        let mut nodes = Vec::new();
        for i in 0..num_nodes {
            let range_low = i
                .checked_mul(<D as Digest>::output_size())
                .and_then(|rl| rl.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            let range_high = i
                .checked_add(1)
                .and_then(|rh| rh.checked_mul(<D as Digest>::output_size()))
                .and_then(|rh| rh.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            nodes.push(
                bytes
                    .get(range_low..range_high)
                    .ok_or(MerkleTreeError::SerializationError)?
                    .to_vec(),
            );
        }
        Ok(Self {
            nodes,
            leaf_off: num_nodes.checked_sub(n).ok_or(MerkleTreeError::SerializationError)?,
            n,
            hasher: PhantomData,
            leaves: PhantomData,
        })
    }

    #[cfg(feature = "future_snark")]
    // TODO: remove this allow dead_code directive when function is called or future_snark is activated
    #[allow(dead_code)]
    /// Convert merkle tree to a commitment. This function simply returns the root.
    pub(crate) fn to_merkle_tree_commitment(&self) -> MerkleTreeCommitment<D, L> {
        MerkleTreeCommitment::new(self.nodes[0].clone()) // Use private constructor
    }

    #[cfg(feature = "future_snark")]
    // TODO: remove this allow dead_code directive when function is called or future_snark is activated
    #[allow(dead_code)]
    /// Get a path (hashes of siblings of the path to the root node)
    /// for the `i`th value stored in the tree.
    /// Requires `i < self.n`
    pub(crate) fn compute_merkle_tree_path(&self, i: usize) -> MerklePath<D> {
        assert!(
            i < self.n,
            "Proof index out of bounds: asked for {} out of {}",
            i,
            self.n
        );
        let mut idx = self.get_leaf_index(i);
        let mut proof = Vec::new();

        while idx > 0 {
            let h = if sibling(idx) < self.nodes.len() {
                self.nodes[sibling(idx)].clone()
            } else {
                D::digest([0u8]).to_vec()
            };
            proof.push(h);
            idx = parent(idx);
        }

        MerklePath::new(proof, i)
    }

    #[cfg(feature = "future_snark")]
    /// Get a path (hashes of siblings of the path to the root node)
    /// for the `i`th value stored in the tree and pad it to reach the
    /// given length.
    /// The padding is done by adding values of `0` to the path in the form
    /// of `[0u8; hash_output_size]`. Since finding the preimage is hard, this allows us
    /// to use this value to detect when the "real" path ends.
    /// Requires `i < self.n`
    pub(crate) fn compute_merkle_tree_path_fixed_length(
        &self,
        i: usize,
        path_length: u32,
    ) -> MerklePath<D> {
        let mut path = self.compute_merkle_tree_path(i);

        while path.values.len() < path_length as usize {
            path.values.push(vec![0u8; <D as Digest>::output_size()]);
        }

        path
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    use rand::{rng, seq::IteratorRandom};

    use crate::{
        MembershipDigest, MithrilMembershipDigest, VerificationKeyForConcatenation,
        membership_commitment::MerkleTreeConcatenationLeaf,
    };

    use super::*;

    fn pow2_plus1(h: usize) -> usize {
        1 + 2_usize.pow(h as u32)
    }

    mod concatenation {
        use super::*;

        type ConcatenationHash = <MithrilMembershipDigest as MembershipDigest>::ConcatenationHash;

        prop_compose! {
            fn arb_tree(max_size: u32)
                       (v in vec(any::<u64>(), 2..max_size as usize)) -> (MerkleTree<ConcatenationHash, MerkleTreeConcatenationLeaf>, Vec<MerkleTreeConcatenationLeaf>) {
                let pks = vec![VerificationKeyForConcatenation::default(); v.len()];
                let leaves = pks.into_iter().zip(v.into_iter()).map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake)).collect::<Vec<MerkleTreeConcatenationLeaf>>();
                 (MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves), leaves)
            }
        }

        proptest! {
            // Test the relation that t.get_path(i) is a valid
            // proof for i
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[cfg(feature = "future_snark")]
            #[test]
            fn test_create_proof((t, values) in arb_tree(30)) {
                values.iter().enumerate().for_each(|(i, _v)| {
                    let pf = t.compute_merkle_tree_path(i);
                    assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[i], &pf).is_ok());
                })
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_path((t, values) in arb_tree(30)) {
                values.iter().enumerate().for_each(|(i, _v)| {
                    let pf = t.compute_merkle_tree_path(i);
                    let bytes = pf.to_bytes().expect("MerklePath serialization should not fail");
                    let deserialised = MerklePath::from_bytes(&bytes).unwrap();
                    assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[i], &deserialised).is_ok());
                })
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_tree_commitment((t, values) in arb_tree(5)) {
                let encoded = t.to_merkle_tree_commitment().to_bytes().expect("MerkleTreeCommitment serialization should not fail");
                let decoded = MerkleTreeCommitment::<ConcatenationHash, MerkleTreeConcatenationLeaf>::from_bytes(&encoded).unwrap();

                let tree_commitment = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&values).to_merkle_tree_commitment();
                assert_eq!(tree_commitment.root, decoded.root);
            }

            #[test]
            fn test_bytes_tree((t, values) in arb_tree(5)) {
                let bytes = t.to_bytes().expect("MerkleTree serialization should not fail");
                let deserialised = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::from_bytes(&bytes).unwrap();
                let tree = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&values);
                assert_eq!(tree.nodes, deserialised.nodes);
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_tree_commitment_batch_compat((t, values) in arb_tree(5)) {
                let encoded = t.to_merkle_tree_batch_commitment().to_bytes().expect("MerkleTreeBatchCommitment serialization should not fail");
                let decoded = MerkleTreeBatchCommitment::<ConcatenationHash, MerkleTreeConcatenationLeaf>::from_bytes(&encoded).unwrap();
                let tree_commitment = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&values).to_merkle_tree_batch_commitment();
                assert_eq!(tree_commitment.root, decoded.root);
                assert_eq!(tree_commitment.get_number_of_leaves(), decoded.get_number_of_leaves());

            }

        }

        prop_compose! {
            // Returns values with a randomly generated path
            fn values_with_invalid_proof(max_height: usize)
                                        (h in 1..max_height)
                                        (v in vec(any::<u64>(), 2..pow2_plus1(h)),
                                         proof in vec(vec(any::<u8>(), 16), h)) -> (Vec<MerkleTreeConcatenationLeaf>, Vec<Vec<u8>>) {
                let pks = vec![VerificationKeyForConcatenation::default(); v.len()];
                let leaves = pks.into_iter().zip(v.into_iter()).map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake)).collect::<Vec<MerkleTreeConcatenationLeaf>>();
                (leaves, proof)
            }
        }

        proptest! {
            #[cfg(feature = "future_snark")]
            #[test]
            fn test_create_invalid_proof(
                i in any::<usize>(),
                (values, proof) in values_with_invalid_proof(10)
            ) {
                let t = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&values[1..]);
                let index = i % (values.len() - 1);
                let path_values = proof. iter().map(|x|  ConcatenationHash::digest(x).to_vec()).collect();
                let path = MerklePath::new(path_values, index);
                assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[0], &path).is_err());
            }

            #[test]
            fn test_create_invalid_batch_proof(
                i in any::<usize>(),
                (values, proof) in values_with_invalid_proof(10)
            ) {
                let t = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&values[1..]);
                let indices = vec![i % (values.len() - 1); values.len() / 2];
                let batch_values = vec![values[i % (values.len() - 1)]; values.len() / 2];
                let path = MerkleBatchPath{values: proof
                                .iter()
                                .map(|x|  ConcatenationHash::digest(x).to_vec())
                                .collect(),
                    indices,
                    hasher: PhantomData::<ConcatenationHash>
                    };
                assert!(t.to_merkle_tree_batch_commitment().verify_leaves_membership_from_batch_path(&batch_values, &path).is_err());
            }
        }

        prop_compose! {
            fn arb_tree_arb_batch(max_size: u32)
                       (v in vec(any::<u64>(), 2..max_size as usize)) -> (MerkleTree<ConcatenationHash, MerkleTreeConcatenationLeaf>, Vec<MerkleTreeConcatenationLeaf>, Vec<usize>) {
                let mut rng = rng();
                let size = v.len();
                let pks = vec![VerificationKeyForConcatenation::default(); size];
                let leaves = pks.into_iter().zip(v.into_iter()).map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake)).collect::<Vec<MerkleTreeConcatenationLeaf>>();

                let indices: Vec<usize> = (0..size).collect();
                let mut mt_list: Vec<usize> = indices.into_iter().sample(&mut rng, size * 2 / 10 + 1);
                mt_list.sort_unstable();

                let mut batch_values: Vec<MerkleTreeConcatenationLeaf> = Vec::with_capacity(mt_list.len());
                for i in mt_list.iter() {
                    batch_values.push(leaves[*i]);
                }

                (MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves), batch_values, mt_list)
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn test_create_batch_proof((t, batch_values, indices) in arb_tree_arb_batch(30)) {
                let batch_proof = t.compute_merkle_tree_batch_path(indices);
                assert!(t.to_merkle_tree_batch_commitment().verify_leaves_membership_from_batch_path(&batch_values, &batch_proof).is_ok());
            }

            #[test]
            fn test_bytes_batch_path((t, batch_values, indices) in arb_tree_arb_batch(30)) {
                let bp = t.compute_merkle_tree_batch_path(indices);

                let bytes = bp.to_bytes().expect("MerkleBatchPath serialization should not fail");
                let deserialized = MerkleBatchPath::from_bytes(&bytes).unwrap();
                assert!(t.to_merkle_tree_batch_commitment().verify_leaves_membership_from_batch_path(&batch_values, &deserialized).is_ok());
            }
        }

        #[cfg(feature = "future_snark")]
        mod golden {
            use super::*;

            const GOLDEN_BYTES: &[u8; 40] = &[
                0, 0, 0, 0, 0, 0, 0, 4, 178, 30, 231, 127, 65, 247, 162, 149, 33, 29, 147, 148,
                224, 156, 96, 113, 140, 42, 98, 166, 137, 14, 69, 29, 28, 244, 161, 145, 207, 146,
                236, 249,
            ];

            fn golden_value()
            -> MerkleTreeBatchCommitment<ConcatenationHash, MerkleTreeConcatenationLeaf>
            {
                let number_of_leaves = 4;
                let pks = vec![VerificationKeyForConcatenation::default(); number_of_leaves];
                let stakes: Vec<u64> = (0..number_of_leaves).map(|i| i as u64).collect();
                let leaves = pks
                    .into_iter()
                    .zip(stakes)
                    .map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake))
                    .collect::<Vec<MerkleTreeConcatenationLeaf>>();

                let tree =
                    MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves);

                tree.to_merkle_tree_batch_commitment()
            }

            #[test]
            fn golden_conversions() {
                let value = MerkleTreeBatchCommitment::<
                    ConcatenationHash,
                    MerkleTreeConcatenationLeaf,
                >::from_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
                assert_eq!(golden_value(), value);

                let serialized = MerkleTreeBatchCommitment::<
                    ConcatenationHash,
                    MerkleTreeConcatenationLeaf,
                >::to_bytes(&value)
                .expect("MerkleTreeBatchCommitment serialization should not fail");
                let golden_serialized = MerkleTreeBatchCommitment::to_bytes(&golden_value())
                    .expect("MerkleTreeBatchCommitment serialization should not fail");
                assert_eq!(golden_serialized, serialized);
            }
        }

        #[cfg(feature = "future_snark")]
        mod golden_json {
            use super::*;
            const GOLDEN_JSON: &str = r#"
        {
            "root": [178, 30, 231, 127, 65, 247, 162, 149, 33, 29, 147, 148, 224, 156, 96, 113, 140, 42, 98, 166, 137, 14, 69, 29, 28, 244, 161, 145, 207, 146, 236, 249],
            "nr_leaves": 4,
            "hasher": null
        }"#;

            fn golden_value()
            -> MerkleTreeBatchCommitment<ConcatenationHash, MerkleTreeConcatenationLeaf>
            {
                let number_of_leaves = 4;
                let pks = vec![VerificationKeyForConcatenation::default(); number_of_leaves];
                let stakes: Vec<u64> = (0..number_of_leaves).map(|i| i as u64).collect();
                let leaves = pks
                    .into_iter()
                    .zip(stakes)
                    .map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake))
                    .collect::<Vec<MerkleTreeConcatenationLeaf>>();

                let tree =
                    MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves);

                tree.to_merkle_tree_batch_commitment()
            }

            #[test]
            fn golden_conversions() {
                let value = serde_json::from_str(GOLDEN_JSON)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_value(), value);

                let serialized =
                    serde_json::to_string(&value).expect("This JSON serialization should not fail");
                let golden_serialized = serde_json::to_string(&golden_value())
                    .expect("This JSON serialization should not fail");
                assert_eq!(golden_serialized, serialized);
            }
        }

        mod golden_cbor {
            use super::*;

            fn golden_value() -> MerkleTree<ConcatenationHash, MerkleTreeConcatenationLeaf> {
                let number_of_leaves = 4;
                let pks = vec![VerificationKeyForConcatenation::default(); number_of_leaves];
                let stakes: Vec<u64> = (0..number_of_leaves).map(|i| i as u64).collect();
                let leaves = pks
                    .into_iter()
                    .zip(stakes)
                    .map(|(key, stake)| MerkleTreeConcatenationLeaf(key, stake))
                    .collect::<Vec<MerkleTreeConcatenationLeaf>>();

                MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves)
            }

            const GOLDEN_CBOR_BYTES: &[u8; 485] = &[
                1, 165, 101, 110, 111, 100, 101, 115, 135, 152, 32, 24, 178, 24, 30, 24, 231, 24,
                127, 24, 65, 24, 247, 24, 162, 24, 149, 24, 33, 24, 29, 24, 147, 24, 148, 24, 224,
                24, 156, 24, 96, 24, 113, 24, 140, 24, 42, 24, 98, 24, 166, 24, 137, 14, 24, 69,
                24, 29, 24, 28, 24, 244, 24, 161, 24, 145, 24, 207, 24, 146, 24, 236, 24, 249, 152,
                32, 24, 135, 24, 51, 24, 101, 24, 36, 24, 82, 24, 28, 24, 47, 24, 190, 24, 104, 24,
                152, 24, 106, 24, 167, 24, 128, 24, 167, 22, 24, 36, 24, 125, 24, 91, 24, 137, 24,
                208, 24, 224, 14, 24, 82, 24, 41, 24, 130, 24, 214, 24, 108, 24, 254, 24, 77, 24,
                44, 24, 160, 24, 117, 152, 32, 24, 75, 24, 152, 24, 193, 24, 39, 24, 81, 24, 31,
                24, 79, 24, 34, 24, 232, 24, 192, 24, 38, 24, 94, 24, 109, 24, 160, 24, 171, 24,
                148, 24, 173, 24, 203, 24, 85, 24, 33, 24, 116, 20, 24, 62, 24, 51, 1, 24, 112, 24,
                227, 4, 24, 226, 24, 56, 24, 30, 24, 27, 152, 32, 24, 133, 24, 163, 24, 160, 24,
                181, 24, 171, 24, 82, 24, 229, 24, 168, 24, 80, 24, 193, 24, 182, 24, 163, 24, 172,
                24, 80, 24, 114, 21, 24, 169, 24, 159, 24, 100, 24, 68, 24, 217, 24, 39, 24, 34,
                24, 37, 24, 155, 24, 218, 24, 120, 24, 101, 24, 51, 24, 25, 24, 43, 24, 84, 152,
                32, 24, 57, 20, 24, 139, 24, 83, 24, 194, 24, 218, 24, 202, 24, 66, 24, 139, 24,
                49, 24, 144, 24, 148, 24, 132, 6, 2, 24, 97, 24, 112, 24, 38, 24, 29, 24, 60, 24,
                139, 24, 233, 24, 189, 24, 95, 24, 168, 24, 204, 24, 84, 24, 33, 24, 201, 24, 140,
                23, 22, 152, 32, 24, 102, 24, 192, 24, 198, 24, 230, 0, 24, 203, 24, 217, 24, 240,
                24, 214, 24, 244, 24, 135, 24, 236, 24, 49, 24, 219, 24, 229, 14, 24, 209, 24, 46,
                24, 61, 24, 237, 24, 28, 24, 195, 24, 231, 24, 61, 24, 214, 24, 51, 24, 59, 24, 39,
                24, 186, 24, 114, 24, 64, 24, 107, 152, 32, 24, 128, 24, 78, 24, 52, 24, 132, 24,
                35, 24, 118, 24, 64, 24, 83, 24, 60, 24, 38, 24, 181, 24, 197, 24, 144, 24, 188,
                24, 235, 24, 225, 2, 24, 223, 24, 135, 24, 104, 24, 193, 24, 226, 24, 148, 24, 170,
                24, 114, 24, 26, 24, 173, 24, 161, 24, 34, 24, 70, 24, 241, 24, 90, 104, 108, 101,
                97, 102, 95, 111, 102, 102, 3, 97, 110, 4, 102, 104, 97, 115, 104, 101, 114, 246,
                102, 108, 101, 97, 118, 101, 115, 246,
            ];

            #[test]
            fn cbor_golden_bytes_can_be_decoded() {
                let decoded =
                    MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::from_bytes(
                        GOLDEN_CBOR_BYTES,
                    )
                    .expect("CBOR golden bytes deserialization should not fail");
                assert_eq!(golden_value().nodes, decoded.nodes);
                assert_eq!(golden_value().n, decoded.n);
                assert_eq!(golden_value().leaf_off, decoded.leaf_off);
            }

            #[test]
            fn cbor_encoding_is_stable() {
                let bytes = golden_value().to_bytes().expect("CBOR serialization should not fail");
                assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
            }
        }
    }

    #[cfg(feature = "future_snark")]
    mod snark {
        use midnight_curves::Fq;

        use crate::{
            VerificationKeyForSnark, membership_commitment::MerkleTreeSnarkLeaf,
            signature_scheme::BaseFieldElement,
        };

        use super::*;

        type SnarkHash = <MithrilMembershipDigest as MembershipDigest>::SnarkHash;

        fn make_leaves(n: usize) -> Vec<MerkleTreeSnarkLeaf> {
            let pks = vec![VerificationKeyForSnark::default(); n];
            pks.into_iter()
                .zip(0u64..)
                .map(|(key, stake)| MerkleTreeSnarkLeaf(key, BaseFieldElement(Fq::from(stake))))
                .collect()
        }

        #[test]
        fn padded_path_preserves_natural_prefix() {
            // The first elements of the padded path must match the natural path exactly
            let leaves = make_leaves(4); // natural depth = 2
            let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);
            let natural = tree.compute_merkle_tree_path(0);
            let padded = tree.compute_merkle_tree_path_fixed_length(0, 5);

            assert_eq!(&padded.values[..natural.values.len()], &natural.values[..]);
        }

        #[test]
        fn padding_elements_are_zero_vectors() {
            // Elements added by padding must be zero vectors of the hash output size
            let leaves = make_leaves(4); // natural depth = 2
            let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);
            let natural_len = tree.compute_merkle_tree_path(0).values.len();
            let padded = tree.compute_merkle_tree_path_fixed_length(0, 5);

            let expected_zero = vec![0u8; <SnarkHash as Digest>::output_size()];
            for pad_elem in &padded.values[natural_len..] {
                assert_eq!(pad_elem, &expected_zero);
            }
        }

        #[test]
        fn padded_path_has_correct_length() {
            let leaves = make_leaves(4); // natural depth = 2
            let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);
            let path_length = 5u32;

            let pf = tree.compute_merkle_tree_path_fixed_length(0, path_length);

            assert_eq!(pf.values.len(), path_length as usize);
        }

        #[test]
        fn no_truncation_when_path_length_not_larger_than_natural_depth() {
            // When path_length <= natural depth, the path is returned unchanged
            let leaves = make_leaves(8); // natural depth = 3
            let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);
            let natural = tree.compute_merkle_tree_path(0);
            let pf = tree.compute_merkle_tree_path_fixed_length(0, 2); // 2 < natural depth 3

            assert_eq!(pf.values, natural.values);
        }

        prop_compose! {
            fn arb_tree_poseidon(max_size: u32)
                       (v in vec(any::<u64>(), 2..max_size as usize)) -> (MerkleTree<SnarkHash, MerkleTreeSnarkLeaf>, Vec<MerkleTreeSnarkLeaf>) {
                let pks = vec![VerificationKeyForSnark::default(); v.len()];
                let leaves = pks.into_iter().zip(v.into_iter()).map(|(key, stake)| MerkleTreeSnarkLeaf(key, BaseFieldElement(Fq::from(stake)))).collect::<Vec<MerkleTreeSnarkLeaf>>();
                 (MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves), leaves)
            }
        }

        proptest! {
            // Test the relation that t.get_path(i) is a valid
            // proof for i
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[cfg(feature = "future_snark")]
            #[test]
            fn test_create_proof((t, values) in arb_tree_poseidon(30)) {
                values.iter().enumerate().for_each(|(i, _v)| {
                    let pf = t.compute_merkle_tree_path(i);
                    assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[i], &pf).is_ok());
                })
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_path((t, values) in arb_tree_poseidon(30)) {
                values.iter().enumerate().for_each(|(i, _v)| {
                    let pf = t.compute_merkle_tree_path(i);
                    let bytes = pf.to_bytes().expect("MerklePath serialization should not fail");
                    let deserialised = MerklePath::from_bytes(&bytes).unwrap();
                    assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[i], &deserialised).is_ok());
                })
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_tree_commitment((t, values) in arb_tree_poseidon(5)) {
                let encoded = t.to_merkle_tree_commitment().to_bytes().expect("MerkleTreeCommitment serialization should not fail");
                let decoded = MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(&encoded).unwrap();

                let tree_commitment = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&values).to_merkle_tree_commitment();
                assert_eq!(tree_commitment.root, decoded.root);
            }

            #[cfg(feature = "future_snark")]
            #[test]
            fn test_bytes_tree((t, values) in arb_tree_poseidon(5)) {
                let bytes = t.to_bytes().expect("MerkleTree serialization should not fail");
                let deserialised = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(&bytes).unwrap();
                let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&values);
                assert_eq!(tree.nodes, deserialised.nodes);
            }
        }

        prop_compose! {
            // Returns values with a randomly generated path
            fn values_with_invalid_proof(max_height: usize)
                                        (h in 1..max_height)
                                        (v in vec(any::<u64>(), 2..pow2_plus1(h)),
                                         proof in vec(vec(any::<u8>(), 16), h)) -> (Vec<MerkleTreeSnarkLeaf>, Vec<Vec<u8>>) {
                let pks = vec![VerificationKeyForSnark::default(); v.len()];
                let leaves = pks.into_iter().zip(v.into_iter()).map(|(key, stake)| MerkleTreeSnarkLeaf(key, BaseFieldElement(Fq::from(stake)))).collect::<Vec<MerkleTreeSnarkLeaf>>();
                (leaves, proof)
            }
        }

        mod slow {
            use super::*;

            proptest! {
                #[cfg(feature = "future_snark")]
                #[test]
                fn test_create_invalid_proof(
                    i in any::<usize>(),
                    (values, proof) in values_with_invalid_proof(10)
                ) {
                    let t = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&values[1..]);
                    let index = i % (values.len() - 1);
                    let path_values = proof.iter().map(|x| SnarkHash::digest(x).to_vec()).collect();
                    let path = MerklePath::new(path_values, index);
                    assert!(t.to_merkle_tree_commitment().verify_leaf_membership_from_path(&values[0], &path).is_err());
                }
            }
        }

        #[cfg(feature = "future_snark")]
        mod golden {
            use super::*;

            const GOLDEN_BYTES: &[u8; 32] = &[
                70, 51, 141, 228, 75, 74, 213, 158, 71, 119, 129, 77, 160, 2, 3, 215, 47, 104, 127,
                164, 240, 176, 36, 253, 161, 1, 247, 91, 197, 130, 86, 38,
            ];

            fn golden_value() -> MerkleTreeCommitment<SnarkHash, MerkleTreeSnarkLeaf> {
                let number_of_leaves = 4;
                let pks = vec![VerificationKeyForSnark::default(); number_of_leaves];
                let stakes: Vec<u64> = (0..number_of_leaves).map(|i| i as u64).collect();
                let leaves = pks
                    .into_iter()
                    .zip(stakes)
                    .map(|(key, stake)| MerkleTreeSnarkLeaf(key, BaseFieldElement(Fq::from(stake))))
                    .collect::<Vec<MerkleTreeSnarkLeaf>>();
                let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);

                tree.to_merkle_tree_commitment()
            }

            #[test]
            fn golden_conversions() {
                let value = MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(
                    GOLDEN_BYTES,
                )
                .expect("This from bytes should not fail");
                assert_eq!(golden_value(), value);

                let serialized =
                    MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::to_bytes(&value)
                        .expect("serialization should not fail");
                let golden_serialized = MerkleTreeCommitment::to_bytes(&golden_value())
                    .expect("serialization should not fail");
                assert_eq!(golden_serialized, serialized);
            }
        }

        #[cfg(feature = "future_snark")]
        mod golden_json {
            use super::*;
            const GOLDEN_JSON: &str = r#"
        {
            "root": [70,51,141,228,75,74,213,158,71,119,129,77,160,2,3,215,47,104,127,164,240,176,36,253,161,1,247,91,197,130,86,38],
            "hasher": null
        }"#;

            fn golden_value() -> MerkleTreeCommitment<SnarkHash, MerkleTreeSnarkLeaf> {
                let number_of_leaves = 4;
                let pks = vec![VerificationKeyForSnark::default(); number_of_leaves];
                let stakes: Vec<u64> = (0..number_of_leaves).map(|i| i as u64).collect();
                let leaves = pks
                    .into_iter()
                    .zip(stakes)
                    .map(|(key, stake)| MerkleTreeSnarkLeaf(key, BaseFieldElement(Fq::from(stake))))
                    .collect::<Vec<MerkleTreeSnarkLeaf>>();

                let tree = MerkleTree::<SnarkHash, MerkleTreeSnarkLeaf>::new(&leaves);

                tree.to_merkle_tree_commitment()
            }

            #[test]
            fn golden_conversions() {
                let value = serde_json::from_str(GOLDEN_JSON)
                    .expect("This JSON deserialization should not fail");
                assert_eq!(golden_value(), value);

                let serialized =
                    serde_json::to_string(&value).expect("This JSON serialization should not fail");
                let golden_serialized = serde_json::to_string(&golden_value())
                    .expect("This JSON serialization should not fail");
                assert_eq!(golden_serialized, serialized);
            }
        }
    }
}
