use std::marker::PhantomData;

use anyhow::{Context, anyhow};
use digest::{Digest, FixedOutput};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::codec;

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
use super::MerklePath;
use super::{MerkleBatchPath, MerkleTreeError, MerkleTreeLeaf, parent, sibling};

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
/// `MerkleTree` commitment.
/// This structure differs from `MerkleTree` in that it does not contain all elements, which are not always necessary.
/// Instead, it only contains the root of the tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleTreeCommitment<D: Digest, L: MerkleTreeLeaf> {
    /// Root of the merkle commitment.
    pub root: Vec<u8>,
    hasher: PhantomData<D>,
    #[serde(skip)]
    leaf_type: PhantomData<L>,
}

#[cfg(feature = "future_snark")]
// TODO: remove this allow dead_code directive when function is called or future_snark is activated
#[allow(dead_code)]
impl<D: Digest + FixedOutput, L: MerkleTreeLeaf> MerkleTreeCommitment<D, L> {
    pub(crate) fn new(root: Vec<u8>) -> Self {
        MerkleTreeCommitment {
            root,
            hasher: PhantomData,
            leaf_type: PhantomData,
        }
    }

    /// Check an inclusion proof that `val` is part of the tree by traveling the whole path until the root.
    /// # Error
    /// If the merkle tree path is invalid, then the function fails.
    pub(crate) fn verify_leaf_membership_from_path(
        &self,
        val: &L,
        proof: &MerklePath<D>,
    ) -> StmResult<()>
    where
        D: FixedOutput + Clone,
        L: MerkleTreeLeaf,
    {
        let mut idx = proof.index;

        let mut h = D::digest(val.as_bytes_for_merkle_tree()).to_vec();
        for p in &proof.values {
            if (idx & 0b1) == 0 {
                h = D::new().chain_update(h).chain_update(p).finalize().to_vec();
            } else {
                h = D::new().chain_update(p).chain_update(h).finalize().to_vec();
            }
            idx >>= 1;
        }

        if h == self.root {
            return Ok(());
        }
        Err(anyhow!(MerkleTreeError::PathInvalid(proof.to_bytes()?)))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Extract a `MerkleTreeCommitment` from a byte slice.
    ///
    /// The legacy format for this type is the raw hash digest (no length prefix),
    /// so the first byte can be any value — including `0x01` which is also the CBOR
    /// version prefix. To handle this ambiguity, this method tries CBOR decoding
    /// first and falls back to legacy if CBOR decoding fails.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<MerkleTreeCommitment<D, L>> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes::<Self>(&bytes[1..]).or_else(|_| Self::from_bytes_legacy(bytes))
        } else {
            Self::from_bytes_legacy(bytes)
        }
    }

    /// Extract a `MerkleTreeCommitment` from a byte slice using the legacy format.
    /// # Layout
    /// * Root of the Merkle commitment
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<MerkleTreeCommitment<D, L>> {
        let root = bytes.to_vec();

        Ok(Self {
            root,
            hasher: PhantomData,
            leaf_type: PhantomData,
        })
    }
}

/// Batch compatible `MerkleTree` commitment .
/// This structure differs from `MerkleTreeCommitment` in that it stores the number of leaves in the tree
/// as well as the root of the tree.
/// Number of leaves is required by the batch path generation/verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeBatchCommitment<D: Digest, L: MerkleTreeLeaf> {
    /// Root of the merkle commitment.
    pub root: Vec<u8>,
    nr_leaves: usize,
    hasher: PhantomData<D>,
    #[serde(skip)]
    leaf_type: PhantomData<L>,
}

impl<D: Digest + FixedOutput, L: MerkleTreeLeaf> MerkleTreeBatchCommitment<D, L> {
    pub(crate) fn new(root: Vec<u8>, nr_leaves: usize) -> Self {
        Self {
            root,
            nr_leaves,
            hasher: Default::default(),
            leaf_type: PhantomData,
        }
    }

    #[cfg(feature = "future_snark")]
    // TODO: remove this allow dead_code directive when function is called or future_snark is activated
    #[allow(dead_code)]
    /// Used in property test of `tree`: `test_bytes_tree_commitment_batch_compat`
    pub(crate) fn get_number_of_leaves(&self) -> usize {
        self.nr_leaves
    }

    /// Serializes the Merkle Tree commitment together with a message in a single vector of bytes.
    /// Outputs `msg || self` as a vector of bytes.
    // todo: Do we need to concat msg to whole commitment (nr_leaves and root) or just the root?
    pub(crate) fn concatenate_with_message(&self, msg: &[u8]) -> Vec<u8> {
        let mut msgp = msg.to_vec();
        let mut bytes = self.root.clone();
        msgp.append(&mut bytes);

        msgp
    }

    /// Check a proof of a batched opening. The indices must be ordered.
    ///
    /// # Error
    /// Returns an error if the proof is invalid.
    // todo: Update doc.
    // todo: Simplify the algorithm.
    // todo: Maybe we want more granular errors, rather than only `BatchPathInvalid`
    pub(crate) fn verify_leaves_membership_from_batch_path(
        &self,
        batch_val: &[L],
        proof: &MerkleBatchPath<D>,
    ) -> StmResult<()>
    where
        D: FixedOutput + Clone,
        L: MerkleTreeLeaf,
    {
        if batch_val.len() != proof.indices.len() {
            return Err(anyhow!(MerkleTreeError::BatchPathInvalid(
                proof.to_bytes()?
            )));
        }
        let mut ordered_indices: Vec<usize> = proof.indices.clone();
        ordered_indices.sort_unstable();

        if ordered_indices != proof.indices {
            return Err(anyhow!(MerkleTreeError::BatchPathInvalid(
                proof.to_bytes()?
            )));
        }

        let nr_nodes = self
            .nr_leaves
            .checked_next_power_of_two()
            .and_then(|nr_nodes| nr_nodes.checked_add(self.nr_leaves))
            .and_then(|nr_nodes| nr_nodes.checked_sub(1))
            .ok_or(MerkleTreeError::SerializationError)?;

        ordered_indices = ordered_indices
            .into_iter()
            .map(|i| {
                self.nr_leaves
                    .checked_next_power_of_two()
                    .and_then(|idx| idx.checked_add(i))
                    .and_then(|idx| idx.checked_sub(1))
                    .ok_or(MerkleTreeError::SerializationError)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut idx = ordered_indices[0];
        // First we need to hash the leave values
        let mut leaves: Vec<Vec<u8>> = batch_val
            .iter()
            .map(|val| D::digest(val.as_bytes_for_merkle_tree()).to_vec())
            .collect();

        let mut values = proof.values.clone();

        while idx > 0 {
            let mut new_hashes = Vec::with_capacity(ordered_indices.len());
            let mut new_indices = Vec::with_capacity(ordered_indices.len());
            let mut i = 0;
            idx = parent(idx);
            while i < ordered_indices.len() {
                new_indices.push(parent(ordered_indices[i]));
                if ordered_indices[i] & 1 == 0 {
                    new_hashes.push(
                        D::new()
                            .chain(
                                values
                                    .first()
                                    .ok_or(MerkleTreeError::SerializationError)
                                    .with_context(|| {
                                        format!("Could not verify leave membership from batch path for idx = {} and ordered_indices[{}]", idx, i)
                                    })?,
                            )
                            .chain(&leaves[i])
                            .finalize()
                            .to_vec(),
                    );
                    values.remove(0);
                } else {
                    let sibling = sibling(ordered_indices[i]);
                    if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sibling {
                        new_hashes.push(
                            D::new().chain(&leaves[i]).chain(&leaves[i + 1]).finalize().to_vec(),
                        );
                        i += 1;
                    } else if sibling < nr_nodes {
                        new_hashes.push(
                            D::new()
                                .chain(&leaves[i])
                                .chain(
                                    values
                                        .first()
                                        .ok_or(MerkleTreeError::SerializationError)
                                        .with_context(|| {
                                            format!(
                                                "Could not verify leave membership from batch path for idx = {} where sibling < nr_nodes", idx
                                            )
                                        })?,
                                )
                                .finalize()
                                .to_vec(),
                        );
                        values.remove(0);
                    } else {
                        new_hashes.push(
                            D::new().chain(&leaves[i]).chain(D::digest([0u8])).finalize().to_vec(),
                        );
                    }
                }
                i += 1;
            }
            leaves.clone_from(&new_hashes);
            ordered_indices.clone_from(&new_indices);
        }

        if leaves.len() == 1 && leaves[0] == self.root {
            return Ok(());
        }

        Err(anyhow!(MerkleTreeError::BatchPathInvalid(
            proof.to_bytes()?
        )))
    }

    /// Convert to bytes.
    // TODO: remove this once the 'to_bytes' function is used.
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Extract a `MerkleTreeBatchCommitment` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<MerkleTreeBatchCommitment<D, L>> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Extract a `MerkleTreeBatchCommitment` from a byte slice using the legacy format.
    /// # Layout
    /// * Number of leaves as u64
    /// * Root of the Merkle commitment as bytes
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<MerkleTreeBatchCommitment<D, L>> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(MerkleTreeError::SerializationError)?);
        let nr_leaves = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;
        let mut root = Vec::new();
        root.extend_from_slice(bytes.get(8..).ok_or(MerkleTreeError::SerializationError)?);

        Ok(MerkleTreeBatchCommitment {
            root,
            nr_leaves,
            hasher: PhantomData,
            leaf_type: Default::default(),
        })
    }
}

impl<D: Digest, L: MerkleTreeLeaf> PartialEq for MerkleTreeBatchCommitment<D, L> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.nr_leaves == other.nr_leaves
    }
}

impl<D: Digest, L: MerkleTreeLeaf> Eq for MerkleTreeBatchCommitment<D, L> {}

#[cfg(test)]
mod tests {
    use crate::{
        MembershipDigest, MithrilMembershipDigest, VerificationKeyForConcatenation,
        membership_commitment::merkle_tree::tree::MerkleTree,
        membership_commitment::{MerkleTreeBatchCommitment, MerkleTreeConcatenationLeaf},
    };

    type ConcatenationHash = <MithrilMembershipDigest as MembershipDigest>::ConcatenationHash;

    fn build_batch_commitment(
        nr: usize,
    ) -> MerkleTreeBatchCommitment<ConcatenationHash, MerkleTreeConcatenationLeaf> {
        let pks = vec![VerificationKeyForConcatenation::default(); nr];
        let leaves = pks
            .into_iter()
            .enumerate()
            .map(|(i, k)| MerkleTreeConcatenationLeaf(k, i as u64))
            .collect::<Vec<_>>();
        MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves)
            .to_merkle_tree_batch_commitment()
    }

    #[cfg(feature = "future_snark")]
    mod bytes_codec_ambiguity {
        use crate::{
            MembershipDigest, MithrilMembershipDigest,
            membership_commitment::{MerkleTreeCommitment, MerkleTreeSnarkLeaf},
        };

        type SnarkHash = <MithrilMembershipDigest as MembershipDigest>::SnarkHash;

        #[test]
        fn legacy_data_starting_with_0x01_falls_back_correctly() {
            let mut legacy_root = vec![0x01];
            legacy_root.extend_from_slice(&[0xAA; 31]);

            let decoded =
                MerkleTreeCommitment::<SnarkHash, MerkleTreeSnarkLeaf>::from_bytes(&legacy_root)
                    .expect("Legacy data starting with 0x01 should fall back to legacy decoder");
            assert_eq!(legacy_root, decoded.root);
        }
    }

    mod golden_cbor {
        use super::*;

        const GOLDEN_CBOR_BYTES: &[u8; 91] = &[
            1, 163, 100, 114, 111, 111, 116, 152, 32, 24, 178, 24, 30, 24, 231, 24, 127, 24, 65,
            24, 247, 24, 162, 24, 149, 24, 33, 24, 29, 24, 147, 24, 148, 24, 224, 24, 156, 24, 96,
            24, 113, 24, 140, 24, 42, 24, 98, 24, 166, 24, 137, 14, 24, 69, 24, 29, 24, 28, 24,
            244, 24, 161, 24, 145, 24, 207, 24, 146, 24, 236, 24, 249, 105, 110, 114, 95, 108, 101,
            97, 118, 101, 115, 4, 102, 104, 97, 115, 104, 101, 114, 246,
        ];

        fn golden_value()
        -> MerkleTreeBatchCommitment<ConcatenationHash, MerkleTreeConcatenationLeaf> {
            build_batch_commitment(4)
        }

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = MerkleTreeBatchCommitment::<
                ConcatenationHash,
                MerkleTreeConcatenationLeaf,
            >::from_bytes(GOLDEN_CBOR_BYTES)
            .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = MerkleTreeBatchCommitment::to_bytes(&golden_value())
                .expect("CBOR serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }
}
