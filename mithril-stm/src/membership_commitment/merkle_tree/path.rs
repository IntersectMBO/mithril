use std::marker::PhantomData;

use digest::{Digest, FixedOutput};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::codec;

use super::MerkleTreeError;

#[cfg(feature = "snark")]
/// Path of hashes from root to leaf in a Merkle Tree.
/// Contains all hashes on the path, and the index of the leaf.
/// Used to verify that signatures come from eligible signers.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath<D: Digest> {
    pub(crate) values: Vec<Vec<u8>>,
    pub(crate) index: usize,
    hasher: PhantomData<D>,
}

#[cfg(feature = "snark")]
impl<D: Digest + FixedOutput> MerklePath<D> {
    pub(crate) fn new(values: Vec<Vec<u8>>, index: usize) -> Self {
        Self {
            values,
            index,
            hasher: Default::default(),
        }
    }

    /// Convert to bytes
    #[cfg(test)]
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Extract a `Path` from a byte slice.
    /// # Error
    /// This function fails if the bytes cannot retrieve path.
    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> StmResult<MerklePath<D>> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Extract a `Path` from a byte slice using the legacy format.
    /// # Layout
    /// * Index representing the position in the Merkle Tree
    /// * Size of the Path
    /// * Path of hashes
    #[cfg(test)]
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<MerklePath<D>> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(MerkleTreeError::SerializationError)?);
        let index = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;
        u64_bytes.copy_from_slice(bytes.get(8..16).ok_or(MerkleTreeError::SerializationError)?);
        let len = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;
        let mut values = Vec::new();
        for i in 0..len {
            let range_low = i
                .checked_mul(<D as Digest>::output_size())
                .and_then(|rl| rl.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            let range_high = i
                .checked_add(1)
                .and_then(|rh| rh.checked_mul(<D as Digest>::output_size()))
                .and_then(|rh| rh.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            values.push(
                bytes
                    .get(range_low..range_high)
                    .ok_or(MerkleTreeError::SerializationError)?
                    .to_vec(),
            );
        }

        Ok(MerklePath {
            values,
            index,
            hasher: PhantomData,
        })
    }
}

/// Path of hashes for a batch of indices.
/// Contains the hashes and the corresponding merkle tree indices of given batch.
/// Used to verify the signatures are issued by the registered signers.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleBatchPath<D: Digest + FixedOutput> {
    pub(crate) values: Vec<Vec<u8>>,
    pub(crate) indices: Vec<usize>,
    pub(crate) hasher: PhantomData<D>,
}

impl<D: Digest + FixedOutput> MerkleBatchPath<D> {
    pub(crate) fn new(values: Vec<Vec<u8>>, indices: Vec<usize>) -> MerkleBatchPath<D> {
        Self {
            values,
            indices,
            hasher: Default::default(),
        }
    }

    /// Convert the `BatchPath` into byte representation.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Try to convert a byte string into a `BatchPath`.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    /// Try to convert a byte string into a `BatchPath` using the legacy format.
    ///
    /// # Layout
    /// The layout of a `BatchPath` is
    /// * Length of values
    /// * Length of indices
    /// * Values
    /// * Indices
    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(MerkleTreeError::SerializationError)?);
        let len_v = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;

        u64_bytes.copy_from_slice(bytes.get(8..16).ok_or(MerkleTreeError::SerializationError)?);
        let len_i = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| MerkleTreeError::SerializationError)?;

        let mut values = Vec::new();
        for i in 0..len_v {
            let range_low = i
                .checked_mul(<D as Digest>::output_size())
                .and_then(|rl| rl.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            let range_high = i
                .checked_add(1)
                .and_then(|rh| rh.checked_mul(<D as Digest>::output_size()))
                .and_then(|rh| rh.checked_add(16))
                .ok_or(MerkleTreeError::SerializationError)?;
            values.push(
                bytes
                    .get(range_low..range_high)
                    .ok_or(MerkleTreeError::SerializationError)?
                    .to_vec(),
            );
        }
        let offset = len_v
            .checked_mul(<D as Digest>::output_size())
            .and_then(|off| off.checked_add(16))
            .ok_or(MerkleTreeError::SerializationError)?;

        let mut indices = Vec::new();
        for i in 0..len_i {
            let range_low = i
                .checked_mul(8)
                .and_then(|rl| rl.checked_add(offset))
                .ok_or(MerkleTreeError::SerializationError)?;
            let range_high = i
                .checked_add(1)
                .and_then(|rh| rh.checked_mul(8))
                .and_then(|rh| rh.checked_add(offset))
                .ok_or(MerkleTreeError::SerializationError)?;
            u64_bytes.copy_from_slice(
                bytes
                    .get(range_low..range_high)
                    .ok_or(MerkleTreeError::SerializationError)?,
            );
            indices.push(
                usize::try_from(u64::from_be_bytes(u64_bytes))
                    .map_err(|_| MerkleTreeError::SerializationError)?,
            );
        }

        Ok(MerkleBatchPath {
            values,
            indices,
            hasher: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        MembershipDigest, MithrilMembershipDigest, VerificationKeyForConcatenation,
        membership_commitment::MerkleTreeConcatenationLeaf,
        membership_commitment::merkle_tree::tree::MerkleTree,
    };

    use super::*;

    type ConcatenationHash = <MithrilMembershipDigest as MembershipDigest>::ConcatenationHash;

    mod golden_cbor_batch_path {
        use super::*;

        const GOLDEN_CBOR_BYTES: &[u8; 155] = &[
            1, 163, 102, 118, 97, 108, 117, 101, 115, 130, 152, 32, 24, 57, 20, 24, 139, 24, 83,
            24, 194, 24, 218, 24, 202, 24, 66, 24, 139, 24, 49, 24, 144, 24, 148, 24, 132, 6, 2,
            24, 97, 24, 112, 24, 38, 24, 29, 24, 60, 24, 139, 24, 233, 24, 189, 24, 95, 24, 168,
            24, 204, 24, 84, 24, 33, 24, 201, 24, 140, 23, 22, 152, 32, 24, 128, 24, 78, 24, 52,
            24, 132, 24, 35, 24, 118, 24, 64, 24, 83, 24, 60, 24, 38, 24, 181, 24, 197, 24, 144,
            24, 188, 24, 235, 24, 225, 2, 24, 223, 24, 135, 24, 104, 24, 193, 24, 226, 24, 148, 24,
            170, 24, 114, 24, 26, 24, 173, 24, 161, 24, 34, 24, 70, 24, 241, 24, 90, 103, 105, 110,
            100, 105, 99, 101, 115, 130, 0, 2, 102, 104, 97, 115, 104, 101, 114, 246,
        ];

        fn golden_value() -> MerkleBatchPath<ConcatenationHash> {
            let nr = 4;
            let pks = vec![VerificationKeyForConcatenation::default(); nr];
            let leaves = pks
                .into_iter()
                .enumerate()
                .map(|(i, k)| MerkleTreeConcatenationLeaf(k, i as u64))
                .collect::<Vec<_>>();
            let tree = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves);
            tree.compute_merkle_tree_batch_path(vec![0, 2])
        }

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = MerkleBatchPath::<ConcatenationHash>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            let expected = golden_value();
            assert_eq!(expected.values, decoded.values);
            assert_eq!(expected.indices, decoded.indices);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = MerkleBatchPath::to_bytes(&golden_value())
                .expect("CBOR serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }

    #[cfg(feature = "snark")]
    mod golden_cbor_path {
        use super::*;

        fn golden_value() -> MerklePath<ConcatenationHash> {
            let nr = 4;
            let pks = vec![VerificationKeyForConcatenation::default(); nr];
            let leaves = pks
                .into_iter()
                .enumerate()
                .map(|(i, k)| MerkleTreeConcatenationLeaf(k, i as u64))
                .collect::<Vec<_>>();
            let tree = MerkleTree::<ConcatenationHash, MerkleTreeConcatenationLeaf>::new(&leaves);
            tree.compute_merkle_tree_path(0)
        }

        const GOLDEN_CBOR_BYTES: &[u8; 149] = &[
            1, 163, 102, 118, 97, 108, 117, 101, 115, 130, 152, 32, 24, 57, 20, 24, 139, 24, 83,
            24, 194, 24, 218, 24, 202, 24, 66, 24, 139, 24, 49, 24, 144, 24, 148, 24, 132, 6, 2,
            24, 97, 24, 112, 24, 38, 24, 29, 24, 60, 24, 139, 24, 233, 24, 189, 24, 95, 24, 168,
            24, 204, 24, 84, 24, 33, 24, 201, 24, 140, 23, 22, 152, 32, 24, 75, 24, 152, 24, 193,
            24, 39, 24, 81, 24, 31, 24, 79, 24, 34, 24, 232, 24, 192, 24, 38, 24, 94, 24, 109, 24,
            160, 24, 171, 24, 148, 24, 173, 24, 203, 24, 85, 24, 33, 24, 116, 20, 24, 62, 24, 51,
            1, 24, 112, 24, 227, 4, 24, 226, 24, 56, 24, 30, 24, 27, 101, 105, 110, 100, 101, 120,
            0, 102, 104, 97, 115, 104, 101, 114, 246,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = MerklePath::<ConcatenationHash>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(
                golden_value().to_bytes().expect("serialization should not fail"),
                decoded.to_bytes().expect("serialization should not fail"),
            );
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = golden_value().to_bytes().expect("CBOR serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }
}
