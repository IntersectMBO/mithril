//! Shared Merkle witness boundary types used by circuit integrations.

use digest::Digest;
use ff::Field;
use thiserror::Error;

use crate::circuits::halo2::types::{CircuitBase, CircuitBaseField};
use crate::membership_commitment::MerklePath as StmMerklePath;
use crate::signature_scheme::BaseFieldElement;

/// Position of a sibling node relative to the current hash in a Merkle path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// The sibling node is on the left side of the current hash.
    Left,
    /// The sibling node is on the right side of the current hash.
    Right,
}

impl From<Position> for CircuitBase {
    fn from(position: Position) -> Self {
        match position {
            Position::Left => Self::ZERO,
            Position::Right => Self::ONE,
        }
    }
}

impl From<Position> for CircuitBaseField {
    fn from(position: Position) -> Self {
        CircuitBase::from(position).into()
    }
}

/// Merkle authentication path used by circuit witnesses.
///
/// Each entry stores sibling position and sibling hash value for one tree level.
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Ordered list of `(position, sibling_hash)` from leaf level to root level.
    pub siblings: Vec<(Position, CircuitBaseField)>,
}

impl MerklePath {
    /// Creates a new Merkle path from ordered sibling entries.
    pub fn new(siblings: Vec<(Position, CircuitBaseField)>) -> Self {
        Self { siblings }
    }
}

/// Errors returned when adapting STM Merkle paths to circuit witness paths.
#[derive(Debug, Error)]
pub enum MerklePathAdapterError {
    /// A Merkle digest did not contain the expected 32-byte field encoding.
    #[error("invalid merkle digest length: expected {expected} bytes, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },
    /// A 32-byte digest was not a canonical circuit base-field element encoding.
    #[error("non-canonical merkle digest")]
    NonCanonicalDigest,
}

impl<D: Digest> TryFrom<&StmMerklePath<D>> for MerklePath {
    type Error = MerklePathAdapterError;

    fn try_from(stm_path: &StmMerklePath<D>) -> Result<Self, Self::Error> {
        let mut siblings = Vec::with_capacity(stm_path.values.len());

        for (i, value) in stm_path.values.iter().enumerate() {
            let bytes: [u8; 32] = value.as_slice().try_into().map_err(|_| {
                MerklePathAdapterError::InvalidDigestLength {
                    expected: 32,
                    actual: value.as_slice().len(),
                }
            })?;
            let node = BaseFieldElement::from_canonical_bytes(&bytes)
                .ok()
                .map(|base| base.into())
                .ok_or(MerklePathAdapterError::NonCanonicalDigest)?;
            let bit = (stm_path.index >> i) & 1;
            // At level `i`, `bit = (index >> i) & 1`: `0` means current is left, `1` means right.
            // STM uses `H(current || sibling)` for `bit == 0`, else `H(sibling || current)`.
            // Map `0 -> Position::Right` and `1 -> Position::Left` so circuits fold identically.
            let position = if bit == 0 {
                Position::Right
            } else {
                Position::Left
            };
            siblings.push((position, node));
        }

        Ok(MerklePath::new(siblings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::poseidon::MidnightPoseidonDigest;

    #[test]
    fn converts_valid_merkle_path_and_preserves_position_mapping() {
        let left_node = BaseFieldElement::from(5u64).to_canonical_bytes().to_vec();
        let right_node = BaseFieldElement::from(9u64).to_canonical_bytes().to_vec();
        let stm_path = StmMerklePath::<MidnightPoseidonDigest>::new(vec![left_node, right_node], 1);

        let circuit_path =
            MerklePath::try_from(&stm_path).expect("valid STM merkle path should convert");

        assert_eq!(circuit_path.siblings.len(), 2);
        assert_eq!(circuit_path.siblings[0].0, Position::Left);
        assert_eq!(circuit_path.siblings[1].0, Position::Right);
        assert_eq!(circuit_path.siblings[0].1, 5u64.into());
        assert_eq!(circuit_path.siblings[1].1, 9u64.into());
    }

    #[test]
    fn rejects_invalid_digest_length() {
        let stm_path = StmMerklePath::<MidnightPoseidonDigest>::new(vec![vec![0u8; 31]], 0);

        let error =
            MerklePath::try_from(&stm_path).expect_err("invalid digest length should be rejected");

        assert!(matches!(
            error,
            MerklePathAdapterError::InvalidDigestLength {
                expected: 32,
                actual: 31
            }
        ));
    }

    #[test]
    fn rejects_non_canonical_digest() {
        let stm_path = StmMerklePath::<MidnightPoseidonDigest>::new(vec![vec![0xff; 32]], 0);

        let error =
            MerklePath::try_from(&stm_path).expect_err("non-canonical digest should be rejected");

        assert!(matches!(error, MerklePathAdapterError::NonCanonicalDigest));
    }
}
