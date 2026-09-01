use midnight_proofs::plonk::Error as PlonkError;
use thiserror::Error;

/// Circuit-scoped errors for Halo2 STM validation and execution.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertificateCircuitError {
    /// Invalid relation parameters: requires `k < m <= 2^LOTTERY_BIT_BOUND - 1`.
    #[error(
        "Circuit::validate_parameters failed: expected k < m <= 2^LOTTERY_BIT_BOUND - 1, got k={k}, m={m}"
    )]
    InvalidCircuitParameters { k: u32, m: u32 },

    /// Witness vector length does not match the configured k.
    #[error("Circuit::validate_witness_length failed: expected k {expected_k}, got {actual}")]
    WitnessLengthMismatch { expected_k: u32, actual: u32 },

    /// Witness lottery index exceeds the circuit's maximum supported value.
    #[error(
        "Circuit::validate_lottery_index failed: index ({index}) exceeds max supported ({max_supported})"
    )]
    LotteryIndexTooLarge { index: u64, max_supported: u64 },

    /// Witness lottery index is not a valid in-circuit lottery slot.
    #[error("Circuit::validate_lottery_index failed: index ({index}) must be lower than m ({m})")]
    LotteryIndexOutOfBounds { index: u64, m: u32 },

    /// Merkle sibling path length does not match the configured Merkle depth.
    #[error(
        "Circuit::validate_merkle_sibling_length failed: expected depth {expected_depth}, got {actual}"
    )]
    MerkleSiblingLengthMismatch { expected_depth: u32, actual: u32 },

    /// Merkle position path length does not match the configured Merkle depth.
    #[error(
        "Circuit::validate_merkle_position_length failed: expected depth {expected_depth}, got {actual}"
    )]
    MerklePositionLengthMismatch { expected_depth: u32, actual: u32 },

    /// Failed to parse the prime field modulus while splitting field limbs.
    #[error("Field modulus parse failed")]
    FieldModulusParseFailed,

    /// Failed to convert a reduced integer into a prime field element.
    #[error("Field element conversion failed")]
    FieldElementConversionFailed,

    /// Bit decomposition range is invalid for the selected prime field.
    #[error("Invalid bit decomposition range ({num_bits}) for field size ({field_bits})")]
    InvalidBitDecompositionRange { num_bits: u32, field_bits: u32 },

    /// Merkle tree depth does not fit fixture sizing constraints.
    #[error("Invalid merkle tree depth ({depth})")]
    InvalidMerkleTreeDepth { depth: u32 },

    /// Selected leaf index is out of bounds for the current tree.
    #[error("Invalid selected leaf index ({index}) for {num_leaves} leaves")]
    InvalidSelectedLeafIndex { index: u32, num_leaves: u32 },

    /// Empty lottery indices were provided where at least one is required.
    #[error("Empty indices")]
    EmptyIndices,

    /// Witness must contain at least two entries.
    #[error("Witness too short (got {actual}, expected at least 2)")]
    WitnessTooShort { actual: u32 },

    /// No distinct witness entries were found.
    #[error("No distinct witness entries")]
    NoDistinctWitnessEntries,

    /// Tried to build a witness from an empty signer set.
    #[error("Empty signer leaves")]
    EmptySignerLeaves,

    /// Signer leaf index is out of bounds.
    #[error("Invalid signer leaf index ({index}) for {num_signers} signers")]
    InvalidSignerFixtureIndex { index: u32, num_signers: u32 },

    /// Failed to decode challenge bytes into a base field element.
    #[error("Invalid challenge bytes")]
    InvalidChallengeBytes,

    /// Challenge bytes decode but do not match native challenge value.
    #[error("Challenge endianness mismatch")]
    ChallengeEndiannessMismatch,

    /// Merkle root digest has an invalid byte length.
    #[error("Invalid merkle root digest length ({actual})")]
    InvalidMerkleRootDigestLength { actual: u32 },

    /// Merkle root digest is not a canonical base field element encoding.
    #[error("Non-canonical merkle root digest")]
    NonCanonicalMerkleRootDigest,

    /// STM Merkle-path verification failed for selected leaf.
    #[error("Merkle path verification failed")]
    MerklePathVerificationFailed,

    /// Failed to create the local assets directory for persisted circuit params.
    #[error("Failed to create params assets directory")]
    ParamsAssetsDirCreate,

    /// Signature generation failed while preparing witness.
    #[error("Signature generation failed")]
    SignatureGenerationFailed,

    /// Signature verification failed while preparing witness.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Proof was generated but rejected by the verifier.
    #[error("Proof verification rejected")]
    VerificationRejected,

    /// A proving/verification backend error surfaced at the relation boundary.
    #[error("Backend error: {0}")]
    Backend(String),
}

impl From<PlonkError> for CertificateCircuitError {
    fn from(error: PlonkError) -> Self {
        Self::Backend(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plonk_error_converts_to_backend_variant() {
        let plonk_error = PlonkError::ConstraintSystemFailure;
        let expected_message = plonk_error.to_string();
        assert_eq!(
            CertificateCircuitError::from(plonk_error),
            CertificateCircuitError::Backend(expected_message),
        );
    }
}
