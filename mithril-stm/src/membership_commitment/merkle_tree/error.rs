/// Error types related to merkle trees.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MerkleTreeError {
    /// Serialization error
    #[error("Serialization of a merkle tree failed")]
    SerializationError,

    #[cfg(all(feature = "snark", test))]
    /// Invalid merkle path
    #[error("Path does not verify against root")]
    PathInvalid(Vec<u8>),

    /// Invalid merkle batch path
    #[error("Batch path does not verify against root")]
    BatchPathInvalid(Vec<u8>),
}
