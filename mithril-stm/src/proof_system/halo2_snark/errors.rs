use thiserror::Error;

/// Errors produced while decoding or verifying a non-recursive SNARK proof.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SnarkProofError {
    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    /// The SNARK proof failed to verify
    #[error("The SNARK proof failed to verify.")]
    VerifyProofFail,
}
