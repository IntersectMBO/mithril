use crate::{LotteryIndex, SignerIndex};

use super::AggregateSignatureType;

/// Error types for aggregation.
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum AggregationError {
    /// Not enough signatures were collected, got this many instead.
    #[error("Not enough signatures. Got only {0} out of {1}.")]
    NotEnoughSignatures(u64, u64),

    #[error("Unsupported proof system: {0}")]
    UnsupportedProofSystem(AggregateSignatureType),

    /// There is a duplicate index
    #[error("Indices are not unique.")]
    IndexNotUnique,

    /// Signer registration data could not be found during witness assembly for SNARK prover input.
    #[error("Missing SNARK signer data for signer index {0}.")]
    MissingSnarkSignerData(SignerIndex),

    /// A signature selected for witness assembly is missing its SNARK component.
    #[error("Missing SNARK signature for lottery index {0}.")]
    MissingSnarkSignature(LotteryIndex),

    /// A signature selected for witness assembly is missing its SNARK index mapping.
    #[error("Missing SNARK index mapping for signer index {0}.")]
    MissingSnarkIndexMapping(SignerIndex),

    /// Missing the genesis verification key in the ancillary verifier data
    #[error("Missing the genesis verification key in the ancillary verifier data.")]
    MissingGenesisVerificationKey,

    /// Missing IVC rolling state in the ancillary prover data
    #[error("Missing IVC rolling state in the ancillary prover data.")]
    MissingIvcRollingStateInAncillaryProverData,
}

/// Errors which can be output by Mithril aggregate verification.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum AggregateSignatureError {
    /// This error occurs when the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Batch verification of STM aggregate signatures failed
    #[error(
        "Invalid batch: signatures, aggregate verification keys, message and parameters must have the same length"
    )]
    BatchInvalid,

    /// Missing SNARK aggregate verification key
    #[error("Missing SNARK aggregate verification key")]
    MissingSnarkAggregateVerificationKey,

    /// Missing SNARK clerk for aggregate signature verification
    #[error("Missing SNARK clerk for aggregate signature verification")]
    MissingSnarkClerk,

    /// The proof system used in the aggregate signature is not supported
    #[error("Unsupported proof system: {0}")]
    UnsupportedProofSystem(AggregateSignatureType),

    /// The proof system is unknown
    #[error("Unknown proof system: {0}")]
    UnknownProofSystem(String),

    /// Missing ancillary verifier data to verify the aggregate signature
    #[error("Missing ancillary verifier data to verify the aggregate signature.")]
    MissingAncillaryVerifierData,

    /// Missing IVC verifier data from the AncillaryVerifierData
    #[error("Missing IVC verifier data from the AncillaryVerifierData.")]
    MissingIvcVerifierData,

    /// Missing SNARK verifier data from the AncillaryVerifierData
    #[error("Missing SNARK verifier data from the AncillaryVerifierData.")]
    MissingSnarkVerifierData,

    /// Missing genesis verification key bundle to verify the aggregate signature
    #[error("Missing genesis verification key bundle to verify the aggregate signature.")]
    MissingGenesisVerificationKeyBundle,
}
