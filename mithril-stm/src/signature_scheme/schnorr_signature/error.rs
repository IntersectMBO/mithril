#[cfg(feature = "snark")]
use super::{PrimeOrderProjectivePoint, StandardSchnorrSignature, UniqueSchnorrSignature};

/// Error types for the Unique Schnorr signatures.
#[cfg(feature = "snark")]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SchnorrSignatureError {
    /// Invalid Unique signature
    #[error("Invalid Unique Schnorr single signature")]
    UniqueSignatureInvalid(Box<UniqueSchnorrSignature>),

    /// Invalid Standard signature
    #[error("Invalid Standard Schnorr single signature")]
    StandardSignatureInvalid(Box<StandardSchnorrSignature>),

    /// This error occurs when the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    Serialization,

    /// This error occurs when the serialization of the scalar field bytes failed
    #[error("Invalid scalar field element bytes")]
    ScalarFieldElementSerialization,

    /// This error occurs when the serialization of the base field bytes failed
    #[error("Invalid base field element bytes")]
    BaseFieldElementSerialization,

    /// This error occurs when the serialization of the projective point bytes failed
    #[error("Invalid projective point bytes")]
    ProjectivePointSerialization,

    /// This error occurs when the serialization of the prime order projective point bytes failed
    #[error("Invalid prime order projective point bytes")]
    PrimeOrderProjectivePointSerialization,

    /// This error occurs when the random scalar fails to generate during the signature
    #[error("Failed generation of the signature's random scalar")]
    RandomScalarGeneration,

    /// Given point is not on the curve
    #[error("Given point is not on the curve")]
    PointIsNotOnCurve(Box<PrimeOrderProjectivePoint>),

    /// Given point is not prime order
    #[error("Given point is not prime order")]
    PointIsNotPrimeOrder(Box<PrimeOrderProjectivePoint>),

    /// The commitment point of a Unique signature is not in the prime order subgroup
    #[error("Unique Schnorr signature commitment point is not prime order")]
    CommitmentPointIsNotPrimeOrder(Box<UniqueSchnorrSignature>),
}
