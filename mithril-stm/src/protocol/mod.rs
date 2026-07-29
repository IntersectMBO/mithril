mod aggregate_signature;
mod error;
mod key_registration;
mod parameters;
mod participant;
mod single_signature;

pub use aggregate_signature::{
    AggregateSignature, AggregateSignatureError, AggregateSignatureType, AggregateVerificationKey,
    AggregationError, AncillaryGenesisData, AncillaryProofInput, AncillaryProofOutput,
    AncillaryProverData, AncillaryVerifierData, Clerk, GenesisVerificationKeyBundle,
};
pub use error::{ProtocolError, RegisterError};
pub(crate) use key_registration::RegistrationEntry;
#[cfg(feature = "future_snark")]
pub use key_registration::RegistrationEntryForSnark;
pub use key_registration::{
    ClosedKeyRegistration, ClosedRegistrationEntry, KeyRegistration,
    RegistrationEntryForConcatenation,
};
pub use parameters::Parameters;
pub use participant::{Initializer, Signer};
pub use single_signature::{SignatureError, SingleSignature, SingleSignatureWithRegisteredParty};

/// Wrapper of the Concatenation proof Verification key with proof of possession
pub type VerificationKeyProofOfPossessionForConcatenation =
    crate::signature_scheme::BlsVerificationKeyProofOfPossession;

/// Wrapper of the MultiSignature Verification key
pub type VerificationKeyForConcatenation = crate::signature_scheme::BlsVerificationKey;

#[cfg(feature = "future_snark")]
/// Wrapper of the Snark Verification key
pub type VerificationKeyForSnark = crate::signature_scheme::SchnorrVerificationKey;
