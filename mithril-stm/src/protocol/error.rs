use crate::VerificationKeyForConcatenation;

#[cfg(feature = "future_snark")]
use crate::VerificationKeyForSnark;

/// Errors which can be outputted by key registration.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegisterError {
    /// This key has already been registered by a participant
    #[error("This key has already been registered.")]
    EntryAlreadyRegistered,

    /// Cannot register if the registration is closed.
    #[error("Cannot register if the registration is closed.")]
    RegistrationClosed,

    /// Registration is not closed. Cannot create a signer.
    #[error("Registration is not closed. Cannot create a signer")]
    RegistrationIsNotClosed,

    /// The supplied concatenation key is not valid
    #[error("The verification of correctness of the supplied concatenation key is invalid.")]
    ConcatenationKeyInvalid(Box<VerificationKeyForConcatenation>),

    #[cfg(feature = "future_snark")]
    /// The supplied snark key is not valid
    #[error("The verification of correctness of the supplied SNARK key is invalid.")]
    SnarkKeyInvalid(Box<VerificationKeyForSnark>),

    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    /// UnregisteredInitializer error
    #[error("Initializer not registered. Cannot participate as a signer.")]
    UnregisteredInitializer,

    /// No registration found for the given index.
    #[error("No registration found for the given index.")]
    UnregisteredIndex,

    /// Snark proof signer creation from initializer failed
    #[cfg(feature = "future_snark")]
    #[error("Unable to create SNARK proof signer.")]
    SnarkProofSignerCreation,

    /// Total stake value overflows `u64` during computation.
    #[error("Total stake overflow accumulated stake: {accumulated_stake}, adding stake: {stake}")]
    TotalStakeOverflow { accumulated_stake: u64, stake: u64 },

    /// Total stake of the key registration is zero.
    #[error("Cannot run the protocol if total stake is zero.")]
    ZeroTotalStake,
}

/// Errors which are due to an error in the protocol.
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum ProtocolError {
    /// Value of phi_f is out of the (0,1] range
    #[error("phi_f must be in the range (0, 1], got {0}")]
    PhiFValueOutOfRange(f64),
}
