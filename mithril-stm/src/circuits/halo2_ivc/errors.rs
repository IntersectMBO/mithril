use midnight_proofs::plonk::Error as PlonkError;
use thiserror::Error;

/// Circuit-scoped errors for the IVC recursive SNARK circuit and its off-circuit helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IvcCircuitError {
    /// Off-circuit verifier rejected a certificate proof.
    #[error("Certificate proof verification rejected: {0}")]
    CertificateProofRejected(String),

    /// IVC verification key degree does not match the IVC circuit degree constant RECURSIVE_CIRCUIT_DEGREE.
    #[error(
        "IvcCircuitData::validate_ivc_verification_key_degree failed: expected k={expected}, got k={actual}"
    )]
    IvcVerificationKeyDegreeMismatch { expected: u32, actual: u32 },

    /// `assign_many` returned a different number of values than expected.
    #[error("IvcConstraintBuilder: expected {expected} assigned values, got {actual}")]
    AssignedValueCountMismatch { expected: usize, actual: usize },

    /// `combine_bytes` received more bytes than base weights, which would silently truncate.
    #[error("combine_bytes received {bytes} bytes but only {bases} base weights")]
    ByteCountExceedsBaseCount { bytes: usize, bases: usize },

    /// Not enough advice columns were allocated to satisfy chip requirements.
    #[error(
        "IvcCircuitData::validate_column_counts failed: need {needed} advice columns, only {available} allocated"
    )]
    InsufficientAdviceColumns { needed: usize, available: usize },

    /// Not enough fixed columns were allocated to satisfy chip requirements.
    #[error(
        "IvcCircuitData::validate_column_counts failed: need {needed} fixed columns, only {available} allocated"
    )]
    InsufficientFixedColumns { needed: usize, available: usize },

    /// Off-circuit step transition: the incoming certificate's epoch does not advance the
    /// chain correctly. The `kind` field carries an `EpochTransitionErrorKind` with the
    /// specific violation.
    #[error(
        "IvcProverInput::prepare: invalid epoch transition at last committed epoch {last_committed_epoch}: {kind}"
    )]
    InvalidEpochTransition {
        kind: EpochTransitionErrorKind,
        last_committed_epoch: u64,
    },

    /// Off-circuit step transition: the chain's step counter would overflow u64.
    #[error("IvcProverInput::prepare: step counter overflow advancing past {current}")]
    StepCounterOverflow { current: u64 },

    /// Off-circuit accumulator check: the msm does not match the provided the fixed bases
    #[error("Fixed base `{name}` in the dual MSM does not match the provided map")]
    MsmFixedBasesNamesMismatch { name: String },

    /// Off-circuit check: `SHA256(protocol_message_preimage)` does not match the expected
    /// message hash.
    #[error("protocol message preimage does not hash to the expected message")]
    MessagePreimageMismatch,

    /// Off-circuit check: the rolling state's protocol parameters changed after the first step,
    /// which should never happen off the lookahead-promotion path.
    #[error("protocol parameters changed unexpectedly past the first step")]
    ProtocolParametersChanged,
}

/// Subcategorization for `IvcCircuitError::InvalidEpochTransition`. Lets negative
/// tests downcast on the specific transition violation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EpochTransitionErrorKind {
    /// The incoming certificate's epoch is neither equal to nor exactly one greater than
    /// the last committed epoch.
    #[error(
        "incoming certificate epoch {incoming_certificate_epoch} is neither same-epoch nor next-epoch \
         (last committed epoch {last_committed_epoch})"
    )]
    EpochGap {
        incoming_certificate_epoch: u64,
        last_committed_epoch: u64,
    },

    /// The rolling state parameters (next) merkle tree commitment, protocol parameters or step counter
    /// do not match the protocol message parameters expected for the given transition type.
    #[error("rolling state parameters do not match the current protocol message parameters")]
    RollingStateParametersDoesNotMatchProtocolMessage,

    /// Off-circuit step transition: the chain's epoch would overflow u64.
    #[error(
        "IvcTransitionType::try_compute_transition_type: epoch overflow advancing past the last committed epoch"
    )]
    EpochOverflow,
}

/// Convert an IVC circuit error into a Plonk synthesis error at gadget boundaries.
///
/// Takes `IvcCircuitError` directly rather than `StmError` (unlike the `halo2` variant) because
/// `halo2_ivc::synthesize` has no `anyhow` wrapping layer — call sites always hold the concrete
/// type and no downcasting is needed.
pub(crate) fn to_synthesis_error(error: IvcCircuitError) -> PlonkError {
    PlonkError::Synthesis(error.to_string())
}
