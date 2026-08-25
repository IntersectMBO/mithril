use thiserror::Error;

// TODO: remove this allow dead_code when IvcProof::verify is called from non-test code
#[allow(dead_code)]
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum IvcProofError {
    /// Transcript could not be prepared for KZG opening verification.
    #[error("IVC proof rejected: transcript preparation failed")]
    TranscriptPreparationFailed,

    /// Transcript contained unexpected trailing bytes after preparation.
    #[error("IVC proof rejected: transcript was not fully consumed")]
    TranscriptNotFullyConsumed,

    /// Combined accumulator and dual MSM pairing equation did not verify.
    #[error("IVC proof rejected: combined accumulator and dual MSM pairing check failed")]
    MsmPairingCheckFailed,

    /// The PLONK prover (`create_proof`) failed internally.
    #[error("IVC proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// `prove()` was called with a `rolling_state` carrying a genesis state
    /// (`step_counter == 0`). The genesis step is run internally from `genesis_bootstrap`
    /// when `rolling_state` is `None`; callers must only pass a `rolling_state` produced by a
    /// previous proving step.
    #[error(
        "IVC prover called with invalid context: rolling_state must not be a genesis (step_counter == 0) state; pass None to bootstrap from genesis"
    )]
    InvalidProvingContext,

    /// Mismatch between the messages
    #[error(
        "IVC proof rejected: the message used to create the proof is different from the input message"
    )]
    InvalidMessage,

    /// New accumulator created from the previous ivc proof and new certificate proof does not verify
    #[error(
        "IVC proof rejected: New accumulator created from the previous ivc proof and new certificate proof does not verify"
    )]
    InvalidNextAccumulator,
}
