/// Errors which can be output by Mithril single signature verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SignatureError {
    /// There is an index out of bounds
    #[error("Received index, {0}, is not lower than the lottery size, {1}.")]
    IndexBoundFailed(u64, u64),

    /// The lottery was actually lost for the signature
    #[error("Lottery for this epoch was lost.")]
    LotteryLost,

    /// This error occurs when the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    #[error("Unsupported aggregate verification key")]
    UnsupportedAggregateVerificationKey,
}
