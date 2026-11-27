use thiserror::Error;

use crate::entities::RawCardanoPoint;

/// Errors of the [PallasChainReader](super::PallasChainReader)
#[derive(Debug, Error)]
pub enum PallasChainReaderError {
    /// The node found none of the candidates on its chain
    #[error("PallasChainReader found no intersection for the candidates {candidates:?}")]
    IntersectionNotFound {
        /// Candidates sent to the node
        candidates: Vec<RawCardanoPoint>,
    },

    /// The node answered the intersection with a point which is not among the candidates
    #[error(
        "PallasChainReader found an intersection at {intersection_point:?}, which is not among the candidates {candidates:?}"
    )]
    IntersectionNotACandidate {
        /// Point answered by the node
        intersection_point: RawCardanoPoint,
        /// Candidates sent to the node
        candidates: Vec<RawCardanoPoint>,
    },

    /// The node acknowledged the intersection with a rollback to another point
    #[error(
        "PallasChainReader expected a rollback to the intersection point {intersection_point:?} as acknowledgement, received a rollback to {rollback_point:?}"
    )]
    AcknowledgementToAnotherPoint {
        /// Point of the intersection
        intersection_point: RawCardanoPoint,
        /// Point of the rollback received
        rollback_point: RawCardanoPoint,
    },

    /// The node acknowledged the intersection with another reply than a rollback
    #[error(
        "PallasChainReader expected a rollback to the intersection point {intersection_point:?} as acknowledgement, received no rollback"
    )]
    AcknowledgementWithoutRollback {
        /// Point of the intersection
        intersection_point: RawCardanoPoint,
    },

    /// The node did not answer the intersection request in time
    #[error("PallasChainReader timed out finding the intersection")]
    IntersectionTimeout,

    /// The node did not acknowledge the intersection in time
    #[error("PallasChainReader timed out waiting for the acknowledgement of the intersection")]
    AcknowledgementTimeout,

    /// The node did not send the next chain block in time
    #[error("PallasChainReader timed out waiting for the next chain block")]
    NextChainBlockTimeout,
}
