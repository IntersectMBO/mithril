//! Aggregator specific certificate chain validation errors

use thiserror::Error;

use mithril_common::entities::Epoch;

/// Error raised when the local certificate chain has an epoch gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "There is an epoch gap between the last certificate epoch ({certificate_epoch:?}) and current epoch ({current_epoch:?}). A leader aggregator must be re-genesis by the owner of the genesis keys, a follower aggregator will automatically catchup with the leader's certificate chain."
)]
pub struct CertificateEpochGap {
    /// Epoch of the last issued certificate.
    pub certificate_epoch: Epoch,

    /// Given current epoch.
    pub current_epoch: Epoch,
}

/// Error raised when the parent of a certificate can not be retrieved from a remote source.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemoteParentCertificateError {
    /// The remote source does not have the parent certificate.
    #[error("The remote source does not have the parent certificate '{0}'")]
    NotFound(String),

    /// The remote source returned another certificate than the requested parent certificate.
    #[error(
        "The remote source returned the certificate '{returned_hash}' instead of the requested parent certificate '{requested_hash}'"
    )]
    Unexpected {
        /// Hash of the requested parent certificate.
        requested_hash: String,

        /// Hash of the certificate returned by the remote source.
        returned_hash: String,
    },
}
