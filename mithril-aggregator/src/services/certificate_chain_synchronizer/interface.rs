use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::{Certificate, Epoch};

use crate::entities::OpenMessage;

/// Define how to synchronize the certificate chain with a remote source
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait CertificateChainSynchronizer: Send + Sync {
    /// Synchronize the certificate chain with a remote source
    ///
    /// If `force` is true, the chain will always be synchronized, else it will only synchronize
    /// if the remote source has started a new chain with a new Genesis.
    async fn synchronize_certificate_chain(
        &self,
        current_epoch: Epoch,
        force: bool,
    ) -> StdResult<()>;
}

/// Define how to retrieve remote certificate details
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait RemoteCertificateRetriever: Sync + Send {
    /// Get latest certificate
    async fn get_latest_certificate_details(&self) -> StdResult<Option<Certificate>>;

    /// Get genesis certificate
    async fn get_genesis_certificate_details(&self) -> StdResult<Option<Certificate>>;

    /// Get the certificate with the given hash
    async fn get_certificate_details(&self, hash: &str) -> StdResult<Option<Certificate>>;
}

/// Define how to store the synchronized certificate and retrieve details about the actual local chain
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SynchronizedCertificateStorer: Send + Sync {
    /// Insert a list of Certificates in the database, if some already exists, they will be deleted before inserting
    async fn insert_or_replace_many(&self, certificates: Vec<Certificate>) -> StdResult<()>;

    /// Get the latest genesis Certificate
    async fn get_latest_genesis(&self) -> StdResult<Option<Certificate>>;
}

/// Define how to store the open message created at the end of the synchronization process
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait OpenMessageStorer: Send + Sync {
    /// Store an open_message in the database
    async fn insert_or_replace_open_message(&self, open_message: OpenMessage) -> StdResult<()>;
}
