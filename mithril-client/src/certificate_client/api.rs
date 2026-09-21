use async_trait::async_trait;
use std::sync::Arc;

use mithril_common::logging::LoggerExtensions;

use crate::certificate_client::fetch::InternalCertificateRetriever;
use crate::certificate_client::{fetch, verify};
use crate::{MithrilCertificate, MithrilCertificateListItem, MithrilResult};

/// Aggregator client for the Certificate
pub struct CertificateClient {
    pub(super) aggregator_requester: Arc<dyn CertificateAggregatorRequest>,
    pub(super) retriever: Arc<InternalCertificateRetriever>,
    pub(super) verifier: Arc<dyn CertificateVerifier>,
}

/// Define the requests against an aggregator related to Mithril certificate.
#[cfg_attr(test, mockall::automock)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CertificateAggregatorRequest: Send + Sync {
    /// Get the list of latest Mithril Certificates from the aggregator.
    async fn list_latest(&self) -> MithrilResult<Vec<MithrilCertificateListItem>>;

    /// Get a Mithril Certificate for a given hash from the aggregator.
    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<MithrilCertificate>>;
}

impl CertificateClient {
    /// Constructs a new `CertificateClient`.
    pub fn new(
        aggregator_requester: Arc<dyn CertificateAggregatorRequest>,
        verifier: Arc<dyn CertificateVerifier>,
        logger: slog::Logger,
    ) -> Self {
        let _logger = logger.new_with_component_name::<Self>();
        let retriever = Arc::new(InternalCertificateRetriever::new(
            aggregator_requester.clone(),
        ));

        Self {
            aggregator_requester,
            retriever,
            verifier,
        }
    }

    /// Fetch a list of certificates
    pub async fn list(&self) -> MithrilResult<Vec<MithrilCertificateListItem>> {
        fetch::list(self).await
    }

    /// Get a single certificate full information from the aggregator.
    pub async fn get(&self, certificate_hash: &str) -> MithrilResult<Option<MithrilCertificate>> {
        fetch::get(self, certificate_hash).await
    }

    /// Validate the chain starting with the certificate with given `certificate_hash`, return the certificate if
    /// the chain is valid.
    ///
    /// This method will fail if no certificate exists for the given `certificate_hash`.
    pub async fn verify_chain(&self, certificate_hash: &str) -> MithrilResult<MithrilCertificate> {
        verify::verify_chain(self, certificate_hash).await
    }
}

/// API that defines how to validate certificates.
#[cfg_attr(test, mockall::automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CertificateVerifier: Sync + Send {
    /// Validate the chain starting with the given certificate.
    async fn verify_chain(&self, certificate: &MithrilCertificate) -> MithrilResult<()>;
}

/// Certificate verifier cache mode.
#[cfg(feature = "unstable")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CertificateVerifierCacheMode {
    /// Full verification mode
    ///
    /// - The whole chain is validated.
    /// - Cached certificates are cryptographically re-verified.
    /// - The cache only ever saves a network round-trip, never a security check.
    #[default]
    FullVerification,
    /// Early stop verification mode
    ///
    /// - The chain is validated until a cached certificate is reached.
    /// - The certificate chained to a cached certificate is verified exactly as in full verification mode.
    /// - Cached certificates are trusted without being re-verified, as they were committed after a full validation of their chain.
    /// - The verified certificates are committed to the cache even when the validation stops early.
    /// - The cache saves security checks, so it must be protected against tampering.
    EarlyStopVerification,
}

#[cfg(feature = "unstable")]
/// API that defines how to cache certificates validation results.
#[cfg_attr(test, mockall::automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CertificateVerifierCache: Sync + Send {
    /// Stage a certificate to the cache, unavailable until it is committed.
    async fn stage_certificate(
        &self,
        certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()>;

    /// Commit all certificates that have been staged with the given certificate chain validation id.
    async fn commit_staged_certificates(
        &self,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()>;

    /// Get the certificate with the given hash if present in the cache.
    async fn get_certificate_by_hash(
        &self,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>>;

    /// Check that a committed certificate with the given hash exists in the cache.
    async fn certificate_exist(&self, certificate_hash: &str) -> MithrilResult<bool>;

    /// Reset the stored values
    async fn reset(&self) -> MithrilResult<()>;
}
