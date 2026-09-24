use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "unstable")]
use mithril_common::crypto_helper::GenesisVerifier;
#[cfg(feature = "unstable")]
use mithril_common::entities::HexEncodedDigest;
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
    /// - Only the certificates committed with the same genesis verification key are trusted, see [CertificateVerifierCacheSpace].
    /// - The verified certificates are committed to the cache even when the validation stops early.
    /// - The cache saves security checks, so it must be protected against tampering.
    EarlyStopVerification,
}

/// Partition of the committed certificates of a cache, bound to the genesis verification key
/// that validated them.
///
/// A certificate committed in a space is only trusted by a client using the same genesis
/// verification key, so that a cache can be shared between clients of different networks.
#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateVerifierCacheSpace(HexEncodedDigest);

#[cfg(feature = "unstable")]
impl CertificateVerifierCacheSpace {
    /// Space of the certificates validated with the given genesis verifier, identified by the
    /// fingerprint of its genesis verification key.
    pub fn from_genesis_verifier(genesis_verifier: &GenesisVerifier) -> Self {
        Self(genesis_verifier.compute_fingerprint())
    }

    /// Hex identifier of the space, safe to use as a file name or a storage key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
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

    /// Commit all certificates that have been staged with the given certificate chain validation id
    /// to the given space.
    async fn commit_staged_certificates(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()>;

    /// Get the certificate with the given hash if committed to the given space.
    async fn get_certificate_by_hash(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>>;

    /// Check that a certificate with the given hash is committed to the given space.
    async fn certificate_exist(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<bool>;

    /// Reset the stored values of all the spaces
    async fn reset(&self) -> MithrilResult<()>;
}
