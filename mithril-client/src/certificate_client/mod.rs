//! A client which retrieves and validates certificates from an aggregator.
//!
//! In order to do so it defines a [CertificateClient] exposes the following features:
//!  - [get][CertificateClient::get]: get a certificate data from its hash
//!  - [list][CertificateClient::list]: get the list of available certificates
//!  - [verify_chain][CertificateClient::verify_chain]: verify a certificate chain
//!
//! # Get a certificate
//!
//! To get a certificate using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificate = client.certificate().get("CERTIFICATE_HASH").await?.unwrap();
//!
//! println!("Certificate hash={}, signed_message={}", certificate.hash, certificate.signed_message);
//! #    Ok(())
//! # }
//! ```
//!
//! # List available certificates
//!
//! To list available certificates using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = mithril_client::ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificates = client.certificate().list().await?;
//!
//! for certificate in certificates {
//!     println!("Certificate hash={}, signed_message={}", certificate.hash, certificate.signed_message);
//! }
//! #    Ok(())
//! # }
//! ```
//!
//! # Validate a certificate chain
//!
//! To validate a certificate using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificate = client.certificate().verify_chain("CERTIFICATE_HASH").await?;
//!
//! println!("Chain of Certificate (hash: {}) is valid", certificate.hash);
//! #    Ok(())
//! # }
//! ```

mod api;
mod fetch;
mod verify;
#[cfg(feature = "unstable")]
mod verify_cache;

pub use api::*;
pub use verify::MithrilCertificateVerifier;
#[cfg(feature = "unstable")]
pub use verify_cache::MemoryCertificateVerifierCache;

#[cfg(test)]
pub(crate) mod tests_utils {
    use mithril_common::entities::Certificate;
    use mithril_common::messages::CertificateMessage;
    use mockall::predicate::eq;
    use std::sync::Arc;

    use crate::feedback::{FeedbackReceiver, FeedbackSender};
    use crate::test_utils::TestLogger;

    use super::*;

    #[derive(Default)]
    pub(crate) struct CertificateClientTestBuilder {
        aggregator_requester: MockCertificateAggregatorRequest,
        genesis_verification_key: Option<String>,
        feedback_receivers: Vec<Arc<dyn FeedbackReceiver>>,
        #[cfg(feature = "unstable")]
        verifier_cache: Option<Arc<dyn CertificateVerifierCache>>,
    }

    impl CertificateClientTestBuilder {
        pub fn config_aggregator_requester_mock(
            mut self,
            config: impl FnOnce(&mut MockCertificateAggregatorRequest),
        ) -> Self {
            config(&mut self.aggregator_requester);
            self
        }

        pub fn with_genesis_verification_key(mut self, genesis_verification_key: String) -> Self {
            self.genesis_verification_key = Some(genesis_verification_key);
            self
        }

        pub fn add_feedback_receiver(
            mut self,
            feedback_receiver: Arc<dyn FeedbackReceiver>,
        ) -> Self {
            self.feedback_receivers.push(feedback_receiver);
            self
        }

        #[cfg(feature = "unstable")]
        pub fn with_verifier_cache(
            mut self,
            verifier_cache: Arc<dyn CertificateVerifierCache>,
        ) -> Self {
            self.verifier_cache = Some(verifier_cache);
            self
        }

        /// Builds a new [CertificateClient] with the given configuration.
        ///
        /// If no genesis verification key is provided, a [MockCertificateVerifier] will be used,
        /// else a [MithrilCertificateVerifier] will be used.
        pub fn build(self) -> CertificateClient {
            let logger = TestLogger::stdout();
            let aggregator_client = Arc::new(self.aggregator_requester);

            let certificate_verifier: Arc<dyn CertificateVerifier> =
                match self.genesis_verification_key {
                    None => Arc::new(MockCertificateVerifier::new()),
                    Some(genesis_verification_key) => Arc::new(
                        MithrilCertificateVerifier::new(
                            aggregator_client.clone(),
                            &genesis_verification_key,
                            FeedbackSender::new(&self.feedback_receivers),
                            #[cfg(feature = "unstable")]
                            self.verifier_cache,
                            #[cfg(feature = "future_snark")]
                            None,
                            logger.clone(),
                        )
                        .unwrap(),
                    ),
                };

            CertificateClient::new(aggregator_client.clone(), certificate_verifier, logger)
        }
    }

    impl MockCertificateAggregatorRequest {
        pub(crate) fn expect_certificate_chain(&mut self, certificate_chain: Vec<Certificate>) {
            for certificate in certificate_chain {
                let hash = certificate.hash.clone();
                let message: CertificateMessage = certificate.try_into().unwrap();

                self.expect_get_by_hash()
                    .with(eq(hash))
                    .once()
                    .returning(move |_| Ok(Some(message.to_owned())));
            }
        }
    }
}
