use anyhow::Context;
use async_trait::async_trait;
#[cfg(feature = "unstable")]
use slog::warn;
use slog::{Logger, trace};
use std::sync::Arc;

#[cfg(feature = "unstable")]
use mithril_common::certificate_chain::CertificateRetriever;
#[cfg(all(test, feature = "unstable"))]
use mithril_common::crypto_helper::GenesisEd25519VerificationKey;
use mithril_common::{
    certificate_chain::{
        CertificateVerifier as CommonCertificateVerifier,
        MithrilCertificateVerifier as CommonMithrilCertificateVerifier,
    },
    crypto_helper::GenesisVerifier,
    entities::Certificate,
    logging::LoggerExtensions,
};

use crate::certificate_client::fetch::InternalCertificateRetriever;
use crate::certificate_client::{
    CertificateAggregatorRequest, CertificateClient, CertificateVerifier,
};
#[cfg(feature = "unstable")]
use crate::certificate_client::{
    CertificateVerifierCache, CertificateVerifierCacheMode, fetch::CachedCertificateRetriever,
};
use crate::feedback::{FeedbackSender, MithrilEvent};
use crate::{MithrilCertificate, MithrilResult};

#[inline]
pub(super) async fn verify_chain(
    client: &CertificateClient,
    certificate_hash: &str,
) -> MithrilResult<MithrilCertificate> {
    let certificate = client
        .retriever
        .get(certificate_hash)
        .await?
        .with_context(|| format!("No certificate exist for hash '{certificate_hash}'"))?;

    client.verifier.verify_chain(&certificate).await.with_context(|| {
        format!("Certificate chain of certificate '{certificate_hash}' is invalid")
    })?;

    Ok(certificate)
}

/// Implementation of a [CertificateVerifier] that can send feedbacks using
/// the [feedback][crate::feedback] mechanism.
pub struct MithrilCertificateVerifier {
    internal_verifier: Arc<dyn CommonCertificateVerifier>,
    feedback_sender: FeedbackSender,
    #[cfg(feature = "unstable")]
    verifier_cache: Option<Arc<dyn CertificateVerifierCache>>,
    #[cfg(feature = "unstable")]
    _cache_mode: CertificateVerifierCacheMode, // will be used when the EarlyStopVerification is implemented
    logger: Logger,
}

impl MithrilCertificateVerifier {
    /// Constructs a new `MithrilCertificateVerifier`.
    pub fn new(
        aggregator_requester: Arc<dyn CertificateAggregatorRequest>,
        genesis_verification_key: &str,
        feedback_sender: FeedbackSender,
        #[cfg(feature = "unstable")] verifier_cache: Option<Arc<dyn CertificateVerifierCache>>,
        #[cfg(feature = "unstable")] cache_mode: CertificateVerifierCacheMode,
        logger: Logger,
    ) -> MithrilResult<MithrilCertificateVerifier> {
        let logger = logger.new_with_component_name::<Self>();
        let retriever = Arc::new(InternalCertificateRetriever::new(aggregator_requester));
        #[cfg(feature = "unstable")]
        let certificate_retriever: Arc<dyn CertificateRetriever> = match verifier_cache.as_ref() {
            Some(cache) => Arc::new(CachedCertificateRetriever::new(
                retriever,
                cache.clone(),
                logger.clone(),
            )),
            None => retriever.clone(),
        };
        #[cfg(not(feature = "unstable"))]
        let certificate_retriever = retriever;

        let genesis_verifier = Arc::new(
            GenesisVerifier::try_from_hex(genesis_verification_key)
                .with_context(|| "Invalid genesis verification key")?,
        );
        let internal_verifier = Arc::new(CommonMithrilCertificateVerifier::new(
            logger.clone(),
            certificate_retriever,
            genesis_verifier,
        ));

        Ok(Self {
            internal_verifier,
            feedback_sender,
            #[cfg(feature = "unstable")]
            verifier_cache,
            #[cfg(feature = "unstable")]
            _cache_mode: cache_mode,
            logger,
        })
    }

    async fn verify(
        &self,
        certificate_chain_validation_id: &str,
        certificate: Certificate,
    ) -> MithrilResult<Option<Certificate>> {
        let certificate_hash = certificate.hash.clone();
        let previous_certificate = self.internal_verifier.verify_certificate(&certificate).await?;
        #[cfg(not(feature = "unstable"))]
        let certificate_fetched_from_cache = false;
        #[cfg(feature = "unstable")]
        let certificate_fetched_from_cache = self.matches_committed_certificate(&certificate).await;

        #[cfg(feature = "unstable")]
        if let Some(cache) = self.verifier_cache.as_ref() {
            match certificate.try_into() {
                Ok(message) => {
                    if let Err(err) = cache
                        .stage_certificate(certificate_chain_validation_id, message)
                        .await
                    {
                        warn!(
                            self.logger, "Failed to stage certificate to cache";
                            "hash" => &certificate_hash, "error" => ?err
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        self.logger, "Failed to convert certificate to message before caching";
                        "hash" => &certificate_hash, "error" => ?err
                    );
                }
            }
        }

        trace!(self.logger, "Certificate validated"; "hash" => &certificate_hash);

        let event = if certificate_fetched_from_cache {
            MithrilEvent::CertificateFetchedFromCache {
                certificate_hash: certificate_hash.clone(),
                certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            }
        } else {
            MithrilEvent::CertificateValidated {
                certificate_hash: certificate_hash.clone(),
                certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            }
        };

        self.feedback_sender.send_event(event).await;

        Ok(previous_certificate)
    }

    /// Since the cache is only committed once the whole chain is validated, a certificate whose hash
    /// binds its content and equal to the one committed under its hash was verified within a valid
    /// chain and served by the cache.
    #[cfg(feature = "unstable")]
    async fn matches_committed_certificate(&self, certificate: &Certificate) -> bool {
        let Some(cache) = self.verifier_cache.as_ref() else {
            return false;
        };

        match cache.get_certificate_by_hash(&certificate.hash).await {
            Ok(committed_certificate) => committed_certificate.is_some_and(|committed| {
                CachedCertificateRetriever::matches_hash(certificate, &committed.hash)
                    && MithrilCertificate::try_from(certificate.clone())
                        .is_ok_and(|certificate| certificate == committed)
            }),
            Err(err) => {
                warn!(
                    self.logger, "Failed to retrieve certificate from cache";
                    "hash" => &certificate.hash, "error" => ?err
                );
                false
            }
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifier for MithrilCertificateVerifier {
    async fn verify_chain(&self, certificate: &MithrilCertificate) -> MithrilResult<()> {
        // Todo: move most of this code in the `mithril_common` verifier by defining
        // a new `verify_chain` method that take a callback called when a certificate is
        // validated.
        let certificate_chain_validation_id = MithrilEvent::new_certificate_chain_validation_id();
        self.feedback_sender
            .send_event(MithrilEvent::CertificateChainValidationStarted {
                certificate_chain_validation_id: certificate_chain_validation_id.clone(),
            })
            .await;

        let mut current_certificate: Option<Certificate> = Some(certificate.clone().try_into()?);
        loop {
            match current_certificate {
                None => break,
                Some(next) => {
                    current_certificate =
                        self.verify(&certificate_chain_validation_id, next).await?
                }
            }
        }

        #[cfg(feature = "unstable")]
        if let Some(cache) = self.verifier_cache.as_ref()
            && let Err(err) = cache
                .commit_staged_certificates(&certificate_chain_validation_id)
                .await
        {
            warn!(
                self.logger, "Failed to commit the staged certificate to cache";
                "certificate_chain_validation_id" => &certificate_chain_validation_id, "error" => ?err
            );
        }

        self.feedback_sender
            .send_event(MithrilEvent::CertificateChainValidated {
                certificate_chain_validation_id,
            })
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::builder::CertificateChainBuilder;

    use crate::certificate_client::tests_utils::CertificateClientTestBuilder;
    use crate::certificate_client::{
        CertificateAggregatorRequest, MockCertificateAggregatorRequest,
    };
    use crate::feedback::StackFeedbackReceiver;
    use crate::test_utils::TestLogger;

    use super::*;

    fn ed25519_verification_key_hex(genesis_verifier: &GenesisVerifier) -> String {
        genesis_verifier.to_ed25519_verification_key().try_into().unwrap()
    }

    #[tokio::test]
    async fn validating_chain_send_feedbacks() {
        let chain = CertificateChainBuilder::new()
            .with_total_certificates(3)
            .with_certificates_per_epoch(1)
            .build();
        let last_certificate_hash = chain.first().unwrap().hash.clone();

        let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_certificate_chain(chain.certificates_chained.clone())
            })
            .with_genesis_verification_key(ed25519_verification_key_hex(&chain.genesis_verifier))
            .add_feedback_receiver(feedback_receiver.clone())
            .build();

        certificate_client
            .verify_chain(&last_certificate_hash)
            .await
            .expect("Chain validation should succeed");

        let actual = feedback_receiver.stacked_events();
        let id = actual[0].event_id();

        let expected = {
            let mut vec = vec![MithrilEvent::CertificateChainValidationStarted {
                certificate_chain_validation_id: id.to_string(),
            }];
            vec.extend(chain.certificates_chained.into_iter().map(|c| {
                MithrilEvent::CertificateValidated {
                    certificate_chain_validation_id: id.to_string(),
                    certificate_hash: c.hash,
                }
            }));
            vec.push(MithrilEvent::CertificateChainValidated {
                certificate_chain_validation_id: id.to_string(),
            });
            vec
        };

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn verify_chain_return_certificate_with_given_hash() {
        let chain = CertificateChainBuilder::new()
            .with_total_certificates(3)
            .with_certificates_per_epoch(1)
            .build();
        let last_certificate_hash = chain.first().unwrap().hash.clone();

        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_certificate_chain(chain.certificates_chained.clone())
            })
            .with_genesis_verification_key(ed25519_verification_key_hex(&chain.genesis_verifier))
            .build();

        let certificate = certificate_client
            .verify_chain(&last_certificate_hash)
            .await
            .expect("Chain validation should succeed");

        assert_eq!(certificate.hash, last_certificate_hash);
    }

    fn build_verifier_from_genesis_key_string(genesis_verification_key: &str) -> MithrilResult<()> {
        let aggregator_client: Arc<dyn CertificateAggregatorRequest> =
            Arc::new(MockCertificateAggregatorRequest::new());
        MithrilCertificateVerifier::new(
            aggregator_client,
            genesis_verification_key,
            FeedbackSender::new(&[]),
            #[cfg(feature = "unstable")]
            None,
            #[cfg(feature = "unstable")]
            CertificateVerifierCacheMode::default(),
            TestLogger::stdout(),
        )
        .map(|_| ())
    }

    #[test]
    fn constructor_accepts_legacy_single_ed25519_verification_key() {
        let chain = CertificateChainBuilder::new()
            .with_total_certificates(1)
            .with_certificates_per_epoch(1)
            .build();
        let legacy_hex = ed25519_verification_key_hex(&chain.genesis_verifier);

        build_verifier_from_genesis_key_string(&legacy_hex)
            .expect("legacy single-Ed25519 verification key must be accepted");
    }

    #[test]
    fn constructor_rejects_empty_verification_key() {
        build_verifier_from_genesis_key_string("")
            .expect_err("empty verification key must be rejected");
    }

    #[cfg(feature = "future_snark")]
    mod verification_key_formats {
        use mithril_common::crypto_helper::{
            GenesisSchnorrSigner, GenesisVerificationKeyBundle, ProtocolKey,
        };

        use super::*;

        fn dual_verification_key_hex(
            genesis_verifier: &GenesisVerifier,
            schnorr_signer: &GenesisSchnorrSigner,
        ) -> String {
            let bundle = GenesisVerificationKeyBundle::new(
                genesis_verifier.to_ed25519_verification_key(),
                schnorr_signer.verification_key(),
            );
            ProtocolKey::new(bundle).to_bytes_hex().unwrap()
        }

        #[test]
        fn constructor_accepts_dual_verification_key_bundle() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(1)
                .with_certificates_per_epoch(1)
                .build();
            let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let dual_hex = dual_verification_key_hex(&chain.genesis_verifier, &schnorr_signer);

            build_verifier_from_genesis_key_string(&dual_hex)
                .expect("dual verification key bundle must be accepted");
        }

        #[tokio::test]
        async fn verify_chain_succeeds_with_dual_bundle_on_pythagoras_chain() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(3)
                .with_certificates_per_epoch(1)
                .build();
            let last_certificate_hash = chain.first().unwrap().hash.clone();
            let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let dual_hex = dual_verification_key_hex(&chain.genesis_verifier, &schnorr_signer);

            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    mock.expect_certificate_chain(chain.certificates_chained.clone())
                })
                .with_genesis_verification_key(dual_hex)
                .build();

            certificate_client
                .verify_chain(&last_certificate_hash)
                .await
                .expect(
                    "dual verification key bundle must validate a chain whose genesis is the legacy single-signature variant",
                );
        }

        #[tokio::test]
        async fn verify_chain_succeeds_with_legacy_verification_key_on_lagrange_chain() {
            use mithril_common::entities::SupportedEra;

            let chain = CertificateChainBuilder::new()
                .with_total_certificates(3)
                .with_certificates_per_epoch(1)
                .with_mithril_era(SupportedEra::Lagrange)
                .build();
            let last_certificate_hash = chain.first().unwrap().hash.clone();
            let legacy_hex = ed25519_verification_key_hex(&chain.genesis_verifier);

            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    mock.expect_certificate_chain(chain.certificates_chained.clone())
                })
                .with_genesis_verification_key(legacy_hex)
                .build();

            certificate_client
                .verify_chain(&last_certificate_hash)
                .await
                .expect(
                    "legacy single-Ed25519 verification key must validate a Lagrange-era chain (SNARK half silently skipped per the dual-bundle policy)",
                );
        }
    }

    #[cfg(feature = "unstable")]
    mod cache {
        use chrono::TimeDelta;
        use std::collections::HashSet;

        use mithril_common::test::builder::CertificateChainingMethod;

        use crate::certificate_client::MockCertificateAggregatorRequest;
        use crate::certificate_client::verify_cache::MemoryCertificateVerifierCache;
        use crate::test_utils::TestLogger;

        use super::*;

        fn build_verifier_with_cache(
            aggregator_client_mock_config: impl FnOnce(&mut MockCertificateAggregatorRequest),
            genesis_verification_key: GenesisEd25519VerificationKey,
            cache: Arc<dyn CertificateVerifierCache>,
        ) -> MithrilCertificateVerifier {
            let mut aggregator_client = MockCertificateAggregatorRequest::new();
            aggregator_client_mock_config(&mut aggregator_client);
            let genesis_verification_key: String = genesis_verification_key.try_into().unwrap();

            MithrilCertificateVerifier::new(
                Arc::new(aggregator_client),
                &genesis_verification_key,
                FeedbackSender::new(&[]),
                Some(cache),
                CertificateVerifierCacheMode::FullVerification,
                TestLogger::stdout(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn genesis_certificates_verification_result_is_staged_to_cache() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(1)
                .with_certificates_per_epoch(1)
                .build();
            let genesis_certificate = chain.last().unwrap();
            assert!(genesis_certificate.is_genesis());

            let cache = Arc::new(MemoryCertificateVerifierCache::new(TimeDelta::hours(1)));
            let verifier = build_verifier_with_cache(
                |_mock| {},
                chain.genesis_verifier.to_ed25519_verification_key(),
                cache.clone(),
            );

            verifier
                .verify("chain_validation_id", genesis_certificate.clone())
                .await
                .unwrap();

            assert_eq!(
                cache
                    .get_staged_value(&genesis_certificate.hash, "chain_validation_id")
                    .await,
                Some(genesis_certificate.clone().try_into().unwrap())
            );
        }

        #[tokio::test]
        async fn non_genesis_certificates_verification_result_is_staged_to_cache() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(2)
                .with_certificates_per_epoch(1)
                .build();
            let certificate = chain.first().unwrap();
            let genesis_certificate = chain.last().unwrap();
            assert!(!certificate.is_genesis());

            let cache = Arc::new(MemoryCertificateVerifierCache::new(TimeDelta::hours(1)));
            let verifier = build_verifier_with_cache(
                |mock| mock.expect_certificate_chain(vec![genesis_certificate.clone()]),
                chain.genesis_verifier.to_ed25519_verification_key(),
                cache.clone(),
            );

            verifier
                .verify("chain_validation_id", certificate.clone())
                .await
                .unwrap();

            assert_eq!(
                cache.get_staged_value(&certificate.hash, "chain_validation_id").await,
                Some(certificate.clone().try_into().unwrap())
            );
        }

        #[tokio::test]
        async fn cached_certificate_send_certificate_fetched_from_cache_feedback_event() {
            let feedback_receiver = Arc::new(StackFeedbackReceiver::new());
            let feedback_receiver_clone = feedback_receiver.clone();
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(1)
                .with_certificates_per_epoch(1)
                .build();
            let certificate = chain.last().unwrap();

            let cache = Arc::new(
                MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                    .with_items_from_chain(chain.iter()),
            );
            let mut verifier = build_verifier_with_cache(
                |_mock| {},
                chain.genesis_verifier.to_ed25519_verification_key(),
                cache.clone(),
            );
            verifier.feedback_sender = FeedbackSender::new(&[feedback_receiver_clone]);

            verifier
                .verify("chain_validation_id", certificate.clone())
                .await
                .unwrap();

            assert_eq!(
                vec![MithrilEvent::CertificateFetchedFromCache {
                    certificate_chain_validation_id: "chain_validation_id".to_string(),
                    certificate_hash: certificate.hash.clone(),
                }],
                feedback_receiver.stacked_events()
            );
        }

        #[tokio::test]
        async fn verify_returns_none_for_genesis_certificate() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(1)
                .with_certificates_per_epoch(1)
                .build();
            let genesis_certificate = chain.last().unwrap();
            assert!(genesis_certificate.is_genesis());

            let cache = Arc::new(
                MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                    .with_items_from_chain(chain.iter()),
            );
            let verifier = build_verifier_with_cache(
                |_mock| {},
                chain.genesis_verifier.to_ed25519_verification_key(),
                cache.clone(),
            );

            let parent = verifier
                .verify(
                    "certificate_chain_validation_id",
                    genesis_certificate.clone(),
                )
                .await
                .unwrap();

            assert!(
                parent.is_none(),
                "Expected no certificate to verify, got: {parent:?}",
            );
        }

        #[tokio::test]
        async fn verification_uses_cached_ancestors_after_fetching_the_requested_certificate() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(6)
                .with_certificates_per_epoch(3)
                .build();
            let certificate_to_verify = chain.first().unwrap();

            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(3))
                .with_items_from_chain(chain.iter());

            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    // For now the first certificate is always fetched from network
                    mock.expect_certificate(certificate_to_verify.clone(), 1);
                })
                .with_genesis_verification_key(ed25519_verification_key_hex(
                    &chain.genesis_verifier,
                ))
                .with_verifier_cache(Arc::new(cache))
                .build();

            certificate_client
                .verify_chain(&certificate_to_verify.hash)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn verify_chain_return_fetch_uncached_certificate_from_network() {
            // Scenario:
            // | Certificate | epoch |         Parent | Cached? | Fetched from network? |
            // |     [index] |       |                |         |                       |
            // |------------:|------:|---------------:|---------|-----------------------|
            // |     n°6 [0] |     3 |            n°5 | No      | Yes                   |
            // |     n°5 [1] |     3 |            n°4 | No      | Yes                   |
            // |     n°4 [2] |     2 |            n°3 | Yes     | No                    |
            // |     n°3 [3] |     2 |            n°2 | Yes     | No                    |
            // |     n°2 [4] |     2 |            n°1 | No      | Yes                   |
            // |     n°1 [5] |     1 | None (genesis) | Yes     | No                    |
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(6)
                .with_certificates_per_epoch(3)
                .with_certificate_chaining_method(CertificateChainingMethod::Sequential)
                .build();
            let last_certificate_hash = chain.first().unwrap().hash.clone();

            let cached_certificates =
                vec![chain[2].clone(), chain[3].clone(), chain.last().unwrap().clone()];
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(3))
                .with_items_from_chain(&cached_certificates);

            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    mock.expect_certificate_chain(vec![
                        chain[0].clone(),
                        chain[1].clone(),
                        chain[4].clone(),
                    ])
                })
                .with_genesis_verification_key(ed25519_verification_key_hex(
                    &chain.genesis_verifier,
                ))
                .with_verifier_cache(Arc::new(cache))
                .build();

            let certificate =
                certificate_client.verify_chain(&last_certificate_hash).await.unwrap();

            assert_eq!(certificate.hash, last_certificate_hash);
        }

        #[tokio::test]
        async fn cached_certificate_are_verified() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(2)
                .with_certificates_per_epoch(1)
                // Note: `CertificateChainingMethod::ToMasterCertificate` link certificate based on
                // their epoch, which conflicts with the epoch tempering below
                .with_certificate_chaining_method(CertificateChainingMethod::Sequential)
                .with_genesis_certificate_processor(&|certificate, _context, _signer| {
                    let mut certificate = certificate;
                    certificate.epoch += 2;
                    certificate
                })
                .build();
            let last_certificate = chain.first().unwrap();
            let genesis_certificate = chain.last().unwrap();

            // All certificates are cached except the last two (to cross an epoch boundary) and the genesis
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(3))
                .with_items_from_chain([genesis_certificate]);

            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    // For now the first certificate is always fetched from network
                    mock.expect_certificate(last_certificate.clone(), 1);
                })
                .with_genesis_verification_key(ed25519_verification_key_hex(
                    &chain.genesis_verifier,
                ))
                .with_verifier_cache(Arc::new(cache))
                .build();

            let res = certificate_client.verify_chain(&last_certificate.hash).await;

            assert!(
                res.is_err(),
                "A tampered cached certificate must fail verification, not be trusted"
            )
        }

        #[tokio::test]
        async fn successful_verify_chain_commits_all_staged_certificates() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(3)
                .with_certificates_per_epoch(1)
                .build();
            let last_certificate_hash = chain.first().unwrap().hash.clone();

            let cache = Arc::new(MemoryCertificateVerifierCache::new(TimeDelta::hours(1)));
            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    mock.expect_certificate_chain(chain.certificates_chained.clone())
                })
                .with_genesis_verification_key(ed25519_verification_key_hex(
                    &chain.genesis_verifier,
                ))
                .with_verifier_cache(cache.clone())
                .build();

            certificate_client.verify_chain(&last_certificate_hash).await.unwrap();

            let expected_hashes: HashSet<String> = chain.iter().map(|c| c.hash.clone()).collect();
            assert_eq!(
                expected_hashes,
                cache.content().await.keys().cloned().collect::<HashSet<_>>()
            );
        }

        #[tokio::test]
        async fn failed_verify_chain_never_commits_any_staged_certificate() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(3)
                .with_certificates_per_epoch(1)
                .with_certificate_chaining_method(CertificateChainingMethod::Sequential)
                .with_standard_certificate_processor(&|certificate, context| {
                    let mut certificate = certificate;
                    if !context.is_last_certificate() {
                        certificate.epoch += 2;
                    }
                    certificate
                })
                .build();
            let last_certificate_hash = chain.first().unwrap().hash.clone();

            let cache = Arc::new(MemoryCertificateVerifierCache::new(TimeDelta::hours(1)));
            let certificate_client = CertificateClientTestBuilder::default()
                .config_aggregator_requester_mock(|mock| {
                    mock.expect_certificate_chain(chain.certificates_chained.clone())
                })
                .with_genesis_verification_key(ed25519_verification_key_hex(
                    &chain.genesis_verifier,
                ))
                .with_verifier_cache(cache.clone())
                .build();

            certificate_client
                .verify_chain(&last_certificate_hash)
                .await
                .expect_err("chain should fail due to the tampered certificates");

            assert_eq!(
                HashSet::new(),
                cache.content().await.keys().cloned().collect::<HashSet<_>>()
            );
        }
    }
}
