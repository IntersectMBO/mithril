use anyhow::Context;
use async_trait::async_trait;
#[cfg(feature = "unstable")]
use slog::Logger;
use std::sync::Arc;

use mithril_common::certificate_chain::{CertificateRetriever, CertificateRetrieverError};
use mithril_common::entities::Certificate;
#[cfg(feature = "unstable")]
use mithril_common::logging::LoggerExtensions;

#[cfg(feature = "unstable")]
use crate::certificate_client::CertificateVerifierCache;
use crate::certificate_client::{CertificateAggregatorRequest, CertificateClient};
use crate::{MithrilCertificate, MithrilCertificateListItem, MithrilResult};

#[inline]
pub(super) async fn list(
    client: &CertificateClient,
) -> MithrilResult<Vec<MithrilCertificateListItem>> {
    client.aggregator_requester.list_latest().await
}

#[inline]
pub(super) async fn get(
    client: &CertificateClient,
    certificate_hash: &str,
) -> MithrilResult<Option<MithrilCertificate>> {
    client.retriever.get(certificate_hash).await
}

/// Internal type to implement the [InternalCertificateRetriever] trait and avoid a circular
/// dependency between the [CertificateClient] and the [CommonMithrilCertificateVerifier] that need
/// a [CertificateRetriever] as a dependency.
pub(super) struct InternalCertificateRetriever {
    aggregator_requester: Arc<dyn CertificateAggregatorRequest>,
}

impl InternalCertificateRetriever {
    pub(super) fn new(
        aggregator_requester: Arc<dyn CertificateAggregatorRequest>,
    ) -> InternalCertificateRetriever {
        InternalCertificateRetriever {
            aggregator_requester,
        }
    }

    pub(super) async fn get(
        &self,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        self.aggregator_requester.get_by_hash(certificate_hash).await
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateRetriever for InternalCertificateRetriever {
    async fn get_certificate_details(
        &self,
        certificate_hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        self.get(certificate_hash)
            .await
            .map_err(CertificateRetrieverError)?
            .map(|message| message.try_into())
            .transpose()
            .map_err(CertificateRetrieverError)?
            .with_context(|| format!("Certificate does not exist: '{certificate_hash}'"))
            .map_err(CertificateRetrieverError)
    }
}

#[cfg(feature = "unstable")]
pub(super) struct CachedCertificateRetriever {
    inner: Arc<dyn CertificateRetriever>,
    cache: Arc<dyn CertificateVerifierCache>,
    logger: Logger,
}

#[cfg(feature = "unstable")]
impl CachedCertificateRetriever {
    pub(super) fn new(
        inner: Arc<dyn CertificateRetriever>,
        cache: Arc<dyn CertificateVerifierCache>,
        logger: Logger,
    ) -> Self {
        Self {
            inner,
            cache,
            logger: logger.new_with_component_name::<Self>(),
        }
    }
}

#[cfg(feature = "unstable")]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateRetriever for CachedCertificateRetriever {
    async fn get_certificate_details(
        &self,
        certificate_hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        let certificate = match self.cache.get_certificate_by_hash(certificate_hash).await {
            Ok(None) => None,
            Ok(Some(message)) => match Certificate::try_from(message) {
                Ok(certificate) if certificate.hash == certificate_hash => Some(certificate),
                Ok(certificate) => {
                    slog::warn!(
                        self.logger, "Cached certificate hash does not match requested hash, it may have been tampered with";
                        "certificate_hash" => certificate_hash, "cached_certificate" => ?certificate,
                    );
                    None
                }
                Err(err) => {
                    slog::warn!(
                        self.logger, "Failed to convert cached certificate to entity";
                        "certificate_hash" => certificate_hash, "error" => ?err
                    );
                    None
                }
            },
            Err(err) => {
                slog::warn!(
                    self.logger, "Failed to retrieve certificate from cache";
                    "certificate_hash" => certificate_hash, "error" => ?err
                );
                None
            }
        };

        match certificate {
            Some(certificate) => Ok(certificate),
            None => self.inner.get_certificate_details(certificate_hash).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use mithril_common::test::double::{Dummy, fake_data};

    use crate::certificate_client::tests_utils::CertificateClientTestBuilder;

    use super::*;

    #[tokio::test]
    async fn get_certificate_list() {
        let expected = vec![
            MithrilCertificateListItem {
                hash: "cert-hash-123".to_string(),
                ..MithrilCertificateListItem::dummy()
            },
            MithrilCertificateListItem {
                hash: "cert-hash-456".to_string(),
                ..MithrilCertificateListItem::dummy()
            },
        ];
        let message = expected.clone();
        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_list_latest().return_once(move || Ok(message));
            })
            .build();
        let items = certificate_client.list().await.unwrap();

        assert_eq!(expected, items);
    }

    #[tokio::test]
    async fn get_certificate_empty_list() {
        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_list_latest().return_once(move || Ok(Vec::new()));
            })
            .build();
        let items = certificate_client.list().await.unwrap();

        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_show_ok_some() {
        let certificate_hash = "cert-hash-123".to_string();
        let certificate = fake_data::certificate(certificate_hash.clone());
        let expected_certificate = certificate.clone();

        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_get_by_hash()
                    .return_once(move |_| {
                        let message: MithrilCertificate = certificate.try_into().unwrap();
                        Ok(Some(message))
                    })
                    .times(1);
            })
            .build();

        let cert = certificate_client
            .get("cert-hash-123")
            .await
            .unwrap()
            .expect("The certificate should be found")
            .try_into()
            .unwrap();

        assert_eq!(expected_certificate, cert);
    }

    #[tokio::test]
    async fn test_show_ok_none() {
        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_get_by_hash().return_once(move |_| Ok(None)).times(1);
            })
            .build();

        assert!(certificate_client.get("cert-hash-123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_show_ko() {
        let certificate_client = CertificateClientTestBuilder::default()
            .config_aggregator_requester_mock(|mock| {
                mock.expect_get_by_hash()
                    .return_once(move |_| Err(anyhow!("an error")))
                    .times(1);
            })
            .build();

        certificate_client
            .get("cert-hash-123")
            .await
            .expect_err("The certificate client should fail here.");
    }

    #[cfg(feature = "unstable")]
    mod cached_retriever {
        use chrono::TimeDelta;

        use mithril_common::test::mock_extensions::MockBuilder;

        use crate::certificate_client::{
            MemoryCertificateVerifierCache, MockCertificateAggregatorRequest,
            MockCertificateVerifierCache,
        };
        use crate::test_utils::TestLogger;

        use super::*;

        #[tokio::test]
        async fn returns_cached_certificate_without_calling_the_inner_retriever() {
            let cached = fake_data::certificate("hash");
            let cache = Arc::new(
                MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                    .with_items_from_chain([&cached]),
            );
            let inner = InternalCertificateRetriever::new(Arc::new(
                MockCertificateAggregatorRequest::new(),
            ));

            let retriever =
                CachedCertificateRetriever::new(Arc::new(inner), cache, TestLogger::stdout());
            let result = retriever.get_certificate_details(&cached.hash).await.unwrap();

            assert_eq!(result, cached);
        }

        #[tokio::test]
        async fn falls_back_to_inner_retriever_on_cache_miss() {
            let certificate = fake_data::certificate("hash");
            let cache = Arc::new(MemoryCertificateVerifierCache::new(TimeDelta::hours(1)));
            let mut mock = MockCertificateAggregatorRequest::new();
            mock.expect_certificate_chain(vec![certificate.clone()]);
            let inner = InternalCertificateRetriever::new(Arc::new(mock));

            let retriever =
                CachedCertificateRetriever::new(Arc::new(inner), cache, TestLogger::stdout());
            let result = retriever.get_certificate_details(&certificate.hash).await.unwrap();

            assert_eq!(result, certificate);
        }

        #[tokio::test]
        async fn falls_back_to_inner_retriever_on_cache_failure() {
            let certificate = fake_data::certificate("hash");
            let cache = MockBuilder::<MockCertificateVerifierCache>::configure(|m| {
                m.expect_get_certificate_by_hash()
                    .returning(|_| Err(anyhow!("cache failed")));
            });

            let mut mock = MockCertificateAggregatorRequest::new();
            mock.expect_certificate_chain(vec![certificate.clone()]);
            let inner = InternalCertificateRetriever::new(Arc::new(mock));

            let retriever =
                CachedCertificateRetriever::new(Arc::new(inner), cache, TestLogger::stdout());
            let result = retriever.get_certificate_details(&certificate.hash).await.unwrap();

            assert_eq!(result, certificate);
        }

        #[tokio::test]
        async fn falls_back_to_inner_retriever_if_cached_certificate_hash_does_not_match() {
            let certificate = fake_data::certificate("hash");
            let tampered_certificate = MithrilCertificate {
                hash: "tampered".to_string(),
                ..certificate.clone().try_into().unwrap()
            };
            let cache = MockBuilder::<MockCertificateVerifierCache>::configure(|m| {
                m.expect_get_certificate_by_hash()
                    .return_once(move |_| Ok(Some(tampered_certificate)));
            });

            let mut mock = MockCertificateAggregatorRequest::new();
            mock.expect_certificate_chain(vec![certificate.clone()]);
            let inner = InternalCertificateRetriever::new(Arc::new(mock));

            let retriever =
                CachedCertificateRetriever::new(Arc::new(inner), cache, TestLogger::stdout());
            let result = retriever.get_certificate_details(&certificate.hash).await.unwrap();

            assert_eq!(result, certificate);
        }

        #[tokio::test]
        async fn falls_back_to_inner_if_cached_certificate_could_not_be_converted_to_entity() {
            let certificate = fake_data::certificate("hash");
            let cache = Arc::new(
                MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items([
                    MithrilCertificate {
                        aggregate_verification_key: "invalid_key".to_string(),
                        ..certificate.clone().try_into().unwrap()
                    },
                ]),
            );
            let mut mock = MockCertificateAggregatorRequest::new();
            mock.expect_certificate_chain(vec![certificate.clone()]);
            let inner = InternalCertificateRetriever::new(Arc::new(mock));

            let retriever =
                CachedCertificateRetriever::new(Arc::new(inner), cache, TestLogger::stdout());
            let result = retriever.get_certificate_details(&certificate.hash).await.unwrap();

            assert_eq!(result, certificate);
        }
    }
}
