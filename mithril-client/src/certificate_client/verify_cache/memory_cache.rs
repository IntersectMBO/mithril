use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;
use std::ops::Add;
use tokio::sync::RwLock;

use crate::certificate_client::CertificateVerifierCache;
use crate::{MithrilCertificate, MithrilResult};

pub type CertificateHash = str;

/// An in-memory cache for the certificate verifier.
pub struct MemoryCertificateVerifierCache {
    expiration_delay: TimeDelta,
    cache: RwLock<HashMap<String, CachedCertificate>>,
}

#[derive(Debug, PartialEq, Clone)]
struct CachedCertificate {
    certificate: MithrilCertificate,
    expire_at: DateTime<Utc>,
}

impl CachedCertificate {
    fn new(certificate: MithrilCertificate, expire_at: DateTime<Utc>) -> Self {
        CachedCertificate {
            certificate,
            expire_at,
        }
    }
}

impl MemoryCertificateVerifierCache {
    /// `MemoryCertificateVerifierCache` factory
    pub fn new(expiration_delay: TimeDelta) -> Self {
        MemoryCertificateVerifierCache {
            expiration_delay,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get the number of elements in the cache
    pub async fn len(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Return true if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.cache.read().await.is_empty()
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifierCache for MemoryCertificateVerifierCache {
    // todo: implement staged / commit system
    async fn stage_certificate(
        &self,
        _certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()> {
        let mut cache = self.cache.write().await;
        cache.insert(
            certificate.hash.to_owned(),
            CachedCertificate::new(certificate, Utc::now().add(self.expiration_delay)),
        );
        Ok(())
    }

    async fn get_certificate_by_hash(
        &self,
        certificate_hash: &CertificateHash,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        let cache = self.cache.read().await;
        Ok(cache
            .get(certificate_hash)
            .filter(|cached| cached.expire_at >= Utc::now())
            .map(|cached| cached.certificate.clone()))
    }

    async fn reset(&self) -> MithrilResult<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_tools {
    use mithril_common::entities::Certificate;

    use super::*;

    impl MemoryCertificateVerifierCache {
        /// `Test only` Populate the cache with the given certificates
        pub(crate) fn with_items<T>(mut self, chain: T) -> Self
        where
            T: IntoIterator<Item = MithrilCertificate>,
        {
            let expire_at = Utc::now() + self.expiration_delay;
            self.cache = RwLock::new(
                chain
                    .into_iter()
                    .map(|cert| {
                        (
                            cert.hash.clone(),
                            CachedCertificate::new(cert.clone(), expire_at),
                        )
                    })
                    .collect(),
            );
            self
        }

        /// `Test only` Populate the cache with the given certificates
        pub(crate) fn with_items_from_chain<'a, T>(self, chain: T) -> Self
        where
            T: IntoIterator<Item = &'a Certificate>,
        {
            self.with_items(chain.into_iter().map(|cert| cert.clone().try_into().unwrap()))
        }

        /// `Test only` Return the content of the cache (without the expiration date)
        pub(crate) async fn content(&self) -> HashMap<String, MithrilCertificate> {
            self.cache
                .read()
                .await
                .clone()
                .into_iter()
                .map(|(k, v)| (k, v.certificate))
                .collect()
        }

        /// `Test only` Overwrite the expiration date of an entry the given certificate hash.
        ///
        /// panic if the key is not found
        pub(crate) async fn overwrite_expiration_date(
            &self,
            certificate_hash: &CertificateHash,
            expire_at: DateTime<Utc>,
        ) {
            let mut cache = self.cache.write().await;
            cache.get_mut(certificate_hash).expect("Key not found").expire_at = expire_at;
        }

        /// `Test only` Get the cached value for the given certificate hash
        pub(super) async fn get_cached_value(
            &self,
            certificate_hash: &CertificateHash,
        ) -> Option<CachedCertificate> {
            self.cache.read().await.get(certificate_hash).cloned()
        }
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::Dummy;

    use super::*;

    fn dummy_certificate(hash: &str, previous_hash: &str) -> MithrilCertificate {
        MithrilCertificate {
            hash: hash.to_string(),
            previous_hash: previous_hash.to_string(),
            ..Dummy::dummy()
        }
    }

    #[tokio::test]
    async fn from_certificate_iterator() {
        let chain = vec![
            dummy_certificate("first", "first_parent"),
            dummy_certificate("second", "second_parent"),
        ];
        let cache =
            MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items(chain.clone());

        assert_eq!(
            chain
                .into_iter()
                .map(|c| (c.hash.clone(), c))
                .collect::<HashMap<String, MithrilCertificate>>(),
            cache.content().await
        );
    }

    mod store_validated_certificate {
        use super::*;

        #[tokio::test]
        async fn store_in_empty_cache_add_new_item_that_expire_after_parametrized_delay() {
            let expiration_delay = TimeDelta::hours(1);
            let start_time = Utc::now();
            let cache = MemoryCertificateVerifierCache::new(expiration_delay);
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            let cached = cache
                .get_cached_value("hash")
                .await
                .expect("Cache should have been populated");

            assert_eq!(1, cache.len().await);
            assert_eq!("hash", cached.certificate.hash);
            assert!(cached.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn store_new_hash_push_new_key_at_end_and_dont_alter_existing_values() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items([
                dummy_certificate("existing_hash", "existing_parent"),
                dummy_certificate("another_hash", "another_parent"),
            ]);
            cache
                .stage_certificate(
                    "chain_validation_id",
                    dummy_certificate("new_hash", "new_parent"),
                )
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([
                    (
                        "existing_hash".to_string(),
                        dummy_certificate("existing_hash", "existing_parent")
                    ),
                    (
                        "another_hash".to_string(),
                        dummy_certificate("another_hash", "another_parent")
                    ),
                    (
                        "new_hash".to_string(),
                        dummy_certificate("new_hash", "new_parent")
                    ),
                ]),
                cache.content().await
            );
        }

        #[tokio::test]
        async fn storing_same_hash_update_data_and_expiration_time() {
            let expiration_delay = TimeDelta::days(2);
            let start_time = Utc::now();
            let before_update = dummy_certificate("hash", "parent");
            let unaltered = dummy_certificate("another_hash", "another_parent");
            let expected = MithrilCertificate {
                epoch: before_update.epoch + 10,
                previous_hash: "updated_parent".to_string(),
                ..before_update.clone()
            };
            let cache = MemoryCertificateVerifierCache::new(expiration_delay)
                .with_items([before_update, unaltered.clone()]);

            let initial_value = cache.get_cached_value("hash").await.unwrap();

            cache
                .stage_certificate("chain_validation_id", expected.clone())
                .await
                .unwrap();

            let updated_value = cache.get_cached_value("hash").await.unwrap();

            assert_eq!(2, cache.len().await);
            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash("hash").await.unwrap(),
                "Existing but not updated value should not have been altered"
            );
            assert_ne!(initial_value, updated_value);
            assert_eq!("updated_parent", updated_value.certificate.previous_hash);
            assert!(updated_value.expire_at - start_time >= expiration_delay);
        }
    }

    mod get_previous_hash {
        use super::*;

        #[tokio::test]
        async fn get_previous_hash_when_key_exists() {
            let expected = dummy_certificate("hash", "parent");
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items([
                expected.clone(),
                dummy_certificate("another_hash", "another_parent"),
            ]);

            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash("hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn get_previous_hash_return_none_if_not_found() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items([
                dummy_certificate("hash", "parent"),
                dummy_certificate("another_hash", "another_parent"),
            ]);

            assert_eq!(
                None,
                cache.get_certificate_by_hash("not_found").await.unwrap()
            );
        }

        #[tokio::test]
        async fn get_expired_previous_hash_return_none() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items([dummy_certificate("hash", "parent")]);
            cache
                .overwrite_expiration_date("hash", Utc::now() - TimeDelta::days(5))
                .await;

            assert_eq!(None, cache.get_certificate_by_hash("hash").await.unwrap());
        }
    }

    mod reset {
        use super::*;

        #[tokio::test]
        async fn reset_empty_cache_dont_raise_error() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content().await);
        }

        #[tokio::test]
        async fn reset_not_empty_cache() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items([
                dummy_certificate("hash", "parent"),
                dummy_certificate("another_hash", "another_parent"),
            ]);

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content().await);
        }
    }
}
