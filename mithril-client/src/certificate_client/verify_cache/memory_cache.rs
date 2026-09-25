use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::certificate_client::{CertificateVerifierCache, CertificateVerifierCacheSpace};
use crate::{MithrilCertificate, MithrilResult};

pub type CertificateHash = str;

const DEFAULT_STAGING_BATCH_TTL: TimeDelta = TimeDelta::minutes(15);

/// An in-memory cache for the certificate verifier.
pub struct MemoryCertificateVerifierCache {
    expiration_delay: TimeDelta,
    staging_expiration_delay: TimeDelta,
    committed: RwLock<HashMap<CertificateVerifierCacheSpace, CommittedSpace>>,
    staged: RwLock<HashMap<String, StagedBatch>>,
}

type CommittedSpace = HashMap<String, CachedCertificate>;

#[derive(Debug, PartialEq, Clone)]
struct CachedCertificate {
    certificate: MithrilCertificate,
    expire_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Clone)]
struct StagedBatch {
    certificates: HashMap<String, MithrilCertificate>,
    batch_expire_at: DateTime<Utc>,
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
            staging_expiration_delay: DEFAULT_STAGING_BATCH_TTL,
            committed: RwLock::new(HashMap::new()),
            staged: RwLock::new(HashMap::new()),
        }
    }

    /// Set how long a staged (uncommitted) batch survives before being silently dropped
    /// instead of committed.
    ///
    /// Warn: Too short and a slow-but-valid `verify_chain` call may never get to commit, and too
    /// long and an abandoned batch from a failed run lingers longer.
    pub fn with_staging_expiration_delay(mut self, staging_expiration_delay: TimeDelta) -> Self {
        self.staging_expiration_delay = staging_expiration_delay;
        self
    }

    /// Get the number of elements in the cache, across all the spaces
    pub async fn len(&self) -> usize {
        self.committed.read().await.values().map(HashMap::len).sum()
    }

    /// Return true if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    fn sweep_expired_batches(staged: &mut HashMap<String, StagedBatch>) {
        let now = Utc::now();
        staged.retain(|_, batch| batch.batch_expire_at >= now);
    }

    fn sweep_expired_committed(
        committed: &mut HashMap<CertificateVerifierCacheSpace, CommittedSpace>,
    ) {
        let now = Utc::now();
        committed.retain(|_, committed_space| {
            committed_space.retain(|_, cached| cached.expire_at >= now);
            !committed_space.is_empty()
        });
    }

    async fn get_unexpired_committed_certificate(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &CertificateHash,
    ) -> Option<MithrilCertificate> {
        self.committed
            .read()
            .await
            .get(space)
            .and_then(|committed_space| committed_space.get(certificate_hash))
            .filter(|cached| cached.expire_at >= Utc::now())
            .map(|cached| cached.certificate.clone())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifierCache for MemoryCertificateVerifierCache {
    async fn stage_certificate(
        &self,
        certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()> {
        let mut staged = self.staged.write().await;

        // Only sweep when staging a new batch to limit performance cost.
        if !staged.contains_key(certificate_chain_validation_id) {
            Self::sweep_expired_batches(&mut staged);
            let mut committed = self.committed.write().await;
            Self::sweep_expired_committed(&mut committed);
        }

        let batch = staged
            .entry(certificate_chain_validation_id.to_string())
            .or_insert_with(|| StagedBatch {
                certificates: HashMap::new(),
                batch_expire_at: Utc::now() + self.staging_expiration_delay,
            });

        batch.certificates.insert(certificate.hash.to_owned(), certificate);

        Ok(())
    }

    async fn commit_staged_certificates(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()> {
        let mut staged = self.staged.write().await;
        Self::sweep_expired_batches(&mut staged);

        let mut committed = self.committed.write().await;
        Self::sweep_expired_committed(&mut committed);

        if let Some(batch) = staged.remove(certificate_chain_validation_id) {
            let certificates_expire_at = Utc::now() + self.expiration_delay;
            let committed_space = committed.entry(space.clone()).or_default();

            for (hash, cert) in batch.certificates {
                committed_space.insert(hash, CachedCertificate::new(cert, certificates_expire_at));
            }
        }

        Ok(())
    }

    async fn get_certificate_by_hash(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &CertificateHash,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        Ok(self
            .get_unexpired_committed_certificate(space, certificate_hash)
            .await)
    }

    async fn certificate_exist(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<bool> {
        Ok(self
            .get_unexpired_committed_certificate(space, certificate_hash)
            .await
            .is_some())
    }

    async fn reset(&self) -> MithrilResult<()> {
        self.staged.write().await.clear();
        self.committed.write().await.clear();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_tools {
    use std::collections::HashSet;

    use mithril_common::entities::Certificate;

    use super::*;

    impl MemoryCertificateVerifierCache {
        /// `Test only` Populate the given space of the cache with the given certificates
        pub(crate) fn with_items<T>(
            mut self,
            space: &CertificateVerifierCacheSpace,
            chain: T,
        ) -> Self
        where
            T: IntoIterator<Item = MithrilCertificate>,
        {
            let expire_at = Utc::now() + self.expiration_delay;
            let committed_space = chain
                .into_iter()
                .map(|cert| {
                    (
                        cert.hash.clone(),
                        CachedCertificate::new(cert.clone(), expire_at),
                    )
                })
                .collect();
            self.committed.get_mut().insert(space.clone(), committed_space);
            self
        }

        /// `Test only` Populate the given space of the cache with the given certificates
        pub(crate) fn with_items_from_chain<'a, T>(
            self,
            space: &CertificateVerifierCacheSpace,
            chain: T,
        ) -> Self
        where
            T: IntoIterator<Item = &'a Certificate>,
        {
            self.with_items(
                space,
                chain.into_iter().map(|cert| cert.clone().try_into().unwrap()),
            )
        }

        /// `Test only` Return the content of the given space of the cache (without the expiration date)
        pub(crate) async fn content(
            &self,
            space: &CertificateVerifierCacheSpace,
        ) -> HashMap<String, MithrilCertificate> {
            self.committed
                .read()
                .await
                .get(space)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k, v.certificate))
                .collect()
        }

        /// `Test only` Return the ids of staged batches
        pub(crate) async fn staged_batch_ids(&self) -> HashSet<String> {
            self.staged.read().await.keys().cloned().collect()
        }

        /// `Test only` Overwrite the expiration date of an entry the given certificate hash.
        ///
        /// panic if the key is not found
        pub(crate) async fn overwrite_expiration_date(
            &self,
            space: &CertificateVerifierCacheSpace,
            certificate_hash: &CertificateHash,
            expire_at: DateTime<Utc>,
        ) {
            let mut cache = self.committed.write().await;
            cache
                .get_mut(space)
                .and_then(|committed_space| committed_space.get_mut(certificate_hash))
                .expect("Key not found")
                .expire_at = expire_at;
        }

        /// `Test only` Overwrite the expiration date of a staged batch.
        ///
        /// panic if the key is not found
        pub(crate) async fn overwrite_staged_expiration_date(
            &self,
            certificate_chain_validation_id: &str,
            expire_at: DateTime<Utc>,
        ) {
            let mut staging = self.staged.write().await;
            staging
                .get_mut(certificate_chain_validation_id)
                .unwrap()
                .batch_expire_at = expire_at;
        }

        /// `Test only` Get the cached value for the given certificate hash
        pub(super) async fn get_cached_value(
            &self,
            space: &CertificateVerifierCacheSpace,
            certificate_hash: &CertificateHash,
        ) -> Option<CachedCertificate> {
            self.committed
                .read()
                .await
                .get(space)
                .and_then(|committed_space| committed_space.get(certificate_hash))
                .cloned()
        }

        /// `Test only` Get the cached value for the given certificate hash
        pub(crate) async fn get_staged_value(
            &self,
            certificate_hash: &CertificateHash,
            certificate_chain_validation_id: &str,
        ) -> Option<MithrilCertificate> {
            self.staged
                .read()
                .await
                .get(certificate_chain_validation_id)
                .and_then(|s| s.certificates.get(certificate_hash))
                .cloned()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};
    use mithril_common::test::double::Dummy;

    use super::*;

    fn space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        )
    }

    fn other_space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::from_ed25519(GenesisEd25519Signer::create_non_deterministic_signer())
                .create_verifier(),
        )
    }

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
        let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
            .with_items(&space(), chain.clone());

        assert_eq!(
            chain
                .into_iter()
                .map(|c| (c.hash.clone(), c))
                .collect::<HashMap<String, MithrilCertificate>>(),
            cache.content(&space()).await
        );
    }

    mod stage_commit {
        use super::*;

        #[tokio::test]
        async fn staging_a_certificate_does_not_make_it_retrievable_before_commit() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn committing_makes_previously_staged_certificates_retrievable() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn committing_one_id_does_not_expose_certificates_staged_under_another_id() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_id_a", dummy_certificate("hash_a", "parent"))
                .await
                .unwrap();
            cache
                .stage_certificate("chain_id_b", dummy_certificate("hash_b", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_id_a")
                .await
                .unwrap();

            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash_a")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash_b").await.unwrap()
            );
        }

        #[tokio::test]
        async fn committing_an_unknown_id_is_a_no_op_not_an_error() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));

            cache
                .commit_staged_certificates(&space(), "never_staged")
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn committing_the_same_id_twice_is_a_no_op_the_second_time() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap(); // must not panic or error
        }

        #[tokio::test]
        async fn committing_an_expired_staged_batch_does_not_commit_it() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn commiting_in_empty_cache_add_new_item_that_expire_after_parametrized_delay() {
            let expiration_delay = TimeDelta::hours(1);
            let start_time = Utc::now();
            let cache = MemoryCertificateVerifierCache::new(expiration_delay);
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let cached = cache
                .get_cached_value(&space(), "hash")
                .await
                .expect("Cache should have been populated");

            assert_eq!(1, cache.len().await);
            assert_eq!("hash", cached.certificate.hash);
            assert!(cached.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn commiting_new_hash_push_new_key_at_end_and_dont_alter_existing_values() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items(
                &space(),
                [
                    dummy_certificate("existing_hash", "existing_parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            );
            cache
                .stage_certificate(
                    "chain_validation_id",
                    dummy_certificate("new_hash", "new_parent"),
                )
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
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
                cache.content(&space()).await
            );
        }

        #[tokio::test]
        async fn commiting_a_certificate_with_an_existing_hash_update_data_and_expiration_time() {
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
                .with_items(&space(), [before_update, unaltered.clone()]);

            let initial_value = cache.get_cached_value(&space(), "hash").await.unwrap();

            cache
                .stage_certificate("chain_validation_id", expected.clone())
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            let updated_value = cache.get_cached_value(&space(), "hash").await.unwrap();

            assert_eq!(2, cache.len().await);
            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap(),
                "Existing but not updated value should not have been altered"
            );
            assert_ne!(initial_value, updated_value);
            assert_eq!("updated_parent", updated_value.certificate.previous_hash);
            assert!(updated_value.expire_at - start_time >= expiration_delay);
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_expired_batches() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("to_commit_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("remaining_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();
            cache
                .stage_certificate("abandoned_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .overwrite_staged_expiration_date("abandoned_id", Utc::now() - TimeDelta::hours(1))
                .await;

            assert_eq!(3, cache.staged_batch_ids().await.len());

            cache
                .commit_staged_certificates(&space(), "to_commit_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["remaining_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn committing_certificates_sweeps_away_expired_committed_certificates() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::zero()).with_items(
                &space(),
                [
                    dummy_certificate("expired_hash", "parent"),
                    dummy_certificate("new_hash", "parent"),
                ],
            );
            cache
                .overwrite_expiration_date(&space(), "new_hash", Utc::now() + TimeDelta::hours(1))
                .await;

            assert_eq!(2, cache.content(&space()).await.len());

            cache.commit_staged_certificates(&space(), "second_id").await.unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_sweeps_away_other_expired_batches() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .overwrite_staged_expiration_date("expired_batch", Utc::now() - TimeDelta::hours(1))
                .await;

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_batch".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[tokio::test]
        async fn staging_a_new_batch_sweeps_away_expired_committed_certificates() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::zero()).with_items(
                &space(),
                [
                    dummy_certificate("expired_hash", "parent"),
                    dummy_certificate("new_hash", "parent"),
                ],
            );
            cache
                .overwrite_expiration_date(&space(), "new_hash", Utc::now() + TimeDelta::hours(1))
                .await;

            assert_eq!(2, cache.content(&space()).await.len());

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[tokio::test]
        async fn staging_under_an_existing_batch_does_not_sweep_other_expired_batches() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_staging_expiration_delay(TimeDelta::hours(1));
            cache
                .stage_certificate("existing_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .overwrite_staged_expiration_date("expired_batch", Utc::now() - TimeDelta::hours(1))
                .await;

            // staging a second certificate under an id that is already staged must not sweep
            cache
                .stage_certificate("existing_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["expired_batch".to_string(), "existing_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }
    }

    mod get_previous_hash {
        use super::*;

        #[tokio::test]
        async fn get_previous_hash_when_key_exists() {
            let expected = dummy_certificate("hash", "parent");
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items(
                &space(),
                [expected.clone(), dummy_certificate("another_hash", "another_parent")],
            );

            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[tokio::test]
        async fn get_previous_hash_return_none_if_not_found() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items(
                &space(),
                [
                    dummy_certificate("hash", "parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            );

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "not_found").await.unwrap()
            );
        }

        #[tokio::test]
        async fn get_expired_previous_hash_return_none() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")]);
            cache
                .overwrite_expiration_date(&space(), "hash", Utc::now() - TimeDelta::days(5))
                .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }
    }

    mod certificate_exist {
        use super::*;

        #[tokio::test]
        async fn returns_false_for_a_hash_never_committed() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_true_for_a_committed_hash() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")]);

            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_false_for_an_expired_committed_entry() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")]);
            cache
                .overwrite_expiration_date(&space(), "hash", Utc::now() - TimeDelta::days(1))
                .await;

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn returns_false_for_a_staged_but_uncommitted_hash() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }
    }

    mod spaces {
        use super::*;

        #[tokio::test]
        async fn populating_a_space_keeps_the_other_spaces() {
            let other_space = other_space();
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")])
                .with_items(&other_space, [dummy_certificate("other_hash", "parent")]);

            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
            assert!(cache.certificate_exist(&other_space, "other_hash").await.unwrap());
        }

        #[tokio::test]
        async fn certificate_committed_in_a_space_is_not_retrievable_from_another_space() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&other_space(), "hash").await.unwrap()
            );
            assert!(!cache.certificate_exist(&other_space(), "hash").await.unwrap());
        }

        #[tokio::test]
        async fn same_hash_committed_in_two_spaces_is_retrieved_per_space() {
            let certificate = dummy_certificate("hash", "parent");
            let other_certificate = dummy_certificate("hash", "other_parent");
            let other_space = other_space();
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_id_a", certificate.clone())
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_id_a")
                .await
                .unwrap();
            cache
                .stage_certificate("chain_id_b", other_certificate.clone())
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&other_space, "chain_id_b")
                .await
                .unwrap();

            assert_eq!(
                Some(certificate),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                Some(other_certificate),
                cache.get_certificate_by_hash(&other_space, "hash").await.unwrap()
            );
            assert_eq!(2, cache.len().await);
        }

        #[tokio::test]
        async fn sweeping_expired_certificates_drops_the_emptied_spaces() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("expired_hash", "parent")]);
            cache
                .overwrite_expiration_date(
                    &space(),
                    "expired_hash",
                    Utc::now() - TimeDelta::hours(1),
                )
                .await;

            cache
                .commit_staged_certificates(&other_space(), "never_staged")
                .await
                .unwrap();

            assert!(cache.committed.read().await.is_empty());
        }
    }

    mod reset {
        use super::*;

        #[tokio::test]
        async fn reset_empty_cache_dont_raise_error() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[tokio::test]
        async fn reset_clears_committed_data() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1)).with_items(
                &space(),
                [
                    dummy_certificate("hash", "parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            );

            assert_eq!(2, cache.content(&space()).await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[tokio::test]
        async fn reset_clears_committed_data_of_all_spaces() {
            let other_space = other_space();
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1))
                .with_items(&space(), [dummy_certificate("hash", "parent")]);
            cache
                .stage_certificate("chain_id", dummy_certificate("another_hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&other_space, "chain_id")
                .await
                .unwrap();

            cache.reset().await.unwrap();

            assert!(cache.is_empty().await);
        }

        #[tokio::test]
        async fn reset_clears_staged_data() {
            let cache = MemoryCertificateVerifierCache::new(TimeDelta::hours(1));
            cache
                .stage_certificate("chain_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(1, cache.staged_batch_ids().await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }
    }
}
