//! Certifiers of circuit verification key digests against the genesis-signed registry.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use slog::{Logger, warn};
use thiserror::Error;
use tokio::sync::RwLock;

use mithril_common::certificate_chain::CircuitVerificationKeyCertifier;
use mithril_common::crypto_helper::{CircuitVerificationKeyDigest, GenesisVerifier};
use mithril_common::entities::Epoch;
use mithril_common::logging::LoggerExtensions;
use mithril_common::{StdError, StdResult};

use crate::{CircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetriever};

/// Time to live in seconds of the registry cached by
/// [CachedCircuitVerificationKeyCertifier].
///
/// Once elapsed, the registry is retrieved and verified again, so a registry updated while a
/// node is running (e.g. a revocation) is picked up without a restart.
pub const REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS: i64 = 3600;

/// Delay in seconds after which [CachedCircuitVerificationKeyCertifier] retries a failed
/// refresh, so a registry published right after a transient failure does not wait a whole time
/// to live.
pub const REGISTRY_REFRESH_RETRY_DELAY_IN_SECONDS: i64 = 300;

/// Maximum age in seconds of the last successful verification of the registry cached by
/// [CachedCircuitVerificationKeyCertifier].
///
/// Once exceeded, a node whose refreshes keep failing fails closed, so an outage of the registry
/// source cannot hide a revocation from a running node indefinitely.
pub const REGISTRY_VERIFICATION_MAXIMUM_AGE_IN_SECONDS: i64 = 24 * 3600;

/// Errors raised by a [CircuitVerificationKeyCertifier] when obtaining a trusted registry.
#[derive(Error, Debug)]
pub enum CircuitVerificationKeyCertifierError {
    /// The signed registry could not be retrieved from its source.
    #[error("circuit verification key registry retrieval failed")]
    RegistryRetrieval(#[source] StdError),

    /// The genesis signature of the retrieved registry is invalid, or its signed payload cannot
    /// be parsed.
    ///
    /// A registry published for another network is also rejected here, as each network signs its
    /// own registry with its own genesis key.
    #[error("circuit verification key registry has an invalid genesis signature")]
    InvalidRegistrySignature(#[source] StdError),

    /// The cached registry could not be refreshed since longer than the maximum age of its
    /// verification.
    #[error(
        "circuit verification key registry could not be refreshed for {age_in_seconds} seconds, more than the {maximum_age_in_seconds} seconds allowed since its last verification"
    )]
    RegistryRefreshOverdue {
        /// Seconds elapsed since the cached registry was last verified.
        age_in_seconds: i64,
        /// Maximum seconds allowed since the last verification.
        maximum_age_in_seconds: i64,
        /// Failure of the last refresh.
        source: StdError,
    },
}

/// Provides the verified circuit verification key registry the digests are checked against.
///
/// Implemented by the certifiers of this crate, so a certifier can decorate another one, e.g. to
/// cache the verified registry.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CircuitVerificationKeyRegistryProvider: Sync + Send {
    /// Obtain the verified registry.
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry>;
}

/// A [CircuitVerificationKeyCertifier] retrieving the registry and verifying its genesis
/// signature at every use.
///
/// Wrap it in a [CachedCircuitVerificationKeyCertifier] to avoid retrieving the registry at
/// every check. Fail-closed: any retrieval or verification failure fails the check.
pub struct MithrilCircuitVerificationKeyCertifier {
    registry_retriever: Arc<dyn CircuitVerificationKeyRegistryRetriever>,
    genesis_verifier: Arc<GenesisVerifier>,
}

impl MithrilCircuitVerificationKeyCertifier {
    /// Build a certifier from a registry retriever and the genesis verifier holding the registry
    /// signing key, which scopes the registry to its network.
    pub fn new(
        registry_retriever: Arc<dyn CircuitVerificationKeyRegistryRetriever>,
        genesis_verifier: Arc<GenesisVerifier>,
    ) -> Self {
        Self {
            registry_retriever,
            genesis_verifier,
        }
    }

    /// Check that every digest is allowed by the verified registry for the given epoch.
    fn certify(
        registry: &CircuitVerificationKeyRegistry,
        digests: &[CircuitVerificationKeyDigest],
        epoch: Epoch,
    ) -> StdResult<()> {
        registry
            .check(digests, epoch)
            .map_err(|e| anyhow!(e))
            .with_context(|| "Circuit verification key certification failed")
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryProvider for MithrilCircuitVerificationKeyCertifier {
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        let signed_registry = self
            .registry_retriever
            .retrieve_signed_registry()
            .await
            .map_err(|e| CircuitVerificationKeyCertifierError::RegistryRetrieval(e.into()))?;

        signed_registry
            .verify(&self.genesis_verifier)
            .map_err(|e| CircuitVerificationKeyCertifierError::InvalidRegistrySignature(e).into())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for MithrilCircuitVerificationKeyCertifier {
    async fn check(&self, digests: &[CircuitVerificationKeyDigest], epoch: Epoch) -> StdResult<()> {
        let registry = self.get_verified_registry().await?;

        Self::certify(&registry, digests, epoch)
    }
}

/// A verified registry together with its refresh schedule.
struct VerifiedRegistryCache {
    /// The verified registry.
    registry: CircuitVerificationKeyRegistry,

    /// Time the registry was last obtained and verified.
    verified_at: DateTime<Utc>,

    /// Time of the last refresh attempt, successful or not.
    refreshed_at: DateTime<Utc>,

    /// Time from which the registry is refreshed again.
    next_refresh_at: DateTime<Utc>,
}

impl VerifiedRegistryCache {
    /// Cache a registry verified now, to be refreshed once the time to live elapsed.
    fn verified(registry: CircuitVerificationKeyRegistry, time_to_live_in_seconds: i64) -> Self {
        let now = Utc::now();

        Self {
            registry,
            verified_at: now,
            refreshed_at: now,
            next_refresh_at: now + TimeDelta::seconds(time_to_live_in_seconds),
        }
    }

    /// Whether the cached registry does not need a refresh yet.
    ///
    /// A cache refreshed in the future (the clock jumped backwards) is stale, so it forces a
    /// refresh instead of staying fresh until the clock catches up.
    fn is_fresh(&self) -> bool {
        (self.refreshed_at..self.next_refresh_at).contains(&Utc::now())
    }

    /// Whether a refreshed registry replaces the cached one: a newer version, or the cached
    /// registry verified again.
    fn is_superseded_by(&self, refreshed: &CircuitVerificationKeyRegistry) -> bool {
        refreshed.version > self.registry.version || *refreshed == self.registry
    }

    /// Keep the cached registry after a failed refresh, to be refreshed again once the delay
    /// elapsed.
    fn postpone_refresh(&mut self, delay_in_seconds: i64) {
        self.refreshed_at = Utc::now();
        self.next_refresh_at = self.refreshed_at + TimeDelta::seconds(delay_in_seconds);
    }

    /// Seconds elapsed since the cached registry was last verified.
    fn verified_age_in_seconds(&self) -> i64 {
        (Utc::now() - self.verified_at).num_seconds()
    }
}

/// A [CircuitVerificationKeyCertifier] decorating a [CircuitVerificationKeyRegistryProvider] with
/// a cache of the verified registry for [REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS].
///
/// Once elapsed, the registry is obtained again from the decorated provider, so a registry
/// updated while the node runs (e.g. a revocation) is picked up without a restart. A refresh
/// that fails, or yields a registry that is not newer than the cached one, is logged and keeps
/// the cached registry until a retry after [REGISTRY_REFRESH_RETRY_DELAY_IN_SECONDS], so an
/// outage of the registry source does not stop a running node. The node fails closed without
/// any verified registry, and once the cached registry could not be refreshed for
/// [REGISTRY_VERIFICATION_MAXIMUM_AGE_IN_SECONDS], so the outage cannot hide a revocation
/// indefinitely.
pub struct CachedCircuitVerificationKeyCertifier {
    /// Provider of the verified registry.
    provider: Arc<dyn CircuitVerificationKeyRegistryProvider>,

    /// Seconds a verified registry is served from the cache before a refresh.
    cache_time_to_live_in_seconds: i64,

    /// Seconds before a failed refresh is retried.
    refresh_retry_delay_in_seconds: i64,

    /// Maximum seconds since the last successful verification before failing closed.
    verification_maximum_age_in_seconds: i64,

    /// The last verified registry with its refresh schedule.
    verified_registry_cache: RwLock<Option<VerifiedRegistryCache>>,

    /// Logger.
    logger: Logger,
}

impl CachedCircuitVerificationKeyCertifier {
    /// Build a caching decorator over the given provider.
    pub fn new(provider: Arc<dyn CircuitVerificationKeyRegistryProvider>, logger: Logger) -> Self {
        Self {
            provider,
            cache_time_to_live_in_seconds: REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS,
            refresh_retry_delay_in_seconds: REGISTRY_REFRESH_RETRY_DELAY_IN_SECONDS,
            verification_maximum_age_in_seconds: REGISTRY_VERIFICATION_MAXIMUM_AGE_IN_SECONDS,
            verified_registry_cache: RwLock::new(None),
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    #[cfg(test)]
    fn with_cache_time_to_live_in_seconds(mut self, cache_time_to_live_in_seconds: i64) -> Self {
        self.cache_time_to_live_in_seconds = cache_time_to_live_in_seconds;
        self
    }

    #[cfg(test)]
    fn with_refresh_retry_delay_in_seconds(mut self, refresh_retry_delay_in_seconds: i64) -> Self {
        self.refresh_retry_delay_in_seconds = refresh_retry_delay_in_seconds;
        self
    }

    #[cfg(test)]
    fn with_verification_maximum_age_in_seconds(
        mut self,
        verification_maximum_age_in_seconds: i64,
    ) -> Self {
        self.verification_maximum_age_in_seconds = verification_maximum_age_in_seconds;
        self
    }

    /// Replace the cached registry with the refreshed one when it supersedes it, otherwise keep
    /// the cached registry until a retry, failing closed once it could not be refreshed for
    /// longer than the maximum age of its verification.
    fn refresh_cached_registry(
        &self,
        cache: &mut VerifiedRegistryCache,
        refreshed: StdResult<CircuitVerificationKeyRegistry>,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        match refreshed {
            Ok(registry) if cache.is_superseded_by(&registry) => {
                *cache =
                    VerifiedRegistryCache::verified(registry, self.cache_time_to_live_in_seconds);
            }
            Ok(registry) => {
                warn!(
                    self.logger,
                    "Refreshed circuit verification key registry is not newer than the cached one, keeping the cached registry";
                    "refreshed_version" => registry.version,
                    "cached_version" => cache.registry.version,
                );
                cache.postpone_refresh(self.refresh_retry_delay_in_seconds);
            }
            Err(error) => {
                warn!(
                    self.logger,
                    "Circuit verification key registry refresh failed, keeping the cached registry";
                    "error" => ?error,
                    "cached_version" => cache.registry.version,
                    "verified_age_in_seconds" => cache.verified_age_in_seconds(),
                );
                cache.postpone_refresh(self.refresh_retry_delay_in_seconds);
                if cache.verified_age_in_seconds() > self.verification_maximum_age_in_seconds {
                    return Err(
                        CircuitVerificationKeyCertifierError::RegistryRefreshOverdue {
                            age_in_seconds: cache.verified_age_in_seconds(),
                            maximum_age_in_seconds: self.verification_maximum_age_in_seconds,
                            source: error,
                        }
                        .into(),
                    );
                }
            }
        }

        Ok(cache.registry.clone())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyRegistryProvider for CachedCircuitVerificationKeyCertifier {
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        {
            let cache = self.verified_registry_cache.read().await;
            if let Some(cache) = cache.as_ref()
                && cache.is_fresh()
            {
                return Ok(cache.registry.clone());
            }
        }

        let mut cache = self.verified_registry_cache.write().await;
        if let Some(cache) = cache.as_ref()
            && cache.is_fresh()
        {
            return Ok(cache.registry.clone());
        }

        let refreshed = self.provider.get_verified_registry().await;
        match cache.as_mut() {
            Some(cache) => self.refresh_cached_registry(cache, refreshed),
            None => {
                let registry = refreshed?;
                *cache = Some(VerifiedRegistryCache::verified(
                    registry.clone(),
                    self.cache_time_to_live_in_seconds,
                ));

                Ok(registry)
            }
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for CachedCircuitVerificationKeyCertifier {
    async fn check(&self, digests: &[CircuitVerificationKeyDigest], epoch: Epoch) -> StdResult<()> {
        let registry = self.get_verified_registry().await?;

        MithrilCircuitVerificationKeyCertifier::certify(&registry, digests, epoch)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};

    use crate::retriever::MockCircuitVerificationKeyRegistryRetriever;
    use crate::test::TestLogger;
    use crate::test::double::FakeCircuitVerificationKeyRegistryRetriever;
    use crate::{
        CircuitVerificationKeyEntry, CircuitVerificationKeyRegistryError,
        CircuitVerificationKeyRegistryRetrieverError, CircuitVerificationKeyRejection,
        CircuitVerificationKeyRejectionReason, CircuitVerificationKeyStatus,
        SignedCircuitVerificationKeyRegistry,
    };

    use super::*;

    fn digest(seed: u8) -> CircuitVerificationKeyDigest {
        hex::encode([seed; 32]).parse().unwrap()
    }

    fn genesis_signer() -> GenesisSigner {
        GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer())
    }

    fn registry_allowing(
        digests: &[CircuitVerificationKeyDigest],
    ) -> CircuitVerificationKeyRegistry {
        CircuitVerificationKeyRegistry {
            version: 1,
            entries: digests
                .iter()
                .map(|digest| CircuitVerificationKeyEntry {
                    digest: *digest,
                    name: "circuit".to_string(),
                    status: CircuitVerificationKeyStatus::Allowed,
                    start_epoch: Epoch(0),
                    end_epoch: None,
                    comment: None,
                })
                .collect(),
        }
    }

    mod mithril_certifier {
        use super::*;

        fn certifier_over(
            registry: CircuitVerificationKeyRegistry,
            genesis_signer: &GenesisSigner,
        ) -> MithrilCircuitVerificationKeyCertifier {
            let signed_registry =
                SignedCircuitVerificationKeyRegistry::try_new(registry, genesis_signer).unwrap();
            MithrilCircuitVerificationKeyCertifier::new(
                Arc::new(
                    FakeCircuitVerificationKeyRegistryRetriever::from_signed_registry(
                        signed_registry,
                    ),
                ),
                Arc::new(genesis_signer.create_verifier()),
            )
        }

        #[tokio::test]
        async fn check_succeeds_with_a_whitelisted_digest() {
            let genesis_signer = genesis_signer();
            let certifier = certifier_over(registry_allowing(&[digest(1)]), &genesis_signer);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
        }

        #[tokio::test]
        async fn check_propagates_registry_check_errors() {
            let genesis_signer = genesis_signer();
            let certifier = certifier_over(registry_allowing(&[digest(1)]), &genesis_signer);

            let error = certifier.check(&[digest(9)], Epoch(10)).await.unwrap_err();

            assert_eq!(
                error.downcast_ref::<CircuitVerificationKeyRegistryError>(),
                Some(&CircuitVerificationKeyRegistryError::Rejected {
                    epoch: Epoch(10),
                    rejections: vec![CircuitVerificationKeyRejection {
                        digest: digest(9),
                        reason: CircuitVerificationKeyRejectionReason::NotWhitelisted,
                    }],
                }),
                "the registry check error must be preserved, got: {error}"
            );
        }

        #[tokio::test]
        async fn check_fails_closed_when_retrieval_fails() {
            let genesis_signer = genesis_signer();
            let certifier = MithrilCircuitVerificationKeyCertifier::new(
                Arc::new(FakeCircuitVerificationKeyRegistryRetriever::that_fails()),
                Arc::new(genesis_signer.create_verifier()),
            );

            let error = certifier.check(&[digest(1)], Epoch(10)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(CircuitVerificationKeyCertifierError::RegistryRetrieval(_))
                ),
                "a retrieval failure must fail the check, got: {error}"
            );
        }

        #[tokio::test]
        async fn check_rejects_a_registry_signed_by_another_genesis_key() {
            let genesis_signer = genesis_signer();
            let other_genesis_signer = GenesisSigner::from_ed25519(
                GenesisEd25519Signer::create_test_signer(ChaCha20Rng::from_seed([7u8; 32])),
            );
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &other_genesis_signer,
            )
            .unwrap();
            let certifier = MithrilCircuitVerificationKeyCertifier::new(
                Arc::new(
                    FakeCircuitVerificationKeyRegistryRetriever::from_signed_registry(
                        signed_registry,
                    ),
                ),
                Arc::new(genesis_signer.create_verifier()),
            );

            let error = certifier.check(&[digest(1)], Epoch(10)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(CircuitVerificationKeyCertifierError::InvalidRegistrySignature(_))
                ),
                "a registry signed by another genesis key must be rejected, got: {error}"
            );
        }

        #[tokio::test]
        async fn check_retrieves_and_verifies_the_registry_at_every_use() {
            let genesis_signer = genesis_signer();
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &genesis_signer,
            )
            .unwrap();
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(2)
                .returning(move || Ok(signed_registry.clone()));
            let certifier = MithrilCircuitVerificationKeyCertifier::new(
                Arc::new(registry_retriever),
                Arc::new(genesis_signer.create_verifier()),
            );

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(11)).await.unwrap();
        }
    }

    mod cached_certifier {
        use super::*;

        fn cached_certifier_over_retriever(
            registry_retriever: MockCircuitVerificationKeyRegistryRetriever,
            genesis_signer: &GenesisSigner,
        ) -> CachedCircuitVerificationKeyCertifier {
            CachedCircuitVerificationKeyCertifier::new(
                Arc::new(MithrilCircuitVerificationKeyCertifier::new(
                    Arc::new(registry_retriever),
                    Arc::new(genesis_signer.create_verifier()),
                )),
                TestLogger::stdout(),
            )
        }

        fn retriever_returning(
            responses: Vec<
                Result<
                    SignedCircuitVerificationKeyRegistry,
                    CircuitVerificationKeyRegistryRetrieverError,
                >,
            >,
        ) -> MockCircuitVerificationKeyRegistryRetriever {
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            for response in responses {
                registry_retriever
                    .expect_retrieve_signed_registry()
                    .times(1)
                    .return_once(move || response);
            }

            registry_retriever
        }

        fn signed(
            registry: CircuitVerificationKeyRegistry,
            genesis_signer: &GenesisSigner,
        ) -> SignedCircuitVerificationKeyRegistry {
            SignedCircuitVerificationKeyRegistry::try_new(registry, genesis_signer).unwrap()
        }

        fn registry_allowing_at_version(
            version: u64,
            digests: &[CircuitVerificationKeyDigest],
        ) -> CircuitVerificationKeyRegistry {
            CircuitVerificationKeyRegistry {
                version,
                ..registry_allowing(digests)
            }
        }

        fn retrieval_failure() -> CircuitVerificationKeyRegistryRetrieverError {
            CircuitVerificationKeyRegistryRetrieverError(anyhow!("registry source unreachable"))
        }

        #[tokio::test]
        async fn check_retrieves_and_verifies_the_registry_only_once_within_the_time_to_live() {
            let genesis_signer = genesis_signer();
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &genesis_signer,
            )
            .unwrap();
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(1)
                .return_once(move || Ok(signed_registry));
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(11)).await.unwrap();
        }

        #[test]
        fn a_cache_is_fresh_until_its_next_refresh() {
            let cache = VerifiedRegistryCache::verified(registry_allowing(&[digest(1)]), 3600);
            assert!(cache.is_fresh());

            let cache = VerifiedRegistryCache::verified(registry_allowing(&[digest(1)]), 0);
            assert!(!cache.is_fresh(), "a cache due for refresh must be stale");
        }

        #[test]
        fn a_cache_refreshed_in_the_future_is_stale() {
            let cache = VerifiedRegistryCache::verified(registry_allowing(&[digest(1)]), 3600);
            let cache = VerifiedRegistryCache {
                refreshed_at: cache.refreshed_at + TimeDelta::hours(2),
                next_refresh_at: cache.next_refresh_at + TimeDelta::hours(2),
                ..cache
            };

            assert!(
                !cache.is_fresh(),
                "a cache refreshed in the future (backwards clock jump) must be stale"
            );
        }

        #[test]
        fn a_cache_is_superseded_by_a_newer_version_or_by_its_registry_verified_again() {
            let cache =
                VerifiedRegistryCache::verified(registry_allowing_at_version(2, &[digest(1)]), 10);

            assert!(cache.is_superseded_by(&registry_allowing_at_version(3, &[digest(1)])));
            assert!(cache.is_superseded_by(&registry_allowing_at_version(2, &[digest(1)])));
            assert!(!cache.is_superseded_by(&registry_allowing_at_version(2, &[digest(2)])));
            assert!(!cache.is_superseded_by(&registry_allowing_at_version(1, &[digest(1)])));
        }

        #[tokio::test]
        async fn check_refreshes_the_registry_after_the_cache_time_to_live_expires() {
            let genesis_signer = genesis_signer();
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &genesis_signer,
            )
            .unwrap();
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(2)
                .returning(move || Ok(signed_registry.clone()));
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(11)).await.unwrap();
        }

        #[tokio::test]
        async fn check_keeps_the_previously_verified_registry_over_a_refreshed_lower_version() {
            let genesis_signer = genesis_signer();
            let mut newer_registry = registry_allowing(&[digest(1), digest(2)]);
            newer_registry.version = 2;
            let newer_signed_registry =
                SignedCircuitVerificationKeyRegistry::try_new(newer_registry, &genesis_signer)
                    .unwrap();
            let older_signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &genesis_signer,
            )
            .unwrap();
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(1)
                .return_once(move || Ok(newer_signed_registry));
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(1)
                .return_once(move || Ok(older_signed_registry));
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1);

            certifier.check(&[digest(2)], Epoch(10)).await.unwrap();
            certifier
                .check(&[digest(2)], Epoch(11))
                .await
                .expect("the newer registry must be kept over a refreshed lower version");
        }

        #[tokio::test]
        async fn check_keeps_the_previously_verified_registry_when_the_refresh_fails() {
            let genesis_signer = genesis_signer();
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry_allowing(&[digest(1)]),
                &genesis_signer,
            )
            .unwrap();
            let mut registry_retriever = MockCircuitVerificationKeyRegistryRetriever::new();
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(1)
                .return_once(move || Ok(signed_registry));
            registry_retriever
                .expect_retrieve_signed_registry()
                .times(1)
                .return_once(|| {
                    Err(CircuitVerificationKeyRegistryRetrieverError(anyhow!(
                        "registry source unreachable"
                    )))
                });
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier
                .check(&[digest(1)], Epoch(11))
                .await
                .expect("the previously verified registry must be kept when the refresh fails");
        }

        #[tokio::test]
        async fn check_replaces_the_cached_registry_with_a_refreshed_newer_version() {
            let genesis_signer = genesis_signer();
            let registry_retriever = retriever_returning(vec![
                Ok(signed(registry_allowing(&[digest(1)]), &genesis_signer)),
                Ok(signed(
                    registry_allowing_at_version(2, &[digest(2)]),
                    &genesis_signer,
                )),
            ]);
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier
                .check(&[digest(2)], Epoch(11))
                .await
                .expect("the refreshed newer registry must replace the cached one");
        }

        #[tokio::test]
        async fn check_keeps_the_cached_registry_over_a_refreshed_same_version_with_another_content()
         {
            let genesis_signer = genesis_signer();
            let registry_retriever = retriever_returning(vec![
                Ok(signed(registry_allowing(&[digest(1)]), &genesis_signer)),
                Ok(signed(
                    registry_allowing(&[digest(1), digest(2)]),
                    &genesis_signer,
                )),
            ]);
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(2)], Epoch(11)).await.expect_err(
                "the cached registry must be kept over a refreshed same version with another content",
            );
        }

        #[tokio::test]
        async fn check_postpones_the_next_refresh_by_the_retry_delay_after_a_failed_refresh() {
            let genesis_signer = genesis_signer();
            let registry_retriever = retriever_returning(vec![
                Ok(signed(registry_allowing(&[digest(1)]), &genesis_signer)),
                Err(retrieval_failure()),
            ]);
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1)
                .with_refresh_retry_delay_in_seconds(3600);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(11)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(12)).await.unwrap();
        }

        #[tokio::test]
        async fn check_retries_a_failed_refresh_once_the_retry_delay_elapsed() {
            let genesis_signer = genesis_signer();
            let registry_retriever = retriever_returning(vec![
                Ok(signed(registry_allowing(&[digest(1)]), &genesis_signer)),
                Err(retrieval_failure()),
                Ok(signed(
                    registry_allowing_at_version(2, &[digest(2)]),
                    &genesis_signer,
                )),
            ]);
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1)
                .with_refresh_retry_delay_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            certifier.check(&[digest(1)], Epoch(11)).await.unwrap();
            certifier
                .check(&[digest(2)], Epoch(12))
                .await
                .expect("the registry must be refreshed again once the retry delay elapsed");
        }

        #[tokio::test]
        async fn check_fails_closed_once_the_cached_registry_could_not_be_refreshed_for_too_long() {
            let genesis_signer = genesis_signer();
            let registry_retriever = retriever_returning(vec![
                Ok(signed(registry_allowing(&[digest(1)]), &genesis_signer)),
                Err(retrieval_failure()),
            ]);
            let certifier = cached_certifier_over_retriever(registry_retriever, &genesis_signer)
                .with_cache_time_to_live_in_seconds(-1)
                .with_verification_maximum_age_in_seconds(-1);

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            let error = certifier.check(&[digest(1)], Epoch(11)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(CircuitVerificationKeyCertifierError::RegistryRefreshOverdue { .. })
                ),
                "a cached registry not refreshed for longer than the maximum age must fail the check, got: {error}"
            );
        }

        #[tokio::test]
        async fn check_fails_closed_without_a_previously_verified_registry() {
            let genesis_signer = genesis_signer();
            let certifier = CachedCircuitVerificationKeyCertifier::new(
                Arc::new(MithrilCircuitVerificationKeyCertifier::new(
                    Arc::new(FakeCircuitVerificationKeyRegistryRetriever::that_fails()),
                    Arc::new(genesis_signer.create_verifier()),
                )),
                TestLogger::stdout(),
            );

            let error = certifier.check(&[digest(1)], Epoch(10)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(CircuitVerificationKeyCertifierError::RegistryRetrieval(_))
                ),
                "a failed retrieval without any verified registry must fail the check, got: {error}"
            );
        }
    }
}
