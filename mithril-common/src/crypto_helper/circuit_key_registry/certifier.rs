//! Certifier of circuit verification key digests against the genesis-signed registry.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::RwLock;

use mithril_stm::CircuitVerificationKeyDigest;

use crate::crypto_helper::GenesisVerifier;
use crate::entities::Epoch;
use crate::{StdError, StdResult};

use super::{CircuitVerificationKeyRegistry, CircuitVerificationKeyRegistryRetriever};

/// Minimum accepted registry version.
///
/// Bumped at release time whenever a revocation ships, it bounds rollback attacks replaying an
/// older, genuinely signed registry that would resurrect a revoked key.
pub const MINIMUM_REGISTRY_VERSION: u64 = 1;

/// Time to live in seconds of the registry cached by
/// [CachedCircuitVerificationKeyCertifier].
///
/// Once elapsed, the registry is retrieved and verified again, so a registry updated while a
/// node is running (e.g. a revocation) is picked up without a restart.
pub const REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS: i64 = 3600;

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

    /// The retrieved registry version is below the compiled minimum.
    #[error(
        "circuit verification key registry version {version} is below the minimum accepted version {minimum_version}"
    )]
    RegistryVersionBelowMinimum {
        /// Version declared by the retrieved registry.
        version: u64,
        /// Minimum version accepted by this build.
        minimum_version: u64,
    },

    /// The refreshed registry version is below the previously verified one.
    #[error(
        "circuit verification key registry version {version} is below the previously verified version {cached_version}"
    )]
    RegistryVersionRollback {
        /// Version declared by the refreshed registry.
        version: u64,
        /// Version of the previously verified registry.
        cached_version: u64,
    },
}

/// Certifies circuit verification key digests against the genesis-signed registry.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CircuitVerificationKeyCertifier: Sync + Send {
    /// Obtain the verified registry the digests are checked against.
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry>;

    /// Check that every digest is whitelisted and not revoked for the given epoch.
    async fn check(&self, digests: &[CircuitVerificationKeyDigest], epoch: Epoch) -> StdResult<()> {
        let registry = self.get_verified_registry().await?;

        registry
            .check(digests, epoch)
            .map_err(|e| anyhow!(e))
            .with_context(|| "Circuit verification key certification failed")
    }
}

/// A [CircuitVerificationKeyCertifier] retrieving and verifying the registry (genesis signature
/// and minimum version) at every use.
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
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for MithrilCircuitVerificationKeyCertifier {
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        let signed_registry = self
            .registry_retriever
            .retrieve_signed_registry()
            .await
            .map_err(|e| CircuitVerificationKeyCertifierError::RegistryRetrieval(e.into()))?;

        let registry = signed_registry
            .verify(&self.genesis_verifier)
            .map_err(CircuitVerificationKeyCertifierError::InvalidRegistrySignature)?;
        if registry.version < MINIMUM_REGISTRY_VERSION {
            return Err(
                CircuitVerificationKeyCertifierError::RegistryVersionBelowMinimum {
                    version: registry.version,
                    minimum_version: MINIMUM_REGISTRY_VERSION,
                }
                .into(),
            );
        }

        Ok(registry)
    }
}

/// A verified registry together with the time it was last obtained.
struct VerifiedRegistryCache {
    /// The verified registry.
    registry: CircuitVerificationKeyRegistry,

    /// Time the registry was last obtained and verified.
    refreshed_at: DateTime<Utc>,
}

/// A [CircuitVerificationKeyCertifier] decorator caching the verified registry for
/// [REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS].
///
/// Once elapsed, the registry is obtained again from the decorated certifier, so a registry
/// updated while the node runs (e.g. a revocation) is picked up without a restart. Fail-closed:
/// a failed refresh fails the check, and a refresh cannot lower the registry version.
pub struct CachedCircuitVerificationKeyCertifier {
    certifier: Arc<dyn CircuitVerificationKeyCertifier>,
    cache_time_to_live_in_seconds: i64,
    verified_registry_cache: RwLock<Option<VerifiedRegistryCache>>,
}

impl CachedCircuitVerificationKeyCertifier {
    /// Build a caching decorator over the given certifier.
    pub fn new(certifier: Arc<dyn CircuitVerificationKeyCertifier>) -> Self {
        Self {
            certifier,
            cache_time_to_live_in_seconds: REGISTRY_CACHE_TIME_TO_LIVE_IN_SECONDS,
            verified_registry_cache: RwLock::new(None),
        }
    }

    #[cfg(test)]
    fn with_cache_time_to_live_in_seconds(mut self, cache_time_to_live_in_seconds: i64) -> Self {
        self.cache_time_to_live_in_seconds = cache_time_to_live_in_seconds;
        self
    }

    /// Whether the cached registry is still within its time to live.
    ///
    /// A negative age (the clock jumped backwards) is treated as stale, so it forces a refresh
    /// instead of keeping the cache fresh until the clock catches up.
    fn is_cache_fresh(&self, cache: &VerifiedRegistryCache) -> bool {
        let age_in_seconds = (Utc::now() - cache.refreshed_at).num_seconds();

        (0..self.cache_time_to_live_in_seconds).contains(&age_in_seconds)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CircuitVerificationKeyCertifier for CachedCircuitVerificationKeyCertifier {
    async fn get_verified_registry(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        {
            let cache = self.verified_registry_cache.read().await;
            if let Some(cache) = cache.as_ref()
                && self.is_cache_fresh(cache)
            {
                return Ok(cache.registry.clone());
            }
        }

        let mut cache = self.verified_registry_cache.write().await;
        if let Some(cache) = cache.as_ref()
            && self.is_cache_fresh(cache)
        {
            return Ok(cache.registry.clone());
        }

        let registry = self.certifier.get_verified_registry().await?;
        if let Some(previous_cache) = cache.as_ref()
            && registry.version < previous_cache.registry.version
        {
            return Err(
                CircuitVerificationKeyCertifierError::RegistryVersionRollback {
                    version: registry.version,
                    cached_version: previous_cache.registry.version,
                }
                .into(),
            );
        }
        *cache = Some(VerifiedRegistryCache {
            registry: registry.clone(),
            refreshed_at: Utc::now(),
        });

        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::crypto_helper::circuit_key_registry::retriever::MockCircuitVerificationKeyRegistryRetriever;
    use crate::crypto_helper::{
        CircuitVerificationKeyEntry, CircuitVerificationKeyRegistryError,
        CircuitVerificationKeyRegistryRetrieverError, CircuitVerificationKeyStatus,
        GenesisEd25519Signer, GenesisSigner, SignedCircuitVerificationKeyRegistry,
    };
    use crate::test::double::FakeCircuitVerificationKeyRegistryRetriever;

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
            version: MINIMUM_REGISTRY_VERSION,
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
                Some(&CircuitVerificationKeyRegistryError::NotWhitelisted {
                    digest: digest(9),
                    epoch: Epoch(10),
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
        async fn check_rejects_a_registry_version_below_the_minimum() {
            let genesis_signer = genesis_signer();
            let mut registry = registry_allowing(&[digest(1)]);
            registry.version = MINIMUM_REGISTRY_VERSION - 1;
            let certifier = certifier_over(registry, &genesis_signer);

            let error = certifier.check(&[digest(1)], Epoch(10)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(
                        CircuitVerificationKeyCertifierError::RegistryVersionBelowMinimum {
                            version: 0,
                            minimum_version: MINIMUM_REGISTRY_VERSION,
                        }
                    )
                ),
                "a registry version below the minimum must be rejected, got: {error}"
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
            CachedCircuitVerificationKeyCertifier::new(Arc::new(
                MithrilCircuitVerificationKeyCertifier::new(
                    Arc::new(registry_retriever),
                    Arc::new(genesis_signer.create_verifier()),
                ),
            ))
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
        fn a_cache_refreshed_in_the_future_is_stale() {
            let genesis_signer = genesis_signer();
            let certifier = CachedCircuitVerificationKeyCertifier::new(Arc::new(
                MithrilCircuitVerificationKeyCertifier::new(
                    Arc::new(FakeCircuitVerificationKeyRegistryRetriever::that_fails()),
                    Arc::new(genesis_signer.create_verifier()),
                ),
            ));
            let cache = VerifiedRegistryCache {
                registry: registry_allowing(&[digest(1)]),
                refreshed_at: Utc::now() + chrono::Duration::hours(2),
            };

            assert!(
                !certifier.is_cache_fresh(&cache),
                "a cache refreshed in the future (backwards clock jump) must be stale"
            );
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
        async fn check_rejects_a_refreshed_registry_with_a_lower_version() {
            let genesis_signer = genesis_signer();
            let mut newer_registry = registry_allowing(&[digest(1)]);
            newer_registry.version = MINIMUM_REGISTRY_VERSION + 1;
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

            certifier.check(&[digest(1)], Epoch(10)).await.unwrap();
            let error = certifier.check(&[digest(1)], Epoch(11)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(
                        CircuitVerificationKeyCertifierError::RegistryVersionRollback {
                            version: 1,
                            cached_version: 2,
                        }
                    )
                ),
                "a refreshed registry with a lower version must be rejected, got: {error}"
            );
        }

        #[tokio::test]
        async fn check_fails_closed_when_the_refresh_fails() {
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
            let error = certifier.check(&[digest(1)], Epoch(11)).await.unwrap_err();

            assert!(
                matches!(
                    error.downcast_ref::<CircuitVerificationKeyCertifierError>(),
                    Some(CircuitVerificationKeyCertifierError::RegistryRetrieval(_))
                ),
                "a failed refresh must fail the check, got: {error}"
            );
        }
    }
}
