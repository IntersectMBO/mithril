//! ## SignedEntityService
//!
//! This service is responsible for dealing with [SignedEntity] type.
//! It creates [Artifact] that can be accessed by clients.
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use slog::{Logger, info, warn};
use std::sync::Arc;
use tokio::task::JoinHandle;

use mithril_common::{
    StdResult,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSnapshot, CardanoDatabaseSnapshot,
        CardanoDbBeacon, CardanoStakeDistribution, CardanoTransactionsSnapshot, Certificate, Epoch,
        MithrilStakeDistribution, SignedEntityType, SignedEntityTypeDiscriminants,
    },
    logging::LoggerExtensions,
    signable_builder::{Artifact, SignedEntity},
};

use crate::{
    MetricsService,
    artifact_builder::ArtifactBuilder,
    database::{record::SignedEntityRecord, repository::SignedEntityStorer},
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

/// ArtifactBuilder Service trait
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignedEntityService: Send + Sync {
    /// Create artifact for a signed entity type and a certificate
    async fn create_artifact(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<JoinHandle<StdResult<()>>>;

    /// Return a list of Cardano Database snapshots order by creation date descending.
    async fn get_last_signed_cardano_database_snapshots(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<CardanoDatabaseSnapshot>>>;

    /// Return a Cardano Database snapshot
    async fn get_signed_cardano_database_snapshot_by_id(
        &self,
        signed_entity_id: &str,
    ) -> StdResult<Option<SignedEntity<CardanoDatabaseSnapshot>>>;

    /// Return a list of signed Mithril stake distribution ordered by creation
    /// date descending.
    async fn get_last_signed_mithril_stake_distributions(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<MithrilStakeDistribution>>>;

    /// Return a signed Mithril stake distribution
    async fn get_signed_mithril_stake_distribution_by_id(
        &self,
        signed_entity_id: &str,
    ) -> StdResult<Option<SignedEntity<MithrilStakeDistribution>>>;

    /// Return the last signed Cardano Transaction Snapshot.
    async fn get_last_cardano_transaction_snapshot(
        &self,
    ) -> StdResult<Option<SignedEntity<CardanoTransactionsSnapshot>>>;

    /// Return the last signed Cardano Blocks and Transactions Snapshot.
    async fn get_last_cardano_blocks_transactions_snapshot(
        &self,
    ) -> StdResult<Option<SignedEntity<CardanoBlocksTransactionsSnapshot>>>;

    /// Return a list of signed Cardano stake distribution ordered by creation
    /// date descending.
    async fn get_last_signed_cardano_stake_distributions(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<CardanoStakeDistribution>>>;
}

/// Mithril ArtifactBuilder Service
#[derive(Clone)]
pub struct MithrilSignedEntityService {
    signed_entity_storer: Arc<dyn SignedEntityStorer>,
    mithril_stake_distribution_artifact_builder:
        Arc<dyn ArtifactBuilder<Epoch, MithrilStakeDistribution>>,
    cardano_transactions_artifact_builder:
        Arc<dyn ArtifactBuilder<BlockNumber, CardanoTransactionsSnapshot>>,
    cardano_blocks_transactions_artifact_builder: Arc<
        dyn ArtifactBuilder<(BlockNumber, BlockNumberOffset), CardanoBlocksTransactionsSnapshot>,
    >,
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    cardano_stake_distribution_artifact_builder:
        Arc<dyn ArtifactBuilder<Epoch, CardanoStakeDistribution>>,
    cardano_database_artifact_builder:
        Arc<dyn ArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot>>,
    metrics_service: Arc<MetricsService>,
    logger: Logger,
}

/// ArtifactsBuilder dependencies required by the [MithrilSignedEntityService].
pub struct SignedEntityServiceArtifactsDependencies {
    mithril_stake_distribution_artifact_builder:
        Arc<dyn ArtifactBuilder<Epoch, MithrilStakeDistribution>>,
    cardano_transactions_artifact_builder:
        Arc<dyn ArtifactBuilder<BlockNumber, CardanoTransactionsSnapshot>>,
    cardano_blocks_transactions_artifact_builder: Arc<
        dyn ArtifactBuilder<(BlockNumber, BlockNumberOffset), CardanoBlocksTransactionsSnapshot>,
    >,
    cardano_stake_distribution_artifact_builder:
        Arc<dyn ArtifactBuilder<Epoch, CardanoStakeDistribution>>,
    cardano_database_artifact_builder:
        Arc<dyn ArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot>>,
}

impl SignedEntityServiceArtifactsDependencies {
    /// Create a new instance of [SignedEntityServiceArtifactsDependencies].
    pub fn new(
        mithril_stake_distribution_artifact_builder: Arc<
            dyn ArtifactBuilder<Epoch, MithrilStakeDistribution>,
        >,
        cardano_transactions_artifact_builder: Arc<
            dyn ArtifactBuilder<BlockNumber, CardanoTransactionsSnapshot>,
        >,
        cardano_blocks_transactions_artifact_builder: Arc<
            dyn ArtifactBuilder<(BlockNumber, BlockNumberOffset), CardanoBlocksTransactionsSnapshot>,
        >,
        cardano_stake_distribution_artifact_builder: Arc<
            dyn ArtifactBuilder<Epoch, CardanoStakeDistribution>,
        >,
        cardano_database_artifact_builder: Arc<
            dyn ArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot>,
        >,
    ) -> Self {
        Self {
            mithril_stake_distribution_artifact_builder,
            cardano_transactions_artifact_builder,
            cardano_blocks_transactions_artifact_builder,
            cardano_stake_distribution_artifact_builder,
            cardano_database_artifact_builder,
        }
    }
}

impl MithrilSignedEntityService {
    /// MithrilSignedEntityService factory
    pub fn new(
        signed_entity_storer: Arc<dyn SignedEntityStorer>,
        dependencies: SignedEntityServiceArtifactsDependencies,
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        metrics_service: Arc<MetricsService>,
        logger: Logger,
    ) -> Self {
        Self {
            signed_entity_storer,
            mithril_stake_distribution_artifact_builder: dependencies
                .mithril_stake_distribution_artifact_builder,
            cardano_transactions_artifact_builder: dependencies
                .cardano_transactions_artifact_builder,
            cardano_blocks_transactions_artifact_builder: dependencies
                .cardano_blocks_transactions_artifact_builder,
            cardano_stake_distribution_artifact_builder: dependencies
                .cardano_stake_distribution_artifact_builder,
            cardano_database_artifact_builder: dependencies.cardano_database_artifact_builder,
            signed_entity_type_lock,
            metrics_service,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn create_artifact_task(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<()> {
        info!(
            self.logger, ">> create_artifact_task";
            "signed_entity_type" => ?signed_entity_type, "certificate_hash" => &certificate.hash
        );

        let mut remaining_retries = 2;
        let artifact = loop {
            remaining_retries -= 1;

            match self.compute_artifact(signed_entity_type.clone(), certificate).await {
                Err(error) if remaining_retries == 0 => break Err(error),
                Err(_error) => (),
                Ok(artifact) => break Ok(artifact),
            };
        }?;

        let signed_entity = SignedEntityRecord {
            signed_entity_id: artifact.get_id(),
            signed_entity_type: signed_entity_type.clone(),
            certificate_id: certificate.hash.clone(),
            artifact: serde_json::to_string(&artifact)?,
            created_at: Utc::now(),
        };

        self.signed_entity_storer
            .store_signed_entity(&signed_entity)
            .await
            .with_context(|| {
                format!(
                    "Signed Entity Service can not store signed entity with type: '{signed_entity_type}'"
                )
            })?;

        self.increment_artifact_total_produced_metric_since_startup(signed_entity_type);

        Ok(())
    }

    /// Compute artifact from signed entity type
    async fn compute_artifact(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<Arc<dyn Artifact>> {
        match signed_entity_type.clone() {
            SignedEntityType::MithrilStakeDistribution(epoch) => Ok(Arc::new(
                self.mithril_stake_distribution_artifact_builder
                    .compute_artifact(epoch, certificate)
                    .await
                    .with_context(|| {
                        format!(
                            "Signed Entity Service can not compute artifact for entity type: '{signed_entity_type}'"
                        )
                    })?,
            )),
            SignedEntityType::CardanoStakeDistribution(epoch) => Ok(Arc::new(
                self.cardano_stake_distribution_artifact_builder
                    .compute_artifact(epoch, certificate)
                    .await
                    .with_context(|| {
                        format!(
                            "Signed Entity Service can not compute artifact for entity type: '{signed_entity_type}'"
                        )
                    })?,
            )),
            SignedEntityType::CardanoTransactions(_epoch, block_number) => Ok(Arc::new(
                self.cardano_transactions_artifact_builder
                    .compute_artifact(block_number, certificate)
                    .await
                    .with_context(|| {
                        format!(
                            "Signed Entity Service can not compute artifact for entity type: '{signed_entity_type}'"
                        )
                    })?,
            )),
            SignedEntityType::CardanoBlocksTransactions(_epoch, block_number, block_number_offset) => Ok(Arc::new(
                self.cardano_blocks_transactions_artifact_builder
                    .compute_artifact((block_number, block_number_offset), certificate)
                    .await
                    .with_context(|| {
                        format!(
                            "Signed Entity Service can not compute artifact for entity type: '{signed_entity_type}'"
                        )
                    })?,
            )),
            SignedEntityType::CardanoDatabase(beacon) => Ok(Arc::new(
                self.cardano_database_artifact_builder
                    .compute_artifact(beacon, certificate)
                    .await
                    .with_context(|| {
                        format!(
                            "Signed Entity Service can not compute artifact for entity type: '{signed_entity_type}'"
                        )
                    })?,
            )),
        }
    }

    async fn get_last_signed_entities(
        &self,
        total: usize,
        discriminants: &SignedEntityTypeDiscriminants,
    ) -> StdResult<Vec<SignedEntityRecord>> {
        self.signed_entity_storer
            .get_last_signed_entities_by_type(discriminants, total)
            .await
            .with_context(|| {
                format!(
                    "Signed Entity Service can not get last signed entities with type: '{discriminants:?}'"
                )
            })
    }

    fn increment_artifact_total_produced_metric_since_startup(
        &self,
        signed_entity_type: SignedEntityType,
    ) {
        let metrics = self.metrics_service.clone();
        let metric_counter = match signed_entity_type {
            SignedEntityType::MithrilStakeDistribution(..) => {
                metrics.get_artifact_mithril_stake_distribution_total_produced_since_startup()
            }
            SignedEntityType::CardanoStakeDistribution(..) => {
                metrics.get_artifact_cardano_stake_distribution_total_produced_since_startup()
            }
            SignedEntityType::CardanoTransactions(..) => {
                metrics.get_artifact_cardano_transaction_total_produced_since_startup()
            }
            SignedEntityType::CardanoBlocksTransactions(..) => {
                metrics.get_artifact_cardano_blocks_transactions_total_produced_since_startup()
            }
            SignedEntityType::CardanoDatabase(..) => {
                metrics.get_artifact_cardano_database_total_produced_since_startup()
            }
        };

        metric_counter.increment();
    }
}

#[async_trait]
impl SignedEntityService for MithrilSignedEntityService {
    async fn create_artifact(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<JoinHandle<StdResult<()>>> {
        if self.signed_entity_type_lock.is_locked(&signed_entity_type) {
            return Err(anyhow!(
                "Signed entity type '{:?}' is already locked",
                signed_entity_type
            ));
        }

        let service = self.clone();
        let certificate_cloned = certificate.clone();
        let lock_guard = service.signed_entity_type_lock.lock(&signed_entity_type);

        Ok(tokio::task::spawn(async move {
            let signed_entity_type_clone = signed_entity_type.clone();
            let service_clone = service.clone();
            let result = tokio::task::spawn(async move {
                // The lock is held by the artifact creation task, so the signed entity type stays
                // locked until the artifact is created, even if the returned handle is aborted
                // (aborting it does not cancel the artifact creation).
                let _lock_guard = lock_guard;
                service_clone
                    .create_artifact_task(signed_entity_type_clone, &certificate_cloned)
                    .await
            })
            .await;

            result.with_context(|| format!(
                "Signed Entity Service can not store signed entity with type: '{signed_entity_type}'"
            ))?.inspect_err(|e| warn!(service.logger, "Error while creating artifact"; "error" => ?e))
        }))
    }

    async fn get_last_signed_cardano_database_snapshots(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<CardanoDatabaseSnapshot>>> {
        let signed_entities = self
            .get_last_signed_entities(total, &SignedEntityTypeDiscriminants::CardanoDatabase)
            .await?
            .into_iter()
            .map(|record| record.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signed_entities)
    }

    async fn get_signed_cardano_database_snapshot_by_id(
        &self,
        signed_entity_id: &str,
    ) -> StdResult<Option<SignedEntity<CardanoDatabaseSnapshot>>> {
        let entity: Option<SignedEntity<CardanoDatabaseSnapshot>> = match self
            .signed_entity_storer
            .get_signed_entity(
                signed_entity_id,
                &SignedEntityTypeDiscriminants::CardanoDatabase,
            )
            .await
            .with_context(|| {
                format!(
                    "Signed Entity Service can not get signed entity with id: '{signed_entity_id}'"
                )
            })? {
            Some(entity) => Some(entity.try_into()?),
            None => None,
        };

        Ok(entity)
    }

    async fn get_last_signed_mithril_stake_distributions(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<MithrilStakeDistribution>>> {
        let signed_entities = self
            .get_last_signed_entities(
                total,
                &SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            )
            .await?
            .into_iter()
            .map(|record| record.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signed_entities)
    }

    async fn get_signed_mithril_stake_distribution_by_id(
        &self,
        signed_entity_id: &str,
    ) -> StdResult<Option<SignedEntity<MithrilStakeDistribution>>> {
        let entity: Option<SignedEntity<MithrilStakeDistribution>> = match self
            .signed_entity_storer
            .get_signed_entity(
                signed_entity_id,
                &SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            )
            .await
            .with_context(|| {
                format!(
                    "Signed Entity Service can not get signed entity with id: '{signed_entity_id}'"
                )
            })? {
            Some(entity) => Some(entity.try_into()?),
            None => None,
        };

        Ok(entity)
    }

    async fn get_last_cardano_transaction_snapshot(
        &self,
    ) -> StdResult<Option<SignedEntity<CardanoTransactionsSnapshot>>> {
        self.get_last_signed_entities(1, &SignedEntityTypeDiscriminants::CardanoTransactions)
            .await?
            .pop()
            .map(|r| r.try_into())
            .transpose()
    }

    async fn get_last_cardano_blocks_transactions_snapshot(
        &self,
    ) -> StdResult<Option<SignedEntity<CardanoBlocksTransactionsSnapshot>>> {
        self.get_last_signed_entities(1, &SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
            .await?
            .pop()
            .map(|r| r.try_into())
            .transpose()
    }

    async fn get_last_signed_cardano_stake_distributions(
        &self,
        total: usize,
    ) -> StdResult<Vec<SignedEntity<CardanoStakeDistribution>>> {
        let signed_entities = self
            .get_last_signed_entities(
                total,
                &SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            )
            .await?
            .into_iter()
            .map(|record| record.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signed_entities)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::Ordering, time::Duration};

    use mithril_common::{
        entities::{BlockNumberOffset, CardanoTransactionsSnapshot, Epoch, StakeDistribution},
        signable_builder,
        test::double::fake_data,
    };
    use mithril_metric::CounterValue;
    use serde::{Serialize, de::DeserializeOwned};
    use std::sync::atomic::AtomicBool;

    use crate::artifact_builder::MockArtifactBuilder;
    use crate::database::repository::MockSignedEntityStorer;
    use crate::test::TestLogger;

    use super::*;

    fn create_stake_distribution(epoch: Epoch, signers: usize) -> MithrilStakeDistribution {
        MithrilStakeDistribution::new(
            epoch,
            fake_data::signers_with_stakes(signers),
            &fake_data::protocol_parameters(),
        )
    }

    fn create_cardano_stake_distribution(
        epoch: Epoch,
        stake_distribution: StakeDistribution,
    ) -> CardanoStakeDistribution {
        CardanoStakeDistribution::new(epoch, stake_distribution)
    }

    fn assert_expected<T>(expected: &T, artifact: &Arc<dyn Artifact>)
    where
        T: Serialize + DeserializeOwned,
    {
        let current: T = serde_json::from_str(&serde_json::to_string(&artifact).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&current).unwrap()
        );
    }

    /// Struct that create mocks needed in tests and build objects injecting them.
    struct MockDependencyInjector {
        mock_signed_entity_storer: MockSignedEntityStorer,
        mock_mithril_stake_distribution_artifact_builder:
            MockArtifactBuilder<Epoch, MithrilStakeDistribution>,
        mock_cardano_transactions_artifact_builder:
            MockArtifactBuilder<BlockNumber, CardanoTransactionsSnapshot>,
        mock_cardano_blocks_transactions_artifact_builder: MockArtifactBuilder<
            (BlockNumber, BlockNumberOffset),
            CardanoBlocksTransactionsSnapshot,
        >,
        mock_cardano_stake_distribution_artifact_builder:
            MockArtifactBuilder<Epoch, CardanoStakeDistribution>,
        mock_cardano_database_artifact_builder:
            MockArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot>,
    }

    impl MockDependencyInjector {
        fn new() -> MockDependencyInjector {
            MockDependencyInjector {
                mock_signed_entity_storer: MockSignedEntityStorer::new(),
                mock_mithril_stake_distribution_artifact_builder: MockArtifactBuilder::<
                    Epoch,
                    MithrilStakeDistribution,
                >::new(),
                mock_cardano_transactions_artifact_builder: MockArtifactBuilder::<
                    BlockNumber,
                    CardanoTransactionsSnapshot,
                >::new(),
                mock_cardano_blocks_transactions_artifact_builder: MockArtifactBuilder::<
                    (BlockNumber, BlockNumberOffset),
                    CardanoBlocksTransactionsSnapshot,
                >::new(),
                mock_cardano_stake_distribution_artifact_builder: MockArtifactBuilder::<
                    Epoch,
                    CardanoStakeDistribution,
                >::new(),
                mock_cardano_database_artifact_builder: MockArtifactBuilder::<
                    CardanoDbBeacon,
                    CardanoDatabaseSnapshot,
                >::new(),
            }
        }

        fn build_artifact_builder_service(self) -> MithrilSignedEntityService {
            let dependencies = SignedEntityServiceArtifactsDependencies::new(
                Arc::new(self.mock_mithril_stake_distribution_artifact_builder),
                Arc::new(self.mock_cardano_transactions_artifact_builder),
                Arc::new(self.mock_cardano_blocks_transactions_artifact_builder),
                Arc::new(self.mock_cardano_stake_distribution_artifact_builder),
                Arc::new(self.mock_cardano_database_artifact_builder),
            );
            MithrilSignedEntityService::new(
                Arc::new(self.mock_signed_entity_storer),
                dependencies,
                Arc::new(SignedEntityTypeLock::default()),
                Arc::new(MetricsService::new(TestLogger::stdout()).unwrap()),
                TestLogger::stdout(),
            )
        }

        fn build_artifact_builder_service_with_time_consuming_process(
            mut self,
            atomic_stop: Arc<AtomicBool>,
        ) -> MithrilSignedEntityService {
            struct LongArtifactBuilder {
                atomic_stop: Arc<AtomicBool>,
                snapshot: CardanoDatabaseSnapshot,
            }

            let snapshot = fake_data::cardano_database_snapshot(1);

            #[async_trait]
            impl ArtifactBuilder<CardanoDbBeacon, CardanoDatabaseSnapshot> for LongArtifactBuilder {
                async fn compute_artifact(
                    &self,
                    _beacon: CardanoDbBeacon,
                    _certificate: &Certificate,
                ) -> StdResult<CardanoDatabaseSnapshot> {
                    let mut max_iteration = 100;
                    while !self.atomic_stop.load(Ordering::Relaxed) {
                        max_iteration -= 1;
                        if max_iteration <= 0 {
                            return Err(anyhow!("Test should handle the stop"));
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Ok(self.snapshot.clone())
                }
            }
            let cardano_database_long_artifact_builder = LongArtifactBuilder {
                atomic_stop: atomic_stop.clone(),
                snapshot: snapshot.clone(),
            };

            let artifact_clone: Arc<dyn Artifact> = Arc::new(snapshot);
            let signed_entity_artifact = serde_json::to_string(&artifact_clone).unwrap();
            self.mock_signed_entity_storer
                .expect_store_signed_entity()
                .withf(move |signed_entity| signed_entity.artifact == signed_entity_artifact)
                .return_once(|_| Ok(()));

            let dependencies = SignedEntityServiceArtifactsDependencies::new(
                Arc::new(self.mock_mithril_stake_distribution_artifact_builder),
                Arc::new(self.mock_cardano_transactions_artifact_builder),
                Arc::new(self.mock_cardano_blocks_transactions_artifact_builder),
                Arc::new(self.mock_cardano_stake_distribution_artifact_builder),
                Arc::new(cardano_database_long_artifact_builder),
            );
            MithrilSignedEntityService::new(
                Arc::new(self.mock_signed_entity_storer),
                dependencies,
                Arc::new(SignedEntityTypeLock::default()),
                Arc::new(MetricsService::new(TestLogger::stdout()).unwrap()),
                TestLogger::stdout(),
            )
        }

        fn mock_artifact_processing<
            T: Artifact + Clone + Serialize + 'static,
            U: signable_builder::Beacon,
        >(
            &mut self,
            artifact: T,
            mock_that_provide_artifact: &dyn Fn(
                &mut MockDependencyInjector,
            ) -> &mut MockArtifactBuilder<U, T>,
        ) {
            {
                let artifact_cloned = artifact.clone();
                mock_that_provide_artifact(self)
                    .expect_compute_artifact()
                    .times(1)
                    .return_once(|_, _| Ok(artifact_cloned));
            }
            {
                let artifact_clone: Arc<dyn Artifact> = Arc::new(artifact.clone());
                let artifact_json = serde_json::to_string(&artifact_clone).unwrap();
                self.mock_signed_entity_storer
                    .expect_store_signed_entity()
                    .withf(move |signed_entity| signed_entity.artifact == artifact_json)
                    .return_once(|_| Ok(()));
            }
        }

        fn mock_stake_distribution_processing(&mut self, artifact: MithrilStakeDistribution) {
            self.mock_artifact_processing(artifact, &|mock_injector| {
                &mut mock_injector.mock_mithril_stake_distribution_artifact_builder
            });
        }
    }

    fn get_artifact_total_produced_metric_since_startup_counter_value(
        metrics_service: Arc<MetricsService>,
        signed_entity_type: &SignedEntityType,
    ) -> CounterValue {
        match signed_entity_type {
            SignedEntityType::MithrilStakeDistribution(..) => metrics_service
                .get_artifact_mithril_stake_distribution_total_produced_since_startup()
                .get(),
            SignedEntityType::CardanoStakeDistribution(..) => metrics_service
                .get_artifact_cardano_stake_distribution_total_produced_since_startup()
                .get(),
            SignedEntityType::CardanoTransactions(..) => metrics_service
                .get_artifact_cardano_transaction_total_produced_since_startup()
                .get(),
            SignedEntityType::CardanoBlocksTransactions(..) => metrics_service
                .get_artifact_cardano_blocks_transactions_total_produced_since_startup()
                .get(),
            SignedEntityType::CardanoDatabase(..) => metrics_service
                .get_artifact_cardano_database_total_produced_since_startup()
                .get(),
        }
    }

    #[tokio::test]
    async fn build_mithril_stake_distribution_artifact_when_given_mithril_stake_distribution_entity_type()
     {
        let mut mock_container = MockDependencyInjector::new();

        let mithril_stake_distribution_expected = create_stake_distribution(Epoch(1), 5);

        mock_container
            .mock_mithril_stake_distribution_artifact_builder
            .expect_compute_artifact()
            .times(1)
            .returning(|_, _| Ok(create_stake_distribution(Epoch(1), 5)));

        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type = SignedEntityType::MithrilStakeDistribution(Epoch(1));
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type.clone(), &certificate)
            .await
            .unwrap();

        assert_expected(&mithril_stake_distribution_expected, &artifact);
    }

    #[tokio::test]
    async fn should_store_the_artifact_when_creating_artifact_for_a_mithril_stake_distribution() {
        generic_test_that_the_artifact_is_stored(
            SignedEntityType::MithrilStakeDistribution(Epoch(1)),
            create_stake_distribution(Epoch(1), 5),
            &|mock_injector| &mut mock_injector.mock_mithril_stake_distribution_artifact_builder,
        )
        .await;
    }

    #[tokio::test]
    async fn build_cardano_stake_distribution_artifact_when_given_cardano_stake_distribution_entity_type()
     {
        let mut mock_container = MockDependencyInjector::new();

        let cardano_stake_distribution_expected = create_cardano_stake_distribution(
            Epoch(1),
            StakeDistribution::from([("pool-1".to_string(), 100)]),
        );

        mock_container
            .mock_cardano_stake_distribution_artifact_builder
            .expect_compute_artifact()
            .times(1)
            .returning(|_, _| {
                Ok(create_cardano_stake_distribution(
                    Epoch(1),
                    StakeDistribution::from([("pool-1".to_string(), 100)]),
                ))
            });

        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type = SignedEntityType::CardanoStakeDistribution(Epoch(1));
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type.clone(), &certificate)
            .await
            .unwrap();

        assert_expected(&cardano_stake_distribution_expected, &artifact);
    }

    #[tokio::test]
    async fn should_store_the_artifact_when_creating_artifact_for_a_cardano_stake_distribution() {
        generic_test_that_the_artifact_is_stored(
            SignedEntityType::CardanoStakeDistribution(Epoch(1)),
            create_cardano_stake_distribution(
                Epoch(1),
                StakeDistribution::from([("pool-1".to_string(), 100)]),
            ),
            &|mock_injector| &mut mock_injector.mock_cardano_stake_distribution_artifact_builder,
        )
        .await;
    }

    #[tokio::test]
    async fn build_cardano_transactions_snapshot_artifact_when_given_cardano_transactions_type() {
        let mut mock_container = MockDependencyInjector::new();

        let block_number = BlockNumber(151);
        let expected = CardanoTransactionsSnapshot::new("merkle_root".to_string(), block_number);

        mock_container
            .mock_cardano_transactions_artifact_builder
            .expect_compute_artifact()
            .times(1)
            .returning(move |_, _| {
                Ok(CardanoTransactionsSnapshot::new(
                    "merkle_root".to_string(),
                    block_number,
                ))
            });

        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type = SignedEntityType::CardanoTransactions(Epoch(1), block_number);
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type.clone(), &certificate)
            .await
            .unwrap();

        assert_expected(&expected, &artifact);
    }

    #[tokio::test]
    async fn should_store_the_artifact_when_creating_artifact_for_cardano_transactions() {
        let block_number = BlockNumber(149);
        generic_test_that_the_artifact_is_stored(
            SignedEntityType::CardanoTransactions(Epoch(1), block_number),
            CardanoTransactionsSnapshot::new("merkle_root".to_string(), block_number),
            &|mock_injector| &mut mock_injector.mock_cardano_transactions_artifact_builder,
        )
        .await;
    }

    #[tokio::test]
    async fn build_cardano_blocks_transactions_snapshot_artifact_when_given_cardano_blocks_transactions_type()
     {
        let mut mock_container = MockDependencyInjector::new();

        let block_number = BlockNumber(151);
        let offset_security_parameter = BlockNumberOffset(15);
        let expected = CardanoBlocksTransactionsSnapshot::new(
            "merkle_root".to_string(),
            block_number,
            offset_security_parameter,
        );

        mock_container
            .mock_cardano_blocks_transactions_artifact_builder
            .expect_compute_artifact()
            .times(1)
            .returning(move |_, _| {
                Ok(CardanoBlocksTransactionsSnapshot::new(
                    "merkle_root".to_string(),
                    block_number,
                    offset_security_parameter,
                ))
            });

        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type = SignedEntityType::CardanoBlocksTransactions(
            Epoch(1),
            block_number,
            offset_security_parameter,
        );
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type.clone(), &certificate)
            .await
            .unwrap();

        assert_expected(&expected, &artifact);
    }

    #[tokio::test]
    async fn should_store_the_artifact_when_creating_artifact_for_cardano_blocks_transactions() {
        let block_number = BlockNumber(149);
        let offset_security_parameter = BlockNumberOffset(15);
        generic_test_that_the_artifact_is_stored(
            SignedEntityType::CardanoBlocksTransactions(
                Epoch(1),
                block_number,
                offset_security_parameter,
            ),
            CardanoBlocksTransactionsSnapshot::new(
                "merkle_root".to_string(),
                block_number,
                offset_security_parameter,
            ),
            &|mock_injector| &mut mock_injector.mock_cardano_blocks_transactions_artifact_builder,
        )
        .await;
    }

    #[tokio::test]
    async fn build_cardano_database_artifact_when_given_cardano_database_entity_type() {
        let mut mock_container = MockDependencyInjector::new();

        let cardano_database_expected = fake_data::cardano_database_snapshot(1);

        mock_container
            .mock_cardano_database_artifact_builder
            .expect_compute_artifact()
            .times(1)
            .returning(|_, _| Ok(fake_data::cardano_database_snapshot(1)));

        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type = SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type.clone(), &certificate)
            .await
            .unwrap();

        assert_expected(&cardano_database_expected, &artifact);
    }

    #[tokio::test]
    async fn should_store_the_artifact_when_creating_artifact_for_a_cardano_database() {
        generic_test_that_the_artifact_is_stored(
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default()),
            fake_data::cardano_database_snapshot(1),
            &|mock_injector| &mut mock_injector.mock_cardano_database_artifact_builder,
        )
        .await;
    }

    async fn generic_test_that_the_artifact_is_stored<
        T: Artifact + Clone + Serialize + 'static,
        U: signable_builder::Beacon,
    >(
        signed_entity_type: SignedEntityType,
        artifact: T,
        mock_that_provide_artifact: &dyn Fn(
            &mut MockDependencyInjector,
        ) -> &mut MockArtifactBuilder<U, T>,
    ) {
        let mut mock_container = MockDependencyInjector::new();
        {
            let artifact_clone: Arc<dyn Artifact> = Arc::new(artifact.clone());
            let signed_entity_artifact = serde_json::to_string(&artifact_clone).unwrap();
            mock_container
                .mock_signed_entity_storer
                .expect_store_signed_entity()
                .withf(move |signed_entity| signed_entity.artifact == signed_entity_artifact)
                .return_once(|_| Ok(()));
        }
        {
            let artifact_cloned = artifact.clone();
            mock_that_provide_artifact(&mut mock_container)
                .expect_compute_artifact()
                .times(1)
                .return_once(|_, _| Ok(artifact_cloned));
        }
        let artifact_builder_service = mock_container.build_artifact_builder_service();

        let certificate = fake_data::certificate("hash".to_string());
        let error_message = format!(
            "Create artifact should not fail for {} signed entity",
            std::any::type_name::<T>()
        );
        let error_message_str = error_message.as_str();

        let initial_counter_value = get_artifact_total_produced_metric_since_startup_counter_value(
            artifact_builder_service.metrics_service.clone(),
            &signed_entity_type,
        );

        artifact_builder_service
            .create_artifact_task(signed_entity_type.clone(), &certificate)
            .await
            .expect(error_message_str);

        assert_eq!(
            initial_counter_value + 1,
            get_artifact_total_produced_metric_since_startup_counter_value(
                artifact_builder_service.metrics_service.clone(),
                &signed_entity_type,
            )
        )
    }

    #[tokio::test]
    async fn create_artifact_for_two_signed_entity_types_in_sequence_not_blocking() {
        let atomic_stop = Arc::new(AtomicBool::new(false));
        let signed_entity_type_service = {
            let mut mock_container = MockDependencyInjector::new();

            let msd = create_stake_distribution(Epoch(1), 5);
            mock_container.mock_stake_distribution_processing(msd);

            mock_container
                .build_artifact_builder_service_with_time_consuming_process(atomic_stop.clone())
        };
        let certificate = fake_data::certificate("hash".to_string());

        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());
        let first_task_that_never_finished = signed_entity_type_service
            .create_artifact(signed_entity_type_immutable, &certificate)
            .await
            .unwrap();

        let signed_entity_type_msd = SignedEntityType::MithrilStakeDistribution(Epoch(1));
        let second_task_that_finish_first = signed_entity_type_service
            .create_artifact(signed_entity_type_msd, &certificate)
            .await
            .unwrap();

        second_task_that_finish_first.await.unwrap().unwrap();
        assert!(!first_task_that_never_finished.is_finished());

        atomic_stop.swap(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn create_artifact_lock_unlock_signed_entity_type_while_processing() {
        let atomic_stop = Arc::new(AtomicBool::new(false));
        let signed_entity_type_service = MockDependencyInjector::new()
            .build_artifact_builder_service_with_time_consuming_process(atomic_stop.clone());
        let certificate = fake_data::certificate("hash".to_string());

        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());
        assert!(
            !signed_entity_type_service
                .signed_entity_type_lock
                .is_locked(&signed_entity_type_immutable)
        );
        let join_handle = signed_entity_type_service
            .create_artifact(signed_entity_type_immutable.clone(), &certificate)
            .await
            .unwrap();

        // Results are stored to finalize the task before assertions,
        // ensuring 'atomic_stop' is always assigned a new value.
        let is_locked = signed_entity_type_service
            .signed_entity_type_lock
            .is_locked(&signed_entity_type_immutable);
        let is_finished = join_handle.is_finished();

        atomic_stop.swap(true, Ordering::Relaxed);
        join_handle.await.unwrap().unwrap();

        assert!(is_locked);
        assert!(!is_finished);

        assert!(
            !signed_entity_type_service
                .signed_entity_type_lock
                .is_locked(&signed_entity_type_immutable)
        );
    }

    #[tokio::test]
    async fn create_artifact_keep_signed_entity_type_locked_when_its_handle_is_aborted() {
        let signed_entity_type_service = MockDependencyInjector::new()
            .build_artifact_builder_service_with_time_consuming_process(Arc::new(AtomicBool::new(
                false,
            )));
        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());

        let join_handle = signed_entity_type_service
            .create_artifact(signed_entity_type_immutable.clone(), &certificate)
            .await
            .unwrap();
        // Let the artifact creation start before aborting its handle
        tokio::time::sleep(Duration::from_millis(50)).await;
        join_handle.abort();
        let _ = join_handle.await;

        assert!(
            signed_entity_type_service
                .signed_entity_type_lock
                .is_locked(&signed_entity_type_immutable)
        );
    }

    #[tokio::test]
    async fn create_artifact_unlock_signed_entity_type_when_error() {
        let signed_entity_type_service = {
            let mut mock_container = MockDependencyInjector::new();
            mock_container
                .mock_cardano_database_artifact_builder
                .expect_compute_artifact()
                .returning(|_, _| Err(anyhow::anyhow!("Error while computing artifact")));

            mock_container.build_artifact_builder_service()
        };
        let certificate = fake_data::certificate("hash".to_string());

        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());

        let join_handle = signed_entity_type_service
            .create_artifact(signed_entity_type_immutable.clone(), &certificate)
            .await
            .unwrap();

        let error = join_handle.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("CardanoDatabase"),
            "Error should contains CardanoDatabase but was: {error}"
        );

        assert!(
            !signed_entity_type_service
                .signed_entity_type_lock
                .is_locked(&signed_entity_type_immutable)
        );
    }

    #[tokio::test]
    async fn create_artifact_unlock_signed_entity_type_when_panic() {
        let signed_entity_type_service =
            MockDependencyInjector::new().build_artifact_builder_service();
        let certificate = fake_data::certificate("hash".to_string());

        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());

        let join_handle = signed_entity_type_service
            .create_artifact(signed_entity_type_immutable.clone(), &certificate)
            .await
            .unwrap();

        let error = join_handle.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("CardanoDatabase"),
            "Error should contains CardanoDatabase but was: {error}"
        );

        assert!(
            !signed_entity_type_service
                .signed_entity_type_lock
                .is_locked(&signed_entity_type_immutable)
        );
    }

    #[tokio::test]
    async fn create_artifact_for_a_signed_entity_type_already_lock_return_error() {
        let atomic_stop = Arc::new(AtomicBool::new(false));
        let signed_entity_service = MockDependencyInjector::new()
            .build_artifact_builder_service_with_time_consuming_process(atomic_stop.clone());
        let certificate = fake_data::certificate("hash".to_string());
        let signed_entity_type_immutable =
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::default());

        signed_entity_service
            .create_artifact(signed_entity_type_immutable.clone(), &certificate)
            .await
            .unwrap();

        signed_entity_service
            .create_artifact(signed_entity_type_immutable, &certificate)
            .await
            .expect_err("Should return error when signed entity type is already locked");

        atomic_stop.swap(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn metrics_counter_value_is_not_incremented_when_compute_artifact_error() {
        let signed_entity_service = {
            let mut mock_container = MockDependencyInjector::new();
            mock_container
                .mock_mithril_stake_distribution_artifact_builder
                .expect_compute_artifact()
                .returning(|_, _| Err(anyhow!("Error while computing artifact")));

            mock_container.build_artifact_builder_service()
        };

        let signed_entity_type = SignedEntityType::MithrilStakeDistribution(Epoch(7));

        let initial_counter_value = get_artifact_total_produced_metric_since_startup_counter_value(
            signed_entity_service.metrics_service.clone(),
            &signed_entity_type,
        );

        signed_entity_service
            .create_artifact(
                signed_entity_type.clone(),
                &fake_data::certificate("hash".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(
            initial_counter_value,
            get_artifact_total_produced_metric_since_startup_counter_value(
                signed_entity_service.metrics_service.clone(),
                &signed_entity_type,
            )
        );
    }

    #[tokio::test]
    async fn metrics_counter_value_is_not_incremented_when_store_signed_entity_error() {
        let signed_entity_service = {
            let mut mock_container = MockDependencyInjector::new();
            mock_container
                .mock_signed_entity_storer
                .expect_store_signed_entity()
                .returning(|_| Err(anyhow!("Error while storing signed entity")));

            mock_container.build_artifact_builder_service()
        };

        let signed_entity_type = SignedEntityType::MithrilStakeDistribution(Epoch(7));

        let initial_counter_value = get_artifact_total_produced_metric_since_startup_counter_value(
            signed_entity_service.metrics_service.clone(),
            &signed_entity_type,
        );

        signed_entity_service
            .create_artifact(
                signed_entity_type.clone(),
                &fake_data::certificate("hash".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(
            initial_counter_value,
            get_artifact_total_produced_metric_since_startup_counter_value(
                signed_entity_service.metrics_service.clone(),
                &signed_entity_type,
            )
        );
    }
}
