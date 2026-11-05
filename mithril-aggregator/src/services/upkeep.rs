//! ## Upkeep Service
//!
//! This service is responsible for the upkeep of the application.
//!
//! It is in charge of the following tasks:
//! * free up space by executing vacuum and WAL checkpoint on the database

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use mithril_common::StdResult;
use mithril_common::entities::Epoch;
use mithril_common::logging::LoggerExtensions;
use mithril_persistence::sqlite::{
    SqliteCleaner, SqliteCleaningTask, SqliteConnection, SqliteConnectionPool,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;
use slog::{Logger, info};

/// Define the service responsible for the upkeep of the application.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UpkeepService: Send + Sync {
    /// Run the upkeep service.
    async fn run(&self, epoch: Epoch) -> StdResult<()>;

    /// Vacuum database.
    async fn vacuum(&self) -> StdResult<()>;
}

/// Define the task responsible for pruning a datasource below a certain epoch threshold.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait EpochPruningTask: Send + Sync {
    /// Get the name of the data that will be pruned.
    fn pruned_data(&self) -> &'static str;

    /// Prune the datasource based on the given current epoch.
    async fn prune(&self, current_epoch: Epoch) -> StdResult<()>;
}

/// Implementation of the upkeep service for the aggregator.
///
/// To ensure that connections are cleaned up properly, it creates new connections itself
/// instead of relying on a connection pool or a shared connection.
pub struct AggregatorUpkeepService {
    main_db_connection: Arc<SqliteConnection>,
    cardano_tx_connection_pool: Arc<SqliteConnectionPool>,
    event_store_connection: Arc<SqliteConnection>,
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    pruning_tasks: Vec<Arc<dyn EpochPruningTask>>,
    logger: Logger,
}

impl AggregatorUpkeepService {
    /// Create a new instance of the aggregator upkeep service.
    pub fn new(
        main_db_connection: Arc<SqliteConnection>,
        cardano_tx_connection_pool: Arc<SqliteConnectionPool>,
        event_store_connection: Arc<SqliteConnection>,
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        pruning_tasks: Vec<Arc<dyn EpochPruningTask>>,
        logger: Logger,
    ) -> Self {
        Self {
            main_db_connection,
            cardano_tx_connection_pool,
            event_store_connection,
            signed_entity_type_lock,
            pruning_tasks,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn execute_pruning_tasks(&self, current_epoch: Epoch) -> StdResult<()> {
        for task in &self.pruning_tasks {
            info!(
                self.logger, "Pruning stale data";
                "pruned_data" => task.pruned_data(), "current_epoch" => ?current_epoch
            );
            task.prune(current_epoch).await?;
        }

        Ok(())
    }

    async fn upkeep_all_databases(&self) -> StdResult<()> {
        if self.signed_entity_type_lock.has_locked_entities() {
            info!(
                self.logger,
                "Some entities are locked - Skipping database upkeep"
            );
            return Ok(());
        }

        let main_db_connection = self.main_db_connection.clone();
        let cardano_tx_db_connection_pool = self.cardano_tx_connection_pool.clone();
        let event_store_connection = self.event_store_connection.clone();
        let db_upkeep_logger = self.logger.clone();

        // Run the database upkeep tasks in another thread to avoid blocking the tokio runtime
        let db_upkeep_thread = tokio::task::spawn_blocking(move || -> StdResult<()> {
            info!(db_upkeep_logger, "Cleaning main database");
            SqliteCleaner::new(&main_db_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[SqliteCleaningTask::WalCheckpointTruncate])
                .run()?;

            info!(db_upkeep_logger, "Cleaning cardano transactions database");
            let cardano_tx_db_connection = cardano_tx_db_connection_pool.connection()?;
            SqliteCleaner::new(&cardano_tx_db_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[SqliteCleaningTask::WalCheckpointTruncate])
                .run()?;

            info!(db_upkeep_logger, "Cleaning event database");
            SqliteCleaner::new(&event_store_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[SqliteCleaningTask::WalCheckpointTruncate])
                .run()?;

            Ok(())
        });

        db_upkeep_thread
            .await
            .with_context(|| "Database Upkeep thread crashed")?
    }

    async fn vacuum_main_database(&self) -> StdResult<()> {
        if self.signed_entity_type_lock.has_locked_entities() {
            info!(
                self.logger,
                "Some entities are locked - Skipping main database vacuum"
            );
            return Ok(());
        }

        let main_db_connection = self.main_db_connection.clone();
        let db_upkeep_logger = self.logger.clone();

        // Run the database upkeep tasks in another thread to avoid blocking the tokio runtime
        let db_upkeep_thread = tokio::task::spawn_blocking(move || -> StdResult<()> {
            info!(db_upkeep_logger, "Vacuum main database");
            SqliteCleaner::new(&main_db_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[SqliteCleaningTask::Vacuum])
                .run()?;

            Ok(())
        });

        db_upkeep_thread
            .await
            .with_context(|| "Database Upkeep thread crashed")?
    }
}

#[async_trait]
impl UpkeepService for AggregatorUpkeepService {
    async fn run(&self, current_epoch: Epoch) -> StdResult<()> {
        info!(self.logger, "Start upkeep of the application");

        self.execute_pruning_tasks(current_epoch)
            .await
            .with_context(|| "Pruning tasks failed")?;

        self.upkeep_all_databases()
            .await
            .with_context(|| "Database upkeep failed")?;

        info!(self.logger, "Upkeep finished");
        Ok(())
    }

    async fn vacuum(&self) -> StdResult<()> {
        info!(self.logger, "Start database vacuum");

        self.vacuum_main_database()
            .await
            .with_context(|| "Vacuuming main database failed")?;

        info!(self.logger, "Vacuum finished");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mockall::predicate::eq;

    use mithril_common::{entities::SignedEntityTypeDiscriminants, temp_dir_create};

    use crate::database::test_helper::{
        cardano_tx_db_connection_builder, main_db_connection, main_db_file_connection,
    };
    use crate::event_store::database::test_helper::{
        event_store_db_connection, event_store_db_file_connection,
    };
    use crate::test::TestLogger;

    use super::*;

    fn mock_epoch_pruning_task(
        mock_config: impl FnOnce(&mut MockEpochPruningTask),
    ) -> Arc<dyn EpochPruningTask> {
        let mut task_mock = MockEpochPruningTask::new();
        task_mock.expect_pruned_data().return_const("mock_data");
        mock_config(&mut task_mock);
        Arc::new(task_mock)
    }

    fn default_upkeep_service(dir: &Path) -> AggregatorUpkeepService {
        AggregatorUpkeepService::new(
            Arc::new(main_db_connection().unwrap()),
            cardano_tx_db_connection_builder(&dir.join("cardano_tx.db"))
                .build_pool(1)
                .map(Arc::new)
                .unwrap(),
            Arc::new(event_store_db_connection().unwrap()),
            Arc::new(SignedEntityTypeLock::default()),
            vec![],
            TestLogger::stdout(),
        )
    }

    #[tokio::test]
    async fn test_cleanup_database() {
        let (logger, log_inspector) = TestLogger::memory();
        let (main_db_path, ctx_db_path, event_store_db_path) = {
            let db_dir = temp_dir_create!();
            (
                db_dir.join("main.db"),
                db_dir.join("cardano_tx.db"),
                db_dir.join("event_store.db"),
            )
        };

        let main_db_connection = main_db_file_connection(&main_db_path).unwrap();
        let cardano_tx_conn_builder = cardano_tx_db_connection_builder(&ctx_db_path);
        let event_store_connection = event_store_db_file_connection(&event_store_db_path).unwrap();

        let service = AggregatorUpkeepService::new(
            Arc::new(main_db_connection),
            Arc::new(cardano_tx_conn_builder.build_pool(1).unwrap()),
            Arc::new(event_store_connection),
            Arc::new(SignedEntityTypeLock::default()),
            vec![],
            logger,
        );

        service.run(Epoch(5)).await.expect("Upkeep service failed");

        assert_eq!(
            log_inspector
                .search_logs(SqliteCleaningTask::WalCheckpointTruncate.log_message())
                .len(),
            3,
            "Should have run three times since the three databases have a `WalCheckpointTruncate` cleanup"
        );
        assert!(
            log_inspector
                .search_logs(SqliteCleaningTask::Vacuum.log_message())
                .is_empty(),
            "Upkeep operation should not include Vacuum tasks"
        );
    }

    #[tokio::test]
    async fn test_doesnt_cleanup_db_if_any_entity_is_locked() {
        let db_dir = temp_dir_create!();
        let (logger, log_inspector) = TestLogger::memory();

        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let _lock_guard =
            signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::CardanoTransactions);

        let service = AggregatorUpkeepService {
            signed_entity_type_lock: signed_entity_type_lock.clone(),
            logger,
            ..default_upkeep_service(&db_dir)
        };
        service.run(Epoch(5)).await.expect("Upkeep service failed");

        assert!(
            log_inspector
                .search_logs(SqliteCleaningTask::WalCheckpointTruncate.log_message())
                .is_empty()
        );
    }
    #[tokio::test]
    async fn test_execute_all_pruning_tasks() {
        let db_dir = temp_dir_create!();
        let task1 = mock_epoch_pruning_task(|mock| {
            mock.expect_prune().once().with(eq(Epoch(14))).returning(|_| Ok(()));
        });
        let task2 = mock_epoch_pruning_task(|mock| {
            mock.expect_prune().once().with(eq(Epoch(14))).returning(|_| Ok(()));
        });

        let service = AggregatorUpkeepService {
            pruning_tasks: vec![task1, task2],
            ..default_upkeep_service(&db_dir)
        };

        service.run(Epoch(14)).await.expect("Upkeep service failed");
    }

    #[tokio::test]
    async fn test_doesnt_vacuum_db_if_any_entity_is_locked() {
        let db_dir = temp_dir_create!();
        let (logger, log_inspector) = TestLogger::memory();

        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let _lock_guard =
            signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::CardanoTransactions);

        let service = AggregatorUpkeepService {
            signed_entity_type_lock: signed_entity_type_lock.clone(),
            logger,
            ..default_upkeep_service(&db_dir)
        };
        service.vacuum().await.expect("Vacuum failed");

        assert!(
            log_inspector
                .search_logs(SqliteCleaningTask::Vacuum.log_message())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_vacuum_database() {
        let db_dir = temp_dir_create!();
        let (logger, log_inspector) = TestLogger::memory();

        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let _lock_guard =
            signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::CardanoTransactions);

        let service = AggregatorUpkeepService {
            logger,
            ..default_upkeep_service(&db_dir)
        };
        service.vacuum().await.expect("Vacuum failed");

        assert_eq!(
            log_inspector
                .search_logs(SqliteCleaningTask::Vacuum.log_message())
                .len(),
            1,
        );
    }
}
