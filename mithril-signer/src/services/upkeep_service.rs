//! ## Upkeep Service
//!
//! This service is responsible for the upkeep of the application.
//!
//! It is in charge of the following tasks:
//! * free up space by executing vacuum and WAL checkpoint on the database

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use slog::{Logger, info};

use mithril_common::StdResult;
use mithril_common::entities::Epoch;
use mithril_common::logging::LoggerExtensions;
use mithril_persistence::sqlite::{
    SqliteCleaner, SqliteCleaningTask, SqliteConnection, SqliteConnectionPool,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

/// Define the service responsible for the upkeep of the application.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UpkeepService: Send + Sync {
    /// Run the upkeep service.
    async fn run(&self, current_epoch: Epoch) -> StdResult<()>;
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

/// Implementation of the upkeep service for the signer.
///
/// To ensure that connections are cleaned up properly, it creates new connections itself
/// instead of relying on a connection pool or a shared connection.
pub struct SignerUpkeepService {
    main_db_connection: Arc<SqliteConnection>,
    cardano_tx_connection_pool: Arc<SqliteConnectionPool>,
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    pruning_tasks: Vec<Arc<dyn EpochPruningTask>>,
    logger: Logger,
}

impl SignerUpkeepService {
    /// Create a new instance of the aggregator upkeep service.
    pub fn new(
        main_db_connection: Arc<SqliteConnection>,
        cardano_tx_connection_pool: Arc<SqliteConnectionPool>,
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        pruning_tasks: Vec<Arc<dyn EpochPruningTask>>,
        logger: Logger,
    ) -> Self {
        Self {
            main_db_connection,
            cardano_tx_connection_pool,
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
        let db_upkeep_logger = self.logger.clone();

        // Run the database upkeep tasks in another thread to avoid blocking the tokio runtime
        let db_upkeep_thread = tokio::task::spawn_blocking(move || -> StdResult<()> {
            info!(db_upkeep_logger, "Cleaning main database");
            SqliteCleaner::new(&main_db_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[
                    SqliteCleaningTask::Vacuum,
                    SqliteCleaningTask::WalCheckpointTruncate,
                ])
                .run()?;

            info!(db_upkeep_logger, "Cleaning cardano transactions database");
            let cardano_tx_db_connection = cardano_tx_db_connection_pool.connection()?;
            SqliteCleaner::new(&cardano_tx_db_connection)
                .with_logger(db_upkeep_logger.clone())
                .with_tasks(&[SqliteCleaningTask::WalCheckpointTruncate])
                .run()?;

            Ok(())
        });

        db_upkeep_thread
            .await
            .with_context(|| "Database Upkeep thread crashed")?
    }
}

#[async_trait]
impl UpkeepService for SignerUpkeepService {
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
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use mithril_common::entities::SignedEntityTypeDiscriminants;
    use mithril_common::temp_dir_create;
    use mithril_common::test::TempDir;

    use crate::database::test_helper::{
        cardano_tx_db_connection_builder, main_db_connection, main_db_file_connection,
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

    #[tokio::test]
    async fn test_cleanup_database() {
        let (logger, log_inspector) = TestLogger::memory();
        let (main_db_path, ctx_db_path) = {
            let db_dir = TempDir::create("signer_upkeep", "test_cleanup_database");
            (db_dir.join("main.db"), db_dir.join("cardano_tx.db"))
        };

        let main_db_connection = main_db_file_connection(&main_db_path).unwrap();
        let cardano_tx_conn_builder = cardano_tx_db_connection_builder(&ctx_db_path);

        let service = SignerUpkeepService::new(
            Arc::new(main_db_connection),
            Arc::new(cardano_tx_conn_builder.build_pool(1).unwrap()),
            Arc::new(SignedEntityTypeLock::default()),
            vec![],
            logger,
        );

        service.run(Epoch(13)).await.expect("Upkeep service failed");

        assert_eq!(
            log_inspector
                .search_logs(SqliteCleaningTask::Vacuum.log_message())
                .len(),
            1,
            "Should have run only once since only the main database has a `Vacuum` cleanup"
        );
        assert_eq!(
            log_inspector
                .search_logs(SqliteCleaningTask::WalCheckpointTruncate.log_message())
                .len(),
            2,
            "Should have run twice since the two databases have a `WalCheckpointTruncate` cleanup"
        );
    }

    #[tokio::test]
    async fn test_doesnt_cleanup_db_if_any_entity_is_locked() {
        let db_dir = temp_dir_create!();
        let (logger, log_inspector) = TestLogger::memory();

        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::CardanoTransactions);

        let service = SignerUpkeepService::new(
            Arc::new(main_db_connection().unwrap()),
            Arc::new(
                cardano_tx_db_connection_builder(&db_dir.join("cardano_tx.db"))
                    .build_pool(1)
                    .unwrap(),
            ),
            signed_entity_type_lock.clone(),
            vec![],
            logger,
        );

        service.run(Epoch(13)).await.expect("Upkeep service failed");

        assert!(
            log_inspector
                .search_logs(SqliteCleaningTask::Vacuum.log_message())
                .is_empty()
        );
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

        let service = SignerUpkeepService::new(
            Arc::new(main_db_connection().unwrap()),
            cardano_tx_db_connection_builder(&db_dir.join("cardano_tx.db"))
                .build_pool(1)
                .map(Arc::new)
                .unwrap(),
            Arc::new(SignedEntityTypeLock::default()),
            vec![task1, task2],
            TestLogger::stdout(),
        );

        service.run(Epoch(14)).await.expect("Upkeep service failed");
    }
}
