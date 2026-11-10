//! # Preload Task
//!
//! This module provides a generic runner for the preload tasks of signed entities, handling the
//! activation check and the locking of the signed entity types while the task is running.

use std::sync::Arc;

use async_trait::async_trait;
use slog::{Logger, debug, info};

use mithril_common::{
    StdResult, entities::SignedEntityTypeDiscriminants, logging::LoggerExtensions,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

/// A task computing in advance the data needed to sign or build the artifacts of some signed
/// entity types.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PreloadTask: Send + Sync {
    /// Signed entity types locked while the task is running.
    fn signed_entities_to_lock(&self) -> Vec<SignedEntityTypeDiscriminants>;

    /// Determine if the task should run.
    async fn is_activated(&self) -> StdResult<bool>;

    /// Run the task.
    async fn preload(&self) -> StdResult<()>;
}

/// Run a [PreloadTask] if activated, locking its signed entity types while it is running.
pub struct PreloadTaskRunner<T: PreloadTask> {
    task: T,
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    logger: Logger,
}

impl<T: PreloadTask> PreloadTaskRunner<T> {
    /// Create a new instance of `PreloadTaskRunner`.
    pub fn new(
        task: T,
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        logger: Logger,
    ) -> Self {
        Self {
            task,
            signed_entity_type_lock,
            logger: logger.new_with_component_name::<T>(),
        }
    }

    /// Return the activation state of the task.
    pub async fn is_activated(&self) -> StdResult<bool> {
        self.task.is_activated().await
    }

    /// Run the task if activated, locking its signed entity types until it finishes.
    pub async fn preload(&self) -> StdResult<()> {
        if !self.is_activated().await? {
            debug!(self.logger, "Not running, conditions not met");
            return Ok(());
        }

        info!(self.logger, "Started");
        let signed_entities_to_lock = self.task.signed_entities_to_lock();
        debug!(self.logger, "Locking signed entity types"; "entity_types" => ?signed_entities_to_lock);
        let lock_guards: Vec<_> = signed_entities_to_lock
            .iter()
            .map(|signed_entity_type| self.signed_entity_type_lock.lock(*signed_entity_type))
            .collect();

        let preload_result = self.task.preload().await;

        debug!(self.logger, "Releasing signed entity types"; "entity_types" => ?signed_entities_to_lock);
        drop(lock_guards);
        info!(self.logger, "Finished");

        preload_result
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use crate::test_tools::TestLogger;

    use super::*;

    const ENTITIES_TO_LOCK: [SignedEntityTypeDiscriminants; 2] = [
        SignedEntityTypeDiscriminants::CardanoTransactions,
        SignedEntityTypeDiscriminants::CardanoDatabase,
    ];

    fn task_to_lock_entities(configure: impl FnOnce(&mut MockPreloadTask)) -> MockPreloadTask {
        let mut task = MockPreloadTask::new();
        task.expect_signed_entities_to_lock()
            .return_const(ENTITIES_TO_LOCK.to_vec());
        configure(&mut task);
        task
    }

    #[track_caller]
    fn assert_no_entities_locked(signed_entity_type_lock: &SignedEntityTypeLock) {
        assert!(
            !signed_entity_type_lock.has_locked_entities(),
            "no signed entity type should be locked"
        );
    }

    #[tokio::test]
    async fn run_the_task_when_activated() {
        let task = task_to_lock_entities(|task| {
            task.expect_is_activated().returning(|| Ok(true));
            task.expect_preload().times(1).returning(|| Ok(()));
        });
        let runner = PreloadTaskRunner::new(
            task,
            Arc::new(SignedEntityTypeLock::default()),
            TestLogger::stdout(),
        );

        runner.preload().await.unwrap();
    }

    #[tokio::test]
    async fn do_not_run_the_task_nor_lock_when_not_activated() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let task = task_to_lock_entities(|task| {
            task.expect_is_activated().returning(|| Ok(false));
            task.expect_preload().never();
        });
        let runner =
            PreloadTaskRunner::new(task, signed_entity_type_lock.clone(), TestLogger::stdout());

        runner.preload().await.unwrap();

        assert_no_entities_locked(&signed_entity_type_lock);
    }

    #[tokio::test]
    async fn return_error_without_running_the_task_when_activation_check_fails() {
        let task = task_to_lock_entities(|task| {
            task.expect_is_activated()
                .returning(|| Err(anyhow!("activation check error")));
            task.expect_preload().never();
        });
        let runner = PreloadTaskRunner::new(
            task,
            Arc::new(SignedEntityTypeLock::default()),
            TestLogger::stdout(),
        );

        runner.preload().await.expect_err("preload should fail");
    }

    #[tokio::test]
    async fn lock_the_task_signed_entity_types_while_running_and_release_them_after() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let task = task_to_lock_entities(|task| {
            task.expect_is_activated().returning(|| Ok(true));
            let lock = signed_entity_type_lock.clone();
            task.expect_preload().returning(move || {
                for entity in ENTITIES_TO_LOCK {
                    assert!(lock.is_locked(entity), "'{entity:?}' should be locked");
                }
                Ok(())
            });
        });
        let runner =
            PreloadTaskRunner::new(task, signed_entity_type_lock.clone(), TestLogger::stdout());

        runner.preload().await.unwrap();

        assert_no_entities_locked(&signed_entity_type_lock);
    }

    #[tokio::test]
    async fn release_the_locks_and_return_error_when_the_task_fails() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let task = task_to_lock_entities(|task| {
            task.expect_is_activated().returning(|| Ok(true));
            task.expect_preload().returning(|| Err(anyhow!("preload error")));
        });
        let runner =
            PreloadTaskRunner::new(task, signed_entity_type_lock.clone(), TestLogger::stdout());

        runner.preload().await.expect_err("preload should fail");

        assert_no_entities_locked(&signed_entity_type_lock);
    }

    #[tokio::test]
    async fn is_activated_returns_the_task_activation_state() {
        for activation in [true, false] {
            let task = task_to_lock_entities(|task| {
                task.expect_is_activated().returning(move || Ok(activation));
            });
            let runner = PreloadTaskRunner::new(
                task,
                Arc::new(SignedEntityTypeLock::default()),
                TestLogger::stdout(),
            );

            assert_eq!(activation, runner.is_activated().await.unwrap());
        }
    }
}
