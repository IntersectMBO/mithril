//! # Immutables Archives Preloader
//!
//! This module provides a preload mechanism for the immutable files archives of the
//! Cardano Database signed entity, allowing to create in advance the missing archives.

use std::sync::Arc;

use async_trait::async_trait;
use slog::{Logger, debug, info};

use mithril_cardano_node_internal_database::ImmutableFileObserver;
use mithril_common::{
    StdResult,
    entities::{ImmutableFileNumber, SignedEntityTypeDiscriminants},
    logging::LoggerExtensions,
};
use mithril_signed_entity_lock::SignedEntityTypeLock;

const SIGNED_ENTITY_TO_LOCK: SignedEntityTypeDiscriminants =
    SignedEntityTypeDiscriminants::CardanoDatabase;

/// Create the missing immutable files archives.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ImmutablesArchivesCreator: Send + Sync {
    /// Create the archives of the immutable files that are missing, up to the given immutable file number.
    async fn create_missing_archives(
        &self,
        up_to_immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<()>;
}

/// Preload mechanism for the immutable files archives of the Cardano Database signed entity.
pub struct ImmutablesArchivesPreloader {
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    archives_creator: Arc<dyn ImmutablesArchivesCreator>,
    immutable_file_observer: Arc<dyn ImmutableFileObserver>,
    is_activated: bool,
    logger: Logger,
}

impl ImmutablesArchivesPreloader {
    /// Create a new instance of `ImmutablesArchivesPreloader`.
    pub fn new(
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        archives_creator: Arc<dyn ImmutablesArchivesCreator>,
        immutable_file_observer: Arc<dyn ImmutableFileObserver>,
        is_activated: bool,
        logger: Logger,
    ) -> Self {
        Self {
            signed_entity_type_lock,
            archives_creator,
            immutable_file_observer,
            is_activated,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Return the activation state of the preloader.
    pub fn is_activated(&self) -> bool {
        self.is_activated
    }

    /// Preload the immutable files archives up to the last immutable file number, locking the
    /// Cardano Database signed entity type while doing so.
    pub async fn preload(&self) -> StdResult<()> {
        if !self.is_activated() {
            debug!(self.logger, "Not running, conditions not met");
            return Ok(());
        }

        info!(self.logger, "Started");
        debug!(self.logger, "Locking signed entity type"; "entity_type" => ?SIGNED_ENTITY_TO_LOCK);
        self.signed_entity_type_lock.lock(SIGNED_ENTITY_TO_LOCK).await;

        let preload_result = self.do_preload().await;

        debug!(self.logger, "Releasing signed entity type"; "entity_type" => ?SIGNED_ENTITY_TO_LOCK);
        self.signed_entity_type_lock.release(SIGNED_ENTITY_TO_LOCK).await;
        info!(self.logger, "Finished");

        preload_result
    }

    async fn do_preload(&self) -> StdResult<()> {
        let last_immutable_file_number =
            self.immutable_file_observer.get_last_immutable_number().await?;
        self.archives_creator
            .create_missing_archives(last_immutable_file_number)
            .await
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use mockall::predicate::eq;

    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;

    use crate::test::TestLogger;

    use super::*;

    struct ArchivesCreatorWithSignedEntityTypeLockCheck {
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    }

    #[async_trait]
    impl ImmutablesArchivesCreator for ArchivesCreatorWithSignedEntityTypeLockCheck {
        async fn create_missing_archives(
            &self,
            _up_to_immutable_file_number: ImmutableFileNumber,
        ) -> StdResult<()> {
            assert!(
                self.signed_entity_type_lock
                    .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                    .await
            );
            Ok(())
        }
    }

    async fn immutable_file_observer(
        last_immutable: ImmutableFileNumber,
    ) -> Arc<DumbImmutableFileObserver> {
        let observer = DumbImmutableFileObserver::new();
        observer.shall_return(Some(last_immutable)).await;
        Arc::new(observer)
    }

    #[tokio::test]
    async fn create_missing_archives_up_to_last_immutable_when_activated() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator
            .expect_create_missing_archives()
            .with(eq(42))
            .times(1)
            .returning(|_| Ok(()));

        let preloader = ImmutablesArchivesPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            Arc::new(archives_creator),
            immutable_file_observer(42).await,
            true,
            TestLogger::stdout(),
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn do_not_create_missing_archives_when_not_activated() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator.expect_create_missing_archives().never();

        let preloader = ImmutablesArchivesPreloader::new(
            Arc::new(SignedEntityTypeLock::default()),
            Arc::new(archives_creator),
            immutable_file_observer(42).await,
            false,
            TestLogger::stdout(),
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn lock_cardano_database_while_creating_archives_and_release_it_after() {
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());
        let preloader = ImmutablesArchivesPreloader::new(
            signed_entity_type_lock.clone(),
            Arc::new(ArchivesCreatorWithSignedEntityTypeLockCheck {
                signed_entity_type_lock: signed_entity_type_lock.clone(),
            }),
            immutable_file_observer(42).await,
            true,
            TestLogger::stdout(),
        );

        preloader.preload().await.unwrap();

        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                .await
        );
    }

    #[tokio::test]
    async fn release_cardano_database_lock_and_return_error_when_archives_creation_fails() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator
            .expect_create_missing_archives()
            .returning(|_| Err(anyhow!("archives creation error")));
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());

        let preloader = ImmutablesArchivesPreloader::new(
            signed_entity_type_lock.clone(),
            Arc::new(archives_creator),
            immutable_file_observer(42).await,
            true,
            TestLogger::stdout(),
        );

        preloader.preload().await.expect_err("preload should fail");

        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                .await
        );
    }

    #[tokio::test]
    async fn release_cardano_database_lock_and_return_error_when_last_immutable_retrieval_fails() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator.expect_create_missing_archives().never();
        let signed_entity_type_lock = Arc::new(SignedEntityTypeLock::default());

        let preloader = ImmutablesArchivesPreloader::new(
            signed_entity_type_lock.clone(),
            Arc::new(archives_creator),
            Arc::new(DumbImmutableFileObserver::new()),
            true,
            TestLogger::stdout(),
        );

        preloader.preload().await.expect_err("preload should fail");

        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                .await
        );
    }
}
