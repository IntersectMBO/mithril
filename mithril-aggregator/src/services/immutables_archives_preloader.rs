//! # Immutables Archives Preloader
//!
//! This module provides a preload mechanism for the immutable files archives of the
//! Cardano Database signed entity, allowing to create in advance the missing archives.

use std::sync::Arc;

use async_trait::async_trait;

use mithril_cardano_node_internal_database::ImmutableFileObserver;
use mithril_common::{
    StdResult,
    entities::{ImmutableFileNumber, SignedEntityTypeDiscriminants},
};
use mithril_signed_entity_preloader::PreloadTask;

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

/// Preload task for the immutable files archives of the Cardano Database signed entity.
///
/// Must be run with a [PreloadTaskRunner][mithril_signed_entity_preloader::PreloadTaskRunner].
pub struct ImmutablesArchivesPreloader {
    archives_creator: Arc<dyn ImmutablesArchivesCreator>,
    immutable_file_observer: Arc<dyn ImmutableFileObserver>,
    is_activated: bool,
}

impl ImmutablesArchivesPreloader {
    /// Create a new instance of `ImmutablesArchivesPreloader`.
    pub fn new(
        archives_creator: Arc<dyn ImmutablesArchivesCreator>,
        immutable_file_observer: Arc<dyn ImmutableFileObserver>,
        is_activated: bool,
    ) -> Self {
        Self {
            archives_creator,
            immutable_file_observer,
            is_activated,
        }
    }
}

#[async_trait]
impl PreloadTask for ImmutablesArchivesPreloader {
    fn signed_entities_to_lock(&self) -> Vec<SignedEntityTypeDiscriminants> {
        vec![SignedEntityTypeDiscriminants::CardanoDatabase]
    }

    async fn is_activated(&self) -> StdResult<bool> {
        Ok(self.is_activated)
    }

    /// Preload the immutable files archives up to the last immutable file number.
    async fn preload(&self) -> StdResult<()> {
        let last_immutable_file_number =
            self.immutable_file_observer.get_last_immutable_number().await?;
        self.archives_creator
            .create_missing_archives(last_immutable_file_number)
            .await
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use mithril_cardano_node_internal_database::test::double::DumbImmutableFileObserver;

    use super::*;

    async fn immutable_file_observer(
        last_immutable: ImmutableFileNumber,
    ) -> Arc<DumbImmutableFileObserver> {
        let observer = DumbImmutableFileObserver::new();
        observer.shall_return(Some(last_immutable)).await;
        Arc::new(observer)
    }

    #[tokio::test]
    async fn preload_create_missing_archives_up_to_last_immutable() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator
            .expect_create_missing_archives()
            .with(eq(42))
            .times(1)
            .returning(|_| Ok(()));

        let preloader = ImmutablesArchivesPreloader::new(
            Arc::new(archives_creator),
            immutable_file_observer(42).await,
            true,
        );

        preloader.preload().await.unwrap();
    }

    #[tokio::test]
    async fn preload_fail_without_creating_archives_when_last_immutable_retrieval_fails() {
        let mut archives_creator = MockImmutablesArchivesCreator::new();
        archives_creator.expect_create_missing_archives().never();

        let preloader = ImmutablesArchivesPreloader::new(
            Arc::new(archives_creator),
            Arc::new(DumbImmutableFileObserver::new()),
            true,
        );

        preloader.preload().await.expect_err("preload should fail");
    }

    #[tokio::test]
    async fn lock_cardano_database() {
        let preloader = ImmutablesArchivesPreloader::new(
            Arc::new(MockImmutablesArchivesCreator::new()),
            immutable_file_observer(42).await,
            true,
        );

        assert_eq!(
            vec![SignedEntityTypeDiscriminants::CardanoDatabase],
            preloader.signed_entities_to_lock()
        );
    }
}
