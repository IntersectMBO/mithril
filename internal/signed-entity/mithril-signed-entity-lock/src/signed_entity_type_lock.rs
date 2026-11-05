//! # Signed Entity Type Lock
//!
//! This module provides a non-blocking lock mechanism for signed entity types to prevent multiple
//! modifications on a same entity type at the same time.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use mithril_common::entities::SignedEntityTypeDiscriminants;

/// Number of holders of the lock of each locked signed entity type.
type LockCounts = BTreeMap<SignedEntityTypeDiscriminants, usize>;

/// Non-blocking lock mechanism for signed entity types to prevent multiple
/// modifications on a same entity type at the same time.
///
/// A signed entity type can be locked by several holders at the same time: it stays locked
/// until it has been released as many times as it has been locked.
pub struct SignedEntityTypeLock {
    locked_entities: Mutex<LockCounts>,
}

impl SignedEntityTypeLock {
    /// Create a new instance of `SignedEntityLock` without any signed entity locked.
    pub fn new() -> Self {
        Self {
            locked_entities: Mutex::new(BTreeMap::new()),
        }
    }

    fn locked_entities(&self) -> MutexGuard<'_, LockCounts> {
        // Poisoning is ignored: each critical section either only reads the counts or applies a
        // single update that can't be left half done, so the counts are consistent even after a panic
        self.locked_entities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Check if a signed entity is locked.
    pub async fn is_locked<T: Into<SignedEntityTypeDiscriminants>>(&self, entity_type: T) -> bool {
        self.locked_entities().contains_key(&entity_type.into())
    }

    /// Lock a signed entity.
    ///
    /// If the entity is already locked, it will stay locked until released as many times as it
    /// has been locked.
    pub async fn lock<T: Into<SignedEntityTypeDiscriminants>>(&self, entity_type: T) {
        let entity_type = entity_type.into();
        self.locked_entities()
            .entry(entity_type)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Release a locked signed entity.
    ///
    /// The entity is unlocked only when released as many times as it has been locked.
    /// If the entity is not locked, this function does nothing.
    pub async fn release<T: Into<SignedEntityTypeDiscriminants>>(&self, entity_type: T) {
        let mut locked_entities = self.locked_entities();
        let entity_type = entity_type.into();
        if let Some(count) = locked_entities.get_mut(&entity_type) {
            *count -= 1;
            if *count == 0 {
                locked_entities.remove(&entity_type);
            }
        }
    }

    /// Check if there are any locked signed entities.
    pub async fn has_locked_entities(&self) -> bool {
        !self.locked_entities().is_empty()
    }

    /// List only the unlocked signed entities in the given list.
    pub async fn filter_unlocked_entries<T: Into<SignedEntityTypeDiscriminants> + Clone>(
        &self,
        entries: Vec<T>,
    ) -> Vec<T> {
        let locked_entities = self.locked_entities();
        entries
            .into_iter()
            .filter(|entry| !locked_entities.contains_key(&entry.clone().into()))
            .collect()
    }
}

impl Default for SignedEntityTypeLock {
    /// Create a new instance of `SignedEntityLock` without any signed entity locked.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn by_default_entity_is_not_locked() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        for entity_type in SignedEntityTypeDiscriminants::all() {
            assert!(!signed_entity_type_lock.is_locked(entity_type).await);
        }
    }

    #[tokio::test]
    async fn lock_a_signed_entity() {
        for entity_type in SignedEntityTypeDiscriminants::all() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();
            signed_entity_type_lock.lock(entity_type).await;
            assert!(signed_entity_type_lock.is_locked(entity_type).await);
        }
    }

    #[tokio::test]
    async fn locking_an_entity_more_than_once_in_a_row_dont_crash() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        signed_entity_type_lock.lock(entity).await;
        signed_entity_type_lock.lock(entity).await;
        signed_entity_type_lock.lock(entity).await;

        assert!(signed_entity_type_lock.is_locked(entity).await);
    }

    #[tokio::test]
    async fn locking_a_signed_entity_does_not_lock_other_entity() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        signed_entity_type_lock
            .lock(SignedEntityTypeDiscriminants::CardanoDatabase)
            .await;
        assert!(
            signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                .await
        );
        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::MithrilStakeDistribution)
                .await
        );
    }

    #[tokio::test]
    async fn releasing_an_locked_entity() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        signed_entity_type_lock.lock(entity).await;
        signed_entity_type_lock.release(entity).await;

        assert!(!signed_entity_type_lock.is_locked(entity).await);
    }

    #[tokio::test]
    async fn releasing_an_already_released_entity() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        assert!(!signed_entity_type_lock.is_locked(entity).await);

        signed_entity_type_lock.release(entity).await;

        assert!(!signed_entity_type_lock.is_locked(entity).await);
    }

    #[tokio::test]
    async fn entity_locked_more_than_once_stays_locked_until_released_as_many_times() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        signed_entity_type_lock.lock(entity).await;
        signed_entity_type_lock.lock(entity).await;

        signed_entity_type_lock.release(entity).await;
        assert!(signed_entity_type_lock.is_locked(entity).await);
        assert!(signed_entity_type_lock.has_locked_entities().await);
        assert!(
            signed_entity_type_lock
                .filter_unlocked_entries(vec![entity])
                .await
                .is_empty()
        );

        signed_entity_type_lock.release(entity).await;
        assert!(!signed_entity_type_lock.is_locked(entity).await);
        assert!(!signed_entity_type_lock.has_locked_entities().await);
    }

    #[tokio::test]
    async fn releasing_an_unlocked_entity_does_not_prevent_it_from_being_locked_later() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        signed_entity_type_lock.release(entity).await;
        signed_entity_type_lock.lock(entity).await;

        assert!(signed_entity_type_lock.is_locked(entity).await);
    }

    #[tokio::test]
    async fn releasing_a_signed_entity_does_not_release_other_entity() {
        let released_entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        for entity in SignedEntityTypeDiscriminants::all() {
            signed_entity_type_lock.lock(entity).await;
        }

        signed_entity_type_lock.release(released_entity).await;

        assert!(!signed_entity_type_lock.is_locked(released_entity).await);
        assert!(
            signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoDatabase)
                .await
        );
        assert!(
            signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
                .await
        );
    }

    #[tokio::test]
    async fn filters_out_locked_entities() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        let signed_entities: Vec<_> = vec![
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            SignedEntityTypeDiscriminants::CardanoTransactions,
        ];

        assert_eq!(
            signed_entity_type_lock
                .filter_unlocked_entries(signed_entities.clone())
                .await,
            signed_entities.clone()
        );

        signed_entity_type_lock
            .lock(SignedEntityTypeDiscriminants::MithrilStakeDistribution)
            .await;

        assert_eq!(
            signed_entity_type_lock
                .filter_unlocked_entries(signed_entities.clone())
                .await,
            vec![SignedEntityTypeDiscriminants::CardanoTransactions]
        );
    }

    #[tokio::test]
    async fn has_locked_entities() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        assert!(!signed_entity_type_lock.has_locked_entities().await);

        signed_entity_type_lock
            .lock(SignedEntityTypeDiscriminants::MithrilStakeDistribution)
            .await;
        assert!(signed_entity_type_lock.has_locked_entities().await);
    }
}
