//! # Signed Entity Type Lock
//!
//! This module provides a non-blocking lock mechanism for signed entity types to prevent multiple
//! modifications on a same entity type at the same time.

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{Arc, Mutex, MutexGuard};

use mithril_common::entities::SignedEntityTypeDiscriminants;

/// Number of holders of the lock of each locked signed entity type.
type LockCounts = BTreeMap<SignedEntityTypeDiscriminants, usize>;

fn lock_counts(counts: &Mutex<LockCounts>) -> MutexGuard<'_, LockCounts> {
    // Poisoning is ignored: each critical section either only reads the counts or applies a
    // single update that can't be left half done, so the counts are consistent even after a panic
    counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Non-blocking lock mechanism for signed entity types to prevent multiple
/// modifications on a same entity type at the same time.
///
/// A signed entity type can be locked by several holders at the same time: it stays locked
/// until all the [guards][SignedEntityTypeLockGuard] returned by [lock][Self::lock] are dropped.
pub struct SignedEntityTypeLock {
    locked_entities: Arc<Mutex<LockCounts>>,
}

impl SignedEntityTypeLock {
    /// Create a new instance of `SignedEntityLock` without any signed entity locked.
    pub fn new() -> Self {
        Self {
            locked_entities: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn locked_entities(&self) -> MutexGuard<'_, LockCounts> {
        lock_counts(&self.locked_entities)
    }

    /// Check if a signed entity is locked.
    pub fn is_locked<T: Into<SignedEntityTypeDiscriminants>>(&self, entity_type: T) -> bool {
        self.locked_entities().contains_key(&entity_type.into())
    }

    /// Lock a signed entity, the lock is released when the returned guard is dropped.
    ///
    /// If the entity is already locked, it will stay locked until all its guards are dropped.
    pub fn lock<T: Into<SignedEntityTypeDiscriminants>>(
        &self,
        entity_type: T,
    ) -> SignedEntityTypeLockGuard {
        let entity_type = entity_type.into();
        self.locked_entities()
            .entry(entity_type)
            .and_modify(|count| *count += 1)
            .or_insert(1);

        SignedEntityTypeLockGuard {
            locked_entities: self.locked_entities.clone(),
            entity_type,
        }
    }

    /// Lock a signed entity only if it is not already locked, the lock is released when the
    /// returned guard is dropped.
    ///
    /// Return `None` if the entity is already locked.
    ///
    /// Note: a guard returned by this method does not prevent the entity from being locked again
    /// with [lock][Self::lock].
    pub fn try_lock<T: Into<SignedEntityTypeDiscriminants>>(
        &self,
        entity_type: T,
    ) -> Option<SignedEntityTypeLockGuard> {
        let entity_type = entity_type.into();
        match self.locked_entities().entry(entity_type) {
            Entry::Occupied(_) => None,
            Entry::Vacant(entry) => {
                entry.insert(1);
                Some(SignedEntityTypeLockGuard {
                    locked_entities: self.locked_entities.clone(),
                    entity_type,
                })
            }
        }
    }

    /// Check if there are any locked signed entities.
    pub fn has_locked_entities(&self) -> bool {
        !self.locked_entities().is_empty()
    }

    /// List only the unlocked signed entities in the given list.
    pub fn filter_unlocked_entries<T: Into<SignedEntityTypeDiscriminants> + Clone>(
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

/// Guard of a signed entity type locked with [SignedEntityTypeLock::lock], releasing the lock
/// when dropped.
#[must_use = "the signed entity type is released as soon as the guard is dropped"]
pub struct SignedEntityTypeLockGuard {
    locked_entities: Arc<Mutex<LockCounts>>,
    entity_type: SignedEntityTypeDiscriminants,
}

impl Drop for SignedEntityTypeLockGuard {
    fn drop(&mut self) {
        if let Entry::Occupied(mut entry) =
            lock_counts(&self.locked_entities).entry(self.entity_type)
        {
            if *entry.get() == 1 {
                entry.remove();
            } else {
                *entry.get_mut() -= 1;
            }
        }
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

    #[test]
    fn by_default_entity_is_not_locked() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        for entity_type in SignedEntityTypeDiscriminants::all() {
            assert!(!signed_entity_type_lock.is_locked(entity_type));
        }
    }

    #[test]
    fn lock_a_signed_entity_while_its_guard_is_alive() {
        for entity_type in SignedEntityTypeDiscriminants::all() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();
            let _guard = signed_entity_type_lock.lock(entity_type);
            assert!(signed_entity_type_lock.is_locked(entity_type));
        }
    }

    #[test]
    fn dropping_the_guard_releases_the_entity() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        let guard = signed_entity_type_lock.lock(entity);
        drop(guard);

        assert!(!signed_entity_type_lock.is_locked(entity));
    }

    #[test]
    fn locking_a_signed_entity_does_not_lock_other_entity() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        let _guard = signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::CardanoDatabase);
        assert!(signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoDatabase));
        assert!(
            !signed_entity_type_lock
                .is_locked(SignedEntityTypeDiscriminants::MithrilStakeDistribution)
        );
    }

    #[test]
    fn entity_locked_more_than_once_stays_locked_until_all_its_guards_are_dropped() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        let first_guard = signed_entity_type_lock.lock(entity);
        let second_guard = signed_entity_type_lock.lock(entity);

        drop(first_guard);
        assert!(signed_entity_type_lock.is_locked(entity));
        assert!(signed_entity_type_lock.has_locked_entities());
        assert!(
            signed_entity_type_lock
                .filter_unlocked_entries(vec![entity])
                .is_empty()
        );

        drop(second_guard);
        assert!(!signed_entity_type_lock.is_locked(entity));
        assert!(!signed_entity_type_lock.has_locked_entities());
    }

    #[test]
    fn dropping_the_guard_of_a_signed_entity_does_not_release_other_entity() {
        let released_entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        let released_entity_guard = signed_entity_type_lock.lock(released_entity);
        let _other_guards: Vec<_> = SignedEntityTypeDiscriminants::all()
            .into_iter()
            .filter(|entity| *entity != released_entity)
            .map(|entity| signed_entity_type_lock.lock(entity))
            .collect();

        drop(released_entity_guard);

        assert!(!signed_entity_type_lock.is_locked(released_entity));
        assert!(signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoDatabase));
        assert!(
            signed_entity_type_lock.is_locked(SignedEntityTypeDiscriminants::CardanoTransactions)
        );
    }

    #[test]
    fn guard_can_be_moved_to_another_thread_and_release_the_entity_there() {
        let entity = SignedEntityTypeDiscriminants::MithrilStakeDistribution;
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        let guard = signed_entity_type_lock.lock(entity);
        std::thread::spawn(move || drop(guard)).join().unwrap();

        assert!(!signed_entity_type_lock.is_locked(entity));
    }

    #[test]
    fn filters_out_locked_entities() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();
        let signed_entities: Vec<_> = vec![
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            SignedEntityTypeDiscriminants::CardanoTransactions,
        ];

        assert_eq!(
            signed_entity_type_lock.filter_unlocked_entries(signed_entities.clone()),
            signed_entities.clone()
        );

        let _guard =
            signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::MithrilStakeDistribution);

        assert_eq!(
            signed_entity_type_lock.filter_unlocked_entries(signed_entities.clone()),
            vec![SignedEntityTypeDiscriminants::CardanoTransactions]
        );
    }

    #[test]
    fn has_locked_entities() {
        let signed_entity_type_lock = SignedEntityTypeLock::new();

        assert!(!signed_entity_type_lock.has_locked_entities());

        let _guard =
            signed_entity_type_lock.lock(SignedEntityTypeDiscriminants::MithrilStakeDistribution);
        assert!(signed_entity_type_lock.has_locked_entities());
    }

    mod try_lock {
        use super::*;

        const ENTITY: SignedEntityTypeDiscriminants =
            SignedEntityTypeDiscriminants::MithrilStakeDistribution;

        #[test]
        fn lock_a_signed_entity_that_is_not_locked() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();

            let guard = signed_entity_type_lock.try_lock(ENTITY);

            assert!(guard.is_some());
            assert!(signed_entity_type_lock.is_locked(ENTITY));
        }

        #[test]
        fn return_none_if_the_signed_entity_is_already_locked_with_lock() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();
            let _guard = signed_entity_type_lock.lock(ENTITY);

            assert!(signed_entity_type_lock.try_lock(ENTITY).is_none());
        }

        #[test]
        fn return_none_if_the_signed_entity_is_already_locked_with_try_lock() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();
            let _guard = signed_entity_type_lock.try_lock(ENTITY);

            assert!(signed_entity_type_lock.try_lock(ENTITY).is_none());
        }

        #[test]
        fn dropping_the_guard_releases_the_entity() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();

            let guard = signed_entity_type_lock.try_lock(ENTITY);
            drop(guard);

            assert!(!signed_entity_type_lock.is_locked(ENTITY));
        }

        #[test]
        fn lock_can_lock_an_entity_already_locked_with_try_lock() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();

            let first_guard = signed_entity_type_lock.try_lock(ENTITY);
            let _second_guard = signed_entity_type_lock.lock(ENTITY);
            drop(first_guard);

            assert!(signed_entity_type_lock.is_locked(ENTITY));
        }

        #[test]
        fn failing_to_lock_an_already_locked_entity_does_not_release_it() {
            let signed_entity_type_lock = SignedEntityTypeLock::new();
            let _guard = signed_entity_type_lock.lock(ENTITY);

            let _ = signed_entity_type_lock.try_lock(ENTITY);

            assert!(signed_entity_type_lock.is_locked(ENTITY));
        }
    }
}
