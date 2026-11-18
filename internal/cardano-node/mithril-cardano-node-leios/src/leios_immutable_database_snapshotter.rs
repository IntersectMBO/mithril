use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, anyhow};
use semver::Version;
use thiserror::Error;

use mithril_common::StdResult;
use mithril_common::entities::ImmutableFileNumber;

use crate::entities::CertifyingBlock;
use crate::{CertifyingBlocksReader, LeiosImmutableDatabase, LeiosImmutableDatabaseLayoutProvider};

/// Error raised when snapshotting the Leios database of a Cardano node.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LeiosImmutableDatabaseSnapshotError {
    /// The copy of the database misses the closures of certified endorser blocks, given by their hashes.
    #[error("The copy of the Leios database misses the closures of the endorser blocks: {0:?}")]
    MissingClosures(Vec<String>),
}

/// Policy of the attempts to copy a database holding the closure of every certifying block.
///
/// The node promotes a closure to `leios.imm.db` shortly after it appends its certifying block to
/// the immutable files, so a closure missing in a copy can be in the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeiosImmutableDatabaseSnapshotRetryPolicy {
    /// Maximum number of copies taken, at least one copy is always taken.
    pub attempts: usize,

    /// Delay between two copies.
    pub delay: Duration,
}

impl Default for LeiosImmutableDatabaseSnapshotRetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            delay: Duration::from_secs(2),
        }
    }
}

/// The certifying blocks of the completed immutable files already scanned, which never change.
#[derive(Default)]
struct CompletedImmutableFilesScan {
    /// Number of the first immutable file not scanned yet.
    next_immutable_file_number: ImmutableFileNumber,

    /// Certifying blocks of the scanned immutable files, in chain order.
    certifying_blocks: Vec<CertifyingBlock>,
}

/// Snapshotter of the `leios.imm.db` database of a Cardano node.
///
/// It takes a consistent copy of the database and checks that the copy holds the closure of every
/// endorser block certified in the immutable files that are shipped with it.
pub struct LeiosImmutableDatabaseSnapshotter {
    /// Database directory of the Cardano node.
    db_directory: PathBuf,

    /// Version of the Cardano node, which selects the layout of its Leios database.
    cardano_node_version: Version,

    /// Policy of the attempts to copy a database holding every closure.
    retry_policy: LeiosImmutableDatabaseSnapshotRetryPolicy,

    /// Certifying blocks of the completed immutable files, scanned once across snapshots.
    completed_immutable_files_scan: Mutex<CompletedImmutableFilesScan>,
}

impl LeiosImmutableDatabaseSnapshotter {
    /// Name of the immutable files directory in the node database directory.
    const IMMUTABLE_DIR: &'static str = "immutable";

    /// Creates a snapshotter of the database directory of a Cardano node of the given version.
    pub fn new(db_directory: PathBuf, cardano_node_version: Version) -> Self {
        Self {
            db_directory,
            cardano_node_version,
            retry_policy: LeiosImmutableDatabaseSnapshotRetryPolicy::default(),
            completed_immutable_files_scan: Mutex::new(CompletedImmutableFilesScan::default()),
        }
    }

    /// Sets the policy of the attempts to copy a database holding every closure.
    pub fn with_retry_policy(
        mut self,
        retry_policy: LeiosImmutableDatabaseSnapshotRetryPolicy,
    ) -> Self {
        self.retry_policy = retry_policy;

        self
    }

    /// Copies the Leios database of the node into the target directory and returns the path of the copy,
    /// or `None` when the node has no Leios database.
    ///
    /// The copy is taken after the copy of the partial immutable file, and must hold the closures of the
    /// certifying blocks of the completed immutable files of the node, up to the given number, and of the
    /// copy of the next, partial, immutable file found in `partial_immutable_directory`.
    pub fn snapshot(
        &self,
        target_directory: &Path,
        last_completed_immutable_file_number: ImmutableFileNumber,
        partial_immutable_directory: &Path,
    ) -> StdResult<Option<PathBuf>> {
        if !LeiosImmutableDatabase::exists(&self.db_directory) {
            return Ok(None);
        }
        let layout = LeiosImmutableDatabaseLayoutProvider::layout_for_cardano_node_version(
            &self.cardano_node_version,
        )?;
        let endorser_block_hashes = self.list_certified_endorser_block_hashes(
            last_completed_immutable_file_number,
            partial_immutable_directory,
        )?;

        let mut missing_closures = Vec::new();
        let attempts = self.retry_policy.attempts.max(1);
        for attempt in 1..=attempts {
            let copy_path =
                LeiosImmutableDatabase::copy_consistent(&self.db_directory, target_directory)?;
            let copy = LeiosImmutableDatabase::open_read_only(target_directory, layout.clone())?;
            missing_closures.clear();
            for endorser_block_hash in &endorser_block_hashes {
                if !copy.has_closure(endorser_block_hash)? {
                    missing_closures.push(endorser_block_hash.clone());
                }
            }
            if missing_closures.is_empty() {
                return Ok(Some(copy_path));
            }

            drop(copy);
            std::fs::remove_file(&copy_path).with_context(|| {
                format!(
                    "Could not remove the incomplete copy '{}'",
                    copy_path.display()
                )
            })?;
            if attempt < attempts {
                std::thread::sleep(self.retry_policy.delay);
            }
        }

        Err(LeiosImmutableDatabaseSnapshotError::MissingClosures(missing_closures).into())
    }

    /// Lists the hashes of the endorser blocks certified in the completed immutable files of the node,
    /// up to the given number, and in the copy of the partial immutable file.
    fn list_certified_endorser_block_hashes(
        &self,
        last_completed_immutable_file_number: ImmutableFileNumber,
        partial_immutable_directory: &Path,
    ) -> StdResult<Vec<String>> {
        let immutable_directory = self.db_directory.join(Self::IMMUTABLE_DIR);
        let mut scan = self
            .completed_immutable_files_scan
            .lock()
            .map_err(|_| anyhow!("The scan of the completed immutable files is poisoned"))?;
        if scan.next_immutable_file_number <= last_completed_immutable_file_number {
            let certifying_blocks = CertifyingBlocksReader::list_range(
                &immutable_directory,
                scan.next_immutable_file_number..=last_completed_immutable_file_number,
            )
            .with_context(
                || "Could not list the certifying blocks of the completed immutable files",
            )?;
            scan.certifying_blocks.extend(certifying_blocks);
            scan.next_immutable_file_number = last_completed_immutable_file_number + 1;
        }
        let partial_certifying_blocks =
            CertifyingBlocksReader::list_partial_with_previous_chunk_dir(
                partial_immutable_directory,
                &immutable_directory,
                last_completed_immutable_file_number + 1,
            )
            .with_context(
                || "Could not list the certifying blocks of the partial immutable file",
            )?;

        Ok(scan
            .certifying_blocks
            .iter()
            .filter(|block| block.immutable_file_number <= last_completed_immutable_file_number)
            .chain(&partial_certifying_blocks)
            .map(|block| block.endorser_block_hash.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mithril_common::test::TempDir;

    use crate::LayoutRc2026w44;
    use crate::test::LeiosFixtures;

    use super::*;

    const LEIOS_CARDANO_NODE_VERSION: Version = Version::new(11, 2, 0);

    struct TestSetup {
        db_directory: PathBuf,
        target_directory: PathBuf,
        partial_immutable_directory: PathBuf,
    }

    impl TestSetup {
        /// A node database with the fixture immutable files 0 to 6 completed and its database, and a
        /// target directory with the copy of the fixture immutable file 7, the partial one.
        fn new(test_name: &str) -> Self {
            let db_directory = TempDir::create("leios_snapshotter", format!("{test_name}_db"));
            LeiosFixtures::copy_to(&db_directory);
            let target_directory =
                TempDir::create("leios_snapshotter", format!("{test_name}_target"));
            LeiosFixtures::copy_immutable_files_to(&target_directory, &[7]);

            Self {
                partial_immutable_directory: target_directory.join("immutable"),
                db_directory,
                target_directory,
            }
        }

        fn snapshotter(&self) -> LeiosImmutableDatabaseSnapshotter {
            LeiosImmutableDatabaseSnapshotter::new(
                self.db_directory.clone(),
                LEIOS_CARDANO_NODE_VERSION,
            )
            .with_retry_policy(LeiosImmutableDatabaseSnapshotRetryPolicy {
                attempts: 2,
                delay: Duration::from_millis(1),
            })
        }

        fn snapshot(
            &self,
            snapshotter: &LeiosImmutableDatabaseSnapshotter,
        ) -> StdResult<Option<PathBuf>> {
            snapshotter.snapshot(&self.target_directory, 6, &self.partial_immutable_directory)
        }
    }

    #[test]
    fn snapshot_returns_nothing_when_the_node_has_no_leios_database() {
        let setup = TestSetup::new("no_database");
        std::fs::remove_file(setup.db_directory.join(LeiosImmutableDatabase::FILE_NAME)).unwrap();

        let snapshot_path = setup.snapshot(&setup.snapshotter()).unwrap();

        assert_eq!(snapshot_path, None);
    }

    #[test]
    fn snapshot_copies_a_database_holding_the_closures_of_the_completed_and_partial_files() {
        let setup = TestSetup::new("complete");

        let snapshot_path = setup.snapshot(&setup.snapshotter()).unwrap();

        assert_eq!(
            snapshot_path,
            Some(setup.target_directory.join(LeiosImmutableDatabase::FILE_NAME))
        );
        let copy = LeiosImmutableDatabase::open_read_only(
            &setup.target_directory,
            Arc::new(LayoutRc2026w44),
        )
        .unwrap();
        for endorser_block_hash in LeiosFixtures::ENDORSER_BLOCK_HASHES {
            assert!(copy.has_closure(endorser_block_hash).unwrap());
        }
    }

    #[test]
    fn snapshot_fails_when_the_closure_of_a_completed_file_is_missing() {
        let setup = TestSetup::new("missing_completed");
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[1]);

        let error = setup.snapshot(&setup.snapshotter()).unwrap_err();

        assert_eq!(
            error.downcast_ref::<LeiosImmutableDatabaseSnapshotError>(),
            Some(&LeiosImmutableDatabaseSnapshotError::MissingClosures(vec![
                LeiosFixtures::ENDORSER_BLOCK_HASHES[1].to_string()
            ]))
        );
        assert!(!LeiosImmutableDatabase::exists(&setup.target_directory));
    }

    #[test]
    fn snapshot_fails_when_the_closure_of_the_partial_file_is_missing() {
        let setup = TestSetup::new("missing_partial");
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[3]);

        let error = setup.snapshot(&setup.snapshotter()).unwrap_err();

        assert_eq!(
            error.downcast_ref::<LeiosImmutableDatabaseSnapshotError>(),
            Some(&LeiosImmutableDatabaseSnapshotError::MissingClosures(vec![
                LeiosFixtures::ENDORSER_BLOCK_HASHES[3].to_string()
            ]))
        );
        assert!(!LeiosImmutableDatabase::exists(&setup.target_directory));
    }

    #[test]
    fn snapshot_ignores_the_closures_certified_after_the_partial_file() {
        let setup = TestSetup::new("beyond_partial");
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[3]);
        LeiosFixtures::copy_immutable_files_to(&setup.target_directory, &[6]);

        let snapshot_path = setup
            .snapshotter()
            .snapshot(
                &setup.target_directory,
                5,
                &setup.partial_immutable_directory,
            )
            .unwrap();

        assert!(snapshot_path.is_some());
    }

    #[test]
    fn snapshot_retries_until_the_node_promotes_the_missing_closure() {
        let setup = TestSetup::new("retry");
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[3]);
        let snapshotter =
            setup
                .snapshotter()
                .with_retry_policy(LeiosImmutableDatabaseSnapshotRetryPolicy {
                    attempts: 50,
                    delay: Duration::from_millis(100),
                });
        let db_directory = setup.db_directory.clone();
        let promotion = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let connection = LeiosFixtures::open_node_connection(&db_directory);
            LeiosFixtures::insert_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[3]);
        });

        let snapshot_path = setup.snapshot(&snapshotter).unwrap();
        promotion.join().unwrap();

        assert!(snapshot_path.is_some());
    }

    #[test]
    fn snapshot_scans_the_completed_files_once_across_snapshots() {
        let setup = TestSetup::new("scan_once");
        let snapshotter = setup.snapshotter();
        setup.snapshot(&snapshotter).unwrap();
        std::fs::remove_file(setup.target_directory.join(LeiosImmutableDatabase::FILE_NAME))
            .unwrap();
        for immutable_file_number in 0..=5 {
            std::fs::remove_file(
                setup
                    .db_directory
                    .join("immutable")
                    .join(format!("{immutable_file_number:05}.chunk")),
            )
            .unwrap();
        }
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[0]);

        let error = setup.snapshot(&snapshotter).unwrap_err();

        assert_eq!(
            error.downcast_ref::<LeiosImmutableDatabaseSnapshotError>(),
            Some(&LeiosImmutableDatabaseSnapshotError::MissingClosures(vec![
                LeiosFixtures::ENDORSER_BLOCK_HASHES[0].to_string()
            ]))
        );
    }

    #[test]
    fn snapshot_of_an_earlier_immutable_file_ignores_the_scanned_files_after_it() {
        let setup = TestSetup::new("earlier_file");
        let snapshotter = setup.snapshotter();
        setup.snapshot(&snapshotter).unwrap();
        std::fs::remove_file(setup.target_directory.join(LeiosImmutableDatabase::FILE_NAME))
            .unwrap();
        LeiosFixtures::copy_immutable_files_to(&setup.target_directory, &[5]);
        let connection = LeiosFixtures::open_node_connection(&setup.db_directory);
        LeiosFixtures::delete_closure(&connection, LeiosFixtures::ENDORSER_BLOCK_HASHES[2]);

        let snapshot_path = snapshotter
            .snapshot(
                &setup.target_directory,
                4,
                &setup.partial_immutable_directory,
            )
            .unwrap();

        assert!(snapshot_path.is_some());
    }

    #[test]
    fn snapshot_takes_one_copy_with_a_retry_policy_of_zero_attempt() {
        let setup = TestSetup::new("zero_attempt");
        let snapshotter =
            setup
                .snapshotter()
                .with_retry_policy(LeiosImmutableDatabaseSnapshotRetryPolicy {
                    attempts: 0,
                    delay: Duration::ZERO,
                });

        let snapshot_path = setup.snapshot(&snapshotter).unwrap();

        assert!(snapshot_path.is_some());
    }

    #[test]
    fn snapshot_fails_for_a_cardano_node_without_leios_database_layout() {
        let setup = TestSetup::new("no_layout");
        let snapshotter = LeiosImmutableDatabaseSnapshotter::new(
            setup.db_directory.clone(),
            Version::new(11, 1, 3),
        );

        setup
            .snapshot(&snapshotter)
            .expect_err("should fail without database layout");
    }
}
