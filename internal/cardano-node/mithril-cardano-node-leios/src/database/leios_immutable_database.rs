use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use sqlite::{Connection, OpenFlags};

use mithril_common::StdResult;

use super::LeiosImmutableDatabaseLayout;

/// The immutable partition of the LeiosDB of a node, accessed through a layout adapter.
pub struct LeiosImmutableDatabase {
    /// Connection to the SQLite database file.
    connection: Connection,

    /// Adapter of the layout of the database.
    layout: Arc<dyn LeiosImmutableDatabaseLayout>,
}

impl LeiosImmutableDatabase {
    /// Name of the immutable partition file of the LeiosDB in the node database directory.
    pub const FILE_NAME: &'static str = "leios.imm.db";

    /// Tells whether the node database directory holds a LeiosDB immutable partition.
    pub fn exists(db_directory: &Path) -> bool {
        Self::file_path(db_directory).exists()
    }

    /// Opens an existing database read-only.
    pub fn open_read_only(
        db_directory: &Path,
        layout: Arc<dyn LeiosImmutableDatabaseLayout>,
    ) -> StdResult<Self> {
        Ok(Self {
            connection: Self::open_connection_read_only(db_directory)?,
            layout,
        })
    }

    /// Takes a consistent copy of the database of a node, running or not, into the target directory.
    ///
    /// The copy is one file without the write-ahead log sidecars and holds every committed row.
    /// Fails when the target directory already holds a database.
    pub fn copy_consistent(db_directory: &Path, target_directory: &Path) -> StdResult<PathBuf> {
        let target_path = Self::file_path(target_directory);
        let target = target_path
            .to_str()
            .ok_or_else(|| anyhow!("Non UTF-8 path '{}'", target_path.display()))?;
        let connection = Self::open_connection_read_only(db_directory)?;
        let mut statement = connection
            .prepare("VACUUM INTO ?")
            .with_context(|| "Could not prepare the copy of the Leios database")?;
        statement.bind((1, target))?;
        statement.next().with_context(|| {
            format!(
                "Could not copy the Leios database of '{}' to '{target}'",
                db_directory.display()
            )
        })?;

        Ok(target_path)
    }

    /// Tells whether the database holds the closure of an endorser block given its hash in lowercase hex.
    pub fn has_closure(&self, endorser_block_hash: &str) -> StdResult<bool> {
        self.layout.has_closure(&self.connection, endorser_block_hash)
    }

    /// Opens a read-only connection on the database of a directory.
    fn open_connection_read_only(db_directory: &Path) -> StdResult<Connection> {
        let path = Self::file_path(db_directory);

        Connection::open_with_flags(&path, OpenFlags::new().with_read_only())
            .with_context(|| format!("Could not open '{}' read-only", path.display()))
    }

    /// Path of the database file in a directory.
    fn file_path(db_directory: &Path) -> PathBuf {
        db_directory.join(Self::FILE_NAME)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::TempDir;

    use crate::database::LayoutRc2026w44;
    use crate::test::LeiosFixtures;

    use super::*;

    #[test]
    fn exists_is_false_without_database_file() {
        let db_directory = TempDir::create("leios_database", "exists_false");

        assert!(!LeiosImmutableDatabase::exists(&db_directory));
    }

    #[test]
    fn exists_is_true_with_a_database_file() {
        let db_directory = TempDir::create("leios_database", "exists_true");
        LeiosFixtures::copy_to(&db_directory);

        assert!(LeiosImmutableDatabase::exists(&db_directory));
    }

    #[test]
    fn open_read_only_fails_without_database_file() {
        let db_directory = TempDir::create("leios_database", "open_fails");

        LeiosImmutableDatabase::open_read_only(&db_directory, Arc::new(LayoutRc2026w44))
            .err()
            .expect("should fail without database file");
    }

    #[test]
    fn copy_consistent_creates_one_file_holding_every_closure() {
        let db_directory = TempDir::create("leios_database", "copy_source");
        let target_directory = TempDir::create("leios_database", "copy_target");
        LeiosFixtures::copy_to(&db_directory);

        let copy_path =
            LeiosImmutableDatabase::copy_consistent(&db_directory, &target_directory).unwrap();

        assert_eq!(
            copy_path,
            target_directory.join(LeiosImmutableDatabase::FILE_NAME)
        );
        let copied_files: Vec<_> = std::fs::read_dir(&target_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(copied_files, vec![LeiosImmutableDatabase::FILE_NAME]);
        let copy =
            LeiosImmutableDatabase::open_read_only(&target_directory, Arc::new(LayoutRc2026w44))
                .unwrap();
        for endorser_block_hash in LeiosFixtures::ENDORSER_BLOCK_HASHES {
            assert!(copy.has_closure(endorser_block_hash).unwrap());
        }
    }

    #[test]
    fn copy_consistent_holds_the_rows_still_in_the_write_ahead_log() {
        let db_directory = TempDir::create("leios_database", "copy_wal_source");
        let target_directory = TempDir::create("leios_database", "copy_wal_target");
        LeiosFixtures::copy_to(&db_directory);
        let endorser_block_hash = "ab".repeat(32);
        let writer = LeiosFixtures::open_node_connection(&db_directory);
        LeiosFixtures::insert_closure(&writer, &endorser_block_hash);

        LeiosImmutableDatabase::copy_consistent(&db_directory, &target_directory).unwrap();

        let copy =
            LeiosImmutableDatabase::open_read_only(&target_directory, Arc::new(LayoutRc2026w44))
                .unwrap();
        assert!(copy.has_closure(&endorser_block_hash).unwrap());
    }

    #[test]
    fn copy_consistent_fails_when_the_target_already_holds_a_database() {
        let db_directory = TempDir::create("leios_database", "copy_twice_source");
        let target_directory = TempDir::create("leios_database", "copy_twice_target");
        LeiosFixtures::copy_to(&db_directory);
        LeiosImmutableDatabase::copy_consistent(&db_directory, &target_directory).unwrap();

        LeiosImmutableDatabase::copy_consistent(&db_directory, &target_directory)
            .expect_err("should fail when the target exists");
    }
}
