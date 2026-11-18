//! Test helpers of the crate.

use std::path::{Path, PathBuf};

use sqlite::Connection;

use crate::LeiosImmutableDatabase;

/// The Leios fixtures captured from a devnet run of the `rc-2026w44` Leios node on 2026-11-18:
/// the immutable files 0 to 7 and the `leios.imm.db` of the node with the closures of their four
/// certifying blocks.
pub struct LeiosFixtures;

impl LeiosFixtures {
    /// Number of the last immutable file of the fixtures.
    pub const LAST_IMMUTABLE_FILE_NUMBER: u64 = 7;

    /// Hashes of the endorser blocks certified in the immutable files of the fixtures, in chain order.
    pub const ENDORSER_BLOCK_HASHES: [&'static str; 4] = [
        "771de5e0899b465990c3e44ced4e852572153f59ee2fc2a3407eb993b1ba8500",
        "50b2ee675434976545b1a59e087708949cb5b539e6c5e1c80806a355e5a05edf",
        "cd130768305a8f01a1383fc369d5804805949fe663f8be93809461aaecc9abd3",
        "5866789c8c45f187e1ed911f48e6cb0a5495b65fb75a7a84f36d9dcd448c2d88",
    ];

    /// Directory of the fixtures.
    pub fn directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("assets")
            .join("leios")
    }

    /// Copies the fixture immutable files and database into a directory, as a node database directory.
    pub fn copy_to(db_directory: &Path) {
        Self::copy_immutable_files_to(
            db_directory,
            &(0..=Self::LAST_IMMUTABLE_FILE_NUMBER).collect::<Vec<_>>(),
        );
        std::fs::copy(
            Self::directory().join(LeiosImmutableDatabase::FILE_NAME),
            db_directory.join(LeiosImmutableDatabase::FILE_NAME),
        )
        .expect("fixture database copy");
    }

    /// Copies the given fixture immutable files into the `immutable` directory of a directory.
    pub fn copy_immutable_files_to(db_directory: &Path, immutable_file_numbers: &[u64]) {
        let immutable_directory = db_directory.join("immutable");
        std::fs::create_dir_all(&immutable_directory).expect("fixture immutable directory");
        for immutable_file_number in immutable_file_numbers {
            for extension in ["chunk", "primary", "secondary"] {
                let file_name = format!("{immutable_file_number:05}.{extension}");
                std::fs::copy(
                    Self::directory().join("immutable").join(&file_name),
                    immutable_directory.join(&file_name),
                )
                .expect("fixture immutable file copy");
            }
        }
    }

    /// Opens a read-write connection on the database of a directory, in the journal mode of the node.
    pub fn open_node_connection(db_directory: &Path) -> Connection {
        let connection = sqlite::open(db_directory.join(LeiosImmutableDatabase::FILE_NAME))
            .expect("fixture database connection");
        connection
            .execute("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;")
            .expect("fixture database pragmas");

        connection
    }

    /// Inserts the closure of an endorser block given its hash in hex, as the node promotes it.
    pub fn insert_closure(connection: &Connection, endorser_block_hash: &str) {
        connection
            .execute(format!(
                "INSERT INTO ebs (ebSlot, ebHashBytes, ebBytesSize) VALUES (1, x'{endorser_block_hash}', 1);
                 INSERT INTO ebBodies (ebHashBytes, txBounds, body) VALUES (x'{endorser_block_hash}', x'00', x'00');
                 INSERT INTO ebClosures (ebHashBytes, txs) VALUES (x'{endorser_block_hash}', x'00');"
            ))
            .expect("fixture closure insertion");
    }

    /// Deletes the closure of an endorser block given its hash in hex.
    pub fn delete_closure(connection: &Connection, endorser_block_hash: &str) {
        connection
            .execute(format!(
                "DELETE FROM ebClosures WHERE ebHashBytes = x'{endorser_block_hash}';
                 DELETE FROM ebBodies WHERE ebHashBytes = x'{endorser_block_hash}';
                 DELETE FROM ebs WHERE ebHashBytes = x'{endorser_block_hash}';"
            ))
            .expect("fixture closure deletion");
    }
}
