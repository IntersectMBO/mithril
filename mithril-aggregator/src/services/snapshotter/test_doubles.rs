use async_trait::async_trait;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use mithril_common::StdResult;
use mithril_common::entities::{CompressionAlgorithm, ImmutableFileNumber};
use mithril_file_archiver::FileArchive;

use crate::services::Snapshotter;

/// Snapshotter that does nothing. It is mainly used for test purposes.
pub struct DumbSnapshotter {
    last_snapshot: RwLock<Option<FileArchive>>,
    compression_algorithm: CompressionAlgorithm,
    archive_size: u64,
}

impl DumbSnapshotter {
    /// Create a new instance of DumbSnapshotter.
    ///
    /// The `compression_algorithm` parameter is used for the output file name extension.
    pub fn new(compression_algorithm: CompressionAlgorithm) -> Self {
        Self {
            last_snapshot: RwLock::new(None),
            compression_algorithm,
            archive_size: 0,
        }
    }

    /// Set the size assigned to the produced snapshots.
    pub fn with_archive_size(mut self, size: u64) -> Self {
        self.archive_size = size;
        self
    }

    /// Return the last fake snapshot produced.
    pub fn get_last_snapshot(&self) -> StdResult<Option<FileArchive>> {
        let value = self.last_snapshot.read().unwrap().as_ref().cloned();

        Ok(value)
    }

    fn create_dumb_archive(&self, archive_name_without_extension: &str) -> FileArchive {
        let mut value = self.last_snapshot.write().unwrap();
        let snapshot = FileArchive::new(
            PathBuf::from(format!(
                "{archive_name_without_extension}.{}",
                self.compression_algorithm.tar_file_extension()
            )),
            self.archive_size,
            0,
            self.compression_algorithm,
        );
        *value = Some(snapshot.clone());

        snapshot
    }
}

impl Default for DumbSnapshotter {
    fn default() -> Self {
        Self {
            last_snapshot: RwLock::new(None),
            compression_algorithm: CompressionAlgorithm::Zstandard,
            archive_size: 0,
        }
    }
}

#[async_trait]
impl Snapshotter for DumbSnapshotter {
    async fn snapshot_ancillary(
        &self,
        _immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        Ok(self.create_dumb_archive(archive_name_without_extension))
    }

    async fn snapshot_immutable_trio(
        &self,
        _immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        Ok(self.create_dumb_archive(archive_name_without_extension))
    }

    async fn compute_immutable_files_total_uncompressed_size(
        &self,
        _up_to_immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<u64> {
        Ok(0)
    }

    fn compression_algorithm(&self) -> CompressionAlgorithm {
        self.compression_algorithm
    }
}

/// Snapshotter that writes empty files to the filesystem. Used for testing purposes.
pub struct FakeSnapshotter {
    work_dir: PathBuf,
    compression_algorithm: CompressionAlgorithm,
}

impl FakeSnapshotter {
    /// `FakeSnapshotter` factory, with a default compression algorithm of `Zstandard`.
    pub fn new<T: AsRef<Path>>(work_dir: T) -> Self {
        Self {
            work_dir: work_dir.as_ref().to_path_buf(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        }
    }

    /// Set the compression algorithm used to for the output file name extension.
    pub fn with_compression_algorithm(
        mut self,
        compression_algorithm: CompressionAlgorithm,
    ) -> Self {
        self.compression_algorithm = compression_algorithm;
        self
    }

    fn create_fake_archive(&self, archive_name_without_extension: &str) -> FileArchive {
        let fake_archive_path = self.work_dir.join(format!(
            "{archive_name_without_extension}.{}",
            self.compression_algorithm.tar_file_extension()
        ));
        if let Some(archive_dir) = fake_archive_path.parent() {
            fs::create_dir_all(archive_dir).unwrap();
        }
        File::create(&fake_archive_path).unwrap();

        FileArchive::new(fake_archive_path, 0, 0, self.compression_algorithm)
    }
}

#[async_trait]
impl Snapshotter for FakeSnapshotter {
    async fn snapshot_ancillary(
        &self,
        _immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        Ok(self.create_fake_archive(archive_name_without_extension))
    }

    async fn snapshot_immutable_trio(
        &self,
        _immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive> {
        Ok(self.create_fake_archive(archive_name_without_extension))
    }

    async fn compute_immutable_files_total_uncompressed_size(
        &self,
        _up_to_immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<u64> {
        Ok(0)
    }

    fn compression_algorithm(&self) -> CompressionAlgorithm {
        self.compression_algorithm
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use super::*;

    mod dumb_snapshotter {
        use super::*;

        #[test]
        fn return_parametrized_compression_algorithm() {
            let snapshotter = DumbSnapshotter::new(CompressionAlgorithm::Zstandard);
            assert_eq!(
                CompressionAlgorithm::Zstandard,
                snapshotter.compression_algorithm()
            );
        }

        #[tokio::test]
        async fn test_dumb_snapshotter_snapshot_return_archive_named_with_compression_algorithm_and_size_of_0()
         {
            let snapshotter = DumbSnapshotter::new(CompressionAlgorithm::Zstandard);

            let snapshot = snapshotter.snapshot_ancillary(3, "archive_ancillary").await.unwrap();
            assert_eq!(
                PathBuf::from("archive_ancillary.tar.zst"),
                *snapshot.get_file_path()
            );
            assert_eq!(0, snapshot.get_archive_size());

            let snapshot = snapshotter
                .snapshot_immutable_trio(4, "archive_immutable_trio")
                .await
                .unwrap();
            assert_eq!(
                PathBuf::from("archive_immutable_trio.tar.zst"),
                *snapshot.get_file_path()
            );
            assert_eq!(0, snapshot.get_archive_size());
        }

        #[tokio::test]
        async fn test_dumb_snapshotter() {
            let snapshotter = DumbSnapshotter::new(CompressionAlgorithm::Zstandard);
            assert!(
                snapshotter
                    .get_last_snapshot()
                    .expect(
                        "Dumb snapshotter::get_last_snapshot should not fail when no last snapshot."
                    )
                    .is_none()
            );

            {
                let ancillary_snapshot = snapshotter
                    .snapshot_ancillary(3, "whatever")
                    .await
                    .expect("Dumb snapshotter::snapshot_ancillary should not fail.");
                assert_eq!(
                    Some(ancillary_snapshot),
                    snapshotter.get_last_snapshot().expect(
                        "Dumb snapshotter::get_last_snapshot should not fail when some last snapshot."
                    )
                );
            }
            {
                let immutable_snapshot = snapshotter
                    .snapshot_immutable_trio(4, "whatever")
                    .await
                    .expect("Dumb snapshotter::snapshot_immutable_trio should not fail.");
                assert_eq!(
                    Some(immutable_snapshot),
                    snapshotter.get_last_snapshot().expect(
                        "Dumb snapshotter::get_last_snapshot should not fail when some last snapshot."
                    )
                );
            }
        }

        #[tokio::test]
        async fn set_dumb_snapshotter_archive_size() {
            let snapshotter = DumbSnapshotter::new(CompressionAlgorithm::Zstandard);

            // Default size is 0
            let snapshot = snapshotter.snapshot_immutable_trio(1, "whatever").await.unwrap();
            assert_eq!(0, snapshot.get_archive_size());

            let snapshotter = snapshotter.with_archive_size(42);
            let snapshot = snapshotter.snapshot_immutable_trio(2, "whatever").await.unwrap();
            assert_eq!(42, snapshot.get_archive_size());
        }
    }

    mod fake_snapshotter {
        use super::*;

        #[test]
        fn return_parametrized_compression_algorithm() {
            let snapshotter = FakeSnapshotter::new("whatever")
                .with_compression_algorithm(CompressionAlgorithm::Zstandard);
            assert_eq!(
                CompressionAlgorithm::Zstandard,
                snapshotter.compression_algorithm()
            );
        }

        #[tokio::test]
        async fn test_fake_snapshotter() {
            let test_dir = temp_dir_create!();
            let fake_snapshotter = FakeSnapshotter::new(&test_dir)
                .with_compression_algorithm(CompressionAlgorithm::Zstandard);

            for filename in ["direct_child", "one_level_subdir/child", "two_levels/subdir/child"] {
                {
                    let ancillary_snapshot =
                        fake_snapshotter.snapshot_ancillary(3, filename).await.unwrap();

                    assert_eq!(
                        ancillary_snapshot.get_file_path(),
                        &test_dir.join(filename).with_extension("tar.zst")
                    );
                    assert!(ancillary_snapshot.get_file_path().is_file());
                }
                {
                    let immutable_snapshot =
                        fake_snapshotter.snapshot_immutable_trio(5, filename).await.unwrap();

                    assert_eq!(
                        immutable_snapshot.get_file_path(),
                        &test_dir.join(filename).with_extension("tar.zst")
                    );
                    assert!(immutable_snapshot.get_file_path().is_file());
                }
            }
        }
    }
}
