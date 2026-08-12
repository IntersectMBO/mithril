use anyhow::{Context, anyhow};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use mithril_common::StdResult;

use crate::tools::file_size;

const READ_WRITE_PERMISSION: u32 = 0o666;

/// Define multiple ways to append content to a tar archive.
pub trait TarAppender: Send {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()>;

    fn compute_uncompressed_data_size(&self) -> StdResult<u64>;

    fn chain<A2: TarAppender>(self, appender_right: A2) -> ChainAppender<Self, A2>
    where
        Self: Sized,
    {
        ChainAppender::new(self, appender_right)
    }
}

#[cfg(test)]
pub struct AppenderDirAll {
    target_directory: PathBuf,
}
#[cfg(test)]
impl AppenderDirAll {
    // Note: Not used anymore outside of tests but useful tool to keep around if we ever need to archive a directory
    pub fn new(target_directory: PathBuf) -> Self {
        Self { target_directory }
    }
}

#[cfg(test)]
impl TarAppender for AppenderDirAll {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        tar.append_dir_all(".", &self.target_directory).with_context(|| {
            format!(
                "Create archive error:  Can not add directory: '{}' to the archive",
                self.target_directory.display()
            )
        })?;
        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        file_size::compute_size_of_path(&self.target_directory)
    }
}

pub struct AppenderFile {
    /// Location of the file in the archive.
    location_in_archive: PathBuf,
    /// Path to the file to add to the archive.
    target_file: PathBuf,
}

impl AppenderFile {
    /// Append the file at the root of the archive, keeping the same file name.
    pub fn append_at_archive_root(target_file: PathBuf) -> StdResult<Self> {
        if !target_file.is_file() {
            return Err(anyhow!(
                "The target file is not a file, path: {}",
                target_file.display()
            ));
        }

        let location_in_archive = target_file
            .file_name()
            .with_context(|| {
                format!(
                    "Can not get the file name from the target file path: '{}'",
                    target_file.display()
                )
            })?
            .to_owned();

        Ok(Self {
            location_in_archive: PathBuf::from(location_in_archive),
            target_file,
        })
    }
}

impl TarAppender for AppenderFile {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        let mut file = File::open(&self.target_file)
            .with_context(|| format!("Can not open file: '{}'", self.target_file.display()))?;
        tar.append_file(&self.location_in_archive, &mut file)
            .with_context(|| {
                format!(
                    "Can not add file: '{}' to the archive",
                    self.target_file.display()
                )
            })?;
        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        file_size::compute_size_of_path(&self.target_file)
    }
}

pub struct AppenderEntries {
    entries: Vec<PathBuf>,
    base_directory: PathBuf,
}

impl AppenderEntries {
    /// Create a new instance of `AppenderEntries`.
    ///
    /// Returns an error if the `entries` are empty.
    pub fn new(entries: Vec<PathBuf>, base_directory: PathBuf) -> StdResult<Self> {
        if entries.is_empty() {
            return Err(anyhow!("The entries can not be empty"));
        }

        Ok(Self {
            entries,
            base_directory,
        })
    }
}

impl TarAppender for AppenderEntries {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        for entry in &self.entries {
            let entry_path = self.base_directory.join(entry);
            if entry_path.is_dir() {
                tar.append_dir(entry, entry_path.clone()).with_context(|| {
                    format!(
                        "Can not add directory: '{}' to the archive",
                        entry_path.display()
                    )
                })?;
            } else if entry_path.is_file() {
                let mut file = File::open(entry_path.clone())?;
                tar.append_file(entry, &mut file).with_context(|| {
                    format!(
                        "Can not add file: '{}' to the archive",
                        entry_path.display()
                    )
                })?;
            } else {
                return Err(anyhow!(
                    "The entry: '{}' is not valid",
                    entry_path.display()
                ));
            }
        }
        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        let full_entries_path = self
            .entries
            .iter()
            .map(|entry| self.base_directory.join(entry))
            .collect();
        file_size::compute_size(full_entries_path)
    }
}

/// Append data to the archive.
pub struct AppenderData {
    /// Location of the file in the archive where the data will be appended.
    location_in_archive: PathBuf,
    /// Byte array of the data to append.
    bytes: Vec<u8>,
}

impl AppenderData {
    /// Timestamp arbitrarily chosen to `2026-01-01 00:00:00 UTC`
    /// IMPORTANT: Do NOT change it, else the `AppenderData` archives bytes would change.
    const FIXED_MTIME_ATTRIBUTE: u64 = 1767225600;

    /// Create a new instance of `AppenderData` from an object that will be serialized to JSON.
    pub fn from_json<T: Serialize + Send>(
        location_in_archive: PathBuf,
        object: &T,
    ) -> StdResult<Self> {
        let json_bytes = serde_json::to_vec(object).with_context(|| {
            format!(
                "Can not serialize JSON to file in archive: {:?}",
                location_in_archive.display()
            )
        })?;

        Ok(Self::from_raw_bytes(location_in_archive, json_bytes))
    }

    /// Create a new instance of `AppenderData` from a byte array.
    pub fn from_raw_bytes(location_in_archive: PathBuf, bytes: Vec<u8>) -> Self {
        Self {
            location_in_archive,
            bytes,
        }
    }
}

impl TarAppender for AppenderData {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(self.bytes.len() as u64);
        header.set_mode(READ_WRITE_PERMISSION);
        header.set_mtime(Self::FIXED_MTIME_ATTRIBUTE);
        header.set_cksum();

        tar.append_data(
            &mut header,
            &self.location_in_archive,
            self.bytes.as_slice(),
        )
        .with_context(|| {
            format!(
                "Can not add file: '{}' to the archive",
                self.location_in_archive.display()
            )
        })?;

        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        Ok(self.bytes.len() as u64)
    }
}

/// Chain multiple `TarAppender` instances together.
pub struct ChainAppender<L, R> {
    appender_left: L,
    appender_right: R,
}

impl<L: TarAppender, R: TarAppender> ChainAppender<L, R> {
    pub fn new(appender_left: L, appender_right: R) -> Self {
        Self {
            appender_left,
            appender_right,
        }
    }
}

impl<L: TarAppender, R: TarAppender> TarAppender for ChainAppender<L, R> {
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        self.appender_left.append(tar)?;
        self.appender_right.append(tar)
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        // Size is aggregated even if the data is overwritten by the right appender because we
        // can't know if there is an overlap or not
        Ok(self.appender_left.compute_uncompressed_data_size()?
            + self.appender_right.compute_uncompressed_data_size()?)
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_internal_database::test::DummyCardanoDbBuilder;
    use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, LEDGER_DIR, VOLATILE_DIR};
    use mithril_common::entities::CompressionAlgorithm;
    use mithril_common::{assert_dir_eq, temp_dir_create};

    use crate::tools::file_archiver::test_tools::*;
    use crate::tools::file_archiver::{ArchiveParameters, FileArchiver};

    use super::*;

    mod appender_entries {
        use super::*;

        #[test]
        fn create_archive_only_for_specified_directories_and_files() {
            let test_dir = temp_dir_create!();
            let source = test_dir.join(create_dir(&test_dir, "source"));

            let directory_to_archive_path = create_dir(&source, "directory_to_archive");
            let file_in_dir_to_archive_path =
                create_file(&source, "directory_to_archive/file_in_dir_to_archive.txt");
            let file_to_archive_path = create_file(&source, "file_to_archive.txt");
            let empty_directory_to_archive_path = create_dir(&source, "empty_directory_to_archive");

            create_dir(&source, "directory_not_to_archive");
            create_file(&source, "file_not_to_archive.txt");
            create_file(
                &source,
                "directory_to_archive/file_in_dir_not_to_archive.txt",
            );

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    AppenderEntries::new(
                        vec![
                            directory_to_archive_path,
                            file_in_dir_to_archive_path,
                            file_to_archive_path,
                            empty_directory_to_archive_path,
                        ],
                        source,
                    )
                    .unwrap(),
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);

            assert_dir_eq!(
                &unpack_path,
                "* directory_to_archive/
                 ** file_in_dir_to_archive.txt
                 * empty_directory_to_archive/
                 * file_to_archive.txt"
            );
        }

        #[test]
        fn return_error_when_appending_file_or_directory_that_does_not_exist() {
            let test_dir = temp_dir_create!();
            let target_archive = test_dir.join("whatever.tar.zst");
            let source = test_dir.join(create_dir(&test_dir, "source"));

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

            file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    AppenderEntries::new(vec![PathBuf::from("not_exist")], source).unwrap(),
                )
                .expect_err("AppenderEntries should return error when file or directory not exist");
            assert!(!target_archive.exists());
        }

        #[test]
        fn return_error_when_appending_empty_entries() {
            let appender_creation_result = AppenderEntries::new(vec![], PathBuf::new());
            assert!(appender_creation_result.is_err(),);
        }

        #[test]
        fn can_append_duplicate_files_and_directories() {
            let test_dir = temp_dir_create!();
            let source = test_dir.join(create_dir(&test_dir, "source"));

            let directory_to_archive_path = create_dir(&source, "directory_to_archive");
            let file_to_archive_path =
                create_file(&source, "directory_to_archive/file_to_archive.txt");

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));

            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    AppenderEntries::new(
                        vec![
                            directory_to_archive_path.clone(),
                            directory_to_archive_path.clone(),
                            file_to_archive_path.clone(),
                            file_to_archive_path.clone(),
                        ],
                        source,
                    )
                    .unwrap(),
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);

            assert_dir_eq!(
                &unpack_path,
                "* directory_to_archive/
                 ** file_to_archive.txt"
            );
        }

        #[test]
        fn compute_uncompressed_size_of_its_paths() {
            let test_dir = "compute_uncompressed_size_of_its_paths";

            let immutable_trio_file_size = 777;
            let ledger_file_size = 6666;
            let volatile_file_size = 99;

            let cardano_db = DummyCardanoDbBuilder::new(test_dir)
                .with_immutables(&[1, 2, 3])
                .set_immutable_trio_file_size(immutable_trio_file_size)
                .with_legacy_ledger_snapshots(&[437, 537, 637, 737])
                .set_ledger_file_size(ledger_file_size)
                .with_volatile_files(&["blocks-0.dat", "blocks-1.dat", "blocks-2.dat"])
                .set_volatile_file_size(volatile_file_size)
                .build();

            let appender_entries = AppenderEntries::new(
                vec![
                    PathBuf::from(IMMUTABLE_DIR),
                    PathBuf::from(LEDGER_DIR).join("437"),
                    PathBuf::from(LEDGER_DIR).join("537"),
                    PathBuf::from(VOLATILE_DIR).join("blocks-0.dat"),
                ],
                cardano_db.get_dir().clone(),
            )
            .unwrap();

            let entries_size = appender_entries.compute_uncompressed_data_size().unwrap();
            let expected_total_size =
                (immutable_trio_file_size * 3) + (2 * ledger_file_size) + volatile_file_size;
            assert_eq!(expected_total_size, entries_size);
        }
    }

    mod appender_file {
        use super::*;

        #[test]
        fn appending_file_to_tar() {
            let test_dir = temp_dir_create!();
            let file_to_archive = create_file(&test_dir, "test_file.txt");

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));
            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    AppenderFile::append_at_archive_root(test_dir.join(&file_to_archive)).unwrap(),
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);

            assert!(unpack_path.join(file_to_archive).exists());
        }

        #[test]
        fn return_error_if_file_does_not_exist() {
            let target_file_path = PathBuf::from("non_existent_file.txt");
            assert!(AppenderFile::append_at_archive_root(target_file_path).is_err());
        }

        #[test]
        fn return_error_if_input_is_not_a_file() {
            let test_dir = temp_dir_create!();
            assert!(AppenderFile::append_at_archive_root(test_dir).is_err());
        }

        #[test]
        fn compute_uncompressed_size() {
            let test_dir = temp_dir_create!();

            let file_path = test_dir.join("file.txt");
            let file = File::create(&file_path).unwrap();
            file.set_len(777).unwrap();

            let appender_file = AppenderFile::append_at_archive_root(file_path).unwrap();

            let entries_size = appender_file.compute_uncompressed_data_size().unwrap();
            assert_eq!(777, entries_size);
        }
    }

    mod appender_dir_all {
        use super::*;

        #[test]
        fn compute_uncompressed_size() {
            let test_dir = "appender_dir_all_compute_size";

            let immutable_trio_file_size = 777;
            let ledger_file_size = 6666;
            let volatile_file_size = 99;

            let cardano_db = DummyCardanoDbBuilder::new(test_dir)
                .with_immutables(&[1, 2])
                .set_immutable_trio_file_size(immutable_trio_file_size)
                .with_legacy_ledger_snapshots(&[437, 537, 637])
                .set_ledger_file_size(ledger_file_size)
                .with_volatile_files(&["blocks-0.dat"])
                .set_volatile_file_size(volatile_file_size)
                .build();

            let appender_dir_all = AppenderDirAll::new(cardano_db.get_dir().clone());

            let entries_size = appender_dir_all.compute_uncompressed_data_size().unwrap();
            let expected_total_size =
                (immutable_trio_file_size * 2) + (3 * ledger_file_size) + volatile_file_size;
            assert_eq!(expected_total_size, entries_size);
        }
    }

    mod appender_data {
        use serde::Deserialize;
        use zstd::Decoder;

        use super::*;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct TestStruct {
            field1: String,
            field2: i32,
        }

        #[test]
        fn append_serializable_json() {
            let test_dir = temp_dir_create!();
            let object = TestStruct {
                field1: "test".to_string(),
                field2: 42,
            };
            let location_in_archive = PathBuf::from("folder").join("test.json");

            let data_appender =
                AppenderData::from_json(location_in_archive.clone(), &object).unwrap();
            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));
            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    data_appender,
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);
            let unpacked_file_path = unpack_path.join(&location_in_archive);

            assert!(unpacked_file_path.exists());

            let deserialized_object: TestStruct =
                serde_json::from_reader(File::open(unpacked_file_path).unwrap()).unwrap();
            assert_eq!(object, deserialized_object);
        }

        #[test]
        fn appended_entry_have_read_write_permissions_and_fixed_time_metadata() {
            let test_dir = temp_dir_create!();
            let object = TestStruct {
                field1: "test".to_string(),
                field2: 42,
            };
            let location_in_archive = PathBuf::from("folder").join("test.json");

            let data_appender =
                AppenderData::from_json(location_in_archive.clone(), &object).unwrap();
            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));
            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    data_appender,
                )
                .unwrap();

            let archive_file = File::open(archive.get_file_path()).unwrap();
            let mut archive = tar::Archive::new(Decoder::new(archive_file).unwrap());
            let mut archive_entries = archive.entries().unwrap();
            let appended_entry = archive_entries.next().unwrap().unwrap();

            assert_eq!(
                READ_WRITE_PERMISSION,
                appended_entry.header().mode().unwrap()
            );
            let mtime = appended_entry.header().mtime().unwrap();
            assert_eq!(AppenderData::FIXED_MTIME_ATTRIBUTE, mtime);
        }

        #[test]
        fn compute_uncompressed_size() {
            let object = TestStruct {
                field1: "test".to_string(),
                field2: 42,
            };

            let data_appender =
                AppenderData::from_json(PathBuf::from("whatever.json"), &object).unwrap();

            let expected_size = serde_json::to_vec(&object).unwrap().len() as u64;
            let entry_size = data_appender.compute_uncompressed_data_size().unwrap();
            assert_eq!(expected_size, entry_size);
        }
    }

    mod chain_appender {
        use super::*;

        #[test]
        fn chain_non_overlapping_appenders() {
            let test_dir = temp_dir_create!();
            let file_to_archive = create_file(&test_dir, "test_file.txt");
            let json_location_in_archive = PathBuf::from("folder").join("test.json");

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));
            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    ChainAppender::new(
                        AppenderFile::append_at_archive_root(test_dir.join(&file_to_archive))
                            .unwrap(),
                        AppenderData::from_json(json_location_in_archive.clone(), &"test").unwrap(),
                    ),
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);

            assert!(unpack_path.join(file_to_archive).exists());
            assert!(unpack_path.join(json_location_in_archive).exists());
        }

        #[test]
        fn chain_overlapping_appenders_data_from_right_appender_overwrite_left_appender_data() {
            let test_dir = temp_dir_create!();
            let json_location_in_archive = PathBuf::from("test.json");

            let file_archiver = FileArchiver::new_for_test(test_dir.join("verification"));
            let archive = file_archiver
                .archive(
                    ArchiveParameters {
                        archive_name_without_extension: "archive".to_string(),
                        target_directory: test_dir.clone(),
                        compression_algorithm: CompressionAlgorithm::Zstandard,
                    },
                    ChainAppender::new(
                        AppenderData::from_json(
                            json_location_in_archive.clone(),
                            &"will be overwritten",
                        )
                        .unwrap(),
                        AppenderData::from_json(json_location_in_archive.clone(), &"test").unwrap(),
                    ),
                )
                .unwrap();

            let unpack_path = archive.unpack_zstandard(&test_dir);
            let unpacked_json_path = unpack_path.join(&json_location_in_archive);

            let deserialized_object: String =
                serde_json::from_reader(File::open(&unpacked_json_path).unwrap()).unwrap();
            assert_eq!("test", deserialized_object);
        }

        #[test]
        fn compute_non_overlapping_uncompressed_size() {
            let left_appender =
                AppenderData::from_json(PathBuf::from("whatever1.json"), &"foo").unwrap();
            let right_appender =
                AppenderData::from_json(PathBuf::from("whatever2.json"), &"bar").unwrap();

            let expected_size = left_appender.compute_uncompressed_data_size().unwrap()
                + right_appender.compute_uncompressed_data_size().unwrap();

            let chain_appender = left_appender.chain(right_appender);
            let size = chain_appender.compute_uncompressed_data_size().unwrap();
            assert_eq!(expected_size, size);
        }

        #[test]
        fn compute_uncompressed_size_cant_discriminate_overlaps_and_return_aggregated_appenders_sizes()
         {
            let overlapping_path = PathBuf::from("whatever.json");
            let left_appender =
                AppenderData::from_json(overlapping_path.clone(), &"overwritten data").unwrap();
            let right_appender =
                AppenderData::from_json(overlapping_path.clone(), &"final data").unwrap();

            let expected_size = left_appender.compute_uncompressed_data_size().unwrap()
                + right_appender.compute_uncompressed_data_size().unwrap();

            let chain_appender = left_appender.chain(right_appender);
            let size = chain_appender.compute_uncompressed_data_size().unwrap();
            assert_eq!(expected_size, size);
        }
    }
}
