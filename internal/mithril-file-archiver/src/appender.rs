//! Define how to append data to a [crate::FileArchiver]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use serde::Serialize;

use mithril_common::StdResult;

use crate::tools::file_size;

const READ_WRITE_PERMISSION: u32 = 0o666;
/// Timestamp arbitrarily chosen to `2026-01-01 00:00:00 UTC`
/// IMPORTANT: Do NOT change it, else the `AppenderData` archives bytes would change.
const FIXED_MTIME_ATTRIBUTE_FOR_DATA: u64 = 1767225600;

/// Define multiple ways to append content to a tar archive.
pub trait TarAppender: Send {
    /// Appends the contents of the current object to the given tar archive builder.
    fn append<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()>;

    /// Computes the total uncompressed size of the data that will be added to the archive.
    fn compute_uncompressed_data_size(&self) -> StdResult<u64>;

    /// Chains this appender with another, combining their contents into a single archive.
    fn chain<A2: TarAppender>(self, appender_right: A2) -> ChainAppender<Self, A2>
    where
        Self: Sized,
    {
        ChainAppender::new(self, appender_right)
    }
}

/// Represents an object that can provide a list of entries to append to a tar archive.
pub trait ArchiveEntryProvider: Send {
    /// Get the list of archive entries held by this provider.
    fn collect_entries(&self) -> StdResult<BTreeSet<ArchiveEntry>>;
}

impl<T: ArchiveEntryProvider> TarAppender for T {
    fn append<W: Write>(&self, tar: &mut tar::Builder<W>) -> StdResult<()> {
        for entry in self
            .collect_entries()
            .with_context(|| "Failed to collect entries from appender")?
        {
            entry.append_to_archive(tar)?;
        }
        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        let mut size: u64 = 0;
        for entry in self
            .collect_entries()
            .with_context(|| "Failed to collect entries from appender")?
        {
            size = size
                .checked_add(entry.compute_uncompressed_data_size()?)
                .with_context(|| "Failed to compute uncompressed data size")?;
        }
        Ok(size)
    }
}

/// Represents an entry to be added to a tar archive.
///
/// Archive entries are identified and ordered solely by their normalized archive path.
/// Content and source fields do not participate in equality.
#[derive(Debug, Clone)]
pub enum ArchiveEntry {
    /// A file entry.
    File {
        /// Path of the file in the archive.
        location_in_archive: PathBuf,
        /// Path to the source file on disk.
        target_file: PathBuf,
    },
    /// A directory entry.
    Directory {
        /// Path of the directory in the archive.
        location_in_archive: PathBuf,
        /// Path to the source directory on disk.
        target_dir: PathBuf,
    },
    /// Raw data entry.
    Data {
        /// Path of the data in the archive.
        location_in_archive: PathBuf,
        /// The data bytes.
        data: Arc<Vec<u8>>,
    },
}

impl ArchiveEntry {
    /// Creates a directory entry.
    pub fn from_dir(location_in_archive: PathBuf, target_dir: PathBuf) -> Self {
        ArchiveEntry::Directory {
            location_in_archive: Self::normalize_entry(location_in_archive),
            target_dir,
        }
    }

    /// Creates a file entry.
    pub fn from_file(location_in_archive: PathBuf, target_file: PathBuf) -> Self {
        ArchiveEntry::File {
            location_in_archive: Self::normalize_entry(location_in_archive),
            target_file,
        }
    }

    /// Creates a data entry.
    pub fn from_data(location_in_archive: PathBuf, data: Vec<u8>) -> Self {
        ArchiveEntry::Data {
            location_in_archive: Self::normalize_entry(location_in_archive),
            data: Arc::new(data),
        }
    }

    /// Returns the location of this entry in the archive.
    pub fn location_in_archive(&self) -> &Path {
        match self {
            ArchiveEntry::File {
                location_in_archive,
                ..
            } => location_in_archive,
            ArchiveEntry::Directory {
                location_in_archive,
                ..
            } => location_in_archive,
            ArchiveEntry::Data {
                location_in_archive,
                ..
            } => location_in_archive,
        }
    }

    /// Appends this entry to the given tar archive builder.
    pub fn append_to_archive<T: Write>(&self, tar: &mut tar::Builder<T>) -> StdResult<()> {
        match self {
            ArchiveEntry::File {
                location_in_archive,
                target_file,
            } => {
                if !target_file.is_file() {
                    anyhow::bail!(
                        "File '{}' does not exist, can not add it to the archive at '{}'",
                        target_file.display(),
                        location_in_archive.display()
                    );
                }

                let mut file = File::open(target_file)?;
                tar.append_file(location_in_archive, &mut file).with_context(|| {
                    format!(
                        "Can not add file: '{}' to the archive",
                        target_file.display()
                    )
                })?;
            }
            ArchiveEntry::Directory {
                location_in_archive,
                target_dir,
            } => {
                if !target_dir.is_dir() {
                    anyhow::bail!(
                        "Directory '{}' does not exist, can not add it to the archive at '{}'",
                        target_dir.display(),
                        location_in_archive.display()
                    );
                }

                tar.append_dir(location_in_archive, target_dir).with_context(|| {
                    format!(
                        "Can not add directory: '{}' to the archive",
                        location_in_archive.display()
                    )
                })?;
            }
            ArchiveEntry::Data {
                location_in_archive,
                data,
            } => {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(READ_WRITE_PERMISSION);
                header.set_mtime(FIXED_MTIME_ATTRIBUTE_FOR_DATA);
                header.set_cksum();

                tar.append_data(&mut header, location_in_archive, data.as_slice())
                    .with_context(|| {
                        format!(
                            "Can not add file: '{}' to the archive",
                            location_in_archive.display()
                        )
                    })?;
            }
        }

        Ok(())
    }

    fn compute_uncompressed_data_size(&self) -> StdResult<u64> {
        match self {
            ArchiveEntry::File { target_file, .. } => file_size::compute_size_of_path(target_file),
            ArchiveEntry::Directory { .. } => Ok(0),
            ArchiveEntry::Data { data, .. } => Ok(data.len() as u64),
        }
    }

    fn normalize_entry(entry: PathBuf) -> PathBuf {
        entry
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .collect()
    }
}

impl Ord for ArchiveEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.location_in_archive().cmp(other.location_in_archive())
    }
}

impl PartialOrd for ArchiveEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<Self> for ArchiveEntry {
    fn eq(&self, other: &Self) -> bool {
        self.location_in_archive() == other.location_in_archive()
    }
}

impl Eq for ArchiveEntry {}

/// An appender that adds one file.
pub struct AppenderFile {
    entry: ArchiveEntry,
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
            entry: ArchiveEntry::from_file(PathBuf::from(location_in_archive), target_file),
        })
    }
}

impl ArchiveEntryProvider for AppenderFile {
    fn collect_entries(&self) -> StdResult<BTreeSet<ArchiveEntry>> {
        Ok(BTreeSet::from([self.entry.clone()]))
    }
}

/// An appender that adds a list of entries, files, or directories.
///
/// Directory contents are not added if not specified.
pub struct AppenderEntries {
    entries: BTreeSet<ArchiveEntry>,
}

impl AppenderEntries {
    /// Create a new instance of `AppenderEntries`.
    ///
    /// Entries are normalized and sorted to ensure deterministic archive output.
    ///
    /// Returns an error if the `entries` are empty.
    pub fn new(entries: Vec<PathBuf>, base_directory: PathBuf) -> StdResult<Self> {
        if entries.is_empty() {
            return Err(anyhow!("The entries can not be empty"));
        }

        let mut archive_entries: BTreeSet<ArchiveEntry> = BTreeSet::new();

        for entry in entries {
            let entry_path = base_directory.join(&entry);
            if entry_path.is_dir() {
                archive_entries.insert(ArchiveEntry::from_dir(entry, entry_path));
            } else if entry_path.is_file() {
                archive_entries.insert(ArchiveEntry::from_file(entry, entry_path));
            } else {
                anyhow::bail!("The entry: '{}' is not valid", entry_path.display());
            }
        }

        Ok(Self {
            entries: archive_entries,
        })
    }
}

impl ArchiveEntryProvider for AppenderEntries {
    fn collect_entries(&self) -> StdResult<BTreeSet<ArchiveEntry>> {
        Ok(self.entries.clone())
    }
}

/// An appender that adds either [serde::Serialize] serializable data or raw bytes.
pub struct AppenderData {
    entry: ArchiveEntry,
}

impl AppenderData {
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
            entry: ArchiveEntry::from_data(location_in_archive, bytes),
        }
    }
}

impl ArchiveEntryProvider for AppenderData {
    fn collect_entries(&self) -> StdResult<BTreeSet<ArchiveEntry>> {
        Ok(BTreeSet::from([self.entry.clone()]))
    }
}

/// Chain multiple `TarAppender` instances together.
pub struct ChainAppender<L, R> {
    appender_left: L,
    appender_right: R,
}

impl<L: TarAppender, R: TarAppender> ChainAppender<L, R> {
    /// [ChainAppender] factory
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
    use mithril_common::entities::CompressionAlgorithm;
    use mithril_common::{assert_dir_eq, temp_dir_create};

    use crate::api::FileArchiver;
    use crate::entities::ArchiveParameters;
    use crate::test::{FileArchiveTestExtension, create_dir, create_file};

    use super::*;

    mod archive_entry {
        use super::*;

        #[test]
        fn removes_trailing_separator_from_directory_component() {
            assert_eq!(
                PathBuf::from("foo"),
                ArchiveEntry::normalize_entry(PathBuf::from("foo/")),
            );
        }

        #[cfg(windows)]
        #[test]
        fn removes_windows_trailing_separator_from_directory_component() {
            assert_eq!(
                PathBuf::from("foo"),
                ArchiveEntry::normalize_entry(PathBuf::from("foo\\")),
            );
        }

        #[test]
        fn removes_leading_current_directory_component() {
            assert_eq!(
                PathBuf::from("foo/bar.txt"),
                ArchiveEntry::normalize_entry(PathBuf::from("./foo/bar.txt")),
            );
        }

        #[cfg(windows)]
        #[test]
        fn removes_windows_leading_current_directory_component() {
            assert_eq!(
                PathBuf::from("foo").join("bar.txt"),
                ArchiveEntry::normalize_entry(PathBuf::from(r".\foo\bar.txt")),
            );
        }

        #[cfg(windows)]
        #[test]
        fn forward_and_backward_separators_have_the_same_normalized_path() {
            assert_eq!(
                ArchiveEntry::normalize_entry(PathBuf::from("foo/bar.txt")),
                ArchiveEntry::normalize_entry(PathBuf::from(r"foo\bar.txt")),
            );
        }

        #[test]
        fn entries_are_sorted_by_path() {
            let mut entries = [
                ArchiveEntry::from_file(PathBuf::from("foo/bar.txt"), PathBuf::new()),
                ArchiveEntry::from_file(PathBuf::from("file_2.txt"), PathBuf::new()),
                ArchiveEntry::from_dir(PathBuf::from("bar/"), PathBuf::new()),
                ArchiveEntry::from_dir(PathBuf::from("foo/"), PathBuf::new()),
                ArchiveEntry::from_file(PathBuf::from("foo/pika/"), PathBuf::new()),
                ArchiveEntry::from_file(PathBuf::from("foo/pika/chuu.txt"), PathBuf::new()),
                ArchiveEntry::from_file(PathBuf::from("file_1.txt"), PathBuf::new()),
            ];
            entries.sort();

            assert_eq!(
                vec![
                    PathBuf::from("bar"),
                    PathBuf::from("file_1.txt"),
                    PathBuf::from("file_2.txt"),
                    PathBuf::from("foo"),
                    PathBuf::from("foo/bar.txt"),
                    PathBuf::from("foo/pika"),
                    PathBuf::from("foo/pika/chuu.txt"),
                ],
                entries
                    .into_iter()
                    .map(|entry| entry.location_in_archive().to_path_buf())
                    .collect::<Vec<_>>()
            );
        }

        #[cfg(windows)]
        #[test]
        fn entries_with_windows_path_are_sorted_by_path() {
            let mut entries = [
                ArchiveEntry::from_file(PathBuf::from(r"foo\pika\chuu.txt"), PathBuf::new()),
                ArchiveEntry::from_file(PathBuf::from(r"foo\bar.txt"), PathBuf::new()),
                ArchiveEntry::from_dir(PathBuf::from(r"bar\\"), PathBuf::new()),
                ArchiveEntry::from_dir(PathBuf::from(r"foo\\"), PathBuf::new()),
            ];
            entries.sort();

            assert_eq!(
                vec![
                    PathBuf::from("bar"),
                    PathBuf::from("foo"),
                    PathBuf::from("foo").join("bar.txt"),
                    PathBuf::from("foo").join("pika").join("chuu.txt"),
                ],
                entries
                    .into_iter()
                    .map(|entry| entry.location_in_archive().to_path_buf())
                    .collect::<Vec<_>>()
            );
        }

        #[test]
        fn appending_fails_if_source_file_does_not_exist() {
            let entry =
                ArchiveEntry::from_file(PathBuf::from("foo.txt"), PathBuf::from("not_exist.txt"));
            let mut tar = tar::Builder::new(Vec::new());

            let res = entry.append_to_archive(&mut tar);
            assert!(res.is_err());
        }

        #[test]
        fn appending_fails_if_source_dir_does_not_exist() {
            let entry = ArchiveEntry::from_dir(PathBuf::from("foo/"), PathBuf::from("not_exist/"));
            let mut tar = tar::Builder::new(Vec::new());

            let res = entry.append_to_archive(&mut tar);
            assert!(res.is_err());
        }

        #[test]
        fn entries_with_the_same_archive_path_but_different_content_are_considered_equal() {
            assert_eq!(
                ArchiveEntry::from_data(PathBuf::from("foo.txt"), vec![0, 1, 2]),
                ArchiveEntry::from_data(PathBuf::from("foo.txt"), vec![3, 4, 5]),
            );

            assert_eq!(
                ArchiveEntry::from_file(PathBuf::from("foo.txt"), PathBuf::from("file.txt")),
                ArchiveEntry::from_file(PathBuf::from("foo.txt"), PathBuf::from("other.txt"))
            );
        }
    }

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
        fn creation_fails_when_entry_does_not_exist() {
            let test_dir = temp_dir_create!();
            let res = AppenderEntries::new(vec![PathBuf::from("not_exist")], test_dir);

            assert!(
                res.is_err(),
                "AppenderEntries should return error when file or directory not exist"
            );
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
            fn create_file_with_len(path: &Path, len: u64) {
                let file = File::create(path)
                    .unwrap_or_else(|_| panic!("failed to create '{}'", path.display()));
                file.set_len(len).unwrap();
            }

            let test_dir = temp_dir_create!();
            let source = test_dir.join(create_dir(&test_dir, "source"));
            let subdir = source.join(create_dir(&source, "subdir"));
            create_file_with_len(&source.join("file_1"), 100);
            create_file_with_len(&source.join("file_2"), 200);
            create_file_with_len(&subdir.join("file_3"), 300);
            create_file_with_len(&subdir.join("file_not_to_include"), 400);

            let appender_entries = AppenderEntries::new(
                vec![
                    PathBuf::from("file_1"),
                    PathBuf::from("file_2"),
                    PathBuf::from("subdir/"),
                    PathBuf::from("subdir/file_3"),
                ],
                source,
            )
            .unwrap();

            let entries_size = appender_entries.compute_uncompressed_data_size().unwrap();
            assert_eq!(600, entries_size);
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
            assert_eq!(FIXED_MTIME_ATTRIBUTE_FOR_DATA, mtime);
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
