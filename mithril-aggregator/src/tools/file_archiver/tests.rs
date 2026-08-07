use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use mithril_common::entities::CompressionAlgorithm;
use mithril_common::temp_dir_create;

use crate::ZstandardCompressionParameters;
use crate::test::TestLogger;
use crate::tools::file_archiver::{ArchiveParameters, FileArchiver, appender::*};

mod helpers {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    use super::*;

    /// Assert that two archive files contain exactly the same bytes.
    ///
    /// SHA-256 hashes and file sizes are reported when they differ.
    macro_rules! assert_archives_are_byte_identical {
        ($expected_path:expr, $actual_path:expr $(,)?) => {{
            use sha2::{Digest as _, Sha256};

            let expected_path_value = $expected_path;
            let actual_path_value = $actual_path;
            let expected_path: &std::path::Path =
                std::convert::AsRef::<std::path::Path>::as_ref(&expected_path_value);
            let actual_path: &std::path::Path =
                std::convert::AsRef::<std::path::Path>::as_ref(&actual_path_value);

            let expected_bytes = std::fs::read(expected_path).unwrap_or_else(|error| {
                panic!(
                    "Could not read expected archive '{}': {error}",
                    expected_path.display()
                )
            });
            let actual_bytes = std::fs::read(actual_path).unwrap_or_else(|error| {
                panic!(
                    "Could not read actual archive '{}': {error}",
                    actual_path.display()
                )
            });

            if expected_bytes != actual_bytes {
                let expected_hash = hex::encode(Sha256::digest(&expected_bytes));
                let actual_hash = hex::encode(Sha256::digest(&actual_bytes));

                panic!(
                    "Archives are not byte-identical:\n\
                     expected: '{}' ({} bytes, SHA-256: {})\n\
                     actual:   '{}' ({} bytes, SHA-256: {})",
                    expected_path.display(),
                    expected_bytes.len(),
                    expected_hash,
                    actual_path.display(),
                    actual_bytes.len(),
                    actual_hash,
                );
            }
        }};
    }
    pub(crate) use assert_archives_are_byte_identical;

    pub fn file_archiver(work_dir: &Path) -> FileArchiver {
        FileArchiver::new(
            ZstandardCompressionParameters::default(),
            create_dir_if_not_exist(&work_dir, "verification"),
            TestLogger::stdout(),
        )
    }

    pub fn create_dir_if_not_exist(base_dir: &Path, dir_name: &str) -> PathBuf {
        let dir_path = base_dir.join(dir_name);
        if !dir_path.exists() {
            std::fs::create_dir(&dir_path).unwrap();
        }
        dir_path
    }

    pub fn create_dir(base_dir: &Path, dir_name: &str) -> PathBuf {
        let dir_path = base_dir.join(dir_name);
        std::fs::create_dir(&dir_path).unwrap();
        dir_path
    }

    pub fn archive_parameters(filename: &str, target_dir: &Path) -> ArchiveParameters {
        ArchiveParameters {
            archive_name_without_extension: filename.to_string(),
            target_directory: target_dir.to_path_buf(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        }
    }

    pub fn compute_sha256_hash(path: &Path) -> String {
        let mut hasher = Sha256::new();

        if path.is_file() {
            hash_file(path, &mut hasher);
        } else if path.is_dir() {
            hash_dir(path, path, &mut hasher);
        } else {
            panic!(
                "Path is neither a file nor a directory: {:?}",
                path.display()
            );
        }

        hex::encode(hasher.finalize())
    }

    fn hash_file(path: &Path, hasher: &mut Sha256) {
        let mut file = File::open(path).unwrap();
        let mut buffer = [0; 64 * 1024];

        loop {
            let bytes_read = file.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }
    }

    fn hash_dir(root_dir: &Path, current_dir: &Path, hasher: &mut Sha256) {
        let mut entries = std::fs::read_dir(current_dir)
            .unwrap()
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<PathBuf>, std::io::Error>>()
            .unwrap();

        // Required: Sort entries by name to ensure consistent hashing.
        entries.sort();

        for entry_path in entries {
            let relative_path = entry_path.strip_prefix(root_dir).unwrap();

            hasher.update(
                relative_path
                    .to_str()
                    .expect("relative path is not valid UTF-8")
                    .as_bytes(),
            );

            if entry_path.is_file() {
                hasher.update(b"file");
                hash_file(&entry_path, hasher);
            } else if entry_path.is_dir() {
                hasher.update(b"dir");
                hash_dir(root_dir, &entry_path, hasher);
            }
        }
    }
}

/// Fixed test data set for file archiver tests.
mod test_data {
    use serde::{Deserialize, Serialize};
    use std::io::Write;

    use super::*;

    pub const TAR_ZSTD_V1_TEST_FILE_SHA256: &str =
        "b3e2f6954eff424f3f1a49b043a9db022595ee2033cad61a0c551b7e693c4049";
    pub const TAR_ZSTD_V1_TEST_DIRECTORY_SHA256: &str =
        "821d1c1af5d1733e2dc184ce06d6d2ee5549306384198314b65a0b5a3ed01ed4";
    pub const TAR_ZSTD_V1_TEST_DATA_SHA256: &str =
        "ec9bc01899252338cb807407af0e0c3acfe7f0ea7e39b8d506bdde217b0919c9";
    pub const TAR_ZSTD_V1_TEST_RAW_BYTES_SHA256: &str =
        "ec9bc01899252338cb807407af0e0c3acfe7f0ea7e39b8d506bdde217b0919c9";

    pub const TEST_BYTES: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct TestStruct {
        field_str: String,
        field_int: i32,
        // Important note: using BTreeMap to ensure deterministic serialization, types like HashMap should
        // not be used as the key order is not guaranteed
        field_map: BTreeMap<String, String>,
    }

    impl Default for TestStruct {
        fn default() -> Self {
            Self {
                field_str: "test".to_string(),
                field_int: 42,
                field_map: BTreeMap::from([
                    ("key_3".to_string(), "value_3".to_string()),
                    ("key_1".to_string(), "value_1".to_string()),
                    ("key_2".to_string(), "value_2".to_string()),
                ]),
            }
        }
    }

    /// Create a file named `test.txt` in the given directory
    pub fn create_test_txt(root_dir: &Path) -> PathBuf {
        create_test_file(root_dir, "test.txt")
    }

    /// Create a directory named `test_dir` in the given directory
    ///
    /// It will be filled with the following structure:
    /// ```no_run
    /// test_dir/
    /// ├── foo/
    /// │   └── bar.txt
    /// ├── file_1.txt
    /// └── file_2.txt
    /// ```
    pub fn create_test_dir(root_dir: &Path) -> PathBuf {
        let test_dir = root_dir.join(Path::new("test_dir"));
        std::fs::create_dir(&test_dir).unwrap();

        let foo_dir = test_dir.join("foo");
        std::fs::create_dir(&foo_dir).unwrap();
        create_test_file(&foo_dir, "bar.txt");

        create_test_file(&test_dir, "file_1.txt");
        create_test_file(&test_dir, "file_2.txt");

        test_dir
    }

    fn create_test_file(root_dir: &Path, file_name: &str) -> PathBuf {
        let path = root_dir.join(file_name);
        let mut file = File::create(&path).unwrap();

        write!(file, "This is a test file named '{file_name}'").unwrap();
        writeln!(file).unwrap();

        path
    }
}

mod reproducibility {
    use std::time::{Duration, SystemTime};

    use super::*;

    #[test]
    #[should_panic(expected = "Archives are not byte-identical")]
    fn changing_one_byte_change_archives_bytes() {
        let test_dir = temp_dir_create!();
        let content = test_data::TEST_BYTES.to_vec();
        let altered_content = {
            let mut altered_content = content.clone();
            altered_content[0] = !altered_content[0];
            altered_content
        };

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_1", &test_dir),
                AppenderData::from_raw_bytes(PathBuf::from("bytes.txt"), content),
            )
            .unwrap();
        let altered_archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_2", &test_dir),
                AppenderData::from_raw_bytes(PathBuf::from("bytes.txt"), altered_content),
            )
            .unwrap();

        helpers::assert_archives_are_byte_identical!(&archive.filepath, &altered_archive.filepath);
    }

    #[test]
    fn same_source_file_archived_twice_at_different_time_produces_same_bytes() {
        let test_dir = temp_dir_create!();
        let content = test_data::create_test_txt(&test_dir);

        let archive_with_content_before_sleep = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_1", &test_dir),
                AppenderFile::append_at_archive_root(content.clone()).unwrap(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(1100));

        let archive_with_same_content_but_after_sleep = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_2", &test_dir),
                AppenderFile::append_at_archive_root(content).unwrap(),
            )
            .unwrap();

        helpers::assert_archives_are_byte_identical!(
            archive_with_content_before_sleep.filepath,
            archive_with_same_content_but_after_sleep.filepath
        );
    }

    #[test]
    fn archives_of_separate_files_with_identical_content_and_different_mtimes_produces_same_bytes()
    {
        let test_dir = temp_dir_create!();
        let subdir_1 = helpers::create_dir_if_not_exist(&test_dir, "dir_1");
        let subdir_2 = helpers::create_dir_if_not_exist(&test_dir, "dir_2");

        let original_content = test_data::create_test_txt(&subdir_1);
        let content_with_different_mtime = test_data::create_test_txt(&subdir_2);
        File::options()
            .write(true)
            .open(&content_with_different_mtime)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_millis(1100))
            .unwrap();

        // Ensure the two files has the same content
        helpers::assert_archives_are_byte_identical!(
            &original_content,
            &content_with_different_mtime
        );

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_1", &test_dir),
                AppenderFile::append_at_archive_root(original_content.clone()).unwrap(),
            )
            .unwrap();

        let archive_with_content_with_different_mtime = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test_2", &test_dir),
                AppenderFile::append_at_archive_root(content_with_different_mtime).unwrap(),
            )
            .unwrap();

        helpers::assert_archives_are_byte_identical!(
            archive.filepath,
            archive_with_content_with_different_mtime.filepath
        );
    }

    mod source_base_directory_does_not_affect_archive {
        use super::*;

        #[test]
        fn appender_file() {
            let test_dir = temp_dir_create!();
            let subdir_1 = helpers::create_dir_if_not_exist(&test_dir, "dir_1");
            let subdir_2 = helpers::create_dir_if_not_exist(&test_dir, "dir_2");

            let content = test_data::create_test_txt(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_txt(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_1", &test_dir),
                    AppenderFile::append_at_archive_root(content).unwrap(),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_2", &test_dir),
                    AppenderFile::append_at_archive_root(same_content_in_other_dir).unwrap(),
                )
                .unwrap();

            helpers::assert_archives_are_byte_identical!(
                &archive.filepath,
                &archive_with_same_content_but_from_another_dir.filepath
            );
        }

        #[test]
        fn appender_dir() {
            let test_dir = temp_dir_create!();
            let subdir_1 = helpers::create_dir_if_not_exist(&test_dir, "dir_1");
            let subdir_2 = helpers::create_dir_if_not_exist(&test_dir, "dir_2");

            let content = test_data::create_test_dir(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_dir(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_1", &test_dir),
                    AppenderDirAll::new(content),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_2", &test_dir),
                    AppenderDirAll::new(same_content_in_other_dir),
                )
                .unwrap();

            helpers::assert_archives_are_byte_identical!(
                &archive.filepath,
                &archive_with_same_content_but_from_another_dir.filepath
            );
        }

        #[test]
        fn appender_entries() {
            let test_dir = temp_dir_create!();
            let subdir_1 = helpers::create_dir_if_not_exist(&test_dir, "dir_1");
            let subdir_2 = helpers::create_dir_if_not_exist(&test_dir, "dir_2");

            let content = test_data::create_test_dir(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_dir(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_1", &test_dir),
                    AppenderEntries::new(
                        vec![
                            PathBuf::from("foo/"),
                            PathBuf::from("foo/bar.txt"),
                            PathBuf::from("file_1.txt"),
                        ],
                        content.clone(),
                    )
                    .unwrap(),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_2", &test_dir),
                    AppenderEntries::new(
                        vec![
                            PathBuf::from("foo/"),
                            PathBuf::from("foo/bar.txt"),
                            PathBuf::from("file_1.txt"),
                        ],
                        same_content_in_other_dir,
                    )
                    .unwrap(),
                )
                .unwrap();

            helpers::assert_archives_are_byte_identical!(
                &archive.filepath,
                &archive_with_same_content_but_from_another_dir.filepath
            );
        }
    }

    mod supplied_entry_order_does_not_affect_archive {
        use super::*;

        #[test]
        fn appender_entries() {
            let test_dir = temp_dir_create!();
            let content = test_data::create_test_dir(&test_dir);

            let reference_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("test_1", &test_dir),
                    AppenderEntries::new(
                        vec![
                            PathBuf::from("foo/"),
                            PathBuf::from("foo/bar.txt"),
                            PathBuf::from("file_1.txt"),
                            PathBuf::from("file_2.txt"),
                        ],
                        content.clone(),
                    )
                    .unwrap(),
                )
                .unwrap();

            for entries in [
                // reverse order
                vec![
                    PathBuf::from("file_2.txt"),
                    PathBuf::from("file_1.txt"),
                    PathBuf::from("foo/bar.txt"),
                    PathBuf::from("foo/"),
                ],
                // mixed order
                vec![
                    PathBuf::from("file_2.txt"),
                    PathBuf::from("foo/"),
                    PathBuf::from("file_1.txt"),
                    PathBuf::from("foo/bar.txt"),
                ],
            ] {
                let archive_with_same_content_but_different_entries_order =
                    helpers::file_archiver(&test_dir)
                        .archive(
                            helpers::archive_parameters("test_2", &test_dir),
                            AppenderEntries::new(entries, content.clone()).unwrap(),
                        )
                        .unwrap();

                helpers::assert_archives_are_byte_identical!(
                    &reference_archive.filepath,
                    &archive_with_same_content_but_different_entries_order.filepath
                );
            }
        }
    }
}

mod golden_master {
    use super::*;

    #[test]
    fn appender_data_from_json() {
        let test_dir = temp_dir_create!();
        let content = test_data::TestStruct::default();

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderData::from_json(PathBuf::from("test_data.json"), &content).unwrap(),
            )
            .unwrap();

        let sha256 = helpers::compute_sha256_hash(&archive.filepath);
        assert_eq!(sha256, test_data::TAR_ZSTD_V1_TEST_DATA_SHA256);
    }

    #[test]
    fn appender_data_from_raw_bytes() {
        let test_dir = temp_dir_create!();
        let content = test_data::TEST_BYTES.to_vec();

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderData::from_raw_bytes(PathBuf::from("bytes.txt"), content),
            )
            .unwrap();

        let sha256 = helpers::compute_sha256_hash(&archive.filepath);
        assert_eq!(sha256, test_data::TAR_ZSTD_V1_TEST_RAW_BYTES_SHA256);
    }

    #[test]
    fn appender_file() {
        let test_dir = temp_dir_create!();
        let content = test_data::create_test_txt(&test_dir);

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderFile::append_at_archive_root(content).unwrap(),
            )
            .unwrap();

        let sha256 = helpers::compute_sha256_hash(&archive.filepath);
        assert_eq!(sha256, test_data::TAR_ZSTD_V1_TEST_FILE_SHA256);
    }

    #[test]
    fn appender_dir() {
        let test_dir = temp_dir_create!();
        let content = test_data::create_test_dir(&test_dir);

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderDirAll::new(content),
            )
            .unwrap();

        let sha256 = helpers::compute_sha256_hash(&archive.filepath);
        assert_eq!(sha256, test_data::TAR_ZSTD_V1_TEST_DIRECTORY_SHA256);
    }

    #[test]
    fn appender_entries() {
        let test_dir = temp_dir_create!();
        let content = test_data::create_test_dir(&test_dir);

        // Reconstruct what would be done by AppenderDirAll through manual entries
        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderEntries::new(
                    vec![
                        PathBuf::from("foo/"),
                        PathBuf::from("foo/bar.txt"),
                        PathBuf::from("file_1.txt"),
                        PathBuf::from("file_2.txt"),
                    ],
                    content.clone(),
                )
                .unwrap(),
            )
            .unwrap();

        let sha256 = helpers::compute_sha256_hash(&archive.filepath);
        assert_eq!(sha256, test_data::TAR_ZSTD_V1_TEST_DIRECTORY_SHA256);
    }
}
