//! Reproducibility contract for archives produced by [`FileArchiver`].
//!
//! Given identical archive entry paths and contents, `FileArchiver` must produce a
//! byte-identical `.tar.zst` archive regardless of the host system, source base
//! directory, creation time, modification times, permissions, or input entry order.
//!
//! This contract assumes identical archive-format dependencies and zstandard
//! compression parameters. Changing either is an archive-format change and requires
//! intentionally versioning the format and updating its golden hashes.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use mithril_common::entities::CompressionAlgorithm;
use mithril_common::temp_dir_create;

use mithril_file_archiver::appender::*;
use mithril_file_archiver::{
    ArchiveParameters, FileArchive, FileArchiver, ZstandardCompressionParameters,
};

mod helpers {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    use super::*;

    /// Assert that two files have exactly the same bytes.
    ///
    /// SHA-256 hashes and file sizes are reported when they differ.
    #[track_caller]
    pub fn assert_files_are_byte_identical<E: AsRef<Path>, A: AsRef<Path>>(expected: E, actual: A) {
        let (expected_path, actual_path) = (expected.as_ref(), actual.as_ref());
        let expected_bytes = std::fs::read(expected_path).unwrap_or_else(|error| {
            panic!(
                "Could not read expected file '{}': {error}",
                expected_path.display()
            )
        });
        let actual_bytes = std::fs::read(actual_path).unwrap_or_else(|error| {
            panic!(
                "Could not read actual file '{}': {error}",
                actual_path.display()
            )
        });

        if expected_bytes != actual_bytes {
            let expected_hash = hex::encode(Sha256::digest(&expected_bytes));
            let actual_hash = hex::encode(Sha256::digest(&actual_bytes));

            panic!(
                "Files are not byte-identical:\n\
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
    }

    /// **IMPORTANT** Default zstandard compression parameters are used.
    pub fn file_archiver(work_dir: &Path) -> FileArchiver {
        FileArchiver::new_with_default_parameters(
            work_dir.join("verification"),
            slog::Logger::root(slog::Discard, slog::o!()),
        )
    }

    pub fn create_dir<P: AsRef<Path>>(base_dir: &Path, dir_name: P) -> PathBuf {
        let dir_path = base_dir.join(dir_name);
        std::fs::create_dir(&dir_path).unwrap();
        dir_path
    }

    pub fn create_file(root_dir: &Path, file_name: &str, size: Option<u64>) -> PathBuf {
        let path = root_dir.join(file_name);
        let mut file = File::create(&path).unwrap();

        write!(file, "This is a test file named '{file_name}'").unwrap();
        writeln!(file).unwrap();

        if let Some(file_size) = size {
            file.set_len(file_size).unwrap();
        }

        path
    }

    pub fn alter_file<F: FnOnce(&File)>(path: &Path, alter_fn: F) {
        let file = File::options().write(true).open(path).unwrap();
        alter_fn(&file);
    }

    pub fn archive_parameters(filename: &str, target_dir: &Path) -> ArchiveParameters {
        ArchiveParameters {
            archive_name_without_extension: filename.to_string(),
            target_directory: target_dir.to_path_buf(),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        }
    }

    pub fn compute_file_sha256(path: &Path) -> String {
        let mut hasher = Sha256::new();

        if path.is_file() {
            hash_file(path, &mut hasher);
        } else {
            panic!("Path is not a file: {:?}", path.display());
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

    #[test]
    fn assert_files_are_byte_identical_succeed_with_identical_files() {
        let test_dir = temp_dir_create!();
        let content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let reference_file_path = test_dir.join("reference_file");
        let mut reference_file = File::create_new(&reference_file_path).unwrap();
        reference_file.write_all(&content).unwrap();

        let identical_file_path = test_dir.join("altered_file");
        std::fs::copy(&reference_file_path, &identical_file_path).unwrap();

        assert_files_are_byte_identical(&reference_file_path, &identical_file_path);
    }

    #[test]
    #[should_panic(expected = "Files are not byte-identical")]
    fn assert_files_are_byte_identical_fails_if_one_byte_changes() {
        let test_dir = temp_dir_create!();
        let content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let altered_content = {
            let mut altered_content = content.clone();
            altered_content[0] = !altered_content[0];
            altered_content
        };

        let reference_file_path = test_dir.join("reference_file");
        let mut reference_file = File::create_new(&reference_file_path).unwrap();
        reference_file.write_all(&content).unwrap();

        let altered_file_path = test_dir.join("altered_file");
        let mut altered_file = File::create_new(&altered_file_path).unwrap();
        altered_file.write_all(&altered_content).unwrap();

        assert_files_are_byte_identical(&reference_file_path, &altered_file_path);
    }
}

/// Fixed test data set for file archiver tests.
mod test_data {
    use serde::{Deserialize, Serialize};

    use super::*;

    pub const TEST_BYTES: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    /// See: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#blocks
    pub(crate) const ZSTD_MAX_BLOCK_SIZE: u64 = 131_072;

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
        helpers::create_file(root_dir, "test.txt", Some(1048))
    }

    /// [AppenderEntries] ready list of entries created by [`create_test_dir`]
    pub fn test_dir_entries() -> Vec<PathBuf> {
        vec![
            PathBuf::from("bar/"),
            PathBuf::from("foo/"),
            PathBuf::from("foo/bar.txt"),
            PathBuf::from("file_1.txt"),
            PathBuf::from("file_2.txt"),
        ]
    }

    /// Create a directory named `test_dir` in the given directory
    ///
    /// It will be filled with the following structure:
    /// ```no_run
    /// test_dir/
    /// ├── bar/
    /// ├── foo/
    /// │   └── bar.txt
    /// ├── file_1.txt
    /// ├── file_2.txt
    /// ├── empty_file.txt
    /// └── file_with_a_name_longer_than_100_caracters_so_tar_switch_to_the_GNU_longname_extension.txt
    /// ```
    pub fn create_test_dir(root_dir: &Path) -> PathBuf {
        let test_dir = helpers::create_dir(root_dir, "test_dir");

        helpers::create_dir(&test_dir, "bar");

        let foo_dir = helpers::create_dir(&test_dir, "foo");
        helpers::create_file(&foo_dir, "bar.txt", None);

        helpers::create_file(&test_dir, "file_1.txt", Some(511));
        helpers::create_file(&test_dir, "file_2.txt", Some(ZSTD_MAX_BLOCK_SIZE * 2 + 1));

        test_dir
    }
}

mod reproducibility {
    use std::time::{Duration, SystemTime};

    use super::*;

    mod repeated_archiving_produces_byte_identical_archives {
        use std::time::Instant;

        use super::*;

        fn run_scenario<T: TarAppender>(test_dir: PathBuf, ref_appender: T, repeated_appender: T) {
            run_scenario_with_hook(test_dir, ref_appender, repeated_appender, || {});
        }

        fn run_scenario_in_different_unix_seconds<T: TarAppender>(
            test_dir: PathBuf,
            ref_appender: T,
            repeated_appender: T,
        ) {
            run_scenario_with_hook(test_dir, ref_appender, repeated_appender, || {
                let seconds_since_unix_epoch = || {
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                };

                let reference_second = seconds_since_unix_epoch();
                let deadline = Instant::now() + Duration::from_millis(1500);

                while seconds_since_unix_epoch() == reference_second {
                    assert!(
                        Instant::now() < deadline,
                        "Unix time did not advance to the next second"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
        }

        fn run_scenario_with_hook<T: TarAppender, F: FnOnce()>(
            test_dir: PathBuf,
            ref_appender: T,
            repeated_appender: T,
            before_repeated_archive: F,
        ) {
            let reference_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    ref_appender,
                )
                .unwrap();

            before_repeated_archive();

            let repeated_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("repeated", &test_dir),
                    repeated_appender,
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                reference_archive.get_file_path(),
                repeated_archive.get_file_path(),
            );
        }

        #[test]
        fn appender_data_from_json() {
            let test_dir = temp_dir_create!();
            let content = test_data::TestStruct::default();

            // AppenderData create metadata itself when the archive is created, making it sensitive to the current unix time.
            run_scenario_in_different_unix_seconds(
                test_dir,
                AppenderData::from_json(PathBuf::from("test_data.json"), &content).unwrap(),
                AppenderData::from_json(PathBuf::from("test_data.json"), &content).unwrap(),
            );
        }

        #[test]
        fn appender_data_from_raw_bytes() {
            let test_dir = temp_dir_create!();
            let content = test_data::TEST_BYTES.to_vec();

            // AppenderData create metadata itself when the archive is created, making it sensitive to the current unix time.
            run_scenario_in_different_unix_seconds(
                test_dir,
                AppenderData::from_raw_bytes(PathBuf::from("bytes.txt"), content.clone()),
                AppenderData::from_raw_bytes(PathBuf::from("bytes.txt"), content),
            );
        }

        #[test]
        fn appender_file() {
            let test_dir = temp_dir_create!();
            let content = test_data::create_test_txt(&helpers::create_dir(&test_dir, "source"));

            run_scenario(
                test_dir,
                AppenderFile::append_at_archive_root(content.clone()).unwrap(),
                AppenderFile::append_at_archive_root(content).unwrap(),
            );
        }

        #[test]
        fn appender_dir_all() {
            let test_dir = temp_dir_create!();
            let content = test_data::create_test_dir(&helpers::create_dir(&test_dir, "source"));

            run_scenario(
                test_dir,
                AppenderDirAll::new(content.clone()),
                AppenderDirAll::new(content),
            );
        }

        #[test]
        fn appender_entries() {
            let test_dir = temp_dir_create!();
            let content = test_data::create_test_dir(&helpers::create_dir(&test_dir, "source"));

            run_scenario(
                test_dir,
                AppenderEntries::new(test_data::test_dir_entries(), content.clone()).unwrap(),
                AppenderEntries::new(test_data::test_dir_entries(), content).unwrap(),
            );
        }
    }

    mod source_metadata_does_not_affect_archive_bytes {
        use std::fs::Permissions;

        use super::*;

        /// [AppenderEntries] ready list of the reference/altered dirs created by [setup_test_dirs].
        fn test_dir_entries() -> Vec<PathBuf> {
            vec![
                PathBuf::from("empty/"),
                PathBuf::from("subdir/"),
                PathBuf::from("subdir/file_2.txt"),
                PathBuf::from("subdir/file_3.txt"),
                PathBuf::from("file_1.txt"),
            ]
        }

        /// Create two directories with the same structure and applies the given function to each
        /// reference/altered files pair.
        ///
        /// To be used with Appender that can work on a group of files and directories.
        ///
        /// Each directory contains the following files:
        /// ```no_run
        /// (reference|altered)/
        /// ├── empty/
        /// ├── subdir/
        /// │   ├── file_2.txt
        /// │   └── file_3.txt
        /// └── file_1.txt
        /// ```
        fn setup_test_dirs<F: Fn(&Path, &Path)>(
            test_dir: &Path,
            setup_reference_and_altered_path_fn: F,
        ) {
            let source = helpers::create_dir(test_dir, "source");
            let reference_dir = helpers::create_dir(&source, "reference");
            let altered_dir = helpers::create_dir(&source, "altered");
            let subdirs = vec![Path::new("empty"), Path::new("subdir")];

            for dir_path in &subdirs {
                helpers::create_dir(&reference_dir, dir_path);
                helpers::create_dir(&altered_dir, dir_path);
            }

            for file_path in ["file_1.txt", "subdir/file_2.txt", "subdir/file_3.txt"] {
                let reference_file = helpers::create_file(&reference_dir, file_path, None);
                let altered_file = helpers::create_file(&altered_dir, file_path, None);

                // Ensure the two files have the same content
                helpers::assert_files_are_byte_identical(&reference_file, &altered_file);

                setup_reference_and_altered_path_fn(&reference_file, &altered_file);
            }

            // Alter dirs after the files to avoid permission issues
            for dir_path in &subdirs {
                setup_reference_and_altered_path_fn(
                    &reference_dir.join(dir_path),
                    &altered_dir.join(dir_path),
                );
            }
            setup_reference_and_altered_path_fn(&reference_dir, &altered_dir);
        }

        /// Create two directories with a single "test.txt" file and applies the given function
        /// to the reference/altered file pair.
        ///
        /// To be used with Appender that can work on a single file.
        fn setup_test_file<F: Fn(&Path, &Path)>(
            test_dir: &Path,
            setup_reference_and_altered_path_fn: F,
        ) {
            let source = helpers::create_dir(test_dir, "source");
            let reference_dir = helpers::create_dir(&source, "reference");
            let altered_dir = helpers::create_dir(&source, "altered");

            let reference_file = helpers::create_file(&reference_dir, "file.txt", None);
            let altered_file = helpers::create_file(&altered_dir, "file.txt", None);

            // Ensure the two files have the same content
            helpers::assert_files_are_byte_identical(&reference_file, &altered_file);

            setup_reference_and_altered_path_fn(&reference_file, &altered_file);
        }

        fn run_scenario<A: TarAppender, B: Fn(PathBuf) -> A>(
            test_dir: PathBuf,
            build_tar_appender: B,
        ) {
            let source = test_dir.join("source");
            let reference_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    build_tar_appender(source.join("reference")),
                )
                .unwrap();

            let archive_with_different_metadata = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("altered_metadata", &test_dir),
                    build_tar_appender(source.join("altered")),
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                reference_archive.get_file_path(),
                archive_with_different_metadata.get_file_path(),
            );
        }

        mod modification_time {
            use super::*;

            fn setup_modification_time(reference_path: &Path, path_with_different_metadata: &Path) {
                if reference_path.is_dir() || path_with_different_metadata.is_dir() {
                    // can't modify dir times until <https://doc.rust-lang.org/std/fs/fn.set_times.html>
                    // is stabilized (currently planned for rust 1.99)
                    return;
                }

                let base_time = SystemTime::UNIX_EPOCH;
                helpers::alter_file(reference_path, |file| file.set_modified(base_time).unwrap());
                helpers::alter_file(path_with_different_metadata, |file| {
                    // note: in TAR, entries mtimes have a granularity of a second
                    file.set_modified(base_time + Duration::from_millis(5300)).unwrap()
                });

                assert_ne!(
                    reference_path.metadata().unwrap().modified().unwrap(),
                    path_with_different_metadata.metadata().unwrap().modified().unwrap()
                );
            }

            #[test]
            fn appender_file() {
                let test_dir = temp_dir_create!();
                setup_test_file(&test_dir, setup_modification_time);
                run_scenario(test_dir, |source| {
                    AppenderFile::append_at_archive_root(source.join("file.txt")).unwrap()
                });
            }

            #[test]
            fn appender_dir_all() {
                let test_dir = temp_dir_create!();
                setup_test_dirs(&test_dir, setup_modification_time);
                run_scenario(test_dir, AppenderDirAll::new);
            }

            #[test]
            fn appender_entries() {
                let test_dir = temp_dir_create!();
                setup_test_dirs(&test_dir, setup_modification_time);
                run_scenario(test_dir, |source| {
                    AppenderEntries::new(test_dir_entries(), source).unwrap()
                });
            }
        }

        mod permissions {
            use super::*;

            #[cfg(unix)]
            fn setup_permissions(reference_path: &Path, path_with_different_metadata: &Path) {
                use std::os::unix::fs::PermissionsExt;

                let (reference_permission, altered_permission) =
                    // IMPORTANT: for directory the owner permission must be `7`, else this prevents
                    // `temp_dir_create` cleanup and make appenders fails on subdir files
                    if reference_path.is_dir() || path_with_different_metadata.is_dir() {
                        (Permissions::from_mode(0o766), Permissions::from_mode(0o767))
                    } else {
                        (Permissions::from_mode(0o644), Permissions::from_mode(0o646))
                    };

                std::fs::set_permissions(reference_path, reference_permission).unwrap();
                std::fs::set_permissions(path_with_different_metadata, altered_permission).unwrap();

                assert_ne!(
                    reference_path.metadata().unwrap().permissions(),
                    path_with_different_metadata.metadata().unwrap().permissions()
                );
            }

            #[cfg(unix)]
            #[test]
            fn appender_file() {
                let test_dir = temp_dir_create!();
                setup_test_file(&test_dir, setup_permissions);
                run_scenario(test_dir, |source| {
                    AppenderFile::append_at_archive_root(source.join("file.txt")).unwrap()
                })
            }

            #[cfg(unix)]
            #[test]
            fn appender_dir_all() {
                let test_dir = temp_dir_create!();
                setup_test_dirs(&test_dir, setup_permissions);
                run_scenario(test_dir, AppenderDirAll::new);
            }

            #[cfg(unix)]
            #[test]
            fn appender_entries() {
                let test_dir = temp_dir_create!();
                setup_test_dirs(&test_dir, setup_permissions);
                run_scenario(test_dir, |source| {
                    AppenderEntries::new(test_dir_entries(), source).unwrap()
                });
            }
        }
    }

    mod source_base_directory_does_not_affect_archive {
        use super::*;

        #[test]
        fn appender_file() {
            let test_dir = temp_dir_create!();
            let source = helpers::create_dir(&test_dir, "source");
            let subdir_1 = helpers::create_dir(&source, "first");
            let subdir_2 = helpers::create_dir(&source, "second");

            let content = test_data::create_test_txt(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_txt(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    AppenderFile::append_at_archive_root(content).unwrap(),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("from_another_dir", &test_dir),
                    AppenderFile::append_at_archive_root(same_content_in_other_dir).unwrap(),
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                archive.get_file_path(),
                archive_with_same_content_but_from_another_dir.get_file_path(),
            );
        }

        #[test]
        fn appender_dir_all() {
            let test_dir = temp_dir_create!();
            let source = helpers::create_dir(&test_dir, "source");
            let subdir_1 = helpers::create_dir(&source, "first");
            let subdir_2 = helpers::create_dir(&source, "second");

            let content = test_data::create_test_dir(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_dir(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    AppenderDirAll::new(content),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("from_another_dir", &test_dir),
                    AppenderDirAll::new(same_content_in_other_dir),
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                archive.get_file_path(),
                archive_with_same_content_but_from_another_dir.get_file_path(),
            );
        }

        #[test]
        fn appender_entries() {
            let test_dir = temp_dir_create!();
            let source = helpers::create_dir(&test_dir, "source");
            let subdir_1 = helpers::create_dir(&source, "first");
            let subdir_2 = helpers::create_dir(&source, "second");

            let content = test_data::create_test_dir(&subdir_1);
            let same_content_in_other_dir = test_data::create_test_dir(&subdir_2);

            let archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    AppenderEntries::new(test_data::test_dir_entries(), content).unwrap(),
                )
                .unwrap();
            let archive_with_same_content_but_from_another_dir = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("from_another_dir", &test_dir),
                    AppenderEntries::new(test_data::test_dir_entries(), same_content_in_other_dir)
                        .unwrap(),
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                archive.get_file_path(),
                archive_with_same_content_but_from_another_dir.get_file_path(),
            );
        }
    }

    mod appender_entry_specifics {
        use super::*;

        fn to_entries<const N: usize>(paths: [&str; N]) -> Vec<PathBuf> {
            paths.into_iter().map(PathBuf::from).collect()
        }

        #[test]
        fn equivalent_entry_paths_produce_identical_archives() {
            let test_dir = temp_dir_create!();
            let source = helpers::create_dir(&test_dir, "source");
            let content = test_data::create_test_dir(&source);

            let reference_entries = ["bar/", "foo/", "foo/bar.txt", "file_1.txt", "file_2.txt"];
            let equivalent_entries = ["bar", "foo", "foo/bar.txt", "file_1.txt", "file_2.txt"];

            let reference_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    AppenderEntries::new(to_entries(reference_entries), content.clone()).unwrap(),
                )
                .unwrap();

            let archive_with_equivalent_entries_spelling = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("equivalent_spelling", &test_dir),
                    AppenderEntries::new(to_entries(equivalent_entries), content).unwrap(),
                )
                .unwrap();

            helpers::assert_files_are_byte_identical(
                reference_archive.get_file_path(),
                archive_with_equivalent_entries_spelling.get_file_path(),
            );
        }

        #[test]
        fn supplied_entry_order_does_not_affect_appender_entries_archive() {
            let test_dir = temp_dir_create!();
            let source = helpers::create_dir(&test_dir, "source");
            let content = test_data::create_test_dir(&source);

            let reference_archive = helpers::file_archiver(&test_dir)
                .archive(
                    helpers::archive_parameters("reference", &test_dir),
                    AppenderEntries::new(test_data::test_dir_entries(), content.clone()).unwrap(),
                )
                .unwrap();

            for (label, entries) in [
                (
                    "child_before_parent_dir",
                    ["bar/", "foo/bar.txt", "foo/", "file_1.txt", "file_2.txt"],
                ),
                (
                    "directories_before_files",
                    ["foo/", "bar/", "file_2.txt", "file_1.txt", "foo/bar.txt"],
                ),
                (
                    "files_before_directories",
                    ["file_2.txt", "file_1.txt", "foo/bar.txt", "foo/", "bar/"],
                ),
                (
                    "reverse_dirs_order",
                    ["foo/", "bar/", "foo/bar.txt", "file_1.txt", "file_2.txt"],
                ),
                (
                    "reverse_files_order",
                    ["bar/", "foo/", "foo/bar.txt", "file_2.txt", "file_1.txt"],
                ),
            ] {
                let archive_with_same_content_but_different_entries_order =
                    helpers::file_archiver(&test_dir)
                        .archive(
                            helpers::archive_parameters(label, &test_dir),
                            AppenderEntries::new(to_entries(entries), content.clone()).unwrap(),
                        )
                        .unwrap();

                helpers::assert_files_are_byte_identical(
                    reference_archive.get_file_path(),
                    archive_with_same_content_but_different_entries_order.get_file_path(),
                );
            }
        }
    }
}

// The golden hashes are pinned to: the tar/zstd crate versions, GOLDEN_COMPRESSION_PARAMETERS
// (multi-threaded zstd), and the exact bytes produced by `test_data::create_test_*`.
// Any change to one of those invalidates them.
mod golden_master {
    use super::*;

    // ** These hashes define TAR_ZSTD_V1. Update them only for an intentional archive-format change. **
    pub const TAR_ZSTD_V1_TEST_FILE_SHA256: &str =
        "792b60f937bd348e5cfe8e4dc9fe7257b146888b8b30c52a547bd3ae4b7b1e4f";
    pub const TAR_ZSTD_V1_TEST_DIRECTORY_APPENDER_DIR_ALL_SHA256: &str =
        "647bba62029e63b0cbd329bccdfdb850ec934a07ab0811cc4d2d7682b72d3054";
    pub const TAR_ZSTD_V1_TEST_DIRECTORY_APPENDER_ENTRIES_SHA256: &str =
        "565da17762fcf8f417f1ad78fda003b19507757bf56ac09ff24a9aac179bf78c";
    pub const TAR_ZSTD_V1_TEST_DATA_SHA256: &str =
        "fd5a178f1c717de39aef526d378e731871b74ee1ba11bdc159a4a872867d3748";
    pub const TAR_ZSTD_V1_TEST_RAW_BYTES_SHA256: &str =
        "6843b658c2c176afa156e82f7ee3d828f63cd7e9de16dc3166a5da96f0d3e15f";
    pub const TAR_ZSTD_V1_TEST_CHAIN_DIRECTORY_AND_DATA_SHA256: &str =
        "ff5447a1b80b530b3d94cfeb2ad69fdc392a4d5175f24ffc13ad10b08a7e12ba";

    /// Create a directory named `test_dir` in the given directory
    ///
    /// It will be filled with the following structure:
    /// ```no_run
    /// test_dir/
    /// ├── bar/
    /// ├── foo/
    /// │   └── bar.txt
    /// ├── empty_file.txt
    /// ├── file_1.txt
    /// ├── file_2.txt
    /// └── file_with_a_very_very_long_name_a_name_longer_than_100_caracters_so_tar_switch_to_the_GNU_longname_extension.txt
    /// ```
    pub fn create_golden_test_dir(root_dir: &Path) -> PathBuf {
        let test_dir = helpers::create_dir(root_dir, "test_dir");

        helpers::create_dir(&test_dir, "bar");

        let foo_dir = helpers::create_dir(&test_dir, "foo");
        helpers::create_file(&foo_dir, "bar.txt", None);

        File::create(test_dir.join("empty.txt")).unwrap();

        helpers::create_file(&test_dir, "file_1.txt", Some(511));
        helpers::create_file(
            &test_dir,
            "file_2.txt",
            Some(test_data::ZSTD_MAX_BLOCK_SIZE * 2 + 1),
        );
        helpers::create_file(
            &test_dir,
            "file_with_a_very_very_long_name_a_name_longer_than_100_caracters_so_tar_switch_to_the_GNU_longname_extension.txt",
            None,
        );

        test_dir
    }

    /// [AppenderEntries] ready list of entries created by [`create_golden_test_dir`]
    pub fn golden_test_dir_entries() -> Vec<PathBuf> {
        vec![
            PathBuf::from("bar/"),
            PathBuf::from("foo/"),
            PathBuf::from("foo/bar.txt"),
            PathBuf::from("empty.txt"),
            PathBuf::from("file_1.txt"),
            PathBuf::from("file_2.txt"),
            PathBuf::from(
                "file_with_a_very_very_long_name_a_name_longer_than_100_caracters_so_tar_switch_to_the_GNU_longname_extension.txt",
            ),
        ]
    }

    #[track_caller]
    fn assert_archive_not_empty(archive: &FileArchive) {
        assert!(
            archive.get_uncompressed_size() > 0,
            "Archive '{}' has no content, fix the archive creation and try again",
            archive.get_file_path().display()
        );
    }

    /// Assert an archive matches its golden hash.
    #[track_caller]
    fn assert_archive_matches_golden_sha256(archive: &FileArchive, expected_sha256: &str) {
        let actual_sha256 = helpers::compute_file_sha256(archive.get_file_path());

        assert_eq!(
            expected_sha256,
            actual_sha256,
            "Archive bytes changed ('{}', {} bytes).\n\
             Either the archive format is no longer reproducible, or the change is intentional \
             and the TAR_ZSTD_V* constants must be recomputed and their version bumped.",
            archive.get_file_path().display(),
            archive.get_archive_size(),
        );
    }

    /// Compression parameters the golden hashes were computed with.
    ///
    /// They must mirror the production defaults, see [defaults_are_the_golden_parameters].
    const GOLDEN_COMPRESSION_PARAMETERS: ZstandardCompressionParameters =
        ZstandardCompressionParameters {
            level: 9,
            number_of_workers: 4,
        };

    #[test]
    fn defaults_are_the_golden_parameters() {
        assert_eq!(
            GOLDEN_COMPRESSION_PARAMETERS,
            ZstandardCompressionParameters::default(),
            "zstandard defaults changed: archives are no longer byte-compatible with the \
             previously published ones, the golden hashes must be recomputed and TAR_ZSTD_V1 \
             bumped to V2"
        );
    }

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

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(&archive, TAR_ZSTD_V1_TEST_DATA_SHA256);
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

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(&archive, TAR_ZSTD_V1_TEST_RAW_BYTES_SHA256);
    }

    #[test]
    fn appender_file() {
        let test_dir = temp_dir_create!();
        let content = test_data::create_test_txt(&helpers::create_dir(&test_dir, "source"));

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderFile::append_at_archive_root(content).unwrap(),
            )
            .unwrap();

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(&archive, TAR_ZSTD_V1_TEST_FILE_SHA256);
    }

    #[test]
    fn appender_dir_all() {
        let test_dir = temp_dir_create!();
        let content = create_golden_test_dir(&helpers::create_dir(&test_dir, "source"));

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderDirAll::new(content),
            )
            .unwrap();

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(
            &archive,
            TAR_ZSTD_V1_TEST_DIRECTORY_APPENDER_DIR_ALL_SHA256,
        );
    }

    #[test]
    fn appender_entries() {
        let test_dir = temp_dir_create!();
        let content = create_golden_test_dir(&helpers::create_dir(&test_dir, "source"));

        // Should construct the same archive as `AppenderDirAll` as we include all the source directory entries
        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderEntries::new(golden_test_dir_entries(), content).unwrap(),
            )
            .unwrap();

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(
            &archive,
            TAR_ZSTD_V1_TEST_DIRECTORY_APPENDER_ENTRIES_SHA256,
        );
    }

    #[test]
    fn chain_appender() {
        let test_dir = temp_dir_create!();
        let content = create_golden_test_dir(&helpers::create_dir(&test_dir, "source"));

        let archive = helpers::file_archiver(&test_dir)
            .archive(
                helpers::archive_parameters("test", &test_dir),
                AppenderEntries::new(golden_test_dir_entries(), content)
                    .unwrap()
                    .chain(
                        AppenderData::from_json(
                            PathBuf::from("test.json"),
                            &test_data::TestStruct::default(),
                        )
                        .unwrap(),
                    ),
            )
            .unwrap();

        assert_archive_not_empty(&archive);
        assert_archive_matches_golden_sha256(
            &archive,
            TAR_ZSTD_V1_TEST_CHAIN_DIRECTORY_AND_DATA_SHA256,
        );
    }
}
