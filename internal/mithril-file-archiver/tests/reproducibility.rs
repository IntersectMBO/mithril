//! Reproducibility contract for archives produced by [`FileArchiver`].
//!
//! Given identical archive entry paths and contents, `FileArchiver` must produce a
//! byte-identical `.tar.zst` archive regardless of the host system, source base
//! directory, creation time, modification times, permissions, or input entry order.
//!
//! This contract assumes identical archive-format dependencies and zstandard
//! compression parameters. Changing either is an archive-format change and requires
//! intentionally versioning the format and updating its golden hashes.

mod extensions;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use mithril_common::temp_dir_create;

use mithril_file_archiver::appender::*;

use extensions::*;

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

    fn run_scenario<A: TarAppender, B: Fn(PathBuf) -> A>(test_dir: PathBuf, build_tar_appender: B) {
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

    #[cfg(unix)]
    mod permissions {
        use std::fs::Permissions;

        use super::*;

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

        #[test]
        fn appender_file() {
            let test_dir = temp_dir_create!();
            setup_test_file(&test_dir, setup_permissions);
            run_scenario(test_dir, |source| {
                AppenderFile::append_at_archive_root(source.join("file.txt")).unwrap()
            })
        }

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
        let equivalent_entries = ["bar", "foo", "foo/bar.txt", "./file_1.txt", "file_2.txt"];

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
