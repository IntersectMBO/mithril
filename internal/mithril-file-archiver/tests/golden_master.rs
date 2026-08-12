//! The golden hashes are pinned to: the tar/zstd crate versions, GOLDEN_COMPRESSION_PARAMETERS
//! (multi-threaded zstd), and the exact bytes produced by `test_data::create_test_*`.
//! Any change to one of those invalidates them.

mod extensions;

use std::fs::File;
use std::path::{Path, PathBuf};

use mithril_common::temp_dir_create;

use mithril_file_archiver::appender::*;
use mithril_file_archiver::{FileArchive, ZstandardCompressionParameters};

use extensions::*;

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
