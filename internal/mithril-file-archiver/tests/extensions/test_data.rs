//! Fixed test data set for file archiver tests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::extensions::helpers;

pub const TEST_BYTES: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// See: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#blocks
pub(crate) const ZSTD_MAX_BLOCK_SIZE: u64 = 131_072;

#[derive(Debug, PartialEq, Serialize)]
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
