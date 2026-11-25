//! Fixtures for the host probe tests, which run against fake `/proc` trees and search paths
use std::path::{Path, PathBuf};

/// Create an empty directory dedicated to a test, removing any leftover of a previous run
#[cfg(test)]
pub fn test_dir(path: impl AsRef<Path>) -> PathBuf {
    let dir = std::env::temp_dir().join("mithril-setup-tests").join(path);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Create an empty directory named after the path of the test function calling this macro
/// (the `tests` module is left out of the path)
#[macro_export]
macro_rules! test_dir {
    () => {
        $crate::test_tools::file::test_dir(
            $crate::current_function_path!()
                .to_string_lossy()
                .replace("/tests/", "/"),
        )
    };
}

/// Write a file, creating its parent directories
#[cfg(test)]
pub fn write_file(path: &Path, content: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}
