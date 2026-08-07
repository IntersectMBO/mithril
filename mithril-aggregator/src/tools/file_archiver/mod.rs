mod api;
pub mod appender;
mod entities;
#[cfg(test)]
mod tests;

pub use api::*;
pub use entities::*;

#[cfg(test)]
pub(crate) mod test_tools {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use mithril_common::test::TempDir;

    pub fn get_test_directory(dir_name: &str) -> PathBuf {
        TempDir::create("file_archiver", dir_name)
    }

    /// Create a file in the root directory.
    ///
    /// Returns the relative path to the created file based on the root directory.
    pub fn create_file(root: &Path, filename: &str) -> PathBuf {
        let file_path = PathBuf::from(filename);
        File::create(root.join(file_path.clone())).unwrap();
        file_path
    }

    /// Create a directory in the root directory.
    ///
    /// Returns the relative path to the created directory based on the root directory.
    pub fn create_dir(root: &Path, dirname: &str) -> PathBuf {
        let dir_path = PathBuf::from(dirname);
        std::fs::create_dir(root.join(dir_path.clone())).unwrap();
        dir_path
    }
}
