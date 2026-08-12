//! Test utilities.
//!
//! ⚠ Do not use in production code ⚠
//!
//! This module provides in particular test doubles for the traits defined in this crate.

pub mod double;
mod extensions;

pub use extensions::*;

#[cfg(test)]
pub(crate) use internal_tests_only::*;

/// Unpack a zstandard-compressed tar archive to a specified directory.
///
/// Note: `unpack_dir` must exist.
pub fn unpack_archive(
    archive_path: &std::path::Path,
    unpack_dir: &std::path::Path,
) -> mithril_common::StdResult<()> {
    let mut archive = {
        let file_tar_zst = std::fs::File::open(archive_path)?;
        let file_tar_zst_decoder = zstd::Decoder::new(file_tar_zst)?;
        tar::Archive::new(file_tar_zst_decoder)
    };

    archive.unpack(unpack_dir)?;
    Ok(())
}

#[cfg(test)]
mod internal_tests_only {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use mithril_common::test::TempDir;

    mithril_common::define_test_logger!();

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
