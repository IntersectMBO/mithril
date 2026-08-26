use std::path::{Path, PathBuf};

use serde::Deserialize;

use mithril_common::entities::CompressionAlgorithm;

/// [Zstandard][CompressionAlgorithm::Zstandard] specific parameters
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct ZstandardCompressionParameters {
    /// Level of compression, default to 9.
    pub level: i32,

    /// Number of workers when compressing, 0 will disable multithreading, default to 4.
    pub number_of_workers: u32,
}

impl Default for ZstandardCompressionParameters {
    fn default() -> Self {
        Self {
            level: 9,
            number_of_workers: 4,
        }
    }
}

/// Parameters for creating an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveParameters {
    /// Archive name without file extension
    pub archive_name_without_extension: String,
    /// Directory where the archive will be created
    pub target_directory: PathBuf,
    /// Compression algorithm to use for the archive
    pub compression_algorithm: CompressionAlgorithm,
}

impl ArchiveParameters {
    pub(super) fn target_path(&self) -> PathBuf {
        self.target_directory.join(format!(
            "{}.{}",
            self.archive_name_without_extension,
            self.compression_algorithm.tar_file_extension()
        ))
    }

    pub(super) fn temporary_archive_path(&self) -> PathBuf {
        self.target_directory
            .join(format!("{}.tar.tmp", self.archive_name_without_extension))
    }
}

/// Result of a file archiving operation, containing the path to the archive and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileArchive {
    pub(super) filepath: PathBuf,
    pub(super) archive_filesize: u64,
    pub(super) uncompressed_size: u64,
    pub(super) compression_algorithm: CompressionAlgorithm,
}

impl FileArchive {
    /// Create a new instance of FileArchive.
    pub fn new(
        filepath: PathBuf,
        archive_filesize: u64,
        uncompressed_size: u64,
        compression_algorithm: CompressionAlgorithm,
    ) -> Self {
        Self {
            filepath,
            archive_filesize,
            uncompressed_size,
            compression_algorithm,
        }
    }

    /// Get the path of the archive.
    pub fn get_file_path(&self) -> &Path {
        &self.filepath
    }

    /// Get the size of the archive.
    pub fn get_archive_size(&self) -> u64 {
        self.archive_filesize
    }

    /// Get the size of the data before compression.
    pub fn get_uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Get the compression algorithm used to create the archive.
    pub fn get_compression_algorithm(&self) -> CompressionAlgorithm {
        self.compression_algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getting_archive_parameters_target_path_should_not_override_trailing_dot_text() {
        let archive_parameters = ArchiveParameters {
            archive_name_without_extension: "archive.test_xxx".to_owned(),
            target_directory: PathBuf::from("/tmp"),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };

        assert_eq!(
            PathBuf::from("/tmp/archive.test_xxx.tar.zst"),
            archive_parameters.target_path()
        );
    }

    #[test]
    fn getting_archive_parameters_temporary_archive_path_should_not_override_trailing_dot_text() {
        let archive_parameters = ArchiveParameters {
            archive_name_without_extension: "archive.test_xxx".to_owned(),
            target_directory: PathBuf::from("/tmp"),
            compression_algorithm: CompressionAlgorithm::Zstandard,
        };

        assert_eq!(
            PathBuf::from("/tmp/archive.test_xxx.tar.tmp"),
            archive_parameters.temporary_archive_path()
        );
    }
}
