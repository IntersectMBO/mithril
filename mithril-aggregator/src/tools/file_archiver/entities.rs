use std::path::{Path, PathBuf};

use mithril_common::entities::CompressionAlgorithm;

/// Parameters for creating an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveParameters {
    pub archive_name_without_extension: String,
    pub target_directory: PathBuf,
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

    /// Unpack the archive to a directory.
    ///
    /// An 'unpack' directory will be created in the given parent directory.
    #[cfg(test)]
    pub fn unpack_zstandard<P: AsRef<Path>>(&self, parent_dir: P) -> PathBuf {
        use super::test_tools::create_dir;
        use std::fs::File;
        use tar::Archive;
        use zstd::stream::read::Decoder;
        if self.compression_algorithm != CompressionAlgorithm::Zstandard {
            panic!("Only Zstandard compression is supported");
        }

        let parent_dir = parent_dir.as_ref();
        let file_tar_zst = File::open(self.get_file_path()).unwrap();
        let file_tar_zst_decoder = Decoder::new(file_tar_zst).unwrap();
        let mut archive = Archive::new(file_tar_zst_decoder);
        let unpack_path = parent_dir.join(create_dir(parent_dir, "unpack"));
        archive.unpack(&unpack_path).unwrap();

        unpack_path
    }
}

#[cfg(test)]
impl mithril_common::test::double::Dummy for FileArchive {
    fn dummy() -> Self {
        Self {
            filepath: PathBuf::from("archive.tar.zst"),
            archive_filesize: 10,
            uncompressed_size: 789,
            compression_algorithm: CompressionAlgorithm::Zstandard,
        }
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
