use std::path::{Path, PathBuf};

use mithril_common::entities::CompressionAlgorithm;

use crate::FileArchive;
use crate::test::unpack_archive;

/// Extension trait adding test utilities to [FileArchive]
pub trait FileArchiveTestExtension {
    /// `TEST ONLY` - Unpack the archive to a directory.
    ///
    /// An 'unpack' directory will be created in the given parent directory.
    fn unpack_zstandard<P: AsRef<Path>>(&self, parent_dir: P) -> PathBuf;
}

impl FileArchiveTestExtension for FileArchive {
    fn unpack_zstandard<P: AsRef<Path>>(&self, parent_dir: P) -> PathBuf {
        if self.compression_algorithm != CompressionAlgorithm::Zstandard {
            panic!("Only Zstandard compression is supported");
        }

        let unpack_path = parent_dir.as_ref().join("unpack");
        std::fs::create_dir(&unpack_path).unwrap();

        unpack_archive(self.get_file_path(), &unpack_path).unwrap();

        unpack_path
    }
}
