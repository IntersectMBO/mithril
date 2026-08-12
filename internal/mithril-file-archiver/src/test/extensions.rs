use std::fs::File;
use std::path::{Path, PathBuf};

use tar::Archive;
use zstd::stream::read::Decoder;

use mithril_common::entities::CompressionAlgorithm;

use crate::FileArchive;

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

        let parent_dir = parent_dir.as_ref();
        let file_tar_zst = File::open(self.get_file_path()).unwrap();
        let file_tar_zst_decoder = Decoder::new(file_tar_zst).unwrap();
        let mut archive = Archive::new(file_tar_zst_decoder);
        let unpack_path = parent_dir.join("unpack");
        std::fs::create_dir(&unpack_path).unwrap();
        archive.unpack(&unpack_path).unwrap();

        unpack_path
    }
}
