use std::path::PathBuf;

use mithril_common::entities::CompressionAlgorithm;
use mithril_common::test::double::Dummy;

use crate::FileArchive;

impl Dummy for FileArchive {
    fn dummy() -> Self {
        Self {
            filepath: PathBuf::from("archive.tar.zst"),
            archive_filesize: 10,
            uncompressed_size: 789,
            compression_algorithm: CompressionAlgorithm::Zstandard,
        }
    }
}
