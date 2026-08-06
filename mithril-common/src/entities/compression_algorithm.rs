use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoEnumIterator};

/// Compression algorithm for the snapshot archive artifacts.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    EnumIter,
    Display,
)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    /// Zstandard compression format
    #[default]
    Zstandard,
}

impl CompressionAlgorithm {
    /// Get the extension associated to tar archive using the current algorithm.
    pub fn tar_file_extension(&self) -> String {
        match self {
            CompressionAlgorithm::Zstandard => "tar.zst".to_owned(),
        }
    }

    /// List all the available [algorithms][CompressionAlgorithm].
    pub fn list() -> Vec<Self> {
        Self::iter().collect()
    }

    /// Those ratio will be multiplied by the snapshot size to check if the available
    /// disk space is sufficient to store the archive plus the extracted files.
    /// If the available space is lower than that, a warning is raised.
    /// Those ratio have been experimentally established.
    pub fn free_space_snapshot_ratio(&self) -> f64 {
        match self {
            CompressionAlgorithm::Zstandard => 4.0,
        }
    }
}
