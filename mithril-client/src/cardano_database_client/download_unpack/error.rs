use std::path::PathBuf;

use thiserror::Error;

/// Error raised when a Cardano database cannot be downloaded and unpacked.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CardanoDatabaseDownloadError {
    /// The target directory does not exist or is not a directory.
    #[error("Target directory '{}' does not exist or is not a directory", .0.display())]
    TargetIsNotADirectory(PathBuf),
}
