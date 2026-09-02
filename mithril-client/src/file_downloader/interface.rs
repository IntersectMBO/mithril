use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use anyhow::anyhow;
use async_trait::async_trait;

use mithril_common::{
    StdError, StdResult,
    entities::{
        AncillaryLocation, CompressionAlgorithm, DigestLocation, FileUri, ImmutableFileNumber,
    },
};

use crate::feedback::{MithrilEvent, MithrilEventCardanoDatabase};

/// A file downloader URI
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FileDownloaderUri {
    /// A single file URI
    FileUri(FileUri),
}

impl FileDownloaderUri {
    /// Get the URI as a string
    pub fn as_str(&self) -> &str {
        match self {
            FileDownloaderUri::FileUri(file_uri) => file_uri.0.as_str(),
        }
    }
}

impl From<String> for FileDownloaderUri {
    fn from(location: String) -> Self {
        Self::FileUri(FileUri(location))
    }
}

impl From<FileUri> for FileDownloaderUri {
    fn from(file_uri: FileUri) -> Self {
        Self::FileUri(file_uri)
    }
}

impl TryFrom<AncillaryLocation> for FileDownloaderUri {
    type Error = StdError;

    fn try_from(location: AncillaryLocation) -> Result<Self, Self::Error> {
        match location {
            AncillaryLocation::CloudStorage {
                uri,
                compression_algorithm: _,
            } => Ok(Self::FileUri(FileUri(uri))),
            AncillaryLocation::Unknown => {
                Err(anyhow!("Unknown location type to download ancillary"))
            }
        }
    }
}

impl TryFrom<DigestLocation> for FileDownloaderUri {
    type Error = StdError;

    fn try_from(location: DigestLocation) -> Result<Self, Self::Error> {
        match location {
            DigestLocation::CloudStorage {
                uri,
                compression_algorithm: _,
            }
            | DigestLocation::Aggregator { uri } => Ok(Self::FileUri(FileUri(uri))),
            DigestLocation::Unknown => Err(anyhow!("Unknown location type to download digest")),
        }
    }
}

/// A download event
///
/// The `download_id` is a unique identifier that allow
/// [feedback receivers][crate::feedback::FeedbackReceiver] to track concurrent downloads.
#[derive(Debug, Clone)]
pub enum DownloadEvent {
    /// Immutable file download
    Immutable {
        /// Unique download identifier
        download_id: String,
        /// Immutable file number
        immutable_file_number: ImmutableFileNumber,
    },
    /// Ancillary file download
    Ancillary {
        /// Unique download identifier
        download_id: String,
    },
    /// Digest file download
    Digest {
        /// Unique download identifier
        download_id: String,
    },
    /// Database download of all immutable files together
    Full {
        /// Unique download identifier
        download_id: String,
        /// Digest of the downloaded snapshot
        digest: String,
    },
    /// Download of the ancillary file associated with a full immutables download
    FullAncillary {
        /// Unique download identifier
        download_id: String,
    },
}

impl DownloadEvent {
    /// Get the unique download identifier
    pub fn download_id(&self) -> &str {
        match self {
            DownloadEvent::Immutable { download_id, .. }
            | DownloadEvent::Ancillary { download_id }
            | DownloadEvent::Digest { download_id }
            | DownloadEvent::Full { download_id, .. }
            | DownloadEvent::FullAncillary { download_id } => download_id,
        }
    }

    /// Build a download started event
    pub fn build_download_started_event(&self, size: u64) -> MithrilEvent {
        match self {
            DownloadEvent::Immutable {
                download_id,
                immutable_file_number,
            } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadStarted {
                    download_id: download_id.to_string(),
                    immutable_file_number: *immutable_file_number,
                    size,
                },
            ),
            DownloadEvent::Ancillary { download_id } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadStarted {
                    download_id: download_id.to_string(),
                    size,
                },
            ),
            DownloadEvent::Digest { download_id } => {
                MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadStarted {
                    download_id: download_id.to_string(),
                    size,
                })
            }
            DownloadEvent::Full {
                download_id,
                digest,
            } => MithrilEvent::SnapshotDownloadStarted {
                download_id: download_id.to_string(),
                digest: digest.to_string(),
                size,
            },
            DownloadEvent::FullAncillary { download_id } => {
                MithrilEvent::SnapshotAncillaryDownloadStarted {
                    download_id: download_id.to_string(),
                    size,
                }
            }
        }
    }

    /// Build a download started event
    pub fn build_download_progress_event(
        &self,
        downloaded_bytes: u64,
        total_bytes: u64,
    ) -> MithrilEvent {
        match self {
            DownloadEvent::Immutable {
                immutable_file_number,
                download_id,
            } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadProgress {
                    download_id: download_id.to_string(),
                    downloaded_bytes,
                    size: total_bytes,
                    immutable_file_number: *immutable_file_number,
                },
            ),
            DownloadEvent::Ancillary { download_id } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadProgress {
                    download_id: download_id.to_string(),
                    downloaded_bytes,
                    size: total_bytes,
                },
            ),
            DownloadEvent::Digest { download_id } => {
                MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadProgress {
                    download_id: download_id.to_string(),
                    downloaded_bytes,
                    size: total_bytes,
                })
            }
            DownloadEvent::Full { download_id, .. } => MithrilEvent::SnapshotDownloadProgress {
                download_id: download_id.to_string(),
                downloaded_bytes,
                size: total_bytes,
            },
            DownloadEvent::FullAncillary { download_id } => {
                MithrilEvent::SnapshotAncillaryDownloadProgress {
                    download_id: download_id.to_string(),
                    downloaded_bytes,
                    size: total_bytes,
                }
            }
        }
    }

    /// Build a download completed event
    pub fn build_download_completed_event(&self) -> MithrilEvent {
        match self {
            DownloadEvent::Immutable {
                download_id,
                immutable_file_number,
            } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadCompleted {
                    download_id: download_id.to_string(),
                    immutable_file_number: *immutable_file_number,
                },
            ),
            DownloadEvent::Ancillary { download_id } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadCompleted {
                    download_id: download_id.to_string(),
                },
            ),
            DownloadEvent::Digest { download_id } => MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::DigestDownloadCompleted {
                    download_id: download_id.to_string(),
                },
            ),
            DownloadEvent::Full { download_id, .. } => MithrilEvent::SnapshotDownloadCompleted {
                download_id: download_id.to_string(),
            },
            DownloadEvent::FullAncillary { download_id, .. } => {
                MithrilEvent::SnapshotAncillaryDownloadCompleted {
                    download_id: download_id.to_string(),
                }
            }
        }
    }
}

/// A file downloader
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait FileDownloader: Sync + Send {
    /// Download and unpack (if necessary) a file on the disk.
    ///
    async fn download_unpack(
        &self,
        location: &FileDownloaderUri,
        file_size: u64,
        target_dir: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
        download_event_type: DownloadEvent,
    ) -> StdResult<()>;
}

/// Error raised by [FileDownloader] when a location could not be reached
#[derive(Debug, PartialEq, Eq)]
pub struct FileDownloaderUnreachable {
    /// Name of the unreachable download source.
    pub source: &'static str,
    /// URI that could not be reached.
    pub uri: String,
}

impl Error for FileDownloaderUnreachable {}

impl Display for FileDownloaderUnreachable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Self { source, uri } = self;
        write!(f, "{source} downloader unreachable, uri: '{uri}'",)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_event_type_builds_started_event() {
        let download_event_type = DownloadEvent::Immutable {
            download_id: "download-123".to_string(),
            immutable_file_number: 123,
        };
        let event = download_event_type.build_download_started_event(1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::ImmutableDownloadStarted {
                immutable_file_number: 123,
                download_id: "download-123".to_string(),
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Ancillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_started_event(1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::AncillaryDownloadStarted {
                download_id: "download-123".to_string(),
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Digest {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_started_event(1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadStarted {
                download_id: "download-123".to_string(),
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Full {
            download_id: "download-123".to_string(),
            digest: "digest-123".to_string(),
        };
        let event = download_event_type.build_download_started_event(1234);
        assert_eq!(
            MithrilEvent::SnapshotDownloadStarted {
                digest: "digest-123".to_string(),
                download_id: "download-123".to_string(),
                size: 1234,
            },
            event,
        );

        let download_event_type = DownloadEvent::FullAncillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_started_event(1234);
        assert_eq!(
            MithrilEvent::SnapshotAncillaryDownloadStarted {
                download_id: "download-123".to_string(),
                size: 1234,
            },
            event,
        );
    }

    #[test]
    fn download_event_type_builds_progress_event() {
        let download_event_type = DownloadEvent::Immutable {
            download_id: "download-123".to_string(),
            immutable_file_number: 123,
        };
        let event = download_event_type.build_download_progress_event(123, 1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::ImmutableDownloadProgress {
                immutable_file_number: 123,
                download_id: "download-123".to_string(),
                downloaded_bytes: 123,
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Ancillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_progress_event(123, 1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::AncillaryDownloadProgress {
                download_id: "download-123".to_string(),
                downloaded_bytes: 123,
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Digest {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_progress_event(123, 1234);
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadProgress {
                download_id: "download-123".to_string(),
                downloaded_bytes: 123,
                size: 1234,
            }),
            event,
        );

        let download_event_type = DownloadEvent::Full {
            download_id: "download-123".to_string(),
            digest: "whatever".to_string(),
        };
        let event = download_event_type.build_download_progress_event(123, 1234);
        assert_eq!(
            MithrilEvent::SnapshotDownloadProgress {
                download_id: "download-123".to_string(),
                downloaded_bytes: 123,
                size: 1234,
            },
            event,
        );

        let download_event_type = DownloadEvent::FullAncillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_progress_event(123, 1234);
        assert_eq!(
            MithrilEvent::SnapshotAncillaryDownloadProgress {
                download_id: "download-123".to_string(),
                downloaded_bytes: 123,
                size: 1234,
            },
            event,
        );
    }

    #[test]
    fn file_downloader_uri_from_ancillary_location() {
        let location = AncillaryLocation::CloudStorage {
            uri: "http://whatever/ancillary-1".to_string(),
            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
        };
        let file_downloader_uri: FileDownloaderUri = location.try_into().unwrap();

        assert_eq!(
            FileDownloaderUri::FileUri(FileUri("http://whatever/ancillary-1".to_string())),
            file_downloader_uri
        );
    }
    #[test]
    fn file_downloader_uri_from_unknown_ancillary_location() {
        let location = AncillaryLocation::Unknown;
        let file_downloader_uri: StdResult<FileDownloaderUri> = location.try_into();

        file_downloader_uri.expect_err("try_into should fail on Unknown ancillary location");
    }

    #[test]
    fn file_downloader_uri_from_digest_location() {
        let location = DigestLocation::CloudStorage {
            uri: "http://whatever/digest-1".to_string(),
            compression_algorithm: None,
        };
        let file_downloader_uri: FileDownloaderUri = location.try_into().unwrap();

        assert_eq!(
            FileDownloaderUri::FileUri(FileUri("http://whatever/digest-1".to_string())),
            file_downloader_uri
        );
    }
    #[test]
    fn file_downloader_uri_from_unknown_digest_location() {
        let location = DigestLocation::Unknown;
        let file_downloader_uri: StdResult<FileDownloaderUri> = location.try_into();

        file_downloader_uri.expect_err("try_into should fail on Unknown digest location");
    }

    #[test]
    fn download_event_type_builds_completed_event() {
        let download_event_type = DownloadEvent::Immutable {
            download_id: "download-123".to_string(),
            immutable_file_number: 123,
        };
        let event = download_event_type.build_download_completed_event();
        assert_eq!(
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadCompleted {
                    immutable_file_number: 123,
                    download_id: "download-123".to_string()
                }
            ),
            event,
        );

        let download_event_type = DownloadEvent::Ancillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_completed_event();
        assert_eq!(
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadCompleted {
                    download_id: "download-123".to_string(),
                }
            ),
            event,
        );

        let download_event_type = DownloadEvent::Digest {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_completed_event();
        assert_eq!(
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadCompleted {
                download_id: "download-123".to_string(),
            }),
            event,
        );

        let download_event_type = DownloadEvent::Full {
            download_id: "download-123".to_string(),
            digest: "whatever".to_string(),
        };
        let event = download_event_type.build_download_completed_event();
        assert_eq!(
            MithrilEvent::SnapshotDownloadCompleted {
                download_id: "download-123".to_string(),
            },
            event,
        );

        let download_event_type = DownloadEvent::FullAncillary {
            download_id: "download-123".to_string(),
        };
        let event = download_event_type.build_download_completed_event();
        assert_eq!(
            MithrilEvent::SnapshotAncillaryDownloadCompleted {
                download_id: "download-123".to_string(),
            },
            event,
        );
    }
}
