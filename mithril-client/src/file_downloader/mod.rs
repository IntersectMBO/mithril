//! File downloader module.
//!
//! This module provides the necessary abstractions to download files from different sources.

mod http;
mod interface;
#[cfg(feature = "unstable")]
mod ipfs;
#[cfg(test)]
mod mock_builder;
mod retry;
mod streaming;

pub use http::HttpFileDownloader;
#[cfg(test)]
pub use interface::MockFileDownloader;
pub use interface::{DownloadEvent, FileDownloader, FileDownloaderUnreachable, FileDownloaderUri};
#[cfg(feature = "unstable")]
pub use ipfs::IpfsFileDownloader;
#[cfg(test)]
pub use mock_builder::{FakeAncillaryFileBuilder, MockFileDownloaderBuilder};
pub use retry::{FileDownloadRetryPolicy, RetryDownloader};
