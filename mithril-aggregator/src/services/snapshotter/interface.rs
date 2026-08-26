use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::{CompressionAlgorithm, ImmutableFileNumber};
use mithril_file_archiver::FileArchive;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
/// Define the ability to create snapshots.
pub trait Snapshotter: Sync + Send {
    /// Create a new snapshot of ancillary files.
    ///
    /// Ancillary files include the last, uncompleted, immutable trio and the two last ledger files.
    async fn snapshot_ancillary(
        &self,
        immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive>;

    /// Create a new snapshot of an immutable trio.
    async fn snapshot_immutable_trio(
        &self,
        immutable_file_number: ImmutableFileNumber,
        archive_name_without_extension: &str,
    ) -> StdResult<FileArchive>;

    /// Compute the total and average uncompressed size of all immutables up to the given immutable
    /// file number.
    async fn compute_immutable_files_total_uncompressed_size(
        &self,
        up_to_immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<u64>;

    /// Return the compression algorithm used by the snapshotter.
    fn compression_algorithm(&self) -> CompressionAlgorithm;
}
