#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "fs")]
use slog::Logger;

#[cfg(feature = "fs")]
use mithril_common::{
    crypto_helper::MKProof,
    messages::{CardanoDatabaseSnapshotMessage, CertificateMessage},
};

#[cfg(feature = "fs")]
use mithril_cardano_node_internal_database::entities::ImmutableFile;

#[cfg(feature = "fs")]
use crate::cardano_database_client::{VerifiedDigests, proving::CardanoDatabaseVerificationError};
use crate::common::{Epoch, EpochSpecifier};
#[cfg(feature = "fs")]
use crate::feedback::FeedbackSender;
#[cfg(feature = "fs")]
use crate::file_downloader::FileDownloader;
#[cfg(feature = "fs")]
use crate::utils::{AncillaryVerifier, TempDirectoryProvider};
use crate::{CardanoDatabaseSnapshot, CardanoDatabaseSnapshotListItem, MithrilResult};

use super::fetch::InternalArtifactRetriever;
use super::statistics::InternalStatisticsSender;
#[cfg(feature = "fs")]
use super::{
    DownloadUnpackOptions, ImmutableFileRange, download_unpack::InternalArtifactDownloader,
    proving::InternalArtifactProver,
};

/// HTTP client for CardanoDatabase API from the aggregator
pub struct CardanoDatabaseClient {
    pub(super) artifact_retriever: InternalArtifactRetriever,
    #[cfg(feature = "fs")]
    pub(super) artifact_downloader: InternalArtifactDownloader,
    #[cfg(feature = "fs")]
    pub(super) artifact_prover: InternalArtifactProver,
    pub(super) statistics_sender: InternalStatisticsSender,
}

/// Define the requests against an aggregator related to Cardano database v2 snapshots.
#[cfg_attr(test, mockall::automock)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CardanoDatabaseAggregatorRequest: Send + Sync {
    /// Get the list of the latest Cardano database v2 snapshots from the aggregator.
    async fn list_latest(&self) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>>;

    /// Get the list of the latest Cardano database v2 snapshots for an [EpochSpecifier] from the aggregator.
    async fn list_by_epoch(
        &self,
        specifier: EpochSpecifier,
    ) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>>;

    /// Get the details of a Cardano database v2 snapshot for a given hash from the aggregator.
    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<CardanoDatabaseSnapshot>>;

    /// Notify the aggregator that a complete Cardano database v2 restoration has been performed.
    async fn increment_cardano_database_complete_restoration_statistic(&self) -> MithrilResult<()>;

    /// Notify the aggregator that a partial Cardano database v2 restoration has been performed.
    async fn increment_cardano_database_partial_restoration_statistic(&self) -> MithrilResult<()>;

    /// Notify the aggregator that a given number of immutable files has been downloaded.
    async fn increment_immutables_snapshot_restored_statistic(
        &self,
        number_of_immutable_files_restored: u32,
    ) -> MithrilResult<()>;

    /// Notify the aggregator that a Cardano database v2 ancillary file has been downloaded.
    async fn increment_ancillary_downloaded_statistic(&self) -> MithrilResult<()>;
}

impl CardanoDatabaseClient {
    /// Constructs a new `CardanoDatabase`.
    pub fn new(
        aggregator_requester: Arc<dyn CardanoDatabaseAggregatorRequest>,
        #[cfg(feature = "fs")] http_file_downloader: Arc<dyn FileDownloader>,
        #[cfg(all(feature = "unstable", feature = "fs"))] ipfs_file_downloader: Option<
            Arc<dyn FileDownloader>,
        >,
        #[cfg(feature = "fs")] ancillary_verifier: Option<Arc<AncillaryVerifier>>,
        #[cfg(feature = "fs")] feedback_sender: FeedbackSender,
        #[cfg(feature = "fs")] temp_directory_provider: Arc<dyn TempDirectoryProvider>,
        #[cfg(feature = "fs")] logger: Logger,
    ) -> Self {
        #[cfg(feature = "fs")]
        let logger =
            mithril_common::logging::LoggerExtensions::new_with_component_name::<Self>(&logger);
        Self {
            artifact_retriever: InternalArtifactRetriever::new(aggregator_requester.clone()),
            #[cfg(feature = "fs")]
            artifact_downloader: InternalArtifactDownloader::new(
                http_file_downloader.clone(),
                #[cfg(feature = "unstable")]
                ipfs_file_downloader,
                ancillary_verifier,
                feedback_sender.clone(),
                logger.clone(),
            ),
            #[cfg(feature = "fs")]
            artifact_prover: InternalArtifactProver::new(
                http_file_downloader.clone(),
                temp_directory_provider.clone(),
                logger.clone(),
            ),
            statistics_sender: InternalStatisticsSender::new(aggregator_requester.clone()),
        }
    }

    /// Fetch a list of signed CardanoDatabase
    pub async fn list(&self) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.artifact_retriever.list().await
    }

    /// Fetch a list of signed CardanoDatabase for a given epoch
    pub async fn list_by_epoch(
        &self,
        epoch: Epoch,
    ) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.artifact_retriever.list_by_epoch(epoch).await
    }

    /// Fetch a list of signed CardanoDatabase for the latest epoch
    pub async fn list_for_latest_epoch(
        &self,
    ) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.artifact_retriever.list_for_latest_epoch().await
    }

    /// Fetch a list of signed CardanoDatabase for the latest epoch minus the given offset
    pub async fn list_for_latest_epoch_with_offset(
        &self,
        offset: u64,
    ) -> MithrilResult<Vec<CardanoDatabaseSnapshotListItem>> {
        self.artifact_retriever
            .list_for_latest_epoch_with_offset(offset)
            .await
    }

    /// Get the given Cardano database data by hash
    pub async fn get(&self, hash: &str) -> MithrilResult<Option<CardanoDatabaseSnapshot>> {
        self.artifact_retriever.get(hash).await
    }

    /// Download and unpack the given Cardano database parts data by hash.
    #[cfg(feature = "fs")]
    pub async fn download_unpack(
        &self,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
        immutable_file_range: &ImmutableFileRange,
        target_dir: &Path,
        download_unpack_options: DownloadUnpackOptions,
    ) -> MithrilResult<()> {
        self.artifact_downloader
            .download_unpack(
                cardano_database_snapshot,
                immutable_file_range,
                target_dir,
                download_unpack_options,
            )
            .await
    }

    /// Download and verify the digests against the certificate.
    #[cfg(feature = "fs")]
    pub async fn download_and_verify_digests(
        &self,
        certificate: &CertificateMessage,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
    ) -> MithrilResult<VerifiedDigests> {
        self.artifact_prover
            .download_and_verify_digests(certificate, cardano_database_snapshot)
            .await
    }

    /// Verify a local cardano database
    #[cfg(feature = "fs")]
    pub async fn verify_cardano_database(
        &self,
        certificate: &CertificateMessage,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
        immutable_file_range: &ImmutableFileRange,
        allow_missing: bool,
        database_dir: &Path,
        verified_digests: &VerifiedDigests,
    ) -> Result<MKProof, CardanoDatabaseVerificationError> {
        self.artifact_prover
            .verify_cardano_database(
                certificate,
                cardano_database_snapshot,
                immutable_file_range,
                allow_missing,
                database_dir,
                verified_digests,
            )
            .await
    }

    /// Checks if immutable directory exists with at least one immutable in it
    #[cfg(feature = "fs")]
    pub fn check_has_immutables(&self, database_dir: &Path) -> MithrilResult<()> {
        ImmutableFile::at_least_one_immutable_files_exist_in_dir(database_dir)?;
        Ok(())
    }

    /// Increments the aggregator Cardano database snapshot download statistics
    pub async fn add_statistics(
        &self,
        full_restoration: bool,
        include_ancillary: bool,
        number_of_immutable_files_restored: u64,
    ) -> MithrilResult<()> {
        self.statistics_sender
            .add_statistics(
                full_restoration,
                include_ancillary,
                number_of_immutable_files_restored,
            )
            .await
    }
}

#[cfg(test)]
pub(crate) mod test_dependency_injector {
    use super::*;

    #[cfg(feature = "fs")]
    use mithril_common::crypto_helper::ManifestVerifierVerificationKey;

    #[cfg(feature = "fs")]
    use crate::file_downloader::{FileDownloader, MockFileDownloaderBuilder};
    #[cfg(feature = "fs")]
    use crate::utils::TimestampTempDirectoryProvider;
    #[cfg(feature = "fs")]
    use crate::{feedback::FeedbackReceiver, test_utils::TestLogger};

    /// Dependency injector for `CardanoDatabaseClient` for testing purposes.
    pub(crate) struct CardanoDatabaseClientDependencyInjector {
        aggregator_requester: MockCardanoDatabaseAggregatorRequest,
        #[cfg(feature = "fs")]
        http_file_downloader: Arc<dyn FileDownloader>,
        #[cfg(all(feature = "unstable", feature = "fs"))]
        ipfs_file_downloader: Option<Arc<dyn FileDownloader>>,
        #[cfg(feature = "fs")]
        ancillary_verifier: Option<Arc<AncillaryVerifier>>,
        #[cfg(feature = "fs")]
        feedback_receivers: Vec<Arc<dyn FeedbackReceiver>>,
        #[cfg(feature = "fs")]
        temp_directory_provider: Arc<dyn TempDirectoryProvider>,
        #[cfg(feature = "fs")]
        logger: Logger,
    }

    impl CardanoDatabaseClientDependencyInjector {
        pub(crate) fn new() -> Self {
            Self {
                aggregator_requester: MockCardanoDatabaseAggregatorRequest::new(),
                #[cfg(feature = "fs")]
                http_file_downloader: Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_compression(None)
                        .with_success()
                        .with_times(0)
                        .build(),
                ),
                #[cfg(all(feature = "unstable", feature = "fs"))]
                ipfs_file_downloader: None,
                #[cfg(feature = "fs")]
                ancillary_verifier: None,
                #[cfg(feature = "fs")]
                feedback_receivers: vec![],
                #[cfg(feature = "fs")]
                temp_directory_provider: Arc::new(TimestampTempDirectoryProvider::new(
                    "cardano_database_client_test",
                )),
                #[cfg(feature = "fs")]
                logger: TestLogger::stdout(),
            }
        }

        #[cfg(feature = "fs")]
        pub(crate) fn with_logger(self, logger: Logger) -> Self {
            #[cfg(feature = "fs")]
            Self { logger, ..self }
        }

        pub(crate) fn with_aggregator_requester_mock_config<F>(mut self, config: F) -> Self
        where
            F: FnOnce(&mut MockCardanoDatabaseAggregatorRequest),
        {
            config(&mut self.aggregator_requester);

            self
        }

        #[cfg(feature = "fs")]
        pub(crate) fn with_http_file_downloader(
            self,
            http_file_downloader: Arc<dyn FileDownloader>,
        ) -> Self {
            Self {
                http_file_downloader,
                ..self
            }
        }

        #[cfg(all(feature = "unstable", feature = "fs"))]
        pub(crate) fn with_ipfs_file_downloader(
            self,
            ipfs_file_downloader: Arc<dyn FileDownloader>,
        ) -> Self {
            Self {
                ipfs_file_downloader: Some(ipfs_file_downloader),
                ..self
            }
        }

        #[cfg(feature = "fs")]
        pub(crate) fn with_ancillary_verifier<T>(self, ancillary_verification_key: T) -> Self
        where
            T: TryInto<ManifestVerifierVerificationKey>,
            T::Error: std::fmt::Debug,
        {
            Self {
                ancillary_verifier: Some(Arc::new(AncillaryVerifier::new(
                    ancillary_verification_key.try_into().unwrap(),
                ))),
                ..self
            }
        }

        #[cfg(feature = "fs")]
        pub(crate) fn with_feedback_receivers(
            self,
            feedback_receivers: &[Arc<dyn FeedbackReceiver>],
        ) -> Self {
            Self {
                feedback_receivers: feedback_receivers.to_vec(),
                ..self
            }
        }

        #[cfg(feature = "fs")]
        pub(crate) fn with_temp_directory_provider(
            self,
            temp_directory_provider: Arc<dyn TempDirectoryProvider>,
        ) -> Self {
            Self {
                temp_directory_provider,
                ..self
            }
        }

        #[cfg(feature = "fs")]
        pub(crate) fn build_cardano_database_client(self) -> CardanoDatabaseClient {
            CardanoDatabaseClient::new(
                Arc::new(self.aggregator_requester),
                self.http_file_downloader,
                #[cfg(feature = "unstable")]
                self.ipfs_file_downloader,
                self.ancillary_verifier,
                FeedbackSender::new(&self.feedback_receivers),
                self.temp_directory_provider,
                self.logger,
            )
        }

        #[cfg(not(feature = "fs"))]
        pub(crate) fn build_cardano_database_client(self) -> CardanoDatabaseClient {
            CardanoDatabaseClient::new(Arc::new(self.aggregator_requester))
        }
    }

    mod tests {
        #[cfg(feature = "fs")]
        use crate::feedback::StackFeedbackReceiver;

        use crate::common::test::Dummy;

        use super::*;

        #[cfg(feature = "fs")]
        #[test]
        fn test_cardano_database_client_dependency_injector_builds() {
            let injector = CardanoDatabaseClientDependencyInjector::new()
                .with_aggregator_requester_mock_config(|requester| {
                    let message = vec![CardanoDatabaseSnapshotListItem {
                        hash: "hash-123".to_string(),
                        ..CardanoDatabaseSnapshotListItem::dummy()
                    }];
                    requester.expect_list_latest().return_once(move || Ok(message));
                })
                .with_http_file_downloader(Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_success()
                        .with_times(0)
                        .build(),
                ))
                .with_feedback_receivers(&[Arc::new(StackFeedbackReceiver::new())]);
            #[cfg(feature = "unstable")]
            let injector = injector.with_ipfs_file_downloader(Arc::new(
                MockFileDownloaderBuilder::default()
                    .with_success()
                    .with_times(0)
                    .build(),
            ));

            injector.build_cardano_database_client();
        }

        #[cfg(not(feature = "fs"))]
        #[test]
        fn test_cardano_database_client_dependency_injector_builds() {
            let _ = CardanoDatabaseClientDependencyInjector::new()
                .with_aggregator_requester_mock_config(|requester| {
                    let message = vec![CardanoDatabaseSnapshotListItem {
                        hash: "hash-123".to_string(),
                        ..CardanoDatabaseSnapshotListItem::dummy()
                    }];
                    requester.expect_list_latest().return_once(move || Ok(message));
                })
                .build_cardano_database_client();
        }
    }
}
