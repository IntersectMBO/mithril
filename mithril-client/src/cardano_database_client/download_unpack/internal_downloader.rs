use std::collections::{BTreeSet, VecDeque};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use slog::warn;
use tokio::task::JoinSet;

#[cfg(feature = "unstable")]
use mithril_common::entities::Percentage;
use mithril_common::entities::{AncillaryLocation, ImmutableFileNumber, ImmutablesLocation};
use mithril_common::messages::{
    AncillaryMessagePart, CardanoDatabaseSnapshotMessage, ImmutablesMessagePart,
};

use crate::MithrilResult;
use crate::cardano_database_client::ImmutableFileRange;
#[cfg(feature = "unstable")]
use crate::cardano_database_client::{
    CardanoDatabaseAggregatorRequest, download_unpack::IpfsShare,
};
use crate::feedback::{FeedbackSender, MithrilEvent, MithrilEventCardanoDatabase};
use crate::file_downloader::{DownloadEvent, FileDownloader, FileDownloaderUri};
use crate::utils::{
    ANCILLARIES_NOT_SIGNED_BY_MITHRIL, AncillaryVerifier, UnexpectedDownloadedFileVerifier,
    VecDequeExtensions, create_bootstrap_node_files,
};
#[cfg(feature = "unstable")]
use crate::utils::{WeightedCoin, timestamp_seed};

use super::DownloadUnpackOptions;
#[cfg(feature = "unstable")]
use super::download_task::CircuitBreaker;
use super::download_task::{DownloadKind, DownloadTask, LocationToDownload};

/// Percentage of immutable files to download through IPFS if IPFS is enabled, but the query to
/// fetch the aggregator share fails.
#[cfg(feature = "unstable")]
const IPFS_FALLBACK_SHARE: Percentage = Percentage::new(15);

pub struct InternalArtifactDownloader {
    http_file_downloader: Arc<dyn FileDownloader>,
    #[cfg(feature = "unstable")]
    ipfs_file_downloader: Option<Arc<dyn FileDownloader>>,
    ancillary_verifier: Option<Arc<AncillaryVerifier>>,
    feedback_sender: FeedbackSender,
    logger: slog::Logger,
    #[cfg(feature = "unstable")]
    aggregator_requester: Arc<dyn CardanoDatabaseAggregatorRequest>,
}

impl InternalArtifactDownloader {
    /// Constructs a new `InternalArtifactDownloader`.
    pub fn new(
        http_file_downloader: Arc<dyn FileDownloader>,
        #[cfg(feature = "unstable")] ipfs_file_downloader: Option<Arc<dyn FileDownloader>>,
        ancillary_verifier: Option<Arc<AncillaryVerifier>>,
        feedback_sender: FeedbackSender,
        logger: slog::Logger,
        #[cfg(feature = "unstable")] aggregator_requester: Arc<
            dyn CardanoDatabaseAggregatorRequest,
        >,
    ) -> Self {
        Self {
            http_file_downloader,
            #[cfg(feature = "unstable")]
            ipfs_file_downloader,
            ancillary_verifier,
            feedback_sender,
            logger,
            #[cfg(feature = "unstable")]
            aggregator_requester,
        }
    }

    /// Download and unpack the given Cardano database parts data by hash.
    pub async fn download_unpack(
        &self,
        cardano_database_snapshot: &CardanoDatabaseSnapshotMessage,
        immutable_file_range: &ImmutableFileRange,
        target_dir: &Path,
        download_unpack_options: DownloadUnpackOptions,
        #[cfg(feature = "unstable")] ipfs_share: IpfsShare,
    ) -> MithrilResult<()> {
        let download_id = MithrilEvent::new_snapshot_download_id();
        let last_immutable_file_number = cardano_database_snapshot.beacon.immutable_file_number;
        let immutable_file_number_range =
            immutable_file_range.to_range_inclusive(last_immutable_file_number)?;
        let immutable_file_range_length =
            immutable_file_number_range.end() - immutable_file_number_range.start() + 1;
        self.feedback_sender
            .send_event(MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::Started {
                    download_id: download_id.clone(),
                    total_immutable_files: immutable_file_range_length,
                    include_ancillary: download_unpack_options.include_ancillary,
                },
            ))
            .await;
        download_unpack_options
            .verify_compatibility(&immutable_file_number_range, last_immutable_file_number)?;
        download_unpack_options.verify_can_write_to_target_directory(target_dir)?;
        if !target_dir.is_dir() {
            anyhow::bail!(
                "Target directory '{}' does not exist or is not a directory",
                target_dir.display()
            );
        }
        self.remove_stale_staging_directories(target_dir).await;

        let expected_files_after_download = UnexpectedDownloadedFileVerifier::new(
            target_dir,
            download_unpack_options.include_ancillary,
            last_immutable_file_number,
            &self.logger,
        )
        .compute_expected_state_after_download()
        .await?;

        #[cfg(feature = "unstable")]
        let locations_have_ipfs = cardano_database_snapshot
            .immutables
            .locations
            .iter()
            .any(|l| matches!(l, ImmutablesLocation::Ipfs { .. }));

        #[cfg(feature = "unstable")]
        if self.ipfs_file_downloader.is_none() && locations_have_ipfs {
            warn!(
                self.logger,
                "IPFS locations are available for immutable files but no IPFS downloader is configured (no `ipfs_rpc_base_url` set); those locations will be skipped."
            );
        }

        #[cfg(feature = "unstable")]
        let ipfs_coin = {
            let ipfs_share_percentage = self
                .expand_ipfs_share_to_percentage(ipfs_share, locations_have_ipfs)
                .await;

            WeightedCoin::new(ipfs_share_percentage, timestamp_seed())
        };

        let mut tasks = VecDeque::from(self.build_download_tasks_for_immutables(
            &cardano_database_snapshot.immutables,
            immutable_file_number_range,
            target_dir,
            &download_id,
            #[cfg(feature = "unstable")]
            ipfs_coin,
        )?);
        if download_unpack_options.include_ancillary {
            warn!(self.logger, "{}", ANCILLARIES_NOT_SIGNED_BY_MITHRIL);
            tasks.push_back(self.new_ancillary_download_task(
                &cardano_database_snapshot.ancillary,
                target_dir,
                &download_id,
            )?);
        } else {
            warn!(
                self.logger,
                "The fast bootstrap of the Cardano node is not available with the current parameters used in this command: the ledger state will be recomputed from genesis at startup of the Cardano node. Set the include_ancillary entry to true in the DownloadUnpackOptions."
            );
        }

        // Return the result later so unexpected file removal is always run
        let download_result = self
            .batch_download_unpack(tasks, download_unpack_options.max_parallel_downloads)
            .await;
        self.remove_staging_directories(target_dir, &download_id).await;
        expected_files_after_download.remove_unexpected_files().await?;
        download_result?;

        create_bootstrap_node_files(&self.logger, target_dir, &cardano_database_snapshot.network)?;

        self.feedback_sender
            .send_event(MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::Completed {
                    download_id: download_id.clone(),
                },
            ))
            .await;

        Ok(())
    }

    fn build_download_tasks_for_immutables(
        &self,
        immutable_locations: &ImmutablesMessagePart,
        immutable_file_number_range: RangeInclusive<ImmutableFileNumber>,
        target_dir: &Path,
        download_id: &str,
        #[cfg(feature = "unstable")] mut ipfs_coin: WeightedCoin,
    ) -> MithrilResult<Vec<DownloadTask>> {
        let immutable_file_numbers_to_download = immutable_file_number_range
            .map(|n| n.to_owned())
            .collect::<BTreeSet<_>>();

        if immutable_locations.locations.iter().any(Self::is_uncompressed) {
            slog::warn!(
                self.logger,
                "Uncompressed immutable locations are skipped, immutable archives must be compressed"
            );
        }

        let mut immutable_tasks = vec![];
        #[cfg(feature = "unstable")]
        let ipfs_circuit_breaker = CircuitBreaker::default();
        for immutable_file_number in immutable_file_numbers_to_download {
            immutable_tasks.push(self.new_immutable_download_task(
                immutable_locations,
                immutable_file_number,
                target_dir,
                download_id,
                #[cfg(feature = "unstable")]
                ipfs_circuit_breaker.clone(),
                #[cfg(feature = "unstable")]
                ipfs_coin.flip(),
            )?);
        }
        Ok(immutable_tasks)
    }

    /// Tell if an immutable location serves uncompressed archives, which are never downloaded.
    fn is_uncompressed(location: &ImmutablesLocation) -> bool {
        matches!(
            location,
            ImmutablesLocation::CloudStorage {
                compression_algorithm: None,
                ..
            } | ImmutablesLocation::Ipfs {
                compression_algorithm: None,
                ..
            }
        )
    }

    fn new_immutable_download_task(
        &self,
        immutable_locations: &ImmutablesMessagePart,
        immutable_file_number: ImmutableFileNumber,
        immutable_files_target_dir: &Path,
        download_id: &str,
        #[cfg(feature = "unstable")] ipfs_circuit_breaker: CircuitBreaker,
        #[cfg(feature = "unstable")] ipfs_first: bool,
    ) -> MithrilResult<DownloadTask> {
        let mut locations_sorted = immutable_locations.sanitized_locations()?;
        locations_sorted.sort();
        // IPFS locations are sorted first, move them last if they lost the coin flip.
        // Note: `sort_by_key` is stable, so the other locations keep their order.
        #[cfg(feature = "unstable")]
        if !ipfs_first {
            locations_sorted.sort_by_key(|l| matches!(l, ImmutablesLocation::Ipfs { .. }));
        }
        let locations_to_try: Vec<_> = locations_sorted
            .into_iter()
            .filter_map(|location| {
                if Self::is_uncompressed(&location) {
                    return None;
                }

                let (file_downloader, uri, compression_algorithm, circuit_breaker) = match location
                {
                    ImmutablesLocation::CloudStorage {
                        uri,
                        compression_algorithm,
                    } => (
                        self.http_file_downloader.clone(),
                        uri,
                        compression_algorithm,
                        None,
                    ),
                    #[cfg(feature = "unstable")]
                    ImmutablesLocation::Ipfs {
                        uri,
                        compression_algorithm,
                    } => (
                        self.ipfs_file_downloader.clone()?,
                        uri,
                        compression_algorithm,
                        Some(ipfs_circuit_breaker.clone()),
                    ),
                    // No IPFS downloader configured (or unstable disabled), or an `Unknown` location that
                    // `sanitized_locations` should already have filtered out — skip rather than
                    // panic, since a wrong invariant here shouldn't take the whole download down.
                    _ => return None,
                };

                Some(LocationToDownload {
                    file_downloader,
                    file_downloader_uri: FileDownloaderUri::from(
                        uri.expand_for_immutable_file_number(immutable_file_number),
                    ),
                    compression_algorithm,
                    circuit_breaker,
                })
            })
            .collect();

        if locations_to_try.is_empty() {
            anyhow::bail!(
                "No valid location found for immutable file number {immutable_file_number}",
            );
        }

        Ok(DownloadTask {
            kind: DownloadKind::Immutable(immutable_file_number),
            locations_to_try,
            target_dir: immutable_files_target_dir.to_path_buf(),
            size_uncompressed: immutable_locations.average_size_uncompressed,
            download_event: DownloadEvent::Immutable {
                download_id: download_id.to_string(),
                immutable_file_number,
            },
        })
    }

    fn new_ancillary_download_task(
        &self,
        locations: &AncillaryMessagePart,
        target_dir: &Path,
        download_id: &str,
    ) -> MithrilResult<DownloadTask> {
        let ancillary_verifier = self.ancillary_verifier.clone().with_context(
            || "ancillary verifier is not set, please use `set_ancillary_verification_key` when creating the client"
        )?;

        let mut locations_to_try = vec![];
        let mut locations_sorted = locations.sanitized_locations()?;
        locations_sorted.sort();
        for location in locations_sorted {
            let location_to_try = match location {
                AncillaryLocation::CloudStorage {
                    compression_algorithm: None,
                    ..
                } => {
                    slog::warn!(
                        self.logger,
                        "Uncompressed ancillary locations are skipped, the ancillary archive must be compressed"
                    );
                    continue;
                }
                AncillaryLocation::CloudStorage {
                    uri,
                    compression_algorithm,
                } => {
                    let file_downloader = self.http_file_downloader.clone();
                    let file_downloader_uri = FileDownloaderUri::from(uri);

                    LocationToDownload {
                        file_downloader,
                        file_downloader_uri,
                        compression_algorithm: compression_algorithm.to_owned(),
                        circuit_breaker: None,
                    }
                }
                // Note: unknown locations should have been filtered out by `sanitized_locations`
                AncillaryLocation::Unknown => unreachable!(),
            };

            locations_to_try.push(location_to_try);
        }

        if locations_to_try.is_empty() {
            anyhow::bail!("No valid location found for the ancillary files");
        }

        Ok(DownloadTask {
            kind: DownloadKind::Ancillary {
                verifier: ancillary_verifier.clone(),
            },
            locations_to_try,
            target_dir: target_dir.to_path_buf(),
            size_uncompressed: locations.size_uncompressed,
            download_event: DownloadEvent::Ancillary {
                download_id: download_id.to_string(),
            },
        })
    }

    /// Remove the staging directories of this download that a cancelled task may have left behind.
    async fn remove_staging_directories(&self, target_dir: &Path, download_id: &str) {
        self.remove_directories(target_dir, |name| {
            DownloadTask::is_staging_directory_name(name, download_id)
        })
        .await;
    }

    /// Remove the staging directories that an earlier download left behind, for instance when its
    /// process was killed.
    ///
    /// The staging directories of any download are removed, which is why only one download at a
    /// time is supported for a target directory.
    async fn remove_stale_staging_directories(&self, target_dir: &Path) {
        self.remove_directories(
            target_dir,
            DownloadTask::is_staging_directory_name_of_any_download,
        )
        .await;
    }

    /// Remove the directories of the target directory whose name is selected, warning when a
    /// removal fails.
    async fn remove_directories(&self, target_dir: &Path, is_removed: impl Fn(&str) -> bool) {
        let Ok(mut entries) = tokio::fs::read_dir(target_dir).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_removed(&name)
                && let Err(e) = tokio::fs::remove_dir_all(entry.path()).await
            {
                slog::warn!(
                    self.logger, "Failed to remove download staging directory '{}'", entry.path().display();
                    "error" => ?e
                );
            }
        }
    }

    /// Download and unpack the files in parallel.
    async fn batch_download_unpack(
        &self,
        mut tasks: VecDeque<DownloadTask>,
        max_parallel_downloads: usize,
    ) -> MithrilResult<()> {
        let mut join_set: JoinSet<MithrilResult<()>> = JoinSet::new();

        let initial_tasks_chunk = tasks.pop_up_to_n(max_parallel_downloads);
        for task in initial_tasks_chunk {
            join_set.spawn(task.build_download_future(self.logger.clone()));
        }

        while let Some(result) = join_set.join_next().await {
            let task_result = result.map_err(anyhow::Error::from).and_then(|r| r);
            if let Err(error) = task_result {
                join_set.shutdown().await;
                anyhow::bail!(error);
            }

            if let Some(task) = tasks.pop_front() {
                join_set.spawn(task.build_download_future(self.logger.clone()));
            }
        }

        Ok(())
    }

    #[cfg(feature = "unstable")]
    async fn expand_ipfs_share_to_percentage(
        &self,
        ipfs_share: IpfsShare,
        locations_have_ipfs: bool,
    ) -> Percentage {
        if !locations_have_ipfs || self.ipfs_file_downloader.is_none() {
            return Percentage::ZERO;
        }

        match ipfs_share {
            IpfsShare::Custom(percentage) => percentage,
            IpfsShare::FromAggregator => match self.aggregator_requester.get_ipfs_share().await {
                Ok(Some(percentage)) => percentage,
                Ok(None) => IPFS_FALLBACK_SHARE,
                Err(err) => {
                    warn!(self.logger, "failed to fetch IPFS share from aggregator"; "error" => ?err);
                    IPFS_FALLBACK_SHARE
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::{fs, sync::Arc};

    use mithril_common::{
        entities::{CardanoDbBeacon, Epoch, MultiFilesUri, TemplateUri},
        messages::CardanoDatabaseSnapshotMessage as CardanoDatabaseSnapshot,
        test::temp_dir_create,
    };

    use crate::cardano_database_client::CardanoDatabaseClientDependencyInjector;
    #[cfg(feature = "unstable")]
    use crate::cardano_database_client::api::MockCardanoDatabaseAggregatorRequest;
    use crate::common::test::Dummy;
    use crate::file_downloader::{MockFileDownloader, MockFileDownloaderBuilder};
    use crate::test_utils::TestLogger;

    use super::*;

    fn immutables_only_options() -> DownloadUnpackOptions {
        DownloadUnpackOptions {
            include_ancillary: false,
            ..DownloadUnpackOptions::default()
        }
    }

    fn artifact_downloader_for_test() -> InternalArtifactDownloader {
        InternalArtifactDownloader::new(
            Arc::new(MockFileDownloader::new()),
            #[cfg(feature = "unstable")]
            None,
            None,
            FeedbackSender::new(&[]),
            TestLogger::stdout(),
            #[cfg(feature = "unstable")]
            Arc::new(MockCardanoDatabaseAggregatorRequest::new()),
        )
    }

    mod download_unpack {
        use std::future::pending;
        use std::path::PathBuf;

        use anyhow::anyhow;
        use async_trait::async_trait;
        use slog::Logger;

        use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, immutable_trio_names};
        use mithril_common::StdResult;
        use mithril_common::assert_dir_eq;
        use mithril_common::crypto_helper::ManifestSigner;
        use mithril_common::entities::CompressionAlgorithm;
        use mithril_common::messages::DigestsMessagePart;

        use crate::cardano_database_client::CardanoDatabaseClient;
        use crate::file_downloader::{FakeAncillaryFileBuilder, MockFileDownloader};

        use super::*;

        fn create_fake_immutable_trio(unpack_dir: &Path, download_event: &DownloadEvent) {
            if let DownloadEvent::Immutable {
                immutable_file_number,
                ..
            } = download_event
            {
                let staged_immutable_dir = unpack_dir.join(IMMUTABLE_DIR);
                fs::create_dir_all(&staged_immutable_dir).unwrap();
                for filename in immutable_trio_names(*immutable_file_number) {
                    fs::File::create(staged_immutable_dir.join(filename)).unwrap();
                }
            }
        }

        fn cloud_storage_location(
            uri_template: &str,
            compression_algorithm: Option<CompressionAlgorithm>,
        ) -> ImmutablesLocation {
            ImmutablesLocation::CloudStorage {
                uri: MultiFilesUri::Template(TemplateUri(uri_template.to_string())),
                compression_algorithm,
            }
        }

        fn snapshot_with_immutable_locations(
            last_immutable_file_number: ImmutableFileNumber,
            locations: Vec<ImmutablesLocation>,
        ) -> CardanoDatabaseSnapshot {
            CardanoDatabaseSnapshot {
                beacon: CardanoDbBeacon {
                    immutable_file_number: last_immutable_file_number,
                    epoch: Epoch(123),
                },
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations,
                },
                ..CardanoDatabaseSnapshot::dummy()
            }
        }

        fn uncompressed_then_compressed_locations() -> Vec<ImmutablesLocation> {
            vec![
                cloud_storage_location("http://a-uncompressed/{immutable_file_number}.tar", None),
                cloud_storage_location(
                    "http://b-compressed/{immutable_file_number}.tar.zst",
                    Some(CompressionAlgorithm::Zstandard),
                ),
            ]
        }

        fn downloader_staging_valid_trios() -> MockFileDownloader {
            let mut mock_downloader = MockFileDownloader::new();
            mock_downloader.expect_download_unpack().returning(
                |_, _, unpack_dir, _, download_event| {
                    create_fake_immutable_trio(unpack_dir, &download_event);
                    Ok(())
                },
            );
            mock_downloader
        }

        fn downloader_never_called() -> MockFileDownloader {
            let mut mock_downloader = MockFileDownloader::new();
            mock_downloader.expect_download_unpack().times(0);
            mock_downloader
        }

        fn client_with_http_downloader(
            file_downloader: impl FileDownloader + 'static,
        ) -> CardanoDatabaseClient {
            CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new(file_downloader))
                .build_cardano_database_client()
        }

        fn client_ending_the_first_immutable_while_the_ancillary_download_runs(
            first_immutable_outcome: FirstImmutableOutcome,
        ) -> CardanoDatabaseClient {
            CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new(EndFirstWhenSiblingIsStagedFileDownloader {
                    first_immutable_outcome,
                    staged_downloads: 3,
                }))
                .with_ancillary_verifier(
                    ManifestSigner::create_deterministic_signer().verification_key(),
                )
                .build_cardano_database_client()
        }

        fn all_downloads_in_parallel_options() -> DownloadUnpackOptions {
            DownloadUnpackOptions {
                include_ancillary: true,
                max_parallel_downloads: 3,
                ..DownloadUnpackOptions::default()
            }
        }

        fn artifact_downloader(
            http_file_downloader: MockFileDownloader,
            logger: Logger,
        ) -> InternalArtifactDownloader {
            InternalArtifactDownloader::new(
                Arc::new(http_file_downloader),
                #[cfg(feature = "unstable")]
                None,
                None,
                FeedbackSender::new(&[]),
                logger,
                #[cfg(feature = "unstable")]
                Arc::new(MockCardanoDatabaseAggregatorRequest::new()),
            )
        }

        fn assert_no_staging_directory_is_left(target_dir: &Path) {
            let leftover = staging_directories(target_dir);
            assert!(
                leftover.is_empty(),
                "orphan staging directories: {leftover:?}"
            );
        }

        fn staging_directories(target_dir: &Path) -> Vec<PathBuf> {
            fs::read_dir(target_dir)
                .unwrap()
                .flatten()
                .filter(|entry| {
                    let name = entry.file_name().to_string_lossy().to_string();
                    name.starts_with("immutable-") || name.starts_with("ancillary-")
                })
                .map(|entry| entry.path())
                .collect()
        }

        /// How the download of the first immutable file ends once a sibling task is staged
        enum FirstImmutableOutcome {
            /// The download returns an error
            Fails,
            /// The download panics
            Panics,
        }

        /// Ends the download of the first immutable file once a sibling task has created its
        /// staging directory, the other downloads never complete.
        struct EndFirstWhenSiblingIsStagedFileDownloader {
            /// How the download of the first immutable file ends
            first_immutable_outcome: FirstImmutableOutcome,
            /// Number of staging directories that must exist before the first download ends
            staged_downloads: usize,
        }

        impl EndFirstWhenSiblingIsStagedFileDownloader {
            /// Upper bound of the scheduler yields spent waiting for the sibling staging directory
            const MAX_YIELDS: usize = 1_000_000;
        }

        #[async_trait]
        impl FileDownloader for EndFirstWhenSiblingIsStagedFileDownloader {
            async fn download_unpack(
                &self,
                _location: &FileDownloaderUri,
                _file_size: u64,
                target_dir: &Path,
                _compression_algorithm: Option<CompressionAlgorithm>,
                download_event_type: DownloadEvent,
            ) -> StdResult<()> {
                match download_event_type {
                    DownloadEvent::Immutable {
                        immutable_file_number: 0,
                        ..
                    } => {
                        let database_dir = target_dir.parent().unwrap();
                        for _ in 0..Self::MAX_YIELDS {
                            if staging_directories(database_dir).len() >= self.staged_downloads {
                                return match self.first_immutable_outcome {
                                    FirstImmutableOutcome::Fails => {
                                        Err(anyhow!("first immutable fails"))
                                    }
                                    FirstImmutableOutcome::Panics => {
                                        panic!("first immutable panics")
                                    }
                                };
                            }
                            tokio::task::yield_now().await;
                        }
                        panic!("the sibling staging directory was never created");
                    }
                    _ => pending().await,
                }
            }
        }

        #[tokio::test]
        async fn download_unpack_fails_with_invalid_immutable_file_range() {
            let immutable_file_range = ImmutableFileRange::Range(1, 0);
            let download_unpack_options = DownloadUnpackOptions::default();
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = Path::new(".");
            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            client
                .download_unpack(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    target_dir,
                    download_unpack_options,
                )
                .await
                .expect_err("download_unpack should fail");
        }

        #[tokio::test]
        async fn download_unpack_fails_when_immutable_files_download_fail() {
            let total_immutable_files = 10;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let download_unpack_options = DownloadUnpackOptions::default();
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },

                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = temp_dir_create!();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new({
                    let mut mock_downloader = MockFileDownloader::new();
                    mock_downloader
                        .expect_download_unpack()
                        .times(1..=total_immutable_files as usize)
                        .returning(|_, _, _, _, _| Err(anyhow!("Download unpack failed")));
                    mock_downloader
                }))
                .build_cardano_database_client();

            let error = client
                .download_unpack(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    download_unpack_options,
                )
                .await
                .expect_err("download_unpack should fail");

            assert!(
                error.to_string().contains("All locations failed"),
                "unexpected error: {error:?}"
            );
        }

        #[tokio::test]
        async fn download_unpack_leaves_no_staging_directory_when_a_task_panics() {
            let target_dir = temp_dir_create!();
            let client = client_with_http_downloader(EndFirstWhenSiblingIsStagedFileDownloader {
                first_immutable_outcome: FirstImmutableOutcome::Panics,
                staged_downloads: 2,
            });

            client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    DownloadUnpackOptions {
                        include_ancillary: false,
                        max_parallel_downloads: 2,
                        ..DownloadUnpackOptions::default()
                    },
                )
                .await
                .expect_err("a panicking task fails the batch");

            assert_no_staging_directory_is_left(&target_dir);
        }

        #[tokio::test]
        async fn download_unpack_leaves_no_staging_directory_when_a_task_panics_while_the_ancillary_download_runs()
         {
            let target_dir = temp_dir_create!();
            let client = client_ending_the_first_immutable_while_the_ancillary_download_runs(
                FirstImmutableOutcome::Panics,
            );

            client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    all_downloads_in_parallel_options(),
                )
                .await
                .expect_err("a panicking task fails the batch");

            assert_no_staging_directory_is_left(&target_dir);
        }

        #[tokio::test]
        async fn download_unpack_leaves_no_staging_directory_when_a_task_fails_while_the_ancillary_download_runs()
         {
            let target_dir = temp_dir_create!();
            let client = client_ending_the_first_immutable_while_the_ancillary_download_runs(
                FirstImmutableOutcome::Fails,
            );

            client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    all_downloads_in_parallel_options(),
                )
                .await
                .expect_err("a failing task fails the batch");

            assert_no_staging_directory_is_left(&target_dir);
        }

        #[tokio::test]
        async fn download_unpack_warns_once_when_an_uncompressed_immutable_location_is_listed() {
            let (logger, log_inspector) = TestLogger::memory();
            let target_dir = temp_dir_create!();
            let cardano_db_snapshot =
                snapshot_with_immutable_locations(2, uncompressed_then_compressed_locations());
            let artifact_downloader = artifact_downloader(downloader_staging_valid_trios(), logger);

            artifact_downloader
                .download_unpack(
                    &cardano_db_snapshot,
                    &ImmutableFileRange::Range(1, 2),
                    &target_dir,
                    immutables_only_options(),
                    #[cfg(feature = "unstable")]
                    IpfsShare::Custom(Percentage::ZERO),
                )
                .await
                .unwrap();

            assert_eq!(
                1,
                log_inspector
                    .search_logs("Uncompressed immutable locations are skipped")
                    .len(),
                "logs:\n{log_inspector}"
            );
        }

        #[tokio::test]
        async fn download_unpack_leaves_no_staging_directory_when_the_batch_is_aborted() {
            let target_dir = temp_dir_create!();
            let client = client_with_http_downloader(EndFirstWhenSiblingIsStagedFileDownloader {
                first_immutable_outcome: FirstImmutableOutcome::Fails,
                staged_downloads: 2,
            });

            let error = client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    DownloadUnpackOptions {
                        include_ancillary: false,
                        max_parallel_downloads: 2,
                        ..DownloadUnpackOptions::default()
                    },
                )
                .await
                .expect_err("the batch must fail");
            assert!(
                error
                    .to_string()
                    .contains("All locations failed for immutable_file_00000"),
                "the first immutable must be the failing task, got: {error:?}"
            );

            assert_no_staging_directory_is_left(&target_dir);
        }

        #[tokio::test]
        async fn download_unpack_fails_when_the_target_directory_does_not_exist() {
            let target_dir = temp_dir_create!().join("missing");
            let client = client_with_http_downloader(downloader_never_called());

            let error = client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    immutables_only_options(),
                )
                .await
                .expect_err("download_unpack must fail when the target directory does not exist");

            assert!(
                error.to_string().contains("does not exist or is not a directory"),
                "unexpected error: {error:?}"
            );

            assert!(
                !target_dir.exists(),
                "the target directory must not be created"
            );
        }

        #[tokio::test]
        async fn download_unpack_fails_before_any_download_when_the_target_is_a_file() {
            let target_dir = temp_dir_create!().join("file");
            fs::File::create(&target_dir).unwrap();
            let client = client_with_http_downloader(downloader_never_called());

            let error = client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    immutables_only_options(),
                )
                .await
                .expect_err("a target that is not a directory must be rejected");

            assert!(
                error.to_string().contains("does not exist or is not a directory"),
                "unexpected error: {error:?}"
            );
        }

        #[tokio::test]
        async fn remove_staging_directories_removes_only_the_staging_directories_of_this_download()
        {
            let target_dir = temp_dir_create!();
            for name in [
                "immutable-00001-this",
                "ancillary-this",
                "immutable-00001-other",
                IMMUTABLE_DIR,
                "notes-this",
            ] {
                fs::create_dir_all(target_dir.join(name)).unwrap();
            }
            fs::File::create(target_dir.join("immutable-00001-this").join("partial")).unwrap();
            let artifact_downloader =
                artifact_downloader(MockFileDownloader::new(), TestLogger::stdout());

            artifact_downloader
                .remove_staging_directories(&target_dir, "this")
                .await;

            assert_dir_eq!(
                &target_dir,
                format!("* {IMMUTABLE_DIR}/\n* immutable-00001-other/\n* notes-this/")
            );
        }

        #[tokio::test]
        async fn download_unpack_fails_when_the_only_immutable_location_is_uncompressed() {
            let target_dir = temp_dir_create!();
            let cardano_db_snapshot = snapshot_with_immutable_locations(
                1,
                vec![cloud_storage_location(
                    "http://whatever/{immutable_file_number}.tar",
                    None,
                )],
            );
            let client = client_with_http_downloader(downloader_never_called());

            let error = client
                .download_unpack(
                    &cardano_db_snapshot,
                    &ImmutableFileRange::Range(1, 1),
                    &target_dir,
                    immutables_only_options(),
                )
                .await
                .expect_err("an uncompressed immutable location must be rejected");

            assert!(
                error
                    .to_string()
                    .contains("No valid location found for immutable file number 1"),
                "unexpected error: {error:?}"
            );
        }

        #[tokio::test]
        async fn download_unpack_removes_a_staging_directory_that_a_task_left_behind() {
            let target_dir = temp_dir_create!();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new({
                    let mut mock_downloader = MockFileDownloader::new();
                    mock_downloader.expect_download_unpack().returning(
                        |_, _, unpack_dir, _, download_event| {
                            let left_behind_dir = unpack_dir
                                .parent()
                                .unwrap()
                                .join(format!("immutable-99999-{}", download_event.download_id()));
                            fs::create_dir_all(left_behind_dir).unwrap();
                            create_fake_immutable_trio(unpack_dir, &download_event);
                            Ok(())
                        },
                    );
                    mock_downloader
                }))
                .build_cardano_database_client();

            client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    immutables_only_options(),
                )
                .await
                .expect("the download must succeed");

            assert_no_staging_directory_is_left(&target_dir);
        }

        #[tokio::test]
        async fn download_unpack_removes_the_staging_directories_left_by_an_earlier_download() {
            let target_dir = temp_dir_create!();
            let earlier_download_id = "0c8d8ea5-7b0c-4d7d-9d7f-5a4a3b1f2e10";
            for name in [
                format!("immutable-00007-{earlier_download_id}"),
                format!("ancillary-{earlier_download_id}"),
            ] {
                fs::create_dir_all(target_dir.join(&name)).unwrap();
                fs::File::create(target_dir.join(&name).join("partial")).unwrap();
            }
            let client = client_with_http_downloader(downloader_staging_valid_trios());

            client
                .download_unpack(
                    &CardanoDatabaseSnapshot::dummy(),
                    &ImmutableFileRange::UpTo(1),
                    &target_dir,
                    DownloadUnpackOptions {
                        allow_override: true,
                        ..immutables_only_options()
                    },
                )
                .await
                .expect("the download must succeed");

            assert_dir_eq!(
                &target_dir,
                format!(
                    "* {IMMUTABLE_DIR}/
                    ** 00000.chunk
                    ** 00000.primary
                    ** 00000.secondary
                    ** 00001.chunk
                    ** 00001.primary
                    ** 00001.secondary
                    * clean
                    * protocolMagicId"
                )
            );
        }

        #[tokio::test]
        async fn download_unpack_uses_the_compressed_immutable_location_when_an_uncompressed_one_is_listed()
         {
            let target_dir = temp_dir_create!();
            let cardano_db_snapshot =
                snapshot_with_immutable_locations(1, uncompressed_then_compressed_locations());
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new({
                    let mut mock_downloader = MockFileDownloader::new();
                    mock_downloader
                        .expect_download_unpack()
                        .times(1)
                        .withf(|location, _, _, compression_algorithm, _| {
                            location.as_str() == "http://b-compressed/00001.tar.zst"
                                && *compression_algorithm == Some(CompressionAlgorithm::Zstandard)
                        })
                        .returning(|_, _, unpack_dir, _, download_event| {
                            create_fake_immutable_trio(unpack_dir, &download_event);
                            Ok(())
                        });
                    mock_downloader
                }))
                .build_cardano_database_client();

            client
                .download_unpack(
                    &cardano_db_snapshot,
                    &ImmutableFileRange::Range(1, 1),
                    &target_dir,
                    immutables_only_options(),
                )
                .await
                .expect("the compressed location must be used");
        }

        #[tokio::test]
        async fn download_unpack_fails_when_target_dir_would_be_overwritten_without_allow_override()
        {
            let immutable_file_range = ImmutableFileRange::Range(1, 10);
            let download_unpack_options = DownloadUnpackOptions::default();
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = temp_dir_create!();
            fs::create_dir_all(target_dir.join(IMMUTABLE_DIR)).unwrap();
            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            client
                .download_unpack(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    download_unpack_options,
                )
                .await
                .expect_err("download_unpack should fail");
        }

        #[tokio::test]
        async fn download_unpack_succeeds_with_valid_range() {
            let immutable_file_range = ImmutableFileRange::Range(1, 2);
            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            };
            let ancillary_signer = ManifestSigner::create_deterministic_signer();
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                beacon: CardanoDbBeacon {
                    immutable_file_number: 2,
                    epoch: Epoch(123),
                },
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },
                ancillary: AncillaryMessagePart {
                    size_uncompressed: 2048,
                    locations: vec![AncillaryLocation::CloudStorage {
                        uri: "http://whatever/ancillary.tar.zst".to_string(),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },
                digests: DigestsMessagePart {
                    size_uncompressed: 1024,
                    locations: vec![],
                },
                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = temp_dir_create!();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new({
                    MockFileDownloaderBuilder::default()
                        .with_file_uri("http://whatever/00001.tar.zst")
                        .with_success_and_create_fake_immutable_files()
                        .next_call()
                        .with_file_uri("http://whatever/00002.tar.zst")
                        .with_success_and_create_fake_immutable_files()
                        .next_call()
                        .with_file_uri("http://whatever/ancillary.tar.zst")
                        .with_compression(Some(CompressionAlgorithm::Zstandard))
                        .with_success_and_create_fake_ancillary_files(
                            FakeAncillaryFileBuilder::builder()
                                .files_in_manifest_to_create(vec!["ledger".to_string()])
                                .sign_manifest(ancillary_signer.clone())
                                .build(),
                        )
                        .build()
                }))
                .with_ancillary_verifier(ancillary_signer.verification_key())
                .build_cardano_database_client();

            client
                .download_unpack(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    download_unpack_options,
                )
                .await
                .unwrap();
        }

        #[cfg(feature = "unstable")]
        #[tokio::test]
        async fn if_ipfs_circuit_breaker_trip_later_download_switch_to_cloud_storage() {
            let immutable_file_range = ImmutableFileRange::Range(1, 3);
            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: false,
                max_parallel_downloads: 1,
                ..DownloadUnpackOptions::default()
            };
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                beacon: CardanoDbBeacon {
                    immutable_file_number: 3,
                    epoch: Epoch(123),
                },
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![
                        ImmutablesLocation::Ipfs {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "WhateverCiD/{immutable_file_number}.tar.zst".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                        ImmutablesLocation::CloudStorage {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                    ],
                },
                ancillary: AncillaryMessagePart {
                    size_uncompressed: 512,
                    locations: vec![],
                },
                digests: DigestsMessagePart {
                    size_uncompressed: 1024,
                    locations: vec![],
                },
                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = temp_dir_create!();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_ipfs_file_downloader(Arc::new({
                    MockFileDownloaderBuilder::default()
                        .with_file_uri("WhateverCiD/00001.tar.zst")
                        .with_success_and_create_fake_immutable_files()
                        .next_call()
                        .with_file_uri("WhateverCiD/00002.tar.zst")
                        // unreachable trigger the circuit breaker
                        .with_unreachable_downloader_failure("ipfs")
                        .build()
                }))
                .with_http_file_downloader(Arc::new({
                    MockFileDownloaderBuilder::default()
                        .with_file_uri("http://whatever/00002.tar.zst")
                        .with_success_and_create_fake_immutable_files()
                        .next_call()
                        .with_file_uri("http://whatever/00003.tar.zst")
                        .with_success_and_create_fake_immutable_files()
                        .build()
                }))
                .build_cardano_database_client();

            client
                .download_unpack_with_ipfs_control(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    download_unpack_options,
                    IpfsShare::Custom(Percentage::HUNDRED),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn download_unpack_remove_unexpected_downloaded_files() {
            let target_dir = temp_dir_create!();
            let immutable_dir = target_dir.join(IMMUTABLE_DIR);

            let immutable_file_range = ImmutableFileRange::UpTo(1);
            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            };
            let cardano_db_snapshot = CardanoDatabaseSnapshot::dummy();
            let client = CardanoDatabaseClientDependencyInjector::new()
                .with_http_file_downloader(Arc::new({
                    let mut mock_downloader = MockFileDownloader::new();
                    mock_downloader.expect_download_unpack().returning(
                        move |_, _, unpack_dir, _, download_event| {
                            create_fake_immutable_trio(unpack_dir, &download_event);
                            // Simulate an additional file written mid-download
                            fs::create_dir_all(&immutable_dir).unwrap();
                            fs::File::create(immutable_dir.join("unexpected.md")).unwrap();
                            Ok(())
                        },
                    );
                    mock_downloader
                }))
                .build_cardano_database_client();

            client
                .download_unpack(
                    &cardano_db_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    download_unpack_options,
                )
                .await
                .unwrap();

            assert_dir_eq!(
                &target_dir,
                format!(
                    "* {IMMUTABLE_DIR}/
                    ** 00000.chunk
                    ** 00000.primary
                    ** 00000.secondary
                    ** 00001.chunk
                    ** 00001.primary
                    ** 00001.secondary
                    * clean
                    * protocolMagicId"
                )
            );
        }

        #[tokio::test]
        async fn fail_if_include_ancillary_is_true_and_ancillary_verifier_is_not_set() {
            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: true,
                ..Default::default()
            };
            let cardano_db_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                ..CardanoDatabaseSnapshot::dummy()
            };
            let target_dir = temp_dir_create!();
            let client =
                CardanoDatabaseClientDependencyInjector::new().build_cardano_database_client();

            let error = client
                .download_unpack(
                    &cardano_db_snapshot,
                    &ImmutableFileRange::Full,
                    &target_dir,
                    download_unpack_options,
                )
                .await
                .unwrap_err();

            let expected_error_text = "ancillary verifier is not set, please use `set_ancillary_verification_key` when creating the client";
            assert!(
                error.to_string().contains(expected_error_text),
                "Expected error message to contain '{expected_error_text}', but got: {error}"
            );
        }
    }

    mod building_download_tasks {
        use mithril_common::{entities::CompressionAlgorithm, test::double::fake_keys};

        use super::*;

        fn fake_ancillary_verifier() -> AncillaryVerifier {
            AncillaryVerifier::new(fake_keys::manifest_verification_key()[0].try_into().unwrap())
        }

        #[tokio::test]
        async fn building_immutables_download_tasks_fails_if_all_locations_are_unknown() {
            let total_immutable_files = 2;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let target_dir = temp_dir_create!();
            let artifact_downloader = artifact_downloader_for_test();

            let build_tasks_result = artifact_downloader.build_download_tasks_for_immutables(
                &ImmutablesMessagePart {
                    locations: vec![ImmutablesLocation::Unknown {}],
                    average_size_uncompressed: 0,
                },
                immutable_file_range
                    .to_range_inclusive(total_immutable_files)
                    .unwrap(),
                &target_dir,
                "download_id",
                #[cfg(feature = "unstable")]
                WeightedCoin::new(Percentage::ZERO, [0; 32]),
            );

            assert!(
                build_tasks_result.is_err(),
                "building tasks should fail if all location are unknown"
            );
        }

        #[tokio::test]
        async fn building_immutables_download_tasks_fails_if_all_locations_are_ipfs_and_there_is_no_ipfs_file_downloader_set()
         {
            let total_immutable_files = 2;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                #[cfg(feature = "unstable")]
                ipfs_file_downloader: None,
                ..artifact_downloader_for_test()
            };

            let build_tasks_result = artifact_downloader.build_download_tasks_for_immutables(
                &ImmutablesMessagePart {
                    locations: vec![ImmutablesLocation::Ipfs {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "Whatever_CID/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                    average_size_uncompressed: 0,
                },
                immutable_file_range
                    .to_range_inclusive(total_immutable_files)
                    .unwrap(),
                &target_dir,
                "download_id",
                #[cfg(feature = "unstable")]
                WeightedCoin::new(Percentage::ZERO, [0; 32]),
            );

            let error = build_tasks_result.err().expect(
                "building tasks should fail if all locations are IPFS and no IPFS file downloader is set",
            );
            assert!(
                error
                    .to_string()
                    .contains("No valid location found for immutable file number"),
                "unexpected error: {error:?}"
            );
        }

        #[cfg(feature = "unstable")]
        #[tokio::test]
        async fn download_unpack_warns_once_when_ipfs_locations_are_offered_without_an_ipfs_downloader_configured()
         {
            let (logger, log_inspector) = TestLogger::memory();
            let total_immutable_files = 2;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                http_file_downloader: Arc::new(
                    MockFileDownloaderBuilder::default()
                        .with_times(total_immutable_files as usize)
                        .with_compression(Some(CompressionAlgorithm::Zstandard))
                        .with_success_and_create_fake_immutable_files()
                        .build(),
                ),
                logger,
                ..artifact_downloader_for_test()
            };
            let cardano_database_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                beacon: CardanoDbBeacon {
                    immutable_file_number: total_immutable_files,
                    epoch: Epoch(123),
                },
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![
                        ImmutablesLocation::CloudStorage {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                        ImmutablesLocation::Ipfs {
                            uri: MultiFilesUri::Template(TemplateUri(
                                "Whatever_CID/{immutable_file_number}.tar.zst".to_string(),
                            )),
                            compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                        },
                    ],
                },
                ..CardanoDatabaseSnapshot::dummy()
            };

            artifact_downloader
                .download_unpack(
                    &cardano_database_snapshot,
                    &immutable_file_range,
                    &target_dir,
                    immutables_only_options(),
                    IpfsShare::Custom(Percentage::new(10)),
                )
                .await
                .unwrap();

            let warning = "IPFS locations are available for immutable files but no IPFS downloader is configured";
            assert_eq!(1, log_inspector.search_logs(warning).len());
        }

        #[tokio::test]
        async fn download_unpack_must_warn_that_ancillary_not_signed_by_mithril_when_included() {
            let (logger, log_inspector) = TestLogger::memory();
            let total_immutable_files = 2;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                logger,
                ..artifact_downloader_for_test()
            };

            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            };
            let cardano_database_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },
                ancillary: AncillaryMessagePart {
                    size_uncompressed: 2048,
                    locations: vec![AncillaryLocation::Unknown {}],
                },
                beacon: CardanoDbBeacon {
                    epoch: Epoch(123),
                    immutable_file_number: 2,
                },
                ..CardanoDatabaseSnapshot::dummy()
            };

            let _ = artifact_downloader
                .download_unpack(
                    &cardano_database_snapshot,
                    &immutable_file_range,
                    target_dir.as_path(),
                    download_unpack_options,
                    #[cfg(feature = "unstable")]
                    IpfsShare::Custom(Percentage::ZERO),
                )
                .await;

            assert!(
                log_inspector.contains_log(&format!("WARN {ANCILLARIES_NOT_SIGNED_BY_MITHRIL}")),
            );
        }

        #[tokio::test]
        async fn download_unpack_without_ancillary_must_warn_that_fast_boostrap_wont_be_available()
        {
            let (logger, log_inspector) = TestLogger::memory();
            let total_immutable_files = 2;
            let immutable_file_range = ImmutableFileRange::Range(1, total_immutable_files);
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                logger,
                ..artifact_downloader_for_test()
            };

            let download_unpack_options = DownloadUnpackOptions {
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            };
            let cardano_database_snapshot = CardanoDatabaseSnapshot {
                hash: "hash-123".to_string(),
                immutables: ImmutablesMessagePart {
                    average_size_uncompressed: 512,
                    locations: vec![ImmutablesLocation::CloudStorage {
                        uri: MultiFilesUri::Template(TemplateUri(
                            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
                        )),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    }],
                },
                ancillary: AncillaryMessagePart {
                    size_uncompressed: 2048,
                    locations: vec![AncillaryLocation::Unknown {}],
                },
                beacon: CardanoDbBeacon {
                    epoch: Epoch(123),
                    immutable_file_number: 2,
                },
                ..CardanoDatabaseSnapshot::dummy()
            };

            let _ = artifact_downloader
                .download_unpack(
                    &cardano_database_snapshot,
                    &immutable_file_range,
                    target_dir.as_path(),
                    download_unpack_options,
                    #[cfg(feature = "unstable")]
                    IpfsShare::Custom(Percentage::ZERO),
                )
                .await;

            assert!(
                log_inspector.contains_log("The fast bootstrap of the Cardano node is not available with the current parameters used in this command: the ledger state will be recomputed from genesis at startup of the Cardano node. Set the include_ancillary entry to true in the DownloadUnpackOptions."),
            );
        }

        #[tokio::test]
        async fn building_ancillary_download_tasks_skips_uncompressed_locations() {
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                ancillary_verifier: Some(Arc::new(fake_ancillary_verifier())),
                ..artifact_downloader_for_test()
            };

            let task = artifact_downloader
                .new_ancillary_download_task(
                    &AncillaryMessagePart {
                        locations: vec![
                            AncillaryLocation::CloudStorage {
                                uri: "http://a-uncompressed/ancillary.tar".to_string(),
                                compression_algorithm: None,
                            },
                            AncillaryLocation::CloudStorage {
                                uri: "http://b-compressed/ancillary.tar.zst".to_string(),
                                compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                            },
                        ],
                        size_uncompressed: 0,
                    },
                    &target_dir,
                    "download_id",
                )
                .unwrap();

            assert_eq!(
                vec!["http://b-compressed/ancillary.tar.zst"],
                task.locations_to_try
                    .iter()
                    .map(|location| location.file_downloader_uri.as_str())
                    .collect::<Vec<_>>()
            );
        }

        #[tokio::test]
        async fn building_ancillary_download_tasks_fails_if_all_locations_are_uncompressed() {
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                ancillary_verifier: Some(Arc::new(fake_ancillary_verifier())),
                ..artifact_downloader_for_test()
            };

            let error = artifact_downloader
                .new_ancillary_download_task(
                    &AncillaryMessagePart {
                        locations: vec![AncillaryLocation::CloudStorage {
                            uri: "http://a-uncompressed/ancillary.tar".to_string(),
                            compression_algorithm: None,
                        }],
                        size_uncompressed: 0,
                    },
                    &target_dir,
                    "download_id",
                )
                .err()
                .expect("an uncompressed ancillary location must not be downloaded");

            assert!(
                error
                    .to_string()
                    .contains("No valid location found for the ancillary files"),
                "unexpected error: {error:?}"
            );
        }

        #[tokio::test]
        async fn building_ancillary_download_tasks_fails_if_all_locations_are_unknown() {
            let target_dir = temp_dir_create!();
            let artifact_downloader = InternalArtifactDownloader {
                ancillary_verifier: Some(Arc::new(fake_ancillary_verifier())),
                ..artifact_downloader_for_test()
            };

            let build_tasks_result = artifact_downloader.new_ancillary_download_task(
                &AncillaryMessagePart {
                    locations: vec![AncillaryLocation::Unknown {}],
                    size_uncompressed: 0,
                },
                &target_dir,
                "download_id",
            );

            assert!(
                build_tasks_result.is_err(),
                "building tasks should fail if all location are unknown"
            );
        }
    }

    #[cfg(feature = "unstable")]
    mod ordering_ipfs_location {
        use mithril_common::entities::CompressionAlgorithm;

        use super::*;

        fn immutable_locations() -> ImmutablesMessagePart {
            let template_uri = |uri: &str| {
                MultiFilesUri::Template(TemplateUri(format!(
                    "{uri}/{{immutable_file_number}}.tar.zst"
                )))
            };

            ImmutablesMessagePart {
                locations: vec![
                    ImmutablesLocation::CloudStorage {
                        uri: template_uri("http://b"),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    },
                    ImmutablesLocation::Ipfs {
                        uri: template_uri("ipfs"),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    },
                    ImmutablesLocation::CloudStorage {
                        uri: template_uri("http://a"),
                        compression_algorithm: Some(CompressionAlgorithm::Zstandard),
                    },
                ],
                average_size_uncompressed: 0,
            }
        }

        fn artifact_downloader_with_ipfs() -> InternalArtifactDownloader {
            InternalArtifactDownloader {
                ipfs_file_downloader: Some(Arc::new(MockFileDownloader::new())),
                ..artifact_downloader_for_test()
            }
        }

        fn locations_uris(task: &DownloadTask) -> Vec<&str> {
            task.locations_to_try
                .iter()
                .map(|location| location.file_downloader_uri.as_str())
                .collect()
        }

        #[test]
        fn ipfs_location_is_tried_first_when_it_wins_the_coin_flip() {
            let target_dir = temp_dir_create!();
            let artifact_downloader = artifact_downloader_with_ipfs();
            let coin_flip_result = true;

            let task = artifact_downloader
                .new_immutable_download_task(
                    &immutable_locations(),
                    1,
                    &target_dir,
                    "download_id",
                    CircuitBreaker::default(),
                    coin_flip_result,
                )
                .unwrap();

            assert_eq!(
                vec![
                    "ipfs/00001.tar.zst",
                    "http://a/00001.tar.zst",
                    "http://b/00001.tar.zst"
                ],
                locations_uris(&task)
            );
        }

        #[test]
        fn ipfs_location_is_tried_last_when_it_loses_the_coin_flip() {
            let target_dir = temp_dir_create!();
            let artifact_downloader = artifact_downloader_with_ipfs();
            let coin_flip_result = false;

            let task = artifact_downloader
                .new_immutable_download_task(
                    &immutable_locations(),
                    1,
                    &target_dir,
                    "download_id",
                    CircuitBreaker::default(),
                    coin_flip_result,
                )
                .unwrap();

            assert_eq!(
                vec![
                    "http://a/00001.tar.zst",
                    "http://b/00001.tar.zst",
                    "ipfs/00001.tar.zst"
                ],
                locations_uris(&task)
            );
        }

        #[test]
        fn building_immutables_download_tasks_put_ipfs_first_following_the_coin_flips() {
            let total_immutable_files = 20;
            let target_dir = temp_dir_create!();
            let artifact_downloader = artifact_downloader_with_ipfs();
            let seed = [3; 32];
            let mut reference_coin = WeightedCoin::new(Percentage::new(50), seed);

            let tasks = artifact_downloader
                .build_download_tasks_for_immutables(
                    &immutable_locations(),
                    1..=total_immutable_files,
                    &target_dir,
                    "download_id",
                    WeightedCoin::new(Percentage::new(50), seed),
                )
                .unwrap();

            let expected_ipfs_first: Vec<bool> =
                (1..=total_immutable_files).map(|_| reference_coin.flip()).collect();
            let ipfs_first: Vec<bool> = tasks
                .iter()
                .map(|task| locations_uris(task)[0].starts_with("ipfs/"))
                .collect();
            assert_eq!(expected_ipfs_first, ipfs_first);
        }
    }

    #[cfg(feature = "unstable")]
    mod expanding_ipfs_share {
        use anyhow::anyhow;

        use mithril_common::test::mock_extensions::MockBuilder;

        use super::*;

        fn artifact_downloader_with_ipfs(
            aggregator_requester_config: impl FnOnce(&mut MockCardanoDatabaseAggregatorRequest),
        ) -> InternalArtifactDownloader {
            InternalArtifactDownloader {
                ipfs_file_downloader: Some(Arc::new(MockFileDownloader::new())),
                aggregator_requester: MockBuilder::configure(aggregator_requester_config),
                ..artifact_downloader_for_test()
            }
        }

        #[tokio::test]
        async fn fetch_share_from_aggregator_if_no_custom_share_is_provided() {
            let locations_have_ipfs = true;
            let artifact_downloader = artifact_downloader_with_ipfs(|mock| {
                mock.expect_get_ipfs_share()
                    .returning(|| Ok(Some(Percentage::new(57))))
                    .once();
            });

            let expanded = artifact_downloader
                .expand_ipfs_share_to_percentage(IpfsShare::FromAggregator, locations_have_ipfs)
                .await;

            assert_eq!(Percentage::new(57), expanded);
        }

        #[tokio::test]
        async fn use_fallback_share_if_aggregator_does_not_advertise_a_share() {
            let locations_have_ipfs = true;
            let artifact_downloader = artifact_downloader_with_ipfs(|mock| {
                mock.expect_get_ipfs_share().returning(|| Ok(None)).once();
            });

            let expanded = artifact_downloader
                .expand_ipfs_share_to_percentage(IpfsShare::FromAggregator, locations_have_ipfs)
                .await;

            assert_eq!(IPFS_FALLBACK_SHARE, expanded);
        }

        #[tokio::test]
        async fn log_warning_and_use_fallback_share_if_fetching_aggregator_share_fails() {
            let locations_have_ipfs = true;
            let (logger, log_inspector) = TestLogger::memory();
            let artifact_downloader = InternalArtifactDownloader {
                logger,
                ..artifact_downloader_with_ipfs(|mock| {
                    mock.expect_get_ipfs_share()
                        .returning(|| Err(anyhow!("failed to fetch from aggregator")))
                        .once();
                })
            };

            let expanded = artifact_downloader
                .expand_ipfs_share_to_percentage(IpfsShare::FromAggregator, locations_have_ipfs)
                .await;

            assert_eq!(IPFS_FALLBACK_SHARE, expanded);
            assert!(log_inspector.contains_log("WARN failed to fetch IPFS share from aggregator"));
        }

        #[tokio::test]
        async fn use_provided_share_without_network_call_if_a_custom_value_is_provided() {
            let locations_have_ipfs = true;
            let artifact_downloader = artifact_downloader_with_ipfs(|mock| {
                mock.expect_get_ipfs_share().never();
            });

            let expanded = artifact_downloader
                .expand_ipfs_share_to_percentage(
                    IpfsShare::Custom(Percentage::new(63)),
                    locations_have_ipfs,
                )
                .await;

            assert_eq!(Percentage::new(63), expanded);
        }

        #[tokio::test]
        async fn return_share_0_if_locations_does_not_have_ipfs() {
            let locations_have_ipfs = false;
            let artifact_downloader = artifact_downloader_with_ipfs(|mock| {
                mock.expect_get_ipfs_share().never();
            });

            let expanded = artifact_downloader
                .expand_ipfs_share_to_percentage(
                    IpfsShare::Custom(Percentage::new(63)),
                    locations_have_ipfs,
                )
                .await;

            assert_eq!(Percentage::ZERO, expanded);
        }

        #[tokio::test]
        async fn return_share_0_if_no_ipfs_downloader_is_set() {
            let locations_have_ipfs = true;
            let artifact_downloader = InternalArtifactDownloader {
                ipfs_file_downloader: None,
                ..artifact_downloader_with_ipfs(|mock| {
                    mock.expect_get_ipfs_share().never();
                })
            };

            let expanded_with_custom_share = artifact_downloader
                .expand_ipfs_share_to_percentage(
                    IpfsShare::Custom(Percentage::new(63)),
                    locations_have_ipfs,
                )
                .await;
            assert_eq!(Percentage::ZERO, expanded_with_custom_share);

            let expanded_with_aggregator_share = artifact_downloader
                .expand_ipfs_share_to_percentage(IpfsShare::FromAggregator, locations_have_ipfs)
                .await;
            assert_eq!(Percentage::ZERO, expanded_with_aggregator_share);
        }
    }
}
