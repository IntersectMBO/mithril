//! # Long task feedbacks
//!
//! Even with fast computer and network, some tasks can take more than a few
//! seconds to run (or even more than an hour for a snapshot download).
//!
//! Those tasks are:
//! - Snapshot download
//! - Certificate chain validation
//!
//! In order to have feedbacks for those tasks, a mechanism is available.
//!
//! Define your feedback receiver and implement the [FeedbackReceiver] trait to receive
//! [events][MithrilEvent] with the [`handle_event`][FeedbackReceiver::handle_event] method.
//! Then pass an instance of your receiver when building your `Client` using
//! [`ClientBuilder::add_feedback_receiver`][crate::ClientBuilder::add_feedback_receiver] method.
//!
//! # Example
//!
//! Using the provided [SlogFeedbackReceiver] to log the events using a [slog] logger.
//!
//! ```no_run
//! use std::sync::Arc;
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::{ClientBuilder, MessageBuilder, feedback::SlogFeedbackReceiver};
//!
//! let client = ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY")
//!     .add_feedback_receiver(Arc::new(SlogFeedbackReceiver::new(build_logger())))
//!     .build()?;
//!
//! let _ = client.certificate().verify_chain("CERTIFICATE_HASH").await?;
//! #
//! #    Ok(())
//! # }
//!
//! pub fn build_logger() -> slog::Logger {
//!   use slog::Drain;
//!   let decorator = slog_term::TermDecorator::new().build();
//!   let drain = slog_term::FullFormat::new(decorator).build().fuse();
//!   let drain = slog_async::Async::new(drain).build().fuse();
//!
//!   slog::Logger::root(Arc::new(drain), slog::o!())
//! }
//! ```
//!
//! Running this code should yield the following logs (example run on _pre-release-preview_):
//!
//! ```shell
//! Nov 08 14:41:40.436 INFO Certificate chain validation started, certificate_chain_validation_id: ab623989-b0ac-4031-8522-1370958bbb4e
//! Nov 08 14:41:40.626 INFO Certificate validated, certificate_chain_validation_id: ab623989-b0ac-4031-8522-1370958bbb4e, certificate_hash: dd4d4299cfb817b5ee5987c3de7cf5f13bdcda69c968ef087effd550470dc081
//! Nov 08 14:42:05.477 INFO Certificate validated, certificate_chain_validation_id: ab623989-b0ac-4031-8522-1370958bbb4e, certificate_hash: 660b3d426a95303254bb255a56bed443616ea63c4d721ea77433b920d7ebdf62
//! Nov 08 14:42:05.477 INFO Certificate chain validated, certificate_chain_validation_id: ab623989-b0ac-4031-8522-1370958bbb4e
//! ```

use async_trait::async_trait;
use mithril_common::entities::ImmutableFileNumber;
use serde::Serialize;
use slog::{Logger, info};
use std::sync::{Arc, RwLock};
use strum::Display;
use uuid::Uuid;

/// Event that can be reported by a [FeedbackReceiver] for Cardano database related events.
#[derive(Debug, Clone, Eq, PartialEq, Display, Serialize)]
#[strum(serialize_all = "PascalCase")]
#[serde(untagged)]
pub enum MithrilEventCardanoDatabase {
    /// Cardano Database download sequence started
    Started {
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Total number of immutable files
        total_immutable_files: u64,
        /// Total number of ancillary files
        include_ancillary: bool,
    },
    /// Cardano Database download sequence completed
    Completed {
        /// Unique identifier used to track a cardano database download
        download_id: String,
    },
    /// An immutable archive file download has started
    ImmutableDownloadStarted {
        /// Immutable file number downloaded
        immutable_file_number: ImmutableFileNumber,
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Size of the downloaded archive
        size: u64,
    },
    /// An immutable archive file download is in progress
    ImmutableDownloadProgress {
        /// Immutable file number downloaded
        immutable_file_number: ImmutableFileNumber,
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Number of bytes that have been downloaded
        downloaded_bytes: u64,
        /// Size of the downloaded archive
        size: u64,
    },
    /// An immutable archive file download has completed
    ImmutableDownloadCompleted {
        /// Immutable file number downloaded
        immutable_file_number: ImmutableFileNumber,
        /// Unique identifier used to track a cardano database download
        download_id: String,
    },
    /// An ancillary archive file download has started
    AncillaryDownloadStarted {
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Size of the downloaded archive
        size: u64,
    },
    /// An ancillary archive file download is in progress
    AncillaryDownloadProgress {
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Number of bytes that have been downloaded
        downloaded_bytes: u64,
        /// Size of the downloaded archive
        size: u64,
    },
    /// An ancillary archive file download has completed
    AncillaryDownloadCompleted {
        /// Unique identifier used to track a cardano database download
        download_id: String,
    },
    /// A digest file download has started
    DigestDownloadStarted {
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A digest file download is in progress
    DigestDownloadProgress {
        /// Unique identifier used to track a cardano database download
        download_id: String,
        /// Number of bytes that have been downloaded
        downloaded_bytes: u64,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A digest file download has completed
    DigestDownloadCompleted {
        /// Unique identifier used to track a cardano database download
        download_id: String,
    },
}

/// Event that can be reported by a [FeedbackReceiver].
#[derive(Debug, Clone, Eq, PartialEq, Display, Serialize)]
#[strum(serialize_all = "PascalCase")]
#[serde(untagged)]
pub enum MithrilEvent {
    /// A snapshot download has started
    SnapshotDownloadStarted {
        /// Digest of the downloaded snapshot
        digest: String,
        /// Unique identifier used to track this specific snapshot download
        download_id: String,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A snapshot download is in progress
    SnapshotDownloadProgress {
        /// Unique identifier used to track this specific snapshot download
        download_id: String,
        /// Number of bytes that have been downloaded
        downloaded_bytes: u64,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A snapshot download has completed
    SnapshotDownloadCompleted {
        /// Unique identifier used to track this specific snapshot download
        download_id: String,
    },
    /// A snapshot ancillary download has started
    SnapshotAncillaryDownloadStarted {
        /// Unique identifier used to track this specific snapshot ancillary download
        download_id: String,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A snapshot ancillary download is in progress
    SnapshotAncillaryDownloadProgress {
        /// Unique identifier used to track this specific snapshot ancillary download
        download_id: String,
        /// Number of bytes that have been downloaded
        downloaded_bytes: u64,
        /// Size of the downloaded archive
        size: u64,
    },
    /// A snapshot ancillary download has completed
    SnapshotAncillaryDownloadCompleted {
        /// Unique identifier used to track this specific snapshot ancillary download
        download_id: String,
    },

    /// Cardano database related events
    CardanoDatabase(MithrilEventCardanoDatabase),

    /// A certificate chain validation has started
    CertificateChainValidationStarted {
        /// Unique identifier used to track this specific certificate chain validation
        certificate_chain_validation_id: String,
    },
    /// An individual certificate of a chain have been validated.
    CertificateValidated {
        /// Unique identifier used to track this specific certificate chain validation
        certificate_chain_validation_id: String,
        /// The validated certificate hash
        certificate_hash: String,
    },
    /// An individual certificate of a chain has been fetched from the cache.
    CertificateFetchedFromCache {
        /// Unique identifier used to track this specific certificate chain validation
        certificate_chain_validation_id: String,
        /// The fetched certificate hash
        certificate_hash: String,
    },
    /// The whole certificate chain is valid.
    CertificateChainValidated {
        /// Unique identifier used to track this specific certificate chain validation
        certificate_chain_validation_id: String,
    },
}

impl MithrilEvent {
    /// Generate a random unique identifier to identify a snapshot download
    pub fn new_snapshot_download_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a random unique identifier to identify a Cardano download
    pub fn new_cardano_database_download_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a random unique identifier to identify a certificate chain validation
    pub fn new_certificate_chain_validation_id() -> String {
        Uuid::new_v4().to_string()
    }

    #[cfg(test)]
    pub(crate) fn event_id(&self) -> &str {
        match self {
            MithrilEvent::SnapshotDownloadStarted { download_id, .. } => download_id,
            MithrilEvent::SnapshotDownloadProgress { download_id, .. } => download_id,
            MithrilEvent::SnapshotDownloadCompleted { download_id } => download_id,
            MithrilEvent::SnapshotAncillaryDownloadStarted { download_id, .. } => download_id,
            MithrilEvent::SnapshotAncillaryDownloadProgress { download_id, .. } => download_id,
            MithrilEvent::SnapshotAncillaryDownloadCompleted { download_id } => download_id,
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::Started {
                download_id,
                ..
            }) => download_id,
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::Completed {
                download_id,
                ..
            }) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadStarted { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadProgress { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadCompleted { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadStarted { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadProgress { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadCompleted { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadStarted {
                download_id,
                ..
            }) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::DigestDownloadProgress { download_id, .. },
            ) => download_id,
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::DigestDownloadCompleted { download_id, .. },
            ) => download_id,
            MithrilEvent::CertificateChainValidationStarted {
                certificate_chain_validation_id,
            } => certificate_chain_validation_id,
            MithrilEvent::CertificateValidated {
                certificate_chain_validation_id,
                ..
            } => certificate_chain_validation_id,
            MithrilEvent::CertificateFetchedFromCache {
                certificate_chain_validation_id,
                ..
            } => certificate_chain_validation_id,
            MithrilEvent::CertificateChainValidated {
                certificate_chain_validation_id,
            } => certificate_chain_validation_id,
        }
    }
}

/// A sender of [MithrilEvent].
///
/// It uses Arc internally so it can be cloned at will.
#[derive(Clone)]
pub struct FeedbackSender {
    receivers: Vec<Arc<dyn FeedbackReceiver>>,
}

impl FeedbackSender {
    /// Create a new [FeedbackSender].
    pub fn new(receivers: &[Arc<dyn FeedbackReceiver>]) -> FeedbackSender {
        Self {
            receivers: receivers.to_vec(),
        }
    }

    /// Send the given event to the known receivers.
    pub async fn send_event(&self, event: MithrilEvent) {
        for receiver in &self.receivers {
            receiver.handle_event(event.clone()).await;
        }
    }
}

/// A receiver of [MithrilEvent].
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait FeedbackReceiver: Sync + Send {
    /// Callback called by a [FeedbackSender] when it needs to send an [event][MithrilEvent].
    async fn handle_event(&self, event: MithrilEvent);
}

/// A [FeedbackReceiver] that writes the event it receives in a [slog logger][Logger].
pub struct SlogFeedbackReceiver {
    logger: Logger,
}

impl SlogFeedbackReceiver {
    /// Create a new [SlogFeedbackReceiver].
    pub fn new(logger: Logger) -> SlogFeedbackReceiver {
        Self { logger }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl FeedbackReceiver for SlogFeedbackReceiver {
    async fn handle_event(&self, event: MithrilEvent) {
        match event {
            MithrilEvent::SnapshotDownloadStarted {
                digest,
                download_id,
                size,
            } => {
                info!(
                    self.logger, "Snapshot download started";
                    "size" => size, "digest" => digest, "download_id" => download_id,
                );
            }
            MithrilEvent::SnapshotDownloadProgress {
                download_id,
                downloaded_bytes,
                size,
            } => {
                info!(
                    self.logger, "Snapshot download in progress ...";
                    "downloaded_bytes" => downloaded_bytes, "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::SnapshotDownloadCompleted { download_id } => {
                info!(self.logger, "Snapshot download completed"; "download_id" => download_id);
            }
            MithrilEvent::SnapshotAncillaryDownloadStarted { download_id, size } => {
                info!(
                    self.logger, "Snapshot ancillary download started";
                    "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::SnapshotAncillaryDownloadProgress {
                download_id,
                downloaded_bytes,
                size,
            } => {
                info!(
                    self.logger, "Snapshot ancillary download in progress ...";
                    "downloaded_bytes" => downloaded_bytes, "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::SnapshotAncillaryDownloadCompleted { download_id } => {
                info!(self.logger, "Snapshot ancillary download completed"; "download_id" => download_id);
            }
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::Started {
                download_id,
                total_immutable_files,
                include_ancillary,
            }) => {
                info!(
                    self.logger, "Cardano database download started"; "download_id" => download_id, "total_immutable_files" => total_immutable_files, "include_ancillary" => include_ancillary,
                );
            }
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::Completed {
                download_id,
            }) => {
                info!(
                    self.logger, "Cardano database download completed"; "download_id" => download_id,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadStarted {
                    immutable_file_number,
                    download_id,
                    size,
                },
            ) => {
                info!(
                    self.logger, "Immutable download started";
                    "immutable_file_number" => immutable_file_number, "download_id" => download_id, "size" => size
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadProgress {
                    immutable_file_number,
                    download_id,
                    downloaded_bytes,
                    size,
                },
            ) => {
                info!(
                    self.logger, "Immutable download in progress ...";
                    "immutable_file_number" => immutable_file_number, "downloaded_bytes" => downloaded_bytes, "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::ImmutableDownloadCompleted {
                    immutable_file_number,
                    download_id,
                },
            ) => {
                info!(self.logger, "Immutable download completed"; "immutable_file_number" => immutable_file_number, "download_id" => download_id);
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadStarted { download_id, size },
            ) => {
                info!(
                    self.logger, "Ancillary download started";
                    "download_id" => download_id,
                    "size" => size,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadProgress {
                    download_id,
                    downloaded_bytes,
                    size,
                },
            ) => {
                info!(
                    self.logger, "Ancillary download in progress ...";
                    "downloaded_bytes" => downloaded_bytes, "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::AncillaryDownloadCompleted { download_id },
            ) => {
                info!(self.logger, "Ancillary download completed"; "download_id" => download_id);
            }
            MithrilEvent::CardanoDatabase(MithrilEventCardanoDatabase::DigestDownloadStarted {
                download_id,
                size,
            }) => {
                info!(
                    self.logger, "Digest download started";
                    "download_id" => download_id,
                    "size" => size,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::DigestDownloadProgress {
                    download_id,
                    downloaded_bytes,
                    size,
                },
            ) => {
                info!(
                    self.logger, "Digest download in progress ...";
                    "downloaded_bytes" => downloaded_bytes, "size" => size, "download_id" => download_id,
                );
            }
            MithrilEvent::CardanoDatabase(
                MithrilEventCardanoDatabase::DigestDownloadCompleted { download_id },
            ) => {
                info!(self.logger, "Digest download completed"; "download_id" => download_id);
            }
            MithrilEvent::CertificateChainValidationStarted {
                certificate_chain_validation_id,
            } => {
                info!(
                    self.logger, "Certificate chain validation started";
                    "certificate_chain_validation_id" => certificate_chain_validation_id,
                );
            }
            MithrilEvent::CertificateValidated {
                certificate_hash,
                certificate_chain_validation_id,
            } => {
                info!(
                    self.logger, "Certificate validated";
                    "certificate_hash" => certificate_hash,
                    "certificate_chain_validation_id" => certificate_chain_validation_id,
                );
            }
            MithrilEvent::CertificateFetchedFromCache {
                certificate_hash,
                certificate_chain_validation_id,
            } => {
                info!(
                    self.logger, "Cached";
                    "certificate_hash" => certificate_hash,
                    "certificate_chain_validation_id" => certificate_chain_validation_id,
                );
            }
            MithrilEvent::CertificateChainValidated {
                certificate_chain_validation_id,
            } => {
                info!(
                    self.logger, "Certificate chain validated";
                    "certificate_chain_validation_id" => certificate_chain_validation_id,
                );
            }
        };
    }
}

/// A [FeedbackReceiver] that stacks the events that it receives in a vec.
///
/// Use it only for tests purpose.
pub struct StackFeedbackReceiver {
    stacked_events: RwLock<Vec<MithrilEvent>>,
}

impl StackFeedbackReceiver {
    /// Create a new [StackFeedbackReceiver].
    pub fn new() -> StackFeedbackReceiver {
        Self {
            stacked_events: RwLock::new(vec![]),
        }
    }

    /// Returns a copy of the stored stacked events.
    ///
    /// Will crash if it can't access the stored events.
    pub fn stacked_events(&self) -> Vec<MithrilEvent> {
        let events = self.stacked_events.read().unwrap();
        events.clone()
    }
}

impl Default for StackFeedbackReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl FeedbackReceiver for StackFeedbackReceiver {
    async fn handle_event(&self, event: MithrilEvent) {
        let mut events = self.stacked_events.write().unwrap();
        events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::MithrilEvent::{SnapshotDownloadCompleted, SnapshotDownloadStarted};
    use crate::test_utils::TestLogger;
    use std::time::Duration;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn send_event_same_thread() {
        let receiver = Arc::new(StackFeedbackReceiver::new());
        let receiver_clone = receiver.clone() as Arc<dyn FeedbackReceiver>;
        let sender = FeedbackSender::new(&[receiver_clone]);

        sender
            .send_event(SnapshotDownloadStarted {
                digest: "digest".to_string(),
                download_id: "download_id".to_string(),
                size: 10,
            })
            .await;
        sender
            .send_event(SnapshotDownloadCompleted {
                download_id: "download_id".to_string(),
            })
            .await;

        assert_eq!(
            receiver.stacked_events(),
            vec![
                SnapshotDownloadStarted {
                    digest: "digest".to_string(),
                    download_id: "download_id".to_string(),
                    size: 10
                },
                SnapshotDownloadCompleted {
                    download_id: "download_id".to_string()
                }
            ]
        );
    }

    #[tokio::test]
    async fn send_event_multiple_thread() {
        let receiver = Arc::new(StackFeedbackReceiver::new());
        let sender = FeedbackSender::new(&[
            receiver.clone(),
            Arc::new(SlogFeedbackReceiver::new(TestLogger::stdout())),
        ]);
        let sender2 = sender.clone();
        let mut join_set = JoinSet::new();

        join_set.spawn(async move {
            // Step 1:
            sender
                .send_event(SnapshotDownloadStarted {
                    digest: "digest1".to_string(),
                    download_id: "download1".to_string(),
                    size: 1,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            // Step 3:
            sender
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download3".to_string(),
                })
                .await;
            sender
                .send_event(SnapshotDownloadStarted {
                    digest: "digest2".to_string(),
                    download_id: "download2".to_string(),
                    size: 2,
                })
                .await;
        });

        join_set.spawn(async move {
            // Step 2:
            sender2
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download1".to_string(),
                })
                .await;
            sender2
                .send_event(SnapshotDownloadStarted {
                    digest: "digest3".to_string(),
                    download_id: "download3".to_string(),
                    size: 3,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            // Step 4:
            sender2
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download2".to_string(),
                })
                .await;
        });

        while let Some(res) = join_set.join_next().await {
            res.unwrap();
        }

        assert_eq!(
            receiver.stacked_events(),
            vec![
                SnapshotDownloadStarted {
                    digest: "digest1".to_string(),
                    download_id: "download1".to_string(),
                    size: 1
                },
                SnapshotDownloadCompleted {
                    download_id: "download1".to_string()
                },
                SnapshotDownloadStarted {
                    digest: "digest3".to_string(),
                    download_id: "download3".to_string(),
                    size: 3
                },
                SnapshotDownloadCompleted {
                    download_id: "download3".to_string()
                },
                SnapshotDownloadStarted {
                    digest: "digest2".to_string(),
                    download_id: "download2".to_string(),
                    size: 2
                },
                SnapshotDownloadCompleted {
                    download_id: "download2".to_string()
                },
            ]
        );
    }

    #[tokio::test]
    async fn send_event_in_one_thread_and_receive_in_another_thread() {
        let receiver = Arc::new(StackFeedbackReceiver::new());
        let receiver_clone = receiver.clone() as Arc<dyn FeedbackReceiver>;
        let receiver2 = receiver.clone();
        let sender = FeedbackSender::new(&[receiver_clone]);
        let mut join_set = JoinSet::new();

        join_set.spawn(async move {
            // Step 1:
            sender
                .send_event(SnapshotDownloadStarted {
                    digest: "digest1".to_string(),
                    download_id: "download1".to_string(),
                    size: 1,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Step 2:
            sender
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download1".to_string(),
                })
                .await;
            sender
                .send_event(SnapshotDownloadStarted {
                    digest: "digest2".to_string(),
                    download_id: "download2".to_string(),
                    size: 2,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Step 3:
            sender
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download2".to_string(),
                })
                .await;
            sender
                .send_event(SnapshotDownloadStarted {
                    digest: "digest3".to_string(),
                    download_id: "download3".to_string(),
                    size: 3,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Final step:
            sender
                .send_event(SnapshotDownloadCompleted {
                    download_id: "download3".to_string(),
                })
                .await;
        });

        join_set.spawn(async move {
            // Little sleep to wait for step 1 completion
            tokio::time::sleep(Duration::from_millis(3)).await;
            assert_eq!(
                receiver2.stacked_events(),
                vec![SnapshotDownloadStarted {
                    digest: "digest1".to_string(),
                    download_id: "download1".to_string(),
                    size: 1
                },]
            );

            // Wait for step 2 completion
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(
                receiver2.stacked_events(),
                vec![
                    SnapshotDownloadStarted {
                        digest: "digest1".to_string(),
                        download_id: "download1".to_string(),
                        size: 1
                    },
                    SnapshotDownloadCompleted {
                        download_id: "download1".to_string()
                    },
                    SnapshotDownloadStarted {
                        digest: "digest2".to_string(),
                        download_id: "download2".to_string(),
                        size: 2
                    },
                ]
            );

            // Wait for step 3 completion
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(
                receiver2.stacked_events(),
                vec![
                    SnapshotDownloadStarted {
                        digest: "digest1".to_string(),
                        download_id: "download1".to_string(),
                        size: 1
                    },
                    SnapshotDownloadCompleted {
                        download_id: "download1".to_string()
                    },
                    SnapshotDownloadStarted {
                        digest: "digest2".to_string(),
                        download_id: "download2".to_string(),
                        size: 2
                    },
                    SnapshotDownloadCompleted {
                        download_id: "download2".to_string()
                    },
                    SnapshotDownloadStarted {
                        digest: "digest3".to_string(),
                        download_id: "download3".to_string(),
                        size: 3
                    },
                ]
            );
        });

        while let Some(res) = join_set.join_next().await {
            res.unwrap();
        }

        assert_eq!(
            receiver.stacked_events(),
            vec![
                SnapshotDownloadStarted {
                    digest: "digest1".to_string(),
                    download_id: "download1".to_string(),
                    size: 1
                },
                SnapshotDownloadCompleted {
                    download_id: "download1".to_string()
                },
                SnapshotDownloadStarted {
                    digest: "digest2".to_string(),
                    download_id: "download2".to_string(),
                    size: 2
                },
                SnapshotDownloadCompleted {
                    download_id: "download2".to_string()
                },
                SnapshotDownloadStarted {
                    digest: "digest3".to_string(),
                    download_id: "download3".to_string(),
                    size: 3
                },
                SnapshotDownloadCompleted {
                    download_id: "download3".to_string()
                },
            ]
        );
    }
}
