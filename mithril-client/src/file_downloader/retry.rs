use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use mithril_common::{StdResult, entities::CompressionAlgorithm};

use super::{DownloadEvent, FileDownloader, FileDownloaderUri};

/// Policy for retrying file downloads.
#[derive(Debug, PartialEq, Clone)]
pub struct FileDownloadRetryPolicy {
    /// Number of attempts to download a file.
    pub attempts: usize,
    /// Delay between two attempts.
    pub delay_between_attempts: Duration,
}

impl FileDownloadRetryPolicy {
    /// Create a policy that never retries.
    pub fn never() -> Self {
        Self {
            attempts: 1,
            delay_between_attempts: Duration::from_secs(0),
        }
    }
}

impl Default for FileDownloadRetryPolicy {
    /// Create a default retry policy.
    fn default() -> Self {
        Self {
            attempts: 3,
            delay_between_attempts: Duration::from_secs(5),
        }
    }
}

/// RetryDownloader is a wrapper around FileDownloader that retries downloading a file if it fails.
pub struct RetryDownloader {
    /// File downloader to use.
    file_downloader: Arc<dyn FileDownloader>,
    /// Number of attempts to download a file.
    retry_policy: FileDownloadRetryPolicy,
}

impl RetryDownloader {
    /// Create a new RetryDownloader.
    pub fn new(
        file_downloader: Arc<dyn FileDownloader>,
        retry_policy: FileDownloadRetryPolicy,
    ) -> Self {
        Self {
            file_downloader,
            retry_policy,
        }
    }
}

#[async_trait]
impl FileDownloader for RetryDownloader {
    async fn download_unpack(
        &self,
        location: &FileDownloaderUri,
        file_size: u64,
        target_dir: &Path,
        compression_algorithm: Option<CompressionAlgorithm>,
        download_event_type: DownloadEvent,
    ) -> StdResult<()> {
        let retry_policy = &self.retry_policy;
        let mut nb_attempts = 0;
        loop {
            nb_attempts += 1;
            match self
                .file_downloader
                .download_unpack(
                    location,
                    file_size,
                    target_dir,
                    compression_algorithm,
                    download_event_type.clone(),
                )
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) if nb_attempts >= retry_policy.attempts => {
                    return Err(e.context(format!(
                        "Download of location {location:?} failed after {nb_attempts} attempts",
                    )));
                }
                _ => tokio::time::sleep(retry_policy.delay_between_attempts).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::Instant};

    use mithril_common::entities::FileUri;

    use crate::file_downloader::MockFileDownloaderBuilder;

    use super::*;

    #[tokio::test]
    async fn download_return_the_result_of_download_without_retry() {
        let mock_file_downloader = MockFileDownloaderBuilder::default()
            .with_file_uri("http://whatever/00001.tar.zst")
            .with_compression(None)
            .with_success()
            .build();
        let retry_downloader = RetryDownloader::new(
            Arc::new(mock_file_downloader),
            FileDownloadRetryPolicy::never(),
        );

        retry_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://whatever/00001.tar.zst".to_string())),
                0,
                Path::new("."),
                None,
                DownloadEvent::Immutable {
                    immutable_file_number: 1,
                    download_id: "download_id".to_string(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn when_download_fails_do_not_retry_by_default() {
        let mock_file_downloader = MockFileDownloaderBuilder::default()
            .with_file_uri("http://whatever/00001.tar.zst")
            .with_compression(None)
            .with_failure()
            .build();
        let retry_downloader = RetryDownloader::new(
            Arc::new(mock_file_downloader),
            FileDownloadRetryPolicy::never(),
        );

        retry_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://whatever/00001.tar.zst".to_string())),
                0,
                Path::new("."),
                None,
                DownloadEvent::Immutable {
                    immutable_file_number: 1,
                    download_id: "download_id".to_string(),
                },
            )
            .await
            .expect_err("An error should be returned when download fails");
    }

    #[tokio::test]
    async fn should_retry_if_fail() {
        let mock_file_downloader = MockFileDownloaderBuilder::default()
            .with_file_uri("http://whatever/00001.tar.zst")
            .with_compression(None)
            .with_failure()
            .with_times(2)
            .next_call()
            .with_file_uri("http://whatever/00001.tar.zst")
            .with_compression(None)
            .with_times(1)
            .with_success()
            .build();
        let retry_downloader = RetryDownloader::new(
            Arc::new(mock_file_downloader),
            FileDownloadRetryPolicy {
                attempts: 3,
                delay_between_attempts: Duration::from_millis(10),
            },
        );

        retry_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://whatever/00001.tar.zst".to_string())),
                0,
                Path::new("."),
                None,
                DownloadEvent::Ancillary {
                    download_id: "download_id".to_string(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn should_recall_a_failing_inner_downloader_up_to_the_limit() {
        let mock_file_downloader = MockFileDownloaderBuilder::default()
            .with_file_uri("http://whatever/00001.tar.zst")
            .with_compression(None)
            .with_failure()
            .with_times(3)
            .build();
        let retry_downloader = RetryDownloader::new(
            Arc::new(mock_file_downloader),
            FileDownloadRetryPolicy {
                attempts: 3,
                delay_between_attempts: Duration::from_millis(10),
            },
        );

        retry_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://whatever/00001.tar.zst".to_string())),
                0,
                Path::new("."),
                None,
                DownloadEvent::Immutable {
                    immutable_file_number: 1,
                    download_id: "download_id".to_string(),
                },
            )
            .await
            .expect_err("An error should be returned when all download attempts fail");
    }

    #[tokio::test]
    async fn should_delay_between_retries() {
        struct FileDownloaderAssertDelay {
            expected_delay_greater_than_or_equal: Duration,
            expected_delay_less_than: Duration,
            last_attempt_start_time: Mutex<Option<Instant>>,
        }

        #[async_trait]
        impl FileDownloader for FileDownloaderAssertDelay {
            async fn download_unpack(
                &self,
                _location: &FileDownloaderUri,
                _file_size: u64,
                _target_dir: &Path,
                _compression_algorithm: Option<CompressionAlgorithm>,
                _download_event_type: DownloadEvent,
            ) -> StdResult<()> {
                let mut last_attempt_start_time = self.last_attempt_start_time.lock().unwrap();
                if let Some(last_start_attempt) = *last_attempt_start_time {
                    let duration = last_start_attempt.elapsed();
                    assert!(
                        duration >= self.expected_delay_greater_than_or_equal,
                        "duration should be greater than or equal to {}ms but was {}ms",
                        self.expected_delay_greater_than_or_equal.as_millis(),
                        duration.as_millis()
                    );
                    assert!(
                        duration < self.expected_delay_less_than,
                        "duration should be less than {}ms but was {}ms",
                        self.expected_delay_less_than.as_millis(),
                        duration.as_millis()
                    );
                }
                *last_attempt_start_time = Some(Instant::now());

                Err(anyhow::anyhow!("Download failed"))
            }
        }

        let delay_ms = 50;
        let mock_file_downloader = Arc::new(FileDownloaderAssertDelay {
            expected_delay_greater_than_or_equal: Duration::from_millis(delay_ms),
            expected_delay_less_than: Duration::from_millis(2 * delay_ms),
            last_attempt_start_time: Mutex::new(None),
        });

        let retry_downloader = RetryDownloader::new(
            mock_file_downloader.clone(),
            FileDownloadRetryPolicy {
                attempts: 4,
                delay_between_attempts: Duration::from_millis(delay_ms),
            },
        );

        retry_downloader
            .download_unpack(
                &FileDownloaderUri::FileUri(FileUri("http://whatever/00001.tar.zst".to_string())),
                0,
                Path::new("."),
                None,
                DownloadEvent::Immutable {
                    immutable_file_number: 1,
                    download_id: "download_id".to_string(),
                },
            )
            .await
            .expect_err("An error should be returned when all download attempts fail");
    }
}
