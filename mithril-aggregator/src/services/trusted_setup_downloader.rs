//! Download of the trusted setup SRS with the aggregator HTTP client.

use std::thread;
use std::time::Duration;

use anyhow::Context;
use reqwest::Client;
use reqwest::header::USER_AGENT;
use slog::{Logger, info, warn};
use thiserror::Error;
use tokio::runtime::Handle;

use mithril_common::StdResult;
use mithril_common::crypto_helper::TrustedSetupDownloader;
use mithril_common::logging::LoggerExtensions;

/// Errors of the SRS download.
#[derive(Debug, Error)]
pub enum TrustedSetupDownloadError {
    /// The download was called from a thread of the runtime it bridges onto, which it would block.
    #[error(
        "The SRS download blocks its thread for the whole transfer and must not run on a runtime thread"
    )]
    CalledFromRuntimeThread,
    /// Every attempt allowed by the retry policy failed.
    #[error("SRS download from '{url}' failed after {attempts} attempts")]
    AttemptsExhausted {
        /// URL the SRS was requested from.
        url: String,
        /// Number of attempts made.
        attempts: usize,
        /// Error of the last attempt.
        #[source]
        source: reqwest::Error,
    },
}

/// Policy for retrying the download of the SRS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSetupDownloadRetryPolicy {
    /// Number of attempts to download the SRS.
    pub attempts: usize,
    /// Delay between two attempts.
    pub delay_between_attempts: Duration,
}

impl TrustedSetupDownloadRetryPolicy {
    /// Policy that never retries.
    pub fn never() -> Self {
        Self {
            attempts: 1,
            delay_between_attempts: Duration::ZERO,
        }
    }
}

impl Default for TrustedSetupDownloadRetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            delay_between_attempts: Duration::from_secs(5),
        }
    }
}

/// Downloads the SRS of the trusted setup with the aggregator HTTP client, from the thread the
/// prover warm-up runs on.
///
/// The library expects a synchronous download while the client is asynchronous, so each attempt is
/// bridged onto the runtime whose handle was captured at construction. The bridge blocks the calling
/// thread for the whole transfer, so a call from a thread of that runtime is refused rather than
/// stalling one of its workers.
pub struct ReqwestTrustedSetupDownloader {
    client: Client,
    runtime_handle: Handle,
    url: String,
    timeout: Duration,
    retry_policy: TrustedSetupDownloadRetryPolicy,
    logger: Logger,
}

impl ReqwestTrustedSetupDownloader {
    /// Timeout of one download attempt, sized for an SRS of several hundred megabytes.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

    /// Factory
    pub fn new(
        url: String,
        runtime_handle: Handle,
        timeout: Duration,
        retry_policy: TrustedSetupDownloadRetryPolicy,
        logger: Logger,
    ) -> StdResult<Self> {
        Ok(Self {
            client: Client::builder()
                .build()
                .with_context(|| "Trusted setup downloader HTTP client creation failed")?,
            runtime_handle,
            url,
            timeout,
            retry_policy,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    /// One download attempt, run on the runtime.
    async fn download_once(&self) -> Result<Vec<u8>, reqwest::Error> {
        let response = self
            .client
            .get(&self.url)
            .header(USER_AGENT, "mithril-aggregator")
            .timeout(self.timeout)
            .send()
            .await?
            .error_for_status()?;

        Ok(response.bytes().await?.to_vec())
    }
}

impl TrustedSetupDownloader for ReqwestTrustedSetupDownloader {
    fn download(&self) -> StdResult<Vec<u8>> {
        if Handle::try_current().is_ok() {
            return Err(TrustedSetupDownloadError::CalledFromRuntimeThread.into());
        }

        let attempts = self.retry_policy.attempts.max(1);
        let mut attempt = 1;
        loop {
            info!(
                self.logger, "Downloading the SRS of the trusted setup";
                "url" => &self.url, "attempt" => attempt, "attempts" => attempts
            );
            match self.runtime_handle.block_on(self.download_once()) {
                Ok(bytes) => return Ok(bytes),
                Err(error) if attempt < attempts => {
                    warn!(
                        self.logger, "SRS download attempt failed, retrying";
                        "attempt" => attempt, "error" => ?error
                    );
                    thread::sleep(self.retry_policy.delay_between_attempts);
                    attempt += 1;
                }
                Err(error) => {
                    return Err(TrustedSetupDownloadError::AttemptsExhausted {
                        url: self.url.clone(),
                        attempts: attempt,
                        source: error,
                    }
                    .into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method::GET, MockServer};
    use tokio::runtime::Runtime;

    use crate::test::TestLogger;

    use super::*;

    fn downloader(
        url: String,
        runtime_handle: Handle,
        retry_policy: TrustedSetupDownloadRetryPolicy,
    ) -> ReqwestTrustedSetupDownloader {
        ReqwestTrustedSetupDownloader::new(
            url,
            runtime_handle,
            Duration::from_secs(5),
            retry_policy,
            TestLogger::stdout(),
        )
        .unwrap()
    }

    fn retry_policy(attempts: usize) -> TrustedSetupDownloadRetryPolicy {
        TrustedSetupDownloadRetryPolicy {
            attempts,
            delay_between_attempts: Duration::ZERO,
        }
    }

    #[test]
    fn downloads_the_bytes_served_at_the_url_on_the_first_successful_attempt() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(200).body(b"srs bytes");
        });
        let runtime = Runtime::new().unwrap();
        let downloader = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );

        let bytes = downloader.download().unwrap();

        assert_eq!(b"srs bytes".to_vec(), bytes);
        mock.assert_calls(1);
    }

    #[test]
    fn refuses_to_download_from_a_runtime_thread() {
        let runtime = Runtime::new().unwrap();
        let downloader = downloader(
            "http://127.0.0.1:1/srs".to_string(),
            runtime.handle().clone(),
            retry_policy(1),
        );

        let error = runtime.block_on(async { downloader.download() }).unwrap_err();

        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::CalledFromRuntimeThread)
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retries_a_failing_download_up_to_the_policy_attempts() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(500);
        });
        let runtime = Runtime::new().unwrap();
        let downloader = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            retry_policy(3),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(3);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::AttemptsExhausted { attempts: 3, .. })
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn fails_on_an_error_status_without_retry_when_the_policy_never_retries() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/srs");
            then.status(404);
        });
        let runtime = Runtime::new().unwrap();
        let downloader = downloader(
            server.url("/srs"),
            runtime.handle().clone(),
            TrustedSetupDownloadRetryPolicy::never(),
        );

        let error = downloader.download().unwrap_err();

        mock.assert_calls(1);
        assert!(
            matches!(
                error.downcast_ref::<TrustedSetupDownloadError>(),
                Some(TrustedSetupDownloadError::AttemptsExhausted { attempts: 1, source, .. })
                    if source.is_status()
            ),
            "unexpected error: {error:?}"
        );
    }
}
